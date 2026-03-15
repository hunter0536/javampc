 package com.example.mpc.scheduler;

import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.dto.CggmpAuxTask;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.NodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class AuxScheduler {
    private static final Logger logger = LoggerFactory.getLogger(AuxScheduler.class);

    @Autowired
    private CggmpAuxService auxService;

    @Autowired
    private NodeService nodeService;

    @Value("${node.id}")
    private int nodeId;

    private final int nodesCount = Constants.NODES_COUNT;
    private final AtomicBoolean auxAutoTriggered = new AtomicBoolean(false);
    private final AtomicBoolean auxAutoCheckRunning = new AtomicBoolean(false);

    @Scheduled(fixedDelayString = "${cggmp.aux.autoCheckIntervalSeconds:60}000", initialDelayString = "${cggmp.aux.autoCheckIntervalSeconds:60}000")
    public void runAuxAutoCheck() {
        if (!auxAutoCheckRunning.compareAndSet(false, true)) {
            return;
        }
        boolean asyncStarted = false;
        try {
            logAuxExecutorStats("AUX auto check");
            int leaderId = resolveAuxAutoLeaderId();

            boolean hasAux = auxService.loadLatestAuxInfo(nodeId) != null;
            broadcastAuxStatus(hasAux);

            if (nodeId != leaderId) {
                logger.debug("Node {} is not auto leader (leader is {}), skipping AUX trigger", nodeId, leaderId);
                return;
            }

            if (hasActiveAuxTask()) {
                logger.debug("AUX auto check: task already in progress on leader {}, skipping", nodeId);
                return;
            }

            broadcastAuxStatus(hasAux);

            asyncStarted = true;
            waitForAuxStatusAsync()
                    .thenRun(() -> {
                        logAuxExecutorStats("AUX status gathered");
                        long nowMs = System.currentTimeMillis();
                        List<Integer> missing = new ArrayList<>();
                        List<Integer> noAux = new ArrayList<>();
                        for (int id = 1; id <= nodesCount; id++) {
                            CggmpAuxService.AuxStatus status = auxService.auxStatus.get(id);
                            if (status == null || nowMs - status.tsMs() > Constants.AUX_STATUS_WAIT_MS) {
                                missing.add(id);
                            } else if (!status.hasAux()) {
                                noAux.add(id);
                            }
                        }
                        if (!missing.isEmpty()) {
                            logger.warn("AUX status missing from nodes {}, skipping auto trigger this round", missing);
                            return;
                        }
                        if (!noAux.isEmpty()) {
                            logger.warn("AUX status mismatch detected. Nodes without AUX={}", noAux);
                            String taskId = auxService.createAuxTask();
                            logger.info("Auto leader {} initiating AUX task {}", nodeId, taskId);
                            auxService.startAuxProcess(taskId).exceptionally(ex -> {
                                logger.error("Auto AUX failed for task {}: {}", taskId, ex.getMessage(), ex);
                                return null;
                            });
                            return;
                        }

                        if (hasAux) {
                            logger.debug("All nodes report AUX present; skipping auto provision on leader {}", nodeId);
                            return;
                        }
                        logger.warn("Leader {} missing AUX but peers reported present; initiating AUX to reconcile", nodeId);
                        String taskId = auxService.createAuxTask();
                        auxService.startAuxProcess(taskId).exceptionally(ex -> {
                            logger.error("Auto AUX failed for task {}: {}", taskId, ex.getMessage(), ex);
                            return null;
                        });
                    })
                    .exceptionally(ex -> {
                        logger.error("Auto AUX status wait failed on node {}: {}", nodeId, ex.getMessage(), ex);
                        return null;
                    })
                    .whenComplete((v, ex) -> auxAutoCheckRunning.set(false));
        } catch (Exception e) {
            auxAutoCheckRunning.set(false);
            logger.error("Auto AUX check failed on node {}: {}", nodeId, e.getMessage(), e);
        } finally {
            if (!asyncStarted) {
                auxAutoCheckRunning.set(false);
            }
        }
    }

    private int resolveAuxAutoLeaderId() {
        int minId = nodeId;
        for (NodeService.NodeInfo info : nodeService.getNodes()) {
            if (info != null) {
                minId = Math.min(minId, info.id);
            }
        }
        return minId;
    }

    private boolean hasActiveAuxTask() {
        for (CggmpAuxTask task : auxService.auxTasks.values()) {
            if (task != null && task.status.get() == TaskStatus.IN_PROGRESS) {
                return true;
            }
        }
        return false;
    }

    private void broadcastAuxStatus(boolean hasAux) {
        auxService.auxStatus.put(nodeId, new CggmpAuxService.AuxStatus(hasAux, System.currentTimeMillis()));
        Map<String, Object> msg = new HashMap<>();
        msg.put("senderId", nodeId);
        msg.put("hasAux", hasAux);
        msg.put("ts", System.currentTimeMillis());
        RetryUtils.retryAsync(auxService.auxScheduler, logger,
                        () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, 
                                com.example.mpc.enums.MessageType.CGGMP_AUX_STATUS, msg)),
                        Constants.BROADCAST_RETRY_COUNT,
                        Constants.BROADCAST_RETRY_INTERVAL_MS,
                        "CGGMP_AUX_STATUS")
                .exceptionally(ex -> {
                    logger.warn("Failed to broadcast AUX status from node {}: {}", nodeId, ex.getMessage());
                    return null;
                });
    }

    private CompletableFuture<Void> waitForAuxStatusAsync() {
        long deadline = System.currentTimeMillis() + Constants.AUX_STATUS_WAIT_MS;
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = auxService.auxScheduler.scheduleAtFixedRate(() -> {
            if (auxService.auxStatus.size() >= nodesCount) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                future.complete(null);
            }
        }, 0, 200, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private void logAuxExecutorStats(String stage) {
        java.util.concurrent.ExecutorService pool = com.example.mpc.common.util.ThreadPoolUtil.getAuxThreadPool();
        if (pool instanceof java.util.concurrent.ThreadPoolExecutor tpe) {
            logger.debug("AUX executor stats [{}]: poolSize={}, active={}, queued={}, completed={}",
                    stage, tpe.getPoolSize(), tpe.getActiveCount(), tpe.getQueue().size(), tpe.getCompletedTaskCount());
        } else {
            logger.debug("AUX executor stats [{}]: poolType={}", stage, pool.getClass().getName());
        }
    }

    public void handleAuxStatusMessage(int senderId, boolean hasAux, long ts) {
        auxService.auxStatus.put(senderId, new CggmpAuxService.AuxStatus(hasAux, ts));
        logger.debug("Received AUX status from node {}: hasAux={}, ts={}", senderId, hasAux, ts);
    }
}
