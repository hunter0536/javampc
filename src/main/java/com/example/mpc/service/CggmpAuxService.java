package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.common.response.AuxTaskStatusResponse;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.dto.AuxInfo;
import com.example.mpc.dto.CggmpAuxTask;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxMessageDispatcher;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxMessageHandler;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxProtocolHandler;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * CGGMP辅助密钥生成服务
 * 负责生成Paillier公钥和Pedersen承诺所需的密钥材料
 */
@Service
public class CggmpAuxService implements NodeService.MessageHandler {
    public static final Logger logger = LoggerFactory.getLogger(CggmpAuxService.class);
    public static final BiPrimeProofValidator BI_PRIME_VALIDATOR = new BiPrimeProofValidator();

    public final CggmpAuxProtocolHandler auxProtocolHandler = new CggmpAuxProtocolHandler(this);
    public final CggmpAuxMessageHandler auxMessageHandler = new CggmpAuxMessageHandler(this);
    public final CggmpAuxMessageDispatcher auxMessageDispatcher = new CggmpAuxMessageDispatcher(this);

    @Autowired
    public NodeService nodeService;

    @Autowired
    public AuxInfoDao auxInfoDao;

    @Value("${node.id}")
    public int nodeId;

    @Value("${app.cggmp.aux.paillierBits:3072}")
    public int auxPaillierBits;

    @Value("${app.cggmp.aux.minPaillierBitsForProof:2048}")
    public int auxMinPaillierBitsForProof;

    @Value("${app.cggmp.aux.autoCheckIntervalSeconds:60}")
    public long auxAutoCheckIntervalSeconds;

    public final Map<String, CggmpAuxTask> auxTasks = new ConcurrentHashMap<>();

    public record AuxStatus(boolean hasAux, long tsMs) {
    }

    public final ConcurrentHashMap<Integer, AuxStatus> auxStatus = new ConcurrentHashMap<>();
    private final AtomicBoolean auxAutoTriggered = new AtomicBoolean(false);
    private final AtomicBoolean auxAutoCheckRunning = new AtomicBoolean(false);

    public final int nodesCount = Constants.NODES_COUNT;
    public final java.util.concurrent.ScheduledExecutorService auxScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();

    public volatile PaillierEncryption auxPaillier;
    public volatile BigInteger auxHatN;
    public volatile BigInteger auxS;
    public volatile BigInteger auxT;

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_AUX_INIT,
                            MessageType.CGGMP_AUX_R1,
                            MessageType.CGGMP_AUX_R1_ECHO,
                            MessageType.CGGMP_AUX_R2,
                            MessageType.CGGMP_AUX_R3,
                            MessageType.CGGMP_AUX_STATUS
                    ), this);
                    logger.info("CGGMP AUX service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP AUX service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    public CompletableFuture<Void> ensureAuxProvisionedAfterNetworkReady() {
        return ThreadPoolUtil.submitIoTask(() -> {
            if (!auxAutoTriggered.compareAndSet(false, true)) {
                return;
            }
            logAuxExecutorStats("AUX init");
            nodeService.waitForNetworkReady()
                    .thenRun(() -> {
                        logAuxExecutorStats("AUX network ready");
                        runAuxAutoCheck();
                        long interval = Math.max(5, auxAutoCheckIntervalSeconds);
                        auxScheduler.scheduleWithFixedDelay(this::runAuxAutoCheck, interval, interval, TimeUnit.SECONDS);
                    })
                    .exceptionally(ex -> {
                        logger.error("Auto AUX provisioning failed on node {}: {}", nodeId, ex.getMessage(), ex);
                        return null;
                    });
        });
    }

    private void runAuxAutoCheck() {
        if (!auxAutoCheckRunning.compareAndSet(false, true)) {
            return;
        }
        boolean asyncStarted = false;
        try {
            logAuxExecutorStats("AUX auto check");
            int leaderId = resolveAuxAutoLeaderId();

            boolean hasAux = loadLatestAuxInfo(nodeId) != null;
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
                            AuxStatus status = auxStatus.get(id);
                            if (status == null || nowMs - status.tsMs > Constants.AUX_STATUS_WAIT_MS) {
                                missing.add(id);
                            } else if (!status.hasAux) {
                                noAux.add(id);
                            }
                        }
                        if (!missing.isEmpty()) {
                            logger.warn("AUX status missing from nodes {}, skipping auto trigger this round", missing);
                            return;
                        }
                        if (!noAux.isEmpty()) {
                            logger.warn("AUX status mismatch detected. Nodes without AUX={}", noAux);
                            String taskId = createAuxTask();
                            logger.info("Auto leader {} initiating AUX task {}", nodeId, taskId);
                            startAuxProcess(taskId).exceptionally(ex -> {
                                logger.error("Auto AUX failed for task {}: {}", taskId, ex.getMessage(), ex);
                                return null;
                            });
                            return;
                        }

                        if (hasAux) {
                            logger.info("All nodes report AUX present; skipping auto provision on leader {}", nodeId);
                            return;
                        }
                        logger.warn("Leader {} missing AUX but peers reported present; initiating AUX to reconcile", nodeId);
                        String taskId = createAuxTask();
                        startAuxProcess(taskId).exceptionally(ex -> {
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
        pruneStaleAuxTasks();
        for (CggmpAuxTask task : auxTasks.values()) {
            if (task != null && task.status.get() == TaskStatus.IN_PROGRESS) {
                return true;
            }
        }
        return false;
    }

    private void pruneStaleAuxTasks() {
        for (var it = auxTasks.entrySet().iterator(); it.hasNext(); ) {
            var entry = it.next();
            CggmpAuxTask task = entry.getValue();
            if (task == null) continue;
            if (task.status.get() == TaskStatus.IN_PROGRESS && task.isTimeout()) {
                task.fail("AUX task timeout");
                task.lastErrorEvidence = CggmpAuxUtils.buildAuxEvidence(task);
                logger.warn("AUX task timed out and will be cleared: taskId={}, executionId={}",
                        task.taskId, task.executionId);
                it.remove();
            }
        }
    }

    private AuxInfo loadLatestAuxInfo(int nodeIdVal) {
        try {
            AuxInfo info = auxInfoDao.loadLatestSync(nodeIdVal);
            if (info != null && auxPaillier == null) {
                BigInteger p = new BigInteger(info.getPaillierP(), 16);
                BigInteger q = new BigInteger(info.getPaillierQ(), 16);
                auxPaillier = new PaillierEncryption(p, q);
                auxHatN = new BigInteger(info.getPedersenHatN(), 16);
                auxS = new BigInteger(info.getPedersenS(), 16);
                auxT = new BigInteger(info.getPedersenT(), 16);
                logger.info("Loaded CGGMP AUX info for node: {}", nodeIdVal);
            }
            return info;
        } catch (Exception e) {
            logger.error("Failed to load CGGMP AUX info", e);
            return null;
        }
    }

    private void broadcastAuxStatus(boolean hasAux) {
        auxStatus.put(nodeId, new AuxStatus(hasAux, System.currentTimeMillis()));
        Map<String, Object> msg = new HashMap<>();
        msg.put("senderId", nodeId);
        msg.put("hasAux", hasAux);
        msg.put("ts", System.currentTimeMillis());
        nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_STATUS, msg))
                .exceptionally(ex -> {
                    logger.warn("Failed to broadcast AUX status from node {}: {}", nodeId, ex.getMessage());
                    return null;
                });
    }

    private CompletableFuture<Void> waitForAuxStatusAsync() {
        long deadline = System.currentTimeMillis() + Constants.AUX_STATUS_WAIT_MS;
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = auxScheduler.scheduleAtFixedRate(() -> {
            if (auxStatus.size() >= nodesCount) {
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

    public String createAuxTask() {
        String taskId = UUID.randomUUID().toString();
        String executionId = UUID.randomUUID().toString();
        Set<Integer> participants = new LinkedHashSet<>();
        for (int i = 1; i <= nodesCount; i++) {
            participants.add(i);
        }
        CggmpAuxTask task = new CggmpAuxTask(taskId, executionId, nodesCount, nodeId, participants);
        auxTasks.put(taskId, task);
        logger.info("Created CGGMP AUX task: {}", taskId);
        return taskId;
    }

    public CompletableFuture<Void> startAuxProcess(String taskId) {
        logger.info("=================== startAuxProcess START: taskId={} ===================", taskId);
        final long auxStartNs = System.nanoTime();
        logAuxExecutorStats("AUX start task " + taskId);
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Aux task not found"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        auxMessageHandler.drainPending(taskId);

        CompletableFuture<Void> flow = nodeService.waitForNetworkReady()
                .thenCompose(v -> {
                    if (nodeId != task.initiatorId) {
                        return CompletableFuture.completedFuture(null);
                    }
                    Map<String, Object> initData = new HashMap<>();
                    initData.put("taskId", task.taskId);
                    initData.put("executionId", task.executionId);
                    initData.put("initiatorId", nodeId);
                    initData.put("participants", new ArrayList<>(task.participants));
                    return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_INIT, initData));
                })
                .thenCompose(v -> auxProtocolHandler.runAuxProtocolAsync(task));

        return flow.whenComplete((v, ex) -> {
            if (ex == null) {
                task.complete();
                logger.debug("CGGMP AUX completed for task: {} in {} ms", taskId, (System.nanoTime() - auxStartNs) / 1_000_000);
            } else {
                task.fail(ex.getMessage());
                logger.error("Error in CGGMP AUX process", ex);
            }
        });
    }

    private void logAuxExecutorStats(String stage) {
        java.util.concurrent.ExecutorService pool = ThreadPoolUtil.getAuxThreadPool();
        if (pool instanceof java.util.concurrent.ThreadPoolExecutor tpe) {
            logger.debug("AUX executor stats [{}]: poolSize={}, active={}, queued={}, completed={}",
                    stage, tpe.getPoolSize(), tpe.getActiveCount(), tpe.getQueue().size(), tpe.getCompletedTaskCount());
        } else {
            logger.debug("AUX executor stats [{}]: poolType={}", stage, pool.getClass().getName());
        }
    }

    public AuxTaskStatusResponse getAuxTaskStatus(String taskId) {
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Aux task not found: " + taskId);
        }
        AuxTaskStatusResponse response = new AuxTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.status.get().isRunning());
        response.setCompleted(task.status.get() == TaskStatus.COMPLETED);
        response.setErrorMessage(task.errorMessage);
        response.setLastErrorEvidence(task.lastErrorEvidence);
        response.setReceivedCommits(task.commitHashes.size());
        response.setReceivedEcho(task.echoReceived.size());
        response.setReceivedReveal(task.peerHatN.size());
        response.setReceivedProofs(task.peerModProofs.size());
        return response;
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return auxMessageDispatcher.handleMessage(senderId, message);
    }
}
