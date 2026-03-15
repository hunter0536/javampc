package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.common.response.AuxTaskStatusResponse;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dto.AuxInfo;
import com.example.mpc.dto.CggmpAuxTask;
import com.example.mpc.enums.MessageType;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxMessageDispatcher;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxMessageHandler;
import com.example.mpc.service.cggmp.auxiliary.CggmpAuxProtocolHandler;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

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

    @Value("${cggmp.aux.paillierBits:3072}")
    public int auxPaillierBits;

    @Value("${cggmp.aux.minPaillierBitsForProof:2048}")
    public int auxMinPaillierBitsForProof;

    public final Map<String, CggmpAuxTask> auxTasks = new ConcurrentHashMap<>();

    public record AuxStatus(boolean hasAux, long tsMs) {
    }

    public final ConcurrentHashMap<Integer, AuxStatus> auxStatus = new ConcurrentHashMap<>();

    public final int nodesCount = Constants.NODES_COUNT;
    public final ScheduledExecutorService auxScheduler = Executors.newSingleThreadScheduledExecutor();

    public volatile PaillierEncryption auxPaillier;
    public volatile BigInteger auxHatN;
    public volatile BigInteger auxS;
    public volatile BigInteger auxT;

    @PostConstruct
    public void validateAuxParams() {
        int max = PaillierEncryption.MAX_KEY_SIZE;
        if (auxPaillierBits > max) {
            logger.warn("cggmp.aux.paillierBits={} exceeds max {}, clamping to {}", auxPaillierBits, max, max);
            auxPaillierBits = max;
        }
        if (auxMinPaillierBitsForProof > max) {
            logger.warn("cggmp.aux.minPaillierBitsForProof={} exceeds max {}, clamping to {}", auxMinPaillierBitsForProof, max, max);
            auxMinPaillierBitsForProof = max;
        }
        if (auxMinPaillierBitsForProof > auxPaillierBits) {
            logger.warn("cggmp.aux.minPaillierBitsForProof={} exceeds cggmp.aux.paillierBits={}, clamping to {}",
                    auxMinPaillierBitsForProof, auxPaillierBits, auxPaillierBits);
            auxMinPaillierBitsForProof = auxPaillierBits;
        }
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_AUX_INIT,
                            MessageType.CGGMP_AUX_R1,
                            MessageType.CGGMP_AUX_R1_ECHO,
                            MessageType.CGGMP_AUX_R2,
                            MessageType.CGGMP_AUX_R3,
                            MessageType.CGGMP_AUX_STATUS,
                            MessageType.CGGMP_AUX_SAVED
                    ), this);
                    logger.info("CGGMP AUX service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP AUX service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    public AuxInfo loadLatestAuxInfo(int nodeIdVal) {
        try {
            AuxInfo info = auxInfoDao.loadLatestSync(nodeIdVal);
            if (info != null && auxPaillier == null) {
                BigInteger p = new BigInteger(info.getPaillierP(), 16);
                BigInteger q = new BigInteger(info.getPaillierQ(), 16);
                auxPaillier = new PaillierEncryption(p, q);
                auxHatN = new BigInteger(info.getPedersenHatN(), 16);
                auxS = new BigInteger(info.getPedersenS(), 16);
                auxT = new BigInteger(info.getPedersenT(), 16);
                logger.debug("Loaded CGGMP AUX info for node: {}", nodeIdVal);
            }
            return info;
        } catch (Exception e) {
            logger.error("Failed to load CGGMP AUX info", e);
            return null;
        }
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
                    Map<String, Object> initData = new java.util.HashMap<>();
                    initData.put("taskId", task.taskId);
                    initData.put("executionId", task.executionId);
                    initData.put("initiatorId", nodeId);
                    initData.put("participants", new java.util.ArrayList<>(task.participants));
                    return com.example.mpc.common.util.RetryUtils.retryAsync(
                            java.util.concurrent.Executors.newSingleThreadScheduledExecutor(),
                            logger,
                            () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_INIT, initData)),
                            Constants.BROADCAST_RETRY_COUNT,
                            Constants.BROADCAST_RETRY_INTERVAL_MS,
                            "CGGMP_AUX_INIT");
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
        response.setReceivedSaved(task.savedReceived.size());
        return response;
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return auxMessageDispatcher.handleMessage(senderId, message);
    }
}
