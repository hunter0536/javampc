package com.example.mpc.service;

import com.example.mpc.cggmp.util.CggmpCodecUtils;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofGenerator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofGenerator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.common.response.AuxTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.AuxInfo;
import com.example.mpc.model.CggmpAuxTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class CggmpAuxService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpAuxService.class);
    private final SecureRandom secureRandom = new SecureRandom();
    private static final ExecutorService auxExecutorService = ThreadPoolUtil.getAuxThreadPool();
    private static final BiPrimeProofValidator BI_PRIME_VALIDATOR = new BiPrimeProofValidator();

    @Autowired
    private NodeService nodeService;

    @Autowired
    private AuxInfoDao auxInfoDao;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.cggmp.aux.paillierBits:3072}")
    private int auxPaillierBits;

    @Value("${app.cggmp.aux.minPaillierBitsForProof:2048}")
    private int auxMinPaillierBitsForProof;

    @Value("${app.cggmp.aux.autoCheckIntervalSeconds:60}")
    private long auxAutoCheckIntervalSeconds;

    private final Map<String, CggmpAuxTask> auxTasks = new ConcurrentHashMap<>();
    private static final class AuxStatus {
        final boolean hasAux;
        final long tsMs;

        AuxStatus(boolean hasAux, long tsMs) {
            this.hasAux = hasAux;
            this.tsMs = tsMs;
        }
    }

    private final ConcurrentHashMap<Integer, AuxStatus> auxStatus = new ConcurrentHashMap<>();
    private final AtomicBoolean auxAutoTriggered = new AtomicBoolean(false);
    private final AtomicBoolean auxAutoCheckRunning = new AtomicBoolean(false);

    private final int nodesCount = Constants.NODES_COUNT;
    private java.util.concurrent.ScheduledExecutorService auxScheduler = java.util.concurrent.Executors.newSingleThreadScheduledExecutor();

    private static final class PendingMsg {
        final int senderId;
        final Object data;
        final MessageType type;

        PendingMsg(int senderId, Object data, MessageType type) {
            this.senderId = senderId;
            this.data = data;
            this.type = type;
        }
    }

    private final ConcurrentHashMap<String, java.util.concurrent.ConcurrentLinkedQueue<PendingMsg>> pendingAuxMessages =
            new ConcurrentHashMap<>();

    private volatile PaillierEncryption auxPaillier;
    private volatile BigInteger auxHatN;
    private volatile BigInteger auxS;
    private volatile BigInteger auxT;

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
            nodeService.waitForNetworkReady()
                    .thenRun(() -> {
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
            if (task != null && task.status.get() == com.example.mpc.enums.TaskStatus.IN_PROGRESS) {
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
            if (task.status.get() == com.example.mpc.enums.TaskStatus.IN_PROGRESS && task.isTimeout()) {
                task.fail("AUX task timeout");
                task.lastErrorEvidence = buildAuxEvidence(task);
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
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Aux task not found"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        drainPending(taskId);

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
                .thenCompose(v -> runAuxProtocolAsync(task));

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

    public AuxTaskStatusResponse getAuxTaskStatus(String taskId) {
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Aux task not found: " + taskId);
        }
        AuxTaskStatusResponse response = new AuxTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.status.get().isRunning());
        response.setCompleted(task.status.get() == com.example.mpc.enums.TaskStatus.COMPLETED);
        response.setErrorMessage(task.errorMessage);
        response.setLastErrorEvidence(task.lastErrorEvidence);
        response.setReceivedCommits(task.commitHashes.size());
        response.setReceivedEcho(task.echoReceived.size());
        response.setReceivedReveal(task.peerHatN.size());
        response.setReceivedProofs(task.peerModProofs.size());
        return response;
    }

    private void fireAndForget(CompletableFuture<Void> future, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    private CompletableFuture<Void> waitForLatchAsync(CggmpAuxTask task, CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = auxScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                task.lastErrorEvidence = buildAuxEvidence(task);
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label + " (taskId=" + task.taskId + ")"));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private java.util.Map<String, Object> buildAuxEvidence(CggmpAuxTask task) {
        java.util.Map<String, Object> ev = new java.util.HashMap<>();
        ev.put("taskId", task.taskId);
        ev.put("executionId", task.executionId);
        ev.put("participants", task.participants);
        ev.put("commitReceived", task.commitHashes.size());
        ev.put("echoReceived", task.echoReceived.size());
        ev.put("revealReceived", task.peerHatN.size());
        ev.put("proofsReceived", task.peerModProofs.size());
        ev.put("commitLatch", task.commitLatch.getCount());
        ev.put("echoLatch", task.echoLatch.getCount());
        ev.put("revealLatch", task.revealLatch.getCount());
        ev.put("proofLatch", task.proofLatch.getCount());
        return ev;
    }

    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private CompletableFuture<Void> runAuxProtocolAsync(CggmpAuxTask task) {
        final long auxStartNs = System.nanoTime();
        logger.debug("AUX protocol starting: taskId={}, executionId={}", task.taskId, task.executionId);
        return CompletableFuture.supplyAsync(() -> {
            logger.debug("AUX protocol running: taskId={}, executionId={}", task.taskId, task.executionId);
            long paillierStart = System.nanoTime();
            PaillierEncryption paillier = new PaillierEncryption(auxPaillierBits);
            logger.debug("AUX Paillier generated in {} ms (bits={})", (System.nanoTime() - paillierStart) / 1_000_000, auxPaillierBits);
            task.paillier = paillier;
            long pedStart = System.nanoTime();
            ZKSetup.ZKSetupWithLambda ped = ZKSetup.generateWithLambda(paillier.getPublicKeyInfo().bitLength);
            logger.debug("AUX Pedersen/ZK setup generated in {} ms (bits={})", (System.nanoTime() - pedStart) / 1_000_000, paillier.getPublicKeyInfo().bitLength);
            task.hatN = ped.zk().hatN();
            task.s = ped.zk().h1();
            task.t = ped.zk().h2();
            task.pedersenLambda = ped.lambda();

            byte[] rho_i = randomBytes(32);
            byte[] u_i = randomBytes(32);
            task.rho.put(nodeId, rho_i);
            task.u.put(nodeId, u_i);

            PiPrmProof prmProof = RefreshProofs.createPrmProof(task.hatN, task.s, task.t, task.pedersenLambda,
                    buildAuxContext(task.taskId, task.executionId, nodeId, "PRM"));
            task.prmProof = prmProof;

            String vCommit = computeAuxCommitHash(task.executionId, task.taskId, nodeId,
                    CggmpCodecUtils.encodePaillierPublicKey(paillier.getPublicKeyInfo()),
                    task.hatN.toString(16), task.s.toString(16), task.t.toString(16),
                    CggmpCodecUtils.encodePiPrmProof(prmProof), rho_i, u_i);
            task.commitHashes.put(nodeId, vCommit);

            Map<String, Object> r1 = new HashMap<>();
            r1.put("taskId", task.taskId);
            r1.put("executionId", task.executionId);
            r1.put("senderId", nodeId);
            r1.put("V", vCommit);
            fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R1, r1)),
                    "CGGMP_AUX_R1_RBC");
            return new AuxContext(task, paillier, prmProof, rho_i, u_i);
        }, auxExecutorService)
                .thenCompose(ctx -> waitForLatchAsync(task, task.commitLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R1")
                        .exceptionally(ex -> {
                            fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R1, Map.of(
                                    "taskId", task.taskId,
                                    "executionId", task.executionId,
                                    "senderId", nodeId,
                                    "V", task.commitHashes.get(nodeId)
                            ))), "CGGMP_AUX_R1_RBC_RETRY");
                            throw new java.util.concurrent.CompletionException(ex);
                        })
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    String echo = computeAuxEchoHash(task);
                    Map<String, Object> r1Echo = new HashMap<>();
                    r1Echo.put("taskId", task.taskId);
                    r1Echo.put("executionId", task.executionId);
                    r1Echo.put("senderId", nodeId);
                    r1Echo.put("hash", echo);
                    fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R1_ECHO, r1Echo)),
                            "CGGMP_AUX_R1_ECHO");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForLatchAsync(task, task.echoLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R1 echo")
                        .exceptionally(ex -> {
                            String echo = computeAuxEchoHash(task);
                            if (echo != null) {
                                Map<String, Object> r1Echo = new HashMap<>();
                                r1Echo.put("taskId", task.taskId);
                                r1Echo.put("executionId", task.executionId);
                                r1Echo.put("senderId", nodeId);
                                r1Echo.put("hash", echo);
                                fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R1_ECHO, r1Echo)),
                                        "CGGMP_AUX_R1_ECHO_RETRY");
                            }
                            throw new java.util.concurrent.CompletionException(ex);
                        })
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    Map<String, Object> r2 = new HashMap<>();
                    r2.put("taskId", task.taskId);
                    r2.put("executionId", task.executionId);
                    r2.put("senderId", nodeId);
                    r2.put("paillierPublicKey", CggmpCodecUtils.encodePaillierPublicKey(ctx.paillier.getPublicKeyInfo()));
                    r2.put("hatN", task.hatN.toString(16));
                    r2.put("s", task.s.toString(16));
                    r2.put("t", task.t.toString(16));
                    r2.put("prmProof", CggmpCodecUtils.encodePiPrmProof(ctx.prmProof));
                    r2.put("rho", HexUtils.bytesToHex(ctx.rho));
                    r2.put("u", HexUtils.bytesToHex(ctx.u));
                    fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R2, r2)),
                            "CGGMP_AUX_R2");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForLatchAsync(task, task.revealLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R2")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    byte[] rho = xorAuxRho(task);
                    byte[] modCtx = buildAuxContext(task.taskId, task.executionId, nodeId, "MOD", rho);
                    long modProofStart = System.nanoTime();
                    BiPrimeBlumProof modProof = new BiPrimeProofGenerator().createProof(ctx.paillier.getPrivateKeyInfo(), modCtx);
                    logger.debug("AUX mod proof generated in {} ms", (System.nanoTime() - modProofStart) / 1_000_000);
                    Map<String, Object> facProofs = new HashMap<>();
                    for (int peerId : task.participants) {
                        if (peerId == nodeId) continue;
                        BigInteger hatN = task.peerHatN.get(peerId);
                        BigInteger s = task.peerS.get(peerId);
                        BigInteger t = task.peerT.get(peerId);
                        if (hatN == null || s == null || t == null) {
                            continue;
                        }
                        ZKSetup zk = new ZKSetup(hatN, s, t);
                        long facStart = System.nanoTime();
                        NoSmallFactorProof facProof = new NoSmallFactorProofGenerator(zk).createProof(ctx.paillier.getPrivateKeyInfo(), modCtx);
                        logger.debug("AUX fac proof generated for peer {} in {} ms", peerId, (System.nanoTime() - facStart) / 1_000_000);
                        facProofs.put(String.valueOf(peerId), CggmpCodecUtils.encodeNoSmallFactorProof(facProof));
                    }
                    Map<String, Object> r3 = new HashMap<>();
                    r3.put("taskId", task.taskId);
                    r3.put("executionId", task.executionId);
                    r3.put("senderId", nodeId);
                    r3.put("modProof", CggmpCodecUtils.encodeBiPrimeProof(modProof));
                    r3.put("facProofs", facProofs);
                    fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_AUX_R3, r3)),
                            "CGGMP_AUX_R3");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForLatchAsync(task, task.proofLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R3")
                        .thenApply(v -> ctx))
                .thenRunAsync(() -> {
                    saveAuxInfo(task);
                    logger.debug("AUX protocol completed in {} ms", (System.nanoTime() - auxStartNs) / 1_000_000);
                }, auxExecutorService);
    }

    private static class AuxContext {
        final CggmpAuxTask task;
        final PaillierEncryption paillier;
        final PiPrmProof prmProof;
        final byte[] rho;
        final byte[] u;

        AuxContext(CggmpAuxTask task, PaillierEncryption paillier, PiPrmProof prmProof, byte[] rho, byte[] u) {
            this.task = task;
            this.paillier = paillier;
            this.prmProof = prmProof;
            this.rho = rho;
            this.u = u;
        }
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        switch (message.type) {
            case CGGMP_AUX_INIT:
                handleCggmpAuxInit(senderId, message.data);
                break;
            case CGGMP_AUX_R1:
                handleCggmpAuxR1(senderId, message.data);
                break;
            case CGGMP_AUX_R1_ECHO:
                handleCggmpAuxR1Echo(senderId, message.data);
                break;
            case CGGMP_AUX_R2:
                handleCggmpAuxR2(senderId, message.data);
                break;
            case CGGMP_AUX_R3:
                handleCggmpAuxR3(senderId, message.data);
                break;
            case CGGMP_AUX_STATUS:
                handleCggmpAuxStatus(senderId, message.data);
                break;
            default:
                break;
        }
        return CompletableFuture.completedFuture(null);
    }

    private void handleCggmpAuxInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object initiatorValue = dataMap.get("initiatorId");
        Object participantsValue = dataMap.get("participants");
        if (taskId == null || executionId == null || initiatorValue == null || !(participantsValue instanceof List<?> list)) {
            return;
        }
        int initiatorId = initiatorValue instanceof Number n ? n.intValue() : senderId;
        Set<Integer> participants = new LinkedHashSet<>();
        for (Object o : list) {
            if (o instanceof Number n) {
                participants.add(n.intValue());
            }
        }
        logger.debug("AUX INIT received: taskId={}, executionId={}, initiatorId={}, senderId={}, participants={}",
                taskId, executionId, initiatorId, senderId, participants);
        if (participants.isEmpty()) {
            return;
        }
        if (!participants.contains(nodeId)) {
            return;
        }
        CggmpAuxTask task = auxTasks.computeIfAbsent(taskId, id -> new CggmpAuxTask(taskId, executionId, nodesCount, initiatorId, participants));
        if (!task.start()) {
            return;
        }
        drainPending(taskId);
        try {
            nodeService.waitForNetworkReady()
                    .thenRun(() -> logger.debug("AUX INIT network ready: taskId={}, executionId={}",
                            task.taskId, task.executionId))
                    .thenCompose(v -> runAuxProtocolAsync(task))
                    .whenComplete((v, ex) -> {
                        if (ex == null) {
                            task.complete();
                        } else {
                            task.fail(ex.getMessage());
                            logger.error("Error in CGGMP AUX process", ex);
                        }
                    });
            return;
        } catch (Exception e) {
            task.fail(e.getMessage());
            logger.error("Error in CGGMP AUX process", e);
        }
    }

    private void handleCggmpAuxR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object senderValue = dataMap.get("senderId");
        String vCommit = (String) dataMap.get("V");
        if (taskId == null || senderValue == null || vCommit == null) {
            return;
        }
        int senderIdVal = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R1));
            return;
        }
        task.commitHashes.put(senderIdVal, vCommit);
        task.commitLatch.countDown();
    }

    private void handleCggmpAuxR1Echo(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        String hash = (String) dataMap.get("hash");
        if (taskId == null || executionId == null || senderValue == null || hash == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R1_ECHO));
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String expected = computeAuxEchoHash(task);
        if (expected == null) {
            task.pendingEcho.put(senderNodeId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            logger.warn("AUX echo mismatch from node {} (task {}): expected={}, received={}",
                    senderNodeId, taskId, expected, hash);
            task.fail("AUX echo mismatch");
            task.errorMessage = "AUX echo mismatch from node " + senderNodeId + " expected=" + expected + " received=" + hash;
            return;
        }
        task.echoReceived.put(senderNodeId, Boolean.TRUE);
        task.echoLatch.countDown();
    }

    private void handleCggmpAuxR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object senderValue = dataMap.get("senderId");
        Object pkObj = dataMap.get("paillierPublicKey");
        String hatNStr = (String) dataMap.get("hatN");
        String sStr = (String) dataMap.get("s");
        String tStr = (String) dataMap.get("t");
        if (taskId == null || senderValue == null || pkObj == null || hatNStr == null || sStr == null || tStr == null) {
            return;
        }
        int senderIdVal = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R2));
            return;
        }
        if (pkObj instanceof Map<?, ?> pkMap) {
            task.peerPaillierKeys.put(senderIdVal, CggmpCodecUtils.decodePaillierPublicKey(pkMap));
        }
        Object prmObj = dataMap.get("prmProof");
        if (prmObj instanceof Map<?, ?> prmMap) {
            task.peerPrmProofs.put(senderIdVal, CggmpCodecUtils.decodePiPrmProof(prmMap));
        }
        task.peerHatN.put(senderIdVal, new BigInteger(hatNStr, 16));
        task.peerS.put(senderIdVal, new BigInteger(sStr, 16));
        task.peerT.put(senderIdVal, new BigInteger(tStr, 16));
        task.revealLatch.countDown();
    }

    private void handleCggmpAuxR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        Map<?, ?> modMap = (Map<?, ?>) dataMap.get("modProof");
        Map<?, ?> facMap = (Map<?, ?>) dataMap.get("facProofs");
        if (taskId == null || executionId == null || senderValue == null || modMap == null || facMap == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        CggmpAuxTask task = auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R3));
            return;
        }
        if (!executionId.equals(task.executionId)) {
            logger.warn("AUX R3 ignored: executionId mismatch (taskId={}, senderId={}, expected={}, got={})",
                    taskId, senderNodeId, task.executionId, executionId);
            return;
        }
        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderNodeId);
        if (pk == null) {
            logger.warn("AUX R3 ignored: missing peer Paillier key (taskId={}, senderId={}, peers={})",
                    taskId, senderNodeId, task.peerPaillierKeys.keySet());
            return;
        }
        BiPrimeBlumProof modProof = CggmpCodecUtils.decodeBiPrimeProof(modMap);
        byte[] rho = xorAuxRho(task);
        byte[] modCtx = buildAuxContext(taskId, task.executionId, senderNodeId, "MOD", rho);
        if (!BI_PRIME_VALIDATOR.verifyProof(modProof, pk, modCtx)) {
            logger.warn("AUX R3 invalid mod proof (taskId={}, senderId={})", taskId, senderNodeId);
            task.fail("Invalid AUX mod proof");
            return;
        }
        Object facForMe = facMap.get(String.valueOf(nodeId));
        if (!(facForMe instanceof Map<?, ?> facProofMap)) {
            logger.warn("AUX R3 missing fac proof for node {} (taskId={}, senderId={})", nodeId, taskId, senderNodeId);
            task.fail("Missing AUX fac proof");
            return;
        }
        BigInteger hatN = task.hatN;
        BigInteger s = task.s;
        BigInteger t = task.t;
        NoSmallFactorProof facProof = CggmpCodecUtils.decodeNoSmallFactorProof(facProofMap);
        ZKSetup zk = new ZKSetup(hatN, s, t);
        NoSmallFactorProofValidator facValidator = new NoSmallFactorProofValidator(zk, auxMinPaillierBitsForProof);
        NoSmallFactorProofValidator.ProofCheckResult facResult = facValidator.verifyProofDetailed(facProof, pk, modCtx);
        if (!facResult.ok()) {
            logger.warn("AUX R3 invalid fac proof (taskId={}, senderId={}, reason={})",
                    taskId, senderNodeId, facResult.reason());
            task.fail("Invalid AUX fac proof");
            return;
        }
        task.peerModProofs.put(senderNodeId, modProof);
        task.peerFacProofs.put(senderNodeId, facProof);
        task.proofLatch.countDown();
    }

    private void handleCggmpAuxStatus(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        Object hasAuxValue = dataMap.get("hasAux");
        if (hasAuxValue == null) {
            return;
        }
        boolean hasAux = Boolean.TRUE.equals(hasAuxValue);
        long ts = System.currentTimeMillis();
        Object tsValue = dataMap.get("ts");
        if (tsValue instanceof Number n) {
            ts = n.longValue();
        }
        auxStatus.put(senderId, new AuxStatus(hasAux, ts));
    }

    private void enqueuePending(String taskId, PendingMsg msg) {
        if (taskId == null) return;
        pendingAuxMessages.computeIfAbsent(taskId, id -> new java.util.concurrent.ConcurrentLinkedQueue<>()).add(msg);
    }

    private void drainPending(String taskId) {
        java.util.concurrent.ConcurrentLinkedQueue<PendingMsg> q = pendingAuxMessages.get(taskId);
        if (q == null || q.isEmpty()) {
            return;
        }
        PendingMsg msg;
        while ((msg = q.poll()) != null) {
            switch (msg.type) {
                case CGGMP_AUX_R1 -> handleCggmpAuxR1(msg.senderId, msg.data);
                case CGGMP_AUX_R1_ECHO -> handleCggmpAuxR1Echo(msg.senderId, msg.data);
                case CGGMP_AUX_R2 -> handleCggmpAuxR2(msg.senderId, msg.data);
                case CGGMP_AUX_R3 -> handleCggmpAuxR3(msg.senderId, msg.data);
                default -> {
                }
            }
        }
        pendingAuxMessages.remove(taskId, q);
    }

    private void saveAuxInfo(CggmpAuxTask task) {
        try {
            AuxInfo info = new AuxInfo(nodeId, task.taskId);
            PaillierEncryption.PrivateKey priv = task.paillier.getPrivateKeyInfo();
            info.setPaillierP(priv.p.toString(16));
            info.setPaillierQ(priv.q.toString(16));
            info.setPaillierN(priv.n.toString(16));
            info.setPaillierG(task.paillier.getPublicKeyInfo().g.toString(16));
            info.setPaillierBitLength(task.paillier.getPublicKeyInfo().bitLength);
            info.setPedersenHatN(task.hatN.toString(16));
            info.setPedersenS(task.s.toString(16));
            info.setPedersenT(task.t.toString(16));
            boolean inserted = auxInfoDao.saveIfAbsentByTask(info);
            auxPaillier = task.paillier;
            auxHatN = task.hatN;
            auxS = task.s;
            auxT = task.t;
            if (inserted) {
                logger.info("Saved CGGMP AUX info for task: {}", task.taskId);
            } else {
                logger.info("CGGMP AUX info already persisted for task: {}", task.taskId);
            }
        } catch (Exception e) {
            logger.error("Failed to save CGGMP AUX info", e);
            throw new RuntimeException(e);
        }
    }

    private static byte[] buildAuxContext(String taskId, String executionId, int senderId, String label) {
        String sid = buildSid(executionId, taskId);
        String base = "AUX:" + label + ":" + sid + ":" + senderId + ":";
        return base.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] buildAuxContext(String taskId, String executionId, int senderId, String label, byte[] rho) {
        byte[] prefix = buildAuxContext(taskId, executionId, senderId, label);
        if (rho == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rho.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rho, 0, out, prefix.length, rho.length);
        return out;
    }

    private static String buildSid(String executionId, String taskId) {
        return "CGGMP24:" + executionId + ":" + taskId;
    }

    private static String computeAuxEchoHash(CggmpAuxTask task) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(task.executionId.getBytes(StandardCharsets.UTF_8));
            md.update(task.taskId.getBytes(StandardCharsets.UTF_8));
            for (Map.Entry<Integer, String> e : task.commitHashes.entrySet()) {
                md.update(String.valueOf(e.getKey()).getBytes(StandardCharsets.UTF_8));
                md.update(e.getValue().getBytes(StandardCharsets.UTF_8));
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            logger.error("Failed to compute AUX echo hash", e);
            return null;
        }
    }

    private byte[] xorAuxRho(CggmpAuxTask task) {
        byte[] result = new byte[32];
        byte[] myRho = task.rho.get(nodeId);
        if (myRho == null) {
            return result;
        }
        System.arraycopy(myRho, 0, result, 0, 32);
        for (byte[] rho : task.rho.values()) {
            for (int i = 0; i < 32; i++) {
                result[i] ^= rho[i];
            }
        }
        return result;
    }

    private static String computeAuxCommitHash(String executionId, String taskId, int senderId,
                                               Map<String, Object> pkMap, String hatN, String s, String t,
                                               Map<String, Object> prmMap, byte[] rho, byte[] u) {
        String sid = buildSid(executionId, taskId);
        return computeTaggedHashHex("AUX_HASH_COM", sid, senderId, pkMap, hatN, s, t, prmMap, rho, u);
    }

    private static String computeTaggedHashHex(String tag, String sid, int senderId,
                                              Map<String, Object> pkMap, String hatN, String s, String t,
                                              Map<String, Object> prmMap, byte[] rho, byte[] u) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(StandardCharsets.UTF_8));
            md.update(sid.getBytes(StandardCharsets.UTF_8));
            md.update(String.valueOf(senderId).getBytes(StandardCharsets.UTF_8));
            for (Map.Entry<String, Object> e : pkMap.entrySet()) {
                md.update(e.getKey().getBytes(StandardCharsets.UTF_8));
                md.update(String.valueOf(e.getValue()).getBytes(StandardCharsets.UTF_8));
            }
            md.update(hatN.getBytes(StandardCharsets.UTF_8));
            md.update(s.getBytes(StandardCharsets.UTF_8));
            md.update(t.getBytes(StandardCharsets.UTF_8));
            for (Map.Entry<String, Object> e : prmMap.entrySet()) {
                md.update(e.getKey().getBytes(StandardCharsets.UTF_8));
                md.update(String.valueOf(e.getValue()).getBytes(StandardCharsets.UTF_8));
            }
            md.update(rho);
            md.update(u);
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute AUX commit hash", e);
        }
    }
}
