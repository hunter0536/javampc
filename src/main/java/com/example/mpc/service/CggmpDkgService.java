package com.example.mpc.service;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CggmpDkgCodec;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.PedersenCommitment;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.AuxInfo;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.model.KeyShare;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class CggmpDkgService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpDkgService.class);
    private static final BiPrimeProofValidator BI_PRIME_VALIDATOR = new BiPrimeProofValidator();
    private static final ExecutorService dkgExecutorService = ThreadPoolUtil.getComputationThreadPool();

    private final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Autowired
    private AuxInfoDao auxInfoDao;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.cggmp.hdEnabled:false}")
    private boolean hdEnabled;

    @Value("${mpc.dkg.echoEnabled:true}")
    private boolean dkgEchoEnabled;

    @Value("${mpc.dkg.useRbc:true}")
    private boolean dkgUseRbc;

    @Value("${app.cggmp.aux.minPaillierBitsForProof:2048}")
    private int auxMinPaillierBitsForProof;

    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;

    private final ScheduledExecutorService dkgScheduler = Executors.newSingleThreadScheduledExecutor();

    private final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, Map<String, Object>>> pendingRound1ByTask =
            new ConcurrentHashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_DKG_INIT,
                            MessageType.CGGMP_DKG_ROUND1,
                            MessageType.CGGMP_DKG_ROUND1_ECHO,
                            MessageType.CGGMP_DKG_ROUND2,
                            MessageType.CGGMP_DKG_ROUND2_BROAD,
                            MessageType.CGGMP_DKG_ROUND2_BATCH,
                            MessageType.CGGMP_DKG_ROUND3,
                            MessageType.CGGMP_DKG_COMPLAINT,
                            MessageType.CGGMP_DKG_EXCLUDE
                    ), this);
                    logger.info("CGGMP DKG service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP DKG service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        String executionId = UUID.randomUUID().toString();
        CggmpDkgTask task = createDkgTaskInternal(taskId, executionId, nodesCount, threshold, null, nodeId);
        dkgTasks.put(taskId, task);
        drainPendingRound1(task);
        logger.info("Created CGGMP DKG task: {}", taskId);
        return taskId;
    }

    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return startDkgProcessInternal(taskId, true);
    }

    private CompletableFuture<Void> startDkgProcessInternal(String taskId, boolean broadcastInit) {
        logger.info("=================== startDkgProcess START: taskId={} ===================", taskId);
        final long dkgStartNs = System.nanoTime();
        final CggmpDkgTask task;
        try {
            task = getDkgTask(taskId);
            if (!nodeService.isTlsEnabled()) {
                throw new RuntimeException("DKG requires TLS-enabled private channels (nodes.ssl.enabled=true).");
            }
            if (loadLatestAuxInfo(nodeId) == null) {
                throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before DKG.");
            }
            if (!task.start()) {
                logger.warn("DKG task {} failed to start (may already be in progress), skipping", taskId);
                return CompletableFuture.completedFuture(null);
            }
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }

        logger.info("Starting CGGMP DKG process for task: {}", taskId);
        logger.info("Waiting for network ready...");
        long waitNetStart = System.nanoTime();

        Map<String, Object> initData = new HashMap<>();
        initData.put("taskId", taskId);
        initData.put("executionId", task.executionId);
        initData.put("nodesCount", Constants.NODES_COUNT);
        initData.put("initiatorId", nodeId);
        initData.put("participants", new ArrayList<>(task.participants));

        CompletableFuture<Void> flow = nodeService.waitForNetworkReady()
                .thenRun(() -> logger.debug("DKG waitForNetworkReady took {} ms", (System.nanoTime() - waitNetStart) / 1_000_000))
                .thenRun(() -> {
                    int networkSize = nodeService.getNodes().size() + 1;
                    if (networkSize < nodesCount) {
                        throw new RuntimeException("Not enough nodes in network. Expected: " + nodesCount + ", found: " + networkSize);
                    }
                    logger.info("Network ready with {} nodes", networkSize);
                })
                .thenCompose(v -> ensureLocalAuxReady())
                .thenCompose(v -> {
                    if (!broadcastInit) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return delayMs(Constants.DKG_INIT_WAIT_MS)
                            .thenCompose(x -> retryAsync(
                                    () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_INIT, initData)),
                                    Constants.DKG_BROADCAST_RETRY_COUNT,
                                    Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                                    "Broadcast CGGMP_DKG_INIT"));
                })
                .thenCompose(v -> {
                    long roundsStart = System.nanoTime();
                    return executeDkgRounds(task)
                            .whenComplete((x, ex) -> logger.debug("DKG executeDkgRounds took {} ms",
                                    (System.nanoTime() - roundsStart) / 1_000_000));
                });

        return flow.whenComplete((v, ex) -> {
            if (ex == null) {
                task.complete();
                logger.info("CGGMP DKG process completed for task: {}", taskId);
                logger.debug("=================== startDkgProcess END: taskId={} total {} ms ===================",
                        taskId, (System.nanoTime() - dkgStartNs) / 1_000_000);
            } else {
                task.fail();
                task.errorMessage = ex.getMessage();
                logger.error("Error in CGGMP DKG process", ex);
            }
        });
    }

    private CompletableFuture<Void> executeDkgRounds(CggmpDkgTask task) {
        final long roundsStart = System.nanoTime();
        if (task.nonThreshold) {
            return executeDkgRoundsNonThreshold(task)
                    .whenComplete((v, ex) -> logger.debug("DKG executeDkgRounds total took {} ms",
                            (System.nanoTime() - roundsStart) / 1_000_000));
        }
        logger.info("Node {} executing CGGMP24 DKG Round 1 (t-of-n)", nodeId);

        CompletableFuture<DkgContext> r1Future = CompletableFuture.supplyAsync(() -> {
            BigInteger q = Secp256k1Curve.n();
            ECPoint g = Secp256k1Curve.G();

            BigInteger[] coeffs = new BigInteger[threshold];
            for (int i = 0; i < threshold; i++) {
                coeffs[i] = randomScalar(q);
            }

            Map<Integer, ECPoint> S_i = new HashMap<>();
            for (int k = 0; k < threshold; k++) {
                S_i.put(k, g.multiply(coeffs[k]).normalize());
            }
            task.Xjks.put(nodeId, new ConcurrentHashMap<>(S_i));

            BigInteger alpha = randomScalar(q);
            ECPoint A_i = g.multiply(alpha).normalize();
            task.Ajks.put(nodeId, new ConcurrentHashMap<>(Map.of(0, A_i)));
            task.schAlphas.put(0, alpha);

            byte[] ridPart = new byte[32];
            secureRandom.nextBytes(ridPart);
            task.ridParts.put(nodeId, ridPart);
            byte[] chainCodePart = hdEnabled ? randomBytes(32) : null;
            if (chainCodePart != null) {
                task.chainCodeParts.put(nodeId, chainCodePart);
            }

            Map<String, Object> r1Open = new LinkedHashMap<>();
            r1Open.put("taskId", task.taskId);
            r1Open.put("executionId", task.executionId);
            r1Open.put("senderId", nodeId);
            r1Open.put("ridPart", HexUtils.bytesToHex(ridPart));
            r1Open.put("S", encodePointMapCompressed(S_i));
            r1Open.put("A", HexUtils.bytesToHex(A_i.getEncoded(true)));
            byte[] uCommit = randomBytes(32);
            r1Open.put("u", HexUtils.bytesToHex(uCommit));
            if (chainCodePart != null) {
                r1Open.put("c", HexUtils.bytesToHex(chainCodePart));
            }
            String vCommit = computeDkgCommitHash(task.executionId, task.taskId, nodeId, ridPart, S_i, A_i, uCommit, chainCodePart);
            task.round1PayloadHashes.put(nodeId, vCommit);
            Map<String, Object> r1Commit = new HashMap<>();
            r1Commit.put("taskId", task.taskId);
            r1Commit.put("executionId", task.executionId);
            r1Commit.put("senderId", nodeId);
            r1Commit.put("V", vCommit);
            if (dkgUseRbc) {
                fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        "CGGMP_DKG_ROUND1_RBC");
            } else {
                fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        "CGGMP_DKG_ROUND1");
            }

            task.startRound1Waiting();
            return new DkgContext(task, q, g, coeffs, r1Open);
        }, dkgExecutorService);

        return r1Future
                .thenCompose(ctx -> waitForDkgLatch(task, task.round1ReceivedLatch, "DKG Round 1 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    if (!dkgEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    fireAndForget(broadcastDkgRound1Echo(task), "CGGMP_DKG_ROUND1_ECHO");
                    return waitForDkgLatch(task, task.round1EchoReceivedLatch, "DKG Round 1 echo messages")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (dkgUseRbc) {
                        fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                "CGGMP_DKG_ROUND2_BROAD_RBC");
                    } else {
                        fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                "CGGMP_DKG_ROUND2_BROAD");
                    }

                    for (int peerId : task.participants) {
                        if (peerId == nodeId) continue;
                        BigInteger sigma = evaluatePolynomial(ctx.coeffs, getIndexValue(task, peerId), ctx.q);
                        Map<String, Object> share = new HashMap<>();
                        share.put("taskId", task.taskId);
                        share.put("executionId", task.executionId);
                        share.put("senderId", nodeId);
                        share.put("receiverId", peerId);
                        share.put("sigma", sigma.toString(16));
                        fireAndForget(nodeService.sendMessage(peerId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2, share)),
                                "CGGMP_DKG_ROUND2");
                    }
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2OpenReceivedLatch, "DKG Round 2 open messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (hdEnabled) {
                        task.chainCode = xorChainCodeParts(task);
                    }
                    task.rid = xorRidParts(task);
                    validatePendingRound3(task);
                    task.startRound2Waiting();
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2ReceivedLatch, "DKG Round 2 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    task.startValidating();
                    BigInteger xStar = BigInteger.ZERO;
                    for (int peerId : task.participants) {
                        BigInteger share = peerId == nodeId
                                ? evaluatePolynomial(ctx.coeffs, getIndexValue(task, nodeId), ctx.q)
                                : task.xji.getOrDefault(peerId, new ConcurrentHashMap<>()).get(nodeId);
                        if (share == null) {
                            throw new RuntimeException("Missing share from peer " + peerId);
                        }
                        xStar = xStar.add(share).mod(ctx.q);
                    }
                    task.secretShare = xStar;

                    ECPoint X_i = computePublicShare(task, nodeId);
                    PiSchProof psi_i = createSchProofWithAlpha(ctx.g, X_i, xStar, task.schAlphas.get(0),
                            buildDkgContext(task.taskId, task.executionId, task.rid, nodeId, "SCH"));
                    Map<String, Object> r3 = new HashMap<>();
                    r3.put("taskId", task.taskId);
                    r3.put("executionId", task.executionId);
                    r3.put("senderId", nodeId);
                    r3.put("psi", encodeSchProof(psi_i));
                    fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND3, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND3, r3))),
                            "CGGMP_DKG_ROUND3");
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round3ReceivedLatch, "DKG Round 3 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    ECPoint groupPublicKey = ctx.g.getCurve().getInfinity();
                    for (int peerId : task.participants) {
                        Map<Integer, ECPoint> sVec = task.Xjks.get(peerId);
                        if (sVec == null || sVec.get(0) == null) {
                            throw new RuntimeException("Missing S_{j,0} from peer " + peerId);
                        }
                        groupPublicKey = groupPublicKey.add(sVec.get(0)).normalize();
                    }
                    task.groupPublicKey = groupPublicKey;
                    task.groupPublicKeyHex = HexUtils.bytesToHex(groupPublicKey.getEncoded(false));

                    saveKeyShareToDatabase(task);
                    task.complete();
                    logger.info("CGGMP24 DKG completed! Group public key: {}", task.groupPublicKeyHex);
                }, dkgExecutorService))
                .whenComplete((v, ex) -> logger.debug("DKG executeDkgRounds total took {} ms",
                        (System.nanoTime() - roundsStart) / 1_000_000));
    }

    private CompletableFuture<Void> executeDkgRoundsNonThreshold(CggmpDkgTask task) {
        logger.info("Node {} executing CGGMP24 DKG Round 1 (n-of-n)", nodeId);
        return CompletableFuture.supplyAsync(() -> {
            BigInteger q = Secp256k1Curve.n();
            ECPoint g = Secp256k1Curve.G();

            BigInteger x_i = randomScalar(q);
            ECPoint X_i = g.multiply(x_i).normalize();
            Map<Integer, ECPoint> S_i = new HashMap<>();
            S_i.put(0, X_i);
            task.Xjks.put(nodeId, new ConcurrentHashMap<>(S_i));

            BigInteger alpha = randomScalar(q);
            ECPoint A_i = g.multiply(alpha).normalize();
            task.Ajks.put(nodeId, new ConcurrentHashMap<>(Map.of(0, A_i)));
            task.schAlphas.put(0, alpha);

            byte[] ridPart = new byte[32];
            secureRandom.nextBytes(ridPart);
            task.ridParts.put(nodeId, ridPart);
            byte[] chainCodePart = hdEnabled ? randomBytes(32) : null;
            if (chainCodePart != null) {
                task.chainCodeParts.put(nodeId, chainCodePart);
            }

            byte[] uCommit = randomBytes(32);
            Map<String, Object> r1Open = new LinkedHashMap<>();
            r1Open.put("taskId", task.taskId);
            r1Open.put("executionId", task.executionId);
            r1Open.put("senderId", nodeId);
            r1Open.put("ridPart", HexUtils.bytesToHex(ridPart));
            r1Open.put("S", encodePointMapCompressed(S_i));
            r1Open.put("A", HexUtils.bytesToHex(A_i.getEncoded(true)));
            r1Open.put("u", HexUtils.bytesToHex(uCommit));
            if (chainCodePart != null) {
                r1Open.put("c", HexUtils.bytesToHex(chainCodePart));
            }
            String vCommit = computeDkgCommitHash(task.executionId, task.taskId, nodeId, ridPart, S_i, A_i, uCommit, chainCodePart);
            task.round1PayloadHashes.put(nodeId, vCommit);
            Map<String, Object> r1Commit = new HashMap<>();
            r1Commit.put("taskId", task.taskId);
            r1Commit.put("executionId", task.executionId);
            r1Commit.put("senderId", nodeId);
            r1Commit.put("V", vCommit);
            if (dkgUseRbc) {
                fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        "CGGMP_DKG_ROUND1_RBC");
            } else {
                fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        "CGGMP_DKG_ROUND1");
            }

            task.startRound1Waiting();
            return new DkgNonThresholdContext(task, q, g, x_i, X_i, r1Open);
        }, dkgExecutorService)
                .thenCompose(ctx -> waitForDkgLatch(task, task.round1ReceivedLatch, "DKG Round 1 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    if (!dkgEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    fireAndForget(broadcastDkgRound1Echo(task), "CGGMP_DKG_ROUND1_ECHO");
                    return waitForDkgLatch(task, task.round1EchoReceivedLatch, "DKG Round 1 echo messages")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (dkgUseRbc) {
                        fireAndForget(nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                "CGGMP_DKG_ROUND2_BROAD_RBC");
                    } else {
                        fireAndForget(nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                "CGGMP_DKG_ROUND2_BROAD");
                    }
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2OpenReceivedLatch, "DKG Round 2 open messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (hdEnabled) {
                        task.chainCode = xorChainCodeParts(task);
                    }
                    task.rid = xorRidParts(task);
                    validatePendingRound3(task);
                    task.startRound2Waiting();
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round3ReceivedLatch, "DKG Round 3 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    ECPoint groupPublicKey = ctx.g.getCurve().getInfinity();
                    for (int peerId : task.participants) {
                        Map<Integer, ECPoint> sVec = task.Xjks.get(peerId);
                        if (sVec == null || sVec.get(0) == null) {
                            throw new RuntimeException("Missing S_{j,0} from peer " + peerId);
                        }
                        groupPublicKey = groupPublicKey.add(sVec.get(0)).normalize();
                    }
                    task.groupPublicKey = groupPublicKey;
                    task.groupPublicKeyHex = HexUtils.bytesToHex(groupPublicKey.getEncoded(false));

                    saveKeyShareToDatabase(task);
                    task.complete();
                    logger.info("CGGMP24 DKG (n-of-n) completed! Group public key: {}", task.groupPublicKeyHex);
                }, dkgExecutorService));
    }

    private Map<String, Object> buildDkgRound1Payload(CggmpDkgTask task,
                                                      CGGMP.DkgRound1Output round1Output,
                                                      Map<Integer, ECPoint> Xjk,
                                                      Map<Integer, ECPoint> Ajk,
                                                      PiPrmProof prmProof,
                                                      byte[] ridPart) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", task.executionId);
        data.put("nodeId", round1Output.nodeId);
        data.put("Xjk", encodePointMapCompressed(Xjk));
        data.put("Ajk", encodePointMapCompressed(Ajk));
        data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(round1Output.paillierKey));
        data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(round1Output.zkSetup));
        data.put("biPrimeProof", CggmpDkgCodec.encodeBiPrimeProof(round1Output.biPrimeProof));
        data.put("factorProof", CggmpDkgCodec.encodeNoSmallFactorProof(round1Output.factorProof));
        data.put("hatN", task.hatN.get(nodeId).toString(16));
        data.put("s", task.sValues.get(nodeId).toString(16));
        data.put("t", task.tValues.get(nodeId).toString(16));
        data.put("prmProof", CggmpDkgCodec.encodePiPrmProof(prmProof));
        data.put("ridPart", HexUtils.bytesToHex(ridPart));
        if (hdEnabled) {
            byte[] cPart = task.chainCodeParts.get(nodeId);
            if (cPart != null) {
                data.put("c", HexUtils.bytesToHex(cPart));
            }
        }
        return data;
    }

    private CompletableFuture<Void> sendDkgRound2Share(String taskId,
                                                       int receiverId,
                                                       BigInteger Cji,
                                                       ECPoint Yji) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", taskId);
        data.put("senderId", nodeId);
        data.put("receiverId", receiverId);
        data.put("C", Cji.toString(16));
        data.put("Y", HexUtils.bytesToHex(Yji.normalize().getEncoded(true)));
        return nodeService.sendMessage(receiverId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2, data));
    }

    private CompletableFuture<Void> broadcastDkgRound2Broad(Map<String, Object> data) {
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, data)));
    }

    private CompletableFuture<Void> broadcastDkgRound2Batch(Map<String, Object> baseData,
                                                            Map<String, Object> shares) {
        Map<String, Object> data = new HashMap<>(baseData);
        data.put("shares", shares);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BATCH, data));
    }

    private CompletableFuture<Void> broadcastDkgRound1Echo(CggmpDkgTask task) {
        String echo = computeDkgEchoHash(task);
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", task.executionId);
        data.put("senderId", nodeId);
        data.put("hash", echo);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1_ECHO, data));
    }

    private CompletableFuture<Void> broadcastDkgRound3(CggmpDkgTask task, Map<Integer, ECPoint> XkStar) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", task.executionId);
        data.put("senderId", nodeId);
        data.put("XkStar", encodePointMapCompressed(XkStar));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND3, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND3, data)));
    }

    public DkgTaskStatusResponse getTaskStatus(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        DkgTaskStatusResponse response = new DkgTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setGroupPublicKey(task.groupPublicKeyHex);
        response.setErrorMessage(task.errorMessage);
        response.setLastComplaintReason(task.lastComplaintReason);
        response.setLastComplaintOffenderId(task.lastComplaintOffenderId);
        response.setLastComplaintEvidence(task.lastComplaintEvidence);
        response.setReceivedRound1(task.round1Received.size());
        response.setReceivedRound2(task.round2Received.size());
        return response;
    }

    public String getGroupPublicKey(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        if (!task.isCompleted()) {
            return null;
        }
        return task.groupPublicKeyHex;
    }

    private void handleCggmpDkgInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            String executionId = (String) dataMap.get("executionId");
            int nodesCount = (Integer) dataMap.get("nodesCount");
            Integer initiatorId = dataMap.get("initiatorId") instanceof Number n ? n.intValue() : senderId;
            Set<Integer> participants = null;
            if (dataMap.get("participants") instanceof java.util.Collection<?> coll) {
                java.util.LinkedHashSet<Integer> p = new java.util.LinkedHashSet<>();
                for (Object o : coll) {
                    if (o instanceof Number n) {
                        p.add(n.intValue());
                    }
                }
                if (!p.isEmpty()) {
                    participants = p;
                }
            }
            logger.info("Received CGGMP_DKG_INIT from node {} for task: {}, nodesCount: {}, initiatorId={}, participants={}",
                    senderId, taskId, nodesCount, initiatorId, participants == null ? "default" : participants.size());

            if (executionId == null || executionId.isBlank()) {
                throw new RuntimeException("Missing executionId");
            }
            CggmpDkgTask task = createDkgTaskInternal(taskId, executionId, nodesCount, threshold, participants, initiatorId);
            CggmpDkgTask existingTask = dkgTasks.putIfAbsent(taskId, task);

            if (existingTask != null) {
                logger.info("DKG task {} already exists, skipping creation", taskId);
                drainPendingRound1(existingTask);
                return;
            }

            logger.info("Created DKG task {} on node {}", taskId, nodeId);
            drainPendingRound1(task);

            startDkgProcessInternal(taskId, false);
        }
    }

    private CggmpDkgTask createDkgTaskInternal(String taskId,
                                               String executionId,
                                               int nodesCount,
                                               int threshold,
                                               Set<Integer> participants,
                                               int initiatorId) {
        CggmpDkgTask task = new CggmpDkgTask(taskId, executionId, nodesCount, threshold, participants, initiatorId);
        task.evalPowers = precomputeEvalPowers(getIndexValue(task, nodeId), threshold);
        return task;
    }

    private void handleCggmpDkgRound1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        String vCommit = (String) dataMap.get("V");
        if (taskId == null || executionId == null || senderValue == null || vCommit == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            cachePendingRound1(taskId, senderNodeId, dataMap);
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        if (task.round1Received.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round1PayloadHashes.put(senderNodeId, vCommit);
            task.round1ReceivedLatch.countDown();
        }
        Map<String, Object> pendingOpen = task.pendingRound2Open.remove(senderNodeId);
        if (pendingOpen != null) {
            processDkgRound2Open(task, senderNodeId, pendingOpen);
        }
        if (task.round1PayloadHashes.size() >= task.participants.size()) {
            if (dkgEchoEnabled) {
                validatePendingRound1Echoes(task);
            }
        }
    }

    private void handleCggmpDkgRound2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        Object receiverValue = dataMap.get("receiverId");
        String sigmaHex = (String) dataMap.get("sigma");
        if (taskId == null || executionId == null || senderValue == null || receiverValue == null || sigmaHex == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        int receiverId = ((Number) receiverValue).intValue();
        if (senderNodeId != senderId || receiverId != nodeId || senderNodeId == nodeId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        if (task.nonThreshold) {
            return;
        }
        if (task.nonThreshold) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            return;
        }
        Map<Integer, ECPoint> S = task.Xjks.get(senderNodeId);
        if (S == null || S.size() != threshold) {
            task.pendingRound2Shares.put(senderNodeId, Map.of("sigma", sigmaHex));
            return;
        }
        if (!verifyDkgShare(S, getIndexValue(task, receiverId), new BigInteger(sigmaHex, 16))) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("receiverId", receiverId);
            evidence.put("sigma", sigmaHex);
            evidence.put("S", encodePointMapCompressed(S));
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid share in DKG Round2", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid share from node " + senderNodeId;
            task.lastComplaintReason = "Invalid share in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.xji.computeIfAbsent(senderNodeId, k -> new ConcurrentHashMap<>()).put(nodeId, new BigInteger(sigmaHex, 16));
        task.round2Received.put(senderNodeId, Boolean.TRUE);
        task.round2ReceivedLatch.countDown();
    }

    private void handleCggmpDkgRound2Broad(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        if (taskId == null || executionId == null || senderValue == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String ridPartHex = (String) dataMap.get("ridPart");
        Map<?, ?> sMap = (Map<?, ?>) dataMap.get("S");
        String aHex = (String) dataMap.get("A");
        String uHex = (String) dataMap.get("u");
        String cHex = (String) dataMap.get("c");
        if (ridPartHex == null || sMap == null || aHex == null || uHex == null) {
            return;
        }
        Map<String, Object> open = new LinkedHashMap<>();
        open.put("taskId", taskId);
        open.put("executionId", executionId);
        open.put("senderId", senderNodeId);
        open.put("ridPart", ridPartHex);
        open.put("S", sMap);
        open.put("A", aHex);
        open.put("u", uHex);
        if (cHex != null) {
            open.put("c", cHex);
        }
        processDkgRound2Open(task, senderNodeId, open);
    }

    private void processDkgRound2Open(CggmpDkgTask task, int senderNodeId, Map<String, Object> open) {
        String taskId = (String) open.get("taskId");
        String executionId = (String) open.get("executionId");
        String ridPartHex = (String) open.get("ridPart");
        Map<?, ?> sMap = (Map<?, ?>) open.get("S");
        String aHex = (String) open.get("A");
        String uHex = (String) open.get("u");
        String cHex = (String) open.get("c");
        if (taskId == null) {
            taskId = task.taskId;
        }
        if (executionId == null) {
            executionId = task.executionId;
        }
        if (ridPartHex == null || sMap == null || aHex == null || uHex == null) {
            return;
        }
        String expected = task.round1PayloadHashes.get(senderNodeId);
        if (expected == null) {
            task.pendingRound2Open.put(senderNodeId, open);
            logger.debug("Cached DKG Round2 open from node {} for task {} (waiting for Round1 commit)", senderNodeId, taskId);
            return;
        }
        String actual = computeDkgCommitHashFromWire(executionId, taskId, senderNodeId, ridPartHex, sMap, aHex, uHex, cHex);
        if (!expected.equals(actual)) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", expected);
            evidence.put("actual", actual);
            evidence.put("ridPart", ridPartHex);
            evidence.put("A", aHex);
            evidence.put("S", sMap);
            evidence.put("u", uHex);
            if (cHex != null) {
                evidence.put("c", cHex);
            }
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Round1 commit mismatch", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Round1 commit mismatch from node " + senderNodeId
                    + " expected=" + expected + " actual=" + actual;
            task.lastComplaintReason = "Round1 commit mismatch";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (hdEnabled && (cHex == null || cHex.length() != 64)) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("c", cHex);
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid chain code part in DKG Round2", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid chain code part from node " + senderNodeId;
            task.lastComplaintReason = "Invalid chain code part in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.ridParts.put(senderNodeId, HexUtils.hexToBytes(ridPartHex));
        if (cHex != null) {
            task.chainCodeParts.put(senderNodeId, HexUtils.hexToBytes(cHex));
        }
        Map<Integer, ECPoint> S;
        ECPoint A;
        try {
            S = decodePointMap(sMap);
            A = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(aHex));
        } catch (Exception e) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("error", e.getMessage());
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid Round2 open encoding", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid Round2 open encoding from node " + senderNodeId;
            task.lastComplaintReason = "Invalid Round2 open encoding";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (!task.nonThreshold && S.size() != threshold) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", threshold);
            evidence.put("actual", S.size());
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid commitment vector size in DKG Round2", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid commitment vector size from node " + senderNodeId;
            task.lastComplaintReason = "Invalid commitment vector size in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (task.nonThreshold && S.size() != 1) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", 1);
            evidence.put("actual", S.size());
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid commitment vector size in DKG Round2", evidence),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid commitment vector size from node " + senderNodeId;
            task.lastComplaintReason = "Invalid commitment vector size in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.Xjks.put(senderNodeId, new ConcurrentHashMap<>(S));
        task.Ajks.put(senderNodeId, new ConcurrentHashMap<>(Map.of(0, A)));
        if (task.round2OpenReceived.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round2OpenReceivedLatch.countDown();
        }
        if (task.nonThreshold) {
            return;
        }
        Map<String, String> pending = task.pendingRound2Shares.remove(senderNodeId);
        if (pending != null) {
            String sigmaHex = pending.get("sigma");
            if (sigmaHex != null && verifyDkgShare(S, getIndexValue(task, nodeId), new BigInteger(sigmaHex, 16))) {
                task.xji.computeIfAbsent(senderNodeId, k -> new ConcurrentHashMap<>()).put(nodeId, new BigInteger(sigmaHex, 16));
                task.round2Received.put(senderNodeId, Boolean.TRUE);
                task.round2ReceivedLatch.countDown();
            }
        }
    }

    private void processRound2WithProofs(CggmpDkgTask task,
                                         int senderNodeId,
                                         int receiverId,
                                         String cHex,
                                         String yHex,
                                         Map<?, ?> schMap,
                                         Map<?, ?> modMap,
                                         Map<?, ?> facMap) {
        if (receiverId != nodeId) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            return;
        }
        if (task.round2Processing.putIfAbsent(senderNodeId, Boolean.TRUE) != null) {
            return;
        }

        Map<Integer, PiSchProof> schProofs = task.round2SchProofs.get(senderNodeId);
        if (schProofs == null) {
            schProofs = decodeSchProofMap(schMap);
            task.round2SchProofs.putIfAbsent(senderNodeId, schProofs);
        }
        if (schProofs.size() != threshold) {
            logger.warn("Invalid schProofs size from node {}: expected {}, got {}", senderNodeId, threshold, schProofs.size());
            task.round2Processing.remove(senderNodeId);
            return;
        }

        BiPrimeBlumProof modProof = task.round2ModProofs.get(senderNodeId);
        if (modProof == null) {
            modProof = CggmpDkgCodec.decodeBiPrimeProof(modMap);
            task.round2ModProofs.putIfAbsent(senderNodeId, modProof);
        }
        NoSmallFactorProof facProof = task.round2FacProofs.get(senderNodeId);
        if (facProof == null) {
            facProof = CggmpDkgCodec.decodeNoSmallFactorProof(facMap);
            task.round2FacProofs.putIfAbsent(senderNodeId, facProof);
        }

        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderNodeId);
        com.example.mpc.cggmp.zk.ZKSetup zk = task.peerZkSetups.get(senderNodeId);
        if (pk == null || zk == null) {
            logger.warn("Missing Paillier/ZK setup for node {}", senderNodeId);
            task.round2Processing.remove(senderNodeId);
            return;
        }
        Map<Integer, ECPoint> Xjk = task.Xjks.get(senderNodeId);
        Map<Integer, ECPoint> Ajk = task.Ajks.get(senderNodeId);
        if (Xjk == null || Ajk == null) {
            logger.warn("Missing Xjk/Ajk from node {} for task {}", senderNodeId, task.taskId);
            task.round2Processing.remove(senderNodeId);
            return;
        }

        final int senderNodeIdFinal = senderNodeId;
        final CggmpDkgTask taskFinal = task;
        final String cHexFinal = cHex;
        final String yHexFinal = yHex;
        final Map<Integer, PiSchProof> schProofsFinal = schProofs;
        final BiPrimeBlumProof modProofFinal = modProof;
        final NoSmallFactorProof facProofFinal = facProof;
        final PaillierEncryption.PublicKey pkFinal = pk;
        final com.example.mpc.cggmp.zk.ZKSetup zkFinal = zk;
        final Map<Integer, ECPoint> XjkFinal = Xjk;
        final Map<Integer, ECPoint> AjkFinal = Ajk;

        CompletableFuture<Boolean> modFacFuture;
        Boolean cached = taskFinal.modFacVerified.get(senderNodeIdFinal);
        if (cached != null) {
            modFacFuture = CompletableFuture.completedFuture(cached);
        } else if (taskFinal.round2ModFacVerifyFutures.containsKey(senderNodeIdFinal)) {
            modFacFuture = taskFinal.round2ModFacVerifyFutures.get(senderNodeIdFinal);
        } else {
            byte[] rho = HexUtils.hexToBytes(cHexFinal);
            byte[] modCtx = buildDkgContext(taskFinal.taskId, taskFinal.executionId, taskFinal.rid, senderNodeIdFinal, "MOD");
            CompletableFuture<Boolean> verifyFuture = CompletableFuture.supplyAsync(
                    () -> BI_PRIME_VALIDATOR.verifyProof(modProofFinal, pkFinal, modCtx), dkgExecutorService)
                    .thenCombine(CompletableFuture.supplyAsync(
                            () -> {
                                NoSmallFactorProofValidator facValidator = new NoSmallFactorProofValidator(zkFinal, auxMinPaillierBitsForProof);
                                return facValidator.verifyProofDetailed(facProofFinal, pkFinal, modCtx).ok();
                            }, dkgExecutorService),
                            (modOk, facOk) -> modOk && facOk);
            taskFinal.round2ModFacVerifyFutures.put(senderNodeIdFinal, verifyFuture);
            modFacFuture = verifyFuture;
        }

        modFacFuture.whenComplete((ok, ex) -> {
            if (ex != null || !Boolean.TRUE.equals(ok)) {
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("senderId", senderNodeIdFinal);
                evidence.put("modOk", ex == null ? ok : false);
                fireAndForget(broadcastDkgComplaint(taskFinal, senderNodeIdFinal, "Invalid PiMod/PiFac proof in DKG Round2", evidence),
                        "CGGMP_DKG_COMPLAINT");
                taskFinal.lastComplaintReason = "Invalid PiMod/PiFac proof in DKG Round2";
                taskFinal.lastComplaintOffenderId = senderNodeIdFinal;
                taskFinal.lastComplaintEvidence = evidence;
                taskFinal.round2Processing.remove(senderNodeIdFinal);
                return;
            }

            verifySchProofsParallelAsync(taskFinal, senderNodeIdFinal, schProofsFinal, XjkFinal, AjkFinal)
                    .whenComplete((schOk, schEx) -> {
                        if (schEx != null || !Boolean.TRUE.equals(schOk)) {
                            Map<String, Object> evidence = new HashMap<>();
                            evidence.put("senderId", senderNodeIdFinal);
                            fireAndForget(broadcastDkgComplaint(taskFinal, senderNodeIdFinal, "Invalid PiSch proof in DKG Round2", evidence),
                                    "CGGMP_DKG_COMPLAINT");
                            taskFinal.lastComplaintReason = "Invalid PiSch proof in DKG Round2";
                            taskFinal.lastComplaintOffenderId = senderNodeIdFinal;
                            taskFinal.lastComplaintEvidence = evidence;
                            taskFinal.round2Processing.remove(senderNodeIdFinal);
                            return;
                        }

                        Map<String, Object> evidence = new HashMap<>();
                        if (!verifyDkgShare(XjkFinal, getIndexValue(taskFinal, receiverId), new BigInteger(yHexFinal, 16))) {
                            evidence.put("senderId", senderNodeIdFinal);
                            evidence.put("receiverId", receiverId);
                            evidence.put("sigma", yHexFinal);
                            evidence.put("S", encodePointMapCompressed(XjkFinal));
                            fireAndForget(broadcastDkgComplaint(taskFinal, senderNodeIdFinal, "Invalid share in DKG Round2", evidence),
                                    "CGGMP_DKG_COMPLAINT");
                            taskFinal.lastComplaintReason = "Invalid share in DKG Round2";
                            taskFinal.lastComplaintOffenderId = senderNodeIdFinal;
                            taskFinal.lastComplaintEvidence = evidence;
                            taskFinal.round2Processing.remove(senderNodeIdFinal);
                            return;
                        }

                        taskFinal.xji.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, new BigInteger(yHexFinal, 16));
                        taskFinal.round2Received.put(senderNodeIdFinal, Boolean.TRUE);
                        taskFinal.round2ReceivedLatch.countDown();
                        taskFinal.round2Processing.remove(senderNodeIdFinal);
                    });
        });
    }

    private void handleCggmpDkgRound2Batch(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        if (taskId == null || executionId == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            logger.info("Already received Round2 from node {}, skipping", senderNodeId);
            return;
        }
        Map<?, ?> shares = (Map<?, ?>) dataMap.get("shares");
        if (shares == null || !shares.containsKey(String.valueOf(nodeId))) {
            return;
        }
        Map<?, ?> share = (Map<?, ?>) shares.get(String.valueOf(nodeId));
        if (share == null) {
            return;
        }
        Map<String, Object> flat = new HashMap<>();
        flat.put("taskId", taskId);
        flat.put("executionId", executionId);
        flat.put("senderId", senderNodeId);
        flat.put("receiverId", nodeId);
        flat.put("sigma", share.get("sigma"));
        handleCggmpDkgRound2(senderId, flat);
    }

    private void handleCggmpDkgRound1Echo(int senderId, Object data) {
        if (!dkgEchoEnabled) {
            return;
        }
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
        int senderNodeId = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null || senderNodeId == nodeId) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String expected = computeDkgEchoHash(task);
        if (expected == null) {
            task.pendingRound1Echo.put(senderNodeId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            logger.warn("Round1 echo mismatch from node {} (task {})", senderNodeId, taskId);
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Round1 echo mismatch",
                    Map.of("senderId", senderNodeId, "expected", expected, "received", hash)),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Round1 echo mismatch from node " + senderNodeId
                    + " expected=" + expected + " received=" + hash;
            task.lastComplaintReason = "Round1 echo mismatch";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = Map.of("senderId", senderNodeId, "expected", expected, "received", hash);
            return;
        }
        if (task.round1EchoReceived.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round1EchoReceivedLatch.countDown();
        }
    }

    private void validatePendingRound1Echoes(CggmpDkgTask task) {
        if (!dkgEchoEnabled) {
            return;
        }
        if (task == null || task.pendingRound1Echo.isEmpty()) {
            return;
        }
        String expected = computeDkgEchoHash(task);
        if (expected == null) {
            return;
        }
        for (Map.Entry<Integer, String> e : new HashMap<>(task.pendingRound1Echo).entrySet()) {
            int senderId = e.getKey();
            String hash = e.getValue();
            if (!expected.equals(hash)) {
                logger.warn("Round1 echo mismatch from node {} (task {})", senderId, task.taskId);
                fireAndForget(broadcastDkgComplaint(task, senderId, "Round1 echo mismatch",
                        Map.of("senderId", senderId, "expected", expected, "received", hash)),
                        "CGGMP_DKG_COMPLAINT");
                task.fail();
                task.errorMessage = "Round1 echo mismatch from node " + senderId
                        + " expected=" + expected + " received=" + hash;
                task.lastComplaintReason = "Round1 echo mismatch";
                task.lastComplaintOffenderId = senderId;
                task.lastComplaintEvidence = Map.of("senderId", senderId, "expected", expected, "received", hash);
                return;
            }
            task.pendingRound1Echo.remove(senderId);
            if (task.round1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null) {
                task.round1EchoReceivedLatch.countDown();
            }
        }
    }

    private void handleCggmpDkgRound3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        if (taskId == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (executionId == null || !executionId.equals(task.executionId)) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId) {
            return;
        }
        if (senderNodeId == nodeId) {
            return;
        }
        Map<?, ?> psiMap = (Map<?, ?>) dataMap.get("psi");
        if (psiMap == null) {
            return;
        }
        PiSchProof proof = decodeSchProof(psiMap);
        Map<Integer, ECPoint> aMap = task.Ajks.get(senderNodeId);
        ECPoint A = aMap == null ? null : aMap.get(0);
        if (A == null || task.rid == null) {
            task.pendingRound3Proofs.put(senderNodeId, proof);
            return;
        }
        verifyAndAcceptRound3(task, senderNodeId, proof, A);
    }

    private void validatePendingRound3(CggmpDkgTask task) {
        if (task == null || task.rid == null || task.pendingRound3Proofs.isEmpty()) {
            return;
        }
        for (Map.Entry<Integer, PiSchProof> e : new HashMap<>(task.pendingRound3Proofs).entrySet()) {
            int senderNodeId = e.getKey();
            PiSchProof proof = e.getValue();
            Map<Integer, ECPoint> aMap = task.Ajks.get(senderNodeId);
            ECPoint A = aMap == null ? null : aMap.get(0);
            if (A == null) {
                continue;
            }
            task.pendingRound3Proofs.remove(senderNodeId);
            verifyAndAcceptRound3(task, senderNodeId, proof, A);
        }
    }

    private void verifyAndAcceptRound3(CggmpDkgTask task, int senderNodeId, PiSchProof proof, ECPoint A) {
        ECPoint X = computePublicShare(task, senderNodeId);
        byte[] ctx = buildDkgContext(task.taskId, task.executionId, task.rid, senderNodeId, "SCH");
        if (!verifySchProofWithCommitment(Secp256k1Curve.G(), X, A, proof.z(), ctx)) {
            fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid Schnorr proof in DKG Round3", Map.of("senderId", senderNodeId)),
                    "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid Schnorr proof from node " + senderNodeId;
            return;
        }
        task.round3SchProofs.put(senderNodeId, proof);
        if (task.round3Received.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round3ReceivedLatch.countDown();
        }
    }

    private Map<String, Object> buildDkgRound3Evidence(CggmpDkgTask task, int offenderId) {
        Map<String, Object> ev = new HashMap<>();
        Map<String, String> xkStar = encodePointMap(task.XkStar);
        ev.put("XkStar", xkStar);
        ev.put("rid", HexUtils.bytesToHex(task.rid == null ? new byte[0] : task.rid));
        return ev;
    }

    private void handleCggmpDkgComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        Object evidence = dataMap.get("evidence");
        if (taskId == null || reason == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received DKG complaint for task {} from node {} against {}: {}", taskId, senderId, offenderId, reason);
        if (evidence instanceof Map<?, ?> ev) {
            task.lastComplaintReason = reason;
            task.lastComplaintOffenderId = offenderId;
            task.lastComplaintEvidence = new HashMap<>();
            task.lastComplaintEvidence.putAll((Map<String, Object>) ev);
            if (!validateDkgComplaintEvidence(task, reason, ev)) {
                logger.warn("Invalid DKG complaint evidence from node {}", senderId);
                if (nodeId == task.initiatorId) {
                    attemptExcludeAndRestartDkg(task, senderId, "Invalid complaint evidence");
                } else {
                    task.fail();
                    task.errorMessage = "DKG complaint invalid evidence from " + senderId;
                }
                return;
            }
        }
        if (nodeId == task.initiatorId && offenderId != null) {
            attemptExcludeAndRestartDkg(task, offenderId, reason);
        } else {
            task.fail();
            task.errorMessage = "DKG complaint: " + reason;
        }
    }

    private boolean validateDkgComplaintEvidence(CggmpDkgTask task, String reason, Map<?, ?> evidence) {
        try {
            if (reason == null) {
                return false;
            }
            if (reason.startsWith("Invalid share")) {
                return true;
            }
            if (reason.contains("Round1 echo") || reason.contains("Round1 commit") || reason.contains("XkStar")) {
                return true;
            }
            if (reason.contains("Schnorr") || reason.contains("PiSch")) {
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private void handleCggmpDkgExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        if (taskId == null || offenderValue == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        int offenderId = offenderValue instanceof Number n ? n.intValue() : -1;
        task.fail();
        task.errorMessage = "DKG excluded offender " + offenderId + ": " + (reason == null ? "" : reason);
        if (nodeId != task.initiatorId && dataMap.get("newTaskId") instanceof String newTaskId
                && dataMap.get("participants") instanceof java.util.Collection<?> coll) {
            java.util.LinkedHashSet<Integer> participants = new java.util.LinkedHashSet<>();
            for (Object o : coll) {
                if (o instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
            if (!participants.isEmpty()) {
                String newExecutionId = dataMap.get("executionId") instanceof String v ? v : UUID.randomUUID().toString();
                CggmpDkgTask newTask = createDkgTaskInternal(newTaskId, newExecutionId, task.nodesCount, task.threshold, participants, senderId);
                dkgTasks.putIfAbsent(newTaskId, newTask);
                drainPendingRound1(newTask);
                startDkgProcessInternal(newTaskId, false);
            }
        }
    }

    private CompletableFuture<Void> broadcastDkgComplaint(CggmpDkgTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_COMPLAINT, data));
    }

    private CompletableFuture<Void> broadcastDkgExclude(CggmpDkgTask task,
                                                        int offenderId,
                                                        String reason,
                                                        String newTaskId,
                                                        Set<Integer> newParticipants,
                                                        String newExecutionId) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", newExecutionId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        data.put("newTaskId", newTaskId);
        data.put("participants", new ArrayList<>(newParticipants));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_EXCLUDE, data));
    }

    private void attemptExcludeAndRestartDkg(CggmpDkgTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            task.fail();
            task.errorMessage = "DKG complaint (offender not participant): " + reason;
            return;
        }
        Set<Integer> newParticipants = new java.util.LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.isEmpty()) {
            task.fail();
            task.errorMessage = "DKG exclusion leaves no participants";
            return;
        }
        String newTaskId = UUID.randomUUID().toString();
        String newExecutionId = UUID.randomUUID().toString();
        CggmpDkgTask newTask = createDkgTaskInternal(newTaskId, newExecutionId, task.nodesCount, task.threshold, newParticipants, task.initiatorId);
        dkgTasks.putIfAbsent(newTaskId, newTask);
        drainPendingRound1(newTask);
        logger.warn("DKG exclusion: offender {} removed, restarting DKG task {}", offenderId, newTaskId);
        fireAndForget(broadcastDkgExclude(task, offenderId, reason, newTaskId, newParticipants, newExecutionId),
                "CGGMP_DKG_EXCLUDE");
        startDkgProcess(newTaskId);
        task.fail();
        task.errorMessage = "DKG restart after excluding offender " + offenderId;
    }

    private CggmpDkgTask getDkgTask(String taskId) {
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("CGGMP DKG task not found: " + taskId);
        }
        return task;
    }

    private void saveKeyShareToDatabase(CggmpDkgTask task) {
        try {
            String shareHex = task.secretShare.toString(16);
            Map<String, String> publicShares = buildPublicShares(task);
            String publicSharesJson = encodeStringMapAsJson(publicShares);
            String indexMapJson = buildIndexMapJson(task);
            String chainCodeHex = task.chainCode == null || task.chainCode.length == 0 ? null : HexUtils.bytesToHex(task.chainCode);
            KeyShare keyShare = new KeyShare(nodeId, shareHex, task.groupPublicKeyHex, task.taskId, publicSharesJson, indexMapJson, chainCodeHex);
            keyShareDao.save(keyShare);
            logger.info("Saved CGGMP key share to database for task: {}", task.taskId);
        } catch (Exception e) {
            logger.error("Failed to save CGGMP key share to database", e);
        }
    }

    private Map<String, String> buildPublicShares(CggmpDkgTask task) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int peerId : task.participants) {
            ECPoint Xj = computePublicShare(task, peerId);
            out.put(String.valueOf(peerId), HexUtils.bytesToHex(Xj.getEncoded(false)));
        }
        return out;
    }

    private String buildIndexMapJson(CggmpDkgTask task) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int peerId : task.participants) {
            BigInteger idx = task.indexMap != null ? task.indexMap.get(peerId) : null;
            out.put(String.valueOf(peerId), idx == null ? String.valueOf(peerId) : idx.toString());
        }
        return encodeStringMapAsJson(out);
    }

    private String encodeStringMapAsJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, String> e : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            first = false;
            sb.append("\"").append(JsonUtils.escapeJson(e.getKey())).append("\":");
            sb.append("\"").append(JsonUtils.escapeJson(e.getValue())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private AuxInfo loadLatestAuxInfo(int nodeId) {
        return auxInfoDao.loadLatestSync(nodeId);
    }

    private CompletableFuture<Void> ensureLocalAuxReady() {
        boolean hasAux = loadLatestAuxInfo(nodeId) != null;
        if (!hasAux) {
            return CompletableFuture.failedFuture(new RuntimeException("Missing auxiliary info on local node."));
        }
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = dkgScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> waitForDkgLatch(CggmpDkgTask task, CountDownLatch latch, String label) {
        return waitForLatchAsync(latch, Constants.DKG_ROUND_TIMEOUT_SECONDS, label)
                .exceptionally(ex -> {
                    task.timeout();
                    throw new CompletionException(ex);
                });
    }

    private void cachePendingRound1(String taskId, int senderId, Map<?, ?> dataMap) {
        if (taskId == null) {
            return;
        }
        ConcurrentHashMap<Integer, Map<String, Object>> pending =
                pendingRound1ByTask.computeIfAbsent(taskId, ignored -> new ConcurrentHashMap<>());
        Map<String, Object> normalized = new HashMap<>();
        for (Map.Entry<?, ?> entry : dataMap.entrySet()) {
            if (entry.getKey() instanceof String key) {
                normalized.put(key, entry.getValue());
            }
        }
        pending.put(senderId, normalized);
        logger.debug("Cached DKG Round1 from node {} for task {} (waiting for task creation)", senderId, taskId);
    }

    private void drainPendingRound1(CggmpDkgTask task) {
        ConcurrentHashMap<Integer, Map<String, Object>> pending = pendingRound1ByTask.remove(task.taskId);
        if (pending == null || pending.isEmpty()) {
            return;
        }
        logger.info("Replaying {} pending DKG Round1 messages for task {}", pending.size(), task.taskId);
        for (Map.Entry<Integer, Map<String, Object>> entry : pending.entrySet()) {
            try {
                handleCggmpDkgRound1(entry.getKey(), entry.getValue());
            } catch (Exception ex) {
                logger.warn("Failed to replay pending DKG Round1 from node {} for task {}: {}",
                        entry.getKey(), task.taskId, ex.getMessage());
            }
        }
    }

    private CompletableFuture<Void> delayMs(long delayMs) {
        if (delayMs <= 0) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> future = new CompletableFuture<>();
        dkgScheduler.schedule(() -> future.complete(null), delayMs, TimeUnit.MILLISECONDS);
        return future;
    }

    private CompletableFuture<Void> retryAsync(java.util.function.Supplier<CompletableFuture<Void>> action,
                                               int maxAttempts,
                                               long delayMs,
                                               String name) {
        int attempts = Math.max(1, maxAttempts);
        AtomicInteger counter = new AtomicInteger(0);
        CompletableFuture<Void> result = new CompletableFuture<>();
        Runnable runner = new Runnable() {
            @Override
            public void run() {
                int attempt = counter.incrementAndGet();
                action.get().whenComplete((v, ex) -> {
                    if (ex == null) {
                        result.complete(null);
                        return;
                    }
                    if (attempt >= attempts) {
                        result.completeExceptionally(ex);
                        return;
                    }
                    logger.warn("{} failed (attempt {}/{}): {}", name, attempt, attempts, ex.getMessage());
                    dkgScheduler.schedule(this, Math.max(0, delayMs), TimeUnit.MILLISECONDS);
                });
            }
        };
        dkgScheduler.execute(runner);
        return result;
    }

    private void fireAndForget(CompletableFuture<Void> future, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    private Object maybeCompressDkgPayload(MessageType type, Object data) {
        return data;
    }

    private Object maybeDecompressDkgPayload(MessageType type, byte[] bytes) {
        return null;
    }

    private Map<String, String> encodePointMap(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            ECPoint p = map.get(k);
            if (p == null) continue;
            out.put(String.valueOf(k), HexUtils.bytesToHex(p.getEncoded(false)));
        }
        return out;
    }

    private Map<String, String> encodePointMapCompressed(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            ECPoint p = map.get(k);
            if (p == null) continue;
            out.put(String.valueOf(k), HexUtils.bytesToHex(p.getEncoded(true)));
        }
        return out;
    }

    private Map<Integer, ECPoint> decodePointMap(Map<?, ?> map) {
        Map<Integer, ECPoint> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, Secp256k1Curve.decodePoint(HexUtils.hexToBytes(String.valueOf(e.getValue()))));
        }
        return out;
    }

    private Map<String, Object> encodeSchProofMap(Map<Integer, PiSchProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiSchProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpDkgCodec.encodePiSchProof(e.getValue()));
        }
        return out;
    }

    private Map<String, Object> encodeSchProof(PiSchProof proof) {
        return CggmpDkgCodec.encodePiSchProof(proof);
    }

    private PiSchProof decodeSchProof(Map<?, ?> map) {
        return CggmpDkgCodec.decodePiSchProof(map);
    }

    private Map<Integer, PiSchProof> decodeSchProofMap(Map<?, ?> map) {
        Map<Integer, PiSchProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpDkgCodec.decodePiSchProof((Map<?, ?>) e.getValue()));
        }
        return out;
    }

    private static byte[] buildDkgContext(String taskId, String executionId, byte[] rid, int senderId, String label) {
        String sid = buildSid(executionId, taskId);
        String base = "DKG:" + label + ":" + sid + ":" + senderId + ":";
        byte[] prefix = base.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (rid == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rid.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rid, 0, out, prefix.length, rid.length);
        return out;
    }

    private static String buildSid(String executionId, String taskId) {
        return "CGGMP24:" + executionId + ":" + taskId;
    }

    private static String computeTaggedHashHex(String tag, Object... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            updateDigest(md, tag);
            for (Object part : parts) {
                updateDigest(md, part);
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute tagged hash", e);
        }
    }

    private static String computeDkgEchoHash(CggmpDkgTask task) {
        try {
            String sid = buildSid(task.executionId, task.taskId);
            List<Integer> ids = new ArrayList<>(task.participants);
            Collections.sort(ids);
            List<String> commits = new ArrayList<>();
            for (int id : ids) {
                String v = task.round1PayloadHashes.get(id);
                if (v == null) {
                    return null;
                }
                commits.add(v);
            }
            return computeTaggedHashHex("DKG_ECHO", sid, commits);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute DKG echo hash", e);
        }
    }

    private static void updateDigest(MessageDigest md, Object part) {
        if (part == null) {
            md.update((byte) 0);
            return;
        }
        if (part instanceof String s) {
            byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof byte[] bytes) {
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof Number n) {
            byte[] bytes = n.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            updateDigestWithLength(md, keys.size());
            for (String k : keys) {
                updateDigest(md, k);
                updateDigest(md, map.get(k));
            }
            return;
        }
        if (part instanceof Iterable<?> it) {
            List<Object> items = new ArrayList<>();
            for (Object o : it) {
                items.add(o);
            }
            updateDigestWithLength(md, items.size());
            for (Object o : items) {
                updateDigest(md, o);
            }
            return;
        }
        updateDigest(md, String.valueOf(part));
    }

    private static void updateDigestWithLength(MessageDigest md, int length) {
        md.update((byte) ((length >>> 24) & 0xFF));
        md.update((byte) ((length >>> 16) & 0xFF));
        md.update((byte) ((length >>> 8) & 0xFF));
        md.update((byte) (length & 0xFF));
    }

    private static String computeDkgCommitHash(String executionId,
                                               String taskId,
                                               int senderId,
                                               byte[] ridPart,
                                               Map<Integer, ECPoint> sVec,
                                               ECPoint A,
                                               byte[] u,
                                               byte[] chainCode) {
        String sid = buildSid(executionId, taskId);
        Map<String, String> sMap = encodePointMapCompressedStatic(sVec);
        String aHex = HexUtils.bytesToHex(A.getEncoded(true));
        return computeTaggedHashHex("DKG_HASH_COM", sid, senderId, ridPart, sMap, aHex, u, chainCode);
    }

    private static String computeDkgCommitHashFromWire(String executionId,
                                                       String taskId,
                                                       int senderId,
                                                       String ridPartHex,
                                                       Map<?, ?> sMap,
                                                       String aHex,
                                                       String uHex,
                                                       String cHex) {
        String sid = buildSid(executionId, taskId);
        byte[] rid = ridPartHex == null ? null : HexUtils.hexToBytes(ridPartHex);
        byte[] u = uHex == null ? null : HexUtils.hexToBytes(uHex);
        byte[] c = cHex == null ? null : HexUtils.hexToBytes(cHex);
        return computeTaggedHashHex("DKG_HASH_COM", sid, senderId, rid, sMap, aHex, u, c);
    }

    private static Map<String, String> encodePointMapCompressedStatic(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        if (map == null) {
            return out;
        }
        for (Map.Entry<Integer, ECPoint> e : map.entrySet()) {
            ECPoint p = e.getValue();
            if (p == null) {
                continue;
            }
            out.put(String.valueOf(e.getKey()), HexUtils.bytesToHex(p.normalize().getEncoded(true)));
        }
        return out;
    }

    private static BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x, BigInteger mod) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        for (BigInteger coeff : coefficients) {
            result = result.add(coeff.multiply(xPower)).mod(mod);
            xPower = xPower.multiply(x).mod(mod);
        }
        return result;
    }

    private static BigInteger[] precomputeEvalPowers(BigInteger x, int threshold) {
        BigInteger q = Secp256k1Curve.n();
        if (x == null) {
            throw new IllegalArgumentException("Missing evaluation index");
        }
        BigInteger[] powers = new BigInteger[threshold];
        BigInteger xPower = BigInteger.ONE;
        for (int k = 0; k < threshold; k++) {
            powers[k] = xPower;
            xPower = xPower.multiply(x).mod(q);
        }
        return powers;
    }

    private static ECPoint computeExpectedShareFromXjk(Map<Integer, ECPoint> Xjk, BigInteger[] evalPowers) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        if (evalPowers == null) {
            throw new IllegalStateException("Missing precomputed DKG evaluation powers");
        }
        int limit = Math.min(Xjk.size(), evalPowers.length);
        for (int k = 0; k < limit; k++) {
            ECPoint X = Xjk.get(k);
            if (X == null) {
                continue;
            }
            sum = sum.add(X.multiply(evalPowers[k])).normalize();
        }
        return sum;
    }

    private CompletableFuture<Boolean> verifySchProofsParallelAsync(CggmpDkgTask task,
                                                                    int senderNodeId,
                                                                    Map<Integer, PiSchProof> schProofs,
                                                                    Map<Integer, ECPoint> Xjk,
                                                                    Map<Integer, ECPoint> Ajk) {
        if (schProofs == null || schProofs.size() != threshold) {
            return CompletableFuture.completedFuture(false);
        }
        if (threshold <= 3) {
            for (int k = 0; k < threshold; k++) {
                PiSchProof proof = schProofs.get(k);
                ECPoint AjkPoint = Ajk.get(k);
                ECPoint XjkPoint = Xjk.get(k);
                if (proof == null || AjkPoint == null || XjkPoint == null) {
                    return CompletableFuture.completedFuture(false);
                }
                byte[] ctx = buildDkgContext(task.taskId, task.executionId, task.rid, senderNodeId, "SCH:" + k);
                long schOneStart = System.nanoTime();
                if (!proof.A().equals(AjkPoint)) {
                    return CompletableFuture.completedFuture(false);
                }
                boolean ok = RefreshProofs.verifySchProof(proof, Secp256k1Curve.G(), XjkPoint, ctx);
                logger.debug("DKG Round2 Sch proof verify k={} took {} ms", k, (System.nanoTime() - schOneStart) / 1_000_000);
                if (!ok) {
                    return CompletableFuture.completedFuture(false);
                }
            }
            return CompletableFuture.completedFuture(true);
        }

        List<CompletableFuture<Boolean>> futures = new ArrayList<>(threshold);
        for (int k = 0; k < threshold; k++) {
            PiSchProof proof = schProofs.get(k);
            ECPoint AjkPoint = Ajk.get(k);
            ECPoint XjkPoint = Xjk.get(k);
            if (proof == null || AjkPoint == null || XjkPoint == null) {
                return CompletableFuture.completedFuture(false);
            }
            byte[] ctx = buildDkgContext(task.taskId, task.executionId, task.rid, senderNodeId, "SCH:" + k);
            final int kk = k;
            futures.add(CompletableFuture.supplyAsync(() -> {
                long schOneStart = System.nanoTime();
                if (!proof.A().equals(AjkPoint)) {
                    return false;
                }
                boolean ok = RefreshProofs.verifySchProof(proof, Secp256k1Curve.G(), XjkPoint, ctx);
                logger.debug("DKG Round2 Sch proof verify k={} took {} ms", kk, (System.nanoTime() - schOneStart) / 1_000_000);
                return ok;
            }, dkgExecutorService));
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(v -> {
                    for (CompletableFuture<Boolean> f : futures) {
                        Boolean ok = f.getNow(false);
                        if (!Boolean.TRUE.equals(ok)) {
                            return false;
                        }
                    }
                    return true;
                });
    }

    private static PiSchProof createSchProofWithAlpha(ECPoint g, ECPoint X, BigInteger x, BigInteger alpha, byte[] context) {
        BigInteger q = Secp256k1Curve.n();
        ECPoint A = g.multiply(alpha).normalize();
        BigInteger e = schChallenge(context, g, X, A);
        BigInteger z = alpha.add(e.multiply(x)).mod(q);
        return new PiSchProof(A, z);
    }

    private static BigInteger schChallenge(byte[] context, ECPoint g, ECPoint X, ECPoint A) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("PI_SCH".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            md.update(Secp256k1Curve.encodePoint(g));
            md.update(Secp256k1Curve.encodePoint(X));
            md.update(Secp256k1Curve.encodePoint(A));
            BigInteger q = Secp256k1Curve.n();
            BigInteger twoQ = q.shiftLeft(1);
            BigInteger e = new BigInteger(1, md.digest()).mod(twoQ);
            return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
        } catch (Exception e) {
            throw new RuntimeException("DKG Schnorr challenge failed", e);
        }
    }

    private static boolean verifySchProofWithCommitment(ECPoint g, ECPoint X, ECPoint A, BigInteger z, byte[] context) {
        BigInteger q = Secp256k1Curve.n();
        BigInteger e = schChallenge(context, g, X, A).mod(q);
        ECPoint lhs = g.multiply(z).normalize();
        ECPoint rhs = A.add(X.multiply(e)).normalize();
        return lhs.equals(rhs);
    }

    private static boolean verifyDkgShare(Map<Integer, ECPoint> sVec, BigInteger x, BigInteger sigma) {
        if (sVec == null || x == null || sigma == null) {
            return false;
        }
        if (x.signum() == 0) {
            return false;
        }
        BigInteger[] powers = precomputeEvalPowers(x, sVec.size());
        ECPoint expected = computeExpectedShareFromXjk(sVec, powers);
        ECPoint actual = Secp256k1Curve.G().multiply(sigma).normalize();
        return expected.equals(actual);
    }

    private static ECPoint computePublicShare(CggmpDkgTask task, int receiverId) {
        BigInteger x = getIndexValue(task, receiverId);
        if (x == null) {
            throw new RuntimeException("Missing index for node " + receiverId);
        }
        Map<Integer, ECPoint> XkStar = task.XkStar;
        if (XkStar.isEmpty()) {
            Map<Integer, ECPoint> merged = new HashMap<>();
            for (int peerId : task.participants) {
                Map<Integer, ECPoint> Xjk = task.Xjks.get(peerId);
                if (Xjk == null) {
                    continue;
                }
                for (Map.Entry<Integer, ECPoint> e : Xjk.entrySet()) {
                    merged.merge(e.getKey(), e.getValue(), (a, b) -> a.add(b).normalize());
                }
            }
            task.XkStar.putAll(merged);
        }
        BigInteger[] evalPowers = precomputeEvalPowers(x, task.threshold);
        ECPoint expected = computeExpectedShareFromXjk(XkStar, evalPowers);
        return expected.normalize();
    }

    private static BigInteger getIndexValue(CggmpDkgTask task, int nodeId) {
        if (task.indexMap != null && task.indexMap.containsKey(nodeId)) {
            return task.indexMap.get(nodeId);
        }
        return BigInteger.valueOf(nodeId);
    }

    private static byte[] xorRidParts(CggmpDkgTask task) {
        byte[] rid = null;
        for (byte[] part : task.ridParts.values()) {
            if (part == null) {
                continue;
            }
            if (rid == null) {
                rid = part.clone();
                continue;
            }
            for (int i = 0; i < rid.length && i < part.length; i++) {
                rid[i] ^= part[i];
            }
        }
        return rid == null ? new byte[0] : rid;
    }

    private static byte[] xorChainCodeParts(CggmpDkgTask task) {
        byte[] code = null;
        for (byte[] part : task.chainCodeParts.values()) {
            if (part == null) {
                continue;
            }
            if (code == null) {
                code = part.clone();
                continue;
            }
            for (int i = 0; i < code.length && i < part.length; i++) {
                code[i] ^= part[i];
            }
        }
        return code == null ? new byte[0] : code;
    }

    private BigInteger randomScalar(BigInteger n) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), secureRandom).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }


    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            }
        }
        logger.info("=== CGGMP DKG handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, logTaskId);
        ExecutorService executor = dkgExecutorService;
        if (message.type == MessageType.CGGMP_DKG_ROUND2
                || message.type == MessageType.CGGMP_DKG_ROUND2_BROAD
                || message.type == MessageType.CGGMP_DKG_ROUND2_BATCH) {
            executor = dkgExecutorService;
        }
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data;
                if (data instanceof byte[] bytes) {
                    Object decoded = maybeDecompressDkgPayload(message.type, bytes);
                    if (decoded != null) {
                        data = decoded;
                    }
                }
                logger.info("=== CGGMP DKG processing: type={} ===", message.type);
                switch (message.type) {
                    case CGGMP_DKG_INIT:
                        handleCggmpDkgInit(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1:
                        handleCggmpDkgRound1(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1_ECHO:
                        handleCggmpDkgRound1Echo(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2:
                        handleCggmpDkgRound2(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BROAD:
                        handleCggmpDkgRound2Broad(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BATCH:
                        handleCggmpDkgRound2Batch(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND3:
                        handleCggmpDkgRound3(senderId, data);
                        break;
                    case CGGMP_DKG_COMPLAINT:
                        handleCggmpDkgComplaint(senderId, data);
                        break;
                    case CGGMP_DKG_EXCLUDE:
                        handleCggmpDkgExclude(senderId, data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP DKG service", message.type);
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP DKG message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }

    private static final class DkgContext {
        final CggmpDkgTask task;
        final BigInteger q;
        final ECPoint g;
        final BigInteger[] coeffs;
        final Map<String, Object> r1Open;

        private DkgContext(CggmpDkgTask task,
                           BigInteger q,
                           ECPoint g,
                           BigInteger[] coeffs,
                           Map<String, Object> r1Open) {
            this.task = task;
            this.q = q;
            this.g = g;
            this.coeffs = coeffs;
            this.r1Open = r1Open;
        }
    }

    private static final class DkgNonThresholdContext {
        final CggmpDkgTask task;
        final BigInteger q;
        final ECPoint g;
        final BigInteger x_i;
        final ECPoint X_i;
        final Map<String, Object> r1Open;

        private DkgNonThresholdContext(CggmpDkgTask task,
                                       BigInteger q,
                                       ECPoint g,
                                       BigInteger x_i,
                                       ECPoint X_i,
                                       Map<String, Object> r1Open) {
            this.task = task;
            this.q = q;
            this.g = g;
            this.x_i = x_i;
            this.X_i = X_i;
            this.r1Open = r1Open;
        }
    }
}
