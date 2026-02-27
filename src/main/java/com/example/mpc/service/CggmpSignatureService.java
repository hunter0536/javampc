package com.example.mpc.service;

import com.example.mpc.cggmp.CggmpDkgCodec;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.cggmp.proof.*;
import com.example.mpc.cggmp.sign.CggmpIntegrityChecker;
import com.example.mpc.cggmp.sign.EcChaumPedersenProof;
import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpAuxTask;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
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
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class CggmpSignatureService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureService.class);

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;
    @Autowired
    private com.example.mpc.dao.ComplaintDao complaintDao;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.cggmp.proof.kappa:128}")
    private int proofKappa;

    @Value("${app.cggmp.proof.epsBits:16}")
    private int proofEpsBits;

    @Value("${app.cggmp.presign.retentionDays:30}")
    private long presignRetentionDays;
    @Value("${app.cggmp.presign.echoEnabled:true}")
    private boolean presignEchoEnabled;
    @Value("${app.cggmp.presign.useRbc:false}")
    private boolean presignUseRbc;
    @Value("${app.cggmp.hdEnabled:false}")
    private boolean hdEnabled;
    @Value("${app.cggmp.complaint.logPath:logs/complaints.jsonl}")
    private String complaintLogPath;
    private final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private static final ExecutorService dkgExecutorService = ThreadPoolUtil.getComputationThreadPool();

    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;
    private final ScheduledExecutorService cggmpScheduler = Executors.newSingleThreadScheduledExecutor();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initialize() throws Exception {
        logger.info("Initializing CGGMP service for node {}", nodeId);
        PresignUsageStore.configureRetentionDays(presignRetentionDays);
        logger.info("CGGMP service initialized successfully");
    }

    private CompletableFuture<Void> delayMs(long delayMs) {
        if (delayMs <= 0) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> future = new CompletableFuture<>();
        cggmpScheduler.schedule(() -> future.complete(null), delayMs, TimeUnit.MILLISECONDS);
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
                    cggmpScheduler.schedule(this, Math.max(0, delayMs), TimeUnit.MILLISECONDS);
                });
            }
        };
        cggmpScheduler.execute(runner);
        return result;
    }

    private void fireAndForget(CompletableFuture<Void> future, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    public java.util.List<com.example.mpc.dao.ComplaintDao.ComplaintRecord> getComplaints(String taskId,
                                                                                          String reason,
                                                                                          String reasonLike,
                                                                                          Integer senderId,
                                                                                          Integer offenderId,
                                                                                          Long fromTs,
                                                                                          Long toTs,
                                                                                          int limit,
                                                                                          int offset) {
        int safeLimit = Math.max(1, Math.min(500, limit));
        int safeOffset = Math.max(0, offset);
        if ((taskId == null || taskId.isBlank())
                && (reason == null || reason.isBlank())
                && (reasonLike == null || reasonLike.isBlank())
                && senderId == null
                && offenderId == null
                && fromTs == null
                && toTs == null) {
            return complaintDao.list(nodeId, null, safeLimit, safeOffset);
        }
        return complaintDao.listFiltered(
                nodeId,
                taskId == null || taskId.isBlank() ? null : taskId,
                reason == null || reason.isBlank() ? null : reason,
                reasonLike == null || reasonLike.isBlank() ? null : reasonLike,
                senderId,
                offenderId,
                fromTs,
                toTs,
                safeLimit,
                safeOffset);
    }

    @SuppressWarnings("unchecked")

    // Legacy MtA-based DKG handlers removed in CGGMP21 DKG.

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] buildMtaContext(String taskId, int senderId, int receiverId) {
        String ctx = taskId + ":" + senderId + ":" + receiverId;
        return ctx.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message) {
        if (!signatureInProgress.compareAndSet(false, true)) {
            throw new RuntimeException("Signature process is already in progress");
        }

        String fixedGroupPublicKey = null;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        String taskId = UUID.randomUUID().toString();
        Gg20SignatureTask task = new Gg20SignatureTask(taskId, message, fixedGroupPublicKey, nodesCount, threshold, nodeId);
        signatureTasks.put(taskId, task);
        return taskId;
    }

    public String createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message, int initiatorId, Set<Integer> participants) {
        if (!signatureInProgress.compareAndSet(false, true)) {
            throw new RuntimeException("Signature process is already in progress");
        }

        String fixedGroupPublicKey = null;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        Gg20SignatureTask task = new Gg20SignatureTask(signatureTaskId, message, fixedGroupPublicKey, nodesCount, threshold, initiatorId, participants);
        signatureTasks.put(signatureTaskId, task);
        return signatureTaskId;
    }

    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId, true);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId, boolean broadcastInit) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task not found: " + taskId));
        }

        if (task.isInProgress() || task.isCompleted()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task is already in progress or completed"));
        }

        if (!task.participants.contains(nodeId)) {
            logger.info("Node {} not selected for signature task {}, participants={}, skipping", nodeId, taskId, task.participants);
            return CompletableFuture.completedFuture(null);
        }

        if (!task.start()) {
            return CompletableFuture.failedFuture(new RuntimeException("Failed to start signature task"));
        }

        try {
            initSignatureContext(task);
        } catch (Exception e) {
            task.fail(e.getMessage());
            return CompletableFuture.failedFuture(e);
        }

        CompletableFuture<Void> flow = (broadcastInit ? broadcastOfflineInit(task) : CompletableFuture.completedFuture(null))
                .thenCompose(v -> runOfflinePhase(task))
                .thenCompose(v -> {
                    if (!broadcastInit) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return waitForLatchAsync(task.offlineReadyLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline ready")
                            .thenCompose(v2 -> broadcastOnlineInit(task));
                })
                .thenCompose(v -> runOnlinePhase(task));

        return flow.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.error("Error in CGGMP signature process: {}", ex.getMessage());
                task.fail(ex.getMessage());
                signatureInProgress.set(false);
            }
        });
    }

    public SignatureTaskStatusResponse getSignatureTaskStatus(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        SignatureTaskStatusResponse response = new SignatureTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setStatus(task.status.get().name());
        response.setMessage(task.message);
        response.setErrorMessage(task.errorMessage);
        response.setParticipants(new ArrayList<>(task.participants));
        response.setReceivedGammaCommitments(task.participants.size() - 1 - (int) task.gammaCommitLatch.getCount());
        response.setReceivedMtaResponses(task.participants.size() - 1 - (int) task.stResponseLatch.getCount());
        response.setReceivedOffline(0);
        response.setReceivedPartialS(0);
        return response;
    }

    public SignatureResultResponse getSignatureResult(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        if (!task.isCompleted()) {
            throw new RuntimeException("Signature task not completed yet: " + taskId);
        }

        SignatureResultResponse response = new SignatureResultResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setSignature(task.signature);
        response.setVerified(task.verified);
        response.setMessage(task.message);
        return response;
    }

    private byte[] hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private void initSignatureContext(Gg20SignatureTask task) {
        if (task.messageHash == null) {
            task.messageHash = hashMessage(task.message);
        }
        if (task.groupPublicKeyPoint == null) {
            task.groupPublicKeyPoint = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(task.groupPublicKey));
        }
        ensureKeyShareData(task);
    }

    private void ensureKeyShareData(Gg20SignatureTask task) {
        if (task.publicShares != null && task.indexMap != null) {
            return;
        }
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(task.groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        if (task.publicShares == null) {
            task.publicShares = parsePublicShares(keyShare.getPublicShares());
        }
        if (task.indexMap == null) {
            task.indexMap = parseIndexMap(keyShare.getIndexMap());
        }
        if (task.chainCode == null && keyShare.getChainCode() != null) {
            try {
                task.chainCode = HexUtils.hexToBytes(keyShare.getChainCode());
            } catch (Exception e) {
                logger.warn("Failed to decode chain code for task {}: {}", task.taskId, e.getMessage());
            }
        }
    }

    private CompletableFuture<Void> runOfflinePhase(Gg20SignatureTask task) {
        CompletableFuture<PresignR1Context> r1Future = CompletableFuture.supplyAsync(() -> {
            try {
                BigInteger curveOrder = Secp256k1Curve.n();
                initSignaturePaillier(task);

                task.k_i = randomNonZero(curveOrder);
                BigInteger gamma_i = randomNonZero(curveOrder);
                task.presignGamma.put(nodeId, Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i));

                BigInteger y_i = randomNonZero(curveOrder);
                BigInteger a_i = randomNonZero(curveOrder);
                BigInteger b_i = randomNonZero(curveOrder);
                ECPoint Y_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), y_i);
                ECPoint A1 = Secp256k1Curve.multiply(Secp256k1Curve.G(), a_i);
                ECPoint A2 = Y_i.multiply(a_i).add(Secp256k1Curve.multiply(Secp256k1Curve.G(), task.k_i)).normalize();
                ECPoint B1 = Secp256k1Curve.multiply(Secp256k1Curve.G(), b_i);
                ECPoint B2 = Y_i.multiply(b_i).add(Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i)).normalize();
                task.presignYScalar = y_i;
                task.presignAScalar = a_i;
                task.presignBScalar = b_i;
                task.presignY.put(nodeId, Y_i);
                task.presignA1.put(nodeId, A1);
                task.presignA2.put(nodeId, A2);
                task.presignB1.put(nodeId, B1);
                task.presignB2.put(nodeId, B2);

                PaillierEncryption.Encryption encK = task.paillier.encryptWithRandomness(task.k_i);
                PaillierEncryption.Encryption encG = task.paillier.encryptWithRandomness(gamma_i);
                BigInteger K = encK.c;
                BigInteger G = encG.c;
                task.presignK.put(nodeId, K);
                task.presignG.put(nodeId, G);

                byte[] ctxR1K = buildPresignContext(task.taskId, nodeId, "R1K");
                PiEncElgProof encElgK = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1Curve.G(),
                        A1,
                        Y_i,
                        A2,
                        task.k_i,
                        encK.r,
                        a_i,
                        y_i,
                        proofEpsBits,
                        ctxR1K
                );
                PresignProofs.EncElgVerifyResult localEncElgK = PresignProofs.verifyEncElgProofDetailed(
                        encElgK, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1Curve.G(), A1, Y_i, A2, K, proofEpsBits, ctxR1K);
                if (!localEncElgK.ok()) {
                    logger.warn("Local PiEncElg proof (K) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgK.eq1(), localEncElgK.eq2(), localEncElgK.eq3(), localEncElgK.eq4(), localEncElgK.z1InRange());
                }
                byte[] ctxR1G = buildPresignContext(task.taskId, nodeId, "R1G");
                PiEncElgProof encElgG = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1Curve.G(),
                        B1,
                        Y_i,
                        B2,
                        gamma_i,
                        encG.r,
                        b_i,
                        y_i,
                        proofEpsBits,
                        ctxR1G
                );
                PresignProofs.EncElgVerifyResult localEncElgG = PresignProofs.verifyEncElgProofDetailed(
                        encElgG, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1Curve.G(), B1, Y_i, B2, G, proofEpsBits, ctxR1G);
                if (!localEncElgG.ok()) {
                    logger.warn("Local PiEncElg proof (G) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgG.eq1(), localEncElgG.eq2(), localEncElgG.eq3(), localEncElgG.eq4(), localEncElgG.z1InRange());
                }
                fireAndForget(broadcastPresignR1(task, K, G, Y_i, A1, A2, B1, B2, encElgK, encElgG),
                        "CGGMP_PRESIGN_R1");
                return new PresignR1Context(task, curveOrder, gamma_i);
            } catch (Exception e) {
                task.fail(e.getMessage());
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());

        CompletableFuture<PresignR2Context> r2ContextFuture = r1Future
                .thenCompose(ctx -> waitForLatchAsync(task.gammaCommitLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R1")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    if (!presignEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    fireAndForget(broadcastPresignR1Echo(task), "CGGMP_PRESIGN_R1_ECHO");
                    return waitForLatchAsync(task.presignR1EchoLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R1 echo")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        logger.info("Presign R1 completed for task {}, proceeding to R2", task.taskId);
                        ECPoint Gamma_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), ctx.gamma_i);
                        BigInteger x_i_raw = loadLocalShare(task.groupPublicKey);
                        BigInteger lambda_i = computeSignatureLagrange(task, nodeId, ctx.curveOrder);
                        BigInteger x_i = x_i_raw.multiply(lambda_i).mod(ctx.curveOrder);
                        ECPoint X_i = resolvePublicShare(task, nodeId, lambda_i, x_i);

                        long r2StartNs = System.nanoTime();
                        logger.info("Presign R2 starting proof generation for task {} (peers={})", task.taskId, task.participants.size() - 1);
                        List<CompletableFuture<PeerR2Result>> r2Futures = new ArrayList<>();
                        for (int peerId : task.participants) {
                            if (peerId == nodeId) continue;
                            r2Futures.add(CompletableFuture.supplyAsync(() -> {
                                long peerStartNs = System.nanoTime();
                                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                                BigInteger K_peer = task.presignK.get(peerId);
                                if (pk == null || K_peer == null) {
                                    return PeerR2Result.skipped(peerId);
                                }
                                BigInteger beta = randomNonZero(ctx.curveOrder);
                                BigInteger betaHat = randomNonZero(ctx.curveOrder);
                                PaillierEncryption.Encryption encNegBeta = pk.encryptWithRandomness(negateModN(beta, pk.n));
                                PaillierEncryption.Encryption encNegBetaHat = pk.encryptWithRandomness(negateModN(betaHat, pk.n));
                                BigInteger D_ji = pk.multiply(K_peer, ctx.gamma_i).multiply(encNegBeta.c).mod(pk.nSquared);
                                BigInteger Dhat_ji = pk.multiply(K_peer, x_i).multiply(encNegBetaHat.c).mod(pk.nSquared);
                                PaillierEncryption.Encryption encBeta = task.paillier.getPublicKeyInfo().encryptWithRandomness(beta);
                                PaillierEncryption.Encryption encBetaHat = task.paillier.getPublicKeyInfo().encryptWithRandomness(betaHat);
                                BigInteger F_ji = encBeta.c;
                                BigInteger Fhat_ji = encBetaHat.c;
                                PiAffGProof proof = PresignProofs.createAffGProofNegY(
                                        Secp256k1Curve.G(), Gamma_i, pk.n, task.paillier.getPublicKeyInfo().n,
                                        K_peer, D_ji, F_ji, ctx.gamma_i, beta, encNegBeta.r, encBeta.r, proofKappa, proofEpsBits, buildPresignContext(task.taskId, nodeId, "R2")
                                );
                                PiAffGProof proofHat = PresignProofs.createAffGProofNegY(
                                        Secp256k1Curve.G(), X_i, pk.n, task.paillier.getPublicKeyInfo().n,
                                        K_peer, Dhat_ji, Fhat_ji, x_i, betaHat, encNegBetaHat.r, encBetaHat.r, proofKappa, proofEpsBits, buildPresignContext(task.taskId, nodeId, "R2H")
                                );
                                long peerMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - peerStartNs);
                                return PeerR2Result.done(peerId, beta, betaHat, D_ji, Dhat_ji, F_ji, Fhat_ji,
                                        encNegBeta.r, encBeta.r, encNegBetaHat.r, encBetaHat.r, proof, proofHat, peerMs);
                            }, dkgExecutorService));
                        }
                        return new PresignR2Context(task, ctx.curveOrder, ctx.gamma_i, x_i, Gamma_i, X_i, r2Futures, r2StartNs);
                    } catch (Exception e) {
                        task.fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()));

        return r2ContextFuture
                .thenCompose(ctx -> CompletableFuture.allOf(ctx.r2Futures.toArray(new CompletableFuture[0]))
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        Map<Integer, BigInteger> D = new HashMap<>();
                        Map<Integer, BigInteger> Dhat = new HashMap<>();
                        Map<Integer, BigInteger> F = new HashMap<>();
                        Map<Integer, BigInteger> Fhat = new HashMap<>();
                        Map<Integer, PiAffGProof> affGProofs = new HashMap<>();
                        Map<Integer, PiAffGProof> affGProofsHat = new HashMap<>();
                        int skippedPeers = 0;

                        for (CompletableFuture<PeerR2Result> future : ctx.r2Futures) {
                            PeerR2Result result = future.getNow(null);
                            if (result == null) {
                                throw new RuntimeException("Presign R2 missing result after completion");
                            }
                            if (result.skipped) {
                                skippedPeers++;
                                continue;
                            }
                            int peerId = result.peerId;
                            ctx.task.presignBeta.put(peerId, result.beta);
                            ctx.task.presignBetaHat.put(peerId, result.betaHat);
                            D.put(peerId, result.d);
                            Dhat.put(peerId, result.dhat);
                            F.put(peerId, result.f);
                            Fhat.put(peerId, result.fhat);
                            ctx.task.presignFOutgoing.put(peerId, result.f);
                            ctx.task.presignFhatOutgoing.put(peerId, result.fhat);
                            ctx.task.presignRho.put(peerId, result.rho);
                            ctx.task.presignMu.put(peerId, result.mu);
                            ctx.task.presignRhoHat.put(peerId, result.rhoHat);
                            ctx.task.presignMuHat.put(peerId, result.muHat);
                            affGProofs.put(peerId, result.proof);
                            affGProofsHat.put(peerId, result.proofHat);
                            logger.debug("Presign R2 proof generated for task {} peer {} in {} ms",
                                    ctx.task.taskId, peerId, result.peerMs);
                        }
                        long r2Ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.r2StartNs);
                        logger.info("Presign R2 prepared for task {}: peers={}, proofs={}, skipped={}",
                                ctx.task.taskId, ctx.task.participants.size() - 1, affGProofs.size(), skippedPeers);
                        logger.debug("Presign R2 proof generation total time for task {}: {} ms", ctx.task.taskId, r2Ms);

                        ECPoint Y_i_r2 = ctx.task.presignY.get(nodeId);
                        ECPoint B1_r2 = ctx.task.presignB1.get(nodeId);
                        ECPoint B2_r2 = ctx.task.presignB2.get(nodeId);
                        if (Y_i_r2 == null || B1_r2 == null || B2_r2 == null || ctx.task.presignBScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof");
                        }
                        byte[] ctxR2 = buildPresignContext(ctx.task.taskId, nodeId, "R2");
                        PiLogProof logProof = PresignProofs.createLogProof(
                                Secp256k1Curve.G(),
                                Secp256k1Curve.G(),
                                ctx.Gamma_i,
                                Y_i_r2,
                                B1_r2,
                                B2_r2,
                                ctx.gamma_i,
                                ctx.task.presignBScalar,
                                ctxR2
                        );
                        fireAndForget(broadcastPresignR2(ctx.task, ctx.Gamma_i, D, Dhat, F, Fhat, affGProofs, affGProofsHat, logProof, ctx.X_i),
                                "CGGMP_PRESIGN_R2");
                        logger.info("Presign R2 broadcasted for task {}", ctx.task.taskId);

                        return new PresignR2Bundle(ctx, D, Dhat, F, Fhat);
                    } catch (Exception e) {
                        ctx.task.fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(this::continuePresignAfterR2)
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    if (cause == null) {
                        task.fail(ex.getMessage());
                    } else {
                        task.fail(cause.getMessage());
                    }
                });
    }

    private CompletableFuture<Void> runOnlinePhase(Gg20SignatureTask task) {
        return waitForLatchAsync(task.offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline phase")
                .thenCompose(v -> waitForLatchAsync(task.presignatureLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "local presignature"))
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        if (task.messageHash == null) {
                            throw new RuntimeException("Missing message hash for online phase");
                        }

                        BigInteger curveOrder = Secp256k1Curve.n();
                        if (task.presignature == null) {
                            throw new RuntimeException("Missing presignature");
                        }
                        if (task.presignatureUsed) {
                            throw new RuntimeException("Presignature already used");
                        }
                        if (nodeId == task.initiatorId) {
                            if (!PresignUsageStore.markUsed(task.groupPublicKey, task.presignature.Gamma())) {
                                throw new RuntimeException("Presignature already used (persistent)");
                            }
                        }
                        task.presignatureUsed = true;
                        ECPoint Gamma = task.presignature.Gamma();
                        task.r = Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
                        if (task.r.signum() == 0) {
                            throw new RuntimeException("Invalid r (zero), restart signature");
                        }

                        BigInteger e = new BigInteger(1, task.messageHash).mod(curveOrder);
                        BigInteger chiTilde = task.presignature.chiTilde();
                        BigInteger shift = resolveSignShift(task, curveOrder);
                        if (shift.signum() != 0) {
                            chiTilde = chiTilde.add(task.presignature.kTilde().multiply(shift)).mod(curveOrder);
                        }
                        BigInteger sigma_i = task.presignature.kTilde().multiply(e).add(task.r.multiply(chiTilde)).mod(curveOrder);
                        return new OnlineContext(task, curveOrder, sigma_i);
                    } catch (Exception e) {
                        task.fail(e.getMessage());
                        signatureInProgress.set(false);
                        clearPresignAll(task);
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(ctx -> {
                    if (nodeId == ctx.task.initiatorId) {
                        if (!verifySigmaShare(ctx.task, nodeId, ctx.sigma_i)) {
                            failSignatureTask(ctx.task, "Local signature share verification failed");
                            signatureInProgress.set(false);
                            clearPresignAll(ctx.task);
                            return CompletableFuture.completedFuture(null);
                        }
                        ctx.task.sShares.put(nodeId, ctx.sigma_i);
                        return waitForLatchAsync(ctx.task.sShareLatch, Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, "signature shares")
                                .thenRunAsync(() -> finalizeSignatureAsInitiator(ctx), ThreadPoolUtil.getIoThreadPool());
                    }
                    return CompletableFuture.runAsync(() -> {
                        fireAndForget(sendSShare(ctx.task, ctx.sigma_i), "CGGMP_SIGN_S_SHARE");
                        ctx.task.complete();
                        signatureInProgress.set(false);
                        clearPresignLocal(ctx.task);
                    }, ThreadPoolUtil.getIoThreadPool());
                })
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    String msg = cause == null ? ex.getMessage() : cause.getMessage();
                    task.fail(msg);
                    signatureInProgress.set(false);
                    clearPresignAll(task);
                });
    }

    private CompletableFuture<Void> broadcastOfflineInit(Gg20SignatureTask task) {
        Map<String, Object> initData = new HashMap<>();
        initData.put("signatureTaskId", task.taskId);
        initData.put("groupPublicKey", task.groupPublicKey);
        initData.put("message", task.message);
        initData.put("initiatorId", task.initiatorId);
        initData.put("participants", new ArrayList<>(task.participants));
        return retryAsync(
                () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_OFFLINE_INIT, initData)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_OFFLINE_INIT"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_SIGN_OFFLINE_INIT, proceeding: {}", ex.getMessage());
            }
        });
    }

    private CompletableFuture<Void> broadcastOnlineInit(Gg20SignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("messageHash", Base64.getEncoder().encodeToString(task.messageHash));
        data.put("initiatorId", task.initiatorId);
        data.put("participants", new ArrayList<>(task.participants));
        return retryAsync(
                () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_ONLINE_INIT, data)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_ONLINE_INIT"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_SIGN_ONLINE_INIT, proceeding: {}", ex.getMessage());
            }
        });
    }

    private CompletableFuture<Void> broadcastPresignR1(Gg20SignatureTask task,
                                                       BigInteger K,
                                                       BigInteger G,
                                                       ECPoint Y,
                                                       ECPoint A1,
                                                       ECPoint A2,
                                                       ECPoint B1,
                                                       ECPoint B2,
                                                       PiEncElgProof encElgK,
                                                       PiEncElgProof encElgG) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("K", K.toString(16));
        data.put("G", G.toString(16));
        data.put("Y", bytesToHex(Secp256k1Curve.encodePoint(Y)));
        data.put("A1", bytesToHex(Secp256k1Curve.encodePoint(A1)));
        data.put("A2", bytesToHex(Secp256k1Curve.encodePoint(A2)));
        data.put("B1", bytesToHex(Secp256k1Curve.encodePoint(B1)));
        data.put("B2", bytesToHex(Secp256k1Curve.encodePoint(B2)));
        data.put("encElgProofK", CggmpDkgCodec.encodePiEncElgProof(encElgK));
        data.put("encElgProofG", CggmpDkgCodec.encodePiEncElgProof(encElgG));
        data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
        data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
        return retryAsync(
                () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R1, data)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_PRESIGN_R1"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_PRESIGN_R1, proceeding: {}", ex.getMessage());
            }
        });
    }

    private CompletableFuture<Void> broadcastPresignR1Echo(Gg20SignatureTask task) {
        String hash = computePresignR1EchoHash(task);
        if (hash == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Missing presign R1 data for echo"));
        }
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("hash", hash);
        NodeService.Message msg = new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R1_ECHO, data);
        if (presignUseRbc) {
            return nodeService.broadcastRbc(msg);
        }
        return nodeService.broadcastMessage(msg);
    }

    private CompletableFuture<Void> broadcastPresignR2(Gg20SignatureTask task, ECPoint Gamma,
                                                       Map<Integer, BigInteger> D,
                                                       Map<Integer, BigInteger> Dhat,
                                                       Map<Integer, BigInteger> F,
                                                       Map<Integer, BigInteger> Fhat,
                                                       Map<Integer, PiAffGProof> affG,
                                                       Map<Integer, PiAffGProof> affGhat,
                                                       PiLogProof logProof,
                                                       ECPoint X) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("Gamma", bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
        data.put("D", encodeBigIntegerMap(D));
        data.put("Dhat", encodeBigIntegerMap(Dhat));
        data.put("F", encodeBigIntegerMap(F));
        data.put("Fhat", encodeBigIntegerMap(Fhat));
        data.put("affGProofs", encodeAffGProofMap(affG));
        data.put("affGProofsHat", encodeAffGProofMap(affGhat));
        data.put("logProof", CggmpDkgCodec.encodePiLogProof(logProof));
        data.put("X", bytesToHex(Secp256k1Curve.encodePoint(X)));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R2, data));
    }

    private CompletableFuture<Void> broadcastPresignR3(Gg20SignatureTask task, BigInteger delta, ECPoint Delta, ECPoint S, PiLogProof logProof) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("delta", delta.toString(16));
        data.put("Delta", bytesToHex(Secp256k1Curve.encodePoint(Delta)));
        data.put("S", bytesToHex(Secp256k1Curve.encodePoint(S)));
        data.put("logProof", CggmpDkgCodec.encodePiLogProof(logProof));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R3, data));
    }

    private Map<String, String> encodeBigIntegerMap(Map<Integer, BigInteger> map) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<Integer, BigInteger> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue().toString(16));
        }
        return out;
    }

    private Map<Integer, BigInteger> decodeBigIntegerMap(Map<?, ?> map) {
        Map<Integer, BigInteger> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, new BigInteger(String.valueOf(e.getValue()), 16));
        }
        return out;
    }

    private Map<String, String> encodePointMap(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            ECPoint p = map.get(k);
            if (p == null) continue;
            out.put(String.valueOf(k), bytesToHex(p.getEncoded(false)));
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
            out.put(String.valueOf(k), bytesToHex(p.getEncoded(true)));
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

    private Map<String, Object> encodeAffGProofMap(Map<Integer, PiAffGProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiAffGProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpDkgCodec.encodePiAffGProof(e.getValue()));
        }
        return out;
    }

    private Map<Integer, PiAffGProof> decodeAffGProofMap(Map<?, ?> map) {
        Map<Integer, PiAffGProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpDkgCodec.decodePiAffGProof((Map<?, ?>) e.getValue()));
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

    private ECPoint sumPresignGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : task.presignGamma.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private ECPoint sumPoints(Map<Integer, ECPoint> points) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : points.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private static byte[] buildPresignContext(String taskId, int senderId, String round) {
        String sid = buildSignSid(taskId);
        String ctx = "PRESIGN:" + round + ":" + sid + ":" + senderId;
        return ctx.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private BigInteger resolveSignShift(Gg20SignatureTask task, BigInteger q) {
        if (!hdEnabled) {
            return BigInteger.ZERO;
        }
        return deriveShiftFromChainCode(task, q);
    }

    private BigInteger deriveShiftFromChainCode(Gg20SignatureTask task, BigInteger q) {
        if (task == null || task.chainCode == null || task.messageHash == null) {
            return BigInteger.ZERO;
        }
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(task.chainCode, "HmacSHA256");
            mac.init(key);
            byte[] out = mac.doFinal(task.messageHash);
            return new BigInteger(1, out).mod(q);
        } catch (Exception e) {
            logger.warn("Failed to derive HD shift for task {}: {}", task.taskId, e.getMessage());
            return BigInteger.ZERO;
        }
    }

    private static BigInteger parseHexBigIntegerOrNull(String hex) {
        if (hex == null || hex.isBlank()) {
            return null;
        }
        try {
            String cleaned = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
            return new BigInteger(cleaned, 16);
        } catch (Exception e) {
            return null;
        }
    }

    private static String computePayloadHashHex(Map<?, ?> data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            updateDigest(md, data);
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute payload hash", e);
        }
    }

    private static String computePresignR1EchoHash(Gg20SignatureTask task) {
        try {
            String sid = buildSignSid(task.taskId);
            java.util.List<Integer> ids = new java.util.ArrayList<>(task.participants);
            java.util.Collections.sort(ids);
            List<java.util.List<Object>> payloads = new ArrayList<>();
            for (int id : ids) {
                BigInteger K = task.presignK.get(id);
                BigInteger G = task.presignG.get(id);
                ECPoint Y = task.presignY.get(id);
                ECPoint A1 = task.presignA1.get(id);
                ECPoint A2 = task.presignA2.get(id);
                ECPoint B1 = task.presignB1.get(id);
                ECPoint B2 = task.presignB2.get(id);
                if (K == null || G == null || Y == null || A1 == null || A2 == null || B1 == null || B2 == null) {
                    return null;
                }
                java.util.List<Object> entry = new java.util.ArrayList<>(8);
                entry.add(id);
                entry.add(K.toString(16));
                entry.add(G.toString(16));
                entry.add(HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Y)));
                entry.add(HexUtils.bytesToHex(Secp256k1Curve.encodePoint(A1)));
                entry.add(HexUtils.bytesToHex(Secp256k1Curve.encodePoint(A2)));
                entry.add(HexUtils.bytesToHex(Secp256k1Curve.encodePoint(B1)));
                entry.add(HexUtils.bytesToHex(Secp256k1Curve.encodePoint(B2)));
                payloads.add(entry);
            }
            return computeTaggedHashHex("PRESIGN_R1_ECHO", sid, payloads);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute presign R1 echo hash", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void updateDigest(MessageDigest md, Object value) {
        if (value == null) {
            md.update((byte) 0);
            return;
        }
        if (value instanceof byte[] bytes) {
            md.update((byte) 4);
            updateLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (value instanceof Map<?, ?> map) {
            md.update((byte) 1);
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            updateLength(md, keys.size());
            for (String k : keys) {
                updateDigest(md, k);
                updateDigest(md, map.get(k));
            }
            return;
        }
        if (value instanceof Iterable<?> it) {
            md.update((byte) 2);
            int count = 0;
            for (Object ignored : it) {
                count++;
            }
            updateLength(md, count);
            for (Object o : it) {
                updateDigest(md, o);
            }
            return;
        }
        if (value instanceof Number n) {
            md.update((byte) 5);
            byte[] bytes = String.valueOf(n).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            updateLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        md.update((byte) 3);
        byte[] bytes = String.valueOf(value).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        updateLength(md, bytes.length);
        md.update(bytes);
    }

    private static void updateLength(MessageDigest md, int length) {
        md.update((byte) ((length >>> 24) & 0xFF));
        md.update((byte) ((length >>> 16) & 0xFF));
        md.update((byte) ((length >>> 8) & 0xFF));
        md.update((byte) (length & 0xFF));
    }

    private static String buildSid(String executionId, String taskId) {
        return "CGGMP24:" + executionId + ":" + taskId;
    }

    private static String buildSignSid(String taskId) {
        return "CGGMP24:SIGN:" + taskId;
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

    private CompletableFuture<Void> sendOfflineReady(Gg20SignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_OFFLINE_READY, data));
    }

    private void markOfflineReady(Gg20SignatureTask task, int senderId) {
        if (task.offlineReady.putIfAbsent(senderId, Boolean.TRUE) == null) {
            if (task.offlineReadyLatch.getCount() > 0) {
                task.offlineReadyLatch.countDown();
            }
        }
    }

    private void initSignaturePaillier(Gg20SignatureTask task) {
        if (task.paillier == null) {
            task.paillier = new PaillierEncryption();
        }
        if (task.zkSetup == null) {
            task.zkSetup = ZKSetup.generate(task.paillier.getPublicKeyInfo().bitLength);
        }
    }

    public Map<String, Object> runProofSelfCheck() {
        Map<String, Object> result = new HashMap<>();
        result.put("kappa", proofKappa);
        result.put("epsBits", proofEpsBits);
        try {
            SecureRandom rnd = new SecureRandom();
            BigInteger q = Secp256k1Curve.n();

            int selfCheckKeyBits = 1024;
            // PiDec self-check
            PaillierEncryption paillier = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk = paillier.getPublicKeyInfo();
            BigInteger x = randomNonZero(q);
            BigInteger y = randomNonZero(q);
            PaillierEncryption.Encryption encX = pk.encryptWithRandomness(x);
            BigInteger K = encX.c;
            BigInteger rho = BigIntegerUtils.randomZnStar(pk.n, rnd);
            BigInteger encY = pk.encryptWithRandom(y, rho);
            BigInteger KInvX = BigIntegerUtils.powSigned(K, x.negate(), pk.nSquared);
            BigInteger D = encY.multiply(KInvX).mod(pk.nSquared);
            ECPoint X = Secp256k1Curve.multiply(Secp256k1Curve.G(), x);
            ECPoint S = Secp256k1Curve.multiply(Secp256k1Curve.G(), y);
            PiDecProof decProof = PresignProofs.createDecProof(
                    Secp256k1Curve.G(),
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    x,
                    y,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean decOk = PresignProofs.verifyDecProof(
                    decProof,
                    Secp256k1Curve.G(),
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piDecOk", decOk);

            // PiAffG self-check
            PaillierEncryption paillier0 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption paillier1 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk0 = paillier0.getPublicKeyInfo();
            PaillierEncryption.PublicKey pk1 = paillier1.getPublicKeyInfo();
            BigInteger x2 = randomNonZero(q);
            BigInteger y2 = randomNonZero(q);
            BigInteger a = randomNonZero(q);
            PaillierEncryption.Encryption encC = pk0.encryptWithRandomness(a);
            BigInteger C = encC.c;
            BigInteger rho2 = BigIntegerUtils.randomZnStar(pk0.n, rnd);
            BigInteger mu2 = BigIntegerUtils.randomZnStar(pk1.n, rnd);
            BigInteger D2 = BigIntegerUtils.powSigned(C, x2, pk0.nSquared)
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(pk0.n), y2, pk0.nSquared))
                    .multiply(rho2.modPow(pk0.n, pk0.nSquared))
                    .mod(pk0.nSquared);
            BigInteger Y2 = pk1.encryptWithRandom(y2, mu2);
            ECPoint X2 = Secp256k1Curve.multiply(Secp256k1Curve.G(), x2);
            PiAffGProof affProof = PresignProofs.createAffGProof(
                    Secp256k1Curve.G(),
                    X2,
                    pk0.n,
                    pk1.n,
                    C,
                    D2,
                    Y2,
                    x2,
                    y2,
                    rho2,
                    mu2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean affOk = PresignProofs.verifyAffGProof(
                    affProof,
                    Secp256k1Curve.G(),
                    X2,
                    pk0.n,
                    pk1.n,
                    C,
                    D2,
                    Y2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piAffGOk", affOk);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    private BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1Curve.n());
    }

    private SignatureBundle signMessage(BigInteger privateKey, byte[] messageHash, ECPoint publicKey) {
        ECDomainParameters domain = buildDomain();
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(privateKey, domain);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priv);
        BigInteger[] sig = signer.generateSignature(messageHash);
        BigInteger r = sig[0];
        BigInteger s = sig[1];
        BigInteger n = Secp256k1Curve.n();
        if (s.compareTo(n.shiftRight(1)) > 0) {
            s = n.subtract(s);
        }

        byte[] der = derEncodeSignature(r, s);
        boolean verified = verifySignature(publicKey, messageHash, r, s, domain);
        String signatureBase64 = Base64.getEncoder().encodeToString(der);
        return new SignatureBundle(signatureBase64, verified);
    }

    private boolean verifySignature(ECPoint publicKey, byte[] messageHash, BigInteger r, BigInteger s, ECDomainParameters domain) {
        ECDSASigner verifier = new ECDSASigner();
        ECPublicKeyParameters pub = new ECPublicKeyParameters(publicKey, domain);
        verifier.init(false, pub);
        return verifier.verifySignature(messageHash, r, s);
    }

    private byte[] derEncodeSignature(BigInteger r, BigInteger s) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode DER signature", e);
        }
    }

    private ECDomainParameters buildDomain() {
        return new ECDomainParameters(
                Secp256k1Curve.G().getCurve(),
                Secp256k1Curve.G(),
                Secp256k1Curve.n(),
                BigInteger.ONE
        );
    }

    private BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    private static BigInteger negateModN(BigInteger value, BigInteger n) {
        BigInteger v = value.mod(n);
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        return n.subtract(v);
    }

    private static BigInteger lagrangeCoefficientAtZero(int id, Set<Integer> participants, java.util.Map<Integer, BigInteger> indexMap, BigInteger mod) {
        if (participants == null || participants.isEmpty()) {
            throw new IllegalArgumentException("Participants set is empty");
        }
        BigInteger num = BigInteger.ONE;
        BigInteger den = BigInteger.ONE;
        BigInteger idBi = indexMap != null && indexMap.get(id) != null ? indexMap.get(id) : BigInteger.valueOf(id);
        for (int peerId : participants) {
            if (peerId == id) {
                continue;
            }
            BigInteger peerBi = indexMap != null && indexMap.get(peerId) != null ? indexMap.get(peerId) : BigInteger.valueOf(peerId);
            num = num.multiply(peerBi).mod(mod);
            BigInteger diff = peerBi.subtract(idBi).mod(mod);
            den = den.multiply(diff).mod(mod);
        }
        return num.multiply(den.modInverse(mod)).mod(mod);
    }

    private static boolean signatureUsesLagrange(Gg20SignatureTask task) {
        return task.threshold < task.nodesCount;
    }

    private static BigInteger computeSignatureLagrange(Gg20SignatureTask task, int signerId, BigInteger mod) {
        if (task == null) {
            return BigInteger.ONE;
        }
        if (!signatureUsesLagrange(task)) {
            return BigInteger.ONE;
        }
        return lagrangeCoefficientAtZero(signerId, task.participants, task.indexMap, mod);
    }

    private static BigInteger decodeSigned(BigInteger value, BigInteger n) {
        BigInteger half = n.shiftRight(1);
        return value.compareTo(half) > 0 ? value.subtract(n) : value;
    }

    private ECPoint resolvePublicShare(Gg20SignatureTask task, int signerId, BigInteger lambda, BigInteger x_i) {
        if (task.publicShares != null) {
            ECPoint base = task.publicShares.get(signerId);
            if (base != null) {
                return base.multiply(lambda).normalize();
            }
        }
        return Secp256k1Curve.G().multiply(x_i).normalize();
    }

    private ECPoint resolvePublicShareFromMap(Gg20SignatureTask task, int signerId, BigInteger lambda) {
        if (task.publicShares == null) {
            return null;
        }
        ECPoint base = task.publicShares.get(signerId);
        if (base == null) {
            return null;
        }
        return base.multiply(lambda).normalize();
    }

    private Map<Integer, ECPoint> parsePublicShares(String json) {
        Map<String, String> raw = parseStringMap(json);
        Map<Integer, ECPoint> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            int key = Integer.parseInt(e.getKey());
            out.put(key, Secp256k1Curve.decodePoint(HexUtils.hexToBytes(e.getValue())));
        }
        return out;
    }

    private Map<Integer, BigInteger> parseIndexMap(String json) {
        Map<String, String> raw = parseStringMap(json);
        Map<Integer, BigInteger> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            int key = Integer.parseInt(e.getKey());
            out.put(key, new BigInteger(e.getValue(), 10));
        }
        return out;
    }

    private Map<String, String> parseStringMap(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null) {
            return out;
        }
        String s = json.trim();
        if (s.startsWith("{")) {
            s = s.substring(1);
        }
        if (s.endsWith("}")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isBlank()) {
            return out;
        }
        java.util.List<String> parts = splitTopLevel(s);
        for (String part : parts) {
            int idx = part.indexOf(':');
            if (idx <= 0) continue;
            String k = stripQuotes(part.substring(0, idx).trim());
            String v = stripQuotes(part.substring(idx + 1).trim());
            out.put(k, v);
        }
        return out;
    }

    private static java.util.List<String> splitTopLevel(String s) {
        java.util.List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                inQuotes = !inQuotes;
            }
            if (c == ',' && !inQuotes) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) {
            parts.add(cur.toString());
        }
        return parts;
    }

    private static String stripQuotes(String s) {
        String out = s;
        if (out.startsWith("\"") && out.endsWith("\"") && out.length() >= 2) {
            out = out.substring(1, out.length() - 1);
        }
        return out.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static BigInteger challenge(String tag, BigInteger q, byte[] context, Object... items) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            for (Object o : items) {
                if (o == null) continue;
                if (o instanceof BigInteger bi) {
                    md.update(bi.toByteArray());
                } else if (o instanceof ECPoint p) {
                    md.update(Secp256k1Curve.encodePoint(p));
                } else {
                    md.update(String.valueOf(o).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            BigInteger twoQ = q.shiftLeft(1);
            BigInteger e = new BigInteger(1, md.digest()).mod(twoQ);
            return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
        } catch (Exception e) {
            throw new RuntimeException("Schnorr challenge failed", e);
        }
    }

    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static void updatePointMap(MessageDigest md, Map<Integer, ECPoint> map) {
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            md.update(BigInteger.valueOf(k).toByteArray());
            md.update(Secp256k1Curve.encodePoint(map.get(k)));
        }
    }

    private BigInteger lagrangeCoefficient(int i, Set<Integer> participants, BigInteger n) {
        BigInteger result = BigInteger.ONE;
        for (int j : participants) {
            if (j == i) continue;
            BigInteger numerator = BigInteger.valueOf(-j).mod(n);
            BigInteger denominator = BigInteger.valueOf(i - j).modInverse(n);
            result = result.multiply(numerator).multiply(denominator).mod(n);
        }
        return result;
    }

    private ECPoint sumGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : task.gammaPoints.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private BigInteger sumShares(Map<Integer, BigInteger> shares, BigInteger mod) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger v : shares.values()) {
            if (v == null) continue;
            sum = sum.add(v);
        }
        return sum.mod(mod);
    }

    private CompletableFuture<Void> broadcastGammaCommitment(Gg20SignatureTask task, ECPoint commitment, BigInteger gammaValue, BigInteger blinding) {
        byte[] ctx = buildSignContext(task.taskId, nodeId, task.messageHash, "GAMMA-COMMIT");
        EcChaumPedersenProof proof = EcChaumPedersenProof.create(gammaValue, blinding, commitment, ctx);
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("commit", bytesToHex(Secp256k1Curve.encodePoint(commitment)));
        data.put("proofA", bytesToHex(Secp256k1Curve.encodePoint(proof.A())));
        data.put("proofR", proof.r().toString(16));
        data.put("proofS", proof.s().toString(16));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_GAMMA_COMMIT, data));
    }

    private CompletableFuture<Void> broadcastGammaOpen(Gg20SignatureTask task, ECPoint gamma, BigInteger blinding) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("gamma", bytesToHex(Secp256k1Curve.encodePoint(gamma)));
        data.put("r", blinding.toString(16));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_GAMMA_OPEN, data));
    }

    private CompletableFuture<Void> broadcastMtaKaInit(Gg20SignatureTask task) {
        MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (int participantId : task.participants) {
            if (participantId == nodeId) {
                continue;
            }
            byte[] mtaContext = buildMtaContext(task.taskId + ":KA", nodeId, participantId);
            MtAInitiatorMessage initiatorMessage = protocol.generateInitiatorMessage(task.k_i, task.zkSetup, mtaContext);
            task.mtaKaInitiatorMessages.put(participantId, initiatorMessage);

            Map<String, Object> data = new HashMap<>();
            data.put("taskId", task.taskId);
            data.put("initiatorId", nodeId);
            data.put("receiverId", participantId);
            data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
            data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
            data.put("initiatorMessage", CggmpDkgCodec.encodeMtAInitiatorMessage(initiatorMessage));
            futures.add(nodeService.sendMessage(participantId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_KA_INIT, data)));
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    private CompletableFuture<Void> broadcastMtaStInit(Gg20SignatureTask task) {
        MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (int participantId : task.participants) {
            if (participantId == nodeId) {
                continue;
            }
            byte[] mtaContext = buildMtaContext(task.taskId + ":ST", nodeId, participantId);
            MtAInitiatorMessage initiatorMessage = protocol.generateInitiatorMessage(task.kInv_i, task.zkSetup, mtaContext);
            task.mtaStInitiatorMessages.put(participantId, initiatorMessage);

            Map<String, Object> data = new HashMap<>();
            data.put("taskId", task.taskId);
            data.put("initiatorId", nodeId);
            data.put("receiverId", participantId);
            data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
            data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
            data.put("initiatorMessage", CggmpDkgCodec.encodeMtAInitiatorMessage(initiatorMessage));
            futures.add(nodeService.sendMessage(participantId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_ST_INIT, data)));
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    private BigInteger computeUShare(Gg20SignatureTask task, BigInteger mod) {
        BigInteger u = task.k_i.multiply(task.a_i).mod(mod);
        for (BigInteger alpha : task.kaAlphas.values()) {
            u = u.add(alpha);
        }
        for (BigInteger beta : task.kaBetas.values()) {
            u = u.add(beta);
        }
        return u.mod(mod);
    }

    private BigInteger computeSShare(Gg20SignatureTask task, BigInteger mod) {
        BigInteger s = task.kInv_i.multiply(task.t_i).mod(mod);
        for (BigInteger alpha : task.stAlphas.values()) {
            s = s.add(alpha);
        }
        for (BigInteger beta : task.stBetas.values()) {
            s = s.add(beta);
        }
        return s.mod(mod);
    }

    private CompletableFuture<Void> sendUShare(Gg20SignatureTask task, BigInteger u_i) {
        return sendUShare(task, u_i, randomNonZero(Secp256k1Curve.n()));
    }

    private CompletableFuture<Void> sendUShare(Gg20SignatureTask task, BigInteger u_i, BigInteger r) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("u", u_i.toString(16));
        data.put("r", r.toString(16));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_SHARE, data));
    }

    private CompletableFuture<Void> sendUCommit(Gg20SignatureTask task, BigInteger u_i, BigInteger r) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("commit", commitU(task.taskId, nodeId, task.messageHash, u_i, r));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_COMMIT, data));
    }

    private CompletableFuture<Void> broadcastUOpen(Gg20SignatureTask task, BigInteger u) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("u", u.toString(16));
        data.put("senderId", nodeId);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_OPEN, data));
    }

    private CompletableFuture<Void> sendSShare(Gg20SignatureTask task, BigInteger s_i) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("s", s_i.toString(16));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_S_SHARE, data));
    }

    private String commitU(String taskId, int senderId, byte[] messageHash, BigInteger u, BigInteger r) {
        int nLen = (Secp256k1Curve.n().bitLength() + 7) / 8;
        byte[] uBytes = BigIntegerUtils.toUnsignedBytes(u, nLen);
        byte[] rBytes = BigIntegerUtils.toUnsignedBytes(r, nLen);
        byte[] ctx = buildSignContext(taskId, senderId, messageHash, "U-COMMIT");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ctx);
            digest.update(uBytes);
            digest.update(rBytes);
            byte[] out = digest.digest();
            return bytesToHex(out);
        } catch (Exception e) {
            throw new RuntimeException("U commit hash failed", e);
        }
    }

    private static byte[] buildSignContext(String taskId, int senderId, byte[] messageHash, String stage) {
        String prefix = stage + ":" + taskId + ":" + senderId + ":";
        byte[] p = prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (messageHash == null) {
            return p;
        }
        byte[] out = new byte[p.length + messageHash.length];
        System.arraycopy(p, 0, out, 0, p.length);
        System.arraycopy(messageHash, 0, out, p.length, messageHash.length);
        return out;
    }

    private static final class SignatureBundle {
        private final String signatureBase64;
        private final boolean verified;

        private SignatureBundle(String signatureBase64, boolean verified) {
            this.signatureBase64 = signatureBase64;
            this.verified = verified;
        }
    }

    private KeyShare loadKeyShareByGroupPublicKeySync(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }

    private ECPoint decodeECPoint(byte[] encoded) {
        return Secp256k1Curve.decodePoint(encoded);
    }

    private boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return false;
        }
        BigInteger q = Secp256k1Curve.n();
        return publicKey.n.compareTo(q.pow(8)) >= 0;
    }

    private boolean ensurePeerKeyConsistency(Gg20SignatureTask task, int peerId, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup) {
        PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.putIfAbsent(peerId, publicKey);
        if (existingKey != null && !paillierPublicKeyEquals(existingKey, publicKey)) {
            return false;
        }
        ZKSetup existingZk = task.peerZkSetups.putIfAbsent(peerId, zkSetup);
        if (existingZk != null && !existingZk.equals(zkSetup)) {
            return false;
        }
        return true;
    }

    private boolean paillierPublicKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return a.n.equals(b.n) && a.nSquared.equals(b.nSquared) && a.g.equals(b.g) && a.bitLength == b.bitLength;
    }

    private void failSignatureTask(Gg20SignatureTask task, String reason) {
        if (task == null || task.isCompleted() || task.isFailed()) {
            return;
        }
        task.fail(reason);
        signatureInProgress.set(false);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            } else if (map.containsKey("signatureTaskId")) {
                logTaskId = map.get("signatureTaskId");
            }
        }
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, logTaskId);
        Executor executor = ThreadPoolUtil.getSingleThreadPool();        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data;
                logger.info("=== CGGMP processing: type={} ===", message.type);
                switch (message.type) {                    case GG20_SIGN_INIT:
                        handleCggmpSignOfflineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_OFFLINE_INIT:
                        handleCggmpSignOfflineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_ONLINE_INIT:
                        handleCggmpSignOnlineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_OFFLINE_READY:
                        handleCggmpSignOfflineReady(senderId, data);
                        break;
                    case CGGMP_SIGN_COMPLAINT:
                        handleCggmpSignComplaint(senderId, data);
                        break;
                    case CGGMP_SIGN_EXCLUDE:
                        handleCggmpSignExclude(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R1:
                        handlePresignR1(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R1_ECHO:
                        handlePresignR1Echo(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R2:
                        handlePresignR2(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R3:
                        handlePresignR3(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_COMMIT:
                        handleCggmpSignGammaCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_OPEN:
                        handleCggmpSignGammaOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_INIT:
                        handleCggmpSignMtaKaInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_RESPONSE:
                        handleCggmpSignMtaKaResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_U_COMMIT:
                        handleCggmpSignUCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_U_SHARE:
                        handleCggmpSignUShare(senderId, data);
                        break;
                    case CGGMP_SIGN_U_OPEN:
                        handleCggmpSignUOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_INIT:
                        handleCggmpSignMtaStInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_RESPONSE:
                        handleCggmpSignMtaStResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_S_SHARE:
                        handleCggmpSignSShare(senderId, data);
                        break;                    default:
                        logger.debug("Ignoring message of type {} for CGGMP service", message.type);
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }

    private void handleCggmpSignOfflineInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String signatureTaskId = (String) dataMap.get("signatureTaskId");
            String groupPublicKey = (String) dataMap.get("groupPublicKey");
            String msg = (String) dataMap.get("message");
            Integer initiatorId = null;
            Object initiatorValue = dataMap.get("initiatorId");
            if (initiatorValue instanceof Number) {
                initiatorId = ((Number) initiatorValue).intValue();
            }
            List<Integer> participants = null;
            Object participantsValue = dataMap.get("participants");
            if (participantsValue instanceof List<?> list) {
                participants = new ArrayList<>();
                for (Object v : list) {
                    if (v instanceof Number n) {
                        participants.add(n.intValue());
                    }
                }
            }
            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                if (!signatureTasks.containsKey(signatureTaskId)) {
                    int resolvedInitiatorId = initiatorId != null ? initiatorId : senderId;
                    Set<Integer> participantsSet = participants == null ? null : new LinkedHashSet<>(participants);
                    createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg, resolvedInitiatorId, participantsSet);
                    logger.info("Created CGGMP signature task from OFFLINE_INIT: {}", signatureTaskId);
                    CompletableFuture.runAsync(() -> {
                        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
                        if (task == null) {
                            return;
                        }
                        if (!task.participants.contains(nodeId)) {
                            logger.info("Node {} not selected for CGGMP signature task {}, participants={}, skipping", nodeId, signatureTaskId, task.participants);
                            return;
                        }
                        task.start();
                        initSignatureContext(task);
                        runOfflinePhase(task).exceptionally(ex -> {
                            logger.error("Failed offline phase for signature task {}: {}", signatureTaskId, ex.getMessage());
                            return null;
                        });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    logger.info("Signature task {} already exists, ignoring OFFLINE_INIT", signatureTaskId);
                }
            } else {
                logger.warn("Invalid OFFLINE_INIT payload from node {}", senderId);
            }
        }
    }

    private void handleCggmpSignOnlineInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object hashValue = dataMap.get("messageHash");
        if (signatureTaskId == null || !(hashValue instanceof String hashString)) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        task.messageHash = Base64.getDecoder().decode(hashString);
        if (!task.participants.contains(nodeId)) {
            return;
        }
        runOnlinePhase(task).exceptionally(ex -> {
            logger.error("Failed online phase for signature task {}: {}", signatureTaskId, ex.getMessage());
            return null;
        });
    }

    private void handlePresignR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String kHex = (String) dataMap.get("K");
        String gHex = (String) dataMap.get("G");
        String yHex = (String) dataMap.get("Y");
        String a1Hex = (String) dataMap.get("A1");
        String a2Hex = (String) dataMap.get("A2");
        String b1Hex = (String) dataMap.get("B1");
        String b2Hex = (String) dataMap.get("B2");
        Map<?, ?> encElgKMap = (Map<?, ?>) dataMap.get("encElgProofK");
        Map<?, ?> encElgGMap = (Map<?, ?>) dataMap.get("encElgProofG");
        Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
        Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
        if (signatureTaskId == null || senderValue == null || kHex == null || gHex == null
                || yHex == null || a1Hex == null || a2Hex == null || b1Hex == null || b2Hex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            return;
        }
        if (pkMap == null || zkMap == null) {
            return;
        }
        BigInteger K = new BigInteger(kHex, 16);
        BigInteger G = new BigInteger(gHex, 16);
        ECPoint Y = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(yHex));
        ECPoint A1 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(a1Hex));
        ECPoint A2 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(a2Hex));
        ECPoint B1 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(b1Hex));
        ECPoint B2 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(b2Hex));
        PiEncElgProof encElgK = encElgKMap == null ? null : CggmpDkgCodec.decodePiEncElgProof(encElgKMap);
        PiEncElgProof encElgG = encElgGMap == null ? null : CggmpDkgCodec.decodePiEncElgProof(encElgGMap);
        PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
        ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
        if (!ensurePeerKeyConsistency(task, senderId, publicKey, zkSetup)) {
            fireAndForget(broadcastComplaint(task, senderId, "Inconsistent Paillier key/zkSetup (presign R1)", Map.of("paillierPublicKey", pkMap, "zkSetup", zkMap)),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Inconsistent Paillier key/zkSetup (presign R1)");
            return;
        }
        byte[] ctxK = buildPresignContext(task.taskId, senderId, "R1K");
        PresignProofs.EncElgVerifyResult encElgKResult = PresignProofs.verifyEncElgProofDetailed(
                encElgK, publicKey, zkSetup, Secp256k1Curve.G(), A1, Y, A2, K, proofEpsBits, ctxK);
        if (!encElgKResult.ok()) {
            logger.warn("Invalid PiEncElg proof (K) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgKResult.eq1(), encElgKResult.eq2(), encElgKResult.eq3(), encElgKResult.eq4(), encElgKResult.z1InRange());
            fireAndForget(broadcastComplaint(task, senderId, "Invalid PiEncElg proof (K)", Map.of("K", kHex)),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Invalid PiEncElg proof (K)");
            return;
        }
        byte[] ctxG = buildPresignContext(task.taskId, senderId, "R1G");
        PresignProofs.EncElgVerifyResult encElgGResult = PresignProofs.verifyEncElgProofDetailed(
                encElgG, publicKey, zkSetup, Secp256k1Curve.G(), B1, Y, B2, G, proofEpsBits, ctxG);
        if (!encElgGResult.ok()) {
            logger.warn("Invalid PiEncElg proof (G) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgGResult.eq1(), encElgGResult.eq2(), encElgGResult.eq3(), encElgGResult.eq4(), encElgGResult.z1InRange());
            fireAndForget(broadcastComplaint(task, senderId, "Invalid PiEncElg proof (G)", Map.of("G", gHex)),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Invalid PiEncElg proof (G)");
            return;
        }
        task.presignK.put(senderId, K);
        task.presignG.put(senderId, G);
        task.presignY.put(senderId, Y);
        task.presignA1.put(senderId, A1);
        task.presignA2.put(senderId, A2);
        task.presignB1.put(senderId, B1);
        task.presignB2.put(senderId, B2);
        if (task.presignR1Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.gammaCommitLatch.getCount() > 0) {
            task.gammaCommitLatch.countDown();
        }
        if (presignEchoEnabled) {
            validatePendingPresignR1Echo(task);
        }
        Map<String, Object> pendingR2 = task.pendingPresignR2.remove(senderId);
        if (pendingR2 != null) {
            processPresignR2(task, senderId, pendingR2);
        }
        Map<String, Object> pendingR3 = task.pendingPresignR3.remove(senderId);
        if (pendingR3 != null) {
            processPresignR3(task, senderId, pendingR3);
        }
    }

    private void handlePresignR1Echo(int senderId, Object data) {
        if (!presignEchoEnabled) {
            return;
        }
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String hash = (String) dataMap.get("hash");
        if (signatureTaskId == null || senderValue == null || hash == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            return;
        }
        String expected = computePresignR1EchoHash(task);
        if (expected == null) {
            task.pendingPresignR1Echo.put(senderId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            fireAndForget(broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                    Map.of("senderId", senderId, "expected", expected, "received", hash)),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Presign R1 echo mismatch from node " + senderId);
            return;
        }
        if (task.presignR1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR1EchoLatch.getCount() > 0) {
            task.presignR1EchoLatch.countDown();
        }
    }

    private void validatePendingPresignR1Echo(Gg20SignatureTask task) {
        if (task == null || task.pendingPresignR1Echo.isEmpty()) {
            return;
        }
        String expected = computePresignR1EchoHash(task);
        if (expected == null) {
            return;
        }
        for (Map.Entry<Integer, String> e : new HashMap<>(task.pendingPresignR1Echo).entrySet()) {
            int senderId = e.getKey();
            String hash = e.getValue();
            if (!expected.equals(hash)) {
                fireAndForget(broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                        Map.of("senderId", senderId, "expected", expected, "received", hash)),
                        "CGGMP_PRESIGN_COMPLAINT");
                failSignatureTask(task, "Presign R1 echo mismatch from node " + senderId);
                return;
            }
            task.pendingPresignR1Echo.remove(senderId);
            if (task.presignR1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null
                    && task.presignR1EchoLatch.getCount() > 0) {
                task.presignR1EchoLatch.countDown();
            }
        }
    }

    private void handlePresignR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String gammaHex = (String) dataMap.get("Gamma");
        if (signatureTaskId == null || senderValue == null || gammaHex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            logger.info("Skip CGGMP_PRESIGN_R2 for task {} on node {} (not a participant, participants={})",
                    task.taskId, nodeId, task.participants);
            return;
        }
        processPresignR2(task, senderId, dataMap);
    }

    @SuppressWarnings("unchecked")
    private void processPresignR2(Gg20SignatureTask task, int senderId, Map<?, ?> dataMap) {
        String gammaHex = (String) dataMap.get("Gamma");
        if (gammaHex == null) {
            return;
        }
        Map<?, ?> dMap = (Map<?, ?>) dataMap.get("D");
        Map<?, ?> dhMap = (Map<?, ?>) dataMap.get("Dhat");
        Map<?, ?> fMap = (Map<?, ?>) dataMap.get("F");
        Map<?, ?> fhMap = (Map<?, ?>) dataMap.get("Fhat");
        Map<?, ?> affGMap = (Map<?, ?>) dataMap.get("affGProofs");
        Map<?, ?> affGhatMap = (Map<?, ?>) dataMap.get("affGProofsHat");
        Map<?, ?> logProofMap = (Map<?, ?>) dataMap.get("logProof");
        String xHex = (String) dataMap.get("X");
        if (dMap == null || dhMap == null || fMap == null || fhMap == null) {
            return;
        }
        BigInteger curveOrder = Secp256k1Curve.n();
        ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
        task.presignGamma.put(senderId, Gamma);
        Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> Dhat = decodeBigIntegerMap(dhMap);
        Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
        Map<Integer, BigInteger> Fhat = decodeBigIntegerMap(fhMap);
        BigInteger dForNode = D.get(nodeId);
        BigInteger dhatForNode = Dhat.get(nodeId);
        logger.info("Presign R2 received for task {} from {}: D keys={}, Dhat keys={}, D[node]={}, Dhat[node]={}",
                task.taskId,
                senderId,
                D.keySet(),
                Dhat.keySet(),
                dForNode == null ? null : dForNode.toString(16),
                dhatForNode == null ? null : dhatForNode.toString(16));
        PiLogProof logProof = logProofMap == null ? null : CggmpDkgCodec.decodePiLogProof(logProofMap);
        byte[] ctx = buildPresignContext(task.taskId, senderId, "R2");
        ECPoint Y = task.presignY.get(senderId);
        ECPoint B1 = task.presignB1.get(senderId);
        ECPoint B2 = task.presignB2.get(senderId);
        if (Y == null || B1 == null || B2 == null) {
            task.pendingPresignR2.put(senderId, new HashMap<String, Object>((Map<String, Object>) dataMap));
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1Curve.G(), Secp256k1Curve.G(), Gamma, Y, B1, B2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Gamma", gammaHex);
            ev.put("D", dMap);
            ev.put("F", fMap);
            fireAndForget(broadcastComplaint(task, senderId, "Invalid PiLog proof (R2)", ev),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Invalid presign R2 proof");
            return;
        }

        ECPoint expectedX = null;
        BigInteger lambdaSender = computeSignatureLagrange(task, senderId, curveOrder);
        if (task.publicShares != null) {
            expectedX = resolvePublicShareFromMap(task, senderId, lambdaSender);
        }
        if (expectedX != null && xHex != null) {
            ECPoint provided = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            if (!expectedX.equals(provided)) {
                Map<String, Object> ev = new HashMap<>();
                ev.put("expectedX", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(expectedX)));
                ev.put("providedX", xHex);
                fireAndForget(broadcastComplaint(task, senderId, "Invalid X in presign R2", ev),
                        "CGGMP_PRESIGN_COMPLAINT");
                failSignatureTask(task, "Invalid X in presign R2 from node " + senderId);
                return;
            }
        }
        ECPoint X_i_resolved = expectedX;
        if (X_i_resolved == null && xHex != null) {
            X_i_resolved = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
        }
        if (X_i_resolved == null) {
            fireAndForget(broadcastComplaint(task, senderId, "Missing X in presign R2", Map.of("senderId", senderId)),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Missing X in presign R2 from node " + senderId);
            return;
        }

        if (affGMap != null && affGhatMap != null) {
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(affGMap);
            Map<Integer, PiAffGProof> proofsHat = decodeAffGProofMap(affGhatMap);
            PiAffGProof proof = proofs.get(nodeId);
            PiAffGProof proofHat = proofsHat.get(nodeId);
            BigInteger D_ji = D.get(nodeId);
            BigInteger F_ji = F.get(nodeId);
            BigInteger Dhat_ji = Dhat.get(nodeId);
            BigInteger Fhat_ji = Fhat.get(nodeId);
            BigInteger K_self = task.presignK.get(nodeId);
            PaillierEncryption.PublicKey N0 = task.paillier.getPublicKeyInfo();
            PaillierEncryption.PublicKey N1 = task.peerPaillierKeys.get(senderId);
            ECPoint X_i = X_i_resolved;
            if (K_self != null && D_ji != null && F_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        Gamma,
                        N0.n,
                        N1.n,
                        K_self,
                        D_ji,
                        F_ji,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "R2")
                );
                if (!affGResult.ok()) {
                    logger.warn("Invalid PiAffG proof from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGResult.index(), affGResult.eq1(), affGResult.eq2(),
                            affGResult.eq3(), affGResult.zInRange(), affGResult.zPrimeInRange());
                    fireAndForget(broadcastComplaint(task, senderId, "Invalid PiAffG proof", Map.of("D", dMap, "F", fMap)),
                            "CGGMP_PRESIGN_COMPLAINT");
                    failSignatureTask(task, "Invalid presign R2 affG proof");
                    return;
                }
            }
            if (K_self != null && Dhat_ji != null && Fhat_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGHatResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proofHat,
                        Secp256k1Curve.G(),
                        X_i,
                        N0.n,
                        N1.n,
                        K_self,
                        Dhat_ji,
                        Fhat_ji,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "R2H")
                );
                if (!affGHatResult.ok()) {
                    logger.warn("Invalid PiAffG proof (hat) from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGHatResult.index(), affGHatResult.eq1(), affGHatResult.eq2(),
                            affGHatResult.eq3(), affGHatResult.zInRange(), affGHatResult.zPrimeInRange());
                    fireAndForget(broadcastComplaint(task, senderId, "Invalid PiAffG proof (hat)", Map.of("Dhat", dhMap, "Fhat", fhMap)),
                            "CGGMP_PRESIGN_COMPLAINT");
                    failSignatureTask(task, "Invalid presign R2 affG hat proof");
                    return;
                }
            }
        }
        if (!D.containsKey(nodeId) || !Dhat.containsKey(nodeId)) {
            logger.warn("Presign R2 missing payload for receiver {} from sender {} (D or Dhat not found)", nodeId, senderId);
            return;
        }
        task.presignD.put(senderId, D.get(nodeId));
        task.presignDhat.put(senderId, Dhat.get(nodeId));
        if (F.containsKey(nodeId)) task.presignF.put(senderId, F.get(nodeId));
        if (Fhat.containsKey(nodeId)) task.presignFhat.put(senderId, Fhat.get(nodeId));
        if (task.presignR2Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR2Latch.getCount() > 0) {
            task.presignR2Latch.countDown();
        }
    }

    private void handlePresignR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String deltaHex = (String) dataMap.get("delta");
        String deltaPointHex = (String) dataMap.get("Delta");
        String sPointHex = (String) dataMap.get("S");
        if (signatureTaskId == null || senderValue == null || deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            return;
        }
        processPresignR3(task, senderId, dataMap);
    }

    @SuppressWarnings("unchecked")
    private void processPresignR3(Gg20SignatureTask task, int senderId, Map<?, ?> dataMap) {
        String deltaHex = (String) dataMap.get("delta");
        String deltaPointHex = (String) dataMap.get("Delta");
        String sPointHex = (String) dataMap.get("S");
        Map<?, ?> logProofMap = (Map<?, ?>) dataMap.get("logProof");
        if (deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        PiLogProof logProof = logProofMap == null ? null : CggmpDkgCodec.decodePiLogProof(logProofMap);
        ECPoint Delta = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(deltaPointHex));
        ECPoint S = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(sPointHex));
        byte[] ctx = buildPresignContext(task.taskId, senderId, "R3");
        if (task.presignR2Latch.getCount() > 0) {
            task.pendingPresignR3.put(senderId, new HashMap<String, Object>((Map<String, Object>) dataMap));
            return;
        }
        ECPoint Gamma = sumPresignGamma(task);
        ECPoint Y = task.presignY.get(senderId);
        ECPoint A1 = task.presignA1.get(senderId);
        ECPoint A2 = task.presignA2.get(senderId);
        if (Y == null || A1 == null || A2 == null) {
            task.pendingPresignR3.put(senderId, new HashMap<String, Object>((Map<String, Object>) dataMap));
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1Curve.G(), Gamma, Delta, Y, A1, A2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Delta", deltaPointHex);
            ev.put("S", sPointHex);
            fireAndForget(broadcastComplaint(task, senderId, "Invalid PiLog proof (R3)", ev),
                    "CGGMP_PRESIGN_COMPLAINT");
            failSignatureTask(task, "Invalid presign R3 proof");
            return;
        }
        if (task.presignR3Received.putIfAbsent(senderId, Boolean.TRUE) != null) {
            logger.warn("Duplicate presign R3 from node {} for task {}, ignoring", senderId, task.taskId);
            return;
        }
        task.presignDelta.put(senderId, new BigInteger(deltaHex, 16));
        task.presignDeltaPoint.put(senderId, Delta);
        task.presignSPoint.put(senderId, S);
        if (task.offlineDoneLatch.getCount() > 0) {
            task.offlineDoneLatch.countDown();
        }
    }

    private void handleCggmpSignOfflineReady(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        if (signatureTaskId == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        markOfflineReady(task, senderNodeId);
    }

    private void handleCggmpSignComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null || reason == null) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received complaint for task {} from node {} against {}: {}", signatureTaskId, senderId, offenderId, reason);
        logComplaintToFile(signatureTaskId, senderId, offenderId, reason, dataMap.get("evidence"));
        boolean evidenceOk = true;
        boolean hasProofEvidence = false;
        if (dataMap.get("evidence") instanceof Map<?, ?> ev) {
            hasProofEvidence = ev.containsKey("piDecProof") || ev.containsKey("affGProofs") || ev.containsKey("affGProofsHat");
            if (hasProofEvidence) {
                evidenceOk = verifyDecEvidence(task, senderId, ev) && verifyAffGEvidence(task, senderId, ev);
            }
        }
        if (hasProofEvidence && !evidenceOk) {
            String invalidReason = "Invalid proof evidence from sender " + senderId;
            logger.warn("Complaint evidence invalid; treating sender {} as offender", senderId);
            if (nodeId == task.initiatorId) {
                attemptExcludeAndRestart(task, senderId, invalidReason);
            } else {
                failSignatureTask(task, invalidReason);
            }
            return;
        }
        if (nodeId == task.initiatorId && offenderId != null) {
            attemptExcludeAndRestart(task, offenderId, reason);
        } else {
            failSignatureTask(task, "Complaint: " + reason);
        }
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason) {
        return broadcastComplaint(task, offenderId, reason, null);
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data));
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data));
    }

    private Map<String, Object> buildDecEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i, BigInteger delta_i) {
        try {
            BigInteger K = task.presignK.get(nodeId);
            if (K == null) return null;
            BigInteger D = computePresignDForSelf(task, task.presignD, task.presignFOutgoing);
            if (D == null) return null;
            ECPoint Gamma = task.presignGamma.get(nodeId);
            if (Gamma == null) {
                Gamma = Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i);
            }
            ECPoint S = Secp256k1Curve.multiply(Secp256k1Curve.G(), delta_i);
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, gamma_i).multiply(D).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, delta_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Secp256k1Curve.G(),
                    Gamma,
                    S,
                    task.paillier.getPublicKeyInfo().n,
                    K,
                    D,
                    gamma_i,
                    delta_i,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "DEC")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpDkgCodec.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(D));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(S)));
            Map<String, Object> affg = buildAffGEvidenceDelta(task, gamma_i, Gamma);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec delta evidence: {}", e.getMessage());
            return null;
        }
    }

    private Map<String, Object> buildDecEvidenceChi(Gg20SignatureTask task, BigInteger x_i, BigInteger chi_i) {
        try {
            BigInteger K = task.presignK.get(nodeId);
            if (K == null) return null;
            BigInteger Dhat = computePresignDForSelf(task, task.presignDhat, task.presignFhatOutgoing);
            if (Dhat == null) return null;
            ECPoint Gamma = sumPresignGamma(task);
            ECPoint X_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), x_i);
            ECPoint S = Gamma.multiply(chi_i).normalize();
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, x_i).multiply(Dhat).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, chi_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Gamma,
                    X_i,
                    S,
                    task.paillier.getPublicKeyInfo().n,
                    K,
                    Dhat,
                    x_i,
                    chi_i,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "DECH")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpDkgCodec.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(Dhat));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
            ev.put("X", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(X_i)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(S)));
            Map<String, Object> affg = buildAffGEvidenceChi(task, x_i, X_i);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec chi evidence: {}", e.getMessage());
            return null;
        }
    }

    private BigInteger computePresignDForSelf(Gg20SignatureTask task,
                                              Map<Integer, BigInteger> incomingD,
                                              Map<Integer, BigInteger> outgoingF) {
        BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
        BigInteger acc = BigInteger.ONE;
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            BigInteger d = incomingD.get(peerId);
            BigInteger f = outgoingF.get(peerId);
            if (d == null || f == null) {
                return null;
            }
            acc = acc.multiply(d).mod(nSquared);
            acc = acc.multiply(f).mod(nSquared);
        }
        return acc;
    }

    private boolean verifyDecEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        Object proofObj = evidence.get("piDecProof");
        if (!(proofObj instanceof Map<?, ?> proofMap)) {
            return false;
        }
        try {
            PiDecProof proof = CggmpDkgCodec.decodePiDecProof(proofMap);
            String kHex = (String) evidence.get("K");
            String dHex = (String) evidence.get("D");
            String gammaHex = (String) evidence.get("Gamma");
            String xHex = (String) evidence.get("X");
            String sHex = (String) evidence.get("S");
            if (kHex == null || dHex == null || gammaHex == null || sHex == null) {
                return false;
            }
            BigInteger K = HexUtils.fromHex(kHex);
            BigInteger D = HexUtils.fromHex(dHex);
            ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            ECPoint S = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(sHex));
            ECPoint X = xHex == null
                    ? Gamma
                    : Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderId);
            if (pk == null) {
                return false;
            }
            if (!verifyDecEvidenceConsistency(task, senderId, D, evidence)) {
                return false;
            }
            String ctxTag = xHex == null ? "DEC" : "DECH";
            boolean ok = PresignProofs.verifyDecProof(
                    proof,
                    xHex == null ? Secp256k1Curve.G() : Gamma,
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, senderId, ctxTag)
            );
            if (!ok) {
                logger.warn("Invalid PiDec proof evidence from node {}", senderId);
            }
            return ok;
        } catch (Exception e) {
            logger.warn("Failed to verify PiDec evidence: {}", e.getMessage());
            return false;
        }
    }

    private boolean verifyDecEvidenceConsistency(Gg20SignatureTask task,
                                                 int senderId,
                                                 BigInteger claimedD,
                                                 Map<?, ?> evidence) {
        if (evidence.get("DMap") instanceof Map<?, ?> dMap
                && evidence.get("FMap") instanceof Map<?, ?> fMap) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dMap, fMap);
        }
        if (evidence.get("DhatMap") instanceof Map<?, ?> dhMap
                && evidence.get("FhatMap") instanceof Map<?, ?> fhMap) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dhMap, fhMap);
        }
        return true;
    }

    private boolean verifyDecEvidenceConsistencyMap(Gg20SignatureTask task,
                                                    int senderId,
                                                    BigInteger claimedD,
                                                    Map<?, ?> dMap,
                                                    Map<?, ?> fMap) {
        Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderId);
        if (pk == null) {
            return false;
        }
        if (!allPeersPresent(task, senderId, D, F)) {
            return false;
        }
        BigInteger calc = BigInteger.ONE;
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            BigInteger d = D.get(peerId);
            BigInteger f = F.get(peerId);
            if (d == null || f == null) {
                return false;
            }
            calc = calc.multiply(d).mod(pk.nSquared);
            calc = calc.multiply(f).mod(pk.nSquared);
        }
        return calc.equals(claimedD);
    }

    private Map<String, Object> buildAffGEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i, ECPoint Gamma) {
        Map<Integer, PiAffGProof> proofs = new HashMap<>();
        Map<Integer, BigInteger> D = new HashMap<>();
        Map<Integer, BigInteger> F = new HashMap<>();
        PaillierEncryption.PublicKey senderPk = task.paillier.getPublicKeyInfo();
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
            BigInteger K_peer = task.presignK.get(peerId);
            BigInteger beta = task.presignBeta.get(peerId);
            BigInteger rho = task.presignRho.get(peerId);
            BigInteger mu = task.presignMu.get(peerId);
            if (pk == null || K_peer == null || beta == null || rho == null || mu == null) {
                continue;
            }
            BigInteger encNegBeta = pk.encryptWithRandom(negateModN(beta, pk.n), rho);
            BigInteger d = pk.multiply(K_peer, gamma_i).multiply(encNegBeta).mod(pk.nSquared);
            BigInteger f = senderPk.encryptWithRandom(beta, mu);
            PiAffGProof proof = PresignProofs.createAffGProofNegY(
                    Secp256k1Curve.G(),
                    Gamma,
                    pk.n,
                    senderPk.n,
                    K_peer,
                    d,
                    f,
                    gamma_i,
                    beta,
                    rho,
                    mu,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "AFFG")
            );
            proofs.put(peerId, proof);
            D.put(peerId, d);
            F.put(peerId, f);
        }
        if (proofs.isEmpty()) {
            return null;
        }
        Map<String, Object> ev = new HashMap<>();
        ev.put("affGProofs", encodeAffGProofMap(proofs));
        ev.put("DMap", encodeBigIntegerMap(D));
        ev.put("FMap", encodeBigIntegerMap(F));
        ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
        return ev;
    }

    private Map<String, Object> buildAffGEvidenceChi(Gg20SignatureTask task, BigInteger x_i, ECPoint X_i) {
        Map<Integer, PiAffGProof> proofs = new HashMap<>();
        Map<Integer, BigInteger> Dhat = new HashMap<>();
        Map<Integer, BigInteger> Fhat = new HashMap<>();
        PaillierEncryption.PublicKey senderPk = task.paillier.getPublicKeyInfo();
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
            BigInteger K_peer = task.presignK.get(peerId);
            BigInteger betaHat = task.presignBetaHat.get(peerId);
            BigInteger rhoHat = task.presignRhoHat.get(peerId);
            BigInteger muHat = task.presignMuHat.get(peerId);
            if (pk == null || K_peer == null || betaHat == null || rhoHat == null || muHat == null) {
                continue;
            }
            BigInteger encNegBeta = pk.encryptWithRandom(negateModN(betaHat, pk.n), rhoHat);
            BigInteger d = pk.multiply(K_peer, x_i).multiply(encNegBeta).mod(pk.nSquared);
            BigInteger f = senderPk.encryptWithRandom(betaHat, muHat);
            PiAffGProof proof = PresignProofs.createAffGProofNegY(
                    Secp256k1Curve.G(),
                    X_i,
                    pk.n,
                    senderPk.n,
                    K_peer,
                    d,
                    f,
                    x_i,
                    betaHat,
                    rhoHat,
                    muHat,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "AFFGH")
            );
            proofs.put(peerId, proof);
            Dhat.put(peerId, d);
            Fhat.put(peerId, f);
        }
        if (proofs.isEmpty()) {
            return null;
        }
        Map<String, Object> ev = new HashMap<>();
        ev.put("affGProofsHat", encodeAffGProofMap(proofs));
        ev.put("DhatMap", encodeBigIntegerMap(Dhat));
        ev.put("FhatMap", encodeBigIntegerMap(Fhat));
        ev.put("X", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(X_i)));
        return ev;
    }

    private boolean verifyAffGEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        boolean hasAffG = evidence.containsKey("affGProofs") || evidence.containsKey("affGProofsHat");
        if (!hasAffG) {
            return true;
        }
        PaillierEncryption.PublicKey senderPk = task.peerPaillierKeys.get(senderId);
        if (senderPk == null) {
            return false;
        }
        if (evidence.get("affGProofs") instanceof Map<?, ?> proofMap
                && evidence.get("DMap") instanceof Map<?, ?> dMap
                && evidence.get("FMap") instanceof Map<?, ?> fMap) {
            String gammaHex = (String) evidence.get("Gamma");
            if (gammaHex == null) {
                return false;
            }
            ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(proofMap);
            Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
            Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
            if (!allPeersPresent(task, senderId, proofs, D, F)) {
                return false;
            }
            for (Map.Entry<Integer, PiAffGProof> e : proofs.entrySet()) {
                int peerId = e.getKey();
                PiAffGProof proof = e.getValue();
                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                BigInteger K_peer = task.presignK.get(peerId);
                BigInteger d = D.get(peerId);
                BigInteger f = F.get(peerId);
                if (pk == null || K_peer == null || d == null || f == null) {
                    return false;
                }
                boolean ok = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        Gamma,
                        pk.n,
                        senderPk.n,
                        K_peer,
                        d,
                        f,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "AFFG")
                ).ok();
                if (!ok) {
                    return false;
                }
            }
        }
        if (evidence.get("affGProofsHat") instanceof Map<?, ?> proofMap
                && evidence.get("DhatMap") instanceof Map<?, ?> dMap
                && evidence.get("FhatMap") instanceof Map<?, ?> fMap) {
            String xHex = (String) evidence.get("X");
            if (xHex == null) {
                return false;
            }
            ECPoint X = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(proofMap);
            Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
            Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
            if (!allPeersPresent(task, senderId, proofs, D, F)) {
                return false;
            }
            for (Map.Entry<Integer, PiAffGProof> e : proofs.entrySet()) {
                int peerId = e.getKey();
                PiAffGProof proof = e.getValue();
                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                BigInteger K_peer = task.presignK.get(peerId);
                BigInteger d = D.get(peerId);
                BigInteger f = F.get(peerId);
                if (pk == null || K_peer == null || d == null || f == null) {
                    return false;
                }
                boolean ok = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        X,
                        pk.n,
                        senderPk.n,
                        K_peer,
                        d,
                        f,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "AFFGH")
                ).ok();
                if (!ok) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean allPeersPresent(Gg20SignatureTask task,
                                    int senderId,
                                    Map<Integer, ?> proofs,
                                    Map<Integer, ?> dMap,
                                    Map<Integer, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!proofs.containsKey(peerId) || !dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return false;
            }
        }
        return true;
    }

    private boolean allPeersPresent(Gg20SignatureTask task,
                                    int senderId,
                                    Map<Integer, ?> dMap,
                                    Map<Integer, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return false;
            }
        }
        return true;
    }

    private void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            String evidenceJson = evidence == null ? null : encodeObjectAsJson(evidence);
            complaintDao.save(System.currentTimeMillis(), taskId, senderId, offenderId, reason, evidenceJson);
        } catch (Exception e) {
            logger.warn("Failed to persist complaint: {}", e.getMessage());
        }
        try {
            java.nio.file.Path complaintFile = java.nio.file.Paths.get(complaintLogPath);
            java.nio.file.Path dir = complaintFile.getParent();
            if (dir != null) {
                java.nio.file.Files.createDirectories(dir);
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"ts\":").append(System.currentTimeMillis()).append(',');
            sb.append("\"taskId\":\"").append(escapeJson(taskId)).append("\",");
            sb.append("\"senderId\":").append(senderId).append(',');
            sb.append("\"offenderId\":").append(offenderId == null ? "null" : offenderId).append(',');
            sb.append("\"reason\":\"").append(escapeJson(reason)).append("\"");
            if (evidence != null) {
                sb.append(",\"evidence\":").append(encodeObjectAsJson(evidence));
            }
            sb.append('}');
            String line = sb.append(System.lineSeparator()).toString();
            java.nio.file.Files.writeString(complaintFile, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }

    private String encodeObjectAsJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            java.util.List<String> keys = new java.util.ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            java.util.Collections.sort(keys);
            for (String k : keys) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(escapeJson(k)).append("\":");
                sb.append(encodeObjectAsJson(map.get(k)));
            }
            sb.append("}");
            return sb.toString();
        }
        if (value instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object o : it) {
                if (!first) sb.append(",");
                first = false;
                sb.append(encodeObjectAsJson(o));
            }
            sb.append("]");
            return sb.toString();
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        return "\"" + escapeJson(String.valueOf(value)) + "\"";
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private void handleCggmpSignExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received exclude for task {} from node {} (offender {})", signatureTaskId, senderId, offenderId);
        failSignatureTask(task, "Excluded offender " + offenderId);
    }

    private void attemptExcludeAndRestart(Gg20SignatureTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            failSignatureTask(task, "Complaint (offender not participant): " + reason);
            return;
        }
        int required = Math.min(Math.max(1, task.threshold), task.nodesCount);
        java.util.LinkedHashSet<Integer> newParticipants = new java.util.LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.size() < required) {
            failSignatureTask(task, "Not enough participants after exclusion");
            return;
        }
        fireAndForget(broadcastExclude(task, offenderId), "CGGMP_SIGN_EXCLUDE");
        failSignatureTask(task, "Excluded offender " + offenderId + ", restarting");

        String newTaskId = task.taskId + "-excl-" + offenderId + "-" + System.currentTimeMillis();
        createSignatureTaskWithIdAndGroupKey(newTaskId, task.groupPublicKey, task.message, task.initiatorId, newParticipants);
        Gg20SignatureTask newTask = signatureTasks.get(newTaskId);
        if (newTask == null) {
            return;
        }
        initSignatureContext(newTask);
        newTask.start();
        fireAndForget(broadcastOfflineInit(newTask), "CGGMP_SIGN_OFFLINE_INIT");
        runOfflinePhase(newTask).exceptionally(ex -> {
            logger.error("Failed offline phase for restarted task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
    }

    private CompletableFuture<Void> broadcastExclude(Gg20SignatureTask task, int offenderId) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_EXCLUDE, data));
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignGammaCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commitHex = (String) dataMap.get("commit");
        String proofAHex = (String) dataMap.get("proofA");
        String proofRHex = (String) dataMap.get("proofR");
        String proofSHex = (String) dataMap.get("proofS");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commitHex == null || proofAHex == null || proofRHex == null || proofSHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint commitment = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(commitHex));
            ECPoint proofA = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(proofAHex));
            BigInteger proofR = new BigInteger(proofRHex, 16);
            BigInteger proofS = new BigInteger(proofSHex, 16);
            EcChaumPedersenProof proof = new EcChaumPedersenProof(proofA, proofR, proofS);
            byte[] ctx = buildSignContext(task.taskId, senderId, task.messageHash, "GAMMA-COMMIT");
            if (!CggmpIntegrityChecker.verifyGammaCommitment(proof, commitment, ctx)) {
                logger.warn("Invalid gamma commitment proof from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("commit", commitHex);
                evidence.put("proofA", proofAHex);
                evidence.put("proofR", proofRHex);
                evidence.put("proofS", proofSHex);
                fireAndForget(broadcastComplaint(task, senderId, "Invalid gamma commitment proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid gamma commitment proof");
                return;
            }
            if (task.gammaCommitments.containsKey(senderId)) {
                logger.warn("Duplicate gamma commitment from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaCommitments.put(senderId, commitment);
            if (task.gammaCommitLatch.getCount() > 0) {
                task.gammaCommitLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_COMMIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignGammaOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String gammaHex = (String) dataMap.get("gamma");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || gammaHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            BigInteger r = new BigInteger(rHex, 16);
            ECPoint commitment = task.gammaCommitments.get(senderId);
            if (commitment == null) {
                logger.warn("Missing gamma commitment for node {} in task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                fireAndForget(broadcastComplaint(task, senderId, "Missing gamma commitment", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Missing gamma commitment");
                return;
            }
            if (!CggmpIntegrityChecker.isValidGammaPoint(gamma)) {
                logger.warn("Invalid gamma point from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                fireAndForget(broadcastComplaint(task, senderId, "Invalid gamma point", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid gamma point");
                return;
            }
            if (!CggmpIntegrityChecker.verifyGammaOpen(commitment, gamma, r)) {
                logger.warn("Invalid gamma commitment opening from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                evidence.put("r", rHex);
                fireAndForget(broadcastComplaint(task, senderId, "Invalid gamma commitment opening", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid gamma commitment opening");
                return;
            }
            if (task.gammaPoints.containsKey(senderId)) {
                logger.warn("Duplicate gamma open from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaPoints.put(senderId, gamma);
            if (task.gammaLatch.getCount() > 0) {
                task.gammaLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_OPEN from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaKaInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpDkgCodec.decodeMtAInitiatorMessage(msgMap);
            if (!validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Invalid Paillier public key (KA)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid Paillier public key (KA)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Missing KA MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Missing KA MtA initiator proofs");
                return;
            }
            if (!ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (KA)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Inconsistent Paillier key/zkSetup (KA)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Invalid KA MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid KA MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.a_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.kaBetas.put(initiatorId, beta);
            if (task.kaInitLatch.getCount() > 0) {
                task.kaInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpDkgCodec.encodeMtAResult(publicResult));
            fireAndForget(nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_KA_RESPONSE, resp)),
                    "CGGMP_SIGN_MTA_KA_RESPONSE");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaKaResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != nodeId || responderId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpDkgCodec.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaKaInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                fireAndForget(broadcastComplaint(task, responderId, "Missing KA MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Missing KA MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                fireAndForget(broadcastComplaint(task, responderId, "Invalid KA MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid KA MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1Curve.n());
            task.kaAlphas.put(responderId, alpha);
            if (task.kaResponseLatch.getCount() > 0) {
                task.kaResponseLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        try {
            BigInteger u = new BigInteger(uHex, 16);
            BigInteger r = new BigInteger(rHex, 16);
            String commit = task.uCommitments.get(senderId);
            if (commit == null) {
                logger.warn("Missing u commitment from node {} for task {}", senderId, taskId);
                return;
            }
            String expected = commitU(taskId, senderId, task.messageHash, u, r);
            if (!commit.equals(expected)) {
                logger.warn("Invalid u commitment opening from node {} for task {}", senderId, taskId);
                return;
            }
            task.uShares.put(senderId, u);
            if (task.uShareLatch.getCount() > 0) {
                task.uShareLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_U_SHARE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        task.uShares.put(0, new BigInteger(uHex, 16));
        if (task.uOpenLatch.getCount() > 0) {
            task.uOpenLatch.countDown();
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commit = (String) dataMap.get("commit");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commit == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        task.uCommitments.put(senderId, commit);
        if (task.uCommitLatch.getCount() > 0) {
            task.uCommitLatch.countDown();
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaStInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpDkgCodec.decodeMtAInitiatorMessage(msgMap);
            if (!validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Invalid Paillier public key (ST)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid Paillier public key (ST)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Missing ST MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Missing ST MtA initiator proofs");
                return;
            }
            if (!ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (ST)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Inconsistent Paillier key/zkSetup (ST)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                fireAndForget(broadcastComplaint(task, initiatorId, "Invalid ST MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid ST MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.t_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.stBetas.put(initiatorId, beta);
            if (task.stInitLatch.getCount() > 0) {
                task.stInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpDkgCodec.encodeMtAResult(publicResult));
            fireAndForget(nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_ST_RESPONSE, resp)),
                    "CGGMP_SIGN_MTA_ST_RESPONSE");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaStResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != nodeId || responderId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpDkgCodec.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaStInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                fireAndForget(broadcastComplaint(task, responderId, "Missing ST MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Missing ST MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                fireAndForget(broadcastComplaint(task, responderId, "Invalid ST MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                failSignatureTask(task, "Invalid ST MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1Curve.n());
            task.stAlphas.put(responderId, alpha);
            if (task.stResponseLatch.getCount() > 0) {
                task.stResponseLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignSShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String sHex = (String) dataMap.get("s");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || sHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        BigInteger sigma = new BigInteger(sHex, 16);
        if (!verifySigmaShare(task, senderId, sigma)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("sigma", sHex);
            ev.put("r", task.r == null ? null : HexUtils.toHex(task.r));
            ev.put("DeltaTilde", task.presignDeltaTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignDeltaTilde.get(senderId).getEncoded(false)));
            ev.put("STilde", task.presignSTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignSTilde.get(senderId).getEncoded(false)));
            fireAndForget(broadcastComplaint(task, senderId, "Invalid signature share (Figure 10)", ev),
                    "CGGMP_SIGN_COMPLAINT");
            failSignatureTask(task, "Invalid signature share from node " + senderId);
            return;
        }
        task.sShares.put(senderId, sigma);
        if (task.sShareLatch.getCount() > 0) {
            task.sShareLatch.countDown();
        }
    }

    private boolean verifySigmaShare(Gg20SignatureTask task, int senderId, BigInteger sigma) {
        if (task.presignature == null || task.messageHash == null) {
            return false;
        }
        BigInteger curveOrder = Secp256k1Curve.n();
        ECPoint Gamma = task.presignature.Gamma();
        BigInteger r = task.r != null ? task.r : Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
        BigInteger m = new BigInteger(1, task.messageHash).mod(curveOrder);
        ECPoint deltaTilde = task.presignDeltaTilde.get(senderId);
        ECPoint sTilde = task.presignSTilde.get(senderId);
        if (deltaTilde == null || sTilde == null) {
            return false;
        }
        BigInteger shift = resolveSignShift(task, curveOrder);
        if (shift.signum() != 0) {
            sTilde = sTilde.add(deltaTilde.multiply(shift)).normalize();
        }
        ECPoint left = Gamma.multiply(sigma).normalize();
        ECPoint right = deltaTilde.multiply(m).add(sTilde.multiply(r)).normalize();
        return left.equals(right);
    }

    private List<Integer> findInvalidSigmaShares(Gg20SignatureTask task) {
        List<Integer> offenders = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger> e : task.sShares.entrySet()) {
            if (!verifySigmaShare(task, e.getKey(), e.getValue())) {
                offenders.add(e.getKey());
            }
        }
        return offenders;
    }

    private void clearPresignLocal(Gg20SignatureTask task) {
        task.presignature = null;
        task.presignatureUsed = false;
        task.k_i = null;
        task.presignYScalar = null;
        task.presignAScalar = null;
        task.presignBScalar = null;
        task.presignDelta.remove(nodeId);
        task.presignDeltaPoint.remove(nodeId);
        task.presignSPoint.remove(nodeId);
    }

    private void clearPresignAll(Gg20SignatureTask task) {
        clearPresignLocal(task);
        task.presignK.clear();
        task.presignG.clear();
        task.presignGamma.clear();
        task.presignY.clear();
        task.presignA1.clear();
        task.presignA2.clear();
        task.presignB1.clear();
        task.presignB2.clear();
        task.presignD.clear();
        task.presignDhat.clear();
        task.presignF.clear();
        task.presignFhat.clear();
        task.presignFOutgoing.clear();
        task.presignFhatOutgoing.clear();
        task.presignBeta.clear();
        task.presignBetaHat.clear();
        task.presignRho.clear();
        task.presignMu.clear();
        task.presignRhoHat.clear();
        task.presignMuHat.clear();
        task.presignDelta.clear();
        task.presignDeltaPoint.clear();
        task.presignSPoint.clear();
        task.presignDeltaTilde.clear();
        task.presignSTilde.clear();
        task.sShares.clear();
    }

    private static final class PeerR2Result {
        final int peerId;
        final boolean skipped;
        final BigInteger beta;
        final BigInteger betaHat;
        final BigInteger d;
        final BigInteger dhat;
        final BigInteger f;
        final BigInteger fhat;
        final BigInteger rho;
        final BigInteger mu;
        final BigInteger rhoHat;
        final BigInteger muHat;
        final PiAffGProof proof;
        final PiAffGProof proofHat;
        final long peerMs;

        private PeerR2Result(int peerId,
                             boolean skipped,
                             BigInteger beta,
                             BigInteger betaHat,
                             BigInteger d,
                             BigInteger dhat,
                             BigInteger f,
                             BigInteger fhat,
                             BigInteger rho,
                             BigInteger mu,
                             BigInteger rhoHat,
                             BigInteger muHat,
                             PiAffGProof proof,
                             PiAffGProof proofHat,
                             long peerMs) {
            this.peerId = peerId;
            this.skipped = skipped;
            this.beta = beta;
            this.betaHat = betaHat;
            this.d = d;
            this.dhat = dhat;
            this.f = f;
            this.fhat = fhat;
            this.rho = rho;
            this.mu = mu;
            this.rhoHat = rhoHat;
            this.muHat = muHat;
            this.proof = proof;
            this.proofHat = proofHat;
            this.peerMs = peerMs;
        }

        static PeerR2Result skipped(int peerId) {
            return new PeerR2Result(peerId, true, null, null, null, null, null, null, null, null, null, null, null, null, 0L);
        }

        static PeerR2Result done(int peerId,
                                 BigInteger beta,
                                 BigInteger betaHat,
                                 BigInteger d,
                                 BigInteger dhat,
                                 BigInteger f,
                                 BigInteger fhat,
                                 BigInteger rho,
                                 BigInteger mu,
                                 BigInteger rhoHat,
                                 BigInteger muHat,
                                 PiAffGProof proof,
                                 PiAffGProof proofHat,
                                 long peerMs) {
            return new PeerR2Result(peerId, false, beta, betaHat, d, dhat, f, fhat, rho, mu, rhoHat, muHat, proof, proofHat, peerMs);
        }
    }

    private static final class PresignR2Context {
        final Gg20SignatureTask task;
        final BigInteger curveOrder;
        final BigInteger gamma_i;
        final BigInteger x_i;
        final ECPoint Gamma_i;
        final ECPoint X_i;
        final List<CompletableFuture<PeerR2Result>> r2Futures;
        final long r2StartNs;

        private PresignR2Context(Gg20SignatureTask task,
                                 BigInteger curveOrder,
                                 BigInteger gamma_i,
                                 BigInteger x_i,
                                 ECPoint Gamma_i,
                                 ECPoint X_i,
                                 List<CompletableFuture<PeerR2Result>> r2Futures,
                                 long r2StartNs) {
            this.task = task;
            this.curveOrder = curveOrder;
            this.gamma_i = gamma_i;
            this.x_i = x_i;
            this.Gamma_i = Gamma_i;
            this.X_i = X_i;
            this.r2Futures = r2Futures;
            this.r2StartNs = r2StartNs;
        }
    }

    private static final class PresignR1Context {
        final Gg20SignatureTask task;
        final BigInteger curveOrder;
        final BigInteger gamma_i;

        private PresignR1Context(Gg20SignatureTask task,
                                 BigInteger curveOrder,
                                 BigInteger gamma_i) {
            this.task = task;
            this.curveOrder = curveOrder;
            this.gamma_i = gamma_i;
        }
    }

    private static final class PresignR2Bundle {
        final PresignR2Context ctx;
        final Map<Integer, BigInteger> D;
        final Map<Integer, BigInteger> Dhat;
        final Map<Integer, BigInteger> F;
        final Map<Integer, BigInteger> Fhat;

        private PresignR2Bundle(PresignR2Context ctx,
                                Map<Integer, BigInteger> D,
                                Map<Integer, BigInteger> Dhat,
                                Map<Integer, BigInteger> F,
                                Map<Integer, BigInteger> Fhat) {
            this.ctx = ctx;
            this.D = D;
            this.Dhat = Dhat;
            this.F = F;
            this.Fhat = Fhat;
        }
    }

    private static final class PresignR3Context {
        final PresignR2Context ctx;
        final BigInteger delta_i;
        final BigInteger chi_i;
        final ECPoint Gamma;

        private PresignR3Context(PresignR2Context ctx,
                                 BigInteger delta_i,
                                 BigInteger chi_i,
                                 ECPoint Gamma) {
            this.ctx = ctx;
            this.delta_i = delta_i;
            this.chi_i = chi_i;
            this.Gamma = Gamma;
        }
    }

    private static final class AuxContext {
        final CggmpAuxTask task;
        final PaillierEncryption paillier;
        final PiPrmProof prmProof;
        final byte[] rho;
        final byte[] u;

        private AuxContext(CggmpAuxTask task,
                           PaillierEncryption paillier,
                           PiPrmProof prmProof,
                           byte[] rho,
                           byte[] u) {
            this.task = task;
            this.paillier = paillier;
            this.prmProof = prmProof;
            this.rho = rho;
            this.u = u;
        }
    }

    private static final class OnlineContext {
        final Gg20SignatureTask task;
        final BigInteger curveOrder;
        final BigInteger sigma_i;

        private OnlineContext(Gg20SignatureTask task,
                              BigInteger curveOrder,
                              BigInteger sigma_i) {
            this.task = task;
            this.curveOrder = curveOrder;
            this.sigma_i = sigma_i;
        }
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.GG20_SIGN_INIT,
                            MessageType.CGGMP_SIGN_OFFLINE_INIT,
                            MessageType.CGGMP_SIGN_ONLINE_INIT,
                            MessageType.CGGMP_SIGN_OFFLINE_READY,
                            MessageType.CGGMP_SIGN_COMPLAINT,
                            MessageType.CGGMP_SIGN_EXCLUDE,
                            MessageType.CGGMP_PRESIGN_R1,
                            MessageType.CGGMP_PRESIGN_R1_ECHO,
                            MessageType.CGGMP_PRESIGN_R2,
                            MessageType.CGGMP_PRESIGN_R3,
                            MessageType.CGGMP_SIGN_GAMMA_COMMIT,
                            MessageType.CGGMP_SIGN_GAMMA_OPEN,
                            MessageType.CGGMP_SIGN_MTA_KA_INIT,
                            MessageType.CGGMP_SIGN_MTA_KA_RESPONSE,
                            MessageType.CGGMP_SIGN_U_COMMIT,
                            MessageType.CGGMP_SIGN_U_SHARE,
                            MessageType.CGGMP_SIGN_U_OPEN,
                            MessageType.CGGMP_SIGN_MTA_ST_INIT,
                            MessageType.CGGMP_SIGN_MTA_ST_RESPONSE,
                            MessageType.CGGMP_SIGN_S_SHARE), this);
                    logger.info("CGGMP signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP signature service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    private CompletableFuture<Boolean> waitForNetworkReadyAsync(long timeoutSeconds) {
        return nodeService.waitForNetworkReady()
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .thenApply(v -> true)
                .exceptionally(ex -> false);
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = cggmpScheduler.scheduleAtFixedRate(() -> {
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

    private CompletableFuture<Void> continuePresignAfterR2(PresignR2Bundle bundle) {
        PresignR2Context ctx = bundle.ctx;
        return waitForLatchAsync(ctx.task.presignR2Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R2")
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        BigInteger delta_i = ctx.gamma_i.multiply(ctx.task.k_i).mod(ctx.curveOrder);
                        BigInteger chi_i = ctx.x_i.multiply(ctx.task.k_i).mod(ctx.curveOrder);
                        List<Integer> missingR3Peers = new ArrayList<>();
                        for (int peerId : ctx.task.participants) {
                            if (peerId == nodeId) continue;
                            BigInteger D_ij = ctx.task.presignD.get(peerId);
                            BigInteger Dhat_ij = ctx.task.presignDhat.get(peerId);
                            BigInteger beta = ctx.task.presignBeta.get(peerId);
                            BigInteger betaHat = ctx.task.presignBetaHat.get(peerId);
                            if (D_ij == null || Dhat_ij == null || beta == null || betaHat == null) {
                                logger.warn("Presign R3 missing inputs for task {} peer {}: D={}, Dhat={}, beta={}, betaHat={}",
                                        ctx.task.taskId,
                                        peerId,
                                        D_ij == null ? null : D_ij.toString(16),
                                        Dhat_ij == null ? null : Dhat_ij.toString(16),
                                        beta == null ? null : beta.toString(16),
                                        betaHat == null ? null : betaHat.toString(16));
                                missingR3Peers.add(peerId);
                                continue;
                            }
                            BigInteger alpha = decodeSigned(ctx.task.paillier.decrypt(D_ij), ctx.task.paillier.getPublicKeyInfo().n);
                            BigInteger alphaHat = decodeSigned(ctx.task.paillier.decrypt(Dhat_ij), ctx.task.paillier.getPublicKeyInfo().n);
                            BigInteger oldDelta = delta_i;
                            BigInteger oldChi = chi_i;
                            delta_i = delta_i.add(alpha).add(beta).mod(ctx.curveOrder);
                            chi_i = chi_i.add(alphaHat).add(betaHat).mod(ctx.curveOrder);
                            logger.info("Presign R3 accumulate task {} peer {}: alpha={}, beta={}, alphaHat={}, betaHat={}, delta_i: {} -> {}, chi_i: {} -> {}",
                                    ctx.task.taskId,
                                    peerId,
                                    alpha.toString(16),
                                    beta.toString(16),
                                    alphaHat.toString(16),
                                    betaHat.toString(16),
                                    oldDelta.toString(16),
                                    delta_i.toString(16),
                                    oldChi.toString(16),
                                    chi_i.toString(16));
                        }
                        if (!missingR3Peers.isEmpty()) {
                            throw new RuntimeException("Presign R3 missing inputs from peers: " + missingR3Peers);
                        }
                        ECPoint Gamma = sumPresignGamma(ctx.task);
                        ECPoint Delta_i = Gamma.multiply(ctx.task.k_i).normalize();
                        ECPoint S_i = Gamma.multiply(chi_i).normalize();
                        ctx.task.presignDelta.put(nodeId, delta_i);
                        ctx.task.presignDeltaPoint.put(nodeId, Delta_i);
                        ctx.task.presignSPoint.put(nodeId, S_i);
                        byte[] ctxR3 = buildPresignContext(ctx.task.taskId, nodeId, "R3");
                        ECPoint Y_i_r3 = ctx.task.presignY.get(nodeId);
                        ECPoint A1_r3 = ctx.task.presignA1.get(nodeId);
                        ECPoint A2_r3 = ctx.task.presignA2.get(nodeId);
                        if (Y_i_r3 == null || A1_r3 == null || A2_r3 == null || ctx.task.presignAScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof (R3)");
                        }
                        PiLogProof logProofR3 = PresignProofs.createLogProof(
                                Secp256k1Curve.G(),
                                Gamma,
                                Delta_i,
                                Y_i_r3,
                                A1_r3,
                                A2_r3,
                                ctx.task.k_i,
                                ctx.task.presignAScalar,
                                ctxR3
                        );
                        fireAndForget(broadcastPresignR3(ctx.task, delta_i, Delta_i, S_i, logProofR3),
                                "CGGMP_PRESIGN_R3");
                        return new PresignR3Context(ctx, delta_i, chi_i, Gamma);
                    } catch (Exception e) {
                        ctx.task.fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(r3ctx -> waitForLatchAsync(ctx.task.offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R3")
                        .thenRunAsync(() -> finalizePresign(r3ctx), ThreadPoolUtil.getIoThreadPool()));
    }

    private void finalizePresign(PresignR3Context r3ctx) {
        PresignR2Context ctx = r3ctx.ctx;
        BigInteger delta = sumShares(ctx.task.presignDelta, ctx.curveOrder);
        ECPoint left = Secp256k1Curve.multiply(Secp256k1Curve.G(), delta);
        ECPoint right = sumPoints(ctx.task.presignDeltaPoint);
        if (!left.equals(right)) {
            logger.warn("Presign delta verification mismatch for task {}: left={}, right={}, delta={}, participants={}",
                    ctx.task.taskId,
                    HexUtils.bytesToHex(Secp256k1Curve.encodePoint(left)),
                    HexUtils.bytesToHex(Secp256k1Curve.encodePoint(right)),
                    delta.toString(16),
                    ctx.task.participants);
            Map<String, Object> evidence = buildDecEvidenceDelta(ctx.task, ctx.gamma_i, r3ctx.delta_i);
            fireAndForget(broadcastComplaint(ctx.task, null, "Presign delta verification failed", evidence),
                    "CGGMP_PRESIGN_DELTA_COMPLAINT");
            failSignatureTask(ctx.task, "Presign delta verification failed");
            return;
        }
        ECPoint X = ctx.task.groupPublicKeyPoint;
        ECPoint leftS = X.multiply(delta).normalize();
        ECPoint rightS = sumPoints(ctx.task.presignSPoint);
        if (!leftS.equals(rightS)) {
            logger.warn("Presign chi verification mismatch for task {}: leftS={}, rightS={}, delta={}, participants={}",
                    ctx.task.taskId,
                    HexUtils.bytesToHex(Secp256k1Curve.encodePoint(leftS)),
                    HexUtils.bytesToHex(Secp256k1Curve.encodePoint(rightS)),
                    delta.toString(16),
                    ctx.task.participants);
            for (int peerId : ctx.task.participants) {
                ECPoint sPoint = ctx.task.presignSPoint.get(peerId);
                BigInteger deltaShare = ctx.task.presignDelta.get(peerId);
                if (sPoint == null && deltaShare == null) {
                    continue;
                }
                logger.warn("Presign chi mismatch details task {} peer {}: S_i={}, delta_i={}",
                        ctx.task.taskId,
                        peerId,
                        sPoint == null ? null : HexUtils.bytesToHex(Secp256k1Curve.encodePoint(sPoint)),
                        deltaShare == null ? null : deltaShare.toString(16));
            }
            Map<String, Object> evidence = buildDecEvidenceChi(ctx.task, ctx.x_i, r3ctx.chi_i);
            fireAndForget(broadcastComplaint(ctx.task, null, "Presign chi verification failed", evidence),
                    "CGGMP_PRESIGN_CHI_COMPLAINT");
            failSignatureTask(ctx.task, "Presign chi verification failed");
            return;
        }
        BigInteger deltaInv = delta.modInverse(ctx.curveOrder);
        ECPoint GammaFinal = r3ctx.Gamma.normalize();
        BigInteger kTilde = ctx.task.k_i.multiply(deltaInv).mod(ctx.curveOrder);
        BigInteger chiTilde = r3ctx.chi_i.multiply(deltaInv).mod(ctx.curveOrder);
        ctx.task.presignature = new Presignature(GammaFinal, kTilde, chiTilde);
        ctx.task.presignatureLatch.countDown();

        for (Map.Entry<Integer, ECPoint> e : ctx.task.presignDeltaPoint.entrySet()) {
            ctx.task.presignDeltaTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }
        for (Map.Entry<Integer, ECPoint> e : ctx.task.presignSPoint.entrySet()) {
            ctx.task.presignSTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }

        if (nodeId == ctx.task.initiatorId) {
            markOfflineReady(ctx.task, nodeId);
        } else {
            fireAndForget(sendOfflineReady(ctx.task), "CGGMP_SIGN_OFFLINE_READY");
        }
    }

    private void finalizeSignatureAsInitiator(OnlineContext ctx) {
        List<Integer> offenders = findInvalidSigmaShares(ctx.task);
        if (!offenders.isEmpty()) {
            for (int offender : offenders) {
                fireAndForget(broadcastComplaint(ctx.task, offender, "Invalid signature share (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task.r))),
                        "CGGMP_SIGN_SHARE_COMPLAINT");
            }
            failSignatureTask(ctx.task, "Invalid signature shares: " + offenders);
            signatureInProgress.set(false);
            clearPresignAll(ctx.task);
            return;
        }
        BigInteger s = sumShares(ctx.task.sShares, ctx.curveOrder);
        if (s.compareTo(ctx.curveOrder.shiftRight(1)) > 0) {
            s = ctx.curveOrder.subtract(s);
        }
        byte[] der = derEncodeSignature(ctx.task.r, s);
        boolean verified = verifySignature(ctx.task.groupPublicKeyPoint, ctx.task.messageHash, ctx.task.r, s, buildDomain());
        if (!verified) {
            List<Integer> suspects = findInvalidSigmaShares(ctx.task);
            for (int offender : suspects) {
                fireAndForget(broadcastComplaint(ctx.task, offender, "Aggregate signature verification failed (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task.r))),
                        "CGGMP_SIGN_AGG_COMPLAINT");
            }
            failSignatureTask(ctx.task, "Aggregate signature verification failed");
            signatureInProgress.set(false);
            clearPresignAll(ctx.task);
            return;
        }
        ctx.task.signature = Base64.getEncoder().encodeToString(der);
        ctx.task.verified = verified;
        ctx.task.complete();
        signatureInProgress.set(false);
        clearPresignAll(ctx.task);
        logger.info("CGGMP signature task {} completed successfully, verified: {}", ctx.task.taskId, verified);
    }
}
