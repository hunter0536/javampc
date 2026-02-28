package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiDecProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.CggmpCodecUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.service.cggmp.CggmpOnlineContext;
import com.example.mpc.service.cggmp.CggmpPresignR2Bundle;
import com.example.mpc.service.cggmp.CggmpPresignR2Context;
import com.example.mpc.service.cggmp.CggmpPresignR3Context;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
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
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class CggmpSignatureService implements NodeService.MessageHandler {
    static final Logger logger = LoggerFactory.getLogger(CggmpSignatureService.class);


    @Autowired
    NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;
    @Autowired
    ComplaintDao complaintDao;

    @Value("${node.id}")
    int nodeId;

    @Value("${app.cggmp.proof.kappa:128}")
    int proofKappa;

    @Value("${app.cggmp.proof.epsBits:16}")
    int proofEpsBits;

    @Value("${app.cggmp.presign.retentionDays:30}")
    private long presignRetentionDays;
    @Value("${app.cggmp.presign.usagePath:databases/node-{nodeId}/presign-usage.jsonl}")
    private String presignUsagePath;
    @Value("${app.cggmp.presign.echoEnabled:true}")
    boolean presignEchoEnabled;
    @Value("${app.cggmp.presign.useRbc:false}")
    private boolean presignUseRbc;
    @Value("${app.cggmp.hdEnabled:false}")
    private boolean hdEnabled;
    @Value("${app.cggmp.complaint.logPath:logs/complaints.jsonl}")
    private String complaintLogPath;

    final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, Map<String, Object>>> pendingPresignR1ByTask =
            new ConcurrentHashMap<>();
    static final ExecutorService dkgExecutorService = ThreadPoolUtil.getComputationThreadPool();

    final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;
    final ScheduledExecutorService cggmpScheduler = Executors.newSingleThreadScheduledExecutor();
    final CggmpSignatureEvidenceHandler evidenceHandler = new CggmpSignatureEvidenceHandler(this);
    final CggmpSignatureControlHandler controlHandler = new CggmpSignatureControlHandler(this, evidenceHandler);
    final CggmpSignatureOfflineHandler offlineHandler = new CggmpSignatureOfflineHandler(this);
    final CggmpSignaturePresignHandler presignHandler = new CggmpSignaturePresignHandler(this);
    final CggmpSignatureOnlineHandler onlineHandler = new CggmpSignatureOnlineHandler(this);
    final CggmpSignatureMessageDispatcher messageDispatcher = new CggmpSignatureMessageDispatcher(this);

    public void initialize() {
        logger.info("Initializing CGGMP service for node {}", nodeId);
        PresignUsageStore.configureRetentionDays(presignRetentionDays);
        PresignUsageStore.configurePath(presignUsagePath, nodeId);
        logger.info("CGGMP service initialized successfully");
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

    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message) {
        if (!signatureInProgress.compareAndSet(false, true)) {
            throw new RuntimeException("Signature process is already in progress");
        }

        String fixedGroupPublicKey;
        fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        String taskId = UUID.randomUUID().toString();
        Gg20SignatureTask task = new Gg20SignatureTask(taskId, message, fixedGroupPublicKey, nodesCount, threshold, nodeId);
        signatureTasks.put(taskId, task);
        logger.debug("Created CGGMP signature task {} (initiator={}, participants={})", taskId, nodeId, task.participants);
        return taskId;
    }

    public void createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message, int initiatorId, Set<Integer> participants) {
        if (!signatureInProgress.compareAndSet(false, true)) {
            throw new RuntimeException("Signature process is already in progress");
        }

        String fixedGroupPublicKey;
        fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        Gg20SignatureTask task = new Gg20SignatureTask(signatureTaskId, message, fixedGroupPublicKey, nodesCount, threshold, initiatorId, participants);
        signatureTasks.put(signatureTaskId, task);
        logger.debug("Created CGGMP signature task {} (initiator={}, participants={})", signatureTaskId, initiatorId, task.participants);
    }

    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId);
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

    public List<ComplaintDao.ComplaintRecord> getComplaints(String taskId,
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

    public Map<String, Object> runProofSelfCheck() {
        Map<String, Object> result = new HashMap<>();
        result.put("kappa", proofKappa);
        result.put("epsBits", proofEpsBits);
        try {
            SecureRandom rnd = new SecureRandom();
            BigInteger q = Secp256k1CurveUtils.n();

            int selfCheckKeyBits = 1024;
            // PiDec 自检
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
            ECPoint X = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x);
            ECPoint S = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y);
            PiDecProof decProof = PresignProofs.createDecProof(
                    Secp256k1CurveUtils.G(),
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
                    Secp256k1CurveUtils.G(),
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

            // PiAffG 自检
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
            ECPoint X2 = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x2);
            PiAffGProof affProof = PresignProofs.createAffGProof(
                    Secp256k1CurveUtils.G(),
                    pk0.n,
                    pk1.n,
                    C,
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
                    Secp256k1CurveUtils.G(),
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

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return messageDispatcher.handleMessage(senderId, message);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task not found: " + taskId));
        }
        logger.debug("Starting CGGMP signature task {} (broadcastInit={}, initiator={}, participants={})",
                taskId, true, task.initiatorId, task.participants);

        if (task.isInProgress() || task.isCompleted()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task is already in progress or completed"));
        }

        if (!task.participants.contains(nodeId)) {
            logger.info("Node {} not selected for signature task {}, participants={}, skipping", nodeId, taskId, task.participants);
            signatureInProgress.set(false);
            return CompletableFuture.completedFuture(null);
        }

        if (!task.start()) {
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(new RuntimeException("Failed to start signature task"));
        }
        logger.debug("Signature task {} started on node {}", taskId, nodeId);

        try {
            initSignatureContext(task);
            logger.debug("Signature task {} context initialized (groupPublicKey={})", taskId, task.groupPublicKey);
        } catch (Exception e) {
            task.fail(e.getMessage());
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(e);
        }

        CompletableFuture<Void> flow = (broadcastOfflineInit(task))
                .thenCompose(v -> runOfflinePhase(task))
                .thenCompose(v -> waitForLatchAsync(task.offlineReadyLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline ready")
                        .thenCompose(v2 -> broadcastOnlineInit(task)))
                .thenCompose(v -> runOnlinePhase(task));

        return flow.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.error("Error in CGGMP signature process: {}", ex.getMessage());
                task.fail(ex.getMessage());
                signatureInProgress.set(false);
            } else {
                logger.debug("CGGMP signature process finished for task {} (status={})", taskId, task.status.get());
            }
        });
    }

    void initSignatureContext(Gg20SignatureTask task) {
        if (task.messageHash == null) {
            task.messageHash = hashMessage(task.message);
        }
        if (task.groupPublicKeyPoint == null) {
            task.groupPublicKeyPoint = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(task.groupPublicKey));
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

    private byte[] hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    CompletableFuture<Void> runOfflinePhase(Gg20SignatureTask task) {
        return offlineHandler.runOfflinePhase(task);
    }

    private CompletableFuture<Void> runOnlinePhase(Gg20SignatureTask task) {
        return onlineHandler.runOnlinePhase(task);
    }

    CompletableFuture<Void> broadcastOfflineInit(Gg20SignatureTask task) {
        return offlineHandler.broadcastOfflineInit(task);
    }

    private CompletableFuture<Void> broadcastOnlineInit(Gg20SignatureTask task) {
        logger.debug("Broadcasting CGGMP_SIGN_ONLINE_INIT for task {} (participants={})", task.taskId, task.participants);
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("messageHash", Base64.getEncoder().encodeToString(task.messageHash));
        data.put("initiatorId", task.initiatorId);
        data.put("participants", new ArrayList<>(task.participants));
        return RetryUtils.retryAsync(cggmpScheduler, logger, () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_ONLINE_INIT, data)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_ONLINE_INIT"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_SIGN_ONLINE_INIT, proceeding: {}", ex.getMessage());
            }
        });
    }

    CompletableFuture<Void> broadcastPresignR1(Gg20SignatureTask task,
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
        data.put("Y", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Y)));
        data.put("A1", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A1)));
        data.put("A2", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A2)));
        data.put("B1", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B1)));
        data.put("B2", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B2)));
        data.put("encElgProofK", CggmpCodecUtils.encodePiEncElgProof(encElgK));
        data.put("encElgProofG", CggmpCodecUtils.encodePiEncElgProof(encElgG));
        data.put("paillierPublicKey", CggmpCodecUtils.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
        data.put("zkSetup", CggmpCodecUtils.encodeZkSetup(task.zkSetup));
        return RetryUtils.retryAsync(cggmpScheduler, logger, () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R1, data)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_PRESIGN_R1"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_PRESIGN_R1, proceeding: {}", ex.getMessage());
            }
        });
    }

    CompletableFuture<Void> broadcastPresignR1Echo(Gg20SignatureTask task) {
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

    CompletableFuture<Void> broadcastPresignR2(Gg20SignatureTask task, ECPoint Gamma,
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
        data.put("Gamma", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Gamma)));
        data.put("D", JsonUtils.encodeBigIntegerMap(D));
        data.put("Dhat", JsonUtils.encodeBigIntegerMap(Dhat));
        data.put("F", JsonUtils.encodeBigIntegerMap(F));
        data.put("Fhat", JsonUtils.encodeBigIntegerMap(Fhat));
        data.put("affGProofs", encodeAffGProofMap(affG));
        data.put("affGProofsHat", encodeAffGProofMap(affGhat));
        data.put("logProof", CggmpCodecUtils.encodePiLogProof(logProof));
        data.put("X", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(X)));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R2, data));
    }

    private CompletableFuture<Void> broadcastPresignR3(Gg20SignatureTask task, BigInteger delta, ECPoint Delta, ECPoint S, PiLogProof logProof) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("delta", delta.toString(16));
        data.put("Delta", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Delta)));
        data.put("S", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(S)));
        data.put("logProof", CggmpCodecUtils.encodePiLogProof(logProof));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R3, data));
    }

    Map<String, Object> encodeAffGProofMap(Map<Integer, PiAffGProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiAffGProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpCodecUtils.encodePiAffGProof(e.getValue()));
        }
        return out;
    }

    Map<Integer, PiAffGProof> decodeAffGProofMap(Map<?, ?> map) {
        Map<Integer, PiAffGProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpCodecUtils.decodePiAffGProof((Map<?, ?>) e.getValue()));
        }
        return out;
    }

    CompletableFuture<Void> continuePresignAfterR2(CggmpPresignR2Bundle bundle) {
        CggmpPresignR2Context ctx = bundle.ctx();
        return waitForLatchAsync(ctx.task().presignR2Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R2")
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        BigInteger delta_i = ctx.gamma_i().multiply(ctx.task().k_i).mod(ctx.curveOrder());
                        BigInteger chi_i = ctx.x_i().multiply(ctx.task().k_i).mod(ctx.curveOrder());
                        List<Integer> missingR3Peers = new ArrayList<>();
                        for (int peerId : ctx.task().participants) {
                            if (peerId == nodeId) continue;
                            BigInteger D_ij = ctx.task().presignD.get(peerId);
                            BigInteger Dhat_ij = ctx.task().presignDhat.get(peerId);
                            BigInteger beta = ctx.task().presignBeta.get(peerId);
                            BigInteger betaHat = ctx.task().presignBetaHat.get(peerId);
                            if (D_ij == null || Dhat_ij == null || beta == null || betaHat == null) {
                                logger.warn("Presign R3 missing inputs for task {} peer {}: D={}, Dhat={}, beta={}, betaHat={}",
                                        ctx.task().taskId,
                                        peerId,
                                        D_ij == null ? null : D_ij.toString(16),
                                        Dhat_ij == null ? null : Dhat_ij.toString(16),
                                        beta == null ? null : beta.toString(16),
                                        betaHat == null ? null : betaHat.toString(16));
                                missingR3Peers.add(peerId);
                                continue;
                            }
                            BigInteger alpha = SignUtils.decodeSigned(ctx.task().paillier.decrypt(D_ij), ctx.task().paillier.getPublicKeyInfo().n);
                            BigInteger alphaHat = SignUtils.decodeSigned(ctx.task().paillier.decrypt(Dhat_ij), ctx.task().paillier.getPublicKeyInfo().n);
                            BigInteger oldDelta = delta_i;
                            BigInteger oldChi = chi_i;
                            delta_i = delta_i.add(alpha).add(beta).mod(ctx.curveOrder());
                            chi_i = chi_i.add(alphaHat).add(betaHat).mod(ctx.curveOrder());
                            logger.info("Presign R3 accumulate task {} peer {}: alpha={}, beta={}, alphaHat={}, betaHat={}, delta_i: {} -> {}, chi_i: {} -> {}",
                                    ctx.task().taskId,
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
                        ECPoint Gamma = sumPresignGamma(ctx.task());
                        ECPoint Delta_i = Gamma.multiply(ctx.task().k_i).normalize();
                        ECPoint S_i = Gamma.multiply(chi_i).normalize();
                        ctx.task().presignDelta.put(nodeId, delta_i);
                        ctx.task().presignDeltaPoint.put(nodeId, Delta_i);
                        ctx.task().presignSPoint.put(nodeId, S_i);
                        byte[] ctxR3 = SignUtils.buildPresignContext(ctx.task().taskId, nodeId, "R3");
                        ECPoint Y_i_r3 = ctx.task().presignY.get(nodeId);
                        ECPoint A1_r3 = ctx.task().presignA1.get(nodeId);
                        ECPoint A2_r3 = ctx.task().presignA2.get(nodeId);
                        if (Y_i_r3 == null || A1_r3 == null || A2_r3 == null || ctx.task().presignAScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof (R3)");
                        }
                        PiLogProof logProofR3 = PresignProofs.createLogProof(
                                Secp256k1CurveUtils.G(),
                                Gamma,
                                Delta_i,
                                Y_i_r3,
                                A1_r3,
                                A2_r3,
                                ctx.task().k_i,
                                ctx.task().presignAScalar,
                                ctxR3
                        );
                        fireAndForget(broadcastPresignR3(ctx.task(), delta_i, Delta_i, S_i, logProofR3),
                                "CGGMP_PRESIGN_R3");
                        return new CggmpPresignR3Context(ctx, delta_i, chi_i, Gamma);
                    } catch (Exception e) {
                        ctx.task().fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(r3ctx -> waitForLatchAsync(ctx.task().offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R3")
                        .thenRunAsync(() -> finalizePresign(r3ctx), ThreadPoolUtil.getIoThreadPool()));
    }

    private void finalizePresign(CggmpPresignR3Context r3ctx) {
        CggmpPresignR2Context ctx = r3ctx.ctx();
        BigInteger delta = sumShares(ctx.task().presignDelta, ctx.curveOrder());
        ECPoint left = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), delta);
        ECPoint right = Secp256k1CurveUtils.sumPoints(ctx.task().presignDeltaPoint);
        if (!left.equals(right)) {
            logger.warn("Presign delta verification mismatch for task {}: left={}, right={}, delta={}, participants={}",
                    ctx.task().taskId,
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(left)),
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(right)),
                    delta.toString(16),
                    ctx.task().participants);
            Map<String, Object> evidence = evidenceHandler.buildDecEvidenceDelta(ctx.task(), ctx.gamma_i(), r3ctx.delta_i());
            fireAndForget(broadcastComplaint(ctx.task(), null, "Presign delta verification failed", evidence),
                    "CGGMP_PRESIGN_DELTA_COMPLAINT");
            failSignatureTask(ctx.task(), "Presign delta verification failed");
            return;
        }
        ECPoint X = ctx.task().groupPublicKeyPoint;
        ECPoint leftS = X.multiply(delta).normalize();
        ECPoint rightS = Secp256k1CurveUtils.sumPoints(ctx.task().presignSPoint);
        if (!leftS.equals(rightS)) {
            logger.warn("Presign chi verification mismatch for task {}: leftS={}, rightS={}, delta={}, participants={}",
                    ctx.task().taskId,
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(leftS)),
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(rightS)),
                    delta.toString(16),
                    ctx.task().participants);
            for (int peerId : ctx.task().participants) {
                ECPoint sPoint = ctx.task().presignSPoint.get(peerId);
                BigInteger deltaShare = ctx.task().presignDelta.get(peerId);
                if (sPoint == null && deltaShare == null) {
                    continue;
                }
                logger.warn("Presign chi mismatch details task {} peer {}: S_i={}, delta_i={}",
                        ctx.task().taskId,
                        peerId,
                        sPoint == null ? null : HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(sPoint)),
                        deltaShare == null ? null : deltaShare.toString(16));
            }
            Map<String, Object> evidence = evidenceHandler.buildDecEvidenceChi(ctx.task(), ctx.x_i(), r3ctx.chi_i());
            fireAndForget(broadcastComplaint(ctx.task(), null, "Presign chi verification failed", evidence),
                    "CGGMP_PRESIGN_CHI_COMPLAINT");
            failSignatureTask(ctx.task(), "Presign chi verification failed");
            return;
        }
        BigInteger deltaInv = delta.modInverse(ctx.curveOrder());
        ECPoint GammaFinal = r3ctx.Gamma().normalize();
        BigInteger kTilde = ctx.task().k_i.multiply(deltaInv).mod(ctx.curveOrder());
        BigInteger chiTilde = r3ctx.chi_i().multiply(deltaInv).mod(ctx.curveOrder());
        ctx.task().presignature = new Presignature(GammaFinal, kTilde, chiTilde);
        ctx.task().presignatureLatch.countDown();

        for (Map.Entry<Integer, ECPoint> e : ctx.task().presignDeltaPoint.entrySet()) {
            ctx.task().presignDeltaTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }
        for (Map.Entry<Integer, ECPoint> e : ctx.task().presignSPoint.entrySet()) {
            ctx.task().presignSTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }

        if (nodeId == ctx.task().initiatorId) {
            markOfflineReady(ctx.task(), nodeId);
        } else {
            fireAndForget(sendOfflineReady(ctx.task()), "CGGMP_SIGN_OFFLINE_READY");
        }
    }

    void finalizeSignatureAsInitiator(CggmpOnlineContext ctx) {
        List<Integer> offenders = findInvalidSigmaShares(ctx.task());
        if (!offenders.isEmpty()) {
            for (int offender : offenders) {
                fireAndForget(broadcastComplaint(ctx.task(), offender, "Invalid signature share (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task().r))),
                        "CGGMP_SIGN_SHARE_COMPLAINT");
            }
            failSignatureTask(ctx.task(), "Invalid signature shares: " + offenders);
            signatureInProgress.set(false);
            clearPresignAll(ctx.task());
            return;
        }
        BigInteger s = sumShares(ctx.task().sShares, ctx.curveOrder());
        if (s.compareTo(ctx.curveOrder().shiftRight(1)) > 0) {
            s = ctx.curveOrder().subtract(s);
        }
        byte[] der = derEncodeSignature(ctx.task().r, s);
        boolean verified = verifySignature(ctx.task().groupPublicKeyPoint, ctx.task().messageHash, ctx.task().r, s, buildDomain());
        if (!verified) {
            List<Integer> suspects = findInvalidSigmaShares(ctx.task());
            for (int offender : suspects) {
                fireAndForget(broadcastComplaint(ctx.task(), offender, "Aggregate signature verification failed (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task().r))),
                        "CGGMP_SIGN_AGG_COMPLAINT");
            }
            failSignatureTask(ctx.task(), "Aggregate signature verification failed");
            signatureInProgress.set(false);
            clearPresignAll(ctx.task());
            return;
        }
        ctx.task().signature = Base64.getEncoder().encodeToString(der);
        ctx.task().verified = true;
        ctx.task().complete();
        signatureInProgress.set(false);
        clearPresignAll(ctx.task());
        logger.info("CGGMP signature task {} completed successfully, verified: {}", ctx.task().taskId, true);
    }

    CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason) {
        return broadcastComplaint(task, offenderId, reason, null);
    }

    CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason, Map<String, Object> evidence) {
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

    CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
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

    void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            String evidenceJson = evidence == null ? null : JsonUtils.encodeAsJson(evidence);
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
            sb.append("\"taskId\":\"").append(JsonUtils.escapeJson(taskId)).append("\",");
            sb.append("\"senderId\":").append(senderId).append(',');
            sb.append("\"offenderId\":").append(offenderId == null ? "null" : offenderId).append(',');
            sb.append("\"reason\":\"").append(JsonUtils.escapeJson(reason)).append("\"");
            if (evidence != null) {
                sb.append(",\"evidence\":").append(JsonUtils.encodeAsJson(evidence));
            }
            sb.append('}');
            String line = sb.append(System.lineSeparator()).toString();
            java.nio.file.Files.writeString(complaintFile, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }

    void cachePendingPresignR1(String taskId, int senderId, Map<?, ?> dataMap) {
        if (taskId == null) {
            return;
        }
        ConcurrentHashMap<Integer, Map<String, Object>> pending =
                pendingPresignR1ByTask.computeIfAbsent(taskId, ignored -> new ConcurrentHashMap<>());
        Map<String, Object> normalized = new HashMap<>();
        for (Map.Entry<?, ?> entry : dataMap.entrySet()) {
            if (entry.getKey() instanceof String key) {
                normalized.put(key, entry.getValue());
            }
        }
        pending.put(senderId, normalized);
        logger.debug("Cached presign R1 from node {} for task {} (waiting for task creation)", senderId, taskId);
    }

    void drainPendingPresignR1(Gg20SignatureTask task) {
        ConcurrentHashMap<Integer, Map<String, Object>> pending = pendingPresignR1ByTask.remove(task.taskId);
        if (pending == null || pending.isEmpty()) {
            return;
        }
        logger.debug("Replaying {} pending presign R1 messages for task {}", pending.size(), task.taskId);
        for (Map.Entry<Integer, Map<String, Object>> entry : pending.entrySet()) {
            try {
                presignHandler.handlePresignR1(entry.getKey(), entry.getValue());
            } catch (Exception ex) {
                logger.warn("Failed to replay presign R1 from node {} for task {}: {}",
                        entry.getKey(), task.taskId, ex.getMessage());
            }
        }
    }

    CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
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

    void fireAndForget(CompletableFuture<Void> future, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    static String computePresignR1EchoHash(Gg20SignatureTask task) {
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
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Y)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A1)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A2)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B1)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B2)));
                payloads.add(entry);
            }
            return SignUtils.computeTaggedHashHex("PRESIGN_R1_ECHO", sid, payloads);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute presign R1 echo hash", e);
        }
    }

    private static String buildSignSid(String taskId) {
        return "CGGMP24:SIGN:" + taskId;
    }

    ECPoint sumPresignGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1CurveUtils.G().getCurve().getInfinity();
        for (ECPoint p : task.presignGamma.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    BigInteger resolveSignShift(Gg20SignatureTask task, BigInteger q) {
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

    boolean verifySigmaShare(Gg20SignatureTask task, int senderId, BigInteger sigma) {
        if (task.presignature == null || task.messageHash == null) {
            return true;
        }
        BigInteger curveOrder = Secp256k1CurveUtils.n();
        ECPoint Gamma = task.presignature.Gamma();
        BigInteger r = task.r != null ? task.r : Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
        BigInteger m = new BigInteger(1, task.messageHash).mod(curveOrder);
        ECPoint deltaTilde = task.presignDeltaTilde.get(senderId);
        ECPoint sTilde = task.presignSTilde.get(senderId);
        if (deltaTilde == null || sTilde == null) {
            return true;
        }
        BigInteger shift = resolveSignShift(task, curveOrder);
        if (shift.signum() != 0) {
            sTilde = sTilde.add(deltaTilde.multiply(shift)).normalize();
        }
        ECPoint left = Gamma.multiply(sigma).normalize();
        ECPoint right = deltaTilde.multiply(m).add(sTilde.multiply(r)).normalize();
        return !left.equals(right);
    }

    private List<Integer> findInvalidSigmaShares(Gg20SignatureTask task) {
        List<Integer> offenders = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger> e : task.sShares.entrySet()) {
            if (verifySigmaShare(task, e.getKey(), e.getValue())) {
                offenders.add(e.getKey());
            }
        }
        return offenders;
    }

    void clearPresignLocal(Gg20SignatureTask task) {
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

    void clearPresignAll(Gg20SignatureTask task) {
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

    private CompletableFuture<Void> sendOfflineReady(Gg20SignatureTask task) {
        return offlineHandler.sendOfflineReady(task);
    }

    private void markOfflineReady(Gg20SignatureTask task, int senderId) {
        offlineHandler.markOfflineReady(task, senderId);
    }

    void initSignaturePaillier(Gg20SignatureTask task) {
        if (task.paillier == null) {
            long startNs = System.nanoTime();
            task.paillier = new PaillierEncryption();
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
            logger.debug("Signature Paillier keygen complete for task {} in {} ms (bitLength={})",
                    task.taskId, elapsedMs, task.paillier.getPublicKeyInfo().bitLength);
        }
        if (task.zkSetup == null) {
            long startNs = System.nanoTime();
            task.zkSetup = ZKSetup.generate(task.paillier.getPublicKeyInfo().bitLength);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
            logger.debug("Signature ZKSetup generate complete for task {} in {} ms (bitLength={})",
                    task.taskId, elapsedMs, task.paillier.getPublicKeyInfo().bitLength);
        }
    }

    BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1CurveUtils.n());
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
                Secp256k1CurveUtils.G().getCurve(),
                Secp256k1CurveUtils.G(),
                Secp256k1CurveUtils.n(),
                BigInteger.ONE
        );
    }

    BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    static BigInteger computeSignatureLagrange(Gg20SignatureTask task, int signerId, BigInteger mod) {
        if (task == null) {
            return BigInteger.ONE;
        }
        if (!signatureUsesLagrange(task)) {
            return BigInteger.ONE;
        }
        return lagrangeCoefficientAtZero(signerId, task.participants, task.indexMap, mod);
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

    ECPoint resolvePublicShare(Gg20SignatureTask task, int signerId, BigInteger lambda, BigInteger x_i) {
        if (task.publicShares != null) {
            ECPoint base = task.publicShares.get(signerId);
            if (base != null) {
                return base.multiply(lambda).normalize();
            }
        }
        return Secp256k1CurveUtils.G().multiply(x_i).normalize();
    }

    ECPoint resolvePublicShareFromMap(Gg20SignatureTask task, int signerId, BigInteger lambda) {
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
            out.put(key, Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(e.getValue())));
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
        if (!cur.isEmpty()) {
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

    private BigInteger sumShares(Map<Integer, BigInteger> shares, BigInteger mod) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger v : shares.values()) {
            if (v == null) continue;
            sum = sum.add(v);
        }
        return sum.mod(mod);
    }

    CompletableFuture<Void> sendSShare(Gg20SignatureTask task, BigInteger s_i) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("s", s_i.toString(16));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_S_SHARE, data));
    }

    String commitU(String taskId, int senderId, byte[] messageHash, BigInteger u, BigInteger r) {
        int nLen = (Secp256k1CurveUtils.n().bitLength() + 7) / 8;
        byte[] uBytes = BigIntegerUtils.toUnsignedBytes(u, nLen);
        byte[] rBytes = BigIntegerUtils.toUnsignedBytes(r, nLen);
        byte[] ctx = SignUtils.buildSignContext(taskId, senderId, messageHash, "U-COMMIT");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ctx);
            digest.update(uBytes);
            digest.update(rBytes);
            byte[] out = digest.digest();
            return HexUtils.bytesToHex(out);
        } catch (Exception e) {
            throw new RuntimeException("U commit hash failed", e);
        }
    }

    private KeyShare loadKeyShareByGroupPublicKeySync(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }

    boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return true;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        return publicKey.n.compareTo(q.pow(8)) < 0;
    }

    boolean ensurePeerKeyConsistency(Gg20SignatureTask task, int peerId, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup) {
        PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.putIfAbsent(peerId, publicKey);
        if (existingKey != null && !paillierPublicKeyEquals(existingKey, publicKey)) {
            return true;
        }
        ZKSetup existingZk = task.peerZkSetups.putIfAbsent(peerId, zkSetup);
        return existingZk != null && !existingZk.equals(zkSetup);
    }

    private boolean paillierPublicKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return a.n.equals(b.n) && a.nSquared.equals(b.nSquared) && a.g.equals(b.g) && a.bitLength == b.bitLength;
    }

    void failSignatureTask(Gg20SignatureTask task, String reason) {
        if (task == null || task.isCompleted() || task.isFailed()) {
            return;
        }
        task.fail(reason);
        signatureInProgress.set(false);
    }

    static Map<?, ?> asMap(Object value) {
        return value instanceof Map<?, ?> map ? map : null;
    }

    static String asString(Object value) {
        return value instanceof String s ? s : null;
    }

    static Integer asInt(Object value) {
        return value instanceof Number n ? n.intValue() : null;
    }
}
