package com.example.mpc.service;

import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.AuxInfo;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.service.cggmp.signature.CggmpSignatureControlHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureEvidenceHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureMessageDispatcher;
import com.example.mpc.service.cggmp.signature.CggmpSignatureOfflineHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureOnlineHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignaturePresignHandler;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
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
    public static final Logger logger = LoggerFactory.getLogger(CggmpSignatureService.class);

    @Autowired
    public NodeService nodeService;

    @Autowired
    public KeyShareService keyShareService;
    @Autowired
    public ComplaintDao complaintDao;
    @Autowired
    public AuxInfoDao auxInfoDao;

    @Value("${node.id}")
    public int nodeId;

    @Value("${app.cggmp.proof.kappa:128}")
    public int proofKappa;

    @Value("${app.cggmp.proof.epsBits:16}")
    public int proofEpsBits;

    @Value("${app.cggmp.presign.retentionDays:30}")
    public long presignRetentionDays;
    @Value("${app.cggmp.presign.usagePath:databases/node-{nodeId}/presign-usage.jsonl}")
    public String presignUsagePath;
    @Value("${app.cggmp.presign.echoEnabled:true}")
    public boolean presignEchoEnabled;
    @Value("${app.cggmp.presign.useRbc:false}")
    public boolean presignUseRbc;
    @Value("${app.cggmp.hdEnabled:false}")
    public boolean hdEnabled;
    @Value("${app.cggmp.complaint.logPath:logs/complaints.jsonl}")
    public String complaintLogPath;
    public final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    public static final ExecutorService signatureExecutorService = ThreadPoolUtil.getComputationThreadPool();

    public final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    public final int nodesCount = Constants.NODES_COUNT;
    public final int threshold = Constants.THRESHOLD;
    public final ScheduledExecutorService cggmpScheduler = Executors.newSingleThreadScheduledExecutor();

    public final CggmpSignatureEvidenceHandler evidenceHandler = new CggmpSignatureEvidenceHandler(this);
    public final CggmpSignatureControlHandler controlHandler = new CggmpSignatureControlHandler(this, evidenceHandler);
    public final CggmpSignaturePresignHandler presignHandler = new CggmpSignaturePresignHandler(this);
    public final CggmpSignatureOfflineHandler offlineHandler = new CggmpSignatureOfflineHandler(this);
    public final CggmpSignatureOnlineHandler onlineHandler = new CggmpSignatureOnlineHandler(this);
    public final CggmpSignatureMessageDispatcher messageDispatcher = new CggmpSignatureMessageDispatcher(this);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initialize() {
        logger.info("Initializing CGGMP service for node {}", nodeId);
        PresignUsageStore.configureRetentionDays(presignRetentionDays);
        PresignUsageStore.configurePath(presignUsagePath, nodeId);
        logger.info("CGGMP service initialized successfully");
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
    }

    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task not found: " + taskId));
        }
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
            ensureLocalAuxReady(task);
            offlineHandler.initSignatureContext(task);
            logger.debug("Signature task {} context initialized (groupPublicKey={})", taskId, task.groupPublicKey);
        } catch (Exception e) {
            task.fail(e.getMessage());
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(e);
        }

        CompletableFuture<Void> flow = (offlineHandler.broadcastOfflineInit(task))
                .thenCompose(v -> offlineHandler.runOfflinePhase(task))
                .thenCompose(v ->
                        waitForLatchAsync(task.offlineReadyLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline ready")
                                .thenCompose(v2 -> onlineHandler.broadcastOnlineInit(task))
                )
                .thenCompose(v -> onlineHandler.runOnlinePhase(task));

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

    public AuxInfo ensureLocalAuxReady(Gg20SignatureTask task) {
        AuxInfo info = auxInfoDao.loadLatestSync(nodeId);
        if (info == null) {
            String msg = "Missing auxiliary info on local node " + nodeId;
            if (task != null) {
                broadcastComplaint(task, null, msg, java.util.Map.of("nodeId", nodeId));
                failSignatureTask(task, msg);
            }
            throw new RuntimeException(msg);
        }
        try {
            java.util.Map<String, String> auxParams = com.example.mpc.common.util.DbMapUtils.buildAuxParams(info);
            String auxHash = hashJsonMap(auxParams);
            String taskId = task == null ? "null" : task.taskId;
            logger.debug("Loaded local AUX for signature task {} (nodeId={}, auxHash={})", taskId, nodeId, auxHash);
        } catch (Exception e) {
            logger.warn("Failed to compute local AUX hash (nodeId={}): {}", nodeId, e.getMessage());
        }
        return info;
    }

    public boolean ensurePeerAuxConsistency(Gg20SignatureTask task, int peerId, java.util.Map<String, String> auxParams) {
        if (task == null || auxParams == null) {
            return true;
        }
        java.util.Map<String, String> existing = task.peerAuxParams.putIfAbsent(peerId, new java.util.HashMap<>(auxParams));
        if (existing == null) {
            String auxHash = hashJsonMap(auxParams);
            logger.debug("Recorded peer AUX params (taskId={}, peerId={}, auxHash={})", task.taskId, peerId, auxHash);
            return false;
        }
        boolean ok = existing.equals(auxParams);
        if (!ok) {
            String incomingHash = hashJsonMap(auxParams);
            String existingHash = hashJsonMap(existing);
            logger.warn("Peer AUX mismatch (taskId={}, peerId={}, existingHash={}, incomingHash={})",
                    task.taskId, peerId, existingHash, incomingHash);
        }
        return !ok;
    }

    private static String hashJsonMap(Object map) {
        if (map == null) {
            return "null";
        }
        try {
            String json = com.example.mpc.common.util.JsonCodec.toJson(map);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return com.example.mpc.common.util.HexUtils.bytesToHex(md.digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
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


    public void failSignatureTask(Gg20SignatureTask task, String reason) {
        if (task == null || task.isCompleted() || task.isFailed()) {
            return;
        }
        task.fail(reason);
        signatureInProgress.set(false);
    }

    public CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason) {
        return broadcastComplaint(task, offenderId, reason, null);
    }

    public CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task,
                                                      int offenderId,
                                                      String reason,
                                                      Map<String, Object> evidence) {
        return broadcastComplaint(task, Integer.valueOf(offenderId), reason, evidence);
    }

    public CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task,
                                                      Integer offenderId,
                                                      String reason,
                                                      Map<String, Object> evidence) {
        if (task == null) {
            return CompletableFuture.completedFuture(null);
        }
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data));
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return messageDispatcher.handleMessage(senderId, message);
    }


    public void clearPresignLocal(Gg20SignatureTask task) {
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

    public void clearPresignAll(Gg20SignatureTask task) {
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

    public CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
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

}
