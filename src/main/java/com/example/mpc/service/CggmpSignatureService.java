package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.service.HotWalletPresignPoolService;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.dto.AuxInfo;
import com.example.mpc.dto.CggmpSignatureTask;
import com.example.mpc.service.cggmp.signature.CggmpSignatureControlHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureEvidenceHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureMessageDispatcher;
import com.example.mpc.service.cggmp.signature.CggmpSignatureOfflineHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignatureOnlineHandler;
import com.example.mpc.service.cggmp.signature.CggmpSignaturePresignHandler;
import com.example.mpc.util.PresignUsageStore;
import com.example.mpc.common.util.RetryUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * CGGMP签名服务核心类
 * 负责协调CGGMP签名协议的离线阶段和在线阶段的执行
 */
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
    @Autowired
    public HotWalletPresignPoolService presignPoolService;

    @Value("${node.id}")
    public int nodeId;

    @Value("${cggmp.proof.kappa:128}")
    public int proofKappa;

    @Value("${cggmp.proof.epsBits:16}")
    public int proofEpsBits;

    @Value("${cggmp.presign.retentionDays:30}")
    public long presignRetentionDays;
    @Value("${cggmp.presign.usagePath:databases/node-{nodeId}/presign-usage.jsonl}")
    public String presignUsagePath;
    @Value("${cggmp.presign.echoEnabled:true}")
    public boolean presignEchoEnabled;
    @Value("${cggmp.presign.rbcEnabled:false}")
    public boolean presignUseRbc;
    @Value("${cggmp.hdEnabled:false}")
    public boolean hdEnabled;
    @Value("${cggmp.complaint.logPath:logs/complaints.jsonl}")
    public String complaintLogPath;
    public final Map<String, CggmpSignatureTask> signatureTasks = new ConcurrentHashMap<>();
    public static final ExecutorService signatureExecutorService = ThreadPoolUtil.getSignatureThreadPool();

    public final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    public final Map<String, AtomicInteger> hotWalletSignatureLocks = new ConcurrentHashMap<>();
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
        return createSignatureTaskWithGroupKey(groupPublicKey, message, false);
    }

    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message, boolean isHotWallet) {
        int auxCount = auxInfoDao.countAuxSync(nodeId);
        if (auxCount == 0) {
            throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before signature.");
        }

        if (isHotWallet) {
            AtomicInteger lock = hotWalletSignatureLocks.computeIfAbsent(groupPublicKey, k -> new AtomicInteger(0));
            int maxConcurrent = 10;
            if (lock.incrementAndGet() > maxConcurrent) {
                lock.decrementAndGet();
                throw new RuntimeException("Too many concurrent signature tasks for hot wallet: " + groupPublicKey);
            }
        } else {
            if (!signatureInProgress.compareAndSet(false, true)) {
                throw new RuntimeException("Signature process is already in progress");
            }
        }

        try {
            AuxInfo auxInfo = auxInfoDao.loadLatestSync(nodeId);

            String fixedGroupPublicKey;
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
            fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
            String taskId = UUID.randomUUID().toString();
            CggmpSignatureTask task = new CggmpSignatureTask(taskId, message, fixedGroupPublicKey, nodesCount, threshold, nodeId, null, isHotWallet);
            task.auxTaskId = auxInfo.getTaskId();
            initTaskPaillierAndZkSetup(task, auxInfo);
            signatureTasks.put(taskId, task);
            return taskId;
        } catch (RuntimeException e) {
            if (isHotWallet) {
            hotWalletSignatureLocks.get(groupPublicKey).decrementAndGet();
            } else {
                signatureInProgress.set(false);
            }
            throw e;
        }
    }

    public void createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message, int initiatorId, Set<Integer> participants, String auxTaskId) {
        createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, message, initiatorId, participants, auxTaskId, false);
    }

    public void createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message, int initiatorId, Set<Integer> participants, String auxTaskId, boolean isHotWallet) {
        logger.debug("createSignatureTaskWithIdAndGroupKey called: taskId={}, isHotWallet={}, signatureInProgress={}", 
            signatureTaskId, isHotWallet, signatureInProgress.get());
        if (!isHotWallet) {
            if (!signatureInProgress.compareAndSet(false, true)) {
                logger.warn("createSignatureTaskWithIdAndGroupKey FAILED: signatureInProgress is true, taskId={}", signatureTaskId);
                throw new RuntimeException("Signature process is already in progress (non-hotwallet)");
            }
        } else {
            AtomicInteger lock = hotWalletSignatureLocks.computeIfAbsent(groupPublicKey, k -> new AtomicInteger(0));
            int maxConcurrent = 10;
            if (lock.incrementAndGet() > maxConcurrent) {
                lock.decrementAndGet();
                logger.warn("createSignatureTaskWithIdAndGroupKey FAILED: too many concurrent tasks, taskId={}, groupPublicKey={}", 
                    signatureTaskId, groupPublicKey);
                throw new RuntimeException("Too many concurrent signature tasks for hot wallet: " + groupPublicKey);
            }
        }

        AuxInfo auxInfo;
        boolean isInitiator = (initiatorId == nodeId);
        
        if (isInitiator) {
            auxInfo = auxInfoDao.loadLatestSync(nodeId);
            if (auxInfo == null) {
                if (!isHotWallet) {
                    signatureInProgress.set(false);
                }
                throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before signature.");
            }
            logger.info("Initiator loaded latest aux info: auxTaskId={}", auxInfo.getTaskId());
        } else {
            if (auxTaskId == null || auxTaskId.isEmpty()) {
                logger.error("Participant received task without auxTaskId, terminating task {}", signatureTaskId);
                if (!isHotWallet) {
                    signatureInProgress.set(false);
                }
                throw new RuntimeException("Missing auxTaskId from initiator. Task terminated for security.");
            }
            
            auxInfo = auxInfoDao.loadLatestSync(nodeId);
            if (auxInfo == null) {
                if (!isHotWallet) {
                    signatureInProgress.set(false);
                }
                throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before signature.");
            }
            
            if (!auxTaskId.equals(auxInfo.getTaskId())) {
                logger.error("Aux task ID mismatch! Received={}, Local latest={}, terminating task {}", 
                    auxTaskId, auxInfo.getTaskId(), signatureTaskId);
                if (!isHotWallet) {
                    signatureInProgress.set(false);
                }
                throw new RuntimeException("Aux task ID mismatch. Expected: " + auxTaskId + 
                    ", Local latest: " + auxInfo.getTaskId() + ". Task terminated for security.");
            }
            logger.info("Participant verified aux task ID: received={}, local latest={}", auxTaskId, auxInfo.getTaskId());
        }

        String fixedGroupPublicKey;
        fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        CggmpSignatureTask task = new CggmpSignatureTask(signatureTaskId, message, fixedGroupPublicKey, nodesCount, threshold, initiatorId, participants, isHotWallet);
        task.auxTaskId = auxInfo.getTaskId();
        initTaskPaillierAndZkSetup(task, auxInfo);
        signatureTasks.put(signatureTaskId, task);
    }

    public String createPresignTask(String groupPublicKey, String message) {
        if (!signatureInProgress.compareAndSet(false, true)) {
            throw new RuntimeException("Signature process is already in progress");
        }

        AuxInfo auxInfo = auxInfoDao.loadLatestSync(nodeId);
        if (auxInfo == null) {
            signatureInProgress.set(false);
            throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before signature.");
        }
        logger.info("Initiator loaded latest aux info for presign task: auxTaskId={}", auxInfo.getTaskId());

        String fixedGroupPublicKey;
        fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        CggmpSignatureTask task = new CggmpSignatureTask(message, message, fixedGroupPublicKey, nodesCount, threshold, nodeId, null, true);
        task.auxTaskId = auxInfo.getTaskId();
        initTaskPaillierAndZkSetup(task, auxInfo);
        signatureTasks.put(message, task);
        return message;
    }

    public String getSignatureString(String taskId) {
        CggmpSignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return null;
        }
        return task.signature;
    }

    private void initTaskPaillierAndZkSetup(CggmpSignatureTask task, AuxInfo auxInfo) {
        BigInteger p = new BigInteger(auxInfo.getPaillierP(), 16);
        BigInteger q = new BigInteger(auxInfo.getPaillierQ(), 16);
        BigInteger n = new BigInteger(auxInfo.getPaillierN(), 16);
        BigInteger g = new BigInteger(auxInfo.getPaillierG(), 16);
        task.paillier = new PaillierEncryption(p, q);
        if (!task.paillier.getPublicKeyInfo().n().equals(n)) {
            throw new RuntimeException("AUX Paillier n mismatch");
        }
        if (!task.paillier.getPublicKeyInfo().g().equals(g)) {
            throw new RuntimeException("AUX Paillier g mismatch");
        }
        BigInteger hatN = new BigInteger(auxInfo.getPedersenHatN(), 16);
        BigInteger s = new BigInteger(auxInfo.getPedersenS(), 16);
        BigInteger t = new BigInteger(auxInfo.getPedersenT(), 16);
        task.zkSetup = new ZKSetup(hatN, s, t);
    }

    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId) {
        CggmpSignatureTask task = signatureTasks.get(taskId);
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

    public AuxInfo ensureLocalAuxReady(CggmpSignatureTask task) {
        AuxInfo info = auxInfoDao.loadLatestSync(nodeId);
        if (info == null) {
            String msg = "Missing auxiliary info on local node " + nodeId;
            if (task != null) {
                broadcastComplaint(task, null, msg, Map.of("nodeId", nodeId));
                failSignatureTask(task, msg);
            }
            throw new RuntimeException(msg);
        }
        try {
            Map<String, String> auxParams = com.example.mpc.common.util.DbMapUtils.buildAuxParams(info);
            String auxHash = hashJsonMap(auxParams);
            String taskId = task == null ? "null" : task.taskId;
            logger.debug("Loaded local AUX for signature task {} (nodeId={}, auxHash={})", taskId, nodeId, auxHash);
        } catch (Exception e) {
            logger.warn("Failed to compute local AUX hash (nodeId={}): {}", nodeId, e.getMessage());
        }
        return info;
    }

    public boolean ensurePeerAuxConsistency(CggmpSignatureTask task, int peerId, Map<String, String> auxParams) {
        if (task == null || auxParams == null) {
            return true;
        }
        Map<String, String> existing = task.peerAuxParams.putIfAbsent(peerId, new HashMap<>(auxParams));
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
        CggmpSignatureTask task = signatureTasks.get(taskId);
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
        CggmpSignatureTask task = signatureTasks.get(taskId);
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


    public void failSignatureTask(CggmpSignatureTask task, String reason) {
        if (task == null || task.isCompleted() || task.isFailed()) {
            return;
        }
        task.fail(reason);
        signatureInProgress.set(false);
        if (task.isHotWallet) {
            AtomicInteger lock = hotWalletSignatureLocks.get(task.groupPublicKey);
            if (lock != null) {
                lock.decrementAndGet();
            }
        }
    }

    public CompletableFuture<Void> broadcastComplaint(CggmpSignatureTask task, int offenderId, String reason) {
        return broadcastComplaint(task, offenderId, reason, null);
    }

    public CompletableFuture<Void> broadcastComplaint(CggmpSignatureTask task,
                                                      int offenderId,
                                                      String reason,
                                                      Map<String, Object> evidence) {
        return broadcastComplaint(task, Integer.valueOf(offenderId), reason, evidence);
    }

    public CompletableFuture<Void> broadcastComplaint(CggmpSignatureTask task,
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
        return RetryUtils.retryAsync(cggmpScheduler, logger,
                () -> nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_COMPLAINT");
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return messageDispatcher.handleMessage(senderId, message);
    }


    public void clearPresignLocal(CggmpSignatureTask task) {
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

    public void clearPresignAll(CggmpSignatureTask task) {
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
                            MessageType.CGGMP_SIGN_INIT,
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
        logger.debug("waitForLatchAsync started: label={}, timeout={}s, initialCount={}", label, timeoutSeconds, latch.getCount());
        ScheduledFuture<?> tick = cggmpScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                logger.debug("waitForLatchAsync completed: label={}, finalCount=0", label);
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                logger.warn("waitForLatchAsync timeout: label={}, remainingCount={}, timeout={}s", label, latch.getCount(), timeoutSeconds);
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    public String createPresignTaskOnly(String groupPublicKey) {
        int auxCount = auxInfoDao.countAuxSync(nodeId);
        if (auxCount == 0) {
            throw new RuntimeException("Missing auxiliary info. Run AUX provisioning first.");
        }

        logger.info("Creating presign-only task for groupPublicKey={}, nodeId={}", groupPublicKey, nodeId);

        try {
            AuxInfo auxInfo = auxInfoDao.loadLatestSync(nodeId);

            String fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
            fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');

            String taskId = "presign-offline-" + UUID.randomUUID().toString();
            CggmpSignatureTask task = new CggmpSignatureTask(taskId, "", fixedGroupPublicKey, nodesCount, threshold, nodeId, null, true);
            task.auxTaskId = auxInfo.getTaskId();
            initTaskPaillierAndZkSetup(task, auxInfo);
            signatureTasks.put(taskId, task);

            logger.info("Created presign-only task: {}", taskId);
            return taskId;
        } catch (RuntimeException e) {
            logger.error("Failed to create presign task: {}", e.getMessage());
            throw e;
        }
    }

    public Presignature executePresignOffline(String taskId) {
        CggmpSignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Presign task not found: " + taskId);
        }

        String groupPublicKey = task.groupPublicKey;
        try {
            if (!task.start()) {
                throw new RuntimeException("Failed to start presign task");
            }

            offlineHandler.initSignatureContext(task);

            offlineHandler.broadcastOfflineInit(task).get();
            offlineHandler.runOfflinePhase(task).get();

            waitForLatchAsync(task.offlineReadyLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline ready").get();

            waitForLatchAsync(task.presignatureLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presignature").get();

            Presignature presignature = task.presignature;
            if (presignature == null) {
                throw new RuntimeException("Presignature not generated");
            }

            logger.info("Presign offline completed for task: {}", taskId);
            return presignature;
        } catch (Exception e) {
            logger.error("Failed to execute presign offline: {}", e.getMessage());
            throw new RuntimeException(e);
        } finally {
            signatureTasks.remove(taskId);
            if (task != null && task.isHotWallet) {
                AtomicInteger lock = hotWalletSignatureLocks.get(groupPublicKey);
                if (lock != null) {
                    lock.decrementAndGet();
                    logger.debug("Released hotWalletSignatureLocks for groupPublicKey={}", groupPublicKey);
                }
            }
        }
    }

    public String signWithPresignature(String groupPublicKey, String message, Presignature presignature) {
        logger.info("signWithPresignature called: groupPublicKey={}, message={}, presignature={}", 
            groupPublicKey, message, presignature != null ? "present" : "null");
        
        if (!nodeService.areAllPeerConnectionsActive()) {
            throw new RuntimeException("Network not ready: not all peer connections are active");
        }
        
        AtomicInteger lock = hotWalletSignatureLocks.computeIfAbsent(groupPublicKey, k -> new AtomicInteger(0));
        int maxConcurrent = 10;
        if (lock.incrementAndGet() > maxConcurrent) {
            lock.decrementAndGet();
            throw new RuntimeException("Too many concurrent signature tasks for hot wallet: " + groupPublicKey);
        }

        String taskId = null;
        try {
            String fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
            fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');

            taskId = "sign-with-presign-" + UUID.randomUUID().toString();
            CggmpSignatureTask task = new CggmpSignatureTask(taskId, message, fixedGroupPublicKey, nodesCount, threshold, nodeId, null, true);
            
            AuxInfo auxInfo = auxInfoDao.loadLatestSync(nodeId);
            if (auxInfo == null) {
                throw new RuntimeException("Missing auxiliary info. Run AUX provisioning first.");
            }
            task.auxTaskId = auxInfo.getTaskId();
            initTaskPaillierAndZkSetup(task, auxInfo);
            
            task.presignature = presignature;
            if (presignature.deltaTilde() != null) {
                task.presignDeltaTilde.putAll(presignature.deltaTilde());
            }
            if (presignature.sTilde() != null) {
                task.presignSTilde.putAll(presignature.sTilde());
            }
            
            task.groupPublicKeyPoint = com.example.mpc.cggmp.util.Secp256k1CurveUtils.decodePoint(
                com.example.mpc.common.util.HexUtils.hexToBytes(fixedGroupPublicKey));
            
            task.messageHash = CggmpProtocolUtils.hashMessage(task.message);
            logger.info("Computed messageHash for presign signature (redacted)");
            
            signatureTasks.put(taskId, task);

            if (!task.start()) {
                throw new RuntimeException("Failed to start signature task");
            }

            for (int i = 0; i < task.participants.size() - 1; i++) {
                task.offlineDoneLatch.countDown();
            }
            task.presignatureLatch.countDown();
            logger.info("Pre-countdown {} offlineDoneLatch and presignatureLatch for presign signature (participants={})", task.participants.size() - 1, task.participants.size());

            String signature;
            try {
                onlineHandler.broadcastOnlineInit(task).get();
                
                for (int i = 0; i < task.participants.size() - 1; i++) {
                    task.offlineReadyLatch.countDown();
                }
                logger.info("Initiator countdown offlineReadyLatch for hot wallet task {}", taskId);
                
                waitForLatchAsync(task.offlineReadyLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "hot wallet participants ready").get();
                logger.info("All participants ready for hot wallet task {}", taskId);
                
                onlineHandler.runOnlinePhase(task).get();
                signature = getSignatureString(taskId);
                if (signature == null && task.signature != null) {
                    signature = task.signature;
                    logger.warn("getSignatureString returned null, using task.signature directly");
                }
                logger.info("Signature with presign completed for task: {} (signature redacted)", taskId);
            } finally {
                if (taskId != null) {
                    signatureTasks.remove(taskId);
                }
                AtomicInteger lockRef = hotWalletSignatureLocks.get(groupPublicKey);
                if (lockRef != null) {
                    lockRef.decrementAndGet();
                }
            }
            return signature;
        } catch (Exception e) {
            logger.error("Failed to sign with presignature: {}", e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
