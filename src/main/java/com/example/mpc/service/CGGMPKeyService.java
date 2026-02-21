package com.example.mpc.service;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CGGMPProtocol;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.Gg20Codec;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.util.ThreadPoolUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Base64;
import org.exploit.gmp.BigInt;
import org.exploit.secp256k1.Secp256k1;
import org.exploit.secp256k1.Secp256k1CurveParams;
import org.exploit.secp256k1.Secp256k1PointOps;
import org.exploit.sodium.SecretBox;
import org.exploit.tss.TSS;
import org.exploit.tss.ecdsa.GG20Client;
import org.exploit.tss.ecdsa.commitment.ChaumPedersenCommitment;
import org.exploit.tss.ecdsa.commitment.ChaumPedersenCommitmentWithValue;
import org.exploit.tss.ecdsa.commitment.GammaCommitment;
import org.exploit.tss.ecdsa.constant.GG20;
import org.exploit.tss.ecdsa.context.GG20Context;
import org.exploit.tss.ecdsa.context.crypto.CryptoContext;
import org.exploit.tss.ecdsa.context.init.InitContext;
import org.exploit.tss.ecdsa.context.mta.MtAContext;
import org.exploit.tss.ecdsa.context.signature.SignatureContext;
import org.exploit.tss.ecdsa.generator.GG20CommitmentGenerator;
import org.exploit.tss.mta.model.MtAInitiatorMessage;
import org.exploit.tss.mta.model.MtAResult;
import org.exploit.tss.pallier.key.PaillierPublicKey;
import org.exploit.tss.proof.model.ZKSetup;
import org.exploit.tss.signature.ECDSASignature;
import org.exploit.tss.util.Hash;
import org.exploit.tss.util.ZKRandom;

@Service
public class CGGMPKeyService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CGGMPKeyService.class);

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Value("${node.id}")
    private int nodeId;

    private CGGMP cggmp;
    private CGGMPProtocol protocol;
    private PaillierEncryption paillier;

    private final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();

    private static final ExecutorService dkgExecutorService = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "CGGMP-DKG-Thread");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean dkgInProgress = new AtomicBoolean(false);
    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;
    private final ConcurrentHashMap<String, Object> cryptoCache = new ConcurrentHashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initialize() throws Exception {
        logger.info("Initializing CGGMP service for node {}", nodeId);
        this.paillier = new PaillierEncryption();
        logger.info("CGGMP service initialized successfully");
    }

    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        CggmpDkgTask task = new CggmpDkgTask(taskId, nodesCount, threshold);
        dkgTasks.put(taskId, task);
        logger.info("Created CGGMP DKG task: {}", taskId);
        return taskId;
    }

    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return CompletableFuture.runAsync(() -> {
            logger.info("=================== startDkgProcess START: taskId={} ===================", taskId);
            CggmpDkgTask task = null;
            try {
                task = getDkgTask(taskId);
                
                if (!task.start()) {
                    logger.warn("DKG task {} failed to start (may already be in progress), skipping", taskId);
                    return;
                }

                logger.info("Starting CGGMP DKG process for task: {}", taskId);

                logger.info("Waiting for network ready...");
                nodeService.waitForNetworkReady().join();

                int networkSize = nodeService.getNodes().size() + 1;
                if (networkSize < nodesCount) {
                    throw new RuntimeException("Not enough nodes in network. Expected: " + nodesCount + ", found: " + networkSize);
                }
                logger.info("Network ready with {} nodes", networkSize);

                try {
                    Thread.sleep(Constants.DKG_INIT_WAIT_TIME_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }

                Map<String, Object> initData = new HashMap<>();
                initData.put("taskId", taskId);
                initData.put("nodesCount", Constants.NODES_COUNT);
                
                boolean initBroadcastSuccess = false;
                for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
                    try {
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_INIT, initData)).join();
                        logger.info("Broadcasted CGGMP_DKG_INIT for task: {} (attempt {}/{})", taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                        initBroadcastSuccess = true;
                        break;
                    } catch (Exception e) {
                        logger.warn("Failed to broadcast CGGMP_DKG_INIT (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                        if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                            Thread.sleep(Constants.DKG_BROADCAST_RETRY_DELAY_MS);
                        }
                    }
                }
                
                if (!initBroadcastSuccess) {
                    throw new RuntimeException("Failed to broadcast CGGMP_DKG_INIT after 3 attempts");
                }

                executeDkgRounds(task);

                saveKeyShareToDatabase(task);

                task.complete();
                logger.info("CGGMP DKG process completed for task: {}", taskId);
            } catch (Exception e) {
                if (task != null) {
                    task.fail();
                    task.errorMessage = e.getMessage();
                }
                logger.error("Error in CGGMP DKG process", e);
                throw new RuntimeException(e);
            }
        }, dkgExecutorService);
    }

    private void executeDkgRounds(CggmpDkgTask task) throws Exception {
        logger.info("Node {} executing DKG Round 1", nodeId);
        
        task.cggmpInstance = new CGGMP(threshold, nodesCount, nodeId, Constants.CURVE_NAME);
        CGGMP.DkgRound1Output round1Output = task.cggmpInstance.dkgRound1();
        task.round1Outputs.put(nodeId, round1Output);

        Map<String, Object> round1Data = new HashMap<>();
        round1Data.put("taskId", task.taskId);
        round1Data.put("nodeId", round1Output.nodeId);
        round1Data.put("commitments", encodeCommitments(round1Output.commitments));
        round1Data.put("paillierKey", round1Output.paillierKey.n.toString(16));

        boolean round1BroadcastSuccess = false;
        for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
            try {
                nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_ROUND1, round1Data)).join();
                logger.info("Broadcasted CGGMP_DKG_ROUND1 for task: {} (attempt {}/{})", task.taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                round1BroadcastSuccess = true;
                break;
            } catch (Exception e) {
                logger.warn("Failed to broadcast CGGMP_DKG_ROUND1 (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.DKG_BROADCAST_RETRY_DELAY_MS);
                }
            }
        }
        
        if (!round1BroadcastSuccess) {
            throw new RuntimeException("Failed to broadcast CGGMP_DKG_ROUND1 after " + Constants.DKG_BROADCAST_RETRY_COUNT + " attempts");
        }

        task.startRound1Waiting();
        logger.info("Node {} waiting for Round 1 messages...", nodeId);
        if (!task.round1ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for Round 1 messages");
        }

        logger.info("Node {} executing DKG Round 2", nodeId);
        CGGMP.DkgRound2Output round2Output = task.cggmpInstance.dkgRound2(task.round1Outputs);
        task.round2Outputs.put(nodeId, round2Output);

        boolean round2SendSuccess = false;
        for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
            try {
                for (Map.Entry<Integer, BigInteger> entry : round2Output.shares.entrySet()) {
                    int receiverId = entry.getKey();
                    BigInteger share = entry.getValue();

                    Map<String, Object> round2Data = new HashMap<>();
                    round2Data.put("taskId", task.taskId);
                    round2Data.put("nodeId", round2Output.nodeId);
                    round2Data.put("receiverId", receiverId);
                    round2Data.put("share", share.toString(16));

                    nodeService.sendMessage(receiverId, new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_ROUND2, round2Data)).join();
                }
                logger.info("Sent CGGMP_DKG_ROUND2 shares for task: {} (attempt {}/{})", task.taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                round2SendSuccess = true;
                break;
            } catch (Exception e) {
                logger.warn("Failed to send CGGMP_DKG_ROUND2 shares (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.DKG_BROADCAST_RETRY_DELAY_MS);
                }
            }
        }
        
        if (!round2SendSuccess) {
            throw new RuntimeException("Failed to send CGGMP_DKG_ROUND2 shares after " + Constants.DKG_BROADCAST_RETRY_COUNT + " attempts");
        }

        task.startRound2Waiting();
        logger.info("Node {} waiting for Round 2 messages...", nodeId);
        if (!task.round2ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for Round 2 messages");
        }

        task.startValidating();
        logger.info("Node {} completing DKG", nodeId);
        boolean success = task.cggmpInstance.dkgRound3(task.round2Outputs, task.round1Outputs);
        
        if (!success) {
            throw new Exception("CGGMP DKG failed in Round 3");
        }

        task.secretShare = task.cggmpInstance.getSecretShare();
        task.groupPublicKey = task.cggmpInstance.getPublicKey();
        task.groupPublicKeyHex = bytesToHex(task.groupPublicKey.getEncoded(false));
        
        logger.info("CGGMP DKG completed! Group public key: {}", task.groupPublicKeyHex);
    }

    public Map<String, Object> getTaskStatus(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        Map<String, Object> status = new HashMap<>();
        status.put("taskId", task.taskId);
        status.put("status", task.status.get().name());
        status.put("inProgress", task.isInProgress());
        status.put("completed", task.isCompleted());
        status.put("groupPublicKey", task.groupPublicKeyHex);
        status.put("errorMessage", task.errorMessage);
        status.put("receivedRound1", task.round1Outputs.size());
        status.put("receivedRound2", task.round2Outputs.size());
        return status;
    }

    public String getGroupPublicKey(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        if (!task.isCompleted()) {
            return null;
        }
        return task.groupPublicKeyHex;
    }

    public BigInteger getSecretShare() {
        return cggmp != null ? cggmp.getSecretShare() : null;
    }

    public ECPoint getPublicKey() {
        return cggmp != null ? cggmp.getPublicKey() : null;
    }

    public CGGMP getCggmp() {
        return cggmp;
    }

    public CGGMPProtocol getProtocol() {
        return protocol;
    }

    private void handleCggmpDkgInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            int nodesCount = (Integer) dataMap.get("nodesCount");
            logger.info("Received CGGMP_DKG_INIT from node {} for task: {}, nodesCount: {}", senderId, taskId, nodesCount);
            
            CggmpDkgTask task = new CggmpDkgTask(taskId, nodesCount, threshold);
            CggmpDkgTask existingTask = dkgTasks.putIfAbsent(taskId, task);
            
            if (existingTask != null) {
                logger.info("DKG task {} already exists, skipping creation", taskId);
                return;
            }
            
            logger.info("Created DKG task {} on node {}", taskId, nodeId);
            
            startDkgProcess(taskId);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound1(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND1 from node {} for task: {}", senderId, taskId);
            
            try {
                CggmpDkgTask task = dkgTasks.get(taskId);
                if (task == null) {
                    logger.warn("Task {} not found in dkgTasks, ignoring Round1 from node {}", taskId, senderId);
                    return;
                }
                
                int senderNodeId = (Integer) dataMap.get("nodeId");
                if (senderNodeId != senderId) {
                    logger.warn("Discarding CGGMP_DKG_ROUND1: senderId {} does not match payload nodeId {}", senderId, senderNodeId);
                    return;
                }
                
                // 检查是否是重复消息（自己已经处理过了）
                // 注意：如果 senderNodeId == nodeId（当前节点），则这是我们自己之前已经处理过的消息，应该跳过
                if (senderNodeId == nodeId) {
                    logger.info("Received Round1 from self (node {}), this is our own message, skipping", senderNodeId);
                    return;
                }
                
                logger.info("=== DEBUG: senderId={}, senderNodeId={}, match={} ===", senderId, senderNodeId, senderId == senderNodeId);
                
                if (task.round1Outputs.containsKey(senderNodeId)) {
                    logger.info("Already received Round1 from node {}, skipping", senderNodeId);
                    return;
                }
                
                List<String> commitmentHexList = (List<String>) dataMap.get("commitments");
                String paillierKeyHex = (String) dataMap.get("paillierKey");
                
                logger.info("Processing Round1 from node {}: commitments={}, paillierKey={}", 
                    senderNodeId, commitmentHexList != null ? commitmentHexList.size() : "null", 
                    paillierKeyHex != null ? "present" : "null");
                
                if (commitmentHexList == null || commitmentHexList.size() != threshold) {
                    logger.warn("Invalid commitments size from node {}: expected {}, got {}", senderNodeId, threshold, commitmentHexList == null ? "null" : commitmentHexList.size());
                    return;
                }
                List<ECPoint> commitments = new ArrayList<>();
                for (String hex : commitmentHexList) {
                    ECPoint point = decodeECPoint(HexUtils.hexToBytes(hex));
                    if (point == null || point.isInfinity() || !point.isValid()) {
                        logger.warn("Invalid commitment point from node {} for task {}", senderNodeId, taskId);
                        return;
                    }
                    commitments.add(point);
                }
                
                PaillierEncryption.PublicKey paillierKey = new PaillierEncryption.PublicKey(new BigInteger(paillierKeyHex, 16));
                CGGMP.DkgRound1Output output = new CGGMP.DkgRound1Output(senderNodeId, null, commitments, paillierKey);
                boolean first = task.round1Outputs.putIfAbsent(senderNodeId, output) == null;
                if (first) {
                    logger.info("=== BEFORE countDown: latch count = {} ===", task.round1ReceivedLatch.getCount());
                    task.round1ReceivedLatch.countDown();
                    logger.info("=== AFTER countDown: latch count = {} ===", task.round1ReceivedLatch.getCount());
                }
                logger.info("Stored Round1 from node {} for task: {}", senderNodeId, taskId);
            } catch (Exception e) {
                logger.error("Error handling CGGMP_DKG_ROUND1: {}", e.getMessage(), e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound2(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND2 from node {} for task: {}", senderId, taskId);
            
            try {
                CggmpDkgTask task = dkgTasks.get(taskId);
                if (task != null) {
                    int senderNodeId = (Integer) dataMap.get("nodeId");
                    if (senderNodeId != senderId) {
                        logger.warn("Discarding CGGMP_DKG_ROUND2: senderId {} does not match payload nodeId {}", senderId, senderNodeId);
                        return;
                    }
                    
                    if (senderNodeId == nodeId) {
                        logger.info("Received Round2 from self (node {}), this is our own message, skipping", senderNodeId);
                        return;
                    }
                    
                    if (task.round2Outputs.containsKey(senderNodeId)) {
                        logger.info("Already received Round2 from node {}, skipping", senderNodeId);
                        return;
                    }
                    
                    Integer receiverId = (Integer) dataMap.get("receiverId");
                    String shareHex = (String) dataMap.get("share");
                    if (receiverId == null || shareHex == null) {
                        logger.warn("Invalid CGGMP_DKG_ROUND2 payload from node {} for task {}", senderNodeId, taskId);
                        return;
                    }
                    if (receiverId != nodeId) {
                        logger.info("CGGMP_DKG_ROUND2 not intended for this node (receiverId={}, nodeId={}), ignoring", receiverId, nodeId);
                        return;
                    }
                    Map<Integer, BigInteger> shares = new HashMap<>();
                    shares.put(nodeId, new BigInteger(shareHex, 16));
                    
                    CGGMP.DkgRound2Output output = new CGGMP.DkgRound2Output(senderNodeId, shares);
                    boolean first = task.round2Outputs.putIfAbsent(senderNodeId, output) == null;
                    if (first) {
                        task.round2ReceivedLatch.countDown();
                    }
                    logger.info("Stored Round2 from node {} for task: {}", senderNodeId, taskId);
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP_DKG_ROUND2: {}", e.getMessage(), e);
            }
        }
    }

    private CggmpDkgTask getDkgTask(String taskId) {
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("CGGMP DKG task not found: " + taskId);
        }
        return task;
    }

    private List<String> encodeCommitments(List<ECPoint> commitments) {
        List<String> result = new ArrayList<>();
        for (ECPoint point : commitments) {
            result.add(bytesToHex(point.getEncoded(false)));
        }
        return result;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void saveKeyShareToDatabase(CggmpDkgTask task) {
        try {
            String shareHex = task.secretShare.toString(16);
            KeyShare keyShare = new KeyShare(nodeId, shareHex, task.groupPublicKeyHex, task.taskId);
            keyShareDao.save(keyShare);
            logger.info("Saved CGGMP key share to database for task: {}", task.taskId);
        } catch (Exception e) {
            logger.error("Failed to save CGGMP key share to database", e);
        }
    }

    private static final int GG20_MEM_KEY_SIZE = 32;

    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message) {
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
        if (signatureInProgress.get()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature process is already in progress"));
        }

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

        signatureInProgress.set(true);
        if (!task.start()) {
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(new RuntimeException("Failed to start signature task"));
        }

        return CompletableFuture.runAsync(() -> {
            try {
                if (broadcastInit) {
                    Map<String, Object> initData = new HashMap<>();
                    initData.put("signatureTaskId", task.taskId);
                    initData.put("groupPublicKey", task.groupPublicKey);
                    initData.put("message", task.message);
                    initData.put("initiatorId", task.initiatorId);
                    initData.put("participants", new ArrayList<>(task.participants));
                    initData.put("messageHash", Base64.getEncoder().encodeToString(hashMessage(task.message)));
                    try {
                        for (int attempt = 1; attempt <= Constants.SIGNATURE_BROADCAST_RETRY_COUNT; attempt++) {
                            nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.GG20_SIGN_INIT, initData)).join();
                            logger.info("Broadcasted GG20_SIGN_INIT for signature task: {} (attempt {}/{})", task.taskId, attempt, Constants.SIGNATURE_BROADCAST_RETRY_COUNT);
                            if (attempt < Constants.SIGNATURE_BROADCAST_RETRY_COUNT) {
                                Thread.sleep(Constants.SIGNATURE_BROADCAST_RETRY_DELAY_MS);
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to broadcast GG20_SIGN_INIT, proceeding with signature: {}", e.getMessage());
                    }
                }

                initGg20Client(task);

                // Round 1: Gamma commitment
                broadcastGammaCommitment(task).join();
                if (!task.gammaCommitmentLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for gamma commitments");
                }

                // MtA init and responses (only for local initiator)
                broadcastMtaInit(task).join();
                if (!task.mtaResponseLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for MtA responses");
                }

                // Offline phase data
                broadcastOfflineData(task).join();
                if (!task.offlineLatch.await(Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for offline phase");
                }

                BigInt partialS = task.client.signature().computePartialS();
                if (nodeId == task.initiatorId) {
                    storePartialS(task, nodeId, partialS);
                    if (!task.partialSLatch.await(Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for partial signatures");
                    }
                    ECDSASignature signature = task.client.aggregator().calculateSignature();
                    String finalSignature = Base64.getEncoder().encodeToString(signature.der());
                    byte[] sigBytes = signature.encode();
                    byte[] pubCompressed = task.client.context().crypto().publicKey().encode(true);
                    boolean verified = Secp256k1.verifyRecoverable(task.messageHash, sigBytes, pubCompressed);
                    task.signature = finalSignature;
                    task.verified = verified;
                    task.complete();
                    signatureInProgress.set(false);
                    logger.info("GG20 signature task {} completed successfully, verified: {}", taskId, verified);
                } else {
                    sendPartialS(task, partialS);
                    task.complete();
                    signatureInProgress.set(false);
                }
            } catch (Exception e) {
                logger.error("Error in GG20 signature process: {}", e.getMessage());
                task.fail(e.getMessage());
                signatureInProgress.set(false);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
    }

    public Map<String, Object> getSignatureTaskStatus(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        Map<String, Object> status = new HashMap<>();
        status.put("taskId", task.taskId);
        status.put("groupPublicKey", task.groupPublicKey);
        status.put("inProgress", task.isInProgress());
        status.put("completed", task.isCompleted());
        status.put("status", task.status.get().name());
        status.put("message", task.message);
        status.put("errorMessage", task.errorMessage);
        status.put("participants", new ArrayList<>(task.participants));
        status.put("receivedGammaCommitments", task.participants.size() - 1 - (int) task.gammaCommitmentLatch.getCount());
        status.put("receivedMtaResponses", task.participants.size() - 1 - (int) task.mtaResponseLatch.getCount());
        status.put("receivedOffline", task.participants.size() - 1 - (int) task.offlineLatch.getCount());
        status.put("receivedPartialS", task.participants.size() - 1 - (int) task.partialSLatch.getCount());
        return status;
    }

    public Map<String, Object> getSignatureResult(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        if (!task.isCompleted()) {
            throw new RuntimeException("Signature task not completed yet: " + taskId);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("taskId", task.taskId);
        result.put("groupPublicKey", task.groupPublicKey);
        result.put("signature", task.signature);
        result.put("verified", task.verified);
        result.put("message", task.message);
        return result;
    }

    private byte[] hashMessage(String message) {
        return Hash.sha256(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private void initGg20Client(Gg20SignatureTask task) {
        if (task.client != null) {
            return;
        }
        TSS.loadLibraries();
        if (task.curveParams == null) {
            task.curveParams = new Secp256k1CurveParams();
        }
        if (task.messageHash == null) {
            task.messageHash = hashMessage(task.message);
        }
        if (task.memKey == null) {
            task.memKey = new byte[GG20_MEM_KEY_SIZE];
            ZKRandom.getRandom().nextBytes(task.memKey);
        }

        KeyShare keyShare = loadKeyShareByGroupPublicKey(task.groupPublicKey).join();
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        SecretBox ski = SecretBox.of(share.toByteArray(), task.memKey, false);
        Secp256k1PointOps publicKey = task.curveParams.decodePoint(HexUtils.hexToBytes(task.groupPublicKey));

        InitContext initContext = InitContext.inMemoryBuilder()
            .additionalContext(task.taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8))
            .message(task.messageHash)
            .build();

        CryptoContext<Secp256k1PointOps> cryptoContext = CryptoContext.inMemoryBuilder(Secp256k1PointOps.class)
            .idx(nodeId)
            .ski(ski)
            .participants(new ArrayList<>(task.participants))
            .memKey(() -> task.memKey.clone())
            .publicKey(publicKey)
            .curve(task.curveParams)
            .build();

        GG20Context<Secp256k1PointOps> context = GG20Context.newBuilder(Secp256k1PointOps.class)
            .init(initContext)
            .mta(MtAContext.inMemory())
            .crypto(cryptoContext)
            .signature(SignatureContext.inMemory())
            .build();

        GG20CommitmentGenerator<Secp256k1PointOps> generator = new GG20CommitmentGenerator<>(
            task.curveParams.getCurveOrder(),
            task.curveParams.getG(),
            task.curveParams.getGeneratorH()
        );
        task.client = new GG20Client<>(task.taskId, context, generator);
        task.client.init();
    }

    private CompletableFuture<Void> broadcastGammaCommitment(Gg20SignatureTask task) {
        var commitment = task.client.context().crypto().ephemeral();
        GammaCommitment<Secp256k1PointOps> gammaCommitment = new GammaCommitment<>(commitment.commitment(), commitment.r_i());
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("commitment", Gg20Codec.encodeGammaCommitment(gammaCommitment));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.GG20_GAMMA_COMMITMENT, data))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast GG20_GAMMA_COMMITMENT: {}", ex.getMessage());
                return null;
            });
    }

    private CompletableFuture<Void> broadcastMtaInit(Gg20SignatureTask task) {
        MtAInitiatorMessage initiatorMessage = task.client.context().mta().initiator().message();
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("initiatorId", nodeId);
        data.put("paillierPublicKey", Gg20Codec.encodePaillierPublicKey(task.client.context().crypto().paillier().publicKey()));
        data.put("zkSetup", Gg20Codec.encodeZkSetup(task.client.context().crypto().zkSetup()));
        data.put("initiatorMessage", Gg20Codec.encodeMtAInitiatorMessage(initiatorMessage));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.GG20_MTA_INIT, data))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast GG20_MTA_INIT: {}", ex.getMessage());
                return null;
            });
    }

    private CompletableFuture<Void> broadcastOfflineData(Gg20SignatureTask task) {
        var commitment = task.client.context().crypto().ephemeral();
        var gamma = commitment.Gamma_i();
        BigInt deltaShare = task.client.signature().computeDeltaShare();
        ChaumPedersenCommitmentWithValue<Secp256k1PointOps> lambdaCommitment = task.client.integrity().computeLambdaI();
        ChaumPedersenCommitment<Secp256k1PointOps> sigmaCommitment = task.client.integrity().computeSigmaCommitment();

        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("gamma", Gg20Codec.encodePoint(gamma));
        data.put("deltaShare", Gg20Codec.encodeBigInt(deltaShare));
        data.put("lambdaCommitment", Gg20Codec.encodeChaumCommitmentWithValue(lambdaCommitment));
        data.put("sigmaCommitment", Gg20Codec.encodeChaumCommitment(sigmaCommitment));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.GG20_OFFLINE, data))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast GG20_OFFLINE: {}", ex.getMessage());
                return null;
            });
    }

    private void storePartialS(Gg20SignatureTask task, int senderId, BigInt partialS) {
        task.client.context().aggregator().storePartialS(senderId, partialS);
        if (senderId != task.initiatorId && task.partialSReceived.putIfAbsent(senderId, Boolean.TRUE) == null) {
            task.partialSLatch.countDown();
        }
    }

    private void sendPartialS(Gg20SignatureTask task, BigInt partialS) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("partialS", Gg20Codec.encodeBigInt(partialS));
        nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, NodeService.Message.Type.GG20_PARTIAL_S, data))
            .exceptionally(ex -> {
                logger.error("Failed to send GG20_PARTIAL_S: {}", ex.getMessage());
                return null;
            });
    }

    private ECPublicKey getEcPublicKey() throws Exception {
        String cacheKey = "ecPublicKey_" + Constants.CURVE_NAME;
        return (ECPublicKey) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyGen.initialize(ecSpec);
                KeyPair keyPair = keyGen.generateKeyPair();
                return keyPair.getPublic();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private BigInteger getCurveOrder() throws Exception {
        String cacheKey = "curveOrder_" + Constants.CURVE_NAME;
        return (BigInteger) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                return getEcPublicKey().getParameters().getN();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private ECPoint getInfinityPoint() throws Exception {
        String cacheKey = "infinityPoint_" + Constants.CURVE_NAME;
        return (ECPoint) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                return getEcPublicKey().getParameters().getCurve().getInfinity();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    private BigInteger generateSecureRandom() {
        return new BigInteger(256, new SecureRandom());
    }

    private ECPoint generateCommitment(BigInteger k) throws Exception {
        ECPoint G = getEcPublicKey().getParameters().getG();
        return G.multiply(k);
    }


    private CompletableFuture<KeyShare> loadKeyShareByGroupPublicKey(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKey(nodeId, groupPublicKey);
    }

    private ECPoint decodeECPoint(byte[] encoded) throws Exception {
        return getEcPublicKey().getParameters().getCurve().decodePoint(encoded);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===", 
            senderId, message.type, message.data instanceof Map ? ((Map<?,?>)message.data).get("taskId") : "N/A");
        return CompletableFuture.runAsync(() -> {
            try {
                logger.info("=== CGGMP processing: type={} ===", message.type);
                switch (message.type) {
                    case CGGMP_DKG_INIT:
                        handleCggmpDkgInit(senderId, message.data);
                        break;
                    case CGGMP_DKG_ROUND1:
                        handleCggmpDkgRound1(senderId, message.data);
                        break;
                    case CGGMP_DKG_ROUND2:
                        handleCggmpDkgRound2(senderId, message.data);
                        break;
                    case GG20_SIGN_INIT:
                        handleGg20SignInit(senderId, message.data);
                        break;
                    case GG20_GAMMA_COMMITMENT:
                        handleGg20GammaCommitment(senderId, message.data);
                        break;
                    case GG20_MTA_INIT:
                        handleGg20MtaInit(senderId, message.data);
                        break;
                    case GG20_MTA_RESPONSE:
                        handleGg20MtaResponse(senderId, message.data);
                        break;
                    case GG20_OFFLINE:
                        handleGg20Offline(senderId, message.data);
                        break;
                    case GG20_PARTIAL_S:
                        handleGg20PartialS(senderId, message.data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP service", message.type);
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP message", e);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }

    private void handleGg20SignInit(int senderId, Object data) {
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
            byte[] messageHash = null;
            Object messageHashValue = dataMap.get("messageHash");
            if (messageHashValue instanceof String hashString) {
                messageHash = Base64.getDecoder().decode(hashString);
            }
            final byte[] messageHashFinal = messageHash;

            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                if (!signatureTasks.containsKey(signatureTaskId)) {
                    int resolvedInitiatorId = initiatorId != null ? initiatorId : senderId;
                    Set<Integer> participantsSet = participants == null ? null : new LinkedHashSet<>(participants);
                    createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg, resolvedInitiatorId, participantsSet);
                    logger.info("Created GG20 signature task with group key from GG20_SIGN_INIT: {}", signatureTaskId);
                    CompletableFuture.runAsync(() -> {
                        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
                        if (task == null) {
                            return;
                        }
                        if (messageHashFinal != null) {
                            task.messageHash = messageHashFinal;
                        }
                        if (!task.participants.contains(nodeId)) {
                            logger.info("Node {} not selected for GG20 signature task {}, participants={}, skipping", nodeId, signatureTaskId, task.participants);
                            return;
                        }
                        startSignatureTaskInternal(signatureTaskId, false)
                            .exceptionally(ex -> {
                                logger.error("Failed to start GG20 signature task {} from GG20_SIGN_INIT: {}", signatureTaskId, ex.getMessage());
                                return null;
                            });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    logger.info("GG20 signature task {} already exists, ignoring GG20_SIGN_INIT", signatureTaskId);
                }
            } else {
                logger.warn("Invalid GG20_SIGN_INIT payload from node {}", senderId);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleGg20GammaCommitment(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object commitmentObj = dataMap.get("commitment");
        if (!(commitmentObj instanceof Map<?, ?> commitmentMap)) {
            logger.warn("Invalid GG20_GAMMA_COMMITMENT payload from node {}", senderId);
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            initGg20Client(task);
            GammaCommitment<Secp256k1PointOps> commitment = Gg20Codec.decodeGammaCommitment(task.curveParams, commitmentMap);
            task.client.context().integrity().storeGammaCommitment(senderId, commitment);
            if (task.gammaCommitmentLatch.getCount() > 0) {
                task.gammaCommitmentLatch.countDown();
            }
            logger.info("Received GG20_GAMMA_COMMITMENT from node {} for task {}", senderId, taskId);
        } catch (Exception e) {
            logger.error("Failed to handle GG20_GAMMA_COMMITMENT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleGg20MtaInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        if (initiatorValue == null) {
            logger.warn("Invalid GG20_MTA_INIT payload from node {}", senderId);
            return;
        }
        int initiatorId = initiatorValue.intValue();
        if (initiatorId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(nodeId)) {
            return;
        }
        try {
            initGg20Client(task);
            PaillierPublicKey publicKey = Gg20Codec.decodePaillierPublicKey((Map<?, ?>) dataMap.get("paillierPublicKey"));
            ZKSetup zkSetup = Gg20Codec.decodeZkSetup((Map<?, ?>) dataMap.get("zkSetup"));
            MtAInitiatorMessage initiatorMessage = Gg20Codec.decodeMtAInitiatorMessage((Map<?, ?>) dataMap.get("initiatorMessage"));
            MtAResult alpha = task.client.mta().asRespondent().compute(GG20.ComputationType.GAMMA, initiatorId, publicKey, zkSetup, initiatorMessage);
            MtAResult mu = task.client.mta().asRespondent().compute(GG20.ComputationType.LAGRANGE, initiatorId, publicKey, zkSetup, initiatorMessage);

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", nodeId);
            resp.put("alpha", Gg20Codec.encodeMtAResult(alpha));
            resp.put("mu", Gg20Codec.encodeMtAResult(mu));
            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, NodeService.Message.Type.GG20_MTA_RESPONSE, resp)).join();
        } catch (Exception e) {
            logger.error("Failed to handle GG20_MTA_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleGg20MtaResponse(int senderId, Object data) {
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
        if (initiatorId != nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            initGg20Client(task);
            MtAResult alpha = Gg20Codec.decodeMtAResult((Map<?, ?>) dataMap.get("alpha"));
            MtAResult mu = Gg20Codec.decodeMtAResult((Map<?, ?>) dataMap.get("mu"));
            task.client.mta().asInitiator().store(GG20.ComputationType.GAMMA, responderId, alpha);
            task.client.mta().asInitiator().store(GG20.ComputationType.LAGRANGE, responderId, mu);
            if (task.mtaResponses.putIfAbsent(responderId, Boolean.TRUE) == null) {
                task.mtaResponseLatch.countDown();
            }
            logger.info("Received GG20_MTA_RESPONSE from node {} for task {}", senderId, taskId);
        } catch (Exception e) {
            logger.error("Failed to handle GG20_MTA_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleGg20Offline(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            initGg20Client(task);
            Secp256k1PointOps gamma = Gg20Codec.decodePoint(task.curveParams, (String) dataMap.get("gamma"));
            BigInt deltaShare = Gg20Codec.decodeBigInt((String) dataMap.get("deltaShare"));
            ChaumPedersenCommitmentWithValue<Secp256k1PointOps> lambdaCommitment =
                Gg20Codec.decodeChaumCommitmentWithValue(task.curveParams, (Map<?, ?>) dataMap.get("lambdaCommitment"));
            ChaumPedersenCommitment<Secp256k1PointOps> sigmaCommitment =
                Gg20Codec.decodeChaumCommitment(task.curveParams, (Map<?, ?>) dataMap.get("sigmaCommitment"));

            task.client.signature().storeGamma(senderId, gamma);
            task.client.context().signature().storeDeltaShare(senderId, deltaShare);
            task.client.integrity().storeLambdaCommitment(senderId, lambdaCommitment);
            task.client.integrity().storeSigmaCommitment(senderId, sigmaCommitment);
            if (task.offlineReceived.putIfAbsent(senderId, Boolean.TRUE) == null) {
                task.offlineLatch.countDown();
            }
            logger.info("Received GG20_OFFLINE from node {} for task {}", senderId, taskId);
        } catch (Exception e) {
            logger.error("Failed to handle GG20_OFFLINE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleGg20PartialS(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String sEncoded = (String) dataMap.get("partialS");
        if (sEncoded == null) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        BigInt partialS = Gg20Codec.decodeBigInt(sEncoded);
        storePartialS(task, senderId, partialS);
        logger.info("Received GG20_PARTIAL_S from node {} for task {}", senderId, taskId);
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return ThreadPoolUtil.submitIoTask(() -> {
            try {
                nodeService.startP2PServer().join();
                nodeService.registerMessageHandler(-1, this);
                logger.info("CGGMP signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
