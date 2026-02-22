package com.example.mpc.service;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CggmpDkgCodec;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.sign.EcSchnorrProof;
import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.model.KeyShare;
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

@Service
public class CggmpSignatureService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureService.class);

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Value("${node.id}")
    private int nodeId;

    private final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();

    private static final ExecutorService dkgExecutorService = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "CGGMP-DKG-Thread");
        t.setDaemon(true);
        return t;
    });

    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initialize() throws Exception {
        logger.info("Initializing CGGMP service for node {}", nodeId);
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
                    Thread.sleep(Constants.DKG_INIT_WAIT_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }

                Map<String, Object> initData = new HashMap<>();
                initData.put("taskId", taskId);
                initData.put("nodesCount", Constants.NODES_COUNT);

                boolean initBroadcastSuccess = false;
                for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
                    try {
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_INIT, initData)).join();
                        logger.info("Broadcasted CGGMP_DKG_INIT for task: {} (attempt {}/{})", taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                        initBroadcastSuccess = true;
                        break;
                    } catch (Exception e) {
                        logger.warn("Failed to broadcast CGGMP_DKG_INIT (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                        if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                            Thread.sleep(Constants.DKG_BROADCAST_RETRY_INTERVAL_MS);
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
        byte[] dkgContext = task.taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        CGGMP.DkgRound1Output round1Output = task.cggmpInstance.dkgRound1(dkgContext);
        task.round1Outputs.put(nodeId, round1Output);
        task.peerPaillierKeys.put(nodeId, round1Output.paillierKey);
        task.peerZkSetups.put(nodeId, round1Output.zkSetup);

        Map<String, Object> round1Data = new HashMap<>();
        round1Data.put("taskId", task.taskId);
        round1Data.put("nodeId", round1Output.nodeId);
        round1Data.put("commitments", encodeCommitments(round1Output.commitments));
        round1Data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(round1Output.paillierKey));
        round1Data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(round1Output.zkSetup));
        round1Data.put("biPrimeProof", CggmpDkgCodec.encodeBiPrimeProof(round1Output.biPrimeProof));
        round1Data.put("factorProof", CggmpDkgCodec.encodeNoSmallFactorProof(round1Output.factorProof));

        boolean round1BroadcastSuccess = false;
        for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
            try {
                nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, round1Data)).join();
                logger.info("Broadcasted CGGMP_DKG_ROUND1 for task: {} (attempt {}/{})", task.taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                round1BroadcastSuccess = true;
                break;
            } catch (Exception e) {
                logger.warn("Failed to broadcast CGGMP_DKG_ROUND1 (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.DKG_BROADCAST_RETRY_INTERVAL_MS);
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

        logger.info("Node {} executing DKG Round 2 (MtA shares)", nodeId);
        CGGMP.DkgRound2Output round2Output = task.cggmpInstance.dkgRound2(task.round1Outputs);

        MtAProtocol mtaProtocol = new MtAProtocol(task.cggmpInstance.getPaillier(), task.cggmpInstance.getCurveOrder());
        boolean round2SendSuccess = false;
        for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
            try {
                for (Map.Entry<Integer, BigInteger> entry : round2Output.shares.entrySet()) {
                    int receiverId = entry.getKey();
                    BigInteger share = entry.getValue().mod(task.cggmpInstance.getCurveOrder());
                    byte[] mtaContext = buildMtaContext(task.taskId, nodeId, receiverId);
                    com.example.mpc.cggmp.mta.MtAInitiatorMessage initiatorMessage =
                            mtaProtocol.generateInitiatorMessage(share, task.cggmpInstance.getZkSetup(), mtaContext);
                    task.mtaInitiatorMessages.put(receiverId, initiatorMessage);

                    Map<String, Object> round2Data = new HashMap<>();
                    round2Data.put("taskId", task.taskId);
                    round2Data.put("senderId", nodeId);
                    round2Data.put("receiverId", receiverId);
                    round2Data.put("initiatorMessage", CggmpDkgCodec.encodeMtAInitiatorMessage(initiatorMessage));

                    nodeService.sendMessage(receiverId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_MTA_INIT, round2Data)).join();
                }
                logger.info("Sent CGGMP_DKG_MTA_INIT for task: {} (attempt {}/{})", task.taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                round2SendSuccess = true;
                break;
            } catch (Exception e) {
                logger.warn("Failed to send CGGMP_DKG_MTA_INIT (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.DKG_BROADCAST_RETRY_INTERVAL_MS);
                }
            }
        }

        if (!round2SendSuccess) {
            throw new RuntimeException("Failed to send CGGMP_DKG_MTA_INIT after " + Constants.DKG_BROADCAST_RETRY_COUNT + " attempts");
        }

        task.startRound2Waiting();
        logger.info("Node {} waiting for MtA alpha messages...", nodeId);
        if (!task.round2ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for MtA alpha messages");
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

    public DkgTaskStatusResponse getTaskStatus(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        DkgTaskStatusResponse response = new DkgTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setGroupPublicKey(task.groupPublicKeyHex);
        response.setErrorMessage(task.errorMessage);
        response.setReceivedRound1(task.round1Outputs.size());
        response.setReceivedRound2(task.round2Outputs.size());
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
                Map<?, ?> paillierKeyMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
                Map<?, ?> zkSetupMap = (Map<?, ?>) dataMap.get("zkSetup");
                Map<?, ?> biPrimeMap = (Map<?, ?>) dataMap.get("biPrimeProof");
                Map<?, ?> factorMap = (Map<?, ?>) dataMap.get("factorProof");

                logger.info("Processing Round1 from node {}: commitments={}, paillierKey={}, zkSetup={}",
                        senderNodeId, commitmentHexList != null ? commitmentHexList.size() : "null",
                        paillierKeyMap != null ? "present" : "null",
                        zkSetupMap != null ? "present" : "null");

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

                if (paillierKeyMap == null || zkSetupMap == null || biPrimeMap == null || factorMap == null) {
                    logger.warn("Missing Paillier data from node {} for task {}", senderNodeId, taskId);
                    return;
                }

                PaillierEncryption.PublicKey paillierKey = CggmpDkgCodec.decodePaillierPublicKey(paillierKeyMap);
                com.example.mpc.cggmp.zk.ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkSetupMap);
                com.example.mpc.cggmp.proof.BiPrimeBlumProof biPrimeProof = CggmpDkgCodec.decodeBiPrimeProof(biPrimeMap);
                com.example.mpc.cggmp.proof.NoSmallFactorProof factorProof = CggmpDkgCodec.decodeNoSmallFactorProof(factorMap);

                byte[] ctxBytes = taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                com.example.mpc.cggmp.proof.BiPrimeProofValidator biPrimeValidator = new com.example.mpc.cggmp.proof.BiPrimeProofValidator();
                com.example.mpc.cggmp.proof.NoSmallFactorProofValidator factorValidator = new com.example.mpc.cggmp.proof.NoSmallFactorProofValidator(zkSetup);
                if (!biPrimeValidator.verifyProof(biPrimeProof, paillierKey, ctxBytes)) {
                    logger.warn("Invalid Paillier bi-prime proof from node {} for task {}", senderNodeId, taskId);
                    return;
                }
                if (!factorValidator.verifyProof(factorProof, paillierKey, ctxBytes)) {
                    logger.warn("Invalid Paillier factor proof from node {} for task {}", senderNodeId, taskId);
                    return;
                }

                task.peerPaillierKeys.put(senderNodeId, paillierKey);
                task.peerZkSetups.put(senderNodeId, zkSetup);

                CGGMP.DkgRound1Output output = new CGGMP.DkgRound1Output(senderNodeId, null, commitments, paillierKey, zkSetup, biPrimeProof, factorProof);
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

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgMtaInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        Number senderValue = (Number) dataMap.get("senderId");
        if (receiverValue == null || senderValue == null) {
            return;
        }
        int receiverId = receiverValue.intValue();
        int initiatorId = senderValue.intValue();
        if (receiverId != nodeId || initiatorId != senderId) {
            return;
        }

        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }

        try {
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (msgMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAInitiatorMessage initiatorMessage = CggmpDkgCodec.decodeMtAInitiatorMessage(msgMap);
            PaillierEncryption.PublicKey initiatorKey = task.peerPaillierKeys.get(initiatorId);
            com.example.mpc.cggmp.zk.ZKSetup zkSetup = task.peerZkSetups.get(initiatorId);
            if (initiatorKey == null || zkSetup == null) {
                logger.warn("Missing Paillier key or ZK setup for initiator {} in task {}", initiatorId, taskId);
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, task.cggmpInstance.getCurveOrder());
            byte[] mtaContext = buildMtaContext(taskId, initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, initiatorKey, zkSetup, mtaContext)) {
                logger.warn("Invalid MtA range proof from node {} for task {}", initiatorId, taskId);
                return;
            }
            if (!protocol.verifyInitiatorBiPrimeProof(initiatorMessage, initiatorKey, mtaContext)) {
                logger.warn("Invalid MtA bi-prime proof from node {} for task {}", initiatorId, taskId);
                return;
            }
            if (!protocol.verifyInitiatorFactorProof(initiatorMessage, initiatorKey, zkSetup, mtaContext)) {
                logger.warn("Invalid MtA factor proof from node {} for task {}", initiatorId, taskId);
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(initiatorKey, initiatorMessage.cA(), BigInteger.ONE, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.mtaBetas.put(initiatorId, beta);

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("senderId", initiatorId);
            resp.put("receiverId", receiverId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpDkgCodec.encodeMtAResult(publicResult));

            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_MTA_RESPONSE, resp)).join();
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_DKG_MTA_INIT from node {}: {}", senderId, e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgMtaResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number senderValue = (Number) dataMap.get("senderId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (senderValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = senderValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != nodeId || senderId != receiverId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }

        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) return;
            com.example.mpc.cggmp.mta.MtAResult result = CggmpDkgCodec.decodeMtAResult(resultMap);

            com.example.mpc.cggmp.mta.MtAInitiatorMessage initiatorMessage = task.mtaInitiatorMessages.get(receiverId);
            if (initiatorMessage == null) {
                logger.warn("Missing initiator message for receiver {} in task {}", receiverId, taskId);
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.cggmpInstance.getPaillier(), task.cggmpInstance.getCurveOrder());
            byte[] mtaContext = buildMtaContext(taskId, initiatorId, receiverId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.cggmpInstance.getPaillier().getPublicKeyInfo(), task.cggmpInstance.getZkSetup(), mtaContext)) {
                logger.warn("Invalid MtA respondent proof from node {} for task {}", receiverId, taskId);
                return;
            }

            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(task.cggmpInstance.getCurveOrder());

            Map<String, Object> alphaMsg = new HashMap<>();
            alphaMsg.put("taskId", taskId);
            alphaMsg.put("senderId", initiatorId);
            alphaMsg.put("receiverId", receiverId);
            alphaMsg.put("alpha", alpha.toString(16));

            nodeService.sendMessage(receiverId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_MTA_ALPHA, alphaMsg)).join();
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_DKG_MTA_RESPONSE from node {}: {}", senderId, e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgMtaAlpha(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (receiverValue == null) return;
        int receiverId = receiverValue.intValue();
        if (receiverId != nodeId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            String alphaHex = (String) dataMap.get("alpha");
            if (alphaHex == null) return;
            BigInteger alpha = new BigInteger(alphaHex, 16);
            BigInteger beta = task.mtaBetas.get(senderId);
            if (beta == null) {
                logger.warn("Missing beta for sender {} in task {}", senderId, taskId);
                return;
            }
            BigInteger share = alpha.add(beta).mod(task.cggmpInstance.getCurveOrder());
            Map<Integer, BigInteger> shares = new HashMap<>();
            shares.put(nodeId, share);
            CGGMP.DkgRound2Output output = new CGGMP.DkgRound2Output(senderId, shares);
            boolean first = task.round2Outputs.putIfAbsent(senderId, output) == null;
            if (first) {
                task.round2ReceivedLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_DKG_MTA_ALPHA from node {}: {}", senderId, e.getMessage(), e);
        }
    }

    private static byte[] buildMtaContext(String taskId, int senderId, int receiverId) {
        String ctx = taskId + ":" + senderId + ":" + receiverId;
        return ctx.getBytes(java.nio.charset.StandardCharsets.UTF_8);
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
                initSignatureContext(task);
                if (broadcastInit) {
                    Map<String, Object> initData = new HashMap<>();
                    initData.put("signatureTaskId", task.taskId);
                    initData.put("groupPublicKey", task.groupPublicKey);
                    initData.put("message", task.message);
                    initData.put("initiatorId", task.initiatorId);
                    initData.put("participants", new ArrayList<>(task.participants));
                    initData.put("messageHash", Base64.getEncoder().encodeToString(task.messageHash));
                    try {
                        for (int attempt = 1; attempt <= Constants.SIGNATURE_BROADCAST_RETRY_COUNT; attempt++) {
                            nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.GG20_SIGN_INIT, initData)).join();
                            logger.info("Broadcasted GG20_SIGN_INIT for signature task: {} (attempt {}/{})", task.taskId, attempt, Constants.SIGNATURE_BROADCAST_RETRY_COUNT);
                            if (attempt < Constants.SIGNATURE_BROADCAST_RETRY_COUNT) {
                                Thread.sleep(Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS);
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to broadcast GG20_SIGN_INIT, proceeding with signature: {}", e.getMessage());
                    }
                }

                initSignaturePaillier(task);

                BigInteger curveOrder = Secp256k1Curve.n();
                BigInteger ownShare = loadLocalShare(task.groupPublicKey);
                BigInteger lambda = lagrangeCoefficient(nodeId, task.participants, curveOrder);
                BigInteger weightedShare = ownShare.multiply(lambda).mod(curveOrder);

                task.k_i = randomNonZero(curveOrder);
                task.a_i = randomNonZero(curveOrder);

                ECPoint gamma = Secp256k1Curve.multiply(Secp256k1Curve.G(), task.k_i);
                task.gammaPoints.put(nodeId, gamma);
                broadcastGamma(task, gamma).join();
                if (!task.gammaLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for gamma commitments");
                }

                ECPoint gammaSum = sumGamma(task);
                if (gammaSum.isInfinity()) {
                    throw new RuntimeException("Gamma sum is infinity");
                }
                task.r = gammaSum.getAffineXCoord().toBigInteger().mod(curveOrder);
                if (task.r.signum() == 0) {
                    throw new RuntimeException("Invalid r (zero), restart signature");
                }

                BigInteger e = new BigInteger(1, task.messageHash).mod(curveOrder);
                BigInteger m_i = nodeId == task.initiatorId ? e : BigInteger.ZERO;
                task.t_i = task.r.multiply(weightedShare).add(m_i).mod(curveOrder);

                broadcastMtaKaInit(task).join();
                if (!task.kaResponseLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for KA MtA responses");
                }

                BigInteger u_i = computeUShare(task, curveOrder);
                if (nodeId == task.initiatorId) {
                    task.uShares.put(nodeId, u_i);
                    if (!task.uCommitLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for u commitments");
                    }
                    if (!task.uShareLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for u shares");
                    }
                    BigInteger u = sumShares(task.uShares, curveOrder);
                    if (u.signum() == 0) {
                        throw new RuntimeException("Invalid u (zero), restart signature");
                    }
                    task.uShares.put(0, u);
                    broadcastUOpen(task, u).join();
                } else {
                    task.uCommitRand = randomNonZero(curveOrder);
                    sendUCommit(task, u_i, task.uCommitRand).join();
                    sendUShare(task, u_i, task.uCommitRand).join();
                    if (!task.uOpenLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for u open");
                    }
                }

                BigInteger u = task.uShares.get(0);
                if (u == null) {
                    throw new RuntimeException("Missing opened u");
                }
                task.kInv_i = task.a_i.multiply(u.modInverse(curveOrder)).mod(curveOrder);

                broadcastMtaStInit(task).join();
                if (!task.stResponseLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for ST MtA responses");
                }

                BigInteger s_i = computeSShare(task, curveOrder);
                if (nodeId == task.initiatorId) {
                    task.sShares.put(nodeId, s_i);
                    if (!task.sShareLatch.await(Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for signature shares");
                    }
                    BigInteger s = sumShares(task.sShares, curveOrder);
                    if (s.compareTo(curveOrder.shiftRight(1)) > 0) {
                        s = curveOrder.subtract(s);
                    }
                    byte[] der = derEncodeSignature(task.r, s);
                    boolean verified = verifySignature(task.groupPublicKeyPoint, task.messageHash, task.r, s, buildDomain());
                    task.signature = Base64.getEncoder().encodeToString(der);
                    task.verified = verified;
                    task.complete();
                    signatureInProgress.set(false);
                    logger.info("CGGMP signature task {} completed successfully, verified: {}", taskId, verified);
                } else {
                    sendSShare(task, s_i).join();
                    task.complete();
                    signatureInProgress.set(false);
                }
            } catch (Exception e) {
                logger.error("Error in CGGMP signature process: {}", e.getMessage());
                task.fail(e.getMessage());
                signatureInProgress.set(false);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
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
        response.setReceivedGammaCommitments(task.participants.size() - 1 - (int) task.gammaLatch.getCount());
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
    }

    private void initSignaturePaillier(Gg20SignatureTask task) {
        if (task.paillier == null) {
            task.paillier = new PaillierEncryption();
        }
        if (task.zkSetup == null) {
            task.zkSetup = ZKSetup.generate(task.paillier.getPublicKeyInfo().bitLength);
        }
    }

    private BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKey(groupPublicKey).join();
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

    private CompletableFuture<Void> broadcastGamma(Gg20SignatureTask task, ECPoint gamma) {
        byte[] ctx = buildSignContext(task.taskId, nodeId, task.messageHash, "GAMMA");
        EcSchnorrProof proof = EcSchnorrProof.create(task.k_i, gamma, ctx);
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("gamma", bytesToHex(Secp256k1Curve.encodePoint(gamma)));
        data.put("proofR", bytesToHex(Secp256k1Curve.encodePoint(proof.R())));
        data.put("proofS", proof.s().toString(16));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_GAMMA, data));
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


    private CompletableFuture<KeyShare> loadKeyShareByGroupPublicKey(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKey(nodeId, groupPublicKey);
    }

    private ECPoint decodeECPoint(byte[] encoded) {
        return Secp256k1Curve.decodePoint(encoded);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, message.data instanceof Map ? ((Map<?, ?>) message.data).get("taskId") : "N/A");
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
                    case CGGMP_DKG_MTA_INIT:
                        handleCggmpDkgMtaInit(senderId, message.data);
                        break;
                    case CGGMP_DKG_MTA_RESPONSE:
                        handleCggmpDkgMtaResponse(senderId, message.data);
                        break;
                    case CGGMP_DKG_MTA_ALPHA:
                        handleCggmpDkgMtaAlpha(senderId, message.data);
                        break;
                    case GG20_SIGN_INIT:
                        handleGg20SignInit(senderId, message.data);
                        break;
                    case CGGMP_SIGN_GAMMA:
                        handleCggmpSignGamma(senderId, message.data);
                        break;
                    case CGGMP_SIGN_MTA_KA_INIT:
                        handleCggmpSignMtaKaInit(senderId, message.data);
                        break;
                    case CGGMP_SIGN_MTA_KA_RESPONSE:
                        handleCggmpSignMtaKaResponse(senderId, message.data);
                        break;
                    case CGGMP_SIGN_U_COMMIT:
                        handleCggmpSignUCommit(senderId, message.data);
                        break;
                    case CGGMP_SIGN_U_SHARE:
                        handleCggmpSignUShare(senderId, message.data);
                        break;
                    case CGGMP_SIGN_U_OPEN:
                        handleCggmpSignUOpen(senderId, message.data);
                        break;
                    case CGGMP_SIGN_MTA_ST_INIT:
                        handleCggmpSignMtaStInit(senderId, message.data);
                        break;
                    case CGGMP_SIGN_MTA_ST_RESPONSE:
                        handleCggmpSignMtaStResponse(senderId, message.data);
                        break;
                    case CGGMP_SIGN_S_SHARE:
                        handleCggmpSignSShare(senderId, message.data);
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
    private void handleCggmpSignGamma(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String gammaHex = (String) dataMap.get("gamma");
        String proofRHex = (String) dataMap.get("proofR");
        String proofSHex = (String) dataMap.get("proofS");
        Number senderValue = (Number) dataMap.get("senderId");
        if (gammaHex == null || proofRHex == null || proofSHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        if (senderId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            ECPoint proofR = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(proofRHex));
            BigInteger proofS = new BigInteger(proofSHex, 16);
            EcSchnorrProof proof = new EcSchnorrProof(proofR, proofS);
            byte[] ctx = buildSignContext(task.taskId, senderId, task.messageHash, "GAMMA");
            if (!EcSchnorrProof.verify(proof, gamma, ctx)) {
                logger.warn("Invalid gamma Schnorr proof from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaPoints.put(senderId, gamma);
            if (task.gammaLatch.getCount() > 0) {
                task.gammaLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA from node {}: {}", senderId, e.getMessage());
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
            task.peerPaillierKeys.put(initiatorId, publicKey);
            task.peerZkSetups.put(initiatorId, zkSetup);

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA initiator proofs for task {}", taskId);
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
            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_KA_RESPONSE, resp)).join();
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
            if (result.proof() == null) {
                logger.warn("Missing KA MtA respondent proof from node {} for task {}", responderId, taskId);
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA respondent proof from node {} for task {}", responderId, taskId);
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
            task.peerPaillierKeys.put(initiatorId, publicKey);
            task.peerZkSetups.put(initiatorId, zkSetup);

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA initiator proofs for task {}", taskId);
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
            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_ST_RESPONSE, resp)).join();
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
            if (result.proof() == null) {
                logger.warn("Missing ST MtA respondent proof from node {} for task {}", responderId, taskId);
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA respondent proof from node {} for task {}", responderId, taskId);
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
        task.sShares.put(senderId, new BigInteger(sHex, 16));
        if (task.sShareLatch.getCount() > 0) {
            task.sShareLatch.countDown();
        }
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
