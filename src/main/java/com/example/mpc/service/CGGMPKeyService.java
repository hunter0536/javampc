package com.example.mpc.service;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CGGMPProtocol;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.model.CggmpSignatureTask;
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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Base64;

@Service
public class CGGMPKeyService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CGGMPKeyService.class);

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private NodeService nodeService;

    @Value("${node.id}")
    private int nodeId;

    private CGGMP cggmp;
    private CGGMPProtocol protocol;
    private PaillierEncryption paillier;

    private final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final Map<String, CggmpSignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private final Map<String, CGGMPProtocol.ECDSASignature> signatures = new ConcurrentHashMap<>();
    private final Map<String, SignState> signStates = new ConcurrentHashMap<>();

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
            logger.info("startDkgProcess invoked for task {}", taskId);
            CggmpDkgTask task = null;
            try {
                if (dkgInProgress.get()) {
                    throw new RuntimeException("CGGMP DKG process is already in progress");
                }

                task = getDkgTask(taskId);
                if (task.isInProgress() || task.isCompleted()) {
                    throw new RuntimeException("CGGMP DKG task is already in progress or completed");
                }

                dkgInProgress.set(true);
                if (!task.start()) {
                    dkgInProgress.set(false);
                    throw new RuntimeException("Failed to start CGGMP DKG task");
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
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }

                Map<String, Object> initData = new HashMap<>();
                initData.put("taskId", taskId);
                try {
                    for (int attempt = 1; attempt <= 3; attempt++) {
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_INIT, initData)).join();
                        logger.info("Broadcasted CGGMP_DKG_INIT for task: {} (attempt {}/3)", taskId, attempt);
                        if (attempt < 3) {
                            Thread.sleep(1000);
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to broadcast CGGMP_DKG_INIT, proceeding: {}", e.getMessage());
                }

                executeDkgRounds(task);

                saveKeyShareToDatabase(task);

                task.complete();
                dkgInProgress.set(false);
                logger.info("CGGMP DKG process completed for task: {}", taskId);
            } catch (Exception e) {
                if (task != null) {
                    task.fail();
                    task.errorMessage = e.getMessage();
                }
                dkgInProgress.set(false);
                logger.error("Error in CGGMP DKG process", e);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
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

        for (int attempt = 1; attempt <= 3; attempt++) {
            nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_ROUND1, round1Data)).join();
            logger.info("Broadcasted CGGMP_DKG_ROUND1 for task: {} (attempt {}/3)", task.taskId, attempt);
            if (attempt < 3) {
                Thread.sleep(1000);
            }
        }

        logger.info("Node {} waiting for Round 1 messages...", nodeId);
        if (!task.round1ReceivedLatch.await(180, TimeUnit.SECONDS)) {
            throw new Exception("Timeout waiting for Round 1 messages");
        }

        logger.info("Node {} executing DKG Round 2", nodeId);
        CGGMP.DkgRound2Output round2Output = task.cggmpInstance.dkgRound2(task.round1Outputs);
        task.round2Outputs.put(nodeId, round2Output);

        Map<String, Object> round2Data = new HashMap<>();
        round2Data.put("taskId", task.taskId);
        round2Data.put("nodeId", round2Output.nodeId);
        round2Data.put("shares", round2Output.shares);

        for (int attempt = 1; attempt <= 3; attempt++) {
            nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_DKG_ROUND2, round2Data)).join();
            logger.info("Broadcasted CGGMP_DKG_ROUND2 for task: {} (attempt {}/3)", task.taskId, attempt);
            if (attempt < 3) {
                Thread.sleep(1000);
            }
        }

        logger.info("Node {} waiting for Round 2 messages...", nodeId);
        if (!task.round2ReceivedLatch.await(180, TimeUnit.SECONDS)) {
            throw new Exception("Timeout waiting for Round 2 messages");
        }

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
        status.put("inProgress", task.inProgress);
        status.put("completed", task.completed);
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
            logger.info("Received CGGMP_DKG_INIT from node {} for task: {}", senderId, taskId);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound1(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND1 from node {} for task: {}", senderId, taskId);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound2(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND2 from node {} for task: {}", senderId, taskId);
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
            saveKeyShareToDatabase(keyShare);
            logger.info("Saved CGGMP key share to database for task: {}", task.taskId);
        } catch (Exception e) {
            logger.error("Failed to save CGGMP key share to database", e);
        }
    }

    private void saveKeyShareToDatabase(KeyShare keyShare) throws Exception {
        String insertSql;
        String selectSql = "SELECT last_insert_rowid()";

        Connection conn = null;
        PreparedStatement insertStmt = null;
        PreparedStatement selectStmt = null;
        try {
            boolean hasWalletId = false;
            try (var metaConn = databaseService.getShareConnection(keyShare.getShareIndex());
                 var metaStmt = metaConn.createStatement();
                 var rs = metaStmt.executeQuery("PRAGMA table_info(key_shares)")) {
                while (rs.next()) {
                    String name = rs.getString("name");
                    if ("wallet_id".equalsIgnoreCase(name)) {
                        hasWalletId = true;
                        break;
                    }
                }
            } catch (Exception e) {
                hasWalletId = false;
            }

            insertSql = hasWalletId
                ? "INSERT INTO key_shares (wallet_id, share_index, key_share, group_public_key, dkg_task_id) VALUES (?, ?, ?, ?, ?)"
                : "INSERT INTO key_shares (share_index, key_share, group_public_key, dkg_task_id) VALUES (?, ?, ?, ?)";

            conn = databaseService.getShareConnection(keyShare.getShareIndex());
            insertStmt = conn.prepareStatement(insertSql);
            selectStmt = conn.prepareStatement(selectSql);

            int index = 1;
            if (hasWalletId) {
                insertStmt.setInt(index++, 0);
            }
            insertStmt.setInt(index++, keyShare.getShareIndex());
            insertStmt.setString(index++, keyShare.getKeyShare());
            insertStmt.setString(index++, keyShare.getGroupPublicKey());
            insertStmt.setString(index, keyShare.getDkgTaskId());
            insertStmt.executeUpdate();

            var rs = selectStmt.executeQuery();
            if (rs.next()) {
                keyShare.setId(rs.getLong(1));
            }
        } finally {
            if (selectStmt != null) {
                try {
                    selectStmt.close();
                } catch (Exception e) {
                    logger.error("Error closing statement", e);
                }
            }
            if (insertStmt != null) {
                try {
                    insertStmt.close();
                } catch (Exception e) {
                    logger.error("Error closing statement", e);
                }
            }
            if (conn != null) {
                databaseService.releaseShareConnection(conn, keyShare.getShareIndex());
            }
        }
    }

    private static class SignState {
        CGGMPProtocol.SignRound1Output round1Output;
        String message;
        BigInteger k;
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
        CggmpSignatureTask task = new CggmpSignatureTask(taskId, message, fixedGroupPublicKey, nodesCount);
        signatureTasks.put(taskId, task);
        return taskId;
    }

    public String createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message) {
        String fixedGroupPublicKey = null;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        CggmpSignatureTask task = new CggmpSignatureTask(signatureTaskId, message, fixedGroupPublicKey, nodesCount);
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

        CggmpSignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task not found: " + taskId));
        }

        if (task.isInProgress() || task.isCompleted()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task is already in progress or completed"));
        }

        signatureInProgress.set(true);
        if (!task.start()) {
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(new RuntimeException("Failed to start signature task"));
        }

        try {
            if (broadcastInit) {
                Map<String, Object> initData = new HashMap<>();
                initData.put("signatureTaskId", task.taskId);
                initData.put("groupPublicKey", task.groupPublicKey);
                initData.put("message", task.message);
                try {
                    for (int attempt = 1; attempt <= 3; attempt++) {
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_SIGN_INIT, initData)).join();
                        logger.info("Broadcasted CGGMP_SIGN_INIT for signature task: {} (attempt {}/3)", task.taskId, attempt);
                        if (attempt < 3) {
                            Thread.sleep(1000);
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to broadcast CGGMP_SIGN_INIT, proceeding with signature: {}", e.getMessage());
                }
            }

            task.k_i = generateSecureRandom();
            task.R_i = generateCommitment(task.k_i);
            task.receivedCommitments.put(nodeId, task.R_i);

            return broadcastCommitment(taskId, task.R_i)
                .thenCompose(v -> {
                    try {
                        if (!task.commitmentsReceivedLatch.await(60, TimeUnit.SECONDS)) {
                            throw new Exception("Timeout waiting for commitments");
                        }

                        task.R = calculateGlobalCommitment(task);

                        byte[] messageHash = calculateMessageHash(task.message, task.R);
                        BigInteger h = new BigInteger(1, messageHash);

                        return generateSignatureShare(task, task.k_i, h)
                            .thenCompose(signatureShare -> {
                                task.receivedSignatureShares.put(nodeId, signatureShare);
                                return broadcastSignatureShare(taskId, signatureShare);
                            })
                            .thenRun(() -> {
                                try {
                                    if (!task.sharesReceivedLatch.await(60, TimeUnit.SECONDS)) {
                                        throw new Exception("Timeout waiting for signature shares");
                                    }

                                    BigInteger sigma = combineSignatureShares(task);
                                    String finalSignature = convertToECDSASignature(task.R, sigma);

                                    verifySignature(taskId, task.message, finalSignature)
                                        .thenAccept(verified -> {
                                            task.signature = finalSignature;
                                            task.verified = verified;
                                            task.complete();
                                            signatureInProgress.set(false);
                                            logger.info("CGGMP signature task {} completed successfully, verified: {}", taskId, verified);
                                        })
                                        .exceptionally(ex -> {
                                            logger.error("Failed to verify signature: {}", ex.getMessage());
                                            task.fail(ex.getMessage());
                                            signatureInProgress.set(false);
                                            return null;
                                        });
                                } catch (Exception e) {
                                    logger.error("Error in signature process: {}", e.getMessage());
                                    task.fail(e.getMessage());
                                    signatureInProgress.set(false);
                                    throw new RuntimeException(e);
                                }
                            });
                    } catch (Exception e) {
                        logger.error("Error in signature process: {}", e.getMessage());
                        task.fail(e.getMessage());
                        signatureInProgress.set(false);
                        throw new RuntimeException(e);
                    }
                })
                .exceptionally(ex -> {
                    logger.error("Error in signature process: {}", ex.getMessage());
                    task.fail(ex.getMessage());
                    signatureInProgress.set(false);
                    return null;
                });
        } catch (Exception e) {
            logger.error("Error starting signature process: {}", e.getMessage());
            task.fail(e.getMessage());
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(e);
        }
    }

    public Map<String, Object> getSignatureTaskStatus(String taskId) {
        CggmpSignatureTask task = signatureTasks.get(taskId);
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
        status.put("receivedCommitments", task.receivedCommitments.size());
        status.put("receivedSignatureShares", task.receivedSignatureShares.size());
        return status;
    }

    public Map<String, Object> getSignatureResult(String taskId) {
        CggmpSignatureTask task = signatureTasks.get(taskId);
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

    private CompletableFuture<Void> broadcastSignatureShare(String taskId, BigInteger signatureShare) {
        Map<String, Object> shareData = new HashMap<>();
        shareData.put("taskId", taskId);
        shareData.put("signatureShare", signatureShare);

        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_SIGN_ROUND2, shareData))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast signature share: {}", ex.getMessage());
                return null;
            });
    }

    private CompletableFuture<Void> broadcastCommitment(String taskId, ECPoint R_i) {
        Map<String, Object> commitmentData = new HashMap<>();
        commitmentData.put("taskId", taskId);
        commitmentData.put("R_i", Base64.getEncoder().encodeToString(R_i.getEncoded(false)));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.CGGMP_SIGN_ROUND1, commitmentData))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast commitment: {}", ex.getMessage());
                return null;
            });
    }

    private ECPoint calculateGlobalCommitment(CggmpSignatureTask task) throws Exception {
        if (task.receivedCommitments.size() < Constants.THRESHOLD) {
            throw new Exception("Not enough commitments: " + task.receivedCommitments.size() + " < " + Constants.THRESHOLD);
        }

        ECPoint globalR = getInfinityPoint();

        for (ECPoint R_i : task.receivedCommitments.values()) {
            globalR = globalR.add(R_i);
        }

        return globalR.normalize();
    }

    private byte[] calculateMessageHash(String message, ECPoint R) throws Exception {
        ECPoint normalized = R.normalize();
        byte[] RxBytes = normalized.getAffineXCoord().getEncoded();
        byte[] messageBytes = message.getBytes("UTF-8");
        byte[] input = new byte[messageBytes.length + RxBytes.length];
        System.arraycopy(messageBytes, 0, input, 0, messageBytes.length);
        System.arraycopy(RxBytes, 0, input, messageBytes.length, RxBytes.length);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(input);
        logger.info("Message bytes length: {}", messageBytes.length);
        logger.info("Rx bytes length: {}", RxBytes.length);
        logger.info("Total input length: {}", input.length);
        logger.info("Calculated hash: {}", java.util.Arrays.toString(hash));
        return hash;
    }

    private CompletableFuture<BigInteger> generateSignatureShare(CggmpSignatureTask task, BigInteger k_i, BigInteger h) {
        return loadKeyShareByGroupPublicKey(task.groupPublicKey)
            .thenApply(keyShare -> {
                if (keyShare == null) {
                    throw new RuntimeException("Key share not found");
                }
                try {
                    BigInteger s_i = new BigInteger(keyShare.getKeyShare(), 16);
                    return k_i.add(s_i.multiply(h)).mod(getCurveOrder());
                } catch (Exception e) {
                    throw new RuntimeException("Failed to generate signature share: " + e.getMessage());
                }
            })
            .exceptionally(ex -> {
                logger.error("Error generating signature share: {}", ex.getMessage());
                throw new RuntimeException(ex);
            });
    }

    private BigInteger combineSignatureShares(CggmpSignatureTask task) throws Exception {
        var shares = task.receivedSignatureShares;
        if (shares.size() < Constants.THRESHOLD) {
            throw new Exception("Not enough signature shares: " + shares.size() + " < " + Constants.THRESHOLD);
        }

        BigInteger sigma = BigInteger.ZERO;
        for (BigInteger share : shares.values()) {
            sigma = sigma.add(share).mod(getCurveOrder());
        }

        return sigma;
    }

    private String convertToECDSASignature(ECPoint R, BigInteger sigma) throws Exception {
        try {
            ECPoint normalized = R.normalize();
            BigInteger r = normalized.getAffineXCoord().toBigInteger().mod(getCurveOrder());
            BigInteger s = sigma.multiply(r.modInverse(getCurveOrder())).mod(getCurveOrder());

            logger.info("Signature r: {}", r);
            logger.info("Signature s: {}", s);

            byte[] der = encodeEcdsaDer(r, s);
            String signature = Base64.getEncoder().encodeToString(der);
            logger.info("Generated signature: {}", signature);
            return signature;
        } catch (Exception e) {
            logger.error("Error converting to ECDSA signature: {}", e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private byte[] encodeEcdsaDer(BigInteger r, BigInteger s) {
        byte[] rBytes = toUnsignedBytes(r);
        byte[] sBytes = toUnsignedBytes(s);

        int len = 2 + rBytes.length + 2 + sBytes.length;
        byte[] der = new byte[2 + len];
        int pos = 0;
        der[pos++] = 0x30;
        der[pos++] = (byte) len;
        der[pos++] = 0x02;
        der[pos++] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, der, pos, rBytes.length);
        pos += rBytes.length;
        der[pos++] = 0x02;
        der[pos++] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, der, pos, sBytes.length);
        return der;
    }

    private byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        if ((bytes[0] & 0x80) != 0) {
            byte[] prefixed = new byte[bytes.length + 1];
            prefixed[0] = 0x00;
            System.arraycopy(bytes, 0, prefixed, 1, bytes.length);
            bytes = prefixed;
        }
        return bytes;
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

    private CompletableFuture<Boolean> verifySignature(String taskId, String message, String signature) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                CggmpSignatureTask task = signatureTasks.get(taskId);
                if (task == null) {
                    throw new RuntimeException("Signature task not found: " + taskId);
                }

                String groupPublicKey = task.groupPublicKey;
                if (groupPublicKey == null) {
                    throw new RuntimeException("Group public key not found for task: " + taskId);
                }

                return verifyWithPublicKey(groupPublicKey, message, signature);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }

    private boolean verifyWithPublicKey(String publicKeyHex, String message, String signature) throws Exception {
        try {
            byte[] pointBytes = HexUtils.hexToBytes(publicKeyHex);
            ECPoint Q = getEcPublicKey().getParameters().getCurve().decodePoint(pointBytes);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
            keyPairGenerator.initialize(ecSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey paramsPub = (ECPublicKey) keyPair.getPublic();
            org.bouncycastle.jce.spec.ECPublicKeySpec spec = new org.bouncycastle.jce.spec.ECPublicKeySpec(Q, paramsPub.getParameters());
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            String cleanedSignature = signature.replaceAll("\\s+", "")
                                              .replaceAll("[^A-Za-z0-9+/=]", "");

            while (cleanedSignature.length() % 4 != 0) {
                cleanedSignature += "=";
            }

            logger.info("Public key algorithm: {}", publicKey.getAlgorithm());
            logger.info("Public key format: {}", publicKey.getFormat());
            logger.info("Public key (hex): {}", publicKeyHex);
            logger.info("Data: {}", message);
            logger.info("Data bytes length: {}", message.getBytes("UTF-8").length);
            logger.info("Original signature: {}", signature);
            logger.info("Cleaned signature: {}", cleanedSignature);

            byte[] signatureBytes = Base64.getDecoder().decode(cleanedSignature);
            logger.info("Signature bytes length: {}", signatureBytes.length);
            BigInteger[] rs = decodeEcdsaDer(signatureBytes);
            BigInteger r = rs[0];
            BigInteger s = rs[1];
            logger.info("Extracted r: {}", r);
            logger.info("Extracted s: {}", s);

            ECPoint R = reconstructPointFromR(r);
            logger.info("Reconstructed R point: {}", R);

            byte[] messageHash = calculateMessageHash(message, R);
            BigInteger h = new BigInteger(1, messageHash);
            logger.info("Calculated hash during verification: {}", java.util.Arrays.toString(messageHash));

            boolean result = verifyCggmpSignature(publicKey, R, h, r, s);
            logger.info("CGGMP verification result: {}", result);

            return result;
        } catch (Exception e) {
            logger.error("Error verifying signature: {}", e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private BigInteger[] decodeEcdsaDer(byte[] derEncoded) throws Exception {
        int pos = 0;
        if (derEncoded[pos++] != 0x30) {
            throw new Exception("Invalid DER encoding: expected SEQUENCE");
        }
        int len = derEncoded[pos++];
        if (len > derEncoded.length - pos) {
            throw new Exception("Invalid DER encoding: length too long");
        }

        if (derEncoded[pos++] != 0x02) {
            throw new Exception("Invalid DER encoding: expected INTEGER for r");
        }
        int rLen = derEncoded[pos++];
        byte[] rBytes = new byte[rLen];
        System.arraycopy(derEncoded, pos, rBytes, 0, rLen);
        pos += rLen;
        BigInteger r = new BigInteger(1, rBytes);

        if (derEncoded[pos++] != 0x02) {
            throw new Exception("Invalid DER encoding: expected INTEGER for s");
        }
        int sLen = derEncoded[pos++];
        byte[] sBytes = new byte[sLen];
        System.arraycopy(derEncoded, pos, sBytes, 0, sLen);
        BigInteger s = new BigInteger(1, sBytes);

        return new BigInteger[]{r, s};
    }

    private ECPoint reconstructPointFromR(BigInteger r) throws Exception {
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = getEcPublicKey().getParameters();
        org.bouncycastle.math.ec.ECCurve curve = ecSpec.getCurve();

        try {
            byte[] xBytes = new byte[32];
            byte[] rBytes = r.toByteArray();

            if (rBytes.length <= 32) {
                int offset = 32 - rBytes.length;
                System.arraycopy(rBytes, 0, xBytes, offset, rBytes.length);
                for (int i = 0; i < offset; i++) {
                    xBytes[i] = 0;
                }
            } else {
                System.arraycopy(rBytes, rBytes.length - 32, xBytes, 0, 32);
            }

            byte[] encodedR = new byte[33];
            encodedR[0] = 0x02;
            System.arraycopy(xBytes, 0, encodedR, 1, 32);

            try {
                ECPoint point = curve.decodePoint(encodedR);
                logger.info("Reconstructed R point using compressed format (0x02)");
                return point;
            } catch (Exception e) {
                encodedR[0] = 0x03;
                ECPoint point = curve.decodePoint(encodedR);
                logger.info("Reconstructed R point using compressed format (0x03)");
                return point;
            }
        } catch (Exception e) {
            logger.error("Failed to reconstruct R point from r: {}", e.getMessage());
            throw new Exception("Failed to reconstruct R point from r: " + e.getMessage());
        }
    }

    private boolean verifyCggmpSignature(PublicKey publicKey, ECPoint R, BigInteger h, BigInteger r, BigInteger s) throws Exception {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = ecPublicKey.getParameters();
        ECPoint G = ecSpec.getG();
        BigInteger n = ecSpec.getN();
        ECPoint Q = ecPublicKey.getQ();

        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0) {
            logger.warn("Invalid r value: out of range");
            return false;
        }
        if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(n) >= 0) {
            logger.warn("Invalid s value: out of range");
            return false;
        }

        h = h.mod(n);

        BigInteger sigma = s.multiply(r).mod(n);
        logger.info("Calculated sigma: {}", sigma);

        ECPoint sigmaG = G.multiply(sigma).normalize();
        logger.info("Calculated sigma * G: {}", sigmaG);

        ECPoint hQ = Q.multiply(h).normalize();
        ECPoint rightSide = R.add(hQ).normalize();
        logger.info("Calculated R + h * Q: {}", rightSide);

        boolean result = sigmaG.equals(rightSide);
        logger.info("CGGMP verification result: {}", result);

        BigInteger rX = R.getAffineXCoord().toBigInteger().mod(n);
        logger.info("R's x-coordinate mod n: {}", rX);
        logger.info("Expected r: {}", r);
        boolean rXMatch = rX.equals(r);
        logger.info("R's x-coordinate match: {}", rXMatch);

        if (!result) {
            ECPoint ROdd = reconstructPointFromRWithYCoordinate(r, true);
            logger.info("Reconstructed R point (odd y): {}", ROdd);

            ECPoint rightSideOdd = ROdd.add(hQ).normalize();
            logger.info("Calculated ROdd + h * Q: {}", rightSideOdd);

            boolean resultOdd = sigmaG.equals(rightSideOdd);
            logger.info("CGGMP verification result (odd y): {}", resultOdd);

            if (resultOdd) {
                return true;
            }
        }

        return result && rXMatch;
    }

    private ECPoint reconstructPointFromRWithYCoordinate(BigInteger r, boolean useOddY) throws Exception {
        org.bouncycastle.jce.spec.ECParameterSpec ecSpec = getEcPublicKey().getParameters();
        org.bouncycastle.math.ec.ECCurve curve = ecSpec.getCurve();

        try {
            byte[] xBytes = new byte[32];
            byte[] rBytes = r.toByteArray();

            if (rBytes.length <= 32) {
                int offset = 32 - rBytes.length;
                System.arraycopy(rBytes, 0, xBytes, offset, rBytes.length);
                for (int i = 0; i < offset; i++) {
                    xBytes[i] = 0;
                }
            } else {
                System.arraycopy(rBytes, rBytes.length - 32, xBytes, 0, 32);
            }

            byte[] encodedR = new byte[33];
            int formatByte = useOddY ? 0x03 : 0x02;
            encodedR[0] = (byte) formatByte;
            System.arraycopy(xBytes, 0, encodedR, 1, 32);

            ECPoint point = curve.decodePoint(encodedR);
            return point;
        } catch (Exception e) {
            logger.error("Failed to reconstruct R point from r: {}", e.getMessage());
            throw new Exception("Failed to reconstruct R point from r: " + e.getMessage());
        }
    }

    private CompletableFuture<KeyShare> loadKeyShareByGroupPublicKey(String groupPublicKey) {
        return CompletableFuture.supplyAsync(() -> {
            Connection conn = null;
            PreparedStatement pstmt = null;
            try {
                logger.info("Loading key share for group public key: {}", groupPublicKey);
                logger.info("Node ID: {}", nodeId);
                
                String sql = "SELECT id, share_index, key_share, group_public_key, dkg_task_id FROM key_shares WHERE group_public_key = ? ORDER BY id DESC LIMIT 1";
                conn = databaseService.getShareConnection(nodeId);
                pstmt = conn.prepareStatement(sql);
                pstmt.setString(1, groupPublicKey);
                var rs = pstmt.executeQuery();
                
                if (rs.next()) {
                    logger.info("Found key share in database!");
                    KeyShare keyShare = new KeyShare();
                    keyShare.setId(rs.getLong("id"));
                    keyShare.setShareIndex(rs.getInt("share_index"));
                    keyShare.setKeyShare(rs.getString("key_share"));
                    keyShare.setGroupPublicKey(rs.getString("group_public_key"));
                    keyShare.setDkgTaskId(rs.getString("dkg_task_id"));
                    logger.info("Loaded key share: {}", keyShare);
                    return keyShare;
                } else {
                    logger.info("No key share found for group public key: {}", groupPublicKey);
                    return null;
                }
            } catch (Exception e) {
                logger.error("Error loading key share: {}", e.getMessage());
                e.printStackTrace();
                throw new RuntimeException(e);
            } finally {
                if (pstmt != null) {
                    try {
                        pstmt.close();
                    } catch (Exception e) {
                        logger.error("Error closing statement", e);
                    }
                }
                if (conn != null) {
                    databaseService.releaseShareConnection(conn, nodeId);
                }
            }
        }, ThreadPoolUtil.getComputationThreadPool());
    }

    private ECPoint decodeECPoint(byte[] encoded) throws Exception {
        return getEcPublicKey().getParameters().getCurve().decodePoint(encoded);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            try {
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
                    case CGGMP_SIGN_INIT:
                        handleCggmpSignInit(senderId, message.data);
                        break;
                    case CGGMP_SIGN_ROUND1:
                        handleCggmpSignRound1(senderId, message.data);
                        break;
                    case CGGMP_SIGN_ROUND2:
                        handleCggmpSignRound2(senderId, message.data);
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

    private void handleCggmpSignInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String signatureTaskId = (String) dataMap.get("signatureTaskId");
            String groupPublicKey = (String) dataMap.get("groupPublicKey");
            String msg = (String) dataMap.get("message");
            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                if (!signatureTasks.containsKey(signatureTaskId)) {
                    createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg);
                    logger.info("Created CGGMP signature task with group key from CGGMP_SIGN_INIT: {}", signatureTaskId);
                    CompletableFuture.runAsync(() -> {
                        startSignatureTaskInternal(signatureTaskId, false)
                            .exceptionally(ex -> {
                                logger.error("Failed to start CGGMP signature task {} from CGGMP_SIGN_INIT: {}", signatureTaskId, ex.getMessage());
                                return null;
                            });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    logger.info("CGGMP signature task {} already exists, ignoring CGGMP_SIGN_INIT", signatureTaskId);
                }
            } else {
                logger.warn("Invalid CGGMP_SIGN_INIT payload from node {}", senderId);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignRound1(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            String encoded = (String) dataMap.get("R_i");
            ECPoint R_i = null;
            if (encoded != null) {
                try {
                    R_i = decodeECPoint(Base64.getDecoder().decode(encoded));
                } catch (Exception e) {
                    logger.error("Failed to decode R_i from node {}", senderId, e);
                }
            }

            if (R_i != null) {
                CggmpSignatureTask task = signatureTasks.get(taskId);
                if (task != null) {
                    task.receivedCommitments.put(senderId, R_i);
                    task.commitmentsReceivedLatch.countDown();
                    logger.info("Received CGGMP_SIGN_ROUND1 from node {} for task: {}", senderId, taskId);
                } else {
                    logger.warn("Received commitment for non-existent CGGMP signature task: {}", taskId);
                }
            } else {
                logger.warn("Invalid CGGMP_SIGN_ROUND1 payload from node {}", senderId);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignRound2(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            BigInteger signatureShare = (BigInteger) dataMap.get("signatureShare");

            CggmpSignatureTask task = signatureTasks.get(taskId);
            if (task != null) {
                task.receivedSignatureShares.put(senderId, signatureShare);
                task.sharesReceivedLatch.countDown();
                logger.info("Received CGGMP_SIGN_ROUND2 from node {} for task: {}", senderId, taskId);
            } else {
                logger.warn("Received signature share for non-existent CGGMP signature task: {}", taskId);
            }
        }
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return CompletableFuture.runAsync(() -> {
            try {
                for (int i = 1; i <= nodesCount; i++) {
                    if (i != nodeId) {
                        nodeService.registerMessageHandler(i, this);
                    }
                }

                logger.info("CGGMP signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }
}
