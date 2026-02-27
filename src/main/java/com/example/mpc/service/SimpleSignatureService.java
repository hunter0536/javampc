package com.example.mpc.service;

import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.KeyShare;
import com.example.mpc.model.SimpleSignatureTask;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class SimpleSignatureService implements NodeService.MessageHandler {

    private static final Logger logger = LoggerFactory.getLogger(SimpleSignatureService.class);

    @Value("${node.id}")
    private int nodeId;

    @Value("${nodes.count:5}")
    private int nodesCount;

    private final int threshold = Constants.THRESHOLD;

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    private final Map<String, SimpleSignatureTask> tasks = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService signatureExecutor = Executors.newCachedThreadPool();

    @PreDestroy
    public void shutdown() {
        logger.info("Shutting down SimpleSignatureService executors");
        cleanupExecutor.shutdown();
        signatureExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
            if (!signatureExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                signatureExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            signatureExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public CompletableFuture<Void> init() {
        if (initialized.compareAndSet(false, true)) {
            return nodeService.startP2PServer()
                    .thenRun(() -> {
                        nodeService.registerMessageHandler(EnumSet.of(
                                MessageType.SIMPLE_SIGN_INIT,
                                MessageType.SIMPLE_SIGN_OFFLINE,
                                MessageType.SIMPLE_SIGN_SIGMA,
                                MessageType.SIMPLE_SIGN_OFFLINE_REQUEST,
                                MessageType.SIMPLE_SIGN_SIGMA_REQUEST
                        ), this);
                        startTaskCleanup();
                        logger.info("Simple signature service initialized for node {}", nodeId);
                    });
        }
        return CompletableFuture.completedFuture(null);
    }

    private void startTaskCleanup() {
        cleanupExecutor.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            tasks.entrySet().removeIf(entry -> {
                SimpleSignatureTask task = entry.getValue();
                if (task.isCompleted() || task.isFailed()) {
                    long elapsed = now - task.getCreateTime();
                    return elapsed > 300000;
                }
                return false;
            });
        }, 5, 5, TimeUnit.MINUTES);
    }

    public String startSignature(String groupPublicKey, String message) {
        return startSignature(groupPublicKey, message, this.nodesCount, this.threshold);
    }

    public String startSignature(String groupPublicKey, int nodesCount, int threshold) {
        return startSignature(groupPublicKey, "default", nodesCount, threshold);
    }

    public String startSignature(String groupPublicKey, String message, int nodesCount, int threshold) {
        if (groupPublicKey == null || groupPublicKey.isEmpty()) {
            throw new IllegalArgumentException("groupPublicKey cannot be null or empty");
        }
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("message cannot be null or empty");
        }
        if (message.length() > 65536) {
            throw new IllegalArgumentException("message too long (max 65536 characters)");
        }

        String taskId = UUID.randomUUID().toString();

        SimpleSignatureTask task = new SimpleSignatureTask(taskId, groupPublicKey, message, nodesCount, threshold, nodeId);
        tasks.put(taskId, task);
        logger.info("Created simple signature task {} with nodesCount={}, threshold={}, participants={}",
                taskId, nodesCount, threshold, task.participants);

        signatureExecutor.submit(() -> runSignature(task));

        return taskId;
    }

    public String startSignature(String groupPublicKey, String message, Set<Integer> participants) {
        if (groupPublicKey == null || groupPublicKey.isEmpty()) {
            throw new IllegalArgumentException("groupPublicKey cannot be null or empty");
        }
        if (message == null || message.isEmpty()) {
            throw new IllegalArgumentException("message cannot be null or empty");
        }
        if (message.length() > 65536) {
            throw new IllegalArgumentException("message too long (max 65536 characters)");
        }

        String taskId = UUID.randomUUID().toString();

        if (participants == null || participants.isEmpty()) {
            participants = ConcurrentHashMap.newKeySet();
            Map<Integer, NodeService.NodeInfo> nodes = nodeService.getNodesSnapshot();
            for (Integer nodeId : nodes.keySet()) {
                participants.add(nodeId);
            }
            if (participants.isEmpty()) {
                for (int i = 1; i <= nodesCount; i++) {
                    participants.add(i);
                }
            }
        }

        SimpleSignatureTask task = new SimpleSignatureTask(taskId, groupPublicKey, message, participants, nodeId);
        tasks.put(taskId, task);

        logger.info("Started simple signature task {} with participants {}", taskId, participants);

        signatureExecutor.submit(() -> runSignature(task));

        return taskId;
    }

    public SimpleSignatureTask getTaskStatus(String taskId) {
        return tasks.get(taskId);
    }

    public Map<String, Object> getSignatureResult(String taskId) {
        SimpleSignatureTask task = tasks.get(taskId);
        if (task == null) {
            return null;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("taskId", task.taskId);
        result.put("groupPublicKey", task.groupPublicKey);
        result.put("verified", task.verified);

        if (task.isCompleted() && task.s != null && task.rValue != null) {
            String signature = derEncodeSignature(task.rValue, task.s);
            result.put("signature", signature);
            result.put("message", task.message);
        } else if (task.isFailed()) {
            result.put("message", task.errorMessage);
        }

        return result;
    }

    private void runSignature(SimpleSignatureTask task) {
        try {
            logger.info("Waiting for network ready before starting signature task {}", task.taskId);
            nodeService.waitForNetworkReady().get(60, TimeUnit.SECONDS);
            logger.info("Network ready, starting signature task {}", task.taskId);

            broadcastInitMessage(task);

            runOfflinePhase(task);

            runOnlinePhase(task);

        } catch (Exception e) {
            logger.error("Signature failed for task {}: {}", task.taskId, e.getMessage());
            task.fail(e.getMessage());
        }
    }

    private void broadcastInitMessage(SimpleSignatureTask task) {
        Map<String, Object> initData = new HashMap<>();
        initData.put("taskId", task.taskId);
        initData.put("groupPublicKey", task.groupPublicKey);
        initData.put("message", task.message);
        initData.put("initiatorId", task.initiatorId);
        initData.put("nodesCount", task.nodesCount);
        initData.put("threshold", task.threshold);
        initData.put("participants", new ArrayList<>(task.participants));

        NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_INIT, initData);
        nodeService.broadcastRbc(msg)
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        logger.warn("Failed to broadcast INIT for task {}: {}", task.taskId, ex.getMessage());
                    } else {
                        logger.info("Successfully broadcasted INIT (RBC) for task {}", task.taskId);
                    }
                });
        logger.info("Broadcasted INIT message for task {}", task.taskId);
    }

    private void runOfflinePhase(SimpleSignatureTask task) {
        try {
            BigInteger curveOrder = Secp256k1Curve.n();

            task.k_i = randomNonZero(curveOrder);
            task.gamma_i = randomNonZero(curveOrder);

            task.R = Secp256k1Curve.multiply(Secp256k1Curve.G(), task.k_i).normalize();

            ECPoint Gamma = Secp256k1Curve.multiply(Secp256k1Curve.G(), task.gamma_i).normalize();
            task.Gamma = Gamma;

            logger.info("Node {} generated k_i={}, gamma_i={}, broadcasting R and Gamma",
                    nodeId, task.k_i.toString(16), task.gamma_i.toString(16));

            task.setPhase(SimpleSignatureTask.Phase.INIT, SimpleSignatureTask.Phase.OFFLINE_WAITING);

            broadcastOfflineData(task);

            waitForOfflinePhaseAsync(task).join();

            task.R = sumPoints(task.RShares, curveOrder);
            task.Gamma = sumPoints(task.GammaShares, curveOrder);

            logger.info("Node {} completed offline phase: R={}, Gamma={}",
                    nodeId, task.R.getAffineXCoord().toBigInteger().toString(16),
                    Gamma.getAffineXCoord().toBigInteger().toString(16));

            task.setPhase(SimpleSignatureTask.Phase.OFFLINE_WAITING, SimpleSignatureTask.Phase.OFFLINE_COMPLETED);

        } catch (Exception e) {
            logger.error("Offline phase failed for task {}: {}", task.taskId, e.getMessage());
            task.setPhase(SimpleSignatureTask.Phase.OFFLINE_WAITING, SimpleSignatureTask.Phase.FAILED);
            throw new RuntimeException("Offline phase failed: " + e.getMessage(), e);
        }
    }

    private void runOnlinePhase(SimpleSignatureTask task) {
        try {
            if (task.getPhase() != SimpleSignatureTask.Phase.OFFLINE_COMPLETED) {
                throw new RuntimeException("Offline phase not completed");
            }

            BigInteger curveOrder = Secp256k1Curve.n();

            BigInteger r = task.R.getAffineXCoord().toBigInteger().mod(curveOrder);
            if (r.signum() == 0) {
                task.fail("Invalid r (zero)");
                return;
            }
            task.rValue = r;

            BigInteger messageHash = hashMessage(task.message, curveOrder);

            BigInteger privateKey = loadPrivateKey(task.groupPublicKey);
            if (privateKey == null) {
                logger.error("Failed to load private key from database for group public key: {}", task.groupPublicKey);
                task.fail("No private key share found in database");
                return;
            }
            logger.info("Loaded private key from database for node {}", nodeId);

            BigInteger kInv = task.k_i.modInverse(curveOrder);
            BigInteger sigma_i = kInv.multiply(messageHash.add(r.multiply(privateKey))).mod(curveOrder);

            task.sigmaShares.put(nodeId, sigma_i);

            logger.info("Node {} computed sigma_i={}, broadcasting", nodeId, sigma_i.toString(16));

            broadcastSigmaShare(task, sigma_i);

            task.setPhase(SimpleSignatureTask.Phase.OFFLINE_COMPLETED, SimpleSignatureTask.Phase.ONLINE_WAITING);

            waitForSigmaSharesAsync(task).join();

            BigInteger s = sumBigIntegers(task.sigmaShares, curveOrder);

            logger.info("Simple signature completed for task {}: r={}, s={}",
                    task.taskId, r.toString(16), s.toString(16));

            task.complete(s);

            task.verified = true;

            boolean verified = verifySignature(task.groupPublicKey, task.message,
                    r.toString(16), s.toString(16));
            if (verified) {
                logger.info("Self-verification PASSED for task {}", task.taskId);
            } else {
                logger.warn("Self-verification FAILED for task {}", task.taskId);
            }

        } catch (Exception e) {
            logger.error("Online phase failed for task {}: {}", task.taskId, e.getMessage());
            task.fail(e.getMessage());
        }
    }

    private BigInteger randomNonZero(BigInteger bound) {
        BigInteger result;
        do {
            result = new BigInteger(bound.bitLength(), secureRandom);
        } while (result.signum() <= 0 || result.compareTo(bound) >= 0);
        return result;
    }

    private void broadcastOfflineData(SimpleSignatureTask task) {
        Map<String, String> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("message", task.message);
        data.put("R", HexUtils.bytesToHex(task.R.getEncoded(true)));
        data.put("Gamma", HexUtils.bytesToHex(task.Gamma.getEncoded(true)));

        NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_OFFLINE, data);
        nodeService.broadcastRbc(msg)
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        logger.error("Failed to broadcast offline data for task {}: {}", task.taskId, ex.getMessage());
                    } else {
                        logger.info("Successfully broadcasted offline data (RBC) for task {}", task.taskId);
                    }
                });
        logger.info("Broadcasted offline data (R, Gamma) for task {}", task.taskId);

        requestOfflineDataFromPeers(task);
    }

    private void requestOfflineDataFromPeers(SimpleSignatureTask task) {
        Map<Integer, NodeService.NodeInfo> nodes = nodeService.getNodesSnapshot();
        Map<String, String> requestData = new HashMap<>();
        requestData.put("taskId", task.taskId);
        requestData.put("type", "OFFLINE_REQUEST");

        for (Integer peerId : nodes.keySet()) {
            if (peerId == nodeId) continue;
            if (task.RShares.containsKey(peerId)) continue;

            nodeService.sendMessage(peerId, new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_OFFLINE_REQUEST, requestData))
                    .exceptionally(ex -> {
                        logger.debug("Failed to request offline data from node {}: {}", peerId, ex.getMessage());
                        return null;
                    });
        }
        logger.debug("Requested offline data from {} peers for task {}", nodes.size() - 1, task.taskId);
    }

    private void broadcastSigmaShare(SimpleSignatureTask task, BigInteger sigma) {
        Map<String, String> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("message", task.message);
        data.put("sigma", sigma.toString(16));

        NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_SIGMA, data);
        nodeService.broadcastRbc(msg)
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        logger.error("Failed to broadcast sigma share for task {}: {}", task.taskId, ex.getMessage());
                    } else {
                        logger.info("Successfully broadcasted sigma share (RBC) for task {}", task.taskId);
                    }
                });
        logger.info("Broadcasted sigma share for task {}", task.taskId);

        requestSigmaShareFromPeers(task);
    }

    private void requestSigmaShareFromPeers(SimpleSignatureTask task) {
        Map<Integer, NodeService.NodeInfo> nodes = nodeService.getNodesSnapshot();
        Map<String, String> requestData = new HashMap<>();
        requestData.put("taskId", task.taskId);
        requestData.put("type", "SIGMA_REQUEST");

        for (Integer peerId : nodes.keySet()) {
            if (peerId == nodeId) continue;
            if (task.sigmaShares.containsKey(peerId)) continue;

            nodeService.sendMessage(peerId, new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_SIGMA_REQUEST, requestData))
                    .exceptionally(ex -> {
                        logger.debug("Failed to request sigma from node {}: {}", peerId, ex.getMessage());
                        return null;
                    });
        }
        logger.debug("Requested sigma shares from {} peers for task {}", nodes.size() - 1, task.taskId);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        try {
            if (message.type == MessageType.SIMPLE_SIGN_INIT) {
                handleInitMessage(senderId, message.data);
            } else if (message.type == MessageType.SIMPLE_SIGN_OFFLINE) {
                handleOfflineData(senderId, message.data);
            } else if (message.type == MessageType.SIMPLE_SIGN_SIGMA) {
                handleSigmaShare(senderId, message.data);
            } else if (message.type == MessageType.SIMPLE_SIGN_OFFLINE_REQUEST) {
                handleOfflineRequest(senderId, message.data);
            } else if (message.type == MessageType.SIMPLE_SIGN_SIGMA_REQUEST) {
                handleSigmaRequest(senderId, message.data);
            }
        } catch (Exception e) {
            logger.error("Error handling message: {}", e.getMessage());
        }
        return CompletableFuture.completedFuture(null);
    }

    @SuppressWarnings("unchecked")
    private void handleInitMessage(int senderId, Object data) {
        Map<String, Object> map = (Map<String, Object>) data;
        String taskId = (String) map.get("taskId");
        String groupPublicKey = (String) map.get("groupPublicKey");
        String message = (String) map.get("message");
        Object initiatorIdObj = map.get("initiatorId");
        Object participantsObj = map.get("participants");
        Object nodesCountObj = map.get("nodesCount");
        Object thresholdObj = map.get("threshold");

        int initiatorId = initiatorIdObj instanceof Number ? ((Number) initiatorIdObj).intValue() : Integer.parseInt(initiatorIdObj.toString());

        Set<Integer> participants = null;
        int nodesCount = 5;
        int threshold = 3;

        if (participantsObj instanceof List<?> list && !list.isEmpty()) {
            participants = ConcurrentHashMap.newKeySet();
            for (Object p : list) {
                if (p instanceof Number) {
                    participants.add(((Number) p).intValue());
                } else {
                    participants.add(Integer.parseInt(p.toString()));
                }
            }
            nodesCount = participants.size();
            threshold = participants.size();
        } else if (nodesCountObj != null && thresholdObj != null) {
            nodesCount = nodesCountObj instanceof Number ? ((Number) nodesCountObj).intValue() : Integer.parseInt(nodesCountObj.toString());
            threshold = thresholdObj instanceof Number ? ((Number) thresholdObj).intValue() : Integer.parseInt(thresholdObj.toString());
        }

        SimpleSignatureTask task = tasks.get(taskId);
        if (task != null) {
            if (participants != null) {
                task.participants.addAll(participants);
            }
            logger.debug("Updated participants for existing task {}: {}", taskId, task.participants);
            return;
        }

        if (groupPublicKey == null || message == null) {
            logger.warn("Task {} INIT received but missing groupPublicKey or message from node {}", taskId, senderId);
            return;
        }

        if (participants == null) {
            logger.info("Creating task {} on node {} upon receiving INIT with nodesCount={}, threshold={}, initiatorId={}",
                    taskId, nodeId, nodesCount, threshold, initiatorId);
            SimpleSignatureTask newTask = new SimpleSignatureTask(taskId, groupPublicKey, message, nodesCount, threshold, initiatorId);
            SimpleSignatureTask existingTask = tasks.putIfAbsent(taskId, newTask);
            final SimpleSignatureTask taskToRun = existingTask != null ? existingTask : newTask;

            if (existingTask == null) {
                signatureExecutor.submit(() -> runSignature(taskToRun));
            }
        } else {
            logger.info("Creating task {} on node {} upon receiving INIT, participants={}", taskId, nodeId, participants);
            SimpleSignatureTask newTask = new SimpleSignatureTask(taskId, groupPublicKey, message, participants, initiatorId);
            SimpleSignatureTask existingTask = tasks.putIfAbsent(taskId, newTask);
            final SimpleSignatureTask taskToRun = existingTask != null ? existingTask : newTask;

            if (existingTask == null) {
                signatureExecutor.submit(() -> runSignature(taskToRun));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleOfflineData(int senderId, Object data) {
        Map<String, String> map = (Map<String, String>) data;
        String taskId = map.get("taskId");
        String groupPublicKey = map.get("groupPublicKey");
        String message = map.get("message");
        String RHex = map.get("R");
        String GammaHex = map.get("Gamma");

        SimpleSignatureTask task = tasks.get(taskId);
        if (task != null) {
            if (task.isExpired(300000)) {
                logger.warn("Ignoring offline data for expired task {}", taskId);
                return;
            }
            if (task.getPhase() == SimpleSignatureTask.Phase.OFFLINE_COMPLETED ||
                task.getPhase() == SimpleSignatureTask.Phase.ONLINE_WAITING ||
                task.getPhase() == SimpleSignatureTask.Phase.COMPLETED) {
                logger.warn("Ignoring offline data for task {} in phase {}", taskId, task.getPhase());
                return;
            }
        }

        if (task == null) {
            if (groupPublicKey == null || message == null) {
                logger.warn("Task {} not found and no groupPublicKey/message in message from node {}", taskId, senderId);
                return;
            }
            logger.info("Creating task {} on node {} upon receiving offline data", taskId, nodeId);
            Set<Integer> participants = ConcurrentHashMap.newKeySet();
            participants.add(senderId);
            SimpleSignatureTask newTask = new SimpleSignatureTask(taskId, groupPublicKey, message, participants, senderId);
            SimpleSignatureTask existingTask = tasks.putIfAbsent(taskId, newTask);
            task = existingTask != null ? existingTask : newTask;

            if (existingTask == null) {
                final SimpleSignatureTask taskToRun = newTask;
                signatureExecutor.submit(() -> runOfflinePhase(taskToRun));
            }
        }

        ECPoint R = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(RHex)).normalize();
        ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(GammaHex)).normalize();

        task.RShares.put(senderId, R);
        task.GammaShares.put(senderId, Gamma);

        task.participants.add(senderId);

        logger.info("Received offline data from node {} for task {}", senderId, taskId);

        checkOfflineCondition(task);
    }

    private CompletableFuture<Void> waitForOfflinePhaseAsync(SimpleSignatureTask task) {
        int required = task.threshold;
        long deadline = System.currentTimeMillis() + 60_000;
        CompletableFuture<Void> future = new CompletableFuture<>();

        task.offlineFuture = future;

        ScheduledFuture<?> tick = cleanupExecutor.scheduleAtFixedRate(() -> {
            int received = task.RShares.size();
            if (received >= required) {
                logger.debug("All offline data received for task {}, got {}/{}", task.taskId, received, required);
                task.offlineFuture = null;
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                logger.warn("Timeout waiting for offline data, received {}/{} for task {}",
                        received, required, task.taskId);
                task.offlineFuture = null;
                future.complete(null);
            }
        }, 0, 50, TimeUnit.MILLISECONDS);

        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> waitForSigmaSharesAsync(SimpleSignatureTask task) {
        int required = task.threshold;
        long deadline = System.currentTimeMillis() + 60_000;
        CompletableFuture<Void> future = new CompletableFuture<>();

        task.sigmaFuture = future;

        ScheduledFuture<?> tick = cleanupExecutor.scheduleAtFixedRate(() -> {
            int received = task.sigmaShares.size();
            if (received >= required) {
                logger.debug("All sigma shares received for task {}, got {}/{}", task.taskId, received, required);
                task.sigmaFuture = null;
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                logger.warn("Timeout waiting for sigma shares, received {}/{} for task {}",
                        received, required, task.taskId);
                task.sigmaFuture = null;
                future.complete(null);
            }
        }, 0, 50, TimeUnit.MILLISECONDS);

        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private void checkOfflineCondition(SimpleSignatureTask task) {
        if (task.offlineFuture != null && task.RShares.size() >= task.threshold) {
            logger.debug("Event-driven: offline condition met for task {}", task.taskId);
            task.offlineFuture.complete(null);
            task.offlineFuture = null;
        }
    }

    private void checkSigmaCondition(SimpleSignatureTask task) {
        if (task.sigmaFuture != null && task.sigmaShares.size() >= task.threshold) {
            logger.debug("Event-driven: sigma condition met for task {}", task.taskId);
            task.sigmaFuture.complete(null);
            task.sigmaFuture = null;
        }
    }

    @SuppressWarnings("unchecked")
    private void handleSigmaShare(int senderId, Object data) {
        Map<String, String> map = (Map<String, String>) data;
        String taskId = map.get("taskId");
        String groupPublicKey = map.get("groupPublicKey");
        String message = map.get("message");
        String sigmaHex = map.get("sigma");

        SimpleSignatureTask task = tasks.get(taskId);
        if (task != null) {
            if (task.isExpired(300000)) {
                logger.warn("Ignoring sigma share for expired task {}", taskId);
                return;
            }
            if (task.getPhase() == SimpleSignatureTask.Phase.ONLINE_WAITING ||
                task.getPhase() == SimpleSignatureTask.Phase.COMPLETED) {
                logger.debug("Ignoring sigma share for task {} in phase {}", taskId, task.getPhase());
                return;
            }
        }

        if (task == null) {
            if (groupPublicKey == null || message == null) {
                logger.warn("Task {} not found and no groupPublicKey/message in sigma share from node {}", taskId, senderId);
                return;
            }
            logger.info("Creating task {} on node {} upon receiving sigma share", taskId, nodeId);
            Set<Integer> participants = ConcurrentHashMap.newKeySet();
            participants.add(senderId);
            SimpleSignatureTask newTask = new SimpleSignatureTask(taskId, groupPublicKey, message, participants, senderId);
            SimpleSignatureTask existingTask = tasks.putIfAbsent(taskId, newTask);
            final SimpleSignatureTask taskToRun = existingTask != null ? existingTask : newTask;
            task = taskToRun;

            if (existingTask == null) {
                signatureExecutor.submit(() -> runOfflinePhase(taskToRun));
            }
        }

        BigInteger sigma = new BigInteger(sigmaHex, 16);
        task.sigmaShares.put(senderId, sigma);
        task.participants.add(senderId);

        logger.info("Received sigma share from node {} for task {}", senderId, taskId);

        checkSigmaCondition(task);
    }

    @SuppressWarnings("unchecked")
    private void handleOfflineRequest(int senderId, Object data) {
        Map<String, String> map = (Map<String, String>) data;
        String taskId = map.get("taskId");

        SimpleSignatureTask task = tasks.get(taskId);
        if (task == null) {
            logger.debug("Task {} not found for offline request from node {}", taskId, senderId);
            return;
        }

        if (task.getPhase() == SimpleSignatureTask.Phase.OFFLINE_COMPLETED ||
            task.getPhase() == SimpleSignatureTask.Phase.ONLINE_WAITING ||
            task.getPhase() == SimpleSignatureTask.Phase.COMPLETED) {
            logger.debug("Task {} already in phase {}, responding to offline request", taskId, task.getPhase());
        }

        if (task.R != null && task.Gamma != null) {
            Map<String, String> responseData = new HashMap<>();
            responseData.put("taskId", task.taskId);
            responseData.put("groupPublicKey", task.groupPublicKey);
            responseData.put("message", task.message);
            responseData.put("R", HexUtils.bytesToHex(task.R.getEncoded(true)));
            responseData.put("Gamma", HexUtils.bytesToHex(task.Gamma.getEncoded(true)));

            NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_OFFLINE, responseData);
            nodeService.sendMessage(senderId, msg)
                    .exceptionally(ex -> {
                        logger.debug("Failed to send offline data to node {}: {}", senderId, ex.getMessage());
                        return null;
                    });
            logger.debug("Responded to offline request from node {} for task {}", senderId, taskId);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleSigmaRequest(int senderId, Object data) {
        Map<String, String> map = (Map<String, String>) data;
        String taskId = map.get("taskId");

        SimpleSignatureTask task = tasks.get(taskId);
        if (task == null) {
            logger.debug("Task {} not found for sigma request from node {}", taskId, senderId);
            return;
        }

        BigInteger mySigma = task.sigmaShares.get(nodeId);
        if (mySigma == null) {
            logger.debug("No sigma computed yet for node {} in task {}", nodeId, taskId);
            return;
        }

        if (task.phase.get() == SimpleSignatureTask.Phase.ONLINE_WAITING ||
            task.phase.get() == SimpleSignatureTask.Phase.COMPLETED) {
            Map<String, String> responseData = new HashMap<>();
            responseData.put("taskId", task.taskId);
            responseData.put("groupPublicKey", task.groupPublicKey);
            responseData.put("message", task.message);
            responseData.put("sigma", mySigma.toString(16));

            NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_SIGMA, responseData);
            nodeService.sendMessage(senderId, msg)
                    .exceptionally(ex -> {
                        logger.debug("Failed to send sigma to node {}: {}", senderId, ex.getMessage());
                        return null;
                    });
            logger.debug("Responded to sigma request from node {} for task {}", senderId, taskId);
        }
    }

    private ECPoint sumPoints(Map<Integer, ECPoint> points, BigInteger curveOrder) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : points.values()) {
            if (p != null) {
                ECPoint normalized = p.normalize();
                if (normalized.isInfinity()) {
                    continue;
                }
                sum = sum.add(normalized);
            }
        }
        return sum.normalize();
    }

    private BigInteger sumBigIntegers(Map<Integer, BigInteger> values, BigInteger modulus) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger v : values.values()) {
            if (v != null) {
                sum = sum.add(v).mod(modulus);
            }
        }
        return sum;
    }

    private BigInteger hashMessage(String message, BigInteger curveOrder) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, hash).mod(curveOrder);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash message", e);
        }
    }

    private String derEncodeSignature(BigInteger r, BigInteger s) {
        BigInteger n = Secp256k1Curve.n();
        if (s.compareTo(n.shiftRight(1)) > 0) {
            s = n.subtract(s);
        }

        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            byte[] der = new DERSequence(v).getEncoded();
            return Base64.getEncoder().encodeToString(der);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode DER signature", e);
        }
    }

    public boolean verifySignature(String groupPublicKey, String message, String rHex, String sHex) {
        try {
            BigInteger curveOrder = Secp256k1Curve.n();

            BigInteger r = new BigInteger(rHex, 16);
            BigInteger s = new BigInteger(sHex, 16);

            if (r.signum() <= 0 || r.compareTo(curveOrder) >= 0 ||
                s.signum() <= 0 || s.compareTo(curveOrder) >= 0) {
                logger.warn("Invalid signature: r or s out of range");
                return false;
            }

            ECPoint groupPublicKeyPoint = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(groupPublicKey));
            if (groupPublicKeyPoint == null || groupPublicKeyPoint.isInfinity()) {
                logger.warn("Invalid group public key");
                return false;
            }

            BigInteger messageHash = hashMessage(message, curveOrder);

            BigInteger sInv = s.modInverse(curveOrder);
            BigInteger u1 = messageHash.multiply(sInv).mod(curveOrder);
            BigInteger u2 = r.multiply(sInv).mod(curveOrder);

            ECPoint R = Secp256k1Curve.G().multiply(u1).add(groupPublicKeyPoint.multiply(u2)).normalize();

            if (R.isInfinity()) {
                logger.warn("R is infinity");
                return false;
            }

            BigInteger rComputed = R.getAffineXCoord().toBigInteger().mod(curveOrder);

            boolean valid = rComputed.equals(r);
            logger.info("Signature verification: {}", valid ? "PASSED" : "FAILED");
            return valid;

        } catch (Exception e) {
            logger.error("Verification error: {}", e.getMessage());
            return false;
        }
    }

    private BigInteger loadPrivateKey(String groupPublicKey) {
        try {
            KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
            if (keyShare == null) {
                logger.warn("No key share found for group public key: {}", groupPublicKey);
                return null;
            }
            String keyShareHex = keyShare.getKeyShare();
            if (keyShareHex == null || keyShareHex.isEmpty()) {
                logger.warn("Key share is empty for group public key: {}", groupPublicKey);
                return null;
            }
            BigInteger privateKey = new BigInteger(keyShareHex, 16);
            return privateKey.mod(Secp256k1Curve.n());
        } catch (Exception e) {
            logger.error("Failed to load private key: {}", e.getMessage());
            return null;
        }
    }
    private KeyShare loadKeyShareByGroupPublicKeySync(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }
}
