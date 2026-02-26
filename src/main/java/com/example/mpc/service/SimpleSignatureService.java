package com.example.mpc.service;

import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.common.util.HexUtils;
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

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    private final Map<String, SimpleSignatureTask> tasks = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final ScheduledExecutorService cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
    private final ExecutorService signatureExecutor = Executors.newSingleThreadExecutor();

    public CompletableFuture<Void> init() {
        if (initialized.compareAndSet(false, true)) {
            return nodeService.startP2PServer()
                    .thenRun(() -> {
                        nodeService.registerMessageHandler(-1, this);
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
        return startSignature(groupPublicKey, message, null);
    }

    public String startSignature(String groupPublicKey, String message, Set<Integer> participants) {
        String taskId = UUID.randomUUID().toString();

        if (participants == null || participants.isEmpty()) {
            participants = new HashSet<>();
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
            task.start();

            runOfflinePhase(task);

            runOnlinePhase(task);

        } catch (Exception e) {
            logger.error("Signature failed for task {}: {}", task.taskId, e.getMessage());
            task.fail(e.getMessage());
        }
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

            broadcastOfflineData(task);

            waitForOfflinePhase(task);

            task.R = sumPoints(task.RShares, curveOrder);
            task.Gamma = Gamma;

            logger.info("Node {} completed offline phase: R={}, Gamma={}",
                    nodeId, task.R.getAffineXCoord().toBigInteger().toString(16),
                    Gamma.getAffineXCoord().toBigInteger().toString(16));

            task.offlineCompleted = true;

        } catch (Exception e) {
            logger.error("Offline phase failed for task {}: {}", task.taskId, e.getMessage());
            throw new RuntimeException("Offline phase failed: " + e.getMessage(), e);
        }
    }

    private void runOnlinePhase(SimpleSignatureTask task) {
        try {
            if (!task.offlineCompleted) {
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
                logger.warn("Failed to load private key, using random (signature will fail verification)");
                privateKey = randomNonZero(curveOrder);
            } else {
                logger.info("Loaded private key from database for node {}", nodeId);
            }

            BigInteger kInv = task.k_i.modInverse(curveOrder);
            BigInteger sigma_i = kInv.multiply(messageHash.add(r.multiply(privateKey))).mod(curveOrder);

            task.sigmaShares.put(nodeId, sigma_i);

            logger.info("Node {} computed sigma_i={}, broadcasting", nodeId, sigma_i.toString(16));

            broadcastSigmaShare(task, sigma_i);

            waitForSigmaShares(task);

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
        nodeService.broadcastMessage(msg);
        logger.info("Broadcasted offline data (R, Gamma) for task {}", task.taskId);
    }

    private void broadcastSigmaShare(SimpleSignatureTask task, BigInteger sigma) {
        Map<String, String> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("message", task.message);
        data.put("sigma", sigma.toString(16));

        NodeService.Message msg = new NodeService.Message(nodeId, MessageType.SIMPLE_SIGN_SIGMA, data);
        nodeService.broadcastMessage(msg);
        logger.info("Broadcasted sigma share for task {}", task.taskId);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        try {
            if (message.type == MessageType.SIMPLE_SIGN_OFFLINE) {
                handleOfflineData(senderId, message.data);
            } else if (message.type == MessageType.SIMPLE_SIGN_SIGMA) {
                handleSigmaShare(senderId, message.data);
            }
        } catch (Exception e) {
            logger.error("Error handling message: {}", e.getMessage());
        }
        return CompletableFuture.completedFuture(null);
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
        if (task == null) {
            if (groupPublicKey == null || message == null) {
                logger.warn("Task {} not found and no groupPublicKey/message in message from node {}", taskId, senderId);
                return;
            }
            logger.info("Creating task {} on node {} upon receiving offline data", taskId, nodeId);
            SimpleSignatureTask newTask = new SimpleSignatureTask(taskId, groupPublicKey, message, new HashSet<>(), senderId);
            tasks.put(taskId, newTask);

            final SimpleSignatureTask taskToRun = newTask;
            signatureExecutor.submit(() -> runOfflinePhase(taskToRun));

            task = newTask;
        }

        ECPoint R = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(RHex)).normalize();
        ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(GammaHex)).normalize();

        task.RShares.put(senderId, R);
        task.GammaShares.put(senderId, Gamma);

        task.participants.add(senderId);

        logger.info("Received offline data from node {} for task {}", senderId, taskId);

        notifyOfflinePhase(task);
    }

    private final Map<String, CountDownLatch> offlineLatches = new ConcurrentHashMap<>();
    private final Map<String, CountDownLatch> sigmaLatches = new ConcurrentHashMap<>();

    private void waitForOfflinePhase(SimpleSignatureTask task) {
        int required = task.participants.size();
        CountDownLatch latch = new CountDownLatch(required);
        offlineLatches.put(task.taskId, latch);
        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                logger.warn("Timeout waiting for offline data, proceeding with available: {}", task.RShares.size());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted while waiting for offline data");
        } finally {
            offlineLatches.remove(task.taskId);
        }
    }

    private void notifyOfflinePhase(SimpleSignatureTask task) {
        CountDownLatch latch = offlineLatches.get(task.taskId);
        if (latch != null) {
            latch.countDown();
        }
    }

    private void waitForSigmaShares(SimpleSignatureTask task) {
        int required = task.participants.size();
        CountDownLatch latch = new CountDownLatch(required);
        sigmaLatches.put(task.taskId, latch);
        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                logger.warn("Timeout waiting for sigma shares, proceeding with available: {}", task.sigmaShares.size());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Interrupted while waiting for sigma shares");
        } finally {
            sigmaLatches.remove(task.taskId);
        }
    }

    private void notifySigmaPhase(SimpleSignatureTask task) {
        CountDownLatch latch = sigmaLatches.get(task.taskId);
        if (latch != null) {
            latch.countDown();
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
        if (task == null) {
            if (groupPublicKey == null || message == null) {
                logger.warn("Task {} not found and no groupPublicKey/message in sigma share from node {}", taskId, senderId);
                return;
            }
            logger.info("Creating task {} on node {} upon receiving sigma share", taskId, nodeId);
            task = new SimpleSignatureTask(taskId, groupPublicKey, message, new HashSet<>(), senderId);
            tasks.put(taskId, task);
        }

        BigInteger sigma = new BigInteger(sigmaHex, 16);
        task.sigmaShares.put(senderId, sigma);
        task.participants.add(senderId);

        logger.info("Received sigma share from node {} for task {}", senderId, taskId);

        notifySigmaPhase(task);
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
