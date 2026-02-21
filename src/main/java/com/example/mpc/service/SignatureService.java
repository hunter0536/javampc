package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.model.SignatureTask;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class SignatureService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(SignatureService.class);
    
    @Autowired
    private DkgService dkgService;
    
    @Autowired
    private NodeService nodeService;
    
    @Value("${node.id}")
    private int nodeId;
    
    // 使用Constants中的常量
    private final int nodesCount = Constants.NODES_COUNT;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    // 签名任务管理
    private final ConcurrentHashMap<String, SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);
    // 加密参数缓存
    private final ConcurrentHashMap<String, Object> cryptoCache = new ConcurrentHashMap<>();
    private final AtomicLong cryptoOperationCount = new AtomicLong(0);
    private final AtomicLong cachedCryptoOperationCount = new AtomicLong(0);

    // DKG里已有解码ECPoint的方法，这里复用同样逻辑
    private ECPoint decodeECPoint(byte[] encoded) throws Exception {
        return getEcPublicKey().getParameters().getCurve().decodePoint(encoded);
    }
    
    /**
     * 初始化签名服务
     * @param nodesCount 节点总数
     */
    public CompletableFuture<Void> init(int nodesCount) {
        return CompletableFuture.runAsync(() -> {
            try {
                // 注册消息处理器
                for (int i = 1; i <= nodesCount; i++) {
                    if (i != nodeId) {
                        nodeService.registerMessageHandler(i, this);
                    }
                }
                
                logger.info("Signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }
    
    /**
     * 验证签名
     * @param taskId DKG任务ID
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    public CompletableFuture<Boolean> verify(String taskId, String data, String signature) {
        return verifySignature(taskId, data, signature);
    }
    
    /**
     * 根据任务ID验证签名
     * @param taskId 任务ID
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    public CompletableFuture<Boolean> verifyByTaskId(String taskId, String data, String signature) {
        return verifySignature(taskId, data, signature);
    }
    
    /**
     * 验证签名的内部方法
     * @param taskId 签名任务ID
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    private CompletableFuture<Boolean> verifySignature(String taskId, String data, String signature) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 获取签名任务
                SignatureTask task = signatureTasks.get(taskId);
                if (task == null) {
                    throw new RuntimeException("Signature task not found: " + taskId);
                }
                
                // 获取群公钥
                String groupPublicKey = task.groupPublicKey;
                if (groupPublicKey == null) {
                    throw new RuntimeException("Group public key not found for task: " + taskId);
                }
                
                return verifyWithPublicKey(groupPublicKey, data, signature);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }
    
    /**
     * 使用指定的公钥验证签名
     * @param publicKeyBase64 公钥（Base64编码）
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    private boolean verifyWithPublicKey(String publicKeyBase64, String data, String signature) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        
        // 验证签名
        Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
        sig.initVerify(publicKey);
        sig.update(data.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return sig.verify(signatureBytes);
    }
    
    /**
     * 创建签名任务（使用群公钥）
     * @param groupPublicKey 群公钥
     * @param message 要签名的数据
     * @return 签名任务ID
     */
    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message) {
        String taskId = UUID.randomUUID().toString();
        SignatureTask task = new SignatureTask(taskId, message, groupPublicKey, nodesCount);
        signatureTasks.put(taskId, task);
        return taskId;
    }

    public String createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message) {
        SignatureTask task = new SignatureTask(signatureTaskId, message, groupPublicKey, nodesCount);
        signatureTasks.put(signatureTaskId, task);
        return signatureTaskId;
    }
    
    /**
     * 启动签名任务（使用CGGMP分布式签名算法）
     * @param taskId 签名任务ID
     */
    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId, true);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId, boolean broadcastInit) {
        if (signatureInProgress.get()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature process is already in progress"));
        }
        
        SignatureTask task = signatureTasks.get(taskId);
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
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.SIGN_INIT, initData)).join();
                        logger.info("Broadcasted SIGN_INIT for signature task: {} (attempt {}/3)", task.taskId, attempt);
                        if (attempt < 3) {
                            Thread.sleep(1000);
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to broadcast SIGN_INIT, proceeding with signature: {}", e.getMessage());
                }
            }

            // 第一阶段：生成临时公钥并广播（承诺阶段）
            // 1. 生成随机数ki
            task.k_i = generateSecureRandom();
            
            // 2. 计算临时公钥Ri = ki * G
            task.R_i = generateCommitment(task.k_i);
            
            // 3. 广播临时公钥Ri给其他节点
            return broadcastCommitment(taskId, task.R_i)
                .thenCompose(v -> {
                    try {
                        // 4. 等待接收其他节点的临时公钥
                        if (!task.commitmentsReceivedLatch.await(60, TimeUnit.SECONDS)) {
                            throw new Exception("Timeout waiting for commitments");
                        }
                        
                        // 5. 计算全局临时公钥R = ΣRi
                        task.R = calculateGlobalCommitment(task);
                        
                        // 第二阶段：计算签名份额并广播
                        // 6. 计算消息哈希h = H(m || Rx)
                        byte[] messageHash = calculateMessageHash(task.message, task.R);
                        BigInteger h = new BigInteger(1, messageHash);
                        
                        // 7. 生成签名份额σi = ki + si * h
                return generateSignatureShareCGGMP(task.k_i, h)
                    .thenCompose(signatureShare -> {
                        // 8. 广播签名份额给其他节点
                        return broadcastSignatureShare(taskId, signatureShare);
                    })
                            .thenRun(() -> {
                                try {
                                    // 9. 等待接收其他节点的签名份额
                                    if (!task.sharesReceivedLatch.await(60, TimeUnit.SECONDS)) {
                                        throw new Exception("Timeout waiting for signature shares");
                                    }
                                    
                                    // 10. 组合签名份额生成最终签名σ = Σσi
                                    BigInteger sigma = combineSignatureSharesCGGMP(task);
                                    
                                    // 11. 生成最终签名 (R, σ) 并转换为传统ECDSA格式 (r, s)
                                    String finalSignature = convertToECDSASignature(task.R, sigma);
                                    
                                    // 12. 验证最终签名
                                    verifyByTaskId(taskId, task.message, finalSignature)
                                        .thenAccept(verified -> {
                                            // 13. 更新任务状态
                                            task.signature = finalSignature;
                                            task.verified = verified;
                                            task.complete();
                                            signatureInProgress.set(false);
                                            logger.info("Signature task {} completed successfully, verified: {}", taskId, verified);
                                        })
                                        .exceptionally(ex -> {
                                            logger.error("Failed to verify signature: {}", ex.getMessage());
                                            task.fail();
                                            signatureInProgress.set(false);
                                            return null;
                                        });
                                } catch (Exception e) {
                                    logger.error("Error in signature process: {}", e.getMessage());
                                    task.fail();
                                    signatureInProgress.set(false);
                                    throw new RuntimeException(e);
                                }
                            });
                    } catch (Exception e) {
                        logger.error("Error in signature process: {}", e.getMessage());
                        task.fail();
                        signatureInProgress.set(false);
                        throw new RuntimeException(e);
                    }
                })
                .exceptionally(ex -> {
                    logger.error("Error in signature process: {}", ex.getMessage());
                    task.fail();
                    signatureInProgress.set(false);
                    return null;
                });
        } catch (Exception e) {
            logger.error("Error starting signature process: {}", e.getMessage());
            task.fail();
            signatureInProgress.set(false);
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * 获取签名任务状态
     * @param taskId 签名任务ID
     * @return 任务状态
     */
    public Map<String, Object> getSignatureTaskStatus(String taskId) {
        SignatureTask task = signatureTasks.get(taskId);
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
        return status;
    }
    
    /**
     * 获取签名结果
     * @param taskId 签名任务ID
     * @return 签名结果
     */
    public Map<String, Object> getSignatureResult(String taskId) {
        SignatureTask task = signatureTasks.get(taskId);
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
    
    /**
     * 广播签名份额给其他节点
     * @param taskId 签名任务ID
     * @param signatureShare 签名份额
     */
    private CompletableFuture<Void> broadcastSignatureShare(String taskId, BigInteger signatureShare) {
        Map<String, Object> shareData = new HashMap<>();
        shareData.put("taskId", taskId);
        shareData.put("signatureShare", signatureShare);
        
        // 广播签名份额给其他节点
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.SIGNATURE_SHARE, shareData))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast signature share: {}", ex.getMessage());
                return null;
            });
    }
    
    /**
     * 处理接收到的签名份额
     * @param senderId 发送者ID
     * @param taskId 签名任务ID
     * @param signatureShare 签名份额
     */
    public void handleSignatureShare(int senderId, String taskId, BigInteger signatureShare) {
        SignatureTask task = getSignatureTaskWithStats(taskId);
        if (task != null) {
            task.receivedSignatureShares.put(senderId, signatureShare);
            task.sharesReceivedLatch.countDown();
        } else {
            logger.warn("Received signature share for non-existent task: {}", taskId);
        }
    }
    
    /**
     * 处理接收到的临时公钥
     * @param senderId 发送者ID
     * @param taskId 任务ID
     * @param R_i 临时公钥
     */
    public void handleCommitment(int senderId, String taskId, ECPoint R_i) {
        SignatureTask task = getSignatureTaskWithStats(taskId);
        if (task != null) {
            task.receivedCommitments.put(senderId, R_i);
            task.commitmentsReceivedLatch.countDown();
        } else {
            logger.warn("Received commitment for non-existent task: {}", taskId);
        }
    }
    
    /**
     * 生成安全的随机数
     * @return 随机数 BigInteger
     */
    private BigInteger generateSecureRandom() {
        return new BigInteger(256, new SecureRandom());
    }
    
    /**
     * 获取椭圆曲线基点G
     */
    private ECPoint getCurveGenerator() throws Exception {
        String cacheKey = "curveGenerator_" + Constants.CURVE_NAME;
        return (ECPoint) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyGen.initialize(ecSpec);
                KeyPair keyPair = keyGen.generateKeyPair();
                ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
                return publicKey.getParameters().getG();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 生成临时公钥
     * @param k 随机数
     * @return 椭圆曲线点 ECPoint
     */
    private ECPoint generateCommitment(BigInteger k) throws Exception {
        // 获取椭圆曲线基点G
        ECPoint G = getCurveGenerator();
        // 计算 R = k * G
        return G.multiply(k);
    }
    
    /**
     * 广播临时公钥
     * @param taskId 任务ID
     * @param R_i 临时公钥
     */
    private CompletableFuture<Void> broadcastCommitment(String taskId, ECPoint R_i) {
        Map<String, Object> commitmentData = new HashMap<>();
        commitmentData.put("taskId", taskId);
        commitmentData.put("R_i", Base64.getEncoder().encodeToString(R_i.getEncoded(false)));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.SIGN_COMMITMENT, commitmentData))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast commitment: {}", ex.getMessage());
                return null;
            });
    }
    
    /**
     * 计算全局临时公钥
     * @param task 签名任务
     * @return 椭圆曲线点 ECPoint
     */
    private ECPoint calculateGlobalCommitment(SignatureTask task) throws Exception {
        // 初始化全局临时公钥为无穷远点
        ECPoint globalR = getInfinityPoint();
        // 累加本节点承诺
        if (task.R_i != null) {
            globalR = globalR.add(task.R_i);
        }
        // 累加其他节点承诺
        for (ECPoint R_i : task.receivedCommitments.values()) {
            globalR = globalR.add(R_i);
        }
        return globalR;
    }
    
    /**
     * 计算消息哈希
     * @param message 消息
     * @param R 全局临时公钥
     * @return 哈希值 byte[]
     */
    private byte[] calculateMessageHash(String message, ECPoint R) throws Exception {
        // 序列化 R 的 x 坐标
        byte[] RxBytes = R.getAffineXCoord().getEncoded();
        // 构建哈希输入: message || Rx
        byte[] messageBytes = message.getBytes();
        byte[] input = new byte[messageBytes.length + RxBytes.length];
        System.arraycopy(messageBytes, 0, input, 0, messageBytes.length);
        System.arraycopy(RxBytes, 0, input, messageBytes.length, RxBytes.length);
        // 计算 SHA-256 哈希
        return MessageDigest.getInstance("SHA-256").digest(input);
    }
    
    /**
     * 生成 CGMMP 签名份额
     * @param k_i 随机数
     * @param h 消息哈希
     * @return 签名份额 BigInteger
     */
    private CompletableFuture<BigInteger> generateSignatureShareCGGMP(BigInteger k_i, BigInteger h) {
        // 加载密钥份额
        return dkgService.loadKeyShare(1L)
            .thenApply(keyShare -> {
                if (keyShare == null) {
                    throw new RuntimeException("Key share not found");
                }
                try {
                    // 获取密钥份额 s_i
                    BigInteger s_i = new BigInteger(Base64.getDecoder().decode(keyShare.getKeyShare()));
                    // 计算签名份额: σ_i = k_i + s_i * h
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
    
    /**
     * 组合 CGMMP 签名份额
     * @param task 签名任务
     * @return 最终签名 BigInteger
     */
    private BigInteger combineSignatureSharesCGGMP(SignatureTask task) throws Exception {
        BigInteger sigma = BigInteger.ZERO;
        for (BigInteger share : task.receivedSignatureShares.values()) {
            sigma = sigma.add(share).mod(getCurveOrder());
        }
        return sigma;
    }
    
    /**
     * 转换为 ECDSA 签名格式
     * @param R 全局临时公钥
     * @param sigma 签名值
     * @return Base64 编码的签名
     */
    private String convertToECDSASignature(ECPoint R, BigInteger sigma) throws Exception {
        // 获取 R 的 x 坐标作为 r
        BigInteger r = R.getAffineXCoord().toBigInteger().mod(getCurveOrder());
        // 计算 s = sigma * r^{-1} mod n
        BigInteger s = sigma.multiply(r.modInverse(getCurveOrder())).mod(getCurveOrder());
        // 使用DER编码的ECDSA签名格式
        byte[] der = encodeEcdsaDer(r, s);
        return Base64.getEncoder().encodeToString(der);
    }

    private byte[] encodeEcdsaDer(BigInteger r, BigInteger s) {
        byte[] rBytes = toUnsignedBytes(r);
        byte[] sBytes = toUnsignedBytes(s);

        int len = 2 + rBytes.length + 2 + sBytes.length;
        byte[] der = new byte[2 + len];
        int pos = 0;
        der[pos++] = 0x30; // SEQUENCE
        der[pos++] = (byte) len;
        der[pos++] = 0x02; // INTEGER
        der[pos++] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, der, pos, rBytes.length);
        pos += rBytes.length;
        der[pos++] = 0x02; // INTEGER
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
    
    /**
     * 获取椭圆曲线参数
     * @return 椭圆曲线参数
     */
    private ECPublicKey getEcPublicKey() throws Exception {
        String cacheKey = "ecPublicKey_" + Constants.CURVE_NAME;
        return (ECPublicKey) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                cryptoOperationCount.incrementAndGet();
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
    
    /**
     * 获取椭圆曲线阶
     * @return BigInteger
     */
    private BigInteger getCurveOrder() throws Exception {
        String cacheKey = "curveOrder_" + Constants.CURVE_NAME;
        return (BigInteger) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                cachedCryptoOperationCount.incrementAndGet();
                return getEcPublicKey().getParameters().getN();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 获取无穷远点
     * @return ECPoint
     */
    private ECPoint getInfinityPoint() throws Exception {
        String cacheKey = "infinityPoint_" + Constants.CURVE_NAME;
        return (ECPoint) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                cachedCryptoOperationCount.incrementAndGet();
                return getEcPublicKey().getParameters().getCurve().getInfinity();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 获取签名任务（带缓存统计）
     * @param taskId 任务ID
     * @return 签名任务
     */
    private SignatureTask getSignatureTaskWithStats(String taskId) {
        SignatureTask task = signatureTasks.get(taskId);
        if (task != null) {
            cacheHits.incrementAndGet();
        } else {
            cacheMisses.incrementAndGet();
        }
        return task;
    }
    
    /**
     * 处理接收到的消息
     */
    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            try {
                switch (message.type) {
                    case SIGN_COMMITMENT:
                        // 处理签名相关的临时公钥消息
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            String encoded = (String) dataMap.get("R_i");
                            ECPoint R_i = null;
                            if (encoded != null) {
                                R_i = decodeECPoint(Base64.getDecoder().decode(encoded));
                            }
                            
                            // 调用已有的处理方法
                            if (R_i != null) {
                                handleCommitment(senderId, taskId, R_i);
                            } else {
                                logger.warn("Invalid commitment payload from node {} for task {}", senderId, taskId);
                            }
                            logger.info("Received commitment from node {} for signature task: {}", senderId, taskId);
                        }
                        break;
                    case SIGN_INIT:
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String signatureTaskId = (String) dataMap.get("signatureTaskId");
                            String groupPublicKey = (String) dataMap.get("groupPublicKey");
                            String msg = (String) dataMap.get("message");
                            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                                if (!signatureTasks.containsKey(signatureTaskId)) {
                                    createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg);
                                    logger.info("Created signature task with group key from SIGN_INIT: {}", signatureTaskId);
                                    CompletableFuture.runAsync(() -> {
                                        startSignatureTaskInternal(signatureTaskId, false)
                                            .exceptionally(ex -> {
                                                logger.error("Failed to start signature task {} from SIGN_INIT: {}", signatureTaskId, ex.getMessage());
                                                return null;
                                            });
                                    }, ThreadPoolUtil.getIoThreadPool());
                                } else {
                                    logger.info("Signature task {} already exists, ignoring SIGN_INIT", signatureTaskId);
                                }
                            } else {
                                logger.warn("Invalid SIGN_INIT payload from node {}", senderId);
                            }
                        }
                        break;
                    case SIGNATURE_SHARE:
                        // 处理签名份额消息
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            BigInteger signatureShare = (BigInteger) dataMap.get("signatureShare");
                            
                            // 调用已有的处理方法
                            handleSignatureShare(senderId, taskId, signatureShare);
                            logger.info("Received signature share from node {} for task: {}", senderId, taskId);
                        }
                        break;
                }
            } catch (Exception e) {
                logger.error("Error handling message: {}", e.getMessage());
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }
}
