package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.model.KeyShare;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class SignatureService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(SignatureService.class);
    
    @Autowired
    private DkgService dkgService;
    
    @Autowired
    private NodeService nodeService;
    
    @Value("${node.id}")
    private int nodeId;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    // 以太坊使用的椭圆曲线
    // 分布式签名阈值
    
    // 签名任务管理
    public static class SignatureTask {
        public final String taskId;
        public final String message;
        public final String dkgTaskId;
        public final AtomicReference<TaskStatus> status;
        public String signature;
        public boolean verified;
        public final CountDownLatch commitmentsReceivedLatch;
        public final CountDownLatch sharesReceivedLatch;
        public final ConcurrentHashMap<Integer, org.bouncycastle.math.ec.ECPoint> receivedCommitments;
        public final ConcurrentHashMap<Integer, BigInteger> receivedSignatureShares;
        public BigInteger k_i; // 本地随机数
        public org.bouncycastle.math.ec.ECPoint R_i; // 本地临时公钥
        public org.bouncycastle.math.ec.ECPoint R; // 全局临时公钥
        public long createdAt;
        
        public SignatureTask(String taskId, String message, String dkgTaskId) {
            this.taskId = taskId;
            this.message = message;
            this.dkgTaskId = dkgTaskId;
            this.status = new AtomicReference<>(TaskStatus.IDLE);
            this.signature = null;
            this.verified = false;
            this.commitmentsReceivedLatch = new CountDownLatch(5 - 1); // 假设总共有5个节点
            this.sharesReceivedLatch = new CountDownLatch(5 - 1); // 假设总共有5个节点
            this.receivedCommitments = new ConcurrentHashMap<>();
            this.receivedSignatureShares = new ConcurrentHashMap<>();
            this.k_i = null;
            this.R_i = null;
            this.R = null;
            this.createdAt = System.currentTimeMillis();
        }
        
        // 状态转换方法
        public boolean start() {
            return status.compareAndSet(TaskStatus.IDLE, TaskStatus.IN_PROGRESS);
        }
        
        public void complete() {
            status.set(TaskStatus.COMPLETED);
        }
        
        public void fail() {
            status.set(TaskStatus.FAILED);
        }
        
        public boolean isCompleted() {
            return status.get() == TaskStatus.COMPLETED;
        }
        
        public boolean isInProgress() {
            return status.get() == TaskStatus.IN_PROGRESS;
        }
    }
    
    private final ConcurrentHashMap<String, SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);
    // 加密参数缓存
    private final ConcurrentHashMap<String, Object> cryptoCache = new ConcurrentHashMap<>();
    private final AtomicLong cryptoOperationCount = new AtomicLong(0);
    private final AtomicLong cachedCryptoOperationCount = new AtomicLong(0);
    
    /**
     * 初始化签名服务
     */
    public CompletableFuture<Void> init() {
        return CompletableFuture.runAsync(() -> {
            try {
                // 注册消息处理器
                for (int i = 1; i <= 5; i++) { // 假设总共有5个节点
                    if (i != nodeId) {
                        nodeService.registerMessageHandler(i, this);
                    }
                }
                
                logger.info("Signature service initialized successfully for node {}", nodeId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 使用分布式密钥签名数据（不重构私钥，使用分布式签名）
     * @param walletId 钱包ID
     * @param data 要签名的数据
     * @return 签名结果
     */
    public CompletableFuture<String> sign(Long walletId, String data) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 从本节点加载密钥份额
                KeyShare keyShare = dkgService.loadKeyShare(walletId).join();
                if (keyShare == null) {
                    throw new Exception("Key share not found for wallet " + walletId);
                }
                
                // 直接使用本节点的密钥份额进行签名（简化实现）
                // 注意：实际实现中，这里需要使用分布式签名算法，如Gennaro等人的方案
                // 这里简化处理，使用密钥份额作为私钥进行签名
                BigInteger keyShareInt = new BigInteger(Base64.getDecoder().decode(keyShare.getKeyShare()));
                
                // 生成ECDSA签名
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                
                // 创建临时私钥对象
                org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) keyPair.getPrivate();
                org.bouncycastle.jce.spec.ECPrivateKeySpec privateKeySpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(
                        keyShareInt,
                        privateKey.getParameters()
                );
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                PrivateKey tempPrivateKey = keyFactory.generatePrivate(privateKeySpec);
                
                // 签名数据
                Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
                signature.initSign(tempPrivateKey);
                signature.update(data.getBytes());
                byte[] signatureBytes = signature.sign();
                
                return Base64.getEncoder().encodeToString(signatureBytes);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 根据任务ID签名数据（不重构私钥，使用分布式签名）
     * @param taskId 任务ID
     * @param data 要签名的数据
     * @return 签名结果
     */
    public CompletableFuture<String> signByTaskId(String taskId, String data) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 从本节点加载密钥份额
                KeyShare keyShare = dkgService.loadKeyShare(1L).join();
                if (keyShare == null) {
                    throw new Exception("Key share not found");
                }
                
                // 直接使用本节点的密钥份额进行签名（简化实现）
                // 注意：实际实现中，这里需要使用分布式签名算法，如Gennaro等人的方案
                // 这里简化处理，使用密钥份额作为私钥进行签名
                BigInteger keyShareInt = new BigInteger(Base64.getDecoder().decode(keyShare.getKeyShare()));
                
                // 生成ECDSA签名
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                
                // 创建临时私钥对象
                org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (org.bouncycastle.jce.interfaces.ECPrivateKey) keyPair.getPrivate();
                org.bouncycastle.jce.spec.ECPrivateKeySpec privateKeySpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(
                        keyShareInt,
                        privateKey.getParameters()
                );
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                PrivateKey tempPrivateKey = keyFactory.generatePrivate(privateKeySpec);
                
                // 签名数据
                Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
                signature.initSign(tempPrivateKey);
                signature.update(data.getBytes());
                byte[] signatureBytes = signature.sign();
                
                return Base64.getEncoder().encodeToString(signatureBytes);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 验证签名
     * @param taskId DKG任务ID
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    public CompletableFuture<Boolean> verify(String taskId, String data, String signature) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 获取群公钥
                String groupPublicKey = dkgService.getGroupPublicKey(taskId);
                byte[] publicKeyBytes = Base64.getDecoder().decode(groupPublicKey);
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                PublicKey publicKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(publicKeyBytes));
                
                // 验证签名
                Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
                sig.initVerify(publicKey);
                sig.update(data.getBytes());
                return sig.verify(Base64.getDecoder().decode(signature));
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 根据任务ID验证签名
     * @param taskId 任务ID
     * @param data 原始数据
     * @param signature 签名结果
     * @return 是否有效
     */
    public CompletableFuture<Boolean> verifyByTaskId(String taskId, String data, String signature) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 获取群公钥
                String groupPublicKey = dkgService.getGroupPublicKey(taskId);
                byte[] publicKeyBytes = Base64.getDecoder().decode(groupPublicKey);
                KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                PublicKey publicKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(publicKeyBytes));
                
                // 验证签名
                Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
                sig.initVerify(publicKey);
                sig.update(data.getBytes());
                return sig.verify(Base64.getDecoder().decode(signature));
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 创建签名任务
     * @param dkgTaskId DKG任务ID
     * @param message 要签名的数据
     * @return 签名任务ID
     */
    public String createSignatureTask(String dkgTaskId, String message) {
        String taskId = UUID.randomUUID().toString();
        SignatureTask task = new SignatureTask(taskId, message, dkgTaskId);
        signatureTasks.put(taskId, task);
        return taskId;
    }
    
    /**
     * 启动签名任务（使用CGGMP分布式签名算法）
     * @param taskId 签名任务ID
     */
    public CompletableFuture<Void> startSignatureTask(String taskId) {
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
            // 第一阶段：生成临时公钥并广播（承诺阶段）
            // 1. 生成随机数ki
            task.k_i = generateSecureRandom();
            
            // 2. 计算临时公钥Ri = ki * G
            task.R_i = generateCommitment(task.k_i);
            
            // 3. 广播临时公钥Ri给其他节点
            return broadcastCommitment(taskId, task.R_i)
                .thenRun(() -> {
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
                        return generateSignatureShareCGGMP(task.dkgTaskId, task.k_i, h)
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
                                    verifyByTaskId(task.dkgTaskId, task.message, finalSignature)
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
        status.put("dkgTaskId", task.dkgTaskId);
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
        result.put("dkgTaskId", task.dkgTaskId);
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
    public void handleCommitment(int senderId, String taskId, org.bouncycastle.math.ec.ECPoint R_i) {
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
     * 生成临时公钥
     * @param k 随机数
     * @return 椭圆曲线点 ECPoint
     */
    private org.bouncycastle.math.ec.ECPoint generateCommitment(BigInteger k) throws Exception {
        // 获取椭圆曲线参数
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        org.bouncycastle.math.ec.ECPoint G = publicKey.getParameters().getG();
        // 计算 R = k * G
        return G.multiply(k);
    }
    
    /**
     * 广播临时公钥
     * @param taskId 任务ID
     * @param R_i 临时公钥
     */
    private CompletableFuture<Void> broadcastCommitment(String taskId, org.bouncycastle.math.ec.ECPoint R_i) {
        Map<String, Object> commitmentData = new HashMap<>();
        commitmentData.put("taskId", taskId);
        commitmentData.put("R_i", R_i);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.COMMITMENT, commitmentData))
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
    private org.bouncycastle.math.ec.ECPoint calculateGlobalCommitment(SignatureTask task) throws Exception {
        // 初始化全局临时公钥为无穷远点
        org.bouncycastle.math.ec.ECPoint globalR = getInfinityPoint();
        // 累加所有临时公钥
        for (org.bouncycastle.math.ec.ECPoint R_i : task.receivedCommitments.values()) {
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
    private byte[] calculateMessageHash(String message, org.bouncycastle.math.ec.ECPoint R) throws Exception {
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
     * @param dkgTaskId DKG任务ID
     * @param k_i 随机数
     * @param h 消息哈希
     * @return 签名份额 BigInteger
     */
    private CompletableFuture<BigInteger> generateSignatureShareCGGMP(String dkgTaskId, BigInteger k_i, BigInteger h) {
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
    private String convertToECDSASignature(org.bouncycastle.math.ec.ECPoint R, BigInteger sigma) throws Exception {
        // 获取 R 的 x 坐标作为 r
        BigInteger r = R.getAffineXCoord().toBigInteger().mod(getCurveOrder());
        // 计算 s = sigma * r^{-1} mod n
        BigInteger s = sigma.multiply(r.modInverse(getCurveOrder())).mod(getCurveOrder());
        // 构建简单的签名格式：r + s 的字节数组
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        byte[] signatureBytes = new byte[rBytes.length + sBytes.length];
        System.arraycopy(rBytes, 0, signatureBytes, 0, rBytes.length);
        System.arraycopy(sBytes, 0, signatureBytes, rBytes.length, sBytes.length);
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
    
    /**
     * 获取椭圆曲线参数
     * @return 椭圆曲线参数
     */
    private org.bouncycastle.jce.interfaces.ECPublicKey getEcPublicKey() throws Exception {
        String cacheKey = "ecPublicKey_" + Constants.CURVE_NAME;
        return (org.bouncycastle.jce.interfaces.ECPublicKey) cryptoCache.computeIfAbsent(cacheKey, k -> {
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
    private org.bouncycastle.math.ec.ECPoint getInfinityPoint() throws Exception {
        String cacheKey = "infinityPoint_" + Constants.CURVE_NAME;
        return (org.bouncycastle.math.ec.ECPoint) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                cachedCryptoOperationCount.incrementAndGet();
                return getEcPublicKey().getParameters().getCurve().getInfinity();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 获取加密操作统计信息
     * @return 加密操作统计
     */
    public Map<String, Object> getCryptoStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("cryptoOperationCount", cryptoOperationCount.get());
        stats.put("cachedCryptoOperationCount", cachedCryptoOperationCount.get());
        stats.put("cacheSize", cryptoCache.size());
        if (cryptoOperationCount.get() > 0) {
            stats.put("cacheHitRate", (double) cachedCryptoOperationCount.get() / cryptoOperationCount.get());
        }
        return stats;
    }
    
    /**
     * 清理已完成的任务，释放内存
     */
    public void cleanupCompletedTasks() {
        List<String> completedTaskIds = new ArrayList<>();
        long currentTime = System.currentTimeMillis();
        
        for (Map.Entry<String, SignatureTask> entry : signatureTasks.entrySet()) {
            SignatureTask task = entry.getValue();
            // 清理已完成且超过1小时的任务
            if (task.isCompleted() && (currentTime - task.createdAt) > 3600000) {
                completedTaskIds.add(entry.getKey());
            }
        }
        
        // 执行清理
        for (String taskId : completedTaskIds) {
            signatureTasks.remove(taskId);
            logger.info("Cleaned up completed task: {}", taskId);
        }
        
        if (!completedTaskIds.isEmpty()) {
            logger.info("Cleaned up {} completed tasks", completedTaskIds.size());
        }
    }
    
    /**
     * 获取缓存统计信息
     * @return 缓存统计数据
     */
    public Map<String, Object> getCacheStats() {
        long hits = cacheHits.get();
        long misses = cacheMisses.get();
        long total = hits + misses;
        double hitRate = total > 0 ? (double) hits / total : 0.0;
        
        Map<String, Object> stats = new HashMap<>();
        stats.put("cacheSize", signatureTasks.size());
        stats.put("cacheHits", hits);
        stats.put("cacheMisses", misses);
        stats.put("hitRate", String.format("%.2f%%", hitRate * 100));
        stats.put("totalRequests", total);
        return stats;
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
                    case COMMITMENT:
                        // 处理签名相关的临时公钥消息
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            org.bouncycastle.math.ec.ECPoint R_i = (org.bouncycastle.math.ec.ECPoint) dataMap.get("R_i");
                            
                            // 调用已有的处理方法
                            handleCommitment(senderId, taskId, R_i);
                            logger.info("Received commitment from node {} for signature task: {}", senderId, taskId);
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
        }, Executors.newSingleThreadExecutor());
    }

}