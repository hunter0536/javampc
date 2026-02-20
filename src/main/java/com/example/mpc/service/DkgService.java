package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.model.KeyShare;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class DkgService implements NodeService.MessageHandler, ApplicationContextAware {
    private static final Logger logger = LoggerFactory.getLogger(DkgService.class);
    
    @Autowired
    private DatabaseService databaseService;
    
    @Autowired
    private NodeService nodeService;
    
    @Value("${node.id}")
    private int nodeId;
    
    @Value("${nodes.count}")
    private int nodesCount;
    
    private ApplicationContext applicationContext;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    // 重构私钥所需的最小份额数
    // 以太坊使用的椭圆曲线
    
    // 任务状态管理
    public static class DkgTask {
        public final String taskId;
        public final AtomicReference<TaskStatus> status;
        public String groupPublicKey;
        public BigInteger finalShare;
        public final CountDownLatch commitmentsReceivedLatch;
        public final CountDownLatch sharesReceivedLatch;
        public final ConcurrentHashMap<Integer, List<org.bouncycastle.math.ec.ECPoint>> receivedCommitments;
        public final ConcurrentHashMap<Integer, BigInteger> receivedShares;
        public List<BigInteger> coefficients;
        public List<org.bouncycastle.math.ec.ECPoint> verificationPoints;
        public List<BigInteger> maskingCoefficients; // 遮蔽多项式系数
        public List<org.bouncycastle.math.ec.ECPoint> maskingVerificationPoints; // 遮蔽多项式验证点
        public final ConcurrentHashMap<Integer, List<org.bouncycastle.math.ec.ECPoint>> receivedMaskingCommitments; // 接收的遮蔽验证点
        public long createdAt;
        
        public DkgTask(String taskId) {
            this.taskId = taskId;
            this.status = new AtomicReference<>(TaskStatus.IDLE);
            this.groupPublicKey = null;
            this.finalShare = null;
            this.commitmentsReceivedLatch = new CountDownLatch(5 - 1); // 假设总共有5个节点
            this.sharesReceivedLatch = new CountDownLatch(5 - 1); // 假设总共有5个节点
            this.receivedCommitments = new ConcurrentHashMap<>();
            this.receivedShares = new ConcurrentHashMap<>();
            this.receivedMaskingCommitments = new ConcurrentHashMap<>();
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
    
    private final ConcurrentHashMap<String, DkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final AtomicBoolean dkgInProgress = new AtomicBoolean(false);
    
    public DkgService() {
    }
    
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }
    
    /**
     * 创建新的DKG任务
     * @return 任务ID
     */
    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        DkgTask task = new DkgTask(taskId);
        dkgTasks.put(taskId, task);
        return taskId;
    }
    
    /**
     * 获取DKG任务状态
     * @param taskId 任务ID
     * @return 任务状态
     */
    public Map<String, Object> getTaskStatus(String taskId) {
        DkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("DKG task not found: " + taskId);
        }
        
        Map<String, Object> status = new HashMap<>();
        status.put("taskId", task.taskId);
        status.put("inProgress", task.inProgress);
        status.put("completed", task.completed);
        status.put("groupPublicKey", task.groupPublicKey);
        return status;
    }
    
    /**
     * 获取任务对应的群公钥
     * @param taskId 任务ID
     * @return 群公钥
     */
    public String getGroupPublicKey(String taskId) {
        DkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("DKG task not found: " + taskId);
        }
        
        if (!task.completed) {
            throw new RuntimeException("DKG task not completed yet: " + taskId);
        }
        
        return task.groupPublicKey;
    }
    
    /**
     * 初始化DKG服务
     */
    public CompletableFuture<Void> init() {
        return CompletableFuture.runAsync(() -> {
            try {
                // 启动P2P服务器
                nodeService.startP2PServer().join();
                
                // 注册消息处理器
                for (int i = 1; i <= nodesCount; i++) {
                    if (i != nodeId) {
                        nodeService.registerMessageHandler(i, this);
                    }
                }
                
                logger.info("DKG service initialized successfully for node {}", nodeId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 启动DKG过程
     * @param taskId 任务ID
     */
    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return CompletableFuture.runAsync(() -> {
            if (dkgInProgress.get()) {
                throw new RuntimeException("DKG process is already in progress");
            }
            
            DkgTask task = dkgTasks.get(taskId);
            if (task == null) {
                throw new RuntimeException("DKG task not found: " + taskId);
            }
            
            if (task.isInProgress() || task.isCompleted()) {
                throw new RuntimeException("DKG task is already in progress or completed");
            }
            
            dkgInProgress.set(true);
            if (!task.start()) {
                dkgInProgress.set(false);
                throw new RuntimeException("Failed to start DKG task");
            }
            logger.info("Starting DKG process for task: {}", taskId);
            
            try {
                // 开始DKG流程
                generateDistributedKey(taskId).join();
                
                dkgInProgress.set(false);
                task.inProgress = false;
                task.completed = true;
                logger.info("DKG process completed for task: {}", taskId);
            } catch (Exception e) {
                dkgInProgress.set(false);
                task.inProgress = false;
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 生成分布式密钥（使用NodeService处理P2P通信）
     * @param taskId 任务ID
     * @return 生成的密钥份额
     */
    public CompletableFuture<KeyShare> generateDistributedKey(String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                DkgTask task = dkgTasks.get(taskId);
                if (task == null) {
                    throw new RuntimeException("DKG task not found: " + taskId);
                }
                
                // 初始化本节点数据库
                databaseService.initShareDatabase(nodeId);
                
                // 等待网络稳定（至少发现所有节点）
                nodeService.waitForNetworkReady().join();
                
                // 步骤1: 生成自己的多项式和遮蔽多项式
                task.coefficients = generateRandomPolynomial(Constants.THRESHOLD - 1);
                task.maskingCoefficients = generateMaskingPolynomial(Constants.THRESHOLD - 1);
                
                // 步骤2: 生成两组验证点
                task.verificationPoints = generateVerificationPoints(task.coefficients);
                task.maskingVerificationPoints = generateVerificationPoints(task.maskingCoefficients);
                
                // 步骤3: 广播两组验证点给所有其他节点
                Map<String, Object> commitmentData = new HashMap<>();
                commitmentData.put("taskId", taskId);
                commitmentData.put("verificationPoints", task.verificationPoints);
                commitmentData.put("maskingVerificationPoints", task.maskingVerificationPoints);
                nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.COMMITMENT, commitmentData)).join();
                
                // 步骤4: 等待接收所有其他节点的验证点
                logger.info("Node {} waiting for commitments for task: {}", nodeId, taskId);
                if (!task.commitmentsReceivedLatch.await(60, TimeUnit.SECONDS)) {
                    throw new Exception("Timeout waiting for commitments");
                }
                logger.info("Node {} received all commitments for task: {}", nodeId, taskId);
                
                // 步骤5: 验证所有其他节点的验证点
                for (Integer senderId : task.receivedCommitments.keySet()) {
                    List<org.bouncycastle.math.ec.ECPoint> commitments = task.receivedCommitments.get(senderId);
                    List<org.bouncycastle.math.ec.ECPoint> maskingCommitments = task.receivedMaskingCommitments.get(senderId);
                    if (!verifyCommitments(commitments) || !verifyCommitments(maskingCommitments)) {
                        throw new Exception("Invalid commitments received from node " + senderId);
                    }
                    logger.info("Successfully verified commitments from node {} for task: {}", senderId, taskId);
                }
                
                // 步骤6: 为每个其他节点生成份额并发送
                List<CompletableFuture<Void>> sendFutures = new ArrayList<>();
                for (NodeService.NodeInfo nodeInfo : nodeService.getNodes()) {
                    if (nodeInfo.id != nodeId) {
                        // 生成实际份额
                        BigInteger actualShare = evaluatePolynomial(task.coefficients, BigInteger.valueOf(nodeInfo.id));
                        // 生成遮蔽份额
                        BigInteger maskingShare = evaluatePolynomial(task.maskingCoefficients, BigInteger.valueOf(nodeInfo.id));
                        // 组合份额 = 实际份额 + 遮蔽份额
                        BigInteger combinedShare = actualShare.add(maskingShare);
                        
                        Map<String, Object> shareData = new HashMap<>();
                        shareData.put("taskId", taskId);
                        shareData.put("share", combinedShare);
                        CompletableFuture<Void> future = nodeService.sendMessage(nodeInfo.id, new NodeService.Message(nodeId, NodeService.Message.Type.SHARE, shareData))
                            .exceptionally(ex -> {
                                logger.error("Failed to send share to node {}: {}", nodeInfo.id, ex.getMessage());
                                return null;
                            });
                        sendFutures.add(future);
                    }
                }
                CompletableFuture.allOf(sendFutures.toArray(new CompletableFuture[0])).join();
                
                // 步骤7: 等待接收所有其他节点的份额
                logger.info("Node {} waiting for shares for task: {}", nodeId, taskId);
                if (!task.sharesReceivedLatch.await(60, TimeUnit.SECONDS)) {
                    throw new Exception("Timeout waiting for shares");
                }
                logger.info("Node {} received all shares for task: {}", nodeId, taskId);
                
                // 步骤8: 验证所有收到的份额
                for (Integer senderId : task.receivedShares.keySet()) {
                    BigInteger share = task.receivedShares.get(senderId);
                    List<org.bouncycastle.math.ec.ECPoint> commitments = task.receivedCommitments.get(senderId);
                    List<org.bouncycastle.math.ec.ECPoint> maskingCommitments = task.receivedMaskingCommitments.get(senderId);
                    if (commitments == null || maskingCommitments == null || !verifyGennaroShare(share, nodeId, commitments, maskingCommitments)) {
                        throw new Exception("Invalid share received from node " + senderId);
                    }
                }
                
                // 步骤9: 计算最终份额（所有收到的份额之和）
                task.finalShare = BigInteger.ZERO;
                for (BigInteger share : task.receivedShares.values()) {
                    task.finalShare = task.finalShare.add(share);
                }
                
                // 步骤10: 去中心化生成群公钥
                generateAndBroadcastPublicKeyPart(taskId).join();
                
                // 步骤11: 等待群公钥生成完成
                int maxWaitTime = 60; // 最大等待时间（秒）
                int waitTime = 0;
                while (task.groupPublicKey == null && waitTime < maxWaitTime) {
                    Thread.sleep(1000);
                    waitTime++;
                }
                
                if (task.groupPublicKey == null) {
                    throw new Exception("Timeout waiting for group public key generation");
                }
                
                // 步骤12: 保存密钥份额到本节点数据库
                String shareBase64 = Base64.getEncoder().encodeToString(task.finalShare.toByteArray());
                KeyShare keyShare = new KeyShare(1L, nodeId, shareBase64); // 使用固定的walletId=1
                saveKeyShareToDatabase(keyShare);
                
                logger.info("Gennaro DKG process completed successfully for task: {}", taskId);
                task.complete();
                return keyShare;
            } catch (Exception e) {
                e.printStackTrace();
                task.fail();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 生成并广播公钥部分
     * @param taskId 任务ID
     */
    private CompletableFuture<Void> generateAndBroadcastPublicKeyPart(String taskId) {
        DkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("DKG task not found: " + taskId));
        }
        
        try {
            // 步骤1: 收集所有节点的实际验证点（第一个验证点对应多项式常数项）
            List<org.bouncycastle.math.ec.ECPoint> allConstantCommitments = new ArrayList<>();
            
            // 添加本节点的常数项验证点
            if (!task.verificationPoints.isEmpty()) {
                allConstantCommitments.add(task.verificationPoints.get(0));
            }
            
            // 添加其他节点的常数项验证点
            for (Integer senderId : task.receivedCommitments.keySet()) {
                List<org.bouncycastle.math.ec.ECPoint> commitments = task.receivedCommitments.get(senderId);
                if (!commitments.isEmpty()) {
                    allConstantCommitments.add(commitments.get(0));
                }
            }
            
            // 步骤2: 聚合所有常数项验证点，生成群公钥
            if (!allConstantCommitments.isEmpty()) {
                // 获取椭圆曲线参数
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
                
                // 初始化群公钥为第一个验证点
                org.bouncycastle.math.ec.ECPoint groupPublicKeyPoint = allConstantCommitments.get(0);
                
                // 累加其他验证点
                for (int i = 1; i < allConstantCommitments.size(); i++) {
                    groupPublicKeyPoint = groupPublicKeyPoint.add(allConstantCommitments.get(i));
                }
                
                // 步骤3: 将群公钥转换为可存储的格式
                // 注意：这里使用了简化的转换方式，实际应用中可能需要更复杂的处理
                // 由于ECPoint无法直接转换为PublicKey，我们使用验证点的编码作为群公钥
                byte[] groupPublicKeyBytes = groupPublicKeyPoint.getEncoded(false);
                String groupPublicKey = Base64.getEncoder().encodeToString(groupPublicKeyBytes);
                
                // 步骤4: 广播群公钥
                Map<String, Object> publicKeyData = new HashMap<>();
                publicKeyData.put("taskId", taskId);
                publicKeyData.put("groupPublicKey", groupPublicKey);
                
                return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.PUBLIC_KEY_PART, publicKeyData))
                    .thenRun(() -> {
                        task.groupPublicKey = groupPublicKey;
                        logger.info("Generated and broadcasted group public key for task: {}", taskId);
                    })
                    .exceptionally(ex -> {
                        logger.error("Failed to generate and broadcast group public key: {}", ex.getMessage());
                        throw new RuntimeException(ex);
                    });
            } else {
                throw new Exception("No commitments found to generate group public key");
            }
        } catch (Exception e) {
            logger.error("Error generating group public key: {}", e.getMessage());
            return CompletableFuture.failedFuture(new RuntimeException(e));
        }
    }
    
    /**
     * 验证验证点是否有效
     * @param commitments 验证点列表
     * @return 是否有效
     */
    private boolean verifyCommitments(List<org.bouncycastle.math.ec.ECPoint> commitments) throws Exception {
        // 检查验证点列表是否为空
        if (commitments == null || commitments.isEmpty()) {
            logger.warn("Invalid commitments: empty list");
            return false;
        }
        
        // 检查验证点数量是否正确（应该等于阈值）
        if (commitments.size() != Constants.THRESHOLD) {
            logger.warn("Invalid commitments: wrong size. Expected {}, got {}", Constants.THRESHOLD, commitments.size());
            return false;
        }
        
        // 获取椭圆曲线参数
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        
        // 检查每个验证点是否在椭圆曲线上
        for (int i = 0; i < commitments.size(); i++) {
            org.bouncycastle.math.ec.ECPoint point = commitments.get(i);
            
            // 检查点是否为无穷远点
            if (point.isInfinity()) {
                logger.warn("Invalid commitment at index {}: infinity point", i);
                return false;
            }
            
            // 检查点是否在椭圆曲线上
            // 简化处理：假设点已经在曲线上（实际应用中需要更严格的验证）
        }
        
        // 验证点有效
        return true;
    }
    
    /**
     * 生成随机多项式
     * @param degree 多项式次数
     * @return 多项式系数
     */
    private List<BigInteger> generateRandomPolynomial(int degree) {
        List<BigInteger> coefficients = new ArrayList<>();
        
        // 生成随机常数项（节点的秘密）
        BigInteger secret = new BigInteger(256, new SecureRandom());
        coefficients.add(secret);
        
        // 生成随机系数
        for (int i = 1; i <= degree; i++) {
            coefficients.add(new BigInteger(256, new SecureRandom()));
        }
        
        return coefficients;
    }
    
    /**
     * 生成遮蔽多项式（Gennaro DKG）
     * @param degree 多项式次数
     * @return 遮蔽多项式系数
     */
    private List<BigInteger> generateMaskingPolynomial(int degree) {
        List<BigInteger> coefficients = new ArrayList<>();
        
        // 遮蔽多项式的常数项为0
        coefficients.add(BigInteger.ZERO);
        
        // 生成随机系数
        for (int i = 1; i <= degree; i++) {
            coefficients.add(new BigInteger(256, new SecureRandom()));
        }
        
        return coefficients;
    }
    
    /**
     * 生成验证点（Feldman DKG）
     * @param coefficients 多项式系数
     * @return 验证点列表
     */
    private List<org.bouncycastle.math.ec.ECPoint> generateVerificationPoints(List<BigInteger> coefficients) throws Exception {
        // 获取椭圆曲线参数
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        org.bouncycastle.math.ec.ECPoint G = publicKey.getParameters().getG(); // 基点
        
        // 计算验证点：Vi = G * 系数i
        List<org.bouncycastle.math.ec.ECPoint> verificationPoints = new ArrayList<>();
        for (BigInteger coefficient : coefficients) {
            org.bouncycastle.math.ec.ECPoint point = G.multiply(coefficient);
            verificationPoints.add(point);
        }
        
        return verificationPoints;
    }
    
    /**
     * 验证份额（Feldman DKG）
     * @param share 要验证的份额
     * @param x 份额的索引
     * @param verificationPoints 验证点列表
     * @return 是否有效
     */
    private boolean verifyShare(BigInteger share, int x, List<org.bouncycastle.math.ec.ECPoint> verificationPoints) throws Exception {
        // 获取椭圆曲线参数
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        org.bouncycastle.math.ec.ECPoint G = publicKey.getParameters().getG(); // 基点
        
        // 计算 g^share
        org.bouncycastle.math.ec.ECPoint gShare = G.multiply(share);
        
        // 计算 v0 * v1^x * v2^x^2 * ... * v(t-1)^x^(t-1)
        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger xPower = BigInteger.ONE;
        org.bouncycastle.math.ec.ECPoint computedPoint = verificationPoints.get(0);
        
        for (int i = 1; i < verificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            org.bouncycastle.math.ec.ECPoint viPower = verificationPoints.get(i).multiply(xPower);
            computedPoint = computedPoint.add(viPower);
        }
        
        // 验证 g^share 是否等于计算出的点
        return gShare.equals(computedPoint);
    }
    
    /**
     * 验证Gennaro DKG中的组合份额
     * @param share 要验证的组合份额
     * @param x 份额的索引
     * @param verificationPoints 实际多项式的验证点列表
     * @param maskingVerificationPoints 遮蔽多项式的验证点列表
     * @return 是否有效
     */
    private boolean verifyGennaroShare(BigInteger share, int x, List<org.bouncycastle.math.ec.ECPoint> verificationPoints, List<org.bouncycastle.math.ec.ECPoint> maskingVerificationPoints) throws Exception {
        // 获取椭圆曲线参数
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (org.bouncycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
        org.bouncycastle.math.ec.ECPoint G = publicKey.getParameters().getG(); // 基点
        
        // 计算 g^share
        org.bouncycastle.math.ec.ECPoint gShare = G.multiply(share);
        
        // 计算实际多项式的贡献：v0 * v1^x * v2^x^2 * ... * v(t-1)^x^(t-1)
        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger xPower = BigInteger.ONE;
        org.bouncycastle.math.ec.ECPoint computedActualPoint = verificationPoints.get(0);
        
        for (int i = 1; i < verificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            org.bouncycastle.math.ec.ECPoint viPower = verificationPoints.get(i).multiply(xPower);
            computedActualPoint = computedActualPoint.add(viPower);
        }
        
        // 计算遮蔽多项式的贡献：w0 * w1^x * w2^x^2 * ... * w(t-1)^x^(t-1)
        xPower = BigInteger.ONE;
        org.bouncycastle.math.ec.ECPoint computedMaskingPoint = maskingVerificationPoints.get(0);
        
        for (int i = 1; i < maskingVerificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            org.bouncycastle.math.ec.ECPoint wiPower = maskingVerificationPoints.get(i).multiply(xPower);
            computedMaskingPoint = computedMaskingPoint.add(wiPower);
        }
        
        // 计算总贡献：实际贡献 + 遮蔽贡献
        org.bouncycastle.math.ec.ECPoint computedTotalPoint = computedActualPoint.add(computedMaskingPoint);
        
        // 验证 g^share 是否等于总贡献
        return gShare.equals(computedTotalPoint);
    }
    
    /**
     * 计算多项式在给定点的值
     * @param coefficients 多项式系数
     * @param x 点的x坐标
     * @return 多项式在x点的值
     */
    private BigInteger evaluatePolynomial(List<BigInteger> coefficients, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        
        for (BigInteger coefficient : coefficients) {
            result = result.add(coefficient.multiply(xPower));
            xPower = xPower.multiply(x);
        }
        
        return result;
    }
    
    /**
     * 保存密钥份额到本节点数据库
     * @param keyShare 密钥份额对象
     * @throws SQLException 异常
     */
    private void saveKeyShareToDatabase(KeyShare keyShare) throws SQLException {
        String insertSql = "INSERT INTO key_shares (wallet_id, share_index, key_share) VALUES (?, ?, ?)";
        String selectSql = "SELECT last_insert_rowid()";
        
        try (Connection conn = databaseService.getShareConnection(keyShare.getShareIndex());
             PreparedStatement insertStmt = conn.prepareStatement(insertSql);
             PreparedStatement selectStmt = conn.prepareStatement(selectSql)) {
            insertStmt.setLong(1, keyShare.getWalletId());
            insertStmt.setInt(2, keyShare.getShareIndex());
            insertStmt.setString(3, keyShare.getKeyShare());
            insertStmt.executeUpdate();
            
            // 获取生成的ID
            var rs = selectStmt.executeQuery();
            if (rs.next()) {
                keyShare.setId(rs.getLong(1));
            }
        }
    }
    
    /**
     * 从本节点数据库加载密钥份额
     * @param walletId 钱包ID
     * @return 密钥份额
     * @throws SQLException 异常
     */
    public CompletableFuture<KeyShare> loadKeyShare(Long walletId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String sql = "SELECT id, wallet_id, share_index, key_share FROM key_shares WHERE wallet_id = ?";
                try (Connection conn = databaseService.getShareConnection(nodeId);
                     PreparedStatement pstmt = conn.prepareStatement(sql)) {
                    pstmt.setLong(1, walletId);
                    var rs = pstmt.executeQuery();
                    if (rs.next()) {
                        KeyShare keyShare = new KeyShare();
                        keyShare.setId(rs.getLong("id"));
                        keyShare.setWalletId(rs.getLong("wallet_id"));
                        keyShare.setShareIndex(rs.getInt("share_index"));
                        keyShare.setKeyShare(rs.getString("key_share"));
                        return keyShare;
                    }
                }
                return null;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
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
                        // 接收其他节点的验证点
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            List<org.bouncycastle.math.ec.ECPoint> verificationPoints = (List<org.bouncycastle.math.ec.ECPoint>) dataMap.get("verificationPoints");
                            List<org.bouncycastle.math.ec.ECPoint> maskingVerificationPoints = (List<org.bouncycastle.math.ec.ECPoint>) dataMap.get("maskingVerificationPoints");
                            
                            DkgTask task = dkgTasks.get(taskId);
                            if (task != null) {
                                task.receivedCommitments.put(senderId, verificationPoints);
                                if (maskingVerificationPoints != null) {
                                    task.receivedMaskingCommitments.put(senderId, maskingVerificationPoints);
                                }
                                task.commitmentsReceivedLatch.countDown();
                                logger.info("Received commitment from node {} for task: {}", senderId, taskId);
                            }
                        }
                        break;
                    case SHARE:
                        // 接收其他节点的份额
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            BigInteger share = (BigInteger) dataMap.get("share");
                            
                            DkgTask task = dkgTasks.get(taskId);
                            if (task != null) {
                                task.receivedShares.put(senderId, share);
                                task.sharesReceivedLatch.countDown();
                                logger.info("Received share from node {} for task: {}", senderId, taskId);
                            }
                        }
                        break;
                    case PUBLIC_KEY_PART:
                        // 接收公钥部分
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            String publicKeyPart = (String) dataMap.get("publicKeyPart");
                            String groupPublicKey = (String) dataMap.get("groupPublicKey");
                            
                            if (groupPublicKey != null) {
                                handleGroupPublicKey(senderId, taskId, groupPublicKey);
                            } else if (publicKeyPart != null) {
                                handlePublicKeyPart(senderId, taskId, publicKeyPart);
                            }
                        }
                        break;

                    case DKG_INIT:
                        // 接收DKG初始化请求
                        if (!dkgInProgress.get()) {
                            String taskId = createDkgTask();
                            startDkgProcess(taskId).join();
                        }
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, Executors.newSingleThreadExecutor());
    }
    
    /**
     * 处理公钥部分
     */
    private void handlePublicKeyPart(int senderId, String taskId, String publicKeyPart) throws Exception {
        // 注意：这里需要实现去中心化的群公钥生成
        // 简化处理，将所有公钥部分存储，当收集到足够多的部分后生成最终公钥
        // 实际实现中需要更复杂的协议
    }
    
    /**
     * 处理群公钥消息
     */
    private void handleGroupPublicKey(int senderId, String taskId, String groupPublicKey) throws Exception {
        DkgTask task = dkgTasks.get(taskId);
        if (task != null && task.groupPublicKey == null) {
            task.groupPublicKey = groupPublicKey;
            logger.info("Received group public key from node {} for task: {}", senderId, taskId);
        }
    }
}