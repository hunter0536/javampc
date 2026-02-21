package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.model.DkgTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.util.ThreadPoolUtil;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class DkgService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(DkgService.class);
    
    @Autowired
    private DatabaseService databaseService;
    
    @Autowired
    private NodeService nodeService;
    
    @Value("${node.id}")
    private int nodeId;
    
    // 使用Constants中的常量
    private final int nodesCount = Constants.NODES_COUNT;
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    // 任务状态管理
    private final ConcurrentHashMap<String, DkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final AtomicBoolean dkgInProgress = new AtomicBoolean(false);
    // 缓存椭圆曲线参数
    private final ConcurrentHashMap<String, Object> cryptoCache = new ConcurrentHashMap<>();
    
    public DkgService() {
    }
    
    /**
     * 创建新的DKG任务
     * @return 任务ID
     */
    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        DkgTask task = new DkgTask(taskId, nodesCount);
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
        status.put("status", task.status.get().name());
        status.put("inProgress", task.inProgress);
        status.put("completed", task.completed);
        status.put("groupPublicKey", task.groupPublicKey);
        status.put("errorMessage", task.errorMessage);
        status.put("receivedCommitments", task.receivedCommitments.size());
        status.put("receivedShares", task.receivedShares.size());
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
            // 任务未完成时返回null，而不是抛出异常
            return null;
        }
        
        return task.groupPublicKey;
    }
    
    /**
     * 初始化DKG服务
     */
    public CompletableFuture<Void> init() {
        return ThreadPoolUtil.submitIoTask(() -> {
            try {
                // 启动P2P服务器
                nodeService.startP2PServer().join();
                
                // 注册消息处理器
                nodeService.registerMessageHandler(-1, this);
                
                logger.info("DKG service initialized successfully for node {}", nodeId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 启动DKG过程
     * @param taskId 任务ID
     */
    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return CompletableFuture.runAsync(() -> {
            logger.info("startDkgProcess invoked for task {}", taskId);
            boolean started = false;
            DkgTask task = null;
            try {
                if (dkgInProgress.get()) {
                    // 尝试识别并清理卡死的任务
                    long now = System.currentTimeMillis();
                    long staleMs = (Constants.DKG_COMMITMENT_TIMEOUT_SECONDS + Constants.DKG_SHARE_TIMEOUT_SECONDS + 30) * 1000L;
                    DkgTask inProgressTask = null;
                    for (DkgTask t : dkgTasks.values()) {
                        if (t.isInProgress()) {
                            inProgressTask = t;
                            break;
                        }
                    }
                    if (inProgressTask != null) {
                        long ageMs = now - inProgressTask.startedAtMs;
                        logger.warn("DKG already in progress (task {} age {}ms)", inProgressTask.taskId, ageMs);
                        if (inProgressTask.startedAtMs > 0 && ageMs > staleMs) {
                            logger.warn("Clearing stale DKG task {}", inProgressTask.taskId);
                            inProgressTask.fail();
                            inProgressTask.errorMessage = "Stale DKG task cleared before starting new one";
                            dkgInProgress.set(false);
                        } else {
                            throw new RuntimeException("DKG process is already in progress");
                        }
                    } else {
                        // 标志为true但无任务在进度中，重置
                        dkgInProgress.set(false);
                    }
                }

                task = dkgTasks.get(taskId);
                if (task == null) {
                    // DKG_INIT 可能先于任务创建到达，延迟等待任务创建
                    int attempts = 0;
                    while (task == null && attempts < 20) {
                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                        task = dkgTasks.get(taskId);
                        attempts++;
                    }
                    if (task == null) {
                        throw new RuntimeException("DKG task not found: " + taskId);
                    }
                }

                if (task.isInProgress() || task.isCompleted()) {
                    throw new RuntimeException("DKG task is already in progress or completed");
                }

                dkgInProgress.set(true);
                started = true;
                if (!task.start()) {
                    throw new RuntimeException("Failed to start DKG task");
                }
                logger.info("Starting DKG process for task: {}", taskId);

                // 等待网络就绪（最多等待60秒）
                logger.info("Waiting for network ready...");
                boolean networkReady = false;
                int waitTime = 0;
                int maxWaitTime = 60;
                
                while (!networkReady && waitTime < maxWaitTime) {
                    try {
                        nodeService.waitForNetworkReady().get(5, TimeUnit.SECONDS);
                        networkReady = true;
                    } catch (TimeoutException e) {
                        // 网络未就绪，继续等待
                        waitTime += 5;
                        logger.info("Network not ready yet, waiting... ({}/{})\n", waitTime, maxWaitTime);
                    }
                }
                
                if (!networkReady) {
                    logger.warn("Network not fully ready, but proceeding with DKG process");
                } else {
                    logger.info("Network ready, broadcasting DKG_INIT message");
                }
                
                // 广播DKG_INIT消息，通知其他节点启动对应的DKG任务
                Map<String, Object> initData = new HashMap<>();
                initData.put("taskId", taskId);
                try {
                    for (int attempt = 1; attempt <= 3; attempt++) {
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.DKG_INIT, initData)).join();
                        logger.info("Broadcasted DKG_INIT message for task: {} (attempt {}/3)", taskId, attempt);
                        if (attempt < 3) {
                            Thread.sleep(1000);
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to broadcast DKG_INIT message, but proceeding with DKG process: {}", e.getMessage());
                }
                
                // 开始DKG流程
                generateDistributedKey(taskId).join();
                
                dkgInProgress.set(false);
                task.inProgress = false;
                task.completed = true;
                logger.info("DKG process completed for task: {}", taskId);
            } catch (Exception e) {
                if (started) {
                    dkgInProgress.set(false);
                }
                if (task != null) {
                    task.inProgress = false;
                    task.fail();
                    task.errorMessage = e.getMessage();
                }
                logger.error("Error in DKG process: {}", e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
    }
    
    /**
     * 生成分布式密钥（使用NodeService处理P2P通信）
     * @param taskId 任务ID
     * @return 生成的密钥份额
     */
    public CompletableFuture<KeyShare> generateDistributedKey(String taskId) {
        return generateDistributedKey(taskId, false);
    }
    
    /**
     * 生成分布式密钥（使用NodeService处理P2P通信）
     * @param taskId 任务ID
     * @param forceSingleNodeMode 是否强制使用单节点模式
     * @return 生成的密钥份额
     */
    public CompletableFuture<KeyShare> generateDistributedKey(String taskId, boolean forceSingleNodeMode) {
        return CompletableFuture.supplyAsync(() -> {
            DkgTask task = null;
            try {
                task = dkgTasks.get(taskId);
                if (task == null) {
                    throw new RuntimeException("DKG task not found: " + taskId);
                }
                
                // 初始化本节点数据库
                databaseService.initShareDatabase(nodeId);
                
                // 检查是否使用单节点模式（根据用户要求，禁用单节点模式）
                if (forceSingleNodeMode) {
                    throw new RuntimeException("Single node mode is not allowed");
                }
                
                // 等待网络稳定（至少发现所有节点）
                logger.info("Waiting for network ready...");
                nodeService.waitForNetworkReady().join();
                
                // 检查网络中的节点数量
                int networkSize = nodeService.getNodes().size() + 1; // 加上自己
                if (networkSize < nodesCount) {
                    throw new RuntimeException("Not enough nodes in network. Expected: " + nodesCount + ", found: " + networkSize);
                }
                logger.info("Network ready with {} nodes", networkSize);

                // 给其他节点留出时间创建任务，避免承诺消息在任务创建前到达
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                
                // 步骤1: 生成自己的多项式和遮蔽多项式
                task.coefficients = generateRandomPolynomial(Constants.THRESHOLD - 1);
                task.maskingCoefficients = generateMaskingPolynomial(Constants.THRESHOLD - 1);
                
                // 步骤2: 生成两组验证点
                task.verificationPoints = generateVerificationPoints(task.coefficients);
                task.maskingVerificationPoints = generateVerificationPoints(task.maskingCoefficients);
                
                // 步骤3: 广播两组验证点给所有其他节点
                Map<String, Object> commitmentData = new HashMap<>();
                commitmentData.put("taskId", taskId);
                // 将ECPoint转换为Base64编码的字节数组以便序列化
                List<String> encodedVerificationPoints = new ArrayList<>();
                for (ECPoint point : task.verificationPoints) {
                    encodedVerificationPoints.add(Base64.getEncoder().encodeToString(point.getEncoded(false)));
                }
                List<String> encodedMaskingVerificationPoints = new ArrayList<>();
                for (ECPoint point : task.maskingVerificationPoints) {
                    encodedMaskingVerificationPoints.add(Base64.getEncoder().encodeToString(point.getEncoded(false)));
                }
                commitmentData.put("verificationPoints", encodedVerificationPoints);
                commitmentData.put("maskingVerificationPoints", encodedMaskingVerificationPoints);
                for (int attempt = 1; attempt <= 3; attempt++) {
                    nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.COMMITMENT, commitmentData)).join();
                    logger.info("Broadcasted verification points for task: {} (attempt {}/3)", taskId, attempt);
                    if (attempt < 3) {
                        Thread.sleep(1000);
                    }
                }
                
                // 步骤4: 等待接收所有其他节点的验证点
                logger.info("Node {} waiting for commitments for task: {}", nodeId, taskId);
                if (!task.commitmentsReceivedLatch.await(Constants.DKG_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new Exception("Timeout waiting for commitments");
                }
                logger.info("Node {} received all commitments for task: {}", nodeId, taskId);
                
                // 步骤5: 验证所有其他节点的验证点
                for (Integer senderId : task.receivedCommitments.keySet()) {
                    List<ECPoint> commitments = task.receivedCommitments.get(senderId);
                    List<ECPoint> maskingCommitments = task.receivedMaskingCommitments.get(senderId);
                    if (!verifyCommitments(commitments, false) || !verifyCommitments(maskingCommitments, true)) {
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
                                throw new RuntimeException(ex);
                            });
                        sendFutures.add(future);
                    }
                }
                CompletableFuture.allOf(sendFutures.toArray(new CompletableFuture[0])).join();
                logger.info("Sent shares to all nodes for task: {}", taskId);
                
                // 步骤7: 等待接收所有其他节点的份额
                logger.info("Node {} waiting for shares for task: {}", nodeId, taskId);
                if (!task.sharesReceivedLatch.await(Constants.DKG_SHARE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new Exception("Timeout waiting for shares");
                }
                logger.info("Node {} received all shares for task: {}", nodeId, taskId);
                
                // 步骤8: 验证所有收到的份额
                for (Integer senderId : task.receivedShares.keySet()) {
                    BigInteger share = task.receivedShares.get(senderId);
                    List<ECPoint> commitments = task.receivedCommitments.get(senderId);
                    List<ECPoint> maskingCommitments = task.receivedMaskingCommitments.get(senderId);
                    if (commitments == null || maskingCommitments == null || !verifyGennaroShare(share, nodeId, commitments, maskingCommitments)) {
                        throw new Exception("Invalid share received from node " + senderId);
                    }
                }
                logger.info("Verified all received shares for task: {}", taskId);
                
                // 步骤9: 计算最终份额（所有收到的份额之和 + 自己的份额）
                task.finalKeyShare = BigInteger.ZERO;
                for (BigInteger share : task.receivedShares.values()) {
                    task.finalKeyShare = task.finalKeyShare.add(share);
                }
                BigInteger selfActualShare = evaluatePolynomial(task.coefficients, BigInteger.valueOf(nodeId));
                BigInteger selfMaskingShare = evaluatePolynomial(task.maskingCoefficients, BigInteger.valueOf(nodeId));
                task.finalKeyShare = task.finalKeyShare.add(selfActualShare.add(selfMaskingShare));
                logger.info("Calculated final key share for task: {}", taskId);
                
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
                logger.info("Group public key generated for task: {}", taskId);
                
                // 保存密钥份额到本节点数据库
                String shareBase64 = Base64.getEncoder().encodeToString(task.finalKeyShare.toByteArray());
                KeyShare keyShare = new KeyShare(1L, nodeId, shareBase64); // 使用固定的walletId=1
                saveKeyShareToDatabase(keyShare);
                
                logger.info("DKG process completed successfully for task: {}", taskId);
                logger.info("Group public key: {}", task.groupPublicKey);
                task.complete();
                return keyShare;
            } catch (Exception e) {
                e.printStackTrace();
                if (task != null) {
                    task.fail();
                }
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getComputationThreadPool());
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
            // 步骤1: 获取本节点的公钥贡献（实际多项式的常数项验证点）
            ECPoint myContribution = task.verificationPoints.get(0);
            
            // 步骤2: 将公钥贡献编码为可传输的格式
            byte[] contributionBytes = myContribution.getEncoded(false);
            String publicKeyPart = Base64.getEncoder().encodeToString(contributionBytes);
            
            // 步骤3: 广播公钥贡献给其他节点
            Map<String, Object> publicKeyData = new HashMap<>();
            publicKeyData.put("taskId", taskId);
            publicKeyData.put("publicKeyPart", publicKeyPart);
            
            return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.PUBLIC_KEY_PART, publicKeyData))
                .thenRun(() -> {
                    logger.info("Broadcasted public key contribution for task: {}", taskId);
                    
                    // 步骤4: 等待所有节点的公钥贡献
                    try {
                        if (!task.publicKeyContributionsReceivedLatch.await(60, TimeUnit.SECONDS)) {
                            throw new Exception("Timeout waiting for public key contributions");
                        }
                        
                        // 步骤5: 生成群公钥
                        generateGroupPublicKey(task);
                    } catch (Exception e) {
                        logger.error("Error in public key generation process: {}", e.getMessage());
                        throw new RuntimeException(e);
                    }
                })
                .exceptionally(ex -> {
                    logger.error("Failed to broadcast public key contribution: {}", ex.getMessage());
                    throw new RuntimeException(ex);
                });
        } catch (Exception e) {
            logger.error("Error generating public key part: {}", e.getMessage());
            return CompletableFuture.failedFuture(new RuntimeException(e));
        }
    }
    
    /**
     * 验证验证点是否有效
     * @param commitments 验证点列表
     * @return 是否有效
     */
    private boolean verifyCommitments(List<ECPoint> commitments, boolean allowZeroInfinity) throws Exception {
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
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        
        // 检查每个验证点是否在椭圆曲线上
        for (int i = 0; i < commitments.size(); i++) {
            ECPoint point = commitments.get(i);
            
            // 检查点是否为无穷远点
            if (point.isInfinity()) {
                if (allowZeroInfinity && i == 0) {
                    continue;
                }
                logger.warn("Invalid commitment at index {}: infinity point", i);
                return false;
            }
            
            // 检查点是否在椭圆曲线上
            if (!point.isValid()) {
                logger.warn("Invalid commitment at index {}: point not on curve", i);
                return false;
            }
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
     * 获取椭圆曲线基点G
     */
    private ECPoint getCurveGenerator() throws Exception {
        String cacheKey = "curveGenerator_" + Constants.CURVE_NAME;
        return (ECPoint) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
                return publicKey.getParameters().getG();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 获取椭圆曲线
     */
    private ECCurve getCurve() throws Exception {
        String cacheKey = "curve_" + Constants.CURVE_NAME;
        return (ECCurve) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
                return publicKey.getParameters().getCurve();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 生成验证点（Feldman DKG）
     * @param coefficients 多项式系数
     * @return 验证点列表
     */
    private List<ECPoint> generateVerificationPoints(List<BigInteger> coefficients) throws Exception {
        // 获取椭圆曲线基点G
        ECPoint G = getCurveGenerator();
        
        // 计算验证点：Vi = G * 系数i
        List<ECPoint> verificationPoints = new ArrayList<>();
        for (BigInteger coefficient : coefficients) {
            ECPoint point = G.multiply(coefficient);
            verificationPoints.add(point);
        }
        
        return verificationPoints;
    }
    
    /**
     * 验证Gennaro DKG中的组合份额
     * @param share 要验证的组合份额
     * @param x 份额的索引
     * @param verificationPoints 实际多项式的验证点列表
     * @param maskingVerificationPoints 遮蔽多项式的验证点列表
     * @return 是否有效
     */
    private boolean verifyGennaroShare(BigInteger share, int x, List<ECPoint> verificationPoints, List<ECPoint> maskingVerificationPoints) throws Exception {
        // 获取椭圆曲线基点G
        ECPoint G = getCurveGenerator();
        
        // 计算 g^share
        ECPoint gShare = G.multiply(share);
        
        // 计算实际多项式的贡献：v0 * v1^x * v2^x^2 * ... * v(t-1)^x^(t-1)
        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger xPower = BigInteger.ONE;
        ECPoint computedActualPoint = verificationPoints.get(0);
        
        for (int i = 1; i < verificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            ECPoint viPower = verificationPoints.get(i).multiply(xPower);
            computedActualPoint = computedActualPoint.add(viPower);
        }
        
        // 计算遮蔽多项式的贡献：w0 * w1^x * w2^x^2 * ... * w(t-1)^x^(t-1)
        xPower = BigInteger.ONE;
        ECPoint computedMaskingPoint = maskingVerificationPoints.get(0);
        
        for (int i = 1; i < maskingVerificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            ECPoint wiPower = maskingVerificationPoints.get(i).multiply(xPower);
            computedMaskingPoint = computedMaskingPoint.add(wiPower);
        }
        
        // 计算总贡献：实际贡献 + 遮蔽贡献
        ECPoint computedTotalPoint = computedActualPoint.add(computedMaskingPoint);
        
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
        
        Connection conn = null;
        PreparedStatement insertStmt = null;
        PreparedStatement selectStmt = null;
        try {
            conn = databaseService.getShareConnection(keyShare.getShareIndex());
            insertStmt = conn.prepareStatement(insertSql);
            selectStmt = conn.prepareStatement(selectSql);
            
            insertStmt.setLong(1, keyShare.getWalletId());
            insertStmt.setInt(2, keyShare.getShareIndex());
            insertStmt.setString(3, keyShare.getKeyShare());
            insertStmt.executeUpdate();
            
            // 获取生成的ID
            var rs = selectStmt.executeQuery();
            if (rs.next()) {
                keyShare.setId(rs.getLong(1));
            }
        } finally {
            // 关闭语句
            if (selectStmt != null) {
                try {
                    selectStmt.close();
                } catch (SQLException e) {
                    logger.error("Error closing statement: {}", e.getMessage());
                }
            }
            if (insertStmt != null) {
                try {
                    insertStmt.close();
                } catch (SQLException e) {
                    logger.error("Error closing statement: {}", e.getMessage());
                }
            }
            // 回收连接
            if (conn != null) {
                databaseService.releaseShareConnection(conn, keyShare.getShareIndex());
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
            Connection conn = null;
            PreparedStatement pstmt = null;
            try {
                String sql = "SELECT id, wallet_id, share_index, key_share FROM key_shares WHERE wallet_id = ?";
                conn = databaseService.getShareConnection(nodeId);
                pstmt = conn.prepareStatement(sql);
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
                return null;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } finally {
                // 关闭语句
                if (pstmt != null) {
                    try {
                        pstmt.close();
                    } catch (SQLException e) {
                        logger.error("Error closing statement: {}", e.getMessage());
                    }
                }
                // 回收连接
                if (conn != null) {
                    databaseService.releaseShareConnection(conn, nodeId);
                }
            }
        }, ThreadPoolUtil.getComputationThreadPool());
    }
    
    /**
     * 处理接收到的消息
     */
    @Override
    @SuppressWarnings("unchecked")
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            try {
                switch (message.type) {
                    case COMMITMENT:
                        // 接收其他节点的验证点
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            List<String> encodedVerificationPoints = (List<String>) dataMap.get("verificationPoints");
                            List<String> encodedMaskingVerificationPoints = (List<String>) dataMap.get("maskingVerificationPoints");
                            
                            DkgTask task = dkgTasks.get(taskId);
                            if (task == null && taskId != null) {
                                // 如果未收到DKG_INIT，收到承诺后补建任务并启动流程
                                DkgTask newTask = new DkgTask(taskId, nodesCount);
                                dkgTasks.put(taskId, newTask);
                                dkgInProgress.set(true);
                                newTask.start();
                                logger.info("Created DKG task from COMMITMENT with id: {}", taskId);
                                CompletableFuture.runAsync(() -> {
                                    try {
                                        generateDistributedKey(taskId).join();
                                        newTask.completed = true;
                                    } catch (Exception e) {
                                        newTask.errorMessage = e.getMessage();
                                        newTask.fail();
                                        logger.error("Error in DKG process (COMMITMENT) for task {}: {}", taskId, e.getMessage(), e);
                                    } finally {
                                        dkgInProgress.set(false);
                                        newTask.inProgress = false;
                                    }
                                }, ThreadPoolUtil.getIoThreadPool());
                                task = newTask;
                            }
                            if (task != null) {
                                try {
                                    // 将Base64编码的字符串转换回ECPoint
                                    List<ECPoint> verificationPoints = encodedVerificationPoints.stream()
                                        .map(encoded -> {
                                            try {
                                                byte[] bytes = Base64.getDecoder().decode(encoded);
                                                return decodeECPoint(bytes);
                                            } catch (Exception e) {
                                                logger.error("Failed to decode verification point: {}", e.getMessage());
                                                return null;
                                            }
                                        })
                                        .filter(point -> point != null)
                                        .toList();
                                    
                                    List<ECPoint> maskingVerificationPoints = null;
                                    if (encodedMaskingVerificationPoints != null) {
                                        maskingVerificationPoints = encodedMaskingVerificationPoints.stream()
                                            .map(encoded -> {
                                                try {
                                                    byte[] bytes = Base64.getDecoder().decode(encoded);
                                                    return decodeECPoint(bytes);
                                                } catch (Exception e) {
                                                    logger.error("Failed to decode masking verification point: {}", e.getMessage());
                                                    return null;
                                                }
                                            })
                                            .filter(point -> point != null)
                                            .toList();
                                    }
                                    
                                    task.receivedCommitments.put(senderId, verificationPoints);
                                    if (maskingVerificationPoints != null) {
                                        task.receivedMaskingCommitments.put(senderId, maskingVerificationPoints);
                                    }
                                    task.commitmentsReceivedLatch.countDown();
                                    logger.info("Received commitment from node {} for task: {}", senderId, taskId);
                                } catch (Exception e) {
                                    logger.error("Error processing commitment: {}", e.getMessage());
                                }
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
                        if (message.data instanceof Map) {
                            Map<?, ?> dataMap = (Map<?, ?>) message.data;
                            String taskId = (String) dataMap.get("taskId");
                            logger.info("Received DKG_INIT from node {} for task {}", senderId, taskId);
                        }
                        if (!dkgInProgress.get()) {
                            if (message.data instanceof Map) {
                                Map<?, ?> dataMap = (Map<?, ?>) message.data;
                                String taskId = (String) dataMap.get("taskId");
                                if (taskId != null) {
                                    // 检查是否已经存在该任务
                                    if (!dkgTasks.containsKey(taskId)) {
                                        // 使用接收到的taskId创建DKG任务
                                        DkgTask task = new DkgTask(taskId, nodesCount);
                                        dkgTasks.put(taskId, task);
                                        logger.info("Created DKG task with id: {}", taskId);
                                        dkgInProgress.set(true);
                                        task.start();
                                        // 等待本地网络就绪，避免节点列表尚未填充导致失败
                                        try {
                                            nodeService.waitForNetworkReady().join();
                                        } catch (Exception e) {
                                            logger.warn("Network not ready before DKG_INIT, proceeding anyway: {}", e.getMessage());
                                        }
                                        CompletableFuture.runAsync(() -> {
                                            try {
                                                // 直接启动DKG流程，不广播DKG_INIT消息，避免循环调用
                                                generateDistributedKey(taskId).join();
                                                task.completed = true;
                                                logger.info("DKG process completed for task: {}", taskId);
                                            } catch (Exception e) {
                                                task.errorMessage = e.getMessage();
                                                task.fail();
                                                logger.error("Error in DKG process (DKG_INIT) for task {}: {}", taskId, e.getMessage(), e);
                                            } finally {
                                                dkgInProgress.set(false);
                                                task.inProgress = false;
                                            }
                                        }, ThreadPoolUtil.getIoThreadPool());
                                    } else {
                                        logger.info("DKG task with id: {} already exists, skipping initialization", taskId);
                                    }
                                }
                            }
                        } else {
                            logger.warn("Ignoring DKG_INIT from node {} because dkgInProgress is true", senderId);
                        }
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }
    
    /**
     * 处理公钥部分（实现完整的去中心化群公钥生成）
     */
    private void handlePublicKeyPart(int senderId, String taskId, String publicKeyPart) throws Exception {
        DkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            logger.warn("Received public key part for non-existent task: {}", taskId);
            return;
        }
        
        // 步骤1: 解析公钥部分（这里假设 publicKeyPart 是验证点的编码）
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPart);
        
        // 步骤2: 将编码转换为 ECPoint
        ECPoint publicKeyContribution = decodeECPoint(publicKeyBytes);
        
        // 步骤3: 存储其他节点的公钥贡献
        task.receivedPublicKeyContributions.put(senderId, publicKeyContribution);
        task.publicKeyContributionsReceivedLatch.countDown();
        logger.info("Received public key contribution from node {} for task: {}", senderId, taskId);
        
        // 步骤4: 当收集到所有公钥贡献后，生成群公钥
        if (task.publicKeyContributionsReceivedLatch.getCount() == 0) {
            generateGroupPublicKey(task);
        }
    }
    
    /**
     * 将编码的字节数组解码为 ECPoint
     */
    private ECPoint decodeECPoint(byte[] encoded) throws Exception {
        // 获取缓存的椭圆曲线
        ECCurve curve = getCurve();
        
        // 解码点（假设使用压缩格式）
        return curve.decodePoint(encoded);
    }
    
    /**
     * 生成群公钥
     */
    private void generateGroupPublicKey(DkgTask task) throws Exception {
        // 检查群公钥是否已经生成，避免重复生成
        if (task.groupPublicKeyGenerated) {
            logger.info("Group public key already generated for task: {}", task.taskId);
            return;
        }
        
        // 步骤1: 收集所有节点的公钥贡献
        List<ECPoint> allContributions = new ArrayList<>();
        
        // 添加本节点的公钥贡献（实际多项式的常数项验证点）
        if (!task.verificationPoints.isEmpty()) {
            allContributions.add(task.verificationPoints.get(0));
        }
        
        // 添加其他节点的公钥贡献
        for (ECPoint contribution : task.receivedPublicKeyContributions.values()) {
            allContributions.add(contribution);
        }
        
        // 步骤2: 聚合所有公钥贡献生成群公钥
        if (!allContributions.isEmpty()) {
            // 初始化群公钥为第一个贡献
            ECPoint groupPublicKeyPoint = allContributions.get(0);
            
            // 累加其他贡献
            for (int i = 1; i < allContributions.size(); i++) {
                groupPublicKeyPoint = groupPublicKeyPoint.add(allContributions.get(i));
            }
            
            // 步骤3: 将群公钥转换为可存储的X509格式
            String groupPublicKey = encodeGroupPublicKeyX509(groupPublicKeyPoint);
            
            // 步骤4: 存储群公钥
            task.groupPublicKey = groupPublicKey;
            task.groupPublicKeyGenerated = true; // 标记为已生成
            logger.info("Generated group public key");
            
            // 步骤5: 广播群公钥给其他节点（可选，确保所有节点都获得相同的群公钥）
            broadcastGroupPublicKey(task.taskId, groupPublicKey);
        } else {
            throw new Exception("No public key contributions found to generate group public key");
        }
    }
    
    /**
     * 广播群公钥给其他节点
     */
    private CompletableFuture<Void> broadcastGroupPublicKey(String taskId, String groupPublicKey) {
        Map<String, Object> publicKeyData = new HashMap<>();
        publicKeyData.put("taskId", taskId);
        publicKeyData.put("groupPublicKey", groupPublicKey);
        
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, NodeService.Message.Type.PUBLIC_KEY_PART, publicKeyData))
            .exceptionally(ex -> {
                logger.error("Failed to broadcast group public key: {}", ex.getMessage());
                return null;
            });
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

    private String encodeGroupPublicKeyX509(ECPoint groupPublicKeyPoint) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey paramsPub = (ECPublicKey) keyPair.getPublic();
        org.bouncycastle.jce.spec.ECPublicKeySpec spec =
            new org.bouncycastle.jce.spec.ECPublicKeySpec(groupPublicKeyPoint, paramsPub.getParameters());
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
