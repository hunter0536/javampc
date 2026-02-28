package com.example.mpc.service;

import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.GennaroDkgTask;
import com.example.mpc.model.KeyShare;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

@Service
public class GennaroDkgService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(GennaroDkgService.class);

    @Autowired
    private DatabaseService databaseService;

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Value("${node.id}")
    private int nodeId;

    private final int nodesCount = Constants.NODES_COUNT;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final ConcurrentHashMap<String, GennaroDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private static final ExecutorService dkgExecutorService = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "Gennaro-DKG-Thread");
        t.setDaemon(true);
        return t;
    });
    private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "Gennaro-DKG-Scheduler");
        t.setDaemon(true);
        return t;
    });
    private final ConcurrentHashMap<String, Object> cryptoCache = new ConcurrentHashMap<>();

    public GennaroDkgService() {
    }

    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        GennaroDkgTask task = new GennaroDkgTask(taskId, nodesCount);
        dkgTasks.put(taskId, task);
        return taskId;
    }

    public DkgTaskStatusResponse getTaskStatus(String taskId) {
        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("DKG task not found: " + taskId);
        }

        DkgTaskStatusResponse response = new DkgTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setGroupPublicKey(task.groupPublicKey);
        response.setErrorMessage(task.errorMessage);
        response.setReceivedCommitments(task.receivedCommitments.size());
        response.setReceivedShares(task.receivedShares.size());
        return response;
    }

    public String getGroupPublicKey(String taskId) {
        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("DKG task not found: " + taskId);
        }

        if (!task.isCompleted()) {
            return null;
        }

        return task.groupPublicKey;
    }

    public CompletableFuture<Void> init() {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.GENNARO_COMMITMENT,
                            MessageType.GENNARO_SHARE,
                            MessageType.GENNARO_PUBLIC_KEY_PART,
                            MessageType.GENNARO_DKG_INIT
                    ), this);
                    logger.info("Gennaro DKG service initialized successfully for node {}", nodeId);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init Gennaro DKG service", ex);
                    throw new CompletionException(ex);
                });
    }

    public CompletableFuture<Void> startDkgProcess(String taskId) {
        logger.info("startDkgProcess invoked for task {}", taskId);
        return waitForTask(taskId, 20, 200)
                .thenCompose(task -> {
                    if (!task.start()) {
                        logger.warn("DKG task {} failed to start (may already be in progress), skipping", taskId);
                        return CompletableFuture.completedFuture(null);
                    }
                    logger.info("Starting Gennaro DKG process for task: {}", taskId);
                    logger.info("Waiting for network ready...");
                    return waitForNetworkReadyWithRetry(60, 5)
                            .exceptionally(ex -> {
                                logger.warn("Network not fully ready, but proceeding with DKG process");
                                return null;
                            })
                            .thenCompose(v -> {
                                logger.info("Network ready, broadcasting DKG_INIT message");
                                Map<String, Object> initData = new HashMap<>();
                                initData.put("taskId", taskId);
                                return RetryUtils.retryAsync(scheduler, logger, () -> nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.GENNARO_DKG_INIT, initData)),
                                        Constants.DKG_BROADCAST_RETRY_COUNT,
                                        Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                                        "Broadcast GENNARO_DKG_INIT");
                            })
                            .exceptionally(ex -> {
                                logger.warn("Failed to broadcast DKG_INIT after {} attempts, proceeding with DKG process anyway",
                                        Constants.DKG_BROADCAST_RETRY_COUNT);
                                return null;
                            })
                            .thenCompose(v -> generateDistributedKey(taskId))
                            .thenRun(() -> {
                                task.complete();
                                logger.info("Gennaro DKG process completed for task: {}", taskId);
                            });
                })
                .exceptionally(ex -> {
                    GennaroDkgTask task = dkgTasks.get(taskId);
                    if (task != null) {
                        task.fail();
                        task.errorMessage = ex.getMessage();
                    }
                    logger.error("Error in DKG process: {}", ex.getMessage(), ex);
                    return null;
                });
    }

    public CompletableFuture<KeyShare> generateDistributedKey(String taskId) {
        return generateDistributedKey(taskId, false);
    }

    public CompletableFuture<KeyShare> generateDistributedKey(String taskId, boolean forceSingleNodeMode) {
        return CompletableFuture.supplyAsync(() -> {
                    GennaroDkgTask task = dkgTasks.get(taskId);
                    if (task == null) {
                        throw new RuntimeException("DKG task not found: " + taskId);
                    }
                    if (forceSingleNodeMode) {
                        throw new RuntimeException("Single node mode is not allowed");
                    }
                    return task;
                }, ThreadPoolUtil.getComputationThreadPool())
                .thenCompose(task -> waitForNetworkReadyWithRetry(60, 5).thenApply(v -> task))
                .thenCompose(task -> {
                    int networkSize = nodeService.getNodes().size() + 1;
                    if (networkSize < nodesCount) {
                        throw new RuntimeException("Not enough nodes in network. Expected: " + nodesCount + ", found: " + networkSize);
                    }
                    logger.info("Network ready with {} nodes", networkSize);
                    return delayMs(Constants.DKG_INIT_WAIT_MS).thenApply(v -> task);
                })
                .thenCompose(task -> CompletableFuture.supplyAsync(() -> {
                    try {
                        task.coefficients = generateRandomPolynomial(Constants.THRESHOLD - 1);
                        task.maskingCoefficients = generateMaskingPolynomial(Constants.THRESHOLD - 1);
                        task.verificationPoints = generateVerificationPoints(task.coefficients);
                        task.maskingVerificationPoints = generateVerificationPoints(task.maskingCoefficients);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    Map<String, Object> commitmentData = new HashMap<>();
                    commitmentData.put("taskId", taskId);
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
                    return new CommitmentContext(task, commitmentData);
                }, ThreadPoolUtil.getComputationThreadPool()))
                .thenCompose(ctx -> RetryUtils.retryAsync(scheduler, logger, () -> nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.GENNARO_COMMITMENT, ctx.commitmentData)),
                                Constants.DKG_BROADCAST_RETRY_COUNT,
                                Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                                "Broadcast GENNARO_COMMITMENT")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> waitForLatchAsync(ctx.task.commitmentsReceivedLatch, Constants.DKG_COMMITMENT_TIMEOUT_SECONDS, "commitments", ctx.task)
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    try {
                        for (Integer senderId : ctx.task.receivedCommitments.keySet()) {
                            List<ECPoint> commitments = ctx.task.receivedCommitments.get(senderId);
                            List<ECPoint> maskingCommitments = ctx.task.receivedMaskingCommitments.get(senderId);
                            if (!verifyCommitments(commitments, false) || !verifyCommitments(maskingCommitments, true)) {
                                throw new RuntimeException("Invalid commitments received from node " + senderId);
                            }
                            logger.info("Successfully verified commitments from node {} for task: {}", senderId, taskId);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getComputationThreadPool()).thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    List<CompletableFuture<Void>> sendFutures = new ArrayList<>();
                    for (NodeService.NodeInfo nodeInfo : nodeService.getNodes()) {
                        if (nodeInfo.id != nodeId) {
                            BigInteger actualShare;
                            BigInteger maskingShare;
                            BigInteger combinedShare;
                            try {
                                actualShare = evaluatePolynomial(ctx.task.coefficients, BigInteger.valueOf(nodeInfo.id));
                                maskingShare = evaluatePolynomial(ctx.task.maskingCoefficients, BigInteger.valueOf(nodeInfo.id));
                                combinedShare = actualShare.add(maskingShare).mod(getCurveOrder());
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }

                            Map<String, Object> shareData = new HashMap<>();
                            shareData.put("taskId", taskId);
                            shareData.put("share", combinedShare);
                            CompletableFuture<Void> future = nodeService.sendMessage(nodeInfo.id, new NodeService.Message(nodeId, MessageType.GENNARO_SHARE, shareData))
                                    .exceptionally(ex -> {
                                        logger.error("Failed to send share to node {}: {}", nodeInfo.id, ex.getMessage());
                                        throw new RuntimeException(ex);
                                    });
                            sendFutures.add(future);
                        }
                    }
                    return CompletableFuture.allOf(sendFutures.toArray(new CompletableFuture[0]))
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> waitForLatchAsync(ctx.task.sharesReceivedLatch, Constants.DKG_SHARE_TIMEOUT_SECONDS, "shares", ctx.task)
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    try {
                        for (Integer senderId : ctx.task.receivedShares.keySet()) {
                            BigInteger share = ctx.task.receivedShares.get(senderId);
                            List<ECPoint> commitments = ctx.task.receivedCommitments.get(senderId);
                            List<ECPoint> maskingCommitments = ctx.task.receivedMaskingCommitments.get(senderId);
                            if (commitments == null || maskingCommitments == null || !verifyGennaroShare(share, nodeId, commitments, maskingCommitments)) {
                                throw new RuntimeException("Invalid share received from node " + senderId);
                            }
                        }
                        logger.info("Verified all received shares for task: {}", taskId);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getComputationThreadPool()).thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    try {
                        BigInteger curveOrder = getCurveOrder();
                        ctx.task.finalKeyShare = BigInteger.ZERO;
                        for (BigInteger share : ctx.task.receivedShares.values()) {
                            ctx.task.finalKeyShare = ctx.task.finalKeyShare.add(share).mod(curveOrder);
                        }
                        BigInteger selfActualShare = evaluatePolynomial(ctx.task.coefficients, BigInteger.valueOf(nodeId));
                        BigInteger selfMaskingShare = evaluatePolynomial(ctx.task.maskingCoefficients, BigInteger.valueOf(nodeId));
                        ctx.task.finalKeyShare = ctx.task.finalKeyShare.add(selfActualShare.add(selfMaskingShare)).mod(curveOrder);
                        logger.info("Calculated final key share for task: {}", taskId);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getComputationThreadPool()).thenApply(v -> ctx))
                .thenCompose(ctx -> generateAndBroadcastPublicKeyPart(taskId).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForConditionAsync(() -> ctx.task.groupPublicKey != null,
                        TimeUnit.SECONDS.toMillis(60), "group public key", 200)
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        String shareHex = HexUtils.toHex(ctx.task.finalKeyShare);
                        KeyShare keyShare = new KeyShare(nodeId, shareHex, ctx.task.groupPublicKey, ctx.task.taskId);
                        saveKeyShareToDatabase(keyShare);
                        logger.info("Gennaro DKG process completed successfully for task: {}", taskId);
                        logger.info("Group public key: {}", ctx.task.groupPublicKey);
                        ctx.task.complete();
                        return keyShare;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getComputationThreadPool()))
                .exceptionally(ex -> {
                    GennaroDkgTask task = dkgTasks.get(taskId);
                    if (task != null) {
                        task.fail();
                    }
                    throw new CompletionException(ex);
                });
    }

    private CompletableFuture<Void> generateAndBroadcastPublicKeyPart(String taskId) {
        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("DKG task not found: " + taskId));
        }

        try {
            ECPoint myContribution = task.verificationPoints.get(0);

            byte[] contributionBytes = myContribution.getEncoded(false);
            String publicKeyPart = Base64.getEncoder().encodeToString(contributionBytes);

            Map<String, Object> publicKeyData = new HashMap<>();
            publicKeyData.put("taskId", taskId);
            publicKeyData.put("publicKeyPart", publicKeyPart);

            return RetryUtils.retryAsync(scheduler, logger, () -> nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.GENNARO_PUBLIC_KEY_PART, publicKeyData)),
                            Constants.DKG_BROADCAST_RETRY_COUNT,
                            Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                            "Broadcast GENNARO_PUBLIC_KEY_PART")
                    .thenRun(() -> logger.info("Broadcasted public key contribution for task: {}", taskId))
                    .thenCompose(v -> waitForLatchAsync(task.publicKeyContributionsReceivedLatch, 60, "public key contributions", task))
                    .thenRun(() -> {
                        try {
                            generateGroupPublicKey(task);
                        } catch (Exception e) {
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

    private boolean verifyCommitments(List<ECPoint> commitments, boolean allowZeroInfinity) throws Exception {
        if (commitments == null || commitments.isEmpty()) {
            logger.warn("Invalid commitments: empty list");
            return false;
        }

        if (commitments.size() != Constants.THRESHOLD) {
            logger.warn("Invalid commitments: wrong size. Expected {}, got {}", Constants.THRESHOLD, commitments.size());
            return false;
        }

        for (int i = 0; i < commitments.size(); i++) {
            ECPoint point = commitments.get(i);

            if (point.isInfinity()) {
                if (allowZeroInfinity && i == 0) {
                    continue;
                }
                logger.warn("Invalid commitment at index {}: infinity point", i);
                return false;
            }

            if (!point.isValid()) {
                logger.warn("Invalid commitment at index {}: point not on curve", i);
                return false;
            }
        }

        return true;
    }

    private List<BigInteger> generateRandomPolynomial(int degree) throws Exception {
        List<BigInteger> coefficients = new ArrayList<>();
        BigInteger curveOrder = getCurveOrder();

        BigInteger secret = new BigInteger(curveOrder.bitLength() - 1, new SecureRandom()).mod(curveOrder);
        coefficients.add(secret);

        for (int i = 1; i <= degree; i++) {
            coefficients.add(new BigInteger(curveOrder.bitLength() - 1, new SecureRandom()).mod(curveOrder));
        }

        return coefficients;
    }

    private List<BigInteger> generateMaskingPolynomial(int degree) throws Exception {
        List<BigInteger> coefficients = new ArrayList<>();
        BigInteger curveOrder = getCurveOrder();

        coefficients.add(BigInteger.ZERO);

        for (int i = 1; i <= degree; i++) {
            coefficients.add(new BigInteger(curveOrder.bitLength() - 1, new SecureRandom()).mod(curveOrder));
        }

        return coefficients;
    }

    private BigInteger getCurveOrder() throws Exception {
        String cacheKey = "curveOrder_" + Constants.CURVE_NAME;
        return (BigInteger) cryptoCache.computeIfAbsent(cacheKey, k -> {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecSpec = new ECGenParameterSpec(Constants.CURVE_NAME);
                keyPairGenerator.initialize(ecSpec);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
                return publicKey.getParameters().getN();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

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

    private List<ECPoint> generateVerificationPoints(List<BigInteger> coefficients) throws Exception {
        ECPoint G = getCurveGenerator();

        List<ECPoint> verificationPoints = new ArrayList<>();
        for (BigInteger coefficient : coefficients) {
            ECPoint point = G.multiply(coefficient);
            verificationPoints.add(point);
        }

        return verificationPoints;
    }

    private CompletableFuture<GennaroDkgTask> waitForTask(String taskId, int attempts, long intervalMs) {
        CompletableFuture<GennaroDkgTask> future = new CompletableFuture<>();
        AtomicInteger remaining = new AtomicInteger(attempts);
        ScheduledFuture<?> tick = scheduler.scheduleAtFixedRate(() -> {
            GennaroDkgTask task = dkgTasks.get(taskId);
            if (task != null) {
                future.complete(task);
                return;
            }
            if (remaining.decrementAndGet() <= 0) {
                future.completeExceptionally(new RuntimeException("DKG task not found: " + taskId));
            }
        }, 0, intervalMs, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> delayMs(long ms) {
        CompletableFuture<Void> future = new CompletableFuture<>();
        scheduler.schedule(() -> future.complete(null), ms, TimeUnit.MILLISECONDS);
        return future;
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label, GennaroDkgTask task) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();

        if (task != null) {
            if ("commitments".equals(label)) {
                task.commitmentsFuture = future;
            } else if ("shares".equals(label)) {
                task.sharesFuture = future;
            } else if ("public key contributions".equals(label)) {
                task.publicKeyFuture = future;
            }
        }

        ScheduledFuture<?> tick = scheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                if (task != null) {
                    if ("commitments".equals(label)) {
                        task.commitmentsFuture = null;
                    } else if ("shares".equals(label)) {
                        task.sharesFuture = null;
                    } else if ("public key contributions".equals(label)) {
                        task.publicKeyFuture = null;
                    }
                }
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                if (task != null) {
                    if ("commitments".equals(label)) {
                        task.commitmentsFuture = null;
                    } else if ("shares".equals(label)) {
                        task.sharesFuture = null;
                    } else if ("public key contributions".equals(label)) {
                        task.publicKeyFuture = null;
                    }
                }
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> waitForConditionAsync(BooleanSupplier condition, long timeoutMs, String label, long pollMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = scheduler.scheduleAtFixedRate(() -> {
            if (condition.getAsBoolean()) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, pollMs, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> waitForNetworkReadyWithRetry(int maxWaitSeconds, int stepSeconds) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(maxWaitSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        Runnable attempt = new Runnable() {
            @Override
            public void run() {
                nodeService.waitForNetworkReady()
                        .orTimeout(stepSeconds, TimeUnit.SECONDS)
                        .thenRun(() -> future.complete(null))
                        .exceptionally(ex -> {
                            if (System.currentTimeMillis() >= deadline) {
                                future.completeExceptionally(ex);
                            } else {
                                delayMs(TimeUnit.SECONDS.toMillis(stepSeconds)).thenRun(this);
                            }
                            return null;
                        });
            }
        };
        attempt.run();
        return future;
    }


    private static final class CommitmentContext {
        final GennaroDkgTask task;
        final Map<String, Object> commitmentData;
        CompletableFuture<Void> future;

        private CommitmentContext(GennaroDkgTask task, Map<String, Object> commitmentData) {
            this.task = task;
            this.commitmentData = commitmentData;
        }
    }

    private boolean verifyGennaroShare(BigInteger share, int x, List<ECPoint> verificationPoints, List<ECPoint> maskingVerificationPoints) throws Exception {
        ECPoint G = getCurveGenerator();

        ECPoint gShare = G.multiply(share);

        BigInteger xBigInt = BigInteger.valueOf(x);
        BigInteger xPower = BigInteger.ONE;
        ECPoint computedActualPoint = verificationPoints.get(0);

        for (int i = 1; i < verificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            ECPoint viPower = verificationPoints.get(i).multiply(xPower);
            computedActualPoint = computedActualPoint.add(viPower);
        }

        xPower = BigInteger.ONE;
        ECPoint computedMaskingPoint = maskingVerificationPoints.get(0);

        for (int i = 1; i < maskingVerificationPoints.size(); i++) {
            xPower = xPower.multiply(xBigInt);
            ECPoint wiPower = maskingVerificationPoints.get(i).multiply(xPower);
            computedMaskingPoint = computedMaskingPoint.add(wiPower);
        }

        ECPoint computedTotalPoint = computedActualPoint.add(computedMaskingPoint);

        return gShare.equals(computedTotalPoint);
    }

    private BigInteger evaluatePolynomial(List<BigInteger> coefficients, BigInteger x) throws Exception {
        BigInteger curveOrder = getCurveOrder();
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;

        for (BigInteger coefficient : coefficients) {
            result = result.add(coefficient.multiply(xPower)).mod(curveOrder);
            xPower = xPower.multiply(x).mod(curveOrder);
        }

        return result;
    }

    private void saveKeyShareToDatabase(KeyShare keyShare) throws Exception {
        keyShareDao.save(keyShare);
    }

    public CompletableFuture<KeyShare> loadKeyShareByGroupPublicKey(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKey(nodeId, groupPublicKey);
    }

    public CompletableFuture<KeyShare> loadKeyShareByIndexAndGroupPublicKey(int shareIndex, String groupPublicKey) {
        return keyShareDao.findByGroupPublicKey(shareIndex, groupPublicKey);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            try {
                switch (message.type) {
                    case GENNARO_COMMITMENT:
                        handleCommitmentMessage(senderId, message);
                        break;
                    case GENNARO_SHARE:
                        handleShareMessage(senderId, message);
                        break;
                    case GENNARO_PUBLIC_KEY_PART:
                        handlePublicKeyPartMessage(senderId, message);
                        break;
                    case GENNARO_DKG_INIT:
                        handleDkgInitMessage(senderId, message);
                        break;
                    default:
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getSingleThreadPool());
    }

    private void handleCommitmentMessage(int senderId, NodeService.Message message) throws Exception {
        if (!(message.data instanceof Map)) {
            return;
        }
        Map<?, ?> dataMap = (Map<?, ?>) message.data;
        String taskId = (String) dataMap.get("taskId");
        List<String> encodedVerificationPoints = (List<String>) dataMap.get("verificationPoints");
        List<String> encodedMaskingVerificationPoints = (List<String>) dataMap.get("maskingVerificationPoints");

        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task == null && taskId != null) {
            GennaroDkgTask newTask = new GennaroDkgTask(taskId, nodesCount);
            GennaroDkgTask existingTask = dkgTasks.putIfAbsent(taskId, newTask);
            if (existingTask != null) {
                task = existingTask;
            } else {
                task = newTask;
                if (task.start()) {
                    logger.info("Created DKG task from COMMITMENT with id: {}", taskId);
                    startDkgProcessInternal(taskId);
                }
            }
        }

        if (task != null) {
            List<ECPoint> verificationPoints = decodeVerificationPoints(encodedVerificationPoints);
            List<ECPoint> maskingVerificationPoints = decodeVerificationPoints(encodedMaskingVerificationPoints);

            boolean firstCommitment = task.receivedCommitments.putIfAbsent(senderId, verificationPoints) == null;
            if (maskingVerificationPoints != null) {
                task.receivedMaskingCommitments.putIfAbsent(senderId, maskingVerificationPoints);
            }
            if (firstCommitment) {
                task.commitmentsReceivedLatch.countDown();
                checkCommitmentCondition(task);
            }
            logger.info("Received commitment from node {} for task: {}", senderId, taskId);
        }
    }

    private void handleShareMessage(int senderId, NodeService.Message message) {
        if (!(message.data instanceof Map)) {
            return;
        }
        Map<?, ?> dataMap = (Map<?, ?>) message.data;
        String taskId = (String) dataMap.get("taskId");
        BigInteger share = (BigInteger) dataMap.get("share");

        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task != null) {
            boolean firstShare = task.receivedShares.putIfAbsent(senderId, share) == null;
            if (firstShare) {
                task.sharesReceivedLatch.countDown();
                checkShareCondition(task);
            }
            logger.info("Received share from node {} for task: {}", senderId, taskId);
        }
    }

    private void handlePublicKeyPartMessage(int senderId, NodeService.Message message) throws Exception {
        if (!(message.data instanceof Map)) {
            return;
        }
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

    private void handleDkgInitMessage(int senderId, NodeService.Message message) {
        if (!(message.data instanceof Map)) {
            return;
        }
        Map<?, ?> dataMap = (Map<?, ?>) message.data;
        String taskId = (String) dataMap.get("taskId");
        logger.info("Received DKG_INIT from node {} for task {}", senderId, taskId);

        if (taskId != null) {
            GennaroDkgTask newTask = new GennaroDkgTask(taskId, nodesCount);
            GennaroDkgTask existingTask = dkgTasks.putIfAbsent(taskId, newTask);
            if (existingTask == null) {
                logger.info("Created DKG task with id: {} from DKG_INIT", taskId);
                if (newTask.start()) {
                    waitForNetworkReadyWithRetry(60, 5)
                            .exceptionally(ex -> {
                                logger.warn("Network not ready before DKG_INIT, proceeding anyway: {}", ex.getMessage());
                                return null;
                            })
                            .thenRun(() -> startDkgProcessInternal(taskId));
                }
            } else {
                logger.info("DKG task with id: {} already exists, skipping initialization", taskId);
            }
        }
    }

    private void startDkgProcessInternal(String taskId) {
        generateDistributedKey(taskId)
                .thenRun(() -> {
                    GennaroDkgTask task = dkgTasks.get(taskId);
                    if (task != null) {
                        task.complete();
                        logger.info("DKG process completed for task: {}", taskId);
                    }
                })
                .exceptionally(ex -> {
                    GennaroDkgTask task = dkgTasks.get(taskId);
                    if (task != null) {
                        task.errorMessage = ex.getMessage();
                        task.fail();
                    }
                    logger.error("Error in DKG process for task {}: {}", taskId, ex.getMessage(), ex);
                    return null;
                });
    }

    private List<ECPoint> decodeVerificationPoints(List<String> encodedPoints) {
        if (encodedPoints == null) {
            return null;
        }
        return encodedPoints.stream()
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
    }

    private void handlePublicKeyPart(int senderId, String taskId, String publicKeyPart) throws Exception {
        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            logger.warn("Received public key part for non-existent task: {}", taskId);
            return;
        }

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPart);

        ECPoint publicKeyContribution = decodeECPoint(publicKeyBytes);

        boolean firstContribution = task.receivedPublicKeyContributions.putIfAbsent(senderId, publicKeyContribution) == null;
        if (firstContribution) {
            task.publicKeyContributionsReceivedLatch.countDown();
            checkPublicKeyCondition(task);
        }
        logger.info("Received public key contribution from node {} for task: {}", senderId, taskId);

        if (task.publicKeyContributionsReceivedLatch.getCount() == 0) {
            generateGroupPublicKey(task);
        }
    }

    private ECPoint decodeECPoint(byte[] encoded) throws Exception {
        ECCurve curve = getCurve();

        return curve.decodePoint(encoded);
    }

    private void generateGroupPublicKey(GennaroDkgTask task) throws Exception {
        if (task.groupPublicKeyGenerated) {
            logger.info("Group public key already generated for task: {}", task.taskId);
            return;
        }

        List<ECPoint> allContributions = new ArrayList<>();

        if (!task.verificationPoints.isEmpty()) {
            allContributions.add(task.verificationPoints.get(0));
        }

        for (ECPoint contribution : task.receivedPublicKeyContributions.values()) {
            allContributions.add(contribution);
        }

        if (!allContributions.isEmpty()) {
            ECPoint groupPublicKeyPoint = allContributions.get(0);

            for (int i = 1; i < allContributions.size(); i++) {
                groupPublicKeyPoint = groupPublicKeyPoint.add(allContributions.get(i));
            }

            byte[] pointBytes = groupPublicKeyPoint.getEncoded(false);
            String groupPublicKey = HexUtils.bytesToHex(pointBytes);

            task.groupPublicKey = groupPublicKey;
            task.groupPublicKeyGenerated = true;
            logger.info("Generated group public key");

            broadcastGroupPublicKey(task.taskId, groupPublicKey);
        } else {
            throw new Exception("No public key contributions found to generate group public key");
        }
    }

    private CompletableFuture<Void> broadcastGroupPublicKey(String taskId, String groupPublicKey) {
        Map<String, Object> publicKeyData = new HashMap<>();
        publicKeyData.put("taskId", taskId);
        publicKeyData.put("groupPublicKey", groupPublicKey);

        return RetryUtils.retryAsync(scheduler, logger, () -> nodeService.broadcastRbc(new NodeService.Message(nodeId, MessageType.GENNARO_PUBLIC_KEY_PART, publicKeyData)),
                        Constants.DKG_BROADCAST_RETRY_COUNT,
                        Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                        "Broadcast GENNARO_GROUP_PUBLIC_KEY")
                .exceptionally(ex -> {
                    logger.error("Failed to broadcast group public key: {}", ex.getMessage());
                    return null;
                });
    }

    private void handleGroupPublicKey(int senderId, String taskId, String groupPublicKey) throws Exception {
        GennaroDkgTask task = dkgTasks.get(taskId);
        if (task != null && task.groupPublicKey == null) {
            task.groupPublicKey = groupPublicKey;
            logger.info("Received group public key from node {} for task: {}", senderId, taskId);
        }
    }

    private void checkCommitmentCondition(GennaroDkgTask task) {
        if (task.commitmentsFuture != null && task.receivedCommitments.size() >= task.nodesCount - 1) {
            logger.debug("Event-driven: commitments condition met for task {}", task.taskId);
            task.commitmentsFuture.complete(null);
            task.commitmentsFuture = null;
        }
    }

    private void checkShareCondition(GennaroDkgTask task) {
        if (task.sharesFuture != null && task.receivedShares.size() >= task.nodesCount - 1) {
            logger.debug("Event-driven: shares condition met for task {}", task.taskId);
            task.sharesFuture.complete(null);
            task.sharesFuture = null;
        }
    }

    private void checkPublicKeyCondition(GennaroDkgTask task) {
        if (task.publicKeyFuture != null && task.receivedPublicKeyContributions.size() >= task.nodesCount - 1) {
            logger.debug("Event-driven: public key condition met for task {}", task.taskId);
            task.publicKeyFuture.complete(null);
            task.publicKeyFuture = null;
        }
    }
}
