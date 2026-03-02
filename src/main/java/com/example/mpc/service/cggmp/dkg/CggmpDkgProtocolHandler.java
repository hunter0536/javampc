package com.example.mpc.service.cggmp.dkg;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.AuxInfo;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.service.CggmpDkgService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public final class CggmpDkgProtocolHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpDkgProtocolHandler.class);
    private static final ExecutorService dkgExecutorService = CggmpDkgService.dkgExecutorService;

    private final CggmpDkgService svc;

    public CggmpDkgProtocolHandler(CggmpDkgService svc) {
        this.svc = svc;
    }

    public CompletableFuture<Void> startDkgProcessInternal(String taskId, boolean broadcastInit) {
        logger.info("=================== startDkgProcess START: taskId={} ===================", taskId);
        final long dkgStartNs = System.nanoTime();
        final CggmpDkgTask task;
        try {
            task = svc.getDkgTask(taskId);
            if (!svc.nodeService.isTlsEnabled()) {
                throw new RuntimeException("DKG requires TLS-enabled private channels (nodes.ssl.enabled=true).");
            }
            if (loadLatestAuxInfo(svc.nodeId) == null) {
                throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before DKG.");
            }
            if (!validateFullParticipation(task)) {
                throw new RuntimeException("DKG requires full participation");
            }
            if (!task.start()) {
                logger.warn("DKG task {} failed to start (may already be in progress), skipping", taskId);
                return CompletableFuture.completedFuture(null);
            }
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }

        logger.info("Starting CGGMP DKG process for task: {}", taskId);
        logger.info("Waiting for network ready...");
        long waitNetStart = System.nanoTime();

        Map<String, Object> initData = new HashMap<>();
        initData.put("taskId", taskId);
        initData.put("executionId", task.executionId);
        initData.put("nodesCount", Constants.NODES_COUNT);
        initData.put("initiatorId", svc.nodeId);
        initData.put("participants", new ArrayList<>(task.participants));

        CompletableFuture<Void> flow = svc.nodeService.waitForNetworkReady()
                .thenRun(() -> logger.debug("DKG waitForNetworkReady took {} ms", (System.nanoTime() - waitNetStart) / 1_000_000))
                .thenRun(() -> {
                    int networkSize = svc.nodeService.getNodes().size() + 1;
                    if (networkSize < svc.nodesCount) {
                        throw new RuntimeException("Not enough nodes in network. Expected: " + svc.nodesCount + ", found: " + networkSize);
                    }
                    logger.info("Network ready with {} nodes", networkSize);
                })
                .thenCompose(v -> ensureLocalAuxReady())
                .thenCompose(v -> {
                    if (!broadcastInit) {
                        return CompletableFuture.completedFuture(null);
                    }
                    final long initBroadcastStartNs = System.nanoTime();
                    return delayMs(Constants.DKG_INIT_WAIT_MS)
                            .thenCompose(x -> RetryUtils.retryAsync(svc.dkgScheduler, logger,
                                    () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_INIT, initData)),
                                    Constants.DKG_BROADCAST_RETRY_COUNT,
                                    Constants.DKG_BROADCAST_RETRY_INTERVAL_MS,
                                    "Broadcast CGGMP_DKG_INIT"))
                            .whenComplete((x, ex) -> {
                                if (ex == null) {
                                    logger.debug("DKG INIT broadcast completed in {} ms (taskId={})",
                                            (System.nanoTime() - initBroadcastStartNs) / 1_000_000, taskId);
                                } else {
                                    logger.warn("DKG INIT broadcast failed after {} ms (taskId={}): {}",
                                            (System.nanoTime() - initBroadcastStartNs) / 1_000_000, taskId, ex.getMessage());
                                }
                            });
                })
                .thenCompose(v -> {
                    long roundsStart = System.nanoTime();
                    return executeDkgRounds(task)
                            .whenComplete((x, ex) -> logger.debug("DKG executeDkgRounds took {} ms",
                                    (System.nanoTime() - roundsStart) / 1_000_000));
                });

        return flow.whenComplete((v, ex) -> {
            if (ex == null) {
                task.complete();
                logger.info("CGGMP DKG process completed for task: {}", taskId);
                logger.debug("=================== startDkgProcess END: taskId={} total {} ms ===================",
                        taskId, (System.nanoTime() - dkgStartNs) / 1_000_000);
            } else {
                task.fail();
                task.errorMessage = ex.getMessage();
                logger.error("Error in CGGMP DKG process", ex);
            }
        });
    }

    private boolean validateFullParticipation(CggmpDkgTask task) {
        if (task == null || task.participants == null) {
            return false;
        }
        if (task.participants.size() != task.nodesCount) {
            return false;
        }
        for (int i = 1; i <= task.nodesCount; i++) {
            if (!task.participants.contains(i)) {
                return false;
            }
        }
        return true;
    }

    private CompletableFuture<Void> executeDkgRounds(CggmpDkgTask task) {
        final long roundsStart = System.nanoTime();
        if (task.nonThreshold) {
            return executeDkgRoundsNonThreshold(task)
                    .whenComplete((v, ex) -> logger.debug("DKG executeDkgRounds total took {} ms",
                            (System.nanoTime() - roundsStart) / 1_000_000));
        }
        logger.info("Node {} executing CGGMP24 DKG Round 1 (t-of-n)", svc.nodeId);

        CompletableFuture<DkgContext> r1Future = CompletableFuture.supplyAsync(() -> {
            BigInteger q = Secp256k1CurveUtils.n();
            ECPoint g = Secp256k1CurveUtils.G();

            BigInteger[] coeffs = new BigInteger[svc.threshold];
            for (int i = 0; i < svc.threshold; i++) {
                coeffs[i] = CggmpProtocolUtils.randomNonZero(q);
            }

            Map<Integer, ECPoint> S_i = new HashMap<>();
            for (int k = 0; k < svc.threshold; k++) {
                S_i.put(k, g.multiply(coeffs[k]).normalize());
            }
            task.Xjks.put(svc.nodeId, new java.util.concurrent.ConcurrentHashMap<>(S_i));

            BigInteger alpha = CggmpProtocolUtils.randomNonZero(q);
            ECPoint A_i = g.multiply(alpha).normalize();
            task.Ajks.put(svc.nodeId, new java.util.concurrent.ConcurrentHashMap<>(Map.of(0, A_i)));
            task.schAlphas.put(0, alpha);

            byte[] ridPart = CggmpProtocolUtils.randomBytes(32);
            task.ridParts.put(svc.nodeId, ridPart);
            byte[] chainCodePart = svc.hdEnabled ? CggmpProtocolUtils.randomBytes(32) : null;
            if (chainCodePart != null) {
                task.chainCodeParts.put(svc.nodeId, chainCodePart);
            }

            Map<String, Object> r1Open = new LinkedHashMap<>();
            r1Open.put("taskId", task.taskId);
            r1Open.put("executionId", task.executionId);
            r1Open.put("senderId", svc.nodeId);
            r1Open.put("ridPart", HexUtils.bytesToHex(ridPart));
            r1Open.put("S", Secp256k1CurveUtils.encodeECPointMapCompressed(S_i));
            r1Open.put("A", HexUtils.bytesToHex(A_i.getEncoded(true)));
            byte[] uCommit = CggmpProtocolUtils.randomBytes(32);
            r1Open.put("u", HexUtils.bytesToHex(uCommit));
            if (chainCodePart != null) {
                r1Open.put("c", HexUtils.bytesToHex(chainCodePart));
            }
            String vCommit = CggmpDkgUtils.computeDkgCommitHash(task.executionId, task.taskId, svc.nodeId, ridPart, S_i, A_i, uCommit, chainCodePart);
            task.round1PayloadHashes.put(svc.nodeId, vCommit);
            Map<String, Object> r1Commit = new HashMap<>();
            r1Commit.put("taskId", task.taskId);
            r1Commit.put("executionId", task.executionId);
            r1Commit.put("senderId", svc.nodeId);
            r1Commit.put("V", vCommit);
            if (svc.dkgUseRbc) {
                CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND1,
                                CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        logger, "CGGMP_DKG_ROUND1_RBC");
            } else {
                CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND1,
                                CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                        logger, "CGGMP_DKG_ROUND1");
            }

            task.startRound1Waiting();
            return new DkgContext(task, q, g, coeffs, r1Open);
        }, dkgExecutorService);

        return r1Future
                .thenCompose(ctx -> {
                    final long waitStartNs = System.nanoTime();
                    logger.debug("DKG Round1 wait start (taskId={}, expectedPeers={})",
                            task.taskId, task.participants.size() - 1);
                    return waitForDkgLatch(task, task.round1ReceivedLatch, "DKG Round 1 messages")
                            .whenComplete((v, ex) -> {
                                long waitMs = (System.nanoTime() - waitStartNs) / 1_000_000;
                                if (ex == null) {
                                    logger.debug("DKG Round1 wait done in {} ms (taskId={}, remaining={})",
                                            waitMs, task.taskId, task.round1ReceivedLatch.getCount());
                                } else {
                                    logger.warn("DKG Round1 wait failed after {} ms (taskId={}, remaining={}): {}",
                                            waitMs, task.taskId, task.round1ReceivedLatch.getCount(), ex.getMessage());
                                }
                            })
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> {
                    if (!svc.dkgEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    CggmpProtocolUtils.fireAndForget(svc.dkgMessageHandler.sendDkgRound1Echo(task), logger, "CGGMP_DKG_ROUND1_ECHO");
                    return waitForDkgLatch(task, task.round1EchoReceivedLatch, "DKG Round 1 echo messages")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (svc.dkgUseRbc) {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                logger, "CGGMP_DKG_ROUND2_BROAD_RBC");
                    } else {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                logger, "CGGMP_DKG_ROUND2_BROAD");
                    }

                    for (int peerId : task.participants) {
                        if (peerId == svc.nodeId) continue;
                        BigInteger sigma = CggmpDkgUtils.evaluatePolynomial(ctx.coeffs, CggmpDkgUtils.getIndexValue(task, peerId), ctx.q);
                        Map<String, Object> share = new HashMap<>();
                        share.put("taskId", task.taskId);
                        share.put("executionId", task.executionId);
                        share.put("senderId", svc.nodeId);
                        share.put("receiverId", peerId);
                        share.put("sigma", sigma.toString(16));
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.sendMessage(peerId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND2, share)),
                                logger, "CGGMP_DKG_ROUND2");
                    }
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2OpenReceivedLatch, "DKG Round 2 open messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (svc.hdEnabled) {
                        task.chainCode = CggmpDkgUtils.xorChainCodeParts(task);
                    }
                    task.rid = CggmpDkgUtils.xorRidParts(task);
                    svc.dkgMessageHandler.drainPendingRound3(task);
                    task.startRound2Waiting();
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2ReceivedLatch, "DKG Round 2 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    task.startValidating();
                    BigInteger xStar = BigInteger.ZERO;
                    for (int peerId : task.participants) {
                        BigInteger share = peerId == svc.nodeId
                                ? CggmpDkgUtils.evaluatePolynomial(ctx.coeffs, CggmpDkgUtils.getIndexValue(task, svc.nodeId), ctx.q)
                                : task.xji.getOrDefault(peerId, new java.util.concurrent.ConcurrentHashMap<>()).get(svc.nodeId);
                        if (share == null) {
                            throw new RuntimeException("Missing share from peer " + peerId);
                        }
                        xStar = xStar.add(share).mod(ctx.q);
                    }
                    task.secretShare = xStar;

                    ECPoint X_i = CggmpDkgUtils.computePublicShare(task, svc.nodeId);
                    PiSchProof psi_i = CggmpDkgUtils.createSchProofWithAlpha(ctx.g, X_i, xStar, task.schAlphas.get(0),
                            CggmpDkgUtils.buildDkgContext(task.taskId, task.executionId, task.rid, svc.nodeId, "SCH"));
                    Map<String, Object> r3 = new HashMap<>();
                    r3.put("taskId", task.taskId);
                    r3.put("executionId", task.executionId);
                    r3.put("senderId", svc.nodeId);
                    r3.put("psi", CggmpCodecUtils.encodePiSchProof(psi_i));
                    CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND3,
                                    CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND3, r3))),
                            logger, "CGGMP_DKG_ROUND3");
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round3ReceivedLatch, "DKG Round 3 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    ECPoint groupPublicKey = ctx.g.getCurve().getInfinity();
                    for (int peerId : task.participants) {
                        Map<Integer, ECPoint> sVec = task.Xjks.get(peerId);
                        if (sVec == null || sVec.get(0) == null) {
                            throw new RuntimeException("Missing S_{j,0} from peer " + peerId);
                        }
                        groupPublicKey = groupPublicKey.add(sVec.get(0)).normalize();
                    }
                    task.groupPublicKey = groupPublicKey;
                    task.groupPublicKeyHex = HexUtils.bytesToHex(groupPublicKey.getEncoded(false));

                    svc.saveKeyShareToDatabase(task);
                    task.complete();
                    logger.info("CGGMP24 DKG completed! Group public key: {}", task.groupPublicKeyHex);
                }, dkgExecutorService))
                .whenComplete((v, ex) -> logger.debug("DKG executeDkgRounds total took {} ms",
                        (System.nanoTime() - roundsStart) / 1_000_000));
    }

    private CompletableFuture<Void> executeDkgRoundsNonThreshold(CggmpDkgTask task) {
        logger.info("Node {} executing CGGMP24 DKG Round 1 (n-of-n)", svc.nodeId);
        return CompletableFuture.supplyAsync(() -> {
                    BigInteger q = Secp256k1CurveUtils.n();
                    ECPoint g = Secp256k1CurveUtils.G();

                    BigInteger x_i = CggmpProtocolUtils.randomNonZero(q);
                    ECPoint X_i = g.multiply(x_i).normalize();
                    Map<Integer, ECPoint> S_i = new HashMap<>();
                    S_i.put(0, X_i);
                    task.Xjks.put(svc.nodeId, new java.util.concurrent.ConcurrentHashMap<>(S_i));

                    BigInteger alpha = CggmpProtocolUtils.randomNonZero(q);
                    ECPoint A_i = g.multiply(alpha).normalize();
                    task.Ajks.put(svc.nodeId, new java.util.concurrent.ConcurrentHashMap<>(Map.of(0, A_i)));
                    task.schAlphas.put(0, alpha);

                    byte[] ridPart = CggmpProtocolUtils.randomBytes(32);
                    task.ridParts.put(svc.nodeId, ridPart);
                    byte[] chainCodePart = svc.hdEnabled ? CggmpProtocolUtils.randomBytes(32) : null;
                    if (chainCodePart != null) {
                        task.chainCodeParts.put(svc.nodeId, chainCodePart);
                    }

                    byte[] uCommit = CggmpProtocolUtils.randomBytes(32);
                    Map<String, Object> r1Open = new LinkedHashMap<>();
                    r1Open.put("taskId", task.taskId);
                    r1Open.put("executionId", task.executionId);
                    r1Open.put("senderId", svc.nodeId);
                    r1Open.put("ridPart", HexUtils.bytesToHex(ridPart));
                    r1Open.put("S", Secp256k1CurveUtils.encodeECPointMapCompressed(S_i));
                    r1Open.put("A", HexUtils.bytesToHex(A_i.getEncoded(true)));
                    r1Open.put("u", HexUtils.bytesToHex(uCommit));
                    if (chainCodePart != null) {
                        r1Open.put("c", HexUtils.bytesToHex(chainCodePart));
                    }
                    String vCommit = CggmpDkgUtils.computeDkgCommitHash(task.executionId, task.taskId, svc.nodeId, ridPart, S_i, A_i, uCommit, chainCodePart);
                    task.round1PayloadHashes.put(svc.nodeId, vCommit);
                    Map<String, Object> r1Commit = new HashMap<>();
                    r1Commit.put("taskId", task.taskId);
                    r1Commit.put("executionId", task.executionId);
                    r1Commit.put("senderId", svc.nodeId);
                    r1Commit.put("V", vCommit);
                    if (svc.dkgUseRbc) {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND1,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                                logger, "CGGMP_DKG_ROUND1_RBC");
                    } else {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND1,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, r1Commit))),
                                logger, "CGGMP_DKG_ROUND1");
                    }

                    task.startRound1Waiting();
                    return new DkgNonThresholdContext(task, q, g, x_i, X_i, r1Open);
                }, dkgExecutorService)
                .thenCompose(ctx -> waitForDkgLatch(task, task.round1ReceivedLatch, "DKG Round 1 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    if (!svc.dkgEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    CggmpProtocolUtils.fireAndForget(svc.dkgMessageHandler.sendDkgRound1Echo(task), logger, "CGGMP_DKG_ROUND1_ECHO");
                    return waitForDkgLatch(task, task.round1EchoReceivedLatch, "DKG Round 1 echo messages")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (svc.dkgUseRbc) {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                logger, "CGGMP_DKG_ROUND2_BROAD_RBC");
                    } else {
                        CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD,
                                        CggmpDkgUtils.maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, ctx.r1Open))),
                                logger, "CGGMP_DKG_ROUND2_BROAD");
                    }
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round2OpenReceivedLatch, "DKG Round 2 open messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    if (svc.hdEnabled) {
                        task.chainCode = CggmpDkgUtils.xorChainCodeParts(task);
                    }
                    task.rid = CggmpDkgUtils.xorRidParts(task);
                    svc.dkgMessageHandler.drainPendingRound3(task);
                    task.startRound2Waiting();
                }, dkgExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> waitForDkgLatch(task, task.round3ReceivedLatch, "DKG Round 3 messages")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    ECPoint groupPublicKey = ctx.g.getCurve().getInfinity();
                    for (int peerId : task.participants) {
                        Map<Integer, ECPoint> sVec = task.Xjks.get(peerId);
                        if (sVec == null || sVec.get(0) == null) {
                            throw new RuntimeException("Missing S_{j,0} from peer " + peerId);
                        }
                        groupPublicKey = groupPublicKey.add(sVec.get(0)).normalize();
                    }
                    task.groupPublicKey = groupPublicKey;
                    task.groupPublicKeyHex = HexUtils.bytesToHex(groupPublicKey.getEncoded(false));

                    svc.saveKeyShareToDatabase(task);
                    task.complete();
                    logger.info("CGGMP24 DKG (n-of-n) completed! Group public key: {}", task.groupPublicKeyHex);
                }, dkgExecutorService));
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = svc.dkgScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    private CompletableFuture<Void> waitForDkgLatch(CggmpDkgTask task, CountDownLatch latch, String label) {
        return waitForLatchAsync(latch, Constants.DKG_ROUND_TIMEOUT_SECONDS, label)
                .exceptionally(ex -> {
                    task.timeout();
                    throw new CompletionException(ex);
                });
    }

    private CompletableFuture<Void> ensureLocalAuxReady() {
        boolean hasAux = loadLatestAuxInfo(svc.nodeId) != null;
        if (!hasAux) {
            return CompletableFuture.failedFuture(new RuntimeException("Missing auxiliary info on local node."));
        }
        return CompletableFuture.completedFuture(null);
    }

    private AuxInfo loadLatestAuxInfo(int nodeId) {
        return svc.auxInfoDao.loadLatestSync(nodeId);
    }

    private CompletableFuture<Void> delayMs(long delayMs) {
        if (delayMs <= 0) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> future = new CompletableFuture<>();
        svc.dkgScheduler.schedule(() -> future.complete(null), delayMs, TimeUnit.MILLISECONDS);
        return future;
    }

    private record DkgContext(CggmpDkgTask task, BigInteger q, ECPoint g, BigInteger[] coeffs,
                              Map<String, Object> r1Open) {
    }

    private record DkgNonThresholdContext(CggmpDkgTask task, BigInteger q, ECPoint g, BigInteger x_i, ECPoint X_i,
                                          Map<String, Object> r1Open) {
    }
}
