package com.example.mpc.service.cggmp.refresh;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.DbMapUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonCodec;
import com.example.mpc.constant.Constants;
import com.example.mpc.dto.CggmpRefreshTask;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.service.CggmpRefreshService;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.service.cggmp.types.BigIntIndexMap;
import com.example.mpc.service.cggmp.types.ECPointIndexMap;
import com.example.mpc.service.cggmp.types.SchProofMap;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * CGGMP密钥刷新协议处理器
 * 负责执行密钥刷新协议的Round 1-3
 */
public final class CggmpRefreshProtocolHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpRefreshProtocolHandler.class);
    private static final ExecutorService refreshExecutorService = CggmpRefreshService.refreshExecutorService;

    private final CggmpRefreshService svc;

    public CggmpRefreshProtocolHandler(CggmpRefreshService svc) {
        this.svc = svc;
    }

    /**
     * 启动密钥刷新任务（由发起方调用）
     */
    public CompletableFuture<Void> startRefreshTask(String taskId) {
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Refresh task not found"));
        }
        if (task.initiatorId != svc.nodeId) {
            task.fail("Refresh start must be triggered by initiator");
            return CompletableFuture.failedFuture(new RuntimeException("Refresh start must be triggered by initiator"));
        }
        if (!validateFullParticipation(task)) {
            task.fail("Refresh requires full participation");
            return CompletableFuture.failedFuture(new RuntimeException("Refresh requires full participation"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        return runRefreshProtocolAsync(task, true);
    }

    /**
     * 从消息启动密钥刷新任务（由非发起方调用）
     */
    public CompletableFuture<Void> startRefreshTaskFromMessage(String taskId, int senderId) {
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Refresh task not found"));
        }
        if (senderId != task.initiatorId) {
            task.fail("Refresh start must be triggered by initiator");
            return CompletableFuture.failedFuture(new RuntimeException("Refresh start must be triggered by initiator"));
        }
        if (!validateFullParticipation(task)) {
            task.fail("Refresh requires full participation");
            return CompletableFuture.failedFuture(new RuntimeException("Refresh requires full participation"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        return runRefreshProtocolAsync(task, false);
    }

    /**
     * 异步执行密钥刷新协议
     */
    private CompletableFuture<Void> runRefreshProtocolAsync(CggmpRefreshTask task, boolean broadcastInit) {
        return waitForNetworkReadyAsync()
                .thenCompose(ready -> {
                    if (!ready) {
                        return CompletableFuture.failedFuture(new RuntimeException("Refresh network ready timeout"));
                    }
                    return CompletableFuture.supplyAsync(() -> {
                        try {
                            BigInteger q = Secp256k1CurveUtils.n();
                            logger.debug("Refresh {} network ready", task.taskId);
                            if (!task.participants.contains(svc.nodeId)) {
                                return null;
                            }
                            if (broadcastInit) {
                                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.sendRefreshInit(task), logger, "CGGMP_REFRESH_INIT");
                            }

                            BigInteger xi = svc.loadLocalShare(task.groupPublicKey);
                            ECPoint Xi = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xi);
                            Map<Integer, BigInteger> indexMap = svc.loadIndexMap(task.groupPublicKey);
                            generateRefreshShares(task, q, indexMap);
                            for (int peerId : task.participants) {
                                BigInteger x = task.xShares.get(peerId);
                                task.xPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x));
                            }

                            for (int peerId : task.participants) {
                                BigInteger y = CggmpProtocolUtils.randomNonZero(q);
                                task.yShares.put(peerId, y);
                                task.yPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y));
                            }

                            ECPointIndexMap A = ECPointIndexMap.empty();
                            for (int peerId : task.participants) {
                                BigInteger alpha = CggmpProtocolUtils.randomNonZero(q);
                                task.schAlphas.put(peerId, alpha);
                                A = A.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), alpha));
                            }

                            byte[] rid = CggmpProtocolUtils.randomBytes(32);
                            byte[] u = CggmpProtocolUtils.randomBytes(32);

                            String v = CggmpRefreshUtils.computeRefreshCommit(task.taskId, svc.nodeId, task.xPoints, task.yPoints, A.values(), Xi, rid, u);
                            task.round1Commit.put(svc.nodeId, v);
                            logger.debug("Refresh R1 commit generated for task {} (nodeId={}, commit={}, X.size={}, Y.size={}, A.size={})",
                                    task.taskId, svc.nodeId, v, task.xPoints.size(), task.yPoints.size(), A.size());
                            CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.sendRefreshR1(task, v), logger, "CGGMP_REFRESH_R1");

                            ECPointIndexMap yMap = ECPointIndexMap.of(task.yPoints);
                            ECPointIndexMap xMap = ECPointIndexMap.of(task.xPoints);
                            CggmpRefreshTask.RefreshRound2Data r2 = new CggmpRefreshTask.RefreshRound2Data(
                                    yMap,
                                    xMap,
                                    A,
                                    Xi,
                                    rid,
                                    u
                            );
                            task.round2Data.put(svc.nodeId, r2);
                            logger.debug("Refresh R2 prepared for task {} (nodeId={}, X.size={}, Y.size={}, A.size={}, ridLen={}, uLen={})",
                                    task.taskId, svc.nodeId, xMap.size(), yMap.size(), A.size(), rid.length, u.length);
                            return task;
                        } catch (Exception e) {
                            task.fail(e.getMessage());
                            throw new RuntimeException(e);
                        }
                    }, refreshExecutorService);
                })
                .thenCompose(t -> {
                    if (t == null) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return waitForLatchAsync(task.round1Latch, "refresh R1")
                            .thenCompose(v -> svc.refreshMessageHandler.sendRefreshR2(task, task.round2Data.get(svc.nodeId)))
                            .thenCompose(v -> waitForLatchAsync(task.round2Latch, "refresh R2"))
                            .thenCompose(v -> CompletableFuture.runAsync(() -> {
                                byte[] mergedRid = CggmpRefreshUtils.xorAllRid(task);
                                task.rid = mergedRid;

                                BigIntIndexMap C = BigIntIndexMap.empty();
                                SchProofMap schProofs = SchProofMap.empty();
                                for (int peerId : task.participants) {
                                    if (peerId == svc.nodeId) continue;
                                    ECPoint Yji = task.round2Data.get(peerId).Y().get(svc.nodeId).orElse(null);
                                    BigInteger y = task.yShares.get(peerId);
                                    BigInteger rho = CggmpRefreshUtils.deriveRefreshMask(task.taskId, mergedRid, svc.nodeId, peerId, Yji, y);
                                    BigInteger xij = task.xShares.get(peerId);
                                    C = C.put(peerId, xij.add(rho).mod(Secp256k1CurveUtils.n()));
                                }
                                for (int peerId : task.participants) {
                                    BigInteger xij = task.xShares.get(peerId);
                                    PiSchProof sch = RefreshProofs.createSchProof(
                                            Secp256k1CurveUtils.G(),
                                            task.xPoints.get(peerId),
                                            xij,
                                            CggmpRefreshUtils.buildRefreshContext(task.taskId, mergedRid, svc.nodeId, "SCH:" + peerId)
                                    );
                                    schProofs = schProofs.put(peerId, sch);
                                }

                                CggmpRefreshTask.RefreshRound3Data r3 = new CggmpRefreshTask.RefreshRound3Data(
                                        C,
                                        schProofs
                                );
                                task.round3Data.put(svc.nodeId, r3);
                                logger.debug("Refresh R3 prepared for task {} (nodeId={}, C.size={}, schProofs.size={})",
                                        task.taskId, svc.nodeId, C.size(), schProofs.size());
                                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.sendRefreshR3(task, r3), logger, "CGGMP_REFRESH_R3");
                            }, refreshExecutorService))
                            .thenCompose(v -> waitForLatchAsync(task.round3Latch, "refresh R3"))
                            .thenRunAsync(() -> {
                                if (!finalizeRefresh(task)) {
                                    task.fail("Refresh verification failed");
                                }
                            }, refreshExecutorService)
                            .thenCompose(v -> {
                                if (task.status.get() == TaskStatus.FAILED) {
                                    return CompletableFuture.completedFuture(null);
                                }
                                task.commitAcks.put(svc.nodeId, Boolean.TRUE);
                                return svc.refreshMessageHandler.sendRefreshCommit(task)
                                        .thenCompose(x -> waitForLatchAsync(task.commitLatch, "refresh commit"));
                            })
                            .thenRunAsync(() -> {
                                if (task.status.get() == TaskStatus.FAILED) {
                                    return;
                                }
                                task.complete();
                                logger.debug("Refresh task {} completed (nodeId={})", task.taskId, svc.nodeId);
                            }, refreshExecutorService);
                }).whenComplete((v, ex) -> {
                    if (ex == null) {
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    task.fail(cause == null ? ex.getMessage() : cause.getMessage());
                });
    }

    /**
     * 生成刷新用的秘密分片
     */
    private void generateRefreshShares(CggmpRefreshTask task, BigInteger q, Map<Integer, BigInteger> indexMap) {
        int threshold = Math.min(Constants.THRESHOLD, task.participants.size());
        if (threshold <= 1) {
            for (int peerId : task.participants) {
                task.xShares.put(peerId, BigInteger.ZERO);
            }
            return;
        }
        List<BigInteger> coeffs = new ArrayList<>();
        for (int i = 1; i < threshold; i++) {
            coeffs.add(CggmpProtocolUtils.randomNonZero(q));
        }
        for (int peerId : task.participants) {
            BigInteger xVal = indexMap != null && indexMap.get(peerId) != null
                    ? indexMap.get(peerId)
                    : BigInteger.valueOf(peerId);
            BigInteger share = BigInteger.ZERO;
            BigInteger power = BigInteger.ONE;
            for (BigInteger coeff : coeffs) {
                power = BigIntegerUtils.modMul(power, xVal, q);
                share = share.add(coeff.multiply(power)).mod(q);
            }
            task.xShares.put(peerId, share);
        }
    }

    private boolean finalizeRefresh(CggmpRefreshTask task) {
        if (task.rid == null || task.rid.length == 0) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        for (int peerId : task.participants) {
            if (!task.round1Commit.containsKey(peerId) || !task.round2Data.containsKey(peerId) || !task.round3Data.containsKey(peerId)) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing refresh data",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing refresh data", Map.of("peerId", peerId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
        }

        for (int peerId : task.participants) {
            CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(peerId);
            String commit = task.round1Commit.get(peerId);
            if (r2 == null || commit == null) {
                return false;
            }
            String expected = CggmpRefreshUtils.computeRefreshCommit(task.taskId, peerId, r2.X().toMap(), r2.Y().toMap(), r2.A().toMap(), r2.Xi(), r2.rid(), r2.u());
            if (!commit.equals(expected)) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("commit", commit);
                extra.put("expectedCommit", expected);
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Refresh commit mismatch",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Refresh commit mismatch", extra)),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            if (!isRefreshXZeroAtOrigin(task, r2.X().toMap())) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("xSum", HexUtils.bytesToHex(Secp256k1CurveUtils.sumPoints(r2.X().toMap()).getEncoded(false)));
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Sum of X not identity",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Sum of X not identity", extra)),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
        }

        Map<Integer, BigInteger> deltas = new HashMap<>();
        for (int peerId : task.participants) {
            CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(peerId);
            CggmpRefreshTask.RefreshRound3Data r3 = task.round3Data.get(peerId);
            if (r2 == null || r3 == null) {
                return false;
            }

            for (int k : task.participants) {
                PiSchProof sch = r3.schProofs().get(k).orElse(null);
                ECPoint Xjk = r2.X().get(k).orElse(null);
                if (sch == null || Xjk == null) {
                    CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing Schnorr proof",
                                    svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing Schnorr proof", Map.of("peerId", peerId, "k", k))),
                            logger, "CGGMP_REFRESH_COMPLAINT");
                    return false;
                }
                if (!RefreshProofs.verifySchProof(sch, Secp256k1CurveUtils.G(), Xjk, CggmpRefreshUtils.buildRefreshContext(task.taskId, task.rid, peerId, "SCH:" + k))) {
                    CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Invalid Schnorr proof",
                                    svc.refreshMessageHandler.refreshEvidence(task, peerId, "Invalid Schnorr proof", Map.of("peerId", peerId, "k", k))),
                            logger, "CGGMP_REFRESH_COMPLAINT");
                    return false;
                }
            }

            if (peerId == svc.nodeId) {
                continue;
            }
            BigInteger Cji = r3.C().get(svc.nodeId).orElse(null);
            if (Cji == null) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing C_{j,i}",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing C_{j,i}", Map.of("peerId", peerId, "missingFor", svc.nodeId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint Yji = r2.Y().get(svc.nodeId).orElse(null);
            if (Yji == null) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing Y_{j,i}",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing Y_{j,i}", Map.of("peerId", peerId, "missingFor", svc.nodeId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            BigInteger yij = task.yShares.get(peerId);
            if (yij == null) {
                return false;
            }
            BigInteger rho = CggmpRefreshUtils.deriveRefreshMask(task.taskId, task.rid, peerId, svc.nodeId, Yji, yij);
            BigInteger xji = Cji.subtract(rho).mod(q);
            ECPoint Xji = r2.X().get(svc.nodeId).orElse(null);
            if (Xji == null) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing X_{j,i}",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing X_{j,i}", Map.of("peerId", peerId, "missingFor", svc.nodeId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint check = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xji);
            if (!check.equals(Xji)) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Invalid C_{j,i} decryption",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Invalid C_{j,i} decryption", Map.of("peerId", peerId, "missingFor", svc.nodeId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            deltas.put(peerId, xji);
        }

        BigInteger oldShare = svc.loadLocalShare(task.groupPublicKey);
        BigInteger deltaSum = task.xShares.getOrDefault(svc.nodeId, BigInteger.ZERO);
        for (BigInteger v : deltas.values()) {
            deltaSum = deltaSum.add(v).mod(q);
        }
        BigInteger newShare = oldShare.add(deltaSum).mod(q);
        try {
            KeyShare prev = svc.keyShareDao.findByGroupPublicKeySync(svc.nodeId, task.groupPublicKey);
            String oldHash = HexUtils.sha256Hex(oldShare.toString(16));
            String newHash = HexUtils.sha256Hex(newShare.toString(16));
            logger.debug("Refresh key share computed (taskId={}, nodeId={}, groupPublicKey={}, oldShareHash={}, newShareHash={})",
                    task.taskId, svc.nodeId, task.groupPublicKey, oldHash, newHash);
            KeyShare keyShare = new KeyShare(svc.nodeId, newShare.toString(16), task.groupPublicKey, task.taskId);
            String prevPublicShares = prev == null ? null : prev.getPublicShares();
            String refreshedPublicShares = buildRefreshedPublicSharesJson(task, prevPublicShares);
            if (refreshedPublicShares == null) {
                logger.error("Failed to refresh public shares for task {} (nodeId={})", task.taskId, svc.nodeId);
                return false;
            }
            keyShare.setPublicShares(refreshedPublicShares);
            if (prev != null) {
                keyShare.setIndexMap(prev.getIndexMap());
                keyShare.setChainCode(prev.getChainCode());
            }
            if (!verifyLocalPublicShare(newShare, keyShare.getPublicShares())) {
                logger.error("Refresh public share mismatch for task {} (nodeId={})", task.taskId, svc.nodeId);
                return false;
            }
            svc.keyShareDao.save(keyShare);
            logger.debug("Refresh key share persisted (taskId={}, nodeId={}, groupPublicKey={}, newShareHash={})",
                    task.taskId, svc.nodeId, task.groupPublicKey, newHash);
        } catch (Exception e) {
            logger.error("Failed to save refreshed key share", e);
            return false;
        }

        return true;
    }

    private CompletableFuture<Boolean> waitForNetworkReadyAsync() {
        return svc.nodeService.waitForNetworkReady()
                .orTimeout(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .thenApply(v -> true)
                .exceptionally(ex -> false);
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = svc.cggmpScheduler.scheduleAtFixedRate(() -> {
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

    private boolean validateFullParticipation(CggmpRefreshTask task) {
        if (task == null) {
            return false;
        }
        if (task.participants.size() != svc.nodesCount) {
            logger.error("Refresh task {} participants size {} does not match nodesCount {}",
                    task.taskId, task.participants.size(), svc.nodesCount);
            return false;
        }
        for (int id = 1; id <= svc.nodesCount; id++) {
            if (!task.participants.contains(id)) {
                logger.error("Refresh task {} missing participant {}", task.taskId, id);
                return false;
            }
        }
        return true;
    }

    private String buildRefreshedPublicSharesJson(CggmpRefreshTask task, String prevPublicSharesJson) {
        try {
            if (prevPublicSharesJson == null) {
                return null;
            }
            Map<Integer, ECPoint> prevShares = DbMapUtils.parsePublicShares(prevPublicSharesJson);
            if (prevShares.isEmpty()) {
                return null;
            }
            for (int id : task.participants) {
                if (!prevShares.containsKey(id)) {
                    logger.error("Refresh public shares missing prior entry for node {} (taskId={})", id, task.taskId);
                    return null;
                }
            }
            Map<Integer, ECPoint> deltaPoints = new HashMap<>();
            for (int k : task.participants) {
                ECPoint sum = null;
                for (int peerId : task.participants) {
                    CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(peerId);
                    if (r2 == null || r2.X() == null) {
                        return null;
                    }
                    ECPoint xjk = r2.X().get(k).orElse(null);
                    if (xjk == null) {
                        return null;
                    }
                    sum = sum == null ? xjk : sum.add(xjk);
                }
                deltaPoints.put(k, Objects.requireNonNull(sum).normalize());
            }
            Map<Integer, ECPoint> refreshed = new HashMap<>();
            for (int k : task.participants) {
                ECPoint base = prevShares.get(k);
                ECPoint delta = deltaPoints.get(k);
                if (base == null || delta == null) {
                    return null;
                }
                refreshed.put(k, base.add(delta).normalize());
            }
            Map<String, String> out = new LinkedHashMap<>();
            for (int k : task.participants) {
                ECPoint point = refreshed.get(k);
                if (point == null) {
                    return null;
                }
                out.put(String.valueOf(k), HexUtils.bytesToHex(point.getEncoded(false)));
            }
            return JsonCodec.toJson(out);
        } catch (Exception e) {
            logger.error("Failed to build refreshed public shares", e);
            return null;
        }
    }

    private boolean verifyLocalPublicShare(BigInteger newShare, String publicSharesJson) {
        if (publicSharesJson == null) {
            return false;
        }
        try {
            Map<Integer, ECPoint> map = DbMapUtils.parsePublicShares(publicSharesJson);
            ECPoint expected = map.get(svc.nodeId);
            if (expected == null) {
                return false;
            }
            ECPoint actual = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), newShare);
            return expected.equals(actual);
        } catch (Exception e) {
            logger.error("Failed to verify refreshed public share", e);
            return false;
        }
    }

    private boolean isRefreshXZeroAtOrigin(CggmpRefreshTask task, Map<Integer, ECPoint> xMap) {
        if (xMap == null || xMap.isEmpty() || task == null) {
            return false;
        }
        Map<Integer, BigInteger> indexMap = svc.loadIndexMap(task.groupPublicKey);
        BigInteger mod = Secp256k1CurveUtils.n();
        ECPoint sum = Secp256k1CurveUtils.G().getCurve().getInfinity();
        for (int k : task.participants) {
            ECPoint xjk = xMap.get(k);
            if (xjk == null) {
                return false;
            }
            BigInteger lambda = CggmpProtocolUtils.lagrangeAtZero(k, task.participants, indexMap, mod);
            sum = sum.add(xjk.multiply(lambda)).normalize();
        }
        return sum.isInfinity();
    }
}
