package com.example.mpc.service.cggmp.refresh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.model.CggmpRefreshTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.service.CggmpRefreshService;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public final class CggmpRefreshProtocolHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpRefreshProtocolHandler.class);
    private static final ExecutorService refreshExecutorService = CggmpRefreshService.refreshExecutorService;

    private final CggmpRefreshService svc;

    public CggmpRefreshProtocolHandler(CggmpRefreshService svc) {
        this.svc = svc;
    }

    public CompletableFuture<Void> startRefreshTask(String taskId) {
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Refresh task not found"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        return runRefreshProtocolAsync(task);
    }

    private CompletableFuture<Void> runRefreshProtocolAsync(CggmpRefreshTask task) {
        return waitForNetworkReadyAsync(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS)
                .thenCompose(ready -> {
                    if (!ready) {
                        return CompletableFuture.failedFuture(new RuntimeException("Refresh network ready timeout"));
                    }
                    return CompletableFuture.supplyAsync(() -> {
                        try {
                            BigInteger q = Secp256k1CurveUtils.n();
                            logger.info("Refresh {} network ready", task.taskId);
                            if (!task.participants.contains(svc.nodeId)) {
                                return null;
                            }

                            BigInteger xi = svc.loadLocalShare(task.groupPublicKey);
                            ECPoint Xi = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xi);

                            BigInteger sum = BigInteger.ZERO;
                            for (int peerId : task.participants) {
                                if (peerId == svc.nodeId) {
                                    continue;
                                }
                                BigInteger share = CggmpProtocolUtils.randomNonZero(q);
                                task.xShares.put(peerId, share);
                                sum = sum.add(share).mod(q);
                            }
                            BigInteger selfShare = q.subtract(sum).mod(q);
                            task.xShares.put(svc.nodeId, selfShare);
                            for (int peerId : task.participants) {
                                BigInteger x = task.xShares.get(peerId);
                                task.xPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x));
                            }

                            for (int peerId : task.participants) {
                                BigInteger y = CggmpProtocolUtils.randomNonZero(q);
                                task.yShares.put(peerId, y);
                                task.yPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y));
                            }

                            Map<Integer, ECPoint> A = new HashMap<>();
                            for (int peerId : task.participants) {
                                BigInteger alpha = CggmpProtocolUtils.randomNonZero(q);
                                task.schAlphas.put(peerId, alpha);
                                A.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), alpha));
                            }

                            byte[] rid = CggmpProtocolUtils.randomBytes(32);
                            byte[] u = CggmpProtocolUtils.randomBytes(32);

                            String v = CggmpRefreshUtils.computeRefreshCommit(task.taskId, svc.nodeId, task.xPoints, task.yPoints, A, Xi, rid, u);
                            task.round1Commit.put(svc.nodeId, v);
                            logger.debug("Refresh R1 commit generated for task {} (nodeId={}, commit={}, X.size={}, Y.size={}, A.size={})",
                                    task.taskId, svc.nodeId, v, task.xPoints.size(), task.yPoints.size(), A.size());
                            CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.sendRefreshR1(task, v), logger, "CGGMP_REFRESH_R1");

                            Map<Integer, ECPoint> yMap = new HashMap<>(task.yPoints);
                            Map<Integer, ECPoint> xMap = new HashMap<>(task.xPoints);
                            Map<Integer, ECPoint> aMap = A;
                            CggmpRefreshTask.RefreshRound2Data r2 = new CggmpRefreshTask.RefreshRound2Data(
                                    yMap,
                                    xMap,
                                    aMap,
                                    Xi,
                                    rid,
                                    u
                            );
                            task.round2Data.put(svc.nodeId, r2);
                            logger.debug("Refresh R2 prepared for task {} (nodeId={}, X.size={}, Y.size={}, A.size={}, ridLen={}, uLen={})",
                                    task.taskId, svc.nodeId, xMap.size(), yMap.size(), aMap.size(), rid.length, u.length);
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
                    return waitForLatchAsync(task.round1Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R1")
                            .thenCompose(v -> svc.refreshMessageHandler.sendRefreshR2(task, task.round2Data.get(svc.nodeId)))
                            .thenCompose(v -> waitForLatchAsync(task.round2Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R2"))
                            .thenCompose(v -> CompletableFuture.runAsync(() -> {
                                byte[] mergedRid = CggmpRefreshUtils.xorAllRid(task);
                                task.rid = mergedRid;

                                Map<Integer, BigInteger> C = new HashMap<>();
                                Map<Integer, PiSchProof> schProofs = new HashMap<>();
                                for (int peerId : task.participants) {
                                    if (peerId == svc.nodeId) continue;
                                    ECPoint Yji = task.round2Data.get(peerId).Y.get(svc.nodeId);
                                    BigInteger y = task.yShares.get(peerId);
                                    BigInteger rho = CggmpRefreshUtils.deriveRefreshMask(task.taskId, mergedRid, svc.nodeId, peerId, Yji, y);
                                    BigInteger xij = task.xShares.get(peerId);
                                    C.put(peerId, xij.add(rho).mod(Secp256k1CurveUtils.n()));
                                }
                                for (int peerId : task.participants) {
                                    BigInteger xij = task.xShares.get(peerId);
                                    PiSchProof sch = RefreshProofs.createSchProof(
                                            Secp256k1CurveUtils.G(),
                                            task.xPoints.get(peerId),
                                            xij,
                                            CggmpRefreshUtils.buildRefreshContext(task.taskId, mergedRid, svc.nodeId, "SCH:" + peerId)
                                    );
                                    schProofs.put(peerId, sch);
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
                            .thenCompose(v -> waitForLatchAsync(task.round3Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R3"))
                            .thenRunAsync(() -> {
                                if (!finalizeRefresh(task)) {
                                    task.fail("Refresh verification failed");
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
            String expected = CggmpRefreshUtils.computeRefreshCommit(task.taskId, peerId, r2.X, r2.Y, r2.A, r2.Xi, r2.rid, r2.u);
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
            ECPoint sum = Secp256k1CurveUtils.sumPoints(r2.X);
            if (!sum.isInfinity()) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("xSum", HexUtils.bytesToHex(sum.getEncoded(false)));
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
                PiSchProof sch = r3.schProofs.get(k);
                ECPoint Xjk = r2.X.get(k);
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
            BigInteger Cji = r3.C.get(svc.nodeId);
            if (Cji == null) {
                CggmpProtocolUtils.fireAndForget(svc.refreshMessageHandler.broadcastRefreshComplaint(task, peerId, "Missing C_{j,i}",
                                svc.refreshMessageHandler.refreshEvidence(task, peerId, "Missing C_{j,i}", Map.of("peerId", peerId, "missingFor", svc.nodeId))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint Yji = r2.Y.get(svc.nodeId);
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
            ECPoint Xji = r2.X.get(svc.nodeId);
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
            KeyShare keyShare = new KeyShare(svc.nodeId, newShare.toString(16), task.groupPublicKey, task.taskId);
            svc.keyShareDao.save(keyShare);
        } catch (Exception e) {
            logger.error("Failed to save refreshed key share", e);
            return false;
        }

        return true;
    }

    private CompletableFuture<Boolean> waitForNetworkReadyAsync(long timeoutSeconds) {
        return svc.nodeService.waitForNetworkReady()
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .thenApply(v -> true)
                .exceptionally(ex -> false);
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
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
}
