package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.service.cggmp.CggmpPresignPeerR2Result;
import com.example.mpc.service.cggmp.CggmpPresignR1Context;
import com.example.mpc.service.cggmp.CggmpPresignR2Bundle;
import com.example.mpc.service.cggmp.CggmpPresignR2Context;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

final class CggmpSignatureOfflineHandler {
    private final CggmpSignatureService svc;

    CggmpSignatureOfflineHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    CompletableFuture<Void> runOfflinePhase(Gg20SignatureTask task) {
        svc.logger.debug("Signature offline phase start for task {} (node={}, participants={})",
                task.taskId, svc.nodeId, task.participants);
        CompletableFuture<CggmpPresignR1Context> r1Future = CompletableFuture.supplyAsync(() -> {
            try {
                long t0 = System.nanoTime();
                BigInteger curveOrder = Secp256k1CurveUtils.n();
                long t1 = System.nanoTime();
                svc.initSignaturePaillier(task);
                long t2 = System.nanoTime();

                task.k_i = svc.randomNonZero(curveOrder);
                BigInteger gamma_i = svc.randomNonZero(curveOrder);
                task.presignGamma.put(svc.nodeId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), gamma_i));

                BigInteger y_i = svc.randomNonZero(curveOrder);
                BigInteger a_i = svc.randomNonZero(curveOrder);
                BigInteger b_i = svc.randomNonZero(curveOrder);
                ECPoint Y_i = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y_i);
                ECPoint A1 = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), a_i);
                ECPoint A2 = Y_i.multiply(a_i).add(Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), task.k_i)).normalize();
                ECPoint B1 = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), b_i);
                ECPoint B2 = Y_i.multiply(b_i).add(Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), gamma_i)).normalize();
                task.presignYScalar = y_i;
                task.presignAScalar = a_i;
                task.presignBScalar = b_i;
                task.presignY.put(svc.nodeId, Y_i);
                task.presignA1.put(svc.nodeId, A1);
                task.presignA2.put(svc.nodeId, A2);
                task.presignB1.put(svc.nodeId, B1);
                task.presignB2.put(svc.nodeId, B2);

                PaillierEncryption.Encryption encK = task.paillier.encryptWithRandomness(task.k_i);
                PaillierEncryption.Encryption encG = task.paillier.encryptWithRandomness(gamma_i);
                BigInteger K = encK.c;
                BigInteger G = encG.c;
                task.presignK.put(svc.nodeId, K);
                task.presignG.put(svc.nodeId, G);

                byte[] ctxR1K = SignUtils.buildPresignContext(task.taskId, svc.nodeId, "R1K");
                long t3 = System.nanoTime();
                PiEncElgProof encElgK = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1CurveUtils.G(),
                        A1,
                        Y_i,
                        A2,
                        task.k_i,
                        encK.r,
                        a_i,
                        y_i,
                        svc.proofEpsBits,
                        ctxR1K
                );
                long t4 = System.nanoTime();
                PresignProofs.EncElgVerifyResult localEncElgK = PresignProofs.verifyEncElgProofDetailed(
                        encElgK, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1CurveUtils.G(), A1, Y_i, A2, K, svc.proofEpsBits, ctxR1K);
                if (!localEncElgK.ok()) {
                    svc.logger.warn("Local PiEncElg proof (K) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgK.eq1(), localEncElgK.eq2(), localEncElgK.eq3(), localEncElgK.eq4(), localEncElgK.z1InRange());
                }
                byte[] ctxR1G = SignUtils.buildPresignContext(task.taskId, svc.nodeId, "R1G");
                long t5 = System.nanoTime();
                PiEncElgProof encElgG = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1CurveUtils.G(),
                        B1,
                        Y_i,
                        B2,
                        gamma_i,
                        encG.r,
                        b_i,
                        y_i,
                        svc.proofEpsBits,
                        ctxR1G
                );
                long t6 = System.nanoTime();
                PresignProofs.EncElgVerifyResult localEncElgG = PresignProofs.verifyEncElgProofDetailed(
                        encElgG, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1CurveUtils.G(), B1, Y_i, B2, G, svc.proofEpsBits, ctxR1G);
                if (!localEncElgG.ok()) {
                    svc.logger.warn("Local PiEncElg proof (G) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgG.eq1(), localEncElgG.eq2(), localEncElgG.eq3(), localEncElgG.eq4(), localEncElgG.z1InRange());
                }
                svc.logger.debug("Presign R1 timing task {}: curve={}ms, paillier+zk={}ms, encElgK={}ms, encElgG={}ms",
                        task.taskId,
                        TimeUnit.NANOSECONDS.toMillis(t1 - t0),
                        TimeUnit.NANOSECONDS.toMillis(t2 - t1),
                        TimeUnit.NANOSECONDS.toMillis(t4 - t3),
                        TimeUnit.NANOSECONDS.toMillis(t6 - t5));
                svc.fireAndForget(svc.broadcastPresignR1(task, K, G, Y_i, A1, A2, B1, B2, encElgK, encElgG),
                        "CGGMP_PRESIGN_R1");
                return new CggmpPresignR1Context(task, curveOrder, gamma_i);
            } catch (Exception e) {
                svc.logger.debug("Presign R1 failed for task {}: {}", task.taskId, e.getMessage());
                task.fail(e.getMessage());
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());

        CompletableFuture<CggmpPresignR2Context> r2ContextFuture = r1Future
                .thenCompose(ctx -> svc.waitForLatchAsync(task.gammaCommitLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R1")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> {
                    if (!svc.presignEchoEnabled) {
                        return CompletableFuture.completedFuture(ctx);
                    }
                    svc.fireAndForget(svc.broadcastPresignR1Echo(task), "CGGMP_PRESIGN_R1_ECHO");
                    return svc.waitForLatchAsync(task.presignR1EchoLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R1 echo")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        svc.logger.debug("Presign R1 completed for task {}, proceeding to R2", task.taskId);
                        ECPoint Gamma_i = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), ctx.gamma_i());
                        BigInteger x_i_raw = svc.loadLocalShare(task.groupPublicKey);
                        BigInteger lambda_i = svc.computeSignatureLagrange(task, svc.nodeId, ctx.curveOrder());
                        BigInteger x_i = x_i_raw.multiply(lambda_i).mod(ctx.curveOrder());
                        ECPoint X_i = svc.resolvePublicShare(task, svc.nodeId, lambda_i, x_i);

                        long r2StartNs = System.nanoTime();
                        svc.logger.debug("Presign R2 starting proof generation for task {} (peers={})", task.taskId, task.participants.size() - 1);
                        List<CompletableFuture<CggmpPresignPeerR2Result>> r2Futures = new ArrayList<>();
                        for (int peerId : task.participants) {
                            if (peerId == svc.nodeId) continue;
                            r2Futures.add(CompletableFuture.supplyAsync(() -> {
                                long peerStartNs = System.nanoTime();
                                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                                BigInteger K_peer = task.presignK.get(peerId);
                                if (pk == null || K_peer == null) {
                                    return CggmpPresignPeerR2Result.skipped(peerId);
                                }
                                BigInteger beta = svc.randomNonZero(ctx.curveOrder());
                                BigInteger betaHat = svc.randomNonZero(ctx.curveOrder());
                                PaillierEncryption.Encryption encNegBeta = pk.encryptWithRandomness(SignUtils.negateModN(beta, pk.n));
                                PaillierEncryption.Encryption encNegBetaHat = pk.encryptWithRandomness(SignUtils.negateModN(betaHat, pk.n));
                                BigInteger D_ji = pk.multiply(K_peer, ctx.gamma_i()).multiply(encNegBeta.c).mod(pk.nSquared);
                                BigInteger Dhat_ji = pk.multiply(K_peer, x_i).multiply(encNegBetaHat.c).mod(pk.nSquared);
                                PaillierEncryption.Encryption encBeta = task.paillier.getPublicKeyInfo().encryptWithRandomness(beta);
                                PaillierEncryption.Encryption encBetaHat = task.paillier.getPublicKeyInfo().encryptWithRandomness(betaHat);
                                BigInteger F_ji = encBeta.c;
                                BigInteger Fhat_ji = encBetaHat.c;
                                PiAffGProof proof = PresignProofs.createAffGProofNegY(
                                        Secp256k1CurveUtils.G(),
                                        pk.n,
                                        task.paillier.getPublicKeyInfo().n,
                                        K_peer,
                                        ctx.gamma_i(),
                                        beta,
                                        encNegBeta.r,
                                        encBeta.r,
                                        svc.proofKappa,
                                        svc.proofEpsBits,
                                        SignUtils.buildPresignContext(task.taskId, svc.nodeId, "R2")
                                );
                                PiAffGProof proofHat = PresignProofs.createAffGProofNegY(
                                        Secp256k1CurveUtils.G(),
                                        pk.n,
                                        task.paillier.getPublicKeyInfo().n,
                                        K_peer,
                                        x_i,
                                        betaHat,
                                        encNegBetaHat.r,
                                        encBetaHat.r,
                                        svc.proofKappa,
                                        svc.proofEpsBits,
                                        SignUtils.buildPresignContext(task.taskId, svc.nodeId, "R2H")
                                );
                                long peerMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - peerStartNs);
                                return CggmpPresignPeerR2Result.done(peerId, beta, betaHat, D_ji, Dhat_ji, F_ji, Fhat_ji,
                                        encNegBeta.r, encBeta.r, encNegBetaHat.r, encBetaHat.r, proof, proofHat, peerMs);
                            }, svc.dkgExecutorService));
                        }
                        return new CggmpPresignR2Context(task, ctx.curveOrder(), ctx.gamma_i(), x_i, Gamma_i, X_i, r2Futures, r2StartNs);
                    } catch (Exception e) {
                        task.fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()));

        return r2ContextFuture
                .thenCompose(ctx -> CompletableFuture.allOf(ctx.r2Futures().toArray(new CompletableFuture[0]))
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        Map<Integer, BigInteger> D = new HashMap<>();
                        Map<Integer, BigInteger> Dhat = new HashMap<>();
                        Map<Integer, BigInteger> F = new HashMap<>();
                        Map<Integer, BigInteger> Fhat = new HashMap<>();
                        Map<Integer, PiAffGProof> affGProofs = new HashMap<>();
                        Map<Integer, PiAffGProof> affGProofsHat = new HashMap<>();
                        int skippedPeers = 0;

                        for (CompletableFuture<CggmpPresignPeerR2Result> future : ctx.r2Futures()) {
                            CggmpPresignPeerR2Result result = future.getNow(null);
                            if (result == null) {
                                throw new RuntimeException("Presign R2 missing result after completion");
                            }
                            if (result.skipped()) {
                                skippedPeers++;
                                continue;
                            }
                            int peerId = result.peerId();
                            ctx.task().presignBeta.put(peerId, result.beta());
                            ctx.task().presignBetaHat.put(peerId, result.betaHat());
                            D.put(peerId, result.d());
                            Dhat.put(peerId, result.dhat());
                            F.put(peerId, result.f());
                            Fhat.put(peerId, result.fhat());
                            ctx.task().presignFOutgoing.put(peerId, result.f());
                            ctx.task().presignFhatOutgoing.put(peerId, result.fhat());
                            ctx.task().presignRho.put(peerId, result.rho());
                            ctx.task().presignMu.put(peerId, result.mu());
                            ctx.task().presignRhoHat.put(peerId, result.rhoHat());
                            ctx.task().presignMuHat.put(peerId, result.muHat());
                            affGProofs.put(peerId, result.proof());
                            affGProofsHat.put(peerId, result.proofHat());
                            svc.logger.debug("Presign R2 proof generated for task {} peer {} in {} ms",
                                    ctx.task().taskId, peerId, result.peerMs());
                        }
                        long r2Ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.r2StartNs());
                        svc.logger.debug("Presign R2 prepared for task {}: peers={}, proofs={}, skipped={}",
                                ctx.task().taskId, ctx.task().participants.size() - 1, affGProofs.size(), skippedPeers);
                        svc.logger.debug("Presign R2 proof generation total time for task {}: {} ms", ctx.task().taskId, r2Ms);

                        ECPoint Y_i_r2 = ctx.task().presignY.get(svc.nodeId);
                        ECPoint B1_r2 = ctx.task().presignB1.get(svc.nodeId);
                        ECPoint B2_r2 = ctx.task().presignB2.get(svc.nodeId);
                        if (Y_i_r2 == null || B1_r2 == null || B2_r2 == null || ctx.task().presignBScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof");
                        }
                        byte[] ctxR2 = SignUtils.buildPresignContext(ctx.task().taskId, svc.nodeId, "R2");
                        PiLogProof logProof = PresignProofs.createLogProof(
                                Secp256k1CurveUtils.G(),
                                Secp256k1CurveUtils.G(),
                                ctx.Gamma_i(),
                                Y_i_r2,
                                B1_r2,
                                B2_r2,
                                ctx.gamma_i(),
                                ctx.task().presignBScalar,
                                ctxR2
                        );
                        svc.fireAndForget(svc.broadcastPresignR2(ctx.task(), ctx.Gamma_i(), D, Dhat, F, Fhat, affGProofs, affGProofsHat, logProof, ctx.X_i()),
                                "CGGMP_PRESIGN_R2");
                        svc.logger.debug("Presign R2 broadcasted for task {}", ctx.task().taskId);

                        return new CggmpPresignR2Bundle(ctx, D, Dhat, F, Fhat);
                    } catch (Exception e) {
                        ctx.task().fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(svc::continuePresignAfterR2)
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        svc.logger.debug("Signature offline phase completed for task {}", task.taskId);
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    if (cause == null) {
                        task.fail(ex.getMessage());
                    } else {
                        task.fail(cause.getMessage());
                    }
                });
    }

    CompletableFuture<Void> broadcastOfflineInit(Gg20SignatureTask task) {
        svc.logger.debug("Broadcasting CGGMP_SIGN_OFFLINE_INIT for task {} (participants={})", task.taskId, task.participants);
        Map<String, Object> initData = new HashMap<>();
        initData.put("signatureTaskId", task.taskId);
        initData.put("groupPublicKey", task.groupPublicKey);
        initData.put("message", task.message);
        initData.put("initiatorId", task.initiatorId);
        initData.put("participants", new ArrayList<>(task.participants));
        return RetryUtils.retryAsync(svc.cggmpScheduler, svc.logger, () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_OFFLINE_INIT, initData)),
                Constants.SIGNATURE_BROADCAST_RETRY_COUNT,
                Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_OFFLINE_INIT"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                svc.logger.warn("Failed to broadcast CGGMP_SIGN_OFFLINE_INIT, proceeding: {}", ex.getMessage());
            }
        });
    }

    CompletableFuture<Void> sendOfflineReady(Gg20SignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        return svc.nodeService.sendMessage(task.initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_OFFLINE_READY, data));
    }

    void markOfflineReady(Gg20SignatureTask task, int senderId) {
        if (task.offlineReady.putIfAbsent(senderId, Boolean.TRUE) == null) {
            if (task.offlineReadyLatch.getCount() > 0) {
                task.offlineReadyLatch.countDown();
            }
        }
    }

    void handleCggmpSignOfflineInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String signatureTaskId = (String) dataMap.get("signatureTaskId");
            String groupPublicKey = (String) dataMap.get("groupPublicKey");
            String msg = (String) dataMap.get("message");
            Integer initiatorId = null;
            Object initiatorValue = dataMap.get("initiatorId");
            if (initiatorValue instanceof Number) {
                initiatorId = ((Number) initiatorValue).intValue();
            }
            List<Integer> participants = null;
            Object participantsValue = dataMap.get("participants");
            if (participantsValue instanceof List<?> list) {
                participants = new ArrayList<>();
                for (Object v : list) {
                    if (v instanceof Number n) {
                        participants.add(n.intValue());
                    }
                }
            }
            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                if (!svc.signatureTasks.containsKey(signatureTaskId)) {
                    int resolvedInitiatorId = initiatorId != null ? initiatorId : senderId;
                    Set<Integer> participantsSet = participants == null ? null : new LinkedHashSet<>(participants);
                    svc.createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg, resolvedInitiatorId, participantsSet);
                    svc.logger.debug("Created CGGMP signature task from OFFLINE_INIT: {} (initiator={}, participants={})",
                            signatureTaskId, resolvedInitiatorId, participantsSet);
                    CompletableFuture.runAsync(() -> {
                        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
                        if (task == null) {
                            return;
                        }
                        if (!task.participants.contains(svc.nodeId)) {
                            svc.logger.info("Node {} not selected for CGGMP signature task {}, participants={}, skipping", svc.nodeId, signatureTaskId, task.participants);
                            svc.signatureInProgress.set(false);
                            return;
                        }
                        svc.logger.debug("Starting offline phase from OFFLINE_INIT for task {} on node {}", signatureTaskId, svc.nodeId);
                        task.start();
                        svc.initSignatureContext(task);
                        svc.drainPendingPresignR1(task);
                        runOfflinePhase(task).exceptionally(ex -> {
                            svc.logger.error("Failed offline phase for signature task {}: {}", signatureTaskId, ex.getMessage());
                            svc.signatureInProgress.set(false);
                            return null;
                        });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    svc.logger.info("Signature task {} already exists, ignoring OFFLINE_INIT", signatureTaskId);
                }
            } else {
                svc.logger.warn("Invalid OFFLINE_INIT payload from node {}", senderId);
            }
        }
    }

    void handleCggmpSignOfflineReady(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        if (signatureTaskId == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        markOfflineReady(task, senderNodeId);
    }
}
