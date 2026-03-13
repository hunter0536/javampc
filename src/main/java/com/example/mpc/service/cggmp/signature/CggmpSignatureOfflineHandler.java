package com.example.mpc.service.cggmp.signature;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.DbMapUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.dto.CggmpSignatureTask;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.service.cggmp.types.AffGProofMap;
import com.example.mpc.service.cggmp.types.BigIntIndexMap;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

/**
 * CGGMP签名离线阶段处理器
 * 负责执行签名的预计算阶段(presign)，生成可重用的签名分片
 */
public final class CggmpSignatureOfflineHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureOfflineHandler.class);
    private final CggmpSignatureService svc;

    public CggmpSignatureOfflineHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    /**
     * 执行签名离线阶段（预签名），生成可重用的签名分片
     */
    public CompletableFuture<Void> runOfflinePhase(CggmpSignatureTask task) {
        logger.debug("Signature offline phase start for task {} (node={}, participants={})",
                task.taskId, svc.nodeId, task.participants);
        CompletableFuture<CggmpPresignR1Context> r1Future = CompletableFuture.supplyAsync(() -> {
            try {
                long t0 = System.nanoTime();
                BigInteger curveOrder = Secp256k1CurveUtils.n();
                long t1 = System.nanoTime();
                initSignaturePaillier(task);
                long t2 = System.nanoTime();

                task.k_i = CggmpProtocolUtils.randomNonZero(curveOrder);
                BigInteger gamma_i = CggmpProtocolUtils.randomNonZero(curveOrder);
                task.presignGamma.put(svc.nodeId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), gamma_i));

                BigInteger y_i = CggmpProtocolUtils.randomNonZero(curveOrder);
                BigInteger a_i = CggmpProtocolUtils.randomNonZero(curveOrder);
                BigInteger b_i = CggmpProtocolUtils.randomNonZero(curveOrder);
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
                BigInteger K = encK.c();
                BigInteger G = encG.c();
                task.presignK.put(svc.nodeId, K);
                task.presignG.put(svc.nodeId, G);

                byte[] ctxR1K = CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R1K");
                long t3 = System.nanoTime();
                PiEncElgProof encElgK = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1CurveUtils.G(),
                        A1,
                        Y_i,
                        A2,
                        task.k_i,
                        encK.r(),
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
                    logger.warn("Local PiEncElg proof (K) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgK.eq1(), localEncElgK.eq2(), localEncElgK.eq3(), localEncElgK.eq4(), localEncElgK.z1InRange());
                }
                byte[] ctxR1G = CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R1G");
                long t5 = System.nanoTime();
                PiEncElgProof encElgG = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1CurveUtils.G(),
                        B1,
                        Y_i,
                        B2,
                        gamma_i,
                        encG.r(),
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
                    logger.warn("Local PiEncElg proof (G) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgG.eq1(), localEncElgG.eq2(), localEncElgG.eq3(), localEncElgG.eq4(), localEncElgG.z1InRange());
                }
                logger.debug("Presign R1 timing task {}: curve={}ms, paillier+zk={}ms, encElgK={}ms, encElgG={}ms",
                        task.taskId,
                        TimeUnit.NANOSECONDS.toMillis(t1 - t0),
                        TimeUnit.NANOSECONDS.toMillis(t2 - t1),
                        TimeUnit.NANOSECONDS.toMillis(t4 - t3),
                        TimeUnit.NANOSECONDS.toMillis(t6 - t5));
                CggmpProtocolUtils.fireAndForget(broadcastPresignR1(task, K, G, Y_i, A1, A2, B1, B2, encElgK, encElgG),
                        logger, "CGGMP_PRESIGN_R1");
                return new CggmpPresignR1Context(task, curveOrder, gamma_i);
            } catch (Exception e) {
                logger.debug("Presign R1 failed for task {}: {}", task.taskId, e.getMessage());
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
                    CggmpProtocolUtils.fireAndForget(broadcastPresignR1Echo(task), logger, "CGGMP_PRESIGN_R1_ECHO");
                    return svc.waitForLatchAsync(task.presignR1EchoLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R1 echo")
                            .thenApply(v -> ctx);
                })
                .thenCompose(ctx -> CompletableFuture.supplyAsync(() -> {
                    try {
                        logger.debug("Presign R1 completed for task {}, proceeding to R2", task.taskId);
                        ECPoint Gamma_i = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), ctx.gamma_i());
                        BigInteger x_i_raw = loadLocalShare(task.groupPublicKey);
                        BigInteger lambda_i = CggmpProtocolUtils.computeSignatureLagrange(task, svc.nodeId, ctx.curveOrder());
                        BigInteger x_i = x_i_raw.multiply(lambda_i).mod(ctx.curveOrder());
                        ECPoint X_i = CggmpProtocolUtils.resolvePublicShare(task, svc.nodeId, lambda_i, x_i);

                        long r2StartNs = System.nanoTime();
                        logger.debug("Presign R2 starting proof generation for task {} (peers={})", task.taskId, task.participants.size() - 1);
                        synchronized (task) {
                            if (task.r2VerifyLatch == null) {
                                task.r2VerifyLatch = new CountDownLatch(task.participants.size() - 1);
                            }
                        }
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
                                BigInteger beta = CggmpProtocolUtils.randomNonZero(ctx.curveOrder());
                                BigInteger betaHat = CggmpProtocolUtils.randomNonZero(ctx.curveOrder());
                                PaillierEncryption.Encryption encNegBeta = pk.encryptWithRandomness(CggmpProtocolUtils.negateModN(beta, pk.n()));
                                PaillierEncryption.Encryption encNegBetaHat = pk.encryptWithRandomness(CggmpProtocolUtils.negateModN(betaHat, pk.n()));
                                BigInteger D_ji = pk.multiply(K_peer, ctx.gamma_i()).multiply(encNegBeta.c()).mod(pk.nSquared());
                                BigInteger Dhat_ji = pk.multiply(K_peer, x_i).multiply(encNegBetaHat.c()).mod(pk.nSquared());
                                PaillierEncryption.Encryption encBeta = task.paillier.getPublicKeyInfo().encryptWithRandomness(beta);
                                PaillierEncryption.Encryption encBetaHat = task.paillier.getPublicKeyInfo().encryptWithRandomness(betaHat);
                                BigInteger F_ji = encBeta.c();
                                BigInteger Fhat_ji = encBetaHat.c();
                                PiAffGProof proof = PresignProofs.createAffGProofNegY(
                                        Secp256k1CurveUtils.G(),
                                        Gamma_i,
                                        pk.n(),
                                        task.paillier.getPublicKeyInfo().n(),
                                        K_peer,
                                        D_ji,
                                        F_ji,
                                        ctx.gamma_i(),
                                        beta,
                                        encNegBeta.r(),
                                        encBeta.r(),
                                        svc.proofKappa,
                                        svc.proofEpsBits,
                                        CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R2")
                                );
                                PiAffGProof proofHat = PresignProofs.createAffGProofNegY(
                                        Secp256k1CurveUtils.G(),
                                        X_i,
                                        pk.n(),
                                        task.paillier.getPublicKeyInfo().n(),
                                        K_peer,
                                        Dhat_ji,
                                        Fhat_ji,
                                        x_i,
                                        betaHat,
                                        encNegBetaHat.r(),
                                        encBetaHat.r(),
                                        svc.proofKappa,
                                        svc.proofEpsBits,
                                        CggmpProtocolUtils.buildPresignContext(task.taskId, svc.nodeId, "R2H")
                                );
                                long peerMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - peerStartNs);
                                return CggmpPresignPeerR2Result.done(peerId, beta, betaHat, D_ji, Dhat_ji, F_ji, Fhat_ji,
                                        encNegBeta.r(), encBeta.r(), encNegBetaHat.r(), encBetaHat.r(), proof, proofHat, peerMs);
                            }, CggmpSignatureService.signatureExecutorService));
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
                        BigIntIndexMap D = BigIntIndexMap.empty();
                        BigIntIndexMap Dhat = BigIntIndexMap.empty();
                        BigIntIndexMap F = BigIntIndexMap.empty();
                        BigIntIndexMap Fhat = BigIntIndexMap.empty();
                        AffGProofMap affGProofs = AffGProofMap.empty();
                        AffGProofMap affGProofsHat = AffGProofMap.empty();
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
                            D = D.put(peerId, result.d());
                            Dhat = Dhat.put(peerId, result.dhat());
                            F = F.put(peerId, result.f());
                            Fhat = Fhat.put(peerId, result.fhat());
                            ctx.task().presignFOutgoing.put(peerId, result.f());
                            ctx.task().presignFhatOutgoing.put(peerId, result.fhat());
                            ctx.task().presignRho.put(peerId, result.rho());
                            ctx.task().presignMu.put(peerId, result.mu());
                            ctx.task().presignRhoHat.put(peerId, result.rhoHat());
                            ctx.task().presignMuHat.put(peerId, result.muHat());
                            affGProofs = affGProofs.put(peerId, result.proof());
                            affGProofsHat = affGProofsHat.put(peerId, result.proofHat());
                            logger.debug("Presign R2 proof generated for task {} peer {} in {} ms",
                                    ctx.task().taskId, peerId, result.peerMs());
                        }
                        long r2Ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - ctx.r2StartNs());
                        logger.debug("Presign R2 prepared for task {}: peers={}, proofs={}, skipped={}",
                                ctx.task().taskId, ctx.task().participants.size() - 1, affGProofs.size(), skippedPeers);
                        logger.debug("Presign R2 proof generation total time for task {}: {} ms", ctx.task().taskId, r2Ms);

                        ECPoint Y_i_r2 = ctx.task().presignY.get(svc.nodeId);
                        ECPoint B1_r2 = ctx.task().presignB1.get(svc.nodeId);
                        ECPoint B2_r2 = ctx.task().presignB2.get(svc.nodeId);
                        if (Y_i_r2 == null || B1_r2 == null || B2_r2 == null || ctx.task().presignBScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof");
                        }
                        byte[] ctxR2 = CggmpProtocolUtils.buildPresignContext(ctx.task().taskId, svc.nodeId, "R2");
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
                        CggmpProtocolUtils.fireAndForget(broadcastPresignR2(ctx.task(), ctx.Gamma_i(), D, Dhat, F, Fhat, affGProofs, affGProofsHat, logProof, ctx.X_i()),
                                logger, "CGGMP_PRESIGN_R2");
                        logger.debug("Presign R2 broadcasted for task {}", ctx.task().taskId);

                        return new CggmpPresignR2Bundle(ctx, D, Dhat, F, Fhat);
                    } catch (Exception e) {
                        ctx.task().fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(this::continuePresignAfterR2)
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        logger.debug("Signature offline phase completed for task {}", task.taskId);
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    task.fail(Objects.requireNonNullElse(cause, ex).getMessage());
                });
    }

    public CompletableFuture<Void> broadcastOfflineInit(CggmpSignatureTask task) {
        logger.debug("Broadcasting CGGMP_SIGN_OFFLINE_INIT for task {} (participants={})", task.taskId, task.participants);
        Map<String, Object> initData = new HashMap<>();
        initData.put("signatureTaskId", task.taskId);
        initData.put("groupPublicKey", task.groupPublicKey);
        initData.put("message", task.message);
        initData.put("initiatorId", task.initiatorId);
        initData.put("participants", new ArrayList<>(task.participants));
        initData.put("auxTaskId", task.auxTaskId);
        if (task.paillier != null && task.zkSetup != null) {
            initData.put("auxParams", buildAuxParamsFromPaillierAndZkSetup(task));
        }
        return RetryUtils.retryAsync(svc.cggmpScheduler, logger, () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_OFFLINE_INIT, initData)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_SIGN_OFFLINE_INIT"
        ).whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("Failed to broadcast CGGMP_SIGN_OFFLINE_INIT, proceeding: {}", ex.getMessage());
            }
        });
    }

    private Map<String, String> buildAuxParamsFromPaillierAndZkSetup(CggmpSignatureTask task) {
        Map<String, String> auxParams = new HashMap<>();
        auxParams.put("paillierN", task.paillier.getPublicKeyInfo().n().toString(16));
        auxParams.put("paillierG", task.paillier.getPublicKeyInfo().g().toString(16));
        auxParams.put("paillierBitLength", String.valueOf(task.paillier.getPublicKeyInfo().bitLength()));
        auxParams.put("pedersenHatN", task.zkSetup.hatN().toString(16));
        auxParams.put("pedersenS", task.zkSetup.h1().toString(16));
        auxParams.put("pedersenT", task.zkSetup.h2().toString(16));
        return auxParams;
    }

    /**
     * 广播预签名Round 1消息
     */
    CompletableFuture<Void> broadcastPresignR1(CggmpSignatureTask task,
                                               BigInteger K,
                                               BigInteger G,
                                               ECPoint Y,
                                               ECPoint A1,
                                               ECPoint A2,
                                               ECPoint B1,
                                               ECPoint B2,
                                               PiEncElgProof encElgK,
                                               PiEncElgProof encElgG) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("K", K.toString(16));
        data.put("G", G.toString(16));
        data.put("Y", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Y)));
        data.put("A1", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A1)));
        data.put("A2", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A2)));
        data.put("B1", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B1)));
        data.put("B2", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B2)));
        data.put("encElgProofK", CggmpCodecUtils.encodePiEncElgProof(encElgK));
        data.put("encElgProofG", CggmpCodecUtils.encodePiEncElgProof(encElgG));
        Map<String, Object> pkMap = CggmpCodecUtils.encodePaillierPublicKey(task.paillier.getPublicKeyInfo());
        Map<String, Object> zkMap = CggmpCodecUtils.encodeZkSetup(task.zkSetup);
        data.put("paillierPublicKey", pkMap);
        data.put("zkSetup", zkMap);
        if (task.paillier != null && task.zkSetup != null) {
            data.put("auxParams", buildAuxParamsFromPaillierAndZkSetup(task));
        }
        if (logger.isDebugEnabled()) {
            String pkHash = CggmpSignaturePresignHandler.hashJsonMap(pkMap);
            String zkHash = CggmpSignaturePresignHandler.hashJsonMap(zkMap);
            int pkBits = task.paillier == null || task.paillier.getPublicKeyInfo() == null ? -1 : task.paillier.getPublicKeyInfo().bitLength();
            logger.debug("Presign R1 send: taskId={}, senderId={}, pkHash={}, zkHash={}, pkBits={}",
                    task.taskId, svc.nodeId, pkHash, zkHash, pkBits);
        }
        return RetryUtils.retryAsync(svc.cggmpScheduler, logger,
                        () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_PRESIGN_R1, data)),
                        Constants.BROADCAST_RETRY_COUNT,
                        Constants.BROADCAST_RETRY_INTERVAL_MS,
                        "CGGMP_PRESIGN_R1")
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        logger.warn("Failed to broadcast CGGMP_PRESIGN_R1, proceeding: {}", ex.getMessage());
                    }
                });
    }

    /**
     * 广播预签名Round 1 Echo消息
     */
    CompletableFuture<Void> broadcastPresignR1Echo(CggmpSignatureTask task) {
        String hash = CggmpSignaturePresignHandler.computePresignR1EchoHash(task);
        if (hash == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Missing presign R1 data for echo"));
        }
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("hash", hash);
        NodeService.Message msg = new NodeService.Message(svc.nodeId, MessageType.CGGMP_PRESIGN_R1_ECHO, data);
        if (svc.presignUseRbc) {
            return svc.nodeService.broadcastRbc(msg);
        }
        return svc.nodeService.broadcastMessage(msg);
    }

    /**
     * 广播预签名Round 2消息
     */
    CompletableFuture<Void> broadcastPresignR2(CggmpSignatureTask task,
                                               ECPoint Gamma,
                                               BigIntIndexMap D,
                                               BigIntIndexMap Dhat,
                                               BigIntIndexMap F,
                                               BigIntIndexMap Fhat,
                                               AffGProofMap affG,
                                               AffGProofMap affGhat,
                                               PiLogProof logProof,
                                               ECPoint X) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("Gamma", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Gamma)));
        data.put("D", CggmpCodecUtils.encodeBigIntegerMap(D.toMap()));
        data.put("Dhat", CggmpCodecUtils.encodeBigIntegerMap(Dhat.toMap()));
        data.put("F", CggmpCodecUtils.encodeBigIntegerMap(F.toMap()));
        data.put("Fhat", CggmpCodecUtils.encodeBigIntegerMap(Fhat.toMap()));
        data.put("affGProofs", CggmpSignaturePresignHandler.encodeAffGProofMap(affG.toMap()));
        data.put("affGProofsHat", CggmpSignaturePresignHandler.encodeAffGProofMap(affGhat.toMap()));
        data.put("logProof", CggmpCodecUtils.encodePiLogProof(logProof));
        data.put("X", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(X)));
        return RetryUtils.retryAsync(svc.cggmpScheduler, logger,
                () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_PRESIGN_R2, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_PRESIGN_R2");
    }

    /**
     * 广播预签名Round 3消息
     */
    CompletableFuture<Void> broadcastPresignR3(CggmpSignatureTask task,
                                               BigInteger delta,
                                               ECPoint Delta,
                                               ECPoint S,
                                               PiLogProof logProof) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("delta", delta.toString(16));
        data.put("Delta", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Delta)));
        data.put("S", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(S)));
        data.put("logProof", CggmpCodecUtils.encodePiLogProof(logProof));
        return RetryUtils.retryAsync(svc.cggmpScheduler, logger,
                () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_PRESIGN_R3, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_PRESIGN_R3");
    }

    private void initSignaturePaillier(CggmpSignatureTask task) {
        if (task.paillier == null || task.zkSetup == null) {
            throw new RuntimeException("Paillier/ZKSetup not initialized for task " + task.taskId + ". This should have been done during task creation.");
        }
    }

    /**
     * 初始化签名上下文，加载Paillier和ZKSetup
     */
    public void initSignatureContext(CggmpSignatureTask task) {
        if (task.messageHash == null) {
            task.messageHash = CggmpProtocolUtils.hashMessage(task.message);
        }
        if (task.groupPublicKeyPoint == null) {
            task.groupPublicKeyPoint = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(task.groupPublicKey));
        }
        ensureKeyShareData(task);
    }

    private void ensureKeyShareData(CggmpSignatureTask task) {
        if (task.publicShares != null && task.indexMap != null) {
            return;
        }
        KeyShare keyShare = svc.keyShareService.findByGroupPublicKeySync(svc.nodeId, task.groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Signature key share loaded (taskId={}, nodeId={}, groupPublicKey={}, dkgTaskId={}, shareHash={})",
                    task.taskId,
                    svc.nodeId,
                    task.groupPublicKey,
                    keyShare.getDkgTaskId(),
                    HexUtils.sha256Hex(keyShare.getKeyShare()));
        }
        if (task.publicShares == null) {
            task.publicShares = DbMapUtils.parsePublicShares(keyShare.getPublicShares());
        }
        if (task.indexMap == null) {
            task.indexMap = DbMapUtils.parseIndexMap(keyShare.getIndexMap());
        }
        if (task.chainCode == null && keyShare.getChainCode() != null) {
            try {
                task.chainCode = DbMapUtils.decodeChainCode(keyShare.getChainCode());
            } catch (Exception e) {
                logger.warn("Failed to decode chain code for task {}: {}", task.taskId, e.getMessage());
            }
        }
    }

    /**
     * 发送离线阶段就绪消息
     */
    CompletableFuture<Void> sendOfflineReady(CggmpSignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        return svc.nodeService.sendMessage(task.initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_OFFLINE_READY, data));
    }

    /**
     * 标记节点离线阶段就绪
     */
    void markOfflineReady(CggmpSignatureTask task, int senderId) {
        if (task.offlineReady.putIfAbsent(senderId, Boolean.TRUE) == null) {
            if (task.offlineReadyLatch.getCount() > 0) {
                task.offlineReadyLatch.countDown();
            }
        }
    }

    /**
     * 处理离线签名初始化消息
     */
    void handleCggmpSignOfflineInit(int senderId, Object data) {
        if (data instanceof Map<?, ?> dataMap) {
            String signatureTaskId = (String) dataMap.get("signatureTaskId");
            String groupPublicKey = (String) dataMap.get("groupPublicKey");
            String msg = (String) dataMap.get("message");
            String auxTaskId = (String) dataMap.get("auxTaskId");
            Map<?, ?> auxParams = null;
            Object auxValue = dataMap.get("auxParams");
            if (auxValue instanceof Map<?, ?> m) {
                auxParams = m;
            }
            final Map<?, ?> auxParamsFinal = auxParams;
            Integer initiatorId = null;
            Object initiatorValue = dataMap.get("initiatorId");
            if (initiatorValue instanceof Number) {
                initiatorId = ((Number) initiatorValue).intValue();
            }
            if (auxParamsFinal != null) {
                String auxHash = CggmpSignaturePresignHandler.hashJsonMap(auxParamsFinal);
                logger.debug("Received OFFLINE_INIT AUX params (taskId={}, senderId={}, initiatorId={}, auxTaskId={}, auxHash={})",
                        signatureTaskId, senderId, initiatorId, auxTaskId, auxHash);
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
                    boolean isPresignTask = signatureTaskId.startsWith("presign-offline-");
                    svc.createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg, resolvedInitiatorId, participantsSet, auxTaskId, isPresignTask);
                    logger.debug("Created CGGMP signature task from OFFLINE_INIT: {} (initiator={}, participants={}, auxTaskId={}, isPresign={})",
                            signatureTaskId, resolvedInitiatorId, participantsSet, auxTaskId, isPresignTask);
                    CompletableFuture.runAsync(() -> {
                        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
                        if (task == null) {
                            return;
                        }
                        if (!task.participants.contains(svc.nodeId)) {
                            logger.info("Node {} not selected for CGGMP signature task {}, participants={}, skipping", svc.nodeId, signatureTaskId, task.participants);
                            svc.signatureInProgress.set(false);
                            return;
                        }
                        logger.debug("Starting offline phase from OFFLINE_INIT for task {} on node {}", signatureTaskId, svc.nodeId);
                        task.start();
                        if (auxParamsFinal == null) {
                            svc.broadcastComplaint(task, resolvedInitiatorId, "Missing AUX params (signature offline init)", Map.of("senderId", senderId));
                            svc.failSignatureTask(task, "Missing AUX params from initiator " + resolvedInitiatorId);
                            svc.signatureInProgress.set(false);
                            return;
                        }
                        Map<String, String> auxParamStrings = CggmpSignaturePresignHandler.coerceAuxParams(auxParamsFinal);
                        if (svc.ensurePeerAuxConsistency(task, resolvedInitiatorId, auxParamStrings)) {
                            svc.broadcastComplaint(task, resolvedInitiatorId, "Inconsistent AUX params (signature offline init)", Map.of("auxParams", auxParamsFinal));
                            svc.failSignatureTask(task, "Inconsistent AUX params from initiator " + resolvedInitiatorId);
                            svc.signatureInProgress.set(false);
                            return;
                        }
                        initSignatureContext(task);
                        svc.presignHandler.drainPendingPresignR1(task);
                        runOfflinePhase(task).exceptionally(ex -> {
                            logger.error("Failed offline phase for signature task {}: {}", signatureTaskId, ex.getMessage());
                            svc.signatureInProgress.set(false);
                            return null;
                        });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    logger.info("Signature task {} already exists, ignoring OFFLINE_INIT", signatureTaskId);
                }
            } else {
                logger.warn("Invalid OFFLINE_INIT payload from node {}", senderId);
            }
        }
    }

    /**
     * 处理离线签名就绪消息
     */
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
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        markOfflineReady(task, senderNodeId);
    }

    private CompletableFuture<Void> continuePresignAfterR2(CggmpPresignR2Bundle bundle) {
        if (bundle == null || bundle.ctx() == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Missing presign R2 bundle"));
        }
        CggmpPresignR2Context ctx = bundle.ctx();
        svc.presignHandler.waitForR2VerifyAndUpdateState(ctx.task());
        return svc.waitForLatchAsync(ctx.task().presignR2Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R2")
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        BigInteger delta_i = ctx.gamma_i().multiply(ctx.task().k_i).mod(ctx.curveOrder());
                        BigInteger chi_i = ctx.x_i().multiply(ctx.task().k_i).mod(ctx.curveOrder());
                        List<Integer> missingR3Peers = new ArrayList<>();
                        for (int peerId : ctx.task().participants) {
                            if (peerId == svc.nodeId) continue;
                            BigInteger D_ij = ctx.task().presignD.get(peerId);
                            BigInteger Dhat_ij = ctx.task().presignDhat.get(peerId);
                            BigInteger beta = ctx.task().presignBeta.get(peerId);
                            BigInteger betaHat = ctx.task().presignBetaHat.get(peerId);
                            if (D_ij == null || Dhat_ij == null || beta == null || betaHat == null) {
                                logger.warn("Presign R3 missing inputs for task {} peer {}: D={}, Dhat={}, beta={}, betaHat={}",
                                        ctx.task().taskId,
                                        peerId,
                                        D_ij == null ? null : D_ij.toString(16),
                                        Dhat_ij == null ? null : Dhat_ij.toString(16),
                                        beta == null ? null : beta.toString(16),
                                        betaHat == null ? null : betaHat.toString(16));
                                missingR3Peers.add(peerId);
                                continue;
                            }
                            BigInteger alpha = CggmpProtocolUtils.decodeSigned(ctx.task().paillier.decrypt(D_ij), ctx.task().paillier.getPublicKeyInfo().n());
                            BigInteger alphaHat = CggmpProtocolUtils.decodeSigned(ctx.task().paillier.decrypt(Dhat_ij), ctx.task().paillier.getPublicKeyInfo().n());
                            BigInteger oldDelta = delta_i;
                            BigInteger oldChi = chi_i;
                            delta_i = delta_i.add(alpha).add(beta).mod(ctx.curveOrder());
                            chi_i = chi_i.add(alphaHat).add(betaHat).mod(ctx.curveOrder());
                            logger.info("Presign R3 accumulate task {} peer {}: updated delta_i/chi_i (values redacted)",
                                    ctx.task().taskId,
                                    peerId);
                        }
                        if (!missingR3Peers.isEmpty()) {
                            throw new RuntimeException("Presign R3 missing inputs from peers: " + missingR3Peers);
                        }
                        ECPoint Gamma = CggmpProtocolUtils.sumPresignGamma(ctx.task());
                        ECPoint Delta_i = Gamma.multiply(ctx.task().k_i).normalize();
                        ECPoint S_i = Gamma.multiply(chi_i).normalize();
                        ctx.task().presignDelta.put(svc.nodeId, delta_i);
                        ctx.task().presignDeltaPoint.put(svc.nodeId, Delta_i);
                        ctx.task().presignSPoint.put(svc.nodeId, S_i);
                        byte[] ctxR3 = CggmpProtocolUtils.buildPresignContext(ctx.task().taskId, svc.nodeId, "R3");
                        ECPoint Y_i_r3 = ctx.task().presignY.get(svc.nodeId);
                        ECPoint A1_r3 = ctx.task().presignA1.get(svc.nodeId);
                        ECPoint A2_r3 = ctx.task().presignA2.get(svc.nodeId);
                        if (Y_i_r3 == null || A1_r3 == null || A2_r3 == null || ctx.task().presignAScalar == null) {
                            throw new RuntimeException("Missing presign R1 commitments for PiLog proof (R3)");
                        }
                        PiLogProof logProofR3 = PresignProofs.createLogProof(
                                Secp256k1CurveUtils.G(),
                                Gamma,
                                Delta_i,
                                Y_i_r3,
                                A1_r3,
                                A2_r3,
                                ctx.task().k_i,
                                ctx.task().presignAScalar,
                                ctxR3
                        );
                        CggmpProtocolUtils.fireAndForget(broadcastPresignR3(ctx.task(), delta_i, Delta_i, S_i, logProofR3),
                                logger, "CGGMP_PRESIGN_R3");
                        return new CggmpPresignR3Context(ctx, delta_i, chi_i, Gamma);
                    } catch (Exception e) {
                        ctx.task().fail(e.getMessage());
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(r3ctx -> svc.waitForLatchAsync(ctx.task().offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "presign R3")
                        .thenRunAsync(() -> finalizePresign(r3ctx), ThreadPoolUtil.getIoThreadPool()));
    }

    /**
     * 完成预签名，验证delta并生成预签名分片
     */
    void finalizePresign(CggmpPresignR3Context r3ctx) {
        CggmpPresignR2Context ctx = r3ctx.ctx();
        BigInteger delta = CggmpProtocolUtils.sumShares(ctx.task().presignDelta, ctx.curveOrder());
        ECPoint left = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), delta);
        ECPoint right = Secp256k1CurveUtils.sumPoints(ctx.task().presignDeltaPoint);
        if (!left.equals(right)) {
            logger.warn("Presign delta verification mismatch for task {}: left={}, right={}, delta=<redacted>, participants={}",
                    ctx.task().taskId,
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(left)),
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(right)),
                    ctx.task().participants);
            Map<String, Object> evidence = svc.evidenceHandler.buildDecEvidenceDelta(ctx.task(), ctx.gamma_i(), r3ctx.delta_i());
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(ctx.task(), null, "Presign delta verification failed", evidence),
                    logger, "CGGMP_PRESIGN_DELTA_COMPLAINT");
            svc.failSignatureTask(ctx.task(), "Presign delta verification failed");
            return;
        }
        ECPoint X = ctx.task().groupPublicKeyPoint;
        ECPoint leftS = X.multiply(delta).normalize();
        ECPoint rightS = Secp256k1CurveUtils.sumPoints(ctx.task().presignSPoint);
        if (!leftS.equals(rightS)) {
            logger.warn("Presign chi verification mismatch for task {}: leftS={}, rightS={}, delta=<redacted>, participants={}",
                    ctx.task().taskId,
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(leftS)),
                    HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(rightS)),
                    ctx.task().participants);
            logger.warn("Presign chi mismatch summary task {}: presignDelta.size={}, presignSPoint.size={}, presignDeltaPoint.size={}",
                    ctx.task().taskId,
                    ctx.task().presignDelta.size(),
                    ctx.task().presignSPoint.size(),
                    ctx.task().presignDeltaPoint.size());
            for (int peerId : ctx.task().participants) {
                ECPoint sPoint = ctx.task().presignSPoint.get(peerId);
                BigInteger deltaShare = ctx.task().presignDelta.get(peerId);
                if (sPoint == null && deltaShare == null) {
                    continue;
                }
                logger.warn("Presign chi mismatch details task {} peer {}: S_i=<redacted>, delta_i=<redacted>",
                        ctx.task().taskId,
                        peerId);
            }
            // Identify which peer contribution breaks the chi check by excluding it.
            for (int peerId : ctx.task().participants) {
                ECPoint sPoint = ctx.task().presignSPoint.get(peerId);
                BigInteger deltaShare = ctx.task().presignDelta.get(peerId);
                if (sPoint == null || deltaShare == null) {
                    continue;
                }
                BigInteger deltaEx = delta.subtract(deltaShare).mod(ctx.curveOrder());
                ECPoint leftEx = X.multiply(deltaEx).normalize();
                ECPoint rightEx = null;
                for (Map.Entry<Integer, ECPoint> e : ctx.task().presignSPoint.entrySet()) {
                    if (e.getKey() == peerId) {
                        continue;
                    }
                    rightEx = rightEx == null ? e.getValue() : rightEx.add(e.getValue());
                }
                if (rightEx != null) {
                    rightEx = rightEx.normalize();
                }
                boolean matchesEx = rightEx != null && leftEx.equals(rightEx);
                logger.warn("Presign chi mismatch isolate task {} peer {}: excludePeerMatch={}, leftEx={}, rightEx={}",
                        ctx.task().taskId,
                        peerId,
                        matchesEx,
                        HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(leftEx)),
                        rightEx == null ? null : HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(rightEx)));
            }
            Map<String, Object> evidence = svc.evidenceHandler.buildDecEvidenceChi(ctx.task(), ctx.x_i(), r3ctx.chi_i());
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(ctx.task(), null, "Presign chi verification failed", evidence),
                    logger, "CGGMP_PRESIGN_CHI_COMPLAINT");
            svc.failSignatureTask(ctx.task(), "Presign chi verification failed");
            return;
        }
        BigInteger deltaInv = delta.modInverse(ctx.curveOrder());
        ECPoint GammaFinal = r3ctx.Gamma().normalize();
        BigInteger kTilde = ctx.task().k_i.multiply(deltaInv).mod(ctx.curveOrder());
        BigInteger chiTilde = r3ctx.chi_i().multiply(deltaInv).mod(ctx.curveOrder());
        
        for (Map.Entry<Integer, ECPoint> e : ctx.task().presignDeltaPoint.entrySet()) {
            ctx.task().presignDeltaTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }
        for (Map.Entry<Integer, ECPoint> e : ctx.task().presignSPoint.entrySet()) {
            ctx.task().presignSTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
        }
        
        String presignId = ctx.task().taskId;
        ctx.task().presignature = new Presignature(presignId, GammaFinal, kTilde, chiTilde, 
            new java.util.HashMap<>(ctx.task().presignDeltaTilde), 
            new java.util.HashMap<>(ctx.task().presignSTilde));
        ctx.task().presignatureLatch.countDown();

        if (ctx.task().taskId.startsWith("presign-offline-") && ctx.task().presignature != null) {
            svc.presignPoolService.addPresignToPool(ctx.task().groupPublicKey, ctx.task().presignature);
            logger.info("Added presignature to pool for task {} (nodeId={})", ctx.task().taskId, svc.nodeId);
        }

        if (svc.nodeId == ctx.task().initiatorId) {
            markOfflineReady(ctx.task(), svc.nodeId);
        } else {
            CggmpProtocolUtils.fireAndForget(sendOfflineReady(ctx.task()), logger, "CGGMP_SIGN_OFFLINE_READY");
        }
    }

    private BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = svc.keyShareService.findByGroupPublicKeySync(svc.nodeId, groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Signature local share loaded (nodeId={}, groupPublicKey={}, dkgTaskId={}, shareHash={})",
                    svc.nodeId,
                    groupPublicKey,
                    keyShare.getDkgTaskId(),
                    HexUtils.sha256Hex(keyShare.getKeyShare()));
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1CurveUtils.n());
    }
}
