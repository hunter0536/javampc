package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofGenerator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofGenerator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.dto.CggmpAuxTask;
import com.example.mpc.enums.MessageType;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;

/**
 * CGGMP辅助密钥协议处理器
 * 负责执行辅助密钥生成协议的Round 1-2
 */
public final class CggmpAuxProtocolHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpAuxProtocolHandler.class);
    private static final ExecutorService auxExecutorService = com.example.mpc.common.util.ThreadPoolUtil.getAuxThreadPool();

    private final CggmpAuxService svc;

    public CggmpAuxProtocolHandler(CggmpAuxService svc) {
        this.svc = svc;
    }

    /**
     * 异步执行辅助密钥生成协议
     */
    public CompletableFuture<Void> runAuxProtocolAsync(CggmpAuxTask task) {
        final long auxStartNs = System.nanoTime();
        logger.debug("AUX protocol starting: taskId={}, executionId={}", task.taskId, task.executionId);
        return CompletableFuture.supplyAsync(() -> {
                    logger.debug("AUX protocol running: taskId={}, executionId={}", task.taskId, task.executionId);

                    // 并行执行Paillier密钥生成和Pedersen/ZK setup
                    long paillierStart = System.nanoTime();
                    CompletableFuture<PaillierEncryption> paillierFuture = CompletableFuture.supplyAsync(() -> {
                        PaillierEncryption p = new PaillierEncryption(svc.auxPaillierBits);
                        logger.debug("AUX Paillier generated in {} ms (bits={})", (System.nanoTime() - paillierStart) / 1_000_000, svc.auxPaillierBits);
                        return p;
                    }, auxExecutorService);

                    long pedStart = System.nanoTime();
                    CompletableFuture<ZKSetup.ZKSetupWithLambda> pedFuture = CompletableFuture.supplyAsync(() -> {
                        ZKSetup.ZKSetupWithLambda ped = ZKSetup.generateWithLambda(svc.auxPaillierBits);
                        logger.debug("AUX Pedersen/ZK setup generated in {} ms (bits={})", (System.nanoTime() - pedStart) / 1_000_000, svc.auxPaillierBits);
                        return ped;
                    }, auxExecutorService);

                    // 等待两个任务完成
                    PaillierEncryption paillier = paillierFuture.join();
                    ZKSetup.ZKSetupWithLambda ped = pedFuture.join();

                    task.paillier = paillier;
                    task.hatN = ped.zk().hatN();
                    task.s = ped.zk().h1();
                    task.t = ped.zk().h2();
                    task.pedersenLambda = ped.lambda();

                    byte[] rho_i = CggmpProtocolUtils.randomBytes(32);
                    byte[] u_i = CggmpProtocolUtils.randomBytes(32);
                    task.rho.put(svc.nodeId, rho_i);
                    task.u.put(svc.nodeId, u_i);

                    long prmStart = System.nanoTime();
                    logger.debug("AUX PRM proof start: taskId={}, executionId={}, senderId={}", task.taskId, task.executionId, svc.nodeId);
                    PiPrmProof prmProof = RefreshProofs.createPrmProof(task.hatN, task.s, task.t, task.pedersenLambda,
                            CggmpProtocolUtils.buildAuxContext(task.taskId, task.executionId, svc.nodeId, "PRM"));
                    if (logger.isDebugEnabled()) {
                        logger.debug("AUX PRM proof inputs: taskId={}, executionId={}, senderId={}, hatNBits={}, sBits={}, tBits={}, lambdaBits={}, lambdaSign={}",
                                task.taskId,
                                task.executionId,
                                svc.nodeId,
                                task.hatN == null ? -1 : task.hatN.bitLength(),
                                task.s == null ? -1 : task.s.bitLength(),
                                task.t == null ? -1 : task.t.bitLength(),
                                task.pedersenLambda == null ? -1 : task.pedersenLambda.bitLength(),
                                task.pedersenLambda == null ? 0 : task.pedersenLambda.signum());
                        byte[] prmCtx = CggmpProtocolUtils.buildAuxContext(task.taskId, task.executionId, svc.nodeId, "PRM");
                        boolean selfOk = RefreshProofs.verifyPrmProof(prmProof, task.hatN, task.s, task.t, prmCtx);
                        String ctxHash;
                        try {
                            ctxHash = HexUtils.bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(prmCtx));
                        } catch (Exception e) {
                            ctxHash = "error";
                        }
                        String aHex = prmProof.A() == null ? null : prmProof.A().toString(16);
                        String zHex = prmProof.z() == null ? null : prmProof.z().toString(16);
                        logger.debug("AUX PRM proof self-verify: taskId={}, executionId={}, senderId={}, ok={}, ctxHash={}, ctxPrefix={}, A.prefix={}, z.prefix={}",
                                task.taskId,
                                task.executionId,
                                svc.nodeId,
                                selfOk,
                                ctxHash,
                                HexUtils.bytesToHex(prmCtx).substring(0, Math.min(24, prmCtx.length * 2)),
                                aHex == null ? null : aHex.substring(0, Math.min(24, aHex.length())),
                                zHex == null ? null : zHex.substring(0, Math.min(24, zHex.length())));
                    }
                    logger.debug("AUX PRM proof generated in {} ms (taskId={}, executionId={}, senderId={})",
                            (System.nanoTime() - prmStart) / 1_000_000, task.taskId, task.executionId, svc.nodeId);
                    task.prmProof = prmProof;

                    String vCommit = CggmpProtocolUtils.computeAuxCommitHash(task.executionId, task.taskId, svc.nodeId,
                            CggmpCodecUtils.encodePaillierPublicKey(paillier.getPublicKeyInfo()),
                            task.hatN.toString(16), task.s.toString(16), task.t.toString(16),
                            CggmpCodecUtils.encodePiPrmProof(prmProof), rho_i, u_i);
                    task.commitHashes.put(svc.nodeId, vCommit);
                    task.commitLatch.countDown();

                    Map<String, Object> r1 = new HashMap<>();
                    r1.put("taskId", task.taskId);
                    r1.put("executionId", task.executionId);
                    r1.put("senderId", svc.nodeId);
                    r1.put("V", vCommit);
                    logger.debug("AUX R1 broadcast: taskId={}, executionId={}, senderId={}, V.len={}",
                            task.taskId, task.executionId, svc.nodeId, vCommit.length());
                    CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R1, r1)),
                            logger, "CGGMP_AUX_R1_RBC");
                    return new CggmpAuxContext(task, paillier, prmProof, rho_i, u_i);
                }, auxExecutorService)
                .thenCompose(ctx -> CggmpAuxUtils.waitForLatchAsync(svc, task, task.commitLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R1")
                        .exceptionally(ex -> {
                            CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R1, Map.of(
                                    "taskId", task.taskId,
                                    "executionId", task.executionId,
                                    "senderId", svc.nodeId,
                                    "V", task.commitHashes.get(svc.nodeId)
                            ))), logger, "CGGMP_AUX_R1_RBC_RETRY");
                            throw new CompletionException(ex);
                        })
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    String echo = CggmpProtocolUtils.computeAuxEchoHash(task);
                    task.echoReceived.put(svc.nodeId, Boolean.TRUE);
                    task.echoLatch.countDown();
                    Map<String, Object> r1Echo = new HashMap<>();
                    r1Echo.put("taskId", task.taskId);
                    r1Echo.put("executionId", task.executionId);
                    r1Echo.put("senderId", svc.nodeId);
                    r1Echo.put("hash", echo);
                    CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R1_ECHO, r1Echo)),
                            logger, "CGGMP_AUX_R1_ECHO");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> CggmpAuxUtils.waitForLatchAsync(svc, task, task.echoLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R1 echo")
                        .exceptionally(ex -> {
                            String echo = CggmpProtocolUtils.computeAuxEchoHash(task);
                            Map<String, Object> r1Echo = new HashMap<>();
                            r1Echo.put("taskId", task.taskId);
                            r1Echo.put("executionId", task.executionId);
                            r1Echo.put("senderId", svc.nodeId);
                            r1Echo.put("hash", echo);
                            logger.debug("AUX R1 echo retry: taskId={}, executionId={}, senderId={}, hash.len={}",
                                    task.taskId, task.executionId, svc.nodeId, echo.length());
                            CggmpProtocolUtils.fireAndForget(svc.nodeService.broadcastRbc(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R1_ECHO, r1Echo)),
                                    logger, "CGGMP_AUX_R1_ECHO_RETRY");
                            throw new CompletionException(ex);
                        })
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    task.peerPaillierKeys.put(svc.nodeId, ctx.paillier().getPublicKeyInfo());
                    task.peerHatN.put(svc.nodeId, task.hatN);
                    task.peerS.put(svc.nodeId, task.s);
                    task.peerT.put(svc.nodeId, task.t);
                    task.peerPrmProofs.put(svc.nodeId, ctx.prmProof());
                    task.revealLatch.countDown();
                    Map<String, Object> r2 = new HashMap<>();
                    r2.put("taskId", task.taskId);
                    r2.put("executionId", task.executionId);
                    r2.put("senderId", svc.nodeId);
                    r2.put("paillierPublicKey", CggmpCodecUtils.encodePaillierPublicKey(ctx.paillier().getPublicKeyInfo()));
                    r2.put("hatN", task.hatN.toString(16));
                    r2.put("s", task.s.toString(16));
                    r2.put("t", task.t.toString(16));
                    r2.put("prmProof", CggmpCodecUtils.encodePiPrmProof(ctx.prmProof()));
                    r2.put("rho", HexUtils.bytesToHex(ctx.rho()));
                    r2.put("u", HexUtils.bytesToHex(ctx.u()));
                    logger.debug("AUX R2 broadcast: taskId={}, executionId={}, senderId={}", task.taskId, task.executionId, svc.nodeId);
                    CggmpProtocolUtils.fireAndForget(RetryUtils.retryAsync(svc.auxScheduler, logger,
                                    () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R2, r2)),
                                    Constants.BROADCAST_RETRY_COUNT,
                                    Constants.BROADCAST_RETRY_INTERVAL_MS,
                                    "CGGMP_AUX_R2"),
                            logger, "CGGMP_AUX_R2");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> CggmpAuxUtils.waitForLatchAsync(svc, task, task.revealLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R2")
                        .thenApply(v -> ctx))
                .thenCompose(ctx -> CompletableFuture.runAsync(() -> {
                    byte[] rho = CggmpAuxUtils.xorAuxRho(task);
                    byte[] modCtx = CggmpProtocolUtils.buildAuxContext(task.taskId, task.executionId, svc.nodeId, "MOD", rho);
                    long modProofStart = System.nanoTime();
                    BiPrimeBlumProof modProof = new BiPrimeProofGenerator().createProof(ctx.paillier().getPrivateKeyInfo(), modCtx);
                    logger.debug("AUX mod proof generated in {} ms", (System.nanoTime() - modProofStart) / 1_000_000);
                    task.peerModProofs.put(svc.nodeId, modProof);
                    Map<String, Object> facProofs = new HashMap<>();
                    for (int peerId : task.participants) {
                        if (peerId == svc.nodeId) continue;
                        java.math.BigInteger hatN = task.peerHatN.get(peerId);
                        java.math.BigInteger s = task.peerS.get(peerId);
                        java.math.BigInteger t = task.peerT.get(peerId);
                        if (hatN == null || s == null || t == null) {
                            continue;
                        }
                        ZKSetup zk = new ZKSetup(hatN, s, t);
                        long facStart = System.nanoTime();
                        NoSmallFactorProof facProof = new NoSmallFactorProofGenerator(zk).createProof(ctx.paillier().getPrivateKeyInfo(), modCtx);
                        logger.debug("AUX fac proof generated for peer {} in {} ms", peerId, (System.nanoTime() - facStart) / 1_000_000);
                        facProofs.put(String.valueOf(peerId), CggmpCodecUtils.encodeNoSmallFactorProof(facProof));
                    }
                    task.proofLatch.countDown();
                    Map<String, Object> r3 = new HashMap<>();
                    r3.put("taskId", task.taskId);
                    r3.put("executionId", task.executionId);
                    r3.put("senderId", svc.nodeId);
                    r3.put("modProof", CggmpCodecUtils.encodeBiPrimeProof(modProof));
                    r3.put("facProofs", facProofs);
                    logger.debug("AUX R3 broadcast: taskId={}, executionId={}, senderId={}, facProofs={}",
                            task.taskId, task.executionId, svc.nodeId, facProofs.size());
                    CggmpProtocolUtils.fireAndForget(RetryUtils.retryAsync(svc.auxScheduler, logger,
                                    () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_R3, r3)),
                                    Constants.BROADCAST_RETRY_COUNT,
                                    Constants.BROADCAST_RETRY_INTERVAL_MS,
                                    "CGGMP_AUX_R3"),
                            logger, "CGGMP_AUX_R3");
                }, auxExecutorService).thenApply(v -> ctx))
                .thenCompose(ctx -> CggmpAuxUtils.waitForLatchAsync(svc, task, task.proofLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX R3")
                        .thenApply(v -> ctx))
                .thenRunAsync(() -> {
                    CggmpAuxUtils.saveAuxInfo(svc, task);
                    task.savedReceived.put(svc.nodeId, Boolean.TRUE);
                    task.savedLatch.countDown();
                    Map<String, Object> saved = new HashMap<>();
                    saved.put("taskId", task.taskId);
                    saved.put("executionId", task.executionId);
                    saved.put("senderId", svc.nodeId);
                    CggmpProtocolUtils.fireAndForget(RetryUtils.retryAsync(svc.auxScheduler, logger,
                                    () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_AUX_SAVED, saved)),
                                    Constants.BROADCAST_RETRY_COUNT,
                                    Constants.BROADCAST_RETRY_INTERVAL_MS,
                                    "CGGMP_AUX_SAVED"),
                            logger, "CGGMP_AUX_SAVED");
                    logger.debug("AUX saved broadcast: taskId={}, executionId={}, senderId={}",
                            task.taskId, task.executionId, svc.nodeId);
                }, auxExecutorService)
                .thenCompose(v -> CggmpAuxUtils.waitForLatchAsync(svc, task, task.savedLatch, Constants.AUX_ROUND_TIMEOUT_SECONDS, "AUX SAVED"))
                .thenRunAsync(() -> {
                    logger.debug("AUX protocol completed in {} ms", (System.nanoTime() - auxStartNs) / 1_000_000);
                }, auxExecutorService);
    }
}
