package com.example.mpc.service.cggmp.signature;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.sign.CggmpIntegrityChecker;
import com.example.mpc.cggmp.sign.EcChaumPedersenProof;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.RetryUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.dto.CggmpSignatureTask;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * CGGMP签名在线阶段处理器
 * 负责执行实际签名计算，生成最终签名
 */
public final class CggmpSignatureOnlineHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureOnlineHandler.class);
    private final CggmpSignatureService svc;

    public CggmpSignatureOnlineHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    private void logProgress(CggmpSignatureTask task, String stage) {
        if (task == null || !logger.isDebugEnabled()) {
            return;
        }
        int participants = Math.max(0, task.participants.size() - 1);
        long gammaCommit = participants - task.gammaCommitLatch.getCount();
        long gammaOpen = participants - task.gammaLatch.getCount();
        long presignR1Echo = participants - task.presignR1EchoLatch.getCount();
        long presignR2 = participants - task.presignR2Latch.getCount();
        long kaInit = participants - task.kaInitLatch.getCount();
        long kaResp = participants - task.kaResponseLatch.getCount();
        long uCommit = participants - task.uCommitLatch.getCount();
        long uShare = participants - task.uShareLatch.getCount();
        long uOpen = participants - task.uOpenLatch.getCount();
        long stInit = participants - task.stInitLatch.getCount();
        long stResp = participants - task.stResponseLatch.getCount();
        long sShare = participants - task.sShareLatch.getCount();
        logger.debug("Signature progress [{}] taskId={} gammaCommit={}/{}, gammaOpen={}/{}, presignR1Echo={}/{}, presignR2={}/{}, kaInit={}/{}, kaResp={}/{}, uCommit={}/{}, uShare={}/{}, uOpen={}/{}, stInit={}/{}, stResp={}/{}, sShare={}/{}",
                stage,
                task.taskId,
                gammaCommit, participants,
                gammaOpen, participants,
                presignR1Echo, participants,
                presignR2, participants,
                kaInit, participants,
                kaResp, participants,
                uCommit, participants,
                uShare, participants,
                uOpen, participants,
                stInit, participants,
                stResp, participants,
                sShare, participants);
    }

    /**
     * 执行签名在线阶段，生成最终签名
     */
    public CompletableFuture<Void> runOnlinePhase(CggmpSignatureTask task) {
        logger.debug("Signature online phase start for task {} (node={}, initiator={})",
                task.taskId, svc.nodeId, task.initiatorId);
        return svc.waitForLatchAsync(task.offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline phase")
                .thenCompose(v -> svc.waitForLatchAsync(task.presignatureLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "local presignature"))
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        if (task.messageHash == null) {
                            throw new RuntimeException("Missing message hash for online phase");
                        }
                        if (logger.isDebugEnabled()) {
                            logger.debug("Online phase inputs: taskId={}, messageHash={}, presignatureReady={}, offlineDoneLatch={}",
                                    task.taskId,
                                    HexUtils.bytesToHex(task.messageHash),
                                    task.presignature != null,
                                    task.offlineDoneLatch.getCount());
                        }

                        BigInteger curveOrder = Secp256k1CurveUtils.n();
                        if (task.presignature == null) {
                            throw new RuntimeException("Missing presignature");
                        }
                        if (task.presignatureUsed) {
                            throw new RuntimeException("Presignature already used");
                        }
                        if (svc.nodeId == task.initiatorId) {
                            if (!PresignUsageStore.markUsed(task.groupPublicKey, task.presignature.Gamma())) {
                                throw new RuntimeException("Presignature already used (persistent)");
                            }
                        }
                        task.presignatureUsed = true;
                        ECPoint Gamma = task.presignature.Gamma();
                        task.r = Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
                        if (task.r.signum() == 0) {
                            throw new RuntimeException("Invalid r (zero), restart signature");
                        }
                        logger.debug("Online phase r computed for task {} (r={})", task.taskId, task.r.toString(16));

                        BigInteger e = new BigInteger(1, task.messageHash).mod(curveOrder);
                        BigInteger chiTilde = task.presignature.chiTilde();
                        BigInteger shift = resolveSignShift(task, curveOrder);
                        if (shift.signum() != 0) {
                            chiTilde = chiTilde.add(task.presignature.kTilde().multiply(shift)).mod(curveOrder);
                        }
                        BigInteger sigma_i = task.presignature.kTilde().multiply(e).add(task.r.multiply(chiTilde)).mod(curveOrder);
                        return new CggmpOnlineContext(task, curveOrder, sigma_i);
                    } catch (Exception e) {
                        task.fail(e.getMessage());
                        svc.signatureInProgress.set(false);
                        svc.clearPresignAll(task);
                        throw new RuntimeException(e);
                    }
                }, ThreadPoolUtil.getIoThreadPool()))
                .thenCompose(ctx -> {
                    if (svc.nodeId == ctx.task().initiatorId) {
                        if (!verifySigmaShare(ctx.task(), svc.nodeId, ctx.sigma_i())) {
                            svc.failSignatureTask(ctx.task(), "Local signature share verification failed");
                            svc.signatureInProgress.set(false);
                            svc.clearPresignAll(ctx.task());
                            return CompletableFuture.completedFuture(null);
                        }
                        ctx.task().sShares.put(svc.nodeId, ctx.sigma_i());
                        return svc.waitForLatchAsync(ctx.task().sShareLatch, Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, "signature shares")
                                .thenRunAsync(() -> finalizeSignatureAsInitiator(ctx), ThreadPoolUtil.getIoThreadPool());
                    }
                    return CompletableFuture.runAsync(() -> {
                        CggmpProtocolUtils.fireAndForget(sendSShare(ctx.task(), ctx.sigma_i()), logger, "CGGMP_SIGN_S_SHARE");
                        ctx.task().complete();
                        svc.signatureInProgress.set(false);
                        svc.clearPresignLocal(ctx.task());
                    }, ThreadPoolUtil.getIoThreadPool());
                })
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        logger.debug("Signature online phase completed for task {}", task.taskId);
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    String msg = cause == null ? ex.getMessage() : cause.getMessage();
                    task.fail(msg);
                    svc.signatureInProgress.set(false);
                    svc.clearPresignAll(task);
                });
    }

    /**
     * 处理在线签名初始化消息
     */
    void handleCggmpSignOnlineInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object hashValue = dataMap.get("messageHash");
        if (signatureTaskId == null || !(hashValue instanceof String hashString)) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        task.messageHash = Base64.getDecoder().decode(hashString);
        logger.debug("Received ONLINE_INIT (taskId={}, senderId={}, messageHash={})",
                signatureTaskId, senderId, HexUtils.bytesToHex(task.messageHash));
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        logProgress(task, "online_init");
        runOnlinePhase(task).exceptionally(ex -> {
            logger.error("Failed online phase for signature task {}: {}", signatureTaskId, ex.getMessage());
            return null;
        });
    }

    public CompletableFuture<Void> broadcastOnlineInit(CggmpSignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("messageHash", Base64.getEncoder().encodeToString(task.messageHash));
        return RetryUtils.retryAsync(svc.cggmpScheduler, logger,
                        () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_ONLINE_INIT, data)),
                        Constants.BROADCAST_RETRY_COUNT,
                        Constants.BROADCAST_RETRY_INTERVAL_MS,
                        "CGGMP_SIGN_ONLINE_INIT")
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        logger.warn("Failed to broadcast CGGMP_SIGN_ONLINE_INIT, proceeding: {}", ex.getMessage());
                    }
                });
    }

    /**
     * 处理Gamma承诺消息
     */
    void handleCggmpSignGammaCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commitHex = (String) dataMap.get("commit");
        String proofAHex = (String) dataMap.get("proofA");
        String proofRHex = (String) dataMap.get("proofR");
        String proofSHex = (String) dataMap.get("proofS");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commitHex == null || proofAHex == null || proofRHex == null || proofSHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == svc.nodeId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint commitment = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(commitHex));
            ECPoint proofA = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(proofAHex));
            BigInteger proofR = new BigInteger(proofRHex, 16);
            BigInteger proofS = new BigInteger(proofSHex, 16);
            EcChaumPedersenProof proof = new EcChaumPedersenProof(proofA, proofR, proofS);
            byte[] ctx = CggmpProtocolUtils.buildSignContext(task.taskId, senderId, task.messageHash, "GAMMA-COMMIT");
            if (!CggmpIntegrityChecker.verifyGammaCommitment(proof, commitment, ctx)) {
                logger.warn("Invalid gamma commitment proof from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("commit", commitHex);
                evidence.put("proofA", proofAHex);
                evidence.put("proofR", proofRHex);
                evidence.put("proofS", proofSHex);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma commitment proof", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma commitment proof");
                return;
            }
            if (task.gammaCommitments.containsKey(senderId)) {
                logger.warn("Duplicate gamma commitment from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaCommitments.put(senderId, commitment);
            if (task.gammaCommitLatch.getCount() > 0) {
                task.gammaCommitLatch.countDown();
            }
            logger.debug("Gamma commit stored (taskId={}, senderId={}, gammaCommitLatch={})",
                    taskId, senderId, task.gammaCommitLatch.getCount());
            logProgress(task, "gamma_commit");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_COMMIT from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理Gamma公开消息，验证承诺并计算R点
     */
    void handleCggmpSignGammaOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String gammaHex = (String) dataMap.get("gamma");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || gammaHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == svc.nodeId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint gamma = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(gammaHex));
            BigInteger r = new BigInteger(rHex, 16);
            ECPoint commitment = task.gammaCommitments.get(senderId);
            if (commitment == null) {
                logger.warn("Missing gamma commitment for node {} in task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Missing gamma commitment", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing gamma commitment");
                return;
            }
            if (!CggmpIntegrityChecker.isValidGammaPoint(gamma)) {
                logger.warn("Invalid gamma point from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma point", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma point");
                return;
            }
            if (!CggmpIntegrityChecker.verifyGammaOpen(commitment, gamma, r)) {
                logger.warn("Invalid gamma commitment opening from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                evidence.put("r", rHex);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma commitment opening", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma commitment opening");
                return;
            }
            if (task.gammaPoints.containsKey(senderId)) {
                logger.warn("Duplicate gamma open from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaPoints.put(senderId, gamma);
            if (task.gammaLatch.getCount() > 0) {
                task.gammaLatch.countDown();
            }
            logger.debug("Gamma open stored (taskId={}, senderId={}, gammaLatch={})",
                    taskId, senderId, task.gammaLatch.getCount());
            logProgress(task, "gamma_open");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_OPEN from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理MtA-Ka协议初始化消息
     */
    void handleCggmpSignMtaKaInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != svc.nodeId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(svc.nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            logger.debug("KA init received (taskId={}, initiatorId={}, receiverId={})", taskId, initiatorId, receiverId);
            PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpCodecUtils.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpCodecUtils.decodeMtAInitiatorMessage(msgMap);
            if (!CggmpSignatureKeyValidator.ensurePeerKeyMatchesAux(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("AUX params mismatch with Paillier/zkSetup for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("auxHash", CggmpSignatureKeyValidator.computeAuxHash(task.peerAuxParams.get(initiatorId)));
                evidence.put("pkHash", CggmpSignatureKeyValidator.computePkHash(publicKey));
                evidence.put("zkHash", CggmpSignatureKeyValidator.computeZkHash(zkSetup));
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "AUX params mismatch with Paillier/zkSetup (KA)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "AUX params mismatch with Paillier/zkSetup (KA)");
                return;
            }
            if (!CggmpSignatureKeyValidator.validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid Paillier public key (KA)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid Paillier public key (KA)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Missing KA MtA initiator proofs", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing KA MtA initiator proofs");
                return;
            }
            if (!CggmpSignatureKeyValidator.ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (KA)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (KA)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1CurveUtils.n());
            byte[] mtaContext = CggmpProtocolUtils.buildMtaContext(taskId + ":KA", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid KA MtA initiator proofs", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid KA MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.a_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.kaBetas.put(initiatorId, beta);
            if (task.kaInitLatch.getCount() > 0) {
                task.kaInitLatch.countDown();
            }
            logger.debug("KA init stored (taskId={}, initiatorId={}, kaInitLatch={})",
                    taskId, initiatorId, task.kaInitLatch.getCount());
            logProgress(task, "ka_init");

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", svc.nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpCodecUtils.encodeMtAResult(publicResult));
            CggmpProtocolUtils.fireAndForget(svc.nodeService.sendMessage(initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_MTA_KA_RESPONSE, resp)),
                    logger, "CGGMP_SIGN_MTA_KA_RESPONSE");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理MtA-Ka协议响应消息
     */
    void handleCggmpSignMtaKaResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != svc.nodeId || responderId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpCodecUtils.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaKaInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, responderId, "Missing KA MtA respondent proof", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing KA MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1CurveUtils.n());
            byte[] mtaContext = CggmpProtocolUtils.buildMtaContext(taskId + ":KA", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, responderId, "Invalid KA MtA respondent proof", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid KA MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1CurveUtils.n());
            task.kaAlphas.put(responderId, alpha);
            if (task.kaResponseLatch.getCount() > 0) {
                task.kaResponseLatch.countDown();
            }
            logger.debug("KA response stored (taskId={}, responderId={}, kaResponseLatch={})",
                    taskId, responderId, task.kaResponseLatch.getCount());
            logProgress(task, "ka_resp");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理U分片消息
     */
    void handleCggmpSignUShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        try {
            BigInteger u = new BigInteger(uHex, 16);
            BigInteger r = new BigInteger(rHex, 16);
            String commit = task.uCommitments.get(senderId);
            if (commit == null) {
                logger.warn("Missing u commitment from node {} for task {}", senderId, taskId);
                return;
            }
            String expected = commitU(taskId, senderId, task.messageHash, u, r);
            if (!commit.equals(expected)) {
                logger.warn("Invalid u commitment opening from node {} for task {}", senderId, taskId);
                return;
            }
            task.uShares.put(senderId, u);
            if (task.uShareLatch.getCount() > 0) {
                task.uShareLatch.countDown();
            }
            logger.debug("U share stored (taskId={}, senderId={}, uShareLatch={})",
                    taskId, senderId, task.uShareLatch.getCount());
            logProgress(task, "u_share");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_U_SHARE from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理U公开消息
     */
    void handleCggmpSignUOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        task.uShares.put(0, new BigInteger(uHex, 16));
        if (task.uOpenLatch.getCount() > 0) {
            task.uOpenLatch.countDown();
        }
        logger.debug("U open stored (taskId={}, senderId={}, uOpenLatch={})",
                taskId, senderId, task.uOpenLatch.getCount());
        logProgress(task, "u_open");
    }

    /**
     * 处理U承诺消息
     */
    void handleCggmpSignUCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commit = (String) dataMap.get("commit");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commit == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        task.uCommitments.put(senderId, commit);
        if (task.uCommitLatch.getCount() > 0) {
            task.uCommitLatch.countDown();
        }
        logger.debug("U commit stored (taskId={}, senderId={}, uCommitLatch={})",
                taskId, senderId, task.uCommitLatch.getCount());
        logProgress(task, "u_commit");
    }

    /**
     * 处理MtA-St协议初始化消息
     */
    void handleCggmpSignMtaStInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != svc.nodeId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(svc.nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            logger.debug("ST init received (taskId={}, initiatorId={}, receiverId={})", taskId, initiatorId, receiverId);
            PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpCodecUtils.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpCodecUtils.decodeMtAInitiatorMessage(msgMap);
            if (!CggmpSignatureKeyValidator.ensurePeerKeyMatchesAux(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("AUX params mismatch with Paillier/zkSetup for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("auxHash", CggmpSignatureKeyValidator.computeAuxHash(task.peerAuxParams.get(initiatorId)));
                evidence.put("pkHash", CggmpSignatureKeyValidator.computePkHash(publicKey));
                evidence.put("zkHash", CggmpSignatureKeyValidator.computeZkHash(zkSetup));
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "AUX params mismatch with Paillier/zkSetup (ST)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "AUX params mismatch with Paillier/zkSetup (ST)");
                return;
            }
            if (!CggmpSignatureKeyValidator.validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid Paillier public key (ST)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid Paillier public key (ST)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Missing ST MtA initiator proofs", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing ST MtA initiator proofs");
                return;
            }
            if (!CggmpSignatureKeyValidator.ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (ST)", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (ST)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1CurveUtils.n());
            byte[] mtaContext = CggmpProtocolUtils.buildMtaContext(taskId + ":ST", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid ST MtA initiator proofs", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid ST MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.t_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.stBetas.put(initiatorId, beta);
            if (task.stInitLatch.getCount() > 0) {
                task.stInitLatch.countDown();
            }
            logger.debug("ST init stored (taskId={}, initiatorId={}, stInitLatch={})",
                    taskId, initiatorId, task.stInitLatch.getCount());
            logProgress(task, "st_init");

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", svc.nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpCodecUtils.encodeMtAResult(publicResult));
            CggmpProtocolUtils.fireAndForget(svc.nodeService.sendMessage(initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_MTA_ST_RESPONSE, resp)),
                    logger, "CGGMP_SIGN_MTA_ST_RESPONSE");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理MtA-St协议响应消息
     */
    void handleCggmpSignMtaStResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != svc.nodeId || responderId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpCodecUtils.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaStInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, responderId, "Missing ST MtA respondent proof", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing ST MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1CurveUtils.n());
            byte[] mtaContext = CggmpProtocolUtils.buildMtaContext(taskId + ":ST", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, responderId, "Invalid ST MtA respondent proof", evidence),
                        logger, "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid ST MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1CurveUtils.n());
            task.stAlphas.put(responderId, alpha);
            if (task.stResponseLatch.getCount() > 0) {
                task.stResponseLatch.countDown();
            }
            logger.debug("ST response stored (taskId={}, responderId={}, stResponseLatch={})",
                    taskId, responderId, task.stResponseLatch.getCount());
            logProgress(task, "st_resp");
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    /**
     * 处理S分片消息，计算最终签名
     */
    void handleCggmpSignSShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String sHex = (String) dataMap.get("s");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || sHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        BigInteger sigma = new BigInteger(sHex, 16);
        if (!verifySigmaShare(task, senderId, sigma)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("sigma", sHex);
            ev.put("r", task.r == null ? null : HexUtils.toHex(task.r));
            ev.put("DeltaTilde", task.presignDeltaTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignDeltaTilde.get(senderId).getEncoded(false)));
            ev.put("STilde", task.presignSTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignSTilde.get(senderId).getEncoded(false)));
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid signature share (Figure 10)", ev),
                    logger, "CGGMP_SIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid signature share from node " + senderId);
            return;
        }
        task.sShares.put(senderId, sigma);
        if (task.sShareLatch.getCount() > 0) {
            task.sShareLatch.countDown();
        }
        logger.debug("S share stored (taskId={}, senderId={}, sShareLatch={})",
                taskId, senderId, task.sShareLatch.getCount());
        logProgress(task, "s_share");
    }

    private void finalizeSignatureAsInitiator(CggmpOnlineContext ctx) {
        if (ctx == null) {
            return;
        }
        List<Integer> offenders = findInvalidSigmaShares(ctx.task());
        if (!offenders.isEmpty()) {
            for (int offender : offenders) {
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(ctx.task(), offender, "Invalid signature share (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task().r))),
                        logger, "CGGMP_SIGN_SHARE_COMPLAINT");
            }
            svc.failSignatureTask(ctx.task(), "Invalid signature shares: " + offenders);
            svc.signatureInProgress.set(false);
            svc.clearPresignAll(ctx.task());
            return;
        }
        BigInteger s = CggmpProtocolUtils.sumShares(ctx.task().sShares, ctx.curveOrder());
        if (s.compareTo(ctx.curveOrder().shiftRight(1)) > 0) {
            s = ctx.curveOrder().subtract(s);
        }
        byte[] der = derEncodeSignature(ctx.task().r, s);
        boolean verified = verifySignature(ctx.task().groupPublicKeyPoint, ctx.task().messageHash, ctx.task().r, s, buildDomain());
        if (!verified) {
            List<Integer> suspects = findInvalidSigmaShares(ctx.task());
            for (int offender : suspects) {
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(ctx.task(), offender, "Aggregate signature verification failed (Figure 10)", Map.of("r", HexUtils.toHex(ctx.task().r))),
                        logger, "CGGMP_SIGN_AGG_COMPLAINT");
            }
            svc.failSignatureTask(ctx.task(), "Aggregate signature verification failed");
            svc.signatureInProgress.set(false);
            svc.clearPresignAll(ctx.task());
            return;
        }
        ctx.task().signature = Base64.getEncoder().encodeToString(der);
        ctx.task().verified = verified;
        ctx.task().complete();
        svc.signatureInProgress.set(false);
        svc.clearPresignAll(ctx.task());
        logger.info("CGGMP signature task {} completed successfully, verified: {}", ctx.task().taskId, verified);
    }

    private List<Integer> findInvalidSigmaShares(CggmpSignatureTask task) {
        List<Integer> offenders = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger> e : task.sShares.entrySet()) {
            if (!verifySigmaShare(task, e.getKey(), e.getValue())) {
                offenders.add(e.getKey());
            }
        }
        return offenders;
    }

    private BigInteger resolveSignShift(CggmpSignatureTask task, BigInteger q) {
        if (!svc.hdEnabled) {
            return BigInteger.ZERO;
        }
        return deriveShiftFromChainCode(task, q);
    }

    private BigInteger deriveShiftFromChainCode(CggmpSignatureTask task, BigInteger q) {
        if (task == null || task.chainCode == null || task.messageHash == null) {
            return BigInteger.ZERO;
        }
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec key = new javax.crypto.spec.SecretKeySpec(task.chainCode, "HmacSHA256");
            mac.init(key);
            byte[] out = mac.doFinal(task.messageHash);
            return new BigInteger(1, out).mod(q);
        } catch (Exception e) {
            logger.warn("Failed to derive HD shift for task {}: {}", task.taskId, e.getMessage());
            return BigInteger.ZERO;
        }
    }

    private boolean verifySigmaShare(CggmpSignatureTask task, int senderId, BigInteger sigma) {
        if (task.presignature == null || task.messageHash == null) {
            return false;
        }
        BigInteger curveOrder = Secp256k1CurveUtils.n();
        ECPoint Gamma = task.presignature.Gamma();
        BigInteger r = task.r != null ? task.r : Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
        BigInteger m = new BigInteger(1, task.messageHash).mod(curveOrder);
        ECPoint deltaTilde = task.presignDeltaTilde.get(senderId);
        ECPoint sTilde = task.presignSTilde.get(senderId);
        if (deltaTilde == null || sTilde == null) {
            return false;
        }
        BigInteger shift = resolveSignShift(task, curveOrder);
        if (shift.signum() != 0) {
            sTilde = sTilde.add(deltaTilde.multiply(shift)).normalize();
        }
        ECPoint left = Gamma.multiply(sigma).normalize();
        ECPoint right = deltaTilde.multiply(m).add(sTilde.multiply(r)).normalize();
        return left.equals(right);
    }

    private ECDomainParameters buildDomain() {
        return new ECDomainParameters(
                Secp256k1CurveUtils.G().getCurve(),
                Secp256k1CurveUtils.G(),
                Secp256k1CurveUtils.n(),
                BigInteger.ONE
        );
    }

    private boolean verifySignature(ECPoint publicKey, byte[] messageHash, BigInteger r, BigInteger s, ECDomainParameters domain) {
        ECDSASigner verifier = new ECDSASigner();
        ECPublicKeyParameters pub = new ECPublicKeyParameters(publicKey, domain);
        verifier.init(false, pub);
        return verifier.verifySignature(messageHash, r, s);
    }

    private byte[] derEncodeSignature(BigInteger r, BigInteger s) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode DER signature", e);
        }
    }

    private CompletableFuture<Void> sendSShare(CggmpSignatureTask task, BigInteger s_i) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("s", s_i.toString(16));
        return svc.nodeService.sendMessage(task.initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_S_SHARE, data));
    }

    private String commitU(String taskId, int senderId, byte[] messageHash, BigInteger u, BigInteger r) {
        int nLen = (Secp256k1CurveUtils.n().bitLength() + 7) / 8;
        byte[] uBytes = BigIntegerUtils.toUnsignedBytes(u, nLen);
        byte[] rBytes = BigIntegerUtils.toUnsignedBytes(r, nLen);
        byte[] ctx = CggmpProtocolUtils.buildSignContext(taskId, senderId, messageHash, "U-COMMIT");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ctx);
            digest.update(uBytes);
            digest.update(rBytes);
            byte[] out = digest.digest();
            return HexUtils.bytesToHex(out);
        } catch (Exception e) {
            throw new RuntimeException("U commit hash failed", e);
        }
    }
}
