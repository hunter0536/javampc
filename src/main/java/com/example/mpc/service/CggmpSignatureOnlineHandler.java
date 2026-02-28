package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.sign.CggmpIntegrityChecker;
import com.example.mpc.cggmp.sign.EcChaumPedersenProof;
import com.example.mpc.cggmp.util.CggmpCodecUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.service.cggmp.CggmpOnlineContext;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

final class CggmpSignatureOnlineHandler {
    private final CggmpSignatureService svc;

    CggmpSignatureOnlineHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    CompletableFuture<Void> runOnlinePhase(Gg20SignatureTask task) {
        svc.logger.debug("Signature online phase start for task {} (node={}, initiator={})",
                task.taskId, svc.nodeId, task.initiatorId);
        return svc.waitForLatchAsync(task.offlineDoneLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "offline phase")
                .thenCompose(v -> svc.waitForLatchAsync(task.presignatureLatch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "local presignature"))
                .thenCompose(v -> CompletableFuture.supplyAsync(() -> {
                    try {
                        if (task.messageHash == null) {
                            throw new RuntimeException("Missing message hash for online phase");
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

                        BigInteger e = new BigInteger(1, task.messageHash).mod(curveOrder);
                        BigInteger chiTilde = task.presignature.chiTilde();
                        BigInteger shift = svc.resolveSignShift(task, curveOrder);
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
                        if (svc.verifySigmaShare(ctx.task(), svc.nodeId, ctx.sigma_i())) {
                            svc.failSignatureTask(ctx.task(), "Local signature share verification failed");
                            svc.signatureInProgress.set(false);
                            svc.clearPresignAll(ctx.task());
                            return CompletableFuture.completedFuture(null);
                        }
                        ctx.task().sShares.put(svc.nodeId, ctx.sigma_i());
                        return svc.waitForLatchAsync(ctx.task().sShareLatch, Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, "signature shares")
                                .thenRunAsync(() -> svc.finalizeSignatureAsInitiator(ctx), ThreadPoolUtil.getIoThreadPool());
                    }
                    return CompletableFuture.runAsync(() -> {
                        svc.fireAndForget(svc.sendSShare(ctx.task(), ctx.sigma_i()), "CGGMP_SIGN_S_SHARE");
                        ctx.task().complete();
                        svc.signatureInProgress.set(false);
                        svc.clearPresignLocal(ctx.task());
                    }, ThreadPoolUtil.getIoThreadPool());
                })
                .whenComplete((v, ex) -> {
                    if (ex == null) {
                        svc.logger.debug("Signature online phase completed for task {}", task.taskId);
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    String msg = cause == null ? ex.getMessage() : cause.getMessage();
                    task.fail(msg);
                    svc.signatureInProgress.set(false);
                    svc.clearPresignAll(task);
                });
    }

    void handleCggmpSignOnlineInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object hashValue = dataMap.get("messageHash");
        if (signatureTaskId == null || !(hashValue instanceof String hashString)) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        task.messageHash = Base64.getDecoder().decode(hashString);
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        runOnlinePhase(task).exceptionally(ex -> {
            svc.logger.error("Failed online phase for signature task {}: {}", signatureTaskId, ex.getMessage());
            return null;
        });
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint commitment = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(commitHex));
            ECPoint proofA = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(proofAHex));
            BigInteger proofR = new BigInteger(proofRHex, 16);
            BigInteger proofS = new BigInteger(proofSHex, 16);
            EcChaumPedersenProof proof = new EcChaumPedersenProof(proofA, proofR, proofS);
            byte[] ctx = SignUtils.buildSignContext(task.taskId, senderId, task.messageHash, "GAMMA-COMMIT");
            if (!CggmpIntegrityChecker.verifyGammaCommitment(proof, commitment, ctx)) {
                svc.logger.warn("Invalid gamma commitment proof from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("commit", commitHex);
                evidence.put("proofA", proofAHex);
                evidence.put("proofR", proofRHex);
                evidence.put("proofS", proofSHex);
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma commitment proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma commitment proof");
                return;
            }
            if (task.gammaCommitments.containsKey(senderId)) {
                svc.logger.warn("Duplicate gamma commitment from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaCommitments.put(senderId, commitment);
            if (task.gammaCommitLatch.getCount() > 0) {
                task.gammaCommitLatch.countDown();
            }
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_GAMMA_COMMIT from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint gamma = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(gammaHex));
            BigInteger r = new BigInteger(rHex, 16);
            ECPoint commitment = task.gammaCommitments.get(senderId);
            if (commitment == null) {
                svc.logger.warn("Missing gamma commitment for node {} in task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Missing gamma commitment", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing gamma commitment");
                return;
            }
            if (!CggmpIntegrityChecker.isValidGammaPoint(gamma)) {
                svc.logger.warn("Invalid gamma point from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma point", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma point");
                return;
            }
            if (!CggmpIntegrityChecker.verifyGammaOpen(commitment, gamma, r)) {
                svc.logger.warn("Invalid gamma commitment opening from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                evidence.put("r", rHex);
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid gamma commitment opening", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid gamma commitment opening");
                return;
            }
            if (task.gammaPoints.containsKey(senderId)) {
                svc.logger.warn("Duplicate gamma open from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaPoints.put(senderId, gamma);
            if (task.gammaLatch.getCount() > 0) {
                task.gammaLatch.countDown();
            }
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_GAMMA_OPEN from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
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
            PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpCodecUtils.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpCodecUtils.decodeMtAInitiatorMessage(msgMap);
            if (!svc.validatePaillierPublicKey(publicKey)) {
                svc.logger.warn("Invalid Paillier public key for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid Paillier public key (KA)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid Paillier public key (KA)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                svc.logger.warn("Missing KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Missing KA MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing KA MtA initiator proofs");
                return;
            }
            if (!svc.ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                svc.logger.warn("Inconsistent Paillier key/zkSetup for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (KA)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (KA)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1CurveUtils.n());
            byte[] mtaContext = SignUtils.buildMtaContext(taskId + ":KA", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                svc.logger.warn("Invalid KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid KA MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid KA MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.a_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.kaBetas.put(initiatorId, beta);
            if (task.kaInitLatch.getCount() > 0) {
                task.kaInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", svc.nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpCodecUtils.encodeMtAResult(publicResult));
            svc.fireAndForget(svc.nodeService.sendMessage(initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_MTA_KA_RESPONSE, resp)),
                    "CGGMP_SIGN_MTA_KA_RESPONSE");
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_MTA_KA_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
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
                svc.logger.warn("Missing KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                svc.fireAndForget(svc.broadcastComplaint(task, responderId, "Missing KA MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing KA MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1CurveUtils.n());
            byte[] mtaContext = SignUtils.buildMtaContext(taskId + ":KA", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                svc.logger.warn("Invalid KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                svc.fireAndForget(svc.broadcastComplaint(task, responderId, "Invalid KA MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid KA MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1CurveUtils.n());
            task.kaAlphas.put(responderId, alpha);
            if (task.kaResponseLatch.getCount() > 0) {
                task.kaResponseLatch.countDown();
            }
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_MTA_KA_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        try {
            BigInteger u = new BigInteger(uHex, 16);
            BigInteger r = new BigInteger(rHex, 16);
            String commit = task.uCommitments.get(senderId);
            if (commit == null) {
                svc.logger.warn("Missing u commitment from node {} for task {}", senderId, taskId);
                return;
            }
            String expected = svc.commitU(taskId, senderId, task.messageHash, u, r);
            if (!commit.equals(expected)) {
                svc.logger.warn("Invalid u commitment opening from node {} for task {}", senderId, taskId);
                return;
            }
            task.uShares.put(senderId, u);
            if (task.uShareLatch.getCount() > 0) {
                task.uShareLatch.countDown();
            }
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_U_SHARE from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        task.uShares.put(0, new BigInteger(uHex, 16));
        if (task.uOpenLatch.getCount() > 0) {
            task.uOpenLatch.countDown();
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        task.uCommitments.put(senderId, commit);
        if (task.uCommitLatch.getCount() > 0) {
            task.uCommitLatch.countDown();
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
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
            PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpCodecUtils.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpCodecUtils.decodeMtAInitiatorMessage(msgMap);
            if (!svc.validatePaillierPublicKey(publicKey)) {
                svc.logger.warn("Invalid Paillier public key for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid Paillier public key (ST)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid Paillier public key (ST)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                svc.logger.warn("Missing ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Missing ST MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing ST MtA initiator proofs");
                return;
            }
            if (!svc.ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                svc.logger.warn("Inconsistent Paillier key/zkSetup for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (ST)", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (ST)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1CurveUtils.n());
            byte[] mtaContext = SignUtils.buildMtaContext(taskId + ":ST", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                svc.logger.warn("Invalid ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                svc.fireAndForget(svc.broadcastComplaint(task, initiatorId, "Invalid ST MtA initiator proofs", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid ST MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.t_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.stBetas.put(initiatorId, beta);
            if (task.stInitLatch.getCount() > 0) {
                task.stInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", svc.nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpCodecUtils.encodeMtAResult(publicResult));
            svc.fireAndForget(svc.nodeService.sendMessage(initiatorId, new NodeService.Message(svc.nodeId, MessageType.CGGMP_SIGN_MTA_ST_RESPONSE, resp)),
                    "CGGMP_SIGN_MTA_ST_RESPONSE");
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_MTA_ST_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
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
                svc.logger.warn("Missing ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                svc.fireAndForget(svc.broadcastComplaint(task, responderId, "Missing ST MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Missing ST MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1CurveUtils.n());
            byte[] mtaContext = SignUtils.buildMtaContext(taskId + ":ST", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                svc.logger.warn("Invalid ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                svc.fireAndForget(svc.broadcastComplaint(task, responderId, "Invalid ST MtA respondent proof", evidence),
                        "CGGMP_SIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid ST MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1CurveUtils.n());
            task.stAlphas.put(responderId, alpha);
            if (task.stResponseLatch.getCount() > 0) {
                task.stResponseLatch.countDown();
            }
        } catch (Exception e) {
            svc.logger.error("Failed to handle CGGMP_SIGN_MTA_ST_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(taskId);
        if (task == null || svc.nodeId != task.initiatorId) {
            return;
        }
        BigInteger sigma = new BigInteger(sHex, 16);
        if (svc.verifySigmaShare(task, senderId, sigma)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("sigma", sHex);
            ev.put("r", task.r == null ? null : HexUtils.toHex(task.r));
            ev.put("DeltaTilde", task.presignDeltaTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignDeltaTilde.get(senderId).getEncoded(false)));
            ev.put("STilde", task.presignSTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignSTilde.get(senderId).getEncoded(false)));
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid signature share (Figure 10)", ev),
                    "CGGMP_SIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid signature share from node " + senderId);
            return;
        }
        task.sShares.put(senderId, sigma);
        if (task.sShareLatch.getCount() > 0) {
            task.sShareLatch.countDown();
        }
    }
}
