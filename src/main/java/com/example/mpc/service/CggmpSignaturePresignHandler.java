package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.CggmpCodecUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonUtils;
import com.example.mpc.model.Gg20SignatureTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

final class CggmpSignaturePresignHandler {
    private final CggmpSignatureService svc;

    CggmpSignaturePresignHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    void handlePresignR1(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpSignatureService.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpSignatureService.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpSignatureService.asInt(dataMap.get("senderId"));
        String kHex = CggmpSignatureService.asString(dataMap.get("K"));
        String gHex = CggmpSignatureService.asString(dataMap.get("G"));
        String yHex = CggmpSignatureService.asString(dataMap.get("Y"));
        String a1Hex = CggmpSignatureService.asString(dataMap.get("A1"));
        String a2Hex = CggmpSignatureService.asString(dataMap.get("A2"));
        String b1Hex = CggmpSignatureService.asString(dataMap.get("B1"));
        String b2Hex = CggmpSignatureService.asString(dataMap.get("B2"));
        Map<?, ?> encElgKMap = CggmpSignatureService.asMap(dataMap.get("encElgProofK"));
        Map<?, ?> encElgGMap = CggmpSignatureService.asMap(dataMap.get("encElgProofG"));
        Map<?, ?> pkMap = CggmpSignatureService.asMap(dataMap.get("paillierPublicKey"));
        Map<?, ?> zkMap = CggmpSignatureService.asMap(dataMap.get("zkSetup"));
        if (signatureTaskId == null || senderNodeId == null || kHex == null || gHex == null
                || yHex == null || a1Hex == null || a2Hex == null || b1Hex == null || b2Hex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            svc.cachePendingPresignR1(signatureTaskId, senderId, dataMap);
            return;
        }
        if (!task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        if (pkMap == null || zkMap == null) {
            return;
        }
        BigInteger K = new BigInteger(kHex, 16);
        BigInteger G = new BigInteger(gHex, 16);
        ECPoint Y = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(yHex));
        ECPoint A1 = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(a1Hex));
        ECPoint A2 = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(a2Hex));
        ECPoint B1 = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(b1Hex));
        ECPoint B2 = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(b2Hex));
        PiEncElgProof encElgK = encElgKMap == null ? null : CggmpCodecUtils.decodePiEncElgProof(encElgKMap);
        PiEncElgProof encElgG = encElgGMap == null ? null : CggmpCodecUtils.decodePiEncElgProof(encElgGMap);
        PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
        ZKSetup zkSetup = CggmpCodecUtils.decodeZkSetup(zkMap);
        if (svc.ensurePeerKeyConsistency(task, senderId, publicKey, zkSetup)) {
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Inconsistent Paillier key/zkSetup (presign R1)", Map.of("paillierPublicKey", pkMap, "zkSetup", zkMap)),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (presign R1)");
            return;
        }
        byte[] ctxK = SignUtils.buildPresignContext(task.taskId, senderId, "R1K");
        PresignProofs.EncElgVerifyResult encElgKResult = PresignProofs.verifyEncElgProofDetailed(
                encElgK, publicKey, zkSetup, Secp256k1CurveUtils.G(), A1, Y, A2, K, svc.proofEpsBits, ctxK);
        if (!encElgKResult.ok()) {
            svc.logger.warn("Invalid PiEncElg proof (K) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgKResult.eq1(), encElgKResult.eq2(), encElgKResult.eq3(), encElgKResult.eq4(), encElgKResult.z1InRange());
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiEncElg proof (K)", Map.of("K", kHex)),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid PiEncElg proof (K)");
            return;
        }
        byte[] ctxG = SignUtils.buildPresignContext(task.taskId, senderId, "R1G");
        PresignProofs.EncElgVerifyResult encElgGResult = PresignProofs.verifyEncElgProofDetailed(
                encElgG, publicKey, zkSetup, Secp256k1CurveUtils.G(), B1, Y, B2, G, svc.proofEpsBits, ctxG);
        if (!encElgGResult.ok()) {
            svc.logger.warn("Invalid PiEncElg proof (G) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgGResult.eq1(), encElgGResult.eq2(), encElgGResult.eq3(), encElgGResult.eq4(), encElgGResult.z1InRange());
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiEncElg proof (G)", Map.of("G", gHex)),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid PiEncElg proof (G)");
            return;
        }
        task.presignK.put(senderId, K);
        task.presignG.put(senderId, G);
        task.presignY.put(senderId, Y);
        task.presignA1.put(senderId, A1);
        task.presignA2.put(senderId, A2);
        task.presignB1.put(senderId, B1);
        task.presignB2.put(senderId, B2);
        if (task.presignR1Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.gammaCommitLatch.getCount() > 0) {
            task.gammaCommitLatch.countDown();
        }
        if (svc.presignEchoEnabled) {
            validatePendingPresignR1Echo(task);
        }
        Map<String, Object> pendingR2 = task.pendingPresignR2.remove(senderId);
        if (pendingR2 != null) {
            processPresignR2(task, senderId, pendingR2);
        }
        Map<String, Object> pendingR3 = task.pendingPresignR3.remove(senderId);
        if (pendingR3 != null) {
            processPresignR3(task, senderId, pendingR3);
        }
    }

    void handlePresignR1Echo(int senderId, Object data) {
        if (!svc.presignEchoEnabled) {
            return;
        }
        Map<?, ?> dataMap = CggmpSignatureService.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpSignatureService.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpSignatureService.asInt(dataMap.get("senderId"));
        String hash = CggmpSignatureService.asString(dataMap.get("hash"));
        if (signatureTaskId == null || senderNodeId == null || hash == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        String expected = svc.computePresignR1EchoHash(task);
        if (expected == null) {
            task.pendingPresignR1Echo.put(senderId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                            Map.of("senderId", senderId, "expected", expected, "received", hash)),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Presign R1 echo mismatch from node " + senderId);
            return;
        }
        if (task.presignR1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR1EchoLatch.getCount() > 0) {
            task.presignR1EchoLatch.countDown();
        }
    }

    void validatePendingPresignR1Echo(Gg20SignatureTask task) {
        if (task == null || task.pendingPresignR1Echo.isEmpty()) {
            return;
        }
        String expected = svc.computePresignR1EchoHash(task);
        if (expected == null) {
            return;
        }
        for (Map.Entry<Integer, String> e : new HashMap<>(task.pendingPresignR1Echo).entrySet()) {
            int senderId = e.getKey();
            String hash = e.getValue();
            if (!expected.equals(hash)) {
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                                Map.of("senderId", senderId, "expected", expected, "received", hash)),
                        "CGGMP_PRESIGN_COMPLAINT");
                svc.failSignatureTask(task, "Presign R1 echo mismatch from node " + senderId);
                return;
            }
            task.pendingPresignR1Echo.remove(senderId);
            if (task.presignR1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null
                    && task.presignR1EchoLatch.getCount() > 0) {
                task.presignR1EchoLatch.countDown();
            }
        }
    }

    void handlePresignR2(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpSignatureService.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpSignatureService.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpSignatureService.asInt(dataMap.get("senderId"));
        String gammaHex = CggmpSignatureService.asString(dataMap.get("Gamma"));
        if (signatureTaskId == null || senderNodeId == null || gammaHex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            svc.logger.info("Skip CGGMP_PRESIGN_R2 for task {} on node {} (not a participant, participants={})",
                    task.taskId, svc.nodeId, task.participants);
            return;
        }
        processPresignR2(task, senderId, dataMap);
    }

    void processPresignR2(Gg20SignatureTask task, int senderId, Map<?, ?> dataMap) {
        String gammaHex = CggmpSignatureService.asString(dataMap.get("Gamma"));
        if (gammaHex == null) {
            return;
        }
        Map<?, ?> dMap = CggmpSignatureService.asMap(dataMap.get("D"));
        Map<?, ?> dhMap = CggmpSignatureService.asMap(dataMap.get("Dhat"));
        Map<?, ?> fMap = CggmpSignatureService.asMap(dataMap.get("F"));
        Map<?, ?> fhMap = CggmpSignatureService.asMap(dataMap.get("Fhat"));
        Map<?, ?> affGMap = CggmpSignatureService.asMap(dataMap.get("affGProofs"));
        Map<?, ?> affGhatMap = CggmpSignatureService.asMap(dataMap.get("affGProofsHat"));
        Map<?, ?> logProofMap = CggmpSignatureService.asMap(dataMap.get("logProof"));
        String xHex = CggmpSignatureService.asString(dataMap.get("X"));
        if (dMap == null || dhMap == null || fMap == null || fhMap == null) {
            return;
        }
        BigInteger curveOrder = Secp256k1CurveUtils.n();
        ECPoint Gamma = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(gammaHex));
        task.presignGamma.put(senderId, Gamma);
        Map<Integer, BigInteger> D = JsonUtils.decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> Dhat = JsonUtils.decodeBigIntegerMap(dhMap);
        Map<Integer, BigInteger> F = JsonUtils.decodeBigIntegerMap(fMap);
        Map<Integer, BigInteger> Fhat = JsonUtils.decodeBigIntegerMap(fhMap);
        BigInteger dForNode = D.get(svc.nodeId);
        BigInteger dhatForNode = Dhat.get(svc.nodeId);
        svc.logger.info("Presign R2 received for task {} from {}: D keys={}, Dhat keys={}, D[node]={}, Dhat[node]={}",
                task.taskId,
                senderId,
                D.keySet(),
                Dhat.keySet(),
                dForNode == null ? null : dForNode.toString(16),
                dhatForNode == null ? null : dhatForNode.toString(16));
        PiLogProof logProof = logProofMap == null ? null : CggmpCodecUtils.decodePiLogProof(logProofMap);
        byte[] ctx = SignUtils.buildPresignContext(task.taskId, senderId, "R2");
        ECPoint Y = task.presignY.get(senderId);
        ECPoint B1 = task.presignB1.get(senderId);
        ECPoint B2 = task.presignB2.get(senderId);
        if (Y == null || B1 == null || B2 == null) {
            task.pendingPresignR2.put(senderId, copyStringObjectMap(dataMap));
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1CurveUtils.G(), Secp256k1CurveUtils.G(), Gamma, Y, B1, B2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Gamma", gammaHex);
            ev.put("D", dMap);
            ev.put("F", fMap);
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiLog proof (R2)", ev),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid presign R2 proof");
            return;
        }

        ECPoint expectedX = null;
        BigInteger lambdaSender = svc.computeSignatureLagrange(task, senderId, curveOrder);
        if (task.publicShares != null) {
            expectedX = svc.resolvePublicShareFromMap(task, senderId, lambdaSender);
        }
        if (expectedX != null && xHex != null) {
            ECPoint provided = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(xHex));
            if (!expectedX.equals(provided)) {
                Map<String, Object> ev = new HashMap<>();
                ev.put("expectedX", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(expectedX)));
                ev.put("providedX", xHex);
                svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid X in presign R2", ev),
                        "CGGMP_PRESIGN_COMPLAINT");
                svc.failSignatureTask(task, "Invalid X in presign R2 from node " + senderId);
                return;
            }
        }
        ECPoint X_i_resolved = expectedX;
        if (X_i_resolved == null && xHex != null) {
            X_i_resolved = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(xHex));
        }
        if (X_i_resolved == null) {
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Missing X in presign R2", Map.of("senderId", senderId)),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Missing X in presign R2 from node " + senderId);
            return;
        }

        if (affGMap != null && affGhatMap != null) {
            Map<Integer, PiAffGProof> proofs = svc.decodeAffGProofMap(affGMap);
            Map<Integer, PiAffGProof> proofsHat = svc.decodeAffGProofMap(affGhatMap);
            PiAffGProof proof = proofs.get(svc.nodeId);
            PiAffGProof proofHat = proofsHat.get(svc.nodeId);
            BigInteger D_ji = D.get(svc.nodeId);
            BigInteger F_ji = F.get(svc.nodeId);
            BigInteger Dhat_ji = Dhat.get(svc.nodeId);
            BigInteger Fhat_ji = Fhat.get(svc.nodeId);
            BigInteger K_self = task.presignK.get(svc.nodeId);
            PaillierEncryption.PublicKey N0 = task.paillier.getPublicKeyInfo();
            PaillierEncryption.PublicKey N1 = task.peerPaillierKeys.get(senderId);
            ECPoint X_i = X_i_resolved;
            if (K_self != null && D_ji != null && F_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1CurveUtils.G(),
                        Gamma,
                        N0.n,
                        N1.n,
                        K_self,
                        D_ji,
                        F_ji,
                        svc.proofKappa,
                        svc.proofEpsBits,
                        SignUtils.buildPresignContext(task.taskId, senderId, "R2")
                );
                if (!affGResult.ok()) {
                    svc.logger.warn("Invalid PiAffG proof from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGResult.index(), affGResult.eq1(), affGResult.eq2(),
                            affGResult.eq3(), affGResult.zInRange(), affGResult.zPrimeInRange());
                    svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiAffG proof", Map.of("D", dMap, "F", fMap)),
                            "CGGMP_PRESIGN_COMPLAINT");
                    svc.failSignatureTask(task, "Invalid presign R2 affG proof");
                    return;
                }
            }
            if (K_self != null && Dhat_ji != null && Fhat_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGHatResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proofHat,
                        Secp256k1CurveUtils.G(),
                        X_i,
                        N0.n,
                        N1.n,
                        K_self,
                        Dhat_ji,
                        Fhat_ji,
                        svc.proofKappa,
                        svc.proofEpsBits,
                        SignUtils.buildPresignContext(task.taskId, senderId, "R2H")
                );
                if (!affGHatResult.ok()) {
                    svc.logger.warn("Invalid PiAffG proof (hat) from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGHatResult.index(), affGHatResult.eq1(), affGHatResult.eq2(),
                            affGHatResult.eq3(), affGHatResult.zInRange(), affGHatResult.zPrimeInRange());
                    svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiAffG proof (hat)", Map.of("Dhat", dhMap, "Fhat", fhMap)),
                            "CGGMP_PRESIGN_COMPLAINT");
                    svc.failSignatureTask(task, "Invalid presign R2 affG hat proof");
                    return;
                }
            }
        }
        if (!D.containsKey(svc.nodeId) || !Dhat.containsKey(svc.nodeId)) {
            svc.logger.warn("Presign R2 missing payload for receiver {} from sender {} (D or Dhat not found)", svc.nodeId, senderId);
            return;
        }
        task.presignD.put(senderId, D.get(svc.nodeId));
        task.presignDhat.put(senderId, Dhat.get(svc.nodeId));
        if (F.containsKey(svc.nodeId)) task.presignF.put(senderId, F.get(svc.nodeId));
        if (Fhat.containsKey(svc.nodeId)) task.presignFhat.put(senderId, Fhat.get(svc.nodeId));
        if (task.presignR2Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR2Latch.getCount() > 0) {
            task.presignR2Latch.countDown();
        }
    }

    void handlePresignR3(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpSignatureService.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpSignatureService.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpSignatureService.asInt(dataMap.get("senderId"));
        String deltaHex = CggmpSignatureService.asString(dataMap.get("delta"));
        String deltaPointHex = CggmpSignatureService.asString(dataMap.get("Delta"));
        String sPointHex = CggmpSignatureService.asString(dataMap.get("S"));
        if (signatureTaskId == null || senderNodeId == null || deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        processPresignR3(task, senderId, dataMap);
    }

    void processPresignR3(Gg20SignatureTask task, int senderId, Map<?, ?> dataMap) {
        String deltaHex = CggmpSignatureService.asString(dataMap.get("delta"));
        String deltaPointHex = CggmpSignatureService.asString(dataMap.get("Delta"));
        String sPointHex = CggmpSignatureService.asString(dataMap.get("S"));
        Map<?, ?> logProofMap = CggmpSignatureService.asMap(dataMap.get("logProof"));
        if (deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        PiLogProof logProof = logProofMap == null ? null : CggmpCodecUtils.decodePiLogProof(logProofMap);
        ECPoint Delta = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(deltaPointHex));
        ECPoint S = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(sPointHex));
        byte[] ctx = SignUtils.buildPresignContext(task.taskId, senderId, "R3");
        if (task.presignR2Latch.getCount() > 0) {
            task.pendingPresignR3.put(senderId, copyStringObjectMap(dataMap));
            return;
        }
        ECPoint Gamma = svc.sumPresignGamma(task);
        ECPoint Y = task.presignY.get(senderId);
        ECPoint A1 = task.presignA1.get(senderId);
        ECPoint A2 = task.presignA2.get(senderId);
        if (Y == null || A1 == null || A2 == null) {
            task.pendingPresignR3.put(senderId, copyStringObjectMap(dataMap));
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1CurveUtils.G(), Gamma, Delta, Y, A1, A2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Delta", deltaPointHex);
            ev.put("S", sPointHex);
            svc.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiLog proof (R3)", ev),
                    "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid presign R3 proof");
            return;
        }
        if (task.presignR3Received.putIfAbsent(senderId, Boolean.TRUE) != null) {
            svc.logger.warn("Duplicate presign R3 from node {} for task {}, ignoring", senderId, task.taskId);
            return;
        }
        task.presignDelta.put(senderId, new BigInteger(deltaHex, 16));
        task.presignDeltaPoint.put(senderId, Delta);
        task.presignSPoint.put(senderId, S);
        if (task.offlineDoneLatch.getCount() > 0) {
            task.offlineDoneLatch.countDown();
        }
    }

    private static Map<String, Object> copyStringObjectMap(Map<?, ?> source) {
        Map<String, Object> copy = new HashMap<>();
        if (source == null) {
            return copy;
        }
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            Object key = entry.getKey();
            if (key instanceof String) {
                copy.put((String) key, entry.getValue());
            }
        }
        return copy;
    }
}
