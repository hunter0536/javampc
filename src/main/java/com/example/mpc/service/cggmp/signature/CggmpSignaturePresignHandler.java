package com.example.mpc.service.cggmp.signature;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonCodec;
import com.example.mpc.dto.CggmpSignatureTask;
import com.example.mpc.dto.R2VerifyResult;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.service.cggmp.types.AffGProofMap;
import com.example.mpc.service.cggmp.types.BigIntIndexMap;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CGGMP签名预计算处理器
 * 负责协调预签名各轮的分布式计算
 */
public final class CggmpSignaturePresignHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignaturePresignHandler.class);
    private final CggmpSignatureService svc;
    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, Map<String, Object>>> pendingPresignR1ByTask =
            new ConcurrentHashMap<>();

    public CggmpSignaturePresignHandler(CggmpSignatureService svc) {
        this.svc = svc;
    }

    static Map<String, Object> encodeAffGProofMap(Map<Integer, PiAffGProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiAffGProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpCodecUtils.encodePiAffGProof(e.getValue()));
        }
        return out;
    }

    static Map<Integer, PiAffGProof> decodeAffGProofMap(Map<?, ?> map) {
        Map<Integer, PiAffGProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpCodecUtils.decodePiAffGProof((Map<?, ?>) e.getValue()));
        }
        return out;
    }

    static String computePresignR1EchoHash(CggmpSignatureTask task) {
        try {
            String sid = "CGGMP24:SIGN:" + task.taskId;
            List<Integer> ids = new ArrayList<>(task.participants);
            Collections.sort(ids);
            List<List<Object>> payloads = new ArrayList<>();
            for (int id : ids) {
                BigInteger K = task.presignK.get(id);
                BigInteger G = task.presignG.get(id);
                ECPoint Y = task.presignY.get(id);
                ECPoint A1 = task.presignA1.get(id);
                ECPoint A2 = task.presignA2.get(id);
                ECPoint B1 = task.presignB1.get(id);
                ECPoint B2 = task.presignB2.get(id);
                if (K == null || G == null || Y == null || A1 == null || A2 == null || B1 == null || B2 == null) {
                    return null;
                }
                List<Object> entry = new ArrayList<>(8);
                entry.add(id);
                entry.add(K.toString(16));
                entry.add(G.toString(16));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(Y)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A1)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(A2)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B1)));
                entry.add(HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(B2)));
                payloads.add(entry);
            }
            return CggmpProtocolUtils.computeTaggedHashHex("PRESIGN_R1_ECHO", sid, payloads);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute presign R1 echo hash", e);
        }
    }

    static String hashJsonMap(Object map) {
        if (map == null) {
            return "null";
        }
        try {
            String json = JsonCodec.toJson(map);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexUtils.bytesToHex(md.digest(json.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
    }

    static Map<String, String> coerceAuxParams(Map<?, ?> map) {
        if (map == null) {
            return null;
        }
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (e.getKey() == null) {
                continue;
            }
            out.put(String.valueOf(e.getKey()), e.getValue() == null ? null : String.valueOf(e.getValue()));
        }
        return out;
    }

    /**
     * 处理预签名Round 1消息，接收K和Gamma承诺
     */
    void handlePresignR1(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpProtocolUtils.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpProtocolUtils.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpProtocolUtils.asInt(dataMap.get("senderId"));
        String kHex = CggmpProtocolUtils.asString(dataMap.get("K"));
        String gHex = CggmpProtocolUtils.asString(dataMap.get("G"));
        String yHex = CggmpProtocolUtils.asString(dataMap.get("Y"));
        String a1Hex = CggmpProtocolUtils.asString(dataMap.get("A1"));
        String a2Hex = CggmpProtocolUtils.asString(dataMap.get("A2"));
        String b1Hex = CggmpProtocolUtils.asString(dataMap.get("B1"));
        String b2Hex = CggmpProtocolUtils.asString(dataMap.get("B2"));
        Map<?, ?> encElgKMap = CggmpProtocolUtils.asMap(dataMap.get("encElgProofK"));
        Map<?, ?> encElgGMap = CggmpProtocolUtils.asMap(dataMap.get("encElgProofG"));
        Map<?, ?> pkMap = CggmpProtocolUtils.asMap(dataMap.get("paillierPublicKey"));
        Map<?, ?> zkMap = CggmpProtocolUtils.asMap(dataMap.get("zkSetup"));
        Map<?, ?> auxMap = CggmpProtocolUtils.asMap(dataMap.get("auxParams"));
        if (auxMap != null) {
            String auxHash = hashJsonMap(auxMap);
            logger.debug("Received PRESIGN_R1 AUX params (taskId={}, senderId={}, auxHash={})", signatureTaskId, senderId, auxHash);
        }
        if (signatureTaskId == null || senderNodeId == null || kHex == null || gHex == null
                || yHex == null || a1Hex == null || a2Hex == null || b1Hex == null || b2Hex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            cachePendingPresignR1(signatureTaskId, senderId, dataMap);
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
        if (auxMap == null) {
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Missing AUX params (presign R1)", Map.of("senderId", senderId)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Missing AUX params from node " + senderId);
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
        Map<String, String> auxParams = coerceAuxParams(auxMap);
        if (svc.ensurePeerAuxConsistency(task, senderId, auxParams)) {
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Inconsistent AUX params (presign R1)", Map.of("auxParams", auxMap)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Inconsistent AUX params from node " + senderId);
            return;
        }
        if (!CggmpSignatureKeyValidator.ensurePeerKeyMatchesAux(task, senderId, publicKey, zkSetup)) {
            String auxHash = CggmpSignatureKeyValidator.computeAuxHash(auxParams);
            String pkHash = CggmpSignatureKeyValidator.computePkHash(publicKey);
            String zkHash = CggmpSignatureKeyValidator.computeZkHash(zkSetup);
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "AUX params mismatch with Paillier/zkSetup (presign R1)",
                            Map.of("auxHash", auxHash, "pkHash", pkHash, "zkHash", zkHash)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "AUX params mismatch with Paillier/zkSetup (presign R1)");
            return;
        }
        if (logger.isDebugEnabled()) {
            String pkHash = hashJsonMap(pkMap);
            String zkHash = hashJsonMap(zkMap);
            logger.debug("Presign R1 recv: taskId={}, senderId={}, pkHash={}, zkHash={}, pkBits={}",
                    signatureTaskId, senderId, pkHash, zkHash, publicKey == null ? -1 : publicKey.bitLength());
        }
        if (!CggmpSignatureKeyValidator.ensurePeerKeyConsistency(task, senderId, publicKey, zkSetup)) {
            if (logger.isDebugEnabled()) {
                String pkHash = hashJsonMap(pkMap);
                String zkHash = hashJsonMap(zkMap);
                PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.get(senderId);
                ZKSetup existingZk = task.peerZkSetups.get(senderId);
                String existingPkHash = hashJsonMap(existingKey == null ? null : CggmpCodecUtils.encodePaillierPublicKey(existingKey));
                String existingZkHash = hashJsonMap(existingZk == null ? null : CggmpCodecUtils.encodeZkSetup(existingZk));
                logger.debug("Presign R1 key mismatch: taskId={}, senderId={}, existingPkHash={}, recvPkHash={}, existingZkHash={}, recvZkHash={}",
                        signatureTaskId, senderId, existingPkHash, pkHash, existingZkHash, zkHash);
            }
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Inconsistent Paillier key/zkSetup (presign R1)", Map.of("paillierPublicKey", pkMap, "zkSetup", zkMap)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Inconsistent Paillier key/zkSetup (presign R1)");
            return;
        }
        byte[] ctxK = CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R1K");
        PresignProofs.EncElgVerifyResult encElgKResult = PresignProofs.verifyEncElgProofDetailed(
                encElgK, publicKey, zkSetup, Secp256k1CurveUtils.G(), A1, Y, A2, K, svc.proofEpsBits, ctxK);
        if (!encElgKResult.ok()) {
            logger.warn("Invalid PiEncElg proof (K) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgKResult.eq1(), encElgKResult.eq2(), encElgKResult.eq3(), encElgKResult.eq4(), encElgKResult.z1InRange());
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiEncElg proof (K)", Map.of("K", kHex)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid PiEncElg proof (K)");
            return;
        }
        byte[] ctxG = CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R1G");
        PresignProofs.EncElgVerifyResult encElgGResult = PresignProofs.verifyEncElgProofDetailed(
                encElgG, publicKey, zkSetup, Secp256k1CurveUtils.G(), B1, Y, B2, G, svc.proofEpsBits, ctxG);
        if (!encElgGResult.ok()) {
            logger.warn("Invalid PiEncElg proof (G) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgGResult.eq1(), encElgGResult.eq2(), encElgGResult.eq3(), encElgGResult.eq4(), encElgGResult.z1InRange());
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiEncElg proof (G)", Map.of("G", gHex)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
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

    /**
     * 处理预签名Round 1 Echo消息，验证承诺一致性
     */
    void handlePresignR1Echo(int senderId, Object data) {
        if (!svc.presignEchoEnabled) {
            return;
        }
        Map<?, ?> dataMap = CggmpProtocolUtils.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpProtocolUtils.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpProtocolUtils.asInt(dataMap.get("senderId"));
        String hash = CggmpProtocolUtils.asString(dataMap.get("hash"));
        if (signatureTaskId == null || senderNodeId == null || hash == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        String expected = computePresignR1EchoHash(task);
        if (expected == null) {
            task.pendingPresignR1Echo.put(senderId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                            Map.of("senderId", senderId, "expected", expected, "received", hash)),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Presign R1 echo mismatch from node " + senderId);
            return;
        }
        if (task.presignR1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR1EchoLatch.getCount() > 0) {
            task.presignR1EchoLatch.countDown();
        }
    }

    /**
     * 验证待处理的预签名Round 1 Echo
     */
    void validatePendingPresignR1Echo(CggmpSignatureTask task) {
        if (task == null || task.pendingPresignR1Echo.isEmpty()) {
            return;
        }
        String expected = computePresignR1EchoHash(task);
        if (expected == null) {
            return;
        }
        for (Map.Entry<Integer, String> e : new HashMap<>(task.pendingPresignR1Echo).entrySet()) {
            int senderId = e.getKey();
            String hash = e.getValue();
            if (!expected.equals(hash)) {
                CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Presign R1 echo mismatch",
                                Map.of("senderId", senderId, "expected", expected, "received", hash)),
                        logger, "CGGMP_PRESIGN_COMPLAINT");
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

    /**
     * 处理预签名Round 2消息，接收MtA协议结果
     */
    void handlePresignR2(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpProtocolUtils.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpProtocolUtils.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpProtocolUtils.asInt(dataMap.get("senderId"));
        String gammaHex = CggmpProtocolUtils.asString(dataMap.get("Gamma"));
        if (signatureTaskId == null || senderNodeId == null || gammaHex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            logger.info("Skip CGGMP_PRESIGN_R2 for task {} on node {} (not a participant, participants={})",
                    task.taskId, svc.nodeId, task.participants);
            return;
        }
        processPresignR2(task, senderId, dataMap);
    }

    /**
     * 处理预签名Round 2数据 - 使用并行验证优化
     */
    void processPresignR2(CggmpSignatureTask task, int senderId, Map<?, ?> dataMap) {
        String gammaHex = CggmpProtocolUtils.asString(dataMap.get("Gamma"));
        if (gammaHex == null) {
            return;
        }
        Map<?, ?> dMap = CggmpProtocolUtils.asMap(dataMap.get("D"));
        Map<?, ?> dhMap = CggmpProtocolUtils.asMap(dataMap.get("Dhat"));
        Map<?, ?> fMap = CggmpProtocolUtils.asMap(dataMap.get("F"));
        Map<?, ?> fhMap = CggmpProtocolUtils.asMap(dataMap.get("Fhat"));
        Map<?, ?> affGMap = CggmpProtocolUtils.asMap(dataMap.get("affGProofs"));
        Map<?, ?> affGhatMap = CggmpProtocolUtils.asMap(dataMap.get("affGProofsHat"));
        Map<?, ?> logProofMap = CggmpProtocolUtils.asMap(dataMap.get("logProof"));
        String xHex = CggmpProtocolUtils.asString(dataMap.get("X"));
        if (dMap == null || dhMap == null || fMap == null || fhMap == null) {
            return;
        }
        
        ECPoint Gamma = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(gammaHex));
        task.presignGamma.put(senderId, Gamma);
        BigIntIndexMap D = BigIntIndexMap.of(CggmpCodecUtils.decodeBigIntegerMap(dMap));
        BigIntIndexMap Dhat = BigIntIndexMap.of(CggmpCodecUtils.decodeBigIntegerMap(dhMap));
        BigIntIndexMap F = BigIntIndexMap.of(CggmpCodecUtils.decodeBigIntegerMap(fMap));
        BigIntIndexMap Fhat = BigIntIndexMap.of(CggmpCodecUtils.decodeBigIntegerMap(fhMap));
        BigInteger dForNode = D.get(svc.nodeId).orElse(null);
        BigInteger dhatForNode = Dhat.get(svc.nodeId).orElse(null);
        logger.info("Presign R2 received for task {} from {}: D keys={}, Dhat keys={}, D[node]={}, Dhat[node]={}",
                task.taskId,
                senderId,
                D.values().keySet(),
                Dhat.values().keySet(),
                dForNode == null ? null : dForNode.toString(16),
                dhatForNode == null ? null : dhatForNode.toString(16));
        
        ECPoint Y = task.presignY.get(senderId);
        ECPoint B1 = task.presignB1.get(senderId);
        ECPoint B2 = task.presignB2.get(senderId);
        if (Y == null || B1 == null || B2 == null) {
            task.pendingPresignR2.put(senderId, copyStringObjectMap(dataMap));
            return;
        }
        
        R2VerifyContext ctx = new R2VerifyContext(
            senderId, gammaHex, dMap, dhMap, fMap, fhMap, 
            affGMap, affGhatMap, logProofMap, xHex, D, Dhat, F, Fhat, Gamma
        );
        
        com.example.mpc.common.util.ThreadPoolUtil.getComputationThreadPool().execute(() -> {
            try {
                R2VerifyResult result = verifyR2Proofs(task, ctx);
                task.r2VerifyResults.put(senderId, result);
            } catch (Exception e) {
                logger.error("R2 verification failed for task {} sender {}", task.taskId, senderId, e);
                task.r2VerifyResults.put(senderId, R2VerifyResult.failure(senderId, e.getMessage()));
            } finally {
                if (task.r2VerifyLatch != null) {
                    task.r2VerifyLatch.countDown();
                }
            }
        });
    }
    
    private static class R2VerifyContext {
        final int senderId;
        final String gammaHex;
        final Map<?, ?> dMap, dhMap, fMap, fhMap;
        final Map<?, ?> affGMap, affGhatMap, logProofMap;
        final String xHex;
        final BigIntIndexMap D, Dhat, F, Fhat;
        final ECPoint Gamma;
        
        R2VerifyContext(int senderId, String gammaHex, Map<?, ?> dMap, Map<?, ?> dhMap, 
                       Map<?, ?> fMap, Map<?, ?> fhMap, Map<?, ?> affGMap, Map<?, ?> affGhatMap,
                       Map<?, ?> logProofMap, String xHex, BigIntIndexMap D, BigIntIndexMap Dhat,
                       BigIntIndexMap F, BigIntIndexMap Fhat, ECPoint Gamma) {
            this.senderId = senderId;
            this.gammaHex = gammaHex;
            this.dMap = dMap;
            this.dhMap = dhMap;
            this.fMap = fMap;
            this.fhMap = fhMap;
            this.affGMap = affGMap;
            this.affGhatMap = affGhatMap;
            this.logProofMap = logProofMap;
            this.xHex = xHex;
            this.D = D;
            this.Dhat = Dhat;
            this.F = F;
            this.Fhat = Fhat;
            this.Gamma = Gamma;
        }
    }
    
    /**
     * 验证 R2 证明 - 可并行执行，只读操作
     */
    private R2VerifyResult verifyR2Proofs(CggmpSignatureTask task, R2VerifyContext ctx) {
        int senderId = ctx.senderId;
        PiLogProof logProof = ctx.logProofMap == null ? null : CggmpCodecUtils.decodePiLogProof(ctx.logProofMap);
        byte[] verifyCtx = CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R2");
        ECPoint Y = task.presignY.get(senderId);
        ECPoint B1 = task.presignB1.get(senderId);
        ECPoint B2 = task.presignB2.get(senderId);
        
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1CurveUtils.G(), Secp256k1CurveUtils.G(), ctx.Gamma, Y, B1, B2, verifyCtx)) {
            return R2VerifyResult.failure(senderId, "Invalid PiLog proof (R2)");
        }
        
        BigInteger curveOrder = Secp256k1CurveUtils.n();
        ECPoint expectedX = null;
        BigInteger lambdaSender = CggmpProtocolUtils.computeSignatureLagrange(task, senderId, curveOrder);
        if (task.publicShares != null) {
            expectedX = CggmpProtocolUtils.resolvePublicShareFromMap(task, senderId, lambdaSender);
        }
        if (expectedX != null && ctx.xHex != null) {
            ECPoint provided = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(ctx.xHex));
            if (!expectedX.equals(provided)) {
                return R2VerifyResult.failure(senderId, "Invalid X in presign R2");
            }
        }
        ECPoint X_i_resolved = expectedX;
        if (X_i_resolved == null && ctx.xHex != null) {
            X_i_resolved = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(ctx.xHex));
        }
        if (X_i_resolved == null) {
            return R2VerifyResult.failure(senderId, "Missing X in presign R2");
        }
        
        if (ctx.affGMap != null && ctx.affGhatMap != null) {
            AffGProofMap proofs = AffGProofMap.of(decodeAffGProofMap(ctx.affGMap));
            AffGProofMap proofsHat = AffGProofMap.of(decodeAffGProofMap(ctx.affGhatMap));
            PiAffGProof proof = proofs.get(svc.nodeId).orElse(null);
            PiAffGProof proofHat = proofsHat.get(svc.nodeId).orElse(null);
            BigInteger D_ji = ctx.D.get(svc.nodeId).orElse(null);
            BigInteger F_ji = ctx.F.get(svc.nodeId).orElse(null);
            BigInteger Dhat_ji = ctx.Dhat.get(svc.nodeId).orElse(null);
            BigInteger Fhat_ji = ctx.Fhat.get(svc.nodeId).orElse(null);
            BigInteger K_self = task.presignK.get(svc.nodeId);
            PaillierEncryption.PublicKey N0 = task.paillier.getPublicKeyInfo();
            PaillierEncryption.PublicKey N1 = task.peerPaillierKeys.get(senderId);
            ECPoint X_i = X_i_resolved;
            
            if (K_self != null && D_ji != null && F_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1CurveUtils.G(),
                        ctx.Gamma,
                        N0.n(),
                        N1.n(),
                        K_self,
                        D_ji,
                        F_ji,
                        svc.proofKappa,
                        svc.proofEpsBits,
                        CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R2")
                );
                if (!affGResult.ok()) {
                    logger.warn("Invalid PiAffG proof from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGResult.index(), affGResult.eq1(), affGResult.eq2(),
                            affGResult.eq3(), affGResult.zInRange(), affGResult.zPrimeInRange());
                    return R2VerifyResult.failure(senderId, "Invalid PiAffG proof");
                }
            }
            if (K_self != null && Dhat_ji != null && Fhat_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGHatResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proofHat,
                        Secp256k1CurveUtils.G(),
                        X_i,
                        N0.n(),
                        N1.n(),
                        K_self,
                        Dhat_ji,
                        Fhat_ji,
                        svc.proofKappa,
                        svc.proofEpsBits,
                        CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R2H")
                );
                if (!affGHatResult.ok()) {
                    logger.warn("Invalid PiAffG proof (hat) from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGHatResult.index(), affGHatResult.eq1(), affGHatResult.eq2(),
                            affGHatResult.eq3(), affGHatResult.zInRange(), affGHatResult.zPrimeInRange());
                    return R2VerifyResult.failure(senderId, "Invalid PiAffG proof (hat)");
                }
            }
        }
        
        if (!ctx.D.containsKey(svc.nodeId) || !ctx.Dhat.containsKey(svc.nodeId)) {
            logger.warn("Presign R2 missing payload for receiver {} from sender {} (D or Dhat not found)", svc.nodeId, senderId);
            return R2VerifyResult.failure(senderId, "Missing payload");
        }
        
        BigInteger D_ji = ctx.D.get(svc.nodeId).orElse(null);
        BigInteger Dhat_ji = ctx.Dhat.get(svc.nodeId).orElse(null);
        BigInteger F_ji = ctx.F.containsKey(svc.nodeId) ? ctx.F.get(svc.nodeId).orElse(null) : null;
        BigInteger Fhat_ji = ctx.Fhat.containsKey(svc.nodeId) ? ctx.Fhat.get(svc.nodeId).orElse(null) : null;
        
        return R2VerifyResult.success(senderId, D_ji, Dhat_ji, F_ji, Fhat_ji, null);
    }
    
    /**
     * 等待所有 R2 验证完成并更新共享状态
     */
    void waitForR2VerifyAndUpdateState(CggmpSignatureTask task) {
        if (task.r2VerifyLatch == null) {
            return;
        }
        
        try {
            task.r2VerifyLatch.await();
            logger.info("R2 verification completed for task {}, processing {} results", task.taskId, task.r2VerifyResults.size());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        
        for (R2VerifyResult result : task.r2VerifyResults.values()) {
            if (!result.success) {
                CggmpProtocolUtils.fireAndForget(
                    svc.broadcastComplaint(task, result.senderId, result.errorMessage, Map.of()),
                    logger, "CGGMP_PRESIGN_COMPLAINT"
                );
                svc.failSignatureTask(task, result.errorMessage);
                return;
            }
            
            task.presignD.put(result.senderId, result.D_ji);
            task.presignDhat.put(result.senderId, result.Dhat_ji);
            if (result.F_ji != null) task.presignF.put(result.senderId, result.F_ji);
            if (result.Fhat_ji != null) task.presignFhat.put(result.senderId, result.Fhat_ji);
            
            if (task.presignR2Received.putIfAbsent(result.senderId, Boolean.TRUE) == null
                    && task.presignR2Latch.getCount() > 0) {
                task.presignR2Latch.countDown();
            }
        }
        
        for (Map.Entry<Integer, java.util.Map<String, Object>> entry : task.pendingPresignR3.entrySet()) {
            processPresignR3(task, entry.getKey(), entry.getValue());
        }
        task.pendingPresignR3.clear();
    }

    /**
     * 处理预签名Round 3消息，接收delta和chi分片
     */
    void handlePresignR3(int senderId, Object data) {
        Map<?, ?> dataMap = CggmpProtocolUtils.asMap(data);
        if (dataMap == null) {
            return;
        }
        String signatureTaskId = CggmpProtocolUtils.asString(dataMap.get("signatureTaskId"));
        Integer senderNodeId = CggmpProtocolUtils.asInt(dataMap.get("senderId"));
        String deltaHex = CggmpProtocolUtils.asString(dataMap.get("delta"));
        String deltaPointHex = CggmpProtocolUtils.asString(dataMap.get("Delta"));
        String sPointHex = CggmpProtocolUtils.asString(dataMap.get("S"));
        if (signatureTaskId == null || senderNodeId == null || deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        if (senderNodeId != senderId) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(svc.nodeId)) {
            return;
        }
        processPresignR3(task, senderId, dataMap);
    }

    /**
     * 处理预签名Round 3数据
     */
    void processPresignR3(CggmpSignatureTask task, int senderId, Map<?, ?> dataMap) {
        String deltaHex = CggmpProtocolUtils.asString(dataMap.get("delta"));
        String deltaPointHex = CggmpProtocolUtils.asString(dataMap.get("Delta"));
        String sPointHex = CggmpProtocolUtils.asString(dataMap.get("S"));
        Map<?, ?> logProofMap = CggmpProtocolUtils.asMap(dataMap.get("logProof"));
        if (deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        PiLogProof logProof = logProofMap == null ? null : CggmpCodecUtils.decodePiLogProof(logProofMap);
        ECPoint Delta = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(deltaPointHex));
        ECPoint S = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(sPointHex));
        byte[] ctx = CggmpProtocolUtils.buildPresignContext(task.taskId, senderId, "R3");
        if (task.presignR2Latch.getCount() > 0) {
            task.pendingPresignR3.put(senderId, copyStringObjectMap(dataMap));
            return;
        }
        ECPoint Gamma = CggmpProtocolUtils.sumPresignGamma(task);
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
            CggmpProtocolUtils.fireAndForget(svc.broadcastComplaint(task, senderId, "Invalid PiLog proof (R3)", ev),
                    logger, "CGGMP_PRESIGN_COMPLAINT");
            svc.failSignatureTask(task, "Invalid presign R3 proof");
            return;
        }
        if (task.presignR3Received.putIfAbsent(senderId, Boolean.TRUE) != null) {
            logger.warn("Duplicate presign R3 from node {} for task {}, ignoring", senderId, task.taskId);
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

    /**
     * 缓存待处理的预签名Round 1数据
     */
    void cachePendingPresignR1(String taskId, int senderId, Map<?, ?> dataMap) {
        if (taskId == null) {
            return;
        }
        ConcurrentHashMap<Integer, Map<String, Object>> pending =
                pendingPresignR1ByTask.computeIfAbsent(taskId, ignored -> new ConcurrentHashMap<>());
        Map<String, Object> normalized = new HashMap<>();
        for (Map.Entry<?, ?> entry : dataMap.entrySet()) {
            if (entry.getKey() instanceof String key) {
                normalized.put(key, entry.getValue());
            }
        }
        pending.put(senderId, normalized);
        logger.debug("Cached presign R1 from node {} for task {} (waiting for task creation)", senderId, taskId);
    }

    /**
     * 处理待处理的预签名Round 1数据
     */
    void drainPendingPresignR1(CggmpSignatureTask task) {
        ConcurrentHashMap<Integer, Map<String, Object>> pending = pendingPresignR1ByTask.remove(task.taskId);
        if (pending == null || pending.isEmpty()) {
            return;
        }
        logger.debug("Replaying {} pending presign R1 messages for task {}", pending.size(), task.taskId);
        for (Map.Entry<Integer, Map<String, Object>> entry : pending.entrySet()) {
            try {
                handlePresignR1(entry.getKey(), entry.getValue());
            } catch (Exception ex) {
                logger.warn("Failed to replay presign R1 from node {} for task {}: {}",
                        entry.getKey(), task.taskId, ex.getMessage());
            }
        }
    }
}
