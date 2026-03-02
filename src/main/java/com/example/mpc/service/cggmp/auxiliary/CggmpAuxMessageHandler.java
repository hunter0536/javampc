package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpAuxTask;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class CggmpAuxMessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpAuxMessageHandler.class);
    private final CggmpAuxService svc;
    private final ConcurrentHashMap<String, java.util.concurrent.ConcurrentLinkedQueue<PendingMsg>> pendingAuxMessages =
            new ConcurrentHashMap<>();

    public CggmpAuxMessageHandler(CggmpAuxService svc) {
        this.svc = svc;
    }

    void handleCggmpAuxInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object initiatorValue = dataMap.get("initiatorId");
        Object participantsValue = dataMap.get("participants");
        if (taskId == null || executionId == null || initiatorValue == null || !(participantsValue instanceof List<?> list)) {
            return;
        }
        int initiatorId = initiatorValue instanceof Number n ? n.intValue() : senderId;
        Set<Integer> participants = new java.util.LinkedHashSet<>();
        for (Object o : list) {
            if (o instanceof Number n) {
                participants.add(n.intValue());
            }
        }
        logger.debug("AUX INIT received: taskId={}, executionId={}, initiatorId={}, senderId={}, participants={}",
                taskId, executionId, initiatorId, senderId, participants);
        if (participants.isEmpty()) {
            return;
        }
        if (!participants.contains(svc.nodeId)) {
            return;
        }
        CggmpAuxTask task = svc.auxTasks.computeIfAbsent(taskId, id -> new CggmpAuxTask(taskId, executionId, svc.nodesCount, initiatorId, participants));
        if (!task.start()) {
            return;
        }
        drainPending(taskId);
        try {
            svc.nodeService.waitForNetworkReady()
                    .thenRun(() -> logger.debug("AUX INIT network ready: taskId={}, executionId={}",
                            task.taskId, task.executionId))
                    .thenCompose(v -> svc.auxProtocolHandler.runAuxProtocolAsync(task))
                    .whenComplete((v, ex) -> {
                        if (ex == null) {
                            task.complete();
                        } else {
                            task.fail(ex.getMessage());
                            logger.error("Error in CGGMP AUX process", ex);
                        }
                    });
        } catch (Exception e) {
            task.fail(e.getMessage());
            logger.error("Error in CGGMP AUX process", e);
        }
    }

    void handleCggmpAuxR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object senderValue = dataMap.get("senderId");
        String vCommit = (String) dataMap.get("V");
        if (taskId == null || senderValue == null || vCommit == null) {
            return;
        }
        int senderIdVal = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpAuxTask task = svc.auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R1));
            return;
        }
        task.commitHashes.put(senderIdVal, vCommit);
        task.commitLatch.countDown();
        String vShort = vCommit.length() > 12 ? vCommit.substring(0, 12) : vCommit;
        logger.debug("AUX R1 received: taskId={}, senderId={}, V={}, commitReceived={}, commitLatch={}",
                taskId, senderIdVal, vShort, task.commitHashes.size(), task.commitLatch.getCount());
        Map<String, Object> pending = task.pendingReveal.remove(senderIdVal);
        if (pending != null) {
            processAuxR2(task, senderIdVal, pending);
        }
    }

    void handleCggmpAuxR1Echo(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        String hash = (String) dataMap.get("hash");
        if (taskId == null || executionId == null || senderValue == null || hash == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == svc.nodeId) {
            return;
        }
        CggmpAuxTask task = svc.auxTasks.get(taskId);
        if (task == null) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R1_ECHO));
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String expected = CggmpProtocolUtils.computeAuxEchoHash(task);
        if (!expected.equals(hash)) {
            logger.warn("AUX echo mismatch from node {} (task {}): expected={}, received={}, commits={}/{}",
                    senderNodeId, taskId, expected, hash, task.commitHashes.size(), task.participants.size());
            task.fail("AUX echo mismatch");
            task.errorMessage = "AUX echo mismatch from node " + senderNodeId + " expected=" + expected + " received=" + hash;
            return;
        }
        task.echoReceived.put(senderNodeId, Boolean.TRUE);
        task.echoLatch.countDown();
        logger.debug("AUX R1 echo received: taskId={}, senderId={}, echoReceived={}, echoLatch={}",
                taskId, senderNodeId, task.echoReceived.size(), task.echoLatch.getCount());
    }

    void handleCggmpAuxR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object senderValue = dataMap.get("senderId");
        Object pkObj = dataMap.get("paillierPublicKey");
        String hatNStr = (String) dataMap.get("hatN");
        String sStr = (String) dataMap.get("s");
        String tStr = (String) dataMap.get("t");
        String rhoHex = (String) dataMap.get("rho");
        String uHex = (String) dataMap.get("u");
        if (taskId == null || senderValue == null || pkObj == null || hatNStr == null || sStr == null || tStr == null || rhoHex == null || uHex == null) {
            logger.warn("AUX R2 missing fields (taskId={}, senderId={}, hasTaskId={}, hasSenderId={}, hasPk={}, hasHatN={}, hasS={}, hasT={}, hasRho={}, hasU={})",
                    taskId,
                    senderId,
                    taskId != null,
                    senderValue != null,
                    pkObj != null,
                    hatNStr != null,
                    sStr != null,
                    tStr != null,
                    rhoHex != null,
                    uHex != null);
            return;
        }
        int senderIdVal = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpAuxTask task = svc.auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            logger.warn("AUX R2 ignored: task missing or not running (taskId={}, senderId={}, taskExists={}, status={})",
                    taskId,
                    senderIdVal,
                    task != null,
                    task == null ? null : task.status.get());
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R2));
            return;
        }
        processAuxR2(task, senderIdVal, dataMap);
    }

    private void processAuxR2(CggmpAuxTask task, int senderIdVal, Map<?, ?> dataMap) {
        if (task == null || dataMap == null) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object pkObj = dataMap.get("paillierPublicKey");
        String hatNStr = (String) dataMap.get("hatN");
        String sStr = (String) dataMap.get("s");
        String tStr = (String) dataMap.get("t");
        String rhoHex = (String) dataMap.get("rho");
        String uHex = (String) dataMap.get("u");
        Object prmObj = dataMap.get("prmProof");
        if (taskId == null || pkObj == null || hatNStr == null || sStr == null || tStr == null || rhoHex == null || uHex == null) {
            return;
        }
        String commit = task.commitHashes.get(senderIdVal);
        if (commit == null) {
            Map<String, Object> pending = new java.util.HashMap<>();
            for (Map.Entry<?, ?> entry : dataMap.entrySet()) {
                Object key = entry.getKey();
                if (key instanceof String s) {
                    pending.put(s, entry.getValue());
                }
            }
            task.pendingReveal.putIfAbsent(senderIdVal, pending);
            logger.debug("AUX R2 pending: missing R1 commit (taskId={}, senderId={})", taskId, senderIdVal);
            return;
        }
        if (!(pkObj instanceof Map<?, ?> pkMap)) {
            logger.warn("AUX R2 invalid paillierPublicKey type (taskId={}, senderId={}, type={})",
                    taskId, senderIdVal, pkObj == null ? null : pkObj.getClass().getName());
            return;
        }
        Map<String, Object> pkMapCopy = new java.util.HashMap<>();
        for (Map.Entry<?, ?> entry1 : pkMap.entrySet()) {
            Object key = entry1.getKey();
            if (key instanceof String s) {
                pkMapCopy.put(s, entry1.getValue());
            }
        }
        PaillierEncryption.PublicKey publicKey = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
        if (publicKey.bitLength() < svc.auxMinPaillierBitsForProof) {
            logger.warn("AUX R2 Paillier bitLength too small (taskId={}, senderId={}, bits={}, min={})",
                    taskId, senderIdVal, publicKey.bitLength(), svc.auxMinPaillierBitsForProof);
            task.fail("AUX R2 Paillier bit length too small: " + publicKey.bitLength());
            return;
        }
        byte[] rho = HexUtils.hexToBytes(rhoHex);
        byte[] u = HexUtils.hexToBytes(uHex);
        Map<?, ?> prmMap = prmObj instanceof Map<?, ?> map ? map : null;
        Map<String, Object> prmMapCopy = null;
        if (prmMap != null) {
            prmMapCopy = new java.util.HashMap<>();
            for (Map.Entry<?, ?> entry : prmMap.entrySet()) {
                Object key = entry.getKey();
                if (key instanceof String s) {
                    prmMapCopy.put(s, entry.getValue());
                }
            }
        }
        String expectedCommit = CggmpProtocolUtils.computeAuxCommitHash(task.executionId, task.taskId, senderIdVal,
                pkMapCopy, hatNStr, sStr, tStr, prmMapCopy, rho, u);
        if (!commit.equals(expectedCommit)) {
            logger.warn("AUX R2 commit mismatch (taskId={}, senderId={}, expected={}, got={})",
                    task.taskId, senderIdVal, expectedCommit, commit);
            task.fail("AUX R2 commit mismatch from node " + senderIdVal);
            return;
        }
        BigInteger hatN = new BigInteger(hatNStr, 16);
        BigInteger s = new BigInteger(sStr, 16);
        BigInteger t = new BigInteger(tStr, 16);
        if (logger.isDebugEnabled()) {
            String hatNHash;
            String sHash;
            String tHash;
            try {
                hatNHash = HexUtils.bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(hatN.toByteArray()));
                sHash = HexUtils.bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray()));
                tHash = HexUtils.bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(t.toByteArray()));
            } catch (Exception e) {
                hatNHash = "error";
                sHash = "error";
                tHash = "error";
            }
            logger.debug("AUX R2 params hash: taskId={}, senderId={}, hatNHash={}, sHash={}, tHash={}",
                    taskId, senderIdVal, hatNHash, sHash, tHash);
        }
        if (hatN.signum() <= 0 || s.signum() <= 0 || t.signum() <= 0 || s.compareTo(hatN) >= 0 || t.compareTo(hatN) >= 0) {
            logger.warn("AUX R2 invalid Pedersen params (taskId={}, senderId={}, hatN.sign={}, s.sign={}, t.sign={}, s>=hatN={}, t>=hatN={})",
                    taskId,
                    senderIdVal,
                    hatN.signum(),
                    s.signum(),
                    t.signum(),
                    s.compareTo(hatN) >= 0,
                    t.compareTo(hatN) >= 0);
            task.fail("Invalid Pedersen params in AUX R2");
            return;
        }
        if (prmMap == null) {
            logger.warn("AUX R2 missing PiPrmProof (taskId={}, senderId={})", taskId, senderIdVal);
            task.fail("Missing PiPrmProof in AUX R2");
            return;
        }
        var prmProof = CggmpCodecUtils.decodePiPrmProof(prmMap);
        byte[] prmCtx = CggmpProtocolUtils.buildAuxContext(task.taskId, task.executionId, senderIdVal, "PRM");
        if (!RefreshProofs.verifyPrmProof(prmProof, hatN, s, t, prmCtx)) {
            String ctxHex = HexUtils.bytesToHex(prmCtx);
            String ctxHash;
            try {
                ctxHash = HexUtils.bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(prmCtx));
            } catch (Exception e) {
                ctxHash = "error";
            }
            String aHex = prmProof.A() == null ? null : prmProof.A().toString(16);
            String zHex = prmProof.z() == null ? null : prmProof.z().toString(16);
            logger.warn("AUX R2 invalid PiPrmProof (taskId={}, senderId={}, ctxHash={}, ctxPrefix={}, hatNBits={}, sBits={}, tBits={}, A.prefix={}, z.prefix={})",
                    taskId,
                    senderIdVal,
                    ctxHash,
                    ctxHex.length() > 24 ? ctxHex.substring(0, 24) : ctxHex,
                    hatN.bitLength(),
                    s.bitLength(),
                    t.bitLength(),
                    aHex == null ? null : aHex.substring(0, Math.min(24, aHex.length())),
                    zHex == null ? null : zHex.substring(0, Math.min(24, zHex.length())));
            task.fail("Invalid PiPrmProof in AUX R2 from node " + senderIdVal);
            return;
        }

        PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.putIfAbsent(senderIdVal, publicKey);
        if (existingKey != null && !paillierKeyEquals(existingKey, publicKey)) {
            task.fail("Inconsistent Paillier key in AUX R2 from node " + senderIdVal);
            return;
        }
        PiPrmProof existingPrm = task.peerPrmProofs.putIfAbsent(senderIdVal, prmProof);
        if (existingPrm != null && !existingPrm.equals(prmProof)) {
            task.fail("Inconsistent PiPrmProof in AUX R2 from node " + senderIdVal);
            return;
        }
        BigInteger existingHatN = task.peerHatN.putIfAbsent(senderIdVal, hatN);
        if (existingHatN != null && !existingHatN.equals(hatN)) {
            task.fail("Inconsistent hatN in AUX R2 from node " + senderIdVal);
            return;
        }
        BigInteger existingS = task.peerS.putIfAbsent(senderIdVal, s);
        if (existingS != null && !existingS.equals(s)) {
            task.fail("Inconsistent s in AUX R2 from node " + senderIdVal);
            return;
        }
        BigInteger existingT = task.peerT.putIfAbsent(senderIdVal, t);
        if (existingT != null && !existingT.equals(t)) {
            task.fail("Inconsistent t in AUX R2 from node " + senderIdVal);
            return;
        }
        byte[] existingRho = task.rho.putIfAbsent(senderIdVal, rho);
        if (existingRho != null && !java.util.Arrays.equals(existingRho, rho)) {
            task.fail("Inconsistent rho in AUX R2 from node " + senderIdVal);
            return;
        }
        byte[] existingU = task.u.putIfAbsent(senderIdVal, u);
        if (existingU != null && !java.util.Arrays.equals(existingU, u)) {
            task.fail("Inconsistent u in AUX R2 from node " + senderIdVal);
            return;
        }

        task.revealLatch.countDown();
        logger.debug("AUX R2 received: taskId={}, senderId={}, revealReceived={}, revealLatch={}",
                task.taskId, senderIdVal, task.peerHatN.size(), task.revealLatch.getCount());
    }

    private boolean paillierKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        return a.n().equals(b.n()) && a.nSquared().equals(b.nSquared()) && a.g().equals(b.g()) && a.bitLength() == b.bitLength();
    }

    void handleCggmpAuxR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        Map<?, ?> modMap = (Map<?, ?>) dataMap.get("modProof");
        Map<?, ?> facMap = (Map<?, ?>) dataMap.get("facProofs");
        if (taskId == null || executionId == null || senderValue == null || modMap == null || facMap == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == svc.nodeId) {
            return;
        }
        CggmpAuxTask task = svc.auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R3));
            return;
        }
        if (!executionId.equals(task.executionId)) {
            logger.warn("AUX R3 ignored: executionId mismatch (taskId={}, senderId={}, expected={}, got={})",
                    taskId, senderNodeId, task.executionId, executionId);
            return;
        }
        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderNodeId);
        if (pk == null) {
            logger.warn("AUX R3 ignored: missing peer Paillier key (taskId={}, senderId={}, peers={})",
                    taskId, senderNodeId, task.peerPaillierKeys.keySet());
            return;
        }
        BiPrimeBlumProof modProof = CggmpCodecUtils.decodeBiPrimeProof(modMap);
        byte[] rho = CggmpAuxUtils.xorAuxRho(task);
        byte[] modCtx = CggmpProtocolUtils.buildAuxContext(taskId, task.executionId, senderNodeId, "MOD", rho);
        if (!CggmpAuxService.BI_PRIME_VALIDATOR.verifyProof(modProof, pk, modCtx)) {
            logger.warn("AUX R3 invalid mod proof (taskId={}, senderId={})", taskId, senderNodeId);
            task.fail("Invalid AUX mod proof");
            return;
        }
        Object facForMe = facMap.get(String.valueOf(svc.nodeId));
        if (!(facForMe instanceof Map<?, ?> facProofMap)) {
            logger.warn("AUX R3 missing fac proof for node {} (taskId={}, senderId={})", svc.nodeId, taskId, senderNodeId);
            task.fail("Missing AUX fac proof");
            return;
        }
        BigInteger hatN = task.hatN;
        BigInteger s = task.s;
        BigInteger t = task.t;
        NoSmallFactorProof facProof = CggmpCodecUtils.decodeNoSmallFactorProof(facProofMap);
        ZKSetup zk = new ZKSetup(hatN, s, t);
        NoSmallFactorProofValidator facValidator = new NoSmallFactorProofValidator(zk, svc.auxMinPaillierBitsForProof);
        NoSmallFactorProofValidator.ProofCheckResult facResult = facValidator.verifyProofDetailed(facProof, pk, modCtx);
        if (!facResult.ok()) {
            logger.warn("AUX R3 invalid fac proof (taskId={}, senderId={}, reason={})",
                    taskId, senderNodeId, facResult.reason());
            task.fail("Invalid AUX fac proof");
            return;
        }
        task.peerModProofs.put(senderNodeId, modProof);
        task.peerFacProofs.put(senderNodeId, facProof);
        task.proofLatch.countDown();
        logger.debug("AUX R3 received: taskId={}, senderId={}, proofsReceived={}, proofLatch={}",
                taskId, senderNodeId, task.peerModProofs.size(), task.proofLatch.getCount());
    }

    void handleCggmpAuxStatus(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        Object hasAuxValue = dataMap.get("hasAux");
        if (hasAuxValue == null) {
            return;
        }
        boolean hasAux = Boolean.TRUE.equals(hasAuxValue);
        long ts = System.currentTimeMillis();
        Object tsValue = dataMap.get("ts");
        if (tsValue instanceof Number n) {
            ts = n.longValue();
        }
        svc.auxStatus.put(senderId, new CggmpAuxService.AuxStatus(hasAux, ts));
    }

    void enqueuePending(String taskId, PendingMsg msg) {
        if (taskId == null) return;
        pendingAuxMessages.computeIfAbsent(taskId, id -> new java.util.concurrent.ConcurrentLinkedQueue<>()).add(msg);
    }

    public void drainPending(String taskId) {
        java.util.concurrent.ConcurrentLinkedQueue<PendingMsg> q = pendingAuxMessages.get(taskId);
        if (q == null || q.isEmpty()) {
            return;
        }
        PendingMsg msg;
        while ((msg = q.poll()) != null) {
            switch (msg.type) {
                case CGGMP_AUX_R1 -> handleCggmpAuxR1(msg.senderId, msg.data);
                case CGGMP_AUX_R1_ECHO -> handleCggmpAuxR1Echo(msg.senderId, msg.data);
                case CGGMP_AUX_R2 -> handleCggmpAuxR2(msg.senderId, msg.data);
                case CGGMP_AUX_R3 -> handleCggmpAuxR3(msg.senderId, msg.data);
                default -> {
                }
            }
        }
        pendingAuxMessages.remove(taskId, q);
    }

    record PendingMsg(int senderId, Object data, MessageType type) {
    }
}
