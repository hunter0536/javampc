package com.example.mpc.service.cggmp.auxiliary;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpAuxTask;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;

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
        if (expected == null) {
            task.pendingEcho.put(senderNodeId, hash);
            return;
        }
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
        if (taskId == null || senderValue == null || pkObj == null || hatNStr == null || sStr == null || tStr == null) {
            return;
        }
        int senderIdVal = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpAuxTask task = svc.auxTasks.get(taskId);
        if (task == null || !task.status.get().isRunning()) {
            enqueuePending(taskId, new PendingMsg(senderId, data, MessageType.CGGMP_AUX_R2));
            return;
        }
        if (pkObj instanceof Map<?, ?> pkMap) {
            task.peerPaillierKeys.put(senderIdVal, CggmpCodecUtils.decodePaillierPublicKey(pkMap));
        }
        Object prmObj = dataMap.get("prmProof");
        if (prmObj instanceof Map<?, ?> prmMap) {
            task.peerPrmProofs.put(senderIdVal, CggmpCodecUtils.decodePiPrmProof(prmMap));
        }
        task.peerHatN.put(senderIdVal, new BigInteger(hatNStr, 16));
        task.peerS.put(senderIdVal, new BigInteger(sStr, 16));
        task.peerT.put(senderIdVal, new BigInteger(tStr, 16));
        task.revealLatch.countDown();
        logger.debug("AUX R2 received: taskId={}, senderId={}, revealReceived={}, revealLatch={}",
                taskId, senderIdVal, task.peerHatN.size(), task.revealLatch.getCount());
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
        byte[] rho = CggmpAuxUtils.xorAuxRho(svc.nodeId, task);
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

    static final class PendingMsg {
        final int senderId;
        final Object data;
        final MessageType type;

        PendingMsg(int senderId, Object data, MessageType type) {
            this.senderId = senderId;
            this.data = data;
            this.type = type;
        }
    }
}
