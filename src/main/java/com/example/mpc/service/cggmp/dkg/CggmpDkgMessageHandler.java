package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.dto.CggmpDkgTask;
import com.example.mpc.service.CggmpDkgService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import com.example.mpc.common.util.RetryUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CGGMP DKG消息处理器
 * 负责接收和处理DKG协议各轮次的网络消息
 */
public final class CggmpDkgMessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpDkgMessageHandler.class);
    private final CggmpDkgService svc;
    private final ConcurrentHashMap<String, ConcurrentHashMap<Integer, Map<String, Object>>> pendingRound1ByTask =
            new ConcurrentHashMap<>();

    public CggmpDkgMessageHandler(CggmpDkgService svc) {
        this.svc = svc;
    }

    /**
     * 广播DKG Round 1 Echo消息
     */
    CompletableFuture<Void> sendDkgRound1Echo(CggmpDkgTask task) {
        String echo = CggmpDkgUtils.computeDkgEchoHash(task);
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", task.executionId);
        data.put("senderId", svc.nodeId);
        data.put("hash", echo);
        return RetryUtils.retryAsync(svc.dkgScheduler, logger,
                () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_ROUND1_ECHO, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_DKG_ROUND1_ECHO");
    }

    /**
     * 处理DKG初始化消息
     */
    void onDkgInit(int senderId, Object data) {
        if (data instanceof Map<?, ?> dataMap) {
            String taskId = (String) dataMap.get("taskId");
            String executionId = (String) dataMap.get("executionId");
            int nodesCount = (Integer) dataMap.get("nodesCount");
            int initiatorId = dataMap.get("initiatorId") instanceof Number n ? n.intValue() : senderId;
            Set<Integer> participants = null;
            if (dataMap.get("participants") instanceof Collection<?> coll) {
                LinkedHashSet<Integer> p = new LinkedHashSet<>();
                for (Object o : coll) {
                    if (o instanceof Number n) {
                        p.add(n.intValue());
                    }
                }
                if (!p.isEmpty()) {
                    participants = p;
                }
            }
            if (participants != null && !isFullParticipants(participants, nodesCount)) {
                logger.error("Rejecting DKG init {}: requires full participation (participants={}, nodesCount={})",
                        taskId, participants.size(), nodesCount);
                return;
            }
            logger.info("Received CGGMP_DKG_INIT from node {} for task: {}, nodesCount: {}, initiatorId={}, participants={}",
                    senderId, taskId, nodesCount, initiatorId, participants == null ? "default" : participants.size());

            if (executionId == null || executionId.isBlank()) {
                throw new RuntimeException("Missing executionId");
            }
            CggmpDkgTask task = svc.createDkgTaskInternal(taskId, executionId, nodesCount, svc.threshold, participants, initiatorId);
            CggmpDkgTask existingTask = svc.dkgTasks.putIfAbsent(taskId, task);

            if (existingTask != null) {
                logger.info("DKG task {} already exists, skipping creation", taskId);
                drainPendingRound1(existingTask);
                return;
            }

            logger.info("Created DKG task {} on node {}", taskId, svc.nodeId);
            drainPendingRound1(task);

            svc.dkgProtocolHandler.startDkgProcessInternal(taskId, false);
        }
    }

    private static boolean isFullParticipants(Set<Integer> participants, int nodesCount) {
        if (participants.size() != nodesCount) {
            return false;
        }
        for (int i = 1; i <= nodesCount; i++) {
            if (!participants.contains(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 处理DKG Round 1消息，接收承诺和公钥分片
     */
    void onDkgRound1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            logger.debug("Skip DKG Round1: invalid payload type from node {} (type={})", senderId,
                    data == null ? "null" : data.getClass().getName());
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        String vCommit = (String) dataMap.get("V");
        if (taskId == null || executionId == null || senderValue == null || vCommit == null) {
            logger.debug("Skip DKG Round1: missing fields (taskId={}, executionId={}, senderId={}, V={}) from node {}",
                    taskId, executionId, senderValue, vCommit == null ? "null" : "present", senderId);
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == svc.nodeId) {
            logger.debug("Skip DKG Round1: sender mismatch or self (senderId={}, payloadSenderId={}, localNode={})",
                    senderId, senderNodeId, svc.nodeId);
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            cachePendingRound1(taskId, senderNodeId, dataMap);
            // 再次检查任务是否已经创建（解决竞态条件问题）
            // 使用同步块确保原子性
            synchronized (pendingRound1ByTask) {
                task = svc.dkgTasks.get(taskId);
                if (task != null) {
                    // 任务已创建，处理所有缓存的消息
                    drainPendingRound1(task);
                }
            }
            return;
        }
        if (!executionId.equals(task.executionId)) {
            logger.debug("Skip DKG Round1: executionId mismatch (taskId={}, senderId={}, expected={}, received={})",
                    taskId, senderNodeId, task.executionId, executionId);
            return;
        }
        if (task.round1Received.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round1PayloadHashes.put(senderNodeId, vCommit);
            task.round1ReceivedLatch.countDown();
        } else {
            logger.debug("Skip DKG Round1: duplicate from node {} (taskId={})", senderNodeId, taskId);
        }
        Map<String, Object> pendingOpen = task.pendingRound2Open.remove(senderNodeId);
        if (pendingOpen != null) {
            processDkgRound2Open(task, senderNodeId, pendingOpen);
        }
        if (task.round1PayloadHashes.size() >= task.participants.size()) {
            if (svc.dkgEchoEnabled) {
                drainPendingRound1Echoes(task);
            }
        }
    }

    /**
     * 处理DKG Round 1 Echo消息，验证承诺一致性
     */
    void onDkgRound1Echo(int senderId, Object data) {
        if (!svc.dkgEchoEnabled) {
            return;
        }
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
        int senderNodeId = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null || senderNodeId == svc.nodeId) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String expected = CggmpDkgUtils.computeDkgEchoHash(task);
        if (expected == null) {
            task.pendingRound1Echo.put(senderNodeId, hash);
            return;
        }
        if (!expected.equals(hash)) {
            logger.warn("Round1 echo mismatch from node {} (task {})", senderNodeId, taskId);
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Round1 echo mismatch",
                            Map.of("senderId", senderNodeId, "expected", expected, "received", hash)),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Round1 echo mismatch from node " + senderNodeId
                    + " expected=" + expected + " received=" + hash;
            task.lastComplaintReason = "Round1 echo mismatch";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = Map.of("senderId", senderNodeId, "expected", expected, "received", hash);
            return;
        }
        if (task.round1EchoReceived.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round1EchoReceivedLatch.countDown();
        }
    }

    /**
     * 处理DKG Round 2消息，接收加密的秘密分片
     */
    void onDkgRound2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        Object receiverValue = dataMap.get("receiverId");
        String sigmaHex = (String) dataMap.get("sigma");
        if (taskId == null || executionId == null || senderValue == null || receiverValue == null || sigmaHex == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        int receiverId = ((Number) receiverValue).intValue();
        if (senderNodeId != senderId || receiverId != svc.nodeId || senderNodeId == svc.nodeId) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        if (task.nonThreshold) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            return;
        }
        Map<Integer, ECPoint> S = task.Xjks.get(senderNodeId);
        if (S == null || S.size() != svc.threshold) {
            task.pendingRound2Shares.put(senderNodeId, Map.of("sigma", sigmaHex));
            return;
        }
        if (!CggmpDkgUtils.verifyDkgShare(S, CggmpDkgUtils.getIndexValue(task, receiverId), new BigInteger(sigmaHex, 16))) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("receiverId", receiverId);
            evidence.put("sigma", sigmaHex);
            evidence.put("S", Secp256k1CurveUtils.encodeECPointMapCompressed(S));
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid share in DKG Round2", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid share from node " + senderNodeId;
            task.lastComplaintReason = "Invalid share in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.xji.computeIfAbsent(senderNodeId, k -> new ConcurrentHashMap<>()).put(svc.nodeId, new BigInteger(sigmaHex, 16));
        task.round2Received.put(senderNodeId, Boolean.TRUE);
        task.round2ReceivedLatch.countDown();
    }

    /**
     * 处理DKG Round 2广播消息
     */
    void onDkgRound2Broad(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        Object senderValue = dataMap.get("senderId");
        if (taskId == null || executionId == null || senderValue == null) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == svc.nodeId) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        String ridPartHex = (String) dataMap.get("ridPart");
        Map<?, ?> sMap = (Map<?, ?>) dataMap.get("S");
        String aHex = (String) dataMap.get("A");
        String uHex = (String) dataMap.get("u");
        String cHex = (String) dataMap.get("c");
        if (ridPartHex == null || sMap == null || aHex == null || uHex == null) {
            return;
        }
        Map<String, Object> open = new LinkedHashMap<>();
        open.put("taskId", taskId);
        open.put("executionId", executionId);
        open.put("senderId", senderNodeId);
        open.put("ridPart", ridPartHex);
        open.put("S", sMap);
        open.put("A", aHex);
        open.put("u", uHex);
        if (cHex != null) {
            open.put("c", cHex);
        }
        processDkgRound2Open(task, senderNodeId, open);
    }

    /**
     * 处理DKG Round 2批量消息
     */
    void onDkgRound2Batch(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        if (taskId == null || executionId == null) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (!executionId.equals(task.executionId)) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == svc.nodeId) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            logger.info("Already received Round2 from node {}, skipping", senderNodeId);
            return;
        }
        Map<?, ?> shares = (Map<?, ?>) dataMap.get("shares");
        if (shares == null || !shares.containsKey(String.valueOf(svc.nodeId))) {
            return;
        }
        Map<?, ?> share = (Map<?, ?>) shares.get(String.valueOf(svc.nodeId));
        if (share == null) {
            return;
        }
        Map<String, Object> flat = new HashMap<>();
        flat.put("taskId", taskId);
        flat.put("executionId", executionId);
        flat.put("senderId", senderNodeId);
        flat.put("receiverId", svc.nodeId);
        flat.put("sigma", share.get("sigma"));
        onDkgRound2(senderId, flat);
    }

    /**
     * 处理DKG Round 3消息，接收公开值和验证数据
     */
    void onDkgRound3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String executionId = (String) dataMap.get("executionId");
        if (taskId == null) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        if (executionId == null || !executionId.equals(task.executionId)) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId) {
            return;
        }
        if (senderNodeId == svc.nodeId) {
            return;
        }
        Map<?, ?> psiMap = (Map<?, ?>) dataMap.get("psi");
        if (psiMap == null) {
            return;
        }
        PiSchProof proof = CggmpCodecUtils.decodePiSchProof(psiMap);
        Map<Integer, ECPoint> aMap = task.Ajks.get(senderNodeId);
        ECPoint A = aMap == null ? null : aMap.get(0);
        if (A == null || task.rid == null) {
            task.pendingRound3Proofs.put(senderNodeId, proof);
            return;
        }
        verifyAndAcceptRound3(task, senderNodeId, proof, A);
    }

    /**
     * 处理DKG投诉消息
     */
    void onDkgComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        Object evidence = dataMap.get("evidence");
        if (taskId == null || reason == null) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received DKG complaint for task {} from node {} against {}: {}", taskId, senderId, offenderId, reason);
        if (evidence instanceof Map<?, ?> ev) {
            task.lastComplaintReason = reason;
            task.lastComplaintOffenderId = offenderId;
            task.lastComplaintEvidence = new HashMap<>();
            for (Map.Entry<?, ?> entry : ev.entrySet()) {
                if (entry.getKey() instanceof String key) {
                    task.lastComplaintEvidence.put(key, entry.getValue());
                }
            }
            if (!validateDkgComplaintEvidence(reason)) {
                logger.warn("Invalid DKG complaint evidence from node {}", senderId);
                if (svc.nodeId == task.initiatorId) {
                    attemptExcludeAndRestartDkg(task, senderId, "Invalid complaint evidence");
                } else {
                    task.fail();
                    task.errorMessage = "DKG complaint invalid evidence from " + senderId;
                }
                return;
            }
        }
        if (svc.nodeId == task.initiatorId && offenderId != null) {
            attemptExcludeAndRestartDkg(task, offenderId, reason);
        } else {
            task.fail();
            task.errorMessage = "DKG complaint: " + reason;
        }
    }

    /**
     * 处理DKG排除消息
     */
    void onDkgExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        if (taskId == null || offenderValue == null) {
            return;
        }
        CggmpDkgTask task = svc.dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        int offenderId = offenderValue instanceof Number n ? n.intValue() : -1;
        task.fail();
        task.errorMessage = "DKG excluded offender " + offenderId + ": " + (reason == null ? "" : reason);
        if (svc.nodeId != task.initiatorId && dataMap.get("newTaskId") instanceof String newTaskId
                && dataMap.get("participants") instanceof Collection<?> coll) {
            LinkedHashSet<Integer> participants = new LinkedHashSet<>();
            for (Object o : coll) {
                if (o instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
            if (!participants.isEmpty()) {
                String newExecutionId = dataMap.get("executionId") instanceof String v ? v : UUID.randomUUID().toString();
                CggmpDkgTask newTask = svc.createDkgTaskInternal(newTaskId, newExecutionId, task.nodesCount, task.threshold, participants, senderId);
                svc.dkgTasks.putIfAbsent(newTaskId, newTask);
                drainPendingRound1(newTask);
                svc.dkgProtocolHandler.startDkgProcessInternal(newTaskId, false);
            }
        }
    }

    /**
     * 处理待处理的Round 1 Echo消息
     */
    public void drainPendingRound1Echoes(CggmpDkgTask task) {
        if (!svc.dkgEchoEnabled) {
            return;
        }
        if (task == null || task.pendingRound1Echo.isEmpty()) {
            return;
        }
        String expected = CggmpDkgUtils.computeDkgEchoHash(task);
        if (expected == null) {
            return;
        }
        for (Map.Entry<Integer, String> e : new HashMap<>(task.pendingRound1Echo).entrySet()) {
            int senderId = e.getKey();
            String hash = e.getValue();
            if (!expected.equals(hash)) {
                logger.warn("Round1 echo mismatch from node {} (task {})", senderId, task.taskId);
                CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderId, "Round1 echo mismatch",
                                Map.of("senderId", senderId, "expected", expected, "received", hash)),
                        logger, "CGGMP_DKG_COMPLAINT");
                task.fail();
                task.errorMessage = "Round1 echo mismatch from node " + senderId
                        + " expected=" + expected + " received=" + hash;
                task.lastComplaintReason = "Round1 echo mismatch";
                task.lastComplaintOffenderId = senderId;
                task.lastComplaintEvidence = Map.of("senderId", senderId, "expected", expected, "received", hash);
                return;
            }
            task.pendingRound1Echo.remove(senderId);
            if (task.round1EchoReceived.putIfAbsent(senderId, Boolean.TRUE) == null) {
                task.round1EchoReceivedLatch.countDown();
            }
        }
    }

    /**
     * 处理待处理的Round 3证明
     */
    void drainPendingRound3(CggmpDkgTask task) {
        if (task == null || task.rid == null || task.pendingRound3Proofs.isEmpty()) {
            return;
        }
        for (Map.Entry<Integer, PiSchProof> e : new HashMap<>(task.pendingRound3Proofs).entrySet()) {
            int senderNodeId = e.getKey();
            PiSchProof proof = e.getValue();
            Map<Integer, ECPoint> aMap = task.Ajks.get(senderNodeId);
            ECPoint A = aMap == null ? null : aMap.get(0);
            if (A == null) {
                continue;
            }
            task.pendingRound3Proofs.remove(senderNodeId);
            verifyAndAcceptRound3(task, senderNodeId, proof, A);
        }
    }

    /**
     * 处理待处理的Round 1消息
     */
    public void drainPendingRound1(CggmpDkgTask task) {
        ConcurrentHashMap<Integer, Map<String, Object>> pending;
        synchronized (pendingRound1ByTask) {
            pending = pendingRound1ByTask.remove(task.taskId);
        }
        if (pending == null || pending.isEmpty()) {
            return;
        }
        logger.info("Replaying {} pending DKG Round1 messages for task {}", pending.size(), task.taskId);
        for (Map.Entry<Integer, Map<String, Object>> entry : pending.entrySet()) {
            try {
                onDkgRound1(entry.getKey(), entry.getValue());
            } catch (Exception ex) {
                logger.warn("Failed to replay pending DKG Round1 from node {} for task {}: {}",
                        entry.getKey(), task.taskId, ex.getMessage());
            }
        }
    }

    private void processDkgRound2Open(CggmpDkgTask task, int senderNodeId, Map<String, Object> open) {
        String taskId = (String) open.get("taskId");
        String executionId = (String) open.get("executionId");
        String ridPartHex = (String) open.get("ridPart");
        Map<?, ?> sMap = (Map<?, ?>) open.get("S");
        String aHex = (String) open.get("A");
        String uHex = (String) open.get("u");
        String cHex = (String) open.get("c");
        if (taskId == null) {
            taskId = task.taskId;
        }
        if (executionId == null) {
            executionId = task.executionId;
        }
        if (ridPartHex == null || sMap == null || aHex == null || uHex == null) {
            return;
        }
        String expected = task.round1PayloadHashes.get(senderNodeId);
        if (expected == null) {
            task.pendingRound2Open.put(senderNodeId, open);
            logger.debug("Cached DKG Round2 open from node {} for task {} (waiting for Round1 commit)", senderNodeId, taskId);
            return;
        }
        String actual = CggmpDkgUtils.computeDkgCommitHashFromWire(executionId, taskId, senderNodeId, ridPartHex, sMap, aHex, uHex, cHex);
        if (!expected.equals(actual)) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", expected);
            evidence.put("actual", actual);
            evidence.put("ridPart", ridPartHex);
            evidence.put("A", aHex);
            evidence.put("S", sMap);
            evidence.put("u", uHex);
            if (cHex != null) {
                evidence.put("c", cHex);
            }
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Round1 commit mismatch", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Round1 commit mismatch from node " + senderNodeId
                    + " expected=" + expected + " actual=" + actual;
            task.lastComplaintReason = "Round1 commit mismatch";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (svc.hdEnabled && (cHex == null || cHex.length() != 64)) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("c", cHex);
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid chain code part in DKG Round2", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid chain code part from node " + senderNodeId;
            task.lastComplaintReason = "Invalid chain code part in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.ridParts.put(senderNodeId, HexUtils.hexToBytes(ridPartHex));
        if (cHex != null) {
            task.chainCodeParts.put(senderNodeId, HexUtils.hexToBytes(cHex));
        }
        Map<Integer, ECPoint> S;
        ECPoint A;
        try {
            S = Secp256k1CurveUtils.decodeECPointMap(sMap);
            A = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(aHex));
        } catch (Exception e) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("error", e.getMessage());
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid Round2 open encoding", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid Round2 open encoding from node " + senderNodeId;
            task.lastComplaintReason = "Invalid Round2 open encoding";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (!task.nonThreshold && S.size() != svc.threshold) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", svc.threshold);
            evidence.put("actual", S.size());
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid commitment vector size in DKG Round2", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid commitment vector size from node " + senderNodeId;
            task.lastComplaintReason = "Invalid commitment vector size in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        if (task.nonThreshold && S.size() != 1) {
            Map<String, Object> evidence = new HashMap<>();
            evidence.put("senderId", senderNodeId);
            evidence.put("expected", 1);
            evidence.put("actual", S.size());
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid commitment vector size in DKG Round2", evidence),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid commitment vector size from node " + senderNodeId;
            task.lastComplaintReason = "Invalid commitment vector size in DKG Round2";
            task.lastComplaintOffenderId = senderNodeId;
            task.lastComplaintEvidence = evidence;
            return;
        }
        task.Xjks.put(senderNodeId, new ConcurrentHashMap<>(S));
        task.Ajks.put(senderNodeId, new ConcurrentHashMap<>(Map.of(0, A)));
        if (task.round2OpenReceived.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round2OpenReceivedLatch.countDown();
        }
        if (task.nonThreshold) {
            return;
        }
        Map<String, String> pending = task.pendingRound2Shares.remove(senderNodeId);
        if (pending != null) {
            String sigmaHex = pending.get("sigma");
            if (sigmaHex != null && CggmpDkgUtils.verifyDkgShare(S, CggmpDkgUtils.getIndexValue(task, svc.nodeId), new BigInteger(sigmaHex, 16))) {
                task.xji.computeIfAbsent(senderNodeId, k -> new ConcurrentHashMap<>()).put(svc.nodeId, new BigInteger(sigmaHex, 16));
                task.round2Received.put(senderNodeId, Boolean.TRUE);
                task.round2ReceivedLatch.countDown();
            }
        }
    }

    private void verifyAndAcceptRound3(CggmpDkgTask task, int senderNodeId, PiSchProof proof, ECPoint A) {
        ECPoint X = CggmpDkgUtils.computePublicShare(task, senderNodeId);
        byte[] ctx = CggmpDkgUtils.buildDkgContext(task.taskId, task.executionId, task.rid, senderNodeId, "SCH");
        if (!CggmpDkgUtils.verifySchProofWithCommitment(Secp256k1CurveUtils.G(), X, A, proof.z(), ctx)) {
            CggmpProtocolUtils.fireAndForget(broadcastDkgComplaint(task, senderNodeId, "Invalid Schnorr proof in DKG Round3", Map.of("senderId", senderNodeId)),
                    logger, "CGGMP_DKG_COMPLAINT");
            task.fail();
            task.errorMessage = "Invalid Schnorr proof from node " + senderNodeId;
            return;
        }
        task.round3SchProofs.put(senderNodeId, proof);
        if (task.round3Received.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round3ReceivedLatch.countDown();
        }
    }

    private CompletableFuture<Void> broadcastDkgComplaint(CggmpDkgTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return RetryUtils.retryAsync(svc.dkgScheduler, logger,
                () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_COMPLAINT, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_DKG_COMPLAINT");
    }

    private CompletableFuture<Void> broadcastDkgExclude(CggmpDkgTask task,
                                                        int offenderId,
                                                        String reason,
                                                        String newTaskId,
                                                        Set<Integer> newParticipants,
                                                        String newExecutionId) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("executionId", newExecutionId);
        data.put("senderId", svc.nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        data.put("newTaskId", newTaskId);
        data.put("participants", new ArrayList<>(newParticipants));
        return RetryUtils.retryAsync(svc.dkgScheduler, logger,
                () -> svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_DKG_EXCLUDE, data)),
                Constants.BROADCAST_RETRY_COUNT,
                Constants.BROADCAST_RETRY_INTERVAL_MS,
                "CGGMP_DKG_EXCLUDE");
    }

    private void attemptExcludeAndRestartDkg(CggmpDkgTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            task.fail();
            task.errorMessage = "DKG complaint (offender not participant): " + reason;
            return;
        }
        Set<Integer> newParticipants = new LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.isEmpty()) {
            task.fail();
            task.errorMessage = "DKG exclusion leaves no participants";
            return;
        }
        String newTaskId = UUID.randomUUID().toString();
        String newExecutionId = UUID.randomUUID().toString();
        CggmpDkgTask newTask = svc.createDkgTaskInternal(newTaskId, newExecutionId, task.nodesCount, task.threshold, newParticipants, task.initiatorId);
        svc.dkgTasks.putIfAbsent(newTaskId, newTask);
        drainPendingRound1(newTask);
        logger.warn("DKG exclusion: offender {} removed, restarting DKG task {}", offenderId, newTaskId);
        CggmpProtocolUtils.fireAndForget(broadcastDkgExclude(task, offenderId, reason, newTaskId, newParticipants, newExecutionId),
                logger, "CGGMP_DKG_EXCLUDE");
        svc.startDkgProcess(newTaskId);
        task.fail();
        task.errorMessage = "DKG restart after excluding offender " + offenderId;
    }

    private boolean validateDkgComplaintEvidence(String reason) {
        try {
            if (reason == null) {
                return false;
            }
            if (reason.startsWith("Invalid share")) {
                return true;
            }
            if (reason.contains("Round1 echo") || reason.contains("Round1 commit") || reason.contains("XkStar")) {
                return true;
            }
            return reason.contains("Schnorr") || reason.contains("PiSch");
        } catch (Exception e) {
            return false;
        }
    }

    private void cachePendingRound1(String taskId, int senderId, Map<?, ?> dataMap) {
        if (taskId == null) {
            return;
        }
        synchronized (pendingRound1ByTask) {
            ConcurrentHashMap<Integer, Map<String, Object>> pending =
                    pendingRound1ByTask.computeIfAbsent(taskId, ignored -> new ConcurrentHashMap<>());
            Map<String, Object> normalized = new HashMap<>();
            for (Map.Entry<?, ?> entry : dataMap.entrySet()) {
                if (entry.getKey() instanceof String key) {
                    normalized.put(key, entry.getValue());
                }
            }
            pending.put(senderId, normalized);
        }
        logger.debug("Cached DKG Round1 from node {} for task {} (waiting for task creation)", senderId, taskId);
    }
}
