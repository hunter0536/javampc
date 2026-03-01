package com.example.mpc.service.cggmp.refresh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonUtils;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpRefreshTask;
import com.example.mpc.service.CggmpRefreshService;
import com.example.mpc.service.NodeService;
import com.example.mpc.service.cggmp.CggmpCodecUtils;
import com.example.mpc.service.cggmp.CggmpProtocolUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class CggmpRefreshMessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpRefreshMessageHandler.class);
    private final CggmpRefreshService svc;

    public CggmpRefreshMessageHandler(CggmpRefreshService svc) {
        this.svc = svc;
    }

    CompletableFuture<Void> sendRefreshR1(CggmpRefreshTask task, String commit) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("initiatorId", task.initiatorId);
        data.put("participants", new ArrayList<>(task.participants));
        data.put("commit", commit);
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_REFRESH_R1, data));
    }

    CompletableFuture<Void> sendRefreshR2(CggmpRefreshTask task, CggmpRefreshTask.RefreshRound2Data r2) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("paillierPublicKey", CggmpCodecUtils.encodePaillierPublicKey(r2.paillierKey));
        data.put("zkSetup", CggmpCodecUtils.encodeZkSetup(r2.zkSetup));
        data.put("hatN", r2.hatN.toString(16));
        data.put("s", r2.s.toString(16));
        data.put("t", r2.t.toString(16));
        data.put("prmProof", CggmpCodecUtils.encodePiPrmProof(r2.prmProof));
        data.put("Y", Secp256k1CurveUtils.encodeECPointMap(r2.Y));
        data.put("X", Secp256k1CurveUtils.encodeECPointMap(r2.X));
        data.put("A", Secp256k1CurveUtils.encodeECPointMap(r2.A));
        data.put("Xi", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(r2.Xi)));
        data.put("rid", Base64.getEncoder().encodeToString(r2.rid));
        data.put("u", Base64.getEncoder().encodeToString(r2.u));
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_REFRESH_R2, data));
    }

    CompletableFuture<Void> sendRefreshR3(CggmpRefreshTask task, CggmpRefreshTask.RefreshRound3Data r3) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("C", JsonUtils.encodeBigIntegerMap(r3.C));
        data.put("schProofs", CggmpCodecUtils.encodeSchProofMap(r3.schProofs));
        data.put("biPrimeProof", CggmpCodecUtils.encodeBiPrimeProof(r3.biPrimeProof));
        data.put("factorProof", CggmpCodecUtils.encodeNoSmallFactorProof(r3.factorProof));
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_REFRESH_R3, data));
    }

    CompletableFuture<Void> broadcastRefreshComplaint(CggmpRefreshTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null) {
            data.put("evidence", evidence);
        }
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_REFRESH_COMPLAINT, data));
    }

    CompletableFuture<Void> broadcastRefreshExclude(CggmpRefreshTask task, int offenderId, String reason, String newTaskId, Set<Integer> newParticipants) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", svc.nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        data.put("newTaskId", newTaskId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("participants", new ArrayList<>(newParticipants));
        return svc.nodeService.broadcastMessage(new NodeService.Message(svc.nodeId, MessageType.CGGMP_REFRESH_EXCLUDE, data));
    }

    void onRefreshR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == svc.nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String groupPublicKey = (String) dataMap.get("groupPublicKey");
        Object participantsValue = dataMap.get("participants");
        Object initiatorValue = dataMap.get("initiatorId");
        String commit = (String) dataMap.get("commit");
        if (taskId == null || groupPublicKey == null || commit == null) {
            return;
        }
        int initiatorId = initiatorValue instanceof Number n ? n.intValue() : senderId;
        Set<Integer> participants = new LinkedHashSet<>();
        if (participantsValue instanceof List<?> list) {
            for (Object v : list) {
                if (v instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
        }
        if (participants.isEmpty()) {
            for (int i = 1; i <= svc.nodesCount; i++) {
                participants.add(i);
            }
        }
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null) {
            task = new CggmpRefreshTask(taskId, groupPublicKey, svc.nodesCount, initiatorId, participants);
            svc.refreshTasks.put(taskId, task);
        }
        if (!task.participants.contains(senderId)) {
            return;
        }
        if (task.round1Commit.putIfAbsent(senderId, commit) == null && task.round1Latch.getCount() > 0) {
            task.round1Latch.countDown();
        }
        if (task.participants.contains(svc.nodeId) && !task.isInProgress() && !task.isCompleted()) {
            svc.startRefreshTask(taskId).exceptionally(ex -> {
                logger.error("Failed to auto-start refresh task {}: {}", taskId, ex.getMessage());
                return null;
            });
        }
    }

    void onRefreshR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == svc.nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            String hatNHex = (String) dataMap.get("hatN");
            String sHex = (String) dataMap.get("s");
            String tHex = (String) dataMap.get("t");
            Map<?, ?> prmMap = (Map<?, ?>) dataMap.get("prmProof");
            Map<?, ?> yMap = (Map<?, ?>) dataMap.get("Y");
            Map<?, ?> xMap = (Map<?, ?>) dataMap.get("X");
            Map<?, ?> aMap = (Map<?, ?>) dataMap.get("A");
            String xiHex = (String) dataMap.get("Xi");
            String ridB64 = (String) dataMap.get("rid");
            String uB64 = (String) dataMap.get("u");

            if (pkMap == null || zkMap == null || hatNHex == null || sHex == null || tHex == null || prmMap == null
                    || yMap == null || xMap == null || aMap == null || xiHex == null || ridB64 == null || uB64 == null) {
                return;
            }

            PaillierEncryption.PublicKey pk = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zk = CggmpCodecUtils.decodeZkSetup(zkMap);
            BigInteger hatN = new BigInteger(hatNHex, 16);
            BigInteger s = new BigInteger(sHex, 16);
            BigInteger t = new BigInteger(tHex, 16);
            PiPrmProof prmProof = CggmpCodecUtils.decodePiPrmProof(prmMap);
            Map<Integer, ECPoint> Y = Secp256k1CurveUtils.decodeECPointMap(yMap);
            Map<Integer, ECPoint> X = Secp256k1CurveUtils.decodeECPointMap(xMap);
            Map<Integer, ECPoint> A = Secp256k1CurveUtils.decodeECPointMap(aMap);
            ECPoint Xi = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(xiHex));
            byte[] rid = Base64.getDecoder().decode(ridB64);
            byte[] u = Base64.getDecoder().decode(uB64);

            String commit = task.round1Commit.get(senderId);
            if (commit == null) {
                CggmpProtocolUtils.fireAndForget(broadcastRefreshComplaint(task, senderId, "Missing refresh R1 commit",
                        refreshEvidence(task, senderId, "Missing refresh R1 commit", null)), logger, "CGGMP_REFRESH_COMPLAINT");
                task.fail("Missing refresh R1 commit");
                return;
            }

            String expected = CggmpRefreshUtils.computeRefreshCommit(task.taskId, senderId, X, Y, A, Xi, pk, zk, hatN, s, t, prmProof, rid, u);
            if (!commit.equals(expected)) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("expectedCommit", expected);
                extra.put("commit", commit);
                CggmpProtocolUtils.fireAndForget(broadcastRefreshComplaint(task, senderId, "Refresh R1 commit mismatch",
                        refreshEvidence(task, senderId, "Refresh R1 commit mismatch", extra)), logger, "CGGMP_REFRESH_COMPLAINT");
                task.fail("Refresh commit mismatch");
                return;
            }

            if (!CggmpRefreshUtils.validatePaillierPublicKey(pk)) {
                CggmpProtocolUtils.fireAndForget(broadcastRefreshComplaint(task, senderId, "Invalid Paillier public key",
                                refreshEvidence(task, senderId, "Invalid Paillier public key", Map.of("n", pk.n.toString(16)))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                task.fail("Invalid Paillier key");
                return;
            }

            if (!RefreshProofs.verifyPrmProof(prmProof, hatN, s, t, CggmpRefreshUtils.buildRefreshContext(task.taskId, null, senderId, "PRM"))) {
                CggmpProtocolUtils.fireAndForget(broadcastRefreshComplaint(task, senderId, "Invalid PiPrm proof",
                                refreshEvidence(task, senderId, "Invalid PiPrm proof", Map.of("hatN", hatN.toString(16)))),
                        logger, "CGGMP_REFRESH_COMPLAINT");
                task.fail("Invalid PiPrm proof");
                return;
            }

            CggmpRefreshTask.RefreshRound2Data r2 = new CggmpRefreshTask.RefreshRound2Data(
                    pk, zk, hatN, s, t, prmProof, Y, X, A, Xi, rid, u
            );
            if (task.round2Data.putIfAbsent(senderId, r2) == null && task.round2Latch.getCount() > 0) {
                task.round2Latch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle refresh R2", e);
        }
    }

    void onRefreshR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == svc.nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            Map<?, ?> cMap = (Map<?, ?>) dataMap.get("C");
            Map<?, ?> schMap = (Map<?, ?>) dataMap.get("schProofs");
            Map<?, ?> biPrimeMap = (Map<?, ?>) dataMap.get("biPrimeProof");
            Map<?, ?> factorMap = (Map<?, ?>) dataMap.get("factorProof");
            if (cMap == null || schMap == null || biPrimeMap == null || factorMap == null) {
                return;
            }
            Map<Integer, BigInteger> C = JsonUtils.decodeBigIntegerMap(cMap);
            Map<Integer, PiSchProof> schProofs = CggmpCodecUtils.decodeSchProofMap(schMap);
            BiPrimeBlumProof biPrime = CggmpCodecUtils.decodeBiPrimeProof(biPrimeMap);
            NoSmallFactorProof factor = CggmpCodecUtils.decodeNoSmallFactorProof(factorMap);

            CggmpRefreshTask.RefreshRound3Data r3 = new CggmpRefreshTask.RefreshRound3Data(C, schProofs, biPrime, factor);
            if (task.round3Data.putIfAbsent(senderId, r3) == null && task.round3Latch.getCount() > 0) {
                task.round3Latch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle refresh R3", e);
        }
    }

    void onRefreshComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        Object evidenceObj = dataMap.get("evidence");
        logComplaintToFile(taskId, senderId, offenderId, reason == null ? "refresh complaint" : reason, evidenceObj);
        Map<?, ?> evidence = evidenceObj instanceof Map<?, ?> m ? m : null;
        boolean evidenceOk = validateRefreshComplaintEvidence(task, offenderId, reason, evidence);
        if (task.initiatorId == svc.nodeId) {
            if (!evidenceOk) {
                attemptExcludeAndRestartRefresh(task, senderId, "Invalid refresh complaint evidence");
                return;
            }
            if (offenderId != null) {
                attemptExcludeAndRestartRefresh(task, offenderId, reason == null ? "refresh complaint" : reason);
                return;
            }
            task.fail("Refresh complaint without offender");
            return;
        }
        if (!evidenceOk) {
            task.fail("Refresh complaint invalid: " + (reason == null ? "unknown" : reason));
            return;
        }
        task.fail("Refresh complaint: " + (reason == null ? "unknown" : reason));
    }

    void onRefreshExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        String newTaskId = (String) dataMap.get("newTaskId");
        String groupPublicKey = (String) dataMap.get("groupPublicKey");
        Object participantsValue = dataMap.get("participants");
        if (taskId == null || newTaskId == null || groupPublicKey == null) {
            return;
        }
        int offenderId = offenderValue instanceof Number n ? n.intValue() : -1;
        Set<Integer> participants = new LinkedHashSet<>();
        if (participantsValue instanceof List<?> list) {
            for (Object v : list) {
                if (v instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
        }
        CggmpRefreshTask task = svc.refreshTasks.get(taskId);
        if (task != null) {
            task.fail("Refresh excluded offender " + offenderId + ": " + (reason == null ? "" : reason));
        }
        if (!participants.isEmpty()) {
            if (!svc.refreshTasks.containsKey(newTaskId)) {
                svc.createRefreshTaskInternal(newTaskId, groupPublicKey, participants, senderId);
            }
            if (participants.contains(svc.nodeId)) {
                svc.startRefreshTask(newTaskId).exceptionally(ex -> {
                    logger.error("Failed to start new refresh task {}: {}", newTaskId, ex.getMessage());
                    return null;
                });
            }
        }
    }

    Map<String, Object> refreshEvidence(CggmpRefreshTask task, int offenderId, String reason, Map<String, Object> extra) {
        Map<String, Object> ev = new HashMap<>();
        ev.put("v", 1);
        ev.put("taskId", task.taskId);
        ev.put("offenderId", offenderId);
        ev.put("reason", reason);
        if (task.rid != null && task.rid.length > 0) {
            ev.put("rid", HexUtils.bytesToHex(task.rid));
        }
        if (extra != null) {
            for (Map.Entry<String, Object> entry : extra.entrySet()) {
                String key = entry.getKey();
                if (isRefreshEvidenceKeyAllowed(key)) {
                    ev.put(key, entry.getValue());
                }
            }
        }
        return ev;
    }

    private boolean validateRefreshComplaintEvidence(CggmpRefreshTask task, Integer offenderId, String reason, Map<?, ?> evidence) {
        if (task == null || offenderId == null || reason == null) {
            return false;
        }
        if (!task.participants.contains(offenderId)) {
            return false;
        }
        if (evidence != null) {
            Object evVersion = evidence.get("v");
            if (evVersion instanceof Number n && n.intValue() != 1) {
                return false;
            }
            for (Object k : evidence.keySet()) {
                if (k instanceof String s) {
                    if (!isRefreshEvidenceKeyAllowed(s)) {
                        return false;
                    }
                }
            }
            Object evOffender = evidence.get("offenderId");
            if (evOffender instanceof Number n && n.intValue() != offenderId) {
                return false;
            }
            Object evReason = evidence.get("reason");
            if (evReason instanceof String s && !s.equals(reason)) {
                return false;
            }
            Object evRid = evidence.get("rid");
            if (evRid instanceof String s && task.rid != null) {
                String ridHex = HexUtils.bytesToHex(task.rid);
                if (!ridHex.equalsIgnoreCase(s)) {
                    return false;
                }
            }
        }
        String r = reason.trim();
        CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(offenderId);
        CggmpRefreshTask.RefreshRound3Data r3 = task.round3Data.get(offenderId);
        String commit = task.round1Commit.get(offenderId);
        try {
            if (r.startsWith("Missing refresh data")) {
                return commit == null || r2 == null || r3 == null;
            }
            if (r.startsWith("Missing refresh R1 commit")) {
                return commit == null;
            }
            if (r.startsWith("Refresh R1 commit mismatch") || r.startsWith("Refresh commit mismatch")) {
                if (commit == null || r2 == null) return false;
                String expected = CggmpRefreshUtils.computeRefreshCommit(task.taskId, offenderId, r2.X, r2.Y, r2.A, r2.Xi, r2.paillierKey,
                        r2.zkSetup, r2.hatN, r2.s, r2.t, r2.prmProof, r2.rid, r2.u);
                if (evidence != null) {
                    Object evCommit = evidence.get("commit");
                    Object evExpected = evidence.get("expectedCommit");
                    if (evCommit instanceof String s && !s.equalsIgnoreCase(commit)) {
                        return false;
                    }
                    if (evExpected instanceof String s && !s.equalsIgnoreCase(expected)) {
                        return false;
                    }
                }
                return !commit.equals(expected);
            }
            if (r.startsWith("Invalid Paillier public key")) {
                return r2 != null && !CggmpRefreshUtils.validatePaillierPublicKey(r2.paillierKey);
            }
            if (r.startsWith("Invalid PiPrm proof")) {
                return r2 != null && !RefreshProofs.verifyPrmProof(r2.prmProof, r2.hatN, r2.s, r2.t,
                        CggmpRefreshUtils.buildRefreshContext(task.taskId, null, offenderId, "PRM"));
            }
            if (r.startsWith("Sum of X not identity")) {
                return r2 != null && !Secp256k1CurveUtils.sumPoints(r2.X).isInfinity();
            }
            if (r.startsWith("Invalid Blum proof")) {
                if (r2 == null || r3 == null) return false;
                BiPrimeProofValidator biPrimeValidator = new BiPrimeProofValidator();
                return !biPrimeValidator.verifyProof(r3.biPrimeProof, r2.paillierKey,
                        CggmpRefreshUtils.buildRefreshContext(task.taskId, task.rid, offenderId, "MOD"));
            }
            if (r.startsWith("Invalid NoSmallFactor proof")) {
                if (r2 == null || r3 == null) return false;
                NoSmallFactorProofValidator factorValidator = new NoSmallFactorProofValidator(r2.zkSetup);
                return !factorValidator.verifyProof(r3.factorProof, r2.paillierKey,
                        CggmpRefreshUtils.buildRefreshContext(task.taskId, task.rid, offenderId, "FAC"));
            }
            if (r.startsWith("Missing Schnorr proof")) {
                if (r2 == null || r3 == null) return false;
                for (int k : task.participants) {
                    if (!r3.schProofs.containsKey(k) || !r2.X.containsKey(k)) {
                        return true;
                    }
                }
                return false;
            }
            if (r.startsWith("Invalid Schnorr proof")) {
                if (r2 == null || r3 == null) return false;
                for (int k : task.participants) {
                    PiSchProof sch = r3.schProofs.get(k);
                    ECPoint Xjk = r2.X.get(k);
                    if (sch == null || Xjk == null) continue;
                    boolean ok = RefreshProofs.verifySchProof(sch, Secp256k1CurveUtils.G(), Xjk,
                            CggmpRefreshUtils.buildRefreshContext(task.taskId, task.rid, offenderId, "SCH:" + k));
                    if (!ok) return true;
                }
                return false;
            }
            if (r.startsWith("Missing C_{j,i}")) {
                return r3 == null || r3.C.get(svc.nodeId) == null;
            }
            if (r.startsWith("Missing Y_{j,i}")) {
                return r2 == null || r2.Y.get(svc.nodeId) == null;
            }
            if (r.startsWith("Missing X_{j,i}")) {
                return r2 == null || r2.X.get(svc.nodeId) == null;
            }
            if (r.startsWith("Invalid C_{j,i} decryption")) {
                if (r2 == null || r3 == null) return false;
                BigInteger Cji = r3.C.get(svc.nodeId);
                ECPoint Yji = r2.Y.get(svc.nodeId);
                ECPoint Xji = r2.X.get(svc.nodeId);
                BigInteger yij = task.yShares.get(offenderId);
                if (Cji == null || Yji == null || Xji == null || yij == null) return false;
                BigInteger rho = CggmpRefreshUtils.deriveRefreshMask(task.taskId, task.rid, offenderId, svc.nodeId, Yji, yij);
                BigInteger xji = Cji.subtract(rho).mod(Secp256k1CurveUtils.n());
                ECPoint check = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xji);
                return !check.equals(Xji);
            }
        } catch (Exception e) {
            logger.warn("Refresh complaint evidence check failed: {}", e.getMessage());
            return false;
        }
        return false;
    }

    private boolean isRefreshEvidenceKeyAllowed(String key) {
        return switch (key) {
            case "v", "taskId", "offenderId", "reason", "rid",
                 "expectedCommit", "commit", "peerId", "k", "missingFor", "xSum", "n" -> true;
            default -> false;
        };
    }

    private void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            String evidenceJson = evidence == null ? null : JsonUtils.encodeAsJson(evidence);
            svc.complaintDao.save(System.currentTimeMillis(), taskId, senderId, offenderId, reason, evidenceJson);
        } catch (Exception e) {
            logger.warn("Failed to persist complaint: {}", e.getMessage());
        }
        try {
            java.nio.file.Path complaintFile = java.nio.file.Paths.get(svc.complaintLogPath);
            java.nio.file.Path dir = complaintFile.getParent();
            if (dir != null) {
                java.nio.file.Files.createDirectories(dir);
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"ts\":").append(System.currentTimeMillis()).append(',');
            sb.append("\"taskId\":\"").append(JsonUtils.escapeJson(taskId)).append("\",");
            sb.append("\"senderId\":").append(senderId).append(',');
            sb.append("\"offenderId\":").append(offenderId == null ? "null" : offenderId).append(',');
            sb.append("\"reason\":\"").append(JsonUtils.escapeJson(reason)).append("\"");
            if (evidence != null) {
                sb.append(",\"evidence\":").append(JsonUtils.encodeAsJson(evidence));
            }
            sb.append('}');
            String line = sb.append(System.lineSeparator()).toString();
            java.nio.file.Files.writeString(complaintFile, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }

    private void attemptExcludeAndRestartRefresh(CggmpRefreshTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            task.fail("Refresh complaint (offender not participant): " + reason);
            return;
        }
        int required = Math.min(Math.max(1, svc.threshold), task.nodesCount);
        LinkedHashSet<Integer> newParticipants = new LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.size() < required) {
            task.fail("Not enough participants after refresh exclusion");
            return;
        }
        String newTaskId = UUID.randomUUID().toString();
        svc.createRefreshTaskInternal(newTaskId, task.groupPublicKey, newParticipants, task.initiatorId);
        logger.warn("Refresh exclusion: offender {} removed, restarting refresh task {}", offenderId, newTaskId);
        CggmpProtocolUtils.fireAndForget(broadcastRefreshExclude(task, offenderId, reason, newTaskId, newParticipants),
                logger, "CGGMP_REFRESH_EXCLUDE");
        svc.startRefreshTask(newTaskId).exceptionally(ex -> {
            logger.error("Failed to restart refresh task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
        task.fail("Refresh restart after excluding offender " + offenderId);
    }
}
