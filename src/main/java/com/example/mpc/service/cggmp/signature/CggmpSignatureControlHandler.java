package com.example.mpc.service.cggmp.signature;

import com.example.mpc.common.util.JsonCodec;
import com.example.mpc.dto.CggmpSignatureTask;
import com.example.mpc.service.CggmpSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CGGMP签名控制处理器
 * 负责处理签名过程中的投诉和争议
 */
public final class CggmpSignatureControlHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureControlHandler.class);
    private final CggmpSignatureService svc;
    private final CggmpSignatureEvidenceHandler evidenceHandler;

    public CggmpSignatureControlHandler(CggmpSignatureService svc, CggmpSignatureEvidenceHandler evidenceHandler) {
        this.svc = svc;
        this.evidenceHandler = evidenceHandler;
    }

    /**
     * 处理签名投诉消息
     */
    void handleCggmpSignComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null || reason == null) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received complaint for task {} from node {} against {}: {}", signatureTaskId, senderId, offenderId, reason);
        logComplaintToFile(signatureTaskId, senderId, offenderId, reason, dataMap.get("evidence"));
        boolean evidenceOk = true;
        boolean hasProofEvidence = false;
        if (dataMap.get("evidence") instanceof Map<?, ?> ev) {
            hasProofEvidence = ev.containsKey("piDecProof") || ev.containsKey("affGProofs") || ev.containsKey("affGProofsHat");
            if (hasProofEvidence) {
                evidenceOk = evidenceHandler.verifyDecEvidence(task, senderId, ev)
                        && evidenceHandler.verifyAffGEvidence(task, senderId, ev);
            }
        }
        if (hasProofEvidence && !evidenceOk) {
            String invalidReason = "Invalid proof evidence from sender " + senderId;
            logger.warn("Complaint evidence invalid; treating sender {} as offender", senderId);
            if (svc.nodeId == task.initiatorId) {
                evidenceHandler.attemptExcludeAndRestart(task, senderId, invalidReason);
            } else {
                svc.failSignatureTask(task, invalidReason);
            }
            return;
        }
        if (svc.nodeId == task.initiatorId && offenderId != null) {
            evidenceHandler.attemptExcludeAndRestart(task, offenderId, reason);
        } else {
            svc.failSignatureTask(task, "Complaint: " + reason);
        }
    }

    /**
     * 处理签名排除消息
     */
    void handleCggmpSignExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null) {
            return;
        }
        CggmpSignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received exclude for task {} from node {} (offender {})", signatureTaskId, senderId, offenderId);
        svc.failSignatureTask(task, "Excluded offender " + offenderId);
    }

    private void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            String evidenceJson = evidence == null ? null : JsonCodec.toJson(evidence);
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
            Map<String, Object> line = new LinkedHashMap<>();
            line.put("ts", System.currentTimeMillis());
            line.put("taskId", taskId);
            line.put("senderId", senderId);
            line.put("offenderId", offenderId);
            line.put("reason", reason);
            if (evidence != null) {
                line.put("evidence", evidence);
            }
            String lineJson = JsonCodec.toJson(line) + System.lineSeparator();
            java.nio.file.Files.writeString(complaintFile, lineJson,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }
}
