package com.example.mpc.service;

import com.example.mpc.model.Gg20SignatureTask;

import java.util.Map;

final class CggmpSignatureControlHandler {
    private final CggmpSignatureService svc;
    private final CggmpSignatureEvidenceHandler evidenceHandler;

    CggmpSignatureControlHandler(CggmpSignatureService svc, CggmpSignatureEvidenceHandler evidenceHandler) {
        this.svc = svc;
        this.evidenceHandler = evidenceHandler;
    }

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
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        svc.logger.warn("Received complaint for task {} from node {} against {}: {}", signatureTaskId, senderId, offenderId, reason);
        svc.logComplaintToFile(signatureTaskId, senderId, offenderId, reason, dataMap.get("evidence"));
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
            svc.logger.warn("Complaint evidence invalid; treating sender {} as offender", senderId);
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

    void handleCggmpSignExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null) {
            return;
        }
        Gg20SignatureTask task = svc.signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        svc.logger.warn("Received exclude for task {} from node {} (offender {})", signatureTaskId, senderId, offenderId);
        svc.failSignatureTask(task, "Excluded offender " + offenderId);
    }
}
