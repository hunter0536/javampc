package com.example.mpc.common.response;

public class SignatureTaskStartResponse {
    private String signatureTaskId;
    private String groupPublicKey;
    private String message;
    private String status;

    public SignatureTaskStartResponse() {
    }

    public SignatureTaskStartResponse(String signatureTaskId, String groupPublicKey, String message, String status) {
        this.signatureTaskId = signatureTaskId;
        this.groupPublicKey = groupPublicKey;
        this.message = message;
        this.status = status;
    }

    public String getSignatureTaskId() {
        return signatureTaskId;
    }

    public void setSignatureTaskId(String signatureTaskId) {
        this.signatureTaskId = signatureTaskId;
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
