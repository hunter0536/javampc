package com.example.mpc.common.request;

public class SignatureTaskIdRequest {
    private String signatureTaskId;

    public SignatureTaskIdRequest() {
    }

    public SignatureTaskIdRequest(String signatureTaskId) {
        this.signatureTaskId = signatureTaskId;
    }

    public String getSignatureTaskId() {
        return signatureTaskId;
    }

    public void setSignatureTaskId(String signatureTaskId) {
        this.signatureTaskId = signatureTaskId;
    }
}
