package com.example.mpc.common.request;

public class SignStartRequest {
    private String groupPublicKey;
    private String message;

    public SignStartRequest() {}

    public SignStartRequest(String groupPublicKey, String message) {
        this.groupPublicKey = groupPublicKey;
        this.message = message;
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
}
