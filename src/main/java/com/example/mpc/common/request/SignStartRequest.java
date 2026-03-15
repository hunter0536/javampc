package com.example.mpc.common.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignStartRequest {
    private String groupPublicKey;
    private String message;

    @JsonProperty("isHotWallet")
    private boolean isHotWallet;

    public SignStartRequest() {
    }

    public SignStartRequest(String groupPublicKey, String message) {
        this.groupPublicKey = groupPublicKey;
        this.message = message;
    }

    public SignStartRequest(String groupPublicKey, String message, boolean isHotWallet) {
        this.groupPublicKey = groupPublicKey;
        this.message = message;
        this.isHotWallet = isHotWallet;
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

    public boolean isHotWallet() {
        return isHotWallet;
    }

    public void setHotWallet(boolean hotWallet) {
        isHotWallet = hotWallet;
    }
}
