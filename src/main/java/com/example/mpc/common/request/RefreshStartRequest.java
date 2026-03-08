package com.example.mpc.common.request;

public class RefreshStartRequest {
    private String groupPublicKey;

    public RefreshStartRequest() {}

    public RefreshStartRequest(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }
}
