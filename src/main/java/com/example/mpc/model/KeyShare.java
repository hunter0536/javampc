package com.example.mpc.model;

public class KeyShare {
    private Long id;
    private Integer shareIndex;
    private String keyShare;
    private String groupPublicKey;
    private String dkgTaskId;

    public KeyShare() {
    }

    public KeyShare(Integer shareIndex, String keyShare, String groupPublicKey, String dkgTaskId) {
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.groupPublicKey = groupPublicKey;
        this.dkgTaskId = dkgTaskId;
    }

    public KeyShare(Long id, Integer shareIndex, String keyShare, String groupPublicKey, String dkgTaskId) {
        this.id = id;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.groupPublicKey = groupPublicKey;
        this.dkgTaskId = dkgTaskId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getShareIndex() {
        return shareIndex;
    }

    public void setShareIndex(Integer shareIndex) {
        this.shareIndex = shareIndex;
    }

    public String getKeyShare() {
        return keyShare;
    }

    public void setKeyShare(String keyShare) {
        this.keyShare = keyShare;
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getDkgTaskId() {
        return dkgTaskId;
    }

    public void setDkgTaskId(String dkgTaskId) {
        this.dkgTaskId = dkgTaskId;
    }
}
