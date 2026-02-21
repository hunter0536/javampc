package com.example.mpc.model;

public class KeyShare {
    private Long id;
    private Long walletId;
    private Integer shareIndex;
    private String keyShare;

    public KeyShare() {
    }

    public KeyShare(Long walletId, Integer shareIndex, String keyShare) {
        this.walletId = walletId;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
    }

    public KeyShare(Long id, Long walletId, Integer shareIndex, String keyShare) {
        this.id = id;
        this.walletId = walletId;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getWalletId() {
        return walletId;
    }

    public void setWalletId(Long walletId) {
        this.walletId = walletId;
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
}