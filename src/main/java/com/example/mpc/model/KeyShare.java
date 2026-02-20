package com.example.mpc.model;

import java.time.LocalDateTime;

public class KeyShare {
    private Long id;
    private Long walletId;
    private int shareIndex;
    private String keyShare;
    private LocalDateTime createdAt;
    
    public KeyShare() {
        this.createdAt = LocalDateTime.now();
    }
    
    public KeyShare(Long walletId, int shareIndex, String keyShare) {
        this.walletId = walletId;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.createdAt = LocalDateTime.now();
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
    
    public int getShareIndex() {
        return shareIndex;
    }
    
    public void setShareIndex(int shareIndex) {
        this.shareIndex = shareIndex;
    }
    
    public String getKeyShare() {
        return keyShare;
    }
    
    public void setKeyShare(String keyShare) {
        this.keyShare = keyShare;
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}