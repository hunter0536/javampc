package com.example.mpc.model;

public class KeyShare {
    private Long id;
    private Integer shareIndex;
    private String keyShare;
    private String groupPublicKey;
    private String dkgTaskId;
    private String publicShares;
    private String indexMap;
    private String chainCode;

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

    public KeyShare(Integer shareIndex, String keyShare, String groupPublicKey, String dkgTaskId, String publicShares, String indexMap) {
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.groupPublicKey = groupPublicKey;
        this.dkgTaskId = dkgTaskId;
        this.publicShares = publicShares;
        this.indexMap = indexMap;
    }

    public KeyShare(Integer shareIndex, String keyShare, String groupPublicKey, String dkgTaskId, String publicShares, String indexMap, String chainCode) {
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.groupPublicKey = groupPublicKey;
        this.dkgTaskId = dkgTaskId;
        this.publicShares = publicShares;
        this.indexMap = indexMap;
        this.chainCode = chainCode;
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

    public String getPublicShares() {
        return publicShares;
    }

    public void setPublicShares(String publicShares) {
        this.publicShares = publicShares;
    }

    public String getIndexMap() {
        return indexMap;
    }

    public void setIndexMap(String indexMap) {
        this.indexMap = indexMap;
    }

    public String getChainCode() {
        return chainCode;
    }

    public void setChainCode(String chainCode) {
        this.chainCode = chainCode;
    }
}
