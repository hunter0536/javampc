package com.example.mpc.model;

import java.math.BigInteger;

public class AuxInfo {
    private Long id;
    private Integer nodeId;
    private String taskId;

    // Paillier private key components
    private String paillierP;
    private String paillierQ;
    private String paillierN;
    private String paillierG;
    private Integer paillierBitLength;

    // Pedersen parameters (hatN, s, t)
    private String pedersenHatN;
    private String pedersenS;
    private String pedersenT;

    public AuxInfo() {
    }

    public AuxInfo(Integer nodeId, String taskId) {
        this.nodeId = nodeId;
        this.taskId = taskId;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getNodeId() {
        return nodeId;
    }

    public void setNodeId(Integer nodeId) {
        this.nodeId = nodeId;
    }

    public String getTaskId() {
        return taskId;
    }

    public void setTaskId(String taskId) {
        this.taskId = taskId;
    }

    public String getPaillierP() {
        return paillierP;
    }

    public void setPaillierP(String paillierP) {
        this.paillierP = paillierP;
    }

    public String getPaillierQ() {
        return paillierQ;
    }

    public void setPaillierQ(String paillierQ) {
        this.paillierQ = paillierQ;
    }

    public String getPaillierN() {
        return paillierN;
    }

    public void setPaillierN(String paillierN) {
        this.paillierN = paillierN;
    }

    public String getPaillierG() {
        return paillierG;
    }

    public void setPaillierG(String paillierG) {
        this.paillierG = paillierG;
    }

    public Integer getPaillierBitLength() {
        return paillierBitLength;
    }

    public void setPaillierBitLength(Integer paillierBitLength) {
        this.paillierBitLength = paillierBitLength;
    }

    public String getPedersenHatN() {
        return pedersenHatN;
    }

    public void setPedersenHatN(String pedersenHatN) {
        this.pedersenHatN = pedersenHatN;
    }

    public String getPedersenS() {
        return pedersenS;
    }

    public void setPedersenS(String pedersenS) {
        this.pedersenS = pedersenS;
    }

    public String getPedersenT() {
        return pedersenT;
    }

    public void setPedersenT(String pedersenT) {
        this.pedersenT = pedersenT;
    }

    public static String toHex(BigInteger v) {
        return v == null ? null : v.toString(16);
    }
}
