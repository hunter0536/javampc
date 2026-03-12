package com.example.mpc.dto;

import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class PresignData implements java.io.Serializable {
    private static final long serialVersionUID = 2L;
    private static final Logger logger = LoggerFactory.getLogger(PresignData.class);

    private String groupPublicKey;
    private String gamma;       
    private String kTilde;      
    private String chiTilde;    
    private long createdAt;
    private String presignId;
    private Map<Integer, String> deltaTilde;
    private Map<Integer, String> sTilde;

    public PresignData() {}

    public PresignData(String groupPublicKey, Presignature presignature) {
        this.groupPublicKey = groupPublicKey;
        this.gamma = serializeECPoint(presignature.Gamma());
        this.kTilde = presignature.kTilde().toString(16);
        this.chiTilde = presignature.chiTilde().toString(16);
        this.createdAt = System.currentTimeMillis();
        this.presignId = presignature.presignId() != null ? presignature.presignId() : java.util.UUID.randomUUID().toString();
        
        if (presignature.deltaTilde() != null) {
            this.deltaTilde = new HashMap<>();
            for (Map.Entry<Integer, ECPoint> e : presignature.deltaTilde().entrySet()) {
                this.deltaTilde.put(e.getKey(), serializeECPoint(e.getValue()));
            }
        }
        if (presignature.sTilde() != null) {
            this.sTilde = new HashMap<>();
            for (Map.Entry<Integer, ECPoint> e : presignature.sTilde().entrySet()) {
                this.sTilde.put(e.getKey(), serializeECPoint(e.getValue()));
            }
        }
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public void setGroupPublicKey(String groupPublicKey) {
        this.groupPublicKey = groupPublicKey;
    }

    public String getGamma() {
        return gamma;
    }

    public void setGamma(String gamma) {
        this.gamma = gamma;
    }

    public String getkTilde() {
        return kTilde;
    }

    public void setkTilde(String kTilde) {
        this.kTilde = kTilde;
    }

    public String getChiTilde() {
        return chiTilde;
    }

    public void setChiTilde(String chiTilde) {
        this.chiTilde = chiTilde;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public String getPresignId() {
        return presignId;
    }

    public void setPresignId(String presignId) {
        this.presignId = presignId;
    }

    public Map<Integer, String> getDeltaTilde() {
        return deltaTilde;
    }

    public void setDeltaTilde(Map<Integer, String> deltaTilde) {
        this.deltaTilde = deltaTilde;
    }

    public Map<Integer, String> getSTilde() {
        return sTilde;
    }

    public void setSTilde(Map<Integer, String> sTilde) {
        this.sTilde = sTilde;
    }

    public Presignature toPresignature() {
        logger.info("Converting PresignData to Presignature: presignId={}, gamma={}, kTilde length={}, chiTilde length={}", 
            presignId,
            gamma != null ? gamma.substring(0, Math.min(20, gamma.length())) : "null",
            kTilde != null ? kTilde.length() : "null",
            chiTilde != null ? chiTilde.length() : "null");
        ECPoint gammaPoint = deserializeECPoint(gamma);
        BigInteger k = new BigInteger(kTilde, 16);
        BigInteger chi = new BigInteger(chiTilde, 16);
        
        Map<Integer, ECPoint> deltaTildeMap = null;
        Map<Integer, ECPoint> sTildeMap = null;
        
        if (deltaTilde != null) {
            deltaTildeMap = new HashMap<>();
            for (Map.Entry<Integer, String> e : deltaTilde.entrySet()) {
                deltaTildeMap.put(e.getKey(), deserializeECPoint(e.getValue()));
            }
        }
        if (sTilde != null) {
            sTildeMap = new HashMap<>();
            for (Map.Entry<Integer, String> e : sTilde.entrySet()) {
                sTildeMap.put(e.getKey(), deserializeECPoint(e.getValue()));
            }
        }
        
        return new Presignature(presignId, gammaPoint, k, chi, deltaTildeMap, sTildeMap);
    }

    public boolean isExpired(int maxAgeMinutes) {
        return System.currentTimeMillis() - createdAt > maxAgeMinutes * 60 * 1000L;
    }

    private static String serializeECPoint(ECPoint point) {
        if (point == null) return null;
        byte[] encoded = point.getEncoded(false);
        return com.example.mpc.common.util.HexUtils.bytesToHex(encoded);
    }

    private static ECPoint deserializeECPoint(String hex) {
        if (hex == null || hex.isEmpty()) return null;
        byte[] bytes = com.example.mpc.common.util.HexUtils.hexToBytes(hex);
        return Secp256k1CurveUtils.decodePoint(bytes);
    }
}
