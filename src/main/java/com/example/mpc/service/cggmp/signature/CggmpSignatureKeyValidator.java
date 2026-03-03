package com.example.mpc.service.cggmp.signature;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.model.Gg20SignatureTask;

import java.math.BigInteger;

public final class CggmpSignatureKeyValidator {
    private CggmpSignatureKeyValidator() {
    }

    public static boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n() == null || publicKey.nSquared() == null || publicKey.g() == null) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        return publicKey.n().compareTo(q.pow(8)) >= 0;
    }

    public static boolean ensurePeerKeyConsistency(Gg20SignatureTask task,
                                                   int peerId,
                                                   PaillierEncryption.PublicKey publicKey,
                                                   ZKSetup zkSetup) {
        PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.putIfAbsent(peerId, publicKey);
        if (existingKey != null && !paillierPublicKeyEquals(existingKey, publicKey)) {
            return false;
        }
        ZKSetup existingZk = task.peerZkSetups.putIfAbsent(peerId, zkSetup);
        return existingZk == null || existingZk.equals(zkSetup);
    }

    public static boolean ensurePeerKeyMatchesAux(Gg20SignatureTask task,
                                                  int peerId,
                                                  PaillierEncryption.PublicKey publicKey,
                                                  ZKSetup zkSetup) {
        if (task == null || publicKey == null || zkSetup == null) {
            return false;
        }
        java.util.Map<String, String> auxParams = task.peerAuxParams.get(peerId);
        if (auxParams == null) {
            return false;
        }
        String auxN = auxParams.get("paillierN");
        String auxG = auxParams.get("paillierG");
        String auxBits = auxParams.get("paillierBitLength");
        String auxHatN = auxParams.get("pedersenHatN");
        String auxS = auxParams.get("pedersenS");
        String auxT = auxParams.get("pedersenT");

        if (auxN != null && !auxN.equalsIgnoreCase(publicKey.n().toString(16))) {
            return false;
        }
        if (auxG != null && !auxG.equalsIgnoreCase(publicKey.g().toString(16))) {
            return false;
        }
        if (auxBits != null) {
            try {
                int bits = Integer.parseInt(auxBits);
                if (publicKey.bitLength() != bits) {
                    return false;
                }
            } catch (Exception e) {
                return false;
            }
        }
        if (auxHatN != null && !auxHatN.equalsIgnoreCase(zkSetup.hatN().toString(16))) {
            return false;
        }
        if (auxS != null && !auxS.equalsIgnoreCase(zkSetup.h1().toString(16))) {
            return false;
        }
        return auxT == null || auxT.equalsIgnoreCase(zkSetup.h2().toString(16));
    }

    private static boolean paillierPublicKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        return a.n().equals(b.n()) && a.nSquared().equals(b.nSquared()) && a.g().equals(b.g()) && a.bitLength() == b.bitLength();
    }

    public static String computeAuxHash(java.util.Map<String, String> auxParams) {
        if (auxParams == null) {
            return "null";
        }
        try {
            String json = com.example.mpc.common.util.JsonCodec.toJson(auxParams);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return com.example.mpc.common.util.HexUtils.bytesToHex(md.digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
    }

    public static String computePkHash(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null) {
            return "null";
        }
        try {
            java.util.Map<String, Object> map = com.example.mpc.service.cggmp.CggmpCodecUtils.encodePaillierPublicKey(publicKey);
            String json = com.example.mpc.common.util.JsonCodec.toJson(map);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return com.example.mpc.common.util.HexUtils.bytesToHex(md.digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
    }

    public static String computeZkHash(ZKSetup zkSetup) {
        if (zkSetup == null) {
            return "null";
        }
        try {
            java.util.Map<String, Object> map = com.example.mpc.service.cggmp.CggmpCodecUtils.encodeZkSetup(zkSetup);
            String json = com.example.mpc.common.util.JsonCodec.toJson(map);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return com.example.mpc.common.util.HexUtils.bytesToHex(md.digest(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
    }
}
