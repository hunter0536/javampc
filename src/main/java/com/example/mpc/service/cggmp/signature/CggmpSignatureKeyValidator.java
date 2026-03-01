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
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        return publicKey.n.compareTo(q.pow(8)) >= 0;
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
        if (existingZk != null && !existingZk.equals(zkSetup)) {
            return false;
        }
        return true;
    }

    private static boolean paillierPublicKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        return a.n.equals(b.n) && a.nSquared.equals(b.nSquared) && a.g.equals(b.g) && a.bitLength == b.bitLength;
    }
}
