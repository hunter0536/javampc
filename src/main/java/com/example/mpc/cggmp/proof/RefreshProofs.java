package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public final class RefreshProofs {
    private RefreshProofs() {
    }

    public static PiSchProof createSchProof(ECPoint g, ECPoint X, BigInteger x, byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        SecureRandom rnd = new SecureRandom();
        BigInteger alpha = new BigInteger(q.bitLength(), rnd).mod(q);
        ECPoint A = g.multiply(alpha).normalize();
        BigInteger e = challenge("PI_SCH", q, context, g, X, A);
        BigInteger z = alpha.add(e.multiply(x)).mod(q);
        return new PiSchProof(A, z);
    }

    public static boolean verifySchProof(PiSchProof proof, ECPoint g, ECPoint X, byte[] context) {
        if (proof == null || proof.A() == null || proof.z() == null) return false;
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger e = challenge("PI_SCH", q, context, g, X, proof.A());
        ECPoint left = g.multiply(proof.z()).normalize();
        ECPoint right = proof.A().add(X.multiply(e)).normalize();
        return left.equals(right);
    }

    public static PiPrmProof createPrmProof(BigInteger hatN, BigInteger s, BigInteger t, BigInteger lambda, byte[] context) {
        SecureRandom rnd = new SecureRandom();
        BigInteger alpha = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        BigInteger A = BigIntegerUtils.powSigned(t, alpha, hatN);
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger e = challenge("PI_PRM", q, context, hatN, s, t, A);
        BigInteger z = alpha.add(e.multiply(lambda));
        return new PiPrmProof(A, z);
    }

    public static boolean verifyPrmProof(PiPrmProof proof, BigInteger hatN, BigInteger s, BigInteger t, byte[] context) {
        if (proof == null || proof.A() == null || proof.z() == null) return false;
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger e = challenge("PI_PRM", q, context, hatN, s, t, proof.A());
        BigInteger left = BigIntegerUtils.powSigned(t, proof.z(), hatN);
        BigInteger right = proof.A().multiply(BigIntegerUtils.powSigned(s, e, hatN)).mod(hatN);
        return left.equals(right);
    }

    private static BigInteger challenge(String tag, BigInteger q, byte[] context, Object... items) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            for (Object o : items) {
                if (o == null) continue;
                if (o instanceof BigInteger bi) {
                    md.update(bi.toByteArray());
                } else if (o instanceof ECPoint p) {
                    md.update(Secp256k1CurveUtils.encodePoint(p));
                } else {
                    md.update(String.valueOf(o).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            BigInteger twoQ = q.shiftLeft(1);
            BigInteger e = new BigInteger(1, md.digest()).mod(twoQ);
            return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
        } catch (Exception e) {
            throw new RuntimeException("Refresh proof challenge failed", e);
        }
    }
}
