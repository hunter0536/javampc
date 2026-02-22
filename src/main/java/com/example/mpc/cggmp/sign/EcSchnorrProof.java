package com.example.mpc.cggmp.sign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;

public final class EcSchnorrProof {
    private final ECPoint R;
    private final BigInteger s;

    public EcSchnorrProof(ECPoint R, BigInteger s) {
        this.R = R.normalize();
        this.s = s;
    }

    public ECPoint R() {
        return R;
    }

    public BigInteger s() {
        return s;
    }

    public static EcSchnorrProof create(BigInteger k, ECPoint Gamma, byte[] context) {
        BigInteger n = Secp256k1Curve.n();
        BigInteger r = Secp256k1Curve.randomScalar(n);
        ECPoint R = Secp256k1Curve.multiply(Secp256k1Curve.G(), r);
        BigInteger c = challenge(Gamma, R, context, n);
        BigInteger s = r.add(c.multiply(k)).mod(n);
        return new EcSchnorrProof(R, s);
    }

    public static boolean verify(EcSchnorrProof proof, ECPoint Gamma, byte[] context) {
        if (proof == null || Gamma == null) {
            return false;
        }
        BigInteger n = Secp256k1Curve.n();
        BigInteger c = challenge(Gamma, proof.R, context, n);
        ECPoint left = Secp256k1Curve.multiply(Secp256k1Curve.G(), proof.s);
        ECPoint right = proof.R.add(Secp256k1Curve.multiply(Gamma, c)).normalize();
        return left.equals(right);
    }

    private static BigInteger challenge(ECPoint Gamma, ECPoint R, byte[] context, BigInteger n) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("CGGMP-SCHNORR".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                digest.update(context);
            }
            digest.update(Secp256k1Curve.encodePoint(Gamma));
            digest.update(Secp256k1Curve.encodePoint(R));
            byte[] hash = digest.digest();
            return new BigInteger(1, hash).mod(n);
        } catch (Exception e) {
            throw new RuntimeException("Schnorr challenge hash failed", e);
        }
    }
}
