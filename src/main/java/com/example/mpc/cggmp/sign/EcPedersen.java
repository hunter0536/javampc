package com.example.mpc.cggmp.sign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;

public final class EcPedersen {
    private static final BigInteger N = Secp256k1Curve.n();
    private static final ECPoint G = Secp256k1Curve.G();
    private static final ECPoint H = deriveH();

    private EcPedersen() {
    }

    public static ECPoint G() {
        return G;
    }

    public static ECPoint H() {
        return H;
    }

    public static BigInteger n() {
        return N;
    }

    public static ECPoint commit(BigInteger value, BigInteger blinding) {
        return G.multiply(value).add(H.multiply(blinding)).normalize();
    }

    private static ECPoint deriveH() {
        byte[] seed = "CGGMP:PEDERSEN:H".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] hash;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(seed);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive Pedersen H", e);
        }
        BigInteger scalar = new BigInteger(1, hash).mod(N);
        if (scalar.signum() == 0) {
            scalar = BigInteger.ONE;
        }
        return G.multiply(scalar).normalize();
    }
}
