package com.example.mpc.cggmp.sign;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;

public final class EcPedersen {
    private static final BigInteger ORDER = Secp256k1CurveUtils.n();
    private static final ECPoint BASE_POINT = Secp256k1CurveUtils.G();
    private static final ECPoint COMMITMENT_POINT = deriveH();

    private EcPedersen() {
    }

    public static ECPoint G() {
        return BASE_POINT;
    }

    public static ECPoint H() {
        return COMMITMENT_POINT;
    }

    public static BigInteger n() {
        return ORDER;
    }

    public static ECPoint commit(BigInteger value, BigInteger blinding) {
        return BASE_POINT.multiply(value).add(COMMITMENT_POINT.multiply(blinding)).normalize();
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

        BigInteger scalar = new BigInteger(1, hash).mod(ORDER);
        if (scalar.signum() == 0) {
            scalar = BigInteger.ONE;
        }
        return BASE_POINT.multiply(scalar).normalize();
    }
}
