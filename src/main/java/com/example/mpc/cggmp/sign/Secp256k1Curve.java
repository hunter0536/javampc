package com.example.mpc.cggmp.sign;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class Secp256k1Curve {
    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");

    private Secp256k1Curve() {
    }

    public static ECPoint G() {
        return CURVE.getG();
    }

    public static BigInteger n() {
        return CURVE.getN();
    }

    public static ECPoint decodePoint(byte[] encoded) {
        return CURVE.getCurve().decodePoint(encoded).normalize();
    }

    public static byte[] encodePoint(ECPoint point) {
        return point.normalize().getEncoded(false);
    }

    public static ECPoint multiply(ECPoint point, BigInteger k) {
        return point.multiply(k).normalize();
    }

    public static ECPoint add(ECPoint a, ECPoint b) {
        return a.add(b).normalize();
    }

    public static BigInteger randomScalar(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }
}
