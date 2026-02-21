package com.example.mpc.core.crypto;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class ECCUtils {
    private static final Logger logger = LoggerFactory.getLogger(ECCUtils.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static ECPoint multiply(ECPoint point, BigInteger scalar) {
        return point.multiply(scalar).normalize();
    }

    public static ECPoint add(ECPoint p1, ECPoint p2) {
        return p1.add(p2).normalize();
    }

    public static boolean isOnCurve(ECPoint point, org.bouncycastle.jce.spec.ECParameterSpec spec) {
        return point.isValid();
    }

    public static org.bouncycastle.jce.spec.ECParameterSpec getCurveParams(String curveName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        return publicKey.getParameters();
    }

    public static byte[] encodePoint(ECPoint point, boolean compressed) {
        return point.getEncoded(compressed);
    }

    public static ECPoint decodePoint(byte[] encoded, org.bouncycastle.jce.spec.ECParameterSpec spec) {
        return spec.getCurve().decodePoint(encoded);
    }

    public static BigInteger generateRandomScalar(BigInteger order) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(order.bitLength() - 1, random).mod(order);
    }
}
