package com.example.mpc.cggmp.util;

import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.SecureRandomUtils;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Secp256k1CurveUtils {
    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");

    private Secp256k1CurveUtils() {
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

    public static ECPoint sumPoints(Map<Integer, ECPoint> points) {
        ECPoint sum = CURVE.getCurve().getInfinity();
        for (ECPoint p : points.values()) {
            if (p != null) {
                ECPoint normalized = p.normalize();
                if (!normalized.isInfinity()) {
                    sum = sum.add(normalized);
                }
            }
        }
        return sum.normalize();
    }

    public static BigInteger randomScalar(BigInteger n) {
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    public static Map<String, String> encodeECPointMap(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            ECPoint p = map.get(k);
            if (p == null) continue;
            out.put(String.valueOf(k), HexUtils.bytesToHex(p.getEncoded(false)));
        }
        return out;
    }

    public static Map<String, String> encodeECPointMapCompressed(Map<Integer, ECPoint> map) {
        Map<String, String> out = new LinkedHashMap<>();
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            ECPoint p = map.get(k);
            if (p == null) continue;
            out.put(String.valueOf(k), HexUtils.bytesToHex(p.getEncoded(true)));
        }
        return out;
    }

    public static Map<Integer, ECPoint> decodeECPointMap(Map<?, ?> map) {
        Map<Integer, ECPoint> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, decodePoint(HexUtils.hexToBytes(String.valueOf(e.getValue()))));
        }
        return out;
    }
}
