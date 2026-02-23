package com.example.mpc.cggmp;

import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAResult;
import com.example.mpc.cggmp.proof.*;
import com.example.mpc.cggmp.zk.ZKSetup;

import org.bouncycastle.math.ec.ECPoint;
import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.common.util.HexUtils;

import java.math.BigInteger;
import java.util.*;

public final class CggmpDkgCodec {
    private CggmpDkgCodec() {
    }

    private static String toHex(BigInteger v) {
        return v.toString(16);
    }

    private static BigInteger fromHex(Object v) {
        return new BigInteger((String) v, 16);
    }

    private static String toB64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] fromB64(Object v) {
        return Base64.getDecoder().decode((String) v);
    }

    private static String bytesToHex(byte[] bytes) {
        return HexUtils.bytesToHex(bytes);
    }

    private static byte[] hexToBytes(String hex) {
        return HexUtils.hexToBytes(hex);
    }

    public static Map<String, Object> encodePaillierPublicKey(PaillierEncryption.PublicKey key) {
        Map<String, Object> map = new HashMap<>();
        map.put("n", toHex(key.n));
        map.put("nsquare", toHex(key.nSquared));
        map.put("g", toHex(key.g));
        map.put("bitLength", key.bitLength);
        return map;
    }

    public static PaillierEncryption.PublicKey decodePaillierPublicKey(Map<?, ?> map) {
        BigInteger n = fromHex(map.get("n"));
        BigInteger nsq = fromHex(map.get("nsquare"));
        BigInteger g = fromHex(map.get("g"));
        int bitLength = ((Number) map.get("bitLength")).intValue();
        return new PaillierEncryption.PublicKey(n, nsq, g, bitLength);
    }

    public static Map<String, Object> encodeZkSetup(ZKSetup setup) {
        Map<String, Object> map = new HashMap<>();
        map.put("hatN", toHex(setup.hatN()));
        map.put("h1", toHex(setup.h1()));
        map.put("h2", toHex(setup.h2()));
        return map;
    }

    public static ZKSetup decodeZkSetup(Map<?, ?> map) {
        BigInteger hatN = fromHex(map.get("hatN"));
        BigInteger h1 = fromHex(map.get("h1"));
        BigInteger h2 = fromHex(map.get("h2"));
        return new ZKSetup(hatN, h1, h2);
    }

    public static Map<String, Object> encodePaillierRangeProof(PaillierRangeProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("z", toB64(proof.z()));
        map.put("u", toB64(proof.u()));
        map.put("w", toB64(proof.w()));
        map.put("s", toB64(proof.s()));
        map.put("s1", toHex(proof.s1()));
        map.put("s2", toHex(proof.s2()));
        return map;
    }

    public static PaillierRangeProof decodePaillierRangeProof(Map<?, ?> map) {
        byte[] z = fromB64(map.get("z"));
        byte[] u = fromB64(map.get("u"));
        byte[] w = fromB64(map.get("w"));
        byte[] s = fromB64(map.get("s"));
        BigInteger s1 = fromHex(map.get("s1"));
        BigInteger s2 = fromHex(map.get("s2"));
        return new PaillierRangeProof(z, u, w, s, s1, s2);
    }

    public static Map<String, Object> encodePaillierRespondentProof(PaillierRespondentProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("z", toB64(proof.z()));
        map.put("zPrime", toB64(proof.zPrime()));
        map.put("t", toB64(proof.t()));
        map.put("v", toB64(proof.v()));
        map.put("w", toB64(proof.w()));
        map.put("s", toB64(proof.s()));
        map.put("s1", toHex(proof.s1()));
        map.put("s2", toHex(proof.s2()));
        map.put("t1", toHex(proof.t1()));
        map.put("t2", toHex(proof.t2()));
        return map;
    }

    public static PaillierRespondentProof decodePaillierRespondentProof(Map<?, ?> map) {
        byte[] z = fromB64(map.get("z"));
        byte[] zPrime = fromB64(map.get("zPrime"));
        byte[] t = fromB64(map.get("t"));
        byte[] v = fromB64(map.get("v"));
        byte[] w = fromB64(map.get("w"));
        byte[] s = fromB64(map.get("s"));
        BigInteger s1 = fromHex(map.get("s1"));
        BigInteger s2 = fromHex(map.get("s2"));
        BigInteger t1 = fromHex(map.get("t1"));
        BigInteger t2 = fromHex(map.get("t2"));
        return new PaillierRespondentProof(z, zPrime, t, v, w, s, s1, s2, t1, t2);
    }

    public static Map<String, Object> encodeBiPrimeProof(BiPrimeBlumProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("N", toHex(proof.N()));
        map.put("w", toHex(proof.w()));
        map.put("sigmas", encodeBigIntegerList(proof.sigmas()));
        map.put("xs", encodeBigIntegerList(proof.xs()));
        map.put("zs", encodeBigIntegerList(proof.zs()));
        map.put("aBits", toB64(proof.aBits()));
        map.put("bBits", toB64(proof.bBits()));
        map.put("sfRounds", proof.sfRounds());
        map.put("blumRounds", proof.blumRounds());
        return map;
    }

    public static BiPrimeBlumProof decodeBiPrimeProof(Map<?, ?> map) {
        BigInteger N = fromHex(map.get("N"));
        BigInteger w = fromHex(map.get("w"));
        List<BigInteger> sigmas = decodeBigIntegerList((List<?>) map.get("sigmas"));
        List<BigInteger> xs = decodeBigIntegerList((List<?>) map.get("xs"));
        List<BigInteger> zs = decodeBigIntegerList((List<?>) map.get("zs"));
        byte[] aBits = fromB64(map.get("aBits"));
        byte[] bBits = fromB64(map.get("bBits"));
        int sfRounds = ((Number) map.get("sfRounds")).intValue();
        int blumRounds = ((Number) map.get("blumRounds")).intValue();
        return new BiPrimeBlumProof(N, w, sigmas, xs, aBits, bBits, zs, sfRounds, blumRounds);
    }

    public static Map<String, Object> encodeNoSmallFactorProof(NoSmallFactorProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("P", toB64(proof.P()));
        map.put("Q", toB64(proof.Q()));
        map.put("A", toB64(proof.A()));
        map.put("B", toB64(proof.B()));
        map.put("T", toB64(proof.T()));
        map.put("z1", toHex(proof.z1()));
        map.put("z2", toHex(proof.z2()));
        map.put("w1", toHex(proof.w1()));
        map.put("w2", toHex(proof.w2()));
        map.put("v", toHex(proof.v()));
        return map;
    }

    public static NoSmallFactorProof decodeNoSmallFactorProof(Map<?, ?> map) {
        byte[] P = fromB64(map.get("P"));
        byte[] Q = fromB64(map.get("Q"));
        byte[] A = fromB64(map.get("A"));
        byte[] B = fromB64(map.get("B"));
        byte[] T = fromB64(map.get("T"));
        BigInteger z1 = fromHex(map.get("z1"));
        BigInteger z2 = fromHex(map.get("z2"));
        BigInteger w1 = fromHex(map.get("w1"));
        BigInteger w2 = fromHex(map.get("w2"));
        BigInteger v = fromHex(map.get("v"));
        return new NoSmallFactorProof(P, Q, A, B, T, z1, z2, w1, w2, v);
    }

    public static Map<String, Object> encodeMtAInitiatorMessage(MtAInitiatorMessage msg) {
        Map<String, Object> map = new HashMap<>();
        map.put("cA", toHex(msg.cA()));
        map.put("rangeProof", encodePaillierRangeProof(msg.rangeProof()));
        map.put("biPrimeProof", encodeBiPrimeProof(msg.biPrimeProof()));
        map.put("factorProof", encodeNoSmallFactorProof(msg.factorProof()));
        return map;
    }

    public static MtAInitiatorMessage decodeMtAInitiatorMessage(Map<?, ?> map) {
        BigInteger cA = fromHex(map.get("cA"));
        PaillierRangeProof rangeProof = decodePaillierRangeProof((Map<?, ?>) map.get("rangeProof"));
        BiPrimeBlumProof biPrime = decodeBiPrimeProof((Map<?, ?>) map.get("biPrimeProof"));
        NoSmallFactorProof factor = decodeNoSmallFactorProof((Map<?, ?>) map.get("factorProof"));
        return new MtAInitiatorMessage(cA, rangeProof, biPrime, factor);
    }

    public static Map<String, Object> encodeMtAResult(MtAResult result) {
        Map<String, Object> map = new HashMap<>();
        map.put("c_j", toHex(result.c_j()));
        if (result.y() != null) {
            map.put("y", toHex(result.y()));
        }
        if (result.r() != null) {
            map.put("r", toHex(result.r()));
        }
        if (result.proof() != null) {
            map.put("proof", encodePaillierRespondentProof(result.proof()));
        }
        return map;
    }

    public static MtAResult decodeMtAResult(Map<?, ?> map) {
        BigInteger c_j = fromHex(map.get("c_j"));
        BigInteger y = map.containsKey("y") ? fromHex(map.get("y")) : null;
        BigInteger r = map.containsKey("r") ? fromHex(map.get("r")) : null;
        if (map.containsKey("proof")) {
            PaillierRespondentProof proof = decodePaillierRespondentProof((Map<?, ?>) map.get("proof"));
            return new MtAResult(c_j, y, r, proof);
        }
        return new MtAResult(c_j, y, r);
    }

    public static Map<String, Object> encodePiEncProof(PiEncProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("kProof", encodePaillierRangeProof(proof.kProof()));
        map.put("gProof", encodePaillierRangeProof(proof.gProof()));
        return map;
    }

    public static PiEncProof decodePiEncProof(Map<?, ?> map) {
        PaillierRangeProof kProof = decodePaillierRangeProof((Map<?, ?>) map.get("kProof"));
        PaillierRangeProof gProof = decodePaillierRangeProof((Map<?, ?>) map.get("gProof"));
        return new PiEncProof(kProof, gProof);
    }

    public static Map<String, Object> encodePiEncElgProof(PiEncElgProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("S", toHex(proof.S()));
        map.put("T", toHex(proof.T()));
        map.put("D", toHex(proof.D()));
        map.put("Y", toHexPoint(proof.Y()));
        map.put("Z", toHexPoint(proof.Z()));
        map.put("z1", toHex(proof.z1()));
        map.put("z2", toHex(proof.z2()));
        map.put("z3", toHex(proof.z3()));
        map.put("w", toHex(proof.w()));
        return map;
    }

    public static PiEncElgProof decodePiEncElgProof(Map<?, ?> map) {
        BigInteger S = fromHex(map.get("S"));
        BigInteger T = fromHex(map.get("T"));
        BigInteger D = fromHex(map.get("D"));
        ECPoint Y = fromHexPoint((String) map.get("Y"));
        ECPoint Z = fromHexPoint((String) map.get("Z"));
        BigInteger z1 = fromHex(map.get("z1"));
        BigInteger z2 = fromHex(map.get("z2"));
        BigInteger z3 = fromHex(map.get("z3"));
        BigInteger w = fromHex(map.get("w"));
        return new PiEncElgProof(S, T, D, Y, Z, z1, z2, z3, w);
    }

    public static Map<String, Object> encodePiAffGProof(PiAffGProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", encodeBigIntegerList(proof.A()));
        map.put("B", encodeBigIntegerList(proof.B()));
        map.put("R", encodeECPointList(proof.R()));
        map.put("z", encodeBigIntegerList(proof.z()));
        map.put("zPrime", encodeBigIntegerList(proof.zPrime()));
        map.put("w", encodeBigIntegerList(proof.w()));
        map.put("lambda", encodeBigIntegerList(proof.lambda()));
        return map;
    }

    public static PiAffGProof decodePiAffGProof(Map<?, ?> map) {
        List<BigInteger> A = decodeBigIntegerList((List<?>) map.get("A"));
        List<BigInteger> B = decodeBigIntegerList((List<?>) map.get("B"));
        List<ECPoint> R = decodeECPointList((List<?>) map.get("R"));
        List<BigInteger> z = decodeBigIntegerList((List<?>) map.get("z"));
        List<BigInteger> zPrime = decodeBigIntegerList((List<?>) map.get("zPrime"));
        List<BigInteger> w = decodeBigIntegerList((List<?>) map.get("w"));
        List<BigInteger> lambda = decodeBigIntegerList((List<?>) map.get("lambda"));
        return new PiAffGProof(A, B, R, z, zPrime, w, lambda);
    }

    public static Map<String, Object> encodePiLogStarProof(PiLogStarProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", toHexPoint(proof.A()));
        map.put("z", toHex(proof.z()));
        return map;
    }

    public static PiLogStarProof decodePiLogStarProof(Map<?, ?> map) {
        ECPoint A = fromHexPoint((String) map.get("A"));
        BigInteger z = fromHex(map.get("z"));
        return new PiLogStarProof(A, z);
    }

    public static Map<String, Object> encodePiSchProof(PiSchProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", toHexPoint(proof.A()));
        map.put("z", toHex(proof.z()));
        return map;
    }

    public static PiSchProof decodePiSchProof(Map<?, ?> map) {
        ECPoint A = fromHexPoint((String) map.get("A"));
        BigInteger z = fromHex(map.get("z"));
        return new PiSchProof(A, z);
    }

    public static Map<String, Object> encodePiPrmProof(PiPrmProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", toHex(proof.A()));
        map.put("z", toHex(proof.z()));
        return map;
    }

    public static PiPrmProof decodePiPrmProof(Map<?, ?> map) {
        BigInteger A = fromHex(map.get("A"));
        BigInteger z = fromHex(map.get("z"));
        return new PiPrmProof(A, z);
    }

    public static Map<String, Object> encodePiLogProof(PiLogProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("U1", toHexPoint(proof.U1()));
        map.put("U2", toHexPoint(proof.U2()));
        map.put("U3", toHexPoint(proof.U3()));
        map.put("z1", toHex(proof.z1()));
        map.put("z2", toHex(proof.z2()));
        return map;
    }

    public static PiLogProof decodePiLogProof(Map<?, ?> map) {
        ECPoint U1 = fromHexPoint((String) map.get("U1"));
        ECPoint U2 = fromHexPoint((String) map.get("U2"));
        ECPoint U3 = fromHexPoint((String) map.get("U3"));
        BigInteger z1 = fromHex(map.get("z1"));
        BigInteger z2 = fromHex(map.get("z2"));
        return new PiLogProof(U1, U2, U3, z1, z2);
    }

    public static Map<String, Object> encodePiDecProof(PiDecProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", encodeBigIntegerList(proof.A()));
        map.put("B", encodeECPointList(proof.B()));
        map.put("C", encodeECPointList(proof.C()));
        map.put("z", encodeBigIntegerList(proof.z()));
        map.put("w", encodeBigIntegerList(proof.w()));
        map.put("nu", encodeBigIntegerList(proof.nu()));
        return map;
    }

    public static PiDecProof decodePiDecProof(Map<?, ?> map) {
        List<BigInteger> A = decodeBigIntegerList((List<?>) map.get("A"));
        List<ECPoint> B = decodeECPointList((List<?>) map.get("B"));
        List<ECPoint> C = decodeECPointList((List<?>) map.get("C"));
        List<BigInteger> z = decodeBigIntegerList((List<?>) map.get("z"));
        List<BigInteger> w = decodeBigIntegerList((List<?>) map.get("w"));
        List<BigInteger> nu = decodeBigIntegerList((List<?>) map.get("nu"));
        return new PiDecProof(A, B, C, z, w, nu);
    }

    private static List<String> encodeBigIntegerList(List<BigInteger> list) {
        List<String> out = new ArrayList<>(list.size());
        for (BigInteger v : list) {
            out.add(toHex(v));
        }
        return out;
    }

    private static List<BigInteger> decodeBigIntegerList(List<?> list) {
        List<BigInteger> out = new ArrayList<>(list.size());
        for (Object v : list) {
            out.add(new BigInteger((String) v, 16));
        }
        return out;
    }

    private static List<String> encodeECPointList(List<ECPoint> list) {
        List<String> out = new ArrayList<>(list.size());
        for (ECPoint p : list) {
            out.add(bytesToHex(p.getEncoded(false)));
        }
        return out;
    }

    private static List<ECPoint> decodeECPointList(List<?> list) {
        List<ECPoint> out = new ArrayList<>(list.size());
        for (Object v : list) {
            out.add(fromHexPoint((String) v));
        }
        return out;
    }

    private static String toHexPoint(ECPoint p) {
        return bytesToHex(p.getEncoded(false));
    }

    private static ECPoint fromHexPoint(String hex) {
        return Secp256k1Curve.decodePoint(hexToBytes(hex));
    }
}
