package com.example.mpc.cggmp;

import org.exploit.gmp.BigInt;
import org.exploit.secp256k1.Secp256k1CurveParams;
import org.exploit.secp256k1.Secp256k1PointOps;
import org.exploit.tss.curve.PointOps;
import org.exploit.tss.ecdsa.commitment.ChaumPedersenCommitment;
import org.exploit.tss.ecdsa.commitment.ChaumPedersenCommitmentWithValue;
import org.exploit.tss.ecdsa.commitment.GammaCommitment;
import org.exploit.tss.mta.model.MtAInitiatorMessage;
import org.exploit.tss.mta.model.MtAResult;
import org.exploit.tss.pallier.key.PaillierPublicKey;
import org.exploit.tss.proof.model.*;

import java.util.*;
import java.util.Base64;

public final class Gg20Codec {
    private Gg20Codec() {}

    public static String encodeBigInt(BigInt value) {
        return Base64.getEncoder().encodeToString(value.toByteArray());
    }

    public static BigInt decodeBigInt(String encoded) {
        return new BigInt(Base64.getDecoder().decode(encoded));
    }

    public static String encodeBytes(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] decodeBytes(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    public static String encodePoint(PointOps<?> point) {
        return encodeBytes(point.encode(true));
    }

    public static Secp256k1PointOps decodePoint(Secp256k1CurveParams curve, String encoded) {
        return curve.decodePoint(decodeBytes(encoded));
    }

    public static Map<String, Object> encodePaillierPublicKey(PaillierPublicKey key) {
        Map<String, Object> map = new HashMap<>();
        map.put("n", encodeBigInt(key.n()));
        map.put("nsquare", encodeBigInt(key.nsquare()));
        map.put("g", encodeBigInt(key.g()));
        map.put("bitLength", key.bitLength());
        return map;
    }

    public static PaillierPublicKey decodePaillierPublicKey(Map<?, ?> map) {
        BigInt n = decodeBigInt((String) map.get("n"));
        BigInt nsquare = decodeBigInt((String) map.get("nsquare"));
        BigInt g = decodeBigInt((String) map.get("g"));
        int bitLength = ((Number) map.get("bitLength")).intValue();
        return new PaillierPublicKey(n, nsquare, g, bitLength);
    }

    public static Map<String, Object> encodeZkSetup(ZKSetup setup) {
        Map<String, Object> map = new HashMap<>();
        map.put("hatN", encodeBigInt(setup.hatN()));
        map.put("h1", encodeBigInt(setup.h1()));
        map.put("h2", encodeBigInt(setup.h2()));
        return map;
    }

    public static ZKSetup decodeZkSetup(Map<?, ?> map) {
        BigInt hatN = decodeBigInt((String) map.get("hatN"));
        BigInt h1 = decodeBigInt((String) map.get("h1"));
        BigInt h2 = decodeBigInt((String) map.get("h2"));
        return new ZKSetup(hatN, h1, h2);
    }

    public static Map<String, Object> encodePaillierRangeProof(PaillierRangeProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("z", encodeBytes(proof.z()));
        map.put("u", encodeBytes(proof.u()));
        map.put("w", encodeBytes(proof.w()));
        map.put("s", encodeBytes(proof.s()));
        map.put("s1", encodeBigInt(proof.s1()));
        map.put("s2", encodeBigInt(proof.s2()));
        return map;
    }

    public static PaillierRangeProof decodePaillierRangeProof(Map<?, ?> map) {
        byte[] z = decodeBytes((String) map.get("z"));
        byte[] u = decodeBytes((String) map.get("u"));
        byte[] w = decodeBytes((String) map.get("w"));
        byte[] s = decodeBytes((String) map.get("s"));
        BigInt s1 = decodeBigInt((String) map.get("s1"));
        BigInt s2 = decodeBigInt((String) map.get("s2"));
        return new PaillierRangeProof(z, u, w, s, s1, s2);
    }

    public static Map<String, Object> encodeBiPrimeBlumProof(BiPrimeBlumProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("N", encodeBigInt(proof.N()));
        map.put("w", encodeBigInt(proof.w()));
        map.put("sigmas", encodeBigIntList(proof.sigmas()));
        map.put("xs", encodeBigIntList(proof.xs()));
        map.put("aBits", encodeBytes(proof.aBits()));
        map.put("bBits", encodeBytes(proof.bBits()));
        map.put("zs", encodeBigIntList(proof.zs()));
        map.put("sfRounds", proof.sfRounds());
        map.put("blumRounds", proof.blumRounds());
        return map;
    }

    public static BiPrimeBlumProof decodeBiPrimeBlumProof(Map<?, ?> map) {
        BigInt N = decodeBigInt((String) map.get("N"));
        BigInt w = decodeBigInt((String) map.get("w"));
        List<BigInt> sigmas = decodeBigIntList((List<?>) map.get("sigmas"));
        List<BigInt> xs = decodeBigIntList((List<?>) map.get("xs"));
        byte[] aBits = decodeBytes((String) map.get("aBits"));
        byte[] bBits = decodeBytes((String) map.get("bBits"));
        List<BigInt> zs = decodeBigIntList((List<?>) map.get("zs"));
        int sfRounds = ((Number) map.get("sfRounds")).intValue();
        int blumRounds = ((Number) map.get("blumRounds")).intValue();
        return new BiPrimeBlumProof(N, w, sigmas, xs, aBits, bBits, zs, sfRounds, blumRounds);
    }

    public static Map<String, Object> encodeNoSmallFactorProof(NoSmallFactorProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("P", encodeBytes(proof.P()));
        map.put("Q", encodeBytes(proof.Q()));
        map.put("A", encodeBytes(proof.A()));
        map.put("B", encodeBytes(proof.B()));
        map.put("T", encodeBytes(proof.T()));
        map.put("z1", encodeBigInt(proof.z1()));
        map.put("z2", encodeBigInt(proof.z2()));
        map.put("w1", encodeBigInt(proof.w1()));
        map.put("w2", encodeBigInt(proof.w2()));
        map.put("v", encodeBigInt(proof.v()));
        return map;
    }

    public static NoSmallFactorProof decodeNoSmallFactorProof(Map<?, ?> map) {
        byte[] P = decodeBytes((String) map.get("P"));
        byte[] Q = decodeBytes((String) map.get("Q"));
        byte[] A = decodeBytes((String) map.get("A"));
        byte[] B = decodeBytes((String) map.get("B"));
        byte[] T = decodeBytes((String) map.get("T"));
        BigInt z1 = decodeBigInt((String) map.get("z1"));
        BigInt z2 = decodeBigInt((String) map.get("z2"));
        BigInt w1 = decodeBigInt((String) map.get("w1"));
        BigInt w2 = decodeBigInt((String) map.get("w2"));
        BigInt v = decodeBigInt((String) map.get("v"));
        return new NoSmallFactorProof(P, Q, A, B, T, z1, z2, w1, w2, v);
    }

    public static Map<String, Object> encodePaillierRespondentProof(PaillierRespondentProof proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("z", encodeBytes(proof.z()));
        map.put("zPrime", encodeBytes(proof.zPrime()));
        map.put("t", encodeBytes(proof.t()));
        map.put("v", encodeBytes(proof.v()));
        map.put("w", encodeBytes(proof.w()));
        map.put("s", encodeBytes(proof.s()));
        map.put("s1", encodeBigInt(proof.s1()));
        map.put("s2", encodeBigInt(proof.s2()));
        map.put("t1", encodeBigInt(proof.t1()));
        map.put("t2", encodeBigInt(proof.t2()));
        return map;
    }

    public static PaillierRespondentProof decodePaillierRespondentProof(Map<?, ?> map) {
        byte[] z = decodeBytes((String) map.get("z"));
        byte[] zPrime = decodeBytes((String) map.get("zPrime"));
        byte[] t = decodeBytes((String) map.get("t"));
        byte[] v = decodeBytes((String) map.get("v"));
        byte[] w = decodeBytes((String) map.get("w"));
        byte[] s = decodeBytes((String) map.get("s"));
        BigInt s1 = decodeBigInt((String) map.get("s1"));
        BigInt s2 = decodeBigInt((String) map.get("s2"));
        BigInt t1 = decodeBigInt((String) map.get("t1"));
        BigInt t2 = decodeBigInt((String) map.get("t2"));
        return new PaillierRespondentProof(z, zPrime, t, v, w, s, s1, s2, t1, t2);
    }

    public static Map<String, Object> encodeMtAInitiatorMessage(MtAInitiatorMessage msg) {
        Map<String, Object> map = new HashMap<>();
        map.put("cA", encodeBigInt(msg.cA()));
        map.put("rangeProof", encodePaillierRangeProof(msg.proof()));
        map.put("biPrimeProof", encodeBiPrimeBlumProof(msg.biPrimeProof()));
        map.put("factorProof", encodeNoSmallFactorProof(msg.factorProof()));
        return map;
    }

    public static MtAInitiatorMessage decodeMtAInitiatorMessage(Map<?, ?> map) {
        BigInt cA = decodeBigInt((String) map.get("cA"));
        PaillierRangeProof rangeProof = decodePaillierRangeProof((Map<?, ?>) map.get("rangeProof"));
        BiPrimeBlumProof biPrime = decodeBiPrimeBlumProof((Map<?, ?>) map.get("biPrimeProof"));
        NoSmallFactorProof factor = decodeNoSmallFactorProof((Map<?, ?>) map.get("factorProof"));
        return new MtAInitiatorMessage(cA, rangeProof, biPrime, factor);
    }

    public static Map<String, Object> encodeMtAResult(MtAResult result) {
        Map<String, Object> map = new HashMap<>();
        map.put("c_j", encodeBigInt(result.c_j()));
        map.put("y", encodeBigInt(result.y()));
        map.put("r", encodeBigInt(result.r()));
        if (result.proof() != null) {
            map.put("proof", encodePaillierRespondentProof(result.proof()));
        }
        return map;
    }

    public static MtAResult decodeMtAResult(Map<?, ?> map) {
        BigInt c_j = decodeBigInt((String) map.get("c_j"));
        BigInt y = decodeBigInt((String) map.get("y"));
        BigInt r = decodeBigInt((String) map.get("r"));
        if (map.containsKey("proof")) {
            PaillierRespondentProof proof = decodePaillierRespondentProof((Map<?, ?>) map.get("proof"));
            return new MtAResult(c_j, y, r, proof);
        }
        return new MtAResult(c_j, y, r);
    }

    public static Map<String, Object> encodeGammaCommitment(GammaCommitment<Secp256k1PointOps> commitment) {
        Map<String, Object> map = new HashMap<>();
        map.put("C_i", encodePoint(commitment.C_i()));
        map.put("r_i", encodeBigInt(commitment.r_i()));
        return map;
    }

    public static GammaCommitment<Secp256k1PointOps> decodeGammaCommitment(Secp256k1CurveParams curve, Map<?, ?> map) {
        Secp256k1PointOps c = decodePoint(curve, (String) map.get("C_i"));
        BigInt r = decodeBigInt((String) map.get("r_i"));
        return new GammaCommitment<>(c, r);
    }

    public static Map<String, Object> encodeChaumCommitment(ChaumPedersenCommitment<Secp256k1PointOps> commitment) {
        Map<String, Object> map = new HashMap<>();
        map.put("T", encodePoint(commitment.T()));
        map.put("proof", encodeChaumProof(commitment.proof()));
        return map;
    }

    public static ChaumPedersenCommitment<Secp256k1PointOps> decodeChaumCommitment(Secp256k1CurveParams curve, Map<?, ?> map) {
        Secp256k1PointOps T = decodePoint(curve, (String) map.get("T"));
        ChaumPedersenProof<Secp256k1PointOps> proof = decodeChaumProof(curve, (Map<?, ?>) map.get("proof"));
        return new ChaumPedersenCommitment<>(T, proof);
    }

    public static Map<String, Object> encodeChaumCommitmentWithValue(ChaumPedersenCommitmentWithValue<Secp256k1PointOps> commitment) {
        Map<String, Object> map = new HashMap<>();
        map.put("commitment", encodeChaumCommitment(commitment.commitment()));
        map.put("value", encodePoint(commitment.value()));
        return map;
    }

    public static ChaumPedersenCommitmentWithValue<Secp256k1PointOps> decodeChaumCommitmentWithValue(Secp256k1CurveParams curve, Map<?, ?> map) {
        ChaumPedersenCommitment<Secp256k1PointOps> commitment = decodeChaumCommitment(curve, (Map<?, ?>) map.get("commitment"));
        Secp256k1PointOps value = decodePoint(curve, (String) map.get("value"));
        return new ChaumPedersenCommitmentWithValue<>(commitment, value);
    }

    public static Map<String, Object> encodeChaumProof(ChaumPedersenProof<Secp256k1PointOps> proof) {
        Map<String, Object> map = new HashMap<>();
        map.put("A", encodePoint(proof.A()));
        map.put("r", encodeBigInt(proof.r()));
        map.put("s", encodeBigInt(proof.s()));
        return map;
    }

    public static ChaumPedersenProof<Secp256k1PointOps> decodeChaumProof(Secp256k1CurveParams curve, Map<?, ?> map) {
        Secp256k1PointOps A = decodePoint(curve, (String) map.get("A"));
        BigInt r = decodeBigInt((String) map.get("r"));
        BigInt s = decodeBigInt((String) map.get("s"));
        return new ChaumPedersenProof<>(A, r, s);
    }

    private static List<String> encodeBigIntList(List<BigInt> values) {
        List<String> out = new ArrayList<>();
        for (BigInt v : values) {
            out.add(encodeBigInt(v));
        }
        return out;
    }

    private static List<BigInt> decodeBigIntList(List<?> values) {
        List<BigInt> out = new ArrayList<>();
        for (Object v : values) {
            out.add(decodeBigInt((String) v));
        }
        return out;
    }
}
