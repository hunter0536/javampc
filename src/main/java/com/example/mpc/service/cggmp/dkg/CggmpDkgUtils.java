package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.dto.CggmpDkgTask;
import com.example.mpc.enums.MessageType;
import com.example.mpc.service.cggmp.CggmpHashUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CGGMP DKG工具类
 * 提供分布式密钥生成协议专用的工具方法
 */
public final class CggmpDkgUtils {
    private CggmpDkgUtils() {
    }

    public static byte[] buildDkgContext(String taskId, String executionId, byte[] rid, int senderId, String label) {
        String sid = buildSid(executionId, taskId);
        String base = "DKG:" + label + ":" + sid + ":" + senderId + ":";
        byte[] prefix = base.getBytes(StandardCharsets.UTF_8);
        if (rid == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rid.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rid, 0, out, prefix.length, rid.length);
        return out;
    }

    public static String buildSid(String executionId, String taskId) {
        return "CGGMP24:" + executionId + ":" + taskId;
    }

    public static String computeTaggedHashHex(String tag, Object... parts) {
        return CggmpHashUtils.computeTaggedHashHex(tag, parts);
    }

    public static String computeDkgEchoHash(CggmpDkgTask task) {
        try {
            String sid = buildSid(task.executionId, task.taskId);
            List<Integer> ids = new ArrayList<>(task.participants);
            Collections.sort(ids);
            List<String> commits = new ArrayList<>();
            for (int id : ids) {
                String v = task.round1PayloadHashes.get(id);
                if (v == null) {
                    return null;
                }
                commits.add(v);
            }
            return computeTaggedHashHex("DKG_ECHO", sid, commits);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute DKG echo hash", e);
        }
    }


    public static String computeDkgCommitHash(String executionId,
                                              String taskId,
                                              int senderId,
                                              byte[] ridPart,
                                              Map<Integer, ECPoint> sVec,
                                              ECPoint A,
                                              byte[] u,
                                              byte[] chainCode) {
        String sid = buildSid(executionId, taskId);
        Map<String, String> sMap = Secp256k1CurveUtils.encodeECPointMapCompressed(sVec);
        String aHex = HexUtils.bytesToHex(A.getEncoded(true));
        return computeTaggedHashHex("DKG_HASH_COM", sid, senderId, ridPart, sMap, aHex, u, chainCode);
    }

    public static String computeDkgCommitHashFromWire(String executionId,
                                                      String taskId,
                                                      int senderId,
                                                      String ridPartHex,
                                                      Map<?, ?> sMap,
                                                      String aHex,
                                                      String uHex,
                                                      String cHex) {
        String sid = buildSid(executionId, taskId);
        byte[] rid = ridPartHex == null ? null : HexUtils.hexToBytes(ridPartHex);
        byte[] u = uHex == null ? null : HexUtils.hexToBytes(uHex);
        byte[] c = cHex == null ? null : HexUtils.hexToBytes(cHex);
        return computeTaggedHashHex("DKG_HASH_COM", sid, senderId, rid, sMap, aHex, u, c);
    }

    public static BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x, BigInteger mod) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        for (BigInteger coeff : coefficients) {
            result = result.add(coeff.multiply(xPower)).mod(mod);
            xPower = BigIntegerUtils.modMul(xPower, x, mod);
        }
        return result;
    }

    public static BigInteger[] precomputeEvalPowers(BigInteger x, int threshold) {
        BigInteger q = Secp256k1CurveUtils.n();
        if (x == null) {
            throw new IllegalArgumentException("Missing evaluation index");
        }
        BigInteger[] powers = new BigInteger[threshold];
        BigInteger xPower = BigInteger.ONE;
        for (int k = 0; k < threshold; k++) {
            powers[k] = xPower;
            xPower = BigIntegerUtils.modMul(xPower, x, q);
        }
        return powers;
    }

    public static ECPoint computeExpectedShareFromXjk(Map<Integer, ECPoint> Xjk, BigInteger[] evalPowers) {
        ECPoint sum = Secp256k1CurveUtils.G().getCurve().getInfinity();
        if (evalPowers == null) {
            throw new IllegalStateException("Missing precomputed DKG evaluation powers");
        }
        int limit = Math.min(Xjk.size(), evalPowers.length);
        for (int k = 0; k < limit; k++) {
            ECPoint X = Xjk.get(k);
            if (X == null) {
                continue;
            }
            sum = sum.add(X.multiply(evalPowers[k])).normalize();
        }
        return sum;
    }

    public static PiSchProof createSchProofWithAlpha(ECPoint g, ECPoint X, BigInteger x, BigInteger alpha, byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        ECPoint A = g.multiply(alpha).normalize();
        BigInteger e = schChallenge(context, g, X, A);
        BigInteger z = alpha.add(e.multiply(x)).mod(q);
        return new PiSchProof(A, z);
    }

    public static BigInteger schChallenge(byte[] context, ECPoint g, ECPoint X, ECPoint A) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("PI_SCH".getBytes(StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            md.update(Secp256k1CurveUtils.encodePoint(g));
            md.update(Secp256k1CurveUtils.encodePoint(X));
            md.update(Secp256k1CurveUtils.encodePoint(A));
            BigInteger q = Secp256k1CurveUtils.n();
            BigInteger twoQ = q.shiftLeft(1);
            BigInteger e = new BigInteger(1, md.digest()).mod(twoQ);
            return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
        } catch (Exception e) {
            throw new RuntimeException("DKG Schnorr challenge failed", e);
        }
    }

    public static boolean verifySchProofWithCommitment(ECPoint g, ECPoint X, ECPoint A, BigInteger z, byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger e = schChallenge(context, g, X, A).mod(q);
        ECPoint lhs = g.multiply(z).normalize();
        ECPoint rhs = A.add(X.multiply(e)).normalize();
        return lhs.equals(rhs);
    }

    public static boolean verifyDkgShare(Map<Integer, ECPoint> sVec, BigInteger x, BigInteger sigma) {
        if (sVec == null || x == null || sigma == null) {
            return false;
        }
        if (x.signum() == 0) {
            return false;
        }
        BigInteger[] powers = precomputeEvalPowers(x, sVec.size());
        ECPoint expected = computeExpectedShareFromXjk(sVec, powers);
        ECPoint actual = Secp256k1CurveUtils.G().multiply(sigma).normalize();
        return expected.equals(actual);
    }

    public static ECPoint computePublicShare(CggmpDkgTask task, int receiverId) {
        BigInteger x = getIndexValue(task, receiverId);
        if (x == null) {
            throw new RuntimeException("Missing index for node " + receiverId);
        }
        Map<Integer, ECPoint> XkStar = task.XkStar;
        if (XkStar.isEmpty()) {
            Map<Integer, ECPoint> merged = new HashMap<>();
            for (int peerId : task.participants) {
                Map<Integer, ECPoint> Xjk = task.Xjks.get(peerId);
                if (Xjk == null) {
                    continue;
                }
                for (Map.Entry<Integer, ECPoint> e : Xjk.entrySet()) {
                    merged.merge(e.getKey(), e.getValue(), (a, b) -> a.add(b).normalize());
                }
            }
            task.XkStar.putAll(merged);
        }
        BigInteger[] evalPowers = precomputeEvalPowers(x, task.threshold);
        ECPoint expected = computeExpectedShareFromXjk(XkStar, evalPowers);
        return expected.normalize();
    }

    public static BigInteger getIndexValue(CggmpDkgTask task, int nodeId) {
        if (task.indexMap != null && task.indexMap.containsKey(nodeId)) {
            return task.indexMap.get(nodeId);
        }
        return BigInteger.valueOf(nodeId);
    }

    public static byte[] xorRidParts(CggmpDkgTask task) {
        byte[] rid = null;
        for (byte[] part : task.ridParts.values()) {
            if (part == null) {
                continue;
            }
            if (rid == null) {
                rid = part.clone();
                continue;
            }
            for (int i = 0; i < rid.length && i < part.length; i++) {
                rid[i] ^= part[i];
            }
        }
        return rid == null ? new byte[0] : rid;
    }

    public static byte[] xorChainCodeParts(CggmpDkgTask task) {
        byte[] code = null;
        for (byte[] part : task.chainCodeParts.values()) {
            if (part == null) {
                continue;
            }
            if (code == null) {
                code = part.clone();
                continue;
            }
            for (int i = 0; i < code.length && i < part.length; i++) {
                code[i] ^= part[i];
            }
        }
        return code == null ? new byte[0] : code;
    }

    public static Object maybeCompressDkgPayload(MessageType type, Object data) {
        if (type == null) {
            return data;
        }
        return data;
    }

    public static Object maybeDecompressDkgPayload(MessageType type, byte[] bytes) {
        if (type == null || bytes == null || bytes.length == 0) {
            return null;
        }
        return null;
    }
}
