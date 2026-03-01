package com.example.mpc.service.cggmp;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.model.CggmpAuxTask;
import com.example.mpc.model.Gg20SignatureTask;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public final class CggmpProtocolUtils {

    public static byte[] buildMtaContext(String taskId, int senderId, int receiverId) {
        String ctx = taskId + ":" + senderId + ":" + receiverId;
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] buildPresignContext(String taskId, int senderId, String round) {
        String sid = buildSignSid(taskId);
        String ctx = "PRESIGN:" + round + ":" + sid + ":" + senderId;
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] buildSignContext(String taskId, int senderId, byte[] messageHash, String stage) {
        String sid = buildSignSid(taskId);
        String ctx = "SIGN:" + stage + ":" + sid + ":" + senderId + ":" + HexUtils.bytesToHex(messageHash);
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] buildAuxContext(String taskId, String executionId, int senderId, String label) {
        String sid = buildAuxSid(executionId, taskId);
        String base = "AUX:" + label + ":" + sid + ":" + senderId + ":";
        return base.getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] buildAuxContext(String taskId, String executionId, int senderId, String label, byte[] rho) {
        byte[] prefix = buildAuxContext(taskId, executionId, senderId, label);
        if (rho == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rho.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rho, 0, out, prefix.length, rho.length);
        return out;
    }

    public static byte[] hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public static String computeTaggedHashHex(String tag, Object... parts) {
        return com.example.mpc.service.cggmp.CggmpHashUtils.computeCggmpTaggedHashHex(tag, parts);
    }

    public static String computeAuxEchoHash(CggmpAuxTask task) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(task.executionId.getBytes(StandardCharsets.UTF_8));
            md.update(task.taskId.getBytes(StandardCharsets.UTF_8));
            for (Map.Entry<Integer, String> e : task.commitHashes.entrySet()) {
                md.update(String.valueOf(e.getKey()).getBytes(StandardCharsets.UTF_8));
                md.update(e.getValue().getBytes(StandardCharsets.UTF_8));
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute AUX echo hash", e);
        }
    }

    public static String computeAuxCommitHash(String executionId, String taskId, int senderId,
                                              Map<String, Object> pkMap, String hatN, String s, String t,
                                              Map<String, Object> prmMap, byte[] rho, byte[] u) {
        String sid = buildAuxSid(executionId, taskId);
        return computeTaggedHashHex("AUX_HASH_COM", sid, senderId, pkMap, hatN, s, t, prmMap, rho, u);
    }

    public static BigInteger negateModN(BigInteger value, BigInteger n) {
        return value.negate().mod(n);
    }

    public static BigInteger decodeSigned(BigInteger value, BigInteger n) {
        if (value.compareTo(n) < 0) {
            return value;
        }
        return value.subtract(n);
    }

    public static BigInteger computeSignatureLagrange(Gg20SignatureTask task, int signerId, BigInteger mod) {
        if (task == null) {
            return BigInteger.ONE;
        }
        if (!signatureUsesLagrange(task)) {
            return BigInteger.ONE;
        }
        return lagrangeCoefficientAtZero(signerId, task.participants, task.indexMap, mod);
    }

    public static ECPoint resolvePublicShare(Gg20SignatureTask task, int signerId, BigInteger lambda, BigInteger x_i) {
        if (task.publicShares != null) {
            ECPoint base = task.publicShares.get(signerId);
            if (base != null) {
                return base.multiply(lambda).normalize();
            }
        }
        return Secp256k1CurveUtils.G().multiply(x_i).normalize();
    }

    public static ECPoint resolvePublicShareFromMap(Gg20SignatureTask task, int signerId, BigInteger lambda) {
        if (task.publicShares == null) {
            return null;
        }
        ECPoint base = task.publicShares.get(signerId);
        if (base == null) {
            return null;
        }
        return base.multiply(lambda).normalize();
    }

    public static BigInteger sumShares(Map<Integer, BigInteger> shares, BigInteger mod) {
        if (shares == null || shares.isEmpty()) {
            return BigInteger.ZERO;
        }
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger v : shares.values()) {
            if (v == null) {
                continue;
            }
            sum = sum.add(v);
        }
        return sum.mod(mod);
    }

    public static ECPoint sumPresignGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1CurveUtils.G().getCurve().getInfinity();
        for (ECPoint p : task.presignGamma.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    public static BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    public static Map<?, ?> asMap(Object value) {
        return value instanceof Map<?, ?> map ? map : null;
    }

    public static String asString(Object value) {
        return value instanceof String s ? s : null;
    }

    public static Integer asInt(Object value) {
        return value instanceof Number n ? n.intValue() : null;
    }

    public static void fireAndForget(CompletableFuture<Void> future, Logger logger, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    public static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static boolean signatureUsesLagrange(Gg20SignatureTask task) {
        return task.threshold < task.nodesCount;
    }

    private static BigInteger lagrangeCoefficientAtZero(int id, Set<Integer> participants, Map<Integer, BigInteger> indexMap, BigInteger mod) {
        if (participants == null || participants.isEmpty()) {
            throw new IllegalArgumentException("Participants set is empty");
        }
        BigInteger num = BigInteger.ONE;
        BigInteger den = BigInteger.ONE;
        BigInteger idBi = indexMap != null && indexMap.get(id) != null ? indexMap.get(id) : BigInteger.valueOf(id);
        for (int peerId : participants) {
            if (peerId == id) {
                continue;
            }
            BigInteger peerBi = indexMap != null && indexMap.get(peerId) != null ? indexMap.get(peerId) : BigInteger.valueOf(peerId);
            num = num.multiply(peerBi).mod(mod);
            BigInteger diff = peerBi.subtract(idBi).mod(mod);
            den = den.multiply(diff).mod(mod);
        }
        return num.multiply(den.modInverse(mod)).mod(mod);
    }

    private static String buildSignSid(String taskId) {
        return "CGGMP24:SIGN:" + taskId;
    }

    private static String buildAuxSid(String executionId, String taskId) {
        return "CGGMP24:" + executionId + ":" + taskId;
    }

}
