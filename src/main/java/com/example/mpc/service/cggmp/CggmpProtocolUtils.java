package com.example.mpc.service.cggmp;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.dto.CggmpAuxTask;
import com.example.mpc.dto.CggmpSignatureTask;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;

import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * CGGMP协议工具类
 * 提供协议通用的工具方法，如哈希、编码、消息处理等
 */
public final class CggmpProtocolUtils {

    /**
     * 构建MtA协议上下文
     */
    public static byte[] buildMtaContext(String taskId, int senderId, int receiverId) {
        String ctx = taskId + ":" + senderId + ":" + receiverId;
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建预签名上下文
     */
    public static byte[] buildPresignContext(String taskId, int senderId, String round) {
        String sid = buildSignSid(taskId);
        String ctx = "PRESIGN:" + round + ":" + sid + ":" + senderId;
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建签名上下文
     */
    public static byte[] buildSignContext(String taskId, int senderId, byte[] messageHash, String stage) {
        String sid = buildSignSid(taskId);
        String ctx = "SIGN:" + stage + ":" + sid + ":" + senderId + ":" + HexUtils.bytesToHex(messageHash);
        return ctx.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建辅助密钥上下文
     */
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

    /**
     * 计算消息的SHA-256哈希
     */
    public static byte[] hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 计算带标签的哈希值
     */
    public static String computeTaggedHashHex(String tag, Object... parts) {
        return CggmpHashUtils.computeCggmpTaggedHashHex(tag, parts);
    }

    /**
     * 计算辅助密钥Echo哈希
     */
    public static String computeAuxEchoHash(CggmpAuxTask task) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(task.executionId.getBytes(StandardCharsets.UTF_8));
            md.update(task.taskId.getBytes(StandardCharsets.UTF_8));
            int count = 0;
            java.util.SortedMap<Integer, String> ordered = new java.util.TreeMap<>(task.commitHashes);
            for (Map.Entry<Integer, String> e : ordered.entrySet()) {
                count++;
                md.update(String.valueOf(e.getKey()).getBytes(StandardCharsets.UTF_8));
                md.update(e.getValue().getBytes(StandardCharsets.UTF_8));
            }
            String out = HexUtils.bytesToHex(md.digest());
            if (count < task.participants.size()) {
                org.slf4j.LoggerFactory.getLogger(CggmpProtocolUtils.class)
                        .debug("AUX echo hash computed with incomplete commits: taskId={}, executionId={}, commits={}/{}",
                                task.taskId, task.executionId, count, task.participants.size());
            }
            return out;
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

    /**
     * 模N取负
     */
    public static BigInteger negateModN(BigInteger value, BigInteger n) {
        return value.negate().mod(n);
    }

    /**
     * 解码有符号整数
     */
    public static BigInteger decodeSigned(BigInteger value, BigInteger n) {
        if (value.compareTo(n) < 0) {
            return value;
        }
        return value.subtract(n);
    }

    /**
     * 计算签名的拉格朗日系数
     */
    public static BigInteger computeSignatureLagrange(CggmpSignatureTask task, int signerId, BigInteger mod) {
        if (task == null) {
            return BigInteger.ONE;
        }
        if (!signatureUsesLagrange(task)) {
            return BigInteger.ONE;
        }
        return lagrangeCoefficientAtZero(signerId, task.participants, task.indexMap, mod);
    }

    /**
     * 解析公钥分片
     */
    public static ECPoint resolvePublicShare(CggmpSignatureTask task, int signerId, BigInteger lambda, BigInteger x_i) {
        if (task.publicShares != null) {
            ECPoint base = task.publicShares.get(signerId);
            if (base != null) {
                return base.multiply(lambda).normalize();
            }
        }
        return Secp256k1CurveUtils.G().multiply(x_i).normalize();
    }

    public static ECPoint resolvePublicShareFromMap(CggmpSignatureTask task, int signerId, BigInteger lambda) {
        if (task.publicShares == null) {
            return null;
        }
        ECPoint base = task.publicShares.get(signerId);
        if (base == null) {
            return null;
        }
        return base.multiply(lambda).normalize();
    }

    /**
     * 求和分片值
     */
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

    /**
     * 求和预签名Gamma点
     */
    public static ECPoint sumPresignGamma(CggmpSignatureTask task) {
        ECPoint sum = Secp256k1CurveUtils.G().getCurve().getInfinity();
        for (ECPoint p : task.presignGamma.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    /**
     * 生成非零随机数
     */
    public static BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    public static Map<?, ?> asMap(Object value) {
        return value instanceof Map<?, ?> map ? map : null;
    }

    /**
     * 类型转换为String
     */
    public static String asString(Object value) {
        return value instanceof String s ? s : null;
    }

    /**
     * 类型转换为Integer
     */
    public static Integer asInt(Object value) {
        return value instanceof Number n ? n.intValue() : null;
    }

    /**
     * 发送并忘记（异步执行，仅记录错误）
     */
    public static void fireAndForget(CompletableFuture<Void> future, Logger logger, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    public static byte[] randomBytes(int len) {
        return SecureRandomUtils.randomBytes(len);
    }

    private static boolean signatureUsesLagrange(CggmpSignatureTask task) {
        return task.threshold < task.nodesCount;
    }

    public static BigInteger lagrangeAtZero(int id, Set<Integer> participants, Map<Integer, BigInteger> indexMap, BigInteger mod) {
        if (participants == null || participants.isEmpty()) {
            return BigInteger.ZERO;
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
