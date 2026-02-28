package com.example.mpc.service;

import com.example.mpc.common.util.HexUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Set;

public class SignUtils {

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

    public static String computeTaggedHashHex(String tag, Object... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(("CGGMP:" + tag).getBytes(StandardCharsets.UTF_8));
            for (Object part : parts) {
                updateDigest(md, part);
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute tagged hash", e);
        }
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

    private static String buildSignSid(String taskId) {
        return "SIGN" + ":" + taskId;
    }

    private static void updateDigest(MessageDigest md, Object value) {
        if (value == null) {
            md.update((byte) 0);
        } else if (value instanceof byte[]) {
            md.update((byte[]) value);
        } else if (value instanceof String) {
            md.update(((String) value).getBytes(StandardCharsets.UTF_8));
        } else if (value instanceof BigInteger) {
            byte[] bytes = ((BigInteger) value).toByteArray();
            md.update(bytes);
        } else if (value instanceof org.bouncycastle.math.ec.ECPoint) {
            md.update(((org.bouncycastle.math.ec.ECPoint) value).getEncoded(true));
        } else if (value instanceof Number) {
            md.update(value.toString().getBytes(StandardCharsets.UTF_8));
        } else if (value instanceof Map) {
            md.update(value.toString().getBytes(StandardCharsets.UTF_8));
        } else if (value instanceof Set) {
            for (Object o : (Set<?>) value) {
                updateDigest(md, o);
            }
        }
    }
}
