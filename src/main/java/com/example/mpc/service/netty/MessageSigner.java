package com.example.mpc.service.netty;

import com.example.mpc.common.util.HexUtils;
import com.example.mpc.service.NodeService;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class MessageSigner {
    private static final String HMAC_ALG = "HmacSHA256";

    private MessageSigner() {
    }

    public static String sign(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALG));
            byte[] out = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexUtils.bytesToHex(out);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign message", e);
        }
    }

    public static boolean verify(String payload, String secret, String signature) {
        if (payload == null || secret == null || signature == null) {
            return false;
        }
        String expected = sign(payload, secret);
        return constantTimeEquals(expected, signature);
    }

    public static String canonicalPayload(NodeService.Message message) {
        String data = canonicalize(message.data());
        return message.senderId() + ":" + message.type() + ":" + message.messageId() + ":" + message.requireAck() + ":" + message.ackForId() + ":" + message.rbc() + ":" + message.rbcHash() + ":" + data;
    }

    private static String canonicalize(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(",");
                first = false;
                sb.append(k).append("=").append(canonicalize(map.get(k)));
            }
            sb.append("}");
            return sb.toString();
        }
        if (value instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object o : it) {
                if (!first) sb.append(",");
                first = false;
                sb.append(canonicalize(o));
            }
            sb.append("]");
            return sb.toString();
        }
        if (value.getClass().isArray()) {
            int len = java.lang.reflect.Array.getLength(value);
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for (int i = 0; i < len; i++) {
                if (i > 0) sb.append(",");
                sb.append(canonicalize(java.lang.reflect.Array.get(value, i)));
            }
            sb.append("]");
            return sb.toString();
        }
        return String.valueOf(value);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
