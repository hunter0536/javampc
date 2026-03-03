package com.example.mpc.service.cggmp;

import com.example.mpc.common.util.HexUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CGGMP哈希工具类
 * 提供协议专用的哈希计算方法，如标签哈希、消息哈希等
 */
public final class CggmpHashUtils {
    private CggmpHashUtils() {
    }

    /**
     * 计算带标签的哈希值（十六进制输出）
     */
    public static String computeTaggedHashHex(String tag, Object... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            updateDigestCanonical(md, tag);
            for (Object part : parts) {
                updateDigestCanonical(md, part);
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute tagged hash", e);
        }
    }

    /**
     * 计算CGGMP协议专用的带标签哈希值
     */
    public static String computeCggmpTaggedHashHex(String tag, Object... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(("CGGMP:" + tag).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            for (Object part : parts) {
                updateDigestPlain(md, part);
            }
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute tagged hash", e);
        }
    }

    private static void updateDigestCanonical(MessageDigest md, Object part) {
        if (part == null) {
            md.update((byte) 0);
            return;
        }
        if (part instanceof String s) {
            byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof byte[] bytes) {
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof Number n) {
            byte[] bytes = n.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            updateDigestWithLength(md, bytes.length);
            md.update(bytes);
            return;
        }
        if (part instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            updateDigestWithLength(md, keys.size());
            for (String k : keys) {
                updateDigestCanonical(md, k);
                updateDigestCanonical(md, map.get(k));
            }
            return;
        }
        if (part instanceof Iterable<?> it) {
            List<Object> items = new ArrayList<>();
            for (Object o : it) {
                items.add(o);
            }
            updateDigestWithLength(md, items.size());
            for (Object o : items) {
                updateDigestCanonical(md, o);
            }
            return;
        }
        updateDigestCanonical(md, String.valueOf(part));
    }

    private static void updateDigestPlain(MessageDigest md, Object value) {
        if (value == null) {
            md.update((byte) 0);
        } else if (value instanceof byte[] bytes) {
            md.update(bytes);
        } else if (value instanceof String s) {
            md.update(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } else if (value instanceof BigInteger bi) {
            md.update(bi.toByteArray());
        } else if (value instanceof ECPoint point) {
            md.update(point.getEncoded(true));
        } else if (value instanceof Number) {
            md.update(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } else if (value instanceof Map) {
            md.update(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } else if (value instanceof Set) {
            for (Object o : (Set<?>) value) {
                updateDigestPlain(md, o);
            }
        }
    }

    private static void updateDigestWithLength(MessageDigest md, int length) {
        md.update((byte) ((length >>> 24) & 0xFF));
        md.update((byte) ((length >>> 16) & 0xFF));
        md.update((byte) ((length >>> 8) & 0xFF));
        md.update((byte) (length & 0xFF));
    }
}
