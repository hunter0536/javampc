package com.example.mpc.common.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class HexUtils {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    private static final int[] HEX_VALUE = new int[128];

    static {
        for (int i = 0; i < HEX_VALUE.length; i++) {
            HEX_VALUE[i] = -1;
        }
        for (int i = '0'; i <= '9'; i++) {
            HEX_VALUE[i] = i - '0';
        }
        for (int i = 'a'; i <= 'f'; i++) {
            HEX_VALUE[i] = i - 'a' + 10;
        }
        for (int i = 'A'; i <= 'F'; i++) {
            HEX_VALUE[i] = i - 'A' + 10;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int high = HEX_VALUE[hex.charAt(i)];
            int low = HEX_VALUE[hex.charAt(i + 1)];
            data[i / 2] = (byte) ((high << 4) + low);
        }
        return data;
    }

    public static String toHex(BigInteger value) {
        return value.toString(16);
    }

    public static BigInteger fromHex(String hex) {
        return new BigInteger(hex, 16);
    }

    public static BigInteger fromHex(Object hex) {
        return new BigInteger((String) hex, 16);
    }

    public static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static byte[] fromBase64(Object base64) {
        return Base64.getDecoder().decode((String) base64);
    }

    public static String sha256Hex(String input) {
        try {
            return bytesToHex(MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return "error";
        }
    }
}
