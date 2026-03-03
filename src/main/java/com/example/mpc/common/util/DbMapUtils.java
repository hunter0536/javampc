package com.example.mpc.common.util;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.dto.AuxInfo;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DbMapUtils {

    private DbMapUtils() {
    }

    public static Map<String, String> buildAuxParams(AuxInfo info) {
        if (info == null) {
            return null;
        }
        Map<String, String> out = new HashMap<>();
        out.put("paillierN", info.getPaillierN());
        out.put("paillierG", info.getPaillierG());
        out.put("paillierBitLength", info.getPaillierBitLength() == null ? null : String.valueOf(info.getPaillierBitLength()));
        out.put("pedersenHatN", info.getPedersenHatN());
        out.put("pedersenS", info.getPedersenS());
        out.put("pedersenT", info.getPedersenT());
        return out;
    }

    public static Map<Integer, ECPoint> parsePublicShares(String json) {
        Map<String, String> raw = parseStringMap(json);
        Map<Integer, ECPoint> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            int key = Integer.parseInt(e.getKey());
            out.put(key, Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(e.getValue())));
        }
        return out;
    }

    public static Map<Integer, BigInteger> parseIndexMap(String json) {
        Map<String, String> raw = parseStringMap(json);
        Map<Integer, BigInteger> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            int key = Integer.parseInt(e.getKey());
            out.put(key, new BigInteger(e.getValue(), 10));
        }
        return out;
    }

    public static byte[] decodeChainCode(String hex) {
        return HexUtils.hexToBytes(hex);
    }

    private static Map<String, String> parseStringMap(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null) {
            return out;
        }
        String s = json.trim();
        if (s.startsWith("{")) {
            s = s.substring(1);
        }
        if (s.endsWith("}")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isBlank()) {
            return out;
        }
        List<String> parts = splitTopLevel(s);
        for (String part : parts) {
            int idx = part.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String k = stripQuotes(part.substring(0, idx).trim());
            String v = stripQuotes(part.substring(idx + 1).trim());
            out.put(k, v);
        }
        return out;
    }

    private static List<String> splitTopLevel(String s) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                inQuotes = !inQuotes;
            }
            if (c == ',' && !inQuotes) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (!cur.isEmpty()) {
            parts.add(cur.toString());
        }
        return parts;
    }

    private static String stripQuotes(String s) {
        String out = s;
        if (out.startsWith("\"") && out.endsWith("\"") && out.length() >= 2) {
            out = out.substring(1, out.length() - 1);
        }
        return out.replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
