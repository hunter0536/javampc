package com.example.mpc.common.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class JsonUtils {

    private JsonUtils() {
    }

    public static String encodeAsJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof java.util.Map<?, ?> map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            for (String k : keys) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(escapeJson(k)).append("\":");
                sb.append(encodeAsJson(map.get(k)));
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
                sb.append(encodeAsJson(o));
            }
            sb.append("]");
            return sb.toString();
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof String s) {
            return "\"" + escapeJson(s) + "\"";
        }
        return "\"" + escapeJson(String.valueOf(value)) + "\"";
    }

    public static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}
