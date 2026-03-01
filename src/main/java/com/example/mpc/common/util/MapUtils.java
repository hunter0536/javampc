package com.example.mpc.common.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class MapUtils {
    private MapUtils() {
    }

    public static List<String> toStringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return null;
        }
        List<String> out = new ArrayList<>(list.size());
        for (Object item : list) {
            out.add(item == null ? null : item.toString());
        }
        return out;
    }

    public static Map<String, Object> asStringObjectMap(Object data) {
        if (!(data instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            if (key == null) {
                continue;
            }
            out.put(key.toString(), entry.getValue());
        }
        return out;
    }

    public static Map<String, String> asStringStringMap(Object data) {
        if (!(data instanceof Map<?, ?> map)) {
            return null;
        }
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            if (key == null) {
                continue;
            }
            Object value = entry.getValue();
            out.put(key.toString(), value == null ? null : value.toString());
        }
        return out;
    }
}
