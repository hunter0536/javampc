package com.example.mpc.service.cggmp.types;

import org.bouncycastle.math.ec.ECPoint;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public record ECPointIndexMap(Map<Integer, ECPoint> values) {

    public static ECPointIndexMap empty() {
        return new ECPointIndexMap(Map.of());
    }

    public static ECPointIndexMap of(Map<Integer, ECPoint> values) {
        return new ECPointIndexMap(new HashMap<>(values));
    }

    public ECPointIndexMap put(int key, ECPoint value) {
        Map<Integer, ECPoint> newMap = new HashMap<>(values);
        newMap.put(key, value);
        return new ECPointIndexMap(newMap);
    }

    public ECPointIndexMap putAll(Map<Integer, ECPoint> other) {
        Map<Integer, ECPoint> newMap = new HashMap<>(values);
        newMap.putAll(other);
        return new ECPointIndexMap(newMap);
    }

    public Optional<ECPoint> get(int key) {
        return Optional.ofNullable(values.get(key));
    }

    public boolean containsKey(int key) {
        return values.containsKey(key);
    }

    public int size() {
        return values.size();
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }

    public Map<Integer, ECPoint> toMap() {
        return new HashMap<>(values);
    }
}
