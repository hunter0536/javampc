package com.example.mpc.service.cggmp.types;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * BigInteger的索引Map，用于存储按节点ID索引的大整数
 */
public record BigIntIndexMap(Map<Integer, BigInteger> values) {

    /**
     * 创建空的BigInt索引Map
     */
    public static BigIntIndexMap empty() {
        return new BigIntIndexMap(Map.of());
    }

    public static BigIntIndexMap of(Map<Integer, BigInteger> values) {
        return new BigIntIndexMap(new HashMap<>(values));
    }

    public BigIntIndexMap put(int key, BigInteger value) {
        Map<Integer, BigInteger> newMap = new HashMap<>(values);
        newMap.put(key, value);
        return new BigIntIndexMap(newMap);
    }

    public BigIntIndexMap putAll(Map<Integer, BigInteger> other) {
        Map<Integer, BigInteger> newMap = new HashMap<>(values);
        newMap.putAll(other);
        return new BigIntIndexMap(newMap);
    }

    public Optional<BigInteger> get(int key) {
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

    public Map<Integer, BigInteger> toMap() {
        return new HashMap<>(values);
    }
}
