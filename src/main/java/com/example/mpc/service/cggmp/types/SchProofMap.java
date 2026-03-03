package com.example.mpc.service.cggmp.types;

import com.example.mpc.cggmp.proof.PiSchProof;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Schnorr证明的索引Map，用于存储按节点ID索引的PiSchProof
 */
public record SchProofMap(Map<Integer, PiSchProof> values) {

    /**
     * 创建空的Schnorr证明Map
     */
    public static SchProofMap empty() {
        return new SchProofMap(Map.of());
    }

    public static SchProofMap of(Map<Integer, PiSchProof> values) {
        return new SchProofMap(new HashMap<>(values));
    }

    public SchProofMap put(int key, PiSchProof value) {
        Map<Integer, PiSchProof> newMap = new HashMap<>(values);
        newMap.put(key, value);
        return new SchProofMap(newMap);
    }

    public SchProofMap putAll(Map<Integer, PiSchProof> other) {
        Map<Integer, PiSchProof> newMap = new HashMap<>(values);
        newMap.putAll(other);
        return new SchProofMap(newMap);
    }

    public Optional<PiSchProof> get(int key) {
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

    public Map<Integer, PiSchProof> toMap() {
        return new HashMap<>(values);
    }
}
