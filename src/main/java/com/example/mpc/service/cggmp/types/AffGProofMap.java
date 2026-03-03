package com.example.mpc.service.cggmp.types;

import com.example.mpc.cggmp.proof.PiAffGProof;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public record AffGProofMap(Map<Integer, PiAffGProof> values) {

    public static AffGProofMap empty() {
        return new AffGProofMap(Map.of());
    }

    public static AffGProofMap of(Map<Integer, PiAffGProof> values) {
        return new AffGProofMap(new HashMap<>(values));
    }

    public AffGProofMap put(int key, PiAffGProof value) {
        Map<Integer, PiAffGProof> newMap = new HashMap<>(values);
        newMap.put(key, value);
        return new AffGProofMap(newMap);
    }

    public AffGProofMap putAll(Map<Integer, PiAffGProof> other) {
        Map<Integer, PiAffGProof> newMap = new HashMap<>(values);
        newMap.putAll(other);
        return new AffGProofMap(newMap);
    }

    public Optional<PiAffGProof> get(int key) {
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

    public Map<Integer, PiAffGProof> toMap() {
        return new HashMap<>(values);
    }
}
