package com.example.mpc.cggmp.util;

import java.security.MessageDigest;

public final class ZkHash {
    private ZkHash() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute sha256", e);
        }
    }
}
