package com.example.mpc.cggmp.presign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

public record Presignature(
        String presignId,
        ECPoint Gamma,
        BigInteger kTilde,
        BigInteger chiTilde,
        Map<Integer, ECPoint> deltaTilde,
        Map<Integer, ECPoint> sTilde
) {
    public Presignature(String presignId, ECPoint Gamma, BigInteger kTilde, BigInteger chiTilde) {
        this(presignId, Gamma, kTilde, chiTilde, null, null);
    }
}
