package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class GmpBackend implements BigIntegerBackend {
    private static final GmpBackend INSTANCE = new GmpBackend();

    private GmpBackend() {
    }

    public static GmpBackend getInstance() {
        return INSTANCE;
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.modPow(base, exp, mod);
    }

    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        return NativeBigInteger.modInverse(val, mod);
    }

    @Override
    public BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return NativeBigInteger.modMul(a, b, mod);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.batchModPow(bases, exp, mod);
    }

    @Override
    public BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        return NativeBigInteger.batchMod(vals, mod);
    }

    @Override
    public BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        return NativeBigInteger.crt(a, p, b, q, n);
    }

    @Override
    public int jacobi(BigInteger a, BigInteger n) {
        return NativeBigInteger.jacobi(a, n);
    }

    @Override
    public int[] batchJacobi(BigInteger[] as, BigInteger n) {
        return NativeBigInteger.batchJacobi(as, n);
    }

    @Override
    public BigInteger probablePrime(int bitLength, SecureRandom random) {
        return NativeBigInteger.probablePrime(bitLength, random);
    }

    @Override
    public boolean isNative() {
        return NativeBigInteger.isNativeAvailable();
    }
}
