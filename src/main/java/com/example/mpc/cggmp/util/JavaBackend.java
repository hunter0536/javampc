package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.util.stream.IntStream;

public final class JavaBackend implements BigIntegerBackend {
    private static final JavaBackend INSTANCE = new JavaBackend();

    private JavaBackend() {
    }

    public static JavaBackend getInstance() {
        return INSTANCE;
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return base.modPow(exp, mod);
    }

    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        return val.modInverse(mod);
    }

    @Override
    public BigInteger multiply(BigInteger a, BigInteger b) {
        return a.multiply(b);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exp, mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public boolean isNative() {
        return false;
    }
}
