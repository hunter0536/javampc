package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.util.stream.IntStream;

public interface BigIntegerBackend {
    BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod);

    BigInteger modInverse(BigInteger val, BigInteger mod);

    BigInteger multiply(BigInteger a, BigInteger b);

    BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);

    BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod);

    boolean isNative();
}
