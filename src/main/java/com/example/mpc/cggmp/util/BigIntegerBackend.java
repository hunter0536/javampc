package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public interface BigIntegerBackend {
    BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod);
    BigInteger modInverse(BigInteger val, BigInteger mod);
    BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod);
    BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);
    BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod);
    BigInteger[] batchMod(BigInteger[] vals, BigInteger mod);
    BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n);
    int jacobi(BigInteger a, BigInteger n);
    int[] batchJacobi(BigInteger[] as, BigInteger n);
    BigInteger probablePrime(int bitLength, SecureRandom random);
    boolean isNative();
}
