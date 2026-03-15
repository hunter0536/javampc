package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public interface BigIntegerBackend {
    BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod);

    BigInteger modInverse(BigInteger val, BigInteger mod);

    BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod);

    BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);

    BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod);

    BigInteger[][] batchModPowAll(
            BigInteger[] bases1, BigInteger[] bases2, BigInteger[] bases3,
            BigInteger[] bases4, BigInteger[] bases5,
            BigInteger[] exps1, BigInteger[] exps2, BigInteger[] exps3,
            BigInteger[] exps4, BigInteger[] exps5,
            BigInteger mod1, BigInteger mod2, BigInteger mod3,
            BigInteger mod4, BigInteger mod5);

    BigInteger[] batchMod(BigInteger[] vals, BigInteger mod);

    BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n);

    int jacobi(BigInteger a, BigInteger n);

    int[] batchJacobi(BigInteger[] as, BigInteger n);

    BigInteger probablePrime(int bitLength, SecureRandom random);

    boolean isNative();
}
