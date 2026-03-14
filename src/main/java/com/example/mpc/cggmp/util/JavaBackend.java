package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;
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
    public BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return a.multiply(b).mod(mod);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exp, mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have the same length");
        }
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        return IntStream.range(0, vals.length)
                .parallel()
                .mapToObj(i -> vals[i].mod(mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        BigInteger t = b.subtract(a).mod(q);
        BigInteger ip = p.modInverse(q);
        BigInteger k = t.multiply(ip).mod(q);
        BigInteger x = a.add(k.multiply(p));
        return (x.signum() < 0 || x.compareTo(n) >= 0) ? x.mod(n) : x;
    }

    @Override
    public int jacobi(BigInteger a, BigInteger n) {
        if (n.signum() <= 0 || !n.testBit(0)) {
            throw new IllegalArgumentException("n must be positive and odd");
        }
        a = a.mod(n);
        int result = 1;
        while (a.signum() != 0) {
            while (!a.testBit(0)) {
                a = a.shiftRight(1);
                BigInteger nMod8 = n.and(BigInteger.valueOf(7));
                if (nMod8.equals(BigInteger.valueOf(3)) || nMod8.equals(BigInteger.valueOf(5))) {
                    result = -result;
                }
            }
            BigInteger temp = a;
            a = n;
            n = temp;
            if (a.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3)) && n.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3))) {
                result = -result;
            }
            a = a.mod(n);
        }
        return n.equals(BigInteger.ONE) ? result : 0;
    }

    @Override
    public int[] batchJacobi(BigInteger[] as, BigInteger n) {
        int[] results = new int[as.length];
        for (int i = 0; i < as.length; i++) {
            results[i] = jacobi(as[i], n);
        }
        return results;
    }

    @Override
    public BigInteger probablePrime(int bitLength, SecureRandom random) {
        return BigInteger.probablePrime(bitLength, random);
    }

    @Override
    public boolean isNative() {
        return false;
    }
}
