package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.util.BigIntegerUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

public record ZKSetup(BigInteger hatN, BigInteger h1, BigInteger h2) {
    public static ZKSetup generate(int bitLength) {
        SecureRandom rnd = new SecureRandom();
        BigInteger p = generateSafePrime(bitLength / 2, rnd);
        BigInteger q = generateSafePrime(bitLength / 2, rnd);
        while (p.equals(q)) {
            q = generateSafePrime(bitLength / 2, rnd);
        }
        BigInteger hatN = p.multiply(q);

        BigInteger h1 = sampleUnit(hatN, rnd);
        BigInteger h2;
        do {
            h2 = sampleUnit(hatN, rnd);
        } while (h2.equals(h1));

        h1 = h1.modPow(BigInteger.TWO, hatN);
        h2 = h2.modPow(BigInteger.TWO, hatN);

        return new ZKSetup(hatN, h1, h2);
    }

    private static BigInteger sampleUnit(BigInteger hatN, SecureRandom rnd) {
        BigInteger u;
        do {
            u = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        } while (u.signum() == 0 || u.equals(BigInteger.ONE) || u.equals(hatN.subtract(BigInteger.ONE)) || !u.gcd(hatN).equals(BigInteger.ONE));
        return u;
    }

    private static BigInteger generateSafePrime(int bits, SecureRandom rnd) {
        BigInteger p;
        while (true) {
            BigInteger q = BigInteger.probablePrime(bits - 1, rnd);
            p = q.shiftLeft(1).add(BigInteger.ONE);
            if (p.isProbablePrime(128)) {
                return p;
            }
        }
    }
}
