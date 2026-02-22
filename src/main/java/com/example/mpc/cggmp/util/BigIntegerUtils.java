package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BigIntegerUtils {
    private BigIntegerUtils() {
    }

    public static BigInteger randomZnStar(BigInteger n, SecureRandom rnd) {
        BigInteger x;
        do {
            x = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (x.signum() == 0 || !x.gcd(n).equals(BigInteger.ONE));
        return x;
    }

    public static BigInteger powSigned(BigInteger base, BigInteger exp, BigInteger mod) {
        if (exp.signum() >= 0) {
            return base.modPow(exp, mod);
        }
        BigInteger inv = base.modInverse(mod);
        return inv.modPow(exp.negate(), mod);
    }

    public static int jacobi(BigInteger a, BigInteger n) {
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

    public static byte[] toUnsignedBytes(BigInteger x, int len) {
        byte[] raw = x.toByteArray();
        if (raw.length == len) {
            return raw;
        }
        byte[] out = new byte[len];
        if (raw.length > len) {
            System.arraycopy(raw, raw.length - len, out, 0, len);
        } else {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        return out;
    }
}
