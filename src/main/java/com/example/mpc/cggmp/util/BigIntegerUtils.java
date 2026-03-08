package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BigIntegerUtils {
    private static final boolean USE_NATIVE = NativeBigInteger.isNativeAvailable();
    
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
        if (USE_NATIVE) {
            if (exp.signum() >= 0) {
                return NativeBigInteger.modPow(base, exp, mod);
            }
            BigInteger inv = NativeBigInteger.modInverse(base, mod);
            return NativeBigInteger.modPow(inv, exp.negate(), mod);
        }
        if (exp.signum() >= 0) {
            return base.modPow(exp, mod);
        }
        BigInteger inv = base.modInverse(mod);
        return inv.modPow(exp.negate(), mod);
    }
    
    public static BigInteger powSigned(NativeBigInteger.NativeModPowContext ctx, BigInteger base, BigInteger exp) {
        if (ctx != null && NativeBigInteger.isNativeAvailable()) {
            return ctx.modPow(base, exp);
        }
        if (exp.signum() >= 0) {
            return base.modPow(exp, BigInteger.ONE);
        }
        BigInteger inv = base.modInverse(BigInteger.ONE);
        return inv.modPow(exp.negate(), BigInteger.ONE);
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
