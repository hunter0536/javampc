package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class BigIntegerUtils {
    private static final Logger logger = LoggerFactory.getLogger(BigIntegerUtils.class);
    
    private static final BigIntegerBackend BACKEND;
    
    static {
        boolean gmpEnabled = Boolean.parseBoolean(System.getProperty("cggmp.gmp.enabled", "true"));
        boolean nativeAvailable = false;
        
        try {
            nativeAvailable = NativeBigInteger.isNativeAvailable();
        } catch (Throwable e) {
            logger.warn("NativeBigInteger not available: {}", e.getMessage());
        }
        
        boolean useGmp = gmpEnabled && nativeAvailable;
        BACKEND = useGmp ? GmpBackend.getInstance() : JavaBackend.getInstance();
        
        logger.info("BigIntegerUtils initialized: gmpEnabled={}, nativeAvailable={}, useGmp={}", 
                    gmpEnabled, nativeAvailable, useGmp);
    }
    
    private BigIntegerUtils() {
    }

    public static BigIntegerBackend getBackend() {
        return BACKEND;
    }
    
    public static boolean isNativeAvailable() {
        return BACKEND.isNative();
    }

    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return BACKEND.modPow(base, exp, mod);
    }

    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        return BACKEND.modInverse(val, mod);
    }

    public static BigInteger multiply(BigInteger a, BigInteger b) {
        return BACKEND.multiply(a, b);
    }

    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return BACKEND.batchModPow(bases, exp, mod);
    }

    public static BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        return BACKEND.batchModPowDifferentExp(bases, exps, mod);
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
            return BACKEND.modPow(base, exp, mod);
        }
        BigInteger inv = BACKEND.modInverse(base, mod);
        return BACKEND.modPow(inv, exp.negate(), mod);
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
