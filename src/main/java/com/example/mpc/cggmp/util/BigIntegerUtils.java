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

    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return BACKEND.modPow(base, exp, mod);
    }

    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        return BACKEND.modInverse(val, mod);
    }

    public static BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return BACKEND.modMul(a, b, mod);
    }

    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return BACKEND.batchModPow(bases, exp, mod);
    }

    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        return BACKEND.batchModPow(bases, exps, mod);
    }

    public static BigInteger randomZnStar(BigInteger n, SecureRandom rnd) {
        if (n.compareTo(BigInteger.valueOf(3)) <= 0) {
            throw new IllegalArgumentException("n must be greater than 3");
        }
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);
        BigInteger x;
        do {
            x = new BigInteger(nMinusOne.bitLength(), rnd).mod(nMinusOne).add(BigInteger.ONE);
        } while (!x.gcd(n).equals(BigInteger.ONE));
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
        return BACKEND.jacobi(a, n);
    }

    public static int[] batchJacobi(BigInteger[] as, BigInteger n) {
        return BACKEND.batchJacobi(as, n);
    }

    public static BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        return BACKEND.batchMod(vals, mod);
    }

    public static BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        return BACKEND.crt(a, p, b, q, n);
    }

    public static BigInteger probablePrime(int bitLength, SecureRandom random) {
        return BACKEND.probablePrime(bitLength, random);
    }

    public static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }

    public static BigInteger positiveModInverse(BigInteger a, BigInteger mod) {
        BigInteger x = BACKEND.modInverse(a, mod);
        return x.signum() < 0 ? x.add(mod) : x;
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public static BigInteger generateSafePrime(int bits, SecureRandom rnd) {
        final int batchSize = Runtime.getRuntime().availableProcessors() * 2;
        
        while (true) {
            java.util.List<BigInteger> candidates = java.util.stream.IntStream.range(0, batchSize)
                .parallel()
                .mapToObj(i -> {
                    BigInteger q = probablePrime(bits - 1, rnd);
                    return q.shiftLeft(1).add(BigInteger.ONE);
                })
                .toList();
            
            java.util.Optional<BigInteger> found = candidates.parallelStream()
                .filter(p -> p.isProbablePrime(128))
                .findAny();
            
            if (found.isPresent()) {
                return found.get();
            }
        }
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
