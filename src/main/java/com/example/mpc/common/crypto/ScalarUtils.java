package com.example.mpc.common.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class ScalarUtils {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private ScalarUtils() {
    }

    public static BigInteger mod(BigInteger value, BigInteger modulus) {
        return value.mod(modulus);
    }

    public static BigInteger randomScalar(BigInteger modulus) {
        if (modulus == null || modulus.signum() <= 0) {
            throw new IllegalArgumentException("Modulus must be positive");
        }
        BigInteger upper = modulus.subtract(BigInteger.ONE);
        BigInteger k;
        do {
            k = new BigInteger(modulus.bitLength(), SECURE_RANDOM).mod(upper).add(BigInteger.ONE);
        } while (k.signum() == 0 || k.compareTo(modulus) >= 0);
        return k;
    }
}
