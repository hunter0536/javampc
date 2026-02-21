package com.example.mpc.common.crypto;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ScalarUtilsTest {

    @Test
    public void testRandomScalarInRange() {
        BigInteger modulus = BigInteger.valueOf(17);
        for (int i = 0; i < 100; i++) {
            BigInteger k = ScalarUtils.randomScalar(modulus);
            assertTrue(k.compareTo(BigInteger.ONE) >= 0);
            assertTrue(k.compareTo(modulus) < 0);
        }
    }

    @Test
    public void testModHelper() {
        BigInteger modulus = BigInteger.valueOf(17);
        BigInteger value = BigInteger.valueOf(34);
        assertEquals(BigInteger.ZERO, ScalarUtils.mod(value, modulus));
    }
}
