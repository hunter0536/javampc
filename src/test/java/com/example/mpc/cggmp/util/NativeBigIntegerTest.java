package com.example.mpc.cggmp.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class NativeBigIntegerTest {

    private static void assumeNativeAvailable() {
        Assumptions.assumeTrue(NativeBigInteger.isNativeAvailable(), "Native GMP library not available");
    }

    private static BigInteger javaPowSigned(BigInteger base, BigInteger exp, BigInteger mod) {
        if (exp.signum() >= 0) {
            return base.modPow(exp, mod);
        }
        BigInteger inv = base.modInverse(mod);
        return inv.modPow(exp.negate(), mod);
    }

    @Test
    public void testNativeModPowSignedMatchesJava() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = new BigInteger("-123456789");
        BigInteger exp = new BigInteger("-12345");

        BigInteger expected = BigIntegerUtils.powSigned(base, exp, mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow signed result mismatch");
    }

    @Test
    public void testNativeModPowNegativeExponentNonInvertibleThrows() {
        assumeNativeAvailable();
        BigInteger mod = BigInteger.valueOf(21);
        BigInteger base = BigInteger.valueOf(3);
        BigInteger exp = BigInteger.valueOf(-1);

        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeModPow(base, exp, mod));
    }

    @Test
    public void testNativeModInverseNegativeValueMatchesJava() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger val = new BigInteger("-987654321");
        if (!val.gcd(mod).equals(BigInteger.ONE)) {
            val = val.add(mod);
        }

        BigInteger expected = val.modInverse(mod);
        BigInteger actual = NativeBigInteger.nativeModInverse(val, mod);
        assertEquals(expected, actual, "nativeModInverse result mismatch");
    }

    @Test
    public void testNativeModPowNegativeBasePositiveExpMatchesJava() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = new BigInteger("-123456789");
        BigInteger exp = BigInteger.valueOf(12345);

        BigInteger expected = base.modPow(exp, mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow negative base result mismatch");
    }

    @Test
    public void testNativeModPowZeroExponentIsOne() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = new BigInteger("-987654321");
        BigInteger exp = BigInteger.ZERO;

        BigInteger expected = BigInteger.ONE.mod(mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow zero exponent result mismatch");
    }

    @Test
    public void testNativeModPowModulusNotPositiveThrows() {
        assumeNativeAvailable();
        BigInteger base = BigInteger.valueOf(2);
        BigInteger exp = BigInteger.TEN;
        BigInteger mod = BigInteger.ZERO;
        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeModPow(base, exp, mod));
    }

    @Test
    public void testNativeModInverseModulusNotPositiveThrows() {
        assumeNativeAvailable();
        BigInteger val = BigInteger.valueOf(3);
        BigInteger mod = BigInteger.ZERO;
        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeModInverse(val, mod));
    }

    @Test
    public void testNativeModPowNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger base = BigInteger.valueOf(2);
        BigInteger exp = BigInteger.TEN;
        BigInteger mod = BigInteger.valueOf(13);

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeModPow(null, exp, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeModPow(base, null, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeModPow(base, exp, null));
    }

    @Test
    public void testNativeModInverseNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger val = BigInteger.valueOf(3);
        BigInteger mod = BigInteger.valueOf(13);

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeModInverse(null, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeModInverse(val, null));
    }

    @Test
    public void testNativeBatchModPowNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger[] bases = new BigInteger[] { BigInteger.valueOf(2) };
        BigInteger exp = BigInteger.TWO;
        BigInteger mod = BigInteger.valueOf(13);

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPow(null, exp, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPow(bases, null, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPow(bases, exp, null));
    }

    @Test
    public void testNativeBatchModPowDifferentExpNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger[] bases = new BigInteger[] { BigInteger.valueOf(2) };
        BigInteger[] exps = new BigInteger[] { BigInteger.TWO };
        BigInteger mod = BigInteger.valueOf(13);

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPowDifferentExp(null, exps, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPowDifferentExp(bases, null, mod));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeBatchModPowDifferentExp(bases, exps, null));
    }

    @Test
    public void testNativeAffGProofTupleNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N1 = BigInteger.valueOf(103);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        BigInteger C = BigInteger.valueOf(2);
        BigInteger[] arr = new BigInteger[] { BigInteger.ONE };

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                null, onePlusN0, N0sq, onePlusN1, N1sq, arr, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, null, N0sq, onePlusN1, N1sq, arr, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, null, onePlusN1, N1sq, arr, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, null, N1sq, arr, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, null, arr, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq, null, arr, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq, arr, null, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq, arr, arr, null, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq, arr, arr, arr, null, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq, arr, arr, arr, arr, null));
    }

    @Test
    public void testNativeDecProofTupleNullArgsThrowNpe() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger K = BigInteger.valueOf(2);
        BigInteger[] arr = new BigInteger[] { BigInteger.ONE };

        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                null, N0, N0sq, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                K, null, N0sq, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                K, N0, null, arr, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                K, N0, N0sq, null, arr, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                K, N0, N0sq, arr, null, arr));
        assertThrows(NullPointerException.class, () -> NativeBigInteger.nativeDecProofTuple(
                K, N0, N0sq, arr, arr, null));
    }

    @Test
    public void testNativeBatchModPowEmptyArrayReturnsEmpty() {
        assumeNativeAvailable();
        BigInteger[] bases = new BigInteger[0];
        BigInteger exp = BigInteger.TWO;
        BigInteger mod = new BigInteger("1000003");
        BigInteger[] results = NativeBigInteger.nativeBatchModPow(bases, exp, mod);
        assertEquals(0, results.length, "nativeBatchModPow empty result length");
    }

    @Test
    public void testNativeBatchModPowDifferentExpEmptyArrayReturnsEmpty() {
        assumeNativeAvailable();
        BigInteger[] bases = new BigInteger[0];
        BigInteger[] exps = new BigInteger[0];
        BigInteger mod = new BigInteger("1000003");
        BigInteger[] results = NativeBigInteger.nativeBatchModPowDifferentExp(bases, exps, mod);
        assertEquals(0, results.length, "nativeBatchModPowDifferentExp empty result length");
    }

    @Test
    public void testNativeAffGProofTupleEmptyReturnsEmpty() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N1 = BigInteger.valueOf(103);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        BigInteger C = BigInteger.valueOf(2);
        BigInteger[] empty = new BigInteger[0];
        BigInteger[] results = NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq,
                empty, empty, empty, empty, empty);
        assertEquals(0, results.length, "nativeAffGProofTuple empty result length");
    }

    @Test
    public void testNativeDecProofTupleEmptyReturnsEmpty() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger K = BigInteger.valueOf(2);
        BigInteger[] empty = new BigInteger[0];
        BigInteger[] results = NativeBigInteger.nativeDecProofTuple(K, N0, N0sq, empty, empty, empty);
        assertEquals(0, results.length, "nativeDecProofTuple empty result length");
    }

    @Test
    public void testNativeBatchModPowDifferentExpLargeDoesNotOverflowLocalRefs() {
        assumeNativeAvailable();
        int n = 2000;
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger[] bases = new BigInteger[n];
        BigInteger[] exps = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            bases[i] = BigInteger.valueOf(i + 2);
            exps[i] = BigInteger.valueOf((i % 17) - 8); // includes negatives
        }
        BigInteger[] results = NativeBigInteger.nativeBatchModPowDifferentExp(bases, exps, mod);
        for (int i = 0; i < n; i++) {
            BigInteger expected = javaPowSigned(bases[i], exps[i], mod);
            assertEquals(expected, results[i], "nativeBatchModPowDifferentExp mismatch at index " + i);
        }
    }

    @Test
    public void testNativeModPowModulusOneReturnsZero() {
        assumeNativeAvailable();
        BigInteger mod = BigInteger.ONE;
        BigInteger base = BigInteger.valueOf(12345);
        BigInteger exp = BigInteger.valueOf(6789);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(BigInteger.ZERO, actual, "nativeModPow mod=1 should return 0");
    }

    @Test
    public void testNativeModPowBaseZero() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = BigInteger.ZERO;
        BigInteger exp = BigInteger.valueOf(123);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(BigInteger.ZERO, actual, "nativeModPow 0^exp should be 0");
    }

    @Test
    public void testNativeModPowExponentZero() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = new BigInteger("-987654321");
        BigInteger exp = BigInteger.ZERO;
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(BigInteger.ONE.mod(mod), actual, "nativeModPow base^0 should be 1 mod m");
    }

    @Test
    public void testNativeModPowNegativeExponentNonCoprimeThrows() {
        assumeNativeAvailable();
        BigInteger mod = BigInteger.valueOf(15);
        BigInteger base = BigInteger.valueOf(5);
        BigInteger exp = BigInteger.valueOf(-3);
        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeModPow(base, exp, mod));
    }

    @Test
    public void testNativeModPowExtremeNegativeBaseMatchesJava() {
        assumeNativeAvailable();
        BigInteger mod = new BigInteger("1000003"); // prime
        BigInteger base = BigInteger.ONE.shiftLeft(255).negate();
        BigInteger exp = BigInteger.valueOf(3);
        BigInteger expected = base.modPow(exp, mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow extreme negative base mismatch");
    }

    @Test
    public void testNativeModPow4096BitRandomMatchesJava() {
        assumeNativeAvailable();
        java.util.Random rnd = new java.util.Random(1234);
        BigInteger base = new BigInteger(4090, rnd);
        BigInteger exp = new BigInteger(256, rnd);
        BigInteger mod = new BigInteger(4090, rnd).nextProbablePrime();
        BigInteger expected = base.modPow(exp, mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow 4096-bit mismatch");
    }

    @Test
    public void testNativeModPow4096BitNegativeExponentMatchesJava() {
        assumeNativeAvailable();
        java.util.Random rnd = new java.util.Random(5678);
        BigInteger mod = new BigInteger(4090, rnd).nextProbablePrime();
        BigInteger base = new BigInteger(4090, rnd);
        if (!base.gcd(mod).equals(BigInteger.ONE)) {
            base = base.add(mod);
        }
        BigInteger exp = new BigInteger(256, rnd).negate().subtract(BigInteger.ONE);
        BigInteger expected = javaPowSigned(base, exp, mod);
        BigInteger actual = NativeBigInteger.nativeModPow(base, exp, mod);
        assertEquals(expected, actual, "nativeModPow 4096-bit negative exp mismatch");
    }

    @Test
    public void testNativeAffGProofTupleSignedMatchesJava() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N1 = BigInteger.valueOf(103);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        BigInteger C = BigInteger.valueOf(2);

        BigInteger[] alphas = new BigInteger[] {
                BigInteger.valueOf(5),
                BigInteger.valueOf(-7),
                BigInteger.valueOf(11)
        };
        BigInteger[] betasForN0 = new BigInteger[] {
                BigInteger.valueOf(3),
                BigInteger.valueOf(-2),
                BigInteger.ZERO
        };
        BigInteger[] betasForN1 = new BigInteger[] {
                BigInteger.valueOf(-1),
                BigInteger.valueOf(4),
                BigInteger.valueOf(-5)
        };
        BigInteger[] rs = new BigInteger[] {
                BigInteger.valueOf(3),
                BigInteger.valueOf(5),
                BigInteger.valueOf(7)
        };
        BigInteger[] ss = new BigInteger[] {
                BigInteger.valueOf(11),
                BigInteger.valueOf(13),
                BigInteger.valueOf(17)
        };

        BigInteger[] nativeResults = NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq,
                alphas, betasForN0, betasForN1, rs, ss);

        BigInteger[] expected = new BigInteger[alphas.length * 2];
        for (int i = 0; i < alphas.length; i++) {
            BigInteger Aj = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                    .multiply(BigIntegerUtils.powSigned(onePlusN0, betasForN0[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);
            BigInteger Bj = BigIntegerUtils.powSigned(onePlusN1, betasForN1[i], N1sq)
                    .multiply(ss[i].modPow(N1, N1sq))
                    .mod(N1sq);
            expected[i * 2] = Aj;
            expected[i * 2 + 1] = Bj;
        }

        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], nativeResults[i], "nativeAffGProofTuple mismatch at index " + i);
        }
    }

    @Test
    public void testNativeAffGProofTupleNonInvertibleThrows() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(15);
        BigInteger N1 = BigInteger.valueOf(21);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        BigInteger C = BigInteger.valueOf(15); // not invertible mod N0sq

        BigInteger[] alphas = new BigInteger[] { BigInteger.valueOf(-3) };
        BigInteger[] betasForN0 = new BigInteger[] { BigInteger.ZERO };
        BigInteger[] betasForN1 = new BigInteger[] { BigInteger.ZERO };
        BigInteger[] rs = new BigInteger[] { BigInteger.valueOf(2) };
        BigInteger[] ss = new BigInteger[] { BigInteger.valueOf(2) };

        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeAffGProofTuple(
                C, onePlusN0, N0sq, onePlusN1, N1sq,
                alphas, betasForN0, betasForN1, rs, ss));
    }

    @Test
    public void testNativeDecProofTupleSignedMatchesJava() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(101);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger K = BigInteger.valueOf(2);

        BigInteger[] alphas = new BigInteger[] {
                BigInteger.valueOf(3),
                BigInteger.valueOf(-4),
                BigInteger.valueOf(5)
        };
        BigInteger[] betas = new BigInteger[] {
                BigInteger.valueOf(-2),
                BigInteger.ZERO,
                BigInteger.valueOf(7)
        };
        BigInteger[] rs = new BigInteger[] {
                BigInteger.valueOf(4),
                BigInteger.valueOf(5),
                BigInteger.valueOf(6)
        };

        BigInteger[] nativeResults = NativeBigInteger.nativeDecProofTuple(K, N0, N0sq, alphas, betas, rs);

        BigInteger[] expected = new BigInteger[alphas.length];
        for (int i = 0; i < alphas.length; i++) {
            expected[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                    .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);
        }

        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], nativeResults[i], "nativeDecProofTuple mismatch at index " + i);
        }
    }

    @Test
    public void testNativeDecProofTupleNonInvertibleThrows() {
        assumeNativeAvailable();
        BigInteger N0 = BigInteger.valueOf(15);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger K = BigInteger.valueOf(15); // not invertible mod N0sq

        BigInteger[] alphas = new BigInteger[] { BigInteger.valueOf(3) };
        BigInteger[] betas = new BigInteger[] { BigInteger.ZERO };
        BigInteger[] rs = new BigInteger[] { BigInteger.valueOf(2) };

        assertThrows(ArithmeticException.class, () -> NativeBigInteger.nativeDecProofTuple(K, N0, N0sq, alphas, betas, rs));
    }
}
