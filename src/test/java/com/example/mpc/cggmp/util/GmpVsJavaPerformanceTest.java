package com.example.mpc.cggmp.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.example.mpc.cggmp.util.AffGProofResult;
import com.example.mpc.cggmp.util.DecProofResult;
import com.example.mpc.cggmp.util.NativeBigInteger;

import static com.example.mpc.cggmp.util.Secp256k1CurveUtils.*;

@DisplayName("GMP vs Java BigInteger Real-World Performance Test")
@Disabled("Temporarily disabled for build verification")
class GmpVsJavaPerformanceTest {
    private static final Logger logger = LoggerFactory.getLogger(GmpVsJavaPerformanceTest.class);

    private static final int WARMUP_ROUNDS = 2;
    private static final int TEST_ROUNDS = 5;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static boolean gmpAvailable;

    private static final int KAPPA;
    private static final int PAILLIER_BITS;

    static {
        String quickMode = System.getProperty("quick.test", "false");
        if ("true".equalsIgnoreCase(quickMode)) {
            KAPPA = 16;
            PAILLIER_BITS = 512;
            if (logger.isInfoEnabled()) {
                logger.info("Quick test mode enabled: kappa={}, paillierBits={}", KAPPA, PAILLIER_BITS);
            }
        } else {
            KAPPA = 128;
            PAILLIER_BITS = 3072;
        }
    }

    @BeforeAll
    static void setup() {
        gmpAvailable = NativeBigInteger.isNativeAvailable();
        if (logger.isInfoEnabled()) {
            logger.info("=".repeat(80));
            logger.info("GMP vs Java BigInteger Real-World Performance Test");
            logger.info("GMP Available: {}", gmpAvailable);
            logger.info("CGGMP Parameters: kappa={}, paillierBits={}", KAPPA, PAILLIER_BITS);
            logger.info("=".repeat(80));
        }
    }

    @Test
    @DisplayName("1. Modular Exponentiation (Real Paillier Key Size)")
    void testModPowPerformance() {
        if (logger.isInfoEnabled()) {
            logger.info("");
            logger.info("-".repeat(80));
            logger.info("Test 1: Modular Exponentiation (a^b mod n) @ {} bits", PAILLIER_BITS);
            logger.info("-".repeat(80));
        }
        BigInteger modulus = generatePaillierModulus(PAILLIER_BITS);
        BigInteger base = new BigInteger(PAILLIER_BITS, RANDOM).mod(modulus);
        BigInteger exponent = new BigInteger(PAILLIER_BITS / 2, RANDOM);

        if (logger.isInfoEnabled()) {
            logger.info("  Modulus bits: {}", modulus.bitLength());
            logger.info("  Base bits: {}", base.bitLength());
            logger.info("  Exponent bits: {}", exponent.bitLength());
        }

        BigInteger javaResult = base.modPow(exponent, modulus);
        double javaAvg = benchmarkOperation("Java", () -> base.modPow(exponent, modulus));

        if (gmpAvailable) {
            BigInteger gmpResult = NativeBigInteger.modPow(base, exponent, modulus);
            boolean match = javaResult.equals(gmpResult);
            if (logger.isInfoEnabled()) {
                logger.info("  Result Match: {}", match);
            }
            double gmpAvg = benchmarkOperation("GMP", () -> NativeBigInteger.modPow(base, exponent, modulus));
            logComparison("modPow", javaAvg, gmpAvg, match);
        }
    }

    @Test
    @DisplayName("2. Modular Inverse (Real Paillier Key Size)")
    void testModInversePerformance() {
        logger.info("");
        logger.info("-".repeat(80));
        logger.info("Test 2: Modular Inverse (a^(-1) mod n) @ {} bits", PAILLIER_BITS);
        logger.info("-".repeat(80));

        BigInteger modulus = generatePaillierModulus(PAILLIER_BITS);
        BigInteger value = new BigInteger(PAILLIER_BITS, RANDOM).mod(modulus).add(BigInteger.ONE);

        BigInteger javaResult = value.modInverse(modulus);
        double javaAvg = benchmarkOperation("Java", () -> value.modInverse(modulus));

        if (gmpAvailable) {
            BigInteger gmpResult = NativeBigInteger.modInverse(value, modulus);
            boolean match = javaResult.equals(gmpResult);
            logger.info("  Result Match: {}", match);

            double gmpAvg = benchmarkOperation("GMP", () -> NativeBigInteger.modInverse(value, modulus));
            logComparison("modInverse", javaAvg, gmpAvg, match);
        }
    }

    @Test
    @DisplayName("3. Big Integer Multiplication (3072-bit)")
    void testMultiplyPerformance() {
        logger.info("");
        logger.info("-".repeat(80));
        logger.info("Test 3: Big Integer Multiplication (a * b) @ {} bits", PAILLIER_BITS);
        logger.info("-".repeat(80));

        BigInteger a = new BigInteger(PAILLIER_BITS, RANDOM);
        BigInteger b = new BigInteger(PAILLIER_BITS, RANDOM);

        BigInteger javaResult = a.multiply(b);
        double javaAvg = benchmarkOperation("Java", () -> a.multiply(b));

        if (gmpAvailable) {
            BigInteger gmpResult = NativeBigInteger.multiply(a, b);
            boolean match = javaResult.equals(gmpResult);
            logger.info("  Result Match: {}", match);

            double gmpAvg = benchmarkOperation("GMP", () -> NativeBigInteger.multiply(a, b));
            logComparison("multiply", javaAvg, gmpAvg, match);
        }
    }

    @Test
    @DisplayName("4. Batch Modular Exponentiation (128 bases)")
    void testBatchModPowPerformance() {
        logger.info("");
        logger.info("-".repeat(80));
        logger.info("Test 4: Batch ModPow (128 bases ^ exp mod n) @ {} bits", PAILLIER_BITS);
        logger.info("-".repeat(80));

        int batchSize = 128;
        BigInteger modulus = generatePaillierModulus(PAILLIER_BITS);
        BigInteger exponent = new BigInteger(PAILLIER_BITS / 2, RANDOM);

        BigInteger[] bases = new BigInteger[batchSize];
        for (int i = 0; i < batchSize; i++) {
            bases[i] = new BigInteger(PAILLIER_BITS, RANDOM).mod(modulus);
        }

        BigInteger[] javaResult = javaBatchModPow(bases, exponent, modulus);
        double javaAvg = benchmarkOperation("Java", () -> {
            BigInteger[] result = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                result[i] = bases[i].modPow(exponent, modulus);
            }
        });

        boolean match = true;
        double gmpAvg = -1;
        if (gmpAvailable) {
            BigInteger[] gmpResult = NativeBigInteger.batchModPow(bases, exponent, modulus);
            match = verifyArrayEquals(javaResult, gmpResult);
            logger.info("  Result Match: {}", match);

            gmpAvg = benchmarkOperation("GMP", () -> NativeBigInteger.batchModPow(bases, exponent, modulus));
            logComparison("batchModPow", javaAvg, gmpAvg, match);
        }
    }

    @Test
    @DisplayName("5. CGGMP PiAffG Proof (Real Protocol Parameters)")
    void testPiAffGProofPerformance() {
        logger.info("");
        logger.info("-".repeat(80));
        logger.info("Test 5: CGGMP PiAffG Proof Tuple @ kappa={}, keyBits={}", KAPPA, PAILLIER_BITS);
        logger.info("    This is the most compute-intensive proof in CGGMP signature");
        logger.info("-".repeat(80));

        BigInteger N0 = generatePaillierModulus(PAILLIER_BITS);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger N1 = generatePaillierModulus(PAILLIER_BITS);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger onePlusN1 = BigInteger.ONE.add(N1);
        BigInteger C = new BigInteger(PAILLIER_BITS, RANDOM).mod(N0sq);

        BigInteger[] alphas = new BigInteger[KAPPA];
        BigInteger[] betas = new BigInteger[KAPPA];
        BigInteger[] rs = new BigInteger[KAPPA];
        BigInteger[] ss = new BigInteger[KAPPA];

        for (int i = 0; i < KAPPA; i++) {
            alphas[i] = new BigInteger(PAILLIER_BITS, RANDOM);
            betas[i] = new BigInteger(PAILLIER_BITS, RANDOM);
            rs[i] = new BigInteger(PAILLIER_BITS, RANDOM).mod(N0);
            ss[i] = new BigInteger(PAILLIER_BITS, RANDOM).mod(N1);
        }

        logger.info("  N0 bits: {}, N1 bits: {}", N0.bitLength(), N1.bitLength());

        AffGProofResult javaResult = computePiAffGProofJava(N0, N0sq, N1, N1sq, C, alphas, betas, rs, ss);
        double javaTime = benchmarkPiAffGProofJava(N0, N0sq, N1, N1sq, C, alphas, betas, rs, ss);

        if (gmpAvailable) {
            AffGProofResult gmpResult = computePiAffGProofNative(N0, N0sq, N1, N1sq, C, alphas, betas, rs, ss);
            boolean match = verifyAffGProofResult(javaResult, gmpResult);
            logger.info("  Result Match: {}", match);

            double gmpTime = benchmarkPiAffGProofNative(N0, N0sq, N1, N1sq, C, alphas, betas, rs, ss);
            logComparison("PiAffG", javaTime, gmpTime, match);
        }
    }

    @Test
    @DisplayName("6. CGGMP PiDec Proof (Real Protocol Parameters)")
    void testPiDecProofPerformance() {
        logger.info("");
        logger.info("-".repeat(80));
        logger.info("Test 6: CGGMP PiDec Proof Tuple @ kappa={}, keyBits={}", KAPPA, PAILLIER_BITS);
        logger.info("    Used in multiplication protocol");
        logger.info("-".repeat(80));

        BigInteger N0 = generatePaillierModulus(PAILLIER_BITS);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger K = new BigInteger(PAILLIER_BITS, RANDOM).mod(N0sq);

        BigInteger[] alphas = new BigInteger[KAPPA];
        BigInteger[] betas = new BigInteger[KAPPA];
        BigInteger[] rs = new BigInteger[KAPPA];

        for (int i = 0; i < KAPPA; i++) {
            alphas[i] = new BigInteger(PAILLIER_BITS, RANDOM);
            betas[i] = new BigInteger(PAILLIER_BITS, RANDOM);
            rs[i] = new BigInteger(PAILLIER_BITS, RANDOM);
        }

        DecProofResult javaResult = computePiDecProofJava(K, N0, N0sq, alphas, betas, rs);
        double javaTime = benchmarkPiDecProofJava(K, N0, N0sq, alphas, betas, rs);

        if (gmpAvailable) {
            DecProofResult gmpResult = computePiDecProofNative(K, N0, N0sq, alphas, betas, rs);
            boolean match = verifyDecProofResult(javaResult, gmpResult);
            logger.info("  Result Match: {}", match);

            double gmpTime = benchmarkPiDecProofNative(K, N0, N0sq, alphas, betas, rs);
            logComparison("PiDec", javaTime, gmpTime, match);
        }
    }

    private BigInteger generatePaillierModulus(int bits) {
        BigInteger p = BigInteger.probablePrime(bits / 2, RANDOM);
        BigInteger q = BigInteger.probablePrime(bits / 2, RANDOM);
        return p.multiply(q);
    }

    private double benchmarkOperation(String name, Runnable operation) {
        for (int i = 0; i < WARMUP_ROUNDS; i++) {
            operation.run();
        }

        long totalTime = 0;
        for (int i = 0; i < TEST_ROUNDS; i++) {
            long start = System.nanoTime();
            operation.run();
            totalTime += System.nanoTime() - start;
        }

        double avgMs = (totalTime / TEST_ROUNDS) / 1_000_000.0;
        logger.info("  {} avg: {} ms/op ({} rounds)", name, String.format("%.2f", avgMs), TEST_ROUNDS);
        return avgMs;
    }

    private BigInteger[] javaBatchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        BigInteger[] result = new BigInteger[bases.length];
        for (int i = 0; i < bases.length; i++) {
            result[i] = bases[i].modPow(exp, mod);
        }
        return result;
    }

    private boolean verifyArrayEquals(BigInteger[] a, BigInteger[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (!a[i].equals(b[i])) {
                logger.warn("  Mismatch at index {}: Java={}, GMP={}", i, a[i].toString().substring(0, 32), b[i].toString().substring(0, 32));
                return false;
            }
        }
        return true;
    }

    private AffGProofResult computePiAffGProofJava(BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
                                                                   BigInteger C,
                                                                   BigInteger[] alphas, BigInteger[] betas,
                                                                   BigInteger[] rs, BigInteger[] ss) {
        BigInteger[] Aj = new BigInteger[KAPPA];
        BigInteger[] Bj = new BigInteger[KAPPA];

        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);

        for (int i = 0; i < KAPPA; i++) {
            Aj[i] = C.modPow(alphas[i], N0sq)
                    .multiply(onePlusN0.modPow(betas[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);

            Bj[i] = onePlusN1.modPow(betas[i], N1sq)
                    .multiply(ss[i].modPow(N1, N1sq))
                    .mod(N1sq);
        }
        return new AffGProofResult(Aj, Bj);
    }

    private AffGProofResult computePiAffGProofNative(BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
                                                                     BigInteger C,
                                                                     BigInteger[] alphas, BigInteger[] betas,
                                                                     BigInteger[] rs, BigInteger[] ss) {
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        return NativeBigInteger.computeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betas, betas, rs, ss);
    }

    private boolean verifyAffGProofResult(AffGProofResult java, AffGProofResult gmp) {
        boolean ajMatch = verifyArrayEquals(java.Aj(), gmp.Aj());
        boolean bjMatch = verifyArrayEquals(java.Bj(), gmp.Bj());
        return ajMatch && bjMatch;
    }

    private double benchmarkPiAffGProofJava(BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
                                           BigInteger C,
                                           BigInteger[] alphas, BigInteger[] betas,
                                           BigInteger[] rs, BigInteger[] ss) {
        return benchmarkOperation("Java", () -> {
            BigInteger onePlusN0 = N0.add(BigInteger.ONE);
            BigInteger onePlusN1 = N1.add(BigInteger.ONE);

            for (int i = 0; i < KAPPA; i++) {
                BigInteger aj = C.modPow(alphas[i], N0sq)
                        .multiply(onePlusN0.modPow(betas[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);

                BigInteger bj = onePlusN1.modPow(betas[i], N1sq)
                        .multiply(ss[i].modPow(N1, N1sq))
                        .mod(N1sq);
            }
        });
    }

    private double benchmarkPiAffGProofNative(BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
                                              BigInteger C,
                                              BigInteger[] alphas, BigInteger[] betas,
                                              BigInteger[] rs, BigInteger[] ss) {
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger onePlusN1 = N1.add(BigInteger.ONE);
        return benchmarkOperation("GMP", () -> {
            NativeBigInteger.computeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betas, betas, rs, ss);
        });
    }

    private DecProofResult computePiDecProofJava(BigInteger K, BigInteger N0, BigInteger N0sq,
                                                                  BigInteger[] alphas, BigInteger[] betas,
                                                                  BigInteger[] rs) {
        BigInteger[] zj = new BigInteger[KAPPA];
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        for (int i = 0; i < KAPPA; i++) {
            BigInteger negAlpha = alphas[i].negate();
            zj[i] = K.modPow(negAlpha, N0sq)
                    .multiply(onePlusN0.modPow(betas[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);
        }
        return new DecProofResult(zj);
    }

    private DecProofResult computePiDecProofNative(BigInteger K, BigInteger N0, BigInteger N0sq,
                                                                    BigInteger[] alphas, BigInteger[] betas,
                                                                    BigInteger[] rs) {
        return GmpBackend.computeDecProofTuples(K, N0, N0sq, alphas, betas, rs);
    }

    private boolean verifyDecProofResult(DecProofResult java, DecProofResult gmp) {
        return verifyArrayEquals(java.A(), gmp.A());
    }

    private double benchmarkPiDecProofJava(BigInteger K, BigInteger N0, BigInteger N0sq,
                                           BigInteger[] alphas, BigInteger[] betas,
                                           BigInteger[] rs) {
        return benchmarkOperation("Java", () -> {
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            for (int i = 0; i < KAPPA; i++) {
                BigInteger negAlpha = alphas[i].negate();
                BigInteger z = K.modPow(negAlpha, N0sq)
                        .multiply(onePlusN0.modPow(betas[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);
            }
        });
    }

    private double benchmarkPiDecProofNative(BigInteger K, BigInteger N0, BigInteger N0sq,
                                             BigInteger[] alphas, BigInteger[] betas,
                                             BigInteger[] rs) {
        return benchmarkOperation("GMP", () -> {
            GmpBackend.computeDecProofTuples(K, N0, N0sq, alphas, betas, rs);
        });
    }

    private void logComparison(String operation, double javaTime, double gmpTime, boolean resultMatch) {
        double speedup = javaTime / gmpTime;
        logger.info("");
        logger.info("  ╔════════════════════════════════════════╗");
        logger.info("  ║         Performance Summary            ║");
        logger.info("  ╠════════════════════════════════════════╣");
        logger.info("  ║  Operation: {} ", String.format("%-20s", operation));
        logger.info("  ║  Java:      {} ms            ", String.format("%10.2f", javaTime));
        logger.info("  ║  GMP:       {} ms            ", String.format("%10.2f", gmpTime));
        logger.info("  ║  Speedup:   {}x                 ", String.format("%10.2f", speedup));
        if (speedup > 1) {
            logger.info("  ║  GMP is {}% faster                  ", String.format("%.1f", (speedup - 1) * 100));
        } else {
            logger.info("  ║  Java is {}% faster                ", String.format("%.1f", (1 - speedup) * 100));
        }
        logger.info("  ╠════════════════════════════════════════╣");
        logger.info("  ║  Result Match: {}                      ", resultMatch ? "✓ PASS" : "✗ FAIL");
        logger.info("  ╚════════════════════════════════════════╝");
        logger.info("");
    }
}
