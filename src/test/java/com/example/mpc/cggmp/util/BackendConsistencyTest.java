package com.example.mpc.cggmp.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(180)
public class BackendConsistencyTest {
    
    private static final int PAILLIER_BITS = 3072;
    private static final int KAPPA = 128;
    private static final int BLUM_ROUNDS = 64;
    private static final int ECDSA_BITS = 256;
    
    private static GmpBackend gmpBackend;
    private static JavaBackend javaBackend;
    private static boolean gmpAvailable;
    private static SecureRandom random;
    
    @BeforeAll
    static void setup() {
        gmpBackend = GmpBackend.getInstance();
        javaBackend = JavaBackend.getInstance();
        gmpAvailable = NativeBigInteger.isNativeAvailable();
        random = new SecureRandom();
        
        System.out.println("=".repeat(80));
        System.out.println("Backend Consistency Test (Real CGGMP Scenarios)");
        System.out.println("GMP Available: " + gmpAvailable);
        System.out.println("Config: paillierBits=" + PAILLIER_BITS + 
                           ", kappa=" + KAPPA + 
                           ", blumRounds=" + BLUM_ROUNDS);
        System.out.println("=".repeat(80));
    }
    
    @Test
    void testModPow() {
        System.out.println("\n=== modPow (basic operation) ===");
        
        BigInteger mod = BigInteger.probablePrime(PAILLIER_BITS, random);
        
        for (int i = 0; i < 3; i++) {
            BigInteger base = BigIntegerUtils.randomZnStar(mod, random);
            BigInteger exp = new BigInteger(PAILLIER_BITS, random);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.modPow(base, exp, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.modPow(base, exp, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, "modPow should match");
                
                System.out.printf("  modPow #%d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, mod.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  modPow #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testModInverse() {
        System.out.println("\n=== modInverse (n^2 ~" + (PAILLIER_BITS * 2) + " bits) ===");
        
        BigInteger p = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger q = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);
        
        for (int i = 0; i < 3; i++) {
            BigInteger val = BigIntegerUtils.randomZnStar(nSquared, random);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.modInverse(val, nSquared);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.modInverse(val, nSquared);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, "modInverse should match");
                assertEquals(BigInteger.ONE, BigIntegerUtils.modMul(val, javaResult, nSquared), "Verification failed");
                
                System.out.printf("  modInverse #%d: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  modInverse #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testModMul() {
        System.out.println("\n=== modMul (a * b mod m) ===");
        
        BigInteger mod = BigInteger.probablePrime(PAILLIER_BITS * 2, random);
        
        for (int i = 0; i < 3; i++) {
            BigInteger a = new BigInteger(PAILLIER_BITS * 2, random).mod(mod);
            BigInteger b = new BigInteger(PAILLIER_BITS * 2, random).mod(mod);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.modMul(a, b, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.modMul(a, b, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, "modMul should match");
                assertEquals(a.multiply(b).mod(mod), javaResult, "Verification failed");
                
                System.out.printf("  modMul #%d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, mod.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  modMul #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBatchModPow() {
        System.out.println("\n=== batchModPow (batch exponentiation) ===");
        
        BigInteger mod = BigInteger.probablePrime(PAILLIER_BITS * 2, random);
        BigInteger exp = new BigInteger(PAILLIER_BITS, random);
        
        for (int batchSize : new int[]{64, 128}) {
            BigInteger[] bases = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                bases[i] = BigIntegerUtils.randomZnStar(mod, random);
            }
            
            long javaStart = System.nanoTime();
            BigInteger[] javaResults = javaBackend.batchModPow(bases, exp, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger[] gmpResults = gmpBackend.batchModPow(bases, exp, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                for (int i = 0; i < batchSize; i++) {
                    assertEquals(javaResults[i], gmpResults[i], "batchModPow[" + i + "] should match");
                }
                
                System.out.printf("  batch %3d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    batchSize, mod.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                    batchSize, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBatchMod() {
        System.out.println("\n=== batchMod (batch modulo) ===");
        
        BigInteger p = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger q = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger N = p.multiply(q);
        
        for (int batchSize : new int[]{64}) {
            BigInteger[] values = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                values[i] = new BigInteger(PAILLIER_BITS, random);
            }
            
            long javaStart = System.nanoTime();
            BigInteger[] javaResultsP = javaBackend.batchMod(values, p);
            BigInteger[] javaResultsQ = javaBackend.batchMod(values, q);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger[] gmpResultsP = gmpBackend.batchMod(values, p);
                BigInteger[] gmpResultsQ = gmpBackend.batchMod(values, q);
                long gmpTime = System.nanoTime() - gmpStart;
                
                for (int i = 0; i < batchSize; i++) {
                    assertEquals(javaResultsP[i], gmpResultsP[i], "batchMod p[" + i + "] should match");
                    assertEquals(javaResultsQ[i], gmpResultsQ[i], "batchMod q[" + i + "] should match");
                }
                
                System.out.printf("  batch %3d (p,q %d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    batchSize, p.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                    batchSize, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testCrt() {
        System.out.println("\n=== crt (Chinese Remainder Theorem) ===");
        
        BigInteger p = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger q = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger N = p.multiply(q);
        
        for (int i = 0; i < 3; i++) {
            BigInteger a = new BigInteger(PAILLIER_BITS / 2 - 1, random);
            BigInteger b = new BigInteger(PAILLIER_BITS / 2 - 1, random);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.crt(a, p, b, q, N);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.crt(a, p, b, q, N);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, "crt should match");
                assertEquals(a, javaResult.mod(p), "crt mod p should equal a");
                assertEquals(b, javaResult.mod(q), "crt mod q should equal b");
                
                System.out.printf("  crt #%d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, N.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  crt #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testJacobi() {
        System.out.println("\n=== jacobi (Jacobi symbol) ===");
        
        BigInteger p = generateBlumPrime(PAILLIER_BITS / 2);
        
        for (int i = 0; i < 3; i++) {
            BigInteger a = BigIntegerUtils.randomZnStar(p, random);
            
            long javaStart = System.nanoTime();
            int javaResult = javaBackend.jacobi(a, p);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                int gmpResult = gmpBackend.jacobi(a, p);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, "jacobi should match");
                assertTrue(javaResult == -1 || javaResult == 0 || javaResult == 1, "jacobi should be -1, 0, or 1");
                
                System.out.printf("  jacobi #%d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, p.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  jacobi #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBatchJacobi() {
        System.out.println("\n=== batchJacobi (batch Jacobi symbol) ===");
        
        BigInteger p = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger q = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger N = p.multiply(q);
        
        for (int batchSize : new int[]{64}) {
            BigInteger[] values = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                values[i] = BigIntegerUtils.randomZnStar(N, random);
            }
            
            long javaStart = System.nanoTime();
            int[] javaResults = javaBackend.batchJacobi(values, p);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                int[] gmpResults = gmpBackend.batchJacobi(values, p);
                long gmpTime = System.nanoTime() - gmpStart;
                
                for (int i = 0; i < batchSize; i++) {
                    assertEquals(javaResults[i], gmpResults[i], "jacobi[" + i + "] should match");
                }
                
                System.out.printf("  batch %3d (%d bits): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    batchSize, p.bitLength(), javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                    batchSize, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testPaillierEncryption() {
        System.out.println("\n=== Paillier Encryption (n^2 modulus ~" + (PAILLIER_BITS * 2) + " bits) ===");
        
        BigInteger p = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger q = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);
        BigInteger g = n.add(BigInteger.ONE);
        
        System.out.println("  n bits: " + n.bitLength() + ", n^2 bits: " + nSquared.bitLength());
        
        for (int i = 0; i < 3; i++) {
            BigInteger m = new BigInteger(PAILLIER_BITS - 1, random);
            BigInteger r = BigIntegerUtils.randomZnStar(n, random);
            
            long javaStart = System.nanoTime();
            BigInteger gmJava = javaBackend.modPow(g, m, nSquared);
            BigInteger rnJava = javaBackend.modPow(r, n, nSquared);
            BigInteger cJava = javaBackend.modMul(gmJava, rnJava, nSquared);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmGmp = gmpBackend.modPow(g, m, nSquared);
                BigInteger rnGmp = gmpBackend.modPow(r, n, nSquared);
                BigInteger cGmp = gmpBackend.modMul(gmGmp, rnGmp, nSquared);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(cJava, cGmp, "Paillier ciphertext should match");
                
                System.out.printf("  encrypt #%d: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  encrypt #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBiPrimeProofScenario() {
        System.out.println("\n=== BiPrime Proof Scenario (blumRounds=" + BLUM_ROUNDS + ") ===");
        
        BigInteger p = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger q = generateBlumPrime(PAILLIER_BITS / 2);
        BigInteger N = p.multiply(q);
        
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = BigIntegerUtils.lcm(pMinus1, qMinus1);
        BigInteger NInv = BigIntegerUtils.positiveModInverse(N, lambda);
        BigInteger eP = NInv.mod(pMinus1);
        BigInteger eQ = NInv.mod(qMinus1);
        
        BigInteger inv4p = BigInteger.valueOf(4).modInverse(pMinus1.divide(BigInteger.TWO));
        BigInteger inv4q = BigInteger.valueOf(4).modInverse(qMinus1.divide(BigInteger.TWO));
        
        System.out.println("  p bits: " + p.bitLength() + ", q bits: " + q.bitLength());
        
        BigInteger[] yValues = new BigInteger[BLUM_ROUNDS];
        for (int i = 0; i < BLUM_ROUNDS; i++) {
            yValues[i] = BigIntegerUtils.randomZnStar(N, random);
        }
        
        long javaStart = System.nanoTime();
        BigInteger[] basesPJava = javaBackend.batchMod(yValues, p);
        BigInteger[] basesQJava = javaBackend.batchMod(yValues, q);
        BigInteger[] zpsJava = javaBackend.batchModPow(basesPJava, eP, p);
        BigInteger[] zqsJava = javaBackend.batchModPow(basesQJava, eQ, q);
        int[] jacobiPJava = javaBackend.batchJacobi(yValues, p);
        int[] jacobiQJava = javaBackend.batchJacobi(yValues, q);
        BigInteger[] rhsPJava = javaBackend.batchMod(yValues, p);
        BigInteger[] rhsQJava = javaBackend.batchMod(yValues, q);
        BigInteger[] xpsJava = javaBackend.batchModPow(rhsPJava, inv4p, p);
        BigInteger[] xqsJava = javaBackend.batchModPow(rhsQJava, inv4q, q);
        long javaTime = System.nanoTime() - javaStart;
        
        if (gmpAvailable) {
            long gmpStart = System.nanoTime();
            BigInteger[] basesPGmp = gmpBackend.batchMod(yValues, p);
            BigInteger[] basesQGmp = gmpBackend.batchMod(yValues, q);
            BigInteger[] zpsGmp = gmpBackend.batchModPow(basesPGmp, eP, p);
            BigInteger[] zqsGmp = gmpBackend.batchModPow(basesQGmp, eQ, q);
            int[] jacobiPGmp = gmpBackend.batchJacobi(yValues, p);
            int[] jacobiQGmp = gmpBackend.batchJacobi(yValues, q);
            BigInteger[] rhsPGmp = gmpBackend.batchMod(yValues, p);
            BigInteger[] rhsQGmp = gmpBackend.batchMod(yValues, q);
            BigInteger[] xpsGmp = gmpBackend.batchModPow(rhsPGmp, inv4p, p);
            BigInteger[] xqsGmp = gmpBackend.batchModPow(rhsQGmp, inv4q, q);
            long gmpTime = System.nanoTime() - gmpStart;
            
            for (int i = 0; i < BLUM_ROUNDS; i++) {
                assertEquals(zpsJava[i], zpsGmp[i], "zp[" + i + "] should match");
                assertEquals(zqsJava[i], zqsGmp[i], "zq[" + i + "] should match");
                assertEquals(jacobiPJava[i], jacobiPGmp[i], "jacobiP[" + i + "] should match");
                assertEquals(jacobiQJava[i], jacobiQGmp[i], "jacobiQ[" + i + "] should match");
                assertEquals(xpsJava[i], xpsGmp[i], "xp[" + i + "] should match");
                assertEquals(xqsJava[i], xqsGmp[i], "xq[" + i + "] should match");
            }
            
            System.out.printf("  BiPrime total: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                (double) javaTime / gmpTime);
        } else {
            System.out.printf("  BiPrime total: Java=%8.3f ms (GMP not available)%n",
                javaTime / 1_000_000.0);
        }
    }
    
    @Test
    void testPresignAffGScenario() {
        System.out.println("\n=== Presign AffG Scenario (kappa=" + KAPPA + ", N^2 ~" + (PAILLIER_BITS * 2) + " bits) ===");
        
        BigInteger p0 = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger q0 = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger N0 = p0.multiply(q0);
        BigInteger N0sq = N0.multiply(N0);
        
        BigInteger[] rArr = new BigInteger[KAPPA];
        for (int i = 0; i < KAPPA; i++) {
            rArr[i] = BigIntegerUtils.randomZnStar(N0, random);
        }
        
        System.out.println("  N0 bits: " + N0.bitLength() + ", N0^2 bits: " + N0sq.bitLength());
        
        long javaStart = System.nanoTime();
        BigInteger[] rPowN0Java = javaBackend.batchModPow(rArr, N0, N0sq);
        long javaTime = System.nanoTime() - javaStart;
        
        if (gmpAvailable) {
            long gmpStart = System.nanoTime();
            BigInteger[] rPowN0Gmp = gmpBackend.batchModPow(rArr, N0, N0sq);
            long gmpTime = System.nanoTime() - gmpStart;
            
            for (int i = 0; i < KAPPA; i++) {
                assertEquals(rPowN0Java[i], rPowN0Gmp[i], "r^N0[" + i + "] should match");
            }
            
            System.out.printf("  batch %3d (N0^2): Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                KAPPA, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                (double) javaTime / gmpTime);
        } else {
            System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                KAPPA, javaTime / 1_000_000.0);
        }
    }
    
    @Test
    void testMtAProtocol() {
        System.out.println("\n=== MtA Protocol (c^b mod n^2) ===");
        
        BigInteger p = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger q = BigInteger.probablePrime(PAILLIER_BITS / 2, random);
        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);
        BigInteger ecQ = Secp256k1CurveUtils.n();
        
        for (int i = 0; i < 3; i++) {
            BigInteger c_i = new BigInteger(PAILLIER_BITS * 2, random).mod(nSquared);
            BigInteger b_j = new BigInteger(ECDSA_BITS, random).mod(ecQ);
            
            long javaStart = System.nanoTime();
            BigInteger c_jJava = javaBackend.modPow(c_i, b_j, nSquared);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger c_jGmp = gmpBackend.modPow(c_i, b_j, nSquared);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(c_jJava, c_jGmp, "MtA result should match");
                
                System.out.printf("  MtA #%d: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx%n",
                    i + 1, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime);
            } else {
                System.out.printf("  MtA #%d: Java=%8.3f ms (GMP not available)%n",
                    i + 1, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBigIntegerUtilsMethods() {
        System.out.println("\n=== BigIntegerUtils Methods ===");
        
        System.out.println("  Testing lcm:");
        BigInteger a = new BigInteger("123456789");
        BigInteger b = new BigInteger("987654321");
        BigInteger lcmResult = BigIntegerUtils.lcm(a, b);
        assertEquals(a.multiply(b).divide(a.gcd(b)), lcmResult, "lcm should match");
        System.out.println("    lcm(" + a + ", " + b + ") = " + lcmResult);
        
        System.out.println("  Testing positiveModInverse:");
        BigInteger mod = new BigInteger("1000000007");
        BigInteger invResult = BigIntegerUtils.positiveModInverse(a, mod);
        assertTrue(invResult.signum() >= 0, "positiveModInverse should return positive");
        assertEquals(BigInteger.ONE, BigIntegerUtils.modMul(a, invResult, mod), "a * a^-1 mod m should be 1");
        System.out.println("    positiveModInverse(" + a + ", " + mod + ") = " + invResult);
        
        System.out.println("  Testing generateSafePrime:");
        long start = System.nanoTime();
        BigInteger safePrime = BigIntegerUtils.generateSafePrime(256, random);
        long elapsed = System.nanoTime() - start;
        assertTrue(safePrime.isProbablePrime(128), "safePrime should be prime");
        BigInteger q = safePrime.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        assertTrue(q.isProbablePrime(128), "(p-1)/2 should be prime");
        System.out.println("    generateSafePrime(256) = " + safePrime + " (took " + elapsed / 1_000_000.0 + " ms)");
        
        System.out.println("  Testing powSigned with negative exponent:");
        BigInteger base = BigIntegerUtils.randomZnStar(mod, random);
        BigInteger negExp = BigInteger.valueOf(-5);
        BigInteger posExp = BigInteger.valueOf(5);
        BigInteger negResult = BigIntegerUtils.powSigned(base, negExp, mod);
        BigInteger posResult = BigIntegerUtils.modPow(base, posExp, mod);
        BigInteger invBase = BigIntegerUtils.modInverse(base, mod);
        assertEquals(BigIntegerUtils.modPow(invBase, posExp, mod), negResult, "powSigned with negative exp should equal base^-1^exp");
        System.out.println("    powSigned(" + base + ", -5, " + mod + ") verified");
    }
    
    @Test
    void testIsNative() {
        System.out.println("\n=== Backend Status ===");
        
        assertFalse(javaBackend.isNative(), "JavaBackend should return false for isNative");
        
        if (gmpAvailable) {
            assertTrue(gmpBackend.isNative(), "GmpBackend should return true for isNative");
        } else {
            assertFalse(gmpBackend.isNative(), "GmpBackend should return false when GMP not available");
        }
        
        System.out.println("  JavaBackend.isNative() = " + javaBackend.isNative());
        System.out.println("  GmpBackend.isNative() = " + gmpBackend.isNative());
    }
    
    @Test
    void testEdgeCases() {
        System.out.println("\n=== Edge Cases ===");
        
        BigInteger zero = BigInteger.ZERO;
        BigInteger one = BigInteger.ONE;
        BigInteger two = BigInteger.TWO;
        BigInteger mod = BigInteger.probablePrime(1024, random);
        
        System.out.println("  Testing modPow with zero exp (should return 1):");
        BigInteger javaResult = javaBackend.modPow(new BigInteger("12345"), zero, mod);
        assertEquals(one, javaResult, "base^0 mod m should be 1");
        if (gmpAvailable) {
            BigInteger gmpResult = gmpBackend.modPow(new BigInteger("12345"), zero, mod);
            assertEquals(one, gmpResult, "GMP: base^0 mod m should be 1");
            System.out.println("    GMP and Java both return 1: Match=true");
        }
        
        System.out.println("  Testing modPow with base=0:");
        javaResult = javaBackend.modPow(zero, two, mod);
        assertEquals(zero, javaResult, "0^exp mod m should be 0");
        if (gmpAvailable) {
            BigInteger gmpResult = gmpBackend.modPow(zero, two, mod);
            assertEquals(zero, gmpResult, "GMP: 0^exp mod m should be 0");
            System.out.println("    GMP and Java both return 0: Match=true");
        }
        
        System.out.println("  Testing modMul with zero:");
        javaResult = javaBackend.modMul(zero, new BigInteger("12345"), mod);
        assertEquals(zero, javaResult, "0 * b mod m should be 0");
        if (gmpAvailable) {
            BigInteger gmpResult = gmpBackend.modMul(zero, new BigInteger("12345"), mod);
            assertEquals(zero, gmpResult, "GMP: 0 * b mod m should be 0");
            System.out.println("    GMP and Java both return 0: Match=true");
        }
    }
    
    private static BigInteger generateBlumPrime(int bits) {
        while (true) {
            BigInteger p = BigInteger.probablePrime(bits, random);
            if (p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
                return p;
            }
        }
    }
}
