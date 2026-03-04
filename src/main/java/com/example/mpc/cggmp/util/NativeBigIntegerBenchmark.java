package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class NativeBigIntegerBenchmark {
    private static final Logger logger = LoggerFactory.getLogger(NativeBigIntegerBenchmark.class);
    
    private static final int WARMUP_ITERATIONS = 10;
    private static final int BENCHMARK_ITERATIONS = 100;
    
    private NativeBigIntegerBenchmark() {
    }
    
    public static void main(String[] args) {
        logger.info("=== Native BigInteger Benchmark ===");
        logger.info("");
        
        boolean nativeAvailable = NativeBigInteger.isNativeAvailable();
        logger.info("Native GMP library: {}", nativeAvailable ? "AVAILABLE" : "NOT AVAILABLE");
        logger.info("");
        
        if (!nativeAvailable) {
            logger.warn("GMP native library not loaded. Benchmark will only test Java BigInteger.");
            logger.warn("To enable GMP acceleration:");
            logger.warn("  1. Install GMP: brew install gmp (macOS) or apt-get install libgmp-dev (Linux)");
            logger.warn("  2. Run: ./scripts/build_native.sh --static");
            logger.warn("  3. Restart application");
            logger.info("");
        }
        
        runBenchmark();
    }
    
    public static void runBenchmark() {
        SecureRandom random = new SecureRandom();
        
        int[] bitSizes = {1024, 2048, 3072};
        
        for (int bits : bitSizes) {
            logger.info("--- Testing {}-bit numbers ---", bits);
            
            BigInteger base = new BigInteger(bits, random);
            BigInteger exp = new BigInteger(bits / 2, random);
            BigInteger mod = BigInteger.probablePrime(bits, random);
            
            benchmarkModPow(base, exp, mod);
            benchmarkModInverse(base.mod(mod).add(BigInteger.ONE), mod);
            benchmarkMultiply(base, exp);
            
            logger.info("");
        }
        
        benchmarkRealWorldScenario();
    }
    
    private static void benchmarkModPow(BigInteger base, BigInteger exp, BigInteger mod) {
        logger.info("modPow ({} bits):", mod.bitLength());
        
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            base.modPow(exp, mod);
            if (NativeBigInteger.isNativeAvailable()) {
                NativeBigInteger.modPow(base, exp, mod);
            }
        }
        
        long javaStart = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            base.modPow(exp, mod);
        }
        long javaTime = (System.nanoTime() - javaStart) / 1_000_000;
        
        long nativeTime = -1;
        if (NativeBigInteger.isNativeAvailable()) {
            long nativeStart = System.nanoTime();
            for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
                NativeBigInteger.modPow(base, exp, mod);
            }
            nativeTime = (System.nanoTime() - nativeStart) / 1_000_000;
        }
        
        logger.info("  Java BigInteger: {} ms ({} ops, avg {} ms/op)", 
                javaTime, BENCHMARK_ITERATIONS, String.format("%.2f", (double) javaTime / BENCHMARK_ITERATIONS));
        
        if (nativeTime >= 0) {
            logger.info("  Native GMP:      {} ms ({} ops, avg {} ms/op)", 
                    nativeTime, BENCHMARK_ITERATIONS, String.format("%.2f", (double) nativeTime / BENCHMARK_ITERATIONS));
            double speedup = (double) javaTime / nativeTime;
            logger.info("  Speedup:         {}x", String.format("%.2f", speedup));
        }
    }
    
    private static void benchmarkModInverse(BigInteger val, BigInteger mod) {
        logger.info("modInverse ({} bits):", mod.bitLength());
        
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            val.modInverse(mod);
            if (NativeBigInteger.isNativeAvailable()) {
                NativeBigInteger.modInverse(val, mod);
            }
        }
        
        long javaStart = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
            val.modInverse(mod);
        }
        long javaTime = (System.nanoTime() - javaStart) / 1_000_000;
        
        long nativeTime = -1;
        if (NativeBigInteger.isNativeAvailable()) {
            long nativeStart = System.nanoTime();
            for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
                NativeBigInteger.modInverse(val, mod);
            }
            nativeTime = (System.nanoTime() - nativeStart) / 1_000_000;
        }
        
        logger.info("  Java BigInteger: {} ms", javaTime);
        
        if (nativeTime >= 0) {
            logger.info("  Native GMP:      {} ms", nativeTime);
            double speedup = (double) javaTime / nativeTime;
            logger.info("  Speedup:         {}x", String.format("%.2f", speedup));
        }
    }
    
    private static void benchmarkMultiply(BigInteger a, BigInteger b) {
        logger.info("multiply ({} bits):", a.bitLength());
        
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            a.multiply(b);
            if (NativeBigInteger.isNativeAvailable()) {
                NativeBigInteger.multiply(a, b);
            }
        }
        
        long javaStart = System.nanoTime();
        for (int i = 0; i < BENCHMARK_ITERATIONS * 10; i++) {
            a.multiply(b);
        }
        long javaTime = (System.nanoTime() - javaStart) / 1_000_000;
        
        long nativeTime = -1;
        if (NativeBigInteger.isNativeAvailable()) {
            long nativeStart = System.nanoTime();
            for (int i = 0; i < BENCHMARK_ITERATIONS * 10; i++) {
                NativeBigInteger.multiply(a, b);
            }
            nativeTime = (System.nanoTime() - nativeStart) / 1_000_000;
        }
        
        logger.info("  Java BigInteger: {} ms", javaTime);
        
        if (nativeTime >= 0) {
            logger.info("  Native GMP:      {} ms", nativeTime);
            double speedup = (double) javaTime / nativeTime;
            logger.info("  Speedup:         {}x", String.format("%.2f", speedup));
        }
    }
    
    private static void benchmarkRealWorldScenario() {
        logger.info("--- Real-world CGGMP Scenario ---");
        logger.info("Simulating PiAffG proof generation (kappa=128)");
        
        SecureRandom random = new SecureRandom();
        int kappa = 128;
        int keyBits = 2048;
        
        BigInteger N0 = new BigInteger(keyBits, random).setBit(keyBits - 1);
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1 = new BigInteger(keyBits, random).setBit(keyBits - 1);
        BigInteger N1sq = N1.multiply(N1);
        BigInteger C = new BigInteger(keyBits, random).mod(N0sq);
        
        BigInteger[] alphas = new BigInteger[kappa];
        BigInteger[] betas = new BigInteger[kappa];
        BigInteger[] rs = new BigInteger[kappa];
        BigInteger[] ss = new BigInteger[kappa];
        
        for (int i = 0; i < kappa; i++) {
            alphas[i] = new BigInteger(keyBits, random);
            betas[i] = new BigInteger(keyBits, random);
            rs[i] = new BigInteger(keyBits, random).mod(N0);
            ss[i] = new BigInteger(keyBits, random).mod(N1);
        }
        
        for (int i = 0; i < 5; i++) {
            computeProofTupleJava(N0sq, N1sq, C, alphas, betas, rs, ss, kappa);
        }
        
        long javaStart = System.nanoTime();
        for (int iter = 0; iter < 3; iter++) {
            computeProofTupleJava(N0sq, N1sq, C, alphas, betas, rs, ss, kappa);
        }
        long javaTime = (System.nanoTime() - javaStart) / 1_000_000;
        
        long nativeTime = -1;
        long nativeBatchTime = -1;
        if (NativeBigInteger.isNativeAvailable()) {
            for (int i = 0; i < 5; i++) {
                computeProofTupleNative(N0sq, N1sq, C, alphas, betas, rs, ss, kappa);
            }
            
            long nativeStart = System.nanoTime();
            for (int iter = 0; iter < 3; iter++) {
                computeProofTupleNative(N0sq, N1sq, C, alphas, betas, rs, ss, kappa);
            }
            nativeTime = (System.nanoTime() - nativeStart) / 1_000_000;
            
            for (int i = 0; i < 5; i++) {
                NativeBigInteger.computeAffGProofTuples(C, N0sq, N1sq, alphas, betas, rs, ss);
            }
            
            long nativeBatchStart = System.nanoTime();
            for (int iter = 0; iter < 3; iter++) {
                NativeBigInteger.computeAffGProofTuples(C, N0sq, N1sq, alphas, betas, rs, ss);
            }
            nativeBatchTime = (System.nanoTime() - nativeBatchStart) / 1_000_000;
        }
        
        logger.info("  Java BigInteger:          {} ms (avg {} ms/proof)", 
                javaTime, String.format("%.1f", (double) javaTime / 3));
        
        if (nativeTime >= 0) {
            logger.info("  Native GMP (individual):  {} ms (avg {} ms/proof)", 
                    nativeTime, String.format("%.1f", (double) nativeTime / 3));
            double speedup = (double) javaTime / nativeTime;
            logger.info("  Speedup (individual):     {}x", String.format("%.2f", speedup));
        }
        
        if (nativeBatchTime >= 0) {
            logger.info("  Native GMP (batch JNI):   {} ms (avg {} ms/proof)", 
                    nativeBatchTime, String.format("%.1f", (double) nativeBatchTime / 3));
            double batchSpeedup = (double) javaTime / nativeBatchTime;
            logger.info("  Speedup (batch JNI):      {}x", String.format("%.2f", batchSpeedup));
            logger.info("");
            logger.info("  PiAffG proof time: {} ms (Java) -> {} ms (GMP batch) = {}x faster", 
                    String.format("%.0f", (double) javaTime / 3),
                    String.format("%.0f", (double) nativeBatchTime / 3),
                    String.format("%.1f", (double) javaTime / nativeBatchTime));
        }
    }
    
    private static void computeProofTupleJava(BigInteger N0sq, BigInteger N1sq, BigInteger C,
                                               BigInteger[] alphas, BigInteger[] betas,
                                               BigInteger[] rs, BigInteger[] ss, int kappa) {
        BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
        BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
        BigInteger lastAj = BigInteger.ZERO;
        BigInteger lastBj = BigInteger.ZERO;
        for (int i = 0; i < kappa; i++) {
            lastAj = C.modPow(alphas[i], N0sq)
                    .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                    .multiply(rs[i].modPow(N0sq, N0sq))
                    .mod(N0sq);
            
            lastBj = onePlusN1sq.modPow(betas[i], N1sq)
                    .multiply(ss[i].modPow(N1sq, N1sq))
                    .mod(N1sq);
        }
        if (lastAj.signum() < 0 || lastBj.signum() < 0) {
            throw new RuntimeException("Unreachable");
        }
    }
    
    private static void computeProofTupleNative(BigInteger N0sq, BigInteger N1sq, BigInteger C,
                                                 BigInteger[] alphas, BigInteger[] betas,
                                                 BigInteger[] rs, BigInteger[] ss, int kappa) {
        BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
        BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
        BigInteger lastAj = BigInteger.ZERO;
        BigInteger lastBj = BigInteger.ZERO;
        for (int i = 0; i < kappa; i++) {
            lastAj = NativeBigInteger.modPow(C, alphas[i], N0sq)
                    .multiply(NativeBigInteger.modPow(onePlusN0sq, betas[i], N0sq))
                    .multiply(NativeBigInteger.modPow(rs[i], N0sq, N0sq))
                    .mod(N0sq);
            
            lastBj = NativeBigInteger.modPow(onePlusN1sq, betas[i], N1sq)
                    .multiply(NativeBigInteger.modPow(ss[i], N1sq, N1sq))
                    .mod(N1sq);
        }
        if (lastAj.signum() < 0 || lastBj.signum() < 0) {
            throw new RuntimeException("Unreachable");
        }
    }
}
