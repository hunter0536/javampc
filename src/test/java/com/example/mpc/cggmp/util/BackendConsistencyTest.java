package com.example.mpc.cggmp.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(120)
public class BackendConsistencyTest {
    
    private static GmpBackend gmpBackend;
    private static JavaBackend javaBackend;
    private static boolean gmpAvailable;
    
    @BeforeAll
    static void setup() {
        gmpBackend = GmpBackend.getInstance();
        javaBackend = JavaBackend.getInstance();
        gmpAvailable = NativeBigInteger.isNativeAvailable();
        
        System.out.println("=".repeat(80));
        System.out.println("Backend Consistency Test");
        System.out.println("GMP Available: " + gmpAvailable);
        System.out.println("=".repeat(80));
    }
    
    @Test
    void testModPowConsistency() {
        System.out.println("\n=== Testing modPow Consistency ===");
        
        SecureRandom random = new SecureRandom();
        int[] bitLengths = {512, 1024, 2048, 3072};
        
        for (int bits : bitLengths) {
            BigInteger base = new BigInteger(bits, random);
            BigInteger exp = new BigInteger(bits / 2, random);
            BigInteger mod = BigInteger.probablePrime(bits, random);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.modPow(base, exp, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.modPow(base, exp, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, 
                    "modPow results should match for " + bits + " bits");
                
                System.out.printf("  %4d bits: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx, Match=%s%n",
                    bits, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime, javaResult.equals(gmpResult));
            } else {
                System.out.printf("  %4d bits: Java=%8.3f ms (GMP not available)%n",
                    bits, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testModInverseConsistency() {
        System.out.println("\n=== Testing modInverse Consistency ===");
        
        SecureRandom random = new SecureRandom();
        int[] bitLengths = {512, 1024, 2048, 3072};
        
        for (int bits : bitLengths) {
            BigInteger mod = BigInteger.probablePrime(bits, random);
            BigInteger val;
            do {
                val = new BigInteger(bits, random);
            } while (val.gcd(mod).compareTo(BigInteger.ONE) != 0 || val.compareTo(mod) >= 0);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.modInverse(val, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.modInverse(val, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, 
                    "modInverse results should match for " + bits + " bits");
                
                System.out.printf("  %4d bits: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx, Match=%s%n",
                    bits, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime, javaResult.equals(gmpResult));
            } else {
                System.out.printf("  %4d bits: Java=%8.3f ms (GMP not available)%n",
                    bits, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testMultiplyConsistency() {
        System.out.println("\n=== Testing multiply Consistency ===");
        
        SecureRandom random = new SecureRandom();
        int[] bitLengths = {512, 1024, 2048, 3072};
        
        for (int bits : bitLengths) {
            BigInteger a = new BigInteger(bits, random);
            BigInteger b = new BigInteger(bits, random);
            
            long javaStart = System.nanoTime();
            BigInteger javaResult = javaBackend.multiply(a, b);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger gmpResult = gmpBackend.multiply(a, b);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResult, gmpResult, 
                    "multiply results should match for " + bits + " bits");
                
                System.out.printf("  %4d bits: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx, Match=%s%n",
                    bits, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime, javaResult.equals(gmpResult));
            } else {
                System.out.printf("  %4d bits: Java=%8.3f ms (GMP not available)%n",
                    bits, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBatchModPowConsistency() {
        System.out.println("\n=== Testing batchModPow Consistency ===");
        
        SecureRandom random = new SecureRandom();
        int[] batchSizes = {10, 50, 100};
        int bits = 1024;
        
        for (int batchSize : batchSizes) {
            BigInteger[] bases = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                bases[i] = new BigInteger(bits, random);
            }
            BigInteger exp = new BigInteger(bits / 2, random);
            BigInteger mod = BigInteger.probablePrime(bits, random);
            
            long javaStart = System.nanoTime();
            BigInteger[] javaResults = javaBackend.batchModPow(bases, exp, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger[] gmpResults = gmpBackend.batchModPow(bases, exp, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResults.length, gmpResults.length, 
                    "batch sizes should match");
                
                boolean allMatch = true;
                for (int i = 0; i < javaResults.length; i++) {
                    if (!javaResults[i].equals(gmpResults[i])) {
                        allMatch = false;
                        break;
                    }
                }
                
                assertTrue(allMatch, "All batch modPow results should match");
                
                System.out.printf("  batch %3d: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx, Match=%s%n",
                    batchSize, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime, allMatch);
            } else {
                System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                    batchSize, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testBatchModPowDifferentExpConsistency() {
        System.out.println("\n=== Testing batchModPowDifferentExp Consistency ===");
        
        SecureRandom random = new SecureRandom();
        int[] batchSizes = {10, 50, 100};
        int bits = 1024;
        
        for (int batchSize : batchSizes) {
            BigInteger[] bases = new BigInteger[batchSize];
            BigInteger[] exps = new BigInteger[batchSize];
            for (int i = 0; i < batchSize; i++) {
                bases[i] = new BigInteger(bits, random);
                exps[i] = new BigInteger(bits / 2, random);
            }
            BigInteger mod = BigInteger.probablePrime(bits, random);
            
            long javaStart = System.nanoTime();
            BigInteger[] javaResults = javaBackend.batchModPowDifferentExp(bases, exps, mod);
            long javaTime = System.nanoTime() - javaStart;
            
            if (gmpAvailable) {
                long gmpStart = System.nanoTime();
                BigInteger[] gmpResults = gmpBackend.batchModPowDifferentExp(bases, exps, mod);
                long gmpTime = System.nanoTime() - gmpStart;
                
                assertEquals(javaResults.length, gmpResults.length, 
                    "batch sizes should match");
                
                boolean allMatch = true;
                for (int i = 0; i < javaResults.length; i++) {
                    if (!javaResults[i].equals(gmpResults[i])) {
                        allMatch = false;
                        break;
                    }
                }
                
                assertTrue(allMatch, "All batch modPowDifferentExp results should match");
                
                System.out.printf("  batch %3d: Java=%8.3f ms, GMP=%8.3f ms, Speedup=%.2fx, Match=%s%n",
                    batchSize, javaTime / 1_000_000.0, gmpTime / 1_000_000.0,
                    (double) javaTime / gmpTime, allMatch);
            } else {
                System.out.printf("  batch %3d: Java=%8.3f ms (GMP not available)%n",
                    batchSize, javaTime / 1_000_000.0);
            }
        }
    }
    
    @Test
    void testIsNative() {
        System.out.println("\n=== Testing isNative ===");
        
        assertFalse(javaBackend.isNative(), "JavaBackend should return false for isNative");
        
        if (gmpAvailable) {
            assertTrue(gmpBackend.isNative(), "GmpBackend should return true for isNative");
        } else {
            assertFalse(gmpBackend.isNative(), "GmpBackend should return false when GMP not available");
        }
        
        System.out.println("  JavaBackend.isNative() = " + javaBackend.isNative());
        System.out.println("  GmpBackend.isNative() = " + gmpBackend.isNative());
    }
}
