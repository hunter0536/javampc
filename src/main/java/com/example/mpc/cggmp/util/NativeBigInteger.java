package com.example.mpc.cggmp.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NativeBigInteger {
    private static final Logger logger = LoggerFactory.getLogger(NativeBigInteger.class);
    private static final boolean NATIVE_AVAILABLE;
    
    static {
        logger.info("NativeBigInteger static initialization started");
        boolean available = false;
        try {
            String libName = System.mapLibraryName("mpc_gmp");
            logger.info("Attempting to load native library: {}", libName);
            
            InputStream libStream = NativeBigInteger.class.getResourceAsStream("/native/cpu/" + libName);
            if (libStream != null) {
                logger.info("Native library found in classpath: /native/cpu/{}", libName);
                Path tempDir = Files.createTempDirectory("mpc_native");
                Path tempLib = tempDir.resolve(libName);
                Files.copy(libStream, tempLib, StandardCopyOption.REPLACE_EXISTING);
                libStream.close();
                
                System.load(tempLib.toAbsolutePath().toString());
                available = true;
                logger.info("Native GMP library loaded from classpath: {}", libName);
            } else {
                logger.info("Native library not found in classpath, trying system library");
                System.loadLibrary("mpc_gmp");
                available = true;
                logger.info("Native GMP library loaded from system path");
            }
        } catch (UnsatisfiedLinkError e) {
            logger.error("Native GMP library not available, falling back to Java BigInteger: {}", e.getMessage());
            logger.error("UnsatisfiedLinkError stack trace:", e);
        } catch (IOException e) {
            logger.error("Failed to extract native library: {}", e.getMessage());
            logger.error("IOException stack trace:", e);
        }
        NATIVE_AVAILABLE = available;
        logger.info("NativeBigInteger static initialization completed, NATIVE_AVAILABLE={}", NATIVE_AVAILABLE);
    }
    
    public static boolean isNativeAvailable() {
        return NATIVE_AVAILABLE;
    }
    
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.modPow(base, exp, mod);
    }
    
    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.modInverse(val, mod);
    }
    
    public static BigInteger multiply(BigInteger a, BigInteger b) {
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.multiply(a, b);
    }
    
    public static byte[] toByteArray(BigInteger val) {
        return val.toByteArray();
    }
    
    public static BigInteger fromByteArray(byte[] data) {
        return new BigInteger(data);
    }
    
    public static native BigInteger nativeModPow(BigInteger base, BigInteger exp, BigInteger mod);
    public static native BigInteger nativeModInverse(BigInteger val, BigInteger mod);
    public static native BigInteger nativeMultiply(BigInteger a, BigInteger b);
    
    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.batchModPow(bases, exp, mod);
    }
    
    public static BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.batchModPowDifferentExp(bases, exps, mod);
    }
    
    public static AffGProofResult computeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq, BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss) {
        // 使用 GpuBigInteger 作为默认实现
        return GpuBigInteger.computeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
    }
    
    public record AffGProofResult(BigInteger[] Aj, BigInteger[] Bj) {}
    
    public static native BigInteger[] nativeBatchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);
    public static native BigInteger[] nativeBatchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod);
    public static native BigInteger[] nativeAffGProofTuple(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq, BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss);
    public static native BigInteger[] nativeDecProofTuple(
            BigInteger K, BigInteger N0, BigInteger N0sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs);
    
    public static class NativeModPowContext implements AutoCloseable {
        private long nativePtr;
        private final BigInteger mod;
        private final int modBits;
        
        public NativeModPowContext(BigInteger mod) {
            this.mod = mod;
            this.modBits = mod.bitLength();
            if (NATIVE_AVAILABLE) {
                this.nativePtr = initMontgomeryContext(mod);
            }
        }
        
        public BigInteger getMod() {
            return mod;
        }
        
        public BigInteger modPow(BigInteger base, BigInteger exp) {
            if (nativePtr != 0) {
                return nativeMontgomeryModPow(nativePtr, base, exp);
            }
            return base.modPow(exp, mod);
        }
        
        @Override
        public void close() {
            if (nativePtr != 0) {
                freeMontgomeryContext(nativePtr);
                nativePtr = 0;
            }
        }
        
        private native long initMontgomeryContext(BigInteger mod);
        private native void freeMontgomeryContext(long ptr);
        private native BigInteger nativeMontgomeryModPow(long ptr, BigInteger base, BigInteger exp);
    }
}
