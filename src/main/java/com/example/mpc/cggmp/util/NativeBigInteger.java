package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class NativeBigInteger {
    private static final Logger logger = LoggerFactory.getLogger(NativeBigInteger.class);
    private static final boolean NATIVE_AVAILABLE;
    
    static {
        logger.info("NativeBigInteger static initialization started");
        boolean available = false;
        try {
            String libName = System.mapLibraryName("mpc_gmp");
            logger.info("Attempting to load native library: {}", libName);
            
            InputStream libStream = NativeBigInteger.class.getResourceAsStream("/native/gmp/" + libName);
            if (libStream != null) {
                logger.info("Native library found in classpath: /native/gmp/{}", libName);
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
        } catch (IOException e) {
            logger.error("Failed to extract native library: {}", e.getMessage());
        }
        NATIVE_AVAILABLE = available;
        logger.info("NativeBigInteger static initialization completed, NATIVE_AVAILABLE={}", NATIVE_AVAILABLE);
    }
    
    public static boolean isNativeAvailable() {
        return NATIVE_AVAILABLE;
    }
    
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (NATIVE_AVAILABLE) {
            return nativeModPow(base, exp, mod);
        }
        return base.modPow(exp, mod);
    }
    
    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        if (NATIVE_AVAILABLE) {
            return nativeModInverse(val, mod);
        }
        return val.modInverse(mod);
    }
    
    public static BigInteger multiply(BigInteger a, BigInteger b) {
        if (NATIVE_AVAILABLE) {
            return nativeMultiply(a, b);
        }
        return a.multiply(b);
    }
    
    public static byte[] toByteArray(BigInteger val) {
        return val.toByteArray();
    }
    
    public static BigInteger fromByteArray(byte[] data) {
        return new BigInteger(data);
    }
    
    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (NATIVE_AVAILABLE) {
            return nativeBatchModPow(bases, exp, mod);
        }
        BigInteger[] result = new BigInteger[bases.length];
        for (int i = 0; i < bases.length; i++) {
            result[i] = bases[i].modPow(exp, mod);
        }
        return result;
    }
    
    public static BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (NATIVE_AVAILABLE) {
            return nativeBatchModPowDifferentExp(bases, exps, mod);
        }
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        BigInteger[] result = new BigInteger[bases.length];
        for (int i = 0; i < bases.length; i++) {
            result[i] = bases[i].modPow(exps[i], mod);
        }
        return result;
    }
    
    public static AffGProofResult computeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq, BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss) {
        if (NATIVE_AVAILABLE) {
            return nativeComputeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
        }
        return javaComputeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
    }
    
    private static native BigInteger nativeModPow(BigInteger base, BigInteger exp, BigInteger mod);
    private static native BigInteger nativeModInverse(BigInteger val, BigInteger mod);
    private static native BigInteger nativeMultiply(BigInteger a, BigInteger b);
    private static native BigInteger[] nativeBatchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);
    private static native BigInteger[] nativeBatchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod);
    private static native AffGProofResult nativeComputeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq, BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss);
    
    private static AffGProofResult javaComputeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq,
            BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1,
            BigInteger[] rs, BigInteger[] ss) {
        int kappa = alphas.length;
        BigInteger N0 = N0sq.sqrt();
        BigInteger N1 = N1sq.sqrt();
        BigInteger[] Aj = new BigInteger[kappa];
        BigInteger[] Bj = new BigInteger[kappa];

        for (int i = 0; i < kappa; i++) {
            Aj[i] = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                    .multiply(BigIntegerUtils.powSigned(onePlusN0, betasForN0[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);

            Bj[i] = BigIntegerUtils.powSigned(onePlusN1, betasForN1[i], N1sq)
                    .multiply(ss[i].modPow(N1, N1sq))
                    .mod(N1sq);
        }

        return new AffGProofResult(Aj, Bj);
    }
    
    public static class NativeModPowContext implements AutoCloseable {
        private final BigInteger mod;
        
        public NativeModPowContext(BigInteger mod) {
            this.mod = mod;
        }
        
        public BigInteger getMod() {
            return mod;
        }
        
        public BigInteger modPow(BigInteger base, BigInteger exp) {
            return base.modPow(exp, mod);
        }
        
        @Override
        public void close() {
        }
    }
}
