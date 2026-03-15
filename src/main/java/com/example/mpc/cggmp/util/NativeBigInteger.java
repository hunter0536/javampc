package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.stream.IntStream;

public final class NativeBigInteger {
    private static final Logger logger = LoggerFactory.getLogger(NativeBigInteger.class);
    private static final boolean NATIVE_AVAILABLE;
    private static final int MODULUS_THRESHOLD = 2048;

    static {
        NATIVE_AVAILABLE = loadNativeLibrary();
        logger.info("NativeBigInteger initialized, GMP available: {}", NATIVE_AVAILABLE);
    }

    private NativeBigInteger() {
    }

    private static boolean loadNativeLibrary() {
        String libName = System.mapLibraryName("mpc_gmp");

        try (InputStream libStream = NativeBigInteger.class.getResourceAsStream("/native/gmp/" + libName)) {
            if (libStream != null) {
                return loadFromClasspath(libStream, libName);
            }
            return loadFromSystem(libName);
        } catch (UnsatisfiedLinkError e) {
            logger.warn("Native GMP library not available: {}", e.getMessage());
            return false;
        } catch (IOException e) {
            logger.warn("Failed to load native library: {}", e.getMessage());
            return false;
        }
    }

    private static boolean loadFromClasspath(InputStream libStream, String libName) throws IOException {
        Path tempDir = Files.createTempDirectory("mpc_native");
        Path tempLib = tempDir.resolve(libName);
        Files.copy(libStream, tempLib, StandardCopyOption.REPLACE_EXISTING);

        tempLib.toFile().deleteOnExit();
        tempDir.toFile().deleteOnExit();

        System.load(tempLib.toAbsolutePath().toString());
        logger.debug("GMP library loaded from classpath");
        return true;
    }

    private static boolean loadFromSystem(String libName) {
        System.loadLibrary("mpc_gmp");
        logger.debug("GMP library loaded from system path: {}", libName);
        return true;
    }

    public static boolean isNativeAvailable() {
        return NATIVE_AVAILABLE;
    }

    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return nativeModPow(base, exp, mod);
    }

    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        return nativeModInverse(val, mod);
    }

    public static BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return nativeModMul(a, b, mod);
    }

    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (mod.bitLength() < MODULUS_THRESHOLD) {
            return IntStream.range(0, bases.length)
                    .parallel()
                    .mapToObj(i -> bases[i].modPow(exp, mod))
                    .toArray(BigInteger[]::new);
        }

        byte[][] baseBytes = new byte[bases.length][];
        for (int i = 0; i < bases.length; i++) {
            baseBytes[i] = bases[i].toByteArray();
        }
        byte[] expBytes = exp.toByteArray();
        byte[] modBytes = mod.toByteArray();

        byte[][] resultBytes = nativeBatchModPowOptimized(baseBytes, expBytes, modBytes);

        BigInteger[] results = new BigInteger[resultBytes.length];
        for (int i = 0; i < resultBytes.length; i++) {
            results[i] = new BigInteger(resultBytes[i]);
        }
        return results;
    }

    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have the same length");
        }
        if (mod.bitLength() < MODULUS_THRESHOLD) {
            return IntStream.range(0, bases.length)
                    .parallel()
                    .mapToObj(i -> bases[i].modPow(exps[i], mod))
                    .toArray(BigInteger[]::new);
        }

        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> nativeModPow(bases[i], exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    private static native BigInteger nativeModPow(BigInteger base, BigInteger exp, BigInteger mod);

    private static native BigInteger nativeModInverse(BigInteger val, BigInteger mod);

    private static native BigInteger nativeModMul(BigInteger a, BigInteger b, BigInteger mod);

    private static native byte[][] nativeBatchModPowOptimized(byte[][] baseBytes, byte[] expBytes, byte[] modBytes);

    public static boolean[] verifyAffGBatch(
            BigInteger C, BigInteger[] z_arr,
            BigInteger onePlusN0, BigInteger[] zPrimeForN0_arr,
            BigInteger[] w_arr, BigInteger N0,
            BigInteger D, boolean[] e_arr,
            BigInteger[] A_arr, BigInteger N0sq) {

        int n = z_arr.length;
        boolean[] results = new boolean[n];

        try {
            byte[] C_bytes = C.toByteArray();
            byte[][] z_bytes = toByteArrays(z_arr);
            byte[] onePlusN0_bytes = onePlusN0.toByteArray();
            byte[][] zPrimeForN0_bytes = toByteArrays(zPrimeForN0_arr);
            byte[][] w_bytes = toByteArrays(w_arr);
            byte[] N0_bytes = N0.toByteArray();
            byte[] D_bytes = D.toByteArray();
            byte[][] A_bytes = toByteArrays(A_arr);
            byte[] N0sq_bytes = N0sq.toByteArray();

            byte[] nativeResults = nativeVerifyAffGBatchV3(
                    C_bytes, z_bytes, onePlusN0_bytes, zPrimeForN0_bytes,
                    w_bytes, N0_bytes, D_bytes, e_arr, A_bytes, N0sq_bytes, n);

            if (nativeResults != null && nativeResults.length == n) {
                for (int i = 0; i < n; i++) {
                    results[i] = (nativeResults[i] != 0);
                }
            } else {
                for (int i = 0; i < n; i++) {
                    results[i] = false;
                }
            }
        } catch (Exception ex) {
            for (int i = 0; i < n; i++) {
                results[i] = false;
            }
        }

        return results;
    }

    private static byte[][] toByteArrays(BigInteger[] arr) {
        byte[][] result = new byte[arr.length][];
        for (int i = 0; i < arr.length; i++) {
            result[i] = arr[i].toByteArray();
        }
        return result;
    }

    private static native byte[] nativeVerifyAffGBatchV3(
            byte[] C, byte[][] z_arr, byte[] onePlusN0,
            byte[][] zPrimeForN0_arr, byte[][] w_arr, byte[] N0,
            byte[] D, boolean[] e_arr, byte[][] A_arr, byte[] N0sq, int n);

    private static native byte[] nativeVerifyAffGBatchV2(
            byte[] C, byte[] z_packed, byte[] onePlusN0,
            byte[] zPrimeForN0_packed, byte[] w_packed, byte[] N0,
            byte[] D, boolean[] e_arr, byte[] A_packed, byte[] N0sq, int n);

    private static native byte[] nativeVerifyAffGBatch(
            byte[] C, byte[][] z_arr, byte[] onePlusN0,
            byte[][] zPrimeForN0_arr, byte[][] w_arr, byte[] N0,
            byte[] D, boolean[] e_arr, byte[][] A_arr, byte[] N0sq);

    public static BigInteger[][] batchModPowAll(
            BigInteger[] bases1, BigInteger[] bases2, BigInteger[] bases3,
            BigInteger[] bases4, BigInteger[] bases5,
            BigInteger[] exps1, BigInteger[] exps2, BigInteger[] exps3,
            BigInteger[] exps4, BigInteger[] exps5,
            BigInteger mod1, BigInteger mod2, BigInteger mod3,
            BigInteger mod4, BigInteger mod5) {
        
        BigInteger[][] results = new BigInteger[5][];
        
        BigInteger[] r0 = (bases1 != null && exps1 != null && mod1 != null) ? batchModPow(bases1, exps1, mod1) : null;
        BigInteger[] r1 = (bases2 != null && exps2 != null && mod2 != null) ? batchModPow(bases2, exps2, mod2) : null;
        BigInteger[] r2 = (bases3 != null && exps3 != null && mod3 != null) ? batchModPow(bases3, exps3, mod3) : null;
        BigInteger[] r3 = (bases4 != null && exps4 != null && mod4 != null) ? batchModPow(bases4, exps4, mod4) : null;
        BigInteger[] r4 = (bases5 != null && exps5 != null && mod5 != null) ? batchModPow(bases5, exps5, mod5) : null;
        
        results[0] = r0;
        results[1] = r1;
        results[2] = r2;
        results[3] = r3;
        results[4] = r4;
        
        return results;
    }

    private static BigInteger[] computeBatch(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    private static byte[][] toByteArray(BigInteger[] arr) {
        byte[][] result = new byte[arr.length][];
        for (int i = 0; i < arr.length; i++) {
            result[i] = arr[i].toByteArray();
        }
        return result;
    }

    private static native byte[][][] nativeBatchModPowAll(
            byte[][][] baseBytes, byte[][][] expBytes, byte[][] modBytes);

    private static native int nativeJacobi(byte[] aBytes, byte[] nBytes);

    private static native int[] nativeBatchJacobi(byte[][] aBytes, byte[] nBytes);

    private static native byte[][] nativeBatchMod(byte[][] valsBytes, byte[] modBytes);

    private static native byte[] nativeCrt(byte[] aBytes, byte[] pBytes, byte[] bBytes, byte[] qBytes, byte[] nBytes);

    private static native byte[] nativeProbablePrime(int bitLength, byte[] seedBytes);

    public static BigInteger probablePrime(int bitLength, SecureRandom random) {
        byte[] seed = new byte[32];
        random.nextBytes(seed);
        byte[] resultBytes = nativeProbablePrime(bitLength, seed);
        return new BigInteger(resultBytes);
    }

    public static int jacobi(BigInteger a, BigInteger n) {
        return nativeJacobi(a.toByteArray(), n.toByteArray());
    }

    public static BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        byte[][] valsBytes = new byte[vals.length][];
        for (int i = 0; i < vals.length; i++) {
            valsBytes[i] = vals[i].toByteArray();
        }
        byte[] modBytes = mod.toByteArray();

        byte[][] resultBytes = nativeBatchMod(valsBytes, modBytes);

        BigInteger[] results = new BigInteger[resultBytes.length];
        for (int i = 0; i < resultBytes.length; i++) {
            results[i] = new BigInteger(resultBytes[i]);
        }
        return results;
    }

    public static BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        byte[] resultBytes = nativeCrt(a.toByteArray(), p.toByteArray(), b.toByteArray(), q.toByteArray(), n.toByteArray());
        return new BigInteger(resultBytes);
    }

    public static int[] batchJacobi(BigInteger[] as, BigInteger n) {
        byte[][] aBytes = new byte[as.length][];
        for (int i = 0; i < as.length; i++) {
            aBytes[i] = as[i].toByteArray();
        }
        byte[] nBytes = n.toByteArray();

        return nativeBatchJacobi(aBytes, nBytes);
    }
}
