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
