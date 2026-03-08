package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MetalBigIntegerBackend implements GpuBigInteger.GpuBackend {
    private static final Logger logger = LoggerFactory.getLogger(MetalBigIntegerBackend.class);
    private static final int BIGINT_BITS = 4096;
    private static final int R_CACHE_MAX = 64;
    private static final ThreadLocal<BatchBuffers> BATCH_BUFFERS =
            ThreadLocal.withInitial(BatchBuffers::new);
    private static final ThreadLocal<SingleBuffers> SINGLE_BUFFERS =
            ThreadLocal.withInitial(SingleBuffers::new);
    private static final ThreadLocal<DirectBuffers> DIRECT_BUFFERS =
            ThreadLocal.withInitial(DirectBuffers::new);
    private static final java.util.Map<ModKey, RPair> R_CACHE =
            new java.util.LinkedHashMap<>(R_CACHE_MAX, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(java.util.Map.Entry<ModKey, RPair> eldest) {
                    return size() > R_CACHE_MAX;
                }
            };
    
    private long nativeHandle = 0;
    private boolean initialized = false;
    private String deviceName = null;
    
    static {
        try {
            // 尝试从JAR包中加载native库
            String libName = System.mapLibraryName("metal_biginteger");
            String resourcePath = "/native/darwin/" + libName;
            
            java.io.InputStream in = MetalBigIntegerBackend.class.getResourceAsStream(resourcePath);
            if (in != null) {
                // 从JAR包中加载
                java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("metal_native");
                java.nio.file.Path tempLib = tempDir.resolve(libName);
                java.nio.file.Files.copy(in, tempLib, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                in.close();
                
                System.load(tempLib.toAbsolutePath().toString());
                logger.debug("MetalBigIntegerBackend: Native library loaded from JAR: {}", libName);
            } else {
                // 尝试从系统路径加载
                System.loadLibrary("metal_biginteger");
                logger.debug("MetalBigIntegerBackend: Native library loaded from system path");
            }
        } catch (Exception e) {
            logger.error("MetalBigIntegerBackend: Failed to load native library: {}", e.getMessage());
        }
    }
    
    public MetalBigIntegerBackend() {
        try {
            logger.debug("MetalBigIntegerBackend: Calling nativeInit()");
            String shaderPath = extractShaderToTemp();
            if (shaderPath != null) {
                nativeHandle = nativeInitWithShaderPath(shaderPath);
                logger.debug("MetalBigIntegerBackend: nativeInitWithShaderPath() returned handle: {}", nativeHandle);
            } else {
                nativeHandle = nativeInit();
                logger.debug("MetalBigIntegerBackend: nativeInit() returned handle: {}", nativeHandle);
            }
            
            if (nativeHandle != 0) {
                boolean available = nativeIsAvailable(nativeHandle);
                logger.debug("MetalBigIntegerBackend: nativeIsAvailable() returned: {}", available);
                initialized = available;
                if (initialized) {
                    deviceName = nativeGetDeviceName(nativeHandle);
                    logger.debug("MetalBigIntegerBackend: GPU device name: {}", deviceName);
                }
            } else {
                logger.warn("MetalBigIntegerBackend: nativeInit() returned 0, initialization failed");
                initialized = false;
            }
            
            if (initialized) {
                logger.debug("MetalBigIntegerBackend: Initialized successfully");
            } else {
                logger.warn("MetalBigIntegerBackend: Initialization failed");
            }
        } catch (Exception e) {
            logger.error("MetalBigIntegerBackend: Initialization error: {}", e.getMessage(), e);
            initialized = false;
        }
    }

    private String extractShaderToTemp() {
        // 直接从JAR中提取metallib文件
        String resourcePath = "/native/darwin/big_integer_shaders_complete.metallib";
        try (InputStream in = MetalBigIntegerBackend.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                logger.debug("MetalBigIntegerBackend: Shader resource not found in classpath: {}", resourcePath);
                return null;
            }
            java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("metal_shader");
            java.nio.file.Path tempFile = tempDir.resolve("big_integer_shaders_complete.metallib");
            java.nio.file.Files.copy(in, tempFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            logger.debug("MetalBigIntegerBackend: Shader extracted from JAR to {}", tempFile);
            return tempFile.toAbsolutePath().toString();
        } catch (Exception e) {
            logger.warn("MetalBigIntegerBackend: Failed to extract shader: {}", e.getMessage());
            return null;
        }
    }
    
    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (!initialized) {
            return BigIntegerUtils.powSigned(base, exp, mod);
        }
        if (mod.bitLength() > BIGINT_BITS) {
            return BigIntegerUtils.powSigned(base, exp, mod);
        }
        if (exp.signum() < 0) {
            try {
                base.modInverse(mod);
            } catch (ArithmeticException e) {
                return BigIntegerUtils.powSigned(base, exp, mod);
            }
        }
        
        int numLength = getNumLength(mod);
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer basesBuffer = directBuffers.ensureBases(numLength);
        java.nio.ByteBuffer expsBuffer = directBuffers.ensureExps(numLength);
        java.nio.ByteBuffer modsBuffer = directBuffers.ensureMods(numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureResults(numLength);
        java.nio.ByteBuffer baseInvsBuffer = null;
        if (exp.signum() < 0) {
            baseInvsBuffer = directBuffers.ensureBaseInvs(numLength);
        }
        writeBigIntegerToIntBuffer(base, basesBuffer, 0, numLength);
        writeBigIntegerToIntBuffer(exp, expsBuffer, 0, numLength);
        writeBigIntegerToIntBuffer(mod, modsBuffer, 0, numLength);
        if (exp.signum() < 0) {
            BigInteger baseInv = base.modInverse(mod);
            writeBigIntegerToIntBuffer(baseInv, baseInvsBuffer, 0, numLength);
        }
        RPair rPair = getRPair(mod, numLength);
        
        long startTime = System.currentTimeMillis();
        boolean ok;
        if (exp.signum() < 0) {
            ok = nativeModPowSignedDirect(nativeHandle, basesBuffer, baseInvsBuffer, expsBuffer, modsBuffer, rPair.r, rPair.r2, resultsBuffer, numLength, 1);
        } else {
            ok = nativeModPowDirect(nativeHandle, basesBuffer, expsBuffer, modsBuffer, rPair.r, rPair.r2, resultsBuffer, numLength, 1);
        }
        if (!ok) {
            SingleBuffers singleBuffers = SINGLE_BUFFERS.get();
            int[] basesArray = singleBuffers.ensureBases(numLength);
            int[] expsArray = singleBuffers.ensureExps(numLength);
            int[] modsArray = singleBuffers.ensureMods(numLength);
            int[] resultsArray = singleBuffers.ensureResults(numLength);
            int[] baseInvsArray = null;
            if (exp.signum() < 0) {
                baseInvsArray = singleBuffers.ensureBaseInvs(numLength);
            }
            writeBigIntegerToIntArray(base, basesArray, 0, numLength);
            writeBigIntegerToIntArray(exp, expsArray, 0, numLength);
            writeBigIntegerToIntArray(mod, modsArray, 0, numLength);
            if (exp.signum() < 0) {
                BigInteger baseInv = base.modInverse(mod);
                writeBigIntegerToIntArray(baseInv, baseInvsArray, 0, numLength);
                nativeModPowSigned(nativeHandle, basesArray, baseInvsArray, expsArray, modsArray, rPair.r, rPair.r2, resultsArray, numLength, 1);
            } else {
                nativeModPow(nativeHandle, basesArray, expsArray, modsArray, rPair.r, rPair.r2, resultsArray, numLength, 1);
            }
            long endTime = System.currentTimeMillis();
            if (endTime - startTime > 100) {
                logger.debug("MetalBigIntegerBackend: modPow completed in {} ms (GPU)", endTime - startTime);
            }
            return intArrayToBigInteger(resultsArray, 0, numLength);
        }
        long endTime = System.currentTimeMillis();
        
        if (endTime - startTime > 100) {
            logger.debug("MetalBigIntegerBackend: modPow completed in {} ms (GPU)", endTime - startTime);
        }
        
        return intBufferToBigInteger(resultsBuffer, 0, numLength);
    }
    
    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        if (!initialized) {
            return val.modInverse(mod);
        }
        if (mod.bitLength() > BIGINT_BITS) {
            return val.modInverse(mod);
        }
        
        int numLength = getNumLength(mod);
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer valuesBuffer = directBuffers.ensureValues(numLength);
        java.nio.ByteBuffer modsBuffer = directBuffers.ensureMods(numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureResults(numLength);
        writeBigIntegerToIntBuffer(val, valuesBuffer, 0, numLength);
        writeBigIntegerToIntBuffer(mod, modsBuffer, 0, numLength);
        RPair rPair = getRPair(mod, numLength);
        boolean ok = nativeModInverseDirect(nativeHandle, valuesBuffer, modsBuffer, rPair.r, rPair.r2, resultsBuffer, numLength, 1);
        if (!ok) {
            SingleBuffers singleBuffers = SINGLE_BUFFERS.get();
            int[] valuesArray = singleBuffers.ensureValues(numLength);
            int[] modsArray = singleBuffers.ensureMods(numLength);
            int[] resultsArray = singleBuffers.ensureResults(numLength);
            writeBigIntegerToIntArray(val, valuesArray, 0, numLength);
            writeBigIntegerToIntArray(mod, modsArray, 0, numLength);
            nativeModInverse(nativeHandle, valuesArray, modsArray, rPair.r, rPair.r2, resultsArray, numLength, 1);
            return intArrayToBigInteger(resultsArray, 0, numLength);
        }
        
        return intBufferToBigInteger(resultsBuffer, 0, numLength);
    }
    
    @Override
    public BigInteger multiply(BigInteger a, BigInteger b) {
        if (!initialized) {
            return a.multiply(b);
        }
        if (Math.max(a.bitLength(), b.bitLength()) > BIGINT_BITS) {
            return a.multiply(b);
        }
        
        int numLength = Math.max(getNumLength(a), getNumLength(b));
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer aBuffer = directBuffers.ensureBases(numLength);
        java.nio.ByteBuffer bBuffer = directBuffers.ensureExps(numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureResults(numLength * 2);
        writeBigIntegerToIntBuffer(a, aBuffer, 0, numLength);
        writeBigIntegerToIntBuffer(b, bBuffer, 0, numLength);
        
        boolean ok = nativeMultiplyDirect(nativeHandle, aBuffer, bBuffer, resultsBuffer, numLength, 1);
        if (!ok) {
            SingleBuffers singleBuffers = SINGLE_BUFFERS.get();
            int[] aArray = singleBuffers.ensureBases(numLength);
            int[] bArray = singleBuffers.ensureExps(numLength);
            int[] resultsArray = singleBuffers.ensureResults(numLength * 2);
            writeBigIntegerToIntArray(a, aArray, 0, numLength);
            writeBigIntegerToIntArray(b, bArray, 0, numLength);
            nativeMultiply(nativeHandle, aArray, bArray, resultsArray, numLength, 1);
            return intArrayToBigInteger(resultsArray, 0, numLength * 2);
        }
        
        return intBufferToBigInteger(resultsBuffer, 0, numLength * 2);
    }
    
    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (!initialized) {
            BigInteger[] results = new BigInteger[bases.length];
            for (int i = 0; i < bases.length; i++) {
                results[i] = bases[i].modPow(exp, mod);
            }
            return results;
        }
        
        int kappa = bases.length;
        BigInteger[] results = new BigInteger[kappa];
        int numLength = getNumLength(mod);
        if (mod.bitLength() > BIGINT_BITS) {
            for (int i = 0; i < kappa; i++) {
                results[i] = bases[i].modPow(exp, mod);
            }
            return results;
        }

        RPair rPair = getRPair(mod, numLength);
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer basesBuffer = directBuffers.ensureBases(kappa * numLength);
        java.nio.ByteBuffer expBuffer = directBuffers.ensureExps(numLength);
        java.nio.ByteBuffer modBuffer = directBuffers.ensureMods(numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureResults(kappa * numLength);
        java.nio.IntBuffer basesIntBuffer = basesBuffer.asIntBuffer();
        for (int i = 0; i < kappa; i++) {
            writeBigIntegerToIntBuffer(bases[i], basesIntBuffer, i * numLength, numLength);
        }
        writeBigIntegerToIntBuffer(exp, expBuffer, 0, numLength);
        writeBigIntegerToIntBuffer(mod, modBuffer, 0, numLength);
        
        long startTime = System.currentTimeMillis();
        boolean ok = nativeBatchModPowDirect(nativeHandle, basesBuffer, expBuffer, modBuffer, rPair.r, rPair.r2, resultsBuffer, numLength, kappa);
        if (!ok) {
            BatchBuffers buffers = BATCH_BUFFERS.get();
            int[] basesArray = buffers.ensureBases(kappa * numLength);
            int[] expArray = buffers.ensureExp(numLength);
            int[] modArray = buffers.ensureMod(numLength);
            writeBigIntegerToIntArray(exp, expArray, 0, numLength);
            writeBigIntegerToIntArray(mod, modArray, 0, numLength);
            
            for (int i = 0; i < kappa; i++) {
                writeBigIntegerToIntArray(bases[i], basesArray, i * numLength, numLength);
            }
            
            int[] resultsArray = buffers.ensureResults(kappa * numLength);
            nativeBatchModPow(nativeHandle, basesArray, expArray, modArray, rPair.r, rPair.r2, resultsArray, numLength, kappa);
            long endTime = System.currentTimeMillis();
            logger.debug("MetalBigIntegerBackend: batchModPow completed for {} bases in {} ms (GPU)",
                    bases.length, endTime - startTime);
            
            for (int i = 0; i < kappa; i++) {
                results[i] = intArrayToBigInteger(resultsArray, i * numLength, numLength);
            }
            return results;
        }
        long endTime = System.currentTimeMillis();
        logger.debug("MetalBigIntegerBackend: batchModPow completed for {} bases in {} ms (GPU)",
                bases.length, endTime - startTime);
        
        for (int i = 0; i < kappa; i++) {
            results[i] = intBufferToBigInteger(resultsBuffer, i * numLength, numLength);
        }
        
        return results;
    }
    
    @Override
    public BigInteger[] computeDecProofTuple(
            BigInteger K, BigInteger N0, BigInteger N0sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs) {
        
        if (!initialized) {
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa];
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            
            java.util.stream.IntStream.range(0, kappa)
                .parallel()
                .forEach(i -> {
                    results[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                            .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                });
            return results;
        }
        
        int kappa = alphas.length;
        BigInteger[] results = new BigInteger[kappa];
        int numLength = getNumLength(N0sq);
        if (N0sq.bitLength() > BIGINT_BITS) {
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            java.util.stream.IntStream.range(0, kappa)
                .parallel()
                .forEach(i -> {
                    results[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                            .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                });
            return results;
        }
        
        SingleBuffers singleBuffers = SINGLE_BUFFERS.get();
        int[] kArray = singleBuffers.ensureK(numLength);
        int[] n0Array = singleBuffers.ensureN0(numLength);
        int[] n0sqArray = singleBuffers.ensureN0sq(numLength);
        int[] kInvArray = singleBuffers.ensureKInv(numLength);
        int[] onePlusN0InvArray = singleBuffers.ensureOnePlusN0Inv(numLength);
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger kInv = K.modInverse(N0sq);
        BigInteger onePlusN0Inv = onePlusN0.modInverse(N0sq);
        writeBigIntegerToIntArray(K, kArray, 0, numLength);
        writeBigIntegerToIntArray(N0, n0Array, 0, numLength);
        writeBigIntegerToIntArray(N0sq, n0sqArray, 0, numLength);
        writeBigIntegerToIntArray(kInv, kInvArray, 0, numLength);
        writeBigIntegerToIntArray(onePlusN0Inv, onePlusN0InvArray, 0, numLength);
        RPair rPair = getRPair(N0sq, numLength);
        
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer negAlphasBuffer = directBuffers.ensureNegAlphas(kappa * numLength);
        java.nio.ByteBuffer betasBuffer = directBuffers.ensureDecBetas(kappa * numLength);
        java.nio.ByteBuffer rsBuffer = directBuffers.ensureDecRs(kappa * numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureDecResults(kappa * numLength);
        java.nio.IntBuffer negAlphasIntBuffer = negAlphasBuffer.asIntBuffer();
        java.nio.IntBuffer betasIntBuffer = betasBuffer.asIntBuffer();
        java.nio.IntBuffer rsIntBuffer = rsBuffer.asIntBuffer();
        
        for (int i = 0; i < kappa; i++) {
            int offset = i * numLength;
            BigInteger negAlpha = alphas[i].negate();
            writeBigIntegerToIntBuffer(negAlpha, negAlphasIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(betas[i], betasIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(rs[i], rsIntBuffer, offset, numLength);
        }
        
        boolean ok = nativeComputeDecProofTupleDirect(nativeHandle, kArray, n0Array, n0sqArray,
                kInvArray, onePlusN0InvArray, rPair.r, rPair.r2,
                negAlphasBuffer, betasBuffer, rsBuffer,
                resultsBuffer, numLength, kappa);
        if (!ok) {
            BatchBuffers buffers = BATCH_BUFFERS.get();
            int[] negAlphasArray = buffers.ensureNegAlphas(kappa * numLength);
            int[] betasArray = buffers.ensureBetas(kappa * numLength);
            int[] rsArray = buffers.ensureRs(kappa * numLength);
            
            for (int i = 0; i < kappa; i++) {
                BigInteger negAlpha = alphas[i].negate();
                writeBigIntegerToIntArray(negAlpha, negAlphasArray, i * numLength, numLength);
                writeBigIntegerToIntArray(betas[i], betasArray, i * numLength, numLength);
                writeBigIntegerToIntArray(rs[i], rsArray, i * numLength, numLength);
            }
            
            int[] resultsArray = buffers.ensureResults(kappa * numLength);
            nativeComputeDecProofTuple(nativeHandle, kArray, n0Array, n0sqArray,
                    kInvArray, onePlusN0InvArray, rPair.r, rPair.r2,
                    negAlphasArray, betasArray, rsArray,
                    resultsArray, numLength, kappa);
            
            for (int i = 0; i < kappa; i++) {
                results[i] = intArrayToBigInteger(resultsArray, i * numLength, numLength);
            }
            return results;
        }
        
        for (int i = 0; i < kappa; i++) {
            results[i] = intBufferToBigInteger(resultsBuffer, i * numLength, numLength);
        }
        
        return results;
    }
    
    @Override
    public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (!initialized) {
            BigInteger[] results = new BigInteger[bases.length];
            for (int i = 0; i < bases.length; i++) {
                results[i] = BigIntegerUtils.powSigned(bases[i], exps[i], mod);
            }
            return results;
        }
        
        int kappa = bases.length;
        BigInteger[] results = new BigInteger[kappa];
        int numLength = getNumLength(mod);
        if (mod.bitLength() > BIGINT_BITS) {
            for (int i = 0; i < kappa; i++) {
                results[i] = BigIntegerUtils.powSigned(bases[i], exps[i], mod);
            }
            return results;
        }

        RPair rPair = getRPair(mod, numLength);
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer basesBuffer = directBuffers.ensureBases(kappa * numLength);
        java.nio.ByteBuffer expsBuffer = directBuffers.ensureExps(kappa * numLength);
        java.nio.ByteBuffer modsBuffer = directBuffers.ensureMods(kappa * numLength);
        java.nio.ByteBuffer resultsBuffer = directBuffers.ensureResults(kappa * numLength);
        java.nio.ByteBuffer baseInvsBuffer = directBuffers.ensureBaseInvs(kappa * numLength);
        java.nio.IntBuffer basesIntBuffer = basesBuffer.asIntBuffer();
        java.nio.IntBuffer expsIntBuffer = expsBuffer.asIntBuffer();
        java.nio.IntBuffer modsIntBuffer = modsBuffer.asIntBuffer();
        java.nio.IntBuffer baseInvsIntBuffer = baseInvsBuffer.asIntBuffer();
        boolean hasNegativeExp = false;
        for (int i = 0; i < kappa; i++) {
            int offset = i * numLength;
            writeBigIntegerToIntBuffer(bases[i], basesIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(exps[i], expsIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(mod, modsIntBuffer, offset, numLength);
            if (exps[i].signum() < 0) {
                hasNegativeExp = true;
                try {
                    BigInteger baseInv = bases[i].modInverse(mod);
                    writeBigIntegerToIntBuffer(baseInv, baseInvsIntBuffer, offset, numLength);
                } catch (ArithmeticException e) {
                    for (int j = 0; j < kappa; j++) {
                        results[j] = BigIntegerUtils.powSigned(bases[j], exps[j], mod);
                    }
                    return results;
                }
            }
        }
        
        boolean ok;
        if (hasNegativeExp) {
            ok = nativeBatchModPowDifferentExpSignedDirect(nativeHandle, basesBuffer, baseInvsBuffer, expsBuffer, modsBuffer,
                    rPair.r, rPair.r2, resultsBuffer, numLength, kappa);
        } else {
            ok = nativeBatchModPowDifferentExpDirect(nativeHandle, basesBuffer, expsBuffer, modsBuffer,
                    rPair.r, rPair.r2, resultsBuffer, numLength, kappa);
        }
        if (!ok) {
            BatchBuffers buffers = BATCH_BUFFERS.get();
            int[] basesArray = buffers.ensureBases(kappa * numLength);
            int[] expsArray = buffers.ensureExps(kappa * numLength);
            int[] modsArray = buffers.ensureMods(kappa * numLength);
            int[] baseInvsArray = buffers.ensureBaseInvs(kappa * numLength);
            int[] modArray = buffers.ensureMod(numLength);
            writeBigIntegerToIntArray(mod, modArray, 0, numLength);
            
            for (int i = 0; i < kappa; i++) {
                writeBigIntegerToIntArray(bases[i], basesArray, i * numLength, numLength);
                writeBigIntegerToIntArray(exps[i], expsArray, i * numLength, numLength);
                System.arraycopy(modArray, 0, modsArray, i * numLength, numLength);
                if (exps[i].signum() < 0) {
                    BigInteger baseInv = bases[i].modInverse(mod);
                    writeBigIntegerToIntArray(baseInv, baseInvsArray, i * numLength, numLength);
                }
            }
            
            int[] resultsArray = buffers.ensureResults(kappa * numLength);
            if (hasNegativeExp) {
                nativeBatchModPowDifferentExpSigned(nativeHandle, basesArray, baseInvsArray, expsArray, modsArray,
                        rPair.r, rPair.r2, resultsArray, numLength, kappa);
            } else {
                nativeBatchModPowDifferentExp(nativeHandle, basesArray, expsArray, modsArray,
                        rPair.r, rPair.r2, resultsArray, numLength, kappa);
            }
            
            for (int i = 0; i < kappa; i++) {
                results[i] = intArrayToBigInteger(resultsArray, i * numLength, numLength);
            }
            return results;
        }
        
        for (int i = 0; i < kappa; i++) {
            results[i] = intBufferToBigInteger(resultsBuffer, i * numLength, numLength);
        }
        
        return results;
    }
    
    @Override
    public BigInteger[] computeAffGProofTuple(
            BigInteger C, BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss) {
        
        if (!initialized) {
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa * 2];
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            BigInteger onePlusN1 = BigInteger.ONE.add(N1);
            
            java.util.stream.IntStream.range(0, kappa)
                .parallel()
                .forEach(i -> {
                    BigInteger Aj = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                            .multiply(BigIntegerUtils.powSigned(onePlusN0, betasForN0[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                    
                    BigInteger Bj = BigIntegerUtils.powSigned(onePlusN1, betasForN1[i], N1sq)
                            .multiply(ss[i].modPow(N1, N1sq))
                            .mod(N1sq);
                    
                    results[i * 2] = Aj;
                    results[i * 2 + 1] = Bj;
                });
            
            return results;
        }
        
        int kappa = alphas.length;
        BigInteger[] results = new BigInteger[kappa * 2];
        int numLength = getNumLength(N0sq);
        if (N0sq.bitLength() > BIGINT_BITS || N1sq.bitLength() > BIGINT_BITS) {
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            BigInteger onePlusN1 = BigInteger.ONE.add(N1);
            java.util.stream.IntStream.range(0, kappa)
                .parallel()
                .forEach(i -> {
                    BigInteger Aj = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                            .multiply(BigIntegerUtils.powSigned(onePlusN0, betasForN0[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                    
                    BigInteger Bj = BigIntegerUtils.powSigned(onePlusN1, betasForN1[i], N1sq)
                            .multiply(ss[i].modPow(N1, N1sq))
                            .mod(N1sq);
                    
                    results[i * 2] = Aj;
                    results[i * 2 + 1] = Bj;
                });
            return results;
        }
        
        SingleBuffers singleBuffers = SINGLE_BUFFERS.get();
        int[] cArray = singleBuffers.ensureC(numLength);
        int[] n0Array = singleBuffers.ensureN0(numLength);
        int[] n0sqArray = singleBuffers.ensureN0sq(numLength);
        int[] n1Array = singleBuffers.ensureN1(numLength);
        int[] n1sqArray = singleBuffers.ensureN1sq(numLength);
        int[] cInvArray = singleBuffers.ensureCInv(numLength);
        int[] onePlusN0InvArray = singleBuffers.ensureOnePlusN0Inv(numLength);
        int[] onePlusN1InvArray = singleBuffers.ensureOnePlusN1Inv(numLength);
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger onePlusN1 = BigInteger.ONE.add(N1);
        BigInteger cInv = C.modInverse(N0sq);
        BigInteger onePlusN0Inv = onePlusN0.modInverse(N0sq);
        BigInteger onePlusN1Inv = onePlusN1.modInverse(N1sq);
        writeBigIntegerToIntArray(C, cArray, 0, numLength);
        writeBigIntegerToIntArray(N0, n0Array, 0, numLength);
        writeBigIntegerToIntArray(N0sq, n0sqArray, 0, numLength);
        writeBigIntegerToIntArray(N1, n1Array, 0, numLength);
        writeBigIntegerToIntArray(N1sq, n1sqArray, 0, numLength);
        writeBigIntegerToIntArray(cInv, cInvArray, 0, numLength);
        writeBigIntegerToIntArray(onePlusN0Inv, onePlusN0InvArray, 0, numLength);
        writeBigIntegerToIntArray(onePlusN1Inv, onePlusN1InvArray, 0, numLength);
        RPair rN0Pair = getRPair(N0sq, numLength);
        RPair rN1Pair = getRPair(N1sq, numLength);
        
        DirectBuffers directBuffers = DIRECT_BUFFERS.get();
        java.nio.ByteBuffer alphasBuffer = directBuffers.ensureAlphas(kappa * numLength);
        java.nio.ByteBuffer betasForN0Buffer = directBuffers.ensureBetasForN0(kappa * numLength);
        java.nio.ByteBuffer betasForN1Buffer = directBuffers.ensureBetasForN1(kappa * numLength);
        java.nio.ByteBuffer rsBuffer = directBuffers.ensureRs(kappa * numLength);
        java.nio.ByteBuffer ssBuffer = directBuffers.ensureSs(kappa * numLength);
        java.nio.ByteBuffer ajBuffer = directBuffers.ensureAj(kappa * numLength);
        java.nio.ByteBuffer bjBuffer = directBuffers.ensureBj(kappa * numLength);
        java.nio.IntBuffer alphasIntBuffer = alphasBuffer.asIntBuffer();
        java.nio.IntBuffer betasForN0IntBuffer = betasForN0Buffer.asIntBuffer();
        java.nio.IntBuffer betasForN1IntBuffer = betasForN1Buffer.asIntBuffer();
        java.nio.IntBuffer rsIntBuffer = rsBuffer.asIntBuffer();
        java.nio.IntBuffer ssIntBuffer = ssBuffer.asIntBuffer();
        
        for (int i = 0; i < kappa; i++) {
            int offset = i * numLength;
            writeBigIntegerToIntBuffer(alphas[i], alphasIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(betasForN0[i], betasForN0IntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(betasForN1[i], betasForN1IntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(rs[i], rsIntBuffer, offset, numLength);
            writeBigIntegerToIntBuffer(ss[i], ssIntBuffer, offset, numLength);
        }
        
        boolean ok = nativeComputeAffGProofTupleDirect(nativeHandle, cArray, n0Array, n0sqArray, n1Array, n1sqArray,
                rN0Pair.r, rN0Pair.r2, rN1Pair.r, rN1Pair.r2,
                cInvArray, onePlusN0InvArray, onePlusN1InvArray,
                alphasBuffer, betasForN0Buffer, betasForN1Buffer, rsBuffer, ssBuffer,
                ajBuffer, bjBuffer, numLength, kappa);
        
        if (!ok) {
            BatchBuffers buffers = BATCH_BUFFERS.get();
            int[] alphasArray = buffers.ensureAlphas(kappa * numLength);
            int[] betasForN0Array = buffers.ensureBetasForN0(kappa * numLength);
            int[] betasForN1Array = buffers.ensureBetasForN1(kappa * numLength);
            int[] rsArray = buffers.ensureRs(kappa * numLength);
            int[] ssArray = buffers.ensureSs(kappa * numLength);
            
            for (int i = 0; i < kappa; i++) {
                writeBigIntegerToIntArray(alphas[i], alphasArray, i * numLength, numLength);
                writeBigIntegerToIntArray(betasForN0[i], betasForN0Array, i * numLength, numLength);
                writeBigIntegerToIntArray(betasForN1[i], betasForN1Array, i * numLength, numLength);
                writeBigIntegerToIntArray(rs[i], rsArray, i * numLength, numLength);
                writeBigIntegerToIntArray(ss[i], ssArray, i * numLength, numLength);
            }
            
            int[] ajArray = buffers.ensureAj(kappa * numLength);
            int[] bjArray = buffers.ensureBj(kappa * numLength);
            nativeComputeAffGProofTuple(nativeHandle, cArray, n0Array, n0sqArray, n1Array, n1sqArray,
                    cInvArray, onePlusN0InvArray, onePlusN1InvArray,
                    rN0Pair.r, rN0Pair.r2, rN1Pair.r, rN1Pair.r2,
                    alphasArray, betasForN0Array, betasForN1Array, rsArray, ssArray,
                    ajArray, bjArray, numLength, kappa);
            
            for (int i = 0; i < kappa; i++) {
                results[i * 2] = intArrayToBigInteger(ajArray, i * numLength, numLength);
                results[i * 2 + 1] = intArrayToBigInteger(bjArray, i * numLength, numLength);
            }
            return results;
        }
        
        for (int i = 0; i < kappa; i++) {
            results[i * 2] = intBufferToBigInteger(ajBuffer, i * numLength, numLength);
            results[i * 2 + 1] = intBufferToBigInteger(bjBuffer, i * numLength, numLength);
        }
        
        return results;
    }
    
    @Override
    public boolean isAvailable() {
        return initialized;
    }

    public String getDeviceName() {
        return deviceName;
    }
    
    public void destroy() {
        if (nativeHandle != 0) {
            nativeDestroy(nativeHandle);
            nativeHandle = 0;
        }
    }
    
    private int getNumLength(BigInteger value) {
        int bitLength = value.bitLength();
        int numLength = (bitLength + 31) / 32;
        return Math.max(numLength, 128); // Minimum 4096 bits for MPC
    }

    private RPair getRPair(BigInteger mod, int numLength) {
        ModKey key = new ModKey(mod, numLength);
        synchronized (R_CACHE) {
            RPair cached = R_CACHE.get(key);
            if (cached != null) {
                return cached;
            }
        }
        BigInteger r = BigInteger.ONE.shiftLeft(BIGINT_BITS).mod(mod);
        BigInteger r2 = r.multiply(r).mod(mod);
        RPair computed = new RPair(
                bigIntegerToIntArray(r, numLength),
                bigIntegerToIntArray(r2, numLength)
        );
        synchronized (R_CACHE) {
            R_CACHE.put(key, computed);
        }
        return computed;
    }
    
    private int[] bigIntegerToIntArray(BigInteger value, int numLength) {
        int[] result = new int[numLength];
        writeBigIntegerToIntArray(value, result, 0, numLength);
        return result;
    }

    private void writeBigIntegerToIntArray(BigInteger value, int[] dest, int offset, int numLength) {
        int fill = value.signum() < 0 ? 0xFFFFFFFF : 0;
        java.util.Arrays.fill(dest, offset, offset + numLength, fill);
        
        // Get bytes in big-endian order
        byte[] bytes = value.toByteArray();
        
        // Skip the sign byte if present
        int start = (bytes.length > 0 && bytes[0] == 0) ? 1 : 0;
        if (value.signum() < 0 && bytes.length > 0 && bytes[0] == (byte)0xFF) {
            start = 1;
        }
        
        // Convert to little-endian int array
        int byteIndex = bytes.length - 1;
        int intIndex = 0;
        int bitOffset = 0;
        
        // Process each byte, starting from the least significant
        while (byteIndex >= start && intIndex < numLength) {
            byte b = bytes[byteIndex];
            
            int current = dest[offset + intIndex];
            int mask = ~(0xFF << bitOffset);
            current = (current & mask) | ((b & 0xFF) << bitOffset);
            dest[offset + intIndex] = current;
            
            // Move to the next byte
            bitOffset += 8;
            if (bitOffset >= 32) {
                bitOffset = 0;
                intIndex++;
            }
            
            byteIndex--;
        }
    }

    private void writeBigIntegerToIntBuffer(BigInteger value, java.nio.ByteBuffer buffer, int offset, int numLength) {
        java.nio.IntBuffer intBuffer = buffer.asIntBuffer();
        writeBigIntegerToIntBuffer(value, intBuffer, offset, numLength);
    }

    private void writeBigIntegerToIntBuffer(BigInteger value, java.nio.IntBuffer intBuffer, int offset, int numLength) {
        int fill = value.signum() < 0 ? 0xFFFFFFFF : 0;
        for (int i = 0; i < numLength; i++) {
            intBuffer.put(offset + i, fill);
        }
        
        byte[] bytes = value.toByteArray();
        int start = (bytes.length > 0 && bytes[0] == 0) ? 1 : 0;
        if (value.signum() < 0 && bytes.length > 0 && bytes[0] == (byte)0xFF) {
            start = 1;
        }
        int byteIndex = bytes.length - 1;
        int intIndex = 0;
        int bitOffset = 0;
        
        while (byteIndex >= start && intIndex < numLength) {
            int current = intBuffer.get(offset + intIndex);
            int mask = ~(0xFF << bitOffset);
            current = (current & mask) | ((bytes[byteIndex] & 0xFF) << bitOffset);
            intBuffer.put(offset + intIndex, current);
            
            bitOffset += 8;
            if (bitOffset >= 32) {
                bitOffset = 0;
                intIndex++;
            }
            byteIndex--;
        }
    }
    
    private BigInteger intArrayToBigInteger(int[] array) {
        return intArrayToBigInteger(array, 0, array.length);
    }

    private BigInteger intArrayToBigInteger(int[] array, int offset, int numLength) {
        int lastNonZero = -1;
        for (int i = numLength - 1; i >= 0; i--) {
            int value = array[offset + i];
            if (value != 0) {
                if ((value & 0xFF000000) != 0) {
                    lastNonZero = i * 4 + 3;
                } else if ((value & 0x00FF0000) != 0) {
                    lastNonZero = i * 4 + 2;
                } else if ((value & 0x0000FF00) != 0) {
                    lastNonZero = i * 4 + 1;
                } else {
                    lastNonZero = i * 4;
                }
                break;
            }
        }
        
        if (lastNonZero < 0) {
            return BigInteger.ZERO;
        }
        
        byte[] bigEndianBytes = new byte[lastNonZero + 1];
        for (int i = 0; i <= lastNonZero; i++) {
            int srcIndex = lastNonZero - i;
            int intIndex = srcIndex >>> 2;
            int byteOffset = srcIndex & 3;
            int value = array[offset + intIndex];
            bigEndianBytes[i] = (byte) ((value >>> (byteOffset * 8)) & 0xFF);
        }
        
        return new BigInteger(1, bigEndianBytes);
    }

    private BigInteger intBufferToBigInteger(java.nio.ByteBuffer buffer, int offset, int numLength) {
        java.nio.IntBuffer intBuffer = buffer.asIntBuffer();
        int lastNonZero = -1;
        for (int i = numLength - 1; i >= 0; i--) {
            int value = intBuffer.get(offset + i);
            if (value != 0) {
                if ((value & 0xFF000000) != 0) {
                    lastNonZero = i * 4 + 3;
                } else if ((value & 0x00FF0000) != 0) {
                    lastNonZero = i * 4 + 2;
                } else if ((value & 0x0000FF00) != 0) {
                    lastNonZero = i * 4 + 1;
                } else {
                    lastNonZero = i * 4;
                }
                break;
            }
        }
        
        if (lastNonZero < 0) {
            return BigInteger.ZERO;
        }
        
        byte[] bigEndianBytes = new byte[lastNonZero + 1];
        for (int i = 0; i <= lastNonZero; i++) {
            int srcIndex = lastNonZero - i;
            int intIndex = srcIndex >>> 2;
            int byteOffset = srcIndex & 3;
            int value = intBuffer.get(offset + intIndex);
            bigEndianBytes[i] = (byte) ((value >>> (byteOffset * 8)) & 0xFF);
        }
        
        return new BigInteger(1, bigEndianBytes);
    }

    private void writeIntArrayToIntBuffer(int[] src, java.nio.ByteBuffer buffer, int offset, int numLength) {
        java.nio.IntBuffer intBuffer = buffer.asIntBuffer();
        for (int i = 0; i < numLength; i++) {
            intBuffer.put(offset + i, src[offset + i]);
        }
    }
    
    private BigInteger[] fallbackComputeAffGProofTuple(
            BigInteger C, BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs, BigInteger[] ss) {
        
        int kappa = alphas.length;
        BigInteger[] results = new BigInteger[kappa * 2];
        
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger onePlusN1 = BigInteger.ONE.add(N1);
        
        for (int i = 0; i < kappa; i++) {
            BigInteger Aj = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                    .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);
            
            BigInteger Bj = BigIntegerUtils.powSigned(onePlusN1, betas[i], N1sq)
                    .multiply(ss[i].modPow(N1, N1sq))
                    .mod(N1sq);
            
            results[i * 2] = Aj;
            results[i * 2 + 1] = Bj;
        }
        
        return results;
    }
    
    // Native methods
    private native long nativeInit();
    private native long nativeInitWithShaderPath(String shaderPath);
    private native void nativeDestroy(long handle);
    private native boolean nativeIsAvailable(long handle);
    private native String nativeGetDeviceName(long handle);
    private native void nativeModPow(long handle, int[] bases, int[] exps, int[] mods, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeModPowDirect(long handle, java.nio.ByteBuffer bases, java.nio.ByteBuffer exps, java.nio.ByteBuffer mods, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeModPowSigned(long handle, int[] bases, int[] baseInvs, int[] exps, int[] mods, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeModPowSignedDirect(long handle, java.nio.ByteBuffer bases, java.nio.ByteBuffer baseInvs, java.nio.ByteBuffer exps, java.nio.ByteBuffer mods, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeBatchModPow(long handle, int[] bases, int[] exp, int[] mod, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeBatchModPowDirect(long handle, java.nio.ByteBuffer bases, java.nio.ByteBuffer exp, java.nio.ByteBuffer mod, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeComputeAffGProofTuple(long handle, int[] C, int[] N0, int[] N0sq, int[] N1, int[] N1sq,
            int[] C_inv, int[] onePlusN0_inv, int[] onePlusN1_inv,
            int[] rN0, int[] r2N0, int[] rN1, int[] r2N1,
            int[] alphas, int[] betasForN0, int[] betasForN1, int[] rs, int[] ss,
            int[] Aj, int[] Bj, int numLength, int kappa);
    private native boolean nativeComputeAffGProofTupleDirect(long handle, int[] C, int[] N0, int[] N0sq, int[] N1, int[] N1sq,
            int[] rN0, int[] r2N0, int[] rN1, int[] r2N1,
            int[] C_inv, int[] onePlusN0_inv, int[] onePlusN1_inv,
            java.nio.ByteBuffer alphas, java.nio.ByteBuffer betasForN0, java.nio.ByteBuffer betasForN1, java.nio.ByteBuffer rs, java.nio.ByteBuffer ss,
            java.nio.ByteBuffer Aj, java.nio.ByteBuffer Bj, int numLength, int kappa);
    private native void nativeComputeDecProofTuple(long handle, int[] K, int[] N0, int[] N0sq,
            int[] K_inv, int[] onePlusN0_inv, int[] rN0, int[] r2N0,
            int[] negAlphas, int[] betas, int[] rs,
            int[] A, int numLength, int kappa);
    private native boolean nativeComputeDecProofTupleDirect(long handle, int[] K, int[] N0, int[] N0sq,
            int[] K_inv, int[] onePlusN0_inv, int[] rN0, int[] r2N0,
            java.nio.ByteBuffer negAlphas, java.nio.ByteBuffer betas, java.nio.ByteBuffer rs,
            java.nio.ByteBuffer A, int numLength, int kappa);
    private native void nativeModInverse(long handle, int[] values, int[] mods, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeModInverseDirect(long handle, java.nio.ByteBuffer values, java.nio.ByteBuffer mods, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeMultiply(long handle, int[] a, int[] b, int[] results, int numLength, int count);
    private native boolean nativeMultiplyDirect(long handle, java.nio.ByteBuffer a, java.nio.ByteBuffer b, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeBatchModPowDifferentExp(long handle, int[] bases, int[] exps, int[] mods, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeBatchModPowDifferentExpDirect(long handle, java.nio.ByteBuffer bases, java.nio.ByteBuffer exps, java.nio.ByteBuffer mods, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);
    private native void nativeBatchModPowDifferentExpSigned(long handle, int[] bases, int[] baseInvs, int[] exps, int[] mods, int[] r, int[] r2, int[] results, int numLength, int count);
    private native boolean nativeBatchModPowDifferentExpSignedDirect(long handle, java.nio.ByteBuffer bases, java.nio.ByteBuffer baseInvs, java.nio.ByteBuffer exps, java.nio.ByteBuffer mods, int[] r, int[] r2, java.nio.ByteBuffer results, int numLength, int count);

    private static final class BatchBuffers {
        private int[] bases;
        private int[] baseInvs;
        private int[] exps;
        private int[] mods;
        private int[] results;
        private int[] exp;
        private int[] mod;
        private int[] negAlphas;
        private int[] betas;
        private int[] rs;
        private int[] alphas;
        private int[] betasForN0;
        private int[] betasForN1;
        private int[] ss;
        private int[] aj;
        private int[] bj;

        int[] ensureBases(int size) { bases = ensureCapacity(bases, size); return bases; }
        int[] ensureBaseInvs(int size) { baseInvs = ensureCapacity(baseInvs, size); return baseInvs; }
        int[] ensureExps(int size) { exps = ensureCapacity(exps, size); return exps; }
        int[] ensureMods(int size) { mods = ensureCapacity(mods, size); return mods; }
        int[] ensureResults(int size) { results = ensureCapacity(results, size); return results; }
        int[] ensureExp(int size) { exp = ensureCapacity(exp, size); return exp; }
        int[] ensureMod(int size) { mod = ensureCapacity(mod, size); return mod; }
        int[] ensureNegAlphas(int size) { negAlphas = ensureCapacity(negAlphas, size); return negAlphas; }
        int[] ensureBetas(int size) { betas = ensureCapacity(betas, size); return betas; }
        int[] ensureRs(int size) { rs = ensureCapacity(rs, size); return rs; }
        int[] ensureAlphas(int size) { alphas = ensureCapacity(alphas, size); return alphas; }
        int[] ensureBetasForN0(int size) { betasForN0 = ensureCapacity(betasForN0, size); return betasForN0; }
        int[] ensureBetasForN1(int size) { betasForN1 = ensureCapacity(betasForN1, size); return betasForN1; }
        int[] ensureSs(int size) { ss = ensureCapacity(ss, size); return ss; }
        int[] ensureAj(int size) { aj = ensureCapacity(aj, size); return aj; }
        int[] ensureBj(int size) { bj = ensureCapacity(bj, size); return bj; }
    }

    private static int[] ensureCapacity(int[] existing, int size) {
        if (existing == null || existing.length < size) {
            return new int[size];
        }
        return existing;
    }

    private static final class SingleBuffers {
        private int[] bases;
        private int[] baseInvs;
        private int[] exps;
        private int[] mods;
        private int[] values;
        private int[] results;
        private int[] c;
        private int[] cInv;
        private int[] k;
        private int[] kInv;
        private int[] n0;
        private int[] n0sq;
        private int[] onePlusN0Inv;
        private int[] n1;
        private int[] n1sq;
        private int[] onePlusN1Inv;

        int[] ensureBases(int size) { bases = ensureExact(bases, size); return bases; }
        int[] ensureBaseInvs(int size) { baseInvs = ensureExact(baseInvs, size); return baseInvs; }
        int[] ensureExps(int size) { exps = ensureExact(exps, size); return exps; }
        int[] ensureMods(int size) { mods = ensureExact(mods, size); return mods; }
        int[] ensureValues(int size) { values = ensureExact(values, size); return values; }
        int[] ensureResults(int size) { results = ensureExact(results, size); return results; }
        int[] ensureC(int size) { c = ensureExact(c, size); return c; }
        int[] ensureCInv(int size) { cInv = ensureExact(cInv, size); return cInv; }
        int[] ensureK(int size) { k = ensureExact(k, size); return k; }
        int[] ensureKInv(int size) { kInv = ensureExact(kInv, size); return kInv; }
        int[] ensureN0(int size) { n0 = ensureExact(n0, size); return n0; }
        int[] ensureN0sq(int size) { n0sq = ensureExact(n0sq, size); return n0sq; }
        int[] ensureOnePlusN0Inv(int size) { onePlusN0Inv = ensureExact(onePlusN0Inv, size); return onePlusN0Inv; }
        int[] ensureN1(int size) { n1 = ensureExact(n1, size); return n1; }
        int[] ensureN1sq(int size) { n1sq = ensureExact(n1sq, size); return n1sq; }
        int[] ensureOnePlusN1Inv(int size) { onePlusN1Inv = ensureExact(onePlusN1Inv, size); return onePlusN1Inv; }
    }

    private static final class DirectBuffers {
        private java.nio.ByteBuffer bases;
        private java.nio.ByteBuffer baseInvs;
        private java.nio.ByteBuffer exps;
        private java.nio.ByteBuffer mods;
        private java.nio.ByteBuffer values;
        private java.nio.ByteBuffer results;
        private java.nio.ByteBuffer alphas;
        private java.nio.ByteBuffer betasForN0;
        private java.nio.ByteBuffer betasForN1;
        private java.nio.ByteBuffer rs;
        private java.nio.ByteBuffer ss;
        private java.nio.ByteBuffer aj;
        private java.nio.ByteBuffer bj;
        private java.nio.ByteBuffer negAlphas;
        private java.nio.ByteBuffer decBetas;
        private java.nio.ByteBuffer decRs;
        private java.nio.ByteBuffer decResults;

        java.nio.ByteBuffer ensureBases(int numLength) { bases = ensureDirect(bases, numLength); return bases; }
        java.nio.ByteBuffer ensureBaseInvs(int numLength) { baseInvs = ensureDirect(baseInvs, numLength); return baseInvs; }
        java.nio.ByteBuffer ensureExps(int numLength) { exps = ensureDirect(exps, numLength); return exps; }
        java.nio.ByteBuffer ensureMods(int numLength) { mods = ensureDirect(mods, numLength); return mods; }
        java.nio.ByteBuffer ensureValues(int numLength) { values = ensureDirect(values, numLength); return values; }
        java.nio.ByteBuffer ensureResults(int numLength) { results = ensureDirect(results, numLength); return results; }
        java.nio.ByteBuffer ensureAlphas(int numLength) { alphas = ensureDirect(alphas, numLength); return alphas; }
        java.nio.ByteBuffer ensureBetasForN0(int numLength) { betasForN0 = ensureDirect(betasForN0, numLength); return betasForN0; }
        java.nio.ByteBuffer ensureBetasForN1(int numLength) { betasForN1 = ensureDirect(betasForN1, numLength); return betasForN1; }
        java.nio.ByteBuffer ensureRs(int numLength) { rs = ensureDirect(rs, numLength); return rs; }
        java.nio.ByteBuffer ensureSs(int numLength) { ss = ensureDirect(ss, numLength); return ss; }
        java.nio.ByteBuffer ensureAj(int numLength) { aj = ensureDirect(aj, numLength); return aj; }
        java.nio.ByteBuffer ensureBj(int numLength) { bj = ensureDirect(bj, numLength); return bj; }
        java.nio.ByteBuffer ensureNegAlphas(int numLength) { negAlphas = ensureDirect(negAlphas, numLength); return negAlphas; }
        java.nio.ByteBuffer ensureDecBetas(int numLength) { decBetas = ensureDirect(decBetas, numLength); return decBetas; }
        java.nio.ByteBuffer ensureDecRs(int numLength) { decRs = ensureDirect(decRs, numLength); return decRs; }
        java.nio.ByteBuffer ensureDecResults(int numLength) { decResults = ensureDirect(decResults, numLength); return decResults; }
    }

    private static java.nio.ByteBuffer ensureDirect(java.nio.ByteBuffer existing, int numLength) {
        int bytes = numLength * 4;
        if (existing == null || existing.capacity() < bytes) {
            return java.nio.ByteBuffer.allocateDirect(bytes).order(java.nio.ByteOrder.nativeOrder());
        }
        return existing;
    }

    private static int[] ensureExact(int[] existing, int size) {
        if (existing == null || existing.length != size) {
            return new int[size];
        }
        return existing;
    }

    private record ModKey(BigInteger mod, int numLength) {}
    private record RPair(int[] r, int[] r2) {}
}
