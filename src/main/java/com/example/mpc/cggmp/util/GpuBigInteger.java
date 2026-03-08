package com.example.mpc.cggmp.util;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class GpuBigInteger {
    private static final Logger logger = LoggerFactory.getLogger(GpuBigInteger.class);
    private static final AtomicBoolean GPU_AVAILABLE = new AtomicBoolean(false);
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);
    private static GpuBackend backend;
    private static String preferredBackend;
    
    public interface GpuBackend {
        BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod);
        BigInteger modInverse(BigInteger val, BigInteger mod);
        BigInteger multiply(BigInteger a, BigInteger b);
        BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);
        BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod);
        BigInteger[] computeAffGProofTuple(
                BigInteger C, BigInteger N0, BigInteger N0sq, BigInteger N1, BigInteger N1sq,
                BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss);
        BigInteger[] computeDecProofTuple(
                BigInteger K, BigInteger N0, BigInteger N0sq,
                BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs);
        boolean isAvailable();
    }
    
    static {
        logger.debug("GpuBigInteger static initialization started");
        preferredBackend = System.getProperty("mpc.gpu.backend", "auto");
        logger.debug("Preferred GPU backend: {}", preferredBackend);
        
        // 检查是否启用GPU加速
        String gpuEnabled = System.getProperty("app.cggmp.gpu.enabled", "true");
        logger.debug("GPU enabled: {}", gpuEnabled);
        
        // 检查是否启用GMP加速
        String gmpEnabled = System.getProperty("app.cggmp.gmp.enabled", "true");
        logger.debug("GMP enabled: {}", gmpEnabled);
        
        if (Boolean.parseBoolean(gpuEnabled)) {
            loadNativeLibraries();
            initialize();
        } else {
            logger.debug("GPU acceleration is disabled via system property");
        }
        
        logger.debug("GpuBigInteger static initialization completed, GPU_AVAILABLE={}, backend={}", GPU_AVAILABLE.get(), backend);
    }
    
    // 检查是否启用GMP加速
    private static boolean isGmpEnabled() {
        String gmpEnabled = System.getProperty("app.cggmp.gmp.enabled", "true");
        return Boolean.parseBoolean(gmpEnabled);
    }
    
    private static void loadNativeLibraries() {
        // Metal不需要预加载native库，由MetalBigIntegerBackend自己加载
        logger.debug("Metal backend will load native libraries on demand");
    }
    
    private static void initialize() {
        if (INITIALIZED.compareAndSet(false, true)) {
            logger.debug("GpuBigInteger initialization started");
            try {
                // 检查是否强制使用 CPU
                if ("cpu".equals(preferredBackend)) {
                    logger.debug("CPU backend forced by preference");
                    return;
                }
                
                // 尝试初始化不同的 GPU 后端
                boolean jcudaAvailable = false;
                MetalBigIntegerBackend metalBackend = null;
                
                try {
                    jcudaAvailable = tryInitializeJCuda();
                    logger.debug("JCuda initialization result: {}", jcudaAvailable);
                } catch (Exception e) {
                    logger.error("JCuda initialization failed: {}", e.getMessage());
                    logger.error("Exception stack trace:", e);
                }
                
                // 尝试Metal后端（仅macOS）
                String osName = System.getProperty("os.name", "").toLowerCase();
                if (osName.contains("mac")) {
                    try {
                        metalBackend = tryInitializeMetal();
                        logger.debug("Metal initialization result: {}", metalBackend != null);
                    } catch (Exception e) {
                        logger.error("Metal initialization failed: {}", e.getMessage());
                        logger.error("Exception stack trace:", e);
                    }
                }
                
                // 根据优先级选择后端
                if (jcudaAvailable && ("jcuda".equals(preferredBackend) || "auto".equals(preferredBackend))) {
                    backend = new JCudaBackend();
                    GPU_AVAILABLE.set(true);
                    logger.debug("Selected NVIDIA GPU via JCuda");
                } else if (metalBackend != null && ("metal".equals(preferredBackend) || "auto".equals(preferredBackend))) {
                    backend = metalBackend;
                    GPU_AVAILABLE.set(true);
                    logger.debug("Selected Apple Silicon GPU via Metal");
                } else {
                    logger.debug("No GPU backend available, falling back to CPU");
                }
            } catch (Exception e) {
                logger.error("Failed to initialize GPU backends: {}", e.getMessage());
                logger.error("Exception stack trace:", e);
            }
        }
    }
    
    private static boolean tryInitializeJCuda() {
        try {
            // 尝试加载 JCuda 库
            Class.forName("org.jcuda.driver.JCudaDriver");
            // 尝试初始化 JCuda
            try {
                // 动态调用 JCuda 初始化方法
                Class<?> jcudaDriverClass = Class.forName("org.jcuda.driver.JCudaDriver");
                java.lang.reflect.Method initMethod = jcudaDriverClass.getMethod("init");
                initMethod.invoke(null);
                // 检查设备数量
                java.lang.reflect.Method getDeviceCountMethod = jcudaDriverClass.getMethod("getDeviceCount");
                int deviceCount = (int) getDeviceCountMethod.invoke(null);
                return deviceCount > 0;
            } catch (Exception e) {
                System.err.println("JCuda initialization failed: " + e.getMessage());
                return false;
            }
        } catch (ClassNotFoundException | UnsatisfiedLinkError e) {
            return false;
        }
    }
    
    private static MetalBigIntegerBackend tryInitializeMetal() {
        try {
            logger.debug("Metal initialization: Creating MetalBigIntegerBackend instance");
            MetalBigIntegerBackend instance = new MetalBigIntegerBackend();
            boolean available = instance.isAvailable();
            logger.debug("Metal initialization: Backend available: {}", available);
            if (available) {
                logger.info("Metal GPU device detected: {}", instance.getDeviceName());
            }
            return available ? instance : null;
        } catch (UnsatisfiedLinkError e) {
            logger.error("Metal initialization: UnsatisfiedLinkError - native library not loaded: {}", e.getMessage());
            logger.error("Exception stack trace:", e);
            return null;
        } catch (Exception e) {
            logger.error("Metal initialization failed: {}", e.getMessage());
            logger.error("Exception stack trace:", e);
            return null;
        }
    }
    
    
    public static boolean isGpuAvailable() {
        return GPU_AVAILABLE.get();
    }
    
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        // 第一层：GMP加速（对于单个操作，GMP通常比GPU更快）
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                return NativeBigInteger.nativeModPow(base, exp, mod);
            } catch (Exception e) {
                logger.warn("GMP native modPow failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第二层：Java BigInteger
        return base.modPow(exp, mod);
    }
    
    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        // 第一层：GMP加速（对于单个操作，GMP通常比GPU更快）
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                return NativeBigInteger.nativeModInverse(val, mod);
            } catch (Exception e) {
                logger.warn("GMP native modInverse failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第二层：Java BigInteger
        return val.modInverse(mod);
    }
    
    public static BigInteger multiply(BigInteger a, BigInteger b) {
        // 第一层：GMP加速（对于单个操作，GMP通常比GPU更快）
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                return NativeBigInteger.nativeMultiply(a, b);
            } catch (Exception e) {
                logger.warn("GMP native multiply failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第二层：Java BigInteger
        return a.multiply(b);
    }
    
    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        // 第一层：GPU加速（仅当批量大小足够大时）
        if (GPU_AVAILABLE.get() && backend != null && bases.length >= 16) {
            try {
                return backend.batchModPow(bases, exp, mod);
            } catch (Exception e) {
                logger.warn("GPU batchModPow failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第二层：GMP加速
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                return NativeBigInteger.nativeBatchModPow(bases, exp, mod);
            } catch (Exception e) {
                logger.warn("GMP native batchModPow failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第三层：Java并行流
        return java.util.Arrays.stream(bases)
            .parallel()
            .map(base -> base.modPow(exp, mod))
            .toArray(BigInteger[]::new);
    }
    
    public static BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        // 第一层：GPU加速（仅当批量大小足够大时）
        if (GPU_AVAILABLE.get() && backend != null && bases.length >= 16) {
            try {
                return backend.batchModPowDifferentExp(bases, exps, mod);
            } catch (Exception e) {
                logger.warn("GPU batchModPowDifferentExp failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第二层：GMP加速
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                return NativeBigInteger.nativeBatchModPowDifferentExp(bases, exps, mod);
            } catch (Exception e) {
                logger.warn("GMP native batchModPowDifferentExp failed, falling back to Java: {}", e.getMessage());
            }
        }
        // 第三层：Java并行流
        return java.util.stream.IntStream.range(0, bases.length)
            .parallel()
            .mapToObj(i -> bases[i].modPow(exps[i], mod))
            .toArray(BigInteger[]::new);
    }
    
    public static NativeBigInteger.AffGProofResult computeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq, BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1, BigInteger[] rs, BigInteger[] ss) {
        int kappa = alphas.length;
        BigInteger N0 = N0sq.sqrt();
        BigInteger N1 = N1sq.sqrt();
        
        // 第一层：GPU加速
        if (GPU_AVAILABLE.get() && backend != null && kappa >= 16) {
            BigInteger[] results = backend.computeAffGProofTuple(C, N0, N0sq, N1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
            BigInteger[] Aj = new BigInteger[kappa];
            BigInteger[] Bj = new BigInteger[kappa];
            for (int i = 0; i < kappa; i++) {
                Aj[i] = results[i * 2];
                Bj[i] = results[i * 2 + 1];
            }
            return new NativeBigInteger.AffGProofResult(Aj, Bj);
        }
        
        // 第二层：GMP加速
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                BigInteger[] results = NativeBigInteger.nativeAffGProofTuple(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
                BigInteger[] Aj = new BigInteger[kappa];
                BigInteger[] Bj = new BigInteger[kappa];
                for (int i = 0; i < kappa; i++) {
                    Aj[i] = results[i * 2];
                    Bj[i] = results[i * 2 + 1];
                }
                return new NativeBigInteger.AffGProofResult(Aj, Bj);
            } catch (Exception e) {
                logger.warn("GMP native AffG proof failed, falling back to Java: {}", e.getMessage());
            }
        }
        
        // 第三层：Java并行流（修复bug：使用正确的onePlusN0和onePlusN1）
        BigInteger[] Aj = new BigInteger[kappa];
        BigInteger[] Bj = new BigInteger[kappa];
        
        java.util.stream.IntStream.range(0, kappa)
            .parallel()
            .forEach(i -> {
                Aj[i] = BigIntegerUtils.powSigned(C, alphas[i], N0sq)
                        .multiply(BigIntegerUtils.powSigned(onePlusN0, betasForN0[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);
                
                Bj[i] = BigIntegerUtils.powSigned(onePlusN1, betasForN1[i], N1sq)
                        .multiply(ss[i].modPow(N1, N1sq))
                        .mod(N1sq);
            });
        
        return new NativeBigInteger.AffGProofResult(Aj, Bj);
    }
    
    public static DecProofResult computeDecProofTuples(
            BigInteger K, BigInteger N0, BigInteger N0sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs) {
        int kappa = alphas.length;
        
        // 第一层：GPU加速
        if (GPU_AVAILABLE.get() && backend != null && kappa >= 16) {
            BigInteger[] results = backend.computeDecProofTuple(K, N0, N0sq, alphas, betas, rs);
            BigInteger[] A = new BigInteger[kappa];
            for (int i = 0; i < kappa; i++) {
                A[i] = results[i];
            }
            return new DecProofResult(A);
        }
        
        // 第二层：GMP加速
        if (isGmpEnabled() && NativeBigInteger.isNativeAvailable()) {
            try {
                BigInteger[] results = NativeBigInteger.nativeDecProofTuple(K, N0, N0sq, alphas, betas, rs);
                BigInteger[] A = new BigInteger[kappa];
                for (int i = 0; i < kappa; i++) {
                    A[i] = results[i];
                }
                return new DecProofResult(A);
            } catch (Exception e) {
                logger.warn("GMP native Dec proof failed, falling back to Java: {}", e.getMessage());
            }
        }
        
        // 第三层：Java并行流
        BigInteger[] A = new BigInteger[kappa];
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        
        java.util.stream.IntStream.range(0, kappa)
            .parallel()
            .forEach(i -> {
                A[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                        .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);
            });
        
        return new DecProofResult(A);
    }
    
    public record DecProofResult(BigInteger[] A) {}
    
    // 内部实现类，用于不同的 GPU 后端
    private static class JCudaBackend implements GpuBackend {
        private boolean initialized = false;
        
        public JCudaBackend() {
            try {
                // 初始化 JCuda
                Class<?> jcudaDriverClass = Class.forName("org.jcuda.driver.JCudaDriver");
                java.lang.reflect.Method initMethod = jcudaDriverClass.getMethod("init");
                initMethod.invoke(null);
                // 检查设备数量
                java.lang.reflect.Method getDeviceCountMethod = jcudaDriverClass.getMethod("getDeviceCount");
                int deviceCount = (int) getDeviceCountMethod.invoke(null);
                if (deviceCount > 0) {
                    initialized = true;
                    System.out.println("JCuda backend initialized successfully with " + deviceCount + " device(s)");
                } else {
                    System.err.println("JCuda backend initialization failed: no devices found");
                    initialized = false;
                }
            } catch (Exception e) {
                System.err.println("JCuda backend initialization failed: " + e.getMessage());
                initialized = false;
            }
        }
        
        @Override
        public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
            if (!initialized) {
                return base.modPow(exp, mod);
            }
            // 这里实现 JCuda 版本的模幂运算
            // 由于我们没有添加 JCuda 依赖，这里暂时回退到 Java 实现
            return base.modPow(exp, mod);
        }
        
        @Override
        public BigInteger modInverse(BigInteger val, BigInteger mod) {
            if (!initialized) {
                return val.modInverse(mod);
            }
            // 这里实现 JCuda 版本的模逆运算
            return val.modInverse(mod);
        }
        
        @Override
        public BigInteger multiply(BigInteger a, BigInteger b) {
            if (!initialized) {
                return a.multiply(b);
            }
            // 这里实现 JCuda 版本的乘法
            return a.multiply(b);
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
            // 这里实现 JCuda 版本的批量模幂运算
            BigInteger[] results = new BigInteger[bases.length];
            for (int i = 0; i < bases.length; i++) {
                results[i] = bases[i].modPow(exp, mod);
            }
            return results;
        }
        
        @Override
        public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
            if (!initialized) {
                BigInteger[] results = new BigInteger[bases.length];
                for (int i = 0; i < bases.length; i++) {
                    results[i] = bases[i].modPow(exps[i], mod);
                }
                return results;
            }
            // 这里实现 JCuda 版本的批量模幂运算（不同指数）
            BigInteger[] results = new BigInteger[bases.length];
            for (int i = 0; i < bases.length; i++) {
                results[i] = bases[i].modPow(exps[i], mod);
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
                
                for (int i = 0; i < kappa; i++) {
                    BigInteger Aj = C.modPow(alphas[i], N0sq)
                            .multiply(onePlusN0.modPow(betasForN0[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                    
                    BigInteger Bj = onePlusN1.modPow(betasForN1[i], N1sq)
                            .multiply(ss[i].modPow(N1, N1sq))
                            .mod(N1sq);
                    
                    results[i * 2] = Aj;
                    results[i * 2 + 1] = Bj;
                }
                return results;
            }
            // 这里实现 JCuda 版本的 AffG 证明计算
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa * 2];
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            BigInteger onePlusN1 = BigInteger.ONE.add(N1);
            
            for (int i = 0; i < kappa; i++) {
                BigInteger Aj = C.modPow(alphas[i], N0sq)
                        .multiply(onePlusN0.modPow(betasForN0[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);
                
                BigInteger Bj = onePlusN1.modPow(betasForN1[i], N1sq)
                        .multiply(ss[i].modPow(N1, N1sq))
                        .mod(N1sq);
                
                results[i * 2] = Aj;
                results[i * 2 + 1] = Bj;
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
                
                for (int i = 0; i < kappa; i++) {
                    results[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                            .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                            .multiply(rs[i].modPow(N0, N0sq))
                            .mod(N0sq);
                }
                return results;
            }
            // 这里实现 JCuda 版本的 Dec 证明计算
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa];
            BigInteger onePlusN0 = BigInteger.ONE.add(N0);
            
            for (int i = 0; i < kappa; i++) {
                results[i] = BigIntegerUtils.powSigned(K, alphas[i].negate(), N0sq)
                        .multiply(BigIntegerUtils.powSigned(onePlusN0, betas[i], N0sq))
                        .multiply(rs[i].modPow(N0, N0sq))
                        .mod(N0sq);
            }
            return results;
        }
        
        @Override
        public boolean isAvailable() {
            return initialized;
        }
    }
}
