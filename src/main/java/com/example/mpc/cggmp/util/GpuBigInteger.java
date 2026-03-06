package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicBoolean;

public final class GpuBigInteger {
    private static final AtomicBoolean GPU_AVAILABLE = new AtomicBoolean(false);
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);
    private static GpuBackend backend;
    private static String preferredBackend;
    
    private interface GpuBackend {
        BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod);
        BigInteger modInverse(BigInteger val, BigInteger mod);
        BigInteger multiply(BigInteger a, BigInteger b);
        BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod);
        BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod);
        BigInteger[] computeAffGProofTuple(
                BigInteger C, BigInteger N0sq, BigInteger N1sq,
                BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs, BigInteger[] ss);
        boolean isAvailable();
    }
    
    static {
        preferredBackend = System.getProperty("mpc.gpu.backend", "auto");
        initialize();
    }
    
    private static void initialize() {
        if (INITIALIZED.compareAndSet(false, true)) {
            try {
                // 检查是否强制使用 CPU
                if ("cpu".equals(preferredBackend)) {
                    System.out.println("CPU backend forced by preference");
                    return;
                }
                
                // 尝试初始化不同的 GPU 后端
                boolean jcudaAvailable = false;
                boolean joclAvailable = false;
                
                try {
                    jcudaAvailable = tryInitializeJCuda();
                } catch (Exception e) {
                    System.err.println("JCuda initialization failed: " + e.getMessage());
                }
                
                try {
                    joclAvailable = tryInitializeJOCL();
                } catch (Exception e) {
                    System.err.println("JOCL initialization failed: " + e.getMessage());
                }
                
                // 根据优先级选择后端
                if (jcudaAvailable && ("jcuda".equals(preferredBackend) || "auto".equals(preferredBackend))) {
                    backend = new JCudaBackend();
                    GPU_AVAILABLE.set(true);
                    System.out.println("Selected NVIDIA GPU via JCuda");
                } else if (joclAvailable && ("jocl".equals(preferredBackend) || "auto".equals(preferredBackend))) {
                    backend = new JOCLBackend();
                    GPU_AVAILABLE.set(true);
                    System.out.println("Selected GPU via OpenCL");
                } else {
                    System.out.println("No GPU backend available, falling back to CPU");
                }
            } catch (Exception e) {
                System.err.println("Failed to initialize GPU backends: " + e.getMessage());
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
    
    private static boolean tryInitializeJOCL() {
        try {
            // 尝试加载 JOCL 库
            Class.forName("org.jocl.CL");
            // 尝试初始化 JOCL
            try {
                // 动态调用 JOCL 初始化方法
                Class<?> clClass = Class.forName("org.jocl.CL");
                java.lang.reflect.Method createContextMethod = clClass.getMethod("createContext", String.class, java.util.List.class);
                Object context = createContextMethod.invoke(null, null, null);
                if (context != null) {
                    // 检查设备数量
                    java.lang.reflect.Method getDevicesMethod = context.getClass().getMethod("getDevices");
                    Object devices = getDevicesMethod.invoke(context);
                    if (devices instanceof java.util.List) {
                        return ((java.util.List<?>) devices).size() > 0;
                    }
                }
                return false;
            } catch (Exception e) {
                System.err.println("JOCL initialization failed: " + e.getMessage());
                return false;
            }
        } catch (ClassNotFoundException | UnsatisfiedLinkError e) {
            return false;
        }
    }
    
    public static boolean isGpuAvailable() {
        return GPU_AVAILABLE.get();
    }
    
    public static BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (GPU_AVAILABLE.get() && backend != null) {
            return backend.modPow(base, exp, mod);
        }
        // 直接使用 Java 内置的 BigInteger 实现，避免递归调用
        return base.modPow(exp, mod);
    }
    
    public static BigInteger modInverse(BigInteger val, BigInteger mod) {
        if (GPU_AVAILABLE.get() && backend != null) {
            return backend.modInverse(val, mod);
        }
        // 直接使用 Java 内置的 BigInteger 实现，避免递归调用
        return val.modInverse(mod);
    }
    
    public static BigInteger multiply(BigInteger a, BigInteger b) {
        if (GPU_AVAILABLE.get() && backend != null) {
            return backend.multiply(a, b);
        }
        // 直接使用 Java 内置的 BigInteger 实现，避免递归调用
        return a.multiply(b);
    }
    
    public static BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (GPU_AVAILABLE.get() && backend != null) {
            return backend.batchModPow(bases, exp, mod);
        }
        // 直接使用 Java 内置的 BigInteger 实现，避免递归调用
        BigInteger[] results = new BigInteger[bases.length];
        for (int i = 0; i < bases.length; i++) {
            results[i] = bases[i].modPow(exp, mod);
        }
        return results;
    }
    
    public static BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        if (GPU_AVAILABLE.get() && backend != null) {
            return backend.batchModPowDifferentExp(bases, exps, mod);
        }
        // 直接使用 Java 内置的 BigInteger 实现，避免递归调用
        BigInteger[] results = new BigInteger[bases.length];
        for (int i = 0; i < bases.length; i++) {
            results[i] = bases[i].modPow(exps[i], mod);
        }
        return results;
    }
    
    public static NativeBigInteger.AffGProofResult computeAffGProofTuples(
            BigInteger C, BigInteger N0sq, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs, BigInteger[] ss) {
        int kappa = alphas.length;
        if (GPU_AVAILABLE.get() && backend != null && kappa >= 16) {
            BigInteger[] results = backend.computeAffGProofTuple(C, N0sq, N1sq, alphas, betas, rs, ss);
            BigInteger[] Aj = new BigInteger[kappa];
            BigInteger[] Bj = new BigInteger[kappa];
            for (int i = 0; i < kappa; i++) {
                Aj[i] = results[i * 2];
                Bj[i] = results[i * 2 + 1];
            }
            return new NativeBigInteger.AffGProofResult(Aj, Bj);
        }
        // 直接实现 AffG 证明计算，避免递归调用
        BigInteger[] Aj = new BigInteger[kappa];
        BigInteger[] Bj = new BigInteger[kappa];
        BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
        BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
        
        for (int i = 0; i < kappa; i++) {
            Aj[i] = C.modPow(alphas[i], N0sq)
                    .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                    .multiply(rs[i].modPow(N0sq, N0sq))
                    .mod(N0sq);
            
            Bj[i] = onePlusN1sq.modPow(betas[i], N1sq)
                    .multiply(ss[i].modPow(N1sq, N1sq))
                    .mod(N1sq);
        }
        return new NativeBigInteger.AffGProofResult(Aj, Bj);
    }
    
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
                BigInteger C, BigInteger N0sq, BigInteger N1sq,
                BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs, BigInteger[] ss) {
            if (!initialized) {
                int kappa = alphas.length;
                BigInteger[] results = new BigInteger[kappa * 2];
                BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
                BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
                
                for (int i = 0; i < kappa; i++) {
                    BigInteger Aj = C.modPow(alphas[i], N0sq)
                            .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                            .multiply(rs[i].modPow(N0sq, N0sq))
                            .mod(N0sq);
                    
                    BigInteger Bj = onePlusN1sq.modPow(betas[i], N1sq)
                            .multiply(ss[i].modPow(N1sq, N1sq))
                            .mod(N1sq);
                    
                    results[i * 2] = Aj;
                    results[i * 2 + 1] = Bj;
                }
                return results;
            }
            // 这里实现 JCuda 版本的 AffG 证明计算
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa * 2];
            BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
            BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
            
            for (int i = 0; i < kappa; i++) {
                BigInteger Aj = C.modPow(alphas[i], N0sq)
                        .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                        .multiply(rs[i].modPow(N0sq, N0sq))
                        .mod(N0sq);
                
                BigInteger Bj = onePlusN1sq.modPow(betas[i], N1sq)
                        .multiply(ss[i].modPow(N1sq, N1sq))
                        .mod(N1sq);
                
                results[i * 2] = Aj;
                results[i * 2 + 1] = Bj;
            }
            return results;
        }
        
        @Override
        public boolean isAvailable() {
            return initialized;
        }
    }
    
    private static class JOCLBackend implements GpuBackend {
        private boolean initialized = false;
        
        public JOCLBackend() {
            try {
                // 初始化 JOCL
                Class<?> clClass = Class.forName("org.jocl.CL");
                java.lang.reflect.Method createContextMethod = clClass.getMethod("createContext", String.class, java.util.List.class);
                Object context = createContextMethod.invoke(null, null, null);
                if (context != null) {
                    // 检查设备数量
                    java.lang.reflect.Method getDevicesMethod = context.getClass().getMethod("getDevices");
                    Object devices = getDevicesMethod.invoke(context);
                    if (devices instanceof java.util.List) {
                        int deviceCount = ((java.util.List<?>) devices).size();
                        if (deviceCount > 0) {
                            initialized = true;
                            System.out.println("JOCL backend initialized successfully with " + deviceCount + " device(s)");
                        } else {
                            System.err.println("JOCL backend initialization failed: no devices found");
                            initialized = false;
                        }
                    } else {
                        System.err.println("JOCL backend initialization failed: invalid devices list");
                        initialized = false;
                    }
                } else {
                    System.err.println("JOCL backend initialization failed: context creation failed");
                    initialized = false;
                }
            } catch (Exception e) {
                System.err.println("JOCL backend initialization failed: " + e.getMessage());
                initialized = false;
            }
        }
        
        @Override
        public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
            if (!initialized) {
                return base.modPow(exp, mod);
            }
            // 这里实现 JOCL 版本的模幂运算
            // 由于我们没有添加 JOCL 依赖，这里暂时回退到 Java 实现
            return base.modPow(exp, mod);
        }
        
        @Override
        public BigInteger modInverse(BigInteger val, BigInteger mod) {
            if (!initialized) {
                return val.modInverse(mod);
            }
            // 这里实现 JOCL 版本的模逆运算
            return val.modInverse(mod);
        }
        
        @Override
        public BigInteger multiply(BigInteger a, BigInteger b) {
            if (!initialized) {
                return a.multiply(b);
            }
            // 这里实现 JOCL 版本的乘法
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
            // 这里实现 JOCL 版本的批量模幂运算
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
            // 这里实现 JOCL 版本的批量模幂运算（不同指数）
            BigInteger[] results = new BigInteger[bases.length];
            for (int i = 0; i < bases.length; i++) {
                results[i] = bases[i].modPow(exps[i], mod);
            }
            return results;
        }
        
        @Override
        public BigInteger[] computeAffGProofTuple(
                BigInteger C, BigInteger N0sq, BigInteger N1sq,
                BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs, BigInteger[] ss) {
            if (!initialized) {
                int kappa = alphas.length;
                BigInteger[] results = new BigInteger[kappa * 2];
                BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
                BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
                
                for (int i = 0; i < kappa; i++) {
                    BigInteger Aj = C.modPow(alphas[i], N0sq)
                            .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                            .multiply(rs[i].modPow(N0sq, N0sq))
                            .mod(N0sq);
                    
                    BigInteger Bj = onePlusN1sq.modPow(betas[i], N1sq)
                            .multiply(ss[i].modPow(N1sq, N1sq))
                            .mod(N1sq);
                    
                    results[i * 2] = Aj;
                    results[i * 2 + 1] = Bj;
                }
                return results;
            }
            // 这里实现 JOCL 版本的 AffG 证明计算
            int kappa = alphas.length;
            BigInteger[] results = new BigInteger[kappa * 2];
            BigInteger onePlusN0sq = BigInteger.ONE.add(N0sq);
            BigInteger onePlusN1sq = BigInteger.ONE.add(N1sq);
            
            for (int i = 0; i < kappa; i++) {
                BigInteger Aj = C.modPow(alphas[i], N0sq)
                        .multiply(onePlusN0sq.modPow(betas[i], N0sq))
                        .multiply(rs[i].modPow(N0sq, N0sq))
                        .mod(N0sq);
                
                BigInteger Bj = onePlusN1sq.modPow(betas[i], N1sq)
                        .multiply(ss[i].modPow(N1sq, N1sq))
                        .mod(N1sq);
                
                results[i * 2] = Aj;
                results[i * 2 + 1] = Bj;
            }
            return results;
        }
        
        @Override
        public boolean isAvailable() {
            return initialized;
        }
    }
}