package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.stream.IntStream;

/**
 * Java后端实现 - 使用Java内置BigInteger进行大整数运算
 * 作为GMP不可用时的备选方案
 */
public final class JavaBackend implements BigIntegerBackend {
    private static final JavaBackend INSTANCE = new JavaBackend();

    private JavaBackend() {
    }

    public static JavaBackend getInstance() {
        return INSTANCE;
    }

    /**
     * 模幂运算: base^exp mod mod
     * 使用Java内置的modPow方法
     */
    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return base.modPow(exp, mod);
    }

    /**
     * 模逆元: 计算val在模mod下的乘法逆元
     * 即 find x, s.t. val * x ≡ 1 (mod mod)
     * 使用扩展欧几里得算法
     */
    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        return val.modInverse(mod);
    }

    /**
     * 模乘法: a * b mod mod
     */
    @Override
    public BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return a.multiply(b).mod(mod);
    }

    /**
     * 批量模幂运算: 对多个base使用相同exp进行模幂
     * 使用并行流提高性能
     */
    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exp, mod))
                .toArray(BigInteger[]::new);
    }

    /**
     * 批量模幂运算: 对多个base使用不同exp进行模幂
     * 使用并行流提高性能
     */
    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have the same length");
        }
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger[][] batchModPowAll(
            BigInteger[] bases1, BigInteger[] bases2, BigInteger[] bases3,
            BigInteger[] bases4, BigInteger[] bases5,
            BigInteger[] exps1, BigInteger[] exps2, BigInteger[] exps3,
            BigInteger[] exps4, BigInteger[] exps5,
            BigInteger mod1, BigInteger mod2, BigInteger mod3,
            BigInteger mod4, BigInteger mod5) {

        BigInteger[][] results = new BigInteger[5][];
        results[0] = (bases1 != null && exps1 != null && mod1 != null) ? batchModPow(bases1, exps1, mod1) : null;
        results[1] = (bases2 != null && exps2 != null && mod2 != null) ? batchModPow(bases2, exps2, mod2) : null;
        results[2] = (bases3 != null && exps3 != null && mod3 != null) ? batchModPow(bases3, exps3, mod3) : null;
        results[3] = (bases4 != null && exps4 != null && mod4 != null) ? batchModPow(bases4, exps4, mod4) : null;
        results[4] = (bases5 != null && exps5 != null && mod5 != null) ? batchModPow(bases5, exps5, mod5) : null;
        return results;
    }

    /**
     * 批量模运算: 对多个val取模
     * 使用并行流提高性能
     */
    @Override
    public BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        return IntStream.range(0, vals.length)
                .parallel()
                .mapToObj(i -> vals[i].mod(mod))
                .toArray(BigInteger[]::new);
    }

    /**
     * 中国剩余定理(CRT): 合并两个同余方程
     * x ≡ a (mod p), x ≡ b (mod q) -> x mod n (n=p*q)
     * 使用 Garner 算法实现
     */
    @Override
    public BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        BigInteger t = b.subtract(a).mod(q);
        BigInteger ip = p.modInverse(q);
        BigInteger k = t.multiply(ip).mod(q);
        BigInteger x = a.add(k.multiply(p));
        return (x.signum() < 0 || x.compareTo(n) >= 0) ? x.mod(n) : x;
    }

    /**
     * Jacobi符号: (a/n)
     * 用于判断a是否是n的二次剩余
     * 返回值: 1 (二次剩余), -1 (非二次剩余), 0 (n整除a)
     * 实现基于二进制算法
     */
    @Override
    public int jacobi(BigInteger a, BigInteger n) {
        if (n.signum() <= 0 || !n.testBit(0)) {
            throw new IllegalArgumentException("n must be positive and odd");
        }
        a = a.mod(n);
        int result = 1;
        while (a.signum() != 0) {
            while (!a.testBit(0)) {
                a = a.shiftRight(1);
                BigInteger nMod8 = n.and(BigInteger.valueOf(7));
                if (nMod8.equals(BigInteger.valueOf(3)) || nMod8.equals(BigInteger.valueOf(5))) {
                    result = -result;
                }
            }
            BigInteger temp = a;
            a = n;
            n = temp;
            if (a.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3)) && n.and(BigInteger.valueOf(3)).equals(BigInteger.valueOf(3))) {
                result = -result;
            }
            a = a.mod(n);
        }
        return n.equals(BigInteger.ONE) ? result : 0;
    }

    /**
     * 批量Jacobi符号计算
     * 串行计算每个as[i]相对于n的Jacobi符号
     */
    @Override
    public int[] batchJacobi(BigInteger[] as, BigInteger n) {
        int[] results = new int[as.length];
        for (int i = 0; i < as.length; i++) {
            results[i] = jacobi(as[i], n);
        }
        return results;
    }

    /**
     * 生成可能素数: 使用Miller-Rabin概率素性检测
     * @param bitLength 指定素数的比特长度
     * @param random 随机数生成器
     */
    @Override
    public BigInteger probablePrime(int bitLength, SecureRandom random) {
        return BigInteger.probablePrime(bitLength, random);
    }

    /**
     * 检查是否使用GMP原生后端
     * Java后端始终返回false
     */
    @Override
    public boolean isNative() {
        return false;
    }
}
