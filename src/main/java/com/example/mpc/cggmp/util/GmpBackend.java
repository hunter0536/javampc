package com.example.mpc.cggmp.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * GMP后端实现 - 使用GMP库进行大整数运算
 * 相比Java后端性能更高,特别是在模幂运算和Jacobi符号计算方面
 */
public final class GmpBackend implements BigIntegerBackend {
    private static final GmpBackend INSTANCE = new GmpBackend();

    private GmpBackend() {
    }

    public static GmpBackend getInstance() {
        return INSTANCE;
    }

    /**
     * 模幂运算: base^exp mod mod
     * 支持负数指数(通过模逆元转换)
     */
    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.modPow(base, exp, mod);
    }

    /**
     * 模逆元: 计算val在模mod下的乘法逆元
     * 即 find x, s.t. val * x ≡ 1 (mod mod)
     */
    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        return NativeBigInteger.modInverse(val, mod);
    }

    /**
     * 模乘法: a * b mod mod
     */
    @Override
    public BigInteger modMul(BigInteger a, BigInteger b, BigInteger mod) {
        return NativeBigInteger.modMul(a, b, mod);
    }

    /**
     * 批量模幂运算: 对多个base使用相同exp进行模幂
     * bases[i]^exp mod mod
     */
    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.batchModPow(bases, exp, mod);
    }

    /**
     * 批量模幂运算: 对多个base使用不同exp进行模幂
     * bases[i]^exps[i] mod mod
     */
    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        return NativeBigInteger.batchModPow(bases, exps, mod);
    }

    @Override
    public BigInteger[][] batchModPowAll(
            BigInteger[] bases1, BigInteger[] bases2, BigInteger[] bases3,
            BigInteger[] bases4, BigInteger[] bases5,
            BigInteger[] exps1, BigInteger[] exps2, BigInteger[] exps3,
            BigInteger[] exps4, BigInteger[] exps5,
            BigInteger mod1, BigInteger mod2, BigInteger mod3,
            BigInteger mod4, BigInteger mod5) {
        return NativeBigInteger.batchModPowAll(
                bases1, bases2, bases3, bases4, bases5,
                exps1, exps2, exps3, exps4, exps5,
                mod1, mod2, mod3, mod4, mod5);
    }

    /**
     * 批量模运算: 对多个val取模
     * vals[i] mod mod
     */
    @Override
    public BigInteger[] batchMod(BigInteger[] vals, BigInteger mod) {
        return NativeBigInteger.batchMod(vals, mod);
    }

    /**
     * 中国剩余定理(CRT): 合并两个同余方程
     * x ≡ a (mod p), x ≡ b (mod q) -> x mod n (n=p*q)
     */
    @Override
    public BigInteger crt(BigInteger a, BigInteger p, BigInteger b, BigInteger q, BigInteger n) {
        return NativeBigInteger.crt(a, p, b, q, n);
    }

    /**
     * Jacobi符号: (a/n)
     * 用于判断a是否是n的二次剩余
     * 返回值: 1, -1, 或 0
     */
    @Override
    public int jacobi(BigInteger a, BigInteger n) {
        return NativeBigInteger.jacobi(a, n);
    }

    /**
     * 批量Jacobi符号计算
     * 计算每个as[i]相对于n的Jacobi符号
     */
    @Override
    public int[] batchJacobi(BigInteger[] as, BigInteger n) {
        return NativeBigInteger.batchJacobi(as, n);
    }

    /**
     * 生成可能素数: 使用概率素性检测
     * @param bitLength 指定素数的比特长度
     * @param random 随机数生成器
     */
    @Override
    public BigInteger probablePrime(int bitLength, SecureRandom random) {
        return NativeBigInteger.probablePrime(bitLength, random);
    }

    /**
     * 检查是否使用GMP原生后端
     */
    @Override
    public boolean isNative() {
        return NativeBigInteger.isNativeAvailable();
    }
}
