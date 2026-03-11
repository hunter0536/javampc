package com.example.mpc.cggmp.util;

import java.math.BigInteger;

public final class GmpBackend implements BigIntegerBackend {
    private static final GmpBackend INSTANCE = new GmpBackend();

    private GmpBackend() {
    }

    public static GmpBackend getInstance() {
        return INSTANCE;
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.modPow(base, exp, mod);
    }

    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        return NativeBigInteger.modInverse(val, mod);
    }

    @Override
    public BigInteger multiply(BigInteger a, BigInteger b) {
        return NativeBigInteger.multiply(a, b);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        return NativeBigInteger.batchModPow(bases, exp, mod);
    }

    @Override
    public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        return NativeBigInteger.batchModPowDifferentExp(bases, exps, mod);
    }

    @Override
    public boolean isNative() {
        return NativeBigInteger.isNativeAvailable();
    }

    public static AffGProofResult computeAffGProofTuples(
            BigInteger C, BigInteger onePlusN0, BigInteger N0sq,
            BigInteger onePlusN1, BigInteger N1sq,
            BigInteger[] alphas, BigInteger[] betasForN0, BigInteger[] betasForN1,
            BigInteger[] rs, BigInteger[] ss) {
        return NativeBigInteger.computeAffGProofTuples(C, onePlusN0, N0sq, onePlusN1, N1sq, alphas, betasForN0, betasForN1, rs, ss);
    }

    public static DecProofResult computeDecProofTuples(
            BigInteger K, BigInteger N0, BigInteger N0sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs) {
        return javaComputeDecProofTuples(K, N0, N0sq, alphas, betas, rs);
    }

    private static DecProofResult javaComputeDecProofTuples(
            BigInteger K, BigInteger N0, BigInteger N0sq,
            BigInteger[] alphas, BigInteger[] betas, BigInteger[] rs) {
        int kappa = alphas.length;
        BigInteger onePlusN0 = N0.add(BigInteger.ONE);
        BigInteger[] A = new BigInteger[kappa];

        for (int i = 0; i < kappa; i++) {
            A[i] = powSigned(K, alphas[i].negate(), N0sq)
                    .multiply(powSigned(onePlusN0, betas[i], N0sq))
                    .multiply(rs[i].modPow(N0, N0sq))
                    .mod(N0sq);
        }

        return new DecProofResult(A);
    }

    private static BigInteger powSigned(BigInteger base, BigInteger exp, BigInteger mod) {
        if (exp.signum() >= 0) {
            return base.modPow(exp, mod);
        }
        BigInteger inv = base.modInverse(mod);
        return inv.modPow(exp.negate(), mod);
    }
}
