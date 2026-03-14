package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.BigIntegerUtils;

import java.math.BigInteger;

public final class BiPrimeProofValidator {
    public boolean verifyProof(BiPrimeBlumProof pr, PaillierEncryption.PublicKey pk, byte[] ctx) {
        if (!basicChecks(pr, pk)) {
            return false;
        }
        BigInteger N = pr.N();
        BigInteger w = pr.w();
        boolean[] A = unpack(pr.aBits(), pr.blumRounds());
        boolean[] B = unpack(pr.bBits(), pr.blumRounds());

        return verifySigmaRounds(pr, N) && verifyBlumRounds(pr, N, w, ctx, A, B);
    }

    private static boolean basicChecks(BiPrimeBlumProof pr, PaillierEncryption.PublicKey pk) {
        if (pr == null || pk == null) {
            return false;
        }
        if (!pk.n().equals(pr.N())) {
            return false;
        }
        if (pr.sigmas() == null || pr.xs() == null || pr.zs() == null) {
            return false;
        }
        int sf = pr.sfRounds();
        int blum = pr.blumRounds();
        if (pr.sigmas().size() != sf || pr.xs().size() != blum || pr.zs().size() != blum) {
            return false;
        }
        return BigIntegerUtils.jacobi(pr.w(), pr.N()) == -1;
    }

    private static boolean verifySigmaRounds(BiPrimeBlumProof pr, BigInteger N) {
        int sf = pr.sfRounds();
        for (int i = 0; i < sf; i++) {
            if (!verifySigma(pr.sigmas().get(i), N)) {
                return false;
            }
        }
        return true;
    }

    private static boolean verifyBlumRounds(BiPrimeBlumProof pr, BigInteger N, BigInteger w, byte[] ctx, boolean[] A, boolean... B) {
        int blum = pr.blumRounds();
        for (int i = 0; i < blum; i++) {
            if (!verifyBlumRound(pr, N, w, ctx, A[i], B[i], i)) {
                return false;
            }
        }
        return true;
    }

    private static boolean verifySigma(BigInteger sigma, BigInteger N) {
        if (sigma.signum() <= 0 || sigma.compareTo(N) >= 0) return false;
        if (sigma.equals(BigInteger.ONE) || sigma.equals(N.subtract(BigInteger.ONE))) return false;
        if (!sigma.gcd(N).equals(BigInteger.ONE)) return false;
        return sigma.subtract(BigInteger.ONE).gcd(N).equals(BigInteger.ONE);
    }

    private static boolean verifyBlumRound(BiPrimeBlumProof pr, BigInteger N, BigInteger w, byte[] ctx, boolean a, boolean b, int i) {
        BigInteger x = pr.xs().get(i);
        BigInteger z = pr.zs().get(i);

        if (x.signum() < 0 || x.compareTo(N) >= 0) return false;
        if (z.signum() < 0 || z.compareTo(N) >= 0) return false;

        BigInteger y = BiPrimeProofGenerator.genY(N, w, ctx, i);
        if (!BigIntegerUtils.modPow(z, N, N).equals(y)) return false;

        BigInteger rhs = y;
        if (b) rhs = BigIntegerUtils.modMul(rhs, w, N);
        if (a) rhs = N.subtract(rhs).mod(N);

        BigInteger x2 = BigIntegerUtils.modMul(x, x, N);
        BigInteger x4 = BigIntegerUtils.modMul(x2, x2, N);

        return x4.equals(rhs);
    }

    private static boolean[] unpack(byte[] arr, int len) {
        boolean[] out = new boolean[len];
        for (int i = 0; i < len; i++) {
            out[i] = (arr[i >>> 3] & (1 << (i & 7))) != 0;
        }
        return out;
    }
}
