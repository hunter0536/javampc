package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.BigIntegerUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Objects;

public final class BiPrimeProofGenerator {
    private final int sfRounds;
    private final int blumRounds;

    public BiPrimeProofGenerator() {
        this(40, 64);
    }

    public BiPrimeProofGenerator(int blum) {
        this(blum, 0);
    }

    public BiPrimeProofGenerator(int blum, int sf) {
        this.sfRounds = sf;
        this.blumRounds = blum;
    }

    public BiPrimeBlumProof createProof(PaillierEncryption.PrivateKey sk, byte[] ctx) {
        Objects.requireNonNull(sk, "sk");

        BigInteger p = sk.p();
        BigInteger q = sk.q();
        BigInteger N = p.multiply(q);

        validateBlum(p, q);
        var lambda = BigIntegerUtils.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        ensureCoprime(N, lambda);

        var Ninverse = BigIntegerUtils.positiveModInverse(N, lambda);
        var eP = Ninverse.mod(p.subtract(BigInteger.ONE));
        var eQ = Ninverse.mod(q.subtract(BigInteger.ONE));

        var inv4p = inv4(p);
        var inv4q = inv4(q);

        var w = pickW(N, ctx);
        var sigmas = generateSigmas(N, ctx);

        int wP = BigIntegerUtils.jacobi(w, p);
        int wQ = BigIntegerUtils.jacobi(w, q);

        var rounds = generateBlumRounds(N, p, q, eP, eQ, inv4p, inv4q, w, wP, wQ, ctx);

        BitSet aBits = new BitSet(blumRounds);
        BitSet bBits = new BitSet(blumRounds);

        List<BigInteger> xs = new ArrayList<>(blumRounds);
        List<BigInteger> zs = new ArrayList<>(blumRounds);

        for (int i = 0; i < blumRounds; i++) {
            Round r = rounds.get(i);
            if (r.a) aBits.set(i);
            if (r.b) bBits.set(i);
            xs.add(r.x);
            zs.add(r.z);
        }

        return new BiPrimeBlumProof(
                N, w, sigmas, xs,
                toByteArray(aBits, blumRounds),
                toByteArray(bBits, blumRounds),
                zs,
                sfRounds, blumRounds
        );
    }

    private static void validateBlum(BigInteger p, BigInteger q) {
        if (!p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)) || !q.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            throw new IllegalArgumentException("N not Blum");
        }
    }

    private static void ensureCoprime(BigInteger N, BigInteger lambda) {
        if (!N.gcd(lambda).equals(BigInteger.ONE)) {
            throw new IllegalStateException("gcd(N, lambda) != 1");
        }
    }

    private static BigInteger inv4(BigInteger prime) {
        var half = prime.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        return BigIntegerUtils.modInverse(BigInteger.valueOf(4), half);
    }

    private static BigInteger pickW(BigInteger N, byte[] ctx) {
        BigInteger w = null;
        for (int t = 0; t < 5000 && w == null; t++) {
            var cand = hashToZNStarDet(N, ctx, "w", t);
            if (BigIntegerUtils.jacobi(cand, N) == -1) {
                w = cand;
            }
        }
        return Objects.requireNonNull(w, "could not find w in 5000 attempts");
    }

    private List<BigInteger> generateSigmas(BigInteger N, byte[] ctx) {
        List<BigInteger> sigmas = new ArrayList<>(sfRounds);
        for (int i = 0; i < sfRounds; i++) {
            BigInteger sigma;
            do {
                BigInteger s = hashToZNStarDet(N, ctx, "sigma", i);
                sigma = BigIntegerUtils.modPow(s, N, N);
            } while (sigma.equals(BigInteger.ONE) || sigma.equals(N.subtract(BigInteger.ONE)) || !sigma.subtract(BigInteger.ONE).gcd(N).equals(BigInteger.ONE));
            sigmas.add(sigma);
        }
        return sigmas;
    }

    private List<Round> generateBlumRounds(
            BigInteger N, BigInteger p, BigInteger q,
            BigInteger eP, BigInteger eQ,
            BigInteger inv4p, BigInteger inv4q,
            BigInteger w, int wP, int wQ,
            byte[] ctx
    ) {
        List<Round> rounds = new ArrayList<>(blumRounds);
        
        // Batch optimization: collect all y values for batch processing
        BigInteger[] yValues = new BigInteger[blumRounds];
        
        // Step 1: Generate all y values
        for (int i = 0; i < blumRounds; i++) {
            yValues[i] = genY(N, w, ctx, i);
        }
        
        // Step 2: Batch compute y mod p and y mod q
        BigInteger[] basesP = BigIntegerUtils.batchMod(yValues, p);
        BigInteger[] basesQ = BigIntegerUtils.batchMod(yValues, q);
        
        // Step 3: Use BigIntegerUtils batch modPow for better performance
        BigInteger[] zps = BigIntegerUtils.batchModPow(basesP, eP, p);
        BigInteger[] zqs = BigIntegerUtils.batchModPow(basesQ, eQ, q);
        
        // Step 4: Batch compute jacobi symbols
        int[] yPs = BigIntegerUtils.batchJacobi(yValues, p);
        int[] yQs = BigIntegerUtils.batchJacobi(yValues, q);
        
        BigInteger[] zValues = new BigInteger[blumRounds];
        BigInteger[] rhsValues = new BigInteger[blumRounds];
        boolean[] aBits = new boolean[blumRounds];
        boolean[] bBits = new boolean[blumRounds];
        
        // Step 3: Process results and compute remaining operations
        for (int i = 0; i < blumRounds; i++) {
            var y = yValues[i];
            var zp = zps[i];
            var zq = zqs[i];
            var z = BigIntegerUtils.crt(zp, p, zq, q, N);

            int yP = yPs[i];
            int yQ = yQs[i];
            boolean aBit = false;
            boolean bBit = false;

            search:
            for (int B = 0; B <= 1; B++) {
                int sP = (B == 1 ? wP : 1) * yP;
                int sQ = (B == 1 ? wQ : 1) * yQ;
                for (int A = 0; A <= 1; A++) {
                    int sp = (A == 1 ? -sP : sP);
                    int sq = (A == 1 ? -sQ : sQ);
                    if (sp == 1 && sq == 1) {
                        aBit = (A == 1);
                        bBit = (B == 1);
                        break search;
                    }
                }
            }

            var rhs = y;
            if (bBit) rhs = BigIntegerUtils.modMul(rhs, w, N);
            if (aBit) rhs = N.subtract(rhs).mod(N);
            
            zValues[i] = z;
            rhsValues[i] = rhs;
            aBits[i] = aBit;
            bBits[i] = bBit;
        }
        
        // Step 4: Batch compute xp and xq
        BigInteger[] rhsP = BigIntegerUtils.batchMod(rhsValues, p);
        BigInteger[] rhsQ = BigIntegerUtils.batchMod(rhsValues, q);
        
        BigInteger[] xps = BigIntegerUtils.batchModPow(rhsP, inv4p, p);
        BigInteger[] xqs = BigIntegerUtils.batchModPow(rhsQ, inv4q, q);
        
        // Step 5: Create rounds
        for (int i = 0; i < blumRounds; i++) {
            var x = BigIntegerUtils.crt(xps[i], p, xqs[i], q, N);
            rounds.add(new Round(x, zValues[i], aBits[i], bBits[i]));
        }
        
        return rounds;
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public static BigInteger genY(BigInteger N, BigInteger w, byte[] ctx, int i) {
        var rnd = new DeterministicRandom(N, w, "blum", i, ctx);
        BigInteger y;
        do {
            y = new BigInteger(N.bitLength(), rnd);
        } while (y.signum() <= 0 || y.compareTo(N) >= 0 || !y.gcd(N).equals(BigInteger.ONE));
        return y;
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public static BigInteger hashToZNStarDet(BigInteger N, byte[] ctx, String label, int i) {
        var rnd = new DeterministicRandom(N, null, label, i, ctx);
        BigInteger y;
        do {
            y = new BigInteger(N.bitLength(), rnd);
        } while (y.signum() <= 0 || y.compareTo(N) >= 0 || !y.gcd(N).equals(BigInteger.ONE));
        return y;
    }

    private static byte[] toByteArray(BitSet bits, int len) {
        byte[] out = new byte[(len + 7) >>> 3];
        for (int i = 0; i < len; i++) {
            if (bits.get(i)) out[i >>> 3] |= (byte) (1 << (i & 7));
        }
        return out;
    }

    private record Round(BigInteger x, BigInteger z, boolean a, boolean b) {
    }
}
