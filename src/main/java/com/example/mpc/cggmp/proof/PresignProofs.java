package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.SecureRandomUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class PresignProofs {
    private static final Logger logger = LoggerFactory.getLogger(PresignProofs.class);

    public record EncElgVerifyResult(boolean ok, boolean eq1, boolean eq2, boolean eq3, boolean eq4,
                                     boolean z1InRange) {
    }

    public record AffGVerifyResult(boolean ok, int index, boolean eq1, boolean eq2, boolean eq3, boolean zInRange,
                                   boolean zPrimeInRange) {
    }

    private PresignProofs() {
    }

    // 真实的 Π_enc，使用 Paillier 范围证明 (k_i, gamma_i 在范围内)
    public static PiEncProof createEncProof(PaillierEncryption.PublicKey publicKey,
                                            ZKSetup zkSetup,
                                            BigInteger q,
                                            BigInteger k,
                                            BigInteger kRandom,
                                            BigInteger K,
                                            BigInteger gamma,
                                            BigInteger gRandom,
                                            BigInteger G,
                                            byte[] context) {
        PaillierRangeProofGenerator gen = new PaillierRangeProofGenerator();
        PaillierRangeEncryptionWitness kWitness = new PaillierRangeEncryptionWitness(
                k, kRandom, K, publicKey, zkSetup, q
        );
        PaillierRangeProof kProof = gen.createProof(kWitness, context);
        PaillierRangeEncryptionWitness gWitness = new PaillierRangeEncryptionWitness(
                gamma, gRandom, G, publicKey, zkSetup, q
        );
        PaillierRangeProof gProof = gen.createProof(gWitness, context);
        return new PiEncProof(kProof, gProof);
    }

    public static boolean verifyEncProof(PiEncProof proof,
                                         PaillierEncryption.PublicKey publicKey,
                                         ZKSetup zkSetup,
                                         BigInteger q,
                                         BigInteger K,
                                         BigInteger G,
                                         byte[] context) {
        if (proof == null || proof.kProof() == null || proof.gProof() == null) return false;
        PaillierRangeProofValidator validator = new PaillierRangeProofValidator();
        PaillierRangeProofContext kCtx = new PaillierRangeProofContext(K, q, zkSetup, context);
        PaillierRangeProofContext gCtx = new PaillierRangeProofContext(G, q, zkSetup, context);
        return validator.verifyProof(proof.kProof(), publicKey, kCtx)
                && validator.verifyProof(proof.gProof(), publicKey, gCtx);
    }

    private static final int DEFAULT_KAPPA = 128;
    private static final int RANGE_EPS_BITS = 16;

    public static PiAffGProof createAffGProof(ECPoint g,
                                              ECPoint X,
                                              BigInteger N0,
                                              BigInteger N1,
                                              BigInteger C,
                                              BigInteger D,
                                              BigInteger Y,
                                              BigInteger x,
                                              BigInteger y,
                                              BigInteger rho,
                                              BigInteger mu,
                                              byte[] context) {
        return createAffGProof(g, X, N0, N1, C, D, Y, x, y, rho, mu, DEFAULT_KAPPA, RANGE_EPS_BITS, context);
    }

    public static PiAffGProof createAffGProof(ECPoint g,
                                              ECPoint X,
                                              BigInteger N0,
                                              BigInteger N1,
                                              BigInteger C,
                                              BigInteger D,
                                              BigInteger Y,
                                              BigInteger x,
                                              BigInteger y,
                                              BigInteger rho,
                                              BigInteger mu,
                                              int kappa,
                                              int epsBits,
                                              byte[] context) {
        return createAffGProofInternal(g, X, N0, N1, C, x, y, rho, mu, false, kappa, epsBits, context);
    }

    public static PiAffGProof createAffGProofNegY(ECPoint g,
                                                  ECPoint X,
                                                  BigInteger N0,
                                                  BigInteger N1,
                                                  BigInteger C,
                                                  BigInteger D,
                                                  BigInteger Y,
                                                  BigInteger x,
                                                  BigInteger y,
                                                  BigInteger rho,
                                                  BigInteger mu,
                                                  int kappa,
                                                  int epsBits,
                                                  byte[] context) {
        return createAffGProofInternal(g, X, N0, N1, C, x, y, rho, mu, true, kappa, epsBits, context);
    }

    private static PiAffGProof createAffGProofInternal(ECPoint g,
                                                       ECPoint X,
                                                       BigInteger N0,
                                                       BigInteger N1,
                                                       BigInteger C,
                                                       BigInteger x,
                                                       BigInteger y,
                                                       BigInteger rho,
                                                       BigInteger mu,
                                                       boolean negY,
                                                       int kappa,
                                                       int epsBits,
                                                       byte[] context) {
        int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        long t0 = System.nanoTime();
        if (logger.isInfoEnabled()) {
            logger.info("PiAffG start: kappa={}, epsBits={}, negY={}, N0Bits={}, N1Bits={}",
                    effectiveKappa, effectiveEps, negY, N0.bitLength(), N1.bitLength());
        }

        List<ECPoint> R = new ArrayList<>(effectiveKappa);
        List<BigInteger> z = new ArrayList<>(effectiveKappa);
        List<BigInteger> zPrime = new ArrayList<>(effectiveKappa);
        List<BigInteger> w = new ArrayList<>(effectiveKappa);
        List<BigInteger> lambda = new ArrayList<>(effectiveKappa);

        BigInteger[] alphaArr = new BigInteger[effectiveKappa];
        BigInteger[] betaArr = new BigInteger[effectiveKappa];
        BigInteger[] rArr = new BigInteger[effectiveKappa];
        BigInteger[] sArr = new BigInteger[effectiveKappa];

        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger rangeBound = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 1);
        long loop1Start = System.nanoTime();

        java.util.stream.IntStream.range(0, effectiveKappa).parallel().forEach(i -> {
            SecureRandom rnd = SecureRandomUtils.getInstance();
            alphaArr[i] = randomSigned(rangeBound, rnd);
            betaArr[i] = randomSigned(rangeBound, rnd);
            rArr[i] = BigIntegerUtils.randomZnStar(N0, rnd);
            sArr[i] = BigIntegerUtils.randomZnStar(N1, rnd);
        });
        logger.debug("PiAffG random values generated in {} ms",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - loop1Start));

        long batchStart = System.nanoTime();
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger onePlusN1 = BigInteger.ONE.add(N1);

        BigInteger[] betaForN0Arr = new BigInteger[effectiveKappa];
        for (int i = 0; i < effectiveKappa; i++) {
            betaForN0Arr[i] = negY ? betaArr[i].negate() : betaArr[i];
        }

        BigInteger[] onePlusN0Arr = new BigInteger[effectiveKappa];
        BigInteger[] onePlusN1Arr = new BigInteger[effectiveKappa];
        BigInteger[] cArr = new BigInteger[effectiveKappa];
        BigInteger[] n0ExpArr = new BigInteger[effectiveKappa];
        BigInteger[] n1ExpArr = new BigInteger[effectiveKappa];
        for (int i = 0; i < effectiveKappa; i++) {
            onePlusN0Arr[i] = onePlusN0;
            onePlusN1Arr[i] = onePlusN1;
            cArr[i] = C;
            n0ExpArr[i] = N0;
            n1ExpArr[i] = N1;
        }

        BigInteger[] rPowN0, sPowN1, onePlusN0PowBeta, onePlusN1PowBeta, CPowAlpha;
        boolean useBatchAll = false;

        try {
            BigInteger[][] batchResults = BigIntegerUtils.batchModPowAll(
                    rArr, sArr, onePlusN0Arr, onePlusN1Arr, cArr,
                    n0ExpArr, n1ExpArr, betaForN0Arr, betaArr, alphaArr,
                    N0sq, N1sq, N0sq, N1sq, N0sq
            );

            rPowN0 = batchResults[0];
            sPowN1 = batchResults[1];
            onePlusN0PowBeta = batchResults[2];
            onePlusN1PowBeta = batchResults[3];
            CPowAlpha = batchResults[4];
            useBatchAll = true;
        } catch (Exception e) {
            logger.warn("batchModPowAll failed, falling back: {} - {}", 
                e.getClass().getSimpleName(), e.getMessage());
            rPowN0 = BigIntegerUtils.batchModPow(rArr, N0, N0sq);
            sPowN1 = BigIntegerUtils.batchModPow(sArr, N1, N1sq);
            onePlusN0PowBeta = BigIntegerUtils.batchModPow(onePlusN0Arr, betaForN0Arr, N0sq);
            onePlusN1PowBeta = BigIntegerUtils.batchModPow(onePlusN1Arr, betaArr, N1sq);
            CPowAlpha = BigIntegerUtils.batchModPow(
                    java.util.Collections.nCopies(effectiveKappa, C).toArray(new BigInteger[0]),
                    alphaArr,
                    N0sq
            );
        }

        final BigInteger[] finalRPowN0 = rPowN0;
        final BigInteger[] finalSPowN1 = sPowN1;
        final BigInteger[] finalOnePlusN0PowBeta = onePlusN0PowBeta;
        final BigInteger[] finalOnePlusN1PowBeta = onePlusN1PowBeta;
        final BigInteger[] finalCPowAlpha = CPowAlpha;

        long batchEnd = System.nanoTime();

        BigInteger[] AjArr = new BigInteger[effectiveKappa];
        BigInteger[] BjArr = new BigInteger[effectiveKappa];

        java.util.stream.IntStream.range(0, effectiveKappa).parallel().forEach(i -> {
            AjArr[i] = BigIntegerUtils.modMul(
                    BigIntegerUtils.modMul(finalCPowAlpha[i], finalOnePlusN0PowBeta[i], N0sq),
                    finalRPowN0[i],
                    N0sq
            );

            BjArr[i] = BigIntegerUtils.modMul(finalOnePlusN1PowBeta[i], finalSPowN1[i], N1sq);
        });

        logger.debug("PiAffG modPow computed in {} ms",
                TimeUnit.NANOSECONDS.toMillis(batchEnd - batchStart));

        ECPoint[] Rarr = new ECPoint[effectiveKappa];
        java.util.stream.IntStream.range(0, effectiveKappa).parallel().forEach(i -> {
            Rarr[i] = ecMulSigned(g, alphaArr[i]).normalize();
        });

        List<BigInteger> A = new ArrayList<>(effectiveKappa);
        List<BigInteger> B = new ArrayList<>(effectiveKappa);
        for (int i = 0; i < effectiveKappa; i++) {
            A.add(AjArr[i]);
            B.add(BjArr[i]);
            R.add(Rarr[i]);
        }
        logger.debug("PiAffG tuples built in {} ms",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - loop1Start));

        long challengeStart = System.nanoTime();
        boolean[] e = challengeBits("PI_AFFG", context, effectiveKappa, A, B, R);
        long challengeMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - challengeStart);
        logger.debug("PiAffG challenge computed in {} ms", challengeMs);

        BigInteger rhoPow0 = BigInteger.ONE;
        BigInteger rhoPow1 = BigIntegerUtils.modPow(rho, BigInteger.ONE, N0);
        BigInteger muPow0 = BigInteger.ONE;
        BigInteger muPow1 = BigIntegerUtils.modPow(mu, BigInteger.ONE, N1);

        long loop2Start = System.nanoTime();
        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = alphaArr[i].add(ei.multiply(x));
            BigInteger zpi = betaArr[i].add(ei.multiply(y));
            BigInteger rhoPowEi = e[i] ? rhoPow1 : rhoPow0;
            BigInteger muPowEi = e[i] ? muPow1 : muPow0;
            BigInteger wi = BigIntegerUtils.modMul(rArr[i], rhoPowEi, N0);
            BigInteger li = BigIntegerUtils.modMul(sArr[i], muPowEi, N1);
            z.add(zi);
            zPrime.add(zpi);
            w.add(wi);
            lambda.add(li);
            if ((i + 1) % 8 == 0 || i + 1 == effectiveKappa) {
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - loop2Start);
                logger.debug("PiAffG progress: built {}/{} responses in {} ms", i + 1, effectiveKappa, elapsedMs);
            }
        }

        long totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
        logger.debug("PiAffG done in {} ms", totalMs);
        return new PiAffGProof(A, B, R, z, zPrime, w, lambda);
    }

    public static boolean verifyAffGProof(PiAffGProof proof,
                                          ECPoint g,
                                          ECPoint X,
                                          BigInteger N0,
                                          BigInteger N1,
                                          BigInteger C,
                                          BigInteger D,
                                          BigInteger Y,
                                          byte[] context) {
        return verifyAffGProof(proof, g, X, N0, N1, C, D, Y, DEFAULT_KAPPA, RANGE_EPS_BITS, context);
    }

    public static boolean verifyAffGProof(PiAffGProof proof,
                                          ECPoint g,
                                          ECPoint X,
                                          BigInteger N0,
                                          BigInteger N1,
                                          BigInteger C,
                                          BigInteger D,
                                          BigInteger Y,
                                          int kappa,
                                          int epsBits,
                                          byte[] context) {
        return verifyAffGProofDetailed(proof, g, X, N0, N1, C, D, Y, kappa, epsBits, context).ok();
    }

    public static Map<Integer, Boolean> verifyAffGBatchProofs(
            Map<Integer, PiAffGProof> proofs,
            Map<Integer, ECPoint> gammaMap,
            Map<Integer, BigInteger> N0Map,
            BigInteger N1,
            Map<Integer, BigInteger> KMap,
            Map<Integer, BigInteger> DMap,
            Map<Integer, BigInteger> YMap,
            int kappa,
            int epsBits,
            byte[] context) {
        
        if (proofs == null || proofs.isEmpty()) {
            return java.util.Collections.emptyMap();
        }

        Map<Integer, Boolean> results = new java.util.concurrent.ConcurrentHashMap<>();

        proofs.entrySet().parallelStream().forEach(entry -> {
            int nodeId = entry.getKey();
            PiAffGProof proof = entry.getValue();
            ECPoint X = gammaMap.get(nodeId);
            BigInteger N0 = N0Map.get(nodeId);
            BigInteger C = KMap.get(nodeId);
            BigInteger D = DMap.get(nodeId);
            BigInteger Y = YMap.get(nodeId);

            if (X == null || N0 == null || C == null || D == null || Y == null) {
                results.put(nodeId, false);
                return;
            }

            boolean ok = verifyAffGProof(proof, Secp256k1CurveUtils.G(), X, N0, N1, C, D, Y, kappa, epsBits, context);
            results.put(nodeId, ok);
        });

        return results;
    }

    public static boolean verifyAffGBatchProofsAll(
            Map<Integer, Boolean> results) {
        if (results == null || results.isEmpty()) {
            return false;
        }
        return results.values().stream().allMatch(Boolean::booleanValue);
    }

    public static AffGVerifyResult verifyAffGProofDetailed(PiAffGProof proof,
                                                           ECPoint g,
                                                           ECPoint X,
                                                           BigInteger N0,
                                                           BigInteger N1,
                                                           BigInteger C,
                                                           BigInteger D,
                                                           BigInteger Y,
                                                           int kappa,
                                                           int epsBits,
                                                           byte[] context) {
        return verifyAffGProofDetailedInternal(proof, g, X, N0, N1, C, D, Y, false, kappa, epsBits, context);
    }

    public static AffGVerifyResult verifyAffGProofDetailedNegY(PiAffGProof proof,
                                                               ECPoint g,
                                                               ECPoint X,
                                                               BigInteger N0,
                                                               BigInteger N1,
                                                               BigInteger C,
                                                               BigInteger D,
                                                               BigInteger Y,
                                                               int kappa,
                                                               int epsBits,
                                                               byte[] context) {
        return verifyAffGProofDetailedInternal(proof, g, X, N0, N1, C, D, Y, true, kappa, epsBits, context);
    }

    private static AffGVerifyResult verifyAffGProofDetailedInternal(PiAffGProof proof,
                                                                    ECPoint g,
                                                                    ECPoint X,
                                                                    BigInteger N0,
                                                                    BigInteger N1,
                                                                    BigInteger C,
                                                                    BigInteger D,
                                                                    BigInteger Y,
                                                                    boolean negY,
                                                                    int kappa,
                                                                    int epsBits,
                                                                    byte[] context) {
        if (proof == null) {
            return new AffGVerifyResult(false, -1, false, false, false, false, false);
        }
        int n = proof.A().size();
        int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        if (n == 0 || n != effectiveKappa || proof.B().size() != n || proof.R().size() != n
                || proof.z().size() != n || proof.zPrime().size() != n
                || proof.w().size() != n || proof.lambda().size() != n) {
            return new AffGVerifyResult(false, -1, false, false, false, false, false);
        }
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        boolean[] e = challengeBits("PI_AFFG", context, n, proof.A(), proof.B(), proof.R());
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger rangeBound = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 1);

        BigInteger onePlusN0 = BigInteger.ONE.add(N0);
        BigInteger onePlusN1 = BigInteger.ONE.add(N1);

        boolean[] eq1Results = new boolean[n];
        boolean[] eq2Results = new boolean[n];
        boolean[] eq3Results = new boolean[n];
        boolean[] zInRangeResults = new boolean[n];
        boolean[] zPrimeInRangeResults = new boolean[n];

        BigInteger[] z_arr = proof.z().toArray(new BigInteger[0]);
        BigInteger[] zPrime_arr = proof.zPrime().toArray(new BigInteger[0]);
        BigInteger[] zPrimeForN0_arr = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            zPrimeForN0_arr[i] = negY ? zPrime_arr[i].negate() : zPrime_arr[i];
        }
        BigInteger[] w_arr = proof.w().toArray(new BigInteger[0]);
        BigInteger[] A_arr = proof.A().toArray(new BigInteger[0]);
        BigInteger[] lambda_arr = proof.lambda().toArray(new BigInteger[0]);
        BigInteger[] B_arr = proof.B().toArray(new BigInteger[0]);

        java.util.stream.IntStream.range(0, n).parallel().forEach(i -> {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = z_arr[i];
            BigInteger zpi = zPrime_arr[i];
            BigInteger wi = w_arr[i];
            BigInteger li = lambda_arr[i];

            // eq1
            BigInteger zPrimeForN0 = zPrimeForN0_arr[i];
            BigInteger left1 = BigIntegerUtils.modMul(
                    BigIntegerUtils.modMul(
                            BigIntegerUtils.powSigned(C, zi, N0sq),
                            BigIntegerUtils.powSigned(onePlusN0, zPrimeForN0, N0sq),
                            N0sq
                    ),
                    BigIntegerUtils.modPow(wi, N0, N0sq),
                    N0sq
            );
            BigInteger right1 = BigIntegerUtils.modMul(A_arr[i], BigIntegerUtils.modPow(D, ei, N0sq), N0sq);
            eq1Results[i] = left1.equals(right1);

            // eq2
            ECPoint left2 = ecMulSigned(g, zi).normalize();
            ECPoint right2 = proof.R().get(i).add(X.multiply(ei)).normalize();
            eq2Results[i] = left2.equals(right2);

            // eq3
            BigInteger left3 = BigIntegerUtils.modMul(
                    BigIntegerUtils.powSigned(onePlusN1, zpi, N1sq),
                    BigIntegerUtils.modPow(li, N1, N1sq),
                    N1sq
            );
            BigInteger right3 = BigIntegerUtils.modMul(B_arr[i], BigIntegerUtils.modPow(Y, ei, N1sq), N1sq);
            eq3Results[i] = left3.equals(right3);

            zInRangeResults[i] = zi.abs().compareTo(rangeBound) <= 0;
            zPrimeInRangeResults[i] = zpi.abs().compareTo(rangeBound) <= 0;
        });

        for (int i = 0; i < n; i++) {
            if (!(eq1Results[i] && eq2Results[i] && eq3Results[i] && zInRangeResults[i] && zPrimeInRangeResults[i])) {
                return new AffGVerifyResult(false, i, eq1Results[i], eq2Results[i], eq3Results[i], zInRangeResults[i], zPrimeInRangeResults[i]);
            }
        }
        return new AffGVerifyResult(true, -1, true, true, true, true, true);
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public static PiLogStarProof createLogStarProof(ECPoint base, ECPoint X, BigInteger secret, byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger alpha;
        do {
            alpha = new BigInteger(q.bitLength(), rnd).mod(q);
        } while (alpha.signum() == 0);
        ECPoint A = base.multiply(alpha).normalize();
        BigInteger c = challenge("PI_LOGSTAR", base, X, A, context);
        BigInteger z = alpha.add(c.multiply(secret)).mod(q);
        return new PiLogStarProof(A, z);
    }

    public static boolean verifyLogStarProof(PiLogStarProof proof, ECPoint base, ECPoint X, byte[] context) {
        if (proof == null || proof.A() == null || proof.z() == null) return false;
        BigInteger c = challenge("PI_LOGSTAR", base, X, proof.A(), context);
        ECPoint left = base.multiply(proof.z()).normalize();
        ECPoint right = proof.A().add(X.multiply(c)).normalize();
        return left.equals(right);
    }

    public static PiLogProof createLogProof(ECPoint g,
                                            ECPoint h,
                                            ECPoint X,
                                            ECPoint Y,
                                            ECPoint A,
                                            ECPoint B,
                                            BigInteger x,
                                            BigInteger alpha,
                                            byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger u = new BigInteger(q.bitLength(), rnd).mod(q);
        BigInteger v = new BigInteger(q.bitLength(), rnd).mod(q);
        ECPoint U1 = h.multiply(u).normalize();
        ECPoint U2 = g.multiply(v).normalize();
        ECPoint U3 = g.multiply(u).add(Y.multiply(v)).normalize();
        BigInteger e = challengeSigned("PI_LOG", q, context, g, h, X, Y, A, B, U1, U2, U3);
        BigInteger z1 = u.add(e.multiply(x)).mod(q);
        BigInteger z2 = v.add(e.multiply(alpha)).mod(q);
        return new PiLogProof(U1, U2, U3, z1, z2);
    }

    public static boolean verifyLogProof(PiLogProof proof,
                                         ECPoint g,
                                         ECPoint h,
                                         ECPoint X,
                                         ECPoint Y,
                                         ECPoint A,
                                         ECPoint B,
                                         byte[] context) {
        if (proof == null || proof.U1() == null || proof.U2() == null || proof.U3() == null) return false;
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger e = challengeSigned("PI_LOG", q, context, g, h, X, Y, A, B, proof.U1(), proof.U2(), proof.U3());
        ECPoint left1 = h.multiply(proof.z1()).normalize();
        ECPoint right1 = proof.U1().add(X.multiply(e)).normalize();
        if (!left1.equals(right1)) return false;
        ECPoint left2 = g.multiply(proof.z2()).normalize();
        ECPoint right2 = proof.U2().add(A.multiply(e)).normalize();
        if (!left2.equals(right2)) return false;
        ECPoint left3 = g.multiply(proof.z1()).add(Y.multiply(proof.z2())).normalize();
        ECPoint right3 = proof.U3().add(B.multiply(e)).normalize();
        return left3.equals(right3);
    }

    public static PiEncElgProof createEncElgProof(PaillierEncryption.PublicKey publicKey,
                                                  ZKSetup zkSetup,
                                                  ECPoint g,
                                                  ECPoint A,
                                                  ECPoint B,
                                                  ECPoint X,
                                                  BigInteger x,
                                                  BigInteger rho,
                                                  BigInteger a,
                                                  BigInteger b,
                                                  int epsBits,
                                                  byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger N0 = publicKey.n();
        BigInteger N0sq = publicKey.nSquared();
        BigInteger hatN = zkSetup.hatN();
        BigInteger s = zkSetup.h1();
        BigInteger t = zkSetup.h2();
        SecureRandom rnd = SecureRandomUtils.getInstance();
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;

        BigInteger boundX = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 1);
        BigInteger boundMu = BigInteger.ONE.shiftLeft(q.bitLength()).multiply(hatN);
        BigInteger boundGamma = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 2).multiply(hatN);

        BigInteger mu = randomSigned(boundMu, rnd);
        BigInteger alpha = randomSigned(boundX, rnd);
        BigInteger beta = new BigInteger(q.bitLength(), rnd).mod(q);
        BigInteger gamma = randomSigned(boundGamma, rnd);
        BigInteger r = BigIntegerUtils.randomZnStar(N0, rnd);

        BigInteger S = BigIntegerUtils.modMul(
                BigIntegerUtils.powSigned(s, x, hatN),
                BigIntegerUtils.powSigned(t, mu, hatN),
                hatN
        );
        BigInteger D = BigIntegerUtils.modMul(
                BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), alpha, N0sq),
                BigIntegerUtils.modPow(r, N0, N0sq),
                N0sq
        );
        ECPoint Y = A.multiply(beta).add(g.multiply(alpha)).normalize();
        ECPoint Z = g.multiply(beta).normalize();
        BigInteger T = BigIntegerUtils.modMul(
                BigIntegerUtils.powSigned(s, alpha, hatN),
                BigIntegerUtils.powSigned(t, gamma, hatN),
                hatN
        );

        BigInteger e = challengeSignedBounded("PI_ENC_ELG", effectiveEps, context, publicKey.n(), A, B, X, S, T, D, Y, Z);
        BigInteger z1 = alpha.add(e.multiply(x));
        BigInteger w = beta.add(e.multiply(b)).mod(q);
        BigInteger z2 = BigIntegerUtils.modMul(r, BigIntegerUtils.powSigned(rho, e, N0), N0);
        BigInteger z3 = gamma.add(e.multiply(mu));

        return new PiEncElgProof(S, T, D, Y, Z, z1, z2, z3, w);
    }

    public static boolean verifyEncElgProof(PiEncElgProof proof,
                                            PaillierEncryption.PublicKey publicKey,
                                            ZKSetup zkSetup,
                                            ECPoint g,
                                            ECPoint A,
                                            ECPoint B,
                                            ECPoint X,
                                            BigInteger C,
                                            int epsBits,
                                            byte[] context) {
        EncElgVerifyResult result = verifyEncElgProofDetailed(proof, publicKey, zkSetup, g, A, B, X, C, epsBits, context);
        return result.ok();
    }

    public static EncElgVerifyResult verifyEncElgProofDetailed(PiEncElgProof proof,
                                                               PaillierEncryption.PublicKey publicKey,
                                                               ZKSetup zkSetup,
                                                               ECPoint g,
                                                               ECPoint A,
                                                               ECPoint B,
                                                               ECPoint X,
                                                               BigInteger C,
                                                               int epsBits,
                                                               byte[] context) {
        if (proof == null) {
            return new EncElgVerifyResult(false, false, false, false, false, false);
        }
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger N0 = publicKey.n();
        BigInteger N0sq = publicKey.nSquared();
        BigInteger hatN = zkSetup.hatN();
        BigInteger s = zkSetup.h1();
        BigInteger t = zkSetup.h2();
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        BigInteger boundX = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 2);

        BigInteger e = challengeSignedBounded("PI_ENC_ELG", effectiveEps, context, publicKey.n(), A, B, X, proof.S(), proof.T(), proof.D(), proof.Y(), proof.Z());

        BigInteger left1 = BigIntegerUtils.modMul(
                BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), proof.z1(), N0sq),
                BigIntegerUtils.modPow(proof.z2(), N0, N0sq),
                N0sq
        );
        BigInteger right1 = BigIntegerUtils.modMul(proof.D(), BigIntegerUtils.powSigned(C, e, N0sq), N0sq);
        boolean eq1 = left1.equals(right1);

        ECPoint left2 = A.multiply(proof.w()).add(g.multiply(proof.z1())).normalize();
        ECPoint right2 = proof.Y().add(X.multiply(e)).normalize();
        boolean eq2 = left2.equals(right2);

        ECPoint left3 = g.multiply(proof.w()).normalize();
        ECPoint right3 = proof.Z().add(B.multiply(e)).normalize();
        boolean eq3 = left3.equals(right3);

        BigInteger left4 = BigIntegerUtils.modMul(
                BigIntegerUtils.powSigned(s, proof.z1(), hatN),
                BigIntegerUtils.powSigned(t, proof.z3(), hatN),
                hatN
        );
        BigInteger right4 = BigIntegerUtils.modMul(proof.T(), BigIntegerUtils.powSigned(proof.S(), e, hatN), hatN);
        boolean eq4 = left4.equals(right4);
        boolean z1InRange = proof.z1().abs().compareTo(boundX) <= 0;
        boolean ok = eq1 && eq2 && eq3 && eq4 && z1InRange;
        return new EncElgVerifyResult(ok, eq1, eq2, eq3, eq4, z1InRange);
    }

    public static PiDecProof createDecProof(ECPoint g,
                                            ECPoint X,
                                            ECPoint S,
                                            BigInteger N0,
                                            BigInteger K,
                                            BigInteger D,
                                            BigInteger x,
                                            BigInteger y,
                                            BigInteger rho,
                                            byte[] context) {
        return createDecProof(g, X, S, N0, K, D, x, y, rho, DEFAULT_KAPPA, RANGE_EPS_BITS, context);
    }

    public static PiDecProof createDecProof(ECPoint g,
                                            ECPoint X,
                                            ECPoint S,
                                            BigInteger N0,
                                            BigInteger K,
                                            BigInteger D,
                                            BigInteger x,
                                            BigInteger y,
                                            BigInteger rho,
                                            int kappa,
                                            int epsBits,
                                            byte[] context) {
        int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        BigInteger N0sq = N0.multiply(N0);
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger rangeBound = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps);

        List<BigInteger> A = new ArrayList<>(effectiveKappa);
        List<ECPoint> B = new ArrayList<>(effectiveKappa);
        List<ECPoint> C = new ArrayList<>(effectiveKappa);
        List<BigInteger> z = new ArrayList<>(effectiveKappa);
        List<BigInteger> w = new ArrayList<>(effectiveKappa);
        List<BigInteger> nu = new ArrayList<>(effectiveKappa);

        List<BigInteger> alpha = new ArrayList<>(effectiveKappa);
        List<BigInteger> beta = new ArrayList<>(effectiveKappa);
        List<BigInteger> r = new ArrayList<>(effectiveKappa);

        // 生成所有随机数
        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ai = randomSigned(rangeBound, rnd);
            BigInteger bi = randomSigned(rangeBound, rnd);
            BigInteger ri = BigIntegerUtils.randomZnStar(N0, rnd);
            alpha.add(ai);
            beta.add(bi);
            r.add(ri);
        }

        // 批量计算A值
        long batchStart = System.nanoTime();
        BigInteger[] alphaArr = alpha.toArray(new BigInteger[0]);
        BigInteger[] betaArr = beta.toArray(new BigInteger[0]);
        BigInteger[] rArr = r.toArray(new BigInteger[0]);

        BigInteger onePlusN0 = N0.add(BigInteger.ONE);

        BigInteger[] negAlphaArr = new BigInteger[effectiveKappa];
        BigInteger[] onePlusN0Arr = new BigInteger[effectiveKappa];
        BigInteger[] n0ExpArr = new BigInteger[effectiveKappa];
        for (int i = 0; i < effectiveKappa; i++) {
            negAlphaArr[i] = alphaArr[i].negate();
            onePlusN0Arr[i] = onePlusN0;
            n0ExpArr[i] = N0;
        }

        BigInteger[][] batchResults;
        try {
            batchResults = BigIntegerUtils.batchModPowAll(
                    negAlphaArr, onePlusN0Arr, rArr, null, null,
                    negAlphaArr, betaArr, n0ExpArr, null, null,
                    N0sq, N0sq, N0sq, null, null
            );
        } catch (Exception ex) {
            logger.warn("batchModPowAll failed for PiDec, falling back: {}", ex.getMessage());
            BigInteger[] kPowNegAlpha = BigIntegerUtils.batchModPow(
                    java.util.Collections.nCopies(effectiveKappa, K).toArray(new BigInteger[0]),
                    negAlphaArr, N0sq);
            BigInteger[] onePlusN0PowBeta = BigIntegerUtils.batchModPow(
                    java.util.Collections.nCopies(effectiveKappa, onePlusN0).toArray(new BigInteger[0]),
                    betaArr, N0sq);
            BigInteger[] rPowN0 = BigIntegerUtils.batchModPow(rArr, N0, N0sq);
            batchResults = new BigInteger[5][];
            batchResults[0] = kPowNegAlpha;
            batchResults[1] = onePlusN0PowBeta;
            batchResults[2] = rPowN0;
        }

        BigInteger[] kPowNegAlpha = batchResults[0];
        BigInteger[] onePlusN0PowBeta = batchResults[1];
        BigInteger[] rPowN0 = batchResults[2];

        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger Ai = BigIntegerUtils.modMul(
                    BigIntegerUtils.modMul(kPowNegAlpha[i], onePlusN0PowBeta[i], N0sq),
                    rPowN0[i],
                    N0sq
            );
            A.add(Ai);
            B.add(ecMulSigned(g, betaArr[i]).normalize());
            C.add(ecMulSigned(g, alphaArr[i]).normalize());
        }

        logger.debug("PiDec A values computed in {} ms",
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - batchStart));

        boolean[] e = challengeBits("PI_DEC", context, effectiveKappa, A, B, C);

        BigInteger rhoPow0 = BigInteger.ONE;
        BigInteger rhoPow1 = BigIntegerUtils.modPow(rho, BigInteger.ONE, N0);

        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = alpha.get(i).add(ei.multiply(x));
            BigInteger wi = beta.get(i).add(ei.multiply(y));
            BigInteger rhoPowEi = e[i] ? rhoPow1 : rhoPow0;
            BigInteger nui = BigIntegerUtils.modMul(r.get(i), rhoPowEi, N0);
            z.add(zi);
            w.add(wi);
            nu.add(nui);
        }

        return new PiDecProof(A, B, C, z, w, nu);
    }

    public static boolean verifyDecProof(PiDecProof proof,
                                         ECPoint g,
                                         ECPoint X,
                                         ECPoint S,
                                         BigInteger N0,
                                         BigInteger K,
                                         BigInteger D,
                                         byte[] context) {
        return verifyDecProof(proof, g, X, S, N0, K, D, DEFAULT_KAPPA, RANGE_EPS_BITS, context);
    }

    public static boolean verifyDecProof(PiDecProof proof,
                                         ECPoint g,
                                         ECPoint X,
                                         ECPoint S,
                                         BigInteger N0,
                                         BigInteger K,
                                         BigInteger D,
                                         int kappa,
                                         int epsBits,
                                         byte[] context) {
        if (proof == null) return false;
        int n = proof.A().size();
        int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        if (n == 0 || n != effectiveKappa || proof.B().size() != n || proof.C().size() != n
                || proof.z().size() != n || proof.w().size() != n || proof.nu().size() != n) {
            return false;
        }
        BigInteger N0sq = N0.multiply(N0);
        boolean[] e = challengeBits("PI_DEC", context, n, proof.A(), proof.B(), proof.C());
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger rangeBound = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps);
        BigInteger onePlusN0 = BigInteger.ONE.add(N0);

        boolean[] results = new boolean[n];
        java.util.stream.IntStream.range(0, n).parallel().forEach(i -> {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = proof.z().get(i);
            BigInteger wi = proof.w().get(i);
            BigInteger nui = proof.nu().get(i);
            BigInteger left1 = BigIntegerUtils.modMul(
                    BigIntegerUtils.modMul(
                            BigIntegerUtils.powSigned(onePlusN0, wi, N0sq),
                            BigIntegerUtils.modPow(nui, N0, N0sq),
                            N0sq
                    ),
                    BigIntegerUtils.powSigned(K, zi.negate(), N0sq),
                    N0sq
            );
            BigInteger right1 = BigIntegerUtils.modMul(proof.A().get(i), BigIntegerUtils.modPow(D, ei, N0sq), N0sq);
            if (!left1.equals(right1)) {
                results[i] = false;
                return;
            }

            ECPoint leftX = ecMulSigned(g, zi).normalize();
            ECPoint rightX = proof.C().get(i).add(X.multiply(ei)).normalize();
            if (!leftX.equals(rightX)) {
                results[i] = false;
                return;
            }

            ECPoint leftY = ecMulSigned(g, wi).normalize();
            ECPoint rightY = proof.B().get(i).add(S.multiply(ei)).normalize();
            if (!leftY.equals(rightY)) {
                results[i] = false;
                return;
            }

            if (zi.abs().compareTo(rangeBound) > 0) {
                results[i] = false;
                return;
            }
            if (wi.abs().compareTo(rangeBound) > 0) {
                results[i] = false;
                return;
            }

            results[i] = true;
        });

        for (int i = 0; i < n; i++) {
            if (!results[i]) return false;
        }
        return true;
    }

    private static byte[] digest(String tag, byte[] context, Object... items) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            for (Object o : items) {
                if (o == null) continue;
                if (o instanceof BigInteger bi) {
                    md.update(bi.toByteArray());
                } else if (o instanceof ECPoint p) {
                    md.update(Secp256k1CurveUtils.encodePoint(p));
                } else if (o instanceof Map<?, ?> map) {
                    for (Map.Entry<?, ?> e : map.entrySet()) {
                        md.update(String.valueOf(e.getKey()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        md.update(String.valueOf(e.getValue()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                } else if (o instanceof byte[] bytes) {
                    md.update(bytes);
                } else {
                    md.update(String.valueOf(o).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            return md.digest();
        } catch (Exception e) {
            throw new RuntimeException("Presign proof digest failed", e);
        }
    }

    private static BigInteger challenge(String tag, ECPoint base, ECPoint X, ECPoint A, byte[] context) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(Secp256k1CurveUtils.encodePoint(base));
            md.update(Secp256k1CurveUtils.encodePoint(X));
            md.update(Secp256k1CurveUtils.encodePoint(A));
            if (context != null) {
                md.update(context);
            }
            return new BigInteger(1, md.digest()).mod(Secp256k1CurveUtils.n());
        } catch (Exception e) {
            throw new RuntimeException("Challenge failed", e);
        }
    }

    private static boolean[] challengeBits(String tag, byte[] context, int kappa, Object... items) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            for (Object o : items) {
                if (o == null) continue;
                if (o instanceof BigInteger bi) {
                    md.update(bi.toByteArray());
                } else if (o instanceof ECPoint p) {
                    md.update(Secp256k1CurveUtils.encodePoint(p));
                } else if (o instanceof List<?> list) {
                    for (Object li : list) {
                        if (li instanceof BigInteger lbi) {
                            md.update(lbi.toByteArray());
                        } else if (li instanceof ECPoint lp) {
                            md.update(Secp256k1CurveUtils.encodePoint(lp));
                        } else {
                            md.update(String.valueOf(li).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        }
                    }
                } else if (o instanceof Map<?, ?> map) {
                    for (Map.Entry<?, ?> e : map.entrySet()) {
                        md.update(String.valueOf(e.getKey()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        md.update(String.valueOf(e.getValue()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    }
                } else if (o instanceof byte[] bytes) {
                    md.update(bytes);
                } else {
                    md.update(String.valueOf(o).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            byte[] seed = md.digest();
            int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
            boolean[] bits = new boolean[effectiveKappa];
            int idx = 0;
            int off = 0;
            while (idx < effectiveKappa) {
                if (off >= seed.length) {
                    md.update(seed);
                    seed = md.digest();
                    off = 0;
                }
                int b = seed[off++] & 0xff;
                for (int k = 0; k < 8 && idx < effectiveKappa; k++) {
                    bits[idx++] = ((b >> k) & 1) == 1;
                }
            }
            return bits;
        } catch (Exception e) {
            throw new RuntimeException("Challenge bits failed", e);
        }
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static BigInteger randomSigned(BigInteger bound, SecureRandom rnd) {
        BigInteger r;
        int bits = bound.bitLength();
        do {
            r = new BigInteger(bits, rnd);
        } while (r.compareTo(bound) > 0);
        return rnd.nextBoolean() ? r : r.negate();
    }

    private static ECPoint ecMulSigned(ECPoint base, BigInteger k) {
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger m = k.mod(q);
        return base.multiply(m);
    }

    private static BigInteger challengeSigned(String tag, BigInteger q, byte[] context, Object... items) {
        byte[] h = digest(tag, context, items);
        BigInteger twoQ = q.shiftLeft(1);
        BigInteger e = new BigInteger(1, h).mod(twoQ);
        return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
    }

    private static BigInteger challengeSignedBounded(String tag, int bits, byte[] context, Object... items) {
        if (bits <= 0) {
            return BigInteger.ZERO;
        }
        byte[] h = digest(tag, context, items);
        BigInteger bound = BigInteger.ONE.shiftLeft(bits);
        BigInteger e = new BigInteger(1, h).mod(bound.shiftLeft(1));
        return e.compareTo(bound) >= 0 ? e.subtract(bound.shiftLeft(1)) : e;
    }
}
