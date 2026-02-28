package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PaillierRangeEncryptionWitness;
import com.example.mpc.cggmp.proof.PaillierRangeProof;
import com.example.mpc.cggmp.proof.PaillierRangeProofContext;
import com.example.mpc.cggmp.proof.PaillierRangeProofGenerator;
import com.example.mpc.cggmp.proof.PaillierRangeProofValidator;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.example.mpc.cggmp.zk.ZKSetup;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public final class PresignProofs {
    private static final Logger logger = LoggerFactory.getLogger(PresignProofs.class);
    public record EncElgVerifyResult(boolean ok, boolean eq1, boolean eq2, boolean eq3, boolean eq4, boolean z1InRange) {
    }

    public record AffGVerifyResult(boolean ok, int index, boolean eq1, boolean eq2, boolean eq3, boolean zInRange, boolean zPrimeInRange) {
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
        return createAffGProofInternal(g, X, N0, N1, C, D, Y, x, y, rho, mu, false, kappa, epsBits, context);
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
        return createAffGProofInternal(g, X, N0, N1, C, D, Y, x, y, rho, mu, true, kappa, epsBits, context);
    }

    private static PiAffGProof createAffGProofInternal(ECPoint g,
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
                                                       boolean negY,
                                                       int kappa,
                                                       int epsBits,
                                                       byte[] context) {
        int effectiveKappa = kappa > 0 ? kappa : DEFAULT_KAPPA;
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        BigInteger N0sq = N0.multiply(N0);
        BigInteger N1sq = N1.multiply(N1);
        long t0 = System.nanoTime();
        SecureRandom rnd = new SecureRandom();
        logger.info("PiAffG start: kappa={}, epsBits={}, negY={}, N0Bits={}, N1Bits={}",
                effectiveKappa, effectiveEps, negY, N0.bitLength(), N1.bitLength());

        List<BigInteger> A = new ArrayList<>(effectiveKappa);
        List<BigInteger> B = new ArrayList<>(effectiveKappa);
        List<ECPoint> R = new ArrayList<>(effectiveKappa);
        List<BigInteger> z = new ArrayList<>(effectiveKappa);
        List<BigInteger> zPrime = new ArrayList<>(effectiveKappa);
        List<BigInteger> w = new ArrayList<>(effectiveKappa);
        List<BigInteger> lambda = new ArrayList<>(effectiveKappa);

        List<BigInteger> alpha = new ArrayList<>(effectiveKappa);
        List<BigInteger> beta = new ArrayList<>(effectiveKappa);
        List<BigInteger> r = new ArrayList<>(effectiveKappa);
        List<BigInteger> s = new ArrayList<>(effectiveKappa);

        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger rangeBound = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 1);
        long loop1Start = System.nanoTime();
        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ai = randomSigned(rangeBound, rnd);
            BigInteger bi = randomSigned(rangeBound, rnd);
            BigInteger ri = randomZnStar(N0, rnd);
            BigInteger si = randomZnStar(N1, rnd);
            alpha.add(ai);
            beta.add(bi);
            r.add(ri);
            s.add(si);

            BigInteger bForN0 = negY ? bi.negate() : bi;
            BigInteger Aj = BigIntegerUtils.powSigned(C, ai, N0sq)
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), bForN0, N0sq))
                    .multiply(ri.modPow(N0, N0sq))
                    .mod(N0sq);
            BigInteger Bj = BigIntegerUtils.powSigned(BigInteger.ONE.add(N1), bi, N1sq)
                    .multiply(si.modPow(N1, N1sq))
                    .mod(N1sq);
            ECPoint Rj = ecMulSigned(g, ai).normalize();
            A.add(Aj);
            B.add(Bj);
            R.add(Rj);
            if ((i + 1) % 8 == 0 || i + 1 == effectiveKappa) {
                long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - loop1Start);
                logger.debug("PiAffG progress: built {}/{} tuples in {} ms", i + 1, effectiveKappa, elapsedMs);
            }
        }

        long challengeStart = System.nanoTime();
        boolean[] e = challengeBits("PI_AFFG", context, effectiveKappa, A, B, R);
        long challengeMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - challengeStart);
        logger.debug("PiAffG challenge computed in {} ms", challengeMs);
        long loop2Start = System.nanoTime();
        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = alpha.get(i).add(ei.multiply(x));
            BigInteger zpi = beta.get(i).add(ei.multiply(y));
            BigInteger wi = r.get(i).multiply(rho.modPow(ei, N0)).mod(N0);
            BigInteger li = s.get(i).multiply(mu.modPow(ei, N1)).mod(N1);
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

        for (int i = 0; i < n; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = proof.z().get(i);
            BigInteger zpi = proof.zPrime().get(i);
            BigInteger wi = proof.w().get(i);
            BigInteger li = proof.lambda().get(i);

            BigInteger zPrimeForN0 = negY ? zpi.negate() : zpi;
            BigInteger left1 = BigIntegerUtils.powSigned(C, zi, N0sq)
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), zPrimeForN0, N0sq))
                    .multiply(wi.modPow(N0, N0sq))
                    .mod(N0sq);
            BigInteger right1 = proof.A().get(i).multiply(D.modPow(ei, N0sq)).mod(N0sq);
            boolean eq1 = left1.equals(right1);

            ECPoint left2 = ecMulSigned(g, zi).normalize();
            ECPoint right2 = proof.R().get(i).add(X.multiply(ei)).normalize();
            boolean eq2 = left2.equals(right2);

            BigInteger left3 = BigIntegerUtils.powSigned(BigInteger.ONE.add(N1), zpi, N1sq)
                    .multiply(li.modPow(N1, N1sq))
                    .mod(N1sq);
            BigInteger right3 = proof.B().get(i).multiply(Y.modPow(ei, N1sq)).mod(N1sq);
            boolean eq3 = left3.equals(right3);

            boolean zInRange = zi.abs().compareTo(rangeBound) <= 0;
            boolean zPrimeInRange = zpi.abs().compareTo(rangeBound) <= 0;
            if (!(eq1 && eq2 && eq3 && zInRange && zPrimeInRange)) {
                return new AffGVerifyResult(false, i, eq1, eq2, eq3, zInRange, zPrimeInRange);
            }
        }
        return new AffGVerifyResult(true, -1, true, true, true, true, true);
    }

    public static PiLogStarProof createLogStarProof(ECPoint base, ECPoint X, BigInteger secret, byte[] context) {
        BigInteger q = Secp256k1CurveUtils.n();
        SecureRandom rnd = new SecureRandom();
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
        BigInteger q = Secp256k1CurveUtils.n();
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
        SecureRandom rnd = new SecureRandom();
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
        BigInteger N0 = publicKey.n;
        BigInteger N0sq = publicKey.nSquared;
        BigInteger hatN = zkSetup.hatN();
        BigInteger s = zkSetup.h1();
        BigInteger t = zkSetup.h2();
        SecureRandom rnd = new SecureRandom();
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;

        BigInteger boundX = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 1);
        BigInteger boundMu = BigInteger.ONE.shiftLeft(q.bitLength()).multiply(hatN);
        BigInteger boundGamma = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 2).multiply(hatN);

        BigInteger mu = randomSigned(boundMu, rnd);
        BigInteger alpha = randomSigned(boundX, rnd);
        BigInteger beta = new BigInteger(q.bitLength(), rnd).mod(q);
        BigInteger gamma = randomSigned(boundGamma, rnd);
        BigInteger r = randomZnStar(N0, rnd);

        BigInteger S = BigIntegerUtils.powSigned(s, x, hatN)
                .multiply(BigIntegerUtils.powSigned(t, mu, hatN))
                .mod(hatN);
        BigInteger D = BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), alpha, N0sq)
                .multiply(r.modPow(N0, N0sq))
                .mod(N0sq);
        ECPoint Y = A.multiply(beta).add(g.multiply(alpha)).normalize();
        ECPoint Z = g.multiply(beta).normalize();
        BigInteger T = BigIntegerUtils.powSigned(s, alpha, hatN)
                .multiply(BigIntegerUtils.powSigned(t, gamma, hatN))
                .mod(hatN);

        BigInteger e = challengeSignedBounded("PI_ENC_ELG", effectiveEps, context, publicKey.n, A, B, X, S, T, D, Y, Z);
        BigInteger z1 = alpha.add(e.multiply(x));
        BigInteger w = beta.add(e.multiply(b)).mod(q);
        BigInteger z2 = r.multiply(BigIntegerUtils.powSigned(rho, e, N0)).mod(N0);
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
        BigInteger N0 = publicKey.n;
        BigInteger N0sq = publicKey.nSquared;
        BigInteger hatN = zkSetup.hatN();
        BigInteger s = zkSetup.h1();
        BigInteger t = zkSetup.h2();
        int effectiveEps = epsBits > 0 ? epsBits : RANGE_EPS_BITS;
        BigInteger boundX = BigInteger.ONE.shiftLeft(q.bitLength() + effectiveEps + 2);

        BigInteger e = challengeSignedBounded("PI_ENC_ELG", effectiveEps, context, publicKey.n, A, B, X, proof.S(), proof.T(), proof.D(), proof.Y(), proof.Z());

        BigInteger left1 = BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), proof.z1(), N0sq)
                .multiply(proof.z2().modPow(N0, N0sq))
                .mod(N0sq);
        BigInteger right1 = proof.D().multiply(BigIntegerUtils.powSigned(C, e, N0sq)).mod(N0sq);
        boolean eq1 = left1.equals(right1);

        ECPoint left2 = A.multiply(proof.w()).add(g.multiply(proof.z1())).normalize();
        ECPoint right2 = proof.Y().add(X.multiply(e)).normalize();
        boolean eq2 = left2.equals(right2);

        ECPoint left3 = g.multiply(proof.w()).normalize();
        ECPoint right3 = proof.Z().add(B.multiply(e)).normalize();
        boolean eq3 = left3.equals(right3);

        BigInteger left4 = BigIntegerUtils.powSigned(s, proof.z1(), hatN)
                .multiply(BigIntegerUtils.powSigned(t, proof.z3(), hatN))
                .mod(hatN);
        BigInteger right4 = proof.T().multiply(BigIntegerUtils.powSigned(proof.S(), e, hatN)).mod(hatN);
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
        SecureRandom rnd = new SecureRandom();
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

        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ai = randomSigned(rangeBound, rnd);
            BigInteger bi = randomSigned(rangeBound, rnd);
            BigInteger ri = randomZnStar(N0, rnd);
            alpha.add(ai);
            beta.add(bi);
            r.add(ri);

            BigInteger Aj = BigIntegerUtils.powSigned(K, ai.negate(), N0sq)
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), bi, N0sq))
                    .multiply(ri.modPow(N0, N0sq))
                    .mod(N0sq);
            A.add(Aj);
            B.add(ecMulSigned(g, bi).normalize());
            C.add(ecMulSigned(g, ai).normalize());
        }

        boolean[] e = challengeBits("PI_DEC", context, effectiveKappa, A, B, C);
        for (int i = 0; i < effectiveKappa; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = alpha.get(i).add(ei.multiply(x));
            BigInteger wi = beta.get(i).add(ei.multiply(y));
            BigInteger nui = r.get(i).multiply(rho.modPow(ei, N0)).mod(N0);
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
        for (int i = 0; i < n; i++) {
            BigInteger ei = e[i] ? BigInteger.ONE : BigInteger.ZERO;
            BigInteger zi = proof.z().get(i);
            BigInteger wi = proof.w().get(i);
            BigInteger nui = proof.nu().get(i);
            BigInteger left1 = BigIntegerUtils.powSigned(BigInteger.ONE.add(N0), wi, N0sq)
                    .multiply(nui.modPow(N0, N0sq))
                    .multiply(BigIntegerUtils.powSigned(K, zi.negate(), N0sq))
                    .mod(N0sq);
            BigInteger right1 = proof.A().get(i).multiply(D.modPow(ei, N0sq)).mod(N0sq);
            if (!left1.equals(right1)) return false;

            ECPoint leftX = ecMulSigned(g, zi).normalize();
            ECPoint rightX = proof.C().get(i).add(X.multiply(ei)).normalize();
            if (!leftX.equals(rightX)) return false;

            ECPoint leftY = ecMulSigned(g, wi).normalize();
            ECPoint rightY = proof.B().get(i).add(S.multiply(ei)).normalize();
            if (!leftY.equals(rightY)) return false;

            if (zi.abs().compareTo(rangeBound) > 0) return false;
            if (wi.abs().compareTo(rangeBound) > 0) return false;
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

    private static BigInteger randomZnStar(BigInteger n, SecureRandom rnd) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0 || !r.gcd(n).equals(BigInteger.ONE));
        return r;
    }

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
