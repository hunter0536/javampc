package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

public final class NoSmallFactorProofGenerator {
    private final ZKSetup zk;
    private final int ellBits;
    private final int epsBits;

    public NoSmallFactorProofGenerator(ZKSetup zk) {
        this(zk, 256, 16);
    }

    public NoSmallFactorProofGenerator(ZKSetup zk, int ellBits, int epsBits) {
        this.zk = Objects.requireNonNull(zk, "zk");
        this.ellBits = ellBits;
        this.epsBits = epsBits;
    }

    public NoSmallFactorProof createProof(PaillierEncryption.PrivateKey priv, byte[] context) {
        Objects.requireNonNull(priv, "priv");
        BigInteger Ni = priv.n();
        BigInteger Nj = zk.hatN();
        BigInteger s = zk.h1();
        BigInteger t = zk.h2();

        SecureRandom rnd = SecureRandomUtils.getInstance();

        BigInteger sqrtNiUp = sqrtUpper(Ni);
        BigInteger twoEll = BigInteger.ONE.shiftLeft(ellBits);
        BigInteger twoEllEps = BigInteger.ONE.shiftLeft(ellBits + epsBits);

        BigInteger alpha = randomSigned(twoEllEps.multiply(sqrtNiUp), rnd);
        BigInteger beta = randomSigned(twoEllEps.multiply(sqrtNiUp), rnd);
        BigInteger mu = randomSigned(twoEll.multiply(Nj), rnd);
        BigInteger nu = randomSigned(twoEll.multiply(Nj), rnd);
        BigInteger r = randomSigned(twoEllEps.multiply(Nj), rnd);
        BigInteger x = randomSigned(twoEllEps.multiply(Nj), rnd);
        BigInteger y = randomSigned(twoEllEps.multiply(Nj), rnd);

        BigInteger p = priv.p();
        BigInteger q = priv.q();

        BigInteger P = multiexpSigned(Nj, s, p, t, mu);
        BigInteger Q = multiexpSigned(Nj, s, q, t, nu);
        BigInteger A = multiexpSigned(Nj, s, alpha, t, x);
        BigInteger B = multiexpSigned(Nj, s, beta, t, y);
        BigInteger T = multiexpSigned(Nj, Q, alpha, t, r);

        byte[] ctx = (context == null) ? new byte[0] : context;
        byte[] hashInput = ZkBytes.encode(
                Ni.toByteArray(),
                Nj.toByteArray(),
                s.toByteArray(),
                t.toByteArray(),
                P.toByteArray(),
                Q.toByteArray(),
                A.toByteArray(),
                B.toByteArray(),
                T.toByteArray(),
                ctx
        );

        BigInteger eRaw = new BigInteger(1, ZkHash.sha256(hashInput)).mod(twoEll);
        BigInteger e = toSigned(eRaw, twoEll);

        BigInteger z1 = alpha.add(e.multiply(p));
        BigInteger z2 = beta.add(e.multiply(q));
        BigInteger w1 = x.add(e.multiply(mu));
        BigInteger w2 = y.add(e.multiply(nu));
        BigInteger v = r.subtract(nu.multiply(e).multiply(p));

        return new NoSmallFactorProof(
                P.toByteArray(), Q.toByteArray(), A.toByteArray(), B.toByteArray(), T.toByteArray(),
                z1, z2, w1, w2, v
        );
    }

    private static BigInteger sqrtUpper(BigInteger n) {
        int bl = n.bitLength();
        return BigInteger.ONE.shiftLeft((bl + 1) >>> 1);
    }

    private static BigInteger randomSigned(BigInteger bound, SecureRandom rnd) {
        BigInteger x;
        do {
            x = new BigInteger(bound.bitLength() + 1, rnd);
        } while (x.compareTo(bound) > 0);
        return rnd.nextBoolean() ? x : x.negate();
    }

    private static BigInteger multiexpSigned(BigInteger mod, BigInteger a, BigInteger e1, BigInteger b, BigInteger e2) {
        return BigIntegerUtils.powSigned(a, e1, mod).multiply(BigIntegerUtils.powSigned(b, e2, mod)).mod(mod);
    }

    private static BigInteger toSigned(BigInteger x, BigInteger twoEll) {
        BigInteger half = twoEll.shiftRight(1);
        return x.compareTo(half) >= 0 ? x.subtract(twoEll) : x;
    }
}
