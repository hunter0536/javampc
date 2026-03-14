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

        BigInteger sqrtNiUp = sqrtUpper(Ni);
        BigInteger twoEll = BigInteger.ONE.shiftLeft(ellBits);
        BigInteger twoEllEps = BigInteger.ONE.shiftLeft(ellBits + epsBits);

        BigInteger bound1 = twoEllEps.multiply(sqrtNiUp);
        BigInteger bound2 = twoEll.multiply(Nj);
        BigInteger bound3 = twoEllEps.multiply(Nj);

        BigInteger[] randomValues = new BigInteger[7];
        java.util.stream.IntStream.range(0, 7).parallel().forEach(i -> {
            SecureRandom rnd = SecureRandomUtils.getInstance();
            switch (i) {
                case 0: randomValues[0] = randomSigned(bound1, rnd); break;
                case 1: randomValues[1] = randomSigned(bound1, rnd); break;
                case 2: randomValues[2] = randomSigned(bound2, rnd); break;
                case 3: randomValues[3] = randomSigned(bound2, rnd); break;
                case 4: randomValues[4] = randomSigned(bound3, rnd); break;
                case 5: randomValues[5] = randomSigned(bound3, rnd); break;
                case 6: randomValues[6] = randomSigned(bound3, rnd); break;
            }
        });

        BigInteger alpha = randomValues[0];
        BigInteger beta = randomValues[1];
        BigInteger mu = randomValues[2];
        BigInteger nu = randomValues[3];
        BigInteger r = randomValues[4];
        BigInteger x = randomValues[5];
        BigInteger y = randomValues[6];

        BigInteger p = priv.p();
        BigInteger q = priv.q();

        BigInteger[] expResults = new BigInteger[4];
        java.util.stream.IntStream.range(0, 4).parallel().forEach(i -> {
            switch (i) {
                case 0: expResults[0] = multiexpSigned(Nj, s, p, t, mu); break;
                case 1: expResults[1] = multiexpSigned(Nj, s, q, t, nu); break;
                case 2: expResults[2] = multiexpSigned(Nj, s, alpha, t, x); break;
                case 3: expResults[3] = multiexpSigned(Nj, s, beta, t, y); break;
            }
        });

        BigInteger P = expResults[0];
        BigInteger Q = expResults[1];
        BigInteger A = expResults[2];
        BigInteger B = expResults[3];
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

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static BigInteger randomSigned(BigInteger bound, SecureRandom rnd) {
        BigInteger x;
        do {
            x = new BigInteger(bound.bitLength() + 1, rnd);
        } while (x.compareTo(bound) > 0);
        return rnd.nextBoolean() ? x : x.negate();
    }

    private static BigInteger multiexpSigned(BigInteger mod, BigInteger a, BigInteger e1, BigInteger b, BigInteger e2) {
        return BigIntegerUtils.modMul(BigIntegerUtils.powSigned(a, e1, mod), BigIntegerUtils.powSigned(b, e2, mod), mod);
    }

    private static BigInteger toSigned(BigInteger x, BigInteger twoEll) {
        BigInteger half = twoEll.shiftRight(1);
        return x.compareTo(half) >= 0 ? x.subtract(twoEll) : x;
    }
}
