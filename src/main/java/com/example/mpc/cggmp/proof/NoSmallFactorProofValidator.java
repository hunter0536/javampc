package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.ZKSetup;

import java.math.BigInteger;
import java.util.Objects;

public final class NoSmallFactorProofValidator {
    private final ZKSetup zk;
    private final int ellBits;
    private final int epsBits;

    public NoSmallFactorProofValidator(ZKSetup zk) {
        this(zk, 256, 16);
    }

    public NoSmallFactorProofValidator(ZKSetup zk, int ellBits, int epsBits) {
        this.zk = Objects.requireNonNull(zk, "zk");
        this.ellBits = ellBits;
        this.epsBits = epsBits;
    }

    public boolean verifyProof(NoSmallFactorProof pr, PaillierEncryption.PublicKey pk, byte[] context) {
        if (pr == null || pk == null) return false;

        BigInteger Ni = pk.n;
        if (Ni.bitLength() < 2048) return false;

        BigInteger Nj = zk.hatN();
        BigInteger s = zk.h1();
        BigInteger t = zk.h2();

        if (!Nj.gcd(s).equals(BigInteger.ONE)) return false;
        if (!Nj.gcd(t).equals(BigInteger.ONE)) return false;

        BigInteger P = new BigInteger(pr.P());
        BigInteger Q = new BigInteger(pr.Q());
        BigInteger A = new BigInteger(pr.A());
        BigInteger B = new BigInteger(pr.B());
        BigInteger T = new BigInteger(pr.T());

        BigInteger z1 = pr.z1();
        BigInteger z2 = pr.z2();
        BigInteger w1 = pr.w1();
        BigInteger w2 = pr.w2();
        BigInteger v = pr.v();

        if (!inRange(z1, Ni, ellBits, epsBits)) return false;
        if (!inRange(z2, Ni, ellBits, epsBits)) return false;

        if (!Nj.gcd(P).equals(BigInteger.ONE)) return false;
        if (!Nj.gcd(Q).equals(BigInteger.ONE)) return false;

        BigInteger twoEll = BigInteger.ONE.shiftLeft(ellBits);

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

        BigInteger lhs1 = multiexpSigned(Nj, s, z1, t, w1);
        BigInteger rhs1 = A.multiply(BigIntegerUtils.powSigned(P, e, Nj)).mod(Nj);
        if (!lhs1.equals(rhs1)) return false;

        BigInteger lhs2 = multiexpSigned(Nj, s, z2, t, w2);
        BigInteger rhs2 = B.multiply(BigIntegerUtils.powSigned(Q, e, Nj)).mod(Nj);
        if (!lhs2.equals(rhs2)) return false;

        BigInteger lhs3 = BigIntegerUtils.powSigned(Q, z1, Nj).multiply(BigIntegerUtils.powSigned(t, v, Nj)).mod(Nj);
        BigInteger rhs3 = T.multiply(BigIntegerUtils.powSigned(s, Ni.multiply(e), Nj)).mod(Nj);

        return lhs3.equals(rhs3);
    }

    private static boolean inRange(BigInteger z, BigInteger Ni, int ellBits, int epsBits) {
        BigInteger sqrtNiUp = BigInteger.ONE.shiftLeft((Ni.bitLength() + 1) >>> 1);
        BigInteger bound = BigInteger.ONE.shiftLeft(ellBits + epsBits).multiply(sqrtNiUp);
        BigInteger az = z.signum() >= 0 ? z : z.negate();
        return az.compareTo(bound) <= 0;
    }

    private static BigInteger multiexpSigned(BigInteger mod, BigInteger a, BigInteger e1, BigInteger b, BigInteger e2) {
        return BigIntegerUtils.powSigned(a, e1, mod).multiply(BigIntegerUtils.powSigned(b, e2, mod)).mod(mod);
    }

    private static BigInteger toSigned(BigInteger x, BigInteger twoEll) {
        BigInteger half = twoEll.shiftRight(1);
        return x.compareTo(half) >= 0 ? x.subtract(twoEll) : x;
    }
}
