package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.RangeProofGenerator;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

public class PaillierRangeProofGenerator implements RangeProofGenerator {
    @Override
    public PaillierRangeProof createProof(PaillierRangeEncryptionWitness witness, byte[] context) {
        Objects.requireNonNull(witness, "witness");

        var pubKey = witness.publicKey();
        var zkSetup = witness.zk();

        var n = pubKey.n();
        var nsq = pubKey.nSquared();

        var hatN = zkSetup.hatN();
        var h1 = zkSetup.h1();
        var h2 = zkSetup.h2();

        var q = witness.q();
        var q2 = q.pow(2);

        SecureRandom rnd = SecureRandomUtils.getInstance();

        var alpha = BigIntegerUtils.randomZnStar(q2, rnd);
        var beta = BigIntegerUtils.randomZnStar(n, rnd);
        var gamma = BigIntegerUtils.randomZnStar(q2.multiply(hatN), rnd);
        var rho = BigIntegerUtils.randomZnStar(q.multiply(hatN), rnd);

        var gPowAlpha = onePlusN(alpha, n, nsq);

        var betaPowN = BigIntegerUtils.modPow(beta, n, nsq);
        var h1m = BigIntegerUtils.modPow(h1, witness.m(), hatN);
        var h2rho = BigIntegerUtils.modPow(h2, rho, hatN);
        var h1alpha = BigIntegerUtils.modPow(h1, alpha, hatN);
        var h2gamma = BigIntegerUtils.modPow(h2, gamma, hatN);

        var z = BigIntegerUtils.modMul(h1m, h2rho, hatN);
        var u = BigIntegerUtils.modMul(gPowAlpha, betaPowN, nsq);
        var w = BigIntegerUtils.modMul(h1alpha, h2gamma, hatN);

        var ctx = (context == null) ? new byte[0] : context;

        var hashInput = ZkBytes.encode(
                witness.c().toByteArray(),
                z.toByteArray(),
                u.toByteArray(),
                w.toByteArray(),
                ctx
        );

        var e = new BigInteger(1, ZkHash.sha256(hashInput)).mod(q);

        var s = BigIntegerUtils.modMul(BigIntegerUtils.modPow(witness.r(), e, n), beta, n);
        var s1 = e.multiply(witness.m()).add(alpha);
        var s2 = e.multiply(rho).add(gamma);

        return new PaillierRangeProof(z.toByteArray(), u.toByteArray(), w.toByteArray(), s.toByteArray(), s1, s2);
    }

    private static BigInteger onePlusN(BigInteger k, BigInteger n, BigInteger nsq) {
        return BigInteger.ONE.add(n.multiply(k)).mod(nsq);
    }
}
