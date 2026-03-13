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

        var betaPowN = beta.modPow(n, nsq);
        var h1m = h1.modPow(witness.m(), hatN);
        var h2rho = h2.modPow(rho, hatN);
        var h1alpha = h1.modPow(alpha, hatN);
        var h2gamma = h2.modPow(gamma, hatN);

        var z = h1m.multiply(h2rho).mod(hatN);
        var u = gPowAlpha.multiply(betaPowN).mod(nsq);
        var w = h1alpha.multiply(h2gamma).mod(hatN);

        var ctx = (context == null) ? new byte[0] : context;

        var hashInput = ZkBytes.encode(
                witness.c().toByteArray(),
                z.toByteArray(),
                u.toByteArray(),
                w.toByteArray(),
                ctx
        );

        var e = new BigInteger(1, ZkHash.sha256(hashInput)).mod(q);

        var s = witness.r().modPow(e, n).multiply(beta).mod(n);
        var s1 = e.multiply(witness.m()).add(alpha);
        var s2 = e.multiply(rho).add(gamma);

        return new PaillierRangeProof(z.toByteArray(), u.toByteArray(), w.toByteArray(), s.toByteArray(), s1, s2);
    }

    private static BigInteger onePlusN(BigInteger k, BigInteger n, BigInteger nsq) {
        return BigInteger.ONE.add(n.multiply(k)).mod(nsq);
    }
}
