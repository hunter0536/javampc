package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.RespondentProofGenerator;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

public class PaillierRespondentProofGenerator implements RespondentProofGenerator {
    @Override
    public PaillierRespondentProof createProof(PaillierRespondentEncryptionWitness witness, byte[] context) {
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
        var q6 = q.pow(6);
        var hatNq = q.multiply(hatN);

        SecureRandom rnd = SecureRandomUtils.getInstance();

        var alpha = BigIntegerUtils.randomZnStar(q2, rnd);
        var beta = BigIntegerUtils.randomZnStar(n, rnd);
        var gamma = BigIntegerUtils.randomZnStar(q6, rnd);
        var rho = BigIntegerUtils.randomZnStar(hatNq, rnd);
        var sigma = BigIntegerUtils.randomZnStar(hatNq, rnd);
        var tau = BigIntegerUtils.randomZnStar(q6, rnd);

        var gPowGamma = onePlusN(gamma, n, nsq);

        var betaPowN = BigIntegerUtils.modPow(beta, n, nsq);
        var ciPowAlpha = BigIntegerUtils.modPow(witness.c_i(), alpha, nsq);

        var h1b = BigIntegerUtils.modPow(h1, witness.b(), hatN);
        var h2rho = BigIntegerUtils.modPow(h2, rho, hatN);
        var h1alpha = BigIntegerUtils.modPow(h1, alpha, hatN);
        var h2sigma = BigIntegerUtils.modPow(h2, sigma, hatN);

        var h2tau = BigIntegerUtils.modPow(h2, tau, hatN);
        var h1y = BigIntegerUtils.modPow(h1, witness.y(), hatN);
        var h1gamma = BigIntegerUtils.modPow(h1, gamma, hatN);

        var z = BigIntegerUtils.modMul(h1b, h2rho, hatN);
        var zPrime = BigIntegerUtils.modMul(h1alpha, h2sigma, hatN);

        var t = BigIntegerUtils.modMul(h1y, h2tau, hatN);

        var v = BigIntegerUtils.modMul(ciPowAlpha, gPowGamma, nsq);
        v = BigIntegerUtils.modMul(v, betaPowN, nsq);

        var w = BigIntegerUtils.modMul(h1gamma, h2tau, hatN);

        var ctx = (context == null) ? new byte[0] : context;

        var hashInput = ZkBytes.encode(
                witness.c_i().toByteArray(),
                witness.c_j().toByteArray(),
                z.toByteArray(),
                zPrime.toByteArray(),
                t.toByteArray(),
                v.toByteArray(),
                w.toByteArray(),
                ctx
        );
        var e = new BigInteger(1, ZkHash.sha256(hashInput)).mod(q);

        var s1 = e.multiply(witness.b()).add(alpha);
        var s2 = e.multiply(rho).add(sigma);
        var t1 = e.multiply(witness.y()).add(gamma);
        var t2 = e.multiply(tau).add(tau);

        var s = BigIntegerUtils.modMul(BigIntegerUtils.modPow(witness.r(), e, n), beta, n);

        return new PaillierRespondentProof(
                z.toByteArray(),
                zPrime.toByteArray(),
                t.toByteArray(),
                v.toByteArray(),
                w.toByteArray(),
                s.toByteArray(),
                s1, s2,
                t1, t2
        );
    }

    private static BigInteger onePlusN(BigInteger k, BigInteger n, BigInteger nsq) {
        return BigInteger.ONE.add(n.multiply(k)).mod(nsq);
    }
}
