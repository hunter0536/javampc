package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.RespondentProofGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

public class PaillierRespondentProofGenerator implements RespondentProofGenerator {
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

        SecureRandom rnd = new SecureRandom();

        var alpha = BigIntegerUtils.randomZnStar(q2, rnd);
        var beta = BigIntegerUtils.randomZnStar(n, rnd);
        var gamma = BigIntegerUtils.randomZnStar(q6, rnd);
        var rho = BigIntegerUtils.randomZnStar(hatNq, rnd);
        var sigma = BigIntegerUtils.randomZnStar(hatNq, rnd);
        var tau = BigIntegerUtils.randomZnStar(q6, rnd);

        var gPowGamma = onePlusN(gamma, n, nsq);

        var betaPowN = beta.modPow(n, nsq);
        var ciPowAlpha = witness.c_i().modPow(alpha, nsq);

        var h1b = h1.modPow(witness.b(), hatN);
        var h2rho = h2.modPow(rho, hatN);
        var h1alpha = h1.modPow(alpha, hatN);
        var h2sigma = h2.modPow(sigma, hatN);

        var h2tau = h2.modPow(tau, hatN);
        var h1y = h1.modPow(witness.y(), hatN);
        var h1gamma = h1.modPow(gamma, hatN);

        var z = h1b.multiply(h2rho).mod(hatN);
        var zPrime = h1alpha.multiply(h2sigma).mod(hatN);

        var t = h1y.multiply(h2tau).mod(hatN);

        var v = ciPowAlpha.multiply(gPowGamma).mod(nsq);
        v = v.multiply(betaPowN).mod(nsq);

        var w = h1gamma.multiply(h2tau).mod(hatN);

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

        var s = witness.r().modPow(e, n).multiply(beta).mod(n);

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
