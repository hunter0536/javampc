package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;

import java.math.BigInteger;

public class PaillierRespondentProofValidator {
    public boolean verifyProof(PaillierRespondentProof proof, com.example.mpc.cggmp.PaillierEncryption.PublicKey pubKey, PaillierRespondentProofContext ctx) {
        var g = pubKey.g;
        var n = pubKey.n;
        var nsq = pubKey.nSquared;
        var hatN = ctx.zkSetup().hatN();
        var h1 = ctx.zkSetup().h1();
        var h2 = ctx.zkSetup().h2();
        var q = ctx.q();

        var z = new BigInteger(proof.z());
        var zPrime = new BigInteger(proof.zPrime());
        var t = new BigInteger(proof.t());
        var v = new BigInteger(proof.v());
        var w = new BigInteger(proof.w());
        var s = new BigInteger(proof.s());

        var s1 = proof.s1();
        var s2 = proof.s2();
        var t1 = proof.t1();
        var t2 = proof.t2();

        var hashInput = ZkBytes.encode(
                ctx.c_i().toByteArray(),
                ctx.c_j().toByteArray(),
                z.toByteArray(),
                zPrime.toByteArray(),
                t.toByteArray(),
                v.toByteArray(),
                w.toByteArray(),
                ctx.additionalData() == null ? new byte[0] : ctx.additionalData()
        );

        var e = new BigInteger(1, ZkHash.sha256(hashInput)).mod(q);

        var q3 = q.pow(3);
        var q7 = q.pow(7);
        if (s1.compareTo(q3) > 0 || t1.compareTo(q7) > 0) {
            return false;
        }

        var left1 = h1.modPow(s1, hatN).multiply(h2.modPow(s2, hatN)).mod(hatN);
        var right1 = z.modPow(e, hatN).multiply(zPrime).mod(hatN);
        if (!left1.equals(right1)) {
            return false;
        }

        var left2 = h1.modPow(t1, hatN).multiply(h2.modPow(t2, hatN)).mod(hatN);
        var right2 = t.modPow(e, hatN).multiply(w).mod(hatN);
        if (!left2.equals(right2)) {
            return false;
        }

        var left3 = ctx.c_i().modPow(s1, nsq)
                .multiply(s.modPow(n, nsq))
                .multiply(g.modPow(t1, nsq))
                .mod(nsq);

        var right3 = ctx.c_j().modPow(e, nsq).multiply(v).mod(nsq);

        return left3.equals(right3);
    }
}
