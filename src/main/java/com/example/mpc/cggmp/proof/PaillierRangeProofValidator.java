package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.ZkBytes;
import com.example.mpc.cggmp.util.ZkHash;
import com.example.mpc.cggmp.zk.RangeProofValidator;

import java.math.BigInteger;

public class PaillierRangeProofValidator implements RangeProofValidator {
    public boolean verifyProof(PaillierRangeProof proof, com.example.mpc.cggmp.PaillierEncryption.PublicKey pubKey, PaillierRangeProofContext ctx) {
        var g = pubKey.g();
        var n = pubKey.n();
        var nsq = pubKey.nSquared();
        var hatN = ctx.zkSetup().hatN();
        var h1 = ctx.zkSetup().h1();
        var h2 = ctx.zkSetup().h2();

        var z = new BigInteger(proof.z());
        var u = new BigInteger(proof.u());
        var w = new BigInteger(proof.w());
        var s = new BigInteger(proof.s());

        var s1 = proof.s1();
        var s2 = proof.s2();

        var hashInput = ZkBytes.encode(
                ctx.c().toByteArray(),
                z.toByteArray(),
                u.toByteArray(),
                w.toByteArray(),
                ctx.additionalData() == null ? new byte[0] : ctx.additionalData()
        );
        var e = new BigInteger(1, ZkHash.sha256(hashInput)).mod(ctx.q());

        var q3 = ctx.q().pow(3);
        if (s1.compareTo(q3) > 0) {
            return false;
        }

        var left1 = g.modPow(s1, nsq)
                .multiply(s.modPow(n, nsq))
                .mod(nsq);

        var right1 = u.multiply(ctx.c().modPow(e, nsq)).mod(nsq);
        if (!left1.equals(right1)) {
            return false;
        }

        var left2 = h1.modPow(s1, hatN)
                .multiply(h2.modPow(s2, hatN))
                .mod(hatN);

        var right2 = z.modPow(e, hatN).multiply(w).mod(hatN);

        return left2.equals(right2);
    }
}
