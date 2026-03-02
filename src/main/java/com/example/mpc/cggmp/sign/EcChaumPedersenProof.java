package com.example.mpc.cggmp.sign;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public record EcChaumPedersenProof(ECPoint A, BigInteger r, BigInteger s) {

    public static EcChaumPedersenProof create(BigInteger value, BigInteger blinding, ECPoint commitment, byte[] context) {
        BigInteger q = EcPedersen.n();
        SecureRandom rnd = new SecureRandom();
        BigInteger a;
        BigInteger b;
        do {
            a = new BigInteger(q.bitLength(), rnd).mod(q);
        } while (a.signum() == 0);
        do {
            b = new BigInteger(q.bitLength(), rnd).mod(q);
        } while (b.signum() == 0);

        ECPoint A = EcPedersen.G().multiply(a).add(EcPedersen.H().multiply(b)).normalize();
        BigInteger c = challenge(commitment, A, context, q);
        BigInteger rResp = a.add(c.multiply(value)).mod(q);
        BigInteger sResp = b.add(c.multiply(blinding)).mod(q);
        return new EcChaumPedersenProof(A, rResp, sResp);
    }

    public static boolean verify(EcChaumPedersenProof proof, ECPoint commitment, byte[] context) {
        BigInteger q = EcPedersen.n();
        BigInteger c = challenge(commitment, proof.A, context, q);
        ECPoint left = EcPedersen.G().multiply(proof.r).add(EcPedersen.H().multiply(proof.s)).normalize();
        ECPoint right = proof.A.add(commitment.multiply(c)).normalize();
        return left.equals(right);
    }

    private static BigInteger challenge(ECPoint commitment, ECPoint A, byte[] context, BigInteger q) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(Secp256k1CurveUtils.encodePoint(EcPedersen.G()));
            digest.update(Secp256k1CurveUtils.encodePoint(EcPedersen.H()));
            digest.update(Secp256k1CurveUtils.encodePoint(commitment));
            digest.update(Secp256k1CurveUtils.encodePoint(A));
            if (context != null) {
                digest.update(context);
            }
            byte[] out = digest.digest();
            return new BigInteger(1, out).mod(q);
        } catch (Exception e) {
            throw new RuntimeException("Chaum-Pedersen challenge failed", e);
        }
    }
}
