package com.example.mpc.cggmp.sign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public final class CggmpIntegrityChecker {
    private CggmpIntegrityChecker() {
    }

    public static boolean isValidGammaPoint(ECPoint gamma) {
        return gamma != null && !gamma.isInfinity() && gamma.isValid();
    }

    public static boolean verifyGammaCommitment(EcChaumPedersenProof proof, ECPoint commitment, byte[] context) {
        if (proof == null || commitment == null) {
            return false;
        }
        return EcChaumPedersenProof.verify(proof, commitment, context);
    }

    public static boolean verifyGammaOpen(ECPoint commitment, ECPoint gamma, BigInteger blinding) {
        if (commitment == null || gamma == null || blinding == null) {
            return false;
        }
        BigInteger gammaValue = gamma.getAffineXCoord().toBigInteger().mod(Secp256k1Curve.n());
        ECPoint expected = EcPedersen.commit(gammaValue, blinding);
        return expected.equals(commitment);
    }

    public static boolean isValidU(BigInteger u, BigInteger n) {
        return u != null && u.signum() != 0 && u.compareTo(n) < 0;
    }
}
