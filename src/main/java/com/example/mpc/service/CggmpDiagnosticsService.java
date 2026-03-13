package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiDecProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.SecureRandomUtils;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

@Service
public class CggmpDiagnosticsService {
    @Value("${cggmp.proof.kappa:128}")
    int proofKappa;

    @Value("${cggmp.proof.epsBits:16}")
    int proofEpsBits;

    public Map<String, Object> runProofSelfCheck() {
        Map<String, Object> result = new HashMap<>();
        result.put("kappa", proofKappa);
        result.put("epsBits", proofEpsBits);
        try {
            SecureRandom rnd = SecureRandomUtils.getInstance();
            BigInteger q = Secp256k1CurveUtils.n();

            int selfCheckKeyBits = 1024;
            // PiDec 自检
            PaillierEncryption paillier = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk = paillier.getPublicKeyInfo();
            BigInteger x = randomNonZero(q);
            BigInteger y = randomNonZero(q);
            PaillierEncryption.Encryption encX = pk.encryptWithRandomness(x);
            BigInteger K = encX.c();
            BigInteger rho = BigIntegerUtils.randomZnStar(pk.n(), rnd);
            BigInteger encY = pk.encryptWithRandom(y, rho);
            BigInteger KInvX = BigIntegerUtils.powSigned(K, x.negate(), pk.nSquared());
            BigInteger D = encY.multiply(KInvX).mod(pk.nSquared());
            ECPoint X = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x);
            ECPoint S = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y);
            PiDecProof decProof = PresignProofs.createDecProof(
                    Secp256k1CurveUtils.G(),
                    X,
                    S,
                    pk.n(),
                    K,
                    D,
                    x,
                    y,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean decOk = PresignProofs.verifyDecProof(
                    decProof,
                    Secp256k1CurveUtils.G(),
                    X,
                    S,
                    pk.n(),
                    K,
                    D,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piDecOk", decOk);

            // PiAffG 自检
            PaillierEncryption paillier0 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption paillier1 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk0 = paillier0.getPublicKeyInfo();
            PaillierEncryption.PublicKey pk1 = paillier1.getPublicKeyInfo();
            BigInteger x2 = randomNonZero(q);
            BigInteger y2 = randomNonZero(q);
            BigInteger a = randomNonZero(q);
            PaillierEncryption.Encryption encC = pk0.encryptWithRandomness(a);
            BigInteger C = encC.c();
            BigInteger rho2 = BigIntegerUtils.randomZnStar(pk0.n(), rnd);
            BigInteger mu2 = BigIntegerUtils.randomZnStar(pk1.n(), rnd);
            BigInteger D2 = BigIntegerUtils.powSigned(C, x2, pk0.nSquared())
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(pk0.n()), y2, pk0.nSquared()))
                    .multiply(rho2.modPow(pk0.n(), pk0.nSquared()))
                    .mod(pk0.nSquared());
            BigInteger Y2 = pk1.encryptWithRandom(y2, mu2);
            ECPoint X2 = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x2);
            PiAffGProof affProof = PresignProofs.createAffGProof(
                    Secp256k1CurveUtils.G(),
                    X2,
                    pk0.n(),
                    pk1.n(),
                    C,
                    D2,
                    Y2,
                    x2,
                    y2,
                    rho2,
                    mu2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean affOk = PresignProofs.verifyAffGProof(
                    affProof,
                    Secp256k1CurveUtils.G(),
                    X2,
                    pk0.n(),
                    pk1.n(),
                    C,
                    D2,
                    Y2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piAffGOk", affOk);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    private static BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }
}
