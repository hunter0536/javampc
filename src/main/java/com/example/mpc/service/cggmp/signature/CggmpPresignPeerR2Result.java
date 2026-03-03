package com.example.mpc.service.cggmp.signature;

import com.example.mpc.cggmp.proof.PiAffGProof;

import java.math.BigInteger;

/**
 * 预签名Round 2对等方结果
 * 存储与单个对等方执行MtA协议的结果
 */
public record CggmpPresignPeerR2Result(
        int peerId,
        boolean skipped,
        BigInteger beta,
        BigInteger betaHat,
        BigInteger d,
        BigInteger dhat,
        BigInteger f,
        BigInteger fhat,
        BigInteger rho,
        BigInteger mu,
        BigInteger rhoHat,
        BigInteger muHat,
        PiAffGProof proof,
        PiAffGProof proofHat,
        long peerMs) {
    /**
     * 创建跳过的结果
     */
    public static CggmpPresignPeerR2Result skipped(int peerId) {
        return new CggmpPresignPeerR2Result(peerId, true, null, null, null, null, null, null, null, null, null, null, null, null, 0L);
    }

    /**
     * 创建完成的结果
     */
    public static CggmpPresignPeerR2Result done(int peerId,
                                                BigInteger beta,
                                                BigInteger betaHat,
                                                BigInteger d,
                                                BigInteger dhat,
                                                BigInteger f,
                                                BigInteger fhat,
                                                BigInteger rho,
                                                BigInteger mu,
                                                BigInteger rhoHat,
                                                BigInteger muHat,
                                                PiAffGProof proof,
                                                PiAffGProof proofHat,
                                                long peerMs) {
        return new CggmpPresignPeerR2Result(peerId, false, beta, betaHat, d, dhat, f, fhat, rho, mu, rhoHat, muHat, proof, proofHat, peerMs);
    }
}
