package com.example.mpc.cggmp.sign;

import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.zk.ZKSetup;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

public class CggmpSigner {
    private final int nodeId;
    private final BigInteger curveOrder;
    private final SecureRandom random = new SecureRandom();

    private final SignatureContext ctx = new SignatureContext();

    private BigInteger privateShare;
    private ECPoint groupPublicKey;

    public CggmpSigner(int nodeId) {
        this.nodeId = nodeId;
        this.curveOrder = Secp256k1Curve.n();
    }

    public SignatureContext context() {
        return ctx;
    }

    public void init(BigInteger privateShare, ECPoint groupPublicKey) {
        this.privateShare = privateShare.mod(curveOrder);
        this.groupPublicKey = groupPublicKey;
    }

    public byte[] gammaCommitment() {
        ctx.gamma_i = new BigInteger(curveOrder.bitLength() - 1, random).mod(curveOrder);
        ctx.k_i = new BigInteger(curveOrder.bitLength() - 1, random).mod(curveOrder);
        ECPoint gammaPoint = Secp256k1Curve.multiply(Secp256k1Curve.G(), ctx.gamma_i);
        byte[] commitment = Secp256k1Curve.encodePoint(gammaPoint);
        ctx.gammaCommitments.put(nodeId, commitment);
        return commitment;
    }

    public void storeGammaCommitment(int senderId, byte[] commitment) {
        ctx.gammaCommitments.put(senderId, commitment);
    }

    public MtAInitiatorMessage generateMtaInit(MtAProtocol protocol, ZKSetup zkSetup, byte[] mtaContext) {
        if (ctx.k_i == null) {
            throw new IllegalStateException("k_i not initialized");
        }
        return protocol.generateInitiatorMessage(ctx.k_i, zkSetup, mtaContext);
    }

    public void storeAlpha(int senderId, BigInteger alpha) {
        ctx.alphaShares.put(senderId, alpha);
    }

    public void storeBeta(int senderId, BigInteger beta) {
        ctx.betaShares.put(senderId, beta);
    }

    public BigInteger computeShareFromAlphaBeta(int senderId) {
        BigInteger alpha = ctx.alphaShares.get(senderId);
        BigInteger beta = ctx.betaShares.get(senderId);
        if (alpha == null || beta == null) {
            throw new IllegalStateException("missing alpha/beta for " + senderId);
        }
        return alpha.add(beta).mod(curveOrder);
    }

    public BigInteger partialSignature(BigInteger messageHash) {
        if (privateShare == null) {
            throw new IllegalStateException("private share not initialized");
        }
        return privateShare.multiply(messageHash).mod(curveOrder);
    }

    public BigInteger aggregatePartialS(Map<Integer, BigInteger> parts) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger p : parts.values()) {
            sum = sum.add(p).mod(curveOrder);
        }
        return sum;
    }
}
