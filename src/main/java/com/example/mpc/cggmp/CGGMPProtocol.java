package com.example.mpc.cggmp;

import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CGGMPProtocol {
    private static final Logger logger = LoggerFactory.getLogger(CGGMPProtocol.class);

    private final CGGMP cggmp;
    private final SecureRandom random;

    public CGGMPProtocol(CGGMP cggmp) {
        this.cggmp = cggmp;
        this.random = new SecureRandom();
    }

    public SignRound1Output signRound1(BigInteger messageHash) {
        logger.info("Node {} starting Sign Round 1", cggmp.getNodeId());

        BigInteger k = new BigInteger(cggmp.getPedersen().getCurveOrder().bitLength() - 1, random)
                .mod(cggmp.getPedersen().getCurveOrder());
        
        ECPoint Gamma = cggmp.getPedersen().getG().multiply(k).normalize();
        
        PedersenCommitment.Commitment KCommit = cggmp.getPedersen().commit(k);
        
        return new SignRound1Output(cggmp.getNodeId(), Gamma, KCommit.point, messageHash, k);
    }

    public SignRound2Output signRound2(Map<Integer, SignRound1Output> round1Outputs, BigInteger messageHash) {
        logger.info("Node {} starting Sign Round 2", cggmp.getNodeId());

        ECPoint sumGamma = cggmp.getPedersen().getEcSpec().getCurve().getInfinity();
        for (SignRound1Output output : round1Outputs.values()) {
            sumGamma = sumGamma.add(output.Gamma).normalize();
        }

        BigInteger r = sumGamma.getAffineXCoord().toBigInteger().mod(cggmp.getPedersen().getCurveOrder());
        
        BigInteger rho = new BigInteger(cggmp.getPedersen().getCurveOrder().bitLength(), random)
                .mod(cggmp.getPedersen().getCurveOrder());
        
        BigInteger sigma = rho.multiply(r).add(cggmp.getSecretShare()).mod(cggmp.getPedersen().getCurveOrder());
        
        PedersenCommitment.Commitment sigmaCommit = cggmp.getPedersen().commit(sigma);
        
        return new SignRound2Output(cggmp.getNodeId(), sigmaCommit.point, r, messageHash);
    }

    public SignRound3Output signRound3(Map<Integer, SignRound2Output> round2Outputs, BigInteger messageHash, BigInteger k) {
        logger.info("Node {} starting Sign Round 3", cggmp.getNodeId());

        BigInteger r = round2Outputs.values().iterator().next().r;
        
        BigInteger kInv = k.modInverse(cggmp.getPedersen().getCurveOrder());
        
        BigInteger sShare = kInv.multiply(messageHash).add(
            kInv.multiply(cggmp.getSecretShare()).multiply(r)
        ).mod(cggmp.getPedersen().getCurveOrder());
        
        return new SignRound3Output(cggmp.getNodeId(), sShare, r);
    }

    public ECDSASignature combineSignatures(Map<Integer, SignRound3Output> round3Outputs, BigInteger messageHash) {
        logger.info("Node {} combining signatures", cggmp.getNodeId());

        BigInteger r = round3Outputs.values().iterator().next().r;
        
        BigInteger s = BigInteger.ZERO;
        BigInteger lambdaSum = BigInteger.ZERO;
        
        for (Map.Entry<Integer, SignRound3Output> entry : round3Outputs.entrySet()) {
            BigInteger lambda = lagrangeCoefficient(entry.getKey(), round3Outputs.keySet());
            lambdaSum = lambdaSum.add(lambda).mod(cggmp.getPedersen().getCurveOrder());
            s = s.add(entry.getValue().sShare.multiply(lambda)).mod(cggmp.getPedersen().getCurveOrder());
        }
        
        BigInteger halfOrder = cggmp.getPedersen().getCurveOrder().shiftRight(1);
        if (s.compareTo(halfOrder) > 0) {
            s = cggmp.getPedersen().getCurveOrder().subtract(s);
        }
        
        return new ECDSASignature(r, s);
    }

    private BigInteger lagrangeCoefficient(int i, Set<Integer> participants) {
        BigInteger result = BigInteger.ONE;
        BigInteger curveOrder = cggmp.getPedersen().getCurveOrder();
        
        for (int j : participants) {
            if (j != i) {
                BigInteger numerator = BigInteger.valueOf(-j).mod(curveOrder);
                BigInteger denominator = BigInteger.valueOf(i - j).modInverse(curveOrder);
                result = result.multiply(numerator).multiply(denominator).mod(curveOrder);
            }
        }
        
        return result;
    }

    public boolean verifySignature(ECDSASignature signature, ECPoint publicKey, BigInteger messageHash) {
        try {
            BigInteger r = signature.r;
            BigInteger s = signature.s;
            BigInteger n = cggmp.getPedersen().getCurveOrder();
            ECPoint G = cggmp.getPedersen().getG();
            
            if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0) {
                return false;
            }
            if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) {
                return false;
            }
            
            BigInteger sInv = s.modInverse(n);
            BigInteger u1 = messageHash.multiply(sInv).mod(n);
            BigInteger u2 = r.multiply(sInv).mod(n);
            
            ECPoint point = G.multiply(u1).add(publicKey.multiply(u2)).normalize();
            
            if (point.isInfinity()) {
                return false;
            }
            
            BigInteger x = point.getAffineXCoord().toBigInteger().mod(n);
            return x.equals(r);
        } catch (Exception e) {
            logger.error("Error verifying signature", e);
            return false;
        }
    }

    public BigInteger hashMessage(String message, ECPoint R) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = message.getBytes("UTF-8");
        
        ECPoint normalizedR = R.normalize();
        byte[] rBytes = normalizedR.getAffineXCoord().getEncoded();
        
        byte[] input = new byte[messageBytes.length + rBytes.length];
        System.arraycopy(messageBytes, 0, input, 0, messageBytes.length);
        System.arraycopy(rBytes, 0, input, messageBytes.length, rBytes.length);
        
        byte[] hash = digest.digest(input);
        return new BigInteger(1, hash).mod(cggmp.getPedersen().getCurveOrder());
    }

    public static class SignRound1Output {
        public final int nodeId;
        public final ECPoint Gamma;
        public final ECPoint KCommit;
        public final BigInteger messageHash;
        public final BigInteger k;

        public SignRound1Output(int nodeId, ECPoint Gamma, ECPoint KCommit, BigInteger messageHash, BigInteger k) {
            this.nodeId = nodeId;
            this.Gamma = Gamma;
            this.KCommit = KCommit;
            this.messageHash = messageHash;
            this.k = k;
        }
    }

    public static class SignRound2Output {
        public final int nodeId;
        public final ECPoint sigmaCommit;
        public final BigInteger r;
        public final BigInteger messageHash;

        public SignRound2Output(int nodeId, ECPoint sigmaCommit, BigInteger r, BigInteger messageHash) {
            this.nodeId = nodeId;
            this.sigmaCommit = sigmaCommit;
            this.r = r;
            this.messageHash = messageHash;
        }
    }

    public static class SignRound3Output {
        public final int nodeId;
        public final BigInteger sShare;
        public final BigInteger r;

        public SignRound3Output(int nodeId, BigInteger sShare, BigInteger r) {
            this.nodeId = nodeId;
            this.sShare = sShare;
            this.r = r;
        }
    }

    public static class ECDSASignature {
        public final BigInteger r;
        public final BigInteger s;

        public ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }
    }
}
