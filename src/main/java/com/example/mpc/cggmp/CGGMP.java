package com.example.mpc.cggmp;

import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CGGMP {
    private static final Logger logger = LoggerFactory.getLogger(CGGMP.class);

    private final int threshold;
    private final int totalNodes;
    private final int nodeId;
    private final String curveName;
    
    private PedersenCommitment pedersen;
    private PaillierEncryption paillier;
    private PaillierEncryption.PublicKey paillierPublicKey;
    
    private BigInteger secretShare;
    private ECPoint publicKey;
    private Map<Integer, PaillierEncryption.PublicKey> otherPaillierKeys;
    private Map<Integer, ECPoint> otherPublicKeys;
    
    private SecureRandom random;

    public CGGMP(int threshold, int totalNodes, int nodeId, String curveName) throws Exception {
        this.threshold = threshold;
        this.totalNodes = totalNodes;
        this.nodeId = nodeId;
        this.curveName = curveName;
        this.random = new SecureRandom();
        this.otherPaillierKeys = new ConcurrentHashMap<>();
        this.otherPublicKeys = new ConcurrentHashMap<>();
        
        initialize();
    }

    private void initialize() throws Exception {
        this.pedersen = new PedersenCommitment(curveName);
        this.paillier = new PaillierEncryption();
        this.paillierPublicKey = new PaillierEncryption.PublicKey(paillier.getPublicKey());
    }

    public DkgRound1Output dkgRound1() {
        logger.info("Node {} starting DKG Round 1", nodeId);
        
        BigInteger[] coefficients = new BigInteger[threshold];
        coefficients[0] = new BigInteger(pedersen.getCurveOrder().bitLength() - 1, random).mod(pedersen.getCurveOrder());
        
        for (int i = 1; i < threshold; i++) {
            coefficients[i] = new BigInteger(pedersen.getCurveOrder().bitLength() - 1, random).mod(pedersen.getCurveOrder());
        }
        
        this.secretShare = coefficients[0];
        
        List<ECPoint> commitments = new ArrayList<>();
        for (BigInteger coeff : coefficients) {
            commitments.add(pedersen.getG().multiply(coeff).normalize());
        }
        
        ECPoint publicKeyCommitment = commitments.get(0);
        this.publicKey = publicKeyCommitment;
        
        return new DkgRound1Output(nodeId, coefficients, commitments, paillierPublicKey);
    }

    public DkgRound2Output dkgRound2(Map<Integer, DkgRound1Output> round1Outputs) throws Exception {
        logger.info("Node {} starting DKG Round 2", nodeId);
        
        DkgRound1Output selfOutput = round1Outputs.get(nodeId);
        
        for (Map.Entry<Integer, DkgRound1Output> entry : round1Outputs.entrySet()) {
            if (entry.getKey() != nodeId) {
                otherPaillierKeys.put(entry.getKey(), entry.getValue().paillierKey);
                otherPublicKeys.put(entry.getKey(), entry.getValue().commitments.get(0));
            }
        }
        
        Map<Integer, BigInteger> shares = new HashMap<>();
        
        for (int i = 1; i <= totalNodes; i++) {
            if (i != nodeId) {
                BigInteger share = evaluatePolynomial(selfOutput.coefficients, BigInteger.valueOf(i));
                shares.put(i, share);
            }
        }
        
        BigInteger selfShare = evaluatePolynomial(selfOutput.coefficients, BigInteger.valueOf(nodeId));
        this.secretShare = selfShare;
        
        return new DkgRound2Output(nodeId, shares);
    }

    public boolean dkgRound3(Map<Integer, DkgRound2Output> round2Outputs, Map<Integer, DkgRound1Output> round1Outputs) {
        logger.info("Node {} starting DKG Round 3", nodeId);
        
        boolean allValid = true;
        
        for (Map.Entry<Integer, DkgRound2Output> entry : round2Outputs.entrySet()) {
            int senderId = entry.getKey();
            if (senderId != nodeId) {
                DkgRound2Output output = entry.getValue();
                BigInteger share = output.shares.get(nodeId);
                
                ECPoint expected = computeExpectedShare(round1Outputs.get(senderId).commitments, BigInteger.valueOf(nodeId));
                ECPoint actual = pedersen.getG().multiply(share).normalize();
                
                if (!expected.equals(actual)) {
                    logger.warn("Invalid share from node {}", senderId);
                    allValid = false;
                }
            }
        }
        
        if (allValid) {
            BigInteger totalShare = secretShare;
            for (Map.Entry<Integer, DkgRound2Output> entry : round2Outputs.entrySet()) {
                if (entry.getKey() != nodeId) {
                    BigInteger share = entry.getValue().shares.get(nodeId);
                    totalShare = totalShare.add(share).mod(pedersen.getCurveOrder());
                }
            }
            this.secretShare = totalShare;
            
            ECPoint groupPublicKey = publicKey;
            for (ECPoint otherPubKey : otherPublicKeys.values()) {
                groupPublicKey = groupPublicKey.add(otherPubKey).normalize();
            }
            this.publicKey = groupPublicKey;
        }
        
        return allValid;
    }

    public BigInteger getSecretShare() {
        return secretShare;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public int getNodeId() {
        return nodeId;
    }

    public PedersenCommitment getPedersen() {
        return pedersen;
    }

    private BigInteger evaluatePolynomial(List<ECPoint> commitments, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        
        for (int i = 0; i < commitments.size(); i++) {
            result = result.add(xPower).mod(pedersen.getCurveOrder());
            xPower = xPower.multiply(x).mod(pedersen.getCurveOrder());
        }
        
        return result;
    }

    private BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        
        for (BigInteger coeff : coefficients) {
            result = result.add(coeff.multiply(xPower)).mod(pedersen.getCurveOrder());
            xPower = xPower.multiply(x).mod(pedersen.getCurveOrder());
        }
        
        return result;
    }

    private ECPoint computeExpectedShare(List<ECPoint> commitments, BigInteger x) {
        ECPoint result = pedersen.getEcSpec().getCurve().getInfinity();
        BigInteger xPower = BigInteger.ONE;
        
        for (ECPoint commitment : commitments) {
            result = result.add(commitment.multiply(xPower)).normalize();
            xPower = xPower.multiply(x).mod(pedersen.getCurveOrder());
        }
        
        return result;
    }

    public static class DkgRound1Output {
        public final int nodeId;
        public final BigInteger[] coefficients;
        public final List<ECPoint> commitments;
        public final PaillierEncryption.PublicKey paillierKey;

        public DkgRound1Output(int nodeId, BigInteger[] coefficients, List<ECPoint> commitments, PaillierEncryption.PublicKey paillierKey) {
            this.nodeId = nodeId;
            this.coefficients = coefficients;
            this.commitments = commitments;
            this.paillierKey = paillierKey;
        }
    }

    public static class DkgRound2Output {
        public final int nodeId;
        public final Map<Integer, BigInteger> shares;

        public DkgRound2Output(int nodeId, Map<Integer, BigInteger> shares) {
            this.nodeId = nodeId;
            this.shares = shares;
        }
    }
}
