package com.example.mpc.cggmp;

import com.example.mpc.constant.Constants;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class CGGMPTest {
    private static final Logger logger = LoggerFactory.getLogger(CGGMPTest.class);

    @Test
    public void testPaillierEncryption() throws Exception {
        logger.info("Testing Paillier encryption...");
        
        PaillierEncryption paillier = new PaillierEncryption();
        PaillierEncryption.PublicKey publicKey = new PaillierEncryption.PublicKey(paillier.getPublicKey());
        
        BigInteger m1 = BigInteger.valueOf(123);
        BigInteger m2 = BigInteger.valueOf(456);
        
        BigInteger c1 = publicKey.encrypt(m1);
        BigInteger c2 = publicKey.encrypt(m2);
        
        BigInteger decrypted1 = paillier.decrypt(c1);
        BigInteger decrypted2 = paillier.decrypt(c2);
        
        assertEquals(m1, decrypted1);
        assertEquals(m2, decrypted2);
        
        logger.info("Paillier encryption test passed!");
    }

    @Test
    public void testPaillierHomomorphicAddition() throws Exception {
        logger.info("Testing Paillier homomorphic addition...");
        
        PaillierEncryption paillier = new PaillierEncryption();
        PaillierEncryption.PublicKey publicKey = new PaillierEncryption.PublicKey(paillier.getPublicKey());
        
        BigInteger m1 = BigInteger.valueOf(10);
        BigInteger m2 = BigInteger.valueOf(20);
        
        BigInteger c1 = publicKey.encrypt(m1);
        BigInteger c2 = publicKey.encrypt(m2);
        
        BigInteger cSum = publicKey.add(c1, c2);
        BigInteger decryptedSum = paillier.decrypt(cSum);
        
        assertEquals(m1.add(m2), decryptedSum.mod(paillier.getN()));
        
        logger.info("Paillier homomorphic addition test passed!");
    }

    @Test
    public void testPedersenCommitment() throws Exception {
        logger.info("Testing Pedersen commitment...");
        
        PedersenCommitment pedersen = new PedersenCommitment(Constants.CURVE_NAME);
        
        BigInteger value = new BigInteger("123456789");
        PedersenCommitment.Commitment commitment = pedersen.commit(value);
        
        assertTrue(pedersen.verify(value, commitment.blinding, commitment.point));
        
        BigInteger wrongValue = new BigInteger("987654321");
        assertFalse(pedersen.verify(wrongValue, commitment.blinding, commitment.point));
        
        logger.info("Pedersen commitment test passed!");
    }

    @Test
    public void testSingleNodeCGGMP() throws Exception {
        logger.info("Testing single-node CGGMP...");
        
        CGGMP cggmp = new CGGMP(1, 1, 1, Constants.CURVE_NAME);
        CGGMPProtocol protocol = new CGGMPProtocol(cggmp);
        
        Map<Integer, CGGMP.DkgRound1Output> round1Outputs = new HashMap<>();
        CGGMP.DkgRound1Output round1 = cggmp.dkgRound1();
        round1Outputs.put(1, round1);
        
        Map<Integer, CGGMP.DkgRound2Output> round2Outputs = new HashMap<>();
        CGGMP.DkgRound2Output round2 = cggmp.dkgRound2(round1Outputs);
        round2Outputs.put(1, round2);
        
        boolean dkgSuccess = cggmp.dkgRound3(round2Outputs, round1Outputs);
        assertTrue(dkgSuccess);
        
        logger.info("Single-node DKG completed, public key: {}", cggmp.getPublicKey());
        
        String message = "Hello, CGGMP!";
        BigInteger messageHash = protocol.hashMessage(message, cggmp.getPedersen().getG());
        
        Map<Integer, CGGMPProtocol.SignRound1Output> signRound1Outputs = new HashMap<>();
        CGGMPProtocol.SignRound1Output signRound1 = protocol.signRound1(messageHash);
        signRound1Outputs.put(1, signRound1);
        
        Map<Integer, CGGMPProtocol.SignRound2Output> signRound2Outputs = new HashMap<>();
        CGGMPProtocol.SignRound2Output signRound2 = protocol.signRound2(signRound1Outputs, messageHash);
        signRound2Outputs.put(1, signRound2);
        
        Map<Integer, CGGMPProtocol.SignRound3Output> signRound3Outputs = new HashMap<>();
        CGGMPProtocol.SignRound3Output signRound3 = protocol.signRound3(signRound2Outputs, messageHash, signRound1.k);
        signRound3Outputs.put(1, signRound3);
        
        CGGMPProtocol.ECDSASignature signature = protocol.combineSignatures(signRound3Outputs, messageHash);
        
        logger.info("Signature generated: r={}, s={}", signature.r.toString(16), signature.s.toString(16));
        
        boolean verified = protocol.verifySignature(signature, cggmp.getPublicKey(), messageHash);
        assertTrue(verified);
        
        logger.info("Single-node CGGMP test passed!");
    }

    @Test
    public void testDirectSignature() throws Exception {
        logger.info("Testing direct signature...");
        
        CGGMP cggmp = new CGGMP(1, 1, 1, Constants.CURVE_NAME);
        CGGMPProtocol protocol = new CGGMPProtocol(cggmp);
        
        Map<Integer, CGGMP.DkgRound1Output> round1Outputs = new HashMap<>();
        CGGMP.DkgRound1Output round1 = cggmp.dkgRound1();
        round1Outputs.put(1, round1);
        
        Map<Integer, CGGMP.DkgRound2Output> round2Outputs = new HashMap<>();
        CGGMP.DkgRound2Output round2 = cggmp.dkgRound2(round1Outputs);
        round2Outputs.put(1, round2);
        
        cggmp.dkgRound3(round2Outputs, round1Outputs);
        
        String message = "Test message for direct signature";
        BigInteger messageHash = protocol.hashMessage(message, cggmp.getPedersen().getG());
        
        CGGMPProtocol.SignRound1Output signRound1 = protocol.signRound1(messageHash);
        BigInteger k = signRound1.k;
        ECPoint Gamma = signRound1.Gamma;
        BigInteger r = Gamma.getAffineXCoord().toBigInteger().mod(cggmp.getPedersen().getCurveOrder());
        BigInteger s = k.modInverse(cggmp.getPedersen().getCurveOrder())
            .multiply(messageHash.add(cggmp.getSecretShare().multiply(r)))
            .mod(cggmp.getPedersen().getCurveOrder());
        
        BigInteger halfOrder = cggmp.getPedersen().getCurveOrder().shiftRight(1);
        if (s.compareTo(halfOrder) > 0) {
            s = cggmp.getPedersen().getCurveOrder().subtract(s);
        }
        
        CGGMPProtocol.ECDSASignature signature = new CGGMPProtocol.ECDSASignature(r, s);
        
        boolean verified = protocol.verifySignature(signature, cggmp.getPublicKey(), messageHash);
        assertTrue(verified);
        
        logger.info("Direct signature test passed!");
    }
}
