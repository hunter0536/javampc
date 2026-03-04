package com.example.mpc.cggmp;

import com.example.mpc.common.util.SecureRandomUtils;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

public class PedersenCommitment {
    private ECPoint G;
    private ECPoint H;
    private BigInteger curveOrder;
    private org.bouncycastle.jce.spec.ECParameterSpec ecSpec;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public PedersenCommitment(String curveName) throws Exception {
        initializeCurve(curveName);
    }

    public PedersenCommitment(ECPoint G, ECPoint H, BigInteger curveOrder, org.bouncycastle.jce.spec.ECParameterSpec ecSpec) {
        this.G = G;
        this.H = H;
        this.curveOrder = curveOrder;
        this.ecSpec = ecSpec;
    }

    private void initializeCurve(String curveName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpecParam = new ECGenParameterSpec(curveName);
        keyGen.initialize(ecSpecParam);
        KeyPair keyPair = keyGen.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        this.ecSpec = publicKey.getParameters();
        this.G = ecSpec.getG();
        this.curveOrder = ecSpec.getN();

        SecureRandom random = SecureRandomUtils.getInstance();
        BigInteger h = new BigInteger(curveOrder.bitLength(), random).mod(curveOrder);
        this.H = G.multiply(h);
    }

    public Commitment commit(BigInteger value) {
        SecureRandom random = SecureRandomUtils.getInstance();
        BigInteger blinding = new BigInteger(curveOrder.bitLength(), random).mod(curveOrder);
        return commit(value, blinding);
    }

    public Commitment commit(BigInteger value, BigInteger blinding) {
        ECPoint point = G.multiply(value).add(H.multiply(blinding)).normalize();
        return new Commitment(point, blinding);
    }

    public boolean verify(BigInteger value, BigInteger blinding, ECPoint commitment) {
        ECPoint expected = G.multiply(value).add(H.multiply(blinding)).normalize();
        return expected.equals(commitment);
    }

    public ECPoint getG() {
        return G;
    }

    public ECPoint getH() {
        return H;
    }

    public BigInteger getCurveOrder() {
        return curveOrder;
    }

    public org.bouncycastle.jce.spec.ECParameterSpec getEcSpec() {
        return ecSpec;
    }

    public record Commitment(ECPoint point, BigInteger blinding) {
    }
}
