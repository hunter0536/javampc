package com.example.mpc.cggmp;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierEncryption {
    private BigInteger n;
    private BigInteger nSquared;
    private BigInteger g;
    private BigInteger lambda;
    private BigInteger mu;
    private BigInteger p;
    private BigInteger q;
    private int bitLength;

    private static final int KEY_SIZE = 1024;
    public static final int MAX_KEY_SIZE = 4096;
    private final int keySize;

    public PaillierEncryption() {
        this(KEY_SIZE);
    }

    public PaillierEncryption(int keySize) {
        this.keySize = Math.max(512, keySize);
        generateKeys();
    }

    public PaillierEncryption(BigInteger p, BigInteger q) {
        this.keySize = Math.max(p.bitLength() + q.bitLength(), KEY_SIZE);
        this.p = p;
        this.q = q;
        initializeFromPQ();
    }

    private void generateKeys() {
        SecureRandom random = SecureRandomUtils.getInstance();
        int half = keySize / 2;

        p = BigIntegerUtils.generateSafePrime(half, random);
        q = BigIntegerUtils.generateSafePrime(half, random);

        while (p.equals(q)) {
            q = BigIntegerUtils.generateSafePrime(half, random);
        }

        initializeFromPQ();
    }

    private void initializeFromPQ() {
        n = p.multiply(q);
        nSquared = n.multiply(n);
        bitLength = n.bitLength();

        lambda = BigIntegerUtils.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        g = n.add(BigInteger.ONE);

        mu = BigIntegerUtils.modInverse(lambda, n);
    }

    public BigInteger encrypt(BigInteger m) {
        return encryptWithRandomness(m).c;
    }

    public BigInteger encryptWithRandom(BigInteger m, BigInteger r) {
        BigInteger gm;
        if (g.equals(n.add(BigInteger.ONE))) {
            gm = BigInteger.ONE.add(n.multiply(m)).mod(nSquared);
        } else {
            gm = BigIntegerUtils.modPow(g, m, nSquared);
        }
        BigInteger rn = BigIntegerUtils.modPow(r, n, nSquared);
        return BigIntegerUtils.modMul(gm, rn, nSquared);
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public Encryption encryptWithRandomness(BigInteger m) {
        SecureRandom random = SecureRandomUtils.getInstance();
        BigInteger r;

        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));

        BigInteger c = encryptWithRandom(m, r);
        return new Encryption(c, r);
    }

    public BigInteger decrypt(BigInteger c) {
        BigInteger cLambda = BigIntegerUtils.modPow(c, lambda, nSquared);
        BigInteger l = cLambda.subtract(BigInteger.ONE).divide(n);
        return BigIntegerUtils.modMul(l, mu, n);
    }

    public BigInteger recoverRandomizer(BigInteger c, BigInteger m) {
        BigInteger gm = BigIntegerUtils.modPow(g, m, nSquared);
        BigInteger gmInv = BigIntegerUtils.modInverse(gm, nSquared);
        BigInteger cOver = BigIntegerUtils.modMul(c, gmInv, nSquared);
        BigInteger nInv = BigIntegerUtils.modInverse(n, lambda);
        return BigIntegerUtils.modPow(cOver, nInv, nSquared).mod(n);
    }

    public BigInteger add(BigInteger c1, BigInteger c2) {
        return BigIntegerUtils.modMul(c1, c2, nSquared);
    }

    public BigInteger multiply(BigInteger c, BigInteger k) {
        return BigIntegerUtils.modPow(c, k, nSquared);
    }

    public BigInteger getPublicKey() {
        return n;
    }

    public PublicKey getPublicKeyInfo() {
        return new PublicKey(n, nSquared, g, bitLength);
    }

    public PrivateKey getPrivateKeyInfo() {
        return new PrivateKey(lambda, mu, p, q, n, bitLength);
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getNSquared() {
        return nSquared;
    }

    public BigInteger getG() {
        return g;
    }

    public int getBitLength() {
        return bitLength;
    }

    public record PublicKey(BigInteger n, BigInteger nSquared, BigInteger g, int bitLength) {
        public PublicKey(BigInteger n) {
            this(n, n.multiply(n), n.add(BigInteger.ONE), n.bitLength());
        }

        @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
        public BigInteger encrypt(BigInteger m) {
            return encryptWithRandomness(m).c;
        }

        public BigInteger encryptWithRandom(BigInteger m, BigInteger r) {
            BigInteger gm;
            if (g.equals(n.add(BigInteger.ONE))) {
                gm = BigInteger.ONE.add(n.multiply(m)).mod(nSquared);
            } else {
                gm = BigIntegerUtils.modPow(g, m, nSquared);
            }
            BigInteger rn = BigIntegerUtils.modPow(r, n, nSquared);
            return BigIntegerUtils.modMul(gm, rn, nSquared);
        }

        @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
        public Encryption encryptWithRandomness(BigInteger m) {
            SecureRandom random = SecureRandomUtils.getInstance();
            BigInteger r;

            do {
                r = new BigInteger(n.bitLength(), random);
            } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));

            BigInteger c = encryptWithRandom(m, r);
            return new Encryption(c, r);
        }

        public BigInteger add(BigInteger c1, BigInteger c2) {
            return BigIntegerUtils.modMul(c1, c2, nSquared);
        }

        public BigInteger multiply(BigInteger c, BigInteger k) {
            return BigIntegerUtils.modPow(c, k, nSquared);
        }
    }

    public record PrivateKey(BigInteger lambda, BigInteger mu, BigInteger p, BigInteger q, BigInteger n,
                             int bitLength) {
    }

    public record Encryption(BigInteger c, BigInteger r) {
    }
}
