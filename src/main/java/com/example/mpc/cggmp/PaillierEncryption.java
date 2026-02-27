package com.example.mpc.cggmp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierEncryption {
    private static final Logger logger = LoggerFactory.getLogger(PaillierEncryption.class);

    private BigInteger n;
    private BigInteger nSquared;
    private BigInteger g;
    private BigInteger lambda;
    private BigInteger mu;
    private BigInteger p;
    private BigInteger q;
    private int bitLength;

    private static final int KEY_SIZE = 1024;
    private final int keySize;
    private static final BigInteger TWO = BigInteger.valueOf(2);

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
        SecureRandom random = new SecureRandom();
        int half = keySize / 2;

        p = generateSafePrime(half, random);
        q = generateSafePrime(half, random);

        while (p.equals(q)) {
            q = generateSafePrime(half, random);
        }

        initializeFromPQ();
    }

    private void initializeFromPQ() {
        n = p.multiply(q);
        nSquared = n.multiply(n);
        bitLength = n.bitLength();
        
        lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
        g = n.add(BigInteger.ONE);
        
        mu = lambda.modInverse(n);
    }

    public BigInteger encrypt(BigInteger m) {
        return encryptWithRandomness(m).c;
    }

    public BigInteger encryptWithRandom(BigInteger m, BigInteger r) {
        BigInteger gm = g.modPow(m, nSquared);
        BigInteger rn = r.modPow(n, nSquared);
        return gm.multiply(rn).mod(nSquared);
    }

    public Encryption encryptWithRandomness(BigInteger m) {
        SecureRandom random = new SecureRandom();
        BigInteger r;

        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));

        BigInteger c = encryptWithRandom(m, r);
        return new Encryption(c, r);
    }

    public BigInteger decrypt(BigInteger c) {
        BigInteger cLambda = c.modPow(lambda, nSquared);
        BigInteger l = cLambda.subtract(BigInteger.ONE).divide(n);
        return l.multiply(mu).mod(n);
    }

    public BigInteger recoverRandomizer(BigInteger c, BigInteger m) {
        BigInteger gm = g.modPow(m, nSquared);
        BigInteger gmInv = gm.modInverse(nSquared);
        BigInteger cOver = c.multiply(gmInv).mod(nSquared);
        BigInteger nInv = n.modInverse(lambda);
        return cOver.modPow(nInv, nSquared).mod(n);
    }

    public BigInteger add(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(nSquared);
    }

    public BigInteger multiply(BigInteger c, BigInteger k) {
        return c.modPow(k, nSquared);
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

    public static class PublicKey {
        public final BigInteger n;
        public final BigInteger nSquared;
        public final BigInteger g;
        public final int bitLength;

        public PublicKey(BigInteger n) {
            this(n, n.multiply(n), n.add(BigInteger.ONE), n.bitLength());
        }

        public PublicKey(BigInteger n, BigInteger nSquared, BigInteger g, int bitLength) {
            this.n = n;
            this.nSquared = nSquared;
            this.g = g;
            this.bitLength = bitLength;
        }

        public BigInteger encrypt(BigInteger m) {
            return encryptWithRandomness(m).c;
        }

        public BigInteger encryptWithRandom(BigInteger m, BigInteger r) {
            BigInteger gm = g.modPow(m, nSquared);
            BigInteger rn = r.modPow(n, nSquared);
            return gm.multiply(rn).mod(nSquared);
        }

        public Encryption encryptWithRandomness(BigInteger m) {
            SecureRandom random = new SecureRandom();
            BigInteger r;

            do {
                r = new BigInteger(n.bitLength(), random);
            } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));

            BigInteger c = encryptWithRandom(m, r);
            return new Encryption(c, r);
        }

        public BigInteger add(BigInteger c1, BigInteger c2) {
            return c1.multiply(c2).mod(nSquared);
        }

        public BigInteger multiply(BigInteger c, BigInteger k) {
            return c.modPow(k, nSquared);
        }
    }

    public static class PrivateKey {
        public final BigInteger lambda;
        public final BigInteger mu;
        public final BigInteger p;
        public final BigInteger q;
        public final BigInteger n;
        public final int bitLength;

        public PrivateKey(BigInteger lambda, BigInteger mu, BigInteger p, BigInteger q, BigInteger n, int bitLength) {
            this.lambda = lambda;
            this.mu = mu;
            this.p = p;
            this.q = q;
            this.n = n;
            this.bitLength = bitLength;
        }
    }

    public static class Encryption {
        public final BigInteger c;
        public final BigInteger r;

        public Encryption(BigInteger c, BigInteger r) {
            this.c = c;
            this.r = r;
        }
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }

    private static BigInteger generateSafePrime(int bits, SecureRandom rnd) {
        BigInteger p;
        while (true) {
            BigInteger q = BigInteger.probablePrime(bits - 1, rnd);
            p = q.shiftLeft(1).add(BigInteger.ONE);
            if (p.isProbablePrime(128)) {
                return p;
            }
        }
    }
}
