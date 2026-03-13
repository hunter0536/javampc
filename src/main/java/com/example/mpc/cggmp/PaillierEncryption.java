package com.example.mpc.cggmp;

import com.example.mpc.cggmp.util.NativeBigInteger;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierEncryption {
    private static final boolean USE_NATIVE = NativeBigInteger.isNativeAvailable();
    
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
        if (USE_NATIVE) {
            BigInteger gm = NativeBigInteger.modPow(g, m, nSquared);
            BigInteger rn = NativeBigInteger.modPow(r, n, nSquared);
            return gm.multiply(rn).mod(nSquared);
        }
        BigInteger gm = g.modPow(m, nSquared);
        BigInteger rn = r.modPow(n, nSquared);
        return gm.multiply(rn).mod(nSquared);
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
        if (USE_NATIVE) {
            BigInteger cLambda = NativeBigInteger.modPow(c, lambda, nSquared);
            BigInteger l = cLambda.subtract(BigInteger.ONE).divide(n);
            return l.multiply(mu).mod(n);
        }
        BigInteger cLambda = c.modPow(lambda, nSquared);
        BigInteger l = cLambda.subtract(BigInteger.ONE).divide(n);
        return l.multiply(mu).mod(n);
    }

    public BigInteger recoverRandomizer(BigInteger c, BigInteger m) {
        if (USE_NATIVE) {
            BigInteger gm = NativeBigInteger.modPow(g, m, nSquared);
            BigInteger gmInv = NativeBigInteger.modInverse(gm, nSquared);
            BigInteger cOver = c.multiply(gmInv).mod(nSquared);
            BigInteger nInv = NativeBigInteger.modInverse(n, lambda);
            return NativeBigInteger.modPow(cOver, nInv, nSquared).mod(n);
        }
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
        if (USE_NATIVE) {
            return NativeBigInteger.modPow(c, k, nSquared);
        }
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

    public record PublicKey(BigInteger n, BigInteger nSquared, BigInteger g, int bitLength) {
        public PublicKey(BigInteger n) {
            this(n, n.multiply(n), n.add(BigInteger.ONE), n.bitLength());
        }

        @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
        public BigInteger encrypt(BigInteger m) {
            return encryptWithRandomness(m).c;
        }

        public BigInteger encryptWithRandom(BigInteger m, BigInteger r) {
            if (USE_NATIVE) {
                BigInteger gm = NativeBigInteger.modPow(g, m, nSquared);
                BigInteger rn = NativeBigInteger.modPow(r, n, nSquared);
                return gm.multiply(rn).mod(nSquared);
            }
            BigInteger gm = g.modPow(m, nSquared);
            BigInteger rn = r.modPow(n, nSquared);
            return gm.multiply(rn).mod(nSquared);
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
            return c1.multiply(c2).mod(nSquared);
        }

        public BigInteger multiply(BigInteger c, BigInteger k) {
            if (USE_NATIVE) {
                return NativeBigInteger.modPow(c, k, nSquared);
            }
            return c.modPow(k, nSquared);
        }
    }

    public record PrivateKey(BigInteger lambda, BigInteger mu, BigInteger p, BigInteger q, BigInteger n,
                             int bitLength) {
    }

    public record Encryption(BigInteger c, BigInteger r) {
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }

    private static BigInteger generateSafePrime(int bits, SecureRandom rnd) {
        final int batchSize = Runtime.getRuntime().availableProcessors() * 2;
        
        while (true) {
            java.util.List<BigInteger> candidates = java.util.stream.IntStream.range(0, batchSize)
                .parallel()
                .mapToObj(i -> {
                    BigInteger q = BigInteger.probablePrime(bits - 1, rnd);
                    return q.shiftLeft(1).add(BigInteger.ONE);
                })
                .collect(java.util.stream.Collectors.toList());
            
            java.util.Optional<BigInteger> found = candidates.parallelStream()
                .filter(p -> p.isProbablePrime(128))
                .findAny();
            
            if (found.isPresent()) {
                return found.get();
            }
        }
    }
}
