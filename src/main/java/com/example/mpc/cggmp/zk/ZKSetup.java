package com.example.mpc.cggmp.zk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public record ZKSetup(BigInteger hatN, BigInteger h1, BigInteger h2) {
    private static final Logger logger = LoggerFactory.getLogger(ZKSetup.class);

    public static ZKSetup generate(int bitLength) {
        InternalSetup setup = generateInternal(bitLength);
        return new ZKSetup(setup.hatN, setup.h1, setup.h2);
    }

    public static ZKSetupWithLambda generateWithLambda(int bitLength) {
        InternalSetup setup = generateInternal(bitLength);
        return new ZKSetupWithLambda(new ZKSetup(setup.hatN, setup.h1, setup.h2), setup.lambda);
    }

    private static InternalSetup generateInternal(int bitLength) {
        long startNs = System.nanoTime();
        SecureRandom rnd = new SecureRandom();
        logger.debug("ZKSetup generate start: bitLength={}", bitLength);
        BigInteger p = generateSafePrime(bitLength / 2, rnd);
        logger.debug("ZKSetup safe prime p generated: bits={} elapsedMs={}",
                p.bitLength(), (System.nanoTime() - startNs) / 1_000_000);
        BigInteger q = generateSafePrime(bitLength / 2, rnd);
        while (p.equals(q)) {
            q = generateSafePrime(bitLength / 2, rnd);
        }
        logger.debug("ZKSetup safe prime q generated: bits={} elapsedMs={}",
                q.bitLength(), (System.nanoTime() - startNs) / 1_000_000);
        BigInteger hatN = p.multiply(q);

        BigInteger h1 = sampleUnit(hatN, rnd);
        BigInteger h2;
        do {
            h2 = sampleUnit(hatN, rnd);
        } while (h2.equals(h1));

        h1 = h1.modPow(BigInteger.TWO, hatN);
        h2 = h2.modPow(BigInteger.TWO, hatN);
        logger.debug("ZKSetup h1/h2 generated: hatNBits={} elapsedMs={}",
                hatN.bitLength(), (System.nanoTime() - startNs) / 1_000_000);

        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger lambda = lcm(pMinus1, qMinus1);
        logger.debug("ZKSetup lambda computed: elapsedMs={}", (System.nanoTime() - startNs) / 1_000_000);

        return new InternalSetup(hatN, h1, h2, lambda);
    }

    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.divide(a.gcd(b)).multiply(b);
    }

    private record InternalSetup(BigInteger hatN, BigInteger h1, BigInteger h2, BigInteger lambda) {
    }

    public static final class ZKSetupWithLambda {
        private final ZKSetup zk;
        private final BigInteger lambda;

        public ZKSetupWithLambda(ZKSetup zk, BigInteger lambda) {
            this.zk = zk;
            this.lambda = lambda;
        }

        public ZKSetup zk() {
            return zk;
        }

        public BigInteger lambda() {
            return lambda;
        }
    }

    private static BigInteger sampleUnit(BigInteger hatN, SecureRandom rnd) {
        BigInteger u;
        do {
            u = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        } while (u.signum() == 0 || u.equals(BigInteger.ONE) || u.equals(hatN.subtract(BigInteger.ONE)) || !u.gcd(hatN).equals(BigInteger.ONE));
        return u;
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
