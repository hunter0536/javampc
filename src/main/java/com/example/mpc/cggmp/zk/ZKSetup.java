package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.util.SecureRandomUtils;
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
        SecureRandom rnd = SecureRandomUtils.getInstance();
        BigInteger q = Secp256k1CurveUtils.n();
        BigInteger lambda;
        do {
            lambda = new BigInteger(q.bitLength(), rnd).mod(q);
        } while (lambda.signum() == 0);
        BigInteger h2 = BigIntegerUtils.powSigned(setup.h1, lambda, setup.hatN);
        ZKSetup zk = new ZKSetup(setup.hatN, setup.h1, h2);
        if (logger.isDebugEnabled()) {
            BigInteger check = BigIntegerUtils.powSigned(zk.h1(), lambda, zk.hatN());
            logger.debug("ZKSetup lambda relation check: hatNBits={}, h1Bits={}, h2Bits={}, ok={}",
                    zk.hatN().bitLength(), zk.h1().bitLength(), zk.h2().bitLength(), check.equals(zk.h2()));
        }
        return new ZKSetupWithLambda(zk, lambda);
    }

    private static InternalSetup generateInternal(int bitLength) {
        long startNs = System.nanoTime();
        SecureRandom rnd = SecureRandomUtils.getInstance();
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

    public record ZKSetupWithLambda(ZKSetup zk, BigInteger lambda) {
    }

    private static BigInteger sampleUnit(BigInteger hatN, SecureRandom rnd) {
        BigInteger u;
        do {
            u = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        } while (u.signum() == 0 || u.equals(BigInteger.ONE) || u.equals(hatN.subtract(BigInteger.ONE)) || !u.gcd(hatN).equals(BigInteger.ONE));
        return u;
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
