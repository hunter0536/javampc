package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.stream.IntStream;

public final class JavaBackend implements BigIntegerBackend {
    private static final Logger logger = LoggerFactory.getLogger(JavaBackend.class);
    private static final JavaBackend INSTANCE = new JavaBackend();

    private JavaBackend() {
    }

    public static JavaBackend getInstance() {
        return INSTANCE;
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[Java] modPow: base={} bits, exp={} bits, mod={} bits", 
                        base.bitLength(), exp.bitLength(), mod.bitLength());
        }
        return base.modPow(exp, mod);
    }

    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[Java] modInverse: val={} bits, mod={} bits", 
                        val.bitLength(), mod.bitLength());
        }
        return val.modInverse(mod);
    }

    @Override
    public BigInteger multiply(BigInteger a, BigInteger b) {
        if (logger.isDebugEnabled()) {
            logger.debug("[Java] multiply: a={} bits, b={} bits", 
                        a.bitLength(), b.bitLength());
        }
        return a.multiply(b);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[Java] batchModPow: batchSize={}, exp={} bits, mod={} bits", 
                        bases.length, exp.bitLength(), mod.bitLength());
        }
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exp, mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (bases.length != exps.length) {
            throw new IllegalArgumentException("bases and exps must have same length");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("[Java] batchModPowDifferentExp: batchSize={}, mod={} bits", 
                        bases.length, mod.bitLength());
        }
        return IntStream.range(0, bases.length)
                .parallel()
                .mapToObj(i -> bases[i].modPow(exps[i], mod))
                .toArray(BigInteger[]::new);
    }

    @Override
    public boolean isNative() {
        return false;
    }
}
