package com.example.mpc.cggmp.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

public final class GmpBackend implements BigIntegerBackend {
    private static final Logger logger = LoggerFactory.getLogger(GmpBackend.class);
    private static final GmpBackend INSTANCE = new GmpBackend();

    private GmpBackend() {
    }

    public static GmpBackend getInstance() {
        return INSTANCE;
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exp, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[GMP] modPow: base={} bits, exp={} bits, mod={} bits", 
                        base.bitLength(), exp.bitLength(), mod.bitLength());
        }
        return NativeBigInteger.modPow(base, exp, mod);
    }

    @Override
    public BigInteger modInverse(BigInteger val, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[GMP] modInverse: val={} bits, mod={} bits", 
                        val.bitLength(), mod.bitLength());
        }
        return NativeBigInteger.modInverse(val, mod);
    }

    @Override
    public BigInteger multiply(BigInteger a, BigInteger b) {
        if (logger.isDebugEnabled()) {
            logger.debug("[GMP] multiply: a={} bits, b={} bits", 
                        a.bitLength(), b.bitLength());
        }
        return NativeBigInteger.multiply(a, b);
    }

    @Override
    public BigInteger[] batchModPow(BigInteger[] bases, BigInteger exp, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[GMP] batchModPow: batchSize={}, exp={} bits, mod={} bits", 
                        bases.length, exp.bitLength(), mod.bitLength());
        }
        return NativeBigInteger.batchModPow(bases, exp, mod);
    }

    @Override
    public BigInteger[] batchModPowDifferentExp(BigInteger[] bases, BigInteger[] exps, BigInteger mod) {
        if (logger.isDebugEnabled()) {
            logger.debug("[GMP] batchModPowDifferentExp: batchSize={}, mod={} bits", 
                        bases.length, mod.bitLength());
        }
        return NativeBigInteger.batchModPowDifferentExp(bases, exps, mod);
    }

    @Override
    public boolean isNative() {
        return NativeBigInteger.isNativeAvailable();
    }
}
