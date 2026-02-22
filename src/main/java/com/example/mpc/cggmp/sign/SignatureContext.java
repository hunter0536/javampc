package com.example.mpc.cggmp.sign;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

public class SignatureContext {
    public final ConcurrentHashMap<Integer, BigInteger> alphaShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> betaShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> muShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> nuShares = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, byte[]> gammaCommitments = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> rValues = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> deltaShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> partialS = new ConcurrentHashMap<>();

    public BigInteger k_i;
    public BigInteger gamma_i;
    public BigInteger r_i;
    public BigInteger delta_i;
}
