package com.example.mpc.cggmp.proof;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

public record PiAffGProof(List<BigInteger> A,
                          List<BigInteger> B,
                          List<ECPoint> R,
                          List<BigInteger> z,
                          List<BigInteger> zPrime,
                          List<BigInteger> w,
                          List<BigInteger> lambda) {
}
