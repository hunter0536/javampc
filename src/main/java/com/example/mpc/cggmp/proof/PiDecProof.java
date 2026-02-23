package com.example.mpc.cggmp.proof;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;

public record PiDecProof(List<BigInteger> A,
                         List<ECPoint> B,
                         List<ECPoint> C,
                         List<BigInteger> z,
                         List<BigInteger> w,
                         List<BigInteger> nu) {
}
