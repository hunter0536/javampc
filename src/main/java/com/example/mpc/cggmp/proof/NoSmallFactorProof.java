package com.example.mpc.cggmp.proof;

import java.math.BigInteger;

public record NoSmallFactorProof(byte[] P, byte[] Q, byte[] A, byte[] B, byte[] T,
                                 BigInteger z1, BigInteger z2, BigInteger w1, BigInteger w2, BigInteger v) {
}
