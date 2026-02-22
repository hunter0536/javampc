package com.example.mpc.cggmp.proof;

import java.math.BigInteger;

public record PaillierRangeProof(byte[] z, byte[] u, byte[] w, byte[] s, BigInteger s1, BigInteger s2) {
}
