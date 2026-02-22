package com.example.mpc.cggmp.proof;

import java.math.BigInteger;

public record PaillierRespondentProof(byte[] z, byte[] zPrime, byte[] t, byte[] v, byte[] w, byte[] s,
                                      BigInteger s1, BigInteger s2, BigInteger t1, BigInteger t2) {
}
