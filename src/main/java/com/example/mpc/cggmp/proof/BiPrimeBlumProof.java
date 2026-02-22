package com.example.mpc.cggmp.proof;

import java.math.BigInteger;
import java.util.List;

public record BiPrimeBlumProof(
        BigInteger N,
        BigInteger w,
        List<BigInteger> sigmas,
        List<BigInteger> xs,
        byte[] aBits,
        byte[] bBits,
        List<BigInteger> zs,
        int sfRounds,
        int blumRounds
) {
}
