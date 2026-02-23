package com.example.mpc.cggmp.proof;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record PiEncElgProof(BigInteger S,
                            BigInteger T,
                            BigInteger D,
                            ECPoint Y,
                            ECPoint Z,
                            BigInteger z1,
                            BigInteger z2,
                            BigInteger z3,
                            BigInteger w) {
}
