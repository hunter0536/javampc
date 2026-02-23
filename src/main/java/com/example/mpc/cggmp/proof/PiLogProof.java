package com.example.mpc.cggmp.proof;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record PiLogProof(ECPoint U1,
                         ECPoint U2,
                         ECPoint U3,
                         BigInteger z1,
                         BigInteger z2) {
}
