package com.example.mpc.cggmp.proof;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record PiLogStarProof(ECPoint A, BigInteger z) {
}
