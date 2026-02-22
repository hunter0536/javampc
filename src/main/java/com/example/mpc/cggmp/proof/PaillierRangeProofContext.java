package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.zk.ZKSetup;

import java.math.BigInteger;

public record PaillierRangeProofContext(BigInteger c, BigInteger q, ZKSetup zkSetup, byte[] additionalData) {
}
