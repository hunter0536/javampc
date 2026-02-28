package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.zk.ZKSetup;

import java.math.BigInteger;

public record PaillierRespondentProofContext(BigInteger c_i, BigInteger c_j, BigInteger q, ZKSetup zkSetup,
                                             byte[] additionalData) {
}
