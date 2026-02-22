package com.example.mpc.cggmp.mta;

import com.example.mpc.cggmp.proof.PaillierRespondentProof;

import java.math.BigInteger;

public record MtAResult(BigInteger c_j, BigInteger y, BigInteger r, PaillierRespondentProof proof) {
    public MtAResult(BigInteger c_j, BigInteger y, BigInteger r) {
        this(c_j, y, r, null);
    }
}
