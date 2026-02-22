package com.example.mpc.cggmp.mta;

import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.PaillierRangeProof;

import java.math.BigInteger;

public record MtAInitiatorMessage(BigInteger cA,
                                  PaillierRangeProof rangeProof,
                                  BiPrimeBlumProof biPrimeProof,
                                  NoSmallFactorProof factorProof) {
}
