package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.proof.PaillierRangeEncryptionWitness;
import com.example.mpc.cggmp.proof.PaillierRangeProof;

import java.math.BigInteger;
import java.security.SecureRandom;

public interface RangeProofGenerator {
    PaillierRangeProof createProof(PaillierRangeEncryptionWitness witness, byte[] context);
}
