package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.proof.PaillierRespondentEncryptionWitness;
import com.example.mpc.cggmp.proof.PaillierRespondentProof;

public interface RespondentProofGenerator {
    PaillierRespondentProof createProof(PaillierRespondentEncryptionWitness witness, byte[] context);
}
