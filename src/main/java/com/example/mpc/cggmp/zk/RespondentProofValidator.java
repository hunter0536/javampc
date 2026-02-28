package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PaillierRespondentProof;
import com.example.mpc.cggmp.proof.PaillierRespondentProofContext;

public interface RespondentProofValidator {
    boolean verifyProof(PaillierRespondentProof proof, PaillierEncryption.PublicKey pubKey, PaillierRespondentProofContext ctx);
}
