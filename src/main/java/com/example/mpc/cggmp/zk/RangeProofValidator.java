package com.example.mpc.cggmp.zk;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PaillierRangeProof;
import com.example.mpc.cggmp.proof.PaillierRangeProofContext;

public interface RangeProofValidator {
    boolean verifyProof(PaillierRangeProof proof, PaillierEncryption.PublicKey pubKey, PaillierRangeProofContext ctx);
}
