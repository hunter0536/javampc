package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.model.CggmpAuxTask;

public record CggmpAuxContext(
        CggmpAuxTask task,
        PaillierEncryption paillier,
        PiPrmProof prmProof,
        byte[] rho,
        byte[] u) {
}
