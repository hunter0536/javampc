package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.dto.CggmpAuxTask;

/**
 * CGGMP辅助密钥上下文
 * 封装辅助密钥生成协议的执行上下文，包含任务、Paillier加密、零知识证明等
 */
public record CggmpAuxContext(
        CggmpAuxTask task,
        PaillierEncryption paillier,
        PiPrmProof prmProof,
        byte[] rho,
        byte[] u) {
}
