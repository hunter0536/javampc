package com.example.mpc.service.cggmp.signature;

import com.example.mpc.dto.CggmpSignatureTask;

import java.math.BigInteger;

/**
 * CGGMP预签名Round 1上下文
 * 封装签名预计算Round 1的执行上下文，包含任务、随机数等
 */
public record CggmpPresignR1Context(
        CggmpSignatureTask task,
        BigInteger curveOrder,
        BigInteger gamma_i) {
}
