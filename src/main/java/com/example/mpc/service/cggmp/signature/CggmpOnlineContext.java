package com.example.mpc.service.cggmp.signature;

import com.example.mpc.dto.CggmpSignatureTask;

import java.math.BigInteger;

/**
 * CGGMP在线签名上下文
 * 封装签名在线阶段的执行上下文，包含预签名、消息等
 */
public record CggmpOnlineContext(
        CggmpSignatureTask task,
        BigInteger curveOrder,
        BigInteger sigma_i) {
}
