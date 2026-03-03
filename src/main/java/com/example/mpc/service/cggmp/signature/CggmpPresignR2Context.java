package com.example.mpc.service.cggmp.signature;

import com.example.mpc.dto.CggmpSignatureTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * CGGMP预签名Round 2上下文
 * 封装签名预计算Round 2的执行上下文，包含任务、Gamma分片等
 */
public record CggmpPresignR2Context(
        CggmpSignatureTask task,
        BigInteger curveOrder,
        BigInteger gamma_i,
        BigInteger x_i,
        ECPoint Gamma_i,
        ECPoint X_i,
        List<CompletableFuture<CggmpPresignPeerR2Result>> r2Futures,
        long r2StartNs) {
}
