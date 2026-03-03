package com.example.mpc.service.cggmp.signature;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * CGGMP预签名Round 3上下文
 * 封装签名预计算Round 3的执行上下文，包含delta和chi分片
 */
public record CggmpPresignR3Context(
        CggmpPresignR2Context ctx,
        BigInteger delta_i,
        BigInteger chi_i,
        ECPoint Gamma) {
}
