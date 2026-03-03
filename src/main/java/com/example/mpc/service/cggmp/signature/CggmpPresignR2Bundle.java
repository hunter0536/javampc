package com.example.mpc.service.cggmp.signature;

import com.example.mpc.service.cggmp.types.BigIntIndexMap;

/**
 * 预签名Round 2数据包
 * 包含R2上下文和MtA协议结果
 */
public record CggmpPresignR2Bundle(
        CggmpPresignR2Context ctx,
        BigIntIndexMap D,
        BigIntIndexMap Dhat,
        BigIntIndexMap F,
        BigIntIndexMap Fhat) {
}
