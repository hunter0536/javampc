package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.dto.CggmpDkgTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

/**
 * CGGMP DKG非阈值上下文
 * 封装DKG非阈值模式的执行上下文，包含任务、曲线参数、秘密分片等
 */
public record CggmpDkgNonThresholdContext(
        CggmpDkgTask task,
        BigInteger q,
        ECPoint g,
        BigInteger x_i,
        ECPoint X_i,
        Map<String, Object> r1Open) {
}
