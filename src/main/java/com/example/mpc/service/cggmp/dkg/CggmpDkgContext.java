package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.dto.CggmpDkgTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

/**
 * CGGMP DKG阈值上下文
 * 封装DKG Round 1的执行上下文，包含任务、曲线参数、系数等
 */
public record CggmpDkgContext(
        CggmpDkgTask task,
        BigInteger q,
        ECPoint g,
        BigInteger[] coeffs,
        Map<String, Object> r1Open) {
}
