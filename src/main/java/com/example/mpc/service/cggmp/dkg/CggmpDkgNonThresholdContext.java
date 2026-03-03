package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.model.CggmpDkgTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

public record CggmpDkgNonThresholdContext(
        CggmpDkgTask task,
        BigInteger q,
        ECPoint g,
        BigInteger x_i,
        ECPoint X_i,
        Map<String, Object> r1Open) {
}
