package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.model.CggmpDkgTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

public record CggmpDkgContext(
        CggmpDkgTask task,
        BigInteger q,
        ECPoint g,
        BigInteger[] coeffs,
        Map<String, Object> r1Open) {
}
