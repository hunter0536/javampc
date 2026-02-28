package com.example.mpc.service.cggmp;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record CggmpPresignR3Context(
        CggmpPresignR2Context ctx,
        BigInteger delta_i,
        BigInteger chi_i,
        ECPoint Gamma) {
}
