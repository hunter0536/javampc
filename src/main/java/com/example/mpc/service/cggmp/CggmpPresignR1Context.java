package com.example.mpc.service.cggmp;

import com.example.mpc.model.Gg20SignatureTask;

import java.math.BigInteger;

public record CggmpPresignR1Context(
        Gg20SignatureTask task,
        BigInteger curveOrder,
        BigInteger gamma_i) {
}
