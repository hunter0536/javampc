package com.example.mpc.service.cggmp;

import com.example.mpc.model.Gg20SignatureTask;

import java.math.BigInteger;

public record CggmpOnlineContext(
        Gg20SignatureTask task,
        BigInteger curveOrder,
        BigInteger sigma_i) {
}
