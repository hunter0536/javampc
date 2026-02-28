package com.example.mpc.service.cggmp;

import com.example.mpc.model.Gg20SignatureTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public record CggmpPresignR2Context(
        Gg20SignatureTask task,
        BigInteger curveOrder,
        BigInteger gamma_i,
        BigInteger x_i,
        ECPoint Gamma_i,
        ECPoint X_i,
        List<CompletableFuture<CggmpPresignPeerR2Result>> r2Futures,
        long r2StartNs) {
}
