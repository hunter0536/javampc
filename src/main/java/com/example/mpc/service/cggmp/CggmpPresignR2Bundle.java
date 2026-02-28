package com.example.mpc.service.cggmp;

import java.math.BigInteger;
import java.util.Map;

public record CggmpPresignR2Bundle(
        CggmpPresignR2Context ctx,
        Map<Integer, BigInteger> D,
        Map<Integer, BigInteger> Dhat,
        Map<Integer, BigInteger> F,
        Map<Integer, BigInteger> Fhat) {
}
