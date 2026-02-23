package com.example.mpc.cggmp.presign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;

public record PresignRound2Msg(int senderId,
                               ECPoint Gamma,
                               Map<Integer, BigInteger> D,
                               Map<Integer, BigInteger> Dhat,
                               Map<Integer, BigInteger> F,
                               Map<Integer, BigInteger> Fhat) {
}
