package com.example.mpc.cggmp.presign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record PresignRound3Msg(int senderId, BigInteger delta, ECPoint Delta, ECPoint S) {
}
