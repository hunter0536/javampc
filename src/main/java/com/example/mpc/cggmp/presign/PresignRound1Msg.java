package com.example.mpc.cggmp.presign;

import java.math.BigInteger;

public record PresignRound1Msg(int senderId, BigInteger K, BigInteger G) {
}
