package com.example.mpc.cggmp.presign;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record Presignature(ECPoint Gamma, BigInteger kTilde, BigInteger chiTilde) {
}
