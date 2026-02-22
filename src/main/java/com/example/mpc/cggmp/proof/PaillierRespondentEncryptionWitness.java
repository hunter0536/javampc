package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.zk.ZKSetup;

import java.math.BigInteger;

public record PaillierRespondentEncryptionWitness(BigInteger b, BigInteger y, BigInteger c_i, BigInteger c_j,
                                                  BigInteger r, PaillierEncryption.PublicKey publicKey,
                                                  ZKSetup zk, BigInteger q) {
}
