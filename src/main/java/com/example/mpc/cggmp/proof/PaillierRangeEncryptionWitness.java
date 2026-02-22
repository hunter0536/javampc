package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.zk.ZKSetup;

import java.math.BigInteger;

public record PaillierRangeEncryptionWitness(BigInteger m, BigInteger r, BigInteger c,
                                             PaillierEncryption.PublicKey publicKey,
                                             ZKSetup zk, BigInteger q) {
}
