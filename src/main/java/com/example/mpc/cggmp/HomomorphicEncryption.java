package com.example.mpc.cggmp;

import java.math.BigInteger;

public interface HomomorphicEncryption {

    PublicKey getPublicKeyInfo();

    PrivateKey getPrivateKeyInfo();

    BigInteger getN();

    BigInteger getNSquared();

    BigInteger getG();

    int getBitLength();

    Encryption encryptWithRandomness(BigInteger m);

    BigInteger decrypt(BigInteger c);

    BigInteger add(BigInteger c1, BigInteger c2);

    BigInteger multiply(BigInteger c, BigInteger k);

    interface PublicKey {
        BigInteger n();

        BigInteger nSquared();

        BigInteger g();

        int bitLength();

        BigInteger encrypt(BigInteger m);

        Encryption encryptWithRandomness(BigInteger m);

        BigInteger add(BigInteger c1, BigInteger c2);

        BigInteger multiply(BigInteger c, BigInteger k);
    }

    interface PrivateKey {
        BigInteger lambda();

        BigInteger mu();

        BigInteger p();

        BigInteger q();

        BigInteger n();

        int bitLength();
    }

    interface Encryption {
        BigInteger c();

        BigInteger r();
    }

    final class SimpleEncryption implements Encryption {
        private final BigInteger c;
        private final BigInteger r;

        public SimpleEncryption(BigInteger c, BigInteger r) {
            this.c = c;
            this.r = r;
        }

        @Override
        public BigInteger c() {
            return c;
        }

        @Override
        public BigInteger r() {
            return r;
        }
    }
}
