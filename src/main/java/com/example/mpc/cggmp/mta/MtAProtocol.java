package com.example.mpc.cggmp.mta;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofGenerator;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofGenerator;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PaillierRangeEncryptionWitness;
import com.example.mpc.cggmp.proof.PaillierRangeProof;
import com.example.mpc.cggmp.proof.PaillierRangeProofContext;
import com.example.mpc.cggmp.proof.PaillierRangeProofGenerator;
import com.example.mpc.cggmp.proof.PaillierRangeProofValidator;
import com.example.mpc.cggmp.proof.PaillierRespondentEncryptionWitness;
import com.example.mpc.cggmp.proof.PaillierRespondentProof;
import com.example.mpc.cggmp.proof.PaillierRespondentProofContext;
import com.example.mpc.cggmp.proof.PaillierRespondentProofGenerator;
import com.example.mpc.cggmp.proof.PaillierRespondentProofValidator;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.zk.RangeProofGenerator;
import com.example.mpc.cggmp.zk.RangeProofValidator;
import com.example.mpc.cggmp.zk.RespondentProofGenerator;
import com.example.mpc.cggmp.zk.RespondentProofValidator;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.SecureRandomUtils;

import java.math.BigInteger;
import java.util.Objects;

public class MtAProtocol {
    private final RangeProofGenerator rangeGenerator;
    private final RangeProofValidator rangeValidator;
    private final BiPrimeProofGenerator biPrimeProofGenerator;
    private final BiPrimeProofValidator biPrimeProofValidator;
    private final RespondentProofGenerator respondentProofGenerator;
    private final RespondentProofValidator respondentProofValidator;

    private final PaillierEncryption paillier;
    private final BigInteger q;

    public MtAProtocol(PaillierEncryption paillier, BigInteger q) {
        this(paillier, q,
                new PaillierRangeProofGenerator(),
                new PaillierRangeProofValidator(),
                new BiPrimeProofGenerator(),
                new BiPrimeProofValidator(),
                new PaillierRespondentProofGenerator(),
                new PaillierRespondentProofValidator());
    }

    public MtAProtocol(PaillierEncryption paillier, BigInteger q,
                       RangeProofGenerator rangeGenerator,
                       RangeProofValidator rangeValidator,
                       BiPrimeProofGenerator biPrimeProofGenerator,
                       BiPrimeProofValidator biPrimeProofValidator,
                       RespondentProofGenerator respondentProofGenerator,
                       RespondentProofValidator respondentProofValidator) {
        this.paillier = paillier;
        this.q = Objects.requireNonNull(q, "q");
        this.rangeGenerator = rangeGenerator;
        this.rangeValidator = rangeValidator;
        this.biPrimeProofGenerator = biPrimeProofGenerator;
        this.biPrimeProofValidator = biPrimeProofValidator;
        this.respondentProofGenerator = respondentProofGenerator;
        this.respondentProofValidator = respondentProofValidator;
        if (paillier != null) {
            validatePaillierN(paillier.getPublicKeyInfo(), q);
        }
    }

    public MtAInitiatorMessage generateInitiatorMessage(BigInteger a_i, ZKSetup zkSetup, byte[] context) {
        if (paillier == null) {
            throw new IllegalStateException("Paillier keypair required for initiator");
        }
        if (a_i == null || a_i.signum() < 0 || a_i.compareTo(q) >= 0) {
            throw new IllegalArgumentException("a_i must be in [0, q)");
        }

        PaillierEncryption.Encryption encryption = paillier.encryptWithRandomness(a_i);
        BigInteger cA = encryption.c();
        BigInteger r = encryption.r();

        PaillierRangeEncryptionWitness witness = new PaillierRangeEncryptionWitness(
                a_i, r, cA, paillier.getPublicKeyInfo(), zkSetup, q
        );
        PaillierRangeProof rangeProof = rangeGenerator.createProof(witness, context);

        BiPrimeBlumProof biPrimeProof = biPrimeProofGenerator.createProof(paillier.getPrivateKeyInfo(), context);
        NoSmallFactorProof factorProof = new NoSmallFactorProofGenerator(zkSetup).createProof(paillier.getPrivateKeyInfo(), context);

        return new MtAInitiatorMessage(cA, rangeProof, biPrimeProof, factorProof);
    }

    public boolean verifyInitiatorRangeProof(MtAInitiatorMessage msg, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup, byte[] context) {
        PaillierRangeProofContext ctx = new PaillierRangeProofContext(msg.cA(), q, zkSetup, context);
        return rangeValidator.verifyProof(msg.rangeProof(), publicKey, ctx);
    }

    public boolean verifyInitiatorFactorProof(MtAInitiatorMessage msg, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup, byte[] context) {
        NoSmallFactorProofValidator validator = new NoSmallFactorProofValidator(zkSetup);
        return validator.verifyProof(msg.factorProof(), publicKey, context);
    }

    public boolean verifyInitiatorBiPrimeProof(MtAInitiatorMessage msg, PaillierEncryption.PublicKey publicKey, byte[] context) {
        return biPrimeProofValidator.verifyProof(msg.biPrimeProof(), publicKey, context);
    }

    public MtAResult computeCjWithY(PaillierEncryption.PublicKey initiatorPublicKey, BigInteger c_i, BigInteger b_j, ZKSetup zkSetup, byte[] context) {
        if (c_i == null || b_j == null || b_j.compareTo(q) >= 0) {
            throw new IllegalArgumentException("Inputs cannot be null and b_j must be in [0, q)");
        }

        BigInteger nsq = initiatorPublicKey.nSquared();
        BigInteger y = new BigInteger(q.bitLength(), SecureRandomUtils.getInstance()).mod(q);

        PaillierEncryption.PublicKey initiatorPk = initiatorPublicKey;
        PaillierEncryption.Encryption encY = initiatorPk.encryptWithRandomness(y);

        BigInteger c_j = BigIntegerUtils.modPow(c_i, b_j, nsq)
                .multiply(encY.c())
                .mod(nsq);

        if (zkSetup != null) {
            PaillierRespondentEncryptionWitness witness = new PaillierRespondentEncryptionWitness(
                    b_j, y, c_i, c_j, encY.r(), initiatorPk, zkSetup, q
            );
            PaillierRespondentProof proof = respondentProofGenerator.createProof(witness, context);
            return new MtAResult(c_j, y, encY.r(), proof);
        }

        return new MtAResult(c_j, y, encY.r());
    }

    public boolean verifyRespondentProof(MtAResult result, BigInteger c_i, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup, byte[] context) {
        PaillierRespondentProofContext ctx = new PaillierRespondentProofContext(c_i, result.c_j(), q, zkSetup, context);
        return respondentProofValidator.verifyProof(result.proof(), publicKey, ctx);
    }

    public BigInteger decryptCj(BigInteger c_j) {
        if (paillier == null) {
            throw new IllegalStateException("Paillier keypair required for decrypt");
        }
        return paillier.decrypt(c_j);
    }

    public BigInteger computeBeta(BigInteger y) {
        if (y == null) {
            throw new IllegalArgumentException("y cannot be null");
        }
        return y.negate().mod(q);
    }

    private static void validatePaillierN(PaillierEncryption.PublicKey publicKey, BigInteger q) {
        if (publicKey.n().compareTo(q.pow(8)) < 0) {
            throw new IllegalArgumentException("Paillier public key n must be at least 8 times larger than q");
        }
    }
}
