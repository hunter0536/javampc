package com.example.mpc.dto;

import java.math.BigInteger;

public class R2VerifyResult {
    public final int senderId;
    public final boolean success;
    public final String errorMessage;
    public final BigInteger D_ji;
    public final BigInteger Dhat_ji;
    public final BigInteger F_ji;
    public final BigInteger Fhat_ji;
    public final BigInteger GammaScalar;

    private R2VerifyResult(int senderId, boolean success, String errorMessage) {
        this.senderId = senderId;
        this.success = success;
        this.errorMessage = errorMessage;
        this.D_ji = null;
        this.Dhat_ji = null;
        this.F_ji = null;
        this.Fhat_ji = null;
        this.GammaScalar = null;
    }

    private R2VerifyResult(int senderId, boolean success, BigInteger D_ji, BigInteger Dhat_ji, 
                          BigInteger F_ji, BigInteger Fhat_ji, BigInteger GammaScalar) {
        this.senderId = senderId;
        this.success = success;
        this.errorMessage = null;
        this.D_ji = D_ji;
        this.Dhat_ji = Dhat_ji;
        this.F_ji = F_ji;
        this.Fhat_ji = Fhat_ji;
        this.GammaScalar = GammaScalar;
    }

    public static R2VerifyResult success(int senderId, BigInteger D_ji, BigInteger Dhat_ji,
                                         BigInteger F_ji, BigInteger Fhat_ji, BigInteger GammaScalar) {
        return new R2VerifyResult(senderId, true, D_ji, Dhat_ji, F_ji, Fhat_ji, GammaScalar);
    }

    public static R2VerifyResult failure(int senderId, String errorMessage) {
        return new R2VerifyResult(senderId, false, errorMessage);
    }
}
