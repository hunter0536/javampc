package com.example.mpc.model;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class SimpleSignatureTask {

    public final String taskId;
    public final String groupPublicKey;
    public final String message;
    public final Set<Integer> participants;
    public final int initiatorId;

    public BigInteger k_i;
    public BigInteger gamma_i;
    public ECPoint R;
    public ECPoint Gamma;

    public final Map<Integer, ECPoint> RShares = new ConcurrentHashMap<>();
    public final Map<Integer, ECPoint> GammaShares = new ConcurrentHashMap<>();
    public final Map<Integer, BigInteger> sigmaShares = new ConcurrentHashMap<>();

    public BigInteger s;
    public BigInteger rValue;
    public boolean verified = false;

    public boolean offlineCompleted = false;

    public final AtomicReference<State> state = new AtomicReference<>(State.PENDING);

    public final long createTime;

    public enum State {
        PENDING,
        K_GENERATED,
        SIGMA_COMPUTED,
        COMPLETED,
        FAILED
    }

    public String errorMessage;

    public SimpleSignatureTask(String taskId, String groupPublicKey, String message,
                                Set<Integer> participants, int initiatorId) {
        this.taskId = taskId;
        this.groupPublicKey = groupPublicKey;
        this.message = message;
        this.participants = participants;
        this.initiatorId = initiatorId;
        this.createTime = System.currentTimeMillis();
    }

    public boolean start() {
        return state.compareAndSet(State.PENDING, State.K_GENERATED);
    }

    public void complete(BigInteger s) {
        this.s = s;
        state.set(State.COMPLETED);
    }

    public void fail(String error) {
        this.errorMessage = error;
        state.set(State.FAILED);
    }

    public boolean isCompleted() {
        return state.get() == State.COMPLETED;
    }

    public boolean isFailed() {
        return state.get() == State.FAILED;
    }

    public boolean isInProgress() {
        return state.get() == State.K_GENERATED || state.get() == State.SIGMA_COMPUTED;
    }

    public long getCreateTime() {
        return createTime;
    }
}
