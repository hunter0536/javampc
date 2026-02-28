package com.example.mpc.model;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class SimpleSignatureTask {

    public final String taskId;
    public final String groupPublicKey;
    public final String message;
    public final Set<Integer> participants;
    public final int initiatorId;
    public final int threshold;
    public final int nodesCount;
    public final long createTime;
    public final long messageTimestamp;

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

    public volatile CompletableFuture<Void> offlineFuture;
    public volatile CompletableFuture<Void> sigmaFuture;

    public final AtomicReference<Phase> phase = new AtomicReference<>(Phase.INIT);
    public final AtomicInteger round = new AtomicInteger(0);

    public enum Phase {
        INIT,
        OFFLINE_WAITING,
        OFFLINE_COMPLETED,
        ONLINE_WAITING,
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
        this.threshold = participants.size();
        this.nodesCount = participants.size();
        this.createTime = System.currentTimeMillis();
        this.messageTimestamp = System.currentTimeMillis();
    }

    public SimpleSignatureTask(String taskId, String groupPublicKey, String message,
                               int nodesCount, int threshold, int initiatorId) {
        this.taskId = taskId;
        this.groupPublicKey = groupPublicKey;
        this.message = message;
        this.nodesCount = nodesCount;
        this.threshold = Math.min(Math.max(1, threshold), nodesCount);
        this.initiatorId = initiatorId;
        this.participants = selectParticipants(initiatorId, nodesCount, this.threshold);
        this.createTime = System.currentTimeMillis();
        this.messageTimestamp = System.currentTimeMillis();
    }

    private static Set<Integer> selectParticipants(int initiatorId, int nodesCount, int threshold) {
        java.util.LinkedHashSet<Integer> result = new java.util.LinkedHashSet<>();
        if (initiatorId >= 1 && initiatorId <= nodesCount) {
            result.add(initiatorId);
        }
        for (int i = 1; i <= nodesCount && result.size() < threshold; i++) {
            if (i != initiatorId) {
                result.add(i);
            }
        }
        return java.util.Collections.unmodifiableSet(result);
    }

    public boolean setPhase(Phase expected, Phase update) {
        return phase.compareAndSet(expected, update);
    }

    public Phase getPhase() {
        return phase.get();
    }

    public void complete(BigInteger s) {
        this.s = s;
        phase.set(Phase.COMPLETED);
    }

    public void fail(String error) {
        this.errorMessage = error;
        phase.set(Phase.FAILED);
    }

    public boolean isCompleted() {
        return phase.get() == Phase.COMPLETED;
    }

    public boolean isFailed() {
        return phase.get() == Phase.FAILED;
    }

    public boolean isInProgress() {
        Phase current = phase.get();
        return current == Phase.INIT || current == Phase.OFFLINE_WAITING || current == Phase.ONLINE_WAITING;
    }

    public long getCreateTime() {
        return createTime;
    }

    public boolean isExpired(long maxAgeMs) {
        return System.currentTimeMillis() - createTime > maxAgeMs;
    }
}
