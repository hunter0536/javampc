package com.example.mpc.model;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CGGMPProtocol;
import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpSignatureTask {
    public final String taskId;
    public final String message;
    public final String groupPublicKey;
    public final int nodesCount;
    public final int threshold;
    public final int initiatorId;
    public final java.util.Set<Integer> participants;
    public BigInteger k_i;
    public ECPoint R_i;
    public ECPoint R;
    public BigInteger messageHash;
    public String signature;
    public boolean verified = false;
    public final ConcurrentHashMap<Integer, ECPoint> receivedCommitments = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> receivedSignatureShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, CGGMPProtocol.SignRound1Output> round1Outputs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, CGGMPProtocol.SignRound2Output> round2Outputs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, CGGMPProtocol.SignRound3Output> round3Outputs = new ConcurrentHashMap<>();
    public final CountDownLatch commitmentsReceivedLatch;
    public final CountDownLatch round2ReceivedLatch;
    public final CountDownLatch sharesReceivedLatch;
    public CGGMP cggmpInstance;
    public CGGMPProtocol protocol;
    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;

    public CggmpSignatureTask(String taskId, String message, String groupPublicKey, int nodesCount, int threshold, int initiatorId) {
        this.taskId = taskId;
        this.message = message;
        this.groupPublicKey = groupPublicKey;
        this.nodesCount = nodesCount;
        this.threshold = threshold;
        this.initiatorId = initiatorId;
        this.participants = selectParticipants(initiatorId, nodesCount, threshold);
        int waitCount = Math.max(0, this.participants.size() - 1);
        this.commitmentsReceivedLatch = new CountDownLatch(waitCount);
        this.round2ReceivedLatch = new CountDownLatch(waitCount);
        this.sharesReceivedLatch = new CountDownLatch(waitCount);
    }

    private static java.util.Set<Integer> selectParticipants(int initiatorId, int nodesCount, int threshold) {
        int actualThreshold = Math.min(Math.max(1, threshold), nodesCount);
        java.util.LinkedHashSet<Integer> result = new java.util.LinkedHashSet<>();
        if (initiatorId >= 1 && initiatorId <= nodesCount) {
            result.add(initiatorId);
        }
        for (int i = 1; i <= nodesCount && result.size() < actualThreshold; i++) {
            if (i != initiatorId) {
                result.add(i);
            }
        }
        return java.util.Collections.unmodifiableSet(result);
    }

    public boolean start() {
        return status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS);
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }

    public void fail() {
        status.set(TaskStatus.FAILED);
    }

    public void fail(String errorMessage) {
        this.errorMessage = errorMessage;
        status.set(TaskStatus.FAILED);
    }

    public boolean isInProgress() {
        return status.get() == TaskStatus.IN_PROGRESS;
    }

    public boolean isCompleted() {
        return status.get() == TaskStatus.COMPLETED;
    }

    public boolean isFailed() {
        return status.get() == TaskStatus.FAILED;
    }
}
