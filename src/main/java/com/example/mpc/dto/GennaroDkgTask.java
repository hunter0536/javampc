package com.example.mpc.dto;

import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class GennaroDkgTask {
    public final String taskId;
    public final int nodesCount;
    public List<BigInteger> coefficients;
    public List<BigInteger> maskingCoefficients;
    public List<ECPoint> verificationPoints;
    public List<ECPoint> maskingVerificationPoints;
    public final ConcurrentHashMap<Integer, List<ECPoint>> receivedCommitments = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, List<ECPoint>> receivedMaskingCommitments = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> receivedShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> receivedPublicKeyContributions = new ConcurrentHashMap<>();
    public final CountDownLatch commitmentsReceivedLatch;
    public final CountDownLatch sharesReceivedLatch;
    public final CountDownLatch publicKeyContributionsReceivedLatch;

    public volatile CompletableFuture<Void> commitmentsFuture;
    public volatile CompletableFuture<Void> sharesFuture;
    public volatile CompletableFuture<Void> publicKeyFuture;

    public BigInteger finalKeyShare;
    public String groupPublicKey;
    public volatile String errorMessage;
    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public boolean groupPublicKeyGenerated = false;
    public volatile long startedAtMs = 0L;

    public GennaroDkgTask(String taskId, int nodesCount) {
        this.taskId = taskId;
        this.nodesCount = nodesCount;
        this.commitmentsReceivedLatch = new CountDownLatch(nodesCount - 1);
        this.sharesReceivedLatch = new CountDownLatch(nodesCount - 1);
        this.publicKeyContributionsReceivedLatch = new CountDownLatch(nodesCount - 1);
    }

    public boolean start() {
        if (status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS)) {
            startedAtMs = System.currentTimeMillis();
            return true;
        }
        return false;
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }

    public void fail() {
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
