package com.example.mpc.model;

import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class SignatureTask {
    public final String taskId;
    public final String message;
    public final String groupPublicKey;
    public final int nodesCount;
    public BigInteger k_i;
    public ECPoint R_i;
    public ECPoint R;
    public String signature;
    public boolean verified = false;
    public final ConcurrentHashMap<Integer, ECPoint> receivedCommitments = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> receivedSignatureShares = new ConcurrentHashMap<>();
    public final CountDownLatch commitmentsReceivedLatch;
    public final CountDownLatch sharesReceivedLatch;
    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;

    public SignatureTask(String taskId, String message, String groupPublicKey, int nodesCount) {
        this.taskId = taskId;
        this.message = message;
        this.groupPublicKey = groupPublicKey;
        this.nodesCount = nodesCount;
        this.commitmentsReceivedLatch = new CountDownLatch(nodesCount - 1);
        this.sharesReceivedLatch = new CountDownLatch(nodesCount - 1);
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
