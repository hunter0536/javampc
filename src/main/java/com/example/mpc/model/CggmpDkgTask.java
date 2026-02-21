package com.example.mpc.model;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CGGMPProtocol;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpDkgTask {
    public static final long DEFAULT_TIMEOUT_MS = Constants.DKG_TASK_DEFAULT_TIMEOUT_MS;

    public final String taskId;
    public final int nodesCount;
    public final int threshold;

    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;
    public volatile long startedAtMs = 0L;

    public final ConcurrentHashMap<Integer, CGGMP.DkgRound1Output> round1Outputs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, CGGMP.DkgRound2Output> round2Outputs = new ConcurrentHashMap<>();

    public final CountDownLatch round1ReceivedLatch;
    public final CountDownLatch round2ReceivedLatch;

    public CGGMP cggmpInstance;
    public PaillierEncryption paillier;
    public BigInteger secretShare;
    public ECPoint groupPublicKey;
    public String groupPublicKeyHex;

    public CggmpDkgTask(String taskId, int nodesCount, int threshold) {
        this.taskId = taskId;
        this.nodesCount = nodesCount;
        this.threshold = threshold;
        this.round1ReceivedLatch = new CountDownLatch(nodesCount - 1);
        this.round2ReceivedLatch = new CountDownLatch(nodesCount - 1);
    }

    public boolean start() {
        if (status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS)) {
            startedAtMs = System.currentTimeMillis();
            return true;
        }
        return false;
    }

    public boolean startRound1Waiting() {
        return status.compareAndSet(TaskStatus.IN_PROGRESS, TaskStatus.ROUND1_WAITING);
    }

    public boolean startRound2Waiting() {
        return status.compareAndSet(TaskStatus.ROUND1_WAITING, TaskStatus.ROUND2_WAITING);
    }

    public boolean startValidating() {
        return status.compareAndSet(TaskStatus.ROUND2_WAITING, TaskStatus.VALIDATING);
    }

    public boolean startCompleting() {
        return status.compareAndSet(TaskStatus.VALIDATING, TaskStatus.COMPLETING);
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }

    public void fail() {
        status.set(TaskStatus.FAILED);
    }

    public void timeout() {
        status.set(TaskStatus.TIMEOUT);
        errorMessage = "Task timeout";
    }

    public boolean isInProgress() {
        return status.get().isRunning();
    }

    public boolean isCompleted() {
        return status.get() == TaskStatus.COMPLETED;
    }

    public boolean isFailed() {
        return status.get() == TaskStatus.FAILED;
    }

    public boolean isTimeout() {
        if (startedAtMs == 0) return false;
        return System.currentTimeMillis() - startedAtMs > DEFAULT_TIMEOUT_MS;
    }

    public boolean isTimeout(long timeoutMs) {
        if (startedAtMs == 0) return false;
        return System.currentTimeMillis() - startedAtMs > timeoutMs;
    }

    public TaskStatus getStatus() {
        return status.get();
    }

    public long getElapsedTimeMs() {
        if (startedAtMs == 0) return 0;
        return System.currentTimeMillis() - startedAtMs;
    }
}
