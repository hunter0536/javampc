package com.example.mpc.model;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CGGMPProtocol;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpDkgTask {
    public final String taskId;
    public final int nodesCount;
    public final int threshold;
    
    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public boolean inProgress = false;
    public boolean completed = false;
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
            inProgress = true;
            startedAtMs = System.currentTimeMillis();
            return true;
        }
        return false;
    }
    
    public void complete() {
        status.set(TaskStatus.COMPLETED);
        inProgress = false;
        completed = true;
    }
    
    public void fail() {
        status.set(TaskStatus.FAILED);
        inProgress = false;
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
