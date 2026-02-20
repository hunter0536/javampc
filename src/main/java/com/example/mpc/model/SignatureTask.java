package com.example.mpc.model;

import com.example.mpc.enums.TaskStatus;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 签名任务模型，用于管理分布式签名过程
 */
public class SignatureTask {
    public final String taskId;
    public final String message;
    public final String dkgTaskId;
    public final AtomicReference<TaskStatus> status;
    public String signature;
    public boolean verified;
    public final CountDownLatch commitmentsReceivedLatch;
    public final CountDownLatch sharesReceivedLatch;
    public final ConcurrentHashMap<Integer, org.bouncycastle.math.ec.ECPoint> receivedCommitments;
    public final ConcurrentHashMap<Integer, BigInteger> receivedSignatureShares;
    public BigInteger k_i; // 本地随机数
    public org.bouncycastle.math.ec.ECPoint R_i; // 本地临时公钥
    public org.bouncycastle.math.ec.ECPoint R; // 全局临时公钥
    public long createdAt;
    
    public SignatureTask(String taskId, String message, String dkgTaskId, int expectedNodes) {
        this.taskId = taskId;
        this.message = message;
        this.dkgTaskId = dkgTaskId;
        this.status = new AtomicReference<>(TaskStatus.IDLE);
        this.signature = null;
        this.verified = false;
        this.commitmentsReceivedLatch = new CountDownLatch(expectedNodes - 1);
        this.sharesReceivedLatch = new CountDownLatch(expectedNodes - 1);
        this.receivedCommitments = new ConcurrentHashMap<>();
        this.receivedSignatureShares = new ConcurrentHashMap<>();
        this.k_i = null;
        this.R_i = null;
        this.R = null;
        this.createdAt = System.currentTimeMillis();
    }
    
    // 状态转换方法
    public boolean start() {
        return status.compareAndSet(TaskStatus.IDLE, TaskStatus.IN_PROGRESS);
    }
    
    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }
    
    public void fail() {
        status.set(TaskStatus.FAILED);
    }
    
    public boolean isCompleted() {
        return status.get() == TaskStatus.COMPLETED;
    }
    
    public boolean isInProgress() {
        return status.get() == TaskStatus.IN_PROGRESS;
    }
    
    public boolean isFailed() {
        return status.get() == TaskStatus.FAILED;
    }
    
    public boolean isIdle() {
        return status.get() == TaskStatus.IDLE;
    }
}
