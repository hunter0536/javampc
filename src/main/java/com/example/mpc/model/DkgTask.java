package com.example.mpc.model;

import com.example.mpc.enums.TaskStatus;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * DKG任务模型，用于管理分布式密钥生成过程
 */
public class DkgTask {
    public final String taskId;
    public final AtomicReference<TaskStatus> status;
    public String groupPublicKey;
    public BigInteger finalKeyShare;
    public final CountDownLatch commitmentsReceivedLatch;
    public final CountDownLatch sharesReceivedLatch;
    public final CountDownLatch publicKeyContributionsReceivedLatch; // 等待公钥贡献的计数器
    public final ConcurrentHashMap<Integer, List<org.bouncycastle.math.ec.ECPoint>> receivedCommitments;
    public final ConcurrentHashMap<Integer, BigInteger> receivedShares;
    public final ConcurrentHashMap<Integer, org.bouncycastle.math.ec.ECPoint> receivedPublicKeyContributions; // 接收的其他节点公钥贡献
    public List<BigInteger> coefficients;
    public List<org.bouncycastle.math.ec.ECPoint> verificationPoints;
    public List<BigInteger> maskingCoefficients; // 遮蔽多项式系数
    public List<org.bouncycastle.math.ec.ECPoint> maskingVerificationPoints; // 遮蔽多项式验证点
    public final ConcurrentHashMap<Integer, List<org.bouncycastle.math.ec.ECPoint>> receivedMaskingCommitments; // 接收的遮蔽验证点
    public boolean groupPublicKeyGenerated = false; // 群公钥是否已经生成的标志
    public boolean inProgress = false; // 任务是否正在进行中
    public boolean completed = false; // 任务是否已完成
    public long createdAt;
    
    public DkgTask(String taskId, int expectedNodes) {
        this.taskId = taskId;
        this.status = new AtomicReference<>(TaskStatus.IDLE);
        this.groupPublicKey = null;
        this.finalKeyShare = null;
        this.commitmentsReceivedLatch = new CountDownLatch(expectedNodes - 1);
        this.sharesReceivedLatch = new CountDownLatch(expectedNodes - 1);
        this.publicKeyContributionsReceivedLatch = new CountDownLatch(expectedNodes - 1);
        this.receivedCommitments = new ConcurrentHashMap<>();
        this.receivedShares = new ConcurrentHashMap<>();
        this.receivedPublicKeyContributions = new ConcurrentHashMap<>();
        this.receivedMaskingCommitments = new ConcurrentHashMap<>();
        this.createdAt = System.currentTimeMillis();
    }
    
    // 状态转换方法
    public boolean start() {
        boolean started = status.compareAndSet(TaskStatus.IDLE, TaskStatus.IN_PROGRESS);
        if (started) {
            inProgress = true;
        }
        return started;
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
