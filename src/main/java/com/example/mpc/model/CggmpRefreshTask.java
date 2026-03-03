package com.example.mpc.model;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.service.cggmp.types.BigIntIndexMap;
import com.example.mpc.service.cggmp.types.ECPointIndexMap;
import com.example.mpc.service.cggmp.types.SchProofMap;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpRefreshTask {
    public final String taskId;
    public final String groupPublicKey;
    public final int nodesCount;
    public final int initiatorId;
    public final Set<Integer> participants;

    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;

    public final CountDownLatch round1Latch;
    public final CountDownLatch round2Latch;
    public final CountDownLatch round3Latch;

    public final ConcurrentHashMap<Integer, String> round1Commit = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, RefreshRound2Data> round2Data = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, RefreshRound3Data> round3Data = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, BigInteger> yShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> yPoints = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> xShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> xPoints = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> schAlphas = new ConcurrentHashMap<>();

    public byte[] rid;

    public CggmpRefreshTask(String taskId, String groupPublicKey, int nodesCount, int initiatorId, Set<Integer> participants) {
        this.taskId = taskId;
        this.groupPublicKey = groupPublicKey;
        this.nodesCount = nodesCount;
        this.initiatorId = initiatorId;
        this.participants = participants;
        int waitCount = Math.max(0, participants.size() - 1);
        this.round1Latch = new CountDownLatch(waitCount);
        this.round2Latch = new CountDownLatch(waitCount);
        this.round3Latch = new CountDownLatch(waitCount);
    }

    public boolean start() {
        return status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS);
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }

    public void fail(String message) {
        errorMessage = message;
        status.set(TaskStatus.FAILED);
    }

    public boolean isInProgress() {
        return status.get().isRunning();
    }

    public boolean isCompleted() {
        return status.get() == TaskStatus.COMPLETED;
    }

    public record RefreshRound2Data(ECPointIndexMap Y, ECPointIndexMap X, ECPointIndexMap A,
                                    ECPoint Xi, byte[] rid, byte[] u) {
    }

    public record RefreshRound3Data(BigIntIndexMap C, SchProofMap schProofs) {
    }
}
