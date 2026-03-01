package com.example.mpc.model;

import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.enums.TaskStatus;
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

    public static class RefreshRound2Data {
        public final Map<Integer, ECPoint> Y;
        public final Map<Integer, ECPoint> X;
        public final Map<Integer, ECPoint> A;
        public final ECPoint Xi;
        public final byte[] rid;
        public final byte[] u;

        public RefreshRound2Data(Map<Integer, ECPoint> Y,
                                 Map<Integer, ECPoint> X,
                                 Map<Integer, ECPoint> A,
                                 ECPoint Xi,
                                 byte[] rid,
                                 byte[] u) {
            this.Y = Y;
            this.X = X;
            this.A = A;
            this.Xi = Xi;
            this.rid = rid;
            this.u = u;
        }
    }

    public static class RefreshRound3Data {
        public final Map<Integer, BigInteger> C;
        public final Map<Integer, PiSchProof> schProofs;

        public RefreshRound3Data(Map<Integer, BigInteger> C,
                                 Map<Integer, PiSchProof> schProofs) {
            this.C = C;
            this.schProofs = schProofs;
        }
    }
}
