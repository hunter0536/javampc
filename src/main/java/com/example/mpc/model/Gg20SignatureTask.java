package com.example.mpc.model;

import com.example.mpc.enums.TaskStatus;
import org.exploit.secp256k1.Secp256k1CurveParams;
import org.exploit.secp256k1.Secp256k1PointOps;
import org.exploit.tss.ecdsa.GG20Client;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class Gg20SignatureTask {
    public final String taskId;
    public final String message;
    public final String groupPublicKey;
    public final int nodesCount;
    public final int threshold;
    public final int initiatorId;
    public final Set<Integer> participants;

    public byte[] messageHash;
    public byte[] memKey;
    public Secp256k1CurveParams curveParams;
    public GG20Client<Secp256k1PointOps> client;

    public final CountDownLatch gammaCommitmentLatch;
    public final CountDownLatch mtaResponseLatch;
    public final CountDownLatch offlineLatch;
    public final CountDownLatch partialSLatch;
    public final ConcurrentHashMap<Integer, Boolean> mtaResponses = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> offlineReceived = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> partialSReceived = new ConcurrentHashMap<>();

    public String signature;
    public boolean verified = false;
    public volatile String errorMessage;
    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);

    public Gg20SignatureTask(String taskId, String message, String groupPublicKey, int nodesCount, int threshold, int initiatorId) {
        this(taskId, message, groupPublicKey, nodesCount, threshold, initiatorId, null);
    }

    public Gg20SignatureTask(String taskId, String message, String groupPublicKey, int nodesCount, int threshold, int initiatorId, Set<Integer> participantsOverride) {
        this.taskId = taskId;
        this.message = message;
        this.groupPublicKey = groupPublicKey;
        this.nodesCount = nodesCount;
        this.threshold = threshold;
        this.initiatorId = initiatorId;
        this.participants = participantsOverride != null && !participantsOverride.isEmpty()
                ? java.util.Collections.unmodifiableSet(new java.util.LinkedHashSet<>(participantsOverride))
                : selectParticipants(initiatorId, nodesCount, threshold);
        int waitCount = Math.max(0, this.participants.size() - 1);
        this.gammaCommitmentLatch = new CountDownLatch(waitCount);
        this.mtaResponseLatch = new CountDownLatch(waitCount);
        this.offlineLatch = new CountDownLatch(waitCount);
        this.partialSLatch = new CountDownLatch(waitCount);
    }

    public boolean start() {
        return status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS);
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
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

    private static Set<Integer> selectParticipants(int initiatorId, int nodesCount, int threshold) {
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
}
