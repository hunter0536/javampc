package com.example.mpc.model;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpDkgTask {
    public static final long DEFAULT_TIMEOUT_MS = Constants.DKG_TASK_TIMEOUT_MS;

    public final String taskId;
    public final int nodesCount;
    public final int threshold;
    public final Set<Integer> participants;
    public final int initiatorId;

    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;
    public volatile long startedAtMs = 0L;

    public final ConcurrentHashMap<Integer, CGGMP.DkgRound1Output> round1Outputs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, CGGMP.DkgRound2Output> round2Outputs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, PaillierEncryption.PublicKey> peerPaillierKeys = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ZKSetup> peerZkSetups = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, MtAInitiatorMessage> mtaInitiatorMessages = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> mtaBetas = new ConcurrentHashMap<>();

    // Figure 7 (Aux Info / Key Refresh) state
    public final ConcurrentHashMap<Integer, byte[]> ridParts = new ConcurrentHashMap<>();
    public volatile byte[] rid;
    public final ConcurrentHashMap<Integer, BigInteger> hatN = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> sValues = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> tValues = new ConcurrentHashMap<>();
    public volatile BigInteger pedersenLambda;
    public final ConcurrentHashMap<Integer, PiPrmProof> prmProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BiPrimeBlumProof> biPrimeProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, NoSmallFactorProof> factorProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, NoSmallFactorProofValidator> noSmallFactorValidators = new ConcurrentHashMap<>();

    // X_{j,k} and A_{j,k}
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, ECPoint>> Xjks = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, ECPoint>> Ajks = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> schAlphas = new ConcurrentHashMap<>();

    // Y_{j,i} and C_{j,i}
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, ECPoint>> Yji = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, BigInteger>> Cji = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, com.example.mpc.cggmp.proof.BiPrimeBlumProof>> modProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, com.example.mpc.cggmp.proof.NoSmallFactorProof>> facProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<String, Object>> round2Evidence = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.Map<Integer, com.example.mpc.cggmp.proof.PiSchProof>> round2SchProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, com.example.mpc.cggmp.proof.BiPrimeBlumProof> round2ModProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, com.example.mpc.cggmp.proof.NoSmallFactorProof> round2FacProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.Map<String, Object>> round2ProofMaps = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.Map<String, String>> pendingRound2Shares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.concurrent.CompletableFuture<Boolean>> round2ModFacVerifyFutures = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.concurrent.CompletableFuture<Boolean>> round2SchVerifyFutures = new ConcurrentHashMap<>();

    // Derived x_{j,i} shares and X*_k
    public final ConcurrentHashMap<Integer, ConcurrentHashMap<Integer, BigInteger>> xji = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> XkStar = new ConcurrentHashMap<>();

    // Round de-duplication
    public final ConcurrentHashMap<Integer, Boolean> round1Received = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> round1EchoReceived = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> round1Processing = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, String> pendingRound1Echo = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> round2Received = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> round3Received = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> round2Processing = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> modFacVerified = new ConcurrentHashMap<>();

    public final CountDownLatch round1ReceivedLatch;
    public final CountDownLatch round1EchoReceivedLatch;
    public final CountDownLatch round2ReceivedLatch;
    public final CountDownLatch round3ReceivedLatch;

    public CGGMP cggmpInstance;
    public PaillierEncryption paillier;
    public BigInteger secretShare;
    public ECPoint groupPublicKey;
    public String groupPublicKeyHex;
    public volatile BigInteger[] evalPowers;
    public final ConcurrentHashMap<Integer, String> round1PayloadHashes = new ConcurrentHashMap<>();

    public CggmpDkgTask(String taskId, int nodesCount, int threshold) {
        this(taskId, nodesCount, threshold, null, 0);
    }

    public CggmpDkgTask(String taskId, int nodesCount, int threshold, Set<Integer> participantsOverride, int initiatorId) {
        this.taskId = taskId;
        this.nodesCount = nodesCount;
        this.threshold = threshold;
        this.initiatorId = initiatorId;
        this.participants = participantsOverride != null && !participantsOverride.isEmpty()
                ? java.util.Collections.unmodifiableSet(new java.util.LinkedHashSet<>(participantsOverride))
                : defaultParticipants(nodesCount);
        int waitCount = Math.max(0, this.participants.size() - 1);
        this.round1ReceivedLatch = new CountDownLatch(waitCount);
        this.round1EchoReceivedLatch = new CountDownLatch(waitCount);
        this.round2ReceivedLatch = new CountDownLatch(waitCount);
        this.round3ReceivedLatch = new CountDownLatch(waitCount);
    }

    private static Set<Integer> defaultParticipants(int nodesCount) {
        java.util.LinkedHashSet<Integer> result = new java.util.LinkedHashSet<>();
        for (int i = 1; i <= nodesCount; i++) {
            result.add(i);
        }
        return java.util.Collections.unmodifiableSet(result);
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
