package com.example.mpc.model;

import com.example.mpc.enums.TaskStatus;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.presign.Presignature;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
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
    public BigInteger hdShift;

    public byte[] messageHash;
    public ECPoint groupPublicKeyPoint;
    public java.util.Map<Integer, ECPoint> publicShares;
    public java.util.Map<Integer, java.math.BigInteger> indexMap;
    public byte[] chainCode;
    public PaillierEncryption paillier;
    public ZKSetup zkSetup;
    public final ConcurrentHashMap<Integer, PaillierEncryption.PublicKey> peerPaillierKeys = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ZKSetup> peerZkSetups = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, MtAInitiatorMessage> mtaKaInitiatorMessages = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, MtAInitiatorMessage> mtaStInitiatorMessages = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.math.BigInteger> peerShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.math.BigInteger> mtaBetas = new ConcurrentHashMap<>();

    // Presign state (CGGMP21 3-round presigning)
    public final ConcurrentHashMap<Integer, BigInteger> presignK = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignG = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignGamma = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignY = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignA1 = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignA2 = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignB1 = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignB2 = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> presignR1Received = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> presignR1EchoReceived = new ConcurrentHashMap<>();
    public BigInteger presignYScalar;
    public BigInteger presignAScalar;
    public BigInteger presignBScalar;
    public final ConcurrentHashMap<Integer, BigInteger> presignD = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignDhat = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignF = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignFhat = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignFOutgoing = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignFhatOutgoing = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignBeta = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignBetaHat = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignRho = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignMu = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignRhoHat = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignMuHat = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> presignDelta = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignDeltaPoint = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignSPoint = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> presignR2Received = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignDeltaTilde = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> presignSTilde = new ConcurrentHashMap<>();
    public Presignature presignature;
    public volatile boolean presignatureUsed = false;

    public BigInteger k_i;
    public BigInteger a_i;
    public BigInteger kInv_i;
    public BigInteger t_i;
    public BigInteger r;
    public BigInteger gammaCommitRand;
    public final ConcurrentHashMap<Integer, ECPoint> gammaPoints = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, ECPoint> gammaCommitments = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, BigInteger> kaAlphas = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> kaBetas = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> stAlphas = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> stBetas = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> uShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> sShares = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, String> uCommitments = new ConcurrentHashMap<>();
    public BigInteger uCommitRand;

    public final CountDownLatch gammaCommitLatch;
    public final CountDownLatch gammaLatch;
    public final CountDownLatch presignR1EchoLatch;
    public final CountDownLatch presignR2Latch;
    public final CountDownLatch kaInitLatch;
    public final CountDownLatch kaResponseLatch;
    public final CountDownLatch uCommitLatch;
    public final CountDownLatch uShareLatch;
    public final CountDownLatch uOpenLatch;
    public final CountDownLatch stInitLatch;
    public final CountDownLatch stResponseLatch;
    public final CountDownLatch sShareLatch;
    public final CountDownLatch offlineDoneLatch;
    public final CountDownLatch offlineReadyLatch;
    public final CountDownLatch presignatureLatch;
    public final ConcurrentHashMap<Integer, Boolean> offlineReady = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, Boolean> shareResponses = new ConcurrentHashMap<>();

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
        this.gammaCommitLatch = new CountDownLatch(waitCount);
        this.gammaLatch = new CountDownLatch(waitCount);
        this.presignR1EchoLatch = new CountDownLatch(waitCount);
        this.presignR2Latch = new CountDownLatch(waitCount);
        this.kaInitLatch = new CountDownLatch(waitCount);
        this.kaResponseLatch = new CountDownLatch(waitCount);
        this.uCommitLatch = new CountDownLatch(waitCount);
        this.uShareLatch = new CountDownLatch(waitCount);
        this.uOpenLatch = new CountDownLatch(1);
        this.stInitLatch = new CountDownLatch(waitCount);
        this.stResponseLatch = new CountDownLatch(waitCount);
        this.sShareLatch = new CountDownLatch(waitCount);
        this.offlineDoneLatch = new CountDownLatch(waitCount);
        this.offlineReadyLatch = new CountDownLatch(waitCount);
        this.presignatureLatch = new CountDownLatch(1);
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
