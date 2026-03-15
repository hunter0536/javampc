package com.example.mpc.dto;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.TaskStatus;

import java.math.BigInteger;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

public class CggmpAuxTask {
    public static final long DEFAULT_TIMEOUT_MS = Constants.AUX_TASK_TIMEOUT_MS;

    public final String taskId;
    public final String executionId;
    public final int nodesCount;
    public final int initiatorId;
    public final Set<Integer> participants;

    public final AtomicReference<TaskStatus> status = new AtomicReference<>(TaskStatus.PENDING);
    public volatile String errorMessage;
    public volatile long startedAtMs = 0L;
    public volatile java.util.Map<String, Object> lastErrorEvidence;

    // 本地生成的数据
    public volatile PaillierEncryption paillier;
    public volatile BigInteger hatN;
    public volatile BigInteger s;
    public volatile BigInteger t;
    public volatile BigInteger pedersenLambda;
    public volatile PiPrmProof prmProof;

    public final ConcurrentHashMap<Integer, String> commitHashes = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> echoReceived = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, Boolean> savedReceived = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, String> pendingEcho = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, java.util.Map<String, Object>> pendingReveal = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, PaillierEncryption.PublicKey> peerPaillierKeys = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> peerHatN = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> peerS = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, BigInteger> peerT = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, PiPrmProof> peerPrmProofs = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, BiPrimeBlumProof> peerModProofs = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, NoSmallFactorProof> peerFacProofs = new ConcurrentHashMap<>();

    public final ConcurrentHashMap<Integer, byte[]> rho = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Integer, byte[]> u = new ConcurrentHashMap<>();

    public final CountDownLatch commitLatch;
    public final CountDownLatch echoLatch;
    public final CountDownLatch revealLatch;
    public final CountDownLatch proofLatch;
    public final CountDownLatch savedLatch;

    public CggmpAuxTask(String taskId, String executionId, int nodesCount, int initiatorId, Set<Integer> participants) {
        this.taskId = taskId;
        this.executionId = executionId;
        this.nodesCount = nodesCount;
        this.initiatorId = initiatorId;
        this.participants = participants;
        this.commitLatch = new CountDownLatch(participants.size());
        this.echoLatch = new CountDownLatch(participants.size());
        this.revealLatch = new CountDownLatch(participants.size());
        this.proofLatch = new CountDownLatch(participants.size());
        this.savedLatch = new CountDownLatch(participants.size());
    }

    public boolean start() {
        if (status.compareAndSet(TaskStatus.PENDING, TaskStatus.IN_PROGRESS)) {
            startedAtMs = System.currentTimeMillis();
            return true;
        }
        return false;
    }

    public void complete() {
        status.set(TaskStatus.COMPLETED);
    }

    public void fail(String errorMessage) {
        this.errorMessage = errorMessage;
        status.set(TaskStatus.FAILED);
    }

    public boolean isTimeout() {
        if (startedAtMs == 0) return false;
        return System.currentTimeMillis() - startedAtMs > DEFAULT_TIMEOUT_MS;
    }
}
