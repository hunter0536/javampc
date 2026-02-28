package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofGenerator;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofGenerator;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.cggmp.util.CggmpCodecUtils;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.model.CggmpRefreshTask;
import com.example.mpc.model.KeyShare;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Service
public class CggmpRefreshService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpRefreshService.class);
    private static final ExecutorService refreshExecutorService = ThreadPoolUtil.getComputationThreadPool();

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Autowired
    private ComplaintDao complaintDao;

    @Value("${node.id}")
    private int nodeId;
    @Value("${app.cggmp.hdEnabled:false}")
    private boolean hdEnabled;

    @Value("${app.cggmp.refresh.paillierBits:3072}")
    private int refreshPaillierBits;
    @Value("${app.cggmp.complaint.logPath:logs/complaints.jsonl}")
    private String complaintLogPath;
    private final Map<String, CggmpRefreshTask> refreshTasks = new ConcurrentHashMap<>();

    private volatile PaillierEncryption refreshPaillier;
    private volatile ZKSetup refreshZkSetup;

    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;
    private final ScheduledExecutorService cggmpScheduler = Executors.newSingleThreadScheduledExecutor();

    private void fireAndForget(CompletableFuture<Void> future, String name) {
        future.whenComplete((v, ex) -> {
            if (ex != null) {
                logger.warn("{} failed: {}", name, ex.getMessage());
            }
        });
    }

    public String createRefreshTask(String groupPublicKey) {
        String fixedGroupPublicKey;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        String taskId = UUID.randomUUID().toString();
        Set<Integer> participants = new LinkedHashSet<>();
        for (int i = 1; i <= nodesCount; i++) {
            participants.add(i);
        }
        createRefreshTaskInternal(taskId, fixedGroupPublicKey, participants, nodeId);
        return taskId;
    }

    public CompletableFuture<Void> startRefreshTask(String taskId) {
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Refresh task not found"));
        }
        if (!task.start()) {
            return CompletableFuture.completedFuture(null);
        }
        return runRefreshProtocolAsync(task);
    }

    private CggmpRefreshTask createRefreshTaskInternal(String taskId, String groupPublicKey, Set<Integer> participants, int initiatorId) {
        CggmpRefreshTask task = new CggmpRefreshTask(taskId, groupPublicKey, nodesCount, initiatorId, participants);
        refreshTasks.put(taskId, task);
        return task;
    }

    public com.example.mpc.common.response.RefreshTaskStatusResponse getRefreshTaskStatus(String taskId) {
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Refresh task not found: " + taskId);
        }
        com.example.mpc.common.response.RefreshTaskStatusResponse response = new com.example.mpc.common.response.RefreshTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setInProgress(task.status.get().isRunning());
        response.setCompleted(task.status.get() == TaskStatus.COMPLETED);
        response.setStatus(task.status.get().name());
        response.setErrorMessage(task.errorMessage);
        response.setParticipants(new ArrayList<>(task.participants));
        response.setReceivedR1(task.participants.size() - 1 - (int) task.round1Latch.getCount());
        response.setReceivedR2(task.participants.size() - 1 - (int) task.round2Latch.getCount());
        response.setReceivedR3(task.participants.size() - 1 - (int) task.round3Latch.getCount());
        return response;
    }

    // 已废弃：基于 MtA 的 DKG 处理程序，已在 CGGMP21 DKG 中移除


    private static byte[] buildRefreshContext(String taskId, byte[] rid, int senderId, String label) {
        String base = "REFRESH:" + label + ":" + taskId + ":" + senderId + ":";
        byte[] prefix = base.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (rid == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rid.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rid, 0, out, prefix.length, rid.length);
        return out;
    }


    private CompletableFuture<Void> runRefreshProtocolAsync(CggmpRefreshTask task) {
        return waitForNetworkReadyAsync(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS)
                .thenCompose(ready -> {
                    if (!ready) {
                        return CompletableFuture.failedFuture(new RuntimeException("Refresh network ready timeout"));
                    }
                    return CompletableFuture.supplyAsync(() -> {
                        try {
                            BigInteger q = Secp256k1CurveUtils.n();
                            logger.info("Refresh {} network ready", task.taskId);
                            if (!task.participants.contains(nodeId)) {
                                return null;
                            }
                            long paillierStart = System.currentTimeMillis();
                            logger.info("Refresh {} generating Paillier ({} bits)...", task.taskId, refreshPaillierBits);
                            task.paillier = new PaillierEncryption(refreshPaillierBits);
                            logger.debug("Refresh {} Paillier ready in {} ms", task.taskId, System.currentTimeMillis() - paillierStart);
                            task.zkSetup = ZKSetup.generate(task.paillier.getPublicKeyInfo().bitLength);

                            BigInteger[] ped = generateRefreshPedersen(task.paillier.getPublicKeyInfo().bitLength);
                            task.pedersenHatN = ped[0];
                            task.pedersenS = ped[1];
                            task.pedersenT = ped[2];
                            task.pedersenLambda = ped[3];
                            task.prmProof = RefreshProofs.createPrmProof(
                                    task.pedersenHatN,
                                    task.pedersenS,
                                    task.pedersenT,
                                    task.pedersenLambda,
                                    buildRefreshContext(task.taskId, null, nodeId, "PRM")
                            );

                            BigInteger xi = loadLocalShare(task.groupPublicKey);
                            ECPoint Xi = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xi);

                            BigInteger sum = BigInteger.ZERO;
                            for (int peerId : task.participants) {
                                if (peerId == nodeId) {
                                    continue;
                                }
                                BigInteger share = randomNonZero(q);
                                task.xShares.put(peerId, share);
                                sum = sum.add(share).mod(q);
                            }
                            BigInteger selfShare = q.subtract(sum).mod(q);
                            task.xShares.put(nodeId, selfShare);
                            for (int peerId : task.participants) {
                                BigInteger x = task.xShares.get(peerId);
                                task.xPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), x));
                            }

                            for (int peerId : task.participants) {
                                BigInteger y = randomNonZero(q);
                                task.yShares.put(peerId, y);
                                task.yPoints.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), y));
                            }

                            Map<Integer, ECPoint> A = new HashMap<>();
                            SecureRandom rnd = new SecureRandom();
                            for (int peerId : task.participants) {
                                BigInteger alpha = new BigInteger(q.bitLength(), rnd).mod(q);
                                task.schAlphas.put(peerId, alpha);
                                A.put(peerId, Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), alpha));
                            }

                            byte[] rid = randomBytes(32);
                            byte[] u = randomBytes(32);

                            String v = computeRefreshCommit(task.taskId, nodeId, task.xPoints, task.yPoints, A, Xi,
                                    task.paillier.getPublicKeyInfo(), task.zkSetup, task.pedersenHatN, task.pedersenS, task.pedersenT,
                                    task.prmProof, rid, u);
                            task.round1Commit.put(nodeId, v);
                            fireAndForget(broadcastRefreshR1(task, v), "CGGMP_REFRESH_R1");

                            Map<Integer, ECPoint> yMap = new HashMap<>(task.yPoints);
                            Map<Integer, ECPoint> xMap = new HashMap<>(task.xPoints);
                            Map<Integer, ECPoint> aMap = A;
                            CggmpRefreshTask.RefreshRound2Data r2 = new CggmpRefreshTask.RefreshRound2Data(
                                    task.paillier.getPublicKeyInfo(),
                                    task.zkSetup,
                                    task.pedersenHatN,
                                    task.pedersenS,
                                    task.pedersenT,
                                    task.prmProof,
                                    yMap,
                                    xMap,
                                    aMap,
                                    Xi,
                                    rid,
                                    u
                            );
                            task.round2Data.put(nodeId, r2);
                            return task;
                        } catch (Exception e) {
                            task.fail(e.getMessage());
                            throw new RuntimeException(e);
                        }
                    }, refreshExecutorService);
                })
                .thenCompose(t -> {
                    if (t == null) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return waitForLatchAsync(task.round1Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R1")
                            .thenCompose(v -> broadcastRefreshR2(task, task.round2Data.get(nodeId)))
                            .thenCompose(v -> waitForLatchAsync(task.round2Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R2"))
                            .thenCompose(v -> CompletableFuture.runAsync(() -> {
                                byte[] mergedRid = xorAllRid(task);
                                task.rid = mergedRid;

                                Map<Integer, BigInteger> C = new HashMap<>();
                                Map<Integer, PiSchProof> schProofs = new HashMap<>();
                                for (int peerId : task.participants) {
                                    if (peerId == nodeId) continue;
                                    ECPoint Yji = task.round2Data.get(peerId).Y.get(nodeId);
                                    BigInteger y = task.yShares.get(peerId);
                                    BigInteger rho = deriveRefreshMask(task.taskId, mergedRid, nodeId, peerId, Yji, y);
                                    BigInteger xij = task.xShares.get(peerId);
                                    C.put(peerId, xij.add(rho).mod(Secp256k1CurveUtils.n()));
                                }
                                for (int peerId : task.participants) {
                                    BigInteger xij = task.xShares.get(peerId);
                                    PiSchProof sch = RefreshProofs.createSchProof(
                                            Secp256k1CurveUtils.G(),
                                            task.xPoints.get(peerId),
                                            xij,
                                            buildRefreshContext(task.taskId, mergedRid, nodeId, "SCH:" + peerId)
                                    );
                                    schProofs.put(peerId, sch);
                                }

                                BiPrimeBlumProof biPrime = new BiPrimeProofGenerator().createProof(task.paillier.getPrivateKeyInfo(),
                                        buildRefreshContext(task.taskId, mergedRid, nodeId, "MOD"));
                                NoSmallFactorProof factor = new NoSmallFactorProofGenerator(task.zkSetup)
                                        .createProof(task.paillier.getPrivateKeyInfo(), buildRefreshContext(task.taskId, mergedRid, nodeId, "FAC"));

                                CggmpRefreshTask.RefreshRound3Data r3 = new CggmpRefreshTask.RefreshRound3Data(
                                        C,
                                        schProofs,
                                        biPrime,
                                        factor
                                );
                                task.round3Data.put(nodeId, r3);
                                fireAndForget(broadcastRefreshR3(task, r3), "CGGMP_REFRESH_R3");
                            }, refreshExecutorService))
                            .thenCompose(v -> waitForLatchAsync(task.round3Latch, Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, "refresh R3"))
                            .thenRunAsync(() -> {
                                if (!finalizeRefresh(task)) {
                                    task.fail("Refresh verification failed");
                                    return;
                                }
                                task.complete();
                            }, refreshExecutorService);
                }).whenComplete((v, ex) -> {
                    if (ex == null) {
                        return;
                    }
                    Throwable cause = ex instanceof CompletionException ? ex.getCause() : ex;
                    task.fail(cause == null ? ex.getMessage() : cause.getMessage());
                });
    }

    private CompletableFuture<Void> broadcastRefreshR1(CggmpRefreshTask task, String commit) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("initiatorId", task.initiatorId);
        data.put("participants", new ArrayList<>(task.participants));
        data.put("commit", commit);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_R1, data));
    }

    private CompletableFuture<Void> broadcastRefreshR2(CggmpRefreshTask task, CggmpRefreshTask.RefreshRound2Data r2) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("paillierPublicKey", CggmpCodecUtils.encodePaillierPublicKey(r2.paillierKey));
        data.put("zkSetup", CggmpCodecUtils.encodeZkSetup(r2.zkSetup));
        data.put("hatN", r2.hatN.toString(16));
        data.put("s", r2.s.toString(16));
        data.put("t", r2.t.toString(16));
        data.put("prmProof", CggmpCodecUtils.encodePiPrmProof(r2.prmProof));
        data.put("Y", Secp256k1CurveUtils.encodeECPointMap(r2.Y));
        data.put("X", Secp256k1CurveUtils.encodeECPointMap(r2.X));
        data.put("A", Secp256k1CurveUtils.encodeECPointMap(r2.A));
        data.put("Xi", HexUtils.bytesToHex(Secp256k1CurveUtils.encodePoint(r2.Xi)));
        data.put("rid", Base64.getEncoder().encodeToString(r2.rid));
        data.put("u", Base64.getEncoder().encodeToString(r2.u));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_R2, data));
    }

    private CompletableFuture<Void> broadcastRefreshR3(CggmpRefreshTask task, CggmpRefreshTask.RefreshRound3Data r3) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("C", JsonUtils.encodeBigIntegerMap(r3.C));
        data.put("schProofs", CggmpCodecUtils.encodeSchProofMap(r3.schProofs));
        data.put("biPrimeProof", CggmpCodecUtils.encodeBiPrimeProof(r3.biPrimeProof));
        data.put("factorProof", CggmpCodecUtils.encodeNoSmallFactorProof(r3.factorProof));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_R3, data));
    }

    private CompletableFuture<Void> broadcastRefreshComplaint(CggmpRefreshTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_COMPLAINT, data));
    }

    private CompletableFuture<Void> broadcastRefreshExclude(CggmpRefreshTask task, int offenderId, String reason, String newTaskId, Set<Integer> newParticipants) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        data.put("newTaskId", newTaskId);
        data.put("groupPublicKey", task.groupPublicKey);
        data.put("participants", new ArrayList<>(newParticipants));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_EXCLUDE, data));
    }

    private void handleRefreshR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String groupPublicKey = (String) dataMap.get("groupPublicKey");
        Object participantsValue = dataMap.get("participants");
        Object initiatorValue = dataMap.get("initiatorId");
        String commit = (String) dataMap.get("commit");
        if (taskId == null || groupPublicKey == null || commit == null) {
            return;
        }
        int initiatorId = initiatorValue instanceof Number n ? n.intValue() : senderId;
        Set<Integer> participants = new LinkedHashSet<>();
        if (participantsValue instanceof List<?> list) {
            for (Object v : list) {
                if (v instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
        }
        if (participants.isEmpty()) {
            for (int i = 1; i <= nodesCount; i++) {
                participants.add(i);
            }
        }
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            task = new CggmpRefreshTask(taskId, groupPublicKey, nodesCount, initiatorId, participants);
            refreshTasks.put(taskId, task);
        }
        if (!task.participants.contains(senderId)) {
            return;
        }
        if (task.round1Commit.putIfAbsent(senderId, commit) == null && task.round1Latch.getCount() > 0) {
            task.round1Latch.countDown();
        }
        if (task.participants.contains(nodeId) && !task.isInProgress() && !task.isCompleted()) {
            startRefreshTask(taskId).exceptionally(ex -> {
                logger.error("Failed to auto-start refresh task {}: {}", taskId, ex.getMessage());
                return null;
            });
        }
    }

    private void handleRefreshR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            String hatNHex = (String) dataMap.get("hatN");
            String sHex = (String) dataMap.get("s");
            String tHex = (String) dataMap.get("t");
            Map<?, ?> prmMap = (Map<?, ?>) dataMap.get("prmProof");
            Map<?, ?> yMap = (Map<?, ?>) dataMap.get("Y");
            Map<?, ?> xMap = (Map<?, ?>) dataMap.get("X");
            Map<?, ?> aMap = (Map<?, ?>) dataMap.get("A");
            String xiHex = (String) dataMap.get("Xi");
            String ridB64 = (String) dataMap.get("rid");
            String uB64 = (String) dataMap.get("u");

            if (pkMap == null || zkMap == null || hatNHex == null || sHex == null || tHex == null || prmMap == null
                    || yMap == null || xMap == null || aMap == null || xiHex == null || ridB64 == null || uB64 == null) {
                return;
            }

            PaillierEncryption.PublicKey pk = CggmpCodecUtils.decodePaillierPublicKey(pkMap);
            ZKSetup zk = CggmpCodecUtils.decodeZkSetup(zkMap);
            BigInteger hatN = new BigInteger(hatNHex, 16);
            BigInteger s = new BigInteger(sHex, 16);
            BigInteger t = new BigInteger(tHex, 16);
            PiPrmProof prmProof = CggmpCodecUtils.decodePiPrmProof(prmMap);
            Map<Integer, ECPoint> Y = Secp256k1CurveUtils.decodeECPointMap(yMap);
            Map<Integer, ECPoint> X = Secp256k1CurveUtils.decodeECPointMap(xMap);
            Map<Integer, ECPoint> A = Secp256k1CurveUtils.decodeECPointMap(aMap);
            ECPoint Xi = Secp256k1CurveUtils.decodePoint(HexUtils.hexToBytes(xiHex));
            byte[] rid = Base64.getDecoder().decode(ridB64);
            byte[] u = Base64.getDecoder().decode(uB64);

            String commit = task.round1Commit.get(senderId);
            if (commit == null) {
                fireAndForget(broadcastRefreshComplaint(task, senderId, "Missing refresh R1 commit",
                        refreshEvidence(task, senderId, "Missing refresh R1 commit", null)), "CGGMP_REFRESH_COMPLAINT");
                task.fail("Missing refresh R1 commit");
                return;
            }

            String expected = computeRefreshCommit(task.taskId, senderId, X, Y, A, Xi, pk, zk, hatN, s, t, prmProof, rid, u);
            if (!commit.equals(expected)) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("expectedCommit", expected);
                extra.put("commit", commit);
                fireAndForget(broadcastRefreshComplaint(task, senderId, "Refresh R1 commit mismatch",
                        refreshEvidence(task, senderId, "Refresh R1 commit mismatch", extra)), "CGGMP_REFRESH_COMPLAINT");
                task.fail("Refresh commit mismatch");
                return;
            }

            if (!validatePaillierPublicKey(pk)) {
                fireAndForget(broadcastRefreshComplaint(task, senderId, "Invalid Paillier public key",
                                refreshEvidence(task, senderId, "Invalid Paillier public key", Map.of("n", pk.n.toString(16)))),
                        "CGGMP_REFRESH_COMPLAINT");
                task.fail("Invalid Paillier key");
                return;
            }

            if (!RefreshProofs.verifyPrmProof(prmProof, hatN, s, t, buildRefreshContext(task.taskId, null, senderId, "PRM"))) {
                fireAndForget(broadcastRefreshComplaint(task, senderId, "Invalid PiPrm proof",
                                refreshEvidence(task, senderId, "Invalid PiPrm proof", Map.of("hatN", hatN.toString(16)))),
                        "CGGMP_REFRESH_COMPLAINT");
                task.fail("Invalid PiPrm proof");
                return;
            }

            CggmpRefreshTask.RefreshRound2Data r2 = new CggmpRefreshTask.RefreshRound2Data(
                    pk, zk, hatN, s, t, prmProof, Y, X, A, Xi, rid, u
            );
            if (task.round2Data.putIfAbsent(senderId, r2) == null && task.round2Latch.getCount() > 0) {
                task.round2Latch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle refresh R2", e);
        }
    }

    private void handleRefreshR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        if (senderId == nodeId) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            Map<?, ?> cMap = (Map<?, ?>) dataMap.get("C");
            Map<?, ?> schMap = (Map<?, ?>) dataMap.get("schProofs");
            Map<?, ?> biPrimeMap = (Map<?, ?>) dataMap.get("biPrimeProof");
            Map<?, ?> factorMap = (Map<?, ?>) dataMap.get("factorProof");
            if (cMap == null || schMap == null || biPrimeMap == null || factorMap == null) {
                return;
            }
            Map<Integer, BigInteger> C = JsonUtils.decodeBigIntegerMap(cMap);
            Map<Integer, PiSchProof> schProofs = CggmpCodecUtils.decodeSchProofMap(schMap);
            BiPrimeBlumProof biPrime = CggmpCodecUtils.decodeBiPrimeProof(biPrimeMap);
            NoSmallFactorProof factor = CggmpCodecUtils.decodeNoSmallFactorProof(factorMap);

            CggmpRefreshTask.RefreshRound3Data r3 = new CggmpRefreshTask.RefreshRound3Data(C, schProofs, biPrime, factor);
            if (task.round3Data.putIfAbsent(senderId, r3) == null && task.round3Latch.getCount() > 0) {
                task.round3Latch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle refresh R3", e);
        }
    }

    private void handleRefreshComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        if (taskId == null) {
            return;
        }
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        Object evidenceObj = dataMap.get("evidence");
        logComplaintToFile(taskId, senderId, offenderId, reason == null ? "refresh complaint" : reason, evidenceObj);
        Map<?, ?> evidence = evidenceObj instanceof Map<?, ?> m ? m : null;
        boolean evidenceOk = validateRefreshComplaintEvidence(task, offenderId, reason, evidence);
        if (task.initiatorId == nodeId) {
            if (!evidenceOk) {
                attemptExcludeAndRestartRefresh(task, senderId, "Invalid refresh complaint evidence");
                return;
            }
            if (offenderId != null) {
                attemptExcludeAndRestartRefresh(task, offenderId, reason == null ? "refresh complaint" : reason);
                return;
            }
            task.fail("Refresh complaint without offender");
            return;
        }
        if (!evidenceOk) {
            task.fail("Refresh complaint invalid: " + (reason == null ? "unknown" : reason));
            return;
        }
        task.fail("Refresh complaint: " + (reason == null ? "unknown" : reason));
    }

    private void handleRefreshExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        String newTaskId = (String) dataMap.get("newTaskId");
        String groupPublicKey = (String) dataMap.get("groupPublicKey");
        Object participantsValue = dataMap.get("participants");
        if (taskId == null || newTaskId == null || groupPublicKey == null) {
            return;
        }
        int offenderId = offenderValue instanceof Number n ? n.intValue() : -1;
        Set<Integer> participants = new LinkedHashSet<>();
        if (participantsValue instanceof List<?> list) {
            for (Object v : list) {
                if (v instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
        }
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task != null) {
            task.fail("Refresh excluded offender " + offenderId + ": " + (reason == null ? "" : reason));
        }
        if (!participants.isEmpty()) {
            if (!refreshTasks.containsKey(newTaskId)) {
                createRefreshTaskInternal(newTaskId, groupPublicKey, participants, senderId);
            }
            if (participants.contains(nodeId)) {
                startRefreshTask(newTaskId).exceptionally(ex -> {
                    logger.error("Failed to start new refresh task {}: {}", newTaskId, ex.getMessage());
                    return null;
                });
            }
        }
    }

    private boolean finalizeRefresh(CggmpRefreshTask task) {
        if (task.rid == null || task.rid.length == 0) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        for (int peerId : task.participants) {
            if (!task.round1Commit.containsKey(peerId) || !task.round2Data.containsKey(peerId) || !task.round3Data.containsKey(peerId)) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Missing refresh data",
                                refreshEvidence(task, peerId, "Missing refresh data", Map.of("peerId", peerId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
        }

        for (int peerId : task.participants) {
            CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(peerId);
            String commit = task.round1Commit.get(peerId);
            if (r2 == null || commit == null) {
                return false;
            }
            String expected = computeRefreshCommit(task.taskId, peerId, r2.X, r2.Y, r2.A, r2.Xi, r2.paillierKey,
                    r2.zkSetup, r2.hatN, r2.s, r2.t, r2.prmProof, r2.rid, r2.u);
            if (!commit.equals(expected)) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("commit", commit);
                extra.put("expectedCommit", expected);
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Refresh commit mismatch",
                                refreshEvidence(task, peerId, "Refresh commit mismatch", extra)),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            if (!RefreshProofs.verifyPrmProof(r2.prmProof, r2.hatN, r2.s, r2.t, buildRefreshContext(task.taskId, null, peerId, "PRM"))) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Invalid PiPrm proof",
                                refreshEvidence(task, peerId, "Invalid PiPrm proof", Map.of("peerId", peerId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint sum = Secp256k1CurveUtils.sumPoints(r2.X);
            if (!sum.isInfinity()) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("xSum", HexUtils.bytesToHex(sum.getEncoded(false)));
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Sum of X not identity",
                                refreshEvidence(task, peerId, "Sum of X not identity", extra)),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
        }

        Map<Integer, BigInteger> deltas = new HashMap<>();
        for (int peerId : task.participants) {
            CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(peerId);
            CggmpRefreshTask.RefreshRound3Data r3 = task.round3Data.get(peerId);
            if (r2 == null || r3 == null) {
                return false;
            }

            BiPrimeProofValidator biPrimeValidator = new BiPrimeProofValidator();
            if (!biPrimeValidator.verifyProof(r3.biPrimeProof, r2.paillierKey, buildRefreshContext(task.taskId, task.rid, peerId, "MOD"))) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Invalid Blum proof",
                                refreshEvidence(task, peerId, "Invalid Blum proof", Map.of("peerId", peerId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            NoSmallFactorProofValidator factorValidator = new NoSmallFactorProofValidator(r2.zkSetup);
            if (!factorValidator.verifyProof(r3.factorProof, r2.paillierKey, buildRefreshContext(task.taskId, task.rid, peerId, "FAC"))) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Invalid NoSmallFactor proof",
                                refreshEvidence(task, peerId, "Invalid NoSmallFactor proof", Map.of("peerId", peerId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }

            for (int k : task.participants) {
                PiSchProof sch = r3.schProofs.get(k);
                ECPoint Xjk = r2.X.get(k);
                if (sch == null || Xjk == null) {
                    fireAndForget(broadcastRefreshComplaint(task, peerId, "Missing Schnorr proof",
                                    refreshEvidence(task, peerId, "Missing Schnorr proof", Map.of("peerId", peerId, "k", k))),
                            "CGGMP_REFRESH_COMPLAINT");
                    return false;
                }
                if (!RefreshProofs.verifySchProof(sch, Secp256k1CurveUtils.G(), Xjk, buildRefreshContext(task.taskId, task.rid, peerId, "SCH:" + k))) {
                    fireAndForget(broadcastRefreshComplaint(task, peerId, "Invalid Schnorr proof",
                                    refreshEvidence(task, peerId, "Invalid Schnorr proof", Map.of("peerId", peerId, "k", k))),
                            "CGGMP_REFRESH_COMPLAINT");
                    return false;
                }
            }

            if (peerId == nodeId) {
                continue;
            }
            BigInteger Cji = r3.C.get(nodeId);
            if (Cji == null) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Missing C_{j,i}",
                                refreshEvidence(task, peerId, "Missing C_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint Yji = r2.Y.get(nodeId);
            if (Yji == null) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Missing Y_{j,i}",
                                refreshEvidence(task, peerId, "Missing Y_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            BigInteger yij = task.yShares.get(peerId);
            if (yij == null) {
                return false;
            }
            BigInteger rho = deriveRefreshMask(task.taskId, task.rid, peerId, nodeId, Yji, yij);
            BigInteger xji = Cji.subtract(rho).mod(q);
            ECPoint Xji = r2.X.get(nodeId);
            if (Xji == null) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Missing X_{j,i}",
                                refreshEvidence(task, peerId, "Missing X_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            ECPoint check = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xji);
            if (!check.equals(Xji)) {
                fireAndForget(broadcastRefreshComplaint(task, peerId, "Invalid C_{j,i} decryption",
                                refreshEvidence(task, peerId, "Invalid C_{j,i} decryption", Map.of("peerId", peerId, "missingFor", nodeId))),
                        "CGGMP_REFRESH_COMPLAINT");
                return false;
            }
            deltas.put(peerId, xji);
        }

        BigInteger oldShare = loadLocalShare(task.groupPublicKey);
        BigInteger deltaSum = task.xShares.getOrDefault(nodeId, BigInteger.ZERO);
        for (BigInteger v : deltas.values()) {
            deltaSum = deltaSum.add(v).mod(q);
        }
        BigInteger newShare = oldShare.add(deltaSum).mod(q);
        try {
            KeyShare keyShare = new KeyShare(nodeId, newShare.toString(16), task.groupPublicKey, task.taskId);
            keyShareDao.save(keyShare);
        } catch (Exception e) {
            logger.error("Failed to save refreshed key share", e);
            return false;
        }

        refreshPaillier = task.paillier;
        refreshZkSetup = task.zkSetup;
        return true;
    }

    private Map<String, Object> refreshEvidence(CggmpRefreshTask task, int offenderId, String reason, Map<String, Object> extra) {
        Map<String, Object> ev = new HashMap<>();
        ev.put("v", 1);
        ev.put("taskId", task.taskId);
        ev.put("offenderId", offenderId);
        ev.put("reason", reason);
        if (task.rid != null && task.rid.length > 0) {
            ev.put("rid", HexUtils.bytesToHex(task.rid));
        }
        if (extra != null) {
            for (Map.Entry<String, Object> entry : extra.entrySet()) {
                String key = entry.getKey();
                if (isRefreshEvidenceKeyAllowed(key)) {
                    ev.put(key, entry.getValue());
                }
            }
        }
        return ev;
    }

    private boolean validateRefreshComplaintEvidence(CggmpRefreshTask task, Integer offenderId, String reason, Map<?, ?> evidence) {
        if (task == null || offenderId == null || reason == null) {
            return false;
        }
        if (!task.participants.contains(offenderId)) {
            return false;
        }
        if (evidence != null) {
            Object evVersion = evidence.get("v");
            if (evVersion instanceof Number n && n.intValue() != 1) {
                return false;
            }
            for (Object k : evidence.keySet()) {
                if (k instanceof String s) {
                    if (!isRefreshEvidenceKeyAllowed(s)) {
                        return false;
                    }
                }
            }
            Object evOffender = evidence.get("offenderId");
            if (evOffender instanceof Number n && n.intValue() != offenderId) {
                return false;
            }
            Object evReason = evidence.get("reason");
            if (evReason instanceof String s && !s.equals(reason)) {
                return false;
            }
            Object evRid = evidence.get("rid");
            if (evRid instanceof String s && task.rid != null) {
                String ridHex = HexUtils.bytesToHex(task.rid);
                if (!ridHex.equalsIgnoreCase(s)) {
                    return false;
                }
            }
        }
        String r = reason.trim();
        CggmpRefreshTask.RefreshRound2Data r2 = task.round2Data.get(offenderId);
        CggmpRefreshTask.RefreshRound3Data r3 = task.round3Data.get(offenderId);
        String commit = task.round1Commit.get(offenderId);
        try {
            if (r.startsWith("Missing refresh data")) {
                return commit == null || r2 == null || r3 == null;
            }
            if (r.startsWith("Missing refresh R1 commit")) {
                return commit == null;
            }
            if (r.startsWith("Refresh R1 commit mismatch") || r.startsWith("Refresh commit mismatch")) {
                if (commit == null || r2 == null) return false;
                String expected = computeRefreshCommit(task.taskId, offenderId, r2.X, r2.Y, r2.A, r2.Xi, r2.paillierKey,
                        r2.zkSetup, r2.hatN, r2.s, r2.t, r2.prmProof, r2.rid, r2.u);
                if (evidence != null) {
                    Object evCommit = evidence.get("commit");
                    Object evExpected = evidence.get("expectedCommit");
                    if (evCommit instanceof String s && !s.equalsIgnoreCase(commit)) {
                        return false;
                    }
                    if (evExpected instanceof String s && !s.equalsIgnoreCase(expected)) {
                        return false;
                    }
                }
                return !commit.equals(expected);
            }
            if (r.startsWith("Invalid Paillier public key")) {
                return r2 != null && !validatePaillierPublicKey(r2.paillierKey);
            }
            if (r.startsWith("Invalid PiPrm proof")) {
                return r2 != null && !RefreshProofs.verifyPrmProof(r2.prmProof, r2.hatN, r2.s, r2.t,
                        buildRefreshContext(task.taskId, null, offenderId, "PRM"));
            }
            if (r.startsWith("Sum of X not identity")) {
                return r2 != null && !Secp256k1CurveUtils.sumPoints(r2.X).isInfinity();
            }
            if (r.startsWith("Invalid Blum proof")) {
                if (r2 == null || r3 == null) return false;
                BiPrimeProofValidator biPrimeValidator = new BiPrimeProofValidator();
                return !biPrimeValidator.verifyProof(r3.biPrimeProof, r2.paillierKey,
                        buildRefreshContext(task.taskId, task.rid, offenderId, "MOD"));
            }
            if (r.startsWith("Invalid NoSmallFactor proof")) {
                if (r2 == null || r3 == null) return false;
                NoSmallFactorProofValidator factorValidator = new NoSmallFactorProofValidator(r2.zkSetup);
                return !factorValidator.verifyProof(r3.factorProof, r2.paillierKey,
                        buildRefreshContext(task.taskId, task.rid, offenderId, "FAC"));
            }
            if (r.startsWith("Missing Schnorr proof")) {
                if (r2 == null || r3 == null) return false;
                for (int k : task.participants) {
                    if (!r3.schProofs.containsKey(k) || !r2.X.containsKey(k)) {
                        return true;
                    }
                }
                return false;
            }
            if (r.startsWith("Invalid Schnorr proof")) {
                if (r2 == null || r3 == null) return false;
                for (int k : task.participants) {
                    PiSchProof sch = r3.schProofs.get(k);
                    ECPoint Xjk = r2.X.get(k);
                    if (sch == null || Xjk == null) continue;
                    boolean ok = RefreshProofs.verifySchProof(sch, Secp256k1CurveUtils.G(), Xjk,
                            buildRefreshContext(task.taskId, task.rid, offenderId, "SCH:" + k));
                    if (!ok) return true;
                }
                return false;
            }
            if (r.startsWith("Missing C_{j,i}")) {
                return r3 == null || r3.C.get(nodeId) == null;
            }
            if (r.startsWith("Missing Y_{j,i}")) {
                return r2 == null || r2.Y.get(nodeId) == null;
            }
            if (r.startsWith("Missing X_{j,i}")) {
                return r2 == null || r2.X.get(nodeId) == null;
            }
            if (r.startsWith("Invalid C_{j,i} decryption")) {
                if (r2 == null || r3 == null) return false;
                BigInteger Cji = r3.C.get(nodeId);
                ECPoint Yji = r2.Y.get(nodeId);
                ECPoint Xji = r2.X.get(nodeId);
                BigInteger yij = task.yShares.get(offenderId);
                if (Cji == null || Yji == null || Xji == null || yij == null) return false;
                BigInteger rho = deriveRefreshMask(task.taskId, task.rid, offenderId, nodeId, Yji, yij);
                BigInteger xji = Cji.subtract(rho).mod(Secp256k1CurveUtils.n());
                ECPoint check = Secp256k1CurveUtils.multiply(Secp256k1CurveUtils.G(), xji);
                return !check.equals(Xji);
            }
        } catch (Exception e) {
            logger.warn("Refresh complaint evidence check failed: {}", e.getMessage());
            return false;
        }
        return false;
    }

    private boolean isRefreshEvidenceKeyAllowed(String key) {
        return switch (key) {
            case "v", "taskId", "offenderId", "reason", "rid",
                 "expectedCommit", "commit", "peerId", "k", "missingFor", "xSum", "n" -> true;
            default -> false;
        };
    }

    private void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            String evidenceJson = evidence == null ? null : JsonUtils.encodeAsJson(evidence);
            complaintDao.save(System.currentTimeMillis(), taskId, senderId, offenderId, reason, evidenceJson);
        } catch (Exception e) {
            logger.warn("Failed to persist complaint: {}", e.getMessage());
        }
        try {
            java.nio.file.Path complaintFile = java.nio.file.Paths.get(complaintLogPath);
            java.nio.file.Path dir = complaintFile.getParent();
            if (dir != null) {
                java.nio.file.Files.createDirectories(dir);
            }
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"ts\":").append(System.currentTimeMillis()).append(',');
            sb.append("\"taskId\":\"").append(JsonUtils.escapeJson(taskId)).append("\",");
            sb.append("\"senderId\":").append(senderId).append(',');
            sb.append("\"offenderId\":").append(offenderId == null ? "null" : offenderId).append(',');
            sb.append("\"reason\":\"").append(JsonUtils.escapeJson(reason)).append("\"");
            if (evidence != null) {
                sb.append(",\"evidence\":").append(JsonUtils.encodeAsJson(evidence));
            }
            sb.append('}');
            String line = sb.append(System.lineSeparator()).toString();
            java.nio.file.Files.writeString(complaintFile, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }

    private void attemptExcludeAndRestartRefresh(CggmpRefreshTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            task.fail("Refresh complaint (offender not participant): " + reason);
            return;
        }
        int required = Math.min(Math.max(1, threshold), task.nodesCount);
        LinkedHashSet<Integer> newParticipants = new LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.size() < required) {
            task.fail("Not enough participants after refresh exclusion");
            return;
        }
        String newTaskId = UUID.randomUUID().toString();
        createRefreshTaskInternal(newTaskId, task.groupPublicKey, newParticipants, task.initiatorId);
        logger.warn("Refresh exclusion: offender {} removed, restarting refresh task {}", offenderId, newTaskId);
        fireAndForget(broadcastRefreshExclude(task, offenderId, reason, newTaskId, newParticipants),
                "CGGMP_REFRESH_EXCLUDE");
        startRefreshTask(newTaskId).exceptionally(ex -> {
            logger.error("Failed to restart refresh task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
        task.fail("Refresh restart after excluding offender " + offenderId);
    }

    private BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1CurveUtils.n());
    }

    private BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    private static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        new SecureRandom().nextBytes(out);
        return out;
    }

    private static BigInteger[] generateRefreshPedersen(int bitLength) {
        SecureRandom rnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, rnd);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, rnd);
        while (p.equals(q)) {
            q = BigInteger.probablePrime(bitLength / 2, rnd);
        }
        BigInteger hatN = p.multiply(q);
        BigInteger t;
        do {
            t = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        } while (t.signum() == 0 || !t.gcd(hatN).equals(BigInteger.ONE));
        t = t.modPow(BigInteger.TWO, hatN);
        BigInteger lambda = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        BigInteger s = t.modPow(lambda, hatN);
        return new BigInteger[]{hatN, s, t, lambda};
    }

    private static String computeRefreshCommit(String taskId,
                                               int senderId,
                                               Map<Integer, ECPoint> X,
                                               Map<Integer, ECPoint> Y,
                                               Map<Integer, ECPoint> A,
                                               ECPoint Xi,
                                               PaillierEncryption.PublicKey pk,
                                               ZKSetup zkSetup,
                                               BigInteger hatN,
                                               BigInteger s,
                                               BigInteger t,
                                               PiPrmProof prmProof,
                                               byte[] rid,
                                               byte[] u) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(BigInteger.valueOf(senderId).toByteArray());
            updatePointMap(md, X);
            updatePointMap(md, Y);
            updatePointMap(md, A);
            md.update(Secp256k1CurveUtils.encodePoint(Xi));
            md.update(pk.n.toByteArray());
            md.update(zkSetup.hatN().toByteArray());
            md.update(zkSetup.h1().toByteArray());
            md.update(zkSetup.h2().toByteArray());
            md.update(hatN.toByteArray());
            md.update(s.toByteArray());
            md.update(t.toByteArray());
            md.update(prmProof.A().toByteArray());
            md.update(prmProof.z().toByteArray());
            md.update(rid);
            md.update(u);
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Refresh commit failed", e);
        }
    }

    private static void updatePointMap(MessageDigest md, Map<Integer, ECPoint> map) {
        if (map == null) {
            updateLength(md, 0);
            return;
        }
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        updateLength(md, keys.size());
        for (int k : keys) {
            updateLength(md, k);
            ECPoint p = map.get(k);
            if (p != null) {
                byte[] enc = p.normalize().getEncoded(true);
                updateLength(md, enc.length);
                md.update(enc);
            } else {
                updateLength(md, 0);
            }
        }
    }

    private static void updateLength(MessageDigest md, int length) {
        md.update((byte) ((length >>> 24) & 0xFF));
        md.update((byte) ((length >>> 16) & 0xFF));
        md.update((byte) ((length >>> 8) & 0xFF));
        md.update((byte) (length & 0xFF));
    }


    private Object maybeDecompressDkgPayload(MessageType type, byte[] bytes) {
        if (type == null || bytes == null || bytes.length == 0) {
            return null;
        }
        return null;
    }

    private static BigInteger deriveRefreshMask(String taskId, byte[] rid, int i, int j, ECPoint Yji, BigInteger yij) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(rid);
            md.update(BigInteger.valueOf(i).toByteArray());
            md.update(BigInteger.valueOf(j).toByteArray());
            ECPoint shared = Yji.multiply(yij).normalize();
            md.update(Secp256k1CurveUtils.encodePoint(shared));
            return new BigInteger(1, md.digest()).mod(Secp256k1CurveUtils.n());
        } catch (Exception e) {
            throw new RuntimeException("Refresh mask failed", e);
        }
    }

    private static byte[] xorAllRid(CggmpRefreshTask task) {
        byte[] rid = null;
        for (CggmpRefreshTask.RefreshRound2Data d : task.round2Data.values()) {
            if (rid == null) {
                rid = d.rid.clone();
            } else {
                for (int i = 0; i < rid.length; i++) {
                    rid[i] ^= d.rid[i];
                }
            }
        }
        return rid == null ? new byte[0] : rid;
    }

    private KeyShare loadKeyShareByGroupPublicKeySync(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }

    private boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        return publicKey.n.compareTo(q.pow(8)) >= 0;
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            } else if (map.containsKey("signatureTaskId")) {
                logTaskId = map.get("signatureTaskId");
            }
        }
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, logTaskId);
        Executor executor = ThreadPoolUtil.getSingleThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data;
                if (data instanceof byte[] bytes) {
                    Object decoded = maybeDecompressDkgPayload(message.type, bytes);
                    if (decoded != null) {
                        data = decoded;
                    }
                }
                logger.info("=== CGGMP processing: type={} ===", message.type);
                switch (message.type) {
                    case CGGMP_REFRESH_R1:
                        handleRefreshR1(senderId, data);
                        break;
                    case CGGMP_REFRESH_R2:
                        handleRefreshR2(senderId, data);
                        break;
                    case CGGMP_REFRESH_R3:
                        handleRefreshR3(senderId, data);
                        break;
                    case CGGMP_REFRESH_COMPLAINT:
                        handleRefreshComplaint(senderId, data);
                        break;
                    case CGGMP_REFRESH_EXCLUDE:
                        handleRefreshExclude(senderId, data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP service", message.type);
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_REFRESH_R1,
                            MessageType.CGGMP_REFRESH_R2,
                            MessageType.CGGMP_REFRESH_R3,
                            MessageType.CGGMP_REFRESH_COMPLAINT,
                            MessageType.CGGMP_REFRESH_EXCLUDE
                    ), this);
                    logger.info("CGGMP signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP signature service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    private CompletableFuture<Boolean> waitForNetworkReadyAsync(long timeoutSeconds) {
        return nodeService.waitForNetworkReady()
                .orTimeout(timeoutSeconds, TimeUnit.SECONDS)
                .thenApply(v -> true)
                .exceptionally(ex -> false);
    }

    private CompletableFuture<Void> waitForLatchAsync(CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = cggmpScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

}
