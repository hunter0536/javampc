package com.example.mpc.service;

import com.example.mpc.cggmp.CGGMP;
import com.example.mpc.cggmp.CggmpDkgCodec;
import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.PedersenCommitment;
import com.example.mpc.cggmp.mta.MtAInitiatorMessage;
import com.example.mpc.cggmp.mta.MtAProtocol;
import com.example.mpc.cggmp.sign.CggmpIntegrityChecker;
import com.example.mpc.cggmp.sign.EcChaumPedersenProof;
import com.example.mpc.cggmp.sign.EcPedersen;
import com.example.mpc.cggmp.sign.Secp256k1Curve;
import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.cggmp.proof.BiPrimeBlumProof;
import com.example.mpc.cggmp.proof.BiPrimeProofValidator;
import com.example.mpc.cggmp.proof.BiPrimeProofGenerator;
import com.example.mpc.cggmp.proof.NoSmallFactorProof;
import com.example.mpc.cggmp.proof.NoSmallFactorProofValidator;
import com.example.mpc.cggmp.proof.NoSmallFactorProofGenerator;
import com.example.mpc.cggmp.proof.PiAffGProof;
import com.example.mpc.cggmp.proof.PiDecProof;
import com.example.mpc.cggmp.proof.PiEncElgProof;
import com.example.mpc.cggmp.proof.PiLogProof;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.proof.PiSchProof;
import com.example.mpc.cggmp.proof.PresignProofs;
import com.example.mpc.cggmp.proof.RefreshProofs;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpDkgTask;
import com.example.mpc.model.CggmpRefreshTask;
import com.example.mpc.model.Gg20SignatureTask;
import com.example.mpc.model.KeyShare;
import com.example.mpc.util.PresignUsageStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Service
public class CggmpSignatureService implements NodeService.MessageHandler {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureService.class);
    private static final BiPrimeProofValidator BI_PRIME_VALIDATOR = new BiPrimeProofValidator();
    private final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private NodeService nodeService;

    @Autowired
    private KeyShareDao keyShareDao;

    @Value("${node.id}")
    private int nodeId;

    @Value("${app.cggmp.proof.kappa:128}")
    private int proofKappa;

    @Value("${app.cggmp.proof.epsBits:16}")
    private int proofEpsBits;

    @Value("${app.cggmp.presign.retentionDays:30}")
    private long presignRetentionDays;

    @Value("${app.cggmp.refresh.paillierBits:3072}")
    private int refreshPaillierBits;

    private final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();
    private final Map<String, Gg20SignatureTask> signatureTasks = new ConcurrentHashMap<>();
    private final Map<String, com.example.mpc.model.CggmpRefreshTask> refreshTasks = new ConcurrentHashMap<>();

    private volatile PaillierEncryption refreshPaillier;
    private volatile ZKSetup refreshZkSetup;
    private final Object dkgCacheLock = new Object();
    private volatile PaillierEncryption dkgPaillier;
    private volatile ZKSetup dkgZkSetup;
    private volatile PedersenCommitment dkgPedersen;

    private static final ExecutorService dkgExecutorService = ThreadPoolUtil.getComputationThreadPool();

    private final AtomicBoolean signatureInProgress = new AtomicBoolean(false);
    private final int nodesCount = Constants.NODES_COUNT;
    private final int threshold = Constants.THRESHOLD;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void initialize() throws Exception {
        logger.info("Initializing CGGMP service for node {}", nodeId);
        PresignUsageStore.configureRetentionDays(presignRetentionDays);
        logger.info("CGGMP service initialized successfully");
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
        return CompletableFuture.runAsync(() -> {
            com.example.mpc.model.CggmpRefreshTask task = refreshTasks.get(taskId);
            if (task == null) {
                throw new RuntimeException("Refresh task not found");
            }
            if (!task.start()) {
                return;
            }
            runRefreshProtocol(task);
        }, ThreadPoolUtil.getIoThreadPool());
    }

    private CggmpRefreshTask createRefreshTaskInternal(String taskId, String groupPublicKey, Set<Integer> participants, int initiatorId) {
        CggmpRefreshTask task = new CggmpRefreshTask(taskId, groupPublicKey, nodesCount, initiatorId, participants);
        refreshTasks.put(taskId, task);
        return task;
    }

    public com.example.mpc.common.response.RefreshTaskStatusResponse getRefreshTaskStatus(String taskId) {
        com.example.mpc.model.CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Refresh task not found: " + taskId);
        }
        com.example.mpc.common.response.RefreshTaskStatusResponse response = new com.example.mpc.common.response.RefreshTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setInProgress(task.status.get().isRunning());
        response.setCompleted(task.status.get() == com.example.mpc.enums.TaskStatus.COMPLETED);
        response.setStatus(task.status.get().name());
        response.setErrorMessage(task.errorMessage);
        response.setParticipants(new ArrayList<>(task.participants));
        response.setReceivedR1(task.participants.size() - 1 - (int) task.round1Latch.getCount());
        response.setReceivedR2(task.participants.size() - 1 - (int) task.round2Latch.getCount());
        response.setReceivedR3(task.participants.size() - 1 - (int) task.round3Latch.getCount());
        return response;
    }

    public String createDkgTask() {
        String taskId = UUID.randomUUID().toString();
        CggmpDkgTask task = createDkgTaskInternal(taskId, nodesCount, threshold, null, nodeId);
        dkgTasks.put(taskId, task);
        logger.info("Created CGGMP DKG task: {}", taskId);
        return taskId;
    }

    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return CompletableFuture.runAsync(() -> {
            logger.info("=================== startDkgProcess START: taskId={} ===================", taskId);
            final long dkgStartNs = System.nanoTime();
            CggmpDkgTask task = null;
            try {
                task = getDkgTask(taskId);

                if (!task.start()) {
                    logger.warn("DKG task {} failed to start (may already be in progress), skipping", taskId);
                    return;
                }

                logger.info("Starting CGGMP DKG process for task: {}", taskId);

                logger.info("Waiting for network ready...");
                long waitNetStart = System.nanoTime();
                nodeService.waitForNetworkReady().join();
                logger.info("DKG waitForNetworkReady took {} ms", (System.nanoTime() - waitNetStart) / 1_000_000);

                int networkSize = nodeService.getNodes().size() + 1;
                if (networkSize < nodesCount) {
                    throw new RuntimeException("Not enough nodes in network. Expected: " + nodesCount + ", found: " + networkSize);
                }
                logger.info("Network ready with {} nodes", networkSize);

                try {
                    long sleepStart = System.nanoTime();
                    Thread.sleep(Constants.DKG_INIT_WAIT_MS);
                    logger.info("DKG init wait sleep {} ms", (System.nanoTime() - sleepStart) / 1_000_000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }

                Map<String, Object> initData = new HashMap<>();
                initData.put("taskId", taskId);
                initData.put("nodesCount", Constants.NODES_COUNT);
                initData.put("initiatorId", nodeId);
                initData.put("participants", new ArrayList<>(task.participants));

                boolean initBroadcastSuccess = false;
                for (int attempt = 1; attempt <= Constants.DKG_BROADCAST_RETRY_COUNT; attempt++) {
                    try {
                        long bcastStart = System.nanoTime();
                        nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_INIT, initData)).join();
                        logger.info("DKG broadcast CGGMP_DKG_INIT took {} ms (attempt {}/{})",
                                (System.nanoTime() - bcastStart) / 1_000_000, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                        logger.info("Broadcasted CGGMP_DKG_INIT for task: {} (attempt {}/{})", taskId, attempt, Constants.DKG_BROADCAST_RETRY_COUNT);
                        initBroadcastSuccess = true;
                        break;
                    } catch (Exception e) {
                        logger.warn("Failed to broadcast CGGMP_DKG_INIT (attempt {}/{}): {}", attempt, Constants.DKG_BROADCAST_RETRY_COUNT, e.getMessage());
                        if (attempt < Constants.DKG_BROADCAST_RETRY_COUNT) {
                            Thread.sleep(Constants.DKG_BROADCAST_RETRY_INTERVAL_MS);
                        }
                    }
                }

                if (!initBroadcastSuccess) {
                    throw new RuntimeException("Failed to broadcast CGGMP_DKG_INIT after 3 attempts");
                }

                long roundsStart = System.nanoTime();
                executeDkgRounds(task);
                logger.info("DKG executeDkgRounds took {} ms", (System.nanoTime() - roundsStart) / 1_000_000);

                long saveStart = System.nanoTime();
                task.complete();
                logger.info("CGGMP DKG process completed for task: {}", taskId);
                logger.info("=================== startDkgProcess END: taskId={} total {} ms ===================",
                        taskId, (System.nanoTime() - dkgStartNs) / 1_000_000);
            } catch (Exception e) {
                if (task != null) {
                    task.fail();
                    task.errorMessage = e.getMessage();
                }
                logger.error("Error in CGGMP DKG process", e);
                throw new RuntimeException(e);
            }
        }, dkgExecutorService);
    }

    private void executeDkgRounds(CggmpDkgTask task) throws Exception {
        final long roundsStart = System.nanoTime();
        logger.info("Node {} executing CGGMP DKG Round 1 (Figure 7)", nodeId);

        long initCggmpStart = System.nanoTime();
        task.cggmpInstance = createCachedDkgInstance();
        logger.info("DKG init CGGMP instance took {} ms", (System.nanoTime() - initCggmpStart) / 1_000_000);
        byte[] dkgContext = buildDkgContext(task.taskId, null, nodeId, "R1");
        long r1Start = System.nanoTime();
        CGGMP.DkgRound1Output round1Output = task.cggmpInstance.dkgRound1(dkgContext);
        logger.info("DKG Round1 local compute took {} ms", (System.nanoTime() - r1Start) / 1_000_000);
        task.round1Outputs.put(nodeId, round1Output);
        task.peerPaillierKeys.put(nodeId, round1Output.paillierKey);
        task.peerZkSetups.put(nodeId, round1Output.zkSetup);

        long pedStart = System.nanoTime();
        BigInteger[] ped = generateRefreshPedersen(round1Output.paillierKey.bitLength);
        logger.info("DKG generateRefreshPedersen took {} ms", (System.nanoTime() - pedStart) / 1_000_000);
        task.hatN.put(nodeId, ped[0]);
        task.sValues.put(nodeId, ped[1]);
        task.tValues.put(nodeId, ped[2]);
        task.pedersenLambda = ped[3];
        long prmStart = System.nanoTime();
        PiPrmProof prmProof = RefreshProofs.createPrmProof(
                ped[0], ped[1], ped[2], ped[3], buildDkgContext(task.taskId, null, nodeId, "PRM"));
        logger.info("DKG createPrmProof took {} ms", (System.nanoTime() - prmStart) / 1_000_000);
        task.prmProofs.put(nodeId, prmProof);

        Map<Integer, ECPoint> Xjk = new HashMap<>();
        Map<Integer, ECPoint> Ajk = new HashMap<>();
        ECPoint g = Secp256k1Curve.G();
        for (int k = 0; k < round1Output.coefficients.length; k++) {
            BigInteger coeff = round1Output.coefficients[k];
            ECPoint X = g.multiply(coeff).normalize();
            BigInteger alpha = new BigInteger(Secp256k1Curve.n().bitLength(), secureRandom).mod(Secp256k1Curve.n());
            ECPoint A = g.multiply(alpha).normalize();
            Xjk.put(k, X);
            Ajk.put(k, A);
            task.schAlphas.put(k, alpha);
        }
        task.Xjks.put(nodeId, new ConcurrentHashMap<>(Xjk));
        task.Ajks.put(nodeId, new ConcurrentHashMap<>(Ajk));

        byte[] ridPart = new byte[32];
        secureRandom.nextBytes(ridPart);
        task.ridParts.put(nodeId, ridPart);

        Map<String, Object> round1Payload = buildDkgRound1Payload(task, round1Output, Xjk, Ajk, prmProof, ridPart);
        task.round1PayloadHashes.put(nodeId, computePayloadHashHex(round1Payload));
        long r1BroadcastStart = System.nanoTime();
        nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND1, round1Payload))).join();
        logger.info("DKG Round1 broadcast took {} ms", (System.nanoTime() - r1BroadcastStart) / 1_000_000);

        task.startRound1Waiting();
        logger.info("Node {} waiting for DKG Round 1 messages...", nodeId);
        long r1WaitStart = System.nanoTime();
        if (!task.round1ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for DKG Round 1 messages");
        }
        logger.info("DKG Round1 wait took {} ms", (System.nanoTime() - r1WaitStart) / 1_000_000);

        task.rid = xorRidParts(task);
        long r1EchoBroadcastStart = System.nanoTime();
        broadcastDkgRound1Echo(task).join();
        logger.info("DKG Round1 echo broadcast took {} ms", (System.nanoTime() - r1EchoBroadcastStart) / 1_000_000);
        long r1EchoWaitStart = System.nanoTime();
        if (!task.round1EchoReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for DKG Round 1 echo messages");
        }
        logger.info("DKG Round1 echo wait took {} ms", (System.nanoTime() - r1EchoWaitStart) / 1_000_000);

        logger.info("Node {} executing DKG Round 2 (shares)", nodeId);
        BigInteger q = Secp256k1Curve.n();
        Map<Integer, PiSchProof> schProofs = new HashMap<>();
        for (int k = 0; k < round1Output.coefficients.length; k++) {
            BigInteger coeff = round1Output.coefficients[k];
            BigInteger alpha = task.schAlphas.get(k);
            PiSchProof sch = createSchProofWithAlpha(g, Xjk.get(k), coeff, alpha,
                    buildDkgContext(task.taskId, task.rid, nodeId, "SCH:" + k));
            schProofs.put(k, sch);
        }
        BigInteger[] coeffs = round1Output.coefficients;
        byte[] modCtx = buildDkgContext(task.taskId, task.rid, nodeId, "MOD");
        long proofStart = System.nanoTime();
        CompletableFuture<BiPrimeBlumProof> modFuture = CompletableFuture.supplyAsync(
                () -> new BiPrimeProofGenerator().createProof(task.cggmpInstance.getPaillier().getPrivateKeyInfo(), modCtx),
                dkgExecutorService);
        CompletableFuture<NoSmallFactorProof> facFuture = CompletableFuture.supplyAsync(
                () -> new NoSmallFactorProofGenerator(task.cggmpInstance.getZkSetup()).createProof(task.cggmpInstance.getPaillier().getPrivateKeyInfo(), modCtx),
                dkgExecutorService);
        BiPrimeBlumProof modProof = modFuture.join();
        NoSmallFactorProof facProof = facFuture.join();
        logger.info("DKG Round2 mod/fac proof generation took {} ms", (System.nanoTime() - proofStart) / 1_000_000);
        Map<String, Object> modMap = java.util.Collections.unmodifiableMap(CggmpDkgCodec.encodeBiPrimeProof(modProof));
        Map<String, Object> facMap = java.util.Collections.unmodifiableMap(CggmpDkgCodec.encodeNoSmallFactorProof(facProof));
        Map<String, Object> schEncoded = java.util.Collections.unmodifiableMap(encodeSchProofMap(schProofs));
        Map<String, Object> round2Broad = new HashMap<>();
        round2Broad.put("taskId", task.taskId);
        round2Broad.put("senderId", nodeId);
        round2Broad.put("schProofs", schEncoded);
        round2Broad.put("modProof", modMap);
        round2Broad.put("facProof", facMap);

        long r2BroadStart = System.nanoTime();
        broadcastDkgRound2Broad(round2Broad).join();
        logger.info("DKG Round2 broad broadcast took {} ms", (System.nanoTime() - r2BroadStart) / 1_000_000);

        List<CompletableFuture<Void>> shareFutures = new ArrayList<>();
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            BigInteger xji = evaluatePolynomial(coeffs, BigInteger.valueOf(peerId), q);
            ECPoint Yji = g.multiply(new BigInteger(q.bitLength(), secureRandom).mod(q)).normalize();
            BigInteger rho = deriveDkgMask(task.taskId, task.rid, nodeId, peerId, Yji);
            BigInteger Cji = xji.add(rho).mod(q);
            task.Cji.computeIfAbsent(nodeId, k -> new ConcurrentHashMap<>()).put(peerId, Cji);
            task.Yji.computeIfAbsent(nodeId, k -> new ConcurrentHashMap<>()).put(peerId, Yji);
            shareFutures.add(sendDkgRound2Share(task.taskId, peerId, Cji, Yji));
        }
        if (!shareFutures.isEmpty()) {
            CompletableFuture.allOf(shareFutures.toArray(new CompletableFuture[0])).join();
        }

        task.startRound2Waiting();
        logger.info("Node {} waiting for DKG Round 2 messages...", nodeId);
        long r2WaitStart = System.nanoTime();
        if (!task.round2ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for DKG Round 2 messages");
        }
        logger.info("DKG Round2 wait took {} ms", (System.nanoTime() - r2WaitStart) / 1_000_000);

        task.startValidating();
        BigInteger xStar = BigInteger.ZERO;
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                BigInteger selfShare = evaluatePolynomial(coeffs, BigInteger.valueOf(nodeId), q);
                xStar = xStar.add(selfShare).mod(q);
                continue;
            }
            BigInteger share = task.xji.getOrDefault(peerId, new ConcurrentHashMap<>()).get(nodeId);
            if (share == null) {
                throw new Exception("Missing x_{j,i} from peer " + peerId);
            }
            xStar = xStar.add(share).mod(q);
        }
        task.secretShare = xStar;

        Map<Integer, ECPoint> XkStar = new HashMap<>();
        for (int k = 0; k < threshold; k++) {
            ECPoint acc = g.getCurve().getInfinity();
            for (int peerId : task.participants) {
                Map<Integer, ECPoint> XjkPeer = task.Xjks.get(peerId);
                if (XjkPeer == null || XjkPeer.get(k) == null) {
                    throw new Exception("Missing X_{j,k} from peer " + peerId);
                }
                acc = acc.add(XjkPeer.get(k)).normalize();
            }
            XkStar.put(k, acc);
        }
        task.XkStar.putAll(XkStar);

        long r3BroadcastStart = System.nanoTime();
        broadcastDkgRound3(task, XkStar).join();
        logger.info("DKG Round3 broadcast took {} ms", (System.nanoTime() - r3BroadcastStart) / 1_000_000);
        long r3WaitStart = System.nanoTime();
        if (!task.round3ReceivedLatch.await(Constants.DKG_ROUND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            task.timeout();
            throw new Exception("Timeout waiting for DKG Round 3 messages");
        }
        logger.info("DKG Round3 wait took {} ms", (System.nanoTime() - r3WaitStart) / 1_000_000);

        task.groupPublicKey = XkStar.get(0);
        task.groupPublicKeyHex = bytesToHex(task.groupPublicKey.getEncoded(false));
        long saveStart = System.nanoTime();
        saveKeyShareToDatabase(task);
        logger.info("DKG saveKeyShareToDatabase took {} ms", (System.nanoTime() - saveStart) / 1_000_000);
        task.complete();
        logger.info("CGGMP DKG completed! Group public key: {}", task.groupPublicKeyHex);
        logger.info("DKG executeDkgRounds total took {} ms", (System.nanoTime() - roundsStart) / 1_000_000);
    }

    private Map<String, Object> buildDkgRound1Payload(CggmpDkgTask task,
                                                      CGGMP.DkgRound1Output round1Output,
                                                      Map<Integer, ECPoint> Xjk,
                                                      Map<Integer, ECPoint> Ajk,
                                                      PiPrmProof prmProof,
                                                      byte[] ridPart) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("nodeId", round1Output.nodeId);
        data.put("Xjk", encodePointMapCompressed(Xjk));
        data.put("Ajk", encodePointMapCompressed(Ajk));
        data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(round1Output.paillierKey));
        data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(round1Output.zkSetup));
        data.put("biPrimeProof", CggmpDkgCodec.encodeBiPrimeProof(round1Output.biPrimeProof));
        data.put("factorProof", CggmpDkgCodec.encodeNoSmallFactorProof(round1Output.factorProof));
        data.put("hatN", task.hatN.get(nodeId).toString(16));
        data.put("s", task.sValues.get(nodeId).toString(16));
        data.put("t", task.tValues.get(nodeId).toString(16));
        data.put("prmProof", CggmpDkgCodec.encodePiPrmProof(prmProof));
        data.put("ridPart", HexUtils.bytesToHex(ridPart));
        return data;
    }

    private CompletableFuture<Void> sendDkgRound2Share(String taskId,
                                                       int receiverId,
                                                       BigInteger Cji,
                                                       ECPoint Yji) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", taskId);
        data.put("senderId", nodeId);
        data.put("receiverId", receiverId);
        data.put("C", Cji.toString(16));
        data.put("Y", HexUtils.bytesToHex(Yji.normalize().getEncoded(true)));
        return nodeService.sendMessage(receiverId, new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2, data));
    }

    private CompletableFuture<Void> broadcastDkgRound2Broad(Map<String, Object> data) {
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BROAD, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND2_BROAD, data)));
    }

    private CompletableFuture<Void> broadcastDkgRound2Batch(Map<String, Object> baseData,
                                                            Map<String, Object> shares) {
        Map<String, Object> data = new HashMap<>(baseData);
        data.put("shares", shares);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND2_BATCH, data));
    }

    private CompletableFuture<Void> broadcastDkgRound1Echo(CggmpDkgTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("hash", task.round1PayloadHashes.get(nodeId));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND1_ECHO, data));
    }

    private CompletableFuture<Void> broadcastDkgRound3(CggmpDkgTask task, Map<Integer, ECPoint> XkStar) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("XkStar", encodePointMapCompressed(XkStar));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_ROUND3, maybeCompressDkgPayload(MessageType.CGGMP_DKG_ROUND3, data)));
    }

    public DkgTaskStatusResponse getTaskStatus(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        DkgTaskStatusResponse response = new DkgTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setStatus(task.status.get().name());
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setGroupPublicKey(task.groupPublicKeyHex);
        response.setErrorMessage(task.errorMessage);
        response.setReceivedRound1(task.round1Received.size());
        response.setReceivedRound2(task.round2Received.size());
        return response;
    }

    public String getGroupPublicKey(String taskId) {
        CggmpDkgTask task = getDkgTask(taskId);
        if (!task.isCompleted()) {
            return null;
        }
        return task.groupPublicKeyHex;
    }

    private void handleCggmpDkgInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            int nodesCount = (Integer) dataMap.get("nodesCount");
            Integer initiatorId = dataMap.get("initiatorId") instanceof Number n ? n.intValue() : senderId;
            Set<Integer> participants = null;
            if (dataMap.get("participants") instanceof java.util.Collection<?> coll) {
                java.util.LinkedHashSet<Integer> p = new java.util.LinkedHashSet<>();
                for (Object o : coll) {
                    if (o instanceof Number n) {
                        p.add(n.intValue());
                    }
                }
                if (!p.isEmpty()) {
                    participants = p;
                }
            }
            logger.info("Received CGGMP_DKG_INIT from node {} for task: {}, nodesCount: {}, initiatorId={}, participants={}",
                    senderId, taskId, nodesCount, initiatorId, participants == null ? "default" : participants.size());

            CggmpDkgTask task = createDkgTaskInternal(taskId, nodesCount, threshold, participants, initiatorId);
            CggmpDkgTask existingTask = dkgTasks.putIfAbsent(taskId, task);

            if (existingTask != null) {
                logger.info("DKG task {} already exists, skipping creation", taskId);
                return;
            }

            logger.info("Created DKG task {} on node {}", taskId, nodeId);

            startDkgProcess(taskId);
        }
    }

    private CggmpDkgTask createDkgTaskInternal(String taskId,
                                               int nodesCount,
                                               int threshold,
                                               Set<Integer> participants,
                                               int initiatorId) {
        CggmpDkgTask task = new CggmpDkgTask(taskId, nodesCount, threshold, participants, initiatorId);
        task.evalPowers = precomputeEvalPowers(nodeId, threshold);
        return task;
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound1(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND1 from node {} for task: {}", senderId, taskId);

            int senderNodeId = -1;
            CggmpDkgTask task = null;
            try {
                task = dkgTasks.get(taskId);
                if (task == null) {
                    logger.warn("Task {} not found in dkgTasks, ignoring Round1 from node {}", taskId, senderId);
                    return;
                }

                senderNodeId = (Integer) dataMap.get("nodeId");
                if (senderNodeId != senderId) {
                    logger.warn("Discarding CGGMP_DKG_ROUND1: senderId {} does not match payload nodeId {}", senderId, senderNodeId);
                    return;
                }

                if (senderNodeId == nodeId) {
                    logger.info("Received Round1 from self (node {}), this is our own message, skipping", senderNodeId);
                    return;
                }

                if (task.round1Received.containsKey(senderNodeId)) {
                    logger.info("Already received Round1 from node {}, skipping", senderNodeId);
                    return;
                }
                if (task.round1Processing.putIfAbsent(senderNodeId, Boolean.TRUE) != null) {
                    logger.info("Already processing Round1 from node {}, skipping", senderNodeId);
                    return;
                }

                Map<?, ?> xjkMap = (Map<?, ?>) dataMap.get("Xjk");
                Map<?, ?> ajkMap = (Map<?, ?>) dataMap.get("Ajk");
                Map<?, ?> paillierKeyMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
                Map<?, ?> zkSetupMap = (Map<?, ?>) dataMap.get("zkSetup");
                Map<?, ?> biPrimeMap = (Map<?, ?>) dataMap.get("biPrimeProof");
                Map<?, ?> factorMap = (Map<?, ?>) dataMap.get("factorProof");
                String hatNHex = (String) dataMap.get("hatN");
                String sHex = (String) dataMap.get("s");
                String tHex = (String) dataMap.get("t");
                Map<?, ?> prmMap = (Map<?, ?>) dataMap.get("prmProof");
                String ridPartHex = (String) dataMap.get("ridPart");

                if (xjkMap == null || ajkMap == null || xjkMap.size() != threshold || ajkMap.size() != threshold) {
                    logger.warn("Invalid Xjk/Ajk size from node {}: expected {}, got Xjk={}, Ajk={}", senderNodeId, threshold,
                            xjkMap == null ? "null" : xjkMap.size(), ajkMap == null ? "null" : ajkMap.size());
                    return;
                }

                if (paillierKeyMap == null || zkSetupMap == null || biPrimeMap == null || factorMap == null
                        || hatNHex == null || sHex == null || tHex == null || prmMap == null || ridPartHex == null) {
                    logger.warn("Missing Round1 data from node {} for task {}", senderNodeId, taskId);
                    return;
                }

                PaillierEncryption.PublicKey paillierKey = CggmpDkgCodec.decodePaillierPublicKey(paillierKeyMap);
                com.example.mpc.cggmp.zk.ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkSetupMap);
                com.example.mpc.cggmp.proof.BiPrimeBlumProof biPrimeProof = CggmpDkgCodec.decodeBiPrimeProof(biPrimeMap);
                com.example.mpc.cggmp.proof.NoSmallFactorProof factorProof = CggmpDkgCodec.decodeNoSmallFactorProof(factorMap);
                BigInteger hatN = new BigInteger(hatNHex, 16);
                BigInteger s = new BigInteger(sHex, 16);
                BigInteger t = new BigInteger(tHex, 16);
                PiPrmProof prmProof = CggmpDkgCodec.decodePiPrmProof(prmMap);
                if (hatN.compareTo(BigInteger.TWO) < 0 || s.compareTo(BigInteger.TWO) < 0 || t.compareTo(BigInteger.TWO) < 0) {
                    logger.warn("Invalid hatN/s/t from node {} for task {}", senderNodeId, taskId);
                    return;
                }

                final int senderNodeIdFinal = senderNodeId;
                final String taskIdFinal = taskId;
                final CggmpDkgTask taskFinal = task;
                final Map<?, ?> xjkMapFinal = xjkMap;
                final Map<?, ?> ajkMapFinal = ajkMap;
                final String ridPartHexFinal = ridPartHex;
                final PaillierEncryption.PublicKey paillierKeyFinal = paillierKey;
                final ZKSetup zkSetupFinal = zkSetup;
                final com.example.mpc.cggmp.proof.BiPrimeBlumProof biPrimeProofFinal = biPrimeProof;
                final com.example.mpc.cggmp.proof.NoSmallFactorProof factorProofFinal = factorProof;
                final PiPrmProof prmProofFinal = prmProof;
                final BigInteger hatNFinal = hatN;
                final BigInteger sFinal = s;
                final BigInteger tFinal = t;

                CompletableFuture.runAsync(() -> {
                    try {
                        byte[] round1Ctx = buildDkgContext(taskIdFinal, null, senderNodeIdFinal, "R1");
                        byte[] prmCtx = buildDkgContext(taskIdFinal, null, senderNodeIdFinal, "PRM");
                        com.example.mpc.cggmp.proof.BiPrimeProofValidator biPrimeValidator = new com.example.mpc.cggmp.proof.BiPrimeProofValidator();
                        com.example.mpc.cggmp.proof.NoSmallFactorProofValidator factorValidator = new com.example.mpc.cggmp.proof.NoSmallFactorProofValidator(zkSetupFinal);

                        CompletableFuture<Boolean> biPrimeFuture = CompletableFuture.supplyAsync(
                                () -> biPrimeValidator.verifyProof(biPrimeProofFinal, paillierKeyFinal, round1Ctx),
                                dkgExecutorService);
                        CompletableFuture<Boolean> factorFuture = CompletableFuture.supplyAsync(
                                () -> factorValidator.verifyProof(factorProofFinal, paillierKeyFinal, round1Ctx),
                                dkgExecutorService);
                        boolean biPrimeOk = biPrimeFuture.join();
                        boolean factorOk = factorFuture.join();
                        if (!biPrimeOk) {
                            logger.warn("Invalid Paillier bi-prime proof from node {} for task {}", senderNodeIdFinal, taskIdFinal);
                            return;
                        }
                        if (!factorOk) {
                            logger.warn("Invalid Paillier factor proof from node {} for task {}", senderNodeIdFinal, taskIdFinal);
                            return;
                        }
                        if (!RefreshProofs.verifyPrmProof(prmProofFinal, hatNFinal, sFinal, tFinal, prmCtx)) {
                            logger.warn("Invalid PiPrm proof from node {} for task {}", senderNodeIdFinal, taskIdFinal);
                            return;
                        }

                        taskFinal.peerPaillierKeys.put(senderNodeIdFinal, paillierKeyFinal);
                        taskFinal.peerZkSetups.put(senderNodeIdFinal, zkSetupFinal);
                        taskFinal.noSmallFactorValidators.put(senderNodeIdFinal, new NoSmallFactorProofValidator(zkSetupFinal));
                        taskFinal.hatN.put(senderNodeIdFinal, hatNFinal);
                        taskFinal.sValues.put(senderNodeIdFinal, sFinal);
                        taskFinal.tValues.put(senderNodeIdFinal, tFinal);
                        taskFinal.prmProofs.put(senderNodeIdFinal, prmProofFinal);
                        taskFinal.biPrimeProofs.put(senderNodeIdFinal, biPrimeProofFinal);
                        taskFinal.factorProofs.put(senderNodeIdFinal, factorProofFinal);
                        taskFinal.ridParts.put(senderNodeIdFinal, HexUtils.hexToBytes(ridPartHexFinal));
                        taskFinal.round1PayloadHashes.put(senderNodeIdFinal, computePayloadHashHex(dataMap));
                        String pendingEcho = taskFinal.pendingRound1Echo.remove(senderNodeIdFinal);
                        if (pendingEcho != null) {
                            String expected = taskFinal.round1PayloadHashes.get(senderNodeIdFinal);
                            if (expected != null && expected.equals(pendingEcho)) {
                                if (taskFinal.round1EchoReceived.putIfAbsent(senderNodeIdFinal, Boolean.TRUE) == null) {
                                    taskFinal.round1EchoReceivedLatch.countDown();
                                }
                            } else {
                                logger.warn("Round1 echo mismatch from node {} (task {})", senderNodeIdFinal, taskIdFinal);
                                broadcastDkgComplaint(taskFinal, senderNodeIdFinal, "Round1 echo mismatch",
                                        Map.of("senderId", senderNodeIdFinal, "expected", expected, "received", pendingEcho)).join();
                            }
                        }
                        if (taskFinal.rid == null && taskFinal.ridParts.size() == taskFinal.participants.size()) {
                            taskFinal.rid = xorRidParts(taskFinal);
                        }

                        Map<Integer, ECPoint> Xjk = decodePointMap(xjkMapFinal);
                        Map<Integer, ECPoint> Ajk = decodePointMap(ajkMapFinal);
                        for (int k = 0; k < threshold; k++) {
                            ECPoint X = Xjk.get(k);
                            ECPoint A = Ajk.get(k);
                            if (X == null || A == null || X.isInfinity() || A.isInfinity() || !X.isValid() || !A.isValid()) {
                                logger.warn("Invalid Xjk/Ajk point from node {} (k={})", senderNodeIdFinal, k);
                                return;
                            }
                        }
                        taskFinal.Xjks.put(senderNodeIdFinal, new ConcurrentHashMap<>(Xjk));
                        taskFinal.Ajks.put(senderNodeIdFinal, new ConcurrentHashMap<>(Ajk));

                        CGGMP.DkgRound1Output output = new CGGMP.DkgRound1Output(senderNodeIdFinal, null, java.util.Collections.emptyList(), paillierKeyFinal, zkSetupFinal, biPrimeProofFinal, factorProofFinal);
                        taskFinal.round1Outputs.putIfAbsent(senderNodeIdFinal, output);
                        taskFinal.round1Received.put(senderNodeIdFinal, Boolean.TRUE);
                        taskFinal.round1ReceivedLatch.countDown();
                        logger.info("Stored Round1 from node {} for task: {}", senderNodeIdFinal, taskIdFinal);
                    } catch (Exception e) {
                        logger.error("Error handling CGGMP_DKG_ROUND1 (async verify): {}", e.getMessage(), e);
                    } finally {
                        taskFinal.round1Processing.remove(senderNodeIdFinal);
                    }
                }, dkgExecutorService);
            } catch (Exception e) {
                if (task != null && senderNodeId >= 0) {
                    task.round1Processing.remove(senderNodeId);
                }
                logger.error("Error handling CGGMP_DKG_ROUND1: {}", e.getMessage(), e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound2(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String taskId = (String) dataMap.get("taskId");
            logger.info("Received CGGMP_DKG_ROUND2 from node {} for task: {}", senderId, taskId);

            int senderNodeId = -1;
            CggmpDkgTask task = null;
            try {
                task = dkgTasks.get(taskId);
                if (task == null) {
                    return;
                }
                Object senderValue = dataMap.get("senderId");
                if (!(senderValue instanceof Number)) {
                    return;
                }
                senderNodeId = ((Number) senderValue).intValue();
                if (senderNodeId != senderId) {
                    logger.warn("Discarding CGGMP_DKG_ROUND2: senderId {} does not match payload senderId {}", senderId, senderNodeId);
                    return;
                }
                if (senderNodeId == nodeId) {
                    logger.info("Received Round2 from self (node {}), skipping", senderNodeId);
                    return;
                }
                if (task.round2Received.containsKey(senderNodeId)) {
                    logger.info("Already received Round2 from node {}, skipping", senderNodeId);
                    return;
                }
                Object receiverValue = dataMap.get("receiverId");
                if (!(receiverValue instanceof Number)) {
                    return;
                }
                int receiverId = ((Number) receiverValue).intValue();
                if (receiverId != nodeId) {
                    logger.info("Round2 not intended for this node (receiverId={}, nodeId={}), ignoring", receiverId, nodeId);
                    return;
                }

                String cHex = (String) dataMap.get("C");
                String yHex = (String) dataMap.get("Y");
                if (cHex == null || yHex == null) {
                    logger.warn("Invalid DKG Round2 payload from node {} for task {}", senderNodeId, taskId);
                    return;
                }

                Map<?, ?> schMap = (Map<?, ?>) dataMap.get("schProofs");
                Map<?, ?> modMap = (Map<?, ?>) dataMap.get("modProof");
                Map<?, ?> facMap = (Map<?, ?>) dataMap.get("facProof");
                if (schMap == null || modMap == null || facMap == null) {
                    Map<String, Object> cached = task.round2ProofMaps.get(senderNodeId);
                    if (cached == null) {
                        task.pendingRound2Shares.put(senderNodeId, Map.of("C", cHex, "Y", yHex));
                        return;
                    }
                    schMap = (Map<?, ?>) cached.get("schProofs");
                    modMap = (Map<?, ?>) cached.get("modProof");
                    facMap = (Map<?, ?>) cached.get("facProof");
                }
                processRound2WithProofs(task, senderNodeId, receiverId, cHex, yHex, schMap, modMap, facMap);
            } catch (Exception e) {
                logger.error("Error handling CGGMP_DKG_ROUND2: {}", e.getMessage(), e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound2Broad(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Map<?, ?> schMap = (Map<?, ?>) dataMap.get("schProofs");
        Map<?, ?> modMap = (Map<?, ?>) dataMap.get("modProof");
        Map<?, ?> facMap = (Map<?, ?>) dataMap.get("facProof");
        if (schMap == null || modMap == null || facMap == null) {
            logger.warn("Invalid DKG Round2 broad payload from node {} for task {}", senderNodeId, taskId);
            return;
        }
        task.round2ProofMaps.putIfAbsent(senderNodeId, Map.of(
                "schProofs", schMap,
                "modProof", modMap,
                "facProof", facMap
        ));
        task.round2SchProofs.putIfAbsent(senderNodeId, decodeSchProofMap(schMap));
        task.round2ModProofs.putIfAbsent(senderNodeId, CggmpDkgCodec.decodeBiPrimeProof(modMap));
        task.round2FacProofs.putIfAbsent(senderNodeId, CggmpDkgCodec.decodeNoSmallFactorProof(facMap));

        if (task.rid != null) {
            task.round2ModFacVerifyFutures.computeIfAbsent(senderNodeId, id ->
                    CompletableFuture.supplyAsync(() -> {
                        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderNodeId);
                        ZKSetup zk = task.peerZkSetups.get(senderNodeId);
                        if (pk == null || zk == null) {
                            return false;
                        }
                        BiPrimeBlumProof modProof = task.round2ModProofs.get(senderNodeId);
                        NoSmallFactorProof facProof = task.round2FacProofs.get(senderNodeId);
                        if (modProof == null || facProof == null) {
                            return false;
                        }
                        byte[] modCtx = buildDkgContext(taskId, task.rid, senderNodeId, "MOD");
                        NoSmallFactorProofValidator facValidator = task.noSmallFactorValidators.computeIfAbsent(senderNodeId, k -> new NoSmallFactorProofValidator(zk));
                        boolean modOk = BI_PRIME_VALIDATOR.verifyProof(modProof, pk, modCtx);
                        boolean facOk = facValidator.verifyProof(facProof, pk, modCtx);
                        boolean ok = modOk && facOk;
                        task.modFacVerified.put(senderNodeId, ok);
                        return ok;
                    }, dkgExecutorService)
            );
        }

        Map<String, String> pending = task.pendingRound2Shares.remove(senderNodeId);
        if (pending != null) {
            String cHex = pending.get("C");
            String yHex = pending.get("Y");
            if (cHex != null && yHex != null) {
                processRound2WithProofs(task, senderNodeId, nodeId, cHex, yHex, schMap, modMap, facMap);
            }
        }
    }

    private void processRound2WithProofs(CggmpDkgTask task,
                                         int senderNodeId,
                                         int receiverId,
                                         String cHex,
                                         String yHex,
                                         Map<?, ?> schMap,
                                         Map<?, ?> modMap,
                                         Map<?, ?> facMap) {
        if (receiverId != nodeId) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            return;
        }
        if (task.round2Processing.putIfAbsent(senderNodeId, Boolean.TRUE) != null) {
            return;
        }

        Map<Integer, PiSchProof> schProofs = task.round2SchProofs.get(senderNodeId);
        if (schProofs == null) {
            schProofs = decodeSchProofMap(schMap);
            task.round2SchProofs.putIfAbsent(senderNodeId, schProofs);
        }
        if (schProofs.size() != threshold) {
            logger.warn("Invalid schProofs size from node {}: expected {}, got {}", senderNodeId, threshold, schProofs.size());
            task.round2Processing.remove(senderNodeId);
            return;
        }

        BiPrimeBlumProof modProof = task.round2ModProofs.get(senderNodeId);
        if (modProof == null) {
            modProof = CggmpDkgCodec.decodeBiPrimeProof(modMap);
            task.round2ModProofs.putIfAbsent(senderNodeId, modProof);
        }
        NoSmallFactorProof facProof = task.round2FacProofs.get(senderNodeId);
        if (facProof == null) {
            facProof = CggmpDkgCodec.decodeNoSmallFactorProof(facMap);
            task.round2FacProofs.putIfAbsent(senderNodeId, facProof);
        }

        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderNodeId);
        ZKSetup zk = task.peerZkSetups.get(senderNodeId);
        if (pk == null || zk == null) {
            logger.warn("Missing Paillier/ZK setup for node {}", senderNodeId);
            task.round2Processing.remove(senderNodeId);
            return;
        }
        Map<Integer, ECPoint> Xjk = task.Xjks.get(senderNodeId);
        Map<Integer, ECPoint> Ajk = task.Ajks.get(senderNodeId);
        if (Xjk == null || Ajk == null) {
            logger.warn("Missing Xjk/Ajk from node {} for task {}", senderNodeId, task.taskId);
            task.round2Processing.remove(senderNodeId);
            return;
        }

        final int senderNodeIdFinal = senderNodeId;
        final CggmpDkgTask taskFinal = task;
        final String cHexFinal = cHex;
        final String yHexFinal = yHex;
        final Map<Integer, PiSchProof> schProofsFinal = schProofs;
        final BiPrimeBlumProof modProofFinal = modProof;
        final NoSmallFactorProof facProofFinal = facProof;
        final PaillierEncryption.PublicKey pkFinal = pk;
        final ZKSetup zkFinal = zk;
        final Map<Integer, ECPoint> XjkFinal = Xjk;
        final Map<Integer, ECPoint> AjkFinal = Ajk;

        CompletableFuture.runAsync(() -> {
            try {
                byte[] modCtx = buildDkgContext(taskFinal.taskId, taskFinal.rid, senderNodeIdFinal, "MOD");
                NoSmallFactorProofValidator facValidator = taskFinal.noSmallFactorValidators.computeIfAbsent(senderNodeIdFinal, k -> new NoSmallFactorProofValidator(zkFinal));
                Boolean cached = taskFinal.modFacVerified.get(senderNodeIdFinal);
                boolean modFacOk;
                if (cached != null) {
                    modFacOk = cached;
                } else if (taskFinal.round2ModFacVerifyFutures.containsKey(senderNodeIdFinal)) {
                    modFacOk = taskFinal.round2ModFacVerifyFutures.get(senderNodeIdFinal).join();
                } else {
                    long verifyStart = System.nanoTime();
                    CompletableFuture<Boolean> modFuture = CompletableFuture.supplyAsync(
                            () -> BI_PRIME_VALIDATOR.verifyProof(modProofFinal, pkFinal, modCtx), dkgExecutorService);
                    CompletableFuture<Boolean> facFuture = CompletableFuture.supplyAsync(
                            () -> facValidator.verifyProof(facProofFinal, pkFinal, modCtx), dkgExecutorService);
                    boolean modOk = modFuture.join();
                    boolean facOk = facFuture.join();
                    modFacOk = modOk && facOk;
                    taskFinal.modFacVerified.put(senderNodeIdFinal, modFacOk);
                    logger.info("DKG Round2 mod/fac proof verify took {} ms", (System.nanoTime() - verifyStart) / 1_000_000);
                }
                if (!modFacOk) {
                    logger.warn("Invalid PiMod/Blum or PiFac/NoSmallFactor proof from node {}", senderNodeIdFinal);
                    return;
                }

                long schVerifyStart = System.nanoTime();
                boolean schOk;
                if (taskFinal.round2SchVerifyFutures.containsKey(senderNodeIdFinal)) {
                    schOk = taskFinal.round2SchVerifyFutures.get(senderNodeIdFinal).join();
                } else {
                    schOk = verifySchProofsParallel(taskFinal, senderNodeIdFinal, schProofsFinal, XjkFinal, AjkFinal);
                }
                if (!schOk) {
                    logger.warn("Invalid PiSch proof(s) from node {}", senderNodeIdFinal);
                    return;
                }
                logger.info("DKG Round2 Sch proof verify took {} ms", (System.nanoTime() - schVerifyStart) / 1_000_000);

                ECPoint Yji = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(yHexFinal));
                BigInteger Cji = new BigInteger(cHexFinal, 16);
                BigInteger rho = deriveDkgMask(taskFinal.taskId, taskFinal.rid, senderNodeIdFinal, nodeId, Yji);
                BigInteger xji = Cji.subtract(rho).mod(Secp256k1Curve.n());
                ECPoint expected = computeExpectedShareFromXjk(XjkFinal, taskFinal.evalPowers);
                ECPoint actual = Secp256k1Curve.G().multiply(xji).normalize();
                if (!actual.equals(expected)) {
                    logger.warn("Invalid share from node {} for receiver {}", senderNodeIdFinal, nodeId);
                    broadcastDkgComplaint(taskFinal, senderNodeIdFinal, "Invalid share in DKG Round2", Map.of("senderId", senderNodeIdFinal)).join();
                    taskFinal.fail();
                    taskFinal.errorMessage = "Invalid share from node " + senderNodeIdFinal;
                    return;
                }

                taskFinal.xji.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, xji);
                taskFinal.Yji.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, Yji);
                taskFinal.Cji.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, Cji);
                taskFinal.modProofs.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, modProofFinal);
                taskFinal.facProofs.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(nodeId, facProofFinal);
                taskFinal.round2Evidence.computeIfAbsent(senderNodeIdFinal, k -> new ConcurrentHashMap<>()).put(String.valueOf(nodeId), Map.of(
                        "C", cHexFinal,
                        "Y", yHexFinal,
                        "schProofs", schMap,
                        "modProof", modMap,
                        "facProof", facMap
                ));
                taskFinal.round2Received.put(senderNodeIdFinal, Boolean.TRUE);
                taskFinal.round2ReceivedLatch.countDown();
            } catch (Exception e) {
                logger.error("Error handling CGGMP_DKG_ROUND2 (async verify): {}", e.getMessage(), e);
            } finally {
                taskFinal.round2Processing.remove(senderNodeIdFinal);
            }
        }, dkgExecutorService);
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpDkgRound2Batch(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        logger.info("Received CGGMP_DKG_ROUND2_BATCH from node {} for task: {}", senderId, taskId);
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId || senderNodeId == nodeId) {
            return;
        }
        if (task.round2Received.containsKey(senderNodeId)) {
            logger.info("Already received Round2 from node {}, skipping", senderNodeId);
            return;
        }
        if (task.rid == null && task.ridParts.size() == task.participants.size()) {
            task.rid = xorRidParts(task);
        }
        if (task.rid == null) {
            logger.warn("Missing rid for DKG Round2 batch verification (task {})", taskId);
            return;
        }

        Map<?, ?> shares = (Map<?, ?>) dataMap.get("shares");
        if (shares == null || !shares.containsKey(String.valueOf(nodeId))) {
            return;
        }
        Map<?, ?> share = (Map<?, ?>) shares.get(String.valueOf(nodeId));
        if (share == null) {
            return;
        }
        Map<String, Object> flat = new HashMap<>();
        flat.put("taskId", taskId);
        flat.put("senderId", senderNodeId);
        flat.put("receiverId", nodeId);
        flat.put("C", share.get("C"));
        flat.put("Y", share.get("Y"));
        flat.put("schProofs", dataMap.get("schProofs"));
        flat.put("modProof", dataMap.get("modProof"));
        flat.put("facProof", dataMap.get("facProof"));
        handleCggmpDkgRound2(senderId, flat);
    }

    private void handleCggmpDkgRound1Echo(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object senderValue = dataMap.get("senderId");
        String hash = (String) dataMap.get("hash");
        if (taskId == null || senderValue == null || hash == null) {
            return;
        }
        int senderNodeId = senderValue instanceof Number n ? n.intValue() : senderId;
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null || senderNodeId == nodeId) {
            return;
        }
        String expected = task.round1PayloadHashes.get(senderNodeId);
        if (expected == null) {
            task.pendingRound1Echo.put(senderNodeId, hash);
            logger.warn("Missing local Round1 hash for node {} (task {}), queued echo", senderNodeId, taskId);
            return;
        }
        if (!expected.equals(hash)) {
            logger.warn("Round1 echo mismatch from node {} (task {})", senderNodeId, taskId);
            broadcastDkgComplaint(task, senderNodeId, "Round1 echo mismatch",
                    Map.of("senderId", senderNodeId, "expected", expected, "received", hash)).join();
            return;
        }
        if (task.round1EchoReceived.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round1EchoReceivedLatch.countDown();
        }
    }

    private void handleCggmpDkgRound3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        if (taskId == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Object senderValue = dataMap.get("senderId");
        if (!(senderValue instanceof Number)) {
            return;
        }
        int senderNodeId = ((Number) senderValue).intValue();
        if (senderNodeId != senderId) {
            return;
        }
        if (senderNodeId == nodeId) {
            return;
        }
        if (task.round3Received.putIfAbsent(senderNodeId, Boolean.TRUE) == null) {
            task.round3ReceivedLatch.countDown();
        }
        Map<?, ?> xkStarMap = (Map<?, ?>) dataMap.get("XkStar");
        if (xkStarMap == null) {
            return;
        }
        Map<Integer, ECPoint> peerXkStar = decodePointMap(xkStarMap);
        if (task.XkStar.isEmpty()) {
            task.XkStar.putAll(peerXkStar);
            return;
        }
                if (peerXkStar.size() != task.XkStar.size()) {
            broadcastDkgComplaint(task, senderNodeId, "DKG Round3 XkStar size mismatch", buildDkgRound3Evidence(task, senderNodeId)).join();
            return;
        }
        for (Map.Entry<Integer, ECPoint> e : peerXkStar.entrySet()) {
            ECPoint local = task.XkStar.get(e.getKey());
            if (local == null || !local.equals(e.getValue())) {
                broadcastDkgComplaint(task, senderNodeId, "DKG Round3 XkStar mismatch", buildDkgRound3Evidence(task, senderNodeId)).join();
                return;
            }
        }
    }

    private Map<String, Object> buildDkgRound3Evidence(CggmpDkgTask task, int offenderId) {
        Map<String, Object> ev = new HashMap<>();
        Map<String, String> xkStar = encodePointMap(task.XkStar);
        ev.put("XkStar", xkStar);
        Map<String, Object> r2 = task.round2Evidence.getOrDefault(offenderId, new ConcurrentHashMap<>());
        if (!r2.isEmpty()) {
            ev.put("round2Evidence", r2);
        }
        ev.put("rid", HexUtils.bytesToHex(task.rid == null ? new byte[0] : task.rid));
        return ev;
    }

    private void handleCggmpDkgComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        Object evidence = dataMap.get("evidence");
        if (taskId == null || reason == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received DKG complaint for task {} from node {} against {}: {}", taskId, senderId, offenderId, reason);
        if (evidence instanceof Map<?, ?> ev) {
            if (!validateDkgComplaintEvidence(task, reason, ev)) {
                logger.warn("Invalid DKG complaint evidence from node {}", senderId);
                if (nodeId == task.initiatorId) {
                    attemptExcludeAndRestartDkg(task, senderId, "Invalid complaint evidence");
                } else {
                    task.fail();
                    task.errorMessage = "DKG complaint invalid evidence from " + senderId;
                }
                return;
            }
        }
        if (nodeId == task.initiatorId && offenderId != null) {
            attemptExcludeAndRestartDkg(task, offenderId, reason);
        } else {
            task.fail();
            task.errorMessage = "DKG complaint: " + reason;
        }
    }

    private boolean validateDkgComplaintEvidence(CggmpDkgTask task, String reason, Map<?, ?> evidence) {
        try {
            if (evidence.get("XkStar") instanceof Map<?, ?> xkStarMap) {
                Map<Integer, ECPoint> claimed = decodePointMap(xkStarMap);
                if (!task.XkStar.isEmpty() && claimed.size() == task.XkStar.size()) {
                    for (Map.Entry<Integer, ECPoint> e : claimed.entrySet()) {
                        ECPoint local = task.XkStar.get(e.getKey());
                        if (local != null && !local.equals(e.getValue())) {
                            return true;
                        }
                    }
                }
            }
            if (evidence.get("round2Evidence") instanceof Map<?, ?> r2Ev) {
                for (Map.Entry<?, ?> entry : r2Ev.entrySet()) {
                    String receiverKey = String.valueOf(entry.getKey());
                    int receiverId = Integer.parseInt(receiverKey);
                    if (!(entry.getValue() instanceof Map<?, ?> ev)) {
                        continue;
                    }
                    String cHex = (String) ev.get("C");
                    String yHex = (String) ev.get("Y");
                    Map<?, ?> schMap = (Map<?, ?>) ev.get("schProofs");
                    Map<?, ?> modMap = (Map<?, ?>) ev.get("modProof");
                    Map<?, ?> facMap = (Map<?, ?>) ev.get("facProof");
                    if (cHex == null || yHex == null || schMap == null || modMap == null || facMap == null) {
                        return false;
                    }
                    ECPoint Yji = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(yHex));
                    BigInteger Cji = new BigInteger(cHex, 16);
                    Map<Integer, PiSchProof> schProofs = decodeSchProofMap(schMap);
                    if (schProofs.size() != threshold) {
                        return false;
                    }
                    PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(receiverId);
                    ZKSetup zk = task.peerZkSetups.get(receiverId);
                    if (pk == null || zk == null) {
                        return false;
                    }
                    BiPrimeBlumProof modProof = CggmpDkgCodec.decodeBiPrimeProof(modMap);
                    NoSmallFactorProof facProof = CggmpDkgCodec.decodeNoSmallFactorProof(facMap);
                    byte[] modCtx = buildDkgContext(task.taskId, task.rid, receiverId, "MOD");
                    NoSmallFactorProofValidator facValidator = task.noSmallFactorValidators.computeIfAbsent(receiverId, k -> new NoSmallFactorProofValidator(zk));
                    CompletableFuture<Boolean> modFuture = CompletableFuture.supplyAsync(
                            () -> BI_PRIME_VALIDATOR.verifyProof(modProof, pk, modCtx), dkgExecutorService);
                    CompletableFuture<Boolean> facFuture = CompletableFuture.supplyAsync(
                            () -> facValidator.verifyProof(facProof, pk, modCtx), dkgExecutorService);
                    if (!modFuture.join()) {
                        return false;
                    }
                    if (!facFuture.join()) {
                        return false;
                    }
                    Map<Integer, ECPoint> Xjk = task.Xjks.get(receiverId);
                    Map<Integer, ECPoint> Ajk = task.Ajks.get(receiverId);
                    if (Xjk == null || Ajk == null) {
                        return false;
                    }
                    if (!verifySchProofsParallel(task, receiverId, schProofs, Xjk, Ajk)) {
                        return false;
                    }
                    BigInteger rho = deriveDkgMask(task.taskId, task.rid, receiverId, nodeId, Yji);
                    BigInteger xji = Cji.subtract(rho).mod(Secp256k1Curve.n());
                    ECPoint expected = computeExpectedShareFromXjk(Xjk, task.evalPowers);
                    ECPoint actual = Secp256k1Curve.G().multiply(xji).normalize();
                    if (!actual.equals(expected)) {
                        return true;
                    }
                }
            }
            if (reason != null && reason.startsWith("Invalid share")) {
                return true;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void handleCggmpDkgExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Object offenderValue = dataMap.get("offenderId");
        String reason = (String) dataMap.get("reason");
        if (taskId == null || offenderValue == null) {
            return;
        }
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            return;
        }
        int offenderId = offenderValue instanceof Number n ? n.intValue() : -1;
        task.fail();
        task.errorMessage = "DKG excluded offender " + offenderId + ": " + (reason == null ? "" : reason);
        if (nodeId != task.initiatorId && dataMap.get("newTaskId") instanceof String newTaskId
                && dataMap.get("participants") instanceof java.util.Collection<?> coll) {
            java.util.LinkedHashSet<Integer> participants = new java.util.LinkedHashSet<>();
            for (Object o : coll) {
                if (o instanceof Number n) {
                    participants.add(n.intValue());
                }
            }
            if (!participants.isEmpty()) {
                CggmpDkgTask newTask = createDkgTaskInternal(newTaskId, task.nodesCount, task.threshold, participants, senderId);
                dkgTasks.putIfAbsent(newTaskId, newTask);
                startDkgProcess(newTaskId);
            }
        }
    }

    private CompletableFuture<Void> broadcastDkgComplaint(CggmpDkgTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_COMPLAINT, data));
    }

    private CompletableFuture<Void> broadcastDkgExclude(CggmpDkgTask task,
                                                       int offenderId,
                                                       String reason,
                                                       String newTaskId,
                                                       Set<Integer> newParticipants) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        data.put("newTaskId", newTaskId);
        data.put("participants", new ArrayList<>(newParticipants));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_DKG_EXCLUDE, data));
    }

    private void attemptExcludeAndRestartDkg(CggmpDkgTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            task.fail();
            task.errorMessage = "DKG complaint (offender not participant): " + reason;
            return;
        }
        Set<Integer> newParticipants = new java.util.LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.isEmpty()) {
            task.fail();
            task.errorMessage = "DKG exclusion leaves no participants";
            return;
        }
        String newTaskId = UUID.randomUUID().toString();
        CggmpDkgTask newTask = createDkgTaskInternal(newTaskId, task.nodesCount, task.threshold, newParticipants, task.initiatorId);
        dkgTasks.putIfAbsent(newTaskId, newTask);
        logger.warn("DKG exclusion: offender {} removed, restarting DKG task {}", offenderId, newTaskId);
        broadcastDkgExclude(task, offenderId, reason, newTaskId, newParticipants).join();
        startDkgProcess(newTaskId);
        task.fail();
        task.errorMessage = "DKG restart after excluding offender " + offenderId;
    }

    // Legacy MtA-based DKG handlers removed in CGGMP21 DKG.

    private CggmpDkgTask getDkgTask(String taskId) {
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("CGGMP DKG task not found: " + taskId);
        }
        return task;
    }

    private List<String> encodeCommitments(List<ECPoint> commitments) {
        List<String> result = new ArrayList<>();
        for (ECPoint point : commitments) {
            result.add(bytesToHex(point.getEncoded(false)));
        }
        return result;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] buildMtaContext(String taskId, int senderId, int receiverId) {
        String ctx = taskId + ":" + senderId + ":" + receiverId;
        return ctx.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private void saveKeyShareToDatabase(CggmpDkgTask task) {
        try {
            String shareHex = task.secretShare.toString(16);
            KeyShare keyShare = new KeyShare(nodeId, shareHex, task.groupPublicKeyHex, task.taskId);
            keyShareDao.save(keyShare);
            logger.info("Saved CGGMP key share to database for task: {}", task.taskId);
        } catch (Exception e) {
            logger.error("Failed to save CGGMP key share to database", e);
        }
    }

    public String createSignatureTaskWithGroupKey(String groupPublicKey, String message) {
        String fixedGroupPublicKey = null;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        String taskId = UUID.randomUUID().toString();
        Gg20SignatureTask task = new Gg20SignatureTask(taskId, message, fixedGroupPublicKey, nodesCount, threshold, nodeId);
        signatureTasks.put(taskId, task);
        return taskId;
    }

    public String createSignatureTaskWithIdAndGroupKey(String signatureTaskId, String groupPublicKey, String message, int initiatorId, Set<Integer> participants) {
        String fixedGroupPublicKey = null;
        try {
            fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, java.nio.charset.StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            fixedGroupPublicKey = groupPublicKey;
        }
        fixedGroupPublicKey = fixedGroupPublicKey.replace(' ', '+');
        Gg20SignatureTask task = new Gg20SignatureTask(signatureTaskId, message, fixedGroupPublicKey, nodesCount, threshold, initiatorId, participants);
        signatureTasks.put(signatureTaskId, task);
        return signatureTaskId;
    }

    public CompletableFuture<Void> startSignatureTask(String taskId) {
        return startSignatureTaskInternal(taskId, true);
    }

    private CompletableFuture<Void> startSignatureTaskInternal(String taskId, boolean broadcastInit) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task not found: " + taskId));
        }

        if (task.isInProgress() || task.isCompleted()) {
            return CompletableFuture.failedFuture(new RuntimeException("Signature task is already in progress or completed"));
        }

        if (!task.participants.contains(nodeId)) {
            logger.info("Node {} not selected for signature task {}, participants={}, skipping", nodeId, taskId, task.participants);
            return CompletableFuture.completedFuture(null);
        }

        if (!task.start()) {
            return CompletableFuture.failedFuture(new RuntimeException("Failed to start signature task"));
        }

        return CompletableFuture.runAsync(() -> {
            try {
                initSignatureContext(task);
                if (broadcastInit) {
                    broadcastOfflineInit(task).join();
                }
                runOfflinePhase(task).join();
                if (broadcastInit) {
                    if (!task.offlineReadyLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for offline ready");
                    }
                    broadcastOnlineInit(task).join();
                }
                runOnlinePhase(task).join();
            } catch (Exception e) {
                logger.error("Error in CGGMP signature process: {}", e.getMessage());
                task.fail(e.getMessage());
                signatureInProgress.set(false);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
    }

    public SignatureTaskStatusResponse getSignatureTaskStatus(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        SignatureTaskStatusResponse response = new SignatureTaskStatusResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setInProgress(task.isInProgress());
        response.setCompleted(task.isCompleted());
        response.setStatus(task.status.get().name());
        response.setMessage(task.message);
        response.setErrorMessage(task.errorMessage);
        response.setParticipants(new ArrayList<>(task.participants));
        response.setReceivedGammaCommitments(task.participants.size() - 1 - (int) task.gammaCommitLatch.getCount());
        response.setReceivedMtaResponses(task.participants.size() - 1 - (int) task.stResponseLatch.getCount());
        response.setReceivedOffline(0);
        response.setReceivedPartialS(0);
        return response;
    }

    public SignatureResultResponse getSignatureResult(String taskId) {
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Signature task not found: " + taskId);
        }

        if (!task.isCompleted()) {
            throw new RuntimeException("Signature task not completed yet: " + taskId);
        }

        SignatureResultResponse response = new SignatureResultResponse();
        response.setTaskId(task.taskId);
        response.setGroupPublicKey(task.groupPublicKey);
        response.setSignature(task.signature);
        response.setVerified(task.verified);
        response.setMessage(task.message);
        return response;
    }

    private byte[] hashMessage(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private void initSignatureContext(Gg20SignatureTask task) {
        if (task.messageHash == null) {
            task.messageHash = hashMessage(task.message);
        }
        if (task.groupPublicKeyPoint == null) {
            task.groupPublicKeyPoint = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(task.groupPublicKey));
        }
    }

    private CompletableFuture<Void> runOfflinePhase(Gg20SignatureTask task) {
        return CompletableFuture.runAsync(() -> {
            try {
                BigInteger curveOrder = Secp256k1Curve.n();
                initSignaturePaillier(task);

                task.k_i = randomNonZero(curveOrder);
                BigInteger gamma_i = randomNonZero(curveOrder);
                task.presignGamma.put(nodeId, Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i));

                BigInteger y_i = randomNonZero(curveOrder);
                BigInteger a_i = randomNonZero(curveOrder);
                BigInteger b_i = randomNonZero(curveOrder);
                ECPoint Y_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), y_i);
                ECPoint A1 = Secp256k1Curve.multiply(Secp256k1Curve.G(), a_i);
                ECPoint A2 = Y_i.multiply(a_i).add(Secp256k1Curve.multiply(Secp256k1Curve.G(), task.k_i)).normalize();
                ECPoint B1 = Secp256k1Curve.multiply(Secp256k1Curve.G(), b_i);
                ECPoint B2 = Y_i.multiply(b_i).add(Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i)).normalize();
                task.presignYScalar = y_i;
                task.presignAScalar = a_i;
                task.presignBScalar = b_i;
                task.presignY.put(nodeId, Y_i);
                task.presignA1.put(nodeId, A1);
                task.presignA2.put(nodeId, A2);
                task.presignB1.put(nodeId, B1);
                task.presignB2.put(nodeId, B2);

                PaillierEncryption.Encryption encK = task.paillier.encryptWithRandomness(task.k_i);
                PaillierEncryption.Encryption encG = task.paillier.encryptWithRandomness(gamma_i);
                BigInteger K = encK.c;
                BigInteger G = encG.c;
                task.presignK.put(nodeId, K);
                task.presignG.put(nodeId, G);

                byte[] ctxR1K = buildPresignContext(task.taskId, nodeId, "R1K");
                PiEncElgProof encElgK = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1Curve.G(),
                        A1,
                        Y_i,
                        A2,
                        task.k_i,
                        encK.r,
                        a_i,
                        y_i,
                        proofEpsBits,
                        ctxR1K
                );
                PresignProofs.EncElgVerifyResult localEncElgK = PresignProofs.verifyEncElgProofDetailed(
                        encElgK, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1Curve.G(), A1, Y_i, A2, K, proofEpsBits, ctxR1K);
                if (!localEncElgK.ok()) {
                    logger.warn("Local PiEncElg proof (K) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgK.eq1(), localEncElgK.eq2(), localEncElgK.eq3(), localEncElgK.eq4(), localEncElgK.z1InRange());
                } else {
                    PiEncElgProof encElgKDecoded = CggmpDkgCodec.decodePiEncElgProof(CggmpDkgCodec.encodePiEncElgProof(encElgK));
                    PresignProofs.EncElgVerifyResult localEncElgKDecoded = PresignProofs.verifyEncElgProofDetailed(
                            encElgKDecoded, task.paillier.getPublicKeyInfo(), task.zkSetup,
                            Secp256k1Curve.G(), A1, Y_i, A2, K, proofEpsBits, ctxR1K);
                    if (!localEncElgKDecoded.ok()) {
                        logger.warn("Local PiEncElg proof (K) failed after codec roundtrip, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                                task.taskId, localEncElgKDecoded.eq1(), localEncElgKDecoded.eq2(), localEncElgKDecoded.eq3(),
                                localEncElgKDecoded.eq4(), localEncElgKDecoded.z1InRange());
                    }
                }
                byte[] ctxR1G = buildPresignContext(task.taskId, nodeId, "R1G");
                PiEncElgProof encElgG = PresignProofs.createEncElgProof(
                        task.paillier.getPublicKeyInfo(),
                        task.zkSetup,
                        Secp256k1Curve.G(),
                        B1,
                        Y_i,
                        B2,
                        gamma_i,
                        encG.r,
                        b_i,
                        y_i,
                        proofEpsBits,
                        ctxR1G
                );
                PresignProofs.EncElgVerifyResult localEncElgG = PresignProofs.verifyEncElgProofDetailed(
                        encElgG, task.paillier.getPublicKeyInfo(), task.zkSetup,
                        Secp256k1Curve.G(), B1, Y_i, B2, G, proofEpsBits, ctxR1G);
                if (!localEncElgG.ok()) {
                    logger.warn("Local PiEncElg proof (G) failed before broadcast, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                            task.taskId, localEncElgG.eq1(), localEncElgG.eq2(), localEncElgG.eq3(), localEncElgG.eq4(), localEncElgG.z1InRange());
                } else {
                    PiEncElgProof encElgGDecoded = CggmpDkgCodec.decodePiEncElgProof(CggmpDkgCodec.encodePiEncElgProof(encElgG));
                    PresignProofs.EncElgVerifyResult localEncElgGDecoded = PresignProofs.verifyEncElgProofDetailed(
                            encElgGDecoded, task.paillier.getPublicKeyInfo(), task.zkSetup,
                            Secp256k1Curve.G(), B1, Y_i, B2, G, proofEpsBits, ctxR1G);
                    if (!localEncElgGDecoded.ok()) {
                        logger.warn("Local PiEncElg proof (G) failed after codec roundtrip, task {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                                task.taskId, localEncElgGDecoded.eq1(), localEncElgGDecoded.eq2(), localEncElgGDecoded.eq3(),
                                localEncElgGDecoded.eq4(), localEncElgGDecoded.z1InRange());
                    }
                }
                broadcastPresignR1(task, K, G, Y_i, A1, A2, B1, B2, encElgK, encElgG).join();
                if (!task.gammaCommitLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for presign R1");
                }
                logger.info("Presign R1 completed for task {}, proceeding to R2", task.taskId);

                // Round 2: compute Γ_i and D/F/D̂/F̂ for each peer.
                ECPoint Gamma_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i);
                Map<Integer, BigInteger> D = new HashMap<>();
                Map<Integer, BigInteger> Dhat = new HashMap<>();
                Map<Integer, BigInteger> F = new HashMap<>();
                Map<Integer, BigInteger> Fhat = new HashMap<>();
                BigInteger x_i_raw = loadLocalShare(task.groupPublicKey);
                BigInteger lambda_i = lagrangeCoefficientAtZero(nodeId, task.participants, curveOrder);
                BigInteger x_i = x_i_raw.multiply(lambda_i).mod(curveOrder);
                ECPoint X_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), x_i);
                Map<Integer, PiAffGProof> affGProofs = new HashMap<>();
                Map<Integer, PiAffGProof> affGProofsHat = new HashMap<>();
                int skippedPeers = 0;
                long r2StartNs = System.nanoTime();
                logger.info("Presign R2 starting proof generation for task {} (peers={})", task.taskId, task.participants.size() - 1);
                List<CompletableFuture<PeerR2Result>> r2Futures = new ArrayList<>();
                for (int peerId : task.participants) {
                    if (peerId == nodeId) continue;
                    r2Futures.add(CompletableFuture.supplyAsync(() -> {
                        long peerStartNs = System.nanoTime();
                        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                        BigInteger K_peer = task.presignK.get(peerId);
                        if (pk == null || K_peer == null) {
                            return PeerR2Result.skipped(peerId);
                        }
                        BigInteger beta = randomNonZero(curveOrder);
                        BigInteger betaHat = randomNonZero(curveOrder);
                        PaillierEncryption.Encryption encNegBeta = pk.encryptWithRandomness(negateModN(beta, pk.n));
                        PaillierEncryption.Encryption encNegBetaHat = pk.encryptWithRandomness(negateModN(betaHat, pk.n));
                        BigInteger D_ji = pk.multiply(K_peer, gamma_i).multiply(encNegBeta.c).mod(pk.nSquared);
                        BigInteger Dhat_ji = pk.multiply(K_peer, x_i).multiply(encNegBetaHat.c).mod(pk.nSquared);
                        PaillierEncryption.Encryption encBeta = task.paillier.getPublicKeyInfo().encryptWithRandomness(beta);
                        PaillierEncryption.Encryption encBetaHat = task.paillier.getPublicKeyInfo().encryptWithRandomness(betaHat);
                        BigInteger F_ji = encBeta.c;
                        BigInteger Fhat_ji = encBetaHat.c;
                        PiAffGProof proof = PresignProofs.createAffGProofNegY(
                                Secp256k1Curve.G(), Gamma_i, pk.n, task.paillier.getPublicKeyInfo().n,
                                K_peer, D_ji, F_ji, gamma_i, beta, encNegBeta.r, encBeta.r, proofKappa, proofEpsBits, buildPresignContext(task.taskId, nodeId, "R2")
                        );
                        PiAffGProof proofHat = PresignProofs.createAffGProofNegY(
                                Secp256k1Curve.G(), X_i, pk.n, task.paillier.getPublicKeyInfo().n,
                                K_peer, Dhat_ji, Fhat_ji, x_i, betaHat, encNegBetaHat.r, encBetaHat.r, proofKappa, proofEpsBits, buildPresignContext(task.taskId, nodeId, "R2H")
                        );
                        long peerMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - peerStartNs);
                        return PeerR2Result.done(peerId, beta, betaHat, D_ji, Dhat_ji, F_ji, Fhat_ji,
                                encNegBeta.r, encBeta.r, encNegBetaHat.r, encBetaHat.r, proof, proofHat, peerMs);
                    }, dkgExecutorService));
                }
                CompletableFuture.allOf(r2Futures.toArray(new CompletableFuture[0])).join();
                for (CompletableFuture<PeerR2Result> future : r2Futures) {
                    PeerR2Result result = future.join();
                    if (result.skipped) {
                        skippedPeers++;
                        continue;
                    }
                    int peerId = result.peerId;
                    task.presignBeta.put(peerId, result.beta);
                    task.presignBetaHat.put(peerId, result.betaHat);
                    D.put(peerId, result.d);
                    Dhat.put(peerId, result.dhat);
                    F.put(peerId, result.f);
                    Fhat.put(peerId, result.fhat);
                    task.presignFOutgoing.put(peerId, result.f);
                    task.presignFhatOutgoing.put(peerId, result.fhat);
                    task.presignRho.put(peerId, result.rho);
                    task.presignMu.put(peerId, result.mu);
                    task.presignRhoHat.put(peerId, result.rhoHat);
                    task.presignMuHat.put(peerId, result.muHat);
                    affGProofs.put(peerId, result.proof);
                    affGProofsHat.put(peerId, result.proofHat);
                    logger.info("Presign R2 proof generated for task {} peer {} in {} ms", task.taskId, peerId, result.peerMs);
                }
                long r2Ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - r2StartNs);
                logger.info("Presign R2 prepared for task {}: peers={}, proofs={}, skipped={}",
                        task.taskId, task.participants.size() - 1, affGProofs.size(), skippedPeers);
                logger.info("Presign R2 proof generation total time for task {}: {} ms", task.taskId, r2Ms);

                ECPoint Y_i_r2 = task.presignY.get(nodeId);
                ECPoint B1_r2 = task.presignB1.get(nodeId);
                ECPoint B2_r2 = task.presignB2.get(nodeId);
                if (Y_i_r2 == null || B1_r2 == null || B2_r2 == null || task.presignBScalar == null) {
                    throw new RuntimeException("Missing presign R1 commitments for PiLog proof");
                }
                byte[] ctxR2 = buildPresignContext(task.taskId, nodeId, "R2");
                PiLogProof logProof = PresignProofs.createLogProof(
                        Secp256k1Curve.G(),
                        Secp256k1Curve.G(),
                        Gamma_i,
                        Y_i_r2,
                        B1_r2,
                        B2_r2,
                        gamma_i,
                        task.presignBScalar,
                        ctxR2
                );
                broadcastPresignR2(task, Gamma_i, D, Dhat, F, Fhat, affGProofs, affGProofsHat, logProof, X_i).join();
                logger.info("Presign R2 broadcasted for task {}", task.taskId);

                if (!task.presignR2Latch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for presign R2");
                }

                // Round 3: decrypt alphas, compute delta/chi, broadcast.
                BigInteger delta_i = gamma_i.multiply(task.k_i).mod(curveOrder);
                BigInteger chi_i = x_i.multiply(task.k_i).mod(curveOrder);
                List<Integer> missingR3Peers = new ArrayList<>();
                for (int peerId : task.participants) {
                    if (peerId == nodeId) continue;
                    BigInteger D_ij = task.presignD.get(peerId);
                    BigInteger Dhat_ij = task.presignDhat.get(peerId);
                    BigInteger beta = task.presignBeta.get(peerId);
                    BigInteger betaHat = task.presignBetaHat.get(peerId);
                    if (D_ij == null || Dhat_ij == null || beta == null || betaHat == null) {
                        logger.warn("Presign R3 missing inputs for task {} peer {}: D={}, Dhat={}, beta={}, betaHat={}",
                                task.taskId,
                                peerId,
                                D_ij == null ? null : D_ij.toString(16),
                                Dhat_ij == null ? null : Dhat_ij.toString(16),
                                beta == null ? null : beta.toString(16),
                                betaHat == null ? null : betaHat.toString(16));
                        missingR3Peers.add(peerId);
                        continue;
                    }
                    BigInteger alpha = decodeSigned(task.paillier.decrypt(D_ij), task.paillier.getPublicKeyInfo().n);
                    BigInteger alphaHat = decodeSigned(task.paillier.decrypt(Dhat_ij), task.paillier.getPublicKeyInfo().n);
                    BigInteger oldDelta = delta_i;
                    BigInteger oldChi = chi_i;
                    delta_i = delta_i.add(alpha).add(beta).mod(curveOrder);
                    chi_i = chi_i.add(alphaHat).add(betaHat).mod(curveOrder);
                    logger.info("Presign R3 accumulate task {} peer {}: alpha={}, beta={}, alphaHat={}, betaHat={}, delta_i: {} -> {}, chi_i: {} -> {}",
                            task.taskId,
                            peerId,
                            alpha.toString(16),
                            beta.toString(16),
                            alphaHat.toString(16),
                            betaHat.toString(16),
                            oldDelta.toString(16),
                            delta_i.toString(16),
                            oldChi.toString(16),
                            chi_i.toString(16));
                }
                if (!missingR3Peers.isEmpty()) {
                    throw new RuntimeException("Presign R3 missing inputs from peers: " + missingR3Peers);
                }
                ECPoint Gamma = sumPresignGamma(task);
                ECPoint Delta_i = Gamma.multiply(task.k_i).normalize();
                ECPoint S_i = Gamma.multiply(chi_i).normalize();
                task.presignDelta.put(nodeId, delta_i);
                task.presignDeltaPoint.put(nodeId, Delta_i);
                task.presignSPoint.put(nodeId, S_i);
                byte[] ctxR3 = buildPresignContext(task.taskId, nodeId, "R3");
                ECPoint Y_i_r3 = task.presignY.get(nodeId);
                ECPoint A1_r3 = task.presignA1.get(nodeId);
                ECPoint A2_r3 = task.presignA2.get(nodeId);
                if (Y_i_r3 == null || A1_r3 == null || A2_r3 == null || task.presignAScalar == null) {
                    throw new RuntimeException("Missing presign R1 commitments for PiLog proof (R3)");
                }
                PiLogProof logProofR3 = PresignProofs.createLogProof(
                        Secp256k1Curve.G(),
                        Gamma,
                        Delta_i,
                        Y_i_r3,
                        A1_r3,
                        A2_r3,
                        task.k_i,
                        task.presignAScalar,
                        ctxR3
                );
                broadcastPresignR3(task, delta_i, Delta_i, S_i, logProofR3).join();
                if (!task.offlineDoneLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for presign R3");
                }

                BigInteger delta = sumShares(task.presignDelta, curveOrder);
                ECPoint left = Secp256k1Curve.multiply(Secp256k1Curve.G(), delta);
                ECPoint right = sumPoints(task.presignDeltaPoint);
                if (!left.equals(right)) {
                    logger.warn("Presign delta verification mismatch for task {}: left={}, right={}, delta={}, participants={}",
                            task.taskId,
                            HexUtils.bytesToHex(Secp256k1Curve.encodePoint(left)),
                            HexUtils.bytesToHex(Secp256k1Curve.encodePoint(right)),
                            delta.toString(16),
                            task.participants);
                    Map<String, Object> evidence = buildDecEvidenceDelta(task, gamma_i, delta_i);
                    broadcastComplaint(task, null, "Presign delta verification failed", evidence).join();
                    failSignatureTask(task, "Presign delta verification failed");
                    return;
                }
                ECPoint X = task.groupPublicKeyPoint;
                ECPoint leftS = X.multiply(delta).normalize();
                ECPoint rightS = sumPoints(task.presignSPoint);
                if (!leftS.equals(rightS)) {
                    logger.warn("Presign chi verification mismatch for task {}: leftS={}, rightS={}, delta={}, participants={}",
                            task.taskId,
                            HexUtils.bytesToHex(Secp256k1Curve.encodePoint(leftS)),
                            HexUtils.bytesToHex(Secp256k1Curve.encodePoint(rightS)),
                            delta.toString(16),
                            task.participants);
                    for (int peerId : task.participants) {
                        ECPoint sPoint = task.presignSPoint.get(peerId);
                        BigInteger deltaShare = task.presignDelta.get(peerId);
                        if (sPoint == null && deltaShare == null) {
                            continue;
                        }
                        logger.warn("Presign chi mismatch details task {} peer {}: S_i={}, delta_i={}",
                                task.taskId,
                                peerId,
                                sPoint == null ? null : HexUtils.bytesToHex(Secp256k1Curve.encodePoint(sPoint)),
                                deltaShare == null ? null : deltaShare.toString(16));
                    }
                    Map<String, Object> evidence = buildDecEvidenceChi(task, x_i, chi_i);
                    broadcastComplaint(task, null, "Presign chi verification failed", evidence).join();
                    failSignatureTask(task, "Presign chi verification failed");
                    return;
                }
                BigInteger deltaInv = delta.modInverse(curveOrder);
                ECPoint GammaFinal = Gamma.normalize();
                BigInteger kTilde = task.k_i.multiply(deltaInv).mod(curveOrder);
                BigInteger chiTilde = chi_i.multiply(deltaInv).mod(curveOrder);
                task.presignature = new Presignature(GammaFinal, kTilde, chiTilde);
                task.presignatureLatch.countDown();

                for (Map.Entry<Integer, ECPoint> e : task.presignDeltaPoint.entrySet()) {
                    task.presignDeltaTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
                }
                for (Map.Entry<Integer, ECPoint> e : task.presignSPoint.entrySet()) {
                    task.presignSTilde.put(e.getKey(), e.getValue().multiply(deltaInv).normalize());
                }

                if (nodeId == task.initiatorId) {
                    markOfflineReady(task, nodeId);
                } else {
                    sendOfflineReady(task).join();
                }
            } catch (Exception e) {
                task.fail(e.getMessage());
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
    }

    private CompletableFuture<Void> runOnlinePhase(Gg20SignatureTask task) {
        return CompletableFuture.runAsync(() -> {
            try {
                if (!task.offlineDoneLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for offline phase");
                }
                if (!task.presignatureLatch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new RuntimeException("Timeout waiting for local presignature");
                }
                if (task.messageHash == null) {
                    throw new RuntimeException("Missing message hash for online phase");
                }
                if (!signatureInProgress.compareAndSet(false, true)) {
                    throw new RuntimeException("Signature process is already in progress");
                }

                BigInteger curveOrder = Secp256k1Curve.n();
                if (task.presignature == null) {
                    throw new RuntimeException("Missing presignature");
                }
                if (task.presignatureUsed) {
                    throw new RuntimeException("Presignature already used");
                }
                if (nodeId == task.initiatorId) {
                    if (!PresignUsageStore.markUsed(task.groupPublicKey, task.presignature.Gamma())) {
                        throw new RuntimeException("Presignature already used (persistent)");
                    }
                }
                task.presignatureUsed = true;
                ECPoint Gamma = task.presignature.Gamma();
                task.r = Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
                if (task.r.signum() == 0) {
                    throw new RuntimeException("Invalid r (zero), restart signature");
                }

                BigInteger e = new BigInteger(1, task.messageHash).mod(curveOrder);
                BigInteger sigma_i = task.presignature.kTilde().multiply(e).add(task.r.multiply(task.presignature.chiTilde())).mod(curveOrder);
                if (nodeId == task.initiatorId) {
                    if (!verifySigmaShare(task, nodeId, sigma_i)) {
                        throw new RuntimeException("Local signature share verification failed");
                    }
                    task.sShares.put(nodeId, sigma_i);
                    if (!task.sShareLatch.await(Constants.SIGNATURE_SHARE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                        throw new RuntimeException("Timeout waiting for signature shares");
                    }
                    List<Integer> offenders = findInvalidSigmaShares(task);
                    if (!offenders.isEmpty()) {
                        for (int offender : offenders) {
                            broadcastComplaint(task, offender, "Invalid signature share (Figure 10)", Map.of("r", HexUtils.toHex(task.r))).join();
                        }
                        failSignatureTask(task, "Invalid signature shares: " + offenders);
                        return;
                    }
                    BigInteger s = sumShares(task.sShares, curveOrder);
                    if (s.compareTo(curveOrder.shiftRight(1)) > 0) {
                        s = curveOrder.subtract(s);
                    }
                    byte[] der = derEncodeSignature(task.r, s);
                    boolean verified = verifySignature(task.groupPublicKeyPoint, task.messageHash, task.r, s, buildDomain());
                    if (!verified) {
                        List<Integer> suspects = findInvalidSigmaShares(task);
                        for (int offender : suspects) {
                            broadcastComplaint(task, offender, "Aggregate signature verification failed (Figure 10)", Map.of("r", HexUtils.toHex(task.r))).join();
                        }
                        failSignatureTask(task, "Aggregate signature verification failed");
                        return;
                    }
                    task.signature = Base64.getEncoder().encodeToString(der);
                    task.verified = verified;
                    task.complete();
                    signatureInProgress.set(false);
                    clearPresignAll(task);
                    logger.info("CGGMP signature task {} completed successfully, verified: {}", task.taskId, verified);
                } else {
                    sendSShare(task, sigma_i).join();
                    task.complete();
                    signatureInProgress.set(false);
                    clearPresignLocal(task);
                }
            } catch (Exception e) {
                task.fail(e.getMessage());
                signatureInProgress.set(false);
                clearPresignAll(task);
                throw new RuntimeException(e);
            }
        }, ThreadPoolUtil.getIoThreadPool());
    }

    private CompletableFuture<Void> broadcastOfflineInit(Gg20SignatureTask task) {
        Map<String, Object> initData = new HashMap<>();
        initData.put("signatureTaskId", task.taskId);
        initData.put("groupPublicKey", task.groupPublicKey);
        initData.put("message", task.message);
        initData.put("initiatorId", task.initiatorId);
        initData.put("participants", new ArrayList<>(task.participants));
        try {
            for (int attempt = 1; attempt <= Constants.SIGNATURE_BROADCAST_RETRY_COUNT; attempt++) {
                nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_OFFLINE_INIT, initData)).join();
                logger.info("Broadcasted CGGMP_SIGN_OFFLINE_INIT for signature task: {} (attempt {}/{})", task.taskId, attempt, Constants.SIGNATURE_BROADCAST_RETRY_COUNT);
                if (attempt < Constants.SIGNATURE_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to broadcast CGGMP_SIGN_OFFLINE_INIT, proceeding: {}", e.getMessage());
        }
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> broadcastOnlineInit(Gg20SignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("messageHash", Base64.getEncoder().encodeToString(task.messageHash));
        data.put("initiatorId", task.initiatorId);
        data.put("participants", new ArrayList<>(task.participants));
        try {
            for (int attempt = 1; attempt <= Constants.SIGNATURE_BROADCAST_RETRY_COUNT; attempt++) {
                nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_ONLINE_INIT, data)).join();
                logger.info("Broadcasted CGGMP_SIGN_ONLINE_INIT for signature task: {} (attempt {}/{})", task.taskId, attempt, Constants.SIGNATURE_BROADCAST_RETRY_COUNT);
                if (attempt < Constants.SIGNATURE_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to broadcast CGGMP_SIGN_ONLINE_INIT, proceeding: {}", e.getMessage());
        }
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> broadcastPresignR1(Gg20SignatureTask task,
                                                       BigInteger K,
                                                       BigInteger G,
                                                       ECPoint Y,
                                                       ECPoint A1,
                                                       ECPoint A2,
                                                       ECPoint B1,
                                                       ECPoint B2,
                                                       PiEncElgProof encElgK,
                                                       PiEncElgProof encElgG) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("K", K.toString(16));
        data.put("G", G.toString(16));
        data.put("Y", bytesToHex(Secp256k1Curve.encodePoint(Y)));
        data.put("A1", bytesToHex(Secp256k1Curve.encodePoint(A1)));
        data.put("A2", bytesToHex(Secp256k1Curve.encodePoint(A2)));
        data.put("B1", bytesToHex(Secp256k1Curve.encodePoint(B1)));
        data.put("B2", bytesToHex(Secp256k1Curve.encodePoint(B2)));
        data.put("encElgProofK", CggmpDkgCodec.encodePiEncElgProof(encElgK));
        data.put("encElgProofG", CggmpDkgCodec.encodePiEncElgProof(encElgG));
        data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
        data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
        try {
            for (int attempt = 1; attempt <= Constants.SIGNATURE_BROADCAST_RETRY_COUNT; attempt++) {
                nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R1, data)).join();
                logger.info("Broadcasted CGGMP_PRESIGN_R1 for signature task: {} (attempt {}/{})", task.taskId, attempt, Constants.SIGNATURE_BROADCAST_RETRY_COUNT);
                if (attempt < Constants.SIGNATURE_BROADCAST_RETRY_COUNT) {
                    Thread.sleep(Constants.SIGNATURE_BROADCAST_RETRY_INTERVAL_MS);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to broadcast CGGMP_PRESIGN_R1, proceeding: {}", e.getMessage());
        }
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<Void> broadcastPresignR2(Gg20SignatureTask task, ECPoint Gamma,
                                                      Map<Integer, BigInteger> D,
                                                      Map<Integer, BigInteger> Dhat,
                                                      Map<Integer, BigInteger> F,
                                                      Map<Integer, BigInteger> Fhat,
                                                      Map<Integer, PiAffGProof> affG,
                                                      Map<Integer, PiAffGProof> affGhat,
                                                      PiLogProof logProof,
                                                      ECPoint X) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("Gamma", bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
        data.put("D", encodeBigIntegerMap(D));
        data.put("Dhat", encodeBigIntegerMap(Dhat));
        data.put("F", encodeBigIntegerMap(F));
        data.put("Fhat", encodeBigIntegerMap(Fhat));
        data.put("affGProofs", encodeAffGProofMap(affG));
        data.put("affGProofsHat", encodeAffGProofMap(affGhat));
        data.put("logProof", CggmpDkgCodec.encodePiLogProof(logProof));
        data.put("X", bytesToHex(Secp256k1Curve.encodePoint(X)));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R2, data));
    }

    private CompletableFuture<Void> broadcastPresignR3(Gg20SignatureTask task, BigInteger delta, ECPoint Delta, ECPoint S, PiLogProof logProof) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("delta", delta.toString(16));
        data.put("Delta", bytesToHex(Secp256k1Curve.encodePoint(Delta)));
        data.put("S", bytesToHex(Secp256k1Curve.encodePoint(S)));
        data.put("logProof", CggmpDkgCodec.encodePiLogProof(logProof));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_PRESIGN_R3, data));
    }

    private Map<String, String> encodeBigIntegerMap(Map<Integer, BigInteger> map) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<Integer, BigInteger> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), e.getValue().toString(16));
        }
        return out;
    }

    private Map<Integer, BigInteger> decodeBigIntegerMap(Map<?, ?> map) {
        Map<Integer, BigInteger> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, new BigInteger(String.valueOf(e.getValue()), 16));
        }
        return out;
    }

    private Map<String, String> encodePointMap(Map<Integer, ECPoint> map) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<Integer, ECPoint> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), bytesToHex(e.getValue().getEncoded(false)));
        }
        return out;
    }

    private Map<String, String> encodePointMapCompressed(Map<Integer, ECPoint> map) {
        Map<String, String> out = new HashMap<>();
        for (Map.Entry<Integer, ECPoint> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), bytesToHex(e.getValue().getEncoded(true)));
        }
        return out;
    }

    private Map<Integer, ECPoint> decodePointMap(Map<?, ?> map) {
        Map<Integer, ECPoint> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, Secp256k1Curve.decodePoint(HexUtils.hexToBytes(String.valueOf(e.getValue()))));
        }
        return out;
    }

    private Map<String, Object> encodeAffGProofMap(Map<Integer, PiAffGProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiAffGProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpDkgCodec.encodePiAffGProof(e.getValue()));
        }
        return out;
    }

    private Map<Integer, PiAffGProof> decodeAffGProofMap(Map<?, ?> map) {
        Map<Integer, PiAffGProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpDkgCodec.decodePiAffGProof((Map<?, ?>) e.getValue()));
        }
        return out;
    }

    private Map<String, Object> encodeSchProofMap(Map<Integer, PiSchProof> map) {
        Map<String, Object> out = new HashMap<>();
        for (Map.Entry<Integer, PiSchProof> e : map.entrySet()) {
            out.put(String.valueOf(e.getKey()), CggmpDkgCodec.encodePiSchProof(e.getValue()));
        }
        return out;
    }

    private Map<Integer, PiSchProof> decodeSchProofMap(Map<?, ?> map) {
        Map<Integer, PiSchProof> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            int key = Integer.parseInt(String.valueOf(e.getKey()));
            out.put(key, CggmpDkgCodec.decodePiSchProof((Map<?, ?>) e.getValue()));
        }
        return out;
    }

    private ECPoint sumPresignGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : task.presignGamma.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private ECPoint sumPoints(Map<Integer, ECPoint> points) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : points.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private static byte[] buildPresignContext(String taskId, int senderId, String round) {
        String ctx = "PRESIGN:" + round + ":" + taskId + ":" + senderId;
        return ctx.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

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

    private static byte[] buildDkgContext(String taskId, byte[] rid, int senderId, String label) {
        String base = "DKG:" + label + ":" + taskId + ":" + senderId + ":";
        byte[] prefix = base.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (rid == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rid.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rid, 0, out, prefix.length, rid.length);
        return out;
    }

    private static byte[] xorRidParts(CggmpDkgTask task) {
        byte[] out = null;
        for (byte[] part : task.ridParts.values()) {
            if (out == null) {
                out = java.util.Arrays.copyOf(part, part.length);
            } else {
                int len = Math.min(out.length, part.length);
                for (int i = 0; i < len; i++) {
                    out[i] ^= part[i];
                }
            }
        }
        return out == null ? new byte[0] : out;
    }

    private static String computePayloadHashHex(Map<?, ?> data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            updateDigest(md, data);
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute payload hash", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void updateDigest(MessageDigest md, Object value) {
        if (value == null) {
            md.update((byte) 0);
            return;
        }
        if (value instanceof Map<?, ?> map) {
            md.update((byte) 1);
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            Collections.sort(keys);
            for (String k : keys) {
                updateDigest(md, k);
                updateDigest(md, map.get(k));
            }
            return;
        }
        if (value instanceof Iterable<?> it) {
            md.update((byte) 2);
            for (Object o : it) {
                updateDigest(md, o);
            }
            return;
        }
        md.update((byte) 3);
        md.update(String.valueOf(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static BigInteger deriveDkgMask(String taskId, byte[] rid, int senderId, int receiverId, ECPoint Yji) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("DKG_MASK".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (rid != null) {
                md.update(rid);
            }
            md.update(Integer.toString(senderId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(Integer.toString(receiverId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (Yji != null) {
                md.update(Secp256k1Curve.encodePoint(Yji));
            }
            return new BigInteger(1, md.digest()).mod(Secp256k1Curve.n());
        } catch (Exception e) {
            throw new RuntimeException("DKG mask derivation failed", e);
        }
    }

    private static BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x, BigInteger mod) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE;
        for (BigInteger coeff : coefficients) {
            result = result.add(coeff.multiply(xPower)).mod(mod);
            xPower = xPower.multiply(x).mod(mod);
        }
        return result;
    }

    private static BigInteger[] precomputeEvalPowers(int receiverId, int threshold) {
        BigInteger q = Secp256k1Curve.n();
        BigInteger x = BigInteger.valueOf(receiverId);
        BigInteger[] powers = new BigInteger[threshold];
        BigInteger xPower = BigInteger.ONE;
        for (int k = 0; k < threshold; k++) {
            powers[k] = xPower;
            xPower = xPower.multiply(x).mod(q);
        }
        return powers;
    }

    private static ECPoint computeExpectedShareFromXjk(Map<Integer, ECPoint> Xjk, BigInteger[] evalPowers) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        if (evalPowers == null) {
            throw new IllegalStateException("Missing precomputed DKG evaluation powers");
        }
        int limit = Math.min(Xjk.size(), evalPowers.length);
        for (int k = 0; k < limit; k++) {
            ECPoint X = Xjk.get(k);
            if (X == null) {
                continue;
            }
            sum = sum.add(X.multiply(evalPowers[k])).normalize();
        }
        return sum;
    }

    private boolean verifySchProofsParallel(CggmpDkgTask task,
                                            int senderNodeId,
                                            Map<Integer, PiSchProof> schProofs,
                                            Map<Integer, ECPoint> Xjk,
                                            Map<Integer, ECPoint> Ajk) {
        if (schProofs == null || schProofs.size() != threshold) {
            return false;
        }
        if (threshold <= 3) {
            for (int k = 0; k < threshold; k++) {
                PiSchProof proof = schProofs.get(k);
                ECPoint AjkPoint = Ajk.get(k);
                ECPoint XjkPoint = Xjk.get(k);
                if (proof == null || AjkPoint == null || XjkPoint == null) {
                    return false;
                }
                byte[] ctx = buildDkgContext(task.taskId, task.rid, senderNodeId, "SCH:" + k);
                long schOneStart = System.nanoTime();
                if (!proof.A().equals(AjkPoint)) {
                    return false;
                }
                boolean ok = RefreshProofs.verifySchProof(proof, Secp256k1Curve.G(), XjkPoint, ctx);
                logger.info("DKG Round2 Sch proof verify k={} took {} ms", k, (System.nanoTime() - schOneStart) / 1_000_000);
                if (!ok) {
                    return false;
                }
            }
            return true;
        }

        List<CompletableFuture<Boolean>> futures = new ArrayList<>(threshold);
        for (int k = 0; k < threshold; k++) {
            PiSchProof proof = schProofs.get(k);
            ECPoint AjkPoint = Ajk.get(k);
            ECPoint XjkPoint = Xjk.get(k);
            if (proof == null || AjkPoint == null || XjkPoint == null) {
                return false;
            }
            byte[] ctx = buildDkgContext(task.taskId, task.rid, senderNodeId, "SCH:" + k);
            final int kk = k;
            futures.add(CompletableFuture.supplyAsync(() -> {
                long schOneStart = System.nanoTime();
                if (!proof.A().equals(AjkPoint)) {
                    return false;
                }
                boolean ok = RefreshProofs.verifySchProof(proof, Secp256k1Curve.G(), XjkPoint, ctx);
                logger.info("DKG Round2 Sch proof verify k={} took {} ms", kk, (System.nanoTime() - schOneStart) / 1_000_000);
                return ok;
            }, dkgExecutorService));
        }
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        for (CompletableFuture<Boolean> f : futures) {
            if (!f.join()) {
                return false;
            }
        }
        return true;
    }

    private static PiSchProof createSchProofWithAlpha(ECPoint g, ECPoint X, BigInteger x, BigInteger alpha, byte[] context) {
        BigInteger q = Secp256k1Curve.n();
        ECPoint A = g.multiply(alpha).normalize();
        BigInteger e = schChallenge(context, g, X, A);
        BigInteger z = alpha.add(e.multiply(x)).mod(q);
        return new PiSchProof(A, z);
    }

    private static BigInteger schChallenge(byte[] context, ECPoint g, ECPoint X, ECPoint A) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("PI_SCH".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            if (context != null) {
                md.update(context);
            }
            md.update(Secp256k1Curve.encodePoint(g));
            md.update(Secp256k1Curve.encodePoint(X));
            md.update(Secp256k1Curve.encodePoint(A));
            BigInteger q = Secp256k1Curve.n();
            BigInteger twoQ = q.shiftLeft(1);
            BigInteger e = new BigInteger(1, md.digest()).mod(twoQ);
            return e.compareTo(q) >= 0 ? e.subtract(twoQ) : e;
        } catch (Exception e) {
            throw new RuntimeException("DKG Schnorr challenge failed", e);
        }
    }

    private CompletableFuture<Void> sendOfflineReady(Gg20SignatureTask task) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_OFFLINE_READY, data));
    }

    private void runRefreshProtocol(com.example.mpc.model.CggmpRefreshTask task) {
        try {
            BigInteger q = Secp256k1Curve.n();
            logger.info("Refresh {} waiting for network ready...", task.taskId);
            try {
                nodeService.waitForNetworkReady().get(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (Exception e) {
                throw new RuntimeException("Refresh network ready timeout", e);
            }
            logger.info("Refresh {} network ready", task.taskId);
            if (!task.participants.contains(nodeId)) {
                return;
            }
            long paillierStart = System.currentTimeMillis();
            logger.info("Refresh {} generating Paillier ({} bits)...", task.taskId, refreshPaillierBits);
            task.paillier = new PaillierEncryption(refreshPaillierBits);
            logger.info("Refresh {} Paillier ready in {} ms", task.taskId, System.currentTimeMillis() - paillierStart);
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
            ECPoint Xi = Secp256k1Curve.multiply(Secp256k1Curve.G(), xi);

            BigInteger sum = BigInteger.ZERO;
            for (int peerId : task.participants) {
                BigInteger share;
                if (peerId == nodeId) {
                    continue;
                }
                share = randomNonZero(q);
                task.xShares.put(peerId, share);
                sum = sum.add(share).mod(q);
            }
            BigInteger selfShare = q.subtract(sum).mod(q);
            task.xShares.put(nodeId, selfShare);
            for (int peerId : task.participants) {
                BigInteger x = task.xShares.get(peerId);
                task.xPoints.put(peerId, Secp256k1Curve.multiply(Secp256k1Curve.G(), x));
            }

            for (int peerId : task.participants) {
                BigInteger y = randomNonZero(q);
                task.yShares.put(peerId, y);
                task.yPoints.put(peerId, Secp256k1Curve.multiply(Secp256k1Curve.G(), y));
            }

            Map<Integer, ECPoint> A = new HashMap<>();
            SecureRandom rnd = new SecureRandom();
            for (int peerId : task.participants) {
                BigInteger alpha = new BigInteger(q.bitLength(), rnd).mod(q);
                task.schAlphas.put(peerId, alpha);
                A.put(peerId, Secp256k1Curve.multiply(Secp256k1Curve.G(), alpha));
            }

            byte[] rid = randomBytes(32);
            byte[] u = randomBytes(32);

            String v = computeRefreshCommit(task.taskId, nodeId, task.xPoints, task.yPoints, A, Xi,
                    task.paillier.getPublicKeyInfo(), task.zkSetup, task.pedersenHatN, task.pedersenS, task.pedersenT,
                    task.prmProof, rid, u);
            task.round1Commit.put(nodeId, v);
            broadcastRefreshR1(task, v).join();

            if (!task.round1Latch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout waiting for refresh R1");
            }

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
            broadcastRefreshR2(task, r2).join();

            if (!task.round2Latch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout waiting for refresh R2");
            }

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
                C.put(peerId, xij.add(rho).mod(q));
            }
            for (int peerId : task.participants) {
                BigInteger xij = task.xShares.get(peerId);
                PiSchProof sch = RefreshProofs.createSchProof(
                        Secp256k1Curve.G(),
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
            broadcastRefreshR3(task, r3).join();

            if (!task.round3Latch.await(Constants.SIGNATURE_COMMITMENT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new RuntimeException("Timeout waiting for refresh R3");
            }

            if (!finalizeRefresh(task)) {
                task.fail("Refresh verification failed");
                return;
            }
            task.complete();
        } catch (Exception e) {
            task.fail(e.getMessage());
            throw new RuntimeException(e);
        }
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
        data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(r2.paillierKey));
        data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(r2.zkSetup));
        data.put("hatN", r2.hatN.toString(16));
        data.put("s", r2.s.toString(16));
        data.put("t", r2.t.toString(16));
        data.put("prmProof", CggmpDkgCodec.encodePiPrmProof(r2.prmProof));
        data.put("Y", encodePointMap(r2.Y));
        data.put("X", encodePointMap(r2.X));
        data.put("A", encodePointMap(r2.A));
        data.put("Xi", bytesToHex(Secp256k1Curve.encodePoint(r2.Xi)));
        data.put("rid", Base64.getEncoder().encodeToString(r2.rid));
        data.put("u", Base64.getEncoder().encodeToString(r2.u));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_REFRESH_R2, data));
    }

    private CompletableFuture<Void> broadcastRefreshR3(CggmpRefreshTask task, CggmpRefreshTask.RefreshRound3Data r3) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("C", encodeBigIntegerMap(r3.C));
        data.put("schProofs", encodeSchProofMap(r3.schProofs));
        data.put("biPrimeProof", CggmpDkgCodec.encodeBiPrimeProof(r3.biPrimeProof));
        data.put("factorProof", CggmpDkgCodec.encodeNoSmallFactorProof(r3.factorProof));
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

            PaillierEncryption.PublicKey pk = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
            ZKSetup zk = CggmpDkgCodec.decodeZkSetup(zkMap);
            BigInteger hatN = new BigInteger(hatNHex, 16);
            BigInteger s = new BigInteger(sHex, 16);
            BigInteger t = new BigInteger(tHex, 16);
            PiPrmProof prmProof = CggmpDkgCodec.decodePiPrmProof(prmMap);
            Map<Integer, ECPoint> Y = decodePointMap(yMap);
            Map<Integer, ECPoint> X = decodePointMap(xMap);
            Map<Integer, ECPoint> A = decodePointMap(aMap);
            ECPoint Xi = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xiHex));
            byte[] rid = Base64.getDecoder().decode(ridB64);
            byte[] u = Base64.getDecoder().decode(uB64);

            String commit = task.round1Commit.get(senderId);
            if (commit == null) {
                broadcastRefreshComplaint(task, senderId, "Missing refresh R1 commit", refreshEvidence(task, senderId, "Missing refresh R1 commit", null)).join();
                task.fail("Missing refresh R1 commit");
                return;
            }

            String expected = computeRefreshCommit(task.taskId, senderId, X, Y, A, Xi, pk, zk, hatN, s, t, prmProof, rid, u);
            if (!commit.equals(expected)) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("expectedCommit", expected);
                extra.put("commit", commit);
                broadcastRefreshComplaint(task, senderId, "Refresh R1 commit mismatch", refreshEvidence(task, senderId, "Refresh R1 commit mismatch", extra)).join();
                task.fail("Refresh commit mismatch");
                return;
            }

            if (!validatePaillierPublicKey(pk)) {
                broadcastRefreshComplaint(task, senderId, "Invalid Paillier public key",
                        refreshEvidence(task, senderId, "Invalid Paillier public key", Map.of("n", pk.n.toString(16)))).join();
                task.fail("Invalid Paillier key");
                return;
            }

            if (!RefreshProofs.verifyPrmProof(prmProof, hatN, s, t, buildRefreshContext(task.taskId, null, senderId, "PRM"))) {
                broadcastRefreshComplaint(task, senderId, "Invalid PiPrm proof",
                        refreshEvidence(task, senderId, "Invalid PiPrm proof", Map.of("hatN", hatN.toString(16)))).join();
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
            Map<Integer, BigInteger> C = decodeBigIntegerMap(cMap);
            Map<Integer, PiSchProof> schProofs = decodeSchProofMap(schMap);
            BiPrimeBlumProof biPrime = CggmpDkgCodec.decodeBiPrimeProof(biPrimeMap);
            NoSmallFactorProof factor = CggmpDkgCodec.decodeNoSmallFactorProof(factorMap);

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
        BigInteger q = Secp256k1Curve.n();
        for (int peerId : task.participants) {
            if (!task.round1Commit.containsKey(peerId) || !task.round2Data.containsKey(peerId) || !task.round3Data.containsKey(peerId)) {
                broadcastRefreshComplaint(task, peerId, "Missing refresh data",
                        refreshEvidence(task, peerId, "Missing refresh data", Map.of("peerId", peerId))).join();
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
                broadcastRefreshComplaint(task, peerId, "Refresh commit mismatch", refreshEvidence(task, peerId, "Refresh commit mismatch", extra)).join();
                return false;
            }
            if (!RefreshProofs.verifyPrmProof(r2.prmProof, r2.hatN, r2.s, r2.t, buildRefreshContext(task.taskId, null, peerId, "PRM"))) {
                broadcastRefreshComplaint(task, peerId, "Invalid PiPrm proof",
                        refreshEvidence(task, peerId, "Invalid PiPrm proof", Map.of("peerId", peerId))).join();
                return false;
            }
            ECPoint sum = sumPoints(r2.X);
            if (!sum.isInfinity()) {
                Map<String, Object> extra = new HashMap<>();
                extra.put("peerId", peerId);
                extra.put("xSum", bytesToHex(sum.getEncoded(false)));
                broadcastRefreshComplaint(task, peerId, "Sum of X not identity", refreshEvidence(task, peerId, "Sum of X not identity", extra)).join();
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
                broadcastRefreshComplaint(task, peerId, "Invalid Blum proof",
                        refreshEvidence(task, peerId, "Invalid Blum proof", Map.of("peerId", peerId))).join();
                return false;
            }
            NoSmallFactorProofValidator factorValidator = new NoSmallFactorProofValidator(r2.zkSetup);
            if (!factorValidator.verifyProof(r3.factorProof, r2.paillierKey, buildRefreshContext(task.taskId, task.rid, peerId, "FAC"))) {
                broadcastRefreshComplaint(task, peerId, "Invalid NoSmallFactor proof",
                        refreshEvidence(task, peerId, "Invalid NoSmallFactor proof", Map.of("peerId", peerId))).join();
                return false;
            }

            for (int k : task.participants) {
                PiSchProof sch = r3.schProofs.get(k);
                ECPoint Xjk = r2.X.get(k);
                if (sch == null || Xjk == null) {
                    broadcastRefreshComplaint(task, peerId, "Missing Schnorr proof",
                            refreshEvidence(task, peerId, "Missing Schnorr proof", Map.of("peerId", peerId, "k", k))).join();
                    return false;
                }
                if (!RefreshProofs.verifySchProof(sch, Secp256k1Curve.G(), Xjk, buildRefreshContext(task.taskId, task.rid, peerId, "SCH:" + k))) {
                    broadcastRefreshComplaint(task, peerId, "Invalid Schnorr proof",
                            refreshEvidence(task, peerId, "Invalid Schnorr proof", Map.of("peerId", peerId, "k", k))).join();
                    return false;
                }
            }

            if (peerId == nodeId) {
                continue;
            }
            BigInteger Cji = r3.C.get(nodeId);
            if (Cji == null) {
                broadcastRefreshComplaint(task, peerId, "Missing C_{j,i}",
                        refreshEvidence(task, peerId, "Missing C_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))).join();
                return false;
            }
            ECPoint Yji = r2.Y.get(nodeId);
            if (Yji == null) {
                broadcastRefreshComplaint(task, peerId, "Missing Y_{j,i}",
                        refreshEvidence(task, peerId, "Missing Y_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))).join();
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
                broadcastRefreshComplaint(task, peerId, "Missing X_{j,i}",
                        refreshEvidence(task, peerId, "Missing X_{j,i}", Map.of("peerId", peerId, "missingFor", nodeId))).join();
                return false;
            }
            ECPoint check = Secp256k1Curve.multiply(Secp256k1Curve.G(), xji);
            if (!check.equals(Xji)) {
                broadcastRefreshComplaint(task, peerId, "Invalid C_{j,i} decryption",
                        refreshEvidence(task, peerId, "Invalid C_{j,i} decryption", Map.of("peerId", peerId, "missingFor", nodeId))).join();
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
                return r2 != null && !sumPoints(r2.X).isInfinity();
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
                    boolean ok = RefreshProofs.verifySchProof(sch, Secp256k1Curve.G(), Xjk,
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
                BigInteger xji = Cji.subtract(rho).mod(Secp256k1Curve.n());
                ECPoint check = Secp256k1Curve.multiply(Secp256k1Curve.G(), xji);
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
        broadcastRefreshExclude(task, offenderId, reason, newTaskId, newParticipants).join();
        startRefreshTask(newTaskId).exceptionally(ex -> {
            logger.error("Failed to restart refresh task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
        task.fail("Refresh restart after excluding offender " + offenderId);
    }

    private void markOfflineReady(Gg20SignatureTask task, int senderId) {
        if (task.offlineReady.putIfAbsent(senderId, Boolean.TRUE) == null) {
            if (task.offlineReadyLatch.getCount() > 0) {
                task.offlineReadyLatch.countDown();
            }
        }
    }

    private void initSignaturePaillier(Gg20SignatureTask task) {
        if (task.paillier == null) {
            task.paillier = (refreshPaillier != null) ? refreshPaillier : new PaillierEncryption();
        }
        if (task.zkSetup == null) {
            task.zkSetup = (refreshZkSetup != null) ? refreshZkSetup : ZKSetup.generate(task.paillier.getPublicKeyInfo().bitLength);
        }
    }

    public Map<String, Object> runProofSelfCheck() {
        Map<String, Object> result = new HashMap<>();
        result.put("kappa", proofKappa);
        result.put("epsBits", proofEpsBits);
        try {
            SecureRandom rnd = new SecureRandom();
            BigInteger q = Secp256k1Curve.n();

            int selfCheckKeyBits = 1024;
            // PiDec self-check
            PaillierEncryption paillier = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk = paillier.getPublicKeyInfo();
            BigInteger x = randomNonZero(q);
            BigInteger y = randomNonZero(q);
            PaillierEncryption.Encryption encX = pk.encryptWithRandomness(x);
            BigInteger K = encX.c;
            BigInteger rho = BigIntegerUtils.randomZnStar(pk.n, rnd);
            BigInteger encY = pk.encryptWithRandom(y, rho);
            BigInteger KInvX = BigIntegerUtils.powSigned(K, x.negate(), pk.nSquared);
            BigInteger D = encY.multiply(KInvX).mod(pk.nSquared);
            ECPoint X = Secp256k1Curve.multiply(Secp256k1Curve.G(), x);
            ECPoint S = Secp256k1Curve.multiply(Secp256k1Curve.G(), y);
            PiDecProof decProof = PresignProofs.createDecProof(
                    Secp256k1Curve.G(),
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    x,
                    y,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean decOk = PresignProofs.verifyDecProof(
                    decProof,
                    Secp256k1Curve.G(),
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_DEC".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piDecOk", decOk);

            // PiAffG self-check
            PaillierEncryption paillier0 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption paillier1 = new PaillierEncryption(selfCheckKeyBits);
            PaillierEncryption.PublicKey pk0 = paillier0.getPublicKeyInfo();
            PaillierEncryption.PublicKey pk1 = paillier1.getPublicKeyInfo();
            BigInteger x2 = randomNonZero(q);
            BigInteger y2 = randomNonZero(q);
            BigInteger a = randomNonZero(q);
            PaillierEncryption.Encryption encC = pk0.encryptWithRandomness(a);
            BigInteger C = encC.c;
            BigInteger rho2 = BigIntegerUtils.randomZnStar(pk0.n, rnd);
            BigInteger mu2 = BigIntegerUtils.randomZnStar(pk1.n, rnd);
            BigInteger D2 = BigIntegerUtils.powSigned(C, x2, pk0.nSquared)
                    .multiply(BigIntegerUtils.powSigned(BigInteger.ONE.add(pk0.n), y2, pk0.nSquared))
                    .multiply(rho2.modPow(pk0.n, pk0.nSquared))
                    .mod(pk0.nSquared);
            BigInteger Y2 = pk1.encryptWithRandom(y2, mu2);
            ECPoint X2 = Secp256k1Curve.multiply(Secp256k1Curve.G(), x2);
            PiAffGProof affProof = PresignProofs.createAffGProof(
                    Secp256k1Curve.G(),
                    X2,
                    pk0.n,
                    pk1.n,
                    C,
                    D2,
                    Y2,
                    x2,
                    y2,
                    rho2,
                    mu2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            boolean affOk = PresignProofs.verifyAffGProof(
                    affProof,
                    Secp256k1Curve.G(),
                    X2,
                    pk0.n,
                    pk1.n,
                    C,
                    D2,
                    Y2,
                    proofKappa,
                    proofEpsBits,
                    "SELF_CHECK_AFFG".getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );
            result.put("piAffGOk", affOk);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    private BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKey(groupPublicKey).join();
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1Curve.n());
    }

    private SignatureBundle signMessage(BigInteger privateKey, byte[] messageHash, ECPoint publicKey) {
        ECDomainParameters domain = buildDomain();
        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(privateKey, domain);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priv);
        BigInteger[] sig = signer.generateSignature(messageHash);
        BigInteger r = sig[0];
        BigInteger s = sig[1];
        BigInteger n = Secp256k1Curve.n();
        if (s.compareTo(n.shiftRight(1)) > 0) {
            s = n.subtract(s);
        }

        byte[] der = derEncodeSignature(r, s);
        boolean verified = verifySignature(publicKey, messageHash, r, s, domain);
        String signatureBase64 = Base64.getEncoder().encodeToString(der);
        return new SignatureBundle(signatureBase64, verified);
    }

    private boolean verifySignature(ECPoint publicKey, byte[] messageHash, BigInteger r, BigInteger s, ECDomainParameters domain) {
        ECDSASigner verifier = new ECDSASigner();
        ECPublicKeyParameters pub = new ECPublicKeyParameters(publicKey, domain);
        verifier.init(false, pub);
        return verifier.verifySignature(messageHash, r, s);
    }

    private byte[] derEncodeSignature(BigInteger r, BigInteger s) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode DER signature", e);
        }
    }

    private ECDomainParameters buildDomain() {
        return new ECDomainParameters(
                Secp256k1Curve.G().getCurve(),
                Secp256k1Curve.G(),
                Secp256k1Curve.n(),
                BigInteger.ONE
        );
    }

    private BigInteger randomNonZero(BigInteger n) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd).mod(n);
        } while (r.signum() == 0);
        return r;
    }

    private static BigInteger negateModN(BigInteger value, BigInteger n) {
        BigInteger v = value.mod(n);
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        return n.subtract(v);
    }

    private static BigInteger lagrangeCoefficientAtZero(int id, Set<Integer> participants, BigInteger mod) {
        if (participants == null || participants.isEmpty()) {
            throw new IllegalArgumentException("Participants set is empty");
        }
        BigInteger num = BigInteger.ONE;
        BigInteger den = BigInteger.ONE;
        BigInteger idBi = BigInteger.valueOf(id);
        for (int peerId : participants) {
            if (peerId == id) {
                continue;
            }
            BigInteger peerBi = BigInteger.valueOf(peerId);
            num = num.multiply(peerBi).mod(mod);
            BigInteger diff = peerBi.subtract(idBi).mod(mod);
            den = den.multiply(diff).mod(mod);
        }
        return num.multiply(den.modInverse(mod)).mod(mod);
    }

    private static BigInteger decodeSigned(BigInteger value, BigInteger n) {
        BigInteger half = n.shiftRight(1);
        return value.compareTo(half) > 0 ? value.subtract(n) : value;
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
            md.update(Secp256k1Curve.encodePoint(Xi));
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
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        for (int k : keys) {
            md.update(BigInteger.valueOf(k).toByteArray());
            md.update(Secp256k1Curve.encodePoint(map.get(k)));
        }
    }

    private static BigInteger deriveRefreshMask(String taskId, byte[] rid, int i, int j, ECPoint Yji, BigInteger yij) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(rid);
            md.update(BigInteger.valueOf(i).toByteArray());
            md.update(BigInteger.valueOf(j).toByteArray());
            ECPoint shared = Yji.multiply(yij).normalize();
            md.update(Secp256k1Curve.encodePoint(shared));
            return new BigInteger(1, md.digest()).mod(Secp256k1Curve.n());
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

    private BigInteger lagrangeCoefficient(int i, Set<Integer> participants, BigInteger n) {
        BigInteger result = BigInteger.ONE;
        for (int j : participants) {
            if (j == i) continue;
            BigInteger numerator = BigInteger.valueOf(-j).mod(n);
            BigInteger denominator = BigInteger.valueOf(i - j).modInverse(n);
            result = result.multiply(numerator).multiply(denominator).mod(n);
        }
        return result;
    }

    private ECPoint sumGamma(Gg20SignatureTask task) {
        ECPoint sum = Secp256k1Curve.G().getCurve().getInfinity();
        for (ECPoint p : task.gammaPoints.values()) {
            sum = sum.add(p).normalize();
        }
        return sum;
    }

    private BigInteger sumShares(Map<Integer, BigInteger> shares, BigInteger mod) {
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger v : shares.values()) {
            if (v == null) continue;
            sum = sum.add(v);
        }
        return sum.mod(mod);
    }

    private CompletableFuture<Void> broadcastGammaCommitment(Gg20SignatureTask task, ECPoint commitment, BigInteger gammaValue, BigInteger blinding) {
        byte[] ctx = buildSignContext(task.taskId, nodeId, task.messageHash, "GAMMA-COMMIT");
        EcChaumPedersenProof proof = EcChaumPedersenProof.create(gammaValue, blinding, commitment, ctx);
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("commit", bytesToHex(Secp256k1Curve.encodePoint(commitment)));
        data.put("proofA", bytesToHex(Secp256k1Curve.encodePoint(proof.A())));
        data.put("proofR", proof.r().toString(16));
        data.put("proofS", proof.s().toString(16));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_GAMMA_COMMIT, data));
    }

    private CompletableFuture<Void> broadcastGammaOpen(Gg20SignatureTask task, ECPoint gamma, BigInteger blinding) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("gamma", bytesToHex(Secp256k1Curve.encodePoint(gamma)));
        data.put("r", blinding.toString(16));
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_GAMMA_OPEN, data));
    }

    private CompletableFuture<Void> broadcastMtaKaInit(Gg20SignatureTask task) {
        MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (int participantId : task.participants) {
            if (participantId == nodeId) {
                continue;
            }
            byte[] mtaContext = buildMtaContext(task.taskId + ":KA", nodeId, participantId);
            MtAInitiatorMessage initiatorMessage = protocol.generateInitiatorMessage(task.k_i, task.zkSetup, mtaContext);
            task.mtaKaInitiatorMessages.put(participantId, initiatorMessage);

            Map<String, Object> data = new HashMap<>();
            data.put("taskId", task.taskId);
            data.put("initiatorId", nodeId);
            data.put("receiverId", participantId);
            data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
            data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
            data.put("initiatorMessage", CggmpDkgCodec.encodeMtAInitiatorMessage(initiatorMessage));
            futures.add(nodeService.sendMessage(participantId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_KA_INIT, data)));
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    private CompletableFuture<Void> broadcastMtaStInit(Gg20SignatureTask task) {
        MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (int participantId : task.participants) {
            if (participantId == nodeId) {
                continue;
            }
            byte[] mtaContext = buildMtaContext(task.taskId + ":ST", nodeId, participantId);
            MtAInitiatorMessage initiatorMessage = protocol.generateInitiatorMessage(task.kInv_i, task.zkSetup, mtaContext);
            task.mtaStInitiatorMessages.put(participantId, initiatorMessage);

            Map<String, Object> data = new HashMap<>();
            data.put("taskId", task.taskId);
            data.put("initiatorId", nodeId);
            data.put("receiverId", participantId);
            data.put("paillierPublicKey", CggmpDkgCodec.encodePaillierPublicKey(task.paillier.getPublicKeyInfo()));
            data.put("zkSetup", CggmpDkgCodec.encodeZkSetup(task.zkSetup));
            data.put("initiatorMessage", CggmpDkgCodec.encodeMtAInitiatorMessage(initiatorMessage));
            futures.add(nodeService.sendMessage(participantId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_ST_INIT, data)));
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    private BigInteger computeUShare(Gg20SignatureTask task, BigInteger mod) {
        BigInteger u = task.k_i.multiply(task.a_i).mod(mod);
        for (BigInteger alpha : task.kaAlphas.values()) {
            u = u.add(alpha);
        }
        for (BigInteger beta : task.kaBetas.values()) {
            u = u.add(beta);
        }
        return u.mod(mod);
    }

    private BigInteger computeSShare(Gg20SignatureTask task, BigInteger mod) {
        BigInteger s = task.kInv_i.multiply(task.t_i).mod(mod);
        for (BigInteger alpha : task.stAlphas.values()) {
            s = s.add(alpha);
        }
        for (BigInteger beta : task.stBetas.values()) {
            s = s.add(beta);
        }
        return s.mod(mod);
    }

    private CompletableFuture<Void> sendUShare(Gg20SignatureTask task, BigInteger u_i) {
        return sendUShare(task, u_i, randomNonZero(Secp256k1Curve.n()));
    }

    private CompletableFuture<Void> sendUShare(Gg20SignatureTask task, BigInteger u_i, BigInteger r) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("u", u_i.toString(16));
        data.put("r", r.toString(16));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_SHARE, data));
    }

    private CompletableFuture<Void> sendUCommit(Gg20SignatureTask task, BigInteger u_i, BigInteger r) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("commit", commitU(task.taskId, nodeId, task.messageHash, u_i, r));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_COMMIT, data));
    }

    private CompletableFuture<Void> broadcastUOpen(Gg20SignatureTask task, BigInteger u) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("u", u.toString(16));
        data.put("senderId", nodeId);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_U_OPEN, data));
    }

    private CompletableFuture<Void> sendSShare(Gg20SignatureTask task, BigInteger s_i) {
        Map<String, Object> data = new HashMap<>();
        data.put("taskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("s", s_i.toString(16));
        return nodeService.sendMessage(task.initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_S_SHARE, data));
    }

    private String commitU(String taskId, int senderId, byte[] messageHash, BigInteger u, BigInteger r) {
        int nLen = (Secp256k1Curve.n().bitLength() + 7) / 8;
        byte[] uBytes = BigIntegerUtils.toUnsignedBytes(u, nLen);
        byte[] rBytes = BigIntegerUtils.toUnsignedBytes(r, nLen);
        byte[] ctx = buildSignContext(taskId, senderId, messageHash, "U-COMMIT");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ctx);
            digest.update(uBytes);
            digest.update(rBytes);
            byte[] out = digest.digest();
            return bytesToHex(out);
        } catch (Exception e) {
            throw new RuntimeException("U commit hash failed", e);
        }
    }

    private static byte[] buildSignContext(String taskId, int senderId, byte[] messageHash, String stage) {
        String prefix = stage + ":" + taskId + ":" + senderId + ":";
        byte[] p = prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (messageHash == null) {
            return p;
        }
        byte[] out = new byte[p.length + messageHash.length];
        System.arraycopy(p, 0, out, 0, p.length);
        System.arraycopy(messageHash, 0, out, p.length, messageHash.length);
        return out;
    }
    private static final class SignatureBundle {
        private final String signatureBase64;
        private final boolean verified;

        private SignatureBundle(String signatureBase64, boolean verified) {
            this.signatureBase64 = signatureBase64;
            this.verified = verified;
        }
    }


    private CompletableFuture<KeyShare> loadKeyShareByGroupPublicKey(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKey(nodeId, groupPublicKey);
    }

    private ECPoint decodeECPoint(byte[] encoded) {
        return Secp256k1Curve.decodePoint(encoded);
    }

    private CGGMP createCachedDkgInstance() throws Exception {
        if (dkgPaillier == null || dkgZkSetup == null || dkgPedersen == null) {
            synchronized (dkgCacheLock) {
                if (dkgPaillier == null) {
                    dkgPaillier = new PaillierEncryption();
                }
                if (dkgZkSetup == null) {
                    dkgZkSetup = ZKSetup.generate(dkgPaillier.getBitLength());
                }
                if (dkgPedersen == null) {
                    dkgPedersen = new PedersenCommitment(Constants.CURVE_NAME);
                }
            }
        }
        return new CGGMP(threshold, nodesCount, nodeId, Constants.CURVE_NAME, dkgPaillier, dkgZkSetup, dkgPedersen);
    }

    private Object maybeCompressDkgPayload(MessageType type, Object data) {
        return data;
    }

    private Object maybeDecompressDkgPayload(MessageType type, byte[] bytes) {
        return null;
    }

    private boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return false;
        }
        BigInteger q = Secp256k1Curve.n();
        return publicKey.n.compareTo(q.pow(8)) >= 0;
    }

    private boolean ensurePeerKeyConsistency(Gg20SignatureTask task, int peerId, PaillierEncryption.PublicKey publicKey, ZKSetup zkSetup) {
        PaillierEncryption.PublicKey existingKey = task.peerPaillierKeys.putIfAbsent(peerId, publicKey);
        if (existingKey != null && !paillierPublicKeyEquals(existingKey, publicKey)) {
            return false;
        }
        ZKSetup existingZk = task.peerZkSetups.putIfAbsent(peerId, zkSetup);
        if (existingZk != null && !existingZk.equals(zkSetup)) {
            return false;
        }
        return true;
    }

    private boolean paillierPublicKeyEquals(PaillierEncryption.PublicKey a, PaillierEncryption.PublicKey b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return a.n.equals(b.n) && a.nSquared.equals(b.nSquared) && a.g.equals(b.g) && a.bitLength == b.bitLength;
    }

    private void failSignatureTask(Gg20SignatureTask task, String reason) {
        if (task == null || task.isCompleted() || task.isFailed()) {
            return;
        }
        task.fail(reason);
        signatureInProgress.set(false);
    }

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, message.data instanceof Map ? ((Map<?, ?>) message.data).get("taskId") : "N/A");
        Executor executor = ThreadPoolUtil.getSingleThreadPool();
        if (message.type == MessageType.CGGMP_DKG_ROUND2
                || message.type == MessageType.CGGMP_DKG_ROUND2_BROAD
                || message.type == MessageType.CGGMP_DKG_ROUND2_BATCH) {
            executor = dkgExecutorService;
        }
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
                    case CGGMP_DKG_INIT:
                        handleCggmpDkgInit(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1:
                        handleCggmpDkgRound1(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1_ECHO:
                        handleCggmpDkgRound1Echo(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2:
                        handleCggmpDkgRound2(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BROAD:
                        handleCggmpDkgRound2Broad(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BATCH:
                        handleCggmpDkgRound2Batch(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND3:
                        handleCggmpDkgRound3(senderId, data);
                        break;
                    case CGGMP_DKG_COMPLAINT:
                        handleCggmpDkgComplaint(senderId, data);
                        break;
                    case CGGMP_DKG_EXCLUDE:
                        handleCggmpDkgExclude(senderId, data);
                        break;
                    case GG20_SIGN_INIT:
                        handleCggmpSignOfflineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_OFFLINE_INIT:
                        handleCggmpSignOfflineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_ONLINE_INIT:
                        handleCggmpSignOnlineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_OFFLINE_READY:
                        handleCggmpSignOfflineReady(senderId, data);
                        break;
                    case CGGMP_SIGN_COMPLAINT:
                        handleCggmpSignComplaint(senderId, data);
                        break;
                    case CGGMP_SIGN_EXCLUDE:
                        handleCggmpSignExclude(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R1:
                        handlePresignR1(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R2:
                        handlePresignR2(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R3:
                        handlePresignR3(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_COMMIT:
                        handleCggmpSignGammaCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_OPEN:
                        handleCggmpSignGammaOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_INIT:
                        handleCggmpSignMtaKaInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_RESPONSE:
                        handleCggmpSignMtaKaResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_U_COMMIT:
                        handleCggmpSignUCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_U_SHARE:
                        handleCggmpSignUShare(senderId, data);
                        break;
                    case CGGMP_SIGN_U_OPEN:
                        handleCggmpSignUOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_INIT:
                        handleCggmpSignMtaStInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_RESPONSE:
                        handleCggmpSignMtaStResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_S_SHARE:
                        handleCggmpSignSShare(senderId, data);
                        break;
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

    private void handleCggmpSignOfflineInit(int senderId, Object data) {
        if (data instanceof Map) {
            Map<?, ?> dataMap = (Map<?, ?>) data;
            String signatureTaskId = (String) dataMap.get("signatureTaskId");
            String groupPublicKey = (String) dataMap.get("groupPublicKey");
            String msg = (String) dataMap.get("message");
            Integer initiatorId = null;
            Object initiatorValue = dataMap.get("initiatorId");
            if (initiatorValue instanceof Number) {
                initiatorId = ((Number) initiatorValue).intValue();
            }
            List<Integer> participants = null;
            Object participantsValue = dataMap.get("participants");
            if (participantsValue instanceof List<?> list) {
                participants = new ArrayList<>();
                for (Object v : list) {
                    if (v instanceof Number n) {
                        participants.add(n.intValue());
                    }
                }
            }
            if (signatureTaskId != null && msg != null && groupPublicKey != null) {
                if (!signatureTasks.containsKey(signatureTaskId)) {
                    int resolvedInitiatorId = initiatorId != null ? initiatorId : senderId;
                    Set<Integer> participantsSet = participants == null ? null : new LinkedHashSet<>(participants);
                    createSignatureTaskWithIdAndGroupKey(signatureTaskId, groupPublicKey, msg, resolvedInitiatorId, participantsSet);
                    logger.info("Created CGGMP signature task from OFFLINE_INIT: {}", signatureTaskId);
                    CompletableFuture.runAsync(() -> {
                        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
                        if (task == null) {
                            return;
                        }
                        if (!task.participants.contains(nodeId)) {
                            logger.info("Node {} not selected for CGGMP signature task {}, participants={}, skipping", nodeId, signatureTaskId, task.participants);
                            return;
                        }
                        task.start();
                        initSignatureContext(task);
                        runOfflinePhase(task).exceptionally(ex -> {
                            logger.error("Failed offline phase for signature task {}: {}", signatureTaskId, ex.getMessage());
                            return null;
                        });
                    }, ThreadPoolUtil.getIoThreadPool());
                } else {
                    logger.info("Signature task {} already exists, ignoring OFFLINE_INIT", signatureTaskId);
                }
            } else {
                logger.warn("Invalid OFFLINE_INIT payload from node {}", senderId);
            }
        }
    }

    private void handleCggmpSignOnlineInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object hashValue = dataMap.get("messageHash");
        if (signatureTaskId == null || !(hashValue instanceof String hashString)) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        task.messageHash = Base64.getDecoder().decode(hashString);
        if (!task.participants.contains(nodeId)) {
            return;
        }
        runOnlinePhase(task).exceptionally(ex -> {
            logger.error("Failed online phase for signature task {}: {}", signatureTaskId, ex.getMessage());
            return null;
        });
    }

    private void handlePresignR1(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String kHex = (String) dataMap.get("K");
        String gHex = (String) dataMap.get("G");
        String yHex = (String) dataMap.get("Y");
        String a1Hex = (String) dataMap.get("A1");
        String a2Hex = (String) dataMap.get("A2");
        String b1Hex = (String) dataMap.get("B1");
        String b2Hex = (String) dataMap.get("B2");
        Map<?, ?> encElgKMap = (Map<?, ?>) dataMap.get("encElgProofK");
        Map<?, ?> encElgGMap = (Map<?, ?>) dataMap.get("encElgProofG");
        Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
        Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
        if (signatureTaskId == null || senderValue == null || kHex == null || gHex == null
                || yHex == null || a1Hex == null || a2Hex == null || b1Hex == null || b2Hex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            return;
        }
        if (pkMap == null || zkMap == null) {
            return;
        }
        BigInteger K = new BigInteger(kHex, 16);
        BigInteger G = new BigInteger(gHex, 16);
        ECPoint Y = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(yHex));
        ECPoint A1 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(a1Hex));
        ECPoint A2 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(a2Hex));
        ECPoint B1 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(b1Hex));
        ECPoint B2 = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(b2Hex));
        PiEncElgProof encElgK = encElgKMap == null ? null : CggmpDkgCodec.decodePiEncElgProof(encElgKMap);
        PiEncElgProof encElgG = encElgGMap == null ? null : CggmpDkgCodec.decodePiEncElgProof(encElgGMap);
        PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
        ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
        if (!ensurePeerKeyConsistency(task, senderId, publicKey, zkSetup)) {
            broadcastComplaint(task, senderId, "Inconsistent Paillier key/zkSetup (presign R1)", Map.of("paillierPublicKey", pkMap, "zkSetup", zkMap)).join();
            failSignatureTask(task, "Inconsistent Paillier key/zkSetup (presign R1)");
            return;
        }
        byte[] ctxK = buildPresignContext(task.taskId, senderId, "R1K");
        PresignProofs.EncElgVerifyResult encElgKResult = PresignProofs.verifyEncElgProofDetailed(
                encElgK, publicKey, zkSetup, Secp256k1Curve.G(), A1, Y, A2, K, proofEpsBits, ctxK);
        if (!encElgKResult.ok()) {
            logger.warn("Invalid PiEncElg proof (K) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgKResult.eq1(), encElgKResult.eq2(), encElgKResult.eq3(), encElgKResult.eq4(), encElgKResult.z1InRange());
            broadcastComplaint(task, senderId, "Invalid PiEncElg proof (K)", Map.of("K", kHex)).join();
            failSignatureTask(task, "Invalid PiEncElg proof (K)");
            return;
        }
        byte[] ctxG = buildPresignContext(task.taskId, senderId, "R1G");
        PresignProofs.EncElgVerifyResult encElgGResult = PresignProofs.verifyEncElgProofDetailed(
                encElgG, publicKey, zkSetup, Secp256k1Curve.G(), B1, Y, B2, G, proofEpsBits, ctxG);
        if (!encElgGResult.ok()) {
            logger.warn("Invalid PiEncElg proof (G) from node {}: eq1={}, eq2={}, eq3={}, eq4={}, z1InRange={}",
                    senderId, encElgGResult.eq1(), encElgGResult.eq2(), encElgGResult.eq3(), encElgGResult.eq4(), encElgGResult.z1InRange());
            broadcastComplaint(task, senderId, "Invalid PiEncElg proof (G)", Map.of("G", gHex)).join();
            failSignatureTask(task, "Invalid PiEncElg proof (G)");
            return;
        }
        task.presignK.put(senderId, K);
        task.presignG.put(senderId, G);
        task.presignY.put(senderId, Y);
        task.presignA1.put(senderId, A1);
        task.presignA2.put(senderId, A2);
        task.presignB1.put(senderId, B1);
        task.presignB2.put(senderId, B2);
        if (task.presignR1Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.gammaCommitLatch.getCount() > 0) {
            task.gammaCommitLatch.countDown();
        }
    }

    private void handlePresignR2(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String gammaHex = (String) dataMap.get("Gamma");
        if (signatureTaskId == null || senderValue == null || gammaHex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            logger.info("Skip CGGMP_PRESIGN_R2 for task {} on node {} (not a participant, participants={})",
                    task.taskId, nodeId, task.participants);
            return;
        }
        Map<?, ?> dMap = (Map<?, ?>) dataMap.get("D");
        Map<?, ?> dhMap = (Map<?, ?>) dataMap.get("Dhat");
        Map<?, ?> fMap = (Map<?, ?>) dataMap.get("F");
        Map<?, ?> fhMap = (Map<?, ?>) dataMap.get("Fhat");
        Map<?, ?> affGMap = (Map<?, ?>) dataMap.get("affGProofs");
        Map<?, ?> affGhatMap = (Map<?, ?>) dataMap.get("affGProofsHat");
        Map<?, ?> logProofMap = (Map<?, ?>) dataMap.get("logProof");
        String xHex = (String) dataMap.get("X");
        if (dMap == null || dhMap == null || fMap == null || fhMap == null) {
            return;
        }
        ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
        task.presignGamma.put(senderId, Gamma);
        Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> Dhat = decodeBigIntegerMap(dhMap);
        Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
        Map<Integer, BigInteger> Fhat = decodeBigIntegerMap(fhMap);
        BigInteger dForNode = D.get(nodeId);
        BigInteger dhatForNode = Dhat.get(nodeId);
        logger.info("Presign R2 received for task {} from {}: D keys={}, Dhat keys={}, D[node]={}, Dhat[node]={}",
                task.taskId,
                senderId,
                D.keySet(),
                Dhat.keySet(),
                dForNode == null ? null : dForNode.toString(16),
                dhatForNode == null ? null : dhatForNode.toString(16));
        PiLogProof logProof = logProofMap == null ? null : CggmpDkgCodec.decodePiLogProof(logProofMap);
        byte[] ctx = buildPresignContext(task.taskId, senderId, "R2");
        ECPoint Y = task.presignY.get(senderId);
        ECPoint B1 = task.presignB1.get(senderId);
        ECPoint B2 = task.presignB2.get(senderId);
        if (Y == null || B1 == null || B2 == null) {
            broadcastComplaint(task, senderId, "Missing presign R1 commitments for PiLog proof", Map.of("Gamma", gammaHex)).join();
            failSignatureTask(task, "Missing presign R1 commitments for PiLog proof");
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1Curve.G(), Secp256k1Curve.G(), Gamma, Y, B1, B2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Gamma", gammaHex);
            ev.put("D", dMap);
            ev.put("F", fMap);
            broadcastComplaint(task, senderId, "Invalid PiLog proof (R2)", ev).join();
            failSignatureTask(task, "Invalid presign R2 proof");
            return;
        }

        if (affGMap != null && affGhatMap != null && xHex != null) {
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(affGMap);
            Map<Integer, PiAffGProof> proofsHat = decodeAffGProofMap(affGhatMap);
            PiAffGProof proof = proofs.get(nodeId);
            PiAffGProof proofHat = proofsHat.get(nodeId);
            BigInteger D_ji = D.get(nodeId);
            BigInteger F_ji = F.get(nodeId);
            BigInteger Dhat_ji = Dhat.get(nodeId);
            BigInteger Fhat_ji = Fhat.get(nodeId);
            BigInteger K_self = task.presignK.get(nodeId);
            PaillierEncryption.PublicKey N0 = task.paillier.getPublicKeyInfo();
            PaillierEncryption.PublicKey N1 = task.peerPaillierKeys.get(senderId);
            ECPoint X_i = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            if (K_self != null && D_ji != null && F_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        Gamma,
                        N0.n,
                        N1.n,
                        K_self,
                        D_ji,
                        F_ji,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "R2")
                );
                if (!affGResult.ok()) {
                    logger.warn("Invalid PiAffG proof from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGResult.index(), affGResult.eq1(), affGResult.eq2(),
                            affGResult.eq3(), affGResult.zInRange(), affGResult.zPrimeInRange());
                    broadcastComplaint(task, senderId, "Invalid PiAffG proof", Map.of("D", dMap, "F", fMap)).join();
                    failSignatureTask(task, "Invalid presign R2 affG proof");
                    return;
                }
            }
            if (K_self != null && Dhat_ji != null && Fhat_ji != null && N1 != null) {
                PresignProofs.AffGVerifyResult affGHatResult = PresignProofs.verifyAffGProofDetailedNegY(
                        proofHat,
                        Secp256k1Curve.G(),
                        X_i,
                        N0.n,
                        N1.n,
                        K_self,
                        Dhat_ji,
                        Fhat_ji,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "R2H")
                );
                if (!affGHatResult.ok()) {
                    logger.warn("Invalid PiAffG proof (hat) from node {}: index={}, eq1={}, eq2={}, eq3={}, zInRange={}, zPrimeInRange={}",
                            senderId, affGHatResult.index(), affGHatResult.eq1(), affGHatResult.eq2(),
                            affGHatResult.eq3(), affGHatResult.zInRange(), affGHatResult.zPrimeInRange());
                    broadcastComplaint(task, senderId, "Invalid PiAffG proof (hat)", Map.of("Dhat", dhMap, "Fhat", fhMap)).join();
                    failSignatureTask(task, "Invalid presign R2 affG hat proof");
                    return;
                }
            }
        }
        if (!D.containsKey(nodeId) || !Dhat.containsKey(nodeId)) {
            logger.warn("Presign R2 missing payload for receiver {} from sender {} (D or Dhat not found)", nodeId, senderId);
            return;
        }
        task.presignD.put(senderId, D.get(nodeId));
        task.presignDhat.put(senderId, Dhat.get(nodeId));
        if (F.containsKey(nodeId)) task.presignF.put(senderId, F.get(nodeId));
        if (Fhat.containsKey(nodeId)) task.presignFhat.put(senderId, Fhat.get(nodeId));
        if (task.presignR2Received.putIfAbsent(senderId, Boolean.TRUE) == null
                && task.presignR2Latch.getCount() > 0) {
            task.presignR2Latch.countDown();
        }
    }

    private void handlePresignR3(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        String deltaHex = (String) dataMap.get("delta");
        String deltaPointHex = (String) dataMap.get("Delta");
        String sPointHex = (String) dataMap.get("S");
        Map<?, ?> logProofMap = (Map<?, ?>) dataMap.get("logProof");
        if (signatureTaskId == null || senderValue == null || deltaHex == null || deltaPointHex == null || sPointHex == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        if (!task.participants.contains(nodeId)) {
            return;
        }
        PiLogProof logProof = logProofMap == null ? null : CggmpDkgCodec.decodePiLogProof(logProofMap);
        ECPoint Delta = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(deltaPointHex));
        ECPoint S = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(sPointHex));
        byte[] ctx = buildPresignContext(task.taskId, senderId, "R3");
        ECPoint Gamma = sumPresignGamma(task);
        ECPoint Y = task.presignY.get(senderId);
        ECPoint A1 = task.presignA1.get(senderId);
        ECPoint A2 = task.presignA2.get(senderId);
        if (Y == null || A1 == null || A2 == null) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Delta", deltaPointHex);
            ev.put("S", sPointHex);
            broadcastComplaint(task, senderId, "Missing presign R1 commitments for PiLog proof (R3)", ev).join();
            failSignatureTask(task, "Invalid presign R3 proof");
            return;
        }
        if (!PresignProofs.verifyLogProof(logProof, Secp256k1Curve.G(), Gamma, Delta, Y, A1, A2, ctx)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("Delta", deltaPointHex);
            ev.put("S", sPointHex);
            broadcastComplaint(task, senderId, "Invalid PiLog proof (R3)", ev).join();
            failSignatureTask(task, "Invalid presign R3 proof");
            return;
        }
        task.presignDelta.put(senderId, new BigInteger(deltaHex, 16));
        task.presignDeltaPoint.put(senderId, Delta);
        task.presignSPoint.put(senderId, S);
        if (task.offlineDoneLatch.getCount() > 0) {
            task.offlineDoneLatch.countDown();
        }
    }

    private void handleCggmpSignOfflineReady(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Number senderValue = (Number) dataMap.get("senderId");
        if (signatureTaskId == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        markOfflineReady(task, senderNodeId);
    }

    private void handleCggmpSignComplaint(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        String reason = (String) dataMap.get("reason");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null || reason == null) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received complaint for task {} from node {} against {}: {}", signatureTaskId, senderId, offenderId, reason);
        logComplaintToFile(signatureTaskId, senderId, offenderId, reason, dataMap.get("evidence"));
        boolean evidenceOk = true;
        boolean hasProofEvidence = false;
        if (dataMap.get("evidence") instanceof Map<?, ?> ev) {
            hasProofEvidence = ev.containsKey("piDecProof") || ev.containsKey("affGProofs") || ev.containsKey("affGProofsHat");
            if (hasProofEvidence) {
                evidenceOk = verifyDecEvidence(task, senderId, ev) && verifyAffGEvidence(task, senderId, ev);
            }
        }
        if (hasProofEvidence && !evidenceOk) {
            String invalidReason = "Invalid proof evidence from sender " + senderId;
            logger.warn("Complaint evidence invalid; treating sender {} as offender", senderId);
            if (nodeId == task.initiatorId) {
                attemptExcludeAndRestart(task, senderId, invalidReason);
            } else {
                failSignatureTask(task, invalidReason);
            }
            return;
        }
        if (nodeId == task.initiatorId && offenderId != null) {
            attemptExcludeAndRestart(task, offenderId, reason);
        } else {
            failSignatureTask(task, "Complaint: " + reason);
        }
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason) {
        return broadcastComplaint(task, offenderId, reason, null);
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, int offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data));
    }

    private CompletableFuture<Void> broadcastComplaint(Gg20SignatureTask task, Integer offenderId, String reason, Map<String, Object> evidence) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        if (offenderId != null) {
            data.put("offenderId", offenderId);
        }
        data.put("reason", reason);
        if (evidence != null && !evidence.isEmpty()) {
            data.put("evidence", evidence);
        }
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_COMPLAINT, data));
    }

    private Map<String, Object> buildDecEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i, BigInteger delta_i) {
        try {
            BigInteger K = task.presignK.get(nodeId);
            if (K == null) return null;
            BigInteger D = computePresignDForSelf(task, task.presignD, task.presignFOutgoing);
            if (D == null) return null;
            ECPoint Gamma = task.presignGamma.get(nodeId);
            if (Gamma == null) {
                Gamma = Secp256k1Curve.multiply(Secp256k1Curve.G(), gamma_i);
            }
            ECPoint S = Secp256k1Curve.multiply(Secp256k1Curve.G(), delta_i);
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, gamma_i).multiply(D).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, delta_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Secp256k1Curve.G(),
                    Gamma,
                    S,
                    task.paillier.getPublicKeyInfo().n,
                    K,
                    D,
                    gamma_i,
                    delta_i,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "DEC")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpDkgCodec.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(D));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(S)));
            Map<String, Object> affg = buildAffGEvidenceDelta(task, gamma_i, Gamma);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec delta evidence: {}", e.getMessage());
            return null;
        }
    }

    private Map<String, Object> buildDecEvidenceChi(Gg20SignatureTask task, BigInteger x_i, BigInteger chi_i) {
        try {
            BigInteger K = task.presignK.get(nodeId);
            if (K == null) return null;
            BigInteger Dhat = computePresignDForSelf(task, task.presignDhat, task.presignFhatOutgoing);
            if (Dhat == null) return null;
            ECPoint Gamma = sumPresignGamma(task);
            ECPoint X_i = Secp256k1Curve.multiply(Secp256k1Curve.G(), x_i);
            ECPoint S = Gamma.multiply(chi_i).normalize();
            BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
            BigInteger c = task.paillier.getPublicKeyInfo().multiply(K, x_i).multiply(Dhat).mod(nSquared);
            BigInteger rho = task.paillier.recoverRandomizer(c, chi_i);
            PiDecProof proof = PresignProofs.createDecProof(
                    Gamma,
                    X_i,
                    S,
                    task.paillier.getPublicKeyInfo().n,
                    K,
                    Dhat,
                    x_i,
                    chi_i,
                    rho,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "DECH")
            );
            Map<String, Object> ev = new HashMap<>();
            ev.put("piDecProof", CggmpDkgCodec.encodePiDecProof(proof));
            ev.put("K", HexUtils.toHex(K));
            ev.put("D", HexUtils.toHex(Dhat));
            ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
            ev.put("X", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(X_i)));
            ev.put("S", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(S)));
            Map<String, Object> affg = buildAffGEvidenceChi(task, x_i, X_i);
            if (affg != null && !affg.isEmpty()) {
                ev.putAll(affg);
            }
            return ev;
        } catch (Exception e) {
            logger.warn("Failed to build PiDec chi evidence: {}", e.getMessage());
            return null;
        }
    }

    private BigInteger computePresignDForSelf(Gg20SignatureTask task,
                                              Map<Integer, BigInteger> incomingD,
                                              Map<Integer, BigInteger> outgoingF) {
        BigInteger nSquared = task.paillier.getPublicKeyInfo().nSquared;
        BigInteger acc = BigInteger.ONE;
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            BigInteger d = incomingD.get(peerId);
            BigInteger f = outgoingF.get(peerId);
            if (d == null || f == null) {
                return null;
            }
            acc = acc.multiply(d).mod(nSquared);
            acc = acc.multiply(f).mod(nSquared);
        }
        return acc;
    }

    private boolean verifyDecEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        Object proofObj = evidence.get("piDecProof");
        if (!(proofObj instanceof Map<?, ?> proofMap)) {
            return false;
        }
        try {
            PiDecProof proof = CggmpDkgCodec.decodePiDecProof(proofMap);
            String kHex = (String) evidence.get("K");
            String dHex = (String) evidence.get("D");
            String gammaHex = (String) evidence.get("Gamma");
            String xHex = (String) evidence.get("X");
            String sHex = (String) evidence.get("S");
            if (kHex == null || dHex == null || gammaHex == null || sHex == null) {
                return false;
            }
            BigInteger K = HexUtils.fromHex(kHex);
            BigInteger D = HexUtils.fromHex(dHex);
            ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            ECPoint S = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(sHex));
            ECPoint X = xHex == null
                    ? Gamma
                    : Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderId);
            if (pk == null) {
                return false;
            }
            if (!verifyDecEvidenceConsistency(task, senderId, D, evidence)) {
                return false;
            }
            String ctxTag = xHex == null ? "DEC" : "DECH";
            boolean ok = PresignProofs.verifyDecProof(
                    proof,
                    xHex == null ? Secp256k1Curve.G() : Gamma,
                    X,
                    S,
                    pk.n,
                    K,
                    D,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, senderId, ctxTag)
            );
            if (!ok) {
                logger.warn("Invalid PiDec proof evidence from node {}", senderId);
            }
            return ok;
        } catch (Exception e) {
            logger.warn("Failed to verify PiDec evidence: {}", e.getMessage());
            return false;
        }
    }

    private boolean verifyDecEvidenceConsistency(Gg20SignatureTask task,
                                                 int senderId,
                                                 BigInteger claimedD,
                                                 Map<?, ?> evidence) {
        if (evidence.get("DMap") instanceof Map<?, ?> dMap
                && evidence.get("FMap") instanceof Map<?, ?> fMap) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dMap, fMap);
        }
        if (evidence.get("DhatMap") instanceof Map<?, ?> dhMap
                && evidence.get("FhatMap") instanceof Map<?, ?> fhMap) {
            return verifyDecEvidenceConsistencyMap(task, senderId, claimedD, dhMap, fhMap);
        }
        return true;
    }

    private boolean verifyDecEvidenceConsistencyMap(Gg20SignatureTask task,
                                                    int senderId,
                                                    BigInteger claimedD,
                                                    Map<?, ?> dMap,
                                                    Map<?, ?> fMap) {
        Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
        Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
        PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(senderId);
        if (pk == null) {
            return false;
        }
        if (!allPeersPresent(task, senderId, D, F)) {
            return false;
        }
        BigInteger calc = BigInteger.ONE;
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            BigInteger d = D.get(peerId);
            BigInteger f = F.get(peerId);
            if (d == null || f == null) {
                return false;
            }
            calc = calc.multiply(d).mod(pk.nSquared);
            calc = calc.multiply(f).mod(pk.nSquared);
        }
        return calc.equals(claimedD);
    }

    private Map<String, Object> buildAffGEvidenceDelta(Gg20SignatureTask task, BigInteger gamma_i, ECPoint Gamma) {
        Map<Integer, PiAffGProof> proofs = new HashMap<>();
        Map<Integer, BigInteger> D = new HashMap<>();
        Map<Integer, BigInteger> F = new HashMap<>();
        BigInteger curveOrder = Secp256k1Curve.n();
        PaillierEncryption.PublicKey senderPk = task.paillier.getPublicKeyInfo();
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
            BigInteger K_peer = task.presignK.get(peerId);
            BigInteger beta = task.presignBeta.get(peerId);
            BigInteger rho = task.presignRho.get(peerId);
            BigInteger mu = task.presignMu.get(peerId);
            if (pk == null || K_peer == null || beta == null || rho == null || mu == null) {
                continue;
            }
            BigInteger encNegBeta = pk.encryptWithRandom(negateModN(beta, pk.n), rho);
            BigInteger d = pk.multiply(K_peer, gamma_i).multiply(encNegBeta).mod(pk.nSquared);
            BigInteger f = senderPk.encryptWithRandom(beta, mu);
            PiAffGProof proof = PresignProofs.createAffGProofNegY(
                    Secp256k1Curve.G(),
                    Gamma,
                    pk.n,
                    senderPk.n,
                    K_peer,
                    d,
                    f,
                    gamma_i,
                    beta,
                    rho,
                    mu,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "AFFG")
            );
            proofs.put(peerId, proof);
            D.put(peerId, d);
            F.put(peerId, f);
        }
        if (proofs.isEmpty()) {
            return null;
        }
        Map<String, Object> ev = new HashMap<>();
        ev.put("affGProofs", encodeAffGProofMap(proofs));
        ev.put("DMap", encodeBigIntegerMap(D));
        ev.put("FMap", encodeBigIntegerMap(F));
        ev.put("Gamma", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(Gamma)));
        return ev;
    }

    private Map<String, Object> buildAffGEvidenceChi(Gg20SignatureTask task, BigInteger x_i, ECPoint X_i) {
        Map<Integer, PiAffGProof> proofs = new HashMap<>();
        Map<Integer, BigInteger> Dhat = new HashMap<>();
        Map<Integer, BigInteger> Fhat = new HashMap<>();
        BigInteger curveOrder = Secp256k1Curve.n();
        PaillierEncryption.PublicKey senderPk = task.paillier.getPublicKeyInfo();
        for (int peerId : task.participants) {
            if (peerId == nodeId) {
                continue;
            }
            PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
            BigInteger K_peer = task.presignK.get(peerId);
            BigInteger betaHat = task.presignBetaHat.get(peerId);
            BigInteger rhoHat = task.presignRhoHat.get(peerId);
            BigInteger muHat = task.presignMuHat.get(peerId);
            if (pk == null || K_peer == null || betaHat == null || rhoHat == null || muHat == null) {
                continue;
            }
            BigInteger encNegBeta = pk.encryptWithRandom(negateModN(betaHat, pk.n), rhoHat);
            BigInteger d = pk.multiply(K_peer, x_i).multiply(encNegBeta).mod(pk.nSquared);
            BigInteger f = senderPk.encryptWithRandom(betaHat, muHat);
            PiAffGProof proof = PresignProofs.createAffGProofNegY(
                    Secp256k1Curve.G(),
                    X_i,
                    pk.n,
                    senderPk.n,
                    K_peer,
                    d,
                    f,
                    x_i,
                    betaHat,
                    rhoHat,
                    muHat,
                    proofKappa,
                    proofEpsBits,
                    buildPresignContext(task.taskId, nodeId, "AFFGH")
            );
            proofs.put(peerId, proof);
            Dhat.put(peerId, d);
            Fhat.put(peerId, f);
        }
        if (proofs.isEmpty()) {
            return null;
        }
        Map<String, Object> ev = new HashMap<>();
        ev.put("affGProofsHat", encodeAffGProofMap(proofs));
        ev.put("DhatMap", encodeBigIntegerMap(Dhat));
        ev.put("FhatMap", encodeBigIntegerMap(Fhat));
        ev.put("X", HexUtils.bytesToHex(Secp256k1Curve.encodePoint(X_i)));
        return ev;
    }

    private boolean verifyAffGEvidence(Gg20SignatureTask task, int senderId, Map<?, ?> evidence) {
        boolean hasAffG = evidence.containsKey("affGProofs") || evidence.containsKey("affGProofsHat");
        if (!hasAffG) {
            return true;
        }
        PaillierEncryption.PublicKey senderPk = task.peerPaillierKeys.get(senderId);
        if (senderPk == null) {
            return false;
        }
        if (evidence.get("affGProofs") instanceof Map<?, ?> proofMap
                && evidence.get("DMap") instanceof Map<?, ?> dMap
                && evidence.get("FMap") instanceof Map<?, ?> fMap) {
            String gammaHex = (String) evidence.get("Gamma");
            if (gammaHex == null) {
                return false;
            }
            ECPoint Gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(proofMap);
            Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
            Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
            if (!allPeersPresent(task, senderId, proofs, D, F)) {
                return false;
            }
            for (Map.Entry<Integer, PiAffGProof> e : proofs.entrySet()) {
                int peerId = e.getKey();
                PiAffGProof proof = e.getValue();
                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                BigInteger K_peer = task.presignK.get(peerId);
                BigInteger d = D.get(peerId);
                BigInteger f = F.get(peerId);
                if (pk == null || K_peer == null || d == null || f == null) {
                    return false;
                }
                boolean ok = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        Gamma,
                        pk.n,
                        senderPk.n,
                        K_peer,
                        d,
                        f,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "AFFG")
                ).ok();
                if (!ok) {
                    return false;
                }
            }
        }
        if (evidence.get("affGProofsHat") instanceof Map<?, ?> proofMap
                && evidence.get("DhatMap") instanceof Map<?, ?> dMap
                && evidence.get("FhatMap") instanceof Map<?, ?> fMap) {
            String xHex = (String) evidence.get("X");
            if (xHex == null) {
                return false;
            }
            ECPoint X = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(xHex));
            Map<Integer, PiAffGProof> proofs = decodeAffGProofMap(proofMap);
            Map<Integer, BigInteger> D = decodeBigIntegerMap(dMap);
            Map<Integer, BigInteger> F = decodeBigIntegerMap(fMap);
            if (!allPeersPresent(task, senderId, proofs, D, F)) {
                return false;
            }
            for (Map.Entry<Integer, PiAffGProof> e : proofs.entrySet()) {
                int peerId = e.getKey();
                PiAffGProof proof = e.getValue();
                PaillierEncryption.PublicKey pk = task.peerPaillierKeys.get(peerId);
                BigInteger K_peer = task.presignK.get(peerId);
                BigInteger d = D.get(peerId);
                BigInteger f = F.get(peerId);
                if (pk == null || K_peer == null || d == null || f == null) {
                    return false;
                }
                boolean ok = PresignProofs.verifyAffGProofDetailedNegY(
                        proof,
                        Secp256k1Curve.G(),
                        X,
                        pk.n,
                        senderPk.n,
                        K_peer,
                        d,
                        f,
                        proofKappa,
                        proofEpsBits,
                        buildPresignContext(task.taskId, senderId, "AFFGH")
                ).ok();
                if (!ok) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean allPeersPresent(Gg20SignatureTask task,
                                    int senderId,
                                    Map<Integer, ?> proofs,
                                    Map<Integer, ?> dMap,
                                    Map<Integer, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!proofs.containsKey(peerId) || !dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return false;
            }
        }
        return true;
    }

    private boolean allPeersPresent(Gg20SignatureTask task,
                                    int senderId,
                                    Map<Integer, ?> dMap,
                                    Map<Integer, ?> fMap) {
        for (int peerId : task.participants) {
            if (peerId == senderId) {
                continue;
            }
            if (!dMap.containsKey(peerId) || !fMap.containsKey(peerId)) {
                return false;
            }
        }
        return true;
    }

    private void logComplaintToFile(String taskId, int senderId, Integer offenderId, String reason, Object evidence) {
        try {
            java.nio.file.Path dir = java.nio.file.Paths.get("logs");
            java.nio.file.Files.createDirectories(dir);
            java.nio.file.Path file = dir.resolve("complaints.jsonl");
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"ts\":").append(System.currentTimeMillis()).append(',');
            sb.append("\"taskId\":\"").append(escapeJson(taskId)).append("\",");
            sb.append("\"senderId\":").append(senderId).append(',');
            sb.append("\"offenderId\":").append(offenderId == null ? "null" : offenderId).append(',');
            sb.append("\"reason\":\"").append(escapeJson(reason)).append("\"");
            if (evidence != null) {
                sb.append(",\"evidence\":\"").append(escapeJson(String.valueOf(evidence))).append("\"");
            }
            sb.append('}');
            String line = sb.append(System.lineSeparator()).toString();
            java.nio.file.Files.writeString(file, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        } catch (Exception e) {
            logger.warn("Failed to log complaint to file: {}", e.getMessage());
        }
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private void handleCggmpSignExclude(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String signatureTaskId = (String) dataMap.get("signatureTaskId");
        Object offenderValue = dataMap.get("offenderId");
        if (signatureTaskId == null) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(signatureTaskId);
        if (task == null) {
            return;
        }
        Integer offenderId = offenderValue instanceof Number n ? n.intValue() : null;
        logger.warn("Received exclude for task {} from node {} (offender {})", signatureTaskId, senderId, offenderId);
        failSignatureTask(task, "Excluded offender " + offenderId);
    }

    private void attemptExcludeAndRestart(Gg20SignatureTask task, int offenderId, String reason) {
        if (!task.participants.contains(offenderId)) {
            failSignatureTask(task, "Complaint (offender not participant): " + reason);
            return;
        }
        int required = Math.min(Math.max(1, task.threshold), task.nodesCount);
        java.util.LinkedHashSet<Integer> newParticipants = new java.util.LinkedHashSet<>(task.participants);
        newParticipants.remove(offenderId);
        if (newParticipants.size() < required) {
            failSignatureTask(task, "Not enough participants after exclusion");
            return;
        }
        broadcastExclude(task, offenderId).join();
        failSignatureTask(task, "Excluded offender " + offenderId + ", restarting");

        String newTaskId = task.taskId + "-excl-" + offenderId + "-" + System.currentTimeMillis();
        createSignatureTaskWithIdAndGroupKey(newTaskId, task.groupPublicKey, task.message, task.initiatorId, newParticipants);
        Gg20SignatureTask newTask = signatureTasks.get(newTaskId);
        if (newTask == null) {
            return;
        }
        initSignatureContext(newTask);
        newTask.start();
        broadcastOfflineInit(newTask).join();
        runOfflinePhase(newTask).exceptionally(ex -> {
            logger.error("Failed offline phase for restarted task {}: {}", newTaskId, ex.getMessage());
            return null;
        });
    }

    private CompletableFuture<Void> broadcastExclude(Gg20SignatureTask task, int offenderId) {
        Map<String, Object> data = new HashMap<>();
        data.put("signatureTaskId", task.taskId);
        data.put("senderId", nodeId);
        data.put("offenderId", offenderId);
        return nodeService.broadcastMessage(new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_EXCLUDE, data));
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignGammaCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commitHex = (String) dataMap.get("commit");
        String proofAHex = (String) dataMap.get("proofA");
        String proofRHex = (String) dataMap.get("proofR");
        String proofSHex = (String) dataMap.get("proofS");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commitHex == null || proofAHex == null || proofRHex == null || proofSHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint commitment = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(commitHex));
            ECPoint proofA = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(proofAHex));
            BigInteger proofR = new BigInteger(proofRHex, 16);
            BigInteger proofS = new BigInteger(proofSHex, 16);
            EcChaumPedersenProof proof = new EcChaumPedersenProof(proofA, proofR, proofS);
            byte[] ctx = buildSignContext(task.taskId, senderId, task.messageHash, "GAMMA-COMMIT");
            if (!CggmpIntegrityChecker.verifyGammaCommitment(proof, commitment, ctx)) {
                logger.warn("Invalid gamma commitment proof from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("commit", commitHex);
                evidence.put("proofA", proofAHex);
                evidence.put("proofR", proofRHex);
                evidence.put("proofS", proofSHex);
                broadcastComplaint(task, senderId, "Invalid gamma commitment proof", evidence).join();
                failSignatureTask(task, "Invalid gamma commitment proof");
                return;
            }
            if (task.gammaCommitments.containsKey(senderId)) {
                logger.warn("Duplicate gamma commitment from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaCommitments.put(senderId, commitment);
            if (task.gammaCommitLatch.getCount() > 0) {
                task.gammaCommitLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_COMMIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignGammaOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String gammaHex = (String) dataMap.get("gamma");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || gammaHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId || senderId == nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(senderId)) {
            return;
        }
        try {
            ECPoint gamma = Secp256k1Curve.decodePoint(HexUtils.hexToBytes(gammaHex));
            BigInteger r = new BigInteger(rHex, 16);
            ECPoint commitment = task.gammaCommitments.get(senderId);
            if (commitment == null) {
                logger.warn("Missing gamma commitment for node {} in task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                broadcastComplaint(task, senderId, "Missing gamma commitment", evidence).join();
                failSignatureTask(task, "Missing gamma commitment");
                return;
            }
            if (!CggmpIntegrityChecker.isValidGammaPoint(gamma)) {
                logger.warn("Invalid gamma point from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                broadcastComplaint(task, senderId, "Invalid gamma point", evidence).join();
                failSignatureTask(task, "Invalid gamma point");
                return;
            }
            if (!CggmpIntegrityChecker.verifyGammaOpen(commitment, gamma, r)) {
                logger.warn("Invalid gamma commitment opening from node {} for task {}", senderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("gamma", gammaHex);
                evidence.put("r", rHex);
                broadcastComplaint(task, senderId, "Invalid gamma commitment opening", evidence).join();
                failSignatureTask(task, "Invalid gamma commitment opening");
                return;
            }
            if (task.gammaPoints.containsKey(senderId)) {
                logger.warn("Duplicate gamma open from node {} for task {}", senderId, taskId);
                return;
            }
            task.gammaPoints.put(senderId, gamma);
            if (task.gammaLatch.getCount() > 0) {
                task.gammaLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_GAMMA_OPEN from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaKaInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpDkgCodec.decodeMtAInitiatorMessage(msgMap);
            if (!validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                broadcastComplaint(task, initiatorId, "Invalid Paillier public key (KA)", evidence).join();
                failSignatureTask(task, "Invalid Paillier public key (KA)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                broadcastComplaint(task, initiatorId, "Missing KA MtA initiator proofs", evidence).join();
                failSignatureTask(task, "Missing KA MtA initiator proofs");
                return;
            }
            if (!ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for KA from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (KA)", evidence).join();
                failSignatureTask(task, "Inconsistent Paillier key/zkSetup (KA)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                broadcastComplaint(task, initiatorId, "Invalid KA MtA initiator proofs", evidence).join();
                failSignatureTask(task, "Invalid KA MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.a_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.kaBetas.put(initiatorId, beta);
            if (task.kaInitLatch.getCount() > 0) {
                task.kaInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpDkgCodec.encodeMtAResult(publicResult));
            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_KA_RESPONSE, resp)).join();
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaKaResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != nodeId || responderId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpDkgCodec.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaKaInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                broadcastComplaint(task, responderId, "Missing KA MtA respondent proof", evidence).join();
                failSignatureTask(task, "Missing KA MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":KA", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid KA MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                broadcastComplaint(task, responderId, "Invalid KA MtA respondent proof", evidence).join();
                failSignatureTask(task, "Invalid KA MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1Curve.n());
            task.kaAlphas.put(responderId, alpha);
            if (task.kaResponseLatch.getCount() > 0) {
                task.kaResponseLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_KA_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        String rHex = (String) dataMap.get("r");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || rHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        try {
            BigInteger u = new BigInteger(uHex, 16);
            BigInteger r = new BigInteger(rHex, 16);
            String commit = task.uCommitments.get(senderId);
            if (commit == null) {
                logger.warn("Missing u commitment from node {} for task {}", senderId, taskId);
                return;
            }
            String expected = commitU(taskId, senderId, task.messageHash, u, r);
            if (!commit.equals(expected)) {
                logger.warn("Invalid u commitment opening from node {} for task {}", senderId, taskId);
                return;
            }
            task.uShares.put(senderId, u);
            if (task.uShareLatch.getCount() > 0) {
                task.uShareLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_U_SHARE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUOpen(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String uHex = (String) dataMap.get("u");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || uHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        task.uShares.put(0, new BigInteger(uHex, 16));
        if (task.uOpenLatch.getCount() > 0) {
            task.uOpenLatch.countDown();
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignUCommit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String commit = (String) dataMap.get("commit");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || commit == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        task.uCommitments.put(senderId, commit);
        if (task.uCommitLatch.getCount() > 0) {
            task.uCommitLatch.countDown();
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaStInit(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number receiverValue = (Number) dataMap.get("receiverId");
        if (initiatorValue == null || receiverValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int receiverId = receiverValue.intValue();
        if (initiatorId != senderId || receiverId != nodeId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || !task.participants.contains(nodeId)) {
            return;
        }
        try {
            Map<?, ?> pkMap = (Map<?, ?>) dataMap.get("paillierPublicKey");
            Map<?, ?> zkMap = (Map<?, ?>) dataMap.get("zkSetup");
            Map<?, ?> msgMap = (Map<?, ?>) dataMap.get("initiatorMessage");
            if (pkMap == null || zkMap == null || msgMap == null) {
                return;
            }
            PaillierEncryption.PublicKey publicKey = CggmpDkgCodec.decodePaillierPublicKey(pkMap);
            ZKSetup zkSetup = CggmpDkgCodec.decodeZkSetup(zkMap);
            MtAInitiatorMessage initiatorMessage = CggmpDkgCodec.decodeMtAInitiatorMessage(msgMap);
            if (!validatePaillierPublicKey(publicKey)) {
                logger.warn("Invalid Paillier public key for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                broadcastComplaint(task, initiatorId, "Invalid Paillier public key (ST)", evidence).join();
                failSignatureTask(task, "Invalid Paillier public key (ST)");
                return;
            }
            if (initiatorMessage.rangeProof() == null || initiatorMessage.biPrimeProof() == null || initiatorMessage.factorProof() == null) {
                logger.warn("Missing ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                broadcastComplaint(task, initiatorId, "Missing ST MtA initiator proofs", evidence).join();
                failSignatureTask(task, "Missing ST MtA initiator proofs");
                return;
            }
            if (!ensurePeerKeyConsistency(task, initiatorId, publicKey, zkSetup)) {
                logger.warn("Inconsistent Paillier key/zkSetup for ST from node {} task {}", initiatorId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("paillierPublicKey", pkMap);
                evidence.put("zkSetup", zkMap);
                broadcastComplaint(task, initiatorId, "Inconsistent Paillier key/zkSetup (ST)", evidence).join();
                failSignatureTask(task, "Inconsistent Paillier key/zkSetup (ST)");
                return;
            }

            MtAProtocol protocol = new MtAProtocol(null, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, receiverId);
            if (!protocol.verifyInitiatorRangeProof(initiatorMessage, publicKey, zkSetup, mtaContext)
                    || !protocol.verifyInitiatorBiPrimeProof(initiatorMessage, publicKey, mtaContext)
                    || !protocol.verifyInitiatorFactorProof(initiatorMessage, publicKey, zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA initiator proofs for task {}", taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("initiatorMessage", msgMap);
                broadcastComplaint(task, initiatorId, "Invalid ST MtA initiator proofs", evidence).join();
                failSignatureTask(task, "Invalid ST MtA initiator proofs");
                return;
            }

            com.example.mpc.cggmp.mta.MtAResult result = protocol.computeCjWithY(publicKey, initiatorMessage.cA(), task.t_i, zkSetup, mtaContext);
            BigInteger beta = protocol.computeBeta(result.y());
            task.stBetas.put(initiatorId, beta);
            if (task.stInitLatch.getCount() > 0) {
                task.stInitLatch.countDown();
            }

            Map<String, Object> resp = new HashMap<>();
            resp.put("taskId", taskId);
            resp.put("initiatorId", initiatorId);
            resp.put("responderId", nodeId);
            com.example.mpc.cggmp.mta.MtAResult publicResult = new com.example.mpc.cggmp.mta.MtAResult(result.c_j(), null, null, result.proof());
            resp.put("result", CggmpDkgCodec.encodeMtAResult(publicResult));
            nodeService.sendMessage(initiatorId, new NodeService.Message(nodeId, MessageType.CGGMP_SIGN_MTA_ST_RESPONSE, resp)).join();
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_INIT from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignMtaStResponse(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        Number initiatorValue = (Number) dataMap.get("initiatorId");
        Number responderValue = (Number) dataMap.get("responderId");
        if (initiatorValue == null || responderValue == null) {
            return;
        }
        int initiatorId = initiatorValue.intValue();
        int responderId = responderValue.intValue();
        if (initiatorId != nodeId || responderId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null) {
            return;
        }
        try {
            Map<?, ?> resultMap = (Map<?, ?>) dataMap.get("result");
            if (resultMap == null) {
                return;
            }
            com.example.mpc.cggmp.mta.MtAResult result = CggmpDkgCodec.decodeMtAResult(resultMap);
            MtAInitiatorMessage initiatorMessage = task.mtaStInitiatorMessages.get(responderId);
            if (initiatorMessage == null) {
                return;
            }
            if (result.c_j() == null || result.proof() == null) {
                logger.warn("Missing ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                broadcastComplaint(task, responderId, "Missing ST MtA respondent proof", evidence).join();
                failSignatureTask(task, "Missing ST MtA respondent proof");
                return;
            }
            MtAProtocol protocol = new MtAProtocol(task.paillier, Secp256k1Curve.n());
            byte[] mtaContext = buildMtaContext(taskId + ":ST", initiatorId, responderId);
            if (!protocol.verifyRespondentProof(result, initiatorMessage.cA(), task.paillier.getPublicKeyInfo(), task.zkSetup, mtaContext)) {
                logger.warn("Invalid ST MtA respondent proof from node {} for task {}", responderId, taskId);
                Map<String, Object> evidence = new HashMap<>();
                evidence.put("result", resultMap);
                broadcastComplaint(task, responderId, "Invalid ST MtA respondent proof", evidence).join();
                failSignatureTask(task, "Invalid ST MtA respondent proof");
                return;
            }
            BigInteger alpha = protocol.decryptCj(result.c_j()).mod(Secp256k1Curve.n());
            task.stAlphas.put(responderId, alpha);
            if (task.stResponseLatch.getCount() > 0) {
                task.stResponseLatch.countDown();
            }
        } catch (Exception e) {
            logger.error("Failed to handle CGGMP_SIGN_MTA_ST_RESPONSE from node {}: {}", senderId, e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCggmpSignSShare(int senderId, Object data) {
        if (!(data instanceof Map<?, ?> dataMap)) {
            return;
        }
        String taskId = (String) dataMap.get("taskId");
        String sHex = (String) dataMap.get("s");
        Number senderValue = (Number) dataMap.get("senderId");
        if (taskId == null || sHex == null || senderValue == null) {
            return;
        }
        int senderNodeId = senderValue.intValue();
        if (senderNodeId != senderId) {
            return;
        }
        Gg20SignatureTask task = signatureTasks.get(taskId);
        if (task == null || nodeId != task.initiatorId) {
            return;
        }
        BigInteger sigma = new BigInteger(sHex, 16);
        if (!verifySigmaShare(task, senderId, sigma)) {
            Map<String, Object> ev = new HashMap<>();
            ev.put("sigma", sHex);
            ev.put("r", task.r == null ? null : HexUtils.toHex(task.r));
            ev.put("DeltaTilde", task.presignDeltaTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignDeltaTilde.get(senderId).getEncoded(false)));
            ev.put("STilde", task.presignSTilde.get(senderId) == null ? null : HexUtils.bytesToHex(task.presignSTilde.get(senderId).getEncoded(false)));
            broadcastComplaint(task, senderId, "Invalid signature share (Figure 10)", ev).join();
            failSignatureTask(task, "Invalid signature share from node " + senderId);
            return;
        }
        task.sShares.put(senderId, sigma);
        if (task.sShareLatch.getCount() > 0) {
            task.sShareLatch.countDown();
        }
    }

    private boolean verifySigmaShare(Gg20SignatureTask task, int senderId, BigInteger sigma) {
        if (task.presignature == null || task.messageHash == null) {
            return false;
        }
        BigInteger curveOrder = Secp256k1Curve.n();
        ECPoint Gamma = task.presignature.Gamma();
        BigInteger r = task.r != null ? task.r : Gamma.getAffineXCoord().toBigInteger().mod(curveOrder);
        BigInteger m = new BigInteger(1, task.messageHash).mod(curveOrder);
        ECPoint deltaTilde = task.presignDeltaTilde.get(senderId);
        ECPoint sTilde = task.presignSTilde.get(senderId);
        if (deltaTilde == null || sTilde == null) {
            return false;
        }
        ECPoint left = Gamma.multiply(sigma).normalize();
        ECPoint right = deltaTilde.multiply(m).add(sTilde.multiply(r)).normalize();
        return left.equals(right);
    }

    private List<Integer> findInvalidSigmaShares(Gg20SignatureTask task) {
        List<Integer> offenders = new ArrayList<>();
        for (Map.Entry<Integer, BigInteger> e : task.sShares.entrySet()) {
            if (!verifySigmaShare(task, e.getKey(), e.getValue())) {
                offenders.add(e.getKey());
            }
        }
        return offenders;
    }

    private void clearPresignLocal(Gg20SignatureTask task) {
        task.presignature = null;
        task.presignatureUsed = false;
        task.k_i = null;
        task.presignYScalar = null;
        task.presignAScalar = null;
        task.presignBScalar = null;
        task.presignDelta.remove(nodeId);
        task.presignDeltaPoint.remove(nodeId);
        task.presignSPoint.remove(nodeId);
    }

    private void clearPresignAll(Gg20SignatureTask task) {
        clearPresignLocal(task);
        task.presignK.clear();
        task.presignG.clear();
        task.presignGamma.clear();
        task.presignY.clear();
        task.presignA1.clear();
        task.presignA2.clear();
        task.presignB1.clear();
        task.presignB2.clear();
        task.presignD.clear();
        task.presignDhat.clear();
        task.presignF.clear();
        task.presignFhat.clear();
        task.presignFOutgoing.clear();
        task.presignFhatOutgoing.clear();
        task.presignBeta.clear();
        task.presignBetaHat.clear();
        task.presignRho.clear();
        task.presignMu.clear();
        task.presignRhoHat.clear();
        task.presignMuHat.clear();
        task.presignDelta.clear();
        task.presignDeltaPoint.clear();
        task.presignSPoint.clear();
        task.presignDeltaTilde.clear();
        task.presignSTilde.clear();
        task.sShares.clear();
    }

    private static final class PeerR2Result {
        final int peerId;
        final boolean skipped;
        final BigInteger beta;
        final BigInteger betaHat;
        final BigInteger d;
        final BigInteger dhat;
        final BigInteger f;
        final BigInteger fhat;
        final BigInteger rho;
        final BigInteger mu;
        final BigInteger rhoHat;
        final BigInteger muHat;
        final PiAffGProof proof;
        final PiAffGProof proofHat;
        final long peerMs;

        private PeerR2Result(int peerId,
                             boolean skipped,
                             BigInteger beta,
                             BigInteger betaHat,
                             BigInteger d,
                             BigInteger dhat,
                             BigInteger f,
                             BigInteger fhat,
                             BigInteger rho,
                             BigInteger mu,
                             BigInteger rhoHat,
                             BigInteger muHat,
                             PiAffGProof proof,
                             PiAffGProof proofHat,
                             long peerMs) {
            this.peerId = peerId;
            this.skipped = skipped;
            this.beta = beta;
            this.betaHat = betaHat;
            this.d = d;
            this.dhat = dhat;
            this.f = f;
            this.fhat = fhat;
            this.rho = rho;
            this.mu = mu;
            this.rhoHat = rhoHat;
            this.muHat = muHat;
            this.proof = proof;
            this.proofHat = proofHat;
            this.peerMs = peerMs;
        }

        static PeerR2Result skipped(int peerId) {
            return new PeerR2Result(peerId, true, null, null, null, null, null, null, null, null, null, null, null, null, 0L);
        }

        static PeerR2Result done(int peerId,
                                 BigInteger beta,
                                 BigInteger betaHat,
                                 BigInteger d,
                                 BigInteger dhat,
                                 BigInteger f,
                                 BigInteger fhat,
                                 BigInteger rho,
                                 BigInteger mu,
                                 BigInteger rhoHat,
                                 BigInteger muHat,
                                 PiAffGProof proof,
                                 PiAffGProof proofHat,
                                 long peerMs) {
            return new PeerR2Result(peerId, false, beta, betaHat, d, dhat, f, fhat, rho, mu, rhoHat, muHat, proof, proofHat, peerMs);
        }
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return ThreadPoolUtil.submitIoTask(() -> {
            try {
                nodeService.startP2PServer().join();
                nodeService.registerMessageHandler(-1, this);
                logger.info("CGGMP signature service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
