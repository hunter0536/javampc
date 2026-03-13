package com.example.mpc.service;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.exception.ErrorCode;
import com.example.mpc.common.exception.MpcException;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.common.util.JsonCodec;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.dto.AuxInfo;
import com.example.mpc.dto.CggmpDkgTask;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.enums.MessageType;
import com.example.mpc.service.cggmp.dkg.CggmpDkgMessageDispatcher;
import com.example.mpc.service.cggmp.dkg.CggmpDkgMessageHandler;
import com.example.mpc.service.cggmp.dkg.CggmpDkgProtocolHandler;
import com.example.mpc.service.cggmp.dkg.CggmpDkgUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.Security;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * CGGMP分布式密钥生成(DKG)服务
 * 负责执行DKG协议生成组公钥和成员分片
 */
@Service
public class CggmpDkgService implements NodeService.MessageHandler {
    public static final Logger logger = LoggerFactory.getLogger(CggmpDkgService.class);
    public static final ExecutorService dkgExecutorService = ThreadPoolUtil.getDkgThreadPool();

    public final CggmpDkgProtocolHandler dkgProtocolHandler = new CggmpDkgProtocolHandler(this);
    public final CggmpDkgMessageHandler dkgMessageHandler = new CggmpDkgMessageHandler(this);
    public final CggmpDkgMessageDispatcher dkgMessageDispatcher = new CggmpDkgMessageDispatcher(this);

    @Autowired
    public NodeService nodeService;

    @Autowired
    public KeyShareDao keyShareDao;

    @Autowired
    public AuxInfoDao auxInfoDao;

    @Value("${node.id}")
    public int nodeId;

    @Value("${cggmp.hdEnabled:false}")
    public boolean hdEnabled;

    @Value("${cggmp.dkg.echoEnabled:true}")
    public boolean dkgEchoEnabled;

    @Value("${cggmp.dkg.rbcEnabled:true}")
    public boolean dkgUseRbc;

    public final int nodesCount = Constants.NODES_COUNT;
    public final int threshold = Constants.THRESHOLD;

    public final ScheduledExecutorService dkgScheduler = Executors.newSingleThreadScheduledExecutor();
    public final Map<String, CggmpDkgTask> dkgTasks = new ConcurrentHashMap<>();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_DKG_INIT,
                            MessageType.CGGMP_DKG_ROUND1,
                            MessageType.CGGMP_DKG_ROUND1_ECHO,
                            MessageType.CGGMP_DKG_ROUND2,
                            MessageType.CGGMP_DKG_ROUND2_BROAD,
                            MessageType.CGGMP_DKG_ROUND2_BATCH,
                            MessageType.CGGMP_DKG_ROUND3,
                            MessageType.CGGMP_DKG_COMMIT,
                            MessageType.CGGMP_DKG_COMPLAINT,
                            MessageType.CGGMP_DKG_EXCLUDE
                    ), this);
                    logger.info("CGGMP DKG service initialized successfully for node {} with {} total nodes", nodeId, nodesCount);
                })
                .exceptionally(ex -> {
                    logger.error("Failed to init CGGMP DKG service: {}", ex.getMessage(), ex);
                    throw new RuntimeException(ex);
                });
    }

    public String createDkgTask(boolean isHotWallet) {
        if (isHotWallet) {
                int hotWalletCount = keyShareDao.countHotWalletSync(nodeId);
                if (hotWalletCount >= 1) {
                    throw new RuntimeException("Already have 1 hot wallet key share, cannot create new hot wallet DKG task");
                }
            }
        
        int auxCount = auxInfoDao.countAuxSync(nodeId);
        if (auxCount == 0) {
            logger.warn("No AUX data available. Please run AUX provisioning first.");
            throw new MpcException(ErrorCode.NO_AUX_DATA_AVAILABLE);
        }
        
        String taskId = UUID.randomUUID().toString();
        String executionId = UUID.randomUUID().toString();
        CggmpDkgTask task = createDkgTaskInternal(taskId, executionId, nodesCount, threshold, null, nodeId, isHotWallet);
        dkgTasks.put(taskId, task);
        dkgMessageHandler.drainPendingRound1(task);
        logger.info("Created CGGMP DKG task: {}, isHotWallet: {}", taskId, isHotWallet);
        return taskId;
    }

    public String createDkgTask() {
        return createDkgTask(false);
    }

    public CompletableFuture<Void> startDkgProcess(String taskId) {
        return dkgProtocolHandler.startDkgProcessInternal(taskId, true);
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
        response.setLastComplaintReason(task.lastComplaintReason);
        response.setLastComplaintOffenderId(task.lastComplaintOffenderId);
        response.setLastComplaintEvidence(task.lastComplaintEvidence);
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

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return dkgMessageDispatcher.handleMessage(senderId, message);
    }

    public CggmpDkgTask createDkgTaskInternal(String taskId,
                                              String executionId,
                                              int nodesCount,
                                              int threshold,
                                              Set<Integer> participants,
                                              int initiatorId,
                                              boolean isHotWallet) {
        AuxInfo auxInfo = auxInfoDao.loadLatestSync(nodeId);
        if (auxInfo == null) {
            throw new RuntimeException("Missing auxiliary info. Run AUX provisioning before DKG.");
        }

        CggmpDkgTask task = new CggmpDkgTask(taskId, executionId, nodesCount, threshold, participants, initiatorId, isHotWallet);
        
        BigInteger p = new BigInteger(auxInfo.getPaillierP(), 16);
        BigInteger q = new BigInteger(auxInfo.getPaillierQ(), 16);
        BigInteger hatN = new BigInteger(auxInfo.getPedersenHatN(), 16);
        BigInteger s = new BigInteger(auxInfo.getPedersenS(), 16);
        BigInteger t = new BigInteger(auxInfo.getPedersenT(), 16);
        
        task.paillier = new PaillierEncryption(p, q);
        task.zkSetup = new ZKSetup(hatN, s, t);
        
        task.evalPowers = CggmpDkgUtils.precomputeEvalPowers(CggmpDkgUtils.getIndexValue(task, nodeId), threshold);
        logger.info("Loaded AUX data for DKG task: {}, paillier bits: {}", taskId, task.paillier.getBitLength());
        return task;
    }

    public CggmpDkgTask getDkgTask(String taskId) {
        CggmpDkgTask task = dkgTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("CGGMP DKG task not found: " + taskId);
        }
        return task;
    }

    public boolean saveKeyShareToDatabase(CggmpDkgTask task) {
        try {
            String shareHex = task.secretShare.toString(16);
            Map<String, String> publicShares = buildPublicShares(task);
            String publicSharesJson = encodeStringMapAsJson(publicShares);
            String indexMapJson = buildIndexMapJson(task);
            String chainCodeHex = task.chainCode == null || task.chainCode.length == 0 ? null : HexUtils.bytesToHex(task.chainCode);
            KeyShare keyShare = new KeyShare(nodeId, shareHex, task.groupPublicKeyHex, task.taskId, publicSharesJson, indexMapJson, chainCodeHex, task.isHotWallet);
            keyShareDao.save(keyShare);
            logger.info("Saved CGGMP key share to database for task: {}, isHotWallet: {}", task.taskId, task.isHotWallet);
            return true;
        } catch (Exception e) {
            logger.error("Failed to save CGGMP key share to database", e);
            return false;
        }
    }

    private Map<String, String> buildPublicShares(CggmpDkgTask task) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int peerId : task.participants) {
            ECPoint Xj = CggmpDkgUtils.computePublicShare(task, peerId);
            out.put(String.valueOf(peerId), HexUtils.bytesToHex(Xj.getEncoded(false)));
        }
        return out;
    }

    private String buildIndexMapJson(CggmpDkgTask task) {
        Map<String, String> out = new LinkedHashMap<>();
        for (int peerId : task.participants) {
            BigInteger idx = task.indexMap != null ? task.indexMap.get(peerId) : null;
            out.put(String.valueOf(peerId), idx == null ? String.valueOf(peerId) : idx.toString());
        }
        return encodeStringMapAsJson(out);
    }

    private String encodeStringMapAsJson(Map<String, String> map) {
        return JsonCodec.toJson(map);
    }
}
