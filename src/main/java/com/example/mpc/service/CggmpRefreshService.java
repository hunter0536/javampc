package com.example.mpc.service;

import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.common.response.RefreshTaskStatusResponse;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.enums.MessageType;
import com.example.mpc.enums.TaskStatus;
import com.example.mpc.dto.CggmpRefreshTask;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.service.cggmp.refresh.CggmpRefreshMessageDispatcher;
import com.example.mpc.service.cggmp.refresh.CggmpRefreshMessageHandler;
import com.example.mpc.service.cggmp.refresh.CggmpRefreshProtocolHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * CGGMP密钥刷新服务
 * 负责定期刷新成员的分片密钥，更新组公钥
 */
@Service
public class CggmpRefreshService implements NodeService.MessageHandler {
    public static final Logger logger = LoggerFactory.getLogger(CggmpRefreshService.class);
    public static final ExecutorService refreshExecutorService = ThreadPoolUtil.getComputationThreadPool();

    public final CggmpRefreshProtocolHandler refreshProtocolHandler = new CggmpRefreshProtocolHandler(this);
    public final CggmpRefreshMessageHandler refreshMessageHandler = new CggmpRefreshMessageHandler(this);
    public final CggmpRefreshMessageDispatcher refreshMessageDispatcher = new CggmpRefreshMessageDispatcher(this);

    @Autowired
    public NodeService nodeService;

    @Autowired
    public KeyShareDao keyShareDao;

    @Autowired
    public ComplaintDao complaintDao;

    @Value("${node.id}")
    public int nodeId;

    @Value("${cggmp.hdEnabled:false}")
    public boolean hdEnabled;


    @Value("${cggmp.complaint.logPath:logs/complaints.jsonl}")
    public String complaintLogPath;

    public final Map<String, CggmpRefreshTask> refreshTasks = new ConcurrentHashMap<>();


    public final int nodesCount = Constants.NODES_COUNT;
    public final int threshold = Constants.THRESHOLD;
    public final ScheduledExecutorService cggmpScheduler = Executors.newSingleThreadScheduledExecutor();

    public String createRefreshTask(String groupPublicKey) {
        String fixedGroupPublicKey;
        fixedGroupPublicKey = java.net.URLDecoder.decode(groupPublicKey, StandardCharsets.UTF_8);
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
        return refreshProtocolHandler.startRefreshTask(taskId);
    }

    public CompletableFuture<Void> startRefreshTaskFromMessage(String taskId, int senderId) {
        return refreshProtocolHandler.startRefreshTaskFromMessage(taskId, senderId);
    }

    public RefreshTaskStatusResponse getRefreshTaskStatus(String taskId) {
        CggmpRefreshTask task = refreshTasks.get(taskId);
        if (task == null) {
            throw new RuntimeException("Refresh task not found: " + taskId);
        }
        RefreshTaskStatusResponse response = new RefreshTaskStatusResponse();
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

    public CompletableFuture<Void> init(int nodesCount) {
        return nodeService.startP2PServer()
                .thenRun(() -> {
                    nodeService.registerMessageHandler(EnumSet.of(
                            MessageType.CGGMP_REFRESH_INIT,
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

    @Override
    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        return refreshMessageDispatcher.handleMessage(senderId, message);
    }

    public void createRefreshTaskInternal(String taskId, String groupPublicKey, Set<Integer> participants, int initiatorId) {
        CggmpRefreshTask task = new CggmpRefreshTask(taskId, groupPublicKey, nodesCount, initiatorId, participants);
        refreshTasks.put(taskId, task);
    }

    public BigInteger loadLocalShare(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        BigInteger share = new BigInteger(keyShare.getKeyShare(), 16);
        return share.mod(Secp256k1CurveUtils.n());
    }

    public Map<Integer, BigInteger> loadIndexMap(String groupPublicKey) {
        KeyShare keyShare = loadKeyShareByGroupPublicKeySync(groupPublicKey);
        if (keyShare == null) {
            throw new RuntimeException("Key share not found");
        }
        String indexMapJson = keyShare.getIndexMap();
        if (indexMapJson == null || indexMapJson.isBlank()) {
            return new LinkedHashMap<>();
        }
        return com.example.mpc.common.util.DbMapUtils.parseIndexMap(indexMapJson);
    }

    private KeyShare loadKeyShareByGroupPublicKeySync(String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }
}
