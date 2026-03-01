package com.example.mpc.service;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.service.netty.NettyService;
import io.netty.channel.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class NodeService {

    private static final Logger logger = LoggerFactory.getLogger(NodeService.class);

    @Value("${node.id}")
    private int nodeId;

    @Value("${node.port}")
    private int nodePort;

    @Value("${discovery.port}")
    private int discoveryPort;

    @Value("${nodes.sharedSecret:}")
    private String sharedSecret;

    @Value("${nodes.ssl.enabled:false}")
    private boolean sslEnabled;

    @Value("${nodes.ssl.cert:}")
    private String sslCertPath;

    @Value("${nodes.ssl.key:}")
    private String sslKeyPath;

    @Value("${nodes.ssl.trustCert:}")
    private String sslTrustCertPath;

    @Value("#{'${discovery.broadcast.ports}'.split(',')}")
    private List<String> discoveryBroadcastPorts;

    @Value("#{'${nodes.peers:}'.isEmpty() ? null : '${nodes.peers:}'.split(',')}")
    private List<String> peerNodes;

    @Value("${nodes.reliableBroadcast.enabled:true}")
    private boolean reliableBroadcastEnabled;

    @Value("${nodes.reliableBroadcast.retryCount:3}")
    private int reliableBroadcastRetryCount;

    @Value("${nodes.reliableBroadcast.retryIntervalMs:200}")
    private long reliableBroadcastRetryIntervalMs;

    @Value("${nodes.reliableBroadcast.quorum:0}")
    private int reliableBroadcastQuorum;

    @Value("${nodes.chaos.enabled:false}")
    private boolean chaosEnabled;

    @Value("${nodes.chaos.minDelayMs:0}")
    private long chaosMinDelayMs;

    @Value("${nodes.chaos.maxDelayMs:0}")
    private long chaosMaxDelayMs;

    @Value("${nodes.chaos.duplicateChance:0}")
    private double chaosDuplicateChance;

    @Value("#{'${nodes.chaos.types:}'.isEmpty() ? null : '${nodes.chaos.types:}'.split(',')}")
    private List<String> chaosTypes;

    // 使用Constants中的常量
    private final int nodesCount = Constants.NODES_COUNT;

    // P2P通信
    private com.example.mpc.service.netty.NettyService nettyService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong taskCount = new AtomicLong(0);
    private final AtomicLong completedTaskCount = new AtomicLong(0);
    private final AtomicLong totalTaskTime = new AtomicLong(0);

    // 网络拓扑
    private final ConcurrentHashMap<Integer, NodeInfo> nodes = new ConcurrentHashMap<>();
    private final AtomicBoolean discoveryRunning = new AtomicBoolean(false);
    private final ConcurrentHashMap<Integer, java.util.concurrent.CopyOnWriteArrayList<MessageHandler>> messageHandlers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<MessageType, java.util.concurrent.CopyOnWriteArrayList<MessageHandler>> messageTypeHandlers = new ConcurrentHashMap<>();
    private ScheduledExecutorService discoveryScheduler;
    private ScheduledExecutorService retryScheduler = Executors.newSingleThreadScheduledExecutor();
    private final ConcurrentHashMap<String, java.util.Set<Integer>> reliablePending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<Void>> reliableFutures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RbcState> rbcStates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, java.util.Set<Integer>> pendingRbcEchoes = new ConcurrentHashMap<>();

    private synchronized ScheduledExecutorService getRetryScheduler() {
        if (retryScheduler == null || retryScheduler.isShutdown() || retryScheduler.isTerminated()) {
            retryScheduler = Executors.newSingleThreadScheduledExecutor();
        }
        return retryScheduler;
    }

    /**
     * 启动P2P服务器和节点发现
     */
    public CompletableFuture<Void> startP2PServer() {
        return ThreadPoolUtil.submitIoTask(() -> {
            if (running.get()) {
                return;
            }

            running.set(true);

            try {
                // 启动Netty服务器
                nettyService = new NettyService(nodeId, nodePort, sharedSecret,
                        sslEnabled, sslCertPath, sslKeyPath, sslTrustCertPath, this::handleAck,
                        (sender, msg) -> {
                            try {
                                return handleInboundMessage(sender, msg);
                            } catch (Exception e) {
                                CompletableFuture<Void> f = new CompletableFuture<>();
                                f.completeExceptionally(e);
                                return f;
                            }
                        });
                nettyService.startServer();

                // 启动节点发现
                submitTask(this::startNodeDiscovery);

                // 连接配置的静态节点（绕过UDP广播限制）
                submitTask(this::connectStaticPeers);

                logger.info("P2P server started for node {} on port {}", nodeId, nodePort);
            } catch (Exception e) {
                logger.error("Error starting P2P server: {}", e.getMessage());
                running.set(false);
            }
        });
    }

    public boolean isTlsEnabled() {
        return sslEnabled;
    }

    /**
     * 停止P2P服务器
     */
    public CompletableFuture<Void> stopP2PServer() {
        return ThreadPoolUtil.submitIoTask(() -> {
            running.set(false);
            discoveryRunning.set(false);

            if (discoveryScheduler != null) {
                discoveryScheduler.shutdown();
                try {
                    if (!discoveryScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        discoveryScheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    discoveryScheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            if (nettyService != null) {
                nettyService.shutdown();
            }
            if (retryScheduler != null) {
                retryScheduler.shutdown();
                retryScheduler = null;
            }
        });
    }

    /**
     * 发送消息到指定节点
     */
    public CompletableFuture<Void> sendMessage(int receiverId, Message message) {
        if (shouldApplyChaos(message.type)) {
            return sendMessageWithChaos(receiverId, message);
        }
        return sendMessageInternal(receiverId, message);
    }

    private CompletableFuture<Void> sendMessageInternal(int receiverId, Message message) {
        NodeInfo nodeInfo = nodes.get(receiverId);
        if (nodeInfo == null) {
            logger.warn("sendMessage: receiver {} not in nodes map (known={}) for type {}", receiverId, nodes.keySet(), message.type);
            return CompletableFuture.failedFuture(new RuntimeException("Node " + receiverId + " not found in network"));
        }

        if (nettyService == null) {
            return CompletableFuture.failedFuture(new RuntimeException("Netty service not initialized"));
        }

        var channel = nettyService.getNodeChannel(receiverId);
        if (channel == null || !channel.isActive()) {
            return nettyService.connectToNode(receiverId, nodeInfo.host, nodeInfo.port)
                    .thenCompose(v -> nettyService.sendMessage(receiverId, message))
                    .exceptionally(ex -> {
                        logger.error("Failed to send message to node {}: {}", receiverId, ex.getMessage());
                        throw new RuntimeException(ex);
                    });
        }

        return nettyService.sendMessage(receiverId, message)
                .exceptionally(ex -> {
                    logger.error("Failed to send message to node {}: {}", receiverId, ex.getMessage());
                    throw new RuntimeException(ex);
                });
    }

    private boolean shouldApplyChaos(MessageType type) {
        if (!chaosEnabled) {
            return false;
        }
        if (chaosTypes == null || chaosTypes.isEmpty()) {
            return true;
        }
        String name = type.name();
        for (String t : chaosTypes) {
            if (t != null && !t.isBlank() && name.equalsIgnoreCase(t.trim())) {
                return true;
            }
        }
        return false;
    }

    private CompletableFuture<Void> sendMessageWithChaos(int receiverId, Message message) {
        long min = Math.max(0, chaosMinDelayMs);
        long max = Math.max(min, chaosMaxDelayMs);
        long delay = max == 0 ? 0 : java.util.concurrent.ThreadLocalRandom.current().nextLong(min, max + 1);
        CompletableFuture<Void> result = new CompletableFuture<>();
        Runnable sendOnce = () -> sendMessageInternal(receiverId, message)
                .whenComplete((v, ex) -> {
                    if (ex != null) {
                        result.completeExceptionally(ex);
                    } else {
                        result.complete(null);
                    }
                });
        if (delay > 0) {
            getRetryScheduler().schedule(sendOnce, delay, TimeUnit.MILLISECONDS);
        } else {
            sendOnce.run();
        }
        if (chaosDuplicateChance > 0) {
            double r = java.util.concurrent.ThreadLocalRandom.current().nextDouble();
            if (r < chaosDuplicateChance) {
                long dupDelay = max == 0 ? 0 : java.util.concurrent.ThreadLocalRandom.current().nextLong(min, max + 1);
                Runnable dupSend = () -> sendMessageInternal(receiverId, message)
                        .exceptionally(ex -> {
                            logger.debug("Chaos duplicate send failed to node {} (type={}): {}", receiverId, message.type, ex.getMessage());
                            return null;
                        });
                if (dupDelay > 0) {
                    getRetryScheduler().schedule(dupSend, dupDelay, TimeUnit.MILLISECONDS);
                } else {
                    dupSend.run();
                }
            }
        }
        return result;
    }

    /**
     * 广播消息到所有其他节点
     */
    public CompletableFuture<Void> broadcastMessage(Message message) {
        logger.debug("=== broadcastMessage START: type={}, fromNode={}, knownNodes={} ===",
                message.type, nodeId, nodes.keySet());
        // 回退到传统方式，使用并行发送
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        // 并行发送消息到所有节点
        for (NodeInfo nodeInfo : nodes.values()) {
            if (nodeInfo.id != nodeId) {
                logger.debug("=== broadcastMessage: sending {} to node {} ===", message.type, nodeInfo.id);
                CompletableFuture<Void> future = sendMessage(nodeInfo.id, message)
                        .exceptionally(ex -> {
                            logger.warn("=== FAILED to broadcast message to node {}: {} ===", nodeInfo.id, ex.getMessage());
                            return null;
                        });
                futures.add(future);
            }
        }

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    /**
     * Reliable broadcast with retries for each peer.
     * Intended for CGGMP24 round-1 commits where reliability is required.
     */
    public CompletableFuture<Void> broadcastReliable(Message message) {
        if (!reliableBroadcastEnabled) {
            return broadcastMessage(message);
        }
        String msgId = message.messageId != null ? message.messageId : java.util.UUID.randomUUID().toString();
        Message reliable = message.requireAck ? message
                : new Message(message.senderId, message.type, message.data, msgId, true, null);
        java.util.Set<Integer> pending = java.util.concurrent.ConcurrentHashMap.newKeySet();
        pending.addAll(nodes.keySet());
        pending.remove(nodeId);
        if (pending.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> ackFuture = new CompletableFuture<>();
        reliablePending.put(msgId, pending);
        reliableFutures.put(msgId, ackFuture);
        int attempts = Math.max(1, reliableBroadcastRetryCount);
        java.util.concurrent.atomic.AtomicInteger attemptCounter = new java.util.concurrent.atomic.AtomicInteger(0);
        Runnable attemptSend = new Runnable() {
            @Override
            public void run() {
                if (ackFuture.isDone()) {
                    return;
                }
                if (pending.isEmpty()) {
                    ackFuture.complete(null);
                    return;
                }
                int attempt = attemptCounter.incrementAndGet();
                List<CompletableFuture<Integer>> futures = new ArrayList<>();
                for (int peerId : pending) {
                    futures.add(sendMessage(peerId, reliable)
                            .thenApply(v -> peerId)
                            .exceptionally(ex -> null));
                }
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .whenComplete((v, ex) -> {
                            if (ackFuture.isDone()) {
                                return;
                            }
                            if (pending.isEmpty()) {
                                ackFuture.complete(null);
                                return;
                            }
                            if (attempt < attempts) {
                                getRetryScheduler().schedule(this, reliableBroadcastRetryIntervalMs, TimeUnit.MILLISECONDS);
                            } else {
                                logger.warn("Reliable broadcast failed for {} peers: {}", message.type, pending);
                                ackFuture.completeExceptionally(new RuntimeException("Reliable broadcast failed for peers " + pending));
                            }
                        });
            }
        };
        getRetryScheduler().execute(attemptSend);
        ackFuture.whenComplete((v, ex) -> {
            reliablePending.remove(msgId);
            reliableFutures.remove(msgId);
        });
        return ackFuture;
    }

    public CompletableFuture<Void> broadcastRbc(Message message) {
        if (!reliableBroadcastEnabled) {
            return broadcastMessage(message);
        }
        String msgId = message.messageId != null ? message.messageId : java.util.UUID.randomUUID().toString();
        String hash = message.rbcHash != null ? message.rbcHash : computeRbcHash(message);
        Message rbc = new Message(message.senderId, message.type, message.data, msgId, true, null, true, hash);
        RbcState state = new RbcState(rbc);
        rbcStates.putIfAbsent(msgId, state);
        state.echoes.add(nodeId);
        broadcastRbcEcho(rbc);
        return broadcastReliable(rbc).thenCompose(v -> state.delivered);
    }

    private void broadcastRbcEcho(Message original) {
        Map<String, Object> data = new HashMap<>();
        data.put("messageId", original.messageId);
        data.put("hash", original.rbcHash);
        data.put("origSenderId", original.senderId);
        data.put("type", original.type.name());
        Message echo = new Message(nodeId, MessageType.NET_RBC_ECHO, data, null, false, null, false, null);
        broadcastMessage(echo);
    }

    private String computeRbcHash(Message message) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(com.example.mpc.service.netty.MessageSigner.canonicalPayload(message).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return com.example.mpc.common.util.HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute RBC hash", e);
        }
    }

    void handleAck(int senderId, String ackForId) {
        if (ackForId == null) {
            return;
        }
        java.util.Set<Integer> pending = reliablePending.get(ackForId);
        if (pending == null) {
            return;
        }
        pending.remove(senderId);
        if (pending.isEmpty()) {
            CompletableFuture<Void> future = reliableFutures.get(ackForId);
            if (future != null && !future.isDone()) {
                future.complete(null);
            }
        }
    }

    void handleRbcEcho(int senderId, Map<?, ?> dataMap) {
        Object msgIdObj = dataMap.get("messageId");
        Object hashObj = dataMap.get("hash");
        Object origSenderObj = dataMap.get("origSenderId");
        Object typeObj = dataMap.get("type");
        if (msgIdObj == null || hashObj == null || origSenderObj == null || typeObj == null) {
            return;
        }
        String messageId = String.valueOf(msgIdObj);
        RbcState state = rbcStates.get(messageId);
        if (state == null) {
            pendingRbcEchoes.computeIfAbsent(messageId, k -> java.util.concurrent.ConcurrentHashMap.newKeySet()).add(senderId);
            return;
        }
        state.echoes.add(senderId);
        int f = Math.max(0, (nodesCount - 1) / 3);
        int quorum = reliableBroadcastQuorum > 0 ? reliableBroadcastQuorum : (2 * f + 1);
        if (!state.deliveredOnce && state.echoes.size() >= quorum) {
            state.deliveredOnce = true;
            state.delivered.complete(null);
        }
    }

    CompletableFuture<Void> handleInboundMessage(int senderId, Message message) {
        if (message.type == MessageType.NET_ACK) {
            handleAck(senderId, message.ackForId);
            return CompletableFuture.completedFuture(null);
        }
        if (message.type == MessageType.NET_RBC_ECHO) {
            if (message.data instanceof Map<?, ?> map) {
                handleRbcEcho(senderId, map);
            }
            return CompletableFuture.completedFuture(null);
        }
        if (message.requireAck && message.messageId != null && nettyService != null) {
            nettyService.sendAck(senderId, message.messageId);
        }
        if (message.rbc) {
            String expected = message.rbcHash != null ? message.rbcHash : computeRbcHash(message);
            if (message.rbcHash != null && !message.rbcHash.equals(expected)) {
                return CompletableFuture.completedFuture(null);
            }
            RbcState state = rbcStates.computeIfAbsent(message.messageId, id -> new RbcState(message));
            if (state != null) {
                state.echoes.add(nodeId);
            }
            java.util.Set<Integer> pending = pendingRbcEchoes.remove(message.messageId);
            if (pending != null && state != null) {
                state.echoes.addAll(pending);
            }
            broadcastRbcEcho(message);
            return state == null ? CompletableFuture.completedFuture(null) : state.delivered.thenCompose(v -> dispatchToHandlers(senderId, message));
        }
        return dispatchToHandlers(senderId, message);
    }

    private CompletableFuture<Void> dispatchToHandlers(int senderId, Message message) {
        var combinedHandlers = new java.util.LinkedHashSet<MessageHandler>();
        var typeHandlers = messageTypeHandlers.get(message.type);
        if (typeHandlers != null) {
            combinedHandlers.addAll(typeHandlers);
        }
        var senderHandlers = messageHandlers.get(message.senderId);
        if (senderHandlers != null) {
            combinedHandlers.addAll(senderHandlers);
        }
        var globalHandlers = messageHandlers.get(-1);
        if (globalHandlers != null) {
            combinedHandlers.addAll(globalHandlers);
        }
        if (combinedHandlers.isEmpty()) {
            logger.warn("No handlers registered for message type {} from node {} (keys={}, typeKeys={})",
                    message.type, message.senderId, messageHandlers.keySet(), messageTypeHandlers.keySet());
            return CompletableFuture.completedFuture(null);
        }
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (MessageHandler handler : combinedHandlers) {
            try {
                futures.add(handler.handleMessage(senderId, message));
            } catch (Exception e) {
                logger.error("Error handling message: {}", e.getMessage());
            }
        }
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }

    /**
     * 注册消息处理器
     *
     * @param nodeId  节点ID
     * @param handler 消息处理器
     */
    public void registerMessageHandler(int nodeId, MessageHandler handler) {
        messageHandlers.computeIfAbsent(nodeId, k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(handler);
    }

    /**
     * 注册消息处理器（按消息类型）
     *
     * @param type    消息类型
     * @param handler 消息处理器
     */
    public void registerMessageHandler(MessageType type, MessageHandler handler) {
        messageTypeHandlers.computeIfAbsent(type, k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(handler);
    }

    /**
     * 注册消息处理器（多个消息类型）
     *
     * @param types   消息类型集合
     * @param handler 消息处理器
     */
    public void registerMessageHandler(java.util.Set<MessageType> types, MessageHandler handler) {
        if (types == null || types.isEmpty()) return;
        for (MessageType type : types) {
            registerMessageHandler(type, handler);
        }
    }

    /**
     * 取消注册消息处理器
     *
     * @param nodeId 节点ID
     */
    public void unregisterMessageHandler(int nodeId) {
        messageHandlers.remove(nodeId);
    }

    /**
     * 取消注册消息处理器（按处理器实例）
     *
     * @param nodeId  节点ID
     * @param handler 消息处理器
     */
    public void unregisterMessageHandler(int nodeId, MessageHandler handler) {
        var handlers = messageHandlers.get(nodeId);
        if (handlers == null) {
            return;
        }
        handlers.remove(handler);
        if (handlers.isEmpty()) {
            messageHandlers.remove(nodeId, handlers);
        }
    }

    /**
     * 获取当前网络中的节点列表
     *
     * @return 节点列表
     */
    public List<NodeInfo> getNodes() {
        return new ArrayList<>(nodes.values());
    }

    public Map<Integer, NodeInfo> getNodesSnapshot() {
        return new HashMap<>(nodes);
    }

    /**
     * 等待网络稳定（至少发现所有节点）
     *
     * @throws InterruptedException 中断异常
     */
    public CompletableFuture<Void> waitForNetworkReady() {
        CompletableFuture<Void> ready = new CompletableFuture<>();
        ScheduledFuture<?> periodic = getRetryScheduler().scheduleWithFixedDelay(() -> {
            if (ready.isDone()) {
                return;
            }
            try {
                if (logger.isDebugEnabled()) {
                    logger.debug("Network ready check: discoveredPeers={}, requiredPeers={}",
                            nodes.size(), Math.max(0, nodesCount - 1));
                }
                if (nodes.size() < nodesCount - 1) {
                    logger.info("Waiting for all nodes to be discovered... Current count: {}", nodes.size());
                    return;
                }

                boolean allConnected = true;
                if (nettyService != null) {
                    for (NodeInfo nodeInfo : nodes.values()) {
                        if (nodeInfo.id == nodeId) {
                            continue;
                        }
                        var channel = nettyService.getNodeChannel(nodeInfo.id);
                        if (channel == null || !channel.isActive()) {
                            allConnected = false;
                            nettyService.connectToNode(nodeInfo.id, nodeInfo.host, nodeInfo.port)
                                    .whenComplete((v, ex) -> {
                                        if (ex != null) {
                                            logger.debug("Waiting for peer connection to node {}: {}", nodeInfo.id, ex.getMessage());
                                        }
                                    });
                        }
                    }
                }

                if (!allConnected) {
                    logger.info("Waiting for all peer connections to be active...");
                    return;
                }

                logger.info("Network ready with {} nodes", nodes.size() + 1);
                ready.complete(null);
            } catch (Exception e) {
                ready.completeExceptionally(e);
            }
        }, 0, 1, TimeUnit.SECONDS);
        ready.whenComplete((v, ex) -> periodic.cancel(false));
        return ready;
    }

    /**
     * 检查网络是否稳定
     *
     * @return 是否稳定
     */
    public boolean isNetworkReady() {
        return nodes.size() >= nodesCount - 1;
    }

    /**
     * 获取线程池状态
     *
     * @return 线程池状态信息
     */
    public Map<String, Object> getThreadPoolStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("taskCount", taskCount.get());
        status.put("completedTaskCount", completedTaskCount.get());
        status.put("totalTaskTime", totalTaskTime.get() + "ms");
        if (completedTaskCount.get() > 0) {
            status.put("averageTaskTime", totalTaskTime.get() / completedTaskCount.get() + "ms");
        }
        return status;
    }

    /**
     * 提交任务并记录执行时间
     *
     * @param task 任务
     */
    public void submitTask(Runnable task) {
        long startTime = System.currentTimeMillis();
        taskCount.incrementAndGet();

        ThreadPoolUtil.getIoThreadPool().submit(() -> {
            try {
                task.run();
            } finally {
                long endTime = System.currentTimeMillis();
                completedTaskCount.incrementAndGet();
                totalTaskTime.addAndGet(endTime - startTime);
            }
        });
    }

    /**
     * 启动节点发现服务
     */
    private void startNodeDiscovery() {
        if (discoveryRunning.get()) {
            return;
        }

        discoveryRunning.set(true);

        // 启动发现服务器
        ThreadPoolUtil.getIoThreadPool().submit(() -> {
            try (DatagramSocket socket = new DatagramSocket(discoveryPort)) {
                byte[] buffer = new byte[1024];
                while (discoveryRunning.get()) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);
                    String message = new String(packet.getData(), 0, packet.getLength());
                    handleDiscoveryMessage(message, packet.getAddress());
                }
            } catch (Exception e) {
                if (discoveryRunning.get()) {
                    e.printStackTrace();
                }
            }
        });

        // 启动发现客户端
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                if (discoveryRunning.get()) {
                    String message = "DISCOVER_NODE:" + nodeId + ":" + nodePort;
                    byte[] buffer = message.getBytes();

                    // 向配置中的发现端口发送广播，排除当前节点自己的端口
                    if (discoveryBroadcastPorts != null) {
                        for (String portStr : discoveryBroadcastPorts) {
                            try {
                                int port = Integer.parseInt(portStr.trim());
                                // 不向当前节点自己的端口发送广播
                                if (port != discoveryPort) {
                                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName("255.255.255.255"), port);
                                    socket.send(packet);
                                }
                            } catch (NumberFormatException e) {
                                // 忽略无效的端口格式
                            } catch (Exception e) {
                                // 忽略单个端口的发送错误
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (discoveryRunning.get()) {
                    logger.error("Error in discovery client: {}", e.getMessage());
                }
            }
        }, 0, Constants.NODE_DISCOVERY_INTERVAL_MS, TimeUnit.MILLISECONDS);

        // 保存scheduler引用，以便在停止时关闭
        this.discoveryScheduler = scheduler;
    }

    private void connectStaticPeers() {
        if (peerNodes == null || peerNodes.isEmpty()) {
            return;
        }

        for (String peer : peerNodes) {
            String trimmed = peer == null ? "" : peer.trim();
            if (trimmed.isEmpty()) {
                continue;
            }

            String[] parts = trimmed.split("@", 2);
            if (parts.length != 2) {
                logger.warn("Invalid peer config: {}", trimmed);
                continue;
            }

            try {
                int peerId = Integer.parseInt(parts[0]);
                String[] hostPort = parts[1].split(":", 2);
                if (hostPort.length != 2) {
                    logger.warn("Invalid peer host/port: {}", trimmed);
                    continue;
                }
                String host = hostPort[0];
                int port = Integer.parseInt(hostPort[1]);

                if (peerId == this.nodeId) {
                    continue;
                }

                NodeInfo nodeInfo = new NodeInfo(peerId, host, port);
                nodes.put(peerId, nodeInfo);

                if (nettyService != null) {
                    connectWithRetry(peerId, host, port, trimmed);
                }
            } catch (Exception e) {
                logger.warn("Invalid peer config: {}", trimmed);
            }
        }
    }

    private void connectWithRetry(int peerId, String host, int port, String peerDesc) {
        AtomicInteger attempts = new AtomicInteger(0);
        int maxAttempts = 10;
        long retryDelayMs = 2000;

        Runnable attemptConnect = new Runnable() {
            @Override
            public void run() {
                if (nodes.get(peerId) == null) {
                    logger.debug("Peer {} removed from nodes, stopping retry", peerId);
                    return;
                }

                int attempt = attempts.incrementAndGet();
                if (attempt > maxAttempts) {
                    logger.warn("Max retry attempts reached for peer {}, giving up", peerDesc);
                    return;
                }

                nettyService.connectToNode(peerId, host, port)
                        .whenComplete((v, ex) -> {
                            if (ex == null) {
                                logger.info("Successfully connected to peer {} on attempt {}", peerDesc, attempt);
                            } else if (attempt < maxAttempts) {
                                logger.warn("Failed to connect to {} (attempt {}/{}): {}, scheduling retry in {}ms",
                                        peerDesc, attempt, maxAttempts, ex.getMessage(), retryDelayMs);
                                getRetryScheduler().schedule(this, retryDelayMs, TimeUnit.MILLISECONDS);
                            } else {
                                logger.error("Failed to connect to {} after {} attempts: {}", peerDesc, maxAttempts, ex.getMessage());
                            }
                        });
            }
        };

        getRetryScheduler().execute(attemptConnect);
    }

    /**
     * 处理发现消息
     */
    private void handleDiscoveryMessage(String message, InetAddress address) {
        if (message.startsWith("DISCOVER_NODE:")) {
            String[] parts = message.split(":");
            if (parts.length == 3) {
                try {
                    int nodeId = Integer.parseInt(parts[1]);
                    int nodePort = Integer.parseInt(parts[2]);

                    // 不添加自己
                    if (nodeId != this.nodeId) {
                        NodeInfo existingNode = nodes.get(nodeId);
                        if (existingNode != null && nettyService != null) {
                            Channel existingChannel = nettyService.getNodeChannel(nodeId);
                            if (existingChannel != null && existingChannel.isActive()) {
                                logger.debug("Already connected to discovered node {}, skipping", nodeId);
                                return;
                            }
                        }

                        NodeInfo nodeInfo = new NodeInfo(nodeId, address.getHostAddress(), nodePort);
                        nodes.put(nodeId, nodeInfo);
                        logger.info("Discovered node: {} at {}:{}", nodeId, address.getHostAddress(), nodePort);

                        // 自动连接到新发现的节点（带重试）
                        if (nettyService != null) {
                            connectWithRetry(nodeId, address.getHostAddress(), nodePort, "discovered-" + nodeId);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static final class RbcState {
        final Message message;
        final java.util.Set<Integer> echoes = java.util.concurrent.ConcurrentHashMap.newKeySet();
        final CompletableFuture<Void> delivered = new CompletableFuture<>();
        volatile boolean deliveredOnce = false;

        RbcState(Message message) {
            this.message = message;
        }
    }

    // 节点信息类
    public static class NodeInfo {
        public final int id;
        public final String host;
        public final int port;
        public long lastSeen;

        public NodeInfo(int id, String host, int port) {
            this.id = id;
            this.host = host;
            this.port = port;
            this.lastSeen = System.currentTimeMillis();
        }
    }

    // 消息处理器接口
    public interface MessageHandler {
        CompletableFuture<Void> handleMessage(int senderId, Message message) throws Exception;
    }

    // 消息类
    public static class Message implements Serializable {
        public final int senderId;
        public final MessageType type;
        public final Object data;
        public final String messageId;
        public final boolean requireAck;
        public final String ackForId;
        public final boolean rbc;
        public final String rbcHash;

        public Message(int senderId, MessageType type, Object data) {
            this(senderId, type, data, null, false, null, false, null);
        }

        public Message(int senderId, MessageType type, Object data, String messageId, boolean requireAck, String ackForId) {
            this(senderId, type, data, messageId, requireAck, ackForId, false, null);
        }

        public Message(int senderId,
                       MessageType type,
                       Object data,
                       String messageId,
                       boolean requireAck,
                       String ackForId,
                       boolean rbc,
                       String rbcHash) {
            this.senderId = senderId;
            this.type = type;
            this.data = data;
            this.messageId = messageId;
            this.requireAck = requireAck;
            this.ackForId = ackForId;
            this.rbc = rbc;
            this.rbcHash = rbcHash;
        }

        public static Message ack(int senderId, String ackForId) {
            return new Message(senderId, MessageType.NET_ACK, null, null, false, ackForId, false, null);
        }
    }
}
