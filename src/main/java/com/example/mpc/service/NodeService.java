package com.example.mpc.service;

import com.example.mpc.constant.Constants;
import com.example.mpc.enums.MessageType;
import com.example.mpc.service.netty.NettyService;
import com.example.mpc.common.util.ThreadPoolUtil;
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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
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
    private ScheduledExecutorService discoveryScheduler;
    private final ConcurrentHashMap<String, java.util.Set<Integer>> reliablePending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CompletableFuture<Void>> reliableFutures = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RbcState> rbcStates = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, java.util.Set<Integer>> pendingRbcEchoes = new ConcurrentHashMap<>();

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
                nettyService = new NettyService(nodeId, nodePort, messageHandlers, sharedSecret,
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
                    handleDiscoveryMessage(message, packet.getAddress(), packet.getPort());
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
                    nettyService.connectToNode(peerId, host, port)
                            .exceptionally(ex -> {
                                logger.error("Failed to connect to static peer {}: {}", trimmed, ex.getMessage());
                                return null;
                            });
                }
            } catch (Exception e) {
                logger.warn("Invalid peer config: {}", trimmed);
            }
        }
    }

    /**
     * 处理发现消息
     */
    private void handleDiscoveryMessage(String message, InetAddress address, int port) {
        if (message.startsWith("DISCOVER_NODE:")) {
            String[] parts = message.split(":");
            if (parts.length == 3) {
                try {
                    int nodeId = Integer.parseInt(parts[1]);
                    int nodePort = Integer.parseInt(parts[2]);

                    // 不添加自己
                    if (nodeId != this.nodeId) {
                        NodeInfo nodeInfo = new NodeInfo(nodeId, address.getHostAddress(), nodePort);
                        nodes.put(nodeId, nodeInfo);
                        logger.info("Discovered node: {} at {}:{}", nodeId, address.getHostAddress(), nodePort);

                        // 自动连接到新发现的节点
                        if (nettyService != null) {
                            submitTask(() -> {
                                try {
                                    nettyService.connectToNode(nodeId, address.getHostAddress(), nodePort).join();
                                    logger.info("Connected to newly discovered node: {}", nodeId);
                                } catch (Exception e) {
                                    logger.error("Failed to connect to node {}: {}", nodeId, e.getMessage());
                                }
                            });
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
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
        });
    }

    /**
     * 发送消息到指定节点
     */
    public CompletableFuture<Void> sendMessage(int receiverId, Message message) {
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
        return ThreadPoolUtil.submitToIoThreadPool(() -> {
            String msgId = message.messageId != null ? message.messageId : java.util.UUID.randomUUID().toString();
            Message reliable = message.requireAck ? message
                    : new Message(message.senderId, message.type, message.data, msgId, true, null);
            java.util.Set<Integer> pending = java.util.concurrent.ConcurrentHashMap.newKeySet();
            pending.addAll(nodes.keySet());
            pending.remove(nodeId);
            if (pending.isEmpty()) {
                return;
            }
            CompletableFuture<Void> ackFuture = new CompletableFuture<>();
            reliablePending.put(msgId, pending);
            reliableFutures.put(msgId, ackFuture);
            int attempts = Math.max(1, reliableBroadcastRetryCount);
            for (int attempt = 1; attempt <= attempts; attempt++) {
                if (pending.isEmpty()) {
                    break;
                }
                List<CompletableFuture<Integer>> futures = new ArrayList<>();
                for (int peerId : pending) {
                    futures.add(sendMessage(peerId, reliable)
                            .thenApply(v -> peerId)
                            .exceptionally(ex -> null));
                }
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                if (!pending.isEmpty() && attempt < attempts) {
                    try {
                        Thread.sleep(reliableBroadcastRetryIntervalMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            if (!pending.isEmpty()) {
                logger.warn("Reliable broadcast failed for {} peers: {}", message.type, pending);
                ackFuture.completeExceptionally(new RuntimeException("Reliable broadcast failed for peers " + pending));
            } else {
                ackFuture.complete(null);
            }
            reliablePending.remove(msgId);
            reliableFutures.remove(msgId);
            ackFuture.join();
        });
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
        broadcastRbcEcho(rbc).join();
        return broadcastReliable(rbc).thenCompose(v -> state.delivered);
    }

    private CompletableFuture<Void> broadcastRbcEcho(Message original) {
        Map<String, Object> data = new HashMap<>();
        data.put("messageId", original.messageId);
        data.put("hash", original.rbcHash);
        data.put("origSenderId", original.senderId);
        data.put("type", original.type.name());
        Message echo = new Message(nodeId, MessageType.NET_RBC_ECHO, data, null, false, null, false, null);
        return broadcastMessage(echo);
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

    CompletableFuture<Void> handleInboundMessage(int senderId, Message message) throws Exception {
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
        var senderHandlers = messageHandlers.get(message.senderId);
        if (senderHandlers != null) {
            combinedHandlers.addAll(senderHandlers);
        }
        var globalHandlers = messageHandlers.get(-1);
        if (globalHandlers != null) {
            combinedHandlers.addAll(globalHandlers);
        }
        if (combinedHandlers.isEmpty()) {
            logger.warn("No handlers registered for message from node {} (keys={})", message.senderId, messageHandlers.keySet());
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
        return ThreadPoolUtil.submitIoTask(() -> {
            try {
                while (true) {
                    if (nodes.size() < nodesCount - 1) {
                        logger.info("Waiting for all nodes to be discovered... Current count: {}", nodes.size());
                        Thread.sleep(1000);
                        continue;
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
                                try {
                                    nettyService.connectToNode(nodeInfo.id, nodeInfo.host, nodeInfo.port).join();
                                } catch (Exception e) {
                                    logger.debug("Waiting for peer connection to node {}: {}", nodeInfo.id, e.getMessage());
                                }
                            }
                        }
                    }

                    if (!allConnected) {
                        logger.info("Waiting for all peer connections to be active...");
                        Thread.sleep(1000);
                        continue;
                    }

                    logger.info("Network ready with {} nodes", nodes.size() + 1);
                    break;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
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
}
