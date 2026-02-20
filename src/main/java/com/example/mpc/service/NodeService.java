package com.example.mpc.service;

import com.example.mpc.constant.Constants;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class NodeService {
    
    private static final Logger logger = LoggerFactory.getLogger(NodeService.class);
    
    @Value("${node.id}")
    private int nodeId;
    
    @Value("${node.port}")
    private int nodePort;
    
    @Value("${nodes.count}")
    private int nodesCount;
    
    // 节点发现端口
    // 节点发现间隔（毫秒）
    
    // P2P通信
    private com.example.mpc.service.netty.NettyService nettyService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong taskCount = new AtomicLong(0);
    private final AtomicLong completedTaskCount = new AtomicLong(0);
    private final AtomicLong totalTaskTime = new AtomicLong(0);
    
    // 网络拓扑
    private final ConcurrentHashMap<Integer, NodeInfo> nodes = new ConcurrentHashMap<>();
    private final AtomicBoolean discoveryRunning = new AtomicBoolean(false);
    private final ConcurrentHashMap<Integer, MessageHandler> messageHandlers = new ConcurrentHashMap<>();
    
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
        public enum Type {
            COMMITMENT,      // 验证点（承诺）
            SHARE,            // 份额
            PUBLIC_KEY_PART,  // 公钥部分
            SIGNATURE_SHARE,  // 签名份额
            DKG_INIT,         // DKG初始化
            PING,             // 心跳
            PONG              // 心跳响应
        }
        
        public final int senderId;
        public final Type type;
        public final Object data;
        
        public Message(int senderId, Type type, Object data) {
            this.senderId = senderId;
            this.type = type;
            this.data = data;
        }
    }
    
    /**
     * 启动P2P服务器和节点发现
     */
    public CompletableFuture<Void> startP2PServer() {
        return com.example.mpc.util.ThreadPoolUtil.submitIoTask(() -> {
            if (running.get()) {
                return;
            }
            
            running.set(true);
            
            try {
                // 启动Netty服务器
                nettyService = new com.example.mpc.service.netty.NettyService(nodePort, messageHandlers);
                nettyService.startServer();
                
                // 启动节点发现
                submitTask(this::startNodeDiscovery);
                
                logger.info("P2P server started for node {} on port {}", nodeId, nodePort);
            } catch (Exception e) {
                logger.error("Error starting P2P server: {}", e.getMessage());
                running.set(false);
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
        com.example.mpc.util.ThreadPoolUtil.getIoThreadPool().submit(() -> {
            try (DatagramSocket socket = new DatagramSocket(Constants.DISCOVERY_PORT)) {
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
        com.example.mpc.util.ThreadPoolUtil.getIoThreadPool().submit(() -> {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setBroadcast(true);
                while (discoveryRunning.get()) {
                    String message = "DISCOVER_NODE:" + nodeId + ":" + nodePort;
                byte[] buffer = message.getBytes();
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName("255.255.255.255"), Constants.DISCOVERY_PORT);
                socket.send(packet);
                Thread.sleep(Constants.DISCOVERY_INTERVAL);
                }
            } catch (Exception e) {
                if (discoveryRunning.get()) {
                    e.printStackTrace();
                }
            }
        });
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
        return com.example.mpc.util.ThreadPoolUtil.submitIoTask(() -> {
            running.set(false);
            discoveryRunning.set(false);
            
            if (nettyService != null) {
                nettyService.shutdown();
            }
        });
    }
    

    
    /**
     * 发送消息到指定节点
     */
    public CompletableFuture<Void> sendMessage(int receiverId, Message message) {
        return com.example.mpc.util.ThreadPoolUtil.submitIoTask(() -> {
            NodeInfo nodeInfo = nodes.get(receiverId);
            if (nodeInfo == null) {
                throw new RuntimeException("Node " + receiverId + " not found in network");
            }
            
            try {
                // 检查是否已经连接到该节点
                if (nettyService != null) {
                    // 发送消息
                    nettyService.sendMessage(receiverId, message).join();
                } else {
                    throw new RuntimeException("Netty service not initialized");
                }
            } catch (Exception e) {
                logger.error("Failed to send message to node {}: {}", receiverId, e.getMessage());
                // 从节点列表中移除不可达节点
                nodes.remove(receiverId);
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 广播消息到所有其他节点
     */
    public CompletableFuture<Void> broadcastMessage(Message message) {
        if (nettyService != null) {
            return nettyService.broadcastMessage(message);
        } else {
            // 回退到传统方式
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            
            for (NodeInfo nodeInfo : nodes.values()) {
                if (nodeInfo.id != nodeId) {
                    CompletableFuture<Void> future = sendMessage(nodeInfo.id, message)
                        .exceptionally(ex -> {
                            logger.error("Failed to broadcast message to node {}: {}", nodeInfo.id, ex.getMessage());
                            return null;
                        });
                    futures.add(future);
                }
            }
            
            return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        }
    }
    
    /**
     * 注册消息处理器
     * @param nodeId 节点ID
     * @param handler 消息处理器
     */
    public void registerMessageHandler(int nodeId, MessageHandler handler) {
        messageHandlers.put(nodeId, handler);
    }
    
    /**
     * 取消注册消息处理器
     * @param nodeId 节点ID
     */
    public void unregisterMessageHandler(int nodeId) {
        messageHandlers.remove(nodeId);
    }
    
    /**
     * 获取当前网络中的节点列表
     * @return 节点列表
     */
    public List<NodeInfo> getNodes() {
        return new ArrayList<>(nodes.values());
    }
    
    /**
     * 等待网络稳定（至少发现所有节点）
     * @throws InterruptedException 中断异常
     */
    public CompletableFuture<Void> waitForNetworkReady() {
        return com.example.mpc.util.ThreadPoolUtil.submitIoTask(() -> {
            try {
                while (nodes.size() < nodesCount - 1) {
                    logger.info("Waiting for all nodes to be discovered... Current count: {}", nodes.size());
                    Thread.sleep(1000);
                }
                logger.info("Network ready with {} nodes", nodes.size() + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 检查网络是否稳定
     * @return 是否稳定
     */
    public boolean isNetworkReady() {
        return nodes.size() >= nodesCount - 1;
    }
    
    /**
     * 获取线程池状态
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
     * @param task 任务
     */
    public void submitTask(Runnable task) {
        long startTime = System.currentTimeMillis();
        taskCount.incrementAndGet();
        
        com.example.mpc.util.ThreadPoolUtil.getIoThreadPool().submit(() -> {
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