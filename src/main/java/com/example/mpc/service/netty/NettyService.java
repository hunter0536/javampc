package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.serialization.ClassResolvers;
import io.netty.handler.codec.serialization.ObjectDecoder;
import io.netty.handler.codec.serialization.ObjectEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class NettyService {
    private static final Logger logger = LoggerFactory.getLogger(NettyService.class);
    
    private final int port;
    private final Map<Integer, ? extends java.util.List<NodeService.MessageHandler>> messageHandlers;
    private final Map<Integer, Channel> nodeChannels = new ConcurrentHashMap<>();
    
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private EventLoopGroup clientGroup; // 共享的客户端连接线程池
    private Channel serverChannel;
    
    public NettyService(int port, Map<Integer, ? extends java.util.List<NodeService.MessageHandler>> messageHandlers) {
        this.port = port;
        this.messageHandlers = messageHandlers;
        this.clientGroup = new NioEventLoopGroup();
    }
    
    /**
     * 启动Netty服务器
     */
    public void startServer() throws InterruptedException {
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        
        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             .childHandler(new ChannelInitializer<SocketChannel>() {
                 @Override
                 public void initChannel(SocketChannel ch) throws Exception {
                     ChannelPipeline pipeline = ch.pipeline();
                     pipeline.addLast(new ObjectEncoder());
                     pipeline.addLast(new ObjectDecoder(Integer.MAX_VALUE, ClassResolvers.cacheDisabled(null)));
                     pipeline.addLast(new ServerHandler(NettyService.this, messageHandlers));
                 }
             })
             .option(ChannelOption.SO_BACKLOG, 128)
             .childOption(ChannelOption.SO_KEEPALIVE, true);
            
            // 绑定端口并启动服务器
            ChannelFuture f = b.bind(port).sync();
            serverChannel = f.channel();
            logger.info("Netty server started on port {}", port);
            
            // 等待服务器关闭
            // f.channel().closeFuture().sync();
        } catch (InterruptedException e) {
            logger.error("Error starting Netty server: {}", e.getMessage());
            throw e;
        }
    }
    
    /**
     * 连接到其他节点
     */
    public CompletableFuture<Void> connectToNode(int nodeId, String host, int port) {
        CompletableFuture<Void> future = new CompletableFuture<>();
        
        try {
            Bootstrap b = new Bootstrap();
            b.group(clientGroup)
             .channel(NioSocketChannel.class)
             .option(ChannelOption.SO_KEEPALIVE, true)
             .handler(new ChannelInitializer<SocketChannel>() {
                 @Override
                 public void initChannel(SocketChannel ch) throws Exception {
                     ChannelPipeline pipeline = ch.pipeline();
                     pipeline.addLast(new ObjectEncoder());
                     pipeline.addLast(new ObjectDecoder(Integer.MAX_VALUE, ClassResolvers.cacheDisabled(null)));
                     pipeline.addLast(new ClientHandler(nodeId, NettyService.this));
                 }
             });
            
            // 连接到远程节点
            ChannelFuture f = b.connect(host, port).addListener((ChannelFutureListener) future1 -> {
                if (future1.isSuccess()) {
                    nodeChannels.put(nodeId, future1.channel());
                    logger.info("Connected to node {} at {}:{}", nodeId, host, port);
                    future.complete(null);
                } else {
                    logger.error("Failed to connect to node {}: {}", nodeId, future1.cause().getMessage());
                    future.completeExceptionally(future1.cause());
                }
            });
            
            // 等待连接完成
            f.sync();
        } catch (Exception e) {
            logger.error("Error connecting to node {}: {}", nodeId, e.getMessage());
            future.completeExceptionally(e);
        }
        
        return future;
    }
    
    /**
     * 发送消息到指定节点
     */
    public CompletableFuture<Void> sendMessage(int nodeId, NodeService.Message message) {
        CompletableFuture<Void> future = new CompletableFuture<>();
        
        Channel channel = nodeChannels.get(nodeId);
        logger.info("sendMessage: to node {} type {} channelActive={}", nodeId, message.type, channel != null && channel.isActive());
        if (channel != null && channel.isActive()) {
            channel.writeAndFlush(message).addListener((ChannelFutureListener) future1 -> {
                if (future1.isSuccess()) {
                    future.complete(null);
                } else {
                    logger.error("Failed to send message to node {}: {}", nodeId, future1.cause().getMessage());
                    future.completeExceptionally(future1.cause());
                }
            });
        } else {
            future.completeExceptionally(new RuntimeException("Channel not found or inactive for node " + nodeId));
        }
        
        return future;
    }
    
    /**
     * 广播消息到所有节点
     */
    public CompletableFuture<Void> broadcastMessage(NodeService.Message message) {
        if (nodeChannels.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }
        
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        
        try {
            for (Map.Entry<Integer, Channel> entry : nodeChannels.entrySet()) {
                int nodeId = entry.getKey();
                Channel channel = entry.getValue();
                
                if (channel != null && channel.isActive()) {
                    CompletableFuture<Void> nodeFuture = new CompletableFuture<>();
                    channel.writeAndFlush(message).addListener((ChannelFutureListener) future1 -> {
                        if (future1.isSuccess()) {
                            nodeFuture.complete(null);
                        } else {
                            logger.error("Failed to broadcast message to node {}: {}", nodeId, future1.cause().getMessage());
                            nodeFuture.complete(null); // 单个节点失败不影响整体广播
                        }
                    });
                    futures.add(nodeFuture);
                }
            }
            
            return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
        } catch (Exception e) {
            logger.error("Error broadcasting message: {}", e.getMessage());
            return CompletableFuture.failedFuture(e);
        }
    }
    
    /**
     * 关闭Netty服务
     */
    public void shutdown() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (clientGroup != null) {
            clientGroup.shutdownGracefully();
        }
        if (serverChannel != null) {
            serverChannel.close();
        }
        logger.info("Netty service shutdown");
    }
    
    /**
     * 获取节点通道
     */
    public Channel getNodeChannel(int nodeId) {
        return nodeChannels.get(nodeId);
    }
    
    /**
     * 添加节点通道
     */
    public void addNodeChannel(int nodeId, Channel channel) {
        nodeChannels.put(nodeId, channel);
    }
    
    /**
     * 移除节点通道
     */
    public void removeNodeChannel(int nodeId) {
        nodeChannels.remove(nodeId);
    }
}
