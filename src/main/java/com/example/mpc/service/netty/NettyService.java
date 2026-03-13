package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.serialization.ClassResolvers;
import io.netty.handler.codec.serialization.ObjectDecoder;
import io.netty.handler.codec.serialization.ObjectEncoder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

public class NettyService {
    private static final Logger logger = LoggerFactory.getLogger(NettyService.class);

    private final int nodeId;
    private final int port;
    private final java.util.function.BiConsumer<Integer, String> ackHandler;
    private final java.util.function.BiFunction<Integer, NodeService.Message, CompletableFuture<Void>> inboundHandler;
    private final String sharedSecret;
    private final Map<Integer, Channel> nodeChannels = new ConcurrentHashMap<>();
    private final boolean sslEnabled;
    private final String certPath;
    private final String keyPath;
    private final String trustCertPath;
    private final long replayWindowMs;
    private final long replayMaxSkewMs;
    private final int replayMaxCacheSize;

    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private final EventLoopGroup clientGroup; // 共享的客户端连接线程池
    private Channel serverChannel;
    private volatile SslContext serverSslContext;
    private volatile SslContext clientSslContext;

    public NettyService(int nodeId,
                        int port,
                        String sharedSecret,
                        boolean sslEnabled,
                        String certPath,
                        String keyPath,
                        String trustCertPath,
                        long replayWindowMs,
                        long replayMaxSkewMs,
                        int replayMaxCacheSize,
                        java.util.function.BiConsumer<Integer, String> ackHandler,
                        java.util.function.BiFunction<Integer, NodeService.Message, CompletableFuture<Void>> inboundHandler) {
        this.nodeId = nodeId;
        this.port = port;
        this.sharedSecret = sharedSecret;
        this.sslEnabled = sslEnabled;
        this.certPath = certPath;
        this.keyPath = keyPath;
        this.trustCertPath = trustCertPath;
        this.replayWindowMs = replayWindowMs;
        this.replayMaxSkewMs = replayMaxSkewMs;
        this.replayMaxCacheSize = replayMaxCacheSize;
        this.ackHandler = ackHandler;
        this.inboundHandler = inboundHandler;
        int cpuCores = Runtime.getRuntime().availableProcessors();
        this.clientGroup = new NioEventLoopGroup(cpuCores * 2);
    }

    /**
     * 启动Netty服务器
     */
    public void startServer() throws InterruptedException {
        int cpuCores = Runtime.getRuntime().availableProcessors();
        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup(cpuCores * 2);

        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline pipeline = ch.pipeline();
                            if (sslEnabled) {
                                pipeline.addLast(serverSslContext().newHandler(ch.alloc()));
                            }
                            pipeline.addLast(new ObjectEncoder());
                            pipeline.addLast(new ObjectDecoder(10 * 1024 * 1024, ClassResolvers.weakCachingConcurrentResolver(null)));
                            pipeline.addLast(new ServerHandler(NettyService.this, sharedSecret, sslEnabled,
                                    replayWindowMs, replayMaxSkewMs, replayMaxCacheSize));
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childOption(ChannelOption.SO_KEEPALIVE, true)
                    .childOption(ChannelOption.SO_RCVBUF, 1048576)
                    .childOption(ChannelOption.SO_SNDBUF, 1048576)
                    .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childOption(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(256 * 1024, 1024 * 1024));

            // 绑定端口并启动服务器
            ChannelFuture f = b.bind(port).sync();
            serverChannel = f.channel();
            logger.info("Netty server started on port {}", port);

            // 等待服务器关闭
            // f.channel().closeFuture().sync(); // 等待通道关闭
        } catch (InterruptedException e) {
            logger.error("Error starting Netty server: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * 连接到其他节点
     */
    public CompletableFuture<Void> connectToNode(int nodeId, String host, int port) {
        Channel existingChannel = nodeChannels.get(nodeId);
        if (existingChannel != null && existingChannel.isActive()) {
            logger.debug("Already connected to node {} at {}:{}, skipping", nodeId, host, port);
            return CompletableFuture.completedFuture(null);
        }

        CompletableFuture<Void> future = new CompletableFuture<>();

        try {
            Bootstrap b = new Bootstrap();
            b.group(clientGroup)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.TCP_NODELAY, true)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .option(ChannelOption.SO_RCVBUF, 1048576)
                    .option(ChannelOption.SO_SNDBUF, 1048576)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline pipeline = ch.pipeline();
                            if (sslEnabled) {
                                pipeline.addLast(clientSslContext().newHandler(ch.alloc(), host, port));
                            }
                            pipeline.addLast(new ObjectEncoder());
                            pipeline.addLast(new ObjectDecoder(10 * 1024 * 1024, ClassResolvers.weakCachingConcurrentResolver(null)));
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
        logger.info("sendMessage: to node {} type {} channelActive={}", nodeId, message.type(), channel != null && channel.isActive());
        if (channel != null && channel.isActive()) {
            Object payload = wrapSigned(message);
            channel.writeAndFlush(payload).addListener((ChannelFutureListener) future1 -> {
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

    public void sendAck(int receiverId, String ackForId) {
        if (ackForId == null) {
            return;
        }
        sendMessage(receiverId, NodeService.Message.ack(nodeId, ackForId))
                .exceptionally(ex -> {
                    logger.warn("Failed to send ACK to node {}: {}", receiverId, ex.getMessage());
                    return null;
                });
    }

    public void handleAck(int senderId, String ackForId) {
        if (ackHandler != null) {
            ackHandler.accept(senderId, ackForId);
        }
    }

    public CompletableFuture<Void> handleInbound(int senderId, NodeService.Message message) {
        if (inboundHandler == null) {
            return CompletableFuture.completedFuture(null);
        }
        try {
            return inboundHandler.apply(senderId, message);
        } catch (Exception e) {
            CompletableFuture<Void> f = new CompletableFuture<>();
            f.completeExceptionally(e);
            return f;
        }
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
                    Object payload = wrapSigned(message);
                    channel.writeAndFlush(payload).addListener((ChannelFutureListener) future1 -> {
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

    private Object wrapSigned(NodeService.Message message) {
        if (!sslEnabled) {
            throw new RuntimeException("TLS is required for node-to-node communication.");
        }
        if (sharedSecret == null || sharedSecret.isBlank()) {
            throw new RuntimeException("HMAC shared secret is required for node-to-node communication.");
        }
        NodeService.Message signedMessage = message;
        if (message.messageId() == null || message.messageId().isBlank()) {
            String newId = java.util.UUID.randomUUID().toString();
            signedMessage = new NodeService.Message(
                    message.senderId(),
                    message.type(),
                    message.data(),
                    newId,
                    message.requireAck(),
                    message.ackForId(),
                    message.rbc(),
                    message.rbcHash()
            );
        }
        String payload = MessageSigner.canonicalPayload(signedMessage);
        String sig = MessageSigner.sign(payload, sharedSecret);
        return new SignedMessage(signedMessage, sig, System.currentTimeMillis());
    }

    private SslContext serverSslContext() throws SSLException {
        if (serverSslContext != null) {
            return serverSslContext;
        }
        synchronized (this) {
            if (serverSslContext != null) {
                return serverSslContext;
            }
            serverSslContext = SslContextBuilder.forServer(new File(certPath), new File(keyPath)).build();
            return serverSslContext;
        }
    }

    private SslContext clientSslContext() throws SSLException {
        if (clientSslContext != null) {
            return clientSslContext;
        }
        synchronized (this) {
            if (clientSslContext != null) {
                return clientSslContext;
            }
            SslContextBuilder builder = SslContextBuilder.forClient();
            if (trustCertPath != null && !trustCertPath.isBlank()) {
                builder.trustManager(new File(trustCertPath));
            }
            clientSslContext = builder.build();
            return clientSslContext;
        }
    }
}
