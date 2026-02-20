package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Netty服务
 */
public class NettyService {
    private static final Logger logger = LoggerFactory.getLogger(NettyService.class);
    private final int port;
    private final Map<Integer, NodeService.MessageHandler> messageHandlers;
    private final Map<Integer, ClientHandler> clientHandlers = new ConcurrentHashMap<>();
    private final Map<Integer, EventLoopGroup> clientGroups = new ConcurrentHashMap<>();
    
    private EventLoopGroup bossGroup;
    private EventLoopGroup workerGroup;
    private ChannelFuture serverFuture;
    private ServerHandler serverHandler;

    public NettyService(int port, Map<Integer, NodeService.MessageHandler> messageHandlers) {
        this.port = port;
        this.messageHandlers = messageHandlers;
    }

    /**
     * 启动服务器
     */
    public CompletableFuture<Void> startServer() {
        return CompletableFuture.runAsync(() -> {
            bossGroup = new NioEventLoopGroup(1);
            workerGroup = new NioEventLoopGroup();
            serverHandler = new ServerHandler(messageHandlers);

            try {
                ServerBootstrap b = new ServerBootstrap();
                b.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.SO_BACKLOG, 100)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(
                                new MessageDecoder(),
                                new MessageEncoder(),
                                serverHandler
                            );
                        }
                    });

                serverFuture = b.bind(port).sync();
                logger.info("Netty server started on port {}", port);
                
                // 非阻塞方式启动服务器
                serverFuture.channel().closeFuture().addListener(future -> {
                    logger.info("Netty server channel closed");
                    shutdown();
                });
            } catch (Exception e) {
                logger.error("Error starting Netty server: {}", e.getMessage());
                shutdown();
            }
        });
    }

    /**
     * 连接到其他节点
     */
    public CompletableFuture<Void> connectToNode(int nodeId, String host, int port) {
        return CompletableFuture.runAsync(() -> {
            EventLoopGroup group = new NioEventLoopGroup();
            ClientHandler clientHandler = new ClientHandler();

            try {
                Bootstrap b = new Bootstrap();
                b.group(group)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.SO_KEEPALIVE, true)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        public void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(
                                new MessageDecoder(),
                                new MessageEncoder(),
                                clientHandler
                            );
                        }
                    });

                ChannelFuture f = b.connect(host, port).sync();
                logger.info("Connected to node {} at {}:{}", nodeId, host, port);
                
                // 保存客户端处理器
                clientHandlers.put(nodeId, clientHandler);
                clientGroups.put(nodeId, group);
                
                // 非阻塞方式处理连接关闭
                f.channel().closeFuture().addListener(future -> {
                    logger.info("Connection to node {} closed", nodeId);
                    closeConnection(nodeId);
                });
            } catch (Exception e) {
                logger.error("Error connecting to node {}: {}", nodeId, e.getMessage());
                group.shutdownGracefully();
            }
        });
    }

    /**
     * 发送消息到指定节点
     */
    public CompletableFuture<Void> sendMessage(int nodeId, NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            ClientHandler handler = clientHandlers.get(nodeId);
            if (handler != null) {
                handler.sendMessage(message);
                logger.info("Sent message to node {}: {}", nodeId, message.type);
            } else {
                logger.error("No connection to node {}", nodeId);
                throw new RuntimeException("No connection to node " + nodeId);
            }
        });
    }

    /**
     * 广播消息
     */
    public CompletableFuture<Void> broadcastMessage(NodeService.Message message) {
        return CompletableFuture.runAsync(() -> {
            for (ClientHandler handler : clientHandlers.values()) {
                handler.sendMessage(message);
            }
            logger.info("Broadcasted message: {}", message.type);
        });
    }

    /**
     * 关闭连接
     */
    public void closeConnection(int nodeId) {
        ClientHandler handler = clientHandlers.remove(nodeId);
        EventLoopGroup group = clientGroups.remove(nodeId);
        if (group != null) {
            group.shutdownGracefully();
        }
        logger.info("Closed connection to node {}", nodeId);
    }

    /**
     * 关闭服务器
     */
    public void shutdown() {
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        
        // 关闭所有客户端连接
        for (int nodeId : clientGroups.keySet()) {
            closeConnection(nodeId);
        }
        
        logger.info("Netty service shutdown");
    }

    /**
     * 获取服务器处理器
     */
    public ServerHandler getServerHandler() {
        return serverHandler;
    }
}
