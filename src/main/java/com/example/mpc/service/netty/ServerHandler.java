package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ServerHandler extends SimpleChannelInboundHandler<NodeService.Message> {
    private static final Logger logger = LoggerFactory.getLogger(ServerHandler.class);

    private final NettyService nettyService;
    private final Map<Integer, ? extends java.util.List<NodeService.MessageHandler>> messageHandlers;

    public ServerHandler(NettyService nettyService, Map<Integer, ? extends java.util.List<NodeService.MessageHandler>> messageHandlers) {
        this.nettyService = nettyService;
        this.messageHandlers = messageHandlers;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        logger.info("Client connected: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client disconnected: {}", ctx.channel().remoteAddress());
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, NodeService.Message message) {
        logger.info("Received message from node {}: {}", message.senderId, message.type);
        if (message.data instanceof java.util.Map) {
            Object taskId = ((java.util.Map<?, ?>) message.data).get("taskId");
            if (taskId != null) {
                logger.info("Message taskId: {}", taskId);
            }
        }

        // 处理消息：先分发给senderId注册的处理器，再分发给全局(-1)处理器
        var combinedHandlers = new java.util.LinkedHashSet<NodeService.MessageHandler>();
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
            return;
        }

        for (NodeService.MessageHandler handler : combinedHandlers) {
            try {
                CompletableFuture<Void> future = handler.handleMessage(message.senderId, message);
                future.thenAccept(v -> logger.debug("Message handled successfully"))
                        .exceptionally(ex -> {
                            logger.error("Error handling message: {}", ex.getMessage());
                            return null;
                        });
            } catch (Exception e) {
                logger.error("Error handling message: {}", e.getMessage());
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Exception in server handler: {}", cause.getMessage());
        ctx.close();
    }
}
