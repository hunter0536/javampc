package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.util.concurrent.GlobalEventExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务器端处理器
 */
public class ServerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(ServerHandler.class);
    private final Map<Integer, NodeService.MessageHandler> messageHandlers;
    private final Map<Integer, ChannelHandlerContext> nodeChannels = new ConcurrentHashMap<>();
    private final ChannelGroup allChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

    public ServerHandler(Map<Integer, NodeService.MessageHandler> messageHandlers) {
        this.messageHandlers = messageHandlers;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        allChannels.add(ctx);
        logger.info("Channel active: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        allChannels.remove(ctx);
        // 清理节点映射
        nodeChannels.entrySet().removeIf(entry -> entry.getValue().equals(ctx));
        logger.info("Channel inactive: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof NodeService.Message) {
            NodeService.Message message = (NodeService.Message) msg;
            logger.info("Received message from node {}: {}", message.senderId, message.type);

            // 注册节点通道映射
            nodeChannels.put(message.senderId, ctx);

            // 处理消息
            NodeService.MessageHandler handler = messageHandlers.get(message.senderId);
            if (handler != null) {
                try {
                    handler.handleMessage(message.senderId, message);
                } catch (Exception e) {
                    logger.error("Error handling message: {}", e.getMessage());
                }
            } else {
                logger.warn("No handler found for node {}", message.senderId);
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Exception caught: {}", cause.getMessage());
        ctx.close();
    }

    /**
     * 获取节点通道
     */
    public ChannelHandlerContext getNodeChannel(int nodeId) {
        return nodeChannels.get(nodeId);
    }

    /**
     * 获取所有通道
     */
    public ChannelGroup getAllChannels() {
        return allChannels;
    }
}
