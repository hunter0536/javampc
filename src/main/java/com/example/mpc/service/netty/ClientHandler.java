package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 客户端处理器
 */
public class ClientHandler extends ChannelInboundHandlerAdapter {
    private static final Logger logger = LoggerFactory.getLogger(ClientHandler.class);
    private ChannelHandlerContext ctx;
    private final ConcurrentHashMap<String, CompletableFuture<NodeService.Message>> pendingRequests = new ConcurrentHashMap<>();

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        this.ctx = ctx;
        logger.info("Client channel active: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Client channel inactive: {}", ctx.channel().remoteAddress());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof NodeService.Message) {
            NodeService.Message message = (NodeService.Message) msg;
            logger.info("Client received message: {}", message.type);

            // 处理响应
            // 这里可以根据消息ID匹配请求和响应
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Client exception caught: {}", cause.getMessage());
        ctx.close();
    }

    /**
     * 发送消息
     */
    public void sendMessage(NodeService.Message message) {
        if (ctx != null && ctx.channel().isActive()) {
            ctx.writeAndFlush(message);
            logger.info("Sent message: {}", message.type);
        } else {
            logger.error("Cannot send message: channel not active");
        }
    }

    /**
     * 获取通道上下文
     */
    public ChannelHandlerContext getContext() {
        return ctx;
    }
}
