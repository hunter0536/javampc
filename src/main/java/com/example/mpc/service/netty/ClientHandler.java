package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientHandler extends SimpleChannelInboundHandler<NodeService.Message> {
    private static final Logger logger = LoggerFactory.getLogger(ClientHandler.class);

    private final int nodeId;
    private final NettyService nettyService;

    public ClientHandler(int nodeId, NettyService nettyService) {
        this.nodeId = nodeId;
        this.nettyService = nettyService;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        logger.info("Connected to server: {}", ctx.channel().remoteAddress());
        // 保存通道
        nettyService.addNodeChannel(nodeId, ctx.channel());
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        logger.info("Disconnected from server: {}", ctx.channel().remoteAddress());
        // 移除通道
        nettyService.removeNodeChannel(nodeId);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, NodeService.Message message) {
        logger.info("Received message from server: {}", message.type());
        // 客户端处理器主要用于发送消息，接收消息由服务端处理器处理
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Exception in client handler: {}", cause.getMessage());
        ctx.close();
    }
}