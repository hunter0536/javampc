package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerHandler extends SimpleChannelInboundHandler<Object> {
    private static final Logger logger = LoggerFactory.getLogger(ServerHandler.class);

    private final NettyService nettyService;
    private final String sharedSecret;
    private final boolean sslEnabled;

    public ServerHandler(NettyService nettyService,
                         String sharedSecret,
                         boolean sslEnabled) {
        this.nettyService = nettyService;
        this.sharedSecret = sharedSecret;
        this.sslEnabled = sslEnabled;
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
    protected void channelRead0(ChannelHandlerContext ctx, Object raw) {
        NodeService.Message message = unwrapSigned(raw);
        if (message == null) {
            logger.warn("Rejected unsigned/invalid message");
            return;
        }
        nettyService.handleInbound(message.senderId, message)
                .thenAccept(v -> logger.debug("Message handled successfully"))
                .exceptionally(ex -> {
                    logger.error("Error handling message: {}", ex.getMessage());
                    return null;
                });
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        logger.error("Exception in server handler: {}", cause.getMessage());
        ctx.close();
    }

    private NodeService.Message unwrapSigned(Object raw) {
        if (raw instanceof SignedMessage sm) {
            if (sslEnabled || sharedSecret == null || sharedSecret.isBlank()) {
                return sm.message;
            }
            String payload = MessageSigner.canonicalPayload(sm.message);
            if (!MessageSigner.verify(payload, sharedSecret, sm.signature)) {
                return null;
            }
            return sm.message;
        }
        if (raw instanceof NodeService.Message msg) {
            return msg;
        }
        return null;
    }
}
