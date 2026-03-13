package com.example.mpc.service.netty;

import com.example.mpc.service.NodeService;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerHandler extends SimpleChannelInboundHandler<Object> {
    private static final Logger logger = LoggerFactory.getLogger(ServerHandler.class);
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> REPLAY_CACHE = new java.util.concurrent.ConcurrentHashMap<>();

    private final NettyService nettyService;
    private final String sharedSecret;
    private final boolean sslEnabled;
    private final long replayWindowMs;
    private final long replayMaxSkewMs;
    private final int replayMaxCacheSize;

    public ServerHandler(NettyService nettyService,
                         String sharedSecret,
                         boolean sslEnabled,
                         long replayWindowMs,
                         long replayMaxSkewMs,
                         int replayMaxCacheSize) {
        this.nettyService = nettyService;
        this.sharedSecret = sharedSecret;
        this.sslEnabled = sslEnabled;
        this.replayWindowMs = replayWindowMs;
        this.replayMaxSkewMs = replayMaxSkewMs;
        this.replayMaxCacheSize = replayMaxCacheSize;
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
        nettyService.handleInbound(message.senderId(), message)
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
            if (!sslEnabled) {
                return null;
            }
            if (sharedSecret == null || sharedSecret.isBlank()) {
                return null;
            }
            String payload = MessageSigner.canonicalPayload(sm.message());
            if (!MessageSigner.verify(payload, sharedSecret, sm.signature())) {
                return null;
            }
            if (!passesReplayProtection(sm)) {
                return null;
            }
            return sm.message();
        }
        return null;
    }

    private boolean passesReplayProtection(SignedMessage sm) {
        NodeService.Message msg = sm.message();
        String messageId = msg == null ? null : msg.messageId();
        if (messageId == null || messageId.isBlank()) {
            logger.warn("Rejected message without messageId (senderId={})", msg == null ? "?" : msg.senderId());
            return false;
        }
        long now = System.currentTimeMillis();
        long ts = sm.timestampMs();
        if (ts > now + replayMaxSkewMs || now - ts > replayWindowMs) {
            logger.warn("Rejected message outside replay window (senderId={}, messageId={}, ts={}, now={})",
                    msg.senderId(), messageId, ts, now);
            return false;
        }
        String key = msg.senderId() + ":" + messageId;
        Long existing = REPLAY_CACHE.putIfAbsent(key, ts);
        if (existing != null) {
            logger.warn("Rejected replayed message (senderId={}, messageId={})", msg.senderId(), messageId);
            return false;
        }
        if (REPLAY_CACHE.size() > replayMaxCacheSize) {
            cleanupReplayCache(now);
        }
        return true;
    }

    private void cleanupReplayCache(long now) {
        long cutoff = now - replayWindowMs;
        REPLAY_CACHE.entrySet().removeIf(e -> e.getValue() < cutoff);
    }
}
