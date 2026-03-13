package com.example.mpc.service.cggmp.refresh;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.service.CggmpRefreshService;
import com.example.mpc.service.NodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * 密钥刷新消息分发器
 * 根据消息类型将消息分发到对应的处理方法
 */
public final class CggmpRefreshMessageDispatcher {
    private static final Logger logger = LoggerFactory.getLogger(CggmpRefreshMessageDispatcher.class);
    private final CggmpRefreshService svc;

    public CggmpRefreshMessageDispatcher(CggmpRefreshService svc) {
        this.svc = svc;
    }

    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data() instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            } else if (map.containsKey("signatureTaskId")) {
                logTaskId = map.get("signatureTaskId");
            }
        }
        logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type(), logTaskId);
        Executor executor = ThreadPoolUtil.getRefreshDispatchThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data();
                if (data instanceof byte[] bytes) {
                    Object decoded = CggmpRefreshUtils.maybeDecompressPayload(message.type(), bytes);
                    if (decoded != null) {
                        data = decoded;
                    }
                }
                logger.info("=== CGGMP processing: type={} ===", message.type());
                switch (message.type()) {
                    case CGGMP_REFRESH_INIT:
                        svc.refreshMessageHandler.onRefreshInit(senderId, data);
                        break;
                    case CGGMP_REFRESH_R1:
                        svc.refreshMessageHandler.onRefreshR1(senderId, data);
                        break;
                    case CGGMP_REFRESH_R2:
                        svc.refreshMessageHandler.onRefreshR2(senderId, data);
                        break;
                    case CGGMP_REFRESH_R3:
                        svc.refreshMessageHandler.onRefreshR3(senderId, data);
                        break;
                    case CGGMP_REFRESH_COMPLAINT:
                        svc.refreshMessageHandler.onRefreshComplaint(senderId, data);
                        break;
                    case CGGMP_REFRESH_EXCLUDE:
                        svc.refreshMessageHandler.onRefreshExclude(senderId, data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP service", message.type());
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }
}
