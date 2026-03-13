package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.NodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * 辅助密钥消息分发器
 * 根据消息类型将消息分发到对应的处理方法
 */
public final class CggmpAuxMessageDispatcher {
    private static final Logger logger = LoggerFactory.getLogger(CggmpAuxMessageDispatcher.class);
    private final CggmpAuxService svc;

    public CggmpAuxMessageDispatcher(CggmpAuxService svc) {
        this.svc = svc;
    }

    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data() instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            }
        }
        logger.info("=== CGGMP AUX handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type(), logTaskId);
        Executor executor = ThreadPoolUtil.getAuxDispatchThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data();
                logger.info("=== CGGMP AUX processing: type={} ===", message.type());
                switch (message.type()) {
                    case CGGMP_AUX_INIT:
                        svc.auxMessageHandler.handleCggmpAuxInit(senderId, data);
                        break;
                    case CGGMP_AUX_R1:
                        svc.auxMessageHandler.handleCggmpAuxR1(senderId, data);
                        break;
                    case CGGMP_AUX_R1_ECHO:
                        svc.auxMessageHandler.handleCggmpAuxR1Echo(senderId, data);
                        break;
                    case CGGMP_AUX_R2:
                        svc.auxMessageHandler.handleCggmpAuxR2(senderId, data);
                        break;
                    case CGGMP_AUX_R3:
                        svc.auxMessageHandler.handleCggmpAuxR3(senderId, data);
                        break;
                    case CGGMP_AUX_STATUS:
                        svc.auxMessageHandler.handleCggmpAuxStatus(senderId, data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP AUX service", message.type());
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP AUX message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }
}
