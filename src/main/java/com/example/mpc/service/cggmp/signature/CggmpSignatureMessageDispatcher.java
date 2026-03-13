package com.example.mpc.service.cggmp.signature;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.NodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * CGGMP签名消息调度器
 * 负责将签名相关消息路由到对应的处理器
 */
public final class CggmpSignatureMessageDispatcher {
    private static final Logger logger = LoggerFactory.getLogger(CggmpSignatureMessageDispatcher.class);
    private final CggmpSignatureService svc;

    public CggmpSignatureMessageDispatcher(CggmpSignatureService svc) {
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
        Executor executor = ThreadPoolUtil.getSignatureDispatchThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data();
                logger.info("=== CGGMP processing: type={} ===", message.type());
                switch (message.type()) {
                    case CGGMP_SIGN_INIT:
                    case CGGMP_SIGN_OFFLINE_INIT:
                        svc.offlineHandler.handleCggmpSignOfflineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_ONLINE_INIT:
                        svc.onlineHandler.handleCggmpSignOnlineInit(senderId, data);
                        break;
                    case CGGMP_SIGN_OFFLINE_READY:
                        svc.offlineHandler.handleCggmpSignOfflineReady(senderId, data);
                        break;
                    case CGGMP_SIGN_COMPLAINT:
                        svc.controlHandler.handleCggmpSignComplaint(senderId, data);
                        break;
                    case CGGMP_SIGN_EXCLUDE:
                        svc.controlHandler.handleCggmpSignExclude(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R1:
                        svc.presignHandler.handlePresignR1(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R1_ECHO:
                        svc.presignHandler.handlePresignR1Echo(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R2:
                        svc.presignHandler.handlePresignR2(senderId, data);
                        break;
                    case CGGMP_PRESIGN_R3:
                        svc.presignHandler.handlePresignR3(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_COMMIT:
                        svc.onlineHandler.handleCggmpSignGammaCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_GAMMA_OPEN:
                        svc.onlineHandler.handleCggmpSignGammaOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_INIT:
                        svc.onlineHandler.handleCggmpSignMtaKaInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_KA_RESPONSE:
                        svc.onlineHandler.handleCggmpSignMtaKaResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_U_COMMIT:
                        svc.onlineHandler.handleCggmpSignUCommit(senderId, data);
                        break;
                    case CGGMP_SIGN_U_SHARE:
                        svc.onlineHandler.handleCggmpSignUShare(senderId, data);
                        break;
                    case CGGMP_SIGN_U_OPEN:
                        svc.onlineHandler.handleCggmpSignUOpen(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_INIT:
                        svc.onlineHandler.handleCggmpSignMtaStInit(senderId, data);
                        break;
                    case CGGMP_SIGN_MTA_ST_RESPONSE:
                        svc.onlineHandler.handleCggmpSignMtaStResponse(senderId, data);
                        break;
                    case CGGMP_SIGN_S_SHARE:
                        svc.onlineHandler.handleCggmpSignSShare(senderId, data);
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
