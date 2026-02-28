package com.example.mpc.service;

import com.example.mpc.common.util.ThreadPoolUtil;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

final class CggmpSignatureMessageDispatcher {
    private final CggmpSignatureService svc;

    CggmpSignatureMessageDispatcher(CggmpSignatureService svc) {
        this.svc = svc;
    }

    CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            } else if (map.containsKey("signatureTaskId")) {
                logTaskId = map.get("signatureTaskId");
            }
        }
        svc.logger.info("=== CGGMP handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type, logTaskId);
        Executor executor = ThreadPoolUtil.getSingleThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data;
                svc.logger.info("=== CGGMP processing: type={} ===", message.type);
                switch (message.type) {
                    case GG20_SIGN_INIT:
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
                        svc.logger.debug("Ignoring message of type {} for CGGMP service", message.type);
                }
            } catch (Exception e) {
                svc.logger.error("Error handling CGGMP message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }
}
