package com.example.mpc.service.cggmp.dkg;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.service.CggmpDkgService;
import com.example.mpc.service.NodeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public final class CggmpDkgMessageDispatcher {
    private static final Logger logger = LoggerFactory.getLogger(CggmpDkgMessageDispatcher.class);
    private final CggmpDkgService svc;

    public CggmpDkgMessageDispatcher(CggmpDkgService svc) {
        this.svc = svc;
    }

    public CompletableFuture<Void> handleMessage(int senderId, NodeService.Message message) {
        Object logTaskId = "N/A";
        if (message.data() instanceof Map<?, ?> map) {
            if (map.containsKey("taskId")) {
                logTaskId = map.get("taskId");
            }
        }
        logger.info("=== CGGMP DKG handleMessage: senderId={}, type={}, taskId={} ===",
                senderId, message.type(), logTaskId);
        Executor executor = ThreadPoolUtil.getComputationThreadPool();
        return CompletableFuture.runAsync(() -> {
            try {
                Object data = message.data();
                if (data instanceof byte[] bytes) {
                    Object decoded = CggmpDkgUtils.maybeDecompressDkgPayload(message.type(), bytes);
                    if (decoded != null) {
                        data = decoded;
                    }
                }
                logger.info("=== CGGMP DKG processing: type={} ===", message.type());
                switch (message.type()) {
                    case CGGMP_DKG_INIT:
                        svc.dkgMessageHandler.onDkgInit(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1:
                        svc.dkgMessageHandler.onDkgRound1(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND1_ECHO:
                        svc.dkgMessageHandler.onDkgRound1Echo(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2:
                        svc.dkgMessageHandler.onDkgRound2(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BROAD:
                        svc.dkgMessageHandler.onDkgRound2Broad(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND2_BATCH:
                        svc.dkgMessageHandler.onDkgRound2Batch(senderId, data);
                        break;
                    case CGGMP_DKG_ROUND3:
                        svc.dkgMessageHandler.onDkgRound3(senderId, data);
                        break;
                    case CGGMP_DKG_COMPLAINT:
                        svc.dkgMessageHandler.onDkgComplaint(senderId, data);
                        break;
                    case CGGMP_DKG_EXCLUDE:
                        svc.dkgMessageHandler.onDkgExclude(senderId, data);
                        break;
                    default:
                        logger.debug("Ignoring message of type {} for CGGMP DKG service", message.type());
                }
            } catch (Exception e) {
                logger.error("Error handling CGGMP DKG message", e);
                throw new RuntimeException(e);
            }
        }, executor);
    }
}
