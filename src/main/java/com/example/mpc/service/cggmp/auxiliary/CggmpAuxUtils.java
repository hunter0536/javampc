package com.example.mpc.service.cggmp.auxiliary;

import com.example.mpc.model.AuxInfo;
import com.example.mpc.model.CggmpAuxTask;
import com.example.mpc.service.CggmpAuxService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public final class CggmpAuxUtils {
    private static final Logger logger = LoggerFactory.getLogger(CggmpAuxUtils.class);
    private CggmpAuxUtils() {
    }

    public static CompletableFuture<Void> waitForLatchAsync(CggmpAuxService svc, CggmpAuxTask task, CountDownLatch latch, long timeoutSeconds, String label) {
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(timeoutSeconds);
        CompletableFuture<Void> future = new CompletableFuture<>();
        ScheduledFuture<?> tick = svc.auxScheduler.scheduleAtFixedRate(() -> {
            if (latch.getCount() == 0) {
                future.complete(null);
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                task.lastErrorEvidence = buildAuxEvidence(task);
                future.completeExceptionally(new RuntimeException("Timeout waiting for " + label + " (taskId=" + task.taskId + ")"));
            }
        }, 0, 50, TimeUnit.MILLISECONDS);
        future.whenComplete((v, ex) -> tick.cancel(false));
        return future;
    }

    public static Map<String, Object> buildAuxEvidence(CggmpAuxTask task) {
        Map<String, Object> ev = new java.util.HashMap<>();
        ev.put("taskId", task.taskId);
        ev.put("executionId", task.executionId);
        ev.put("participants", task.participants);
        ev.put("commitReceived", task.commitHashes.size());
        ev.put("echoReceived", task.echoReceived.size());
        ev.put("revealReceived", task.peerHatN.size());
        ev.put("proofsReceived", task.peerModProofs.size());
        ev.put("commitLatch", task.commitLatch.getCount());
        ev.put("echoLatch", task.echoLatch.getCount());
        ev.put("revealLatch", task.revealLatch.getCount());
        ev.put("proofLatch", task.proofLatch.getCount());
        return ev;
    }

    static byte[] xorAuxRho(CggmpAuxTask task) {
        byte[] result = new byte[32];
        if (task.rho.isEmpty()) {
            return result;
        }
        for (byte[] rho : task.rho.values()) {
            if (rho == null || rho.length == 0) {
                continue;
            }
            int len = Math.min(rho.length, result.length);
            for (int i = 0; i < len; i++) {
                result[i] ^= rho[i];
            }
        }
        return result;
    }

    static void saveAuxInfo(CggmpAuxService svc, CggmpAuxTask task) {
        try {
            AuxInfo info = new AuxInfo(svc.nodeId, task.taskId);
            com.example.mpc.cggmp.PaillierEncryption.PrivateKey priv = task.paillier.getPrivateKeyInfo();
            info.setPaillierP(priv.p().toString(16));
            info.setPaillierQ(priv.q().toString(16));
            info.setPaillierN(priv.n().toString(16));
            info.setPaillierG(task.paillier.getPublicKeyInfo().g().toString(16));
            info.setPaillierBitLength(task.paillier.getPublicKeyInfo().bitLength());
            info.setPedersenHatN(task.hatN.toString(16));
            info.setPedersenS(task.s.toString(16));
            info.setPedersenT(task.t.toString(16));
            boolean inserted = svc.auxInfoDao.saveIfAbsentByTask(info);
            svc.auxPaillier = task.paillier;
            svc.auxHatN = task.hatN;
            svc.auxS = task.s;
            svc.auxT = task.t;
            if (inserted) {
                logger.info("Saved CGGMP AUX info for task: {}", task.taskId);
            } else {
                logger.info("CGGMP AUX info already persisted for task: {}", task.taskId);
            }
        } catch (Exception e) {
            logger.error("Failed to save CGGMP AUX info", e);
            throw new RuntimeException(e);
        }
    }
}
