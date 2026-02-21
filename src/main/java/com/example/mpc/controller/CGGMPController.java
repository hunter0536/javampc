package com.example.mpc.controller;

import com.example.mpc.service.CGGMPKeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/cggmp")
public class CGGMPController {
    private static final Logger logger = LoggerFactory.getLogger(CGGMPController.class);

    @Autowired
    private CGGMPKeyService cggmpKeyService;

    @PostMapping("/start")
    public CompletableFuture<Map<String, Object>> generateKey() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = cggmpKeyService.createDkgTask();
                logger.info("Created CGGMP DKG task {}", taskId);

                cggmpKeyService.startDkgProcess(taskId)
                    .thenAccept(result -> logger.info("DKG process completed for task {}", taskId))
                    .exceptionally(ex -> {
                        logger.error("Async CGGMP DKG process failed for task {}: {}", taskId, ex.getMessage(), ex);
                        return null;
                    });
                logger.info("Requested CGGMP DKG start for task {}", taskId);

                Map<String, Object> response = new HashMap<>();
                response.put("taskId", taskId);
                response.put("status", "CGGMP DKG process started");

                return response;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }

    @GetMapping("/status")
    public CompletableFuture<Map<String, Object>> getTaskStatus(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    throw new IllegalArgumentException("taskId cannot be null or empty");
                }
                
                return cggmpKeyService.getTaskStatus(taskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }

    @GetMapping("/public-key")
    public CompletableFuture<String> getGroupPublicKey(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    throw new IllegalArgumentException("taskId cannot be null or empty");
                }
                
                return cggmpKeyService.getGroupPublicKey(taskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }

    @PostMapping("/sign/start")
    public CompletableFuture<Map<String, Object>> sign(@RequestParam(required = true) String groupPublicKey, @RequestParam(required = true) String message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    throw new IllegalArgumentException("groupPublicKey cannot be null or empty");
                }
                if (message == null || message.isEmpty()) {
                    throw new IllegalArgumentException("message cannot be null or empty");
                }
                
                String signatureTaskId = cggmpKeyService.createSignatureTaskWithGroupKey(groupPublicKey, message);
                
                cggmpKeyService.startSignatureTask(signatureTaskId)
                    .exceptionally(ex -> {
                        logger.error("Async GG20 signature process failed for task {}: {}", signatureTaskId, ex.getMessage(), ex);
                        return null;
                    });
                
                Map<String, Object> response = new HashMap<>();
                response.put("signatureTaskId", signatureTaskId);
                response.put("groupPublicKey", groupPublicKey);
                response.put("message", message);
                response.put("status", "CGGMP signature process started");
                
                return response;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }

    @GetMapping("/sign/status")
    public CompletableFuture<Map<String, Object>> getSignatureTaskStatus(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    throw new IllegalArgumentException("signatureTaskId cannot be null or empty");
                }
                
                return cggmpKeyService.getSignatureTaskStatus(signatureTaskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }

    @GetMapping("/sign/result")
    public CompletableFuture<Map<String, Object>> getSignatureResult(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    throw new IllegalArgumentException("signatureTaskId cannot be null or empty");
                }
                
                return cggmpKeyService.getSignatureResult(signatureTaskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
