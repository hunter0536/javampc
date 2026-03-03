package com.example.mpc.controller;

import com.example.mpc.common.response.ApiResponse;
import com.example.mpc.common.response.DkgTaskStartResponse;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.service.GennaroDkgService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/gennaro")
public class GennaroController {
    private static final Logger logger = LoggerFactory.getLogger(GennaroController.class);

    @Autowired
    private GennaroDkgService gennaroDkgService;

    /**
     * 启动 Gennaro DKG 任务，生成分布式密钥对
     *
     * @return 任务ID
     */
    @GetMapping("/dkg/start")
    public CompletableFuture<ApiResponse<DkgTaskStartResponse>> generateKey() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = gennaroDkgService.createDkgTask();
                logger.info("Created DKG task {}", taskId);

                gennaroDkgService.startDkgProcess(taskId)
                        .exceptionally(ex -> {
                            logger.error("Async DKG process failed for task {}: {}", taskId, ex.getMessage(), ex);
                            return null;
                        });
                logger.info("Requested DKG start for task {}", taskId);

                DkgTaskStartResponse data = new DkgTaskStartResponse(taskId, "DKG process started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start DKG process", e);
                return ApiResponse.error("Failed to start DKG process: " + e.getMessage());
            }
        });
    }

    /**
     * 查询 Gennaro DKG 任务状态
     *
     * @param taskId 任务ID
     * @return 任务状态
     */
    @PostMapping("/dkg/status")
    public CompletableFuture<ApiResponse<DkgTaskStatusResponse>> getTaskStatus(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }

                DkgTaskStatusResponse status = gennaroDkgService.getTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get task status", e);
                return ApiResponse.error("Failed to get task status: " + e.getMessage());
            }
        });
    }

    /**
     * 查询 Gennaro DKG 生成的聚合公钥
     *
     * @param taskId 任务ID
     * @return 聚合公钥（Hex编码）
     */
    @PostMapping("/dkg/public-key")
    public CompletableFuture<ApiResponse<String>> getGroupPublicKey(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }

                String publicKey = gennaroDkgService.getGroupPublicKey(taskId);
                return ApiResponse.success(publicKey);
            } catch (Exception e) {
                logger.error("Failed to get group public key", e);
                return ApiResponse.error("Failed to get group public key: " + e.getMessage());
            }
        });
    }
}
