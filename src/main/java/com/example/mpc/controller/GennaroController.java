package com.example.mpc.controller;

import com.example.mpc.common.response.ApiResponse;
import com.example.mpc.common.response.DkgTaskStartResponse;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.service.GennaroDkgService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/gennaro")
public class GennaroController {
    private static final Logger logger = LoggerFactory.getLogger(GennaroController.class);

    @Autowired
    private GennaroDkgService gennaroDkgService;

    /**
     * 使用Gennaro协议生成分布式私钥并返回UUID
     *
     * @return 包含任务ID的响应
     */
    @PostMapping("/dkg/start")
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
     * 根据UUID查询对应的Gennaro协议DKG任务是否执行完成
     *
     * @param taskId 任务ID
     * @return 任务状态
     */
    @GetMapping("/dkg/status")
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
     * 根据UUID查询Gennaro协议DKG生成的群公钥
     *
     * @param taskId 任务ID
     * @return 群公钥
     */
    @GetMapping("/dkg/public-key")
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
