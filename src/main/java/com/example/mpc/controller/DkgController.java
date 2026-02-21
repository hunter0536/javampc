package com.example.mpc.controller;

import com.example.mpc.service.DkgService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/dkg")
public class DkgController {
    private static final Logger logger = LoggerFactory.getLogger(DkgController.class);

    @Autowired
    private DkgService dkgService;
    
    /**
     * 生成分布式私钥并返回UUID
     * @return 包含任务ID的响应
     */
    @PostMapping("/start")
    public CompletableFuture<Map<String, Object>> generateKey() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 创建新的DKG任务
                String taskId = dkgService.createDkgTask();
                logger.info("Created DKG task {}", taskId);

                // 启动DKG过程（异步执行，不阻塞）
                dkgService.startDkgProcess(taskId)
                    .exceptionally(ex -> {
                        logger.error("Async DKG process failed for task {}: {}", taskId, ex.getMessage(), ex);
                        return null;
                    });
                logger.info("Requested DKG start for task {}", taskId);

                // 立即构建响应并返回
                Map<String, Object> response = new java.util.HashMap<>();
                response.put("taskId", taskId);
                response.put("status", "DKG process started");

                return response;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 根据UUID查询对应的任务是否执行完成
     * @param taskId 任务ID
     * @return 任务状态
     */
    @GetMapping("/status")
    public CompletableFuture<Map<String, Object>> getTaskStatus(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 参数验证
                if (taskId == null || taskId.isEmpty()) {
                    throw new IllegalArgumentException("taskId cannot be null or empty");
                }
                
                return dkgService.getTaskStatus(taskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 根据UUID查询群公钥
     * @param taskId 任务ID
     * @return 群公钥
     */
    @GetMapping("/public-key")
    public CompletableFuture<String> getGroupPublicKey(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 参数验证
                if (taskId == null || taskId.isEmpty()) {
                    throw new IllegalArgumentException("taskId cannot be null or empty");
                }
                
                return dkgService.getGroupPublicKey(taskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
