package com.example.mpc.controller;

import com.example.mpc.service.DkgService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/dkg")
public class DkgController {
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
                
                // 启动DKG过程
                dkgService.startDkgProcess(taskId).join();
                
                // 构建响应
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
    public CompletableFuture<Map<String, Object>> getTaskStatus(@RequestParam String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
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
    public CompletableFuture<String> getGroupPublicKey(@RequestParam String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return dkgService.getGroupPublicKey(taskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
