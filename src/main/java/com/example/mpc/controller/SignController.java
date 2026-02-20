package com.example.mpc.controller;

import com.example.mpc.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/sign")
public class SignController {
    @Autowired
    private SignatureService signatureService;
    
    /**
     * 根据群公钥对数据进行ECDSA签名（返回签名任务ID）
     * @param taskId DKG任务ID
     * @param message 要签名的数据
     * @return 签名任务ID
     */
    @PostMapping("/start")
    public CompletableFuture<Map<String, Object>> sign(@RequestParam String taskId, @RequestParam String message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 创建签名任务
                String signatureTaskId = signatureService.createSignatureTask(taskId, message);
                
                // 启动签名任务
                signatureService.startSignatureTask(signatureTaskId).join();
                
                // 构建响应
                Map<String, Object> response = new java.util.HashMap<>();
                response.put("signatureTaskId", signatureTaskId);
                response.put("dkgTaskId", taskId);
                response.put("message", message);
                response.put("status", "Signature process started");
                
                return response;
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 查询签名任务是否完成
     * @param signatureTaskId 签名任务ID
     * @return 签名任务状态
     */
    @GetMapping("/status")
    public CompletableFuture<Map<String, Object>> getSignatureTaskStatus(@RequestParam String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return signatureService.getSignatureTaskStatus(signatureTaskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * 查询签名结果
     * @param signatureTaskId 签名任务ID
     * @return 签名结果
     */
    @GetMapping("/result")
    public CompletableFuture<Map<String, Object>> getSignatureResult(@RequestParam String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return signatureService.getSignatureResult(signatureTaskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}
