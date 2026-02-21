package com.example.mpc.controller;

import com.example.mpc.service.SignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/sign")
public class SignController {
    @Autowired
    private SignatureService signatureService;
    
    /**
     * 根据群公钥对数据进行ECDSA签名（返回签名任务ID）
     * @param groupPublicKey 群公钥
     * @param message 要签名的数据
     * @return 签名任务ID
     */
    @PostMapping("/start")
    public CompletableFuture<Map<String, Object>> sign(@RequestParam(required = true) String groupPublicKey, @RequestParam(required = true) String message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 参数验证
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    throw new IllegalArgumentException("groupPublicKey cannot be null or empty");
                }
                if (message == null || message.isEmpty()) {
                    throw new IllegalArgumentException("message cannot be null or empty");
                }
                
                // 创建签名任务
                String signatureTaskId = signatureService.createSignatureTaskWithGroupKey(groupPublicKey, message);
                
                // 启动签名任务
                signatureService.startSignatureTask(signatureTaskId).join();
                
                // 构建响应
                Map<String, Object> response = new HashMap<>();
                response.put("signatureTaskId", signatureTaskId);
                response.put("groupPublicKey", groupPublicKey);
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
    public CompletableFuture<Map<String, Object>> getSignatureTaskStatus(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 参数验证
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    throw new IllegalArgumentException("signatureTaskId cannot be null or empty");
                }
                
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
    public CompletableFuture<Map<String, Object>> getSignatureResult(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 参数验证
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    throw new IllegalArgumentException("signatureTaskId cannot be null or empty");
                }
                
                return signatureService.getSignatureResult(signatureTaskId);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        });
    }
}