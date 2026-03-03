package com.example.mpc.controller;

import com.example.mpc.common.response.ApiResponse;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStartResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.dto.SimpleSignatureTask;
import com.example.mpc.service.SimpleSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/simple-sign")
public class SimpleSignatureController {

    private static final Logger logger = LoggerFactory.getLogger(SimpleSignatureController.class);

    @Autowired
    private SimpleSignatureService simpleSignatureService;

    /**
     * 启动简单签名任务（适用于测试和演示）
     *
     * @param groupPublicKey 聚合公钥（Hex编码）
     * @param message        待签名消息（Hex编码）
     * @return 签名任务ID
     */
    @PostMapping("/sign/start")
    public CompletableFuture<ApiResponse<SignatureTaskStartResponse>> startSignature(
            @RequestParam String groupPublicKey,
            @RequestParam String message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = simpleSignatureService.startSignature(groupPublicKey, message);
                logger.info("Started simple signature task {}", taskId);

                SignatureTaskStartResponse data = new SignatureTaskStartResponse(taskId, groupPublicKey, message, "Simple signature process started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start simple signature: {}", e.getMessage());
                return ApiResponse.error(e.getMessage());
            }
        });
    }

    /**
     * 查询简单签名任务状态
     *
     * @param taskId 任务ID
     * @return 任务状态
     */
    @PostMapping("/sign/status")
    public CompletableFuture<ApiResponse<SignatureTaskStatusResponse>> getStatus(@RequestParam String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SimpleSignatureTask task = simpleSignatureService.getTaskStatus(taskId);
                if (task == null) {
                    return ApiResponse.error("Task not found");
                }

                SignatureTaskStatusResponse status = new SignatureTaskStatusResponse();
                status.setTaskId(task.taskId);
                status.setGroupPublicKey(task.groupPublicKey);
                status.setInProgress(!task.isCompleted() && !task.isFailed());
                status.setCompleted(task.isCompleted());
                status.setMessage(task.message);

                if (task.isFailed()) {
                    status.setStatus("FAILED");
                    status.setErrorMessage(task.errorMessage);
                } else if (task.isCompleted()) {
                    status.setStatus("COMPLETED");
                } else {
                    status.setStatus("IN_PROGRESS");
                }

                status.setParticipants(task.participants != null ? new java.util.ArrayList<>(task.participants) : null);
                status.setReceivedGammaCommitments(task.RShares != null ? task.RShares.size() : 0);
                status.setReceivedPartialS(task.sigmaShares != null ? task.sigmaShares.size() : 0);

                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get task status: {}", e.getMessage());
                return ApiResponse.error(e.getMessage());
            }
        });
    }

    /**
     * 查询简单签名结果
     *
     * @param taskId 任务ID
     * @return 签名结果（DER编码，Base64）
     */
    @PostMapping("/sign/result")
    public CompletableFuture<ApiResponse<SignatureResultResponse>> getResult(@RequestParam String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SimpleSignatureTask task = simpleSignatureService.getTaskStatus(taskId);
                if (task == null) {
                    return ApiResponse.error("Task not found");
                }

                if (!task.isCompleted()) {
                    return ApiResponse.error("Task not completed yet");
                }

                SignatureResultResponse result = new SignatureResultResponse();
                result.setTaskId(task.taskId);
                result.setGroupPublicKey(task.groupPublicKey);
                result.setMessage(task.message);

                Map<String, Object> signatureResult = simpleSignatureService.getSignatureResult(taskId);
                if (signatureResult != null && signatureResult.get("signature") != null) {
                    result.setSignature((String) signatureResult.get("signature"));
                }

                result.setVerified(task.verified);

                return ApiResponse.success(result);
            } catch (Exception e) {
                logger.error("Failed to get signature result: {}", e.getMessage());
                return ApiResponse.error(e.getMessage());
            }
        });
    }
}
