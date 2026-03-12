package com.example.mpc.controller;

import com.example.mpc.common.request.ComplaintsQueryRequest;
import com.example.mpc.common.request.RefreshStartRequest;
import com.example.mpc.common.request.SignStartRequest;
import com.example.mpc.common.request.SignatureTaskIdRequest;
import com.example.mpc.common.request.TaskIdRequest;
import com.example.mpc.common.response.ApiResponse;
import com.example.mpc.common.response.AuxTaskStartResponse;
import com.example.mpc.common.response.AuxTaskStatusResponse;
import com.example.mpc.common.response.DkgTaskStartResponse;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.response.RefreshTaskStartResponse;
import com.example.mpc.common.response.RefreshTaskStatusResponse;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.common.response.SignatureTaskStartResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.util.JsonCodec;
import com.example.mpc.dao.ComplaintDao;
import com.example.mpc.service.CggmpAuxService;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.PresignPoolService;
import com.example.mpc.service.CggmpDiagnosticsService;
import com.example.mpc.service.CggmpDkgService;
import com.example.mpc.service.CggmpRefreshService;
import com.example.mpc.service.CggmpSignatureService;
import com.example.mpc.service.PresignPoolService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/cggmp")
public class CggmpController {
    private static final Logger logger = LoggerFactory.getLogger(CggmpController.class);

    @Autowired
    private CggmpSignatureService cggmpSignatureService;
    @Autowired
    private CggmpDiagnosticsService cggmpDiagnosticsService;
    @Autowired
    private CggmpDkgService cggmpDkgService;
    @Autowired
    private CggmpAuxService cggmpAuxService;
    @Autowired
    private CggmpRefreshService cggmpRefreshService;
    @Autowired
    private PresignPoolService presignPoolService;

    // ==================== AUX 接口 ====================

    /**
     * 启动 AUX 任务，生成 Paillier 公钥和 Pedersen 参数
     *
     * @return 任务ID
     */
    @GetMapping("/aux/start")
    public CompletableFuture<ApiResponse<AuxTaskStartResponse>> startAux() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = cggmpAuxService.createAuxTask();
                cggmpAuxService.startAuxProcess(taskId)
                        .exceptionally(ex -> {
                            logger.error("Async CGGMP AUX process failed for task {}: {}", taskId, ex.getMessage(), ex);
                            return null;
                        });
                AuxTaskStartResponse data = new AuxTaskStartResponse(taskId, "CGGMP AUX process started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start CGGMP AUX process", e);
                return ApiResponse.error("Failed to start CGGMP AUX process: " + e.getMessage());
            }
        });
    }

    /**
     * 查询 AUX 任务状态
     *
     * @param request 任务ID请求
     * @return 任务状态
     */
    @PostMapping("/aux/status")
    public CompletableFuture<ApiResponse<AuxTaskStatusResponse>> getAuxStatus(@RequestBody TaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = request.getTaskId();
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }
                AuxTaskStatusResponse status = cggmpAuxService.getAuxTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get aux task status", e);
                return ApiResponse.error("Failed to get aux task status: " + e.getMessage());
            }
        });
    }

    // ==================== DKG 接口 ====================

    /**
     * 启动 CGGMP DKG 任务，生成分布式密钥对
     *
     * @return 任务ID
     */
    @GetMapping("/dkg/start")
    public CompletableFuture<ApiResponse<DkgTaskStartResponse>> generateKey(
            @RequestParam(required = false, defaultValue = "false") boolean isHotWallet) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = cggmpDkgService.createDkgTask(isHotWallet);
                logger.info("Created CGGMP DKG task {} with isHotWallet={}", taskId, isHotWallet);

                cggmpDkgService.startDkgProcess(taskId)
                        .thenAccept(result -> logger.info("DKG process completed for task {}", taskId))
                        .exceptionally(ex -> {
                            logger.error("Async CGGMP DKG process failed for task {}: {}", taskId, ex.getMessage(), ex);
                            return null;
                        });
                logger.info("Requested CGGMP DKG start for task {}", taskId);

                DkgTaskStartResponse data = new DkgTaskStartResponse(taskId, "CGGMP DKG process started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start CGGMP DKG process", e);
                return ApiResponse.error("Failed to start CGGMP DKG process: " + e.getMessage());
            }
        });
    }

    /**
     * 查询 DKG 任务状态
     *
     * @param request 任务ID请求
     * @return 任务状态
     */
    @PostMapping("/dkg/status")
    public CompletableFuture<ApiResponse<DkgTaskStatusResponse>> getTaskStatus(@RequestBody TaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = request.getTaskId();
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }

                DkgTaskStatusResponse status = cggmpDkgService.getTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get task status", e);
                return ApiResponse.error("Failed to get task status: " + e.getMessage());
            }
        });
    }

    /**
     * 查询 DKG 生成的聚合公钥
     *
     * @param request 任务ID请求
     * @return 聚合公钥（Hex编码）
     */
    @PostMapping("/dkg/public-key")
    public CompletableFuture<ApiResponse<String>> getGroupPublicKey(@RequestBody TaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = request.getTaskId();
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }

                String publicKey = cggmpDkgService.getGroupPublicKey(taskId);
                return ApiResponse.success(publicKey);
            } catch (Exception e) {
                logger.error("Failed to get group public key", e);
                return ApiResponse.error("Failed to get group public key: " + e.getMessage());
            }
        });
    }

    // ==================== Sign 接口 ====================

    /**
     * 启动 CGGMP 门限签名任务
     *
     * @param request 签名请求参数
     * @return 签名任务ID
     */
    @PostMapping("/sign/start")
    public CompletableFuture<ApiResponse<SignatureTaskStartResponse>> sign(@RequestBody SignStartRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String groupPublicKey = request.getGroupPublicKey();
                String message = request.getMessage();
                boolean isHotWallet = request.isHotWallet();
                logger.info("Sign request received: isHotWallet={}, groupPublicKey={}", isHotWallet, groupPublicKey);
                
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    return ApiResponse.badRequest("groupPublicKey cannot be null or empty");
                }
                if (message == null || message.isEmpty()) {
                    return ApiResponse.badRequest("message cannot be null or empty");
                }

                if (isHotWallet && presignPoolService.isEnabled()) {
                    logger.info("Hot wallet sign request, presign pool enabled, trying to consume presign");
                    var presigned = waitAndConsumePresign(groupPublicKey, isHotWallet, 60000);
                    if (presigned.isPresent()) {
                        String signature = presignPoolService.signWithPresignData(groupPublicKey, message, presigned.get());
                        logger.info("Using presigned signature from pool for groupKey: {}", groupPublicKey);
                        SignatureTaskStartResponse data = new SignatureTaskStartResponse(
                            "presign-" + System.currentTimeMillis(),
                            groupPublicKey,
                            message,
                            "Hot wallet signature from presign pool"
                        );
                        data.setSignature(signature);
                        return ApiResponse.success(data);
                    }
                }

                String signatureTaskId = cggmpSignatureService.createSignatureTaskWithGroupKey(groupPublicKey, message, isHotWallet);

                cggmpSignatureService.startSignatureTask(signatureTaskId)
                        .exceptionally(ex -> {
                            logger.error("Async GG20 signature process failed for task {}: {}", signatureTaskId, ex.getMessage(), ex);
                            return null;
                        });

                SignatureTaskStartResponse data = new SignatureTaskStartResponse(signatureTaskId, groupPublicKey, message, "CGGMP signature process started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start signature process", e);
                return ApiResponse.error("Failed to start signature process: " + e.getMessage());
            }
        });
    }

    /**
     * 查询签名任务状态
     *
     * @param request 签名任务ID请求
     * @return 任务状态
     */
    @PostMapping("/sign/status")
    public CompletableFuture<ApiResponse<SignatureTaskStatusResponse>> getSignatureTaskStatus(@RequestBody SignatureTaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String signatureTaskId = request.getSignatureTaskId();
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    return ApiResponse.badRequest("signatureTaskId cannot be null or empty");
                }

                SignatureTaskStatusResponse status = cggmpSignatureService.getSignatureTaskStatus(signatureTaskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get signature task status", e);
                return ApiResponse.error("Failed to get signature task status: " + e.getMessage());
            }
        });
    }

    /**
     * 查询签名结果
     *
     * @param request 签名任务ID请求
     * @return 签名结果（DER编码，Base64）
     */
    @PostMapping("/sign/result")
    public CompletableFuture<ApiResponse<SignatureResultResponse>> getSignatureResult(@RequestBody SignatureTaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String signatureTaskId = request.getSignatureTaskId();
                if (signatureTaskId == null || signatureTaskId.isEmpty()) {
                    return ApiResponse.badRequest("signatureTaskId cannot be null or empty");
                }

                SignatureResultResponse result = cggmpSignatureService.getSignatureResult(signatureTaskId);
                return ApiResponse.success(result);
            } catch (Exception e) {
                logger.error("Failed to get signature result", e);
                return ApiResponse.error("Failed to get signature result: " + e.getMessage());
            }
        });
    }

    // ==================== Refresh 接口 ====================

    /**
     * 启动密钥刷新任务，更新各节点的私钥份额
     *
     * @param request 刷新请求参数
     * @return 刷新任务ID
     */
    @PostMapping("/refresh/start")
    public CompletableFuture<ApiResponse<RefreshTaskStartResponse>> startRefresh(@RequestBody RefreshStartRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String groupPublicKey = request.getGroupPublicKey();
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    return ApiResponse.badRequest("groupPublicKey cannot be null or empty");
                }
                String taskId = cggmpRefreshService.createRefreshTask(groupPublicKey);
                cggmpRefreshService.startRefreshTask(taskId)
                        .exceptionally(ex -> {
                            logger.error("Async CGGMP refresh failed for task {}: {}", taskId, ex.getMessage(), ex);
                            return null;
                        });
                RefreshTaskStartResponse data = new RefreshTaskStartResponse(taskId, groupPublicKey, "CGGMP refresh started");
                return ApiResponse.success(data);
            } catch (Exception e) {
                logger.error("Failed to start CGGMP refresh", e);
                return ApiResponse.error("Failed to start CGGMP refresh: " + e.getMessage());
            }
        });
    }

    /**
     * 查询密钥刷新任务状态
     *
     * @param request 任务ID请求
     * @return 任务状态
     */
    @PostMapping("/refresh/status")
    public CompletableFuture<ApiResponse<RefreshTaskStatusResponse>> getRefreshStatus(@RequestBody TaskIdRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = request.getTaskId();
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }
                RefreshTaskStatusResponse status = cggmpRefreshService.getRefreshTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get refresh task status", e);
                return ApiResponse.error("Failed to get refresh task status: " + e.getMessage());
            }
        });
    }

    // ==================== 诊断接口 ====================

    /**
     * 零知识证明自检，验证参数配置和证明链正确性
     *
     * @return 自检结果
     */
    @GetMapping("/proof/self-check")
    public ApiResponse<Map<String, Object>> proofSelfCheck() {
        try {
            Map<String, Object> result = cggmpDiagnosticsService.runProofSelfCheck();
            return ApiResponse.success(result);
        } catch (Exception e) {
            logger.error("Failed to run proof self-check", e);
            return ApiResponse.error("Failed to run proof self-check: " + e.getMessage());
        }
    }

    // ==================== 投诉接口 ====================

    /**
     * 查询投诉记录
     *
     * @param request 查询参数
     * @return 投诉记录列表
     */
    @PostMapping("/complaints")
    public CompletableFuture<ApiResponse<List<ComplaintDao.ComplaintRecord>>> getComplaints(
            @RequestBody ComplaintsQueryRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                List<ComplaintDao.ComplaintRecord> records =
                        cggmpSignatureService.getComplaints(
                                request.getTaskId(), 
                                request.getReason(), 
                                request.getReasonLike(), 
                                request.getSenderId(), 
                                request.getOffenderId(), 
                                request.getFromTs(), 
                                request.getToTs(), 
                                request.getLimit() != null ? request.getLimit() : 50, 
                                request.getOffset() != null ? request.getOffset() : 0);
                return ApiResponse.success(records);
            } catch (Exception e) {
                logger.error("Failed to get complaints", e);
                return ApiResponse.error("Failed to get complaints: " + e.getMessage());
            }
        });
    }

    /**
     * 导出投诉记录为 JSONL 格式
     */
    @PostMapping(value = "/complaints/export", produces = "application/x-ndjson")
    public CompletableFuture<String> exportComplaintsJsonl(@RequestBody ComplaintsQueryRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            List<ComplaintDao.ComplaintRecord> records =
                    cggmpSignatureService.getComplaints(
                            request.getTaskId(), 
                            request.getReason(), 
                            request.getReasonLike(), 
                            request.getSenderId(), 
                            request.getOffenderId(), 
                            request.getFromTs(), 
                            request.getToTs(), 
                            request.getLimit() != null ? request.getLimit() : 500, 
                            request.getOffset() != null ? request.getOffset() : 0);
            StringBuilder sb = new StringBuilder();
            for (com.example.mpc.dao.ComplaintDao.ComplaintRecord r : records) {
                Map<String, Object> line = new LinkedHashMap<>();
                line.put("ts", r.ts());
                line.put("taskId", r.taskId());
                line.put("senderId", r.senderId());
                line.put("offenderId", r.offenderId());
                line.put("reason", r.reason());
                String evidenceJson = r.evidence();
                if (evidenceJson != null) {
                    Object parsed = JsonCodec.parse(evidenceJson);
                    line.put("evidence", parsed == null ? evidenceJson : parsed);
                } else {
                    line.put("evidence", null);
                }
                sb.append(JsonCodec.toJson(line)).append("\n");
            }
            return sb.toString();
        });
    }

    /**
     * 导出投诉记录为 CSV 格式
     */
    @PostMapping(value = "/complaints/export.csv", produces = "text/csv")
    public CompletableFuture<String> exportComplaintsCsv(@RequestBody ComplaintsQueryRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            List<ComplaintDao.ComplaintRecord> records =
                    cggmpSignatureService.getComplaints(
                            request.getTaskId(), 
                            request.getReason(), 
                            request.getReasonLike(), 
                            request.getSenderId(), 
                            request.getOffenderId(), 
                            request.getFromTs(), 
                            request.getToTs(), 
                            request.getLimit() != null ? request.getLimit() : 500, 
                            request.getOffset() != null ? request.getOffset() : 0);
            StringBuilder sb = new StringBuilder();
            sb.append("ts,taskId,senderId,offenderId,reason,evidence\n");
            for (com.example.mpc.dao.ComplaintDao.ComplaintRecord r : records) {
                sb.append(r.ts()).append(",");
                sb.append(csvEscape(r.taskId())).append(",");
                sb.append(r.senderId()).append(",");
                sb.append(r.offenderId() == null ? "" : r.offenderId()).append(",");
                sb.append(csvEscape(r.reason())).append(",");
                sb.append(csvEscape(r.evidence())).append("\n");
            }
            return sb.toString();
        });
    }

    private static String csvEscape(String value) {
        if (value == null) {
            return "";
        }
        String v = value.replace("\"", "\"\"");
        if (v.contains(",") || v.contains("\n") || v.contains("\r")) {
            return "\"" + v + "\"";
        }
        return v;
    }
    
    private Optional<com.example.mpc.dto.PresignData> waitAndConsumePresign(String groupPublicKey, boolean isHotWallet, long timeoutMs) {
        long startTime = System.currentTimeMillis();
        long intervalMs = 1000;
        
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            var presigned = presignPoolService.tryConsume(groupPublicKey, isHotWallet);
            if (presigned.isPresent()) {
                return presigned;
            }
            
            logger.info("No presign available for groupKey: {}, waiting {}ms...", groupPublicKey, intervalMs);
            try {
                Thread.sleep(intervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        logger.warn("Timeout waiting for presign for groupKey: {}, timeout: {}ms", groupPublicKey, timeoutMs);
        return Optional.empty();
    }
}
