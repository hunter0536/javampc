package com.example.mpc.controller;

import com.example.mpc.common.response.ApiResponse;
import com.example.mpc.common.response.DkgTaskStartResponse;
import com.example.mpc.common.response.DkgTaskStatusResponse;
import com.example.mpc.common.response.AuxTaskStartResponse;
import com.example.mpc.common.response.AuxTaskStatusResponse;
import com.example.mpc.common.response.RefreshTaskStartResponse;
import com.example.mpc.common.response.RefreshTaskStatusResponse;
import com.example.mpc.common.response.SignatureTaskStartResponse;
import com.example.mpc.common.response.SignatureTaskStatusResponse;
import com.example.mpc.common.response.SignatureResultResponse;
import com.example.mpc.service.CggmpSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/cggmp")
public class CggmpController {
    private static final Logger logger = LoggerFactory.getLogger(CggmpController.class);

    @Autowired
    private CggmpSignatureService cggmpSignatureService;

    /**
     * 使用CGGMP协议生成分布式密钥并返回UUID
     *
     * @return 包含任务ID的响应
     */
    @PostMapping("/dkg/start")
    public CompletableFuture<ApiResponse<DkgTaskStartResponse>> generateKey() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = cggmpSignatureService.createDkgTask();
                logger.info("Created CGGMP DKG task {}", taskId);

                cggmpSignatureService.startDkgProcess(taskId)
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
     * CGGMP24 AUX provisioning start
     */
    @PostMapping("/aux/start")
    public CompletableFuture<ApiResponse<AuxTaskStartResponse>> startAux() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String taskId = cggmpSignatureService.createAuxTask();
                cggmpSignatureService.startAuxProcess(taskId)
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
     * CGGMP24 AUX status
     */
    @GetMapping("/aux/status")
    public CompletableFuture<ApiResponse<AuxTaskStatusResponse>> getAuxStatus(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }
                AuxTaskStatusResponse status = cggmpSignatureService.getAuxTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get aux task status", e);
                return ApiResponse.error("Failed to get aux task status: " + e.getMessage());
            }
        });
    }

    /**
     * 查询最近的 complaint 记录（可选按 taskId 过滤）
     */
    @GetMapping("/complaints")
    public CompletableFuture<ApiResponse<java.util.List<com.example.mpc.dao.ComplaintDao.ComplaintRecord>>> getComplaints(
            @RequestParam(required = false) String taskId,
            @RequestParam(required = false) String reason,
            @RequestParam(required = false) String reasonLike,
            @RequestParam(required = false) Integer senderId,
            @RequestParam(required = false) Integer offenderId,
            @RequestParam(required = false) Long fromTs,
            @RequestParam(required = false) Long toTs,
            @RequestParam(required = false, defaultValue = "50") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                java.util.List<com.example.mpc.dao.ComplaintDao.ComplaintRecord> records =
                        cggmpSignatureService.getComplaints(taskId, reason, reasonLike, senderId, offenderId, fromTs, toTs, limit, offset);
                return ApiResponse.success(records);
            } catch (Exception e) {
                logger.error("Failed to get complaints", e);
                return ApiResponse.error("Failed to get complaints: " + e.getMessage());
            }
        });
    }

    /**
     * 导出 complaints 为 JSONL
     */
    @GetMapping(value = "/complaints/export", produces = "application/x-ndjson")
    public CompletableFuture<String> exportComplaintsJsonl(
            @RequestParam(required = false) String taskId,
            @RequestParam(required = false) String reason,
            @RequestParam(required = false) String reasonLike,
            @RequestParam(required = false) Integer senderId,
            @RequestParam(required = false) Integer offenderId,
            @RequestParam(required = false) Long fromTs,
            @RequestParam(required = false) Long toTs,
            @RequestParam(required = false, defaultValue = "500") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {
        return CompletableFuture.supplyAsync(() -> {
            java.util.List<com.example.mpc.dao.ComplaintDao.ComplaintRecord> records =
                    cggmpSignatureService.getComplaints(taskId, reason, reasonLike, senderId, offenderId, fromTs, toTs, limit, offset);
            StringBuilder sb = new StringBuilder();
            for (com.example.mpc.dao.ComplaintDao.ComplaintRecord r : records) {
                sb.append("{\"ts\":").append(r.ts())
                  .append(",\"taskId\":\"").append(escapeJson(r.taskId())).append("\"")
                  .append(",\"senderId\":").append(r.senderId())
                  .append(",\"offenderId\":").append(r.offenderId() == null ? "null" : r.offenderId())
                  .append(",\"reason\":\"").append(escapeJson(r.reason())).append("\"")
                  .append(",\"evidence\":").append(r.evidence() == null ? "null" : r.evidence())
                  .append("}\n");
            }
            return sb.toString();
        });
    }

    /**
     * 导出 complaints 为 CSV
     */
    @GetMapping(value = "/complaints/export.csv", produces = "text/csv")
    public CompletableFuture<String> exportComplaintsCsv(
            @RequestParam(required = false) String taskId,
            @RequestParam(required = false) String reason,
            @RequestParam(required = false) String reasonLike,
            @RequestParam(required = false) Integer senderId,
            @RequestParam(required = false) Integer offenderId,
            @RequestParam(required = false) Long fromTs,
            @RequestParam(required = false) Long toTs,
            @RequestParam(required = false, defaultValue = "500") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {
        return CompletableFuture.supplyAsync(() -> {
            java.util.List<com.example.mpc.dao.ComplaintDao.ComplaintRecord> records =
                    cggmpSignatureService.getComplaints(taskId, reason, reasonLike, senderId, offenderId, fromTs, toTs, limit, offset);
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

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    out.append(c);
                    break;
            }
        }
        return out.toString();
    }

    /**
     * 根据UUID查询对应的CGGMP协议DKG任务是否执行完成
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

                DkgTaskStatusResponse status = cggmpSignatureService.getTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get task status", e);
                return ApiResponse.error("Failed to get task status: " + e.getMessage());
            }
        });
    }

    /**
     * 根据UUID查询CGGMP协议DKG生成的群公钥
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

                String publicKey = cggmpSignatureService.getGroupPublicKey(taskId);
                return ApiResponse.success(publicKey);
            } catch (Exception e) {
                logger.error("Failed to get group public key", e);
                return ApiResponse.error("Failed to get group public key: " + e.getMessage());
            }
        });
    }

    /**
     * 使用CGGMP协议对消息进行门限签名并返回UUID
     *
     * @param groupPublicKey 群公钥
     * @param message        待签名消息
     * @return 包含签名任务ID的响应
     */
    @PostMapping("/sign/start")
    public CompletableFuture<ApiResponse<SignatureTaskStartResponse>> sign(@RequestParam(required = true) String groupPublicKey, @RequestParam(required = true) String message) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    return ApiResponse.badRequest("groupPublicKey cannot be null or empty");
                }
                if (message == null || message.isEmpty()) {
                    return ApiResponse.badRequest("message cannot be null or empty");
                }

                String signatureTaskId = cggmpSignatureService.createSignatureTaskWithGroupKey(groupPublicKey, message);

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
     * 根据UUID查询对应的CGGMP协议签名任务是否执行完成
     *
     * @param signatureTaskId 签名任务ID
     * @return 签名任务状态
     */
    @GetMapping("/sign/status")
    public CompletableFuture<ApiResponse<SignatureTaskStatusResponse>> getSignatureTaskStatus(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
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
     * 根据UUID查询CGGMP协议签名结果
     *
     * @param signatureTaskId 签名任务ID
     * @return 签名结果
     */
    @GetMapping("/sign/result")
    public CompletableFuture<ApiResponse<SignatureResultResponse>> getSignatureResult(@RequestParam(required = true) String signatureTaskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
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

    /**
     * ZK 证明自检（PiDec / PiAffG），用于验证参数配置与证明链
     */
    @GetMapping("/proof/self-check")
    public ApiResponse<Map<String, Object>> proofSelfCheck() {
        try {
            Map<String, Object> result = cggmpSignatureService.runProofSelfCheck();
            return ApiResponse.success(result);
        } catch (Exception e) {
            logger.error("Failed to run proof self-check", e);
            return ApiResponse.error("Failed to run proof self-check: " + e.getMessage());
        }
    }

    /**
     * 启动CGGMP密钥刷新（refresh/proactive）
     *
     * @param groupPublicKey 群公钥
     * @return 包含刷新任务ID的响应
     */
    @PostMapping("/refresh/start")
    public CompletableFuture<ApiResponse<RefreshTaskStartResponse>> startRefresh(@RequestParam(required = true) String groupPublicKey) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (groupPublicKey == null || groupPublicKey.isEmpty()) {
                    return ApiResponse.badRequest("groupPublicKey cannot be null or empty");
                }
                String taskId = cggmpSignatureService.createRefreshTask(groupPublicKey);
                cggmpSignatureService.startRefreshTask(taskId)
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
     * 查询CGGMP刷新任务状态
     *
     * @param taskId 任务ID
     * @return 刷新任务状态
     */
    @GetMapping("/refresh/status")
    public CompletableFuture<ApiResponse<RefreshTaskStatusResponse>> getRefreshStatus(@RequestParam(required = true) String taskId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (taskId == null || taskId.isEmpty()) {
                    return ApiResponse.badRequest("taskId cannot be null or empty");
                }
                RefreshTaskStatusResponse status = cggmpSignatureService.getRefreshTaskStatus(taskId);
                return ApiResponse.success(status);
            } catch (Exception e) {
                logger.error("Failed to get refresh task status", e);
                return ApiResponse.error("Failed to get refresh task status: " + e.getMessage());
            }
        });
    }
}
