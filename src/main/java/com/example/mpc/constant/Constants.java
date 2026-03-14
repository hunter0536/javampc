package com.example.mpc.constant;

/**
 * MPC协议全局常量配置
 * <p>
 * 包含以下配置：
 * - 节点数量和门限值
 * - DKG协议超时参数
 * - AUX协议超时参数
 * - 签名协议超时参数
 * - 广播重试参数
 */
public final class Constants {
    private Constants() {
    }

    // ==================== 节点配置 ====================

    /**
     * 参与MPC协议的节点总数
     */
    public static int NODES_COUNT = 5;

    /**
     * 门限值：签名所需的最少参与者数量
     */
    public static int THRESHOLD = 3;

    // ==================== 网络参数 ====================

    /**
     * 节点发现间隔（毫秒）
     */
    public static long NODE_DISCOVERY_INTERVAL_MS = 5000;

    // ==================== DKG协议超时参数 ====================

    /**
     * DKG承诺接收超时时间（秒）
     */
    public static long DKG_COMMITMENT_TIMEOUT_SECONDS = 180;

    /**
     * DKG秘密份额接收超时时间（秒）
     */
    public static long DKG_SHARE_TIMEOUT_SECONDS = 180;

    /**
     * DKG单轮超时时间（秒）
     */
    public static long DKG_ROUND_TIMEOUT_SECONDS = 180;

    /**
     * DKG任务总超时时间（毫秒）
     */
    public static long DKG_TASK_TIMEOUT_MS = 300000;

    /**
     * DKG初始化等待时间（毫秒），广播初始化消息前的等待时间
     */
    public static long DKG_INIT_WAIT_MS = 0;

    // ==================== AUX协议超时参数 ====================

    /**
     * 等待AUX状态收集的时间（毫秒）
     */
    public static long AUX_STATUS_WAIT_MS = 5000;

    /**
     * AUX单轮超时时间（秒）
     */
    public static long AUX_ROUND_TIMEOUT_SECONDS = 600;

    /**
     * AUX任务总超时时间（毫秒），包含Paillier密钥生成，默认30分钟
     */
    public static long AUX_TASK_TIMEOUT_MS = 30 * 60 * 1000;

    // ==================== 签名协议超时参数 ====================

    /**
     * 签名承诺接收超时时间（秒）
     */
    public static final long SIGNATURE_COMMITMENT_TIMEOUT_SECONDS = 180;

    /**
     * 签名份额接收超时时间（秒）
     */
    public static final long SIGNATURE_SHARE_TIMEOUT_SECONDS = 30;

    // ==================== 广播重试参数 ====================

    /**
     * 消息广播重试次数，所有协议统一使用
     */
    public static int BROADCAST_RETRY_COUNT = 3;

    /**
     * 消息广播重试间隔（毫秒）
     */
    public static long BROADCAST_RETRY_INTERVAL_MS = 1000;
}
