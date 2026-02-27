package com.example.mpc.constant;

public class Constants {
    private Constants() {
    }

    // ==================== 门限签名参数 ====================

    /**
     * 门限值：签名所需的最少参与者数量
     * 用于 DKG 密钥生成和门限签名过程
     */
    public static final int THRESHOLD = 3;

    /**
     * 节点总数：参与 MPC 协议的节点数量
     * 用于 DKG 密钥生成和签名协调
     */
    public static final int NODES_COUNT = 5;

    // ==================== 椭圆曲线参数 ====================

    /**
     * 椭圆曲线名称
     * 用于密钥生成、签名和验签
     */
    public static final String CURVE_NAME = "secp256k1";

    // ==================== 网络参数 ====================

    /**
     * 节点发现间隔（毫秒）
     * 用于 P2P 网络中定期发现其他节点
     */
    public static long NODE_DISCOVERY_INTERVAL_MS = 5000;

    // ==================== DKG 协议超时参数 ====================

    /**
     * DKG 承诺接收超时时间（秒）
     * 等待其他节点发送承诺的最长时间
     */
    public static long DKG_COMMITMENT_TIMEOUT_SECONDS = 60;

    /**
     * DKG 秘密份额接收超时时间（秒）
     * 等待其他节点发送秘密份额的最长时间
     */
    public static long DKG_SHARE_TIMEOUT_SECONDS = 60;

    /**
     * DKG 单轮超时时间（秒）
     * CGGMP 协议中单轮消息接收的最长等待时间
     */
    public static long DKG_ROUND_TIMEOUT_SECONDS = 60;
    public static long AUX_ROUND_TIMEOUT_SECONDS = 600;
    public static long AUX_STATUS_WAIT_MS = 5000;

    /**
     * DKG 任务默认超时时间（毫秒）
     * 整个 DKG 任务的最长执行时间
     */
    public static long DKG_TASK_TIMEOUT_MS = 120000;
    /**
     * AUX 任务默认超时时间（毫秒）
     * AUX 过程包含 Paillier 生成，通常远慢于 DKG
     */
    public static long AUX_TASK_TIMEOUT_MS = 30 * 60 * 1000;

    // ==================== DKG 协议重试参数 ====================

    /**
     * DKG 消息广播重试次数
     * 广播失败时的最大重试次数
     */
    public static int DKG_BROADCAST_RETRY_COUNT = 3;

    /**
     * DKG 消息广播重试间隔（毫秒）
     * 每次重试之间的等待时间
     */
    public static long DKG_BROADCAST_RETRY_INTERVAL_MS = 1000;

    /**
     * DKG 初始化等待时间（毫秒）
     * 广播初始化消息前的等待时间，确保其他节点准备就绪
     */
    public static long DKG_INIT_WAIT_MS = 2000;

    // ==================== 签名协议超时参数 ====================

    /**
     * 签名承诺接收超时时间（秒）
     * 等待其他节点发送 Gamma 承诺和 MtA 响应的最长时间
     */
    public static final long SIGNATURE_COMMITMENT_TIMEOUT_SECONDS = 60;

    /**
     * 签名份额接收超时时间（秒）
     * 等待其他节点发送签名份额的最长时间
     */
    public static final long SIGNATURE_SHARE_TIMEOUT_SECONDS = 30;

    // ==================== 签名协议重试参数 ====================

    /**
     * 签名消息广播重试次数
     */
    public static final int SIGNATURE_BROADCAST_RETRY_COUNT = 3;

    /**
     * 签名消息广播重试间隔（毫秒）
     */
    public static final long SIGNATURE_BROADCAST_RETRY_INTERVAL_MS = 1000;

    // ==================== 数据库参数 ====================

    /**
     * 数据库文件存储目录
     * 用于存储密钥份额等持久化数据
     */
    public static final String DATABASE_DIR = "databases";
}
