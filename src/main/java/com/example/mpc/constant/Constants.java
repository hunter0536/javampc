package com.example.mpc.constant;

public class Constants {
    // 门限参数
    public static final int THRESHOLD = 3;
    
    // 节点参数
    public static final int NODES_COUNT = 5;
    
    // 椭圆曲线参数
    public static final String CURVE_NAME = "secp256k1";
    
    // 网络参数
    public static final long DISCOVERY_INTERVAL = 5000;

    // DKG 超时参数（秒）
    public static final long DKG_COMMITMENT_TIMEOUT_SECONDS = 180;
    public static final long DKG_SHARE_TIMEOUT_SECONDS = 180;
    public static final long DKG_ROUND_TIMEOUT_SECONDS = 180;
    
    // DKG 重试参数
    public static final int DKG_BROADCAST_RETRY_COUNT = 3;
    public static final long DKG_BROADCAST_RETRY_DELAY_MS = 1000;
    public static final long DKG_INIT_WAIT_TIME_MS = 2000;
    
    // DKG 任务默认超时（毫秒）
    public static final long DKG_TASK_DEFAULT_TIMEOUT_MS = 300000;
    
    // 签名超时参数（秒）
    public static final long SIGNATURE_ROUND_TIMEOUT_SECONDS = 60;
    public static final long SIGNATURE_COMMITMENT_TIMEOUT_SECONDS = 60;
    public static final long SIGNATURE_SHARE_TIMEOUT_SECONDS = 60;
    
    // 签名重试参数
    public static final int SIGNATURE_BROADCAST_RETRY_COUNT = 3;
    public static final long SIGNATURE_BROADCAST_RETRY_DELAY_MS = 1000;
    
    // 数据库参数
    public static final String DATABASES_DIR = "databases";
}
