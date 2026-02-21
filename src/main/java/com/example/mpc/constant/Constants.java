package com.example.mpc.constant;

public class Constants {
    // 门限参数
    public static final int THRESHOLD = 3; // 重构私钥所需的最小份额数
    
    // 节点参数
    public static final int NODES_COUNT = 5; // 节点总数
    
    // 椭圆曲线参数
    public static final String CURVE_NAME = "secp256k1"; // 以太坊使用的椭圆曲线
    
    // 网络参数
    public static final long DISCOVERY_INTERVAL = 5000; // 节点发现间隔（毫秒）

    // DKG超时参数（秒）
    public static final long DKG_COMMITMENT_TIMEOUT_SECONDS = 180;
    public static final long DKG_SHARE_TIMEOUT_SECONDS = 180;
    
    // 数据库参数
    public static final String DATABASES_DIR = "databases";
}
