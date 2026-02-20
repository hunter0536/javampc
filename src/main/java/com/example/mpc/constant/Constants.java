package com.example.mpc.constant;

public class Constants {
    // 门限参数
    public static final int THRESHOLD = 3; // 重构私钥所需的最小份额数
    
    // 椭圆曲线参数
    public static final String CURVE_NAME = "secp256k1"; // 以太坊使用的椭圆曲线
    
    // 网络参数
    public static final int DISCOVERY_PORT = 8888; // 节点发现端口
    public static final long DISCOVERY_INTERVAL = 5000; // 节点发现间隔（毫秒）
    
    // 数据库参数
    public static final String DATABASES_DIR = "databases";
}
