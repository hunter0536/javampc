package com.example.mpc.enums;

public enum MessageType {
    // ==================== 网络层 ====================
    /** 网络消息确认 */
    NET_ACK,
    /** RBC回声消息 */
    NET_RBC_ECHO,

    // ==================== Gennaro DKG ====================
    /** Gennaro DKG初始化 */
    GENNARO_DKG_INIT,
    /** Gennaro DKG承诺 */
    GENNARO_COMMITMENT,
    /** Gennaro DKG份额分发 */
    GENNARO_SHARE,
    /** Gennaro DKG公钥部分 */
    GENNARO_PUBLIC_KEY_PART,

    // ==================== CGGMP DKG ====================
    /** CGGMP DKG初始化 */
    CGGMP_DKG_INIT,
    /** CGGMP DKG第1轮 */
    CGGMP_DKG_ROUND1,
    /** CGGMP DKG第1轮回声 */
    CGGMP_DKG_ROUND1_ECHO,
    /** CGGMP DKG第2轮 */
    CGGMP_DKG_ROUND2,
    /** CGGMP DKG第2轮广播 */
    CGGMP_DKG_ROUND2_BROAD,
    /** CGGMP DKG第2轮批量处理 */
    CGGMP_DKG_ROUND2_BATCH,
    /** CGGMP DKG第3轮 */
    CGGMP_DKG_ROUND3,
    /** CGGMP DKG投诉 */
    CGGMP_DKG_COMPLAINT,
    /** CGGMP DKG排除 */
    CGGMP_DKG_EXCLUDE,

    // ==================== CGGMP 辅助信息 ====================
    /** CGGMP辅助信息初始化 */
    CGGMP_AUX_INIT,
    /** CGGMP辅助信息第1轮 */
    CGGMP_AUX_R1,
    /** CGGMP辅助信息第1轮回声 */
    CGGMP_AUX_R1_ECHO,
    /** CGGMP辅助信息第2轮 */
    CGGMP_AUX_R2,
    /** CGGMP辅助信息第3轮 */
    CGGMP_AUX_R3,
    /** CGGMP辅助信息状态 */
    CGGMP_AUX_STATUS,
    /** CGGMP辅助信息投诉 */
    CGGMP_AUX_COMPLAINT,

    // ==================== CGGMP 签名 - 初始化 ====================
    /** CGGMP签名初始化 */
    CGGMP_SIGN_INIT,

    // ==================== CGGMP 签名 - 离线阶段 ====================
    /** CGGMP签名离线初始化 */
    CGGMP_SIGN_OFFLINE_INIT,
    /** CGGMP签名离线就绪 */
    CGGMP_SIGN_OFFLINE_READY,

    // ==================== CGGMP 签名 - 在线阶段 ====================
    /** CGGMP签名在线初始化 */
    CGGMP_SIGN_ONLINE_INIT,
    /** CGGMP签名投诉 */
    CGGMP_SIGN_COMPLAINT,
    /** CGGMP签名排除 */
    CGGMP_SIGN_EXCLUDE,

    // ==================== CGGMP 预签名 ====================
    /** CGGMP预签名第1轮 */
    CGGMP_PRESIGN_R1,
    /** CGGMP预签名第1轮回声 */
    CGGMP_PRESIGN_R1_ECHO,
    /** CGGMP预签名第2轮 */
    CGGMP_PRESIGN_R2,
    /** CGGMP预签名第3轮 */
    CGGMP_PRESIGN_R3,

    // ==================== CGGMP 签名 - MtA协议 ====================
    /** CGGMP签名Gamma承诺 */
    CGGMP_SIGN_GAMMA_COMMIT,
    /** CGGMP签名Gamma公开 */
    CGGMP_SIGN_GAMMA_OPEN,
    /** CGGMP签名MtA密钥Agreement初始化 */
    CGGMP_SIGN_MTA_KA_INIT,
    /** CGGMP签名MtA密钥Agreement响应 */
    CGGMP_SIGN_MTA_KA_RESPONSE,
    /** CGGMP签名U承诺 */
    CGGMP_SIGN_U_COMMIT,
    /** CGGMP签名U份额 */
    CGGMP_SIGN_U_SHARE,
    /** CGGMP签名U公开 */
    CGGMP_SIGN_U_OPEN,
    /** CGGMP签名MtA签名类型初始化 */
    CGGMP_SIGN_MTA_ST_INIT,
    /** CGGMP签名MtA签名类型响应 */
    CGGMP_SIGN_MTA_ST_RESPONSE,
    /** CGGMP签名S份额 */
    CGGMP_SIGN_S_SHARE,

    // ==================== CGGMP 密钥刷新 ====================
    /** CGGMP刷新初始化 */
    CGGMP_REFRESH_INIT,
    /** CGGMP刷新第1轮 */
    CGGMP_REFRESH_R1,
    /** CGGMP刷新第2轮 */
    CGGMP_REFRESH_R2,
    /** CGGMP刷新第3轮 */
    CGGMP_REFRESH_R3,
    /** CGGMP刷新投诉 */
    CGGMP_REFRESH_COMPLAINT,
    /** CGGMP刷新排除 */
    CGGMP_REFRESH_EXCLUDE,

    // ==================== 简单签名 ====================
    /** 简单签名初始化 */
    SIMPLE_SIGN_INIT,
    /** 简单签名K值 */
    SIMPLE_SIGN_K,
    /** 简单签名Sigma值 */
    SIMPLE_SIGN_SIGMA,
    /** 简单签名离线阶段 */
    SIMPLE_SIGN_OFFLINE,
    /** 简单签名离线请求 */
    SIMPLE_SIGN_OFFLINE_REQUEST,
    /** 简单签名Sigma请求 */
    SIMPLE_SIGN_SIGMA_REQUEST
}
