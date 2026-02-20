package com.example.mpc.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;

/**
 * 缓存工具类，用于缓存计算结果，减少重复计算
 */
public class CacheUtil {
    
    // 椭圆曲线点计算缓存，键为计算参数的字符串表示，值为计算结果
    private static final Cache<String, Object> ecPointCache = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .recordStats()
            .build();
    
    // 多项式计算缓存
    private static final Cache<String, Object> polynomialCache = Caffeine.newBuilder()
            .maximumSize(5000)
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .recordStats()
            .build();
    
    // 签名验证缓存
    private static final Cache<String, Boolean> signatureCache = Caffeine.newBuilder()
            .maximumSize(2000)
            .expireAfterWrite(30, TimeUnit.MINUTES)
            .recordStats()
            .build();
    
    /**
     * 获取椭圆曲线点计算缓存
     */
    public static Cache<String, Object> getEcPointCache() {
        return ecPointCache;
    }
    
    /**
     * 获取多项式计算缓存
     */
    public static Cache<String, Object> getPolynomialCache() {
        return polynomialCache;
    }
    
    /**
     * 获取签名验证缓存
     */
    public static Cache<String, Boolean> getSignatureCache() {
        return signatureCache;
    }
    
    /**
     * 生成缓存键
     */
    public static String generateCacheKey(String prefix, Object... args) {
        StringBuilder key = new StringBuilder(prefix);
        for (Object arg : args) {
            key.append("_").append(arg);
        }
        return key.toString();
    }
    
    /**
     * 清理所有缓存
     */
    public static void clearAllCaches() {
        ecPointCache.invalidateAll();
        polynomialCache.invalidateAll();
        signatureCache.invalidateAll();
    }
    
    /**
     * 获取缓存统计信息
     */
    public static String getCacheStats() {
        StringBuilder stats = new StringBuilder();
        stats.append("EC Point Cache Stats: ").append(ecPointCache.stats()).append("\n");
        stats.append("Polynomial Cache Stats: ").append(polynomialCache.stats()).append("\n");
        stats.append("Signature Cache Stats: ").append(signatureCache.stats()).append("\n");
        return stats.toString();
    }
}
