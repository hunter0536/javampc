package com.example.mpc.service;

import com.example.mpc.dao.KeyShareDao;
import com.example.mpc.dto.KeyShare;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class KeyShareService {
    private static final Logger logger = LoggerFactory.getLogger(KeyShareService.class);
    
    @Autowired
    private KeyShareDao keyShareDao;
    
    private final Map<String, KeyShare> cachedHotWalletKeyShares = new ConcurrentHashMap<>();
    private volatile long cachedKeyShareTime = 0;
    private static final long CACHE_VALID_TIME_MS = 5000;

    public KeyShare findByGroupPublicKeySync(int nodeId, String groupPublicKey) {
        return keyShareDao.findByGroupPublicKeySync(nodeId, groupPublicKey);
    }

    public KeyShare getActiveKeyShare(int nodeId) {
        return keyShareDao.findLatestSync(nodeId);
    }
    
    public KeyShare getActiveHotWalletKeyShare(int nodeId) {
        long now = System.currentTimeMillis();
        if (!cachedHotWalletKeyShares.isEmpty() && (now - cachedKeyShareTime) < CACHE_VALID_TIME_MS) {
            logger.debug("Using cached hot wallet key shares, size: {}", cachedHotWalletKeyShares.size());
            return cachedHotWalletKeyShares.values().iterator().next();
        }
        
        List<KeyShare> keyShares = keyShareDao.findAllHotWalletSync(nodeId);
        if (keyShares != null && !keyShares.isEmpty()) {
            cachedHotWalletKeyShares.clear();
            for (KeyShare ks : keyShares) {
                cachedHotWalletKeyShares.put(ks.getGroupPublicKey(), ks);
            }
            cachedKeyShareTime = now;
            logger.info("Cached {} hot wallet key shares", cachedHotWalletKeyShares.size());
            return keyShares.get(0);
        }
        return null;
    }
    
    public Map<String, KeyShare> getAllActiveHotWalletKeyShares(int nodeId) {
        long now = System.currentTimeMillis();
        if (!cachedHotWalletKeyShares.isEmpty() && (now - cachedKeyShareTime) < CACHE_VALID_TIME_MS) {
            logger.debug("Using cached hot wallet key shares, size: {}", cachedHotWalletKeyShares.size());
            return cachedHotWalletKeyShares;
        }
        
        List<KeyShare> keyShares = keyShareDao.findAllHotWalletSync(nodeId);
        if (keyShares != null && !keyShares.isEmpty()) {
            cachedHotWalletKeyShares.clear();
            for (KeyShare ks : keyShares) {
                cachedHotWalletKeyShares.put(ks.getGroupPublicKey(), ks);
            }
            cachedKeyShareTime = now;
            logger.info("Cached {} hot wallet key shares", cachedHotWalletKeyShares.size());
        }
        return cachedHotWalletKeyShares;
    }
}
