package com.example.mpc.service;

import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.dto.PresignData;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class PresignPoolService {

    public static final ExecutorService PRESIGN_EXECUTOR_SERVICE = ThreadPoolUtil.getPresignThreadPool();

    private static final Logger LOGGER = LoggerFactory.getLogger(PresignPoolService.class);

    @Value("${hotwallet.presign-pool.enabled:false}")
    private boolean enabled;

    @Value("${hotwallet.presign-pool.min-size:5}")
    private int minSize;

    @Value("${hotwallet.presign-pool.max-size:15}")
    private int maxSize;

    @Value("${hotwallet.presign-pool.max-age-minutes:20}")
    private int maxAgeMinutes;

    @Value("${hotwallet.presign-pool.generation-threads:1}")
    private int generationThreads;

    @Value("${node.id}")
    private int nodeId;

    @Autowired
    private CggmpSignatureService signatureService;

    @Autowired
    private KeyShareService keyShareService;

    @Autowired
    private AuxInfoDao auxInfoDao;

    @Autowired
    private NodeService nodeService;

    private final Map<String, BlockingQueue<PresignData>> hotWalletPools = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> runningTaskCounts = new ConcurrentHashMap<>();
    private final Map<String, List<Future<?>>> runningTasks = new ConcurrentHashMap<>();
    private final Map<String, Object> poolLocks = new ConcurrentHashMap<>();
    private final AtomicBoolean globalLock = new AtomicBoolean(false);

    @PostConstruct
    public void init() {
        LOGGER.info("PresignPoolService initialized with generationThreads={}", generationThreads);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getPoolSize(String groupPublicKey) {
        BlockingQueue<PresignData> pool = hotWalletPools.get(groupPublicKey);
        return pool != null ? pool.size() : 0;
    }

    public int getTotalPoolSize() {
        return hotWalletPools.values().stream().mapToInt(BlockingQueue::size).sum();
    }

    public Optional<PresignData> tryConsume(String groupPublicKey, boolean isHotWallet) {
        if (!enabled) {
            return Optional.empty();
        }

        if (!isHotWallet) {
            LOGGER.debug("Non-hot-wallet signature, skipping presign pool");
            return Optional.empty();
        }

        BlockingQueue<PresignData> pool = hotWalletPools.get(groupPublicKey);
        if (pool == null) {
            LOGGER.warn("No presign pool for group public key: {}", groupPublicKey);
            return Optional.empty();
        }

        PresignData presignData = pool.poll();
        if (presignData == null) {
            LOGGER.warn("Presign pool is empty for group public key: {}", groupPublicKey);
            return Optional.empty();
        }

        if (presignData.isExpired(maxAgeMinutes)) {
            LOGGER.warn("Presign expired, discarding");
            return Optional.empty();
        }

        LOGGER.info("Consumed presign from pool (groupPublicKey={}, presignId={}), remaining: {}",
                groupPublicKey, presignData.getPresignId(), pool.size());

        return Optional.of(presignData);
    }

    public Optional<PresignData> getPresignById(String groupPublicKey, String presignId) {
        if (!enabled || presignId == null) {
            return Optional.empty();
        }

        BlockingQueue<PresignData> pool = hotWalletPools.get(groupPublicKey);
        if (pool == null) {
            return Optional.empty();
        }

        for (PresignData presignData : pool) {
            if (presignId.equals(presignData.getPresignId())) {
                if (presignData.isExpired(maxAgeMinutes)) {
                    LOGGER.warn("Found presign {} but it is expired", presignId);
                    return Optional.empty();
                }
                return Optional.of(presignData);
            }
        }

        LOGGER.warn("Presign with id {} not found in pool for {}", presignId, groupPublicKey);
        return Optional.empty();
    }

    public String signWithPresignData(String groupPublicKey, String message, PresignData presignData) {
        Presignature presignature = presignData.toPresignature();
        return signatureService.signWithPresignature(groupPublicKey, message, presignature);
    }

    public void addPresignToPool(String groupPublicKey, Presignature presignature) {
        if (!enabled) {
            return;
        }
        BlockingQueue<PresignData> pool = hotWalletPools.computeIfAbsent(groupPublicKey, k -> new LinkedBlockingQueue<>(maxSize));
        if (pool.size() >= maxSize) {
            LOGGER.debug("Presign pool for {} is full, skip adding", groupPublicKey);
            return;
        }
        PresignData presignData = new PresignData(groupPublicKey, presignature);
        pool.offer(presignData);
        LOGGER.info("Added presign to pool (groupPublicKey={}), pool size: {}", groupPublicKey, pool.size());
    }

    @Scheduled(fixedDelayString = "${hotwallet.presign-pool.refresh-interval-ms:30000}")
    public void generateAndRefreshPresigs() {
        if (!enabled) {
            return;
        }

        if (!globalLock.compareAndSet(false, true)) {
            LOGGER.debug("Presign task is already running, skip");
            return;
        }

        try {
            doGenerateAndRefreshPresigs();
        } finally {
            globalLock.set(false);
        }
    }

    private void doGenerateAndRefreshPresigs() {
        LOGGER.info("PresignPoolService doGenerateAndRefreshPresigs called, nodeId={}", nodeId);

        if (nodeId != 1) {
            LOGGER.debug("Only node 1 can initiate presign generation, skipping");
            return;
        }

        int networkSize = nodeService.getNodes().size() + 1;
        if (networkSize < 5) {
            LOGGER.warn("Network not ready: only {} nodes connected, skipping presign generation", networkSize);
            return;
        }

        if (!areAllPeerConnectionsActive()) {
            LOGGER.warn("Not all peer connections are active, skipping presign generation");
            return;
        }

        Map<String, KeyShare> hotWalletKeyShares = keyShareService.getAllActiveHotWalletKeyShares(nodeId);
        if (hotWalletKeyShares == null || hotWalletKeyShares.isEmpty()) {
            LOGGER.warn("No active hot wallet key shares for presign generation");
            return;
        }

        KeyShare latestHotWallet = keyShareService.getActiveHotWalletKeyShare(nodeId);
        if (latestHotWallet == null) {
            LOGGER.warn("No hot wallet key share found");
            return;
        }

        int auxCount = auxInfoDao.countAuxSync(nodeId);
        if (auxCount == 0) {
            LOGGER.warn("Missing auxiliary info. Skip presign generation. Run AUX provisioning first.");
            return;
        }

        String groupPublicKey = latestHotWallet.getGroupPublicKey();

        BlockingQueue<PresignData> pool = hotWalletPools.computeIfAbsent(
            groupPublicKey, k -> new LinkedBlockingQueue<>());

        int currentSize = pool.size();
        int expiredCount = countExpiredPresigns(pool);

        LOGGER.debug("Processing pool for groupPublicKey={}, size={}, expired={}",
            groupPublicKey, currentSize, expiredCount);

        if (expiredCount > 0) {
            removeExpiredPresigns(pool, expiredCount);
            LOGGER.info("Removed expired presigns for groupPublicKey={}", groupPublicKey);
        }

        int availableSize = currentSize - expiredCount;

        if (availableSize >= maxSize) {
            LOGGER.debug("Presign pool for {} is full (available={}), skip generation", groupPublicKey, availableSize);
            return;
        }

        int neededPresigs;
        if (availableSize < minSize) {
            neededPresigs = Math.max(maxSize - availableSize, generationThreads);
            LOGGER.info("Presign pool below min-size (available={}, min={}),紧急生成预签名", availableSize, minSize);
        } else {
            neededPresigs = Math.min(maxSize - availableSize, generationThreads);
        }

        AtomicInteger runningCount = runningTaskCounts.computeIfAbsent(groupPublicKey, k -> new AtomicInteger(0));

        int toSubmit;
        synchronized (runningCount) {
            int currentRunning = runningCount.get();

            if (currentRunning >= generationThreads) {
                LOGGER.debug("Max tasks running for {}, skip", groupPublicKey);
                return;
            }

            int slotsAvailable = generationThreads - currentRunning;
            toSubmit = Math.min(neededPresigs, slotsAvailable);

            runningCount.addAndGet(toSubmit);
        }

        for (int i = 0; i < toSubmit; i++) {
            final int index = i;
            Future<?> future = PRESIGN_EXECUTOR_SERVICE.submit(() -> {
                try {
                    generatePresignForKeyShare(groupPublicKey, latestHotWallet, pool, index, runningCount);
                } catch (Exception e) {
                    LOGGER.error("Failed to generate presign for {}: {}", groupPublicKey, e.getMessage());
                }
            });

            runningTasks.computeIfAbsent(groupPublicKey, k -> new ArrayList<>()).add(future);
        }
    }

    private boolean areAllPeerConnectionsActive() {
        boolean result = nodeService.areAllPeerConnectionsActive();
        if (!result) {
            LOGGER.debug("Not all peer connections are active");
        }
        return result;
    }

    private int countExpiredPresigns(BlockingQueue<PresignData> pool) {
        int count = 0;
        for (PresignData presign : pool) {
            if (presign.isExpired(maxAgeMinutes)) {
                count++;
            }
        }
        return count;
    }

    private void removeExpiredPresigns(BlockingQueue<PresignData> pool, int expectedCount) {
        List<PresignData> remaining = new ArrayList<>();
        pool.drainTo(remaining);

        List<PresignData> valid = new ArrayList<>();
        for (PresignData presign : remaining) {
            if (!presign.isExpired(maxAgeMinutes)) {
                valid.add(presign);
            }
        }

        for (PresignData presign : valid) {
            pool.offer(presign);
        }
    }

    private void generatePresignForKeyShare(String groupPublicKey, KeyShare keyShare, BlockingQueue<PresignData> pool, int index, AtomicInteger runningCount) {
        Object poolLock = poolLocks.computeIfAbsent(groupPublicKey, k -> new Object());

        boolean shouldGenerate;
        synchronized (poolLock) {
            boolean isHotWallet = keyShare.getIsHotWallet() != null && keyShare.getIsHotWallet();
            if (!isHotWallet) {
                LOGGER.debug("Skipping presign generation for non-hot-wallet key share");
                shouldGenerate = false;
            } else if (pool.size() >= maxSize) {
                LOGGER.debug("Presign pool for {} is already full, skip generation", groupPublicKey);
                shouldGenerate = false;
            } else {
                shouldGenerate = true;
            }
        }

        if (!shouldGenerate) {
            if (runningCount != null) {
                runningCount.decrementAndGet();
            }
            return;
        }

        try {
            LOGGER.info("Starting presign generation for groupPublicKey={}, index={}", groupPublicKey, index);

            String taskId = signatureService.createPresignTaskOnly(groupPublicKey);

            signatureService.executePresignOffline(taskId);
        } catch (Exception e) {
            LOGGER.error("Failed to generate presign for groupPublicKey={}: {}", groupPublicKey, e.getMessage());
        } finally {
            if (runningCount != null) {
                runningCount.decrementAndGet();
            }
        }
    }
}
