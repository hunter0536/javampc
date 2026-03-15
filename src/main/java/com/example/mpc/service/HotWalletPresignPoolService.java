package com.example.mpc.service;

import com.example.mpc.cggmp.presign.Presignature;
import com.example.mpc.common.util.ThreadPoolUtil;
import com.example.mpc.dao.AuxInfoDao;
import com.example.mpc.dto.KeyShare;
import com.example.mpc.dto.PresignData;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class HotWalletPresignPoolService {

    public static final ExecutorService PRESIGN_EXECUTOR_SERVICE = ThreadPoolUtil.getHotWalletPresignThreadPool();

    private static final Logger LOGGER = LoggerFactory.getLogger(HotWalletPresignPoolService.class);

    @Value("${cggmp.presign.pool.enabled:false}")
    private boolean enabled;

    @Value("${cggmp.presign.pool.minSize:5}")
    private int minSize;

    @Value("${cggmp.presign.pool.maxSize:15}")
    private int maxSize;

    @Value("${cggmp.presign.pool.maxAgeMinutes:20}")
    private int maxAgeMinutes;

    @Value("${cggmp.presign.pool.generationThreads:1}")
    private int generationThreads;

    @Value("${cggmp.presign.pool.maxTaskHistory:1000}")
    private int maxTaskHistory;

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
    private final Map<String, List<String>> taskHistory = new ConcurrentHashMap<>();
    private final AtomicBoolean globalLock = new AtomicBoolean(false);

    @PostConstruct
    public void init() {
        LOGGER.info("HotWalletPresignPoolService initialized with generationThreads={}", generationThreads);
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

    public boolean removePresignById(String groupPublicKey, String presignId) {
        if (!enabled || presignId == null) {
            return false;
        }

        BlockingQueue<PresignData> pool = hotWalletPools.get(groupPublicKey);
        if (pool == null) {
            return false;
        }

        boolean removed = pool.removeIf(presignData -> presignId.equals(presignData.getPresignId()));
        if (removed) {
            LOGGER.info("Removed presign {} from pool (groupPublicKey={}), remaining: {}", presignId, groupPublicKey, pool.size());
        } else {
            LOGGER.warn("Failed to remove presign {} from pool (groupPublicKey={}), not found", presignId, groupPublicKey);
        }
        return removed;
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

    public void scheduledRefresh() {
        if (!enabled) {
            return;
        }

        if (!globalLock.compareAndSet(false, true)) {
            LOGGER.debug("Presign task is already running, skip");
            return;
        }

        try {
            ThreadPoolUtil.getHotWalletPresignThreadPool().execute(() -> {
                try {
                    doRefreshHotWalletPresignPool();
                } finally {
                    globalLock.set(false);
                }
            });
        } catch (RuntimeException e) {
            globalLock.set(false);
            throw e;
        }
    }

    private void doRefreshHotWalletPresignPool() {
        LOGGER.info("HotWalletPresignPoolService scheduledRefresh called, nodeId={}", nodeId);

        if (nodeId != 1) {
            LOGGER.debug("Only node 1 can initiate presign generation, skipping");
            return;
        }

        if (!areAllPeerConnectionsActive()) {
            LOGGER.warn("Not all peer connections are active, skipping presign generation");
            return;
        }

        Map<String, KeyShare> hotWalletKeyShares = keyShareService.getAllActiveHotWalletKeyShares(nodeId);
        if (hotWalletKeyShares == null || hotWalletKeyShares.isEmpty()) {
            LOGGER.warn("No active hot wallet key shares for presign generation");
            cleanupUnusedPools(Set.of());
            return;
        }

        int auxCount = auxInfoDao.countAuxSync(nodeId);
        if (auxCount == 0) {
            LOGGER.warn("Missing auxiliary info. Skip presign generation. Run AUX provisioning first.");
            return;
        }

        Set<String> activeGroups = new HashSet<>(hotWalletKeyShares.keySet());

        for (Map.Entry<String, KeyShare> entry : hotWalletKeyShares.entrySet()) {
            String groupPublicKey = entry.getKey();
            KeyShare keyShare = entry.getValue();
            if (groupPublicKey == null || keyShare == null) {
                continue;
            }

            BlockingQueue<PresignData> pool = hotWalletPools.computeIfAbsent(
                    groupPublicKey, k -> new LinkedBlockingQueue<>(maxSize));

            int currentSize = pool.size();
            int expiredCount = countExpiredPresigns(pool);

            LOGGER.debug("Processing pool for groupPublicKey={}, size={}, expired={}",
                    groupPublicKey, currentSize, expiredCount);

            if (expiredCount > 0) {
                removeExpiredPresigns(pool, expiredCount);
                LOGGER.info("Removed expired presigns for groupPublicKey={}", groupPublicKey);
            }

            cleanupCompletedTasks(groupPublicKey);

            int availableSize = currentSize - expiredCount;

            if (availableSize >= maxSize) {
                LOGGER.debug("Presign pool for {} is full (available={}), skip generation", groupPublicKey, availableSize);
                continue;
            }

            int neededPresigs;
            if (availableSize < minSize) {
                neededPresigs = Math.max(maxSize - availableSize, generationThreads);
                LOGGER.info("Presign pool below minSize (available={}, min={}), generating presigns", availableSize, minSize);
            } else {
                neededPresigs = Math.min(maxSize - availableSize, generationThreads);
            }

            AtomicInteger runningCount = runningTaskCounts.computeIfAbsent(groupPublicKey, k -> new AtomicInteger(0));

            int toSubmit;
            synchronized (runningCount) {
                int currentRunning = runningCount.get();

                if (currentRunning >= generationThreads) {
                    LOGGER.debug("Max tasks running for {}, skip", groupPublicKey);
                    continue;
                }

                int slotsAvailable = generationThreads - currentRunning;
                toSubmit = Math.min(neededPresigs, slotsAvailable);

                runningCount.addAndGet(toSubmit);
            }

            for (int i = 0; i < toSubmit; i++) {
                final int index = i;
                Future<?> future = PRESIGN_EXECUTOR_SERVICE.submit(() -> {
                    try {
                        generatePresignForKeyShare(groupPublicKey, keyShare, pool, index, runningCount);
                    } catch (Exception e) {
                        LOGGER.error("Failed to generate presign for {}: {}", groupPublicKey, e.getMessage());
                    }
                });

                runningTasks.computeIfAbsent(groupPublicKey, k -> new ArrayList<>()).add(future);
            }
        }

        cleanupUnusedPools(activeGroups);
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
            recordTaskHistory(groupPublicKey, taskId);
            signatureService.executePresignOffline(taskId);
        } catch (Exception e) {
            LOGGER.error("Failed to generate presign for groupPublicKey={}: {}", groupPublicKey, e.getMessage());
        } finally {
            if (runningCount != null) {
                runningCount.decrementAndGet();
            }
        }
    }

    private void cleanupCompletedTasks(String groupPublicKey) {
        List<Future<?>> tasks = runningTasks.get(groupPublicKey);
        if (tasks == null) {
            return;
        }
        tasks.removeIf(task -> task.isDone() || task.isCancelled());
        if (tasks.isEmpty()) {
            runningTasks.remove(groupPublicKey);
        }
    }

    private void cleanupUnusedPools(Set<String> activeGroups) {
        for (String groupPublicKey : new ArrayList<>(hotWalletPools.keySet())) {
            if (activeGroups.contains(groupPublicKey)) {
                continue;
            }
            if (!canCleanupGroup(groupPublicKey)) {
                continue;
            }
            hotWalletPools.remove(groupPublicKey);
            runningTaskCounts.remove(groupPublicKey);
            runningTasks.remove(groupPublicKey);
            poolLocks.remove(groupPublicKey);
            taskHistory.remove(groupPublicKey);
            LOGGER.info("Removed presign pool state for inactive groupPublicKey={}", groupPublicKey);
        }
    }

    private boolean canCleanupGroup(String groupPublicKey) {
        BlockingQueue<PresignData> pool = hotWalletPools.get(groupPublicKey);
        if (pool != null && !pool.isEmpty()) {
            return false;
        }
        AtomicInteger runningCount = runningTaskCounts.get(groupPublicKey);
        if (runningCount != null && runningCount.get() > 0) {
            return false;
        }
        cleanupCompletedTasks(groupPublicKey);
        List<Future<?>> tasks = runningTasks.get(groupPublicKey);
        return tasks == null || tasks.isEmpty();
    }

    private void recordTaskHistory(String groupPublicKey, String taskId) {
        if (taskId == null) {
            return;
        }
        List<String> history = taskHistory.computeIfAbsent(groupPublicKey, k -> new ArrayList<>());
        synchronized (history) {
            history.add(taskId);
            if (history.size() > maxTaskHistory) {
                int overflow = history.size() - maxTaskHistory;
                history.subList(0, overflow).clear();
            }
        }
    }
}
