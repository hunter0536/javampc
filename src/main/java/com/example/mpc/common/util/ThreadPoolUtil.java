package com.example.mpc.common.util;

import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadPoolUtil {

    // ---- Constants ----
    private static final int CORE_POOL_SIZE = Math.max(2, Runtime.getRuntime().availableProcessors());
    private static final int MAX_POOL_SIZE = Math.max(4, CORE_POOL_SIZE * 2);
    private static final int IO_MAX_POOL_SIZE = Math.max(64, CORE_POOL_SIZE * 4);
    private static final long KEEP_ALIVE_TIME = 60L;
    private static final TimeUnit KEEP_ALIVE_TIME_UNIT = TimeUnit.SECONDS;

    private static final int PRESIGN_QUEUE_SIZE = 1000;
    private static final int HOT_WALLET_PRESIGN_QUEUE_SIZE = 1000;
    private static final int IO_QUEUE_SIZE = 500;
    private static final int AUX_QUEUE_SIZE = 500;
    private static final int DISPATCH_QUEUE_SIZE = 1000;
    private static final int PROTOCOL_QUEUE_SIZE = 1000;

    // ---- Thread factories ----
    private static final ThreadFactory IO_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-IO-");
    private static final ThreadFactory AUX_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-AUX-");
    private static final ThreadFactory PRESIGN_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-Presign-");
    private static final ThreadFactory HOT_WALLET_PRESIGN_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-HotWalletPresign-");
    private static final ThreadFactory SINGLE_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-Single-");

    private static final ThreadFactory AUX_DISPATCH_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-AuxDispatch-");
    private static final ThreadFactory REFRESH_DISPATCH_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-RefreshDispatch-");
    private static final ThreadFactory SIGNATURE_DISPATCH_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-SignDispatch-");

    private static final ThreadFactory DKG_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-DKG-");
    private static final ThreadFactory GENNARO_DKG_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-GennaroDKG-");
    private static final ThreadFactory REFRESH_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-Refresh-");
    private static final ThreadFactory SIGNATURE_THREAD_FACTORY = newNamedThreadFactory("ThreadPoolUtil-Sign-");

    // ---- Policies ----
    private static final RejectedExecutionHandler REJECTED_HANDLER = new ThreadPoolExecutor.CallerRunsPolicy();

    // ---- Queues ----
    private static final LinkedBlockingQueue<Runnable> presignQueue = new LinkedBlockingQueue<>(PRESIGN_QUEUE_SIZE);
    private static final LinkedBlockingQueue<Runnable> hotWalletPresignQueue = new LinkedBlockingQueue<>(HOT_WALLET_PRESIGN_QUEUE_SIZE);

    // ---- Thread pools ----
    private static final ThreadPoolExecutor ioThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            IO_MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(IO_QUEUE_SIZE),
            IO_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor auxThreadPool = new ThreadPoolExecutor(
            Math.max(2, CORE_POOL_SIZE / 2),
            Math.max(2, CORE_POOL_SIZE / 2),
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(AUX_QUEUE_SIZE),
            AUX_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor singleThreadPool = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(DISPATCH_QUEUE_SIZE),
            SINGLE_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor auxDispatchThreadPool = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(DISPATCH_QUEUE_SIZE),
            AUX_DISPATCH_THREAD_FACTORY,
            REJECTED_HANDLER
    );
    private static final ThreadPoolExecutor refreshDispatchThreadPool = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(DISPATCH_QUEUE_SIZE),
            REFRESH_DISPATCH_THREAD_FACTORY,
            REJECTED_HANDLER
    );
    private static final ThreadPoolExecutor signatureDispatchThreadPool = new ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            new LinkedBlockingQueue<>(DISPATCH_QUEUE_SIZE),
            SIGNATURE_DISPATCH_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor dkgThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(PROTOCOL_QUEUE_SIZE),
            DKG_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor gennaroDkgThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(PROTOCOL_QUEUE_SIZE),
            GENNARO_DKG_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor refreshThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(PROTOCOL_QUEUE_SIZE),
            REFRESH_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor signatureThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            new LinkedBlockingQueue<>(PROTOCOL_QUEUE_SIZE),
            SIGNATURE_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor presignThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            presignQueue,
            PRESIGN_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ThreadPoolExecutor hotWalletPresignThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            hotWalletPresignQueue,
            HOT_WALLET_PRESIGN_THREAD_FACTORY,
            REJECTED_HANDLER
    );

    // ---- Initialization ----
    static {
        ioThreadPool.allowCoreThreadTimeOut(true);
        auxThreadPool.allowCoreThreadTimeOut(true);
        dkgThreadPool.allowCoreThreadTimeOut(true);
        gennaroDkgThreadPool.allowCoreThreadTimeOut(true);
        refreshThreadPool.allowCoreThreadTimeOut(true);
        signatureThreadPool.allowCoreThreadTimeOut(true);
        presignThreadPool.allowCoreThreadTimeOut(true);
        hotWalletPresignThreadPool.allowCoreThreadTimeOut(true);
    }

    // ---- Accessors ----
    public static ExecutorService getIoThreadPool() {
        return ioThreadPool;
    }

    public static ExecutorService getSingleThreadPool() {
        return singleThreadPool;
    }

    public static ExecutorService getAuxThreadPool() {
        return auxThreadPool;
    }

    public static ExecutorService getPresignThreadPool() {
        return presignThreadPool;
    }

    public static ExecutorService getHotWalletPresignThreadPool() {
        return hotWalletPresignThreadPool;
    }

    public static ExecutorService getAuxDispatchThreadPool() {
        return auxDispatchThreadPool;
    }

    public static ExecutorService getRefreshDispatchThreadPool() {
        return refreshDispatchThreadPool;
    }

    public static ExecutorService getSignatureDispatchThreadPool() {
        return signatureDispatchThreadPool;
    }

    public static ExecutorService getDkgThreadPool() {
        return dkgThreadPool;
    }

    public static ExecutorService getGennaroDkgThreadPool() {
        return gennaroDkgThreadPool;
    }

    public static ExecutorService getRefreshThreadPool() {
        return refreshThreadPool;
    }

    public static ExecutorService getSignatureThreadPool() {
        return signatureThreadPool;
    }

    // ---- Monitoring ----
    public static Map<String, Object> getThreadPoolStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("io", describeThreadPool(ioThreadPool));
        stats.put("aux", describeThreadPool(auxThreadPool));
        stats.put("single", describeThreadPool(singleThreadPool));
        stats.put("auxDispatch", describeThreadPool(auxDispatchThreadPool));
        stats.put("refreshDispatch", describeThreadPool(refreshDispatchThreadPool));
        stats.put("signatureDispatch", describeThreadPool(signatureDispatchThreadPool));
        stats.put("dkg", describeThreadPool(dkgThreadPool));
        stats.put("gennaroDkg", describeThreadPool(gennaroDkgThreadPool));
        stats.put("refresh", describeThreadPool(refreshThreadPool));
        stats.put("signature", describeThreadPool(signatureThreadPool));
        stats.put("presign", describeThreadPool(presignThreadPool));
        stats.put("hotWalletPresign", describeThreadPool(hotWalletPresignThreadPool));
        return stats;
    }

    // ---- Utilities ----
    public static CompletableFuture<Void> submitIoTask(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }

    // ---- Shutdown ----
    public static void shutdown() {
        ioThreadPool.shutdown();
        auxThreadPool.shutdown();
        singleThreadPool.shutdown();
        auxDispatchThreadPool.shutdown();
        refreshDispatchThreadPool.shutdown();
        signatureDispatchThreadPool.shutdown();
        dkgThreadPool.shutdown();
        gennaroDkgThreadPool.shutdown();
        refreshThreadPool.shutdown();
        signatureThreadPool.shutdown();
        presignThreadPool.shutdown();
        hotWalletPresignThreadPool.shutdown();
    }

    // ---- Internals ----
    private static ThreadFactory newNamedThreadFactory(String prefix) {
        return new ThreadFactory() {
            private final ThreadFactory defaultFactory = Executors.defaultThreadFactory();
            private final AtomicInteger threadNumber = new AtomicInteger(1);

            @Override
            public Thread newThread(@NonNull Runnable r) {
                Thread t = defaultFactory.newThread(r);
                t.setName(prefix + threadNumber.getAndIncrement());
                return t;
            }
        };
    }

    private static Map<String, Object> describeThreadPool(ThreadPoolExecutor executor) {
        Map<String, Object> info = new HashMap<>();
        info.put("corePoolSize", executor.getCorePoolSize());
        info.put("maxPoolSize", executor.getMaximumPoolSize());
        info.put("poolSize", executor.getPoolSize());
        info.put("active", executor.getActiveCount());
        info.put("queued", executor.getQueue().size());
        info.put("queueRemaining", executor.getQueue().remainingCapacity());
        info.put("completed", executor.getCompletedTaskCount());
        info.put("taskCount", executor.getTaskCount());
        info.put("largestPoolSize", executor.getLargestPoolSize());
        return info;
    }
}
