package com.example.mpc.util;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import java.util.concurrent.*;
import java.util.function.Supplier;

/**
 * 线程池管理工具类，为不同类型的任务提供专用线程池
 */
public class ThreadPoolUtil {
    
    // 计算密集型任务线程池（如密码学计算）
    private static final ExecutorService computationThreadPool;
    
    // IO密集型任务线程池（如网络通信）
    private static final ExecutorService ioThreadPool;
    
    // 定时任务线程池
    private static final ScheduledExecutorService scheduledThreadPool;
    
    // 单线程池（用于需要串行执行的任务）
    private static final ExecutorService singleThreadPool;
    
    static {
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        
        // 计算密集型任务线程池
        ThreadFactory computationThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("computation-pool-%d")
                .setDaemon(true)
                .build();
        computationThreadPool = new ThreadPoolExecutor(
                availableProcessors,
                availableProcessors * 2,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(500),
                computationThreadFactory,
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        // IO密集型任务线程池
        ThreadFactory ioThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("io-pool-%d")
                .setDaemon(true)
                .build();
        ioThreadPool = new ThreadPoolExecutor(
                availableProcessors * 2,
                availableProcessors * 4,
                60L,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000),
                ioThreadFactory,
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        // 定时任务线程池
        ThreadFactory scheduledThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("scheduled-pool-%d")
                .setDaemon(true)
                .build();
        scheduledThreadPool = new ScheduledThreadPoolExecutor(
                availableProcessors,
                scheduledThreadFactory,
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        // 单线程池
        ThreadFactory singleThreadFactory = new ThreadFactoryBuilder()
                .setNameFormat("single-pool-%d")
                .setDaemon(true)
                .build();
        singleThreadPool = new ThreadPoolExecutor(
                1,
                1,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                singleThreadFactory,
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
    }
    
    /**
     * 获取计算密集型任务线程池
     */
    public static ExecutorService getComputationThreadPool() {
        return computationThreadPool;
    }
    
    /**
     * 获取IO密集型任务线程池
     */
    public static ExecutorService getIoThreadPool() {
        return ioThreadPool;
    }
    
    /**
     * 获取定时任务线程池
     */
    public static ScheduledExecutorService getScheduledThreadPool() {
        return scheduledThreadPool;
    }
    
    /**
     * 获取单线程池
     */
    public static ExecutorService getSingleThreadPool() {
        return singleThreadPool;
    }
    
    /**
     * 关闭所有线程池
     */
    public static void shutdownAll() {
        computationThreadPool.shutdown();
        ioThreadPool.shutdown();
        scheduledThreadPool.shutdown();
        singleThreadPool.shutdown();
    }
    
    /**
     * 强制关闭所有线程池
     */
    public static void shutdownNowAll() {
        computationThreadPool.shutdownNow();
        ioThreadPool.shutdownNow();
        scheduledThreadPool.shutdownNow();
        singleThreadPool.shutdownNow();
    }
    
    /**
     * 提交计算密集型任务
     */
    public static <T> CompletableFuture<T> submitComputationTask(Supplier<T> task) {
        return CompletableFuture.supplyAsync(task, computationThreadPool);
    }
    
    /**
     * 提交IO密集型任务
     */
    public static <T> CompletableFuture<T> submitIoTask(Supplier<T> task) {
        return CompletableFuture.supplyAsync(task, ioThreadPool);
    }
    
    /**
     * 提交计算密集型任务（无返回值）
     */
    public static CompletableFuture<Void> submitComputationTask(Runnable task) {
        return CompletableFuture.runAsync(task, computationThreadPool);
    }
    
    /**
     * 提交IO密集型任务（无返回值）
     */
    public static CompletableFuture<Void> submitIoTask(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }
    
    /**
     * 延迟执行任务
     */
    public static ScheduledFuture<?> scheduleTask(Runnable task, long delay, TimeUnit unit) {
        return scheduledThreadPool.schedule(task, delay, unit);
    }
    
    /**
     * 定期执行任务
     */
    public static ScheduledFuture<?> scheduleAtFixedRate(Runnable task, long initialDelay, long period, TimeUnit unit) {
        return scheduledThreadPool.scheduleAtFixedRate(task, initialDelay, period, unit);
    }
}
