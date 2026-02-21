package com.example.mpc.util;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadPoolUtil {
    private static final int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int MAX_POOL_SIZE = CORE_POOL_SIZE * 2;
    private static final long KEEP_ALIVE_TIME = 60L;
    private static final TimeUnit KEEP_ALIVE_TIME_UNIT = TimeUnit.SECONDS;
    private static final BlockingQueue<Runnable> WORK_QUEUE = new LinkedBlockingQueue<>(1000);
    private static final ThreadFactory THREAD_FACTORY = new ThreadFactory() {
        private final ThreadFactory defaultFactory = Executors.defaultThreadFactory();
        private final AtomicInteger threadNumber = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = defaultFactory.newThread(r);
            t.setName("ThreadPoolUtil-" + threadNumber.getAndIncrement());
            return t;
        }
    };
    private static final RejectedExecutionHandler REJECTED_HANDLER = new ThreadPoolExecutor.CallerRunsPolicy();

    // 计算线程池 - 用于CPU密集型任务
    private static final ExecutorService computationThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            WORK_QUEUE,
            THREAD_FACTORY,
            REJECTED_HANDLER
    );

    // IO线程池 - 用于IO密集型任务
    private static final ExecutorService ioThreadPool = Executors.newCachedThreadPool();

    // 单线程池 - 用于任务协调
    private static final ExecutorService singleThreadPool = Executors.newSingleThreadExecutor();

    /**
     * 获取计算线程池
     */
    public static ExecutorService getComputationThreadPool() {
        return computationThreadPool;
    }

    /**
     * 获取IO线程池
     */
    public static ExecutorService getIoThreadPool() {
        return ioThreadPool;
    }

    /**
     * 获取单线程池
     */
    public static ExecutorService getSingleThreadPool() {
        return singleThreadPool;
    }

    /**
     * 提交任务到计算线程池
     */
    public static CompletableFuture<Void> submitToComputationThreadPool(Runnable task) {
        return CompletableFuture.runAsync(task, computationThreadPool);
    }

    /**
     * 提交任务到IO线程池
     */
    public static CompletableFuture<Void> submitToIoThreadPool(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }

    /**
     * 提交IO任务（简化方法）
     */
    public static CompletableFuture<Void> submitIoTask(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }

    /**
     * 关闭所有线程池
     */
    public static void shutdown() {
        computationThreadPool.shutdown();
        ioThreadPool.shutdown();
        singleThreadPool.shutdown();
    }
}