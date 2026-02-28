package com.example.mpc.common.util;

import java.util.concurrent.BlockingQueue;
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
    private static final int CORE_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int MAX_POOL_SIZE = CORE_POOL_SIZE;
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

    private static final ExecutorService computationThreadPool = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_TIME,
            KEEP_ALIVE_TIME_UNIT,
            WORK_QUEUE,
            THREAD_FACTORY,
            REJECTED_HANDLER
    );

    private static final ExecutorService ioThreadPool = Executors.newCachedThreadPool();

    private static final ExecutorService auxThreadPool = Executors.newFixedThreadPool(
            Math.max(2, CORE_POOL_SIZE / 2),
            THREAD_FACTORY
    );

    private static final ExecutorService singleThreadPool = Executors.newSingleThreadExecutor();

    public static ExecutorService getComputationThreadPool() {
        return computationThreadPool;
    }

    public static ExecutorService getIoThreadPool() {
        return ioThreadPool;
    }

    public static ExecutorService getSingleThreadPool() {
        return singleThreadPool;
    }

    public static ExecutorService getAuxThreadPool() {
        return auxThreadPool;
    }

    public static CompletableFuture<Void> submitToComputationThreadPool(Runnable task) {
        return CompletableFuture.runAsync(task, computationThreadPool);
    }

    public static CompletableFuture<Void> submitToIoThreadPool(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }

    public static CompletableFuture<Void> submitIoTask(Runnable task) {
        return CompletableFuture.runAsync(task, ioThreadPool);
    }

    public static void shutdown() {
        computationThreadPool.shutdown();
        ioThreadPool.shutdown();
        auxThreadPool.shutdown();
        singleThreadPool.shutdown();
    }
}
