package com.example.mpc.common.util;

import org.slf4j.Logger;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

public final class RetryUtils {

    private RetryUtils() {
    }

    public static CompletableFuture<Void> retryAsync(
            ScheduledExecutorService scheduler,
            Logger logger,
            Supplier<CompletableFuture<Void>> action,
            int maxAttempts,
            long delayMs,
            String name) {
        int attempts = Math.max(1, maxAttempts);
        AtomicInteger counter = new AtomicInteger(0);
        CompletableFuture<Void> result = new CompletableFuture<>();
        final Runnable[] runner = new Runnable[1];
        runner[0] = () -> {
            int attempt = counter.incrementAndGet();
            action.get().whenComplete((v, ex) -> {
                if (ex == null) {
                    result.complete(null);
                    return;
                }
                if (attempt >= attempts) {
                    result.completeExceptionally(ex);
                    return;
                }
                logger.warn("{} failed (attempt {}/{}): {}", name, attempt, attempts, ex.getMessage());
                scheduler.schedule(runner[0], Math.max(0, delayMs), TimeUnit.MILLISECONDS);
            });
        };
        scheduler.execute(runner[0]);
        return result;
    }
}
