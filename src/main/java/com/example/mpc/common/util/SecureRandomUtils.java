package com.example.mpc.common.util;

import java.security.SecureRandom;

public final class SecureRandomUtils {

    private static final ThreadLocal<SecureRandom> THREAD_LOCAL_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    private SecureRandomUtils() {
    }

    public static SecureRandom getInstance() {
        return THREAD_LOCAL_RANDOM.get();
    }

    public static void nextBytes(byte[] bytes) {
        THREAD_LOCAL_RANDOM.get().nextBytes(bytes);
    }

    public static byte[] randomBytes(int len) {
        byte[] out = new byte[len];
        THREAD_LOCAL_RANDOM.get().nextBytes(out);
        return out;
    }

    public static int nextInt() {
        return THREAD_LOCAL_RANDOM.get().nextInt();
    }

    public static int nextInt(int bound) {
        return THREAD_LOCAL_RANDOM.get().nextInt(bound);
    }

    public static long nextLong() {
        return THREAD_LOCAL_RANDOM.get().nextLong();
    }

    public static boolean nextBoolean() {
        return THREAD_LOCAL_RANDOM.get().nextBoolean();
    }
}
