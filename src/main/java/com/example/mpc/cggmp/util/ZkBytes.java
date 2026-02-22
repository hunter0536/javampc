package com.example.mpc.cggmp.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Objects;

public final class ZkBytes {
    private ZkBytes() {
    }

    public static byte[] encode(byte[]... parts) {
        Objects.requireNonNull(parts, "parts");
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            for (byte[] p : parts) {
                out.write(ByteBuffer.allocate(4).putInt(p.length).array());
                out.write(p);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
