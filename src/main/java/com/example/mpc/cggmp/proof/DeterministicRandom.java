package com.example.mpc.cggmp.proof;

import com.example.mpc.cggmp.util.BigIntegerUtils;
import com.example.mpc.cggmp.util.ZkBytes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

public final class DeterministicRandom extends Random {
    private static final long serialVersionUID = 1L;
    private final byte[] seed;
    private long counter;
    private int pos;
    private byte[] buf = new byte[0];

    public DeterministicRandom(BigInteger n, BigInteger w, String label, int i, byte[] ctx) {
        byte[] lab = label.getBytes(StandardCharsets.UTF_8);
        int nBits = n.bitLength();
        int nLen = (nBits + 7) / 8;
        byte[] nb = BigIntegerUtils.toUnsignedBytes(n, nLen);

        byte[] wb;
        if (w == null) {
            wb = new byte[0];
        } else {
            int wBits = w.bitLength();
            int wLen = (wBits + 7) / 8;
            wb = BigIntegerUtils.toUnsignedBytes(w, wLen);
        }

        byte[] ib = new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
        byte[] cb = (ctx == null) ? new byte[0] : ctx;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            this.seed = md.digest(ZkBytes.encode(lab, nb, wb, ib, cb));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void nextBytes(byte[] out) {
        int off = 0;
        while (off < out.length) {
            if (pos >= buf.length) {
                refill();
            }
            int n = Math.min(out.length - off, buf.length - pos);
            System.arraycopy(buf, pos, out, off, n);
            pos += n;
            off += n;
        }
    }

    @Override
    protected int next(int bits) {
        int acc = 0;
        int need = (bits + 7) >>> 3;
        for (int i = 0; i < need; i++) {
            if (pos >= buf.length) {
                refill();
            }
            acc = (acc << 8) | (buf[pos++] & 0xFF);
        }
        int excess = (need << 3) - bits;
        return acc >>> excess;
    }

    private void refill() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(seed);
            md.update(new byte[]{
                    (byte) (counter >>> 56), (byte) (counter >>> 48), (byte) (counter >>> 40), (byte) (counter >>> 32),
                    (byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter
            });
            buf = md.digest();
            pos = 0;
            counter++;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
