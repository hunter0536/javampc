package com.example.mpc.service.cggmp.refresh;

import com.example.mpc.cggmp.PaillierEncryption;
import com.example.mpc.cggmp.proof.PiPrmProof;
import com.example.mpc.cggmp.util.Secp256k1CurveUtils;
import com.example.mpc.cggmp.zk.ZKSetup;
import com.example.mpc.common.util.HexUtils;
import com.example.mpc.enums.MessageType;
import com.example.mpc.model.CggmpRefreshTask;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class CggmpRefreshUtils {
    private CggmpRefreshUtils() {
    }

    public static byte[] buildRefreshContext(String taskId, byte[] rid, int senderId, String label) {
        String base = "REFRESH:" + label + ":" + taskId + ":" + senderId + ":";
        byte[] prefix = base.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (rid == null) {
            return prefix;
        }
        byte[] out = new byte[prefix.length + rid.length];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(rid, 0, out, prefix.length, rid.length);
        return out;
    }

    public static BigInteger[] generateRefreshPedersen(int bitLength) {
        SecureRandom rnd = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, rnd);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, rnd);
        while (p.equals(q)) {
            q = BigInteger.probablePrime(bitLength / 2, rnd);
        }
        BigInteger hatN = p.multiply(q);
        BigInteger t;
        do {
            t = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        } while (t.signum() == 0 || !t.gcd(hatN).equals(BigInteger.ONE));
        t = t.modPow(BigInteger.TWO, hatN);
        BigInteger lambda = new BigInteger(hatN.bitLength(), rnd).mod(hatN);
        BigInteger s = t.modPow(lambda, hatN);
        return new BigInteger[]{hatN, s, t, lambda};
    }

    public static String computeRefreshCommit(String taskId,
                                       int senderId,
                                       Map<Integer, ECPoint> X,
                                       Map<Integer, ECPoint> Y,
                                       Map<Integer, ECPoint> A,
                                       ECPoint Xi,
                                       PaillierEncryption.PublicKey pk,
                                       ZKSetup zkSetup,
                                       BigInteger hatN,
                                       BigInteger s,
                                       BigInteger t,
                                       PiPrmProof prmProof,
                                       byte[] rid,
                                       byte[] u) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(BigInteger.valueOf(senderId).toByteArray());
            updatePointMap(md, X);
            updatePointMap(md, Y);
            updatePointMap(md, A);
            md.update(Secp256k1CurveUtils.encodePoint(Xi));
            md.update(pk.n.toByteArray());
            md.update(zkSetup.hatN().toByteArray());
            md.update(zkSetup.h1().toByteArray());
            md.update(zkSetup.h2().toByteArray());
            md.update(hatN.toByteArray());
            md.update(s.toByteArray());
            md.update(t.toByteArray());
            md.update(prmProof.A().toByteArray());
            md.update(prmProof.z().toByteArray());
            md.update(rid);
            md.update(u);
            return HexUtils.bytesToHex(md.digest());
        } catch (Exception e) {
            throw new RuntimeException("Refresh commit failed", e);
        }
    }

    public static BigInteger deriveRefreshMask(String taskId, byte[] rid, int i, int j, ECPoint Yji, BigInteger yij) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(taskId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(rid);
            md.update(BigInteger.valueOf(i).toByteArray());
            md.update(BigInteger.valueOf(j).toByteArray());
            ECPoint shared = Yji.multiply(yij).normalize();
            md.update(Secp256k1CurveUtils.encodePoint(shared));
            return new BigInteger(1, md.digest()).mod(Secp256k1CurveUtils.n());
        } catch (Exception e) {
            throw new RuntimeException("Refresh mask failed", e);
        }
    }

    public static byte[] xorAllRid(CggmpRefreshTask task) {
        byte[] rid = null;
        for (CggmpRefreshTask.RefreshRound2Data d : task.round2Data.values()) {
            if (rid == null) {
                rid = d.rid.clone();
            } else {
                for (int i = 0; i < rid.length; i++) {
                    rid[i] ^= d.rid[i];
                }
            }
        }
        return rid == null ? new byte[0] : rid;
    }

    public static boolean validatePaillierPublicKey(PaillierEncryption.PublicKey publicKey) {
        if (publicKey == null || publicKey.n == null || publicKey.nSquared == null || publicKey.g == null) {
            return false;
        }
        BigInteger q = Secp256k1CurveUtils.n();
        return publicKey.n.compareTo(q.pow(8)) >= 0;
    }

    public static Object maybeDecompressPayload(MessageType type, byte[] bytes) {
        if (type == null || bytes == null || bytes.length == 0) {
            return null;
        }
        return null;
    }

    private static void updatePointMap(MessageDigest md, Map<Integer, ECPoint> map) {
        if (map == null) {
            updateLength(md, 0);
            return;
        }
        List<Integer> keys = new ArrayList<>(map.keySet());
        Collections.sort(keys);
        updateLength(md, keys.size());
        for (int k : keys) {
            updateLength(md, k);
            ECPoint p = map.get(k);
            if (p != null) {
                byte[] enc = p.normalize().getEncoded(true);
                updateLength(md, enc.length);
                md.update(enc);
            } else {
                updateLength(md, 0);
            }
        }
    }

    private static void updateLength(MessageDigest md, int length) {
        md.update((byte) ((length >>> 24) & 0xFF));
        md.update((byte) ((length >>> 16) & 0xFF));
        md.update((byte) ((length >>> 8) & 0xFF));
        md.update((byte) (length & 0xFF));
    }
}
