package com.example.mpc.common.crypto;

import java.math.BigInteger;

public class DerUtils {

    public static byte[] encodeEcdsaSignature(BigInteger r, BigInteger s) {
        byte[] rBytes = toUnsignedBytes(r);
        byte[] sBytes = toUnsignedBytes(s);

        int len = 2 + rBytes.length + 2 + sBytes.length;
        byte[] der = new byte[2 + len];
        int pos = 0;
        der[pos++] = 0x30;
        der[pos++] = (byte) len;
        der[pos++] = 0x02;
        der[pos++] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, der, pos, rBytes.length);
        pos += rBytes.length;
        der[pos++] = 0x02;
        der[pos++] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, der, pos, sBytes.length);
        return der;
    }

    public static BigInteger[] decodeEcdsaSignature(byte[] der) throws Exception {
        int pos = 0;
        if (der[pos++] != 0x30) {
            throw new Exception("Invalid DER encoding: expected SEQUENCE");
        }
        int len = der[pos++] & 0xFF;
        if (len > der.length - pos) {
            throw new Exception("Invalid DER encoding: length too long");
        }

        if (der[pos++] != 0x02) {
            throw new Exception("Invalid DER encoding: expected INTEGER for r");
        }
        int rLen = der[pos++] & 0xFF;
        byte[] rBytes = new byte[rLen];
        System.arraycopy(der, pos, rBytes, 0, rLen);
        pos += rLen;
        BigInteger r = new BigInteger(1, rBytes);

        if (der[pos++] != 0x02) {
            throw new Exception("Invalid DER encoding: expected INTEGER for s");
        }
        int sLen = der[pos++] & 0xFF;
        byte[] sBytes = new byte[sLen];
        System.arraycopy(der, pos, sBytes, 0, sLen);
        BigInteger s = new BigInteger(1, sBytes);

        return new BigInteger[]{r, s};
    }

    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        if ((bytes[0] & 0x80) != 0) {
            byte[] prefixed = new byte[bytes.length + 1];
            prefixed[0] = 0x00;
            System.arraycopy(bytes, 0, prefixed, 1, bytes.length);
            bytes = prefixed;
        }
        return bytes;
    }
}
