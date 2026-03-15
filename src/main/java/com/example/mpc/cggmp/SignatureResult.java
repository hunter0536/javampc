package com.example.mpc.cggmp;

public class SignatureResult {
    private final String r;
    private final String s;
    private final int v;
    private final String groupPublicKey;

    public SignatureResult(String r, String s, int v, String groupPublicKey) {
        this.r = r;
        this.s = s;
        this.v = v;
        this.groupPublicKey = groupPublicKey;
    }

    public String getR() {
        return r;
    }

    public String getS() {
        return s;
    }

    public int getV() {
        return v;
    }

    public String getGroupPublicKey() {
        return groupPublicKey;
    }

    public boolean isValid() {
        return r != null && s != null && v >= 27;
    }

    public String toSignatureString() {
        return r + s + Integer.toHexString(v);
    }
}
