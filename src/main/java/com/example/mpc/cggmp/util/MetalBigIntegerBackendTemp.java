package com.example.mpc.cggmp.util;

public class MetalBigIntegerBackendTemp {
    // Native methods
    private native long nativeInit();
    private native long nativeInitWithShaderPath(String shaderPath);
    private native void nativeDestroy(long handle);
    private native boolean nativeIsAvailable(long handle);
    private native void nativeModPow(long handle, int[] bases, int[] exps, int[] mods, int[] results, int numLength, int count);
    private native void nativeComputeAffGProofTuple(long handle, int[] C, int[] N0, int[] N0sq, int[] N1, int[] N1sq,
            int[] alphas, int[] betasForN0, int[] betasForN1, int[] rs, int[] ss,
            int[] Aj, int[] Bj, int numLength, int kappa);
    private native void nativeComputeDecProofTuple(long handle, int[] K, int[] N0, int[] N0sq,
            int[] negAlphas, int[] betas, int[] rs,
            int[] A, int numLength, int kappa);
    private native void nativeModInverse(long handle, int[] values, int[] mods, int[] results, int numLength, int count);
    private native void nativeMultiply(long handle, int[] a, int[] b, int[] results, int numLength, int count);
    private native void nativeBatchModPowDifferentExp(long handle, int[] bases, int[] exps, int[] mods, int[] results, int numLength, int count);
}