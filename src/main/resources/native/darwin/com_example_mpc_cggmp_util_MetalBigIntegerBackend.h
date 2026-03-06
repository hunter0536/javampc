#include <jni.h>

#ifndef _Included_com_example_mpc_cggmp_util_MetalBigIntegerBackend
#define _Included_com_example_mpc_cggmp_util_MetalBigIntegerBackend

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInit
  (JNIEnv *, jobject);

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeDestroy
  (JNIEnv *, jobject, jlong);

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeIsAvailable
  (JNIEnv *, jobject, jlong);

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModPow
  (JNIEnv *, jobject, jlong, jintArray, jintArray, jintArray, jintArray, jint, jint);

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeComputeAffGProofTuple
  (JNIEnv *, jobject, jlong, jintArray, jintArray, jintArray, jintArray, jintArray, jintArray, jintArray, jintArray, jintArray, jint, jint);

#ifdef __cplusplus
}
#endif

#endif
