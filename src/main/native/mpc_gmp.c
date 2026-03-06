#include <jni.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    mpz_t mod;
    mpz_t r2;
    mpz_t n_prime;
    mp_limb_t n0_inv;
    int bits;
} MontgomeryContext;

typedef struct {
    mpz_t value;
} NativeBigInt;

static void bytes_to_mpz(JNIEnv *env, jbyteArray array, mpz_t result) {
    jsize len = (*env)->GetArrayLength(env, array);
    jbyte *bytes = (*env)->GetByteArrayElements(env, array, NULL);
    mpz_import(result, len, 1, 1, 1, 0, bytes);
    (*env)->ReleaseByteArrayElements(env, array, bytes, JNI_ABORT);
}

static jbyteArray mpz_to_bytes(JNIEnv *env, mpz_t value) {
    size_t count;
    mpz_export(NULL, &count, 1, 1, 1, 0, value);
    
    int needsSignByte = 0;
    if (count > 0) {
        unsigned char *bytes = (unsigned char *)malloc(count);
        mpz_export(bytes, &count, 1, 1, 1, 0, value);
        
        if (bytes[0] >= 0x80) {
            needsSignByte = 1;
        }
        
        jbyteArray result = (*env)->NewByteArray(env, (jsize)(count + needsSignByte));
        jbyte *outBytes = (*env)->GetByteArrayElements(env, result, NULL);
        
        if (needsSignByte) {
            outBytes[0] = 0;
            memcpy(outBytes + 1, bytes, count);
        } else {
            memcpy(outBytes, bytes, count);
        }
        
        (*env)->ReleaseByteArrayElements(env, result, outBytes, 0);
        free(bytes);
        return result;
    }
    
    return (*env)->NewByteArray(env, 0);
}

static jobject create_biginteger(JNIEnv *env, jbyteArray array) {
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jmethodID constructor = (*env)->GetMethodID(env, bigIntegerClass, "<init>", "([B)V");
    return (*env)->NewObject(env, bigIntegerClass, constructor, array);
}

static jbyteArray get_biginteger_bytes(JNIEnv *env, jobject obj) {
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jmethodID toByteArray = (*env)->GetMethodID(env, bigIntegerClass, "toByteArray", "()[B");
    return (jbyteArray)(*env)->CallObjectMethod(env, obj, toByteArray);
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeModPow
  (JNIEnv *env, jclass cls, jobject baseObj, jobject expObj, jobject modObj) {
    mpz_t base, exp, mod, result;
    mpz_inits(base, exp, mod, result, NULL);
    
    jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
    jbyteArray expBytes = get_biginteger_bytes(env, expObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    
    bytes_to_mpz(env, baseBytes, base);
    bytes_to_mpz(env, expBytes, exp);
    bytes_to_mpz(env, modBytes, mod);
    
    mpz_powm(result, base, exp, mod);
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(base, exp, mod, result, NULL);
    return resultObj;
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeModInverse
  (JNIEnv *env, jclass cls, jobject valObj, jobject modObj) {
    mpz_t val, mod, result;
    mpz_inits(val, mod, result, NULL);
    
    jbyteArray valBytes = get_biginteger_bytes(env, valObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    
    bytes_to_mpz(env, valBytes, val);
    bytes_to_mpz(env, modBytes, mod);
    
    if (mpz_invert(result, val, mod) == 0) {
        mpz_clears(val, mod, result, NULL);
        jclass exception = (*env)->FindClass(env, "java/lang/ArithmeticException");
        (*env)->ThrowNew(env, exception, "BigInteger not invertible");
        return NULL;
    }
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(val, mod, result, NULL);
    return resultObj;
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeMultiply
  (JNIEnv *env, jclass cls, jobject aObj, jobject bObj) {
    mpz_t a, b, result;
    mpz_inits(a, b, result, NULL);
    
    jbyteArray aBytes = get_biginteger_bytes(env, aObj);
    jbyteArray bBytes = get_biginteger_bytes(env, bObj);
    
    bytes_to_mpz(env, aBytes, a);
    bytes_to_mpz(env, bBytes, b);
    
    mpz_mul(result, a, b);
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(a, b, result, NULL);
    return resultObj;
}

JNIEXPORT jlong JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_00024NativeModPowContext_initMontgomeryContext
  (JNIEnv *env, jobject thisObj, jobject modObj) {
    MontgomeryContext *ctx = (MontgomeryContext *)malloc(sizeof(MontgomeryContext));
    mpz_init(ctx->mod);
    
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, modBytes, ctx->mod);
    
    ctx->bits = mpz_sizeinbase(ctx->mod, 2);
    
    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_00024NativeModPowContext_freeMontgomeryContext
  (JNIEnv *env, jobject thisObj, jlong ptr) {
    MontgomeryContext *ctx = (MontgomeryContext *)ptr;
    if (ctx) {
        mpz_clear(ctx->mod);
        free(ctx);
    }
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_00024NativeModPowContext_nativeMontgomeryModPow
  (JNIEnv *env, jobject thisObj, jlong ptr, jobject baseObj, jobject expObj) {
    MontgomeryContext *ctx = (MontgomeryContext *)ptr;
    if (!ctx) return NULL;
    
    mpz_t base, exp, result;
    mpz_inits(base, exp, result, NULL);
    
    jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
    jbyteArray expBytes = get_biginteger_bytes(env, expObj);
    
    bytes_to_mpz(env, baseBytes, base);
    bytes_to_mpz(env, expBytes, exp);
    
    mpz_powm(result, base, exp, ctx->mod);
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(base, exp, result, NULL);
    return resultObj;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchModPow
  (JNIEnv *env, jclass cls, jobjectArray baseObjs, jobject expObj, jobject modObj) {
    jsize n = (*env)->GetArrayLength(env, baseObjs);
    if (n == 0) return NULL;
    
    mpz_t exp, mod;
    mpz_inits(exp, mod, NULL);
    
    jbyteArray expBytes = get_biginteger_bytes(env, expObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, expBytes, exp);
    bytes_to_mpz(env, modBytes, mod);
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, bigIntegerClass, NULL);
    
    mpz_t base, result;
    mpz_inits(base, result, NULL);
    
    for (jsize i = 0; i < n; i++) {
        jobject baseObj = (*env)->GetObjectArrayElement(env, baseObjs, i);
        jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
        bytes_to_mpz(env, baseBytes, base);
        
        mpz_powm(result, base, exp, mod);
        
        jbyteArray resultBytes = mpz_to_bytes(env, result);
        jobject resultObj = create_biginteger(env, resultBytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, resultObj);
    }
    
    mpz_clears(exp, mod, base, result, NULL);
    return resultArray;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchModPowDifferentExp
  (JNIEnv *env, jclass cls, jobjectArray baseObjs, jobjectArray expObjs, jobject modObj) {
    jsize n = (*env)->GetArrayLength(env, baseObjs);
    if (n == 0) return NULL;
    
    mpz_t mod;
    mpz_init(mod);
    
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, modBytes, mod);
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, bigIntegerClass, NULL);
    
    mpz_t base, exp, result;
    mpz_inits(base, exp, result, NULL);
    
    for (jsize i = 0; i < n; i++) {
        jobject baseObj = (*env)->GetObjectArrayElement(env, baseObjs, i);
        jobject expObj = (*env)->GetObjectArrayElement(env, expObjs, i);
        
        jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
        jbyteArray expBytes = get_biginteger_bytes(env, expObj);
        
        bytes_to_mpz(env, baseBytes, base);
        bytes_to_mpz(env, expBytes, exp);
        
        mpz_powm(result, base, exp, mod);
        
        jbyteArray resultBytes = mpz_to_bytes(env, result);
        jobject resultObj = create_biginteger(env, resultBytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, resultObj);
    }
    
    mpz_clears(mod, base, exp, result, NULL);
    return resultArray;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeAffGProofTuple
  (JNIEnv *env, jclass cls, 
   jobject CObj, jobject onePlusN0Obj, jobject N0sqObj, 
   jobject onePlusN1Obj, jobject N1sqObj,
   jobjectArray alphaObjs, jobjectArray betaForN0Objs, 
   jobjectArray betaForN1Objs, jobjectArray rObjs, jobjectArray sObjs) {
    jsize kappa = (*env)->GetArrayLength(env, alphaObjs);
    if (kappa == 0) return NULL;
    
    mpz_t C, onePlusN0, N0sq, onePlusN1, N1sq;
    mpz_inits(C, onePlusN0, N0sq, onePlusN1, N1sq, NULL);
    
    jbyteArray CBytes = get_biginteger_bytes(env, CObj);
    jbyteArray onePlusN0Bytes = get_biginteger_bytes(env, onePlusN0Obj);
    jbyteArray N0sqBytes = get_biginteger_bytes(env, N0sqObj);
    jbyteArray onePlusN1Bytes = get_biginteger_bytes(env, onePlusN1Obj);
    jbyteArray N1sqBytes = get_biginteger_bytes(env, N1sqObj);
    
    bytes_to_mpz(env, CBytes, C);
    bytes_to_mpz(env, onePlusN0Bytes, onePlusN0);
    bytes_to_mpz(env, N0sqBytes, N0sq);
    bytes_to_mpz(env, onePlusN1Bytes, onePlusN1);
    bytes_to_mpz(env, N1sqBytes, N1sq);
    
    mpz_t N0, N1;
    mpz_inits(N0, N1, NULL);
    mpz_sqrt(N0, N0sq);
    mpz_sqrt(N1, N1sq);
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, kappa * 2, bigIntegerClass, NULL);
    
    mpz_t alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2;
    mpz_inits(alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
    
    for (jsize i = 0; i < kappa; i++) {
        jobject alphaObj = (*env)->GetObjectArrayElement(env, alphaObjs, i);
        jobject betaForN0Obj = (*env)->GetObjectArrayElement(env, betaForN0Objs, i);
        jobject betaForN1Obj = (*env)->GetObjectArrayElement(env, betaForN1Objs, i);
        jobject rObj = (*env)->GetObjectArrayElement(env, rObjs, i);
        jobject sObj = (*env)->GetObjectArrayElement(env, sObjs, i);
        
        jbyteArray alphaBytes = get_biginteger_bytes(env, alphaObj);
        jbyteArray betaForN0Bytes = get_biginteger_bytes(env, betaForN0Obj);
        jbyteArray betaForN1Bytes = get_biginteger_bytes(env, betaForN1Obj);
        jbyteArray rBytes = get_biginteger_bytes(env, rObj);
        jbyteArray sBytes = get_biginteger_bytes(env, sObj);
        
        bytes_to_mpz(env, alphaBytes, alpha);
        bytes_to_mpz(env, betaForN0Bytes, betaForN0);
        bytes_to_mpz(env, betaForN1Bytes, betaForN1);
        bytes_to_mpz(env, rBytes, r);
        bytes_to_mpz(env, sBytes, s);
        
        // Aj = C^alpha * (1+N0)^betaForN0 * r^N0 mod N0sq
        mpz_powm(tmp1, C, alpha, N0sq);
        mpz_powm(tmp2, onePlusN0, betaForN0, N0sq);
        mpz_mul(tmp1, tmp1, tmp2);
        mpz_powm(tmp2, r, N0, N0sq);
        mpz_mul(Aj, tmp1, tmp2);
        mpz_mod(Aj, Aj, N0sq);
        
        // Bj = (1+N1)^betaForN1 * s^N1 mod N1sq
        mpz_powm(tmp1, onePlusN1, betaForN1, N1sq);
        mpz_powm(tmp2, s, N1, N1sq);
        mpz_mul(Bj, tmp1, tmp2);
        mpz_mod(Bj, Bj, N1sq);
        
        jbyteArray AjBytes = mpz_to_bytes(env, Aj);
        jbyteArray BjBytes = mpz_to_bytes(env, Bj);
        
        (*env)->SetObjectArrayElement(env, resultArray, i * 2, create_biginteger(env, AjBytes));
        (*env)->SetObjectArrayElement(env, resultArray, i * 2 + 1, create_biginteger(env, BjBytes));
    }
    
    mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1,
               alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
    return resultArray;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeDecProofTuple
  (JNIEnv *env, jclass cls, 
   jobject KObj, jobject N0Obj, jobject N0sqObj,
   jobjectArray alphaObjs, jobjectArray betaObjs,
   jobjectArray rObjs) {
    jsize kappa = (*env)->GetArrayLength(env, alphaObjs);
    if (kappa == 0) return NULL;
    
    mpz_t K, N0, N0sq;
    mpz_inits(K, N0, N0sq, NULL);
    
    jbyteArray KBytes = get_biginteger_bytes(env, KObj);
    jbyteArray N0Bytes = get_biginteger_bytes(env, N0Obj);
    jbyteArray N0sqBytes = get_biginteger_bytes(env, N0sqObj);
    
    bytes_to_mpz(env, KBytes, K);
    bytes_to_mpz(env, N0Bytes, N0);
    bytes_to_mpz(env, N0sqBytes, N0sq);
    
    mpz_t ONE_PLUS_N0;
    mpz_init(ONE_PLUS_N0);
    mpz_add_ui(ONE_PLUS_N0, N0, 1);
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, kappa, bigIntegerClass, NULL);
    
    mpz_t alpha, beta, r, A, tmp1, tmp2, neg_alpha;
    mpz_inits(alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
    
    for (jsize i = 0; i < kappa; i++) {
        jobject alphaObj = (*env)->GetObjectArrayElement(env, alphaObjs, i);
        jobject betaObj = (*env)->GetObjectArrayElement(env, betaObjs, i);
        jobject rObj = (*env)->GetObjectArrayElement(env, rObjs, i);
        
        jbyteArray alphaBytes = get_biginteger_bytes(env, alphaObj);
        jbyteArray betaBytes = get_biginteger_bytes(env, betaObj);
        jbyteArray rBytes = get_biginteger_bytes(env, rObj);
        
        bytes_to_mpz(env, alphaBytes, alpha);
        bytes_to_mpz(env, betaBytes, beta);
        bytes_to_mpz(env, rBytes, r);
        
        // A = K^(-alpha) * (1+N0)^beta * r^N0 mod N0sq
        mpz_neg(neg_alpha, alpha);
        mpz_powm(tmp1, K, neg_alpha, N0sq);
        mpz_powm(tmp2, ONE_PLUS_N0, beta, N0sq);
        mpz_mul(tmp1, tmp1, tmp2);
        mpz_powm(tmp2, r, N0, N0sq);
        mpz_mul(A, tmp1, tmp2);
        mpz_mod(A, A, N0sq);
        
        jbyteArray ABytes = mpz_to_bytes(env, A);
        jobject AObj = create_biginteger(env, ABytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, AObj);
    }
    
    mpz_clears(K, N0, N0sq, ONE_PLUS_N0, 
               alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
    return resultArray;
}
