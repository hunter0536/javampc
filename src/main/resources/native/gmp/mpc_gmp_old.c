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
    if (len <= 0) {
        mpz_set_ui(result, 0);
        return;
    }
    jbyte *bytes = (*env)->GetByteArrayElements(env, array, NULL);
    mpz_import(result, (size_t)len, 1, 1, 1, 0, bytes);
    if ((bytes[0] & 0x80) != 0) {
        mpz_t two_pow;
        mpz_init(two_pow);
        mpz_ui_pow_ui(two_pow, 2, (unsigned long)(len * 8));
        mpz_sub(result, result, two_pow);
        mpz_clear(two_pow);
    }
    (*env)->ReleaseByteArrayElements(env, array, bytes, JNI_ABORT);
}

static int mpz_powm_signed(JNIEnv *env, mpz_t result, const mpz_t base, const mpz_t exp, const mpz_t mod) {
    if (mpz_sgn(exp) < 0) {
        mpz_t inv;
        mpz_t exp_abs;
        mpz_inits(inv, exp_abs, NULL);
        if (mpz_invert(inv, base, mod) == 0) {
            mpz_clears(inv, exp_abs, NULL);
            jclass exception = (*env)->FindClass(env, "java/lang/ArithmeticException");
            (*env)->ThrowNew(env, exception, "BigInteger not invertible");
            return 0;
        }
        mpz_neg(exp_abs, exp);
        mpz_powm(result, inv, exp_abs, mod);
        mpz_clears(inv, exp_abs, NULL);
        return 1;
    }
    mpz_powm(result, base, exp, mod);
    return 1;
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
    
    if (!mpz_powm_signed(env, result, base, exp, mod)) {
        mpz_clears(base, exp, mod, result, NULL);
        return NULL;
    }
    
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
    
    if (!mpz_powm_signed(env, result, base, exp, ctx->mod)) {
        mpz_clears(base, exp, result, NULL);
        return NULL;
    }
    
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
        
        if (!mpz_powm_signed(env, result, base, exp, mod)) {
            mpz_clears(exp, mod, base, result, NULL);
            return NULL;
        }
        
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
        
        if (!mpz_powm_signed(env, result, base, exp, mod)) {
            mpz_clears(mod, base, exp, result, NULL);
            return NULL;
        }
        
        jbyteArray resultBytes = mpz_to_bytes(env, result);
        jobject resultObj = create_biginteger(env, resultBytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, resultObj);
    }
    
    mpz_clears(mod, base, exp, result, NULL);
    return resultArray;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeAffGProofTuple
  (JNIEnv *env, jclass cls, 
   jobject CObj, jobject N0sqObj, jobject N1sqObj,
   jobjectArray alphaObjs, jobjectArray betaObjs,
   jobjectArray rObjs, jobjectArray sObjs) {
    jsize kappa = (*env)->GetArrayLength(env, alphaObjs);
    if (kappa == 0) return NULL;
    
    mpz_t C, N0sq, N1sq;
    mpz_inits(C, N0sq, N1sq, NULL);
    
    jbyteArray CBytes = get_biginteger_bytes(env, CObj);
    jbyteArray N0sqBytes = get_biginteger_bytes(env, N0sqObj);
    jbyteArray N1sqBytes = get_biginteger_bytes(env, N1sqObj);
    
    bytes_to_mpz(env, CBytes, C);
    bytes_to_mpz(env, N0sqBytes, N0sq);
    bytes_to_mpz(env, N1sqBytes, N1sq);
    
    mpz_t ONE_PLUS_N0SQ, ONE_PLUS_N1SQ;
    mpz_inits(ONE_PLUS_N0SQ, ONE_PLUS_N1SQ, NULL);
    mpz_add_ui(ONE_PLUS_N0SQ, N0sq, 1);
    mpz_add_ui(ONE_PLUS_N1SQ, N1sq, 1);
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, kappa * 2, bigIntegerClass, NULL);
    
    mpz_t alpha, beta, r, s, Aj, Bj, tmp1, tmp2;
    mpz_inits(alpha, beta, r, s, Aj, Bj, tmp1, tmp2, NULL);
    
    for (jsize i = 0; i < kappa; i++) {
        jobject alphaObj = (*env)->GetObjectArrayElement(env, alphaObjs, i);
        jobject betaObj = (*env)->GetObjectArrayElement(env, betaObjs, i);
        jobject rObj = (*env)->GetObjectArrayElement(env, rObjs, i);
        jobject sObj = (*env)->GetObjectArrayElement(env, sObjs, i);
        
        jbyteArray alphaBytes = get_biginteger_bytes(env, alphaObj);
        jbyteArray betaBytes = get_biginteger_bytes(env, betaObj);
        jbyteArray rBytes = get_biginteger_bytes(env, rObj);
        jbyteArray sBytes = get_biginteger_bytes(env, sObj);
        
        bytes_to_mpz(env, alphaBytes, alpha);
        bytes_to_mpz(env, betaBytes, beta);
        bytes_to_mpz(env, rBytes, r);
        bytes_to_mpz(env, sBytes, s);
        
        // Aj = C^alpha * (1+N0sq)^beta * r^N0 mod N0sq
        if (!mpz_powm_signed(env, tmp1, C, alpha, N0sq)) {
            mpz_clears(C, N0sq, N1sq, ONE_PLUS_N0SQ, ONE_PLUS_N1SQ, 
                       alpha, beta, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        if (!mpz_powm_signed(env, tmp2, ONE_PLUS_N0SQ, beta, N0sq)) {
            mpz_clears(C, N0sq, N1sq, ONE_PLUS_N0SQ, ONE_PLUS_N1SQ, 
                       alpha, beta, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        mpz_mul(tmp1, tmp1, tmp2);
        mpz_powm(tmp2, r, N0sq, N0sq);
        mpz_mul(Aj, tmp1, tmp2);
        mpz_mod(Aj, Aj, N0sq);
        
        // Bj = (1+N1sq)^beta * s^N1 mod N1sq
        if (!mpz_powm_signed(env, tmp1, ONE_PLUS_N1SQ, beta, N1sq)) {
            mpz_clears(C, N0sq, N1sq, ONE_PLUS_N0SQ, ONE_PLUS_N1SQ, 
                       alpha, beta, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        mpz_powm(tmp2, s, N1sq, N1sq);
        mpz_mul(Bj, tmp1, tmp2);
        mpz_mod(Bj, Bj, N1sq);
        
        jbyteArray AjBytes = mpz_to_bytes(env, Aj);
        jbyteArray BjBytes = mpz_to_bytes(env, Bj);
        
        (*env)->SetObjectArrayElement(env, resultArray, i * 2, create_biginteger(env, AjBytes));
        (*env)->SetObjectArrayElement(env, resultArray, i * 2 + 1, create_biginteger(env, BjBytes));
    }
    
    mpz_clears(C, N0sq, N1sq, ONE_PLUS_N0SQ, ONE_PLUS_N1SQ, 
               alpha, beta, r, s, Aj, Bj, tmp1, tmp2, NULL);
    return resultArray;
}
