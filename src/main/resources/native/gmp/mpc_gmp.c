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
    
    // Java BigInteger.toByteArray() 返回大端序二补码
    // mpz_import 参数: order=1 表示大端序, endian=1 表示每个字内部大端序
    mpz_import(result, (size_t)len, 1, 1, 1, 0, bytes);
    
    // 若最高位为1，按二补码转为负数：value -= 2^(8*len)
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
    // 使用大端序导出，与Java BigInteger.toByteArray()格式一致
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
    
    // Java BigInteger(byte[]) 不接受空数组，这里返回单字节 0
    jbyteArray result = (*env)->NewByteArray(env, 1);
    jbyte zero = 0;
    (*env)->SetByteArrayRegion(env, result, 0, 1, &zero);
    return result;
}

static jobject create_biginteger(JNIEnv *env, jbyteArray array) {
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jmethodID constructor = (*env)->GetMethodID(env, bigIntegerClass, "<init>", "([B)V");
    return (*env)->NewObject(env, bigIntegerClass, constructor, array);
}

static void throw_npe(JNIEnv *env, const char *message) {
    jclass exception = (*env)->FindClass(env, "java/lang/NullPointerException");
    (*env)->ThrowNew(env, exception, message);
}

static void throw_arith(JNIEnv *env, const char *message) {
    jclass exception = (*env)->FindClass(env, "java/lang/ArithmeticException");
    (*env)->ThrowNew(env, exception, message);
}

static jbyteArray get_biginteger_bytes(JNIEnv *env, jobject obj) {
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jmethodID toByteArray = (*env)->GetMethodID(env, bigIntegerClass, "toByteArray", "()[B");
    return (jbyteArray)(*env)->CallObjectMethod(env, obj, toByteArray);
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeModPow
  (JNIEnv *env, jclass cls, jobject baseObj, jobject expObj, jobject modObj) {
    if (baseObj == NULL || expObj == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    mpz_t base, exp, mod, result;
    mpz_inits(base, exp, mod, result, NULL);
    
    jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
    jbyteArray expBytes = get_biginteger_bytes(env, expObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    
    bytes_to_mpz(env, baseBytes, base);
    bytes_to_mpz(env, expBytes, exp);
    bytes_to_mpz(env, modBytes, mod);

    if (mpz_sgn(mod) <= 0) {
        mpz_clears(base, exp, mod, result, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
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
    if (valObj == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    mpz_t val, mod, result;
    mpz_inits(val, mod, result, NULL);
    
    jbyteArray valBytes = get_biginteger_bytes(env, valObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    
    bytes_to_mpz(env, valBytes, val);
    bytes_to_mpz(env, modBytes, mod);

    if (mpz_sgn(mod) <= 0) {
        mpz_clears(val, mod, result, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    if (mpz_invert(result, val, mod) == 0) {
        mpz_clears(val, mod, result, NULL);
        throw_arith(env, "BigInteger not invertible");
        return NULL;
    }
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(val, mod, result, NULL);
    return resultObj;
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeMultiply
  (JNIEnv *env, jclass cls, jobject aObj, jobject bObj) {
    if (aObj == NULL || bObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
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
    if (modObj == NULL) {
        throw_npe(env, "Null parameter");
        return 0;
    }
    MontgomeryContext *ctx = (MontgomeryContext *)malloc(sizeof(MontgomeryContext));
    mpz_init(ctx->mod);
    
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, modBytes, ctx->mod);

    if (mpz_sgn(ctx->mod) <= 0) {
        mpz_clear(ctx->mod);
        free(ctx);
        throw_arith(env, "Modulus not positive");
        return 0;
    }
    
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
    if (baseObj == NULL || expObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
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
    // 检查空指针
    if (baseObjs == NULL || expObj == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    jsize n = (*env)->GetArrayLength(env, baseObjs);
    if (n == 0) {
        jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
        return (*env)->NewObjectArray(env, 0, bigIntegerClass, NULL);
    }
    
    mpz_t exp, mod;
    mpz_inits(exp, mod, NULL);
    
    jbyteArray expBytes = get_biginteger_bytes(env, expObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, expBytes, exp);
    bytes_to_mpz(env, modBytes, mod);

    if (mpz_sgn(mod) <= 0) {
        mpz_clears(exp, mod, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, bigIntegerClass, NULL);
    
    mpz_t base, result;
    mpz_inits(base, result, NULL);
    
    for (jsize i = 0; i < n; i++) {
        jobject baseObj = (*env)->GetObjectArrayElement(env, baseObjs, i);
        
        // 检查元素是否为NULL
        if (baseObj == NULL) {
            throw_npe(env, "Null element in baseObjs array");
            mpz_clears(exp, mod, base, result, NULL);
            return NULL;
        }
        
        jbyteArray baseBytes = get_biginteger_bytes(env, baseObj);
        bytes_to_mpz(env, baseBytes, base);
        
        if (!mpz_powm_signed(env, result, base, exp, mod)) {
            mpz_clears(exp, mod, base, result, NULL);
            return NULL;
        }
        
        jbyteArray resultBytes = mpz_to_bytes(env, result);
        jobject resultObj = create_biginteger(env, resultBytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, resultObj);
        (*env)->DeleteLocalRef(env, baseObj);
        (*env)->DeleteLocalRef(env, resultObj);
    }
    
    mpz_clears(exp, mod, base, result, NULL);
    return resultArray;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchModPowDifferentExp
  (JNIEnv *env, jclass cls, jobjectArray baseObjs, jobjectArray expObjs, jobject modObj) {
    // 检查空指针
    if (baseObjs == NULL || expObjs == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    jsize n = (*env)->GetArrayLength(env, baseObjs);
    if (n == 0) {
        jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
        return (*env)->NewObjectArray(env, 0, bigIntegerClass, NULL);
    }
    
    // 检查数组长度一致性
    jsize expLen = (*env)->GetArrayLength(env, expObjs);
    if (expLen != n) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "baseObjs and expObjs must have same length");
        return NULL;
    }
    
    mpz_t mod;
    mpz_init(mod);
    
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    bytes_to_mpz(env, modBytes, mod);

    if (mpz_sgn(mod) <= 0) {
        mpz_clear(mod);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, bigIntegerClass, NULL);
    
    mpz_t base, exp, result;
    mpz_inits(base, exp, result, NULL);
    
    for (jsize i = 0; i < n; i++) {
        jobject baseObj = (*env)->GetObjectArrayElement(env, baseObjs, i);
        jobject expObj = (*env)->GetObjectArrayElement(env, expObjs, i);
        
        // 检查元素是否为NULL
        if (baseObj == NULL || expObj == NULL) {
            throw_npe(env, "Null element in array");
            mpz_clears(mod, base, exp, result, NULL);
            return NULL;
        }
        
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
        (*env)->DeleteLocalRef(env, baseObj);
        (*env)->DeleteLocalRef(env, expObj);
        (*env)->DeleteLocalRef(env, resultObj);
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
    // 检查空指针
    if (CObj == NULL || onePlusN0Obj == NULL || N0sqObj == NULL || onePlusN1Obj == NULL || N1sqObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    if (alphaObjs == NULL || betaForN0Objs == NULL || betaForN1Objs == NULL || rObjs == NULL || sObjs == NULL) {
        throw_npe(env, "Null array parameter");
        return NULL;
    }
    
    // 检查数组长度一致性
    jsize kappa = (*env)->GetArrayLength(env, alphaObjs);
    if (kappa == 0) {
        jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
        return (*env)->NewObjectArray(env, 0, bigIntegerClass, NULL);
    }
    
    jsize betaForN0Len = (*env)->GetArrayLength(env, betaForN0Objs);
    jsize betaForN1Len = (*env)->GetArrayLength(env, betaForN1Objs);
    jsize rLen = (*env)->GetArrayLength(env, rObjs);
    jsize sLen = (*env)->GetArrayLength(env, sObjs);
    
    if (betaForN0Len != kappa || betaForN1Len != kappa || rLen != kappa || sLen != kappa) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "Array lengths mismatch");
        return NULL;
    }
    
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

    if (mpz_sgn(N0sq) <= 0 || mpz_sgn(N1sq) <= 0) {
        mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    mpz_t N0, N1, one;
    mpz_inits(N0, N1, one, NULL);
    mpz_set_ui(one, 1);
    
    // 从onePlusN0和onePlusN1计算N0和N1
    // N0 = onePlusN0 - 1
    mpz_sub(N0, onePlusN0, one);
    // N1 = onePlusN1 - 1
    mpz_sub(N1, onePlusN1, one);
    
    mpz_clear(one);
    if (mpz_sgn(N0) < 0 || mpz_sgn(N1) < 0) {
        mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1, NULL);
        throw_arith(env, "Exponent not non-negative");
        return NULL;
    }
    
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
        
        // 检查元素是否为NULL
        if (alphaObj == NULL || betaForN0Obj == NULL || betaForN1Obj == NULL || rObj == NULL || sObj == NULL) {
            throw_npe(env, "Null element in array");
            mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1, alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        
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
        // 参照Java代码中的公式：GpuBigInteger.java:302-305
        if (!mpz_powm_signed(env, tmp1, C, alpha, N0sq)) {
            mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1, alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        if (!mpz_powm_signed(env, tmp2, onePlusN0, betaForN0, N0sq)) {
            mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1, alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        mpz_mul(tmp1, tmp1, tmp2);
        mpz_powm(tmp2, r, N0, N0sq);
        mpz_mul(Aj, tmp1, tmp2);
        mpz_mod(Aj, Aj, N0sq);
        
        // Bj = (1+N1)^betaForN1 * s^N1 mod N1sq
        // 参照Java代码中的公式：GpuBigInteger.java:307-309
        if (!mpz_powm_signed(env, tmp1, onePlusN1, betaForN1, N1sq)) {
            mpz_clears(C, onePlusN0, N0sq, onePlusN1, N1sq, N0, N1, alpha, betaForN0, betaForN1, r, s, Aj, Bj, tmp1, tmp2, NULL);
            return NULL;
        }
        mpz_powm(tmp2, s, N1, N1sq);
        mpz_mul(Bj, tmp1, tmp2);
        mpz_mod(Bj, Bj, N1sq);
        
        jbyteArray AjBytes = mpz_to_bytes(env, Aj);
        jbyteArray BjBytes = mpz_to_bytes(env, Bj);
        
        jobject AjObj = create_biginteger(env, AjBytes);
        jobject BjObj = create_biginteger(env, BjBytes);
        (*env)->SetObjectArrayElement(env, resultArray, i * 2, AjObj);
        (*env)->SetObjectArrayElement(env, resultArray, i * 2 + 1, BjObj);
        (*env)->DeleteLocalRef(env, alphaObj);
        (*env)->DeleteLocalRef(env, betaForN0Obj);
        (*env)->DeleteLocalRef(env, betaForN1Obj);
        (*env)->DeleteLocalRef(env, rObj);
        (*env)->DeleteLocalRef(env, sObj);
        (*env)->DeleteLocalRef(env, AjObj);
        (*env)->DeleteLocalRef(env, BjObj);
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
    // 检查空指针
    if (KObj == NULL || N0Obj == NULL || N0sqObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    if (alphaObjs == NULL || betaObjs == NULL || rObjs == NULL) {
        throw_npe(env, "Null array parameter");
        return NULL;
    }
    
    // 检查数组长度一致性
    jsize kappa = (*env)->GetArrayLength(env, alphaObjs);
    if (kappa == 0) {
        jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
        return (*env)->NewObjectArray(env, 0, bigIntegerClass, NULL);
    }
    
    jsize betaLen = (*env)->GetArrayLength(env, betaObjs);
    jsize rLen = (*env)->GetArrayLength(env, rObjs);
    
    if (betaLen != kappa || rLen != kappa) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "Array lengths mismatch");
        return NULL;
    }
    
    mpz_t K, N0, N0sq;
    mpz_inits(K, N0, N0sq, NULL);
    
    jbyteArray KBytes = get_biginteger_bytes(env, KObj);
    jbyteArray N0Bytes = get_biginteger_bytes(env, N0Obj);
    jbyteArray N0sqBytes = get_biginteger_bytes(env, N0sqObj);
    
    bytes_to_mpz(env, KBytes, K);
    bytes_to_mpz(env, N0Bytes, N0);
    bytes_to_mpz(env, N0sqBytes, N0sq);

    if (mpz_sgn(N0sq) <= 0) {
        mpz_clears(K, N0, N0sq, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    mpz_t ONE_PLUS_N0;
    mpz_init(ONE_PLUS_N0);
    mpz_add_ui(ONE_PLUS_N0, N0, 1);
    if (mpz_sgn(N0) < 0) {
        mpz_clears(K, N0, N0sq, ONE_PLUS_N0, NULL);
        throw_arith(env, "Exponent not non-negative");
        return NULL;
    }
    
    jclass bigIntegerClass = (*env)->FindClass(env, "java/math/BigInteger");
    jobjectArray resultArray = (*env)->NewObjectArray(env, kappa, bigIntegerClass, NULL);
    
    mpz_t alpha, beta, r, A, tmp1, tmp2, neg_alpha;
    mpz_inits(alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
    
    for (jsize i = 0; i < kappa; i++) {
        jobject alphaObj = (*env)->GetObjectArrayElement(env, alphaObjs, i);
        jobject betaObj = (*env)->GetObjectArrayElement(env, betaObjs, i);
        jobject rObj = (*env)->GetObjectArrayElement(env, rObjs, i);
        
        // 检查元素是否为NULL
        if (alphaObj == NULL || betaObj == NULL || rObj == NULL) {
            throw_npe(env, "Null element in array");
            mpz_clears(K, N0, N0sq, ONE_PLUS_N0, alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
            return NULL;
        }
        
        jbyteArray alphaBytes = get_biginteger_bytes(env, alphaObj);
        jbyteArray betaBytes = get_biginteger_bytes(env, betaObj);
        jbyteArray rBytes = get_biginteger_bytes(env, rObj);
        
        bytes_to_mpz(env, alphaBytes, alpha);
        bytes_to_mpz(env, betaBytes, beta);
        bytes_to_mpz(env, rBytes, r);
        
        // A = K^(-alpha) * (1+N0)^beta * r^N0 mod N0sq
        mpz_neg(neg_alpha, alpha);
        if (!mpz_powm_signed(env, tmp1, K, neg_alpha, N0sq)) {
            mpz_clears(K, N0, N0sq, ONE_PLUS_N0, alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
            return NULL;
        }
        if (!mpz_powm_signed(env, tmp2, ONE_PLUS_N0, beta, N0sq)) {
            mpz_clears(K, N0, N0sq, ONE_PLUS_N0, alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
            return NULL;
        }
        mpz_mul(tmp1, tmp1, tmp2);
        mpz_powm(tmp2, r, N0, N0sq);
        mpz_mul(A, tmp1, tmp2);
        mpz_mod(A, A, N0sq);
        
        jbyteArray ABytes = mpz_to_bytes(env, A);
        jobject AObj = create_biginteger(env, ABytes);
        (*env)->SetObjectArrayElement(env, resultArray, i, AObj);
        (*env)->DeleteLocalRef(env, alphaObj);
        (*env)->DeleteLocalRef(env, betaObj);
        (*env)->DeleteLocalRef(env, rObj);
        (*env)->DeleteLocalRef(env, AObj);
    }
    
    mpz_clears(K, N0, N0sq, ONE_PLUS_N0, 
               alpha, beta, r, A, tmp1, tmp2, neg_alpha, NULL);
    return resultArray;
}
