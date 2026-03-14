#include <jni.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

static jclass bigIntegerClass = NULL;
static jmethodID bigIntegerConstructor = NULL;
static jmethodID bigIntegerToByteArray = NULL;
static mpz_t two_pow_table[2048];
static int two_pow_table_initialized = 0;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

static void init_two_pow_table(void) {
    pthread_mutex_lock(&init_mutex);
    if (!two_pow_table_initialized) {
        for (int i = 0; i < 2048; i++) {
            mpz_init(two_pow_table[i]);
            mpz_ui_pow_ui(two_pow_table[i], 2, i);
        }
        two_pow_table_initialized = 1;
    }
    pthread_mutex_unlock(&init_mutex);
}

static void cache_jni_ids(JNIEnv *env) {
    if (bigIntegerClass == NULL) {
        jclass cls = (*env)->FindClass(env, "java/math/BigInteger");
        bigIntegerClass = (*env)->NewGlobalRef(env, cls);
        bigIntegerConstructor = (*env)->GetMethodID(env, bigIntegerClass, "<init>", "([B)V");
        bigIntegerToByteArray = (*env)->GetMethodID(env, bigIntegerClass, "toByteArray", "()[B");
    }
}

static void bytes_to_mpz(JNIEnv *env, jbyteArray array, mpz_t result) {
    jsize len = (*env)->GetArrayLength(env, array);
    if (len <= 0) {
        mpz_set_ui(result, 0);
        return;
    }
    jbyte *bytes = (*env)->GetByteArrayElements(env, array, NULL);
    
    mpz_import(result, (size_t)len, 1, 1, 1, 0, bytes);
    
    if ((bytes[0] & 0x80) != 0 && len * 8 < 2048) {
        mpz_sub(result, result, two_pow_table[len * 8]);
    } else if ((bytes[0] & 0x80) != 0) {
        mpz_t two_pow;
        mpz_init(two_pow);
        mpz_ui_pow_ui(two_pow, 2, (unsigned long)(len * 8));
        mpz_sub(result, result, two_pow);
        mpz_clear(two_pow);
    }
    
    (*env)->ReleaseByteArrayElements(env, array, bytes, JNI_ABORT);
}

static void bytes_to_mpz_direct(jbyte *bytes, jsize len, mpz_t result) {
    if (len <= 0) {
        mpz_set_ui(result, 0);
        return;
    }
    
    mpz_import(result, (size_t)len, 1, 1, 1, 0, bytes);
    
    if ((bytes[0] & 0x80) != 0 && len * 8 < 2048) {
        mpz_sub(result, result, two_pow_table[len * 8]);
    } else if ((bytes[0] & 0x80) != 0) {
        mpz_t two_pow;
        mpz_init(two_pow);
        mpz_ui_pow_ui(two_pow, 2, (unsigned long)(len * 8));
        mpz_sub(result, result, two_pow);
        mpz_clear(two_pow);
    }
}

static int mpz_powm_signed(mpz_t result, const mpz_t base, const mpz_t exp, const mpz_t mod) {
    if (mpz_sgn(exp) < 0) {
        mpz_t inv;
        mpz_t exp_abs;
        mpz_inits(inv, exp_abs, NULL);
        if (mpz_invert(inv, base, mod) == 0) {
            mpz_clears(inv, exp_abs, NULL);
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

static size_t mpz_to_bytes_buffer(mpz_t value, unsigned char *buffer, size_t buffer_size) {
    int is_negative = mpz_sgn(value) < 0;
    
    mpz_t abs_val;
    mpz_init(abs_val);
    mpz_abs(abs_val, value);
    
    size_t count;
    mpz_export(NULL, &count, 1, 1, 1, 0, abs_val);
    
    if (count + 2 > buffer_size) {
        mpz_clear(abs_val);
        return 0;
    }
    
    int needsSignByte = 0;
    size_t result_len = 0;
    
    if (count > 0) {
        mpz_export(buffer + 1, &count, 1, 1, 1, 0, abs_val);
        buffer[0] = 0;
        
        if (buffer[1] >= 0x80) {
            needsSignByte = 1;
        }
        
        if (is_negative) {
            for (size_t i = 0; i < count + 1; i++) {
                buffer[i] = ~buffer[i];
            }
            int carry = 1;
            for (int i = (int)count; i >= 0 && carry; i--) {
                int sum = (unsigned char)buffer[i] + carry;
                buffer[i] = (unsigned char)(sum & 0xFF);
                carry = sum >> 8;
            }
            if (buffer[0] < 0x80) {
                needsSignByte = 0;
            }
        }
        
        result_len = count + needsSignByte;
        if (!needsSignByte) {
            memmove(buffer, buffer + 1, count);
        }
    } else {
        buffer[0] = 0;
        result_len = 1;
    }
    
    mpz_clear(abs_val);
    return result_len;
}

static jbyteArray mpz_to_bytes(JNIEnv *env, mpz_t value) {
    unsigned char temp[4096];
    size_t len = mpz_to_bytes_buffer(value, temp, sizeof(temp));
    
    jbyteArray result = (*env)->NewByteArray(env, (jsize)len);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)len, (jbyte*)temp);
    return result;
}

static jobject create_biginteger(JNIEnv *env, jbyteArray array) {
    cache_jni_ids(env);
    return (*env)->NewObject(env, bigIntegerClass, bigIntegerConstructor, array);
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
    cache_jni_ids(env);
    return (jbyteArray)(*env)->CallObjectMethod(env, obj, bigIntegerToByteArray);
}

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeModPow
  (JNIEnv *env, jclass cls, jobject baseObj, jobject expObj, jobject modObj) {
    if (baseObj == NULL || expObj == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
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
    
    if (!mpz_powm_signed(result, base, exp, mod)) {
        mpz_clears(base, exp, mod, result, NULL);
        jclass exception = (*env)->FindClass(env, "java/lang/ArithmeticException");
        (*env)->ThrowNew(env, exception, "BigInteger not invertible");
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
    
    init_two_pow_table();
    
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

JNIEXPORT jobject JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeModMul
  (JNIEnv *env, jclass cls, jobject aObj, jobject bObj, jobject modObj) {
    if (aObj == NULL || bObj == NULL || modObj == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
    mpz_t a, b, mod, result;
    mpz_inits(a, b, mod, result, NULL);
    
    jbyteArray aBytes = get_biginteger_bytes(env, aObj);
    jbyteArray bBytes = get_biginteger_bytes(env, bObj);
    jbyteArray modBytes = get_biginteger_bytes(env, modObj);
    
    bytes_to_mpz(env, aBytes, a);
    bytes_to_mpz(env, bBytes, b);
    bytes_to_mpz(env, modBytes, mod);

    if (mpz_sgn(mod) <= 0) {
        mpz_clears(a, b, mod, result, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    mpz_mul(result, a, b);
    mpz_mod(result, result, mod);
    
    jbyteArray resultBytes = mpz_to_bytes(env, result);
    jobject resultObj = create_biginteger(env, resultBytes);
    
    mpz_clears(a, b, mod, result, NULL);
    return resultObj;
}

typedef struct {
    jbyte *base_data;
    jsize base_len;
    mpz_t *exp_ptr;
    mpz_t *mod_ptr;
    mpz_t base;
    mpz_t result;
    size_t result_offset;
    size_t result_len;
    int error;
} BatchTask;

typedef struct {
    BatchTask *tasks;
    jsize start;
    jsize end;
    unsigned char *result_pool;
    size_t max_result_size;
} ThreadArg;

static void* batch_modpow_worker(void *arg) {
    ThreadArg *thread_arg = (ThreadArg *)arg;
    BatchTask *tasks = thread_arg->tasks;
    unsigned char *result_pool = thread_arg->result_pool;
    size_t max_result_size = thread_arg->max_result_size;
    
    for (jsize i = thread_arg->start; i < thread_arg->end; i++) {
        mpz_set_ui(tasks[i].base, 0);
        bytes_to_mpz_direct(tasks[i].base_data, tasks[i].base_len, tasks[i].base);
        
        if (!mpz_powm_signed(tasks[i].result, tasks[i].base, *tasks[i].exp_ptr, *tasks[i].mod_ptr)) {
            tasks[i].error = 1;
            continue;
        }
        tasks[i].error = 0;
        
        unsigned char *result_ptr = result_pool + i * max_result_size;
        tasks[i].result_len = mpz_to_bytes_buffer(tasks[i].result, result_ptr, max_result_size);
    }
    
    return NULL;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchModPowOptimized
  (JNIEnv *env, jclass cls, jobjectArray baseBytesArray, jbyteArray expBytes, jbyteArray modBytes) {
    if (baseBytesArray == NULL || expBytes == NULL || modBytes == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
    jsize n = (*env)->GetArrayLength(env, baseBytesArray);
    if (n == 0) {
        jclass byteArrayClass = (*env)->FindClass(env, "[B");
        return (*env)->NewObjectArray(env, 0, byteArrayClass, NULL);
    }
    
    mpz_t exp, mod;
    mpz_inits(exp, mod, NULL);
    
    jbyte *expData = (*env)->GetByteArrayElements(env, expBytes, NULL);
    jsize expLen = (*env)->GetArrayLength(env, expBytes);
    jbyte *modData = (*env)->GetByteArrayElements(env, modBytes, NULL);
    jsize modLen = (*env)->GetArrayLength(env, modBytes);
    
    bytes_to_mpz_direct(expData, expLen, exp);
    bytes_to_mpz_direct(modData, modLen, mod);
    
    (*env)->ReleaseByteArrayElements(env, expBytes, expData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, modBytes, modData, JNI_ABORT);

    if (mpz_sgn(mod) <= 0) {
        mpz_clears(exp, mod, NULL);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    int cpu_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int num_threads;
    if (n < 8) {
        num_threads = 1;
    } else if (n < 32) {
        num_threads = 2;
    } else if (n < 128) {
        num_threads = (cpu_cores >= 4) ? 4 : cpu_cores;
    } else {
        num_threads = (cpu_cores >= 8) ? 8 : cpu_cores;
    }
    if (num_threads > n) num_threads = n;
    
    size_t max_result_size = (size_t)(mpz_sizeinbase(mod, 2) + 7) / 8 + 2;
    unsigned char *result_pool = (unsigned char *)malloc(n * max_result_size);
    
    BatchTask *tasks = (BatchTask *)malloc(n * sizeof(BatchTask));
    if (!tasks || !result_pool) {
        free(result_pool);
        free(tasks);
        mpz_clears(exp, mod, NULL);
        throw_npe(env, "Memory allocation failed");
        return NULL;
    }
    
    for (jsize i = 0; i < n; i++) {
        jbyteArray baseArr = (jbyteArray)(*env)->GetObjectArrayElement(env, baseBytesArray, i);
        jsize len = (*env)->GetArrayLength(env, baseArr);
        tasks[i].base_data = (jbyte *)malloc(len);
        (*env)->GetByteArrayRegion(env, baseArr, 0, len, tasks[i].base_data);
        tasks[i].base_len = len;
        tasks[i].exp_ptr = &exp;
        tasks[i].mod_ptr = &mod;
        mpz_init(tasks[i].base);
        mpz_init(tasks[i].result);
        tasks[i].result_offset = i * max_result_size;
        tasks[i].result_len = 0;
        tasks[i].error = 0;
        (*env)->DeleteLocalRef(env, baseArr);
    }
    
    if (num_threads == 1) {
        ThreadArg arg = {tasks, 0, n, result_pool, max_result_size};
        batch_modpow_worker(&arg);
    } else {
        pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
        ThreadArg *thread_args = (ThreadArg *)malloc(num_threads * sizeof(ThreadArg));
        
        jsize chunk_size = n / num_threads;
        for (int t = 0; t < num_threads; t++) {
            thread_args[t].tasks = tasks;
            thread_args[t].start = t * chunk_size;
            thread_args[t].end = (t == num_threads - 1) ? n : (t + 1) * chunk_size;
            thread_args[t].result_pool = result_pool;
            thread_args[t].max_result_size = max_result_size;
            pthread_create(&threads[t], NULL, batch_modpow_worker, &thread_args[t]);
        }
        
        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }
        
        free(threads);
        free(thread_args);
    }
    
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, byteArrayClass, NULL);
    
    for (jsize i = 0; i < n; i++) {
        if (tasks[i].error) {
            jbyteArray emptyBytes = (*env)->NewByteArray(env, 0);
            (*env)->SetObjectArrayElement(env, resultArray, i, emptyBytes);
            (*env)->DeleteLocalRef(env, emptyBytes);
        } else {
            unsigned char *result_ptr = result_pool + i * max_result_size;
            jbyteArray jbytes = (*env)->NewByteArray(env, (jsize)tasks[i].result_len);
            (*env)->SetByteArrayRegion(env, jbytes, 0, (jsize)tasks[i].result_len, (jbyte*)result_ptr);
            (*env)->SetObjectArrayElement(env, resultArray, i, jbytes);
            (*env)->DeleteLocalRef(env, jbytes);
        }
    }
    
    for (jsize i = 0; i < n; i++) {
        free(tasks[i].base_data);
        mpz_clears(tasks[i].base, tasks[i].result, NULL);
    }
    free(result_pool);
    free(tasks);
    mpz_clears(exp, mod, NULL);
    
    return resultArray;
}

typedef struct {
    jbyte **a_data_array;
    jsize *a_len_array;
    mpz_t *n_ptr;
    int *results;
    jsize start;
    jsize end;
} JacobiBatchArg;

static void* batch_jacobi_worker(void *arg) {
    JacobiBatchArg *ctx = (JacobiBatchArg *)arg;
    
    for (jsize i = ctx->start; i < ctx->end; i++) {
        mpz_t a, a_mod;
        mpz_inits(a, a_mod, NULL);
        bytes_to_mpz_direct(ctx->a_data_array[i], ctx->a_len_array[i], a);
        mpz_mod(a_mod, a, *ctx->n_ptr);
        
        ctx->results[i] = mpz_jacobi(a_mod, *ctx->n_ptr);
        
        mpz_clears(a, a_mod, NULL);
    }
    
    return NULL;
}

JNIEXPORT jint JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeJacobi
  (JNIEnv *env, jclass cls, jbyteArray aBytes, jbyteArray nBytes) {
    if (aBytes == NULL || nBytes == NULL) {
        throw_npe(env, "Null parameter");
        return 0;
    }
    
    init_two_pow_table();
    
    mpz_t a, n, a_mod;
    mpz_inits(a, n, a_mod, NULL);
    
    jbyte *aData = (*env)->GetByteArrayElements(env, aBytes, NULL);
    jsize aLen = (*env)->GetArrayLength(env, aBytes);
    jbyte *nData = (*env)->GetByteArrayElements(env, nBytes, NULL);
    jsize nLen = (*env)->GetArrayLength(env, nBytes);
    
    bytes_to_mpz_direct(aData, aLen, a);
    bytes_to_mpz_direct(nData, nLen, n);
    
    (*env)->ReleaseByteArrayElements(env, aBytes, aData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nBytes, nData, JNI_ABORT);
    
    if (mpz_sgn(n) <= 0 || mpz_even_p(n)) {
        mpz_clears(a, n, a_mod, NULL);
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "n must be positive and odd");
        return 0;
    }
    
    mpz_mod(a_mod, a, n);
    int result = mpz_jacobi(a_mod, n);
    
    mpz_clears(a, n, a_mod, NULL);
    
    return result;
}

JNIEXPORT jintArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchJacobi
  (JNIEnv *env, jclass cls, jobjectArray aBytesArray, jbyteArray nBytes) {
    if (aBytesArray == NULL || nBytes == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
    jsize count = (*env)->GetArrayLength(env, aBytesArray);
    if (count == 0) {
        return (*env)->NewIntArray(env, 0);
    }
    
    mpz_t n;
    mpz_init(n);
    
    jbyte *nData = (*env)->GetByteArrayElements(env, nBytes, NULL);
    jsize nLen = (*env)->GetArrayLength(env, nBytes);
    bytes_to_mpz_direct(nData, nLen, n);
    (*env)->ReleaseByteArrayElements(env, nBytes, nData, JNI_ABORT);
    
    if (mpz_sgn(n) <= 0 || mpz_even_p(n)) {
        mpz_clear(n);
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "n must be positive and odd");
        return NULL;
    }
    
    int *results = (int *)malloc(count * sizeof(int));
    if (!results) {
        mpz_clear(n);
        throw_npe(env, "Memory allocation failed");
        return NULL;
    }
    
    jbyte **a_data_array = (jbyte **)malloc(count * sizeof(jbyte *));
    jsize *a_len_array = (jsize *)malloc(count * sizeof(jsize));
    
    for (jsize i = 0; i < count; i++) {
        jbyteArray aArr = (jbyteArray)(*env)->GetObjectArrayElement(env, aBytesArray, i);
        a_len_array[i] = (*env)->GetArrayLength(env, aArr);
        a_data_array[i] = (jbyte *)malloc(a_len_array[i]);
        (*env)->GetByteArrayRegion(env, aArr, 0, a_len_array[i], a_data_array[i]);
        (*env)->DeleteLocalRef(env, aArr);
    }
    
    int cpu_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int num_threads = (count < 16) ? 1 : (count < 64) ? 2 : (cpu_cores >= 4) ? 4 : cpu_cores;
    if (num_threads > count) num_threads = count;
    
    if (num_threads == 1) {
        JacobiBatchArg arg = {a_data_array, a_len_array, &n, results, 0, count};
        batch_jacobi_worker(&arg);
    } else {
        pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
        JacobiBatchArg *args = (JacobiBatchArg *)malloc(num_threads * sizeof(JacobiBatchArg));
        
        jsize chunk_size = count / num_threads;
        for (int t = 0; t < num_threads; t++) {
            args[t].a_data_array = a_data_array;
            args[t].a_len_array = a_len_array;
            args[t].n_ptr = &n;
            args[t].results = results;
            args[t].start = t * chunk_size;
            args[t].end = (t == num_threads - 1) ? count : (t + 1) * chunk_size;
            pthread_create(&threads[t], NULL, batch_jacobi_worker, &args[t]);
        }
        
        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }
        
        free(threads);
        free(args);
    }
    
    for (jsize i = 0; i < count; i++) {
        free(a_data_array[i]);
    }
    free(a_data_array);
    free(a_len_array);
    
    jintArray resultArray = (*env)->NewIntArray(env, count);
    (*env)->SetIntArrayRegion(env, resultArray, 0, count, results);
    
    free(results);
    mpz_clear(n);
    
    return resultArray;
}

typedef struct {
    jbyte **val_data_array;
    jsize *val_len_array;
    mpz_t *mod_ptr;
    unsigned char *result_pool;
    size_t *result_len_array;
    size_t max_result_size;
    jsize start;
    jsize end;
} BatchModArg;

static void* batch_mod_worker(void *arg) {
    BatchModArg *ctx = (BatchModArg *)arg;
    
    for (jsize i = ctx->start; i < ctx->end; i++) {
        mpz_t val, result;
        mpz_inits(val, result, NULL);
        
        bytes_to_mpz_direct(ctx->val_data_array[i], ctx->val_len_array[i], val);
        mpz_mod(result, val, *ctx->mod_ptr);
        
        unsigned char *result_ptr = ctx->result_pool + i * ctx->max_result_size;
        ctx->result_len_array[i] = mpz_to_bytes_buffer(result, result_ptr, ctx->max_result_size);
        
        mpz_clears(val, result, NULL);
    }
    
    return NULL;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeBatchMod
  (JNIEnv *env, jclass cls, jobjectArray valsBytesArray, jbyteArray modBytes) {
    if (valsBytesArray == NULL || modBytes == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
    jsize n = (*env)->GetArrayLength(env, valsBytesArray);
    if (n == 0) {
        jclass byteArrayClass = (*env)->FindClass(env, "[B");
        return (*env)->NewObjectArray(env, 0, byteArrayClass, NULL);
    }
    
    mpz_t mod;
    mpz_init(mod);
    
    jbyte *modData = (*env)->GetByteArrayElements(env, modBytes, NULL);
    jsize modLen = (*env)->GetArrayLength(env, modBytes);
    bytes_to_mpz_direct(modData, modLen, mod);
    (*env)->ReleaseByteArrayElements(env, modBytes, modData, JNI_ABORT);
    
    if (mpz_sgn(mod) <= 0) {
        mpz_clear(mod);
        throw_arith(env, "Modulus not positive");
        return NULL;
    }
    
    size_t max_result_size = (size_t)(mpz_sizeinbase(mod, 2) + 7) / 8 + 2;
    unsigned char *result_pool = (unsigned char *)malloc(n * max_result_size);
    size_t *result_len_array = (size_t *)malloc(n * sizeof(size_t));
    
    jbyte **val_data_array = (jbyte **)malloc(n * sizeof(jbyte *));
    jsize *val_len_array = (jsize *)malloc(n * sizeof(jsize));
    
    if (!result_pool || !result_len_array || !val_data_array || !val_len_array) {
        free(result_pool);
        free(result_len_array);
        free(val_data_array);
        free(val_len_array);
        mpz_clear(mod);
        throw_npe(env, "Memory allocation failed");
        return NULL;
    }
    
    for (jsize i = 0; i < n; i++) {
        jbyteArray valArr = (jbyteArray)(*env)->GetObjectArrayElement(env, valsBytesArray, i);
        val_len_array[i] = (*env)->GetArrayLength(env, valArr);
        val_data_array[i] = (jbyte *)malloc(val_len_array[i]);
        (*env)->GetByteArrayRegion(env, valArr, 0, val_len_array[i], val_data_array[i]);
        (*env)->DeleteLocalRef(env, valArr);
    }
    
    int cpu_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int num_threads = (n < 16) ? 1 : (n < 64) ? 2 : (cpu_cores >= 4) ? 4 : cpu_cores;
    if (num_threads > n) num_threads = n;
    
    if (num_threads == 1) {
        BatchModArg arg = {val_data_array, val_len_array, &mod, result_pool, result_len_array, max_result_size, 0, n};
        batch_mod_worker(&arg);
    } else {
        pthread_t *threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
        BatchModArg *args = (BatchModArg *)malloc(num_threads * sizeof(BatchModArg));
        
        jsize chunk_size = n / num_threads;
        for (int t = 0; t < num_threads; t++) {
            args[t].val_data_array = val_data_array;
            args[t].val_len_array = val_len_array;
            args[t].mod_ptr = &mod;
            args[t].result_pool = result_pool;
            args[t].result_len_array = result_len_array;
            args[t].max_result_size = max_result_size;
            args[t].start = t * chunk_size;
            args[t].end = (t == num_threads - 1) ? n : (t + 1) * chunk_size;
            pthread_create(&threads[t], NULL, batch_mod_worker, &args[t]);
        }
        
        for (int t = 0; t < num_threads; t++) {
            pthread_join(threads[t], NULL);
        }
        
        free(threads);
        free(args);
    }
    
    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    jobjectArray resultArray = (*env)->NewObjectArray(env, n, byteArrayClass, NULL);
    
    for (jsize i = 0; i < n; i++) {
        unsigned char *result_ptr = result_pool + i * max_result_size;
        jbyteArray jbytes = (*env)->NewByteArray(env, (jsize)result_len_array[i]);
        (*env)->SetByteArrayRegion(env, jbytes, 0, (jsize)result_len_array[i], (jbyte*)result_ptr);
        (*env)->SetObjectArrayElement(env, resultArray, i, jbytes);
        (*env)->DeleteLocalRef(env, jbytes);
    }
    
    for (jsize i = 0; i < n; i++) {
        free(val_data_array[i]);
    }
    free(val_data_array);
    free(val_len_array);
    free(result_pool);
    free(result_len_array);
    mpz_clear(mod);
    
    return resultArray;
}

JNIEXPORT jbyteArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeCrt
  (JNIEnv *env, jclass cls, jbyteArray aBytes, jbyteArray pBytes, jbyteArray bBytes, jbyteArray qBytes, jbyteArray nBytes) {
    if (aBytes == NULL || pBytes == NULL || bBytes == NULL || qBytes == NULL || nBytes == NULL) {
        throw_npe(env, "Null parameter");
        return NULL;
    }
    
    init_two_pow_table();
    
    mpz_t a, p, b, q, n, t, ip, k, x;
    mpz_inits(a, p, b, q, n, t, ip, k, x, NULL);
    
    jbyte *aData = (*env)->GetByteArrayElements(env, aBytes, NULL);
    jsize aLen = (*env)->GetArrayLength(env, aBytes);
    jbyte *pData = (*env)->GetByteArrayElements(env, pBytes, NULL);
    jsize pLen = (*env)->GetArrayLength(env, pBytes);
    jbyte *bData = (*env)->GetByteArrayElements(env, bBytes, NULL);
    jsize bLen = (*env)->GetArrayLength(env, bBytes);
    jbyte *qData = (*env)->GetByteArrayElements(env, qBytes, NULL);
    jsize qLen = (*env)->GetArrayLength(env, qBytes);
    jbyte *nData = (*env)->GetByteArrayElements(env, nBytes, NULL);
    jsize nLen = (*env)->GetArrayLength(env, nBytes);
    
    bytes_to_mpz_direct(aData, aLen, a);
    bytes_to_mpz_direct(pData, pLen, p);
    bytes_to_mpz_direct(bData, bLen, b);
    bytes_to_mpz_direct(qData, qLen, q);
    bytes_to_mpz_direct(nData, nLen, n);
    
    (*env)->ReleaseByteArrayElements(env, aBytes, aData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, pBytes, pData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, bBytes, bData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, qBytes, qData, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nBytes, nData, JNI_ABORT);
    
    mpz_sub(t, b, a);
    mpz_mod(t, t, q);
    
    if (mpz_invert(ip, p, q) == 0) {
        mpz_clears(a, p, b, q, n, t, ip, k, x, NULL);
        throw_arith(env, "p not invertible mod q");
        return NULL;
    }
    
    mpz_mul(k, t, ip);
    mpz_mod(k, k, q);
    
    mpz_mul(x, k, p);
    mpz_add(x, a, x);
    
    if (mpz_sgn(x) < 0 || mpz_cmp(x, n) >= 0) {
        mpz_mod(x, x, n);
    }
    
    unsigned char temp[4096];
    size_t result_len = mpz_to_bytes_buffer(x, temp, sizeof(temp));
    
    jbyteArray resultArray = (*env)->NewByteArray(env, (jsize)result_len);
    (*env)->SetByteArrayRegion(env, resultArray, 0, (jsize)result_len, (jbyte*)temp);
    
    mpz_clears(a, p, b, q, n, t, ip, k, x, NULL);
    
    return resultArray;
}

JNIEXPORT jbyteArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeProbablePrime
  (JNIEnv *env, jclass cls, jint bitLength, jbyteArray seedBytes) {
    if (bitLength <= 0) {
        throw_npe(env, "Invalid bit length");
        return NULL;
    }
    
    init_two_pow_table();
    
    gmp_randstate_t rstate;
    gmp_randinit_mt(rstate);
    
    if (seedBytes != NULL) {
        jbyte *seedData = (*env)->GetByteArrayElements(env, seedBytes, NULL);
        jsize seedLen = (*env)->GetArrayLength(env, seedBytes);
        
        mpz_t seed;
        mpz_init(seed);
        bytes_to_mpz_direct(seedData, seedLen, seed);
        gmp_randseed(rstate, seed);
        
        (*env)->ReleaseByteArrayElements(env, seedBytes, seedData, JNI_ABORT);
        mpz_clear(seed);
    } else {
        gmp_randseed_ui(rstate, (unsigned long)time(NULL));
    }
    
    mpz_t prime, random_base;
    mpz_inits(prime, random_base, NULL);
    
    mpz_urandomb(random_base, rstate, bitLength);
    mpz_setbit(random_base, bitLength - 1);
    mpz_setbit(random_base, 0);
    
    mpz_nextprime(prime, random_base);
    
    int max_attempts = 1000;
    int attempts = 0;
    while (mpz_sizeinbase(prime, 2) < (size_t)bitLength && attempts < max_attempts) {
        mpz_nextprime(prime, prime);
        attempts++;
    }
    
    if (attempts >= max_attempts) {
        mpz_urandomb(random_base, rstate, bitLength);
        mpz_setbit(random_base, bitLength - 1);
        mpz_setbit(random_base, 0);
        mpz_nextprime(prime, random_base);
    }
    
    gmp_randclear(rstate);
    
    unsigned char temp[4096];
    size_t result_len = mpz_to_bytes_buffer(prime, temp, sizeof(temp));
    
    jbyteArray resultArray = (*env)->NewByteArray(env, (jsize)result_len);
    (*env)->SetByteArrayRegion(env, resultArray, 0, (jsize)result_len, (jbyte*)temp);
    
    mpz_clears(prime, random_base, NULL);
    
    return resultArray;
}
