#include <jni.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#ifdef __APPLE__
#include <dispatch/dispatch.h>
#define USE_GCD 1
#else
#define USE_GCD 0
#endif

static jclass bigIntegerClass = NULL;
static jmethodID bigIntegerConstructor = NULL;
static jmethodID bigIntegerToByteArray = NULL;
static mpz_t two_pow_table[2048];
static pthread_once_t two_pow_once = PTHREAD_ONCE_INIT;
static pthread_once_t jni_ids_once = PTHREAD_ONCE_INIT;
static JNIEnv *jni_env_for_once = NULL;
static pthread_mutex_t jni_ids_mutex = PTHREAD_MUTEX_INITIALIZER;
static void throw_npe(JNIEnv *env, const char *message);

// ==================== 预分配 mpz_t 池 ====================
#define MAX_THREADS 16
#define CACHE_LINE_SIZE 64

// 预分配的 mpz_t 池（每个线程一组，避免 False Sharing）
typedef struct {
    mpz_t z, zP0, w, A, zP1, lam, B, t1, t2, t3, lv, rv;
    char padding[CACHE_LINE_SIZE];
} MpzPool;

static MpzPool mpz_pools[MAX_THREADS];
static int mpz_pools_initialized = 0;
static pthread_mutex_t pool_init_mutex = PTHREAD_MUTEX_INITIALIZER;

// 初始化预分配的 mpz_t 池
static void init_mpz_pools(void) {
    pthread_mutex_lock(&pool_init_mutex);
    if (mpz_pools_initialized) {
        pthread_mutex_unlock(&pool_init_mutex);
        return;
    }
    for (int i = 0; i < MAX_THREADS; i++) {
        mpz_inits(mpz_pools[i].z, mpz_pools[i].zP0, mpz_pools[i].w, mpz_pools[i].A,
                  mpz_pools[i].zP1, mpz_pools[i].lam, mpz_pools[i].B,
                  mpz_pools[i].t1, mpz_pools[i].t2, mpz_pools[i].t3,
                  mpz_pools[i].lv, mpz_pools[i].rv, NULL);
    }
    mpz_pools_initialized = 1;
    pthread_mutex_unlock(&pool_init_mutex);
}

// 程序启动时初始化
__attribute__((constructor))
static void init_native_lib(void) {
    init_mpz_pools();
}

// 程序退出时清理
__attribute__((destructor))
static void cleanup_native_lib(void) {
    if (mpz_pools_initialized) {
        for (int i = 0; i < MAX_THREADS; i++) {
            mpz_clears(mpz_pools[i].z, mpz_pools[i].zP0, mpz_pools[i].w, mpz_pools[i].A,
                      mpz_pools[i].zP1, mpz_pools[i].lam, mpz_pools[i].B,
                      mpz_pools[i].t1, mpz_pools[i].t2, mpz_pools[i].t3,
                      mpz_pools[i].lv, mpz_pools[i].rv, NULL);
        }
    }
}

// 获取当前线程的 mpz_t 池
static MpzPool* get_mpz_pool(int thread_id) {
    if (thread_id >= 0 && thread_id < MAX_THREADS && mpz_pools_initialized) {
        return &mpz_pools[thread_id];
    }
    return NULL;
}

static void init_two_pow_table_once(void) {
    for (int i = 0; i < 2048; i++) {
        mpz_init(two_pow_table[i]);
        mpz_ui_pow_ui(two_pow_table[i], 2, i);
    }
}

static void init_two_pow_table(void) {
    pthread_once(&two_pow_once, init_two_pow_table_once);
}

static void cache_jni_ids_once(void) {
    if (jni_env_for_once == NULL) return;
    jclass cls = (*jni_env_for_once)->FindClass(jni_env_for_once, "java/math/BigInteger");
    if (cls == NULL) return;
    bigIntegerClass = (*jni_env_for_once)->NewGlobalRef(jni_env_for_once, cls);
    (*jni_env_for_once)->DeleteLocalRef(jni_env_for_once, cls);
    if (bigIntegerClass == NULL) return;
    bigIntegerConstructor = (*jni_env_for_once)->GetMethodID(jni_env_for_once, bigIntegerClass, "<init>", "([B)V");
    bigIntegerToByteArray = (*jni_env_for_once)->GetMethodID(jni_env_for_once, bigIntegerClass, "toByteArray", "()[B");
}

static void cache_jni_ids(JNIEnv *env) {
    if (bigIntegerClass != NULL) return;
    pthread_mutex_lock(&jni_ids_mutex);
    if (jni_env_for_once == NULL) {
        jni_env_for_once = env;
    }
    pthread_mutex_unlock(&jni_ids_mutex);
    pthread_once(&jni_ids_once, cache_jni_ids_once);
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
    mpz_t abs_val;
    mpz_init(abs_val);
    mpz_abs(abs_val, value);
    size_t bits = mpz_sizeinbase(abs_val, 2);
    mpz_clear(abs_val);
    
    size_t bytes = (bits + 7) / 8;
    if (bytes == 0) bytes = 1;
    size_t buffer_size = bytes + 2;
    
    unsigned char *temp = (unsigned char *)malloc(buffer_size);
    if (!temp) {
        throw_npe(env, "Memory allocation failed");
        return NULL;
    }
    
    size_t len = mpz_to_bytes_buffer(value, temp, buffer_size);
    if (len == 0) {
        free(temp);
        throw_npe(env, "Result too large");
        return NULL;
    }
    
    jbyteArray result = (*env)->NewByteArray(env, (jsize)len);
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)len, (jbyte*)temp);
    free(temp);
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
        if (tasks[i].result_len == 0) {
            tasks[i].error = 1;
        }
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
    
    size_t base_pool_size = 0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray baseArr = (jbyteArray)(*env)->GetObjectArrayElement(env, baseBytesArray, i);
        jsize len = (*env)->GetArrayLength(env, baseArr);
        tasks[i].base_len = len;
        if (len > 0) {
            if (base_pool_size + (size_t)len < base_pool_size) {
                (*env)->DeleteLocalRef(env, baseArr);
                free(result_pool);
                free(tasks);
                mpz_clears(exp, mod, NULL);
                throw_npe(env, "Memory allocation failed");
                return NULL;
            }
            base_pool_size += (size_t)len;
        }
        (*env)->DeleteLocalRef(env, baseArr);
    }
    
    jbyte *base_pool = NULL;
    if (base_pool_size > 0) {
        base_pool = (jbyte *)malloc(base_pool_size);
        if (!base_pool) {
            free(result_pool);
            free(tasks);
            mpz_clears(exp, mod, NULL);
            throw_npe(env, "Memory allocation failed");
            return NULL;
        }
    }
    
    size_t base_offset = 0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray baseArr = (jbyteArray)(*env)->GetObjectArrayElement(env, baseBytesArray, i);
        jsize len = tasks[i].base_len;
        if (len > 0) {
            (*env)->GetByteArrayRegion(env, baseArr, 0, len, base_pool + base_offset);
            tasks[i].base_data = base_pool + base_offset;
            base_offset += (size_t)len;
        } else {
            tasks[i].base_data = NULL;
        }
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
        if (!threads || !thread_args) {
            free(threads);
            free(thread_args);
            ThreadArg arg = {tasks, 0, n, result_pool, max_result_size};
            batch_modpow_worker(&arg);
        } else {
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
        mpz_clears(tasks[i].base, tasks[i].result, NULL);
    }
    free(base_pool);
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
    
    mpz_t a, a_mod;
    mpz_inits(a, a_mod, NULL);
    for (jsize i = ctx->start; i < ctx->end; i++) {
        mpz_set_ui(a, 0);
        bytes_to_mpz_direct(ctx->a_data_array[i], ctx->a_len_array[i], a);
        mpz_mod(a_mod, a, *ctx->n_ptr);
        
        ctx->results[i] = mpz_jacobi(a_mod, *ctx->n_ptr);
    }
    mpz_clears(a, a_mod, NULL);
    
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
    if (!a_data_array || !a_len_array) {
        free(a_data_array);
        free(a_len_array);
        free(results);
        mpz_clear(n);
        throw_npe(env, "Memory allocation failed");
        return NULL;
    }
    
    size_t a_pool_size = 0;
    for (jsize i = 0; i < count; i++) {
        jbyteArray aArr = (jbyteArray)(*env)->GetObjectArrayElement(env, aBytesArray, i);
        a_len_array[i] = (*env)->GetArrayLength(env, aArr);
        if (a_len_array[i] > 0) {
            if (a_pool_size + (size_t)a_len_array[i] < a_pool_size) {
                (*env)->DeleteLocalRef(env, aArr);
                free(a_data_array);
                free(a_len_array);
                free(results);
                mpz_clear(n);
                throw_npe(env, "Memory allocation failed");
                return NULL;
            }
            a_pool_size += (size_t)a_len_array[i];
        }
        (*env)->DeleteLocalRef(env, aArr);
    }
    
    jbyte *a_pool = NULL;
    if (a_pool_size > 0) {
        a_pool = (jbyte *)malloc(a_pool_size);
        if (!a_pool) {
            free(a_data_array);
            free(a_len_array);
            free(results);
            mpz_clear(n);
            throw_npe(env, "Memory allocation failed");
            return NULL;
        }
    }
    
    size_t a_offset = 0;
    for (jsize i = 0; i < count; i++) {
        jbyteArray aArr = (jbyteArray)(*env)->GetObjectArrayElement(env, aBytesArray, i);
        jsize len = a_len_array[i];
        if (len > 0) {
            (*env)->GetByteArrayRegion(env, aArr, 0, len, a_pool + a_offset);
            a_data_array[i] = a_pool + a_offset;
            a_offset += (size_t)len;
        } else {
            a_data_array[i] = NULL;
        }
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
        if (!threads || !args) {
            free(threads);
            free(args);
            JacobiBatchArg arg = {a_data_array, a_len_array, &n, results, 0, count};
            batch_jacobi_worker(&arg);
        } else {
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
    }
    
    free(a_data_array);
    free(a_len_array);
    free(a_pool);
    
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
    
    mpz_t val, result;
    mpz_inits(val, result, NULL);
    for (jsize i = ctx->start; i < ctx->end; i++) {
        mpz_set_ui(val, 0);
        bytes_to_mpz_direct(ctx->val_data_array[i], ctx->val_len_array[i], val);
        mpz_mod(result, val, *ctx->mod_ptr);
        
        unsigned char *result_ptr = ctx->result_pool + i * ctx->max_result_size;
        ctx->result_len_array[i] = mpz_to_bytes_buffer(result, result_ptr, ctx->max_result_size);
    }
    mpz_clears(val, result, NULL);
    
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
    
    size_t val_pool_size = 0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray valArr = (jbyteArray)(*env)->GetObjectArrayElement(env, valsBytesArray, i);
        val_len_array[i] = (*env)->GetArrayLength(env, valArr);
        if (val_len_array[i] > 0) {
            if (val_pool_size + (size_t)val_len_array[i] < val_pool_size) {
                (*env)->DeleteLocalRef(env, valArr);
                free(val_data_array);
                free(val_len_array);
                free(result_pool);
                free(result_len_array);
                mpz_clear(mod);
                throw_npe(env, "Memory allocation failed");
                return NULL;
            }
            val_pool_size += (size_t)val_len_array[i];
        }
        (*env)->DeleteLocalRef(env, valArr);
    }
    
    jbyte *val_pool = NULL;
    if (val_pool_size > 0) {
        val_pool = (jbyte *)malloc(val_pool_size);
        if (!val_pool) {
            free(val_data_array);
            free(val_len_array);
            free(result_pool);
            free(result_len_array);
            mpz_clear(mod);
            throw_npe(env, "Memory allocation failed");
            return NULL;
        }
    }
    
    size_t val_offset = 0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray valArr = (jbyteArray)(*env)->GetObjectArrayElement(env, valsBytesArray, i);
        jsize len = val_len_array[i];
        if (len > 0) {
            (*env)->GetByteArrayRegion(env, valArr, 0, len, val_pool + val_offset);
            val_data_array[i] = val_pool + val_offset;
            val_offset += (size_t)len;
        } else {
            val_data_array[i] = NULL;
        }
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
        if (!threads || !args) {
            free(threads);
            free(args);
            BatchModArg arg = {val_data_array, val_len_array, &mod, result_pool, result_len_array, max_result_size, 0, n};
            batch_mod_worker(&arg);
        } else {
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
    
    free(val_data_array);
    free(val_len_array);
    free(result_pool);
    free(result_len_array);
    free(val_pool);
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
    
    jbyteArray resultArray = mpz_to_bytes(env, x);
    
    mpz_clears(a, p, b, q, n, t, ip, k, x, NULL);
    
    return resultArray;
}

JNIEXPORT jbyteArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeProbablePrime
  (JNIEnv *env, jclass cls, jint bitLength, jbyteArray seedBytes) {
    if (bitLength <= 0) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        (*env)->ThrowNew(env, exception, "Invalid bit length");
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
        unsigned long seed = (unsigned long)time(NULL);
        unsigned long extra = 0;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t r = read(fd, &extra, sizeof(extra));
            close(fd);
            if (r == (ssize_t)sizeof(extra)) {
                seed ^= extra;
            }
        }
        gmp_randseed_ui(rstate, seed);
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
    
    jbyteArray resultArray = mpz_to_bytes(env, prime);
    
    mpz_clears(prime, random_base, NULL);
    
    return resultArray;
}

// ==================== 合并 eq1 和 eq3 的批量验证 ====================

typedef struct {
    jsize z_len, zPrimeForN0_len, w_len, A_len;
    jsize zPrime_len, lambda_len, B_len;
    jbyte* z_data, *zPrimeForN0_data, *w_data, *A_data;
    jbyte* zPrime_data, *lambda_data, *B_data;
} AllEqTaskItem;

typedef struct {
    AllEqTaskItem* tasks;
    jsize start, end;
    int thread_id;
    mpz_t *C, *onePlusN0, *N0, *D, *N0sq;
    mpz_t *onePlusN1, *N1, *Y, *N1sq;
    jboolean* e_values;
    jbyte* eq1_results, *eq3_results;
} AllEqTaskArg;

static void* verify_all_eq_worker(void* arg) {
    AllEqTaskArg* t = (AllEqTaskArg*)arg;
    mpz_t z, zP0, w, A, zP1, lam, B, t1, t2, t3, lv, rv;
    mpz_inits(z, zP0, w, A, zP1, lam, B, t1, t2, t3, lv, rv, NULL);
    
    for (jsize i = t->start; i < t->end; i++) {
        if (t->tasks[i].z_len > 0) bytes_to_mpz_direct(t->tasks[i].z_data, t->tasks[i].z_len, z); else mpz_set_ui(z, 0);
        if (t->tasks[i].zPrimeForN0_len > 0) bytes_to_mpz_direct(t->tasks[i].zPrimeForN0_data, t->tasks[i].zPrimeForN0_len, zP0); else mpz_set_ui(zP0, 0);
        if (t->tasks[i].w_len > 0) bytes_to_mpz_direct(t->tasks[i].w_data, t->tasks[i].w_len, w); else mpz_set_ui(w, 0);
        if (t->tasks[i].A_len > 0) bytes_to_mpz_direct(t->tasks[i].A_data, t->tasks[i].A_len, A); else mpz_set_ui(A, 0);
        
        mpz_powm_signed(t1, *t->C, z, *t->N0sq);
        mpz_powm_signed(t2, *t->onePlusN0, zP0, *t->N0sq);
        mpz_powm(t3, w, *t->N0, *t->N0sq);
        mpz_mul(lv, t1, t2); mpz_mod(lv, lv, *t->N0sq);
        mpz_mul(lv, lv, t3); mpz_mod(lv, lv, *t->N0sq);
        if (t->e_values[i]) { mpz_mul(rv, A, *t->D); mpz_mod(rv, rv, *t->N0sq); }
        else mpz_mod(rv, A, *t->N0sq);
        t->eq1_results[i] = (mpz_cmp(lv, rv) == 0) ? 1 : 0;
        
        if (t->tasks[i].zPrime_len > 0) bytes_to_mpz_direct(t->tasks[i].zPrime_data, t->tasks[i].zPrime_len, zP1); else mpz_set_ui(zP1, 0);
        if (t->tasks[i].lambda_len > 0) bytes_to_mpz_direct(t->tasks[i].lambda_data, t->tasks[i].lambda_len, lam); else mpz_set_ui(lam, 0);
        if (t->tasks[i].B_len > 0) bytes_to_mpz_direct(t->tasks[i].B_data, t->tasks[i].B_len, B); else mpz_set_ui(B, 0);
        
        mpz_powm_signed(t1, *t->onePlusN1, zP1, *t->N1sq);
        mpz_powm(t2, lam, *t->N1, *t->N1sq);
        mpz_mul(lv, t1, t2); mpz_mod(lv, lv, *t->N1sq);
        if (t->e_values[i]) { mpz_mul(rv, B, *t->Y); mpz_mod(rv, rv, *t->N1sq); }
        else mpz_mod(rv, B, *t->N1sq);
        t->eq3_results[i] = (mpz_cmp(lv, rv) == 0) ? 1 : 0;
    }
    mpz_clears(z, zP0, w, A, zP1, lam, B, t1, t2, t3, lv, rv, NULL);
    return NULL;
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeVerifyAffGAllBatch(
        JNIEnv *env, jclass cls,
        jbyteArray C_bytes, jobjectArray z_arr, jbyteArray onePlusN0_bytes, jobjectArray zPrimeForN0_arr,
        jobjectArray w_arr, jbyteArray N0_bytes, jbyteArray D_bytes, jobjectArray A_arr, jbyteArray N0sq_bytes,
        jbyteArray onePlusN1_bytes, jobjectArray zPrime_arr, jobjectArray lambda_arr,
        jbyteArray N1_bytes, jobjectArray B_arr, jbyteArray Y_bytes, jbyteArray N1sq_bytes,
        jbooleanArray e_arr, jint n) {
    
    if (!C_bytes || !z_arr || !onePlusN0_bytes || !w_arr || !N0_bytes || !D_bytes || !A_arr || !N0sq_bytes ||
        !onePlusN1_bytes || !zPrime_arr || !lambda_arr || !N1_bytes || !B_arr || !Y_bytes || !N1sq_bytes || !e_arr) {
        throw_npe(env, "Null parameter"); return NULL;
    }
    init_two_pow_table();
    if (n == 0) {
        jclass baCls = (*env)->FindClass(env, "[B");
        jobjectArray empty = (*env)->NewObjectArray(env, 2, baCls, NULL);
        jbyteArray row = (*env)->NewByteArray(env, 0);
        (*env)->SetObjectArrayElement(env, empty, 0, row);
        (*env)->SetObjectArrayElement(env, empty, 1, row);
        return empty;
    }
    
    mpz_t C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq;
    mpz_inits(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
    
    jbyte* d; jsize dl;
    #define LOAD_CONST(b, v) d = (*env)->GetByteArrayElements(env, b, NULL); dl = (*env)->GetArrayLength(env, b); bytes_to_mpz_direct(d, dl, v); (*env)->ReleaseByteArrayElements(env, b, d, JNI_ABORT)
    LOAD_CONST(C_bytes, C);
    LOAD_CONST(onePlusN0_bytes, onePlusN0);
    LOAD_CONST(N0_bytes, N0);
    LOAD_CONST(D_bytes, D);
    LOAD_CONST(N0sq_bytes, N0sq);
    LOAD_CONST(onePlusN1_bytes, onePlusN1);
    LOAD_CONST(N1_bytes, N1);
    LOAD_CONST(Y_bytes, Y);
    LOAD_CONST(N1sq_bytes, N1sq);
    #undef LOAD_CONST
    
    jboolean* e_values = (*env)->GetBooleanArrayElements(env, e_arr, NULL);
    
    AllEqTaskItem* tasks = (AllEqTaskItem*)malloc(n * sizeof(AllEqTaskItem));
    if (!tasks) { mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL); (*env)->ReleaseBooleanArrayElements(env, e_arr, e_values, JNI_ABORT); throw_npe(env, "OOM"); return NULL; }
    
    size_t sz_z=0, sz_zp0=0, sz_w=0, sz_A=0, sz_zp1=0, sz_lam=0, sz_B=0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray a;
        #define GET_LEN2(arr, len_field, sz_var) a = (jbyteArray)(*env)->GetObjectArrayElement(env, arr, i); tasks[i].len_field = (*env)->GetArrayLength(env, a); sz_var += tasks[i].len_field; (*env)->DeleteLocalRef(env, a)
        GET_LEN2(z_arr, z_len, sz_z);
        GET_LEN2(zPrimeForN0_arr, zPrimeForN0_len, sz_zp0);
        GET_LEN2(w_arr, w_len, sz_w);
        GET_LEN2(A_arr, A_len, sz_A);
        GET_LEN2(zPrime_arr, zPrime_len, sz_zp1);
        GET_LEN2(lambda_arr, lambda_len, sz_lam);
        GET_LEN2(B_arr, B_len, sz_B);
        #undef GET_LEN2
    }
    
    jbyte *pool_z = malloc(sz_z?:1), *pool_zp0 = malloc(sz_zp0?:1), *pool_w = malloc(sz_w?:1), *pool_A = malloc(sz_A?:1);
    jbyte *pool_zp1 = malloc(sz_zp1?:1), *pool_lam = malloc(sz_lam?:1), *pool_B = malloc(sz_B?:1);
    if (!pool_z || !pool_zp0 || !pool_w || !pool_A || !pool_zp1 || !pool_lam || !pool_B) {
        free(pool_z); free(pool_zp0); free(pool_w); free(pool_A); free(pool_zp1); free(pool_lam); free(pool_B);
        free(tasks); mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
        (*env)->ReleaseBooleanArrayElements(env, e_arr, e_values, JNI_ABORT); throw_npe(env, "OOM"); return NULL;
    }
    
    size_t off_z=0, off_zp0=0, off_w=0, off_A=0, off_zp1=0, off_lam=0, off_B=0;
    for (jsize i = 0; i < n; i++) {
        jbyteArray a;
        #define COPY_DATA2(arr, len_field, data_field, pool, off) \
            a = (jbyteArray)(*env)->GetObjectArrayElement(env, arr, i); \
            if (tasks[i].len_field > 0) { (*env)->GetByteArrayRegion(env, a, 0, tasks[i].len_field, pool + off); tasks[i].data_field = pool + off; off += tasks[i].len_field; } \
            else tasks[i].data_field = NULL; \
            (*env)->DeleteLocalRef(env, a)
        COPY_DATA2(z_arr, z_len, z_data, pool_z, off_z);
        COPY_DATA2(zPrimeForN0_arr, zPrimeForN0_len, zPrimeForN0_data, pool_zp0, off_zp0);
        COPY_DATA2(w_arr, w_len, w_data, pool_w, off_w);
        COPY_DATA2(A_arr, A_len, A_data, pool_A, off_A);
        COPY_DATA2(zPrime_arr, zPrime_len, zPrime_data, pool_zp1, off_zp1);
        COPY_DATA2(lambda_arr, lambda_len, lambda_data, pool_lam, off_lam);
        COPY_DATA2(B_arr, B_len, B_data, pool_B, off_B);
        #undef COPY_DATA2
    }
    
    jbyte *eq1_res = malloc(n), *eq3_res = malloc(n);
    if (!eq1_res || !eq3_res) {
        free(pool_z); free(pool_zp0); free(pool_w); free(pool_A); free(pool_zp1); free(pool_lam); free(pool_B);
        free(eq1_res); free(eq3_res); free(tasks);
        mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
        (*env)->ReleaseBooleanArrayElements(env, e_arr, e_values, JNI_ABORT); throw_npe(env, "OOM"); return NULL;
    }
    
    // 使用预分配的 mpz_t 池和 pthread 并行
    int nth = sysconf(_SC_NPROCESSORS_ONLN);
    if (nth < 1) nth = 1;
    if (nth > n) nth = n;
    if (nth > MAX_THREADS) nth = MAX_THREADS;
    
    pthread_t* ths = malloc(nth * sizeof(pthread_t));
    AllEqTaskArg* args = malloc(nth * sizeof(AllEqTaskArg));
    jsize chunk = (n + nth - 1) / nth;
    
    for (int t = 0; t < nth; t++) {
        args[t].tasks = tasks; args[t].start = t * chunk; args[t].end = (t+1) * chunk; if (args[t].end > n) args[t].end = n;
        args[t].thread_id = t;
        args[t].C = &C; args[t].onePlusN0 = &onePlusN0; args[t].N0 = &N0; args[t].D = &D; args[t].N0sq = &N0sq;
        args[t].onePlusN1 = &onePlusN1; args[t].N1 = &N1; args[t].Y = &Y; args[t].N1sq = &N1sq;
        args[t].e_values = e_values; args[t].eq1_results = eq1_res; args[t].eq3_results = eq3_res;
        if (args[t].start < args[t].end) pthread_create(&ths[t], NULL, verify_all_eq_worker, &args[t]);
    }
    for (int t = 0; t < nth; t++) {
        if (args[t].start < args[t].end) pthread_join(ths[t], NULL);
    }
    free(ths); free(args);
    free(pool_z); free(pool_zp0); free(pool_w); free(pool_A); free(pool_zp1); free(pool_lam); free(pool_B);
    free(tasks);
    mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
    (*env)->ReleaseBooleanArrayElements(env, e_arr, e_values, JNI_ABORT);
    
    jclass baCls = (*env)->FindClass(env, "[B");
    jobjectArray resultArray = (*env)->NewObjectArray(env, 2, baCls, NULL);
    jbyteArray r1 = (*env)->NewByteArray(env, n); (*env)->SetByteArrayRegion(env, r1, 0, n, eq1_res);
    jbyteArray r3 = (*env)->NewByteArray(env, n); (*env)->SetByteArrayRegion(env, r3, 0, n, eq3_res);
    (*env)->SetObjectArrayElement(env, resultArray, 0, r1);
    (*env)->SetObjectArrayElement(env, resultArray, 1, r3);
    free(eq1_res); free(eq3_res);
    return resultArray;
}

// ==================== 优化版本：使用 DirectByteBuffer ====================

static int read_int_from_buffer(jbyte** ptr) {
    int val = ((*ptr)[0] & 0xFF) << 24 | ((*ptr)[1] & 0xFF) << 16 | ((*ptr)[2] & 0xFF) << 8 | ((*ptr)[3] & 0xFF);
    *ptr += 4;
    return val;
}

static void read_mpz_from_buffer(jbyte** ptr, mpz_t dest) {
    int len = read_int_from_buffer(ptr);
    if (len > 0) {
        bytes_to_mpz_direct(*ptr, len, dest);
        *ptr += len;
    } else {
        mpz_set_ui(dest, 0);
    }
}

JNIEXPORT jobjectArray JNICALL Java_com_example_mpc_cggmp_util_NativeBigInteger_nativeVerifyAffGAllBatchOptimized(
        JNIEnv *env, jclass cls, jobject buffer, jint n) {
    
    init_two_pow_table();
    
    if (n == 0) {
        jclass baCls = (*env)->FindClass(env, "[B");
        jobjectArray empty = (*env)->NewObjectArray(env, 2, baCls, NULL);
        jbyteArray row = (*env)->NewByteArray(env, 0);
        (*env)->SetObjectArrayElement(env, empty, 0, row);
        (*env)->SetObjectArrayElement(env, empty, 1, row);
        return empty;
    }
    
    jbyte* data = (*env)->GetDirectBufferAddress(env, buffer);
    if (!data) {
        throw_npe(env, "Invalid buffer");
        return NULL;
    }
    
    jbyte* ptr = data;
    int n_read = read_int_from_buffer(&ptr);
    (void)n_read;
    
    mpz_t C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq;
    mpz_inits(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
    
    read_mpz_from_buffer(&ptr, C);
    read_mpz_from_buffer(&ptr, onePlusN0);
    read_mpz_from_buffer(&ptr, N0);
    read_mpz_from_buffer(&ptr, D);
    read_mpz_from_buffer(&ptr, N0sq);
    read_mpz_from_buffer(&ptr, onePlusN1);
    read_mpz_from_buffer(&ptr, N1);
    read_mpz_from_buffer(&ptr, Y);
    read_mpz_from_buffer(&ptr, N1sq);
    
    AllEqTaskItem* tasks = (AllEqTaskItem*)malloc(n * sizeof(AllEqTaskItem));
    if (!tasks) {
        mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
        throw_npe(env, "OOM");
        return NULL;
    }
    
    // 第一遍：计算总大小
    size_t sz_z=0, sz_zp0=0, sz_w=0, sz_A=0, sz_zp1=0, sz_lam=0, sz_B=0;
    jbyte* ptr_save = ptr;
    for (int i = 0; i < n; i++) {
        int len;
        len = read_int_from_buffer(&ptr); tasks[i].z_len = len; sz_z += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].zPrimeForN0_len = len; sz_zp0 += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].w_len = len; sz_w += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].A_len = len; sz_A += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].zPrime_len = len; sz_zp1 += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].lambda_len = len; sz_lam += len; ptr += len;
        len = read_int_from_buffer(&ptr); tasks[i].B_len = len; sz_B += len; ptr += len;
    }
    ptr = ptr_save;
    
    jbyte *pool_z = malloc(sz_z?:1), *pool_zp0 = malloc(sz_zp0?:1), *pool_w = malloc(sz_w?:1), *pool_A = malloc(sz_A?:1);
    jbyte *pool_zp1 = malloc(sz_zp1?:1), *pool_lam = malloc(sz_lam?:1), *pool_B = malloc(sz_B?:1);
    
    // 第二遍：复制数据
    size_t off_z=0, off_zp0=0, off_w=0, off_A=0, off_zp1=0, off_lam=0, off_B=0;
    for (int i = 0; i < n; i++) {
        tasks[i].z_len = read_int_from_buffer(&ptr);
        if (tasks[i].z_len > 0) { tasks[i].z_data = pool_z + off_z; memcpy(tasks[i].z_data, ptr, tasks[i].z_len); ptr += tasks[i].z_len; off_z += tasks[i].z_len; }
        else tasks[i].z_data = NULL;
        tasks[i].zPrimeForN0_len = read_int_from_buffer(&ptr);
        if (tasks[i].zPrimeForN0_len > 0) { tasks[i].zPrimeForN0_data = pool_zp0 + off_zp0; memcpy(tasks[i].zPrimeForN0_data, ptr, tasks[i].zPrimeForN0_len); ptr += tasks[i].zPrimeForN0_len; off_zp0 += tasks[i].zPrimeForN0_len; }
        else tasks[i].zPrimeForN0_data = NULL;
        tasks[i].w_len = read_int_from_buffer(&ptr);
        if (tasks[i].w_len > 0) { tasks[i].w_data = pool_w + off_w; memcpy(tasks[i].w_data, ptr, tasks[i].w_len); ptr += tasks[i].w_len; off_w += tasks[i].w_len; }
        else tasks[i].w_data = NULL;
        tasks[i].A_len = read_int_from_buffer(&ptr);
        if (tasks[i].A_len > 0) { tasks[i].A_data = pool_A + off_A; memcpy(tasks[i].A_data, ptr, tasks[i].A_len); ptr += tasks[i].A_len; off_A += tasks[i].A_len; }
        else tasks[i].A_data = NULL;
        tasks[i].zPrime_len = read_int_from_buffer(&ptr);
        if (tasks[i].zPrime_len > 0) { tasks[i].zPrime_data = pool_zp1 + off_zp1; memcpy(tasks[i].zPrime_data, ptr, tasks[i].zPrime_len); ptr += tasks[i].zPrime_len; off_zp1 += tasks[i].zPrime_len; }
        else tasks[i].zPrime_data = NULL;
        tasks[i].lambda_len = read_int_from_buffer(&ptr);
        if (tasks[i].lambda_len > 0) { tasks[i].lambda_data = pool_lam + off_lam; memcpy(tasks[i].lambda_data, ptr, tasks[i].lambda_len); ptr += tasks[i].lambda_len; off_lam += tasks[i].lambda_len; }
        else tasks[i].lambda_data = NULL;
        tasks[i].B_len = read_int_from_buffer(&ptr);
        if (tasks[i].B_len > 0) { tasks[i].B_data = pool_B + off_B; memcpy(tasks[i].B_data, ptr, tasks[i].B_len); ptr += tasks[i].B_len; off_B += tasks[i].B_len; }
        else tasks[i].B_data = NULL;
    }
    
    int e_len = read_int_from_buffer(&ptr);
    jboolean* e_values = (jboolean*)malloc(e_len * sizeof(jboolean));
    for (int i = 0; i < e_len; i++) {
        e_values[i] = ptr[i] != 0;
    }
    ptr += e_len;
    
    jbyte *eq1_res = malloc(n), *eq3_res = malloc(n);
    
    int nth = sysconf(_SC_NPROCESSORS_ONLN); if (nth < 1) nth = 1; if (nth > n) nth = n;
    pthread_t* ths = malloc(nth * sizeof(pthread_t));
    AllEqTaskArg* args = malloc(nth * sizeof(AllEqTaskArg));
    jsize chunk = (n + nth - 1) / nth;
    
    for (int t = 0; t < nth; t++) {
        args[t].tasks = tasks; args[t].start = t * chunk; args[t].end = (t+1) * chunk; if (args[t].end > n) args[t].end = n;
        args[t].thread_id = t;
        args[t].C = &C; args[t].onePlusN0 = &onePlusN0; args[t].N0 = &N0; args[t].D = &D; args[t].N0sq = &N0sq;
        args[t].onePlusN1 = &onePlusN1; args[t].N1 = &N1; args[t].Y = &Y; args[t].N1sq = &N1sq;
        args[t].e_values = e_values; args[t].eq1_results = eq1_res; args[t].eq3_results = eq3_res;
        if (args[t].start < args[t].end) pthread_create(&ths[t], NULL, verify_all_eq_worker, &args[t]);
    }
    for (int t = 0; t < nth; t++) if (args[t].start < args[t].end) pthread_join(ths[t], NULL);
    
    free(ths); free(args);
    free(pool_z); free(pool_zp0); free(pool_w); free(pool_A); free(pool_zp1); free(pool_lam); free(pool_B);
    free(tasks); free(e_values);
    mpz_clears(C, onePlusN0, N0, D, N0sq, onePlusN1, N1, Y, N1sq, NULL);
    
    jclass baCls = (*env)->FindClass(env, "[B");
    jobjectArray resultArray = (*env)->NewObjectArray(env, 2, baCls, NULL);
    jbyteArray r1 = (*env)->NewByteArray(env, n); (*env)->SetByteArrayRegion(env, r1, 0, n, eq1_res);
    jbyteArray r3 = (*env)->NewByteArray(env, n); (*env)->SetByteArrayRegion(env, r3, 0, n, eq3_res);
    (*env)->SetObjectArrayElement(env, resultArray, 0, r1);
    (*env)->SetObjectArrayElement(env, resultArray, 1, r3);
    free(eq1_res); free(eq3_res);
    return resultArray;
}
