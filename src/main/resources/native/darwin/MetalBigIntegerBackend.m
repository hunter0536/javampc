/**
 * Metal Backend for Big Integer Operations
 * Objective-C wrapper for Metal Compute Shaders with JNI bridge
 */

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <limits.h>
#include <unistd.h>
#include "com_example_mpc_cggmp_util_MetalBigIntegerBackend.h"

@interface MetalBigIntegerBackend : NSObject

@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@property (nonatomic, strong) id<MTLLibrary> library;
@property (nonatomic, strong) id<MTLComputePipelineState> modPowPipeline;
@property (nonatomic, strong) id<MTLComputePipelineState> computeAffGProofTuplePipeline;
@property (nonatomic, strong) id<MTLComputePipelineState> computeDecProofTuplePipeline;
@property (nonatomic, strong) id<MTLComputePipelineState> batchModPowPipeline;

- (instancetype)init;
- (instancetype)initWithShaderPath:(NSString *)shaderPath;
- (BOOL)isAvailable;
- (void)modPow:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;
- (void)computeAffGProofTuple:(const uint32_t*)C N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq N1:(const uint32_t*)N1 N1sq:(const uint32_t*)N1sq alphas:(const uint32_t*)alphas betasForN0:(const uint32_t*)betasForN0 betasForN1:(const uint32_t*)betasForN1 rs:(const uint32_t*)rs ss:(const uint32_t*)ss Aj_results:(uint32_t*)Aj_results Bj_results:(uint32_t*)Bj_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa;
- (void)computeDecProofTuple:(const uint32_t*)K N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq negAlphas:(const uint32_t*)negAlphas betas:(const uint32_t*)betas rs:(const uint32_t*)rs A_results:(uint32_t*)A_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa;

@end

@implementation MetalBigIntegerBackend

- (instancetype)init {
    return [self initWithShaderPath:nil];
}

- (instancetype)initWithShaderPath:(NSString *)shaderPath {
    self = [super init];
    if (self) {
        @try {
            NSLog(@"MetalBigIntegerBackend: Step 1 - Creating Metal device");
            self.device = MTLCreateSystemDefaultDevice();
            if (!self.device) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Metal is not supported on this device");
                return nil;
            }
            
            NSLog(@"MetalBigIntegerBackend: Step 2 - Using Metal device: %@", self.device.name);
            
            NSLog(@"MetalBigIntegerBackend: Step 3 - Creating command queue");
            self.commandQueue = [self.device newCommandQueue];
            if (!self.commandQueue) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Failed to create command queue");
                return nil;
            }
            
            NSLog(@"MetalBigIntegerBackend: Step 4 - Loading precompiled shader library");
            
            NSString *resolvedShaderPath = shaderPath;
            if (resolvedShaderPath && ![[NSFileManager defaultManager] fileExistsAtPath:resolvedShaderPath]) {
                NSLog(@"MetalBigIntegerBackend: Provided shader path not found: %@", resolvedShaderPath);
                resolvedShaderPath = nil;
            }
            
            if (!resolvedShaderPath) {
                NSBundle *mainBundle = [NSBundle mainBundle];
                resolvedShaderPath = [mainBundle pathForResource:@"big_integer_shaders_complete"
                                                         ofType:@"metallib"
                                                    inDirectory:@"native/darwin"];
                if (!resolvedShaderPath) {
                    resolvedShaderPath = [mainBundle pathForResource:@"big_integer_shaders_complete" ofType:@"metallib"];
                }
                if (!resolvedShaderPath) {
                    NSBundle *classBundle = [NSBundle bundleForClass:[MetalBigIntegerBackend class]];
                    resolvedShaderPath = [classBundle pathForResource:@"big_integer_shaders_complete"
                                                              ofType:@"metallib"
                                                         inDirectory:@"native/darwin"];
                    if (!resolvedShaderPath) {
                        resolvedShaderPath = [classBundle pathForResource:@"big_integer_shaders_complete" ofType:@"metallib"];
                    }
                }
                if (!resolvedShaderPath) {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        NSString *devPath = [NSString stringWithFormat:@"%s/src/main/resources/native/darwin/big_integer_shaders_complete.metallib", cwd];
                        if ([[NSFileManager defaultManager] fileExistsAtPath:devPath]) {
                            resolvedShaderPath = devPath;
                        }
                    }
                }
            }
            
            if (!resolvedShaderPath) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Shader file not found");
                return nil;
            }
            
            NSError *libError = nil;
            self.library = [self.device newLibraryWithFile:resolvedShaderPath error:&libError];
            if (libError) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Failed to load metallib: %@", libError.localizedDescription);
            }
            
            if (!self.library) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Failed to create shader library from metallib");
                return nil;
            }
            
            NSLog(@"MetalBigIntegerBackend: Step 5 - Shader library loaded successfully");
            
            NSLog(@"MetalBigIntegerBackend: Step 6 - Creating compute pipelines");
            id<MTLFunction> modPowFunction = [self.library newFunctionWithName:@"modPowKernel"];
            if (modPowFunction) {
                NSError *error = nil;
                self.modPowPipeline = [self.device newComputePipelineStateWithFunction:modPowFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - modPowPipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - modPowKernel function not found");
            }
            
            id<MTLFunction> computeAffGFunction = [self.library newFunctionWithName:@"computeAffGProofTupleKernel"];
            if (computeAffGFunction) {
                NSError *error = nil;
                self.computeAffGProofTuplePipeline = [self.device newComputePipelineStateWithFunction:computeAffGFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - computeAffGProofTuplePipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - computeAffGProofTupleKernel function not found");
            }

            id<MTLFunction> computeDecFunction = [self.library newFunctionWithName:@"computeDecProofTupleKernel"];
            if (computeDecFunction) {
                NSError *error = nil;
                self.computeDecProofTuplePipeline = [self.device newComputePipelineStateWithFunction:computeDecFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - computeDecProofTuplePipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - computeDecProofTupleKernel function not found");
            }
            
            id<MTLFunction> batchModPowFunction = [self.library newFunctionWithName:@"batchModPowKernel"];
            if (batchModPowFunction) {
                NSError *error = nil;
                self.batchModPowPipeline = [self.device newComputePipelineStateWithFunction:batchModPowFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - batchModPowPipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - batchModPowKernel function not found");
            }
            
            if (!self.modPowPipeline || !self.computeAffGProofTuplePipeline || !self.computeDecProofTuplePipeline || !self.batchModPowPipeline) {
                NSLog(@"MetalBigIntegerBackend: ERROR - Failed to create compute pipelines");
                NSLog(@"MetalBigIntegerBackend: modPowPipeline: %@, computeAffGProofTuplePipeline: %@, computeDecProofTuplePipeline: %@, batchModPowPipeline: %@",
                      self.modPowPipeline ? @"OK" : @"NULL",
                      self.computeAffGProofTuplePipeline ? @"OK" : @"NULL",
                      self.computeDecProofTuplePipeline ? @"OK" : @"NULL",
                      self.batchModPowPipeline ? @"OK" : @"NULL");
                return nil;
            }
            
            NSLog(@"MetalBigIntegerBackend: Step 7 - Initialized successfully");
            
        } @catch (NSException *exception) {
            NSLog(@"MetalBigIntegerBackend: EXCEPTION - Initialization failed: %@", exception.reason);
            NSLog(@"MetalBigIntegerBackend: Exception stack trace: %@", exception.callStackSymbols);
            return nil;
        }
    }
    return self;
}

- (BOOL)isAvailable {
    return self.device != nil && self.commandQueue != nil && self.library != nil;
}

- (void)modPow:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.modPowPipeline) {
            NSLog(@"MetalBigIntegerBackend: modPowPipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        
        id<MTLBuffer> basesBuffer = [self.device newBufferWithBytes:bases length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> expsBuffer = [self.device newBufferWithBytes:exps length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> modsBuffer = [self.device newBufferWithBytes:mods length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> resultsBuffer = [self.device newBufferWithLength:bufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.modPowPipeline];
        [encoder setBuffer:basesBuffer offset:0 atIndex:0];
        [encoder setBuffer:expsBuffer offset:0 atIndex:1];
        [encoder setBuffer:modsBuffer offset:0 atIndex:2];
        [encoder setBuffer:resultsBuffer offset:0 atIndex:3];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:4];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:5];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = 256;
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, resultsBuffer.contents, bufferSize);
    }
}

- (void)computeAffGProofTuple:(const uint32_t*)C N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq N1:(const uint32_t*)N1 N1sq:(const uint32_t*)N1sq alphas:(const uint32_t*)alphas betasForN0:(const uint32_t*)betasForN0 betasForN1:(const uint32_t*)betasForN1 rs:(const uint32_t*)rs ss:(const uint32_t*)ss Aj_results:(uint32_t*)Aj_results Bj_results:(uint32_t*)Bj_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa {
    @autoreleasepool {
        if (!self.computeAffGProofTuplePipeline) {
            NSLog(@"MetalBigIntegerBackend: computeAffGProofTuplePipeline not available");
            return;
        }
        
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        NSUInteger arrayBufferSize = numLength * sizeof(uint32_t) * kappa;
        
        id<MTLBuffer> CBuffer = [self.device newBufferWithBytes:C length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N0Buffer = [self.device newBufferWithBytes:N0 length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N0sqBuffer = [self.device newBufferWithBytes:N0sq length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N1Buffer = [self.device newBufferWithBytes:N1 length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N1sqBuffer = [self.device newBufferWithBytes:N1sq length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> alphasBuffer = [self.device newBufferWithBytes:alphas length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> betasForN0Buffer = [self.device newBufferWithBytes:betasForN0 length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> betasForN1Buffer = [self.device newBufferWithBytes:betasForN1 length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> rsBuffer = [self.device newBufferWithBytes:rs length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> ssBuffer = [self.device newBufferWithBytes:ss length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> AjBuffer = [self.device newBufferWithLength:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> BjBuffer = [self.device newBufferWithLength:arrayBufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.computeAffGProofTuplePipeline];
        [encoder setBuffer:CBuffer offset:0 atIndex:0];
        [encoder setBuffer:N0Buffer offset:0 atIndex:1];
        [encoder setBuffer:N0sqBuffer offset:0 atIndex:2];
        [encoder setBuffer:N1Buffer offset:0 atIndex:3];
        [encoder setBuffer:N1sqBuffer offset:0 atIndex:4];
        [encoder setBuffer:alphasBuffer offset:0 atIndex:5];
        [encoder setBuffer:betasForN0Buffer offset:0 atIndex:6];
        [encoder setBuffer:betasForN1Buffer offset:0 atIndex:7];
        [encoder setBuffer:rsBuffer offset:0 atIndex:8];
        [encoder setBuffer:ssBuffer offset:0 atIndex:9];
        [encoder setBuffer:AjBuffer offset:0 atIndex:10];
        [encoder setBuffer:BjBuffer offset:0 atIndex:11];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:12];
        [encoder setBytes:&kappa length:sizeof(uint32_t) atIndex:13];
        
        MTLSize gridSize = MTLSizeMake(kappa, 1, 1);
        NSUInteger threadGroupSize = 256;
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(Aj_results, AjBuffer.contents, arrayBufferSize);
        memcpy(Bj_results, BjBuffer.contents, arrayBufferSize);
    }
}

- (void)computeDecProofTuple:(const uint32_t*)K N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq negAlphas:(const uint32_t*)negAlphas betas:(const uint32_t*)betas rs:(const uint32_t*)rs A_results:(uint32_t*)A_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa {
    @autoreleasepool {
        if (!self.computeDecProofTuplePipeline) {
            NSLog(@"MetalBigIntegerBackend: computeDecProofTuplePipeline not available");
            return;
        }
        
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        NSUInteger arrayBufferSize = numLength * sizeof(uint32_t) * kappa;
        
        id<MTLBuffer> KBuffer = [self.device newBufferWithBytes:K length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N0Buffer = [self.device newBufferWithBytes:N0 length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> N0sqBuffer = [self.device newBufferWithBytes:N0sq length:singleBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> negAlphasBuffer = [self.device newBufferWithBytes:negAlphas length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> betasBuffer = [self.device newBufferWithBytes:betas length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> rsBuffer = [self.device newBufferWithBytes:rs length:arrayBufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> ABuffer = [self.device newBufferWithLength:arrayBufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.computeDecProofTuplePipeline];
        [encoder setBuffer:KBuffer offset:0 atIndex:0];
        [encoder setBuffer:N0Buffer offset:0 atIndex:1];
        [encoder setBuffer:N0sqBuffer offset:0 atIndex:2];
        [encoder setBuffer:negAlphasBuffer offset:0 atIndex:3];
        [encoder setBuffer:betasBuffer offset:0 atIndex:4];
        [encoder setBuffer:rsBuffer offset:0 atIndex:5];
        [encoder setBuffer:ABuffer offset:0 atIndex:6];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:7];
        [encoder setBytes:&kappa length:sizeof(uint32_t) atIndex:8];
        
        MTLSize gridSize = MTLSizeMake(kappa, 1, 1);
        NSUInteger threadGroupSize = 256;
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(A_results, ABuffer.contents, arrayBufferSize);
    }
}

@end

// JNI Implementation
JNIEXPORT jlong JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInit
  (JNIEnv *env, jobject obj) {
    @autoreleasepool {
        MetalBigIntegerBackend *backend = [[MetalBigIntegerBackend alloc] init];
        if (backend && [backend isAvailable]) {
            return (jlong)CFBridgingRetain(backend);
        }
        return 0;
    }
}

JNIEXPORT jlong JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInitWithShaderPath
  (JNIEnv *env, jobject obj, jstring shaderPath) {
    @autoreleasepool {
        if (shaderPath == NULL) {
            return Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInit(env, obj);
        }
        const char *pathChars = (*env)->GetStringUTFChars(env, shaderPath, NULL);
        if (!pathChars) {
            return Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInit(env, obj);
        }
        NSString *path = [NSString stringWithUTF8String:pathChars];
        (*env)->ReleaseStringUTFChars(env, shaderPath, pathChars);
        
        MetalBigIntegerBackend *backend = [[MetalBigIntegerBackend alloc] initWithShaderPath:path];
        if (backend && [backend isAvailable]) {
            return (jlong)CFBridgingRetain(backend);
        }
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeDestroy
  (JNIEnv *env, jobject obj, jlong handle) {
    @autoreleasepool {
        if (handle != 0) {
            MetalBigIntegerBackend *backend = (__bridge_transfer MetalBigIntegerBackend *)handle;
            backend = nil;
        }
    }
}

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeIsAvailable
  (JNIEnv *env, jobject obj, jlong handle) {
    @autoreleasepool {
        if (handle == 0) return JNI_FALSE;
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)handle;
        return [backend isAvailable] ? JNI_TRUE : JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModPow
  (JNIEnv *env, jobject obj, jlong handle, jintArray bases, jintArray exps, jintArray mods, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)handle;
        
        jsize basesLen = (*env)->GetArrayLength(env, bases);
        jsize expsLen = (*env)->GetArrayLength(env, exps);
        jsize modsLen = (*env)->GetArrayLength(env, mods);
        jsize resultsLen = (*env)->GetArrayLength(env, results);
        
        if (basesLen != expsLen || basesLen != modsLen || basesLen != resultsLen) {
            return;
        }
        
        jint *basesPtr = (*env)->GetIntArrayElements(env, bases, NULL);
        jint *expsPtr = (*env)->GetIntArrayElements(env, exps, NULL);
        jint *modsPtr = (*env)->GetIntArrayElements(env, mods, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (basesPtr && expsPtr && modsPtr && resultsPtr) {
            [backend modPow:(const uint32_t*)basesPtr 
                       exps:(const uint32_t*)expsPtr 
                       mods:(const uint32_t*)modsPtr 
                    results:(uint32_t*)resultsPtr 
                  numLength:(uint32_t)numLength 
                      count:(uint32_t)count];
        }
        
        if (basesPtr) (*env)->ReleaseIntArrayElements(env, bases, basesPtr, JNI_ABORT);
        if (expsPtr) (*env)->ReleaseIntArrayElements(env, exps, expsPtr, JNI_ABORT);
        if (modsPtr) (*env)->ReleaseIntArrayElements(env, mods, modsPtr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeComputeAffGProofTuple
  (JNIEnv *env, jobject obj, jlong handle, jintArray C, jintArray N0, jintArray N0sq, jintArray N1, jintArray N1sq,
            jintArray alphas, jintArray betasForN0, jintArray betasForN1, jintArray rs, jintArray ss,
            jintArray Aj, jintArray Bj, jint numLength, jint kappa) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)handle;
        
        jint *CPtr = (*env)->GetIntArrayElements(env, C, NULL);
        jint *N0Ptr = (*env)->GetIntArrayElements(env, N0, NULL);
        jint *N0sqPtr = (*env)->GetIntArrayElements(env, N0sq, NULL);
        jint *N1Ptr = (*env)->GetIntArrayElements(env, N1, NULL);
        jint *N1sqPtr = (*env)->GetIntArrayElements(env, N1sq, NULL);
        jint *alphasPtr = (*env)->GetIntArrayElements(env, alphas, NULL);
        jint *betasForN0Ptr = (*env)->GetIntArrayElements(env, betasForN0, NULL);
        jint *betasForN1Ptr = (*env)->GetIntArrayElements(env, betasForN1, NULL);
        jint *rsPtr = (*env)->GetIntArrayElements(env, rs, NULL);
        jint *ssPtr = (*env)->GetIntArrayElements(env, ss, NULL);
        jint *AjPtr = (*env)->GetIntArrayElements(env, Aj, NULL);
        jint *BjPtr = (*env)->GetIntArrayElements(env, Bj, NULL);
        
        if (CPtr && N0Ptr && N0sqPtr && N1Ptr && N1sqPtr && alphasPtr && betasForN0Ptr && betasForN1Ptr && rsPtr && ssPtr && AjPtr && BjPtr) {
            [backend computeAffGProofTuple:(const uint32_t*)CPtr
                                       N0:(const uint32_t*)N0Ptr
                                     N0sq:(const uint32_t*)N0sqPtr
                                       N1:(const uint32_t*)N1Ptr
                                     N1sq:(const uint32_t*)N1sqPtr
                                   alphas:(const uint32_t*)alphasPtr
                              betasForN0:(const uint32_t*)betasForN0Ptr
                              betasForN1:(const uint32_t*)betasForN1Ptr
                                       rs:(const uint32_t*)rsPtr
                                       ss:(const uint32_t*)ssPtr
                               Aj_results:(uint32_t*)AjPtr
                               Bj_results:(uint32_t*)BjPtr
                                numLength:(uint32_t)numLength
                                    kappa:(uint32_t)kappa];
        }
        
        if (CPtr) (*env)->ReleaseIntArrayElements(env, C, CPtr, JNI_ABORT);
        if (N0Ptr) (*env)->ReleaseIntArrayElements(env, N0, N0Ptr, JNI_ABORT);
        if (N0sqPtr) (*env)->ReleaseIntArrayElements(env, N0sq, N0sqPtr, JNI_ABORT);
        if (N1Ptr) (*env)->ReleaseIntArrayElements(env, N1, N1Ptr, JNI_ABORT);
        if (N1sqPtr) (*env)->ReleaseIntArrayElements(env, N1sq, N1sqPtr, JNI_ABORT);
        if (alphasPtr) (*env)->ReleaseIntArrayElements(env, alphas, alphasPtr, JNI_ABORT);
        if (betasForN0Ptr) (*env)->ReleaseIntArrayElements(env, betasForN0, betasForN0Ptr, JNI_ABORT);
        if (betasForN1Ptr) (*env)->ReleaseIntArrayElements(env, betasForN1, betasForN1Ptr, JNI_ABORT);
        if (rsPtr) (*env)->ReleaseIntArrayElements(env, rs, rsPtr, JNI_ABORT);
        if (ssPtr) (*env)->ReleaseIntArrayElements(env, ss, ssPtr, JNI_ABORT);
        if (AjPtr) (*env)->ReleaseIntArrayElements(env, Aj, AjPtr, 0);
        if (BjPtr) (*env)->ReleaseIntArrayElements(env, Bj, BjPtr, 0);
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeComputeDecProofTuple
  (JNIEnv *env, jobject obj, jlong handle, jintArray K, jintArray N0, jintArray N0sq,
            jintArray negAlphas, jintArray betas, jintArray rs,
            jintArray A, jint numLength, jint kappa) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)handle;
        
        jint *KPtr = (*env)->GetIntArrayElements(env, K, NULL);
        jint *N0Ptr = (*env)->GetIntArrayElements(env, N0, NULL);
        jint *N0sqPtr = (*env)->GetIntArrayElements(env, N0sq, NULL);
        jint *negAlphasPtr = (*env)->GetIntArrayElements(env, negAlphas, NULL);
        jint *betasPtr = (*env)->GetIntArrayElements(env, betas, NULL);
        jint *rsPtr = (*env)->GetIntArrayElements(env, rs, NULL);
        jint *APtr = (*env)->GetIntArrayElements(env, A, NULL);
        
        if (KPtr && N0Ptr && N0sqPtr && negAlphasPtr && betasPtr && rsPtr && APtr) {
            [backend computeDecProofTuple:(const uint32_t*)KPtr
                                        N0:(const uint32_t*)N0Ptr
                                      N0sq:(const uint32_t*)N0sqPtr
                                 negAlphas:(const uint32_t*)negAlphasPtr
                                     betas:(const uint32_t*)betasPtr
                                        rs:(const uint32_t*)rsPtr
                                 A_results:(uint32_t*)APtr
                                 numLength:(uint32_t)numLength
                                     kappa:(uint32_t)kappa];
        }
        
        if (KPtr) (*env)->ReleaseIntArrayElements(env, K, KPtr, JNI_ABORT);
        if (N0Ptr) (*env)->ReleaseIntArrayElements(env, N0, N0Ptr, JNI_ABORT);
        if (N0sqPtr) (*env)->ReleaseIntArrayElements(env, N0sq, N0sqPtr, JNI_ABORT);
        if (negAlphasPtr) (*env)->ReleaseIntArrayElements(env, negAlphas, negAlphasPtr, JNI_ABORT);
        if (betasPtr) (*env)->ReleaseIntArrayElements(env, betas, betasPtr, JNI_ABORT);
        if (rsPtr) (*env)->ReleaseIntArrayElements(env, rs, rsPtr, JNI_ABORT);
        if (APtr) (*env)->ReleaseIntArrayElements(env, A, APtr, 0);
    }
}
