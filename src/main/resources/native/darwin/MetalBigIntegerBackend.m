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
@property (nonatomic, strong) id<MTLComputePipelineState> modInversePipeline;
@property (nonatomic, strong) id<MTLComputePipelineState> multiplyPipeline;
@property (nonatomic, strong) id<MTLComputePipelineState> batchModPowDifferentExpPipeline;
@property (nonatomic, strong) id<MTLBuffer> cachedModBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedRBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedR2Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedExpBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedBasesBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedExpsBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedModsBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedResultsBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedAjBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedBjBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedRsBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedSsBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedCBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedN0Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedN0sqBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedN1Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedN1sqBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedKBuffer;
@property (nonatomic, strong) id<MTLBuffer> cachedRN0Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedR2N0Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedRN1Buffer;
@property (nonatomic, strong) id<MTLBuffer> cachedR2N1Buffer;
@property (nonatomic, assign) NSUInteger cachedSingleBufferSize;

- (instancetype)init;
- (instancetype)initWithShaderPath:(NSString *)shaderPath;
- (BOOL)isAvailable;
- (void)modPow:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;
- (void)batchModPow:(const uint32_t*)bases exp:(const uint32_t*)exp mod:(const uint32_t*)mod r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;
- (void)computeAffGProofTuple:(const uint32_t*)C N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq N1:(const uint32_t*)N1 N1sq:(const uint32_t*)N1sq rN0:(const uint32_t*)rN0 r2N0:(const uint32_t*)r2N0 rN1:(const uint32_t*)rN1 r2N1:(const uint32_t*)r2N1 alphas:(const uint32_t*)alphas betasForN0:(const uint32_t*)betasForN0 betasForN1:(const uint32_t*)betasForN1 rs:(const uint32_t*)rs ss:(const uint32_t*)ss Aj_results:(uint32_t*)Aj_results Bj_results:(uint32_t*)Bj_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa;
- (void)computeDecProofTuple:(const uint32_t*)K N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq rN0:(const uint32_t*)rN0 r2N0:(const uint32_t*)r2N0 negAlphas:(const uint32_t*)negAlphas betas:(const uint32_t*)betas rs:(const uint32_t*)rs A_results:(uint32_t*)A_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa;
- (void)modInverse:(const uint32_t*)values mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;
- (void)multiply:(const uint32_t*)a b:(const uint32_t*)b results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;
- (void)batchModPowDifferentExp:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count;

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
            
            NSLog(@"MetalBigIntegerBackend: Step 4 - Loading shader library from source");
            
            NSError *libError = nil;
            
            // 优先使用预编译的metallib文件
            if (shaderPath) {
                NSLog(@"MetalBigIntegerBackend: Using provided shader path: %@", shaderPath);
                if ([[NSFileManager defaultManager] fileExistsAtPath:shaderPath]) {
                    NSURL *shaderURL = [NSURL fileURLWithPath:shaderPath];
                    self.library = [self.device newLibraryWithURL:shaderURL error:&libError];
                    if (libError) {
                        NSLog(@"MetalBigIntegerBackend: ERROR - Failed to load metallib: %@", libError.localizedDescription);
                        self.library = nil;
                    } else {
                        NSLog(@"MetalBigIntegerBackend: Successfully loaded precompiled metallib");
                    }
                } else {
                    NSLog(@"MetalBigIntegerBackend: ERROR - Provided shader path not found: %@", shaderPath);
                }
            }
            
            // 如果没有提供shaderPath或加载失败，尝试从默认位置加载
            if (!self.library) {
                NSLog(@"MetalBigIntegerBackend: Loading precompiled metallib from default locations");
                NSString *resolvedShaderPath = nil;
                
                // 尝试多个默认位置
                NSArray *possiblePaths = @[
                    [[NSBundle mainBundle] pathForResource:@"big_integer_shaders_complete" ofType:@"metallib" inDirectory:@"native/darwin"],
                    [[NSBundle mainBundle] pathForResource:@"big_integer_shaders_complete" ofType:@"metallib"],
                    [[NSBundle bundleForClass:[MetalBigIntegerBackend class]] pathForResource:@"big_integer_shaders_complete" ofType:@"metallib" inDirectory:@"native/darwin"],
                    [[NSBundle bundleForClass:[MetalBigIntegerBackend class]] pathForResource:@"big_integer_shaders_complete" ofType:@"metallib"]
                ];
                
                for (NSString *path in possiblePaths) {
                    if (path && [[NSFileManager defaultManager] fileExistsAtPath:path]) {
                        resolvedShaderPath = path;
                        break;
                    }
                }
                
                // 尝试当前工作目录
                if (!resolvedShaderPath) {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        NSString *devPath = [NSString stringWithFormat:@"%s/src/main/resources/native/darwin/big_integer_shaders_complete.metallib", cwd];
                        if ([[NSFileManager defaultManager] fileExistsAtPath:devPath]) {
                            resolvedShaderPath = devPath;
                        }
                    }
                }
                
                if (resolvedShaderPath) {
                    NSLog(@"MetalBigIntegerBackend: Loading precompiled metallib: %@", resolvedShaderPath);
                    NSURL *shaderURL = [NSURL fileURLWithPath:resolvedShaderPath];
                    self.library = [self.device newLibraryWithURL:shaderURL error:&libError];
                    if (libError) {
                        NSLog(@"MetalBigIntegerBackend: ERROR - Failed to load metallib: %@", libError.localizedDescription);
                    }
                } else {
                    NSLog(@"MetalBigIntegerBackend: ERROR - No precompiled metallib found");
                }
            }
            
            // 只有在预编译metallib加载失败时，才尝试从源文件编译
            if (!self.library) {
                NSLog(@"MetalBigIntegerBackend: Falling back to loading from source file");
                NSString *shaderSourcePath = nil;
                
                NSArray *sourcePaths = @[
                    [[NSBundle mainBundle] pathForResource:@"big_integer_shaders_complete" ofType:@"metal" inDirectory:@"native/darwin"],
                    [[NSBundle bundleForClass:[MetalBigIntegerBackend class]] pathForResource:@"big_integer_shaders_complete" ofType:@"metal" inDirectory:@"native/darwin"]
                ];
                
                for (NSString *path in sourcePaths) {
                    if (path && [[NSFileManager defaultManager] fileExistsAtPath:path]) {
                        shaderSourcePath = path;
                        break;
                    }
                }
                
                // 尝试当前工作目录
                if (!shaderSourcePath) {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        NSString *devPath = [NSString stringWithFormat:@"%s/src/main/resources/native/darwin/big_integer_shaders_complete.metal", cwd];
                        if ([[NSFileManager defaultManager] fileExistsAtPath:devPath]) {
                            shaderSourcePath = devPath;
                        }
                    }
                }
                
                if (shaderSourcePath) {
                    NSLog(@"MetalBigIntegerBackend: Loading shader from source file: %@", shaderSourcePath);
                    NSString *shaderSource = [NSString stringWithContentsOfFile:shaderSourcePath encoding:NSUTF8StringEncoding error:&libError];
                    if (shaderSource) {
                        self.library = [self.device newLibraryWithSource:shaderSource options:nil error:&libError];
                        if (libError) {
                            NSLog(@"MetalBigIntegerBackend: ERROR - Failed to create library from source: %@", libError.localizedDescription);
                        }
                    } else {
                        NSLog(@"MetalBigIntegerBackend: ERROR - Failed to read shader source file: %@", libError.localizedDescription);
                    }
                } else {
                    NSLog(@"MetalBigIntegerBackend: ERROR - No shader source file found");
                }
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
            
            id<MTLFunction> modInverseFunction = [self.library newFunctionWithName:@"modInverseKernel"];
            if (modInverseFunction) {
                NSError *error = nil;
                self.modInversePipeline = [self.device newComputePipelineStateWithFunction:modInverseFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - modInversePipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - modInverseKernel function not found");
            }
            
            id<MTLFunction> multiplyFunction = [self.library newFunctionWithName:@"multiplyKernel"];
            if (multiplyFunction) {
                NSError *error = nil;
                self.multiplyPipeline = [self.device newComputePipelineStateWithFunction:multiplyFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - multiplyPipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - multiplyKernel function not found");
            }
            
            id<MTLFunction> batchModPowDifferentExpFunction = [self.library newFunctionWithName:@"batchModPowDifferentExpKernel"];
            if (batchModPowDifferentExpFunction) {
                NSError *error = nil;
                self.batchModPowDifferentExpPipeline = [self.device newComputePipelineStateWithFunction:batchModPowDifferentExpFunction error:&error];
                if (error) {
                    NSLog(@"MetalBigIntegerBackend: ERROR - batchModPowDifferentExpPipeline creation failed: %@", error.localizedDescription);
                }
            } else {
                NSLog(@"MetalBigIntegerBackend: ERROR - batchModPowDifferentExpKernel function not found");
            }
        
        if (!self.modPowPipeline || !self.computeAffGProofTuplePipeline || !self.computeDecProofTuplePipeline || !self.batchModPowPipeline || !self.modInversePipeline || !self.multiplyPipeline || !self.batchModPowDifferentExpPipeline) {
            NSLog(@"MetalBigIntegerBackend: ERROR - Failed to create compute pipelines");
            NSLog(@"MetalBigIntegerBackend: modPowPipeline: %@, computeAffGProofTuplePipeline: %@, computeDecProofTuplePipeline: %@, batchModPowPipeline: %@, modInversePipeline: %@, multiplyPipeline: %@, batchModPowDifferentExpPipeline: %@",
                  self.modPowPipeline ? @"OK" : @"NULL",
                  self.computeAffGProofTuplePipeline ? @"OK" : @"NULL",
                  self.computeDecProofTuplePipeline ? @"OK" : @"NULL",
                  self.batchModPowPipeline ? @"OK" : @"NULL",
                  self.modInversePipeline ? @"OK" : @"NULL",
                  self.multiplyPipeline ? @"OK" : @"NULL",
                  self.batchModPowDifferentExpPipeline ? @"OK" : @"NULL");
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
    return self.device != nil && self.commandQueue != nil;
}

- (id<MTLBuffer>)ensureCachedBuffer:(id<MTLBuffer>)buffer length:(NSUInteger)length {
    if (!buffer || buffer.length < length) {
        buffer = [self.device newBufferWithLength:length options:MTLResourceStorageModeShared];
    }
    return buffer;
}

- (id<MTLBuffer>)updateCachedBuffer:(id<MTLBuffer>)buffer bytes:(const void *)bytes length:(NSUInteger)length {
    buffer = [self ensureCachedBuffer:buffer length:length];
    memcpy(buffer.contents, bytes, length);
    return buffer;
}

- (void)ensureCachedResultBufferLength:(NSUInteger)length {
    self.cachedResultsBuffer = [self ensureCachedBuffer:self.cachedResultsBuffer length:length];
}

- (void)ensureCachedAjBjBuffersLength:(NSUInteger)length {
    self.cachedAjBuffer = [self ensureCachedBuffer:self.cachedAjBuffer length:length];
    self.cachedBjBuffer = [self ensureCachedBuffer:self.cachedBjBuffer length:length];
}

- (NSUInteger)threadgroupSizeForPipeline:(id<MTLComputePipelineState>)pipeline count:(NSUInteger)count {
    if (!pipeline) {
        return 1;
    }
    NSUInteger maxThreads = pipeline.maxTotalThreadsPerThreadgroup;
    if (maxThreads == 0) {
        return 1;
    }
    NSUInteger width = pipeline.threadExecutionWidth;
    if (width == 0) {
        width = 1;
    }
    NSUInteger desired = count < maxThreads ? count : maxThreads;
    NSUInteger rounded = (desired / width) * width;
    if (rounded == 0) {
        rounded = (width <= maxThreads) ? width : 1;
    }
    return rounded;
}

- (void)modPow:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.modPowPipeline) {
            NSLog(@"MetalBigIntegerBackend: modPowPipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        
        self.cachedBasesBuffer = [self updateCachedBuffer:self.cachedBasesBuffer bytes:bases length:bufferSize];
        self.cachedExpsBuffer = [self updateCachedBuffer:self.cachedExpsBuffer bytes:exps length:bufferSize];
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        self.cachedModBuffer = [self updateCachedBuffer:self.cachedModBuffer bytes:mods length:singleBufferSize];
        self.cachedRBuffer = [self updateCachedBuffer:self.cachedRBuffer bytes:r length:singleBufferSize];
        self.cachedR2Buffer = [self updateCachedBuffer:self.cachedR2Buffer bytes:r2 length:singleBufferSize];
        self.cachedSingleBufferSize = singleBufferSize;
        [self ensureCachedResultBufferLength:bufferSize];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.modPowPipeline];
        [encoder setBuffer:self.cachedBasesBuffer offset:0 atIndex:0];
        [encoder setBuffer:self.cachedExpsBuffer offset:0 atIndex:1];
        [encoder setBuffer:self.cachedModBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedRBuffer offset:0 atIndex:3];
        [encoder setBuffer:self.cachedR2Buffer offset:0 atIndex:4];
        [encoder setBuffer:self.cachedResultsBuffer offset:0 atIndex:5];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:6];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:7];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.modPowPipeline count:count];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, self.cachedResultsBuffer.contents, bufferSize);
    }
}

- (void)batchModPow:(const uint32_t*)bases exp:(const uint32_t*)exp mod:(const uint32_t*)mod r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.batchModPowPipeline) {
            NSLog(@"MetalBigIntegerBackend: batchModPowPipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        
        self.cachedBasesBuffer = [self updateCachedBuffer:self.cachedBasesBuffer bytes:bases length:bufferSize];
        self.cachedExpBuffer = [self updateCachedBuffer:self.cachedExpBuffer bytes:exp length:singleBufferSize];
        self.cachedModBuffer = [self updateCachedBuffer:self.cachedModBuffer bytes:mod length:singleBufferSize];
        self.cachedRBuffer = [self updateCachedBuffer:self.cachedRBuffer bytes:r length:singleBufferSize];
        self.cachedR2Buffer = [self updateCachedBuffer:self.cachedR2Buffer bytes:r2 length:singleBufferSize];
        self.cachedSingleBufferSize = singleBufferSize;
        [self ensureCachedResultBufferLength:bufferSize];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.batchModPowPipeline];
        [encoder setBuffer:self.cachedBasesBuffer offset:0 atIndex:0];
        [encoder setBuffer:self.cachedExpBuffer offset:0 atIndex:1];
        [encoder setBuffer:self.cachedModBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedRBuffer offset:0 atIndex:3];
        [encoder setBuffer:self.cachedR2Buffer offset:0 atIndex:4];
        [encoder setBuffer:self.cachedResultsBuffer offset:0 atIndex:5];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:6];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:7];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.batchModPowPipeline count:count];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, self.cachedResultsBuffer.contents, bufferSize);
    }
}

- (void)computeAffGProofTuple:(const uint32_t*)C N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq N1:(const uint32_t*)N1 N1sq:(const uint32_t*)N1sq rN0:(const uint32_t*)rN0 r2N0:(const uint32_t*)r2N0 rN1:(const uint32_t*)rN1 r2N1:(const uint32_t*)r2N1 alphas:(const uint32_t*)alphas betasForN0:(const uint32_t*)betasForN0 betasForN1:(const uint32_t*)betasForN1 rs:(const uint32_t*)rs ss:(const uint32_t*)ss Aj_results:(uint32_t*)Aj_results Bj_results:(uint32_t*)Bj_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa {
    @autoreleasepool {
        if (!self.computeAffGProofTuplePipeline) {
            NSLog(@"MetalBigIntegerBackend: computeAffGProofTuplePipeline not available");
            return;
        }
        
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        NSUInteger arrayBufferSize = numLength * sizeof(uint32_t) * kappa;
        
        self.cachedCBuffer = [self updateCachedBuffer:self.cachedCBuffer bytes:C length:singleBufferSize];
        self.cachedN0Buffer = [self updateCachedBuffer:self.cachedN0Buffer bytes:N0 length:singleBufferSize];
        self.cachedN0sqBuffer = [self updateCachedBuffer:self.cachedN0sqBuffer bytes:N0sq length:singleBufferSize];
        self.cachedN1Buffer = [self updateCachedBuffer:self.cachedN1Buffer bytes:N1 length:singleBufferSize];
        self.cachedN1sqBuffer = [self updateCachedBuffer:self.cachedN1sqBuffer bytes:N1sq length:singleBufferSize];
        self.cachedRN0Buffer = [self updateCachedBuffer:self.cachedRN0Buffer bytes:rN0 length:singleBufferSize];
        self.cachedR2N0Buffer = [self updateCachedBuffer:self.cachedR2N0Buffer bytes:r2N0 length:singleBufferSize];
        self.cachedRN1Buffer = [self updateCachedBuffer:self.cachedRN1Buffer bytes:rN1 length:singleBufferSize];
        self.cachedR2N1Buffer = [self updateCachedBuffer:self.cachedR2N1Buffer bytes:r2N1 length:singleBufferSize];
        self.cachedBasesBuffer = [self updateCachedBuffer:self.cachedBasesBuffer bytes:alphas length:arrayBufferSize];
        self.cachedModsBuffer = [self updateCachedBuffer:self.cachedModsBuffer bytes:betasForN0 length:arrayBufferSize];
        self.cachedExpsBuffer = [self updateCachedBuffer:self.cachedExpsBuffer bytes:betasForN1 length:arrayBufferSize];
        self.cachedRsBuffer = [self updateCachedBuffer:self.cachedRsBuffer bytes:rs length:arrayBufferSize];
        self.cachedSsBuffer = [self updateCachedBuffer:self.cachedSsBuffer bytes:ss length:arrayBufferSize];
        [self ensureCachedAjBjBuffersLength:arrayBufferSize];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.computeAffGProofTuplePipeline];
        [encoder setBuffer:self.cachedCBuffer offset:0 atIndex:0];
        [encoder setBuffer:self.cachedN0Buffer offset:0 atIndex:1];
        [encoder setBuffer:self.cachedN0sqBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedN1Buffer offset:0 atIndex:3];
        [encoder setBuffer:self.cachedN1sqBuffer offset:0 atIndex:4];
        [encoder setBuffer:self.cachedRN0Buffer offset:0 atIndex:5];
        [encoder setBuffer:self.cachedR2N0Buffer offset:0 atIndex:6];
        [encoder setBuffer:self.cachedRN1Buffer offset:0 atIndex:7];
        [encoder setBuffer:self.cachedR2N1Buffer offset:0 atIndex:8];
        [encoder setBuffer:self.cachedBasesBuffer offset:0 atIndex:9];
        [encoder setBuffer:self.cachedModsBuffer offset:0 atIndex:10];
        [encoder setBuffer:self.cachedExpsBuffer offset:0 atIndex:11];
        [encoder setBuffer:self.cachedRsBuffer offset:0 atIndex:12];
        [encoder setBuffer:self.cachedSsBuffer offset:0 atIndex:13];
        [encoder setBuffer:self.cachedAjBuffer offset:0 atIndex:14];
        [encoder setBuffer:self.cachedBjBuffer offset:0 atIndex:15];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:16];
        [encoder setBytes:&kappa length:sizeof(uint32_t) atIndex:17];
        
        MTLSize gridSize = MTLSizeMake(kappa, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.computeAffGProofTuplePipeline count:kappa];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(Aj_results, self.cachedAjBuffer.contents, arrayBufferSize);
        memcpy(Bj_results, self.cachedBjBuffer.contents, arrayBufferSize);
    }
}

- (void)computeDecProofTuple:(const uint32_t*)K N0:(const uint32_t*)N0 N0sq:(const uint32_t*)N0sq rN0:(const uint32_t*)rN0 r2N0:(const uint32_t*)r2N0 negAlphas:(const uint32_t*)negAlphas betas:(const uint32_t*)betas rs:(const uint32_t*)rs A_results:(uint32_t*)A_results numLength:(uint32_t)numLength kappa:(uint32_t)kappa {
    @autoreleasepool {
        if (!self.computeDecProofTuplePipeline) {
            NSLog(@"MetalBigIntegerBackend: computeDecProofTuplePipeline not available");
            return;
        }
        
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        NSUInteger arrayBufferSize = numLength * sizeof(uint32_t) * kappa;
        
        self.cachedKBuffer = [self updateCachedBuffer:self.cachedKBuffer bytes:K length:singleBufferSize];
        self.cachedN0Buffer = [self updateCachedBuffer:self.cachedN0Buffer bytes:N0 length:singleBufferSize];
        self.cachedN0sqBuffer = [self updateCachedBuffer:self.cachedN0sqBuffer bytes:N0sq length:singleBufferSize];
        self.cachedRN0Buffer = [self updateCachedBuffer:self.cachedRN0Buffer bytes:rN0 length:singleBufferSize];
        self.cachedR2N0Buffer = [self updateCachedBuffer:self.cachedR2N0Buffer bytes:r2N0 length:singleBufferSize];
        self.cachedBasesBuffer = [self updateCachedBuffer:self.cachedBasesBuffer bytes:negAlphas length:arrayBufferSize];
        self.cachedExpsBuffer = [self updateCachedBuffer:self.cachedExpsBuffer bytes:betas length:arrayBufferSize];
        self.cachedModsBuffer = [self updateCachedBuffer:self.cachedModsBuffer bytes:rs length:arrayBufferSize];
        [self ensureCachedResultBufferLength:arrayBufferSize];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.computeDecProofTuplePipeline];
        [encoder setBuffer:self.cachedKBuffer offset:0 atIndex:0];
        [encoder setBuffer:self.cachedN0Buffer offset:0 atIndex:1];
        [encoder setBuffer:self.cachedN0sqBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedRN0Buffer offset:0 atIndex:3];
        [encoder setBuffer:self.cachedR2N0Buffer offset:0 atIndex:4];
        [encoder setBuffer:self.cachedBasesBuffer offset:0 atIndex:5];
        [encoder setBuffer:self.cachedExpsBuffer offset:0 atIndex:6];
        [encoder setBuffer:self.cachedModsBuffer offset:0 atIndex:7];
        [encoder setBuffer:self.cachedResultsBuffer offset:0 atIndex:8];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:9];
        [encoder setBytes:&kappa length:sizeof(uint32_t) atIndex:10];
        
        MTLSize gridSize = MTLSizeMake(kappa, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.computeDecProofTuplePipeline count:kappa];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(A_results, self.cachedResultsBuffer.contents, arrayBufferSize);
    }
}

- (void)modInverse:(const uint32_t*)values mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.modInversePipeline) {
            NSLog(@"MetalBigIntegerBackend: modInversePipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        
        id<MTLBuffer> valuesBuffer = [self.device newBufferWithBytes:values length:bufferSize options:MTLResourceStorageModeShared];
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        self.cachedModBuffer = [self updateCachedBuffer:self.cachedModBuffer bytes:mods length:singleBufferSize];
        self.cachedRBuffer = [self updateCachedBuffer:self.cachedRBuffer bytes:r length:singleBufferSize];
        self.cachedR2Buffer = [self updateCachedBuffer:self.cachedR2Buffer bytes:r2 length:singleBufferSize];
        self.cachedSingleBufferSize = singleBufferSize;
        id<MTLBuffer> resultsBuffer = [self.device newBufferWithLength:bufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.modInversePipeline];
        [encoder setBuffer:valuesBuffer offset:0 atIndex:0];
        [encoder setBuffer:self.cachedModBuffer offset:0 atIndex:1];
        [encoder setBuffer:self.cachedRBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedR2Buffer offset:0 atIndex:3];
        [encoder setBuffer:resultsBuffer offset:0 atIndex:4];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:5];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:6];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.modInversePipeline count:count];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, resultsBuffer.contents, bufferSize);
    }
}

- (void)multiply:(const uint32_t*)a b:(const uint32_t*)b results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.multiplyPipeline) {
            NSLog(@"MetalBigIntegerBackend: multiplyPipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        
        id<MTLBuffer> aBuffer = [self.device newBufferWithBytes:a length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> bBuffer = [self.device newBufferWithBytes:b length:bufferSize options:MTLResourceStorageModeShared];
        // Multiply returns 2 * numLength words per result
        NSUInteger resultsBufferSize = bufferSize * 2;
        id<MTLBuffer> resultsBuffer = [self.device newBufferWithLength:resultsBufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.multiplyPipeline];
        [encoder setBuffer:aBuffer offset:0 atIndex:0];
        [encoder setBuffer:bBuffer offset:0 atIndex:1];
        [encoder setBuffer:resultsBuffer offset:0 atIndex:2];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:3];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:4];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.multiplyPipeline count:count];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, resultsBuffer.contents, resultsBufferSize);
    }
}

- (void)batchModPowDifferentExp:(const uint32_t*)bases exps:(const uint32_t*)exps mods:(const uint32_t*)mods r:(const uint32_t*)r r2:(const uint32_t*)r2 results:(uint32_t*)results numLength:(uint32_t)numLength count:(uint32_t)count {
    @autoreleasepool {
        if (!self.batchModPowDifferentExpPipeline) {
            NSLog(@"MetalBigIntegerBackend: batchModPowDifferentExpPipeline not available");
            return;
        }
        
        NSUInteger bufferSize = numLength * sizeof(uint32_t) * count;
        NSUInteger singleBufferSize = numLength * sizeof(uint32_t);
        
        id<MTLBuffer> basesBuffer = [self.device newBufferWithBytes:bases length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> expsBuffer = [self.device newBufferWithBytes:exps length:bufferSize options:MTLResourceStorageModeShared];
        id<MTLBuffer> modsBuffer = [self.device newBufferWithBytes:mods length:bufferSize options:MTLResourceStorageModeShared];
        self.cachedRBuffer = [self updateCachedBuffer:self.cachedRBuffer bytes:r length:singleBufferSize];
        self.cachedR2Buffer = [self updateCachedBuffer:self.cachedR2Buffer bytes:r2 length:singleBufferSize];
        self.cachedSingleBufferSize = singleBufferSize;
        id<MTLBuffer> resultsBuffer = [self.device newBufferWithLength:bufferSize options:MTLResourceStorageModeShared];
        
        id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:self.batchModPowDifferentExpPipeline];
        [encoder setBuffer:basesBuffer offset:0 atIndex:0];
        [encoder setBuffer:expsBuffer offset:0 atIndex:1];
        [encoder setBuffer:modsBuffer offset:0 atIndex:2];
        [encoder setBuffer:self.cachedRBuffer offset:0 atIndex:3];
        [encoder setBuffer:self.cachedR2Buffer offset:0 atIndex:4];
        [encoder setBuffer:resultsBuffer offset:0 atIndex:5];
        [encoder setBytes:&numLength length:sizeof(uint32_t) atIndex:6];
        [encoder setBytes:&count length:sizeof(uint32_t) atIndex:7];
        
        MTLSize gridSize = MTLSizeMake(count, 1, 1);
        NSUInteger threadGroupSize = [self threadgroupSizeForPipeline:self.batchModPowDifferentExpPipeline count:count];
        MTLSize threadgroupSize = MTLSizeMake(threadGroupSize, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        memcpy(results, resultsBuffer.contents, bufferSize);
    }
}

@end

// JNI Implementation
JNIEXPORT jlong JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeInit
  (JNIEnv *env, jobject obj) {
    @autoreleasepool {
        MetalBigIntegerBackend *backend = [[MetalBigIntegerBackend alloc] init];
        if (backend && [backend isAvailable]) {
            return (jlong)(uintptr_t)CFBridgingRetain(backend);
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
            return (jlong)(uintptr_t)CFBridgingRetain(backend);
        }
        return 0;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeDestroy
  (JNIEnv *env, jobject obj, jlong handle) {
    @autoreleasepool {
        if (handle != 0) {
            MetalBigIntegerBackend *backend = (__bridge_transfer MetalBigIntegerBackend *)(void *)handle;
            backend = nil;
        }
    }
}

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeIsAvailable
  (JNIEnv *env, jobject obj, jlong handle) {
    @autoreleasepool {
        if (handle == 0) return JNI_FALSE;
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        return [backend isAvailable] ? JNI_TRUE : JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModPow
  (JNIEnv *env, jobject obj, jlong handle, jintArray bases, jintArray exps, jintArray mods, jintArray r, jintArray r2, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jsize basesLen = (*env)->GetArrayLength(env, bases);
        jsize expsLen = (*env)->GetArrayLength(env, exps);
        jsize modsLen = (*env)->GetArrayLength(env, mods);
        jsize rLen = (*env)->GetArrayLength(env, r);
        jsize r2Len = (*env)->GetArrayLength(env, r2);
        jsize resultsLen = (*env)->GetArrayLength(env, results);
        
        if (basesLen != expsLen || basesLen != modsLen || rLen != numLength || r2Len != numLength || basesLen != resultsLen) {
            return;
        }
        
        jint *basesPtr = (*env)->GetIntArrayElements(env, bases, NULL);
        jint *expsPtr = (*env)->GetIntArrayElements(env, exps, NULL);
        jint *modsPtr = (*env)->GetIntArrayElements(env, mods, NULL);
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (basesPtr && expsPtr && modsPtr && rPtr && r2Ptr && resultsPtr) {
            [backend modPow:(const uint32_t*)basesPtr 
                       exps:(const uint32_t*)expsPtr 
                       mods:(const uint32_t*)modsPtr 
                          r:(const uint32_t*)rPtr
                         r2:(const uint32_t*)r2Ptr
                    results:(uint32_t*)resultsPtr 
                  numLength:(uint32_t)numLength 
                      count:(uint32_t)count];
        }
        
        if (basesPtr) (*env)->ReleaseIntArrayElements(env, bases, basesPtr, JNI_ABORT);
        if (expsPtr) (*env)->ReleaseIntArrayElements(env, exps, expsPtr, JNI_ABORT);
        if (modsPtr) (*env)->ReleaseIntArrayElements(env, mods, modsPtr, JNI_ABORT);
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModPowDirect
  (JNIEnv *env, jobject obj, jlong handle, jobject basesBuffer, jobject expsBuffer, jobject modsBuffer, jintArray r, jintArray r2, jobject resultsBuffer, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return JNI_FALSE;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        void *basesPtr = (*env)->GetDirectBufferAddress(env, basesBuffer);
        void *expsPtr = (*env)->GetDirectBufferAddress(env, expsBuffer);
        void *modsPtr = (*env)->GetDirectBufferAddress(env, modsBuffer);
        void *resultsPtr = (*env)->GetDirectBufferAddress(env, resultsBuffer);
        if (!basesPtr || !expsPtr || !modsPtr || !resultsPtr) {
            return JNI_FALSE;
        }
        
        jlong basesCap = (*env)->GetDirectBufferCapacity(env, basesBuffer);
        jlong expsCap = (*env)->GetDirectBufferCapacity(env, expsBuffer);
        jlong modsCap = (*env)->GetDirectBufferCapacity(env, modsBuffer);
        jlong resultsCap = (*env)->GetDirectBufferCapacity(env, resultsBuffer);
        
        jsize rLen = (*env)->GetArrayLength(env, r);
        jsize r2Len = (*env)->GetArrayLength(env, r2);
        if (rLen != numLength || r2Len != numLength) {
            return JNI_FALSE;
        }
        
        size_t bufferSize = (size_t)numLength * sizeof(uint32_t) * (size_t)count;
        if (basesCap < (jlong)bufferSize || expsCap < (jlong)bufferSize || modsCap < (jlong)bufferSize || resultsCap < (jlong)bufferSize) {
            return JNI_FALSE;
        }
        
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        
        if (rPtr && r2Ptr) {
            [backend modPow:(const uint32_t*)basesPtr
                       exps:(const uint32_t*)expsPtr
                       mods:(const uint32_t*)modsPtr
                          r:(const uint32_t*)rPtr
                         r2:(const uint32_t*)r2Ptr
                    results:(uint32_t*)resultsPtr
                  numLength:(uint32_t)numLength
                      count:(uint32_t)count];
        }
        
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        return (rPtr && r2Ptr) ? JNI_TRUE : JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeBatchModPow
  (JNIEnv *env, jobject obj, jlong handle, jintArray bases, jintArray exp, jintArray mod, jintArray r, jintArray r2, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jsize basesLen = (*env)->GetArrayLength(env, bases);
        jsize expLen = (*env)->GetArrayLength(env, exp);
        jsize modLen = (*env)->GetArrayLength(env, mod);
        jsize rLen = (*env)->GetArrayLength(env, r);
        jsize r2Len = (*env)->GetArrayLength(env, r2);
        jsize resultsLen = (*env)->GetArrayLength(env, results);
        
        if (basesLen != resultsLen || expLen != numLength || modLen != numLength || rLen != numLength || r2Len != numLength) {
            return;
        }
        
        jint *basesPtr = (*env)->GetIntArrayElements(env, bases, NULL);
        jint *expPtr = (*env)->GetIntArrayElements(env, exp, NULL);
        jint *modPtr = (*env)->GetIntArrayElements(env, mod, NULL);
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (basesPtr && expPtr && modPtr && rPtr && r2Ptr && resultsPtr) {
            [backend batchModPow:(const uint32_t*)basesPtr
                             exp:(const uint32_t*)expPtr
                             mod:(const uint32_t*)modPtr
                               r:(const uint32_t*)rPtr
                              r2:(const uint32_t*)r2Ptr
                         results:(uint32_t*)resultsPtr
                       numLength:(uint32_t)numLength
                           count:(uint32_t)count];
        }
        
        if (basesPtr) (*env)->ReleaseIntArrayElements(env, bases, basesPtr, JNI_ABORT);
        if (expPtr) (*env)->ReleaseIntArrayElements(env, exp, expPtr, JNI_ABORT);
        if (modPtr) (*env)->ReleaseIntArrayElements(env, mod, modPtr, JNI_ABORT);
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeComputeAffGProofTuple
  (JNIEnv *env, jobject obj, jlong handle, jintArray C, jintArray N0, jintArray N0sq, jintArray N1, jintArray N1sq,
            jintArray rN0, jintArray r2N0, jintArray rN1, jintArray r2N1,
            jintArray alphas, jintArray betasForN0, jintArray betasForN1, jintArray rs, jintArray ss,
            jintArray Aj, jintArray Bj, jint numLength, jint kappa) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jint *CPtr = (*env)->GetIntArrayElements(env, C, NULL);
        jint *N0Ptr = (*env)->GetIntArrayElements(env, N0, NULL);
        jint *N0sqPtr = (*env)->GetIntArrayElements(env, N0sq, NULL);
        jint *N1Ptr = (*env)->GetIntArrayElements(env, N1, NULL);
        jint *N1sqPtr = (*env)->GetIntArrayElements(env, N1sq, NULL);
        jint *rN0Ptr = (*env)->GetIntArrayElements(env, rN0, NULL);
        jint *r2N0Ptr = (*env)->GetIntArrayElements(env, r2N0, NULL);
        jint *rN1Ptr = (*env)->GetIntArrayElements(env, rN1, NULL);
        jint *r2N1Ptr = (*env)->GetIntArrayElements(env, r2N1, NULL);
        jint *alphasPtr = (*env)->GetIntArrayElements(env, alphas, NULL);
        jint *betasForN0Ptr = (*env)->GetIntArrayElements(env, betasForN0, NULL);
        jint *betasForN1Ptr = (*env)->GetIntArrayElements(env, betasForN1, NULL);
        jint *rsPtr = (*env)->GetIntArrayElements(env, rs, NULL);
        jint *ssPtr = (*env)->GetIntArrayElements(env, ss, NULL);
        jint *AjPtr = (*env)->GetIntArrayElements(env, Aj, NULL);
        jint *BjPtr = (*env)->GetIntArrayElements(env, Bj, NULL);
        
        if (CPtr && N0Ptr && N0sqPtr && N1Ptr && N1sqPtr && rN0Ptr && r2N0Ptr && rN1Ptr && r2N1Ptr && alphasPtr && betasForN0Ptr && betasForN1Ptr && rsPtr && ssPtr && AjPtr && BjPtr) {
            [backend computeAffGProofTuple:(const uint32_t*)CPtr
                                       N0:(const uint32_t*)N0Ptr
                                     N0sq:(const uint32_t*)N0sqPtr
                                       N1:(const uint32_t*)N1Ptr
                                     N1sq:(const uint32_t*)N1sqPtr
                                       rN0:(const uint32_t*)rN0Ptr
                                     r2N0:(const uint32_t*)r2N0Ptr
                                       rN1:(const uint32_t*)rN1Ptr
                                     r2N1:(const uint32_t*)r2N1Ptr
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
        if (rN0Ptr) (*env)->ReleaseIntArrayElements(env, rN0, rN0Ptr, JNI_ABORT);
        if (r2N0Ptr) (*env)->ReleaseIntArrayElements(env, r2N0, r2N0Ptr, JNI_ABORT);
        if (rN1Ptr) (*env)->ReleaseIntArrayElements(env, rN1, rN1Ptr, JNI_ABORT);
        if (r2N1Ptr) (*env)->ReleaseIntArrayElements(env, r2N1, r2N1Ptr, JNI_ABORT);
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
            jintArray rN0, jintArray r2N0,
            jintArray negAlphas, jintArray betas, jintArray rs,
            jintArray A, jint numLength, jint kappa) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jint *KPtr = (*env)->GetIntArrayElements(env, K, NULL);
        jint *N0Ptr = (*env)->GetIntArrayElements(env, N0, NULL);
        jint *N0sqPtr = (*env)->GetIntArrayElements(env, N0sq, NULL);
        jint *rN0Ptr = (*env)->GetIntArrayElements(env, rN0, NULL);
        jint *r2N0Ptr = (*env)->GetIntArrayElements(env, r2N0, NULL);
        jint *negAlphasPtr = (*env)->GetIntArrayElements(env, negAlphas, NULL);
        jint *betasPtr = (*env)->GetIntArrayElements(env, betas, NULL);
        jint *rsPtr = (*env)->GetIntArrayElements(env, rs, NULL);
        jint *APtr = (*env)->GetIntArrayElements(env, A, NULL);
        
        if (KPtr && N0Ptr && N0sqPtr && rN0Ptr && r2N0Ptr && negAlphasPtr && betasPtr && rsPtr && APtr) {
            [backend computeDecProofTuple:(const uint32_t*)KPtr
                                        N0:(const uint32_t*)N0Ptr
                                      N0sq:(const uint32_t*)N0sqPtr
                                      rN0:(const uint32_t*)rN0Ptr
                                    r2N0:(const uint32_t*)r2N0Ptr
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
        if (rN0Ptr) (*env)->ReleaseIntArrayElements(env, rN0, rN0Ptr, JNI_ABORT);
        if (r2N0Ptr) (*env)->ReleaseIntArrayElements(env, r2N0, r2N0Ptr, JNI_ABORT);
        if (negAlphasPtr) (*env)->ReleaseIntArrayElements(env, negAlphas, negAlphasPtr, JNI_ABORT);
        if (betasPtr) (*env)->ReleaseIntArrayElements(env, betas, betasPtr, JNI_ABORT);
        if (rsPtr) (*env)->ReleaseIntArrayElements(env, rs, rsPtr, JNI_ABORT);
        if (APtr) (*env)->ReleaseIntArrayElements(env, A, APtr, 0);
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModInverse
  (JNIEnv *env, jobject obj, jlong handle, jintArray values, jintArray mods, jintArray r, jintArray r2, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jint *valuesPtr = (*env)->GetIntArrayElements(env, values, NULL);
        jint *modsPtr = (*env)->GetIntArrayElements(env, mods, NULL);
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (valuesPtr && modsPtr && rPtr && r2Ptr && resultsPtr) {
            [backend modInverse:(const uint32_t*)valuesPtr
                           mods:(const uint32_t*)modsPtr
                             r:(const uint32_t*)rPtr
                            r2:(const uint32_t*)r2Ptr
                         results:(uint32_t*)resultsPtr
                       numLength:(uint32_t)numLength
                           count:(uint32_t)count];
        }
        
        if (valuesPtr) (*env)->ReleaseIntArrayElements(env, values, valuesPtr, JNI_ABORT);
        if (modsPtr) (*env)->ReleaseIntArrayElements(env, mods, modsPtr, JNI_ABORT);
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeModInverseDirect
  (JNIEnv *env, jobject obj, jlong handle, jobject valuesBuffer, jobject modsBuffer, jintArray r, jintArray r2, jobject resultsBuffer, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return JNI_FALSE;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        void *valuesPtr = (*env)->GetDirectBufferAddress(env, valuesBuffer);
        void *modsPtr = (*env)->GetDirectBufferAddress(env, modsBuffer);
        void *resultsPtr = (*env)->GetDirectBufferAddress(env, resultsBuffer);
        if (!valuesPtr || !modsPtr || !resultsPtr) {
            return JNI_FALSE;
        }
        
        jlong valuesCap = (*env)->GetDirectBufferCapacity(env, valuesBuffer);
        jlong modsCap = (*env)->GetDirectBufferCapacity(env, modsBuffer);
        jlong resultsCap = (*env)->GetDirectBufferCapacity(env, resultsBuffer);
        
        jsize rLen = (*env)->GetArrayLength(env, r);
        jsize r2Len = (*env)->GetArrayLength(env, r2);
        if (rLen != numLength || r2Len != numLength) {
            return JNI_FALSE;
        }
        
        size_t bufferSize = (size_t)numLength * sizeof(uint32_t) * (size_t)count;
        if (valuesCap < (jlong)bufferSize || modsCap < (jlong)bufferSize || resultsCap < (jlong)bufferSize) {
            return JNI_FALSE;
        }
        
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        
        if (rPtr && r2Ptr) {
            [backend modInverse:(const uint32_t*)valuesPtr
                           mods:(const uint32_t*)modsPtr
                             r:(const uint32_t*)rPtr
                            r2:(const uint32_t*)r2Ptr
                         results:(uint32_t*)resultsPtr
                       numLength:(uint32_t)numLength
                           count:(uint32_t)count];
        }
        
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        return (rPtr && r2Ptr) ? JNI_TRUE : JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeMultiply
  (JNIEnv *env, jobject obj, jlong handle, jintArray a, jintArray b, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jint *aPtr = (*env)->GetIntArrayElements(env, a, NULL);
        jint *bPtr = (*env)->GetIntArrayElements(env, b, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (aPtr && bPtr && resultsPtr) {
            [backend multiply:(const uint32_t*)aPtr
                           b:(const uint32_t*)bPtr
                       results:(uint32_t*)resultsPtr
                     numLength:(uint32_t)numLength
                         count:(uint32_t)count];
        }
        
        if (aPtr) (*env)->ReleaseIntArrayElements(env, a, aPtr, JNI_ABORT);
        if (bPtr) (*env)->ReleaseIntArrayElements(env, b, bPtr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}

JNIEXPORT jboolean JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeMultiplyDirect
  (JNIEnv *env, jobject obj, jlong handle, jobject aBuffer, jobject bBuffer, jobject resultsBuffer, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return JNI_FALSE;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        void *aPtr = (*env)->GetDirectBufferAddress(env, aBuffer);
        void *bPtr = (*env)->GetDirectBufferAddress(env, bBuffer);
        void *resultsPtr = (*env)->GetDirectBufferAddress(env, resultsBuffer);
        if (!aPtr || !bPtr || !resultsPtr) {
            return JNI_FALSE;
        }
        
        jlong aCap = (*env)->GetDirectBufferCapacity(env, aBuffer);
        jlong bCap = (*env)->GetDirectBufferCapacity(env, bBuffer);
        jlong resultsCap = (*env)->GetDirectBufferCapacity(env, resultsBuffer);
        
        size_t bufferSize = (size_t)numLength * sizeof(uint32_t) * (size_t)count;
        size_t resultsSize = bufferSize * 2;
        if (aCap < (jlong)bufferSize || bCap < (jlong)bufferSize || resultsCap < (jlong)resultsSize) {
            return JNI_FALSE;
        }
        
        [backend multiply:(const uint32_t*)aPtr
                       b:(const uint32_t*)bPtr
                   results:(uint32_t*)resultsPtr
                 numLength:(uint32_t)numLength
                     count:(uint32_t)count];
        
        return JNI_TRUE;
    }
}

JNIEXPORT void JNICALL Java_com_example_mpc_cggmp_util_MetalBigIntegerBackend_nativeBatchModPowDifferentExp
  (JNIEnv *env, jobject obj, jlong handle, jintArray bases, jintArray exps, jintArray mods, jintArray r, jintArray r2, jintArray results, jint numLength, jint count) {
    @autoreleasepool {
        if (handle == 0) return;
        
        MetalBigIntegerBackend *backend = (__bridge MetalBigIntegerBackend *)(void *)handle;
        
        jint *basesPtr = (*env)->GetIntArrayElements(env, bases, NULL);
        jint *expsPtr = (*env)->GetIntArrayElements(env, exps, NULL);
        jint *modsPtr = (*env)->GetIntArrayElements(env, mods, NULL);
        jint *rPtr = (*env)->GetIntArrayElements(env, r, NULL);
        jint *r2Ptr = (*env)->GetIntArrayElements(env, r2, NULL);
        jint *resultsPtr = (*env)->GetIntArrayElements(env, results, NULL);
        
        if (basesPtr && expsPtr && modsPtr && rPtr && r2Ptr && resultsPtr) {
            [backend batchModPowDifferentExp:(const uint32_t*)basesPtr
                                       exps:(const uint32_t*)expsPtr
                                       mods:(const uint32_t*)modsPtr
                                          r:(const uint32_t*)rPtr
                                         r2:(const uint32_t*)r2Ptr
                                    results:(uint32_t*)resultsPtr
                                  numLength:(uint32_t)numLength
                                      count:(uint32_t)count];
        }
        
        if (basesPtr) (*env)->ReleaseIntArrayElements(env, bases, basesPtr, JNI_ABORT);
        if (expsPtr) (*env)->ReleaseIntArrayElements(env, exps, expsPtr, JNI_ABORT);
        if (modsPtr) (*env)->ReleaseIntArrayElements(env, mods, modsPtr, JNI_ABORT);
        if (rPtr) (*env)->ReleaseIntArrayElements(env, r, rPtr, JNI_ABORT);
        if (r2Ptr) (*env)->ReleaseIntArrayElements(env, r2, r2Ptr, JNI_ABORT);
        if (resultsPtr) (*env)->ReleaseIntArrayElements(env, results, resultsPtr, 0);
    }
}
