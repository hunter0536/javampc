/**
 * Simple Metal Test Program
 * Tests if Metal is working correctly
 */

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"=== Metal Test Program Started ===");
        
        // Step 1: Create Metal device
        NSLog(@"Step 1: Creating Metal device...");
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            NSLog(@"ERROR: Metal is not supported on this device");
            return 1;
        }
        NSLog(@"SUCCESS: Metal device created: %@", device.name);
        
        // Step 2: Create command queue
        NSLog(@"Step 2: Creating command queue...");
        id<MTLCommandQueue> commandQueue = [device newCommandQueue];
        if (!commandQueue) {
            NSLog(@"ERROR: Failed to create command queue");
            return 1;
        }
        NSLog(@"SUCCESS: Command queue created");
        
        // Step 3: Create a simple shader
        NSLog(@"Step 3: Creating simple shader...");
        NSString *shaderSource = @""
        "#include <metal_stdlib>\n"
        "using namespace metal;\n"
        "\n"
        "kernel void simpleKernel(device uint* output [[buffer(0)]], uint id [[thread_position_in_grid]]) {\n"
        "    output[id] = id;\n"
        "}\n";
        
        NSError *error = nil;
        id<MTLLibrary> library = [device newLibraryWithSource:shaderSource options:nil error:&error];
        if (!library) {
            NSLog(@"ERROR: Failed to create shader library: %@", error.localizedDescription);
            return 1;
        }
        NSLog(@"SUCCESS: Shader library created");
        
        // Step 4: Create kernel function
        NSLog(@"Step 4: Creating kernel function...");
        id<MTLFunction> kernelFunction = [library newFunctionWithName:@"simpleKernel"];
        if (!kernelFunction) {
            NSLog(@"ERROR: Failed to create kernel function");
            return 1;
        }
        NSLog(@"SUCCESS: Kernel function created");
        
        // Step 5: Create compute pipeline
        NSLog(@"Step 5: Creating compute pipeline...");
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:kernelFunction error:&error];
        if (!pipeline) {
            NSLog(@"ERROR: Failed to create compute pipeline: %@", error.localizedDescription);
            return 1;
        }
        NSLog(@"SUCCESS: Compute pipeline created");
        
        // Step 6: Create buffer
        NSLog(@"Step 6: Creating buffer...");
        NSUInteger bufferSize = 1024;
        id<MTLBuffer> buffer = [device newBufferWithLength:bufferSize options:MTLResourceStorageModeShared];
        if (!buffer) {
            NSLog(@"ERROR: Failed to create buffer");
            return 1;
        }
        NSLog(@"SUCCESS: Buffer created");
        
        // Step 7: Execute kernel
        NSLog(@"Step 7: Executing kernel...");
        id<MTLCommandBuffer> commandBuffer = [commandQueue commandBuffer];
        id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
        
        [encoder setComputePipelineState:pipeline];
        [encoder setBuffer:buffer offset:0 atIndex:0];
        
        MTLSize gridSize = MTLSizeMake(256, 1, 1);
        MTLSize threadgroupSize = MTLSizeMake(256, 1, 1);
        
        [encoder dispatchThreads:gridSize threadsPerThreadgroup:threadgroupSize];
        [encoder endEncoding];
        
        [commandBuffer commit];
        [commandBuffer waitUntilCompleted];
        
        NSLog(@"SUCCESS: Kernel executed");
        
        // Step 8: Verify results
        NSLog(@"Step 8: Verifying results...");
        uint32_t *data = (uint32_t *)buffer.contents;
        BOOL success = YES;
        for (int i = 0; i < 10; i++) {
            if (data[i] != i) {
                NSLog(@"ERROR: Verification failed at index %d: expected %d, got %d", i, i, data[i]);
                success = NO;
                break;
            }
        }
        
        if (success) {
            NSLog(@"SUCCESS: All tests passed!");
            NSLog(@"=== Metal Test Program Completed Successfully ===");
            return 0;
        } else {
            NSLog(@"ERROR: Tests failed");
            return 1;
        }
    }
}
