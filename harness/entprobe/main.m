//
//  entprobe — entitlement-variant delta probe for the GPU/IOMFB selectors that
//  answered kIOReturnNotPrivileged (0xE00002C1) in the svcreenum ladder.
//
//  Design contract (deliberately minimal):
//    * one IOExternalMethod call per (service, type, selector)
//    * NO caller-supplied input: scalarInputCount = 0, structureInput = NULL/0
//    * output capacity is maxed (16 x u64 / 4096 B) so that IOKit's
//      "scalarOutputCount >= dispatch->checkScalarOutputCount" test never fires
//      and the call reaches the handler's own privilege gate
//    * only the return code is recorded
//
//  Emits JSON lines on stdout, one object per line:
//    {"k":"@meta", ...}                             build/service stamp
//    {"k":"@e","svc":"IOMobileFramebuffer","sel":23,"kr":-536870207,"krh":"0xE00002C1"}
//
//  Compile:
//    xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=16.0 -fobjc-arc \
//      main.m -o out.bin -framework Foundation -framework UIKit -framework IOKit \
//      -framework CoreFoundation
//

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach_error.h>
#include <stdio.h>

enum { kOutScalarCap = 16, kOutStructCap = 4096 };

static void emit(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void emit(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    fputs(s.UTF8String, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

// one selector, no input, max output capacity, record kr only
static void probe(io_connect_t conn, const char *svc, uint32_t type, uint32_t sel) {
    uint64_t out64[kOutScalarCap];
    uint32_t out64cnt = kOutScalarCap;
    uint8_t  outst[kOutStructCap];
    size_t   outstsz = kOutStructCap;
    memset(out64, 0, sizeof(out64));
    memset(outst, 0, sizeof(outst));

    kern_return_t kr = IOConnectCallMethod(conn, sel,
                                          NULL, 0,        // no scalar input
                                          NULL, 0,        // no struct input
                                          out64, &out64cnt,
                                          outst, &outstsz);
    emit(@"{\"k\":\"@e\",\"svc\":\"%s\",\"type\":%u,\"sel\":%u,\"kr\":%d,\"krh\":\"0x%08X\"}",
         svc, type, sel, (int32_t)kr, (uint32_t)kr);
}

typedef struct { const char *svc; uint32_t type; const uint32_t *sels; size_t n; } target_t;

int main(int argc, char **argv) {
    @autoreleasepool {
        static const uint32_t mfb_sels[]  = { 23, 78, 83, 86, 100 };
        static const uint32_t agx_sels[]  = { 0, 2 };
        static const uint32_t isf_sels[]  = { 30 };
        static const target_t targets[] = {
            { "IOMobileFramebuffer", 0,  mfb_sels, sizeof(mfb_sels) / sizeof(mfb_sels[0]) },
            { "AppleCLCD2",          0,  mfb_sels, sizeof(mfb_sels) / sizeof(mfb_sels[0]) },
            { "AGXAcceleratorG18P",  33, agx_sels, sizeof(agx_sels) / sizeof(agx_sels[0]) },
            { "IOSurfaceRoot",       0,  isf_sels, sizeof(isf_sels) / sizeof(isf_sels[0]) },
        };

        emit(@"{\"k\":\"@meta\",\"probe\":\"entprobe\",\"build\":\"%s %s\",\"ios\":\"%@\",\"model\":\"%@\",\"outscalarcap\":%u,\"outstructcap\":%zu,\"inputpolicy\":\"none\"}",
             __DATE__, __TIME__,
             [[NSProcessInfo processInfo] operatingSystemVersionString],
             [[NSProcessInfo processInfo] environment][@"SIMULATOR_MODEL_IDENTIFIER"] ?: @"device",
             (unsigned)kOutScalarCap, (unsigned long)kOutStructCap);

        for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
            const target_t *t = &targets[i];
            io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                           IOServiceMatching(t->svc));
            if (!svc) {
                emit(@"{\"k\":\"@open\",\"svc\":\"%s\",\"type\":%u,\"kr\":-1,\"krh\":\"0xFFFFFFFF\",\"note\":\"noservice\"}",
                     t->svc, t->type);
                continue;
            }
            io_connect_t conn = IO_OBJECT_NULL;
            kern_return_t okr = IOServiceOpen(svc, mach_task_self(), t->type, &conn);
            IOObjectRelease(svc);
            emit(@"{\"k\":\"@open\",\"svc\":\"%s\",\"type\":%u,\"kr\":%d,\"krh\":\"0x%08X\"}",
                 t->svc, t->type, (int32_t)okr, (uint32_t)okr);
            if (okr != KERN_SUCCESS || conn == IO_OBJECT_NULL) continue;

            for (size_t j = 0; j < t->n; j++) probe(conn, t->svc, t->type, t->sels[j]);
            IOServiceClose(conn);
        }
    }
    return 0;
}
