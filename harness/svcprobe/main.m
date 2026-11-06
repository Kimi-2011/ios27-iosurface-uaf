// main.m — IOKit 服务可打开性矩阵（只回答一个问题：本 app 能开哪些服务、什么 type、拒绝码是什么）
//
// 对名字表里每个名字：
//   IOServiceGetMatchingService -> found?
//   对 type 0..3 依次 IOServiceOpen，成功即 Close 并停止试更大 type
// 每行一个 JSON，落 tmp/svcprobe.ndjson，同时 fprintf(stderr)。
//
// 指纹（装之前 strings 校验）: SVCPROBE-20261101-matrix-9f4a21
//
// 不改 harness/israce/main.m。构建/签名/安装/取回见 run.sh。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

static const char *kFingerprint = "SVCPROBE-20261101-matrix-9f4a21";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

static FILE *gLog = NULL;
static FILE *gNd  = NULL;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

// ---------------- 名字表（顺序即探测顺序） ----------------
static const char *kNames[] = {
    "IOSurfaceRoot",
    "IOAccelerator",
    "AGXAcceleratorG18P",
    "IOGPUDevice",
    "IOHIDSystem",
    "IOHIDEventService",
    "AppleH13CamIn",
    "AppleJPEGDriver",
    "AppleM2ScalerCSCDriver",
    "IOMobileFramebuffer",
    "IOMobileFramebufferShim",
    "AppleCLCD2",
    "AppleSPU",
    "AppleH16ANEInterface",
    "AppleVideoEncoder",
    "AppleAVE2Driver",
    "IOBiometricFamily",
    "AppleMultitouchDevice",
    "AppleUSBHostDevice",
    "IOSurfaceAccelerator",
    "AppleProcessorTrace",
    "AppleFirmwareKit",
    "IOStreamUserClient",
    "AppleDisplayCrossbar",
    "IOMobileGraphicsFamily",
};
static const int kNameCount = (int)(sizeof(kNames) / sizeof(kNames[0]));

// ---------------- kern_return 名字 ----------------
static const char *krName(kern_return_t v) {
    switch ((uint32_t)v) {
        case 0x00000000: return "SUCCESS";
        case 0xE00002BC: return "kIOReturnError";
        case 0xE00002BD: return "kIOReturnNoMemory";
        case 0xE00002BE: return "kIOReturnNoResources";
        case 0xE00002BF: return "kIOReturnIPCError";
        case 0xE00002C0: return "kIOReturnNoDevice";
        case 0xE00002C1: return "kIOReturnNotPrivileged";
        case 0xE00002C2: return "kIOReturnBadArgument";
        case 0xE00002C3: return "kIOReturnLockedRead";
        case 0xE00002C4: return "kIOReturnLockedWrite";
        case 0xE00002C5: return "kIOReturnExclusiveAccess";
        case 0xE00002C6: return "kIOReturnBadMessageID";
        case 0xE00002C7: return "kIOReturnUnsupported";
        case 0xE00002C8: return "kIOReturnVMError";
        case 0xE00002C9: return "kIOReturnInternalError";
        case 0xE00002CA: return "kIOReturnIOError";
        case 0xE00002CC: return "kIOReturnCannotLock";
        case 0xE00002CD: return "kIOReturnNotOpen";
        case 0xE00002CE: return "kIOReturnNotReadable";
        case 0xE00002CF: return "kIOReturnNotWritable";
        case 0xE00002D0: return "kIOReturnNotAligned";
        case 0xE00002D1: return "kIOReturnBadMedia";
        case 0xE00002D2: return "kIOReturnStillOpen";
        case 0xE00002D3: return "kIOReturnRLDError";
        case 0xE00002D4: return "kIOReturnDMAError";
        case 0xE00002D5: return "kIOReturnBusy";
        case 0xE00002D6: return "kIOReturnTimeout";
        case 0xE00002D7: return "kIOReturnOffline";
        case 0xE00002D8: return "kIOReturnNotReady";
        case 0xE00002D9: return "kIOReturnNotAttached";
        case 0xE00002DA: return "kIOReturnNoChannels";
        case 0xE00002DB: return "kIOReturnNoSpace";
        case 0xE00002DD: return "kIOReturnPortExists";
        case 0xE00002DE: return "kIOReturnCannotWire";
        case 0xE00002DF: return "kIOReturnNoInterrupt";
        case 0xE00002E0: return "kIOReturnNoFrames";
        case 0xE00002E1: return "kIOReturnMessageTooLarge";
        case 0xE00002E2: return "kIOReturnNotPermitted";
        case 0xE00002E3: return "kIOReturnNoPower";
        case 0xE00002E4: return "kIOReturnNoMedia";
        case 0xE00002E5: return "kIOReturnUnformattedMedia";
        case 0xE00002E6: return "kIOReturnUnsupportedMode";
        case 0xE00002E7: return "kIOReturnUnderrun";
        case 0xE00002E8: return "kIOReturnOverrun";
        case 0x10000001: return "MACH_SEND_INTERRUPTED";
        case 0x10000002: return "MACH_SEND_INVALID_DATA";
        case 0x10000003: return "MACH_SEND_INVALID_DEST";
        case 0x10000004: return "MACH_SEND_TIMED_OUT";
        case 0x10000009: return "MACH_SEND_INVALID_RIGHT";
        default:         return NULL;   // 调用方写十六进制
    }
}

// 短档：任务要求的四档 + 其它十六进制
static const char *krnShort(kern_return_t v) {
    switch ((uint32_t)v) {
        case 0x00000000: return "SUCCESS";
        case 0xE00002E2: return "kIOReturnNotPermitted";
        case 0xE00002C7: return "kIOReturnUnsupported";
        case 0xE00002C2: return "kIOReturnBadArgument";
        default:         return NULL;
    }
}

// ---------------- 输出 ----------------
static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) {
    va_list ap;
    char buf[2048];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    if (gNd) {
        fprintf(gNd, "%s\n", buf);
        fflush(gNd);
        fsync(fileno(gNd));          // 崩了也不丢已经写出的行
    }
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
}

static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...) {
    va_list ap;
    char buf[2048];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (gLog) { fprintf(gLog, "%s\n", buf); fflush(gLog); fsync(fileno(gLog)); }
    fprintf(stderr, "%s\n", buf);
    fflush(stderr);
}

// JSON 字符串转义（名字都是 ASCII，仍按规矩转义）
static void jesc(const char *s, char *out, size_t n) {
    size_t j = 0;
    for (size_t i = 0; s[i] && j + 7 < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c < 0x20) { j += (size_t)snprintf(out + j, n - j, "\\u%04x", c); }
        else out[j++] = (char)c;
    }
    out[j] = 0;
}

static double gT0 = 0;

static double nowSec(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    double t = (double)tv.tv_sec + tv.tv_usec / 1e6;
    if (gT0 == 0) { gT0 = t; return 0; }
    return t - gT0;
}

// ---------------- 主扫描 ----------------
static void sweep(void) {
    (void)nowSec();          // 建立时间基准，否则 @done 的 t 恒为 0
    logf_("=== svcprobe start fp=%s build=%s names=%d ===",
          kFingerprint, kBuildStamp, kNameCount);

    emit("{\"k\":\"@svc\",\"s\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\","
         "\"ios\":\"%s\",\"model\":\"%s\",\"names\":%d}",
         kFingerprint, kBuildStamp,
         [[[UIDevice currentDevice] systemVersion] UTF8String],
         [[[UIDevice currentDevice] model] UTF8String],
         kNameCount);

    for (int i = 0; i < kNameCount; i++) {
        const char *name = kNames[i];
        char jn[512];
        jesc(name, jn, sizeof jn);

        logf_("[%02d/%02d] %s ...", i + 1, kNameCount, name);

        io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault,
                                                     IOServiceMatching(name));
        if (s == 0) {
            emit("{\"k\":\"@svc\",\"name\":\"%s\",\"found\":0}", jn);
            logf_("    found=0（名字不匹配或未发布）");
            continue;
        }

        logf_("    found=1 service=0x%x", (unsigned)s);

        int opened = -1;
        for (uint32_t type = 0; type <= 3; type++) {
            io_connect_t c = 0;
            kern_return_t kr = IOServiceOpen(s, mach_task_self(), type, &c);

            const char *shortn = krnShort(kr);
            if (shortn) {
                emit("{\"k\":\"@svc\",\"name\":\"%s\",\"found\":1,\"type\":%u,"
                     "\"kr\":%u,\"krn\":\"%s\"}",
                     jn, type, (uint32_t)kr, shortn);
            } else {
                const char *longn = krName(kr);
                if (longn) {
                    emit("{\"k\":\"@svc\",\"name\":\"%s\",\"found\":1,\"type\":%u,"
                         "\"kr\":%u,\"krn\":\"%s\",\"krh\":\"0x%08x\"}",
                         jn, type, (uint32_t)kr, longn, (uint32_t)kr);
                } else {
                    emit("{\"k\":\"@svc\",\"name\":\"%s\",\"found\":1,\"type\":%u,"
                         "\"kr\":%u,\"krn\":\"0x%08x\"}",
                         jn, type, (uint32_t)kr, (uint32_t)kr);
                }
            }
            logf_("    type=%u kr=0x%08x (%s) conn=0x%x",
                  type, (uint32_t)kr, krnShort(kr) ? krnShort(kr) : (krName(kr) ? krName(kr) : "?"),
                  (unsigned)c);

            if (kr == KERN_SUCCESS) {
                opened = (int)type;
                IOServiceClose(c);
                break;             // 成功就停，不再试更大 type
            }
            c = 0;
        }

        if (opened >= 0) logf_("    => OPENABLE via type %d", opened);
        else             logf_("    => 全 type 被拒");

        IOObjectRelease(s);
    }

    logf_("=== svcprobe done ===");
    emit("{\"k\":\"@svc\",\"s\":\"@done\",\"names\":%d,\"t\":%.3f}",
         kNameCount, nowSec());
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();   // <container>/tmp/
    gLog = fopen([[dir stringByAppendingPathComponent:@"svcprobe.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"svcprobe.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 svcprobe.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 svcprobe.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"svcprobe…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    // 看门狗：任何一次 IOServiceOpen 卡死都不会把整轮拖住
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(90 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        fprintf(stderr, "!! watchdog 90s 到期，强制退出\n");
        if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
        if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
        exit(3);
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            sweep();
            if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
            if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ exit(0); });
        }
    });
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AD class]));
    }
}
