// rpenum — 实测 iOS IOKit 可达面
// 从 dev-signed app 沙箱出发：枚举全部 IOService，逐个 IOServiceOpen(type 0..3)
// 输出: tmp/reach.json (按规格), tmp/reach-meta.json (统计), tmp/reach.ndjson (增量, 崩溃保命)
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/IOKitKeys.h>
#include <mach/mach_time.h>

static NSString *gTmp;
static FILE *gLog = NULL, *gNd = NULL;
static NSMutableArray *gRows = nil;
static NSLock *gLock = nil;
static FILE *gMetaF = NULL;
static CFTimeInterval gT0 = 0;
static volatile int gDone = 0;
static volatile int gTruncated = 0;
static volatile int gSkipped = 0;
static volatile int gTotal = 0;
static volatile int gOpened = 0;
static volatile int gAttempts = 0;
// 打开预算：枚举 + 探测必须在 35 秒看门狗前收敛
static const double kOpenBudget = 24.0;

static void L(NSString *fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    fprintf(gLog, "%s\n", s.UTF8String);
    fflush(gLog);
}

// 编译期常量解析，避免手抄返回码出错
static struct { kern_return_t k; const char *n; } kNames[] = {
    {KERN_SUCCESS,                  "KERN_SUCCESS"},
    {KERN_INVALID_ADDRESS,          "KERN_INVALID_ADDRESS"},
    {KERN_PROTECTION_FAILURE,       "KERN_PROTECTION_FAILURE"},
    {KERN_NO_SPACE,                 "KERN_NO_SPACE"},
    {KERN_INVALID_ARGUMENT,         "KERN_INVALID_ARGUMENT"},
    {KERN_FAILURE,                  "KERN_FAILURE"},
    {KERN_RESOURCE_SHORTAGE,        "KERN_RESOURCE_SHORTAGE"},
    {KERN_NOT_RECEIVER,             "KERN_NOT_RECEIVER"},
    {KERN_NO_ACCESS,                "KERN_NO_ACCESS"},
    {KERN_MEMORY_FAILURE,           "KERN_MEMORY_FAILURE"},
    {KERN_MEMORY_ERROR,             "KERN_MEMORY_ERROR"},
    {KERN_ABORTED,                  "KERN_ABORTED"},
    {KERN_INVALID_NAME,             "KERN_INVALID_NAME"},
    {KERN_INVALID_TASK,             "KERN_INVALID_TASK"},
    {KERN_INVALID_RIGHT,            "KERN_INVALID_RIGHT"},
    {KERN_INVALID_VALUE,            "KERN_INVALID_VALUE"},
    {KERN_UREFS_OVERFLOW,           "KERN_UREFS_OVERFLOW"},
    {KERN_INVALID_CAPABILITY,       "KERN_INVALID_CAPABILITY"},
    {KERN_RIGHT_EXISTS,             "KERN_RIGHT_EXISTS"},
    {KERN_INVALID_HOST,             "KERN_INVALID_HOST"},
    {KERN_MEMORY_PRESENT,           "KERN_MEMORY_PRESENT"},
    {kIOReturnError,                "kIOReturnError"},
    {kIOReturnNoMemory,             "kIOReturnNoMemory"},
    {kIOReturnNoResources,          "kIOReturnNoResources"},
    {kIOReturnIPCError,             "kIOReturnIPCError"},
    {kIOReturnNoDevice,             "kIOReturnNoDevice"},
    {kIOReturnNotPrivileged,        "kIOReturnNotPrivileged"},
    {kIOReturnBadArgument,          "kIOReturnBadArgument"},
    {kIOReturnLockedRead,           "kIOReturnLockedRead"},
    {kIOReturnLockedWrite,          "kIOReturnLockedWrite"},
    {kIOReturnExclusiveAccess,      "kIOReturnExclusiveAccess"},
    {kIOReturnBadMessageID,         "kIOReturnBadMessageID"},
    {kIOReturnUnsupported,          "kIOReturnUnsupported"},
    {kIOReturnVMError,              "kIOReturnVMError"},
    {kIOReturnInternalError,        "kIOReturnInternalError"},
    {kIOReturnIOError,              "kIOReturnIOError"},
    {kIOReturnCannotLock,           "kIOReturnCannotLock"},
    {kIOReturnNotOpen,              "kIOReturnNotOpen"},
    {kIOReturnNotReadable,          "kIOReturnNotReadable"},
    {kIOReturnNotWritable,          "kIOReturnNotWritable"},
    {kIOReturnNotAligned,           "kIOReturnNotAligned"},
    {kIOReturnBadMedia,             "kIOReturnBadMedia"},
    {kIOReturnStillOpen,            "kIOReturnStillOpen"},
    {kIOReturnRLDError,             "kIOReturnRLDError"},
    {kIOReturnDMAError,             "kIOReturnDMAError"},
    {kIOReturnBusy,                 "kIOReturnBusy"},
    {kIOReturnTimeout,              "kIOReturnTimeout"},
    {kIOReturnOffline,              "kIOReturnOffline"},
    {kIOReturnNotReady,             "kIOReturnNotReady"},
    {kIOReturnNotAttached,          "kIOReturnNotAttached"},
    {kIOReturnNoChannels,           "kIOReturnNoChannels"},
    {kIOReturnNoSpace,              "kIOReturnNoSpace"},
    {kIOReturnPortExists,           "kIOReturnPortExists"},
    {kIOReturnCannotWire,           "kIOReturnCannotWire"},
    {kIOReturnNoInterrupt,          "kIOReturnNoInterrupt"},
    {kIOReturnNoFrames,             "kIOReturnNoFrames"},
    {kIOReturnMessageTooLarge,      "kIOReturnMessageTooLarge"},
    {kIOReturnNotPermitted,         "kIOReturnNotPermitted"},
    {kIOReturnUnsupported,          "kIOReturnUnsupported_dup"},
    {kIOReturnNotResponding,        "kIOReturnNotResponding"},
    {kIOReturnIsoTooOld,            "kIOReturnIsoTooOld"},
    {kIOReturnIsoTooNew,            "kIOReturnIsoTooNew"},
    {kIOReturnNotFound,             "kIOReturnNotFound"},
    {kIOReturnInvalid,              "kIOReturnInvalid"},
};

static const char *krName(kern_return_t r) {
    static __thread char buf[48];
    for (size_t i = 0; i < sizeof(kNames)/sizeof(kNames[0]); i++)
        if (kNames[i].k == r) return kNames[i].n;
    snprintf(buf, sizeof buf, "0x%08X", (unsigned)r);
    return buf;
}

static NSString *propStr(NSDictionary *props, NSString *key) {
    id v = props[key];
    if ([v isKindOfClass:[NSString class]]) return v;
    if ([v isKindOfClass:[NSData class]]) {
        NSString *s = [[NSString alloc] initWithData:v encoding:NSUTF8StringEncoding];
        return s;
    }
    return nil;
}

// ---------- 落盘 ----------
static void writeAll(BOOL final) {
    [gLock lock];
    NSArray *rows = [gRows copy];
    int total = gTotal, opened = gOpened, attempts = gAttempts, skipped = gSkipped, tr = gTruncated;
    [gLock unlock];

    NSMutableArray *out = [NSMutableArray arrayWithCapacity:rows.count];
    for (NSDictionary *r in rows) {
        NSMutableDictionary *d = [NSMutableDictionary dictionary];
        d[@"class"]  = r[@"class"]  ?: @"?";
        d[@"name"]   = r[@"name"]   ?: @"";
        if (r[@"bundle"]) d[@"bundle"] = r[@"bundle"];
        d[@"open"]   = r[@"open"] ?: @{};
        if (r[@"ioclass"])  d[@"ioclass"]  = r[@"ioclass"];
        if (r[@"provider"]) d[@"provider"] = r[@"provider"];
        d[@"uc"]     = r[@"uc"] ?: @NO;
        d[@"eid"]    = r[@"eid"] ?: @0;
        [out addObject:d];
    }

    NSString *jp = [gTmp stringByAppendingPathComponent:@"reach.json"];
    NSData *jd = [NSJSONSerialization dataWithJSONObject:out
                                                options:NSJSONWritingPrettyPrinted
                                                  error:nil];
    [jd writeToFile:jp atomically:YES];

    // 按 type 分组的成功计数
    NSMutableDictionary *byType = [NSMutableDictionary dictionary];
    for (NSDictionary *r in rows) {
        NSDictionary *o = r[@"open"];
        for (NSString *k in o) {
            if ([o[k] intValue] == 0) byType[k] = @([byType[k] intValue] + 1);
        }
    }
    NSMutableDictionary *meta = [NSMutableDictionary dictionary];
    meta[@"services_total"]    = @(total);
    meta[@"services_recorded"] = @(out.count);
    meta[@"open_attempts"]     = @(attempts);
    meta[@"opened_any"]        = @(opened);
    meta[@"opened_by_type"]    = byType;
    meta[@"opens_skipped_by_budget"] = @(skipped);
    meta[@"truncated"]         = @(tr);
    meta[@"elapsed_sec"]       = @([[NSDate date] timeIntervalSinceDate:
                                    [NSDate dateWithTimeIntervalSince1970:gT0]]);
    meta[@"final"]             = final ? @YES : @NO;
    meta[@"budget_sec"]        = @(kOpenBudget);
    NSString *mp = [gTmp stringByAppendingPathComponent:@"reach-meta.json"];
    [[NSJSONSerialization dataWithJSONObject:meta options:NSJSONWritingPrettyPrinted error:nil]
        writeToFile:mp atomically:YES];

    L(@"### 写入 reach.json: %lu 条服务, 可打开 %d, 尝试 %d, 跳过 %d, 截断=%d",
      (unsigned long)out.count, opened, attempts, skipped, tr);
}

// ---------- 主枚举 ----------
static void enumerate(void) {
    io_iterator_t iter = 0;
    CFMutableDictionaryRef match = IOServiceMatching("IOService");
    if (!match) { L(@"!!! IOServiceMatching(IOService) 失败"); return; }
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, match, &iter);
    L(@"IOServiceGetMatchingServices -> %s (%d), iter=%u", krName(kr), (int)kr, iter);
    if (kr != KERN_SUCCESS || !iter) { L(@"!!! 枚举失败"); return; }

    io_object_t svc;
    int n = 0;
    while ((svc = IOIteratorNext(iter))) {
        n++;
        io_name_t cls = {0}, nm = {0};
        IOObjectGetClass(svc, cls);
        IORegistryEntryGetName(svc, nm);
        uint64_t eid = 0;
        IORegistryEntryGetRegistryEntryID(svc, &eid);
        BOOL isUC = IOObjectConformsTo(svc, "IOUserClient");

        NSString *bundle = nil, *ioclass = nil, *provider = nil;
        CFMutableDictionaryRef props = NULL;
        if (IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS && props) {
            NSDictionary *pd = (__bridge_transfer NSDictionary *)props;
            bundle   = propStr(pd, @"CFBundleIdentifier") ?: propStr(pd, @"IOBundleIdentifier");
            ioclass  = propStr(pd, @"IOClass");
            provider = propStr(pd, @"IOProviderClass");
            if (!bundle) {
                // 向上找一层 provider 的 bundle id（很多 nub 自己不挂）
                io_registry_entry_t parent = 0;
                if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &parent) == KERN_SUCCESS) {
                    CFTypeRef pb = IORegistryEntryCreateCFProperty(parent, CFSTR("CFBundleIdentifier"),
                                                                   kCFAllocatorDefault, 0);
                    if (pb) { bundle = [(__bridge_transfer id)pb description]; }
                    IOObjectRelease(parent);
                }
            }
        }

        // --- 打开探测 ---
        NSMutableDictionary *openMap = [NSMutableDictionary dictionary];
        CFTimeInterval el = [NSDate timeIntervalSinceReferenceDate] - gT0;
        BOOL canProbe = (el < kOpenBudget);
        if (canProbe) {
            for (uint32_t t = 0; t <= 3; t++) {
                io_connect_t conn = 0;
                kern_return_t r = IOServiceOpen(svc, mach_task_self(), t, &conn);
                openMap[[NSString stringWithFormat:@"%u", t]] = @((int)r);
                gAttempts++;
                if (r == KERN_SUCCESS) {
                    if (t == 0) gOpened++;
                    L(@"  ✓ %-40s type=%u 打开成功 conn=%u", cls, t, conn);
                    if (conn) IOServiceClose(conn);
                } else if (r != kIOReturnNotPrivileged && r != kIOReturnBadArgument) {
                    L(@"  ? %-40s type=%u -> %s", cls, t, krName(r));
                }
            }
        } else {
            gSkipped++;
        }

        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        row[@"class"] = [NSString stringWithUTF8String:cls];
        row[@"name"]  = [NSString stringWithUTF8String:nm];
        if (bundle)   row[@"bundle"]   = bundle;
        if (ioclass)  row[@"ioclass"]  = ioclass;
        if (provider) row[@"provider"] = provider;
        row[@"uc"]   = @(isUC);
        row[@"eid"]  = @(eid);
        row[@"open"] = openMap;

        [gLock lock];
        [gRows addObject:row];
        gTotal = n;
        [gLock unlock];

        // 增量落盘：崩溃也能保住已测部分
        if (gNd) {
            NSData *ld = [NSJSONSerialization dataWithJSONObject:row options:0 error:nil];
            if (ld) {
                fwrite(ld.bytes, 1, ld.length, gNd);
                fputc('\n', gNd);
                fflush(gNd);
            }
        }
        IOObjectRelease(svc);
        if (n % 250 == 0) L(@"... 已处理 %d 个服务, 可打开 %d, 用时 %.1fs", n, gOpened, el);
    }
    IOObjectRelease(iter);
    gTotal = n;
    L(@"枚举结束: 共 %d 个 IOService, 可打开(type0) %d, 尝试 %d, 预算跳过 %d", n, gOpened, gAttempts, gSkipped);
}

// ---------- App ----------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    gTmp = [NSTemporaryDirectory() copy];
    gT0 = [NSDate timeIntervalSinceReferenceDate];
    gLock = [NSLock new];
    gRows = [NSMutableArray array];

    NSString *lp = [gTmp stringByAppendingPathComponent:@"reach.log"];
    gLog = fopen(lp.UTF8String, "w");
    gNd  = fopen([gTmp stringByAppendingPathComponent:@"reach.ndjson"].UTF8String, "w");
    L(@"=== rpenum 实测 IOKit 可达面 pid=%d tmp=%@", getpid(), gTmp);
    L(@"    iOS %@", [[NSProcessInfo processInfo] operatingSystemVersionString]);

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 20, 60)];
    lab.text = @"rpenum: 枚举 IOKit 可达面…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    lab.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    [root.view addSubview:lab];
    self.label = lab;
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    // 看门狗：35 秒硬收尾（枚举跑在后台队列，主队列永远可用）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(32.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gDone) return;
        gDone = 1;
        gTruncated = 1;
        L(@"!!! 看门狗触发 32s，写部分结果");
        writeAll(YES);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            enumerate();
            if (!gDone) {
                writeAll(YES);
                gDone = 1;
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.label.text = [NSString stringWithFormat:
                        @"完成: %d 服务 / 可打开 %d\n用时 %.1fs", gTotal, gOpened,
                        [NSDate timeIntervalSinceReferenceDate] - gT0];
                });
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ exit(0); });
            }
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
