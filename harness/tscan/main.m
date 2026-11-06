// tscan — 把 IOServiceOpen 的 type 范围从 0..3 扩到 0..15
//
// 动机：IOKit 的 type 是任意 32 位值，不同 user client 子类用不同值。
//       只试 0..3 会把「有 user client 但 type 不在这四个里」的服务误判成不可达。
//
// 输出: tmp/tscan.ndjson  每个服务一行：eid / class / name / 16 个 type 的返回码 / 成功的 type 列表
//       tmp/tscan-done.json  {"complete":bool,"enumerated":N,"scanned":N,"skipped":N}
//       tmp/tscan.log
//
// 断点续跑：启动时读已有的 tscan.ndjson，按 eid 跳过已扫过的服务。
//           一轮跑不完就退出，再启动一次接着跑，直到 complete=true。
// 抗崩溃：每个服务一行，写完立刻 fflush。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <unistd.h>

static NSString *gTmp = nil;
static FILE *gNd = NULL;
static FILE *gLog = NULL;
static NSLock *gLock = nil;
static CFTimeInterval gT0 = 0;
static volatile int gFinished = 0;
static volatile int gScanned = 0, gOpened = 0, gSkipped = 0, gEnumerated = 0;

static uint32_t gTypeMax = 15;             // 由 tmp/tscan-cfg.json 覆盖
static BOOL     gSkipUnsupported = NO;     // 只扫「0..15 里出现过非 Unsupported」的服务
static NSString *gOutName = @"tscan.ndjson";
static const double   kBudget    = 26.0;  // 超过就不再开新服务
static const double   kWatchdog  = 30.0;

static double nowSec(void) { return [NSDate timeIntervalSinceReferenceDate] - gT0; }

static void L(NSString *fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    fprintf(gLog, "%s\n", s.UTF8String);
    fflush(gLog);
}

// 返回码名（与 ucall 一致，覆盖 IOKit 全部 common_err）
static struct { kern_return_t k; const char *n; } kNames[] = {
    {KERN_SUCCESS, "KERN_SUCCESS"},
    {KERN_INVALID_ARGUMENT, "KERN_INVALID_ARGUMENT"},
    {KERN_FAILURE, "KERN_FAILURE"},
    {KERN_INVALID_RIGHT, "KERN_INVALID_RIGHT"},
    {KERN_INVALID_VALUE, "KERN_INVALID_VALUE"},
    {kIOReturnError, "kIOReturnError"},
    {kIOReturnNoMemory, "kIOReturnNoMemory"},
    {kIOReturnNoResources, "kIOReturnNoResources"},
    {kIOReturnIPCError, "kIOReturnIPCError"},
    {kIOReturnNoDevice, "kIOReturnNoDevice"},
    {kIOReturnNotPrivileged, "kIOReturnNotPrivileged"},
    {kIOReturnBadArgument, "kIOReturnBadArgument"},
    {kIOReturnLockedRead, "kIOReturnLockedRead"},
    {kIOReturnLockedWrite, "kIOReturnLockedWrite"},
    {kIOReturnExclusiveAccess, "kIOReturnExclusiveAccess"},
    {kIOReturnBadMessageID, "kIOReturnBadMessageID"},
    {kIOReturnUnsupported, "kIOReturnUnsupported"},
    {kIOReturnVMError, "kIOReturnVMError"},
    {kIOReturnInternalError, "kIOReturnInternalError"},
    {kIOReturnIOError, "kIOReturnIOError"},
    {kIOReturnCannotLock, "kIOReturnCannotLock"},
    {kIOReturnNotOpen, "kIOReturnNotOpen"},
    {kIOReturnNotReadable, "kIOReturnNotReadable"},
    {kIOReturnNotWritable, "kIOReturnNotWritable"},
    {kIOReturnNotAligned, "kIOReturnNotAligned"},
    {kIOReturnBadMedia, "kIOReturnBadMedia"},
    {kIOReturnStillOpen, "kIOReturnStillOpen"},
    {kIOReturnRLDError, "kIOReturnRLDError"},
    {kIOReturnDMAError, "kIOReturnDMAError"},
    {kIOReturnBusy, "kIOReturnBusy"},
    {kIOReturnTimeout, "kIOReturnTimeout"},
    {kIOReturnOffline, "kIOReturnOffline"},
    {kIOReturnNotReady, "kIOReturnNotReady"},
    {kIOReturnNotAttached, "kIOReturnNotAttached"},
    {kIOReturnNoChannels, "kIOReturnNoChannels"},
    {kIOReturnNoSpace, "kIOReturnNoSpace"},
    {kIOReturnPortExists, "kIOReturnPortExists"},
    {kIOReturnCannotWire, "kIOReturnCannotWire"},
    {kIOReturnNoInterrupt, "kIOReturnNoInterrupt"},
    {kIOReturnNoFrames, "kIOReturnNoFrames"},
    {kIOReturnMessageTooLarge, "kIOReturnMessageTooLarge"},
    {kIOReturnNotPermitted, "kIOReturnNotPermitted"},
    {kIOReturnNotResponding, "kIOReturnNotResponding"},
    {kIOReturnIsoTooOld, "kIOReturnIsoTooOld"},
    {kIOReturnIsoTooNew, "kIOReturnIsoTooNew"},
    {kIOReturnNotFound, "kIOReturnNotFound"},
    {kIOReturnInvalid, "kIOReturnInvalid"},
    {kIOReturnUnsupportedMode, "kIOReturnUnsupportedMode"},
    {kIOReturnNoCompletion, "kIOReturnNoCompletion"},
    {kIOReturnDeviceError, "kIOReturnDeviceError"},
    {kIOReturnAborted, "kIOReturnAborted"},
    {kIOReturnUnderrun, "kIOReturnUnderrun"},
    {kIOReturnOverrun, "kIOReturnOverrun"},
    {kIOReturnNoMedia, "kIOReturnNoMedia"},
    {kIOReturnUnformattedMedia, "kIOReturnUnformattedMedia"},
    {kIOReturnNoBandwidth, "kIOReturnNoBandwidth"},
    {kIOReturnNoPower, "kIOReturnNoPower"},
};

static NSString *krName(kern_return_t r) {
    for (size_t i = 0; i < sizeof(kNames)/sizeof(kNames[0]); i++)
        if (kNames[i].k == r) return [NSString stringWithUTF8String:kNames[i].n];
    return [NSString stringWithFormat:@"0x%08X", (unsigned)r];
}

// 已扫过的 eid（断点续跑）
static NSMutableSet *loadDone(void) {
    NSMutableSet *s = [NSMutableSet set];
    NSString *p = [gTmp stringByAppendingPathComponent:gOutName];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        if (line.length < 2) continue;
        NSData *d = [line dataUsingEncoding:NSUTF8StringEncoding];
        id o = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if ([o isKindOfClass:[NSDictionary class]] && o[@"eid"]) [s addObject:o[@"eid"]];
    }
    return s;
}

static void emit(NSDictionary *row) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:row options:0 error:nil];
    if (!d) return;
    [gLock lock];
    if (gNd) { fwrite(d.bytes, 1, d.length, gNd); fputc('\n', gNd); fflush(gNd); }
    [gLock unlock];
}

static void writeDone(BOOL complete, int enumerated, int scanned, int skipped) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    m[@"complete"]   = @(complete);
    m[@"enumerated"] = @(enumerated);
    m[@"scanned"]    = @(scanned);
    m[@"skipped"]    = @(skipped);
    m[@"type_max"]   = @(gTypeMax);
    m[@"out"]        = gOutName;
    m[@"skip_unsupported"] = @(gSkipUnsupported);
    m[@"elapsed_s"]  = @(nowSec());
    m[@"os"] = [[NSProcessInfo processInfo] operatingSystemVersionString];
    NSData *d = [NSJSONSerialization dataWithJSONObject:m options:0 error:nil];
    if (d) [d writeToFile:[gTmp stringByAppendingPathComponent:@"tscan-done.json"] atomically:YES];
}

static void loadCfg(void) {
    NSString *p = [gTmp stringByAppendingPathComponent:@"tscan-cfg.json"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) return;
    id o = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![o isKindOfClass:[NSDictionary class]]) return;
    if (o[@"type_max"]) gTypeMax = [o[@"type_max"] unsignedIntValue];
    if (o[@"skip_unsupported"]) gSkipUnsupported = [o[@"skip_unsupported"] boolValue];
    if ([o[@"out"] isKindOfClass:[NSString class]]) gOutName = o[@"out"];
}

// 从 0..15 那一轮的结果里，挑出「至少一个 type 的返回码不是 Unsupported」的 eid
static NSSet *loadCandidates(void) {
    NSMutableSet *s = [NSMutableSet set];
    NSString *p = [gTmp stringByAppendingPathComponent:@"tscan.ndjson"];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        if (line.length < 2) continue;
        id o = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding]
                                              options:0 error:nil];
        if (![o isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *opens = o[@"open"];
        if (![opens isKindOfClass:[NSDictionary class]]) continue;
        for (id v in opens.allValues) {
            if ([v intValue] != kIOReturnUnsupported) { [s addObject:o[@"eid"]]; break; }
        }
    }
    return s;
}

static void scan(void) {
    NSSet *done = loadDone();
    NSSet *cands = gSkipUnsupported ? loadCandidates() : nil;
    if (cands) L(@"    候选集（0..15 中出现过非 Unsupported）: %lu 个服务", (unsigned long)cands.count);
    L(@"=== tscan 启动 pid=%d type=0..%u out=%@ 已完成 %lu 个服务",
      getpid(), gTypeMax, gOutName, (unsigned long)done.count);

    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                    IOServiceMatching("IOService"), &iter);
    if (kr != KERN_SUCCESS) { L(@"!!! 枚举失败 %@", krName(kr)); gFinished = 1; return; }

    int n = 0, scanned = 0, skipped = 0, opened = 0;
    io_service_t svc = 0;
    while ((svc = IOIteratorNext(iter))) {
        if (gFinished) break;
        n++;

        uint64_t eid = 0;
        IORegistryEntryGetRegistryEntryID(svc, &eid);
        NSNumber *eidN = @(eid);

        if ([done containsObject:eidN]) { skipped++; IOObjectRelease(svc); continue; }
        if (cands && ![cands containsObject:eidN]) { skipped++; IOObjectRelease(svc); continue; }

        if (nowSec() > kBudget) {
            L(@"... 预算 %.0fs 用尽，本轮扫到 %d 个（枚举到第 %d 个）", kBudget, scanned, n);
            IOObjectRelease(svc);
            break;
        }

        char cls[256] = {0}, nm[256] = {0};
        IOObjectGetClass(svc, cls);
        IORegistryEntryGetName(svc, nm);

        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        row[@"eid"] = eidN;
        row[@"class"] = [NSString stringWithUTF8String:cls];
        row[@"name"]  = [NSString stringWithUTF8String:nm];

        NSMutableDictionary *opens = [NSMutableDictionary dictionary];
        NSMutableArray *okTypes = [NSMutableArray array];
        for (uint32_t t = 0; t <= gTypeMax; t++) {
            io_connect_t conn = 0;
            kern_return_t r = IOServiceOpen(svc, mach_task_self(), t, &conn);
            opens[[NSString stringWithFormat:@"%u", t]] = @((int)r);
            if (r == KERN_SUCCESS) {
                [okTypes addObject:@(t)];
                if (conn) IOServiceClose(conn);
            }
        }
        if (okTypes.count) opened++;

        row[@"open"] = opens;
        row[@"ok_types"] = okTypes;
        row[@"ok_count"] = @(okTypes.count);

        emit(row);
        scanned++;
        IOObjectRelease(svc);

        if (scanned % 100 == 0)
            L(@"... 已扫 %d 个，可打开 %d，用时 %.1fs", scanned, opened, nowSec());
    }
    IOObjectRelease(iter);

    gScanned = scanned; gOpened = opened; gSkipped = skipped; gEnumerated = n;
    NSUInteger total = done.count + scanned;
    BOOL complete = (skipped + scanned >= n) && (scanned > 0 || done.count > 0);
    // 只有「没有任何服务因预算被跳过」才算本轮跑完 -> 需要再看是否有未扫的
    BOOL budgetHit = (skipped + scanned < n);
    gFinished = 1;
    writeDone(!budgetHit, n, scanned, skipped);
    L(@"=== 本轮: 枚举 %d, 新扫 %d, 跳过(已扫) %d, 可打开 %d, 累计 %lu, 用时 %.1fs, 仍有剩余=%d",
      n, scanned, skipped, opened, (unsigned long)total, nowSec(), budgetHit);
}

@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    gTmp = [NSTemporaryDirectory() copy];
    gT0 = [NSDate timeIntervalSinceReferenceDate];
    gLock = [NSLock new];
    loadCfg();
    gLog = fopen([gTmp stringByAppendingPathComponent:@"tscan.log"].UTF8String, "a");
    gNd  = fopen([gTmp stringByAppendingPathComponent:gOutName].UTF8String, "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"tscan: type 0..15 扫描…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    lab.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    [root.view addSubview:lab];
    self.label = lab;
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWatchdog * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gFinished) return;
        gFinished = 1;
        L(@"!!! 看门狗 %.0fs，写部分结果", kWatchdog);
        writeDone(NO, gEnumerated, gScanned, gSkipped);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool { scan(); }
        self.label.text = [NSString stringWithFormat:@"本轮扫 %d，可打开 %d\n用时 %.1fs",
                           gScanned, gOpened, nowSec()];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AD class]));
    }
}
