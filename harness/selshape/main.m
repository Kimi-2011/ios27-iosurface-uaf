// selshape — 结构输入尺寸阶梯探针
//
// 目的：`BadArgument` 兜底的类量不出上界（见 SEL-MAP §1.1）。换杠杆：固定 selector，
//       扫「structure 输入尺寸」，看返回码在哪个尺寸上**翻转**。
//       翻转 = handler 真的存在、且这就是它期望的输入尺寸。这是正面证据。
//
// 每次调用：
//   IOConnectCallStructMethod(conn, sel, buf, size, out, &outSize)
//     buf     全零，长度 = size（size==0 时传 NULL）
//     out     4096 B，outSize 每次重置为 4096
//     scalars 按配置（第一轮固定为空）
//
// 安全性：**每次调用一个 conn**，用完立刻 IOServiceClose —— 不存在跨调用的状态污染。
// 抗崩溃：每条结果一行 NDJSON + fflush；按 (class|type|sel|size|pass|scalars) 断点续跑；
//         单条 0.8s 超时 → 记 TIMEOUT 并跳到下一条。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <unistd.h>
#include <stdlib.h>

static NSString *gTmp = nil;
static FILE *gNd = NULL;
static FILE *gLog = NULL;
static NSLock *gLock = nil;
static CFTimeInterval gT0 = 0;
static volatile int gFinished = 0;

static const double kPerCallTimeout = 0.8;
static const double kBudget         = 24.0;
static const double kWatchdog       = 28.0;
static const uint32_t kOutBuf       = 4096;

static double nowSec(void) { return [NSDate timeIntervalSinceReferenceDate] - gT0; }

static void L(NSString *fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    fprintf(gLog, "%s\n", s.UTF8String);
    fflush(gLog);
}

static NSString *krName(kern_return_t r) {
    switch (r) {
        case KERN_SUCCESS: return @"KERN_SUCCESS";
        case kIOReturnUnsupported: return @"kIOReturnUnsupported";
        case kIOReturnBadArgument: return @"kIOReturnBadArgument";
        case kIOReturnNotPermitted: return @"kIOReturnNotPermitted";
        case kIOReturnNotPrivileged: return @"kIOReturnNotPrivileged";
        case kIOReturnNoMemory: return @"kIOReturnNoMemory";
        case kIOReturnError: return @"kIOReturnError";
        case kIOReturnNoCompletion: return @"kIOReturnNoCompletion";
        case kIOReturnUnsupportedMode: return @"kIOReturnUnsupportedMode";
        case kIOReturnExclusiveAccess: return @"kIOReturnExclusiveAccess";
        case kIOReturnNotOpen: return @"kIOReturnNotOpen";
        case kIOReturnBusy: return @"kIOReturnBusy";
        case kIOReturnTimeout: return @"kIOReturnTimeout";
        case kIOReturnNotReady: return @"kIOReturnNotReady";
        case kIOReturnNotFound: return @"kIOReturnNotFound";
        case kIOReturnNoDevice: return @"kIOReturnNoDevice";
        case kIOReturnNoResources: return @"kIOReturnNoResources";
        case kIOReturnAborted: return @"kIOReturnAborted";
        default: return [NSString stringWithFormat:@"0x%08X", (unsigned)r];
    }
}

static void emit(NSDictionary *row) {
    NSData *d = [NSJSONSerialization dataWithJSONObject:row options:0 error:nil];
    if (!d) return;
    [gLock lock];
    if (gNd) { fwrite(d.bytes, 1, d.length, gNd); fputc('\n', gNd); fflush(gNd); }
    [gLock unlock];
}

static NSString *keyOf(NSDictionary *t) {
    NSMutableString *s = [[NSMutableString alloc] initWithFormat:@"%@|%@|%@|%@|",
                          t[@"class"], t[@"type"], t[@"sel"], t[@"pass"]];
    NSData *d = [NSJSONSerialization dataWithJSONObject:t[@"shape"] ?: @{} options:0 error:nil];
    [s appendString:[[NSString alloc] initWithData:d ?: [NSData data] encoding:NSUTF8StringEncoding] ?: @""];
    return s;
}

static NSMutableSet *loadDone(void) {
    NSMutableSet *s = [NSMutableSet set];
    NSString *p = [gTmp stringByAppendingPathComponent:@"selshape.ndjson"];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        if (line.length < 2) continue;
        id o = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding]
                                              options:0 error:nil];
        if (![o isKindOfClass:[NSDictionary class]]) continue;
        if (![o[@"phase"] isEqualToString:@"end"]) continue;   // begin 没有 end ⇒ 那条触发过 panic
        [s addObject:keyOf(o)];
    }
    return s;
}

static io_service_t findService(NSString *cls, uint64_t *eidOut) {
    io_iterator_t iter = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(cls.UTF8String), &iter) != KERN_SUCCESS)
        return 0;
    io_service_t svc = IOIteratorNext(iter);
    if (svc && eidOut) IORegistryEntryGetRegistryEntryID(svc, eidOut);
    IOObjectRelease(iter);
    return svc;
}

// 单条执行（一个 conn，用完即关）。shape 描述调用形式与参数形状。
static NSDictionary *doOne(NSDictionary *t) {
    NSString *cls = t[@"class"];
    uint32_t type = [t[@"type"] unsignedIntValue];
    uint32_t sel  = [t[@"sel"] unsignedIntValue];
    NSDictionary *sh = t[@"shape"] ?: @{};
    NSString *form = sh[@"form"] ?: @"scalar";

    uint64_t eid = 0;
    io_service_t svc = findService(cls, &eid);
    if (!svc) return @{@"rc": @(-1), @"rc_name": @"no_service"};
    io_connect_t conn = 0;
    kern_return_t orc = IOServiceOpen(svc, mach_task_self(), type, &conn);
    if (orc != KERN_SUCCESS || !conn) {
        if (conn) IOServiceClose(conn);
        IOObjectRelease(svc);
        return @{@"rc": @((int)orc), @"rc_name": krName(orc), @"open_rc": @((int)orc),
                 @"eid": @(eid), @"phase": @"open"};
    }

    size_t inSize  = (size_t)[sh[@"struct_in_size"] unsignedIntegerValue];
    uint32_t soCap = sh[@"struct_out_cap"] ? [sh[@"struct_out_cap"] unsignedIntValue] : 0;
    uint32_t scCap = sh[@"scalar_out_cap"] ? [sh[@"scalar_out_cap"] unsignedIntValue] : 0;
    NSArray *scIn  = sh[@"scalar_in"] ?: @[];

    uint64_t sc[8] = {0};
    uint32_t scCount = 0;
    for (id v in scIn) { if (scCount < 8) sc[scCount++] = [v unsignedLongLongValue]; }

    uint8_t *in  = (inSize || soCap) ? calloc(inSize ? inSize : 1, 1) : NULL;
    // struct_in_hex: 十六进制串，长度必须 == struct_in_size
    NSString *hex = sh[@"struct_in_hex"];
    if (in && [hex isKindOfClass:[NSString class]] && hex.length == inSize * 2) {
        for (size_t i = 0; i < inSize; i++) {
            unsigned int b = 0;
            sscanf([[hex substringWithRange:NSMakeRange(i * 2, 2)] UTF8String], "%02x", &b);
            in[i] = (uint8_t)b;
        }
    }
    uint8_t *so  = soCap ? calloc(soCap ? soCap : 1, 1) : NULL;
    uint64_t *sout = scCap ? calloc(scCap, sizeof(uint64_t)) : NULL;
    size_t outSize = soCap;
    uint32_t outCnt = scCap;

    kern_return_t rc;
    if ([form isEqualToString:@"struct"]) {
        rc = IOConnectCallStructMethod(conn, sel, in, inSize, so, &outSize);
    } else if ([form isEqualToString:@"method"]) {
        rc = IOConnectCallMethod(conn, sel, scCount ? sc : NULL, scCount,
                                 inSize ? in : NULL, inSize,
                                 sout, scCap ? &outCnt : NULL,
                                 so, soCap ? &outSize : NULL);
    } else { // scalar —— 本轮的主力形式
        rc = IOConnectCallScalarMethod(conn, sel, scCount ? sc : NULL, scCount,
                                       sout, scCap ? &outCnt : NULL);
    }

    if (in) free(in);
    if (so) free(so);
    if (sout) free(sout);
    IOServiceClose(conn);
    IOObjectRelease(svc);
    return @{@"rc": @((int)rc), @"rc_name": krName(rc),
             @"out_size": @(soCap ? outSize : 0), @"out_cnt": @(outCnt),
             @"eid": @(eid), @"phase": @"call"};
}

#pragma mark - 主循环

static volatile int gCurIdx = -1;

static void runAll(void) {
    NSData *d = [NSData dataWithContentsOfFile:[gTmp stringByAppendingPathComponent:@"selshape.json"]];
    if (!d) { L(@"!!! 读不到 selshape.json"); gFinished = 1; return; }
    NSArray *groups = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![groups isKindOfClass:[NSArray class]]) { L(@"!!! 配置不是数组"); gFinished = 1; return; }

    // 展开成扁平任务表：group × pass × sel × shape
    NSMutableArray *tasks = [NSMutableArray array];
    for (NSDictionary *g in groups) {
        NSArray *sels = g[@"sels"] ?: @[];
        NSArray *shapes = g[@"shapes"] ?: @[@{@"form": @"scalar"}];
        uint32_t passes = g[@"passes"] ? [g[@"passes"] unsignedIntValue] : 2;
        for (uint32_t p = 0; p < passes; p++) {
            for (id sh in sels) {
                for (id z in shapes) {
                    [tasks addObject:@{@"class": g[@"class"], @"type": g[@"type"] ?: @0,
                                       @"sel": sh, @"shape": z, @"pass": @(p)}];
                }
            }
        }
    }

    NSSet *done = loadDone();
    L(@"=== selshape 启动 pid=%d 任务 %lu 条，已完成 %lu 条",
      getpid(), (unsigned long)tasks.count, (unsigned long)done.count);

    for (NSUInteger i = 0; i < tasks.count; i++) {
        if (gFinished) break;
        if (nowSec() > kBudget) { L(@"... 预算用尽，停在 %lu/%lu", (unsigned long)i, (unsigned long)tasks.count); gFinished = 1; break; }
        NSDictionary *t = tasks[i];
        if ([done containsObject:keyOf(t)]) continue;

        gCurIdx = (int)i;
        // 调用前先落 begin 行：若随后 panic，这一行就是「触发值」的唯一记录
        NSMutableDictionary *begin = [NSMutableDictionary dictionaryWithDictionary:t];
        begin[@"phase"] = @"begin";
        emit(begin);

        __block NSDictionary *res = nil;
        __block volatile int fin = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool {
                res = doOne(t);
                fin = 1;
                dispatch_semaphore_signal(sem);
            }
        });
        long w = dispatch_semaphore_wait(sem,
                    dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kPerCallTimeout * NSEC_PER_SEC)));

        NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:t];
        if (w != 0 || !fin) {
            row[@"rc"] = @(-2);
            row[@"rc_name"] = @"TIMEOUT";
            row[@"timeout_ms"] = @((int)(kPerCallTimeout * 1000));
            L(@"    !!! %@ sel=%u shape=%@ 超时", t[@"class"], [t[@"sel"] unsignedIntValue], t[@"shape"]);
        } else {
            [row addEntriesFromDictionary:res];
        }
        row[@"phase"] = @"end";   // 必须放在 addEntriesFromDictionary 之后
        emit(row);

        NSUInteger n = i + 1;
        if (n % 100 == 0) L(@"... %lu/%lu 用时 %.1fs", (unsigned long)n, (unsigned long)tasks.count, nowSec());
    }
    gFinished = 1;
    L(@"=== 完成，用时 %.1fs", nowSec());
}

#pragma mark - App

@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    gTmp = [NSTemporaryDirectory() copy];
    gT0 = [NSDate timeIntervalSinceReferenceDate];
    gLock = [NSLock new];
    gLog = fopen([gTmp stringByAppendingPathComponent:@"selshape.log"].UTF8String, "w");
    gNd  = fopen([gTmp stringByAppendingPathComponent:@"selshape.ndjson"].UTF8String, "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"selshape: 结构输入尺寸阶梯…";
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
        L(@"!!! 看门狗 %.0fs，idx=%d", kWatchdog, gCurIdx);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool { runAll(); }
        self.label.text = [NSString stringWithFormat:@"完成，用时 %.1fs", nowSec()];
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
