// selmap — 零参数 selector 边界测量
//
// 目的：静态派发表普查（census）给的 selector 数不可信，用动态调用量出真实上界。
//
// 探针（严格零参数）：
//   IOConnectCallScalarMethod(conn, sel, NULL, 0, NULL, &outCnt=0)
//   —— 不传 scalar 输入、不传 struct 输入、不请求任何输出。
//
// 判读（只认返回码，不推测语义）：
//   Unsupported（0xE00002C7）  连续出现 → 超出真实 selector 范围
//   BadArgument（0xE00002C2）  handler 存在、参数被拒
//   NotPermitted / NotPrivileged → 进了权限检查
//   0                           零参数即成功
//
// 抗崩溃 / 断点续跑：
//   * 每条 selector 结果一行，写完立刻 fflush —— 任何时刻挂掉，前面的结果都在
//   * 每条 selector 之间用 semaphore 握手，单条超时立即放弃该 conn，从下一条继续（新 conn）
//   * 启动时读已有 selmap.ndjson，跳过已测过的 (class,type,pass,sel)
//   * 总预算 22s，看门狗 26s

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

static const double kPerSelTimeout = 0.8;   // 单条 selector 超时（秒）
static const double kBudget        = 22.0;
static const double kWatchdog      = 26.0;

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
        case kIOReturnNotFound: return @"kIOReturnNotFound";
        case kIOReturnNoCompletion: return @"kIOReturnNoCompletion";
        case kIOReturnUnsupportedMode: return @"kIOReturnUnsupportedMode";
        case kIOReturnExclusiveAccess: return @"kIOReturnExclusiveAccess";
        case kIOReturnNotOpen: return @"kIOReturnNotOpen";
        case kIOReturnBusy: return @"kIOReturnBusy";
        case kIOReturnTimeout: return @"kIOReturnTimeout";
        case kIOReturnNotReady: return @"kIOReturnNotReady";
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

// 已完成键集合：class|type|pass|sel
static NSMutableSet *loadDone(void) {
    NSMutableSet *s = [NSMutableSet set];
    NSString *p = [gTmp stringByAppendingPathComponent:@"selmap.ndjson"];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        if (line.length < 2) continue;
        id o = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding]
                                              options:0 error:nil];
        if (![o isKindOfClass:[NSDictionary class]]) continue;
        [s addObject:[NSString stringWithFormat:@"%@|%@|%@|%@",
                      o[@"class"], o[@"type"], o[@"pass"], o[@"sel"]]];
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

#pragma mark - 单条 target/pass 的执行（可被超时打断后续跑）

typedef struct {
    __unsafe_unretained NSString *cls;
    uint32_t type;
    uint32_t pass;
    uint32_t selMax;
} Ctx;

// 返回值：下一个待跑的 selector（== selMax+1 表示这一 pass 跑完）
static uint32_t runSegment(Ctx ctx, uint32_t startSel, NSSet *done) {
    __block volatile uint32_t curSel = startSel;
    __block volatile int segAbort = 0;
    __block volatile int segDone = 0;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    dispatch_async(q, ^{
        @autoreleasepool {
            uint64_t eid = 0;
            io_service_t svc = findService(ctx.cls, &eid);
            if (!svc) {
                emit(@{@"class": ctx.cls, @"type": @(ctx.type), @"pass": @(ctx.pass),
                       @"sel": @(startSel), @"phase": @"open", @"rc": @(-1),
                       @"rc_name": @"no_service"});
                segDone = 1;
                dispatch_semaphore_signal(sem);
                return;
            }
            io_connect_t conn = 0;
            kern_return_t orc = IOServiceOpen(svc, mach_task_self(), ctx.type, &conn);
            if (orc != KERN_SUCCESS || !conn) {
                emit(@{@"class": ctx.cls, @"type": @(ctx.type), @"pass": @(ctx.pass),
                       @"sel": @(startSel), @"phase": @"open", @"rc": @((int)orc),
                       @"rc_name": krName(orc), @"eid": @(eid)});
                if (conn) IOServiceClose(conn);
                IOObjectRelease(svc);
                segDone = 1;
                dispatch_semaphore_signal(sem);
                return;
            }

            for (uint32_t s = startSel; s <= ctx.selMax; s++) {
                if (segAbort) break;
                NSString *key = [NSString stringWithFormat:@"%@|%u|%u|%u", ctx.cls, ctx.type, ctx.pass, s];
                if ([done containsObject:key]) { continue; }   // 已测过（续跑）

                curSel = s;
                uint32_t outCnt = 0;
                // 严格零参数：NULL 输入、NULL 输出缓冲、输出计数为 0
                kern_return_t rc = IOConnectCallScalarMethod(conn, s, NULL, 0, NULL, &outCnt);
                emit(@{@"class": ctx.cls, @"type": @(ctx.type), @"pass": @(ctx.pass),
                       @"sel": @(s), @"phase": @"call", @"rc": @((int)rc),
                       @"rc_name": krName(rc), @"out_cnt": @(outCnt),
                       @"eid": @(eid), @"seg_start": @(startSel)});
                dispatch_semaphore_signal(sem);
            }
            IOServiceClose(conn);
            IOObjectRelease(svc);
            segDone = 1;
            dispatch_semaphore_signal(sem);
        }
    });

    uint32_t next = startSel;
    while (1) {
        long w = dispatch_semaphore_wait(sem,
                    dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kPerSelTimeout * NSEC_PER_SEC)));
        if (segDone) { next = ctx.selMax + 1; break; }
        if (w != 0) {
            // 卡住：放弃这条 conn，从下一条 selector 用新 conn 继续
            uint32_t stalled = curSel;
            emit(@{@"class": ctx.cls, @"type": @(ctx.type), @"pass": @(ctx.pass),
                   @"sel": @(stalled), @"phase": @"call", @"rc": @(-2),
                   @"rc_name": @"TIMEOUT", @"timeout_ms": @((int)(kPerSelTimeout * 1000)),
                   @"seg_start": @(startSel)});
            L(@"      !!! sel=%u 超时 %.1fs，新 conn 从 %u 继续", stalled, kPerSelTimeout, stalled + 1);
            segAbort = 1;
            next = stalled + 1;
            break;
        }
        next = curSel + 1;
    }
    return next;
}

static void runAll(void) {
    NSData *d = [NSData dataWithContentsOfFile:[gTmp stringByAppendingPathComponent:@"selmap.json"]];
    if (!d) { L(@"!!! 读不到 selmap.json"); gFinished = 1; return; }
    NSArray *targets = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    if (![targets isKindOfClass:[NSArray class]]) { L(@"!!! selmap.json 不是数组"); gFinished = 1; return; }

    NSSet *done = loadDone();
    L(@"=== selmap 启动 pid=%d 目标 %lu 个，已完成记录 %lu 条",
      getpid(), (unsigned long)targets.count, (unsigned long)done.count);

    for (NSDictionary *t in targets) {
        if (gFinished) break;
        NSString *cls = t[@"class"];
        uint32_t type = [t[@"type"] unsignedIntValue];
        uint32_t selMax = t[@"sel_max"] ? [t[@"sel_max"] unsignedIntValue] : 255;
        uint32_t passes = t[@"passes"] ? [t[@"passes"] unsignedIntValue] : 2;

        for (uint32_t p = 0; p < passes; p++) {
            if (gFinished) break;
            if (nowSec() > kBudget) { L(@"... 预算用尽，停在 %@ type=%u pass=%u", cls, type, p); gFinished = 1; break; }

            Ctx ctx = { cls, type, p, selMax };
            uint32_t sel = 0;
            int guard = 0;
            L(@"[%@ type=%u pass=%u] 0..%u …", cls, type, p, selMax);
            while (sel <= selMax && !gFinished && guard++ < 400) {
                uint32_t next = runSegment(ctx, sel, done);
                if (next <= sel) next = sel + 1;      // 防死循环
                sel = next;
                if (nowSec() > kBudget) { gFinished = 1; break; }
            }
        }
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
    gLog = fopen([gTmp stringByAppendingPathComponent:@"selmap.log"].UTF8String, "w");
    gNd  = fopen([gTmp stringByAppendingPathComponent:@"selmap.ndjson"].UTF8String, "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"selmap: 零参数 selector 边界测量…";
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
        L(@"!!! 看门狗 %.0fs", kWatchdog);
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
