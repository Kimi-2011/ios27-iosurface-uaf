// ucall — 配置驱动的 IOKit selector 调用器
//
// 目的：把「能 IOServiceOpen」升级成「能真的调用 externalMethod」。
// 所有目标、参数、selector 都由 app 容器内 tmp/plan.json 决定，改参数不用重编译。
//
// 输入: tmp/plan.json  （数组，或 {"only": [...], "plan": [...]}）
// 输出: tmp/ucall.ndjson  —— 逐条增量，每行 flush，panic 时前面的结果还在
//       tmp/ucall.json    —— 汇总
//       tmp/ucall.log     —— 人读日志
//
// 抗崩溃设计:
//   * 每条独立 @autoreleasepool + 独立 io_connect_t，调完立即 IOServiceClose
//   * 每条结果一产生就写盘并 fflush（不等整轮结束）
//   * 单条超时用 dispatch_semaphore + dispatch_after（不用 sleep 轮询）
//   * 总预算 / 看门狗双保险，到点强制收尾并 exit

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach_time.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

// ---------------- 全局 ----------------
static NSString *gTmp = nil;
static FILE *gNd = NULL;
static FILE *gLog = NULL;
static NSLock *gLock = nil;
static CFTimeInterval gT0 = 0;
static volatile int gFinished = 0;     // 主流程已收尾
static volatile int gTotal = 0;        // 计划总条数
static volatile int gRan = 0;          // 实际发起
static volatile int gTimeouts = 0;
static volatile int gBudgetSkip = 0;
static volatile int gCallOK = 0;       // call 返回 KERN_SUCCESS 的条数

// 预算：单次交互总等待 <= 35s，这里留足余量
static const double kPerEntryTimeout = 1.5;   // 单条默认超时（秒），可被 plan 覆盖
static const double kStartBudget     = 22.0;  // 超过此秒数不再发起新条目
static const double kWatchdog       = 26.0;   // 硬收尾

static double nowSec(void) { return [NSDate timeIntervalSinceReferenceDate] - gT0; }

static void L(NSString *fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    fprintf(gLog, "%s\n", s.UTF8String);
    fflush(gLog);
}

// ---------------- 返回码 → 名字 ----------------
// 编译期常量解析：kern_return_t 段 + IOKit 全部 common_err 码（避免手抄返回码出错）
static struct { kern_return_t k; const char *n; } kNames[] = {
    {KERN_SUCCESS,              "KERN_SUCCESS"},
    {KERN_INVALID_ADDRESS,      "KERN_INVALID_ADDRESS"},
    {KERN_PROTECTION_FAILURE,   "KERN_PROTECTION_FAILURE"},
    {KERN_NO_SPACE,             "KERN_NO_SPACE"},
    {KERN_INVALID_ARGUMENT,     "KERN_INVALID_ARGUMENT"},
    {KERN_FAILURE,              "KERN_FAILURE"},
    {KERN_RESOURCE_SHORTAGE,    "KERN_RESOURCE_SHORTAGE"},
    {KERN_NOT_RECEIVER,         "KERN_NOT_RECEIVER"},
    {KERN_NO_ACCESS,            "KERN_NO_ACCESS"},
    {KERN_MEMORY_FAILURE,       "KERN_MEMORY_FAILURE"},
    {KERN_MEMORY_ERROR,         "KERN_MEMORY_ERROR"},
    {KERN_ABORTED,              "KERN_ABORTED"},
    {KERN_INVALID_NAME,         "KERN_INVALID_NAME"},
    {KERN_INVALID_TASK,         "KERN_INVALID_TASK"},
    {KERN_INVALID_RIGHT,        "KERN_INVALID_RIGHT"},
    {KERN_INVALID_VALUE,        "KERN_INVALID_VALUE"},
    {KERN_UREFS_OVERFLOW,       "KERN_UREFS_OVERFLOW"},
    {KERN_INVALID_CAPABILITY,   "KERN_INVALID_CAPABILITY"},
    {KERN_RIGHT_EXISTS,         "KERN_RIGHT_EXISTS"},
    {KERN_INVALID_HOST,         "KERN_INVALID_HOST"},
    {KERN_MEMORY_PRESENT,       "KERN_MEMORY_PRESENT"},
    {kIOReturnError,            "kIOReturnError"},
    {kIOReturnNoMemory,         "kIOReturnNoMemory"},
    {kIOReturnNoResources,      "kIOReturnNoResources"},
    {kIOReturnIPCError,         "kIOReturnIPCError"},
    {kIOReturnNoDevice,         "kIOReturnNoDevice"},
    {kIOReturnNotPrivileged,    "kIOReturnNotPrivileged"},
    {kIOReturnBadArgument,      "kIOReturnBadArgument"},
    {kIOReturnLockedRead,       "kIOReturnLockedRead"},
    {kIOReturnLockedWrite,      "kIOReturnLockedWrite"},
    {kIOReturnExclusiveAccess,  "kIOReturnExclusiveAccess"},
    {kIOReturnBadMessageID,     "kIOReturnBadMessageID"},
    {kIOReturnUnsupported,      "kIOReturnUnsupported"},
    {kIOReturnVMError,          "kIOReturnVMError"},
    {kIOReturnInternalError,    "kIOReturnInternalError"},
    {kIOReturnIOError,          "kIOReturnIOError"},
    {kIOReturnCannotLock,       "kIOReturnCannotLock"},
    {kIOReturnNotOpen,          "kIOReturnNotOpen"},
    {kIOReturnNotReadable,      "kIOReturnNotReadable"},
    {kIOReturnNotWritable,      "kIOReturnNotWritable"},
    {kIOReturnNotAligned,       "kIOReturnNotAligned"},
    {kIOReturnBadMedia,         "kIOReturnBadMedia"},
    {kIOReturnStillOpen,        "kIOReturnStillOpen"},
    {kIOReturnRLDError,         "kIOReturnRLDError"},
    {kIOReturnDMAError,         "kIOReturnDMAError"},
    {kIOReturnBusy,             "kIOReturnBusy"},
    {kIOReturnTimeout,          "kIOReturnTimeout"},
    {kIOReturnOffline,          "kIOReturnOffline"},
    {kIOReturnNotReady,         "kIOReturnNotReady"},
    {kIOReturnNotAttached,      "kIOReturnNotAttached"},
    {kIOReturnNoChannels,       "kIOReturnNoChannels"},
    {kIOReturnNoSpace,          "kIOReturnNoSpace"},
    {kIOReturnPortExists,       "kIOReturnPortExists"},
    {kIOReturnCannotWire,       "kIOReturnCannotWire"},
    {kIOReturnNoInterrupt,      "kIOReturnNoInterrupt"},
    {kIOReturnNoFrames,         "kIOReturnNoFrames"},
    {kIOReturnMessageTooLarge,  "kIOReturnMessageTooLarge"},
    {kIOReturnNotPermitted,     "kIOReturnNotPermitted"},
    {kIOReturnNoPower,          "kIOReturnNoPower"},
    {kIOReturnNoMedia,          "kIOReturnNoMedia"},
    {kIOReturnUnformattedMedia, "kIOReturnUnformattedMedia"},
    {kIOReturnUnsupportedMode,  "kIOReturnUnsupportedMode"},
    {kIOReturnUnderrun,         "kIOReturnUnderrun"},
    {kIOReturnOverrun,          "kIOReturnOverrun"},
    {kIOReturnDeviceError,      "kIOReturnDeviceError"},
    {kIOReturnNoCompletion,     "kIOReturnNoCompletion"},
    {kIOReturnAborted,          "kIOReturnAborted"},
    {kIOReturnNoBandwidth,      "kIOReturnNoBandwidth"},
    {kIOReturnNotResponding,    "kIOReturnNotResponding"},
    {kIOReturnIsoTooOld,        "kIOReturnIsoTooOld"},
    {kIOReturnIsoTooNew,        "kIOReturnIsoTooNew"},
    {kIOReturnNotFound,         "kIOReturnNotFound"},
    {kIOReturnInvalid,          "kIOReturnInvalid"},
};

static NSString *krName(kern_return_t r) {
    for (size_t i = 0; i < sizeof(kNames)/sizeof(kNames[0]); i++)
        if (kNames[i].k == r) return [NSString stringWithUTF8String:kNames[i].n];
    return [NSString stringWithFormat:@"0x%08X", (unsigned)r];
}

// ---------------- 增量落盘 ----------------
static void emit(NSDictionary *row) {
    NSError *e = nil;
    NSData *d = [NSJSONSerialization dataWithJSONObject:row options:0 error:&e];
    if (!d) { L(@"[!] 序列化失败 idx=%@: %@", row[@"idx"], e); return; }
    [gLock lock];
    if (gNd) {
        fwrite(d.bytes, 1, d.length, gNd);
        fputc('\n', gNd);
        fflush(gNd);      // 每行立刻落盘 —— panic 时保住已完成的条目
    }
    [gLock unlock];
}

// ---------------- 单条执行 ----------------
// 全程同步；超时控制由外层 semaphore 负责（调用一旦进内核无法从用户态打断）
static NSDictionary *runEntry(NSDictionary *e, NSUInteger idx) {
    double t0 = nowSec();

    NSString *cls  = [e[@"class"] isKindOfClass:[NSString class]] ? e[@"class"] : nil;
    uint32_t type  = e[@"type"] ? [e[@"type"] unsignedIntValue] : 0;
    uint32_t sel   = e[@"sel"]  ? [e[@"sel"]  unsignedIntValue] : 0;

    NSDictionary *sc = [e[@"scalars"] isKindOfClass:[NSDictionary class]] ? e[@"scalars"] : nil;
    NSArray *inArr = [sc[@"in"] isKindOfClass:[NSArray class]] ? sc[@"in"] : nil;

    uint32_t countIn = inArr ? (uint32_t)inArr.count : 0;
    if (sc[@"count_in"]) countIn = [sc[@"count_in"] unsignedIntValue];
    if (countIn > 16) countIn = 16;                    // IOKit 标量上限 16

    uint32_t outCount = e[@"out_count"] ? [e[@"out_count"] unsignedIntValue] : 0;
    if (outCount > 16) outCount = 16;

    uint32_t structOutLen = e[@"struct_out_len"] ? [e[@"struct_out_len"] unsignedIntValue] : 0;

    NSData *structIn = nil;
    if ([e[@"struct_in_b64"] isKindOfClass:[NSString class]] && [e[@"struct_in_b64"] length]) {
        structIn = [[NSData alloc] initWithBase64EncodedString:e[@"struct_in_b64"] options:0];
        if (!structIn) structIn = nil;
    }
    // 允许 "struct_in_len" 直接声明长度（用零填充），不必提供 b64
    uint32_t declaredInLen = e[@"struct_in_len"] ? [e[@"struct_in_len"] unsignedIntValue] : 0;
    if (!structIn && declaredInLen > 0) {
        structIn = [NSMutableData dataWithLength:declaredInLen];
    }
    if (structIn && declaredInLen > structIn.length) {
        NSMutableData *pad = [NSMutableData dataWithData:structIn];
        [pad increaseLengthBy:(declaredInLen - structIn.length)];
        structIn = pad;
    }
    if (structIn.length > 65536) {   // 防御性上限
        structIn = [structIn subdataWithRange:NSMakeRange(0, 65536)];
    }

    NSMutableDictionary *row = [NSMutableDictionary dictionary];
    row[@"idx"]   = @(idx);
    row[@"class"] = cls ?: @"?";
    row[@"type"]  = @(type);
    row[@"sel"]   = @(sel);
    row[@"count_in"]  = @(countIn);
    row[@"out_count"] = @(outCount);
    if (e[@"note"]) row[@"note"] = e[@"note"];

    if (!cls) {
        row[@"error"] = @"no_class";
        row[@"elapsed_ms"] = @(0);
        return row;
    }

    // ---- 1. 找服务 ----
    io_service_t svc = 0;
    io_iterator_t iter = 0;
    kern_return_t mrc = IOServiceGetMatchingServices(kIOMainPortDefault,
                                                     IOServiceMatching(cls.UTF8String), &iter);
    if (mrc != KERN_SUCCESS || !iter) {
        row[@"service_found"] = @NO;
        row[@"match_rc"] = @((int)mrc);
        row[@"match_rc_name"] = krName(mrc);
        row[@"elapsed_ms"] = @((int)((nowSec() - t0) * 1000));
        return row;
    }

    NSUInteger wantInstance = e[@"instance"] ? [e[@"instance"] unsignedIntValue] : 0;
    NSNumber *wantEid = e[@"eid"];
    NSUInteger seen = 0;
    io_service_t cur = 0;
    while ((cur = IOIteratorNext(iter))) {
        uint64_t eid = 0;
        IORegistryEntryGetRegistryEntryID(cur, &eid);
        BOOL take = NO;
        if (wantEid) take = (eid == [wantEid unsignedLongLongValue]);
        else take = (seen == wantInstance);
        if (take) { svc = cur; row[@"eid"] = @(eid); break; }
        IOObjectRelease(cur);
        seen++;
    }
    IOObjectRelease(iter);

    if (!svc) {
        row[@"service_found"] = @NO;
        row[@"match_rc"] = @((int)KERN_SUCCESS);
        row[@"match_rc_name"] = @"KERN_SUCCESS";
        row[@"instances"] = @(seen);
        row[@"elapsed_ms"] = @((int)((nowSec() - t0) * 1000));
        return row;
    }
    row[@"service_found"] = @YES;

    // ---- 可选：IOServiceAuthorize ----
    // 该符号在 iOS SDK 里被标记 unavailable，但 libSystem 里仍可能导出；用 dlsym 探测，缺了就如实记录
    if (e[@"authorize"]) {
        typedef kern_return_t (*auth_fn)(io_service_t, uint32_t);
        auth_fn fn = (auth_fn)dlsym(RTLD_DEFAULT, "IOServiceAuthorize");
        if (fn) {
            kern_return_t arc = fn(svc, 0);
            row[@"authorize_rc"] = @((int)arc);
            row[@"authorize_rc_name"] = krName(arc);
        } else {
            row[@"authorize_rc_name"] = @"symbol_unavailable";
        }
    }

    // ---- 2. IOServiceOpen ----
    io_connect_t conn = 0;
    kern_return_t orc = IOServiceOpen(svc, mach_task_self(), type, &conn);
    row[@"open_rc"] = @((int)orc);
    row[@"open_rc_name"] = krName(orc);

    if (orc != KERN_SUCCESS || conn == 0) {
        if (conn) IOServiceClose(conn);
        IOObjectRelease(svc);
        row[@"elapsed_ms"] = @((int)((nowSec() - t0) * 1000));
        return row;
    }

    // ---- 3/4. 选调用方式 ----
    //  auto: 有 struct 输入 → StructMethod（有标量输出时升级成通用 Method）
    //        无 struct 输入但有标量输出 → 通用 Method
    //        全空 → ScalarMethod
    //  说明: IOConnectCallStructMethod 没有标量输出参数，所以「纯标量输出」不能走它。
    NSString *method = [e[@"method"] isKindOfClass:[NSString class]] ? e[@"method"] : @"auto";
    if ([method isEqualToString:@"auto"]) {
        if (structIn.length > 0) {
            method = (outCount > 0) ? @"method" : @"struct";
        } else if (outCount > 0) {
            method = @"method";
        } else {
            method = @"scalar";
        }
    }
    row[@"method"] = method;

    uint64_t scalarIn[16] = {0};
    for (uint32_t i = 0; i < countIn && inArr && i < inArr.count; i++) {
        id v = inArr[i];
        if ([v isKindOfClass:[NSNumber class]]) scalarIn[i] = [v unsignedLongLongValue];
    }
    uint64_t scalarOut[16] = {0};
    uint32_t outCap = outCount;
    uint32_t outCnt = outCap;

    NSMutableData *structOut = nil;
    size_t soLen = 0;
    void *soPtr = NULL;
    if (structOutLen > 0) {
        if (structOutLen > 65536) structOutLen = 65536;
        structOut = [NSMutableData dataWithLength:structOutLen];
        soLen = structOutLen;
        soPtr = structOut.mutableBytes;
    }

    // ---- 5. 调用 ----
    kern_return_t crc;
    if ([method isEqualToString:@"struct"]) {
        crc = IOConnectCallStructMethod(conn, sel,
                                        structIn.bytes, structIn.length,
                                        soPtr, soPtr ? &soLen : NULL);
    } else if ([method isEqualToString:@"method"]) {
        crc = IOConnectCallMethod(conn, sel,
                                  scalarIn, countIn,
                                  structIn.bytes, structIn.length,
                                  scalarOut, &outCnt,
                                  soPtr, soPtr ? &soLen : NULL);
    } else {
        crc = IOConnectCallScalarMethod(conn, sel, scalarIn, countIn, scalarOut, &outCnt);
    }

    row[@"call_rc"] = @((int)crc);
    row[@"call_rc_name"] = krName(crc);
    row[@"call_ok"] = @(crc == KERN_SUCCESS);

    // ---- 6. 结果 ----
    if (outCnt > 16) outCnt = 16;     // 驱动乱写也读不超过缓冲
    uint32_t shown = MIN(outCnt, 8u);   // 只记前 8 个
    row[@"scalar_out_count"] = @(outCnt);
    NSMutableArray *so = [NSMutableArray arrayWithCapacity:shown];
    for (uint32_t i = 0; i < shown; i++) {
        [so addObject:@(scalarOut[i])];
    }
    row[@"scalar_out"] = so;

    if (structOut && soLen > 0) {
        if (soLen > structOut.length) soLen = structOut.length;
        row[@"struct_out_len"] = @((unsigned)soLen);
        NSUInteger keep = MIN((NSUInteger)soLen, (NSUInteger)32);
        NSData *pref = [structOut subdataWithRange:NSMakeRange(0, keep)];
        row[@"struct_out_b64_head"] = [pref base64EncodedStringWithOptions:0];
    }

    // 立刻关闭，绝不跨条目复用
    IOServiceClose(conn);
    IOObjectRelease(svc);

    row[@"elapsed_ms"] = @((int)((nowSec() - t0) * 1000));
    return row;
}

// ---------------- 计划加载 ----------------
static NSArray *loadPlan(NSMutableArray *onlyOut) {
    NSString *p = [gTmp stringByAppendingPathComponent:@"plan.json"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d) { L(@"[!] 读不到 %@", p); return nil; }
    NSError *err = nil;
    id root = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (!root) { L(@"[!] plan.json 解析失败: %@", err); return nil; }

    NSArray *entries = nil;
    if ([root isKindOfClass:[NSArray class]]) {
        entries = root;
    } else if ([root isKindOfClass:[NSDictionary class]]) {
        id p2 = root[@"plan"] ?: root[@"entries"];
        if ([p2 isKindOfClass:[NSArray class]]) entries = p2;
        id o = root[@"only"];
        if ([o isKindOfClass:[NSNumber class]]) [onlyOut addObject:o];
        else if ([o isKindOfClass:[NSArray class]]) [onlyOut addObjectsFromArray:o];
    }
    if (!entries) { L(@"[!] plan 里没有条目数组"); return nil; }
    return entries;
}

// ---------------- 主流程 ----------------
static NSMutableArray *gResults = nil;   // 按 idx 顺序存（超时为占位行）

static void writeSummary(BOOL final) {
    NSMutableDictionary *m = [NSMutableDictionary dictionary];
    m[@"final"] = @(final);
    m[@"total"] = @(gTotal);
    m[@"ran"] = @(gRan);
    m[@"call_ok"] = @(gCallOK);
    m[@"timeouts"] = @(gTimeouts);
    m[@"budget_skipped"] = @(gBudgetSkip);
    m[@"elapsed_s"] = @(nowSec());
    m[@"per_entry_timeout_s"] = @(kPerEntryTimeout);
    m[@"os"] = [[NSProcessInfo processInfo] operatingSystemVersionString];
    [gLock lock];
    NSArray *rows = [gResults copy];
    [gLock unlock];
    m[@"results"] = rows;
    NSData *d = [NSJSONSerialization dataWithJSONObject:m options:0 error:nil];
    if (d) [d writeToFile:[gTmp stringByAppendingPathComponent:@"ucall.json"] atomically:YES];
}

static void runPlan(void) {
    NSMutableArray *only = [NSMutableArray array];
    NSArray *entries = loadPlan(only);
    if (!entries) {
        gFinished = 1;
        writeSummary(YES);
        return;
    }

    // 每条的「只跑我」标记也支持
    NSMutableSet *onlySet = [NSMutableSet set];
    for (id o in only) if ([o isKindOfClass:[NSNumber class]]) [onlySet addObject:o];
    for (NSUInteger i = 0; i < entries.count; i++) {
        id e = entries[i];
        if ([e isKindOfClass:[NSDictionary class]] && [e[@"only"] boolValue]) [onlySet addObject:@(i)];
    }

    gTotal = (int)entries.count;
    gResults = [NSMutableArray array];
    for (NSUInteger i = 0; i < entries.count; i++) [gResults addObject:[NSNull null]];

    L(@"=== ucall 启动 pid=%d tmp=%@", getpid(), gTmp);
    NSString *onlyDesc = onlySet.count
        ? [onlySet.allObjects componentsJoinedByString:@","]
        : @"ALL";
    L(@"    计划 %d 条, only=%@", (int)entries.count, onlyDesc);

    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0);

    for (NSUInteger i = 0; i < entries.count; i++) {
        if (gFinished) break;
        id e = entries[i];
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        if (onlySet.count && ![onlySet containsObject:@(i)]) continue;
        if ([e[@"skip"] boolValue]) continue;

        if (nowSec() > kStartBudget) {
            gBudgetSkip = (int)(entries.count - i);
            L(@"!!! 总预算 %.0fs 用尽，跳过 idx %lu..%lu", kStartBudget,
              (unsigned long)i, (unsigned long)(entries.count - 1));
            break;
        }

        double perT = e[@"timeout_ms"] ? [e[@"timeout_ms"] doubleValue] / 1000.0 : kPerEntryTimeout;
        NSString *cls = e[@"class"] ?: @"?";
        L(@"[%lu] %@ type=%u sel=%u …", (unsigned long)i, cls,
          [e[@"type"] unsignedIntValue], [e[@"sel"] unsignedIntValue]);

        __block NSDictionary *result = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(q, ^{
            @autoreleasepool {
                result = runEntry(e, i);
            }
            dispatch_semaphore_signal(sem);
        });

        long w = dispatch_semaphore_wait(sem,
                     dispatch_time(DISPATCH_TIME_NOW, (int64_t)(perT * NSEC_PER_SEC)));

        NSDictionary *row = nil;
        if (w == 0 && result) {
            row = result;
            if ([row[@"call_ok"] boolValue]) gCallOK++;
            L(@"    open=%s call=%s out_cnt=%s  %sms",
              [row[@"open_rc_name"] UTF8String], [row[@"call_rc_name"] UTF8String],
              [[row[@"scalar_out_count"] description] UTF8String],
              [[row[@"elapsed_ms"] description] UTF8String]);
        } else {
            // 超时：调用卡在内核里，线程放弃，conn 不关（进程退出时一并回收）
            gTimeouts++;
            NSMutableDictionary *t = [NSMutableDictionary dictionary];
            t[@"idx"] = @(i);
            t[@"class"] = cls;
            t[@"type"] = e[@"type"] ?: @0;
            t[@"sel"] = e[@"sel"] ?: @0;
            t[@"timeout"] = @YES;
            t[@"timeout_ms"] = @((int)(perT * 1000));
            if (e[@"note"]) t[@"note"] = e[@"note"];
            t[@"elapsed_ms"] = @((int)(perT * 1000));
            row = t;
            L(@"    !!! 超时 %.2fs，记录并继续", perT);
        }

        gRan++;
        [gLock lock];
        gResults[i] = row;
        [gLock unlock];
        emit(row);   // 增量落盘
    }

    writeSummary(NO);
    gFinished = 1;
    L(@"=== 完成: 计划 %d, 发起 %d, call 成功 %d, 超时 %d, 预算跳过 %d, 用时 %.1fs",
      gTotal, gRan, gCallOK, gTimeouts, gBudgetSkip, nowSec());
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    gTmp = [NSTemporaryDirectory() copy];
    gT0 = [NSDate timeIntervalSinceReferenceDate];
    gLock = [NSLock new];

    gLog = fopen([gTmp stringByAppendingPathComponent:@"ucall.log"].UTF8String, "w");
    gNd  = fopen([gTmp stringByAppendingPathComponent:@"ucall.ndjson"].UTF8String, "w");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"ucall: 调用 IOKit selector…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    lab.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    [root.view addSubview:lab];
    self.label = lab;
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    // 看门狗：到点强制收尾（主队列永远可用，不受阻塞）
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWatchdog * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gFinished) return;
        gFinished = 1;
        L(@"!!! 看门狗触发 %.0fs，写部分结果并退出", kWatchdog);
        writeSummary(YES);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool { runPlan(); }
        self.label.text = [NSString stringWithFormat:
            @"完成 %d/%d 条\ncall 成功 %d, 超时 %d\n用时 %.1fs",
            gRan, gTotal, gCallOK, gTimeouts, nowSec()];
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
