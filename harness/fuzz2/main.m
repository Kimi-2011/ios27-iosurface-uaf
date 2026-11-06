// fuzz2 — 状态感知的内容变异探针（在 selshape 基础上扩展，未重写）
//
// 继承 selshape 的能力：
//   * 三种调用形式：IOConnectCallScalarMethod / IOConnectCallStructMethod / IOConnectCallMethod
//     （另加 legacy 变参 IOConnectMethodScalarIScalarO）
//   * 尺寸阶梯 + struct_in_hex（十六进制字节串）
//   * begin/end 双行落盘（panic 留下「有 begin 无 end」指纹）
//   * 按 key 断点续跑；单条 0.8s 超时后弃 conn 换新
//
// 新增：
//   1) 内容变异：32 种确定性 mut（边界值 / 递增 / 大数 / 指针形 / 长度字段形态）
//   2) scalar 变异：16 组 scalar 输入向量（个数 0..8）
//   3) 输出容量变异：scalar_out_cap / struct_out_cap 独立成维
//   4) 每个用例有确定 key，可只重跑某个 key
//
// 执行纪律：**一个 selector 一个 conn，用完即关**；超时则弃（不 close，避免 UAF 自己）。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static NSString *gTmp = nil;
static FILE *gNd = NULL;
static FILE *gLog = NULL;
static NSLock *gLock = nil;
static CFTimeInterval gT0 = 0;
static volatile int gFinished = 0;
static dispatch_queue_t gQ = NULL;

static const double kPerCallTimeout = 0.8;
static double gBudget = 28.0;
static const double kWatchdog   = 33.0;

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
        case kIOReturnBadMessageID: return @"kIOReturnBadMessageID";
        case kIOReturnVMError: return @"kIOReturnVMError";
        case kIOReturnInternalError: return @"kIOReturnInternalError";
        case kIOReturnOverrun: return @"kIOReturnOverrun";
        case kIOReturnUnderrun: return @"kIOReturnUnderrun";
        case kIOReturnMessageTooLarge: return @"kIOReturnMessageTooLarge";
        case kIOReturnRLDError: return @"kIOReturnRLDError";
        case kIOReturnDMAError: return @"kIOReturnDMAError";
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

#pragma mark - 确定性内容变异（32 种）

static const char *kMutNames[] = {
    "zero", "ff", "7f", "80", "inc8", "inc32", "w32max", "w32i32max",
    "p64neg", "p64_1000", "p64_4g", "mix",
    "L0m1", "L0eq", "L0p1", "L0max",
    "L4m1", "L4eq", "L4p1", "L4max",
    "L8m1", "L8eq", "L8p1", "L8max",
    "L12m1", "L12eq", "L12p1", "L12max",
    "L0eq_L4eq", "L0eq_L4max", "echo", "sizeff",
    NULL
};

static inline void put32(uint8_t *b, size_t n, size_t off, uint32_t v) {
    if (off + 4 <= n) memcpy(b + off, &v, 4);
}
static inline void put64(uint8_t *b, size_t n, size_t off, uint64_t v) {
    if (off + 8 <= n) memcpy(b + off, &v, 8);
}

// 长度字段取值：-1 / ==size / +1 / 0xFFFFFFFF
static uint32_t lenVal(int op, size_t size) {
    uint32_t s = (uint32_t)size;
    switch (op) {
        case 0: return (uint32_t)(s - 1);
        case 1: return s;
        case 2: return (uint32_t)(s + 1);
        default: return 0xFFFFFFFFu;
    }
}

static void fillMut(const char *name, uint8_t *b, size_t n, uint32_t sel, size_t size) {
    if (!strcmp(name, "zero"))      { memset(b, 0x00, n); return; }
    if (!strcmp(name, "ff"))        { memset(b, 0xFF, n); return; }
    if (!strcmp(name, "7f"))        { memset(b, 0x7F, n); return; }
    if (!strcmp(name, "80"))        { memset(b, 0x80, n); return; }
    if (!strcmp(name, "inc8"))      { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(i & 0xFF); return; }
    if (!strcmp(name, "inc32"))     { memset(b, 0, n); for (size_t i = 0; i * 4 < n; i++) put32(b, n, i * 4, (uint32_t)i); return; }
    if (!strcmp(name, "w32max"))    { for (size_t i = 0; i * 4 < n; i++) put32(b, n, i * 4, 0xFFFFFFFFu); return; }
    if (!strcmp(name, "w32i32max")) { for (size_t i = 0; i * 4 < n; i++) put32(b, n, i * 4, 0x7FFFFFFFu); return; }
    if (!strcmp(name, "p64neg"))    { for (size_t i = 0; i * 8 < n; i++) put64(b, n, i * 8, 0xFFFFFFFFFFFFFFFFull); return; }
    if (!strcmp(name, "p64_1000"))  { for (size_t i = 0; i * 8 < n; i++) put64(b, n, i * 8, 0x1000ull); return; }
    if (!strcmp(name, "p64_4g"))    { for (size_t i = 0; i * 8 < n; i++) put64(b, n, i * 8, 0x100000000ull); return; }
    if (!strcmp(name, "mix"))       { memset(b, 0, n); put32(b, n, 0, 0x1000); put32(b, n, 4, (uint32_t)size);
                                      put32(b, n, 8, 0xFFFFFFFFu); put32(b, n, 12, sel); return; }
    // 长度字段形态
    for (int off = 0; off <= 12; off += 4) {
        char buf[16];
        for (int op = 0; op < 4; op++) {
            const char *suffix[4] = {"m1", "eq", "p1", "max"};
            snprintf(buf, sizeof buf, "L%d%s", off, suffix[op]);
            if (!strcmp(name, buf)) { memset(b, 0, n); put32(b, n, (size_t)off, lenVal(op, size)); return; }
        }
    }
    if (!strcmp(name, "L0eq_L4eq"))  { memset(b, 0, n); put32(b, n, 0, (uint32_t)size); put32(b, n, 4, (uint32_t)size); return; }
    if (!strcmp(name, "L0eq_L4max")) { memset(b, 0, n); put32(b, n, 0, (uint32_t)size); put32(b, n, 4, 0xFFFFFFFFu); return; }
    if (!strcmp(name, "echo"))       { memset(b, 0, n); put32(b, n, 0, sel); put32(b, n, 4, (uint32_t)size);
                                       put64(b, n, 8, (uint64_t)size); return; }
    if (!strcmp(name, "sizeff"))     { memset(b, 0xFF, n); put64(b, n, 0, (uint64_t)size); return; }
    memset(b, 0, n);
}

#pragma mark - scalar 变异向量（16 组）

static NSArray *scalarVectors(void) {
    static NSArray *v = nil;
    if (v) return v;
    v = @[
        @[],                                              // 0 个
        @[@0], @[@1], @[@0xFFFFFFFFull], @[@(~0ull)],     // 1 个
        @[@0, @0], @[@1, @1], @[@0xFFFFFFFFull, @0xFFFFFFFFull],   // 2 个
        @[@1, @0, @0, @0], @[@0, @1, @0, @0], @[@0, @0, @1, @0], @[@0, @0, @0, @1],
        @[@0xFFFFFFFFull, @0xFFFFFFFFull, @0xFFFFFFFFull, @0xFFFFFFFFull],
        @[@0x1000, @0x1000, @0x1000, @0x1000, @0x1000, @0x1000, @0x1000, @0x1000],
        @[@1, @2, @3, @4, @5, @6, @7, @8],
        @[@(~0ull), @1, @(~0ull), @1],
    ];
    return v;
}

#pragma mark - key

static NSString *keyOf(NSDictionary *t) {
    // class|type|sel|form|size|mut|scv|socap|socap2|legacy|hex|pass
    // ★ hex 必须在 key 里：否则同一 (class,type,sel,size) 上的不同 hex 变体会塌成一条，
    //   只有第一个能跑到（已复现：18 个 hex 变体只落了 1 条 pass0）。
    return [NSString stringWithFormat:@"%@|%@|%@|%@|%@|%@|%@|%@|%@|%@|%@|%@",
            t[@"class"], t[@"type"], t[@"sel"], t[@"form"] ?: @"method",
            t[@"size"] ?: @0, t[@"mut"] ?: @"-", t[@"scv"] ?: @"-",
            t[@"socap"] ?: @0, t[@"socap2"] ?: @0, t[@"legacy"] ?: @0,
            t[@"struct_in_hex"] ?: @"-", t[@"pass"] ?: @0];
}

static NSMutableSet *loadDone(void) {
    NSMutableSet *s = [NSMutableSet set];
    NSString *p = [gTmp stringByAppendingPathComponent:@"fuzz2.ndjson"];
    NSString *txt = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        if (line.length < 2) continue;
        id o = [NSJSONSerialization JSONObjectWithData:[line dataUsingEncoding:NSUTF8StringEncoding]
                                              options:0 error:nil];
        if (![o isKindOfClass:[NSDictionary class]]) continue;
        if (![o[@"phase"] isEqualToString:@"end"]) continue;   // 有 begin 无 end ⇒ 触发过 panic
        [s addObject:keyOf(o)];
    }
    return s;
}

#pragma mark - 服务

static io_service_t findService(NSString *cls, uint64_t *eidOut) {
    io_iterator_t iter = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(cls.UTF8String), &iter) != KERN_SUCCESS)
        return 0;
    io_service_t svc = IOIteratorNext(iter);
    if (svc && eidOut) IORegistryEntryGetRegistryEntryID(svc, eidOut);
    IOObjectRelease(iter);
    return svc;
}

// 打开一个 conn。返回 0 表示失败（rc 里带原因）。
static io_connect_t openConn(io_service_t svc, uint32_t type, kern_return_t *rcOut, uint64_t *eid) {
    io_connect_t conn = 0;
    kern_return_t orc = IOServiceOpen(svc, mach_task_self(), type, &conn);
    if (rcOut) *rcOut = orc;
    if (orc != KERN_SUCCESS || !conn) { if (conn) IOServiceClose(conn); return 0; }
    return conn;
}

// 单次调用（给定已打开的 conn）
static kern_return_t callOne(io_connect_t conn, NSDictionary *t,
                             uint8_t **inOut, size_t *inSizeOut,
                             size_t *outSizeOut, uint32_t *outCntOut,
                             uint8_t *outCopy, size_t outCopyCap, size_t *outCopyLen) {
    if (outCopyLen) *outCopyLen = 0;
    uint32_t sel   = [t[@"sel"] unsignedIntValue];
    NSString *form = t[@"form"] ?: @"method";
    size_t inSize  = (size_t)[t[@"size"] unsignedIntegerValue];
    uint32_t socap = [t[@"socap"] unsignedIntValue];    // struct 输出容量
    uint32_t socap2= [t[@"socap2"] unsignedIntValue];   // scalar 输出容量
    uint32_t legacy= [t[@"legacy"] unsignedIntValue];

    id vec = @"-";
    id scv = t[@"scv"];
    if ([scv isKindOfClass:[NSNumber class]]) {
        NSUInteger idx = [scv unsignedIntegerValue];
        NSArray *all = scalarVectors();
        if (idx < all.count) vec = all[idx];
    }
    uint64_t sc[8] = {0};
    uint32_t scCount = 0;
    if ([vec isKindOfClass:[NSArray class]]) {
        for (id v in (NSArray *)vec) { if (scCount < 8) sc[scCount++] = [v unsignedLongLongValue]; }
    }

    uint8_t *in = inSize ? calloc(inSize, 1) : NULL;
    if (in) {
        NSString *mut = t[@"mut"];
        if ([mut isKindOfClass:[NSString class]] && ![mut isEqualToString:@"-"]) {
            fillMut(mut.UTF8String, in, inSize, sel, inSize);
        }
        // struct_in_hex 覆盖（保留 selshape 的原始字节串能力）
        NSString *hex = t[@"struct_in_hex"];
        if ([hex isKindOfClass:[NSString class]] && hex.length == inSize * 2) {
            for (size_t i = 0; i < inSize; i++) {
                unsigned int b = 0;
                sscanf([[hex substringWithRange:NSMakeRange(i * 2, 2)] UTF8String], "%02x", &b);
                in[i] = (uint8_t)b;
            }
        }
    }
    uint8_t *so = socap ? calloc(socap, 1) : NULL;
    uint64_t *sout = socap2 ? calloc(socap2, sizeof(uint64_t)) : NULL;
    size_t outSize = socap;
    uint32_t outCnt = socap2;

    // 注：`IOConnectMethodScalarIScalarO` 在 arm64（LP64）上**不存在**——
    //     IOKitLib.h 把它整段放在 `#if !defined(__LP64__)` 里。所以现代设备上只有
    //     IOConnectCallMethod / CallScalarMethod / CallStructMethod / CallAsyncMethod 四条路。
    //     `legacy` 字段保留仅为兼容旧配置；置 1 时直接记 UNSUPPORTED_FORM。
    kern_return_t rc;
    if (legacy) {
        rc = (kern_return_t)0xE00002C7;   // kIOReturnUnsupported：该形式在 LP64 上不可用
        outCnt = 0;
        outSize = 0;
    } else if ([form isEqualToString:@"struct"]) {
        rc = IOConnectCallStructMethod(conn, sel, in, inSize, so, &outSize);
    } else if ([form isEqualToString:@"scalar"]) {
        rc = IOConnectCallScalarMethod(conn, sel, scCount ? sc : NULL, scCount,
                                       sout, socap2 ? &outCnt : NULL);
    } else {
        rc = IOConnectCallMethod(conn, sel, scCount ? sc : NULL, scCount,
                                 inSize ? in : NULL, inSize,
                                 sout, socap2 ? &outCnt : NULL,
                                 so, socap ? &outSize : NULL);
    }

    // 回读输出结构的前 outCopyCap 字节（只记 out_size 不够，要看内核写回什么）
    if (outCopy && so && outCopyLen) {
        size_t w = outSize < outCopyCap ? outSize : outCopyCap;
        memcpy(outCopy, so, w);
        *outCopyLen = w;
    }
    if (in) free(in);
    if (so) free(so);
    if (sout) free(sout);
    if (inOut) *inOut = NULL;
    if (inSizeOut) *inSizeOut = inSize;
    if (outSizeOut) *outSizeOut = socap ? outSize : 0;
    if (outCntOut) *outCntOut = outCnt;
    return rc;
}

#pragma mark - 主循环

static volatile int gCurIdx = -1;

// 给一个 task 补全默认字段
static NSDictionary *normalize(NSDictionary *t) {
    NSMutableDictionary *m = [NSMutableDictionary dictionaryWithDictionary:t];
    if (!m[@"form"])  m[@"form"]  = @"method";
    if (!m[@"size"])  m[@"size"]  = @0;
    if (!m[@"mut"])   m[@"mut"]   = @"-";
    if (!m[@"scv"])   m[@"scv"]   = @"-";
    if (!m[@"socap"]) m[@"socap"] = @0;
    if (!m[@"socap2"])m[@"socap2"]= @0;
    if (!m[@"legacy"])m[@"legacy"]= @0;
    return m;
}

// 按 target 展开成扁平用例表
static NSArray *expand(NSArray *targets) {
    NSMutableArray *tasks = [NSMutableArray array];
    for (NSDictionary *g in targets) {
        NSString *cls = g[@"class"];
        id type = g[@"type"] ?: @0;
        NSString *mode = g[@"mode"] ?: @"content";
        NSArray *sels  = g[@"sels"] ?: @[];
        if ([g[@"skip"] isKindOfClass:[NSArray class]]) {
            NSMutableArray *keep = [NSMutableArray array];
            NSSet *sk = [NSSet setWithArray:g[@"skip"]];
            for (id sv in sels) if (![sk containsObject:sv]) [keep addObject:sv];
            sels = keep;
        }
        NSArray *sizes = g[@"sizes"] ?: @[@0];
        NSString *form = g[@"form"] ?: @"method";
        uint32_t passes = g[@"passes"] ? [g[@"passes"] unsignedIntValue] : 1;
        NSString *hex  = g[@"struct_in_hex"];

        NSMutableArray *muts = [NSMutableArray array];
        if ([mode isEqualToString:@"content"]) {
            id mm = g[@"mutants"];
            if ([mm isKindOfClass:[NSArray class]]) {
                for (id x in (NSArray *)mm) [muts addObject:x];
            } else {
                for (int i = 0; kMutNames[i]; i++)
                    [muts addObject:[NSString stringWithUTF8String:kMutNames[i]]];
            }
        } else {
            [muts addObject:@"-"];     // 无内容变异
        }

        NSMutableArray *scvs = [NSMutableArray array];
        if ([mode isEqualToString:@"scalar"]) {
            for (NSUInteger i = 0; i < scalarVectors().count; i++) [scvs addObject:@(i)];
        } else if ([mode isEqualToString:@"outcap"]) {
            [scvs addObject:@0];
        } else {
            [scvs addObject:g[@"scv"] ?: @"-"];
        }

        // outcaps 只要给了展开成独立一维（与内容变异可叠加），否则固定 0。
        // SEL-SHAPE 已证明非零输出容量会导致拒绝，所以它必须能单独取值。
        NSMutableArray *socaps = [NSMutableArray array];
        if ([g[@"outcaps"] isKindOfClass:[NSArray class]]) {
            for (id c in g[@"outcaps"]) [socaps addObject:c];
        } else {
            [socaps addObject:@0];
        }

        for (uint32_t p = 0; p < passes; p++) {
            for (id sel in sels) {
                for (id sz in sizes) {
                    for (id mut in muts) {
                        for (id scv in scvs) {
                            for (id oc in socaps) {
                                NSMutableDictionary *t = [@{
                                    @"class": cls, @"type": type, @"sel": sel,
                                    @"form": form, @"size": sz, @"mut": mut,
                                    @"scv": scv, @"socap": oc, @"socap2": oc,
                                    @"pass": @(p), @"mode": mode,
                                } mutableCopy];
                                if (hex) t[@"struct_in_hex"] = hex;
                                if (g[@"legacy"]) t[@"legacy"] = g[@"legacy"];
                                [tasks addObject:normalize(t)];
                            }
                        }
                    }
                }
            }
        }
    }
    return tasks;
}

static void runAll(void) {
    NSData *d = [NSData dataWithContentsOfFile:[gTmp stringByAppendingPathComponent:@"fuzz2.json"]];
    if (!d) { L(@"!!! 读不到 fuzz2.json"); gFinished = 1; return; }
    id cfg = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    NSArray *targets = nil;
    if ([cfg isKindOfClass:[NSDictionary class]]) {
        targets = cfg[@"targets"];
        if (cfg[@"budget"]) gBudget = [cfg[@"budget"] doubleValue];
    } else {
        targets = cfg;
    }
    if (![targets isKindOfClass:[NSArray class]]) { L(@"!!! 配置不是数组/无 targets"); gFinished = 1; return; }

    NSArray *tasks = expand(targets);
    NSSet *done = loadDone();
    L(@"=== fuzz2 启动 pid=%d 目标 %lu 组 用例 %lu 条，已完成 %lu 条，预算 %.0fs",
      getpid(), (unsigned long)targets.count, (unsigned long)tasks.count,
      (unsigned long)done.count, gBudget);

    NSUInteger ran = 0, skipped = 0;
    NSString *curGroup = nil;
    // 断路器：同一 (class,type) 连续 wedgeAfter 次超时 ⇒ 该 client 已被内核侧挂死，
    // 后续同 (class,type) 的用例整批跳过（不落 end 行，下轮可重试）。
    int consecTO = 0;
    uint32_t wedgeAfter = 3;
    if ([cfg isKindOfClass:[NSDictionary class]] && cfg[@"wedge_after"])
        wedgeAfter = [cfg[@"wedge_after"] unsignedIntValue];
    NSMutableSet *wedged = [NSMutableSet set];
    io_connect_t conn = 0;
    io_service_t svc = 0;
    uint64_t eid = 0;
    kern_return_t openRc = 0;
    int needReopen = 0;

    for (NSUInteger i = 0; i < tasks.count; i++) {
        if (gFinished) break;
        if (nowSec() > gBudget) { L(@"... 预算用尽，停在 %lu/%lu（已跑 %lu）",
                                     (unsigned long)i, (unsigned long)tasks.count, (unsigned long)ran);
                                  gFinished = 1; break; }
        NSDictionary *t = tasks[i];
        if ([done containsObject:keyOf(t)]) { skipped++; continue; }

        NSString *ct = [NSString stringWithFormat:@"%@|%@", t[@"class"], t[@"type"]];
        if ([wedged containsObject:ct]) { skipped++; continue; }

        NSString *grp = [NSString stringWithFormat:@"%@|%@|%@", t[@"class"], t[@"type"], t[@"sel"]];
        if (![grp isEqualToString:curGroup]) {
            // 一个 selector 一个 conn：换 selector 就关掉上一个
            if (conn) { IOServiceClose(conn); conn = 0; }
            if (svc) { IOObjectRelease(svc); svc = 0; }
            curGroup = grp;
            needReopen = 0;
        }
        if (!conn || needReopen) {
            if (needReopen && conn) { /* 上次超时：弃 conn，不 close */ conn = 0; }
            if (!svc) svc = findService(t[@"class"], &eid);
            if (!svc) {
                NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:t];
                row[@"rc"] = @(-1); row[@"rc_name"] = @"no_service"; row[@"phase"] = @"end";
                row[@"eid"] = @0;
                emit(row); ran++; needReopen = 0; continue;
            }
            conn = openConn(svc, [t[@"type"] unsignedIntValue], &openRc, &eid);
            needReopen = 0;
            if (!conn) {
                NSMutableDictionary *row = [NSMutableDictionary dictionaryWithDictionary:t];
                row[@"rc"] = @((int)openRc); row[@"rc_name"] = @"open_fail";
                row[@"open_rc"] = @((int)openRc); row[@"phase"] = @"end"; row[@"eid"] = @(eid);
                emit(row); ran++; needReopen = 0; continue;
            }
        }

        gCurIdx = (int)i;
        NSMutableDictionary *begin = [NSMutableDictionary dictionaryWithDictionary:t];
        begin[@"phase"] = @"begin";
        emit(begin);

        __block kern_return_t rc = 0;
        __block size_t oSize = 0;
        __block uint32_t oCnt = 0;
        __block size_t hexLen = 0;
        uint8_t *hexBuf = calloc(96, 1);
        __block volatile int fin = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        io_connect_t c = conn;
        dispatch_async(gQ, ^{
            @autoreleasepool {
                rc = callOne(c, t, NULL, NULL, &oSize, &oCnt, hexBuf, 96, &hexLen);
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
            needReopen = 1;       // 下次换新 conn（旧的不 close）
            // ★ 关键：挂死的调用永久占住串行队列。不换队列的话，之后每一条都会超时
            //   （已复现：AGX t131073 sel 55 挂住后，11 个类全被判超时）。
            //   换新队列 = 弃掉那一条 + 它的线程，后续照常跑。
            gQ = dispatch_queue_create("fuzz2.calls", DISPATCH_QUEUE_SERIAL);
            consecTO++;
            L(@"    !!! %@ t%@ sel=%u size=%lu mut=%@ 超时(连续 %d)",
              t[@"class"], t[@"type"], [t[@"sel"] unsignedIntValue],
              (unsigned long)[t[@"size"] unsignedIntegerValue], t[@"mut"], consecTO);
            if ((uint32_t)consecTO >= wedgeAfter) {
                [wedged addObject:ct];
                L(@"!!! 断路器：%@ 连续 %d 次超时 ⇒ 本批跳过该 client 其余用例", ct, consecTO);
            }
        } else {
            row[@"rc"] = @((int)rc);
            row[@"rc_name"] = krName(rc);
            row[@"out_size"] = @(oSize);
            row[@"out_cnt"] = @(oCnt);
            if (hexLen) {
                NSMutableString *hx = [NSMutableString stringWithCapacity:hexLen * 2];
                for (size_t i = 0; i < hexLen; i++) [hx appendFormat:@"%02x", hexBuf[i]];
                row[@"out_hex"] = hx;
            }
            consecTO = 0;
        }
        row[@"eid"] = @(eid);
        row[@"phase"] = @"end";
        emit(row);
        free(hexBuf);
        ran++;

        if (ran % 200 == 0) L(@"... %lu/%lu 用时 %.1fs 跳过 %lu",
                              (unsigned long)(i + 1), (unsigned long)tasks.count, nowSec(),
                              (unsigned long)skipped);
    }
    if (conn) { IOServiceClose(conn); conn = 0; }
    if (svc) { IOObjectRelease(svc); svc = 0; }
    gFinished = 1;
    L(@"=== 完成：跑了 %lu 条，跳过 %lu 条，用时 %.1fs", (unsigned long)ran, (unsigned long)skipped, nowSec());
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
    gQ = dispatch_queue_create("fuzz2.calls", DISPATCH_QUEUE_SERIAL);
    gLog = fopen([gTmp stringByAppendingPathComponent:@"fuzz2.log"].UTF8String, "w");
    gNd  = fopen([gTmp stringByAppendingPathComponent:@"fuzz2.ndjson"].UTF8String, "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"fuzz2: 内容变异…";
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
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool { runAll(); }
        self.label.text = [NSString stringWithFormat:@"完成，用时 %.1fs", nowSec()];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)),
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
