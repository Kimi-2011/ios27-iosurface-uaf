// main.m — scfuzz：对「真机实测 SUCCESS」的 selector 做标量值边界 fuzzing。
//
// 前一轮 svc2probe 扫了 5131 次调用，但标量入参**全传 0**。
// 这些 selector 真机返回 SUCCESS ⇒ handler 真的跑了。
// 若 handler 把标量当索引/长度/偏移用而不校验，传 0 必然成功，传边界值才见真章。
//
// 阶段 1（本文件主菜）：sIn>=1 的目标，逐个标量位置遍历 21 个边界值，每次只动一个位置。
// 阶段 2：MFB sel 56（stIn=156）四种内容模式 A/B/C/D。
//
// 判据：kr 与该目标「全 0 基线」不同 ⇒ 该标量被读到了（live=1）。
//
// 阻塞防护：每次 IOConnectCallMethod 在独立 pthread，主线程 3s 超时；超时记 @timeout
// 并 detach+泄漏该线程，继续下一个值；同 stage 连续 3 次超时即 @abort。
// 200ms 心跳（@hb 带 svc/sel/idx/v）＋整轮看门狗 exit(3)。
// 一个 stage 一个进程 ⇒ 某个 selector 把内核挂死也不影响后面的 stage。
//
// 指纹（装前 strings 校验，必须命中 1）: SCFUZZ-20261101-scalar-bound-a91f37
// 不跑竞态、不碰 harness/israce/、不改 out/ 既有文件。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>

static const char *kFingerprint = "SCFUZZ-20261101-scalar-bound-a91f37";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define SCALAR_CAP     64
#define STRUCT_IN_CAP  4096
#define STRUCT_OUT_CAP 4096
#define CALL_TIMEOUT_S 3
#define MAX_TIMEOUTS_PER_STAGE 3

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[160] = "-";     // 当前 svc/sel/idx/v
static uint64_t g_t0 = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

static void *hb_thread(void *arg) {
    FILE *f = fopen((const char *)arg, "w");
    if (!f) return NULL;
    while (!g_hb_stop) {
        fprintf(f, "{\"k\":\"@hb\",\"t\":%llu,\"at\":\"%s\"}\n",
                (unsigned long long)(now_ms() - g_t0), g_hb_tag);
        fflush(f); fsync(fileno(f));
        usleep(200000);
    }
    fclose(f);
    return NULL;
}

static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);   // 一行一条 ndjson
    fputs(buf, stderr);
    fflush(stderr);
    if (gLog) { fputs(buf, gLog); fflush(gLog); fsync(fileno(gLog)); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd)); }   // @pre 必须在调用前真的落盘
}

static const char *kr_name(unsigned k) {
    switch (k) {
        case 0x00000000: return "SUCCESS";
        case 0xfffffed4: return "MIG_TYPE_ERROR";
        case 0xfffffed3: return "MIG_REPLY_MISMATCH";
        case 0xfffffed2: return "MIG_BAD_ID";
        case 0xfffffed1: return "MIG_BAD_ARGUMENTS";
        case 0xfffffed0: return "MIG_NO_REPLY";
        case 0xfffffecf: return "MIG_EXCEPTION";
        case 0xfffffece: return "MIG_ARRAY_TOO_LARGE";
        case 0xfffffecd: return "MIG_REMOTE_ERROR";
        case 0xfffffecc: return "MIG_SERVER_DIED";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002bd: return "kIOReturnNoMemory";
        case 0xe00002be: return "kIOReturnNoResources";
        case 0xe00002c0: return "kIOReturnNoDevice";
        case 0xe00002c1: return "kIOReturnNotPrivileged";
        case 0xe00002c2: return "kIOReturnBadArgument";
        case 0xe00002c5: return "kIOReturnExclusiveAccess";
        case 0xe00002c6: return "kIOReturnBadMessageID";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c8: return "kIOReturnVMError";
        case 0xe00002c9: return "kIOReturnInternalError";
        case 0xe00002ca: return "kIOReturnIOError";
        case 0xe00002cd: return "kIOReturnNotOpen";
        case 0xe00002d5: return "kIOReturnBusy";
        case 0xe00002d6: return "kIOReturnAborted";
        case 0xe00002d7: return "kIOReturnTimeout";
        default:         return "OTHER";
    }
}

// ---------------- 目标表（契约全部来自 out/svc_selectors.txt 与 out/gpu_selectors.txt） ----------------
typedef struct {
    const char *stage;    // mfb | hid | gpu | jpeg | s56
    const char *svc;      // IOService 名
    const char *kext;
    const char *tab;
    uint32_t    type;     // IOServiceOpen type
    uint32_t    sel;
    uint32_t    si, so;
    size_t      sti, sto;
    const char *handler;
} Tgt;

static const Tgt g_tgts[] = {
    // A. IOMobileFramebuffer type 0 — kext IOMobileGraphicsFamily 表 0xfffffe000832fd70
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,12,1,0,0,0,   "0xa17e984"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,13,1,0,0,0,   "0xa17e994"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,19,1,0,0,0,   "0xa17ebe8"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,22,1,0,0,0,   "0xa17ed58"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,26,0,0,0,0,   "0xa17eea4"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,31,1,0,0,0,   "0xa17f138"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,33,1,0,0,0,   "0xa17f29c"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,51,1,0,0,0,   "0xa17ec28"},
    {"mfb","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,53,2,0,0,0,   "0xa17e0f8"},
    // A'. sel 56 —— 阶段 2（stIn=156），单独 stage 跑，挂死不影响上面的标量扫描
    {"s56","IOMobileFramebuffer","com.apple.iokit.IOMobileGraphicsFamily","0xfffffe000832fd70",0,56,0,0,156,0, "0xa17e13c"},

    // B. AppleJPEGDriver type 0
    {"jpeg","AppleJPEGDriver","com.apple.driver.AppleJPEGDriver","0xfffffe00080dd990",0,0,0,0,0,0, "0xfffffe0009016358"},
    {"jpeg","AppleJPEGDriver","com.apple.driver.AppleJPEGDriver","0xfffffe00080dd990",0,2,0,0,0,0, "0xfffffe0009016398"},

    // C. IOHIDEventService type 2 — 真机 SUCCESS 命中的是表 0xfffffe000831e300
    {"hid","IOHIDEventService","com.apple.iokit.IOHIDFamily","0xfffffe000831e300",2,1,1,0,0,0, "0xfffffe000a0f5eb0"},

    // D. AGXAcceleratorG18P type 1 —— 契约取自 out/gpu_selectors.txt（gpuprobe A 表实测值）
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 0,0,0,0,  64, "0xfffffe000a021ee8"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 1,0,0,0,  64, "0xfffffe000a021ffc"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 2,0,0,0, 536, "0xfffffe000a022030"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 3,0,0,0,   8, "0xfffffe000a022100"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 4,0,0,0,  32, "0xfffffe000a022134"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1, 5,0,0,0,  16, "0xfffffe000a022210"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,16,0,0,0,   8, "0xfffffe000a022578"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,17,0,0,0,   4, "0xfffffe000a02260c"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,19,1,0,0,  24, "0xfffffe000a0227e0"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,21,0,0,0,  48, "0xfffffe000a02281c"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,23,0,1,0,   0, "0xfffffe000a0228c0"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,28,0,2,0,   0, "0xfffffe000a02299c"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,41,1,0,0,   0, "0xfffffe000a0236ac"},
    {"gpu","AGXAcceleratorG18P","com.apple.iokit.IOGPUFamily","A",1,42,2,2,0,   0, "0xfffffe000a023d58"},
};
static const int g_ntgt = (int)(sizeof(g_tgts) / sizeof(g_tgts[0]));

// ---------------- AGX A 表（顺序 = gpuprobe 实测 SUCCESS 的顺序） ----------------
// 真机复现要点：sel 19 / 42 在**全新连接的第一发**调用返回 BadArgument，
// 在 0,1,2,3,4,5,16,17… 依次跑过之后再调就 SUCCESS ⇒ 这些 selector 依赖连接前置状态。
// 所以每个 GPU 目标先用它前面的条目预热，再进基线 + 边界遍历。
typedef struct { uint32_t sel, si, so; size_t sti, sto; } WEnt;
static const WEnt g_gpuA[] = {
    { 0,0,0,0, 64}, { 1,0,0,0, 64}, { 2,0,0,0,536}, { 3,0,0,0,  8},
    { 4,0,0,0, 32}, { 5,0,0,0, 16}, {16,0,0,0,  8}, {17,0,0,0,  4},
    {19,1,0,0, 24}, {21,0,0,0, 48}, {23,0,1,0,  0}, {28,0,2,0,  0},
    {41,1,0,0,  0}, {42,2,2,0,  0},
};
static const int g_gpuAn = (int)(sizeof(g_gpuA) / sizeof(g_gpuA[0]));

// ---------------- 边界值表（任务书原表，21 个） ----------------
static const uint64_t g_vals[] = {
    0ull, 1ull, 2ull, 3ull, 4ull, 7ull, 8ull, 15ull, 16ull,
    0x7Full, 0xFFull, 0x100ull, 0xFFFFull, 0x10000ull,
    0x7FFFFFFFull, 0x80000000ull, 0xFFFFFFFEull, 0xFFFFFFFFull,
    0x100000000ull, 0x2000000000000000ull, 0xFFFFFFFFFFFFFFFFull
};
static const int g_nvals = (int)(sizeof(g_vals) / sizeof(g_vals[0]));

// ---------------- 单次调用（独立线程 + 超时） ----------------
typedef struct {
    io_connect_t conn;
    uint32_t     sel;
    uint32_t     si, so;
    size_t       sti, sto;
    uint64_t     sin[SCALAR_CAP];
    uint8_t      bin[STRUCT_IN_CAP];
    IOReturn     kr;
    uint32_t     oc;
    size_t       sc;
    uint64_t     sout[SCALAR_CAP];
    uint8_t      bout[STRUCT_OUT_CAP];
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int done;
} Job;

static void *job_run(void *p) {
    Job *j = (Job *)p;
    // 关键：scalarOutputCount / structOutputSize 是 in/out —— 调用前必须填成本次容量，
    // 否则 MIG 看到 0 而派发声明是 24/64/536 等，直接 kIOReturnBadArgument(0xe00002c2)，
    // handler 根本不会跑。第一版漏了这一步，GPU sel 0..17/19/42 全部假阴性。
    j->oc = j->so;
    j->sc = j->sto;
    j->kr = (IOReturn)IOConnectCallMethod(
        j->conn, j->sel,
        j->sin, j->si,
        (j->sti ? j->bin : NULL), j->sti,
        (j->so  ? j->sout : NULL), &j->oc,
        (j->sto ? j->bout : NULL), &j->sc);
    pthread_mutex_lock(&j->m);
    j->done = 1;
    pthread_cond_signal(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

// 返回 0 = 有结果；1 = 超时（job 泄漏，不回收）；2 = 线程没起来
static int call_raw(io_connect_t conn, uint32_t sel,
                    const uint64_t *sin, uint32_t si,
                    const uint8_t *bin, size_t sti,
                    uint32_t so, size_t sto, Job **outJob) {
    Job *j = (Job *)calloc(1, sizeof(Job));
    j->conn = conn; j->sel = sel; j->si = si; j->sti = sti; j->so = so; j->sto = sto;
    if (sin && si) memcpy(j->sin, sin, sizeof(uint64_t) * si);
    if (bin && sti) memcpy(j->bin, bin, sti);
    pthread_mutex_init(&j->m, NULL);
    pthread_cond_init(&j->cv, NULL);

    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&th, &at, job_run, j) != 0) {
        pthread_attr_destroy(&at);
        free(j);
        *outJob = NULL;
        return 2;
    }
    pthread_attr_destroy(&at);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += CALL_TIMEOUT_S;

    int timedout = 0;
    pthread_mutex_lock(&j->m);
    while (!j->done) {
        int rc = pthread_cond_timedwait(&j->cv, &j->m, &ts);
        if (rc == ETIMEDOUT) { timedout = !j->done; break; }
    }
    int done = j->done;
    pthread_mutex_unlock(&j->m);

    if (timedout && !done) {
        // 内核调用不返回：内核线程收不回，join 会自己挂死。detach + 故意泄漏。
        pthread_detach(th);
        *outJob = j;
        return 1;
    }
    pthread_join(th, NULL);
    *outJob = j;
    return 0;
}

// ---------------- 基线（全 0） ----------------
typedef struct { IOReturn kr; uint32_t oc; size_t sc; int have; } Base;
static Base g_base[64];

static int tgt_index(const Tgt *t) { return (int)(t - g_tgts); }

static void do_baseline(io_connect_t conn, const Tgt *t, int *tot_timeouts) {
    uint64_t sin[SCALAR_CAP]; memset(sin, 0, sizeof(sin));
    uint8_t  bin[STRUCT_IN_CAP]; memset(bin, 0, sizeof(bin));
    Base *b = &g_base[tgt_index(t)];
    snprintf(g_hb_tag, sizeof g_hb_tag, "base %s sel=%u", t->svc, t->sel);
    emit("{\"k\":\"@pre\",\"ph\":\"base\",\"svc\":\"%s\",\"sel\":%u,\"si\":%u,\"sti\":%zu}",
         t->svc, t->sel, t->si, t->sti);
    Job *j = NULL;
    int rc = call_raw(conn, t->sel, sin, t->si, bin, t->sti, t->so, t->sto, &j);
    if (rc == 1) {
        (*tot_timeouts)++;
        emit("{\"k\":\"@timeout\",\"ph\":\"base\",\"svc\":\"%s\",\"sel\":%u}", t->svc, t->sel);
        return;
    }
    if (rc == 2) { emit("{\"k\":\"@threrr\",\"ph\":\"base\",\"svc\":\"%s\",\"sel\":%u}", t->svc, t->sel); return; }
    b->kr = j->kr; b->oc = j->oc; b->sc = j->sc; b->have = 1;
    emit("{\"k\":\"@base\",\"svc\":\"%s\",\"tab\":\"%s\",\"sel\":%u,\"h\":\"%s\",\"kr\":%d,\"krh\":\"0x%x\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
         t->svc, t->tab, t->sel, t->handler, (int)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
         j->oc, j->sc);
    free(j);
}

// ---------------- 阶段 1：单标量位置遍历 ----------------
static int phase1(io_connect_t conn, const Tgt *t, int *tot_timeouts, int *consec) {
    if (t->si == 0) {
        emit("{\"k\":\"@skip\",\"svc\":\"%s\",\"sel\":%u,\"why\":\"sIn=0\"}", t->svc, t->sel);
        return 0;
    }
    do_baseline(conn, t, tot_timeouts);
    const Base *b = &g_base[tgt_index(t)];
    int nlive = 0;

    for (uint32_t idx = 0; idx < t->si; idx++) {
        for (int vi = 0; vi < g_nvals; vi++) {
            uint64_t sin[SCALAR_CAP]; memset(sin, 0, sizeof(sin));
            uint8_t  bin[STRUCT_IN_CAP]; memset(bin, 0, sizeof(bin));
            sin[idx] = g_vals[vi];

            snprintf(g_hb_tag, sizeof g_hb_tag, "%s sel=%u idx=%u v=0x%llx",
                     t->svc, t->sel, idx, (unsigned long long)g_vals[vi]);
            emit("{\"k\":\"@pre\",\"ph\":1,\"svc\":\"%s\",\"sel\":%u,\"idx\":%u,\"v\":\"0x%llx\"}",
                 t->svc, t->sel, idx, (unsigned long long)g_vals[vi]);

            Job *j = NULL;
            int rc = call_raw(conn, t->sel, sin, t->si, bin, t->sti, t->so, t->sto, &j);
            if (rc == 1) {
                (*tot_timeouts)++; (*consec)++;
                emit("{\"k\":\"@timeout\",\"ph\":1,\"svc\":\"%s\",\"sel\":%u,\"idx\":%u,\"v\":\"0x%llx\"}",
                     t->svc, t->sel, idx, (unsigned long long)g_vals[vi]);
                if (*consec >= MAX_TIMEOUTS_PER_STAGE) {
                    emit("{\"k\":\"@abort\",\"ph\":1,\"svc\":\"%s\",\"sel\":%u,\"idx\":%u,\"v\":\"0x%llx\",\"consec\":%d}",
                         t->svc, t->sel, idx, (unsigned long long)g_vals[vi], *consec);
                    return -1;
                }
                continue;
            }
            if (rc == 2) {
                emit("{\"k\":\"@threrr\",\"ph\":1,\"svc\":\"%s\",\"sel\":%u,\"idx\":%u}", t->svc, t->sel, idx);
                continue;
            }
            *consec = 0;
            int live = 0;
            if (b->have) {
                if (j->kr != b->kr || j->oc != b->oc || j->sc != b->sc) live = 1;
            }
            if (live) nlive++;
            emit("{\"k\":\"@s1\",\"svc\":\"%s\",\"tab\":\"%s\",\"sel\":%u,\"h\":\"%s\",\"idx\":%u,"
                 "\"v\":\"0x%llx\",\"kr\":%d,\"krh\":\"0x%x\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"live\":%d}",
                 t->svc, t->tab, t->sel, t->handler, idx,
                 (unsigned long long)g_vals[vi], (int)j->kr, (unsigned)j->kr,
                 kr_name((unsigned)j->kr), j->oc, j->sc, live);
            if (j->kr == 0 && t->so) {
                char nb[512]; int p = 0; uint32_t n = j->oc < t->so ? j->oc : t->so;
                for (uint32_t i = 0; i < n && p < (int)sizeof(nb) - 24; i++)
                    p += snprintf(nb + p, sizeof(nb) - p, "%s0x%llx", i ? "," : "", (unsigned long long)j->sout[i]);
                emit("{\"k\":\"@so\",\"sel\":%u,\"idx\":%u,\"v\":\"0x%llx\",\"n\":%u,\"vals\":[%s]}",
                     t->sel, idx, (unsigned long long)g_vals[vi], j->oc, nb);
            }
            free(j);
        }
    }
    emit("{\"k\":\"@p1done\",\"svc\":\"%s\",\"sel\":%u,\"live\":%d}", t->svc, t->sel, nlive);
    return 0;
}

// ---------------- GPU 预热：按 A 表顺序跑目标之前的所有条目 ----------------
static void warm_gpu(io_connect_t conn, uint32_t target, int *tot_timeouts) {
    for (int i = 0; i < g_gpuAn; i++) {
        if (g_gpuA[i].sel >= target) break;
        uint64_t sin[SCALAR_CAP]; memset(sin, 0, sizeof(sin));
        uint8_t  bin[STRUCT_IN_CAP]; memset(bin, 0, sizeof(bin));
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", g_gpuA[i].sel);
        emit("{\"k\":\"@pre\",\"ph\":\"warm\",\"svc\":\"AGXAcceleratorG18P\",\"sel\":%u}",
             g_gpuA[i].sel);
        Job *j = NULL;
        int rc = call_raw(conn, g_gpuA[i].sel, sin, g_gpuA[i].si, bin, g_gpuA[i].sti,
                          g_gpuA[i].so, g_gpuA[i].sto, &j);
        if (rc == 1) { (*tot_timeouts)++; emit("{\"k\":\"@timeout\",\"ph\":\"warm\",\"sel\":%u}", g_gpuA[i].sel); continue; }
        if (rc == 2) continue;
        emit("{\"k\":\"@warm\",\"sel\":%u,\"kr\":%d,\"krh\":\"0x%x\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
             g_gpuA[i].sel, (int)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc);
        free(j);
    }
}

// ---------------- 阶段 3：边界细化（±1/±2、高 32 位截断、双标量交叉） ----------------
typedef struct { const char *stage; uint32_t sel; uint64_t v0, v1; const char *why; } P3;
static const P3 g_p3[] = {
    // MFB sel 51（0xa17ec28）：0..4 SUCCESS，>=7 BadArgument ⇒ 细化 5/6 与高位截断
    {"mfb",51, 0x5ull,                0, "0..4 之后第一个值"},
    {"mfb",51, 0x6ull,                0, "0..4 之后第二个值"},
    {"mfb",51, 0x100000004ull,        0, "低32=4 高32=1：测是否按 32 位截断"},
    {"mfb",51, 0x100000005ull,        0, "低32=5 高32=1"},
    {"mfb",51, 0x100000007ull,        0, "低32=7 高32=1"},
    {"mfb",51, 0xFFFFFFFF00000004ull, 0, "低32=4 高32=0xFFFFFFFF"},
    {"mfb",51, 0xFFFFFFFF00000007ull, 0, "低32=7 高32=0xFFFFFFFF"},
    {"mfb",51, 0x2000000000000004ull, 0, "低32=4 高位非0"},
    {"mfb",51, 0x2000000000000007ull, 0, "低32=7 高位非0"},
    {"mfb",51, 0x1FFFFFFFFull,        0, "低32=0xFFFFFFFF"},
    {"mfb",51, 0xFFFFFFFFFFFFFFFBull, 0, "低32=0xFFFFFFFB"},
    {"mfb",51, 0xFFFFFFFFFFFFFFF8ull, 0, "低32=0xFFFFFFF8"},
    // GPU sel 42（0xa023d58）：两个标量都活。0/1 与 0/1/2 各自单独测过，这里做交叉
    {"gpu",42, 0, 0, "交叉 0,0（对照）"},
    {"gpu",42, 0, 1, "交叉 0,1"},
    {"gpu",42, 0, 2, "交叉 0,2"},
    {"gpu",42, 0, 3, "交叉 0,3"},
    {"gpu",42, 1, 0, "交叉 1,0"},
    {"gpu",42, 1, 1, "交叉 1,1"},
    {"gpu",42, 1, 2, "交叉 1,2"},
    {"gpu",42, 1, 3, "交叉 1,3"},
    {"gpu",42, 2, 0, "交叉 2,0"},
    {"gpu",42, 2, 1, "交叉 2,1"},
    {"gpu",42, 2, 2, "交叉 2,2"},
    {"gpu",42, 2, 3, "交叉 2,3"},
    {"gpu",42, 0x80000000ull, 0, "x0 符号位：INT32_MIN"},
    {"gpu",42, 0, 0x80000000ull, "x1 符号位：INT32_MIN"},
    {"gpu",42, 2, 0x80000000ull, "x0=2 越界 + x1 负数"},
    {"gpu",42, 0x80000000ull, 0x80000000ull, "两个都是 INT32_MIN"},
    {"gpu",42, 0x100000002ull, 0, "低32=2 高32=1：测截断"},
    {"gpu",42, 0, 0x100000003ull, "低32=3 高32=1：测截断"},
};
static const int g_p3n = (int)(sizeof(g_p3) / sizeof(g_p3[0]));

static int phase3(io_connect_t conn, const Tgt *t, int *tot_timeouts, int *consec) {
    if (t->stage && strcmp(t->stage, "gpu") == 0) warm_gpu(conn, t->sel, tot_timeouts);
    do_baseline(conn, t, tot_timeouts);
    const Base *b = &g_base[tgt_index(t)];
    int nlive = 0;
    for (int i = 0; i < g_p3n; i++) {
        if (g_p3[i].sel != t->sel) continue;
        uint64_t sin[SCALAR_CAP]; memset(sin, 0, sizeof(sin));
        uint8_t  bin[STRUCT_IN_CAP]; memset(bin, 0, sizeof(bin));
        if (t->si > 0) sin[0] = g_p3[i].v0;
        if (t->si > 1) sin[1] = g_p3[i].v1;
        snprintf(g_hb_tag, sizeof g_hb_tag, "%s sel=%u p3=%llx,%llx",
                 t->svc, t->sel, (unsigned long long)g_p3[i].v0, (unsigned long long)g_p3[i].v1);
        emit("{\"k\":\"@pre\",\"ph\":3,\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%llx\",\"v1\":\"0x%llx\",\"why\":\"%s\"}",
             t->svc, t->sel, (unsigned long long)g_p3[i].v0,
             (unsigned long long)g_p3[i].v1, g_p3[i].why);
        Job *j = NULL;
        int rc = call_raw(conn, t->sel, sin, t->si, bin, t->sti, t->so, t->sto, &j);
        if (rc == 1) {
            (*tot_timeouts)++; (*consec)++;
            emit("{\"k\":\"@timeout\",\"ph\":3,\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%llx\",\"v1\":\"0x%llx\"}",
                 t->svc, t->sel, (unsigned long long)g_p3[i].v0, (unsigned long long)g_p3[i].v1);
            if (*consec >= MAX_TIMEOUTS_PER_STAGE) return -1;
            continue;
        }
        if (rc == 2) continue;
        *consec = 0;
        int live = b->have && (j->kr != b->kr || j->oc != b->oc || j->sc != b->sc);
        if (live) nlive++;
        emit("{\"k\":\"@s3\",\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%llx\",\"v1\":\"0x%llx\",\"why\":\"%s\","
             "\"kr\":%d,\"krh\":\"0x%x\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"live\":%d}",
             t->svc, t->sel, (unsigned long long)g_p3[i].v0, (unsigned long long)g_p3[i].v1,
             g_p3[i].why, (int)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc, live);
        free(j);
    }
    emit("{\"k\":\"@p3done\",\"svc\":\"%s\",\"sel\":%u,\"live\":%d}", t->svc, t->sel, nlive);
    return 0;
}

// ---------------- 阶段 2：sel 56 的 156 字节内容 ----------------
static uint64_t fnv1a64(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static uint64_t xs64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    *s = x;
    return x;
}

static void s56_one(io_connect_t conn, const Tgt *t, const uint8_t *buf, const char *mode,
                    int it, uint32_t off, const char *vstr, uint64_t seed,
                    int *tot_timeouts, int *consec, int *nlive) {
    const Base *b = &g_base[tgt_index(t)];
    snprintf(g_hb_tag, sizeof g_hb_tag, "s56 it=%d mode=%s off=%u", it, mode, off);
    emit("{\"k\":\"@pre\",\"ph\":2,\"svc\":\"%s\",\"sel\":%u,\"it\":%d,\"mode\":\"%s\",\"off\":%u,"
         "\"v\":\"%s\",\"seed\":\"0x%llx\",\"hash\":\"0x%llx\"}",
         t->svc, t->sel, it, mode, off, vstr, (unsigned long long)seed,
         (unsigned long long)fnv1a64(buf, t->sti));

    Job *j = NULL;
    int rc = call_raw(conn, t->sel, NULL, t->si, buf, t->sti, t->so, t->sto, &j);
    if (rc == 1) {
        (*tot_timeouts)++; (*consec)++;
        emit("{\"k\":\"@timeout\",\"ph\":2,\"it\":%d,\"mode\":\"%s\",\"off\":%u,\"v\":\"%s\"}",
             it, mode, off, vstr);
        return;
    }
    if (rc == 2) { emit("{\"k\":\"@threrr\",\"ph\":2,\"it\":%d,\"mode\":\"%s\"}", it, mode); return; }
    *consec = 0;
    int live = 0;
    if (b->have && (j->kr != b->kr || j->oc != b->oc || j->sc != b->sc)) live = 1;
    if (live) (*nlive)++;
    emit("{\"k\":\"@s2\",\"it\":%d,\"mode\":\"%s\",\"off\":%u,\"v\":\"%s\",\"seed\":\"0x%llx\","
         "\"hash\":\"0x%llx\",\"kr\":%d,\"krh\":\"0x%x\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"live\":%d}",
         it, mode, off, vstr, (unsigned long long)seed,
         (unsigned long long)fnv1a64(buf, t->sti),
         (int)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc, live);
    free(j);
}

static int phase2(io_connect_t conn, const Tgt *t, int *tot_timeouts, int *consec) {
    uint8_t buf[STRUCT_IN_CAP];
    int nlive = 0, it = 0;

    do_baseline(conn, t, tot_timeouts);          // 模式 A：全 0（也是基线）

    // 模式 A 显式记一条（与 @base 同内容，便于四模式对比）
    memset(buf, 0, t->sti);
    s56_one(conn, t, buf, "A", it++, 0, "zero", 0, tot_timeouts, consec, &nlive);
    if (*consec >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"ph\":2,\"mode\":\"A\"}"); return -1; }

    // 模式 B：全 0xFF
    memset(buf, 0xFF, t->sti);
    s56_one(conn, t, buf, "B", it++, 0, "0xff", 0, tot_timeouts, consec, &nlive);
    if (*consec >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"ph\":2,\"mode\":\"B\"}"); return -1; }

    // 模式 C：39 个 u32 槽，逐槽填 0..37，其余 0
    for (uint32_t slot = 0; slot < (uint32_t)(t->sti / 4); slot++) {
        for (uint32_t v = 0; v < 38; v++) {
            memset(buf, 0, t->sti);
            uint32_t le = v;
            memcpy(buf + slot * 4, &le, 4);
            char vs[32]; snprintf(vs, sizeof vs, "0x%x", v);
            s56_one(conn, t, buf, "C", it++, slot * 4, vs, 0, tot_timeouts, consec, &nlive);
            if (*consec >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"ph\":2,\"mode\":\"C\",\"off\":%u}", slot * 4); return -1; }
        }
    }

    // 模式 D：固定 seed 的随机，300 次（seed 与 hash 都落盘，可重放）
    uint64_t seed = 0x5CF055EED001ull;
    for (int k = 0; k < 300; k++) {
        uint64_t s = seed + (uint64_t)k * 0x9E3779B97F4A7C15ull;
        uint64_t st = s ? s : 1;
        for (size_t i = 0; i < t->sti; i += 8) {
            uint64_t r = xs64(&st);
            size_t n = (t->sti - i >= 8) ? 8 : (t->sti - i);
            memcpy(buf + i, &r, n);
        }
        char vs[32]; snprintf(vs, sizeof vs, "rnd%d", k);
        s56_one(conn, t, buf, "D", it++, 0, vs, s, tot_timeouts, consec, &nlive);
        if (*consec >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"ph\":2,\"mode\":\"D\",\"it\":%d}", k); return -1; }
    }

    emit("{\"k\":\"@p2done\",\"sel\":%u,\"calls\":%d,\"live\":%d}", t->sel, it, nlive);
    return 0;
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();
    gLog = fopen([[dir stringByAppendingPathComponent:@"scfuzz.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"scfuzz.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 scfuzz.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 scfuzz.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"scfuzz…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;   // 跑测期间不自动锁屏

    NSArray *args = [[NSProcessInfo processInfo] arguments];
    NSString *want = (args.count > 1) ? args[1] : @"all";
    int wd         = (args.count > 2) ? [args[2] intValue] : 300;

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"scfuzz.hb"] UTF8String]);
    pthread_t hb;
    pthread_create(&hb, NULL, hb_thread, hbPath);
    pthread_detach(hb);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(wd * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        emit("{\"k\":\"@watchdog\",\"sec\":%d}", wd);
        exit(3);
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            g_t0 = now_ms();
            emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                 "\"want\":\"%s\",\"wd\":%d,\"tgts\":%d,\"vals\":%d,\"timeout_s\":%d,\"maxto\":%d}",
                 kFingerprint, kBuildStamp,
                 [[[UIDevice currentDevice] systemVersion] UTF8String],
                 [[[UIDevice currentDevice] model] UTF8String],
                 [want UTF8String], wd, g_ntgt, g_nvals, CALL_TIMEOUT_S, MAX_TIMEOUTS_PER_STAGE);

            int tot_timeouts = 0, consec = 0, aborted = 0;

            for (int i = 0; i < g_ntgt && !aborted; i++) {
                const Tgt *t = &g_tgts[i];
                int want_p3 = [want isEqualToString:@"p3"];
                int in_p3 = 0;
                for (int k = 0; k < g_p3n; k++)
                    if (g_p3[k].sel == t->sel && g_p3[k].stage && strcmp(g_p3[k].stage, t->stage) == 0)
                        in_p3 = 1;
                if (want_p3) {
                    if (!in_p3) continue;
                } else if (![want isEqualToString:@"all"] &&
                           ![want isEqualToString:[NSString stringWithUTF8String:t->stage]]) continue;

                io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault,
                                                             IOServiceMatching(t->svc));
                io_connect_t c = 0;
                kern_return_t okr = s ? IOServiceOpen(s, mach_task_self(), t->type, &c)
                                      : (kern_return_t)-1;
                if (s) IOObjectRelease(s);
                emit("{\"k\":\"@open\",\"svc\":\"%s\",\"found\":%d,\"type\":%u,\"kr\":%u,\"krn\":\"%s\"}",
                     t->svc, s ? 1 : 0, t->type, (unsigned)okr, kr_name((unsigned)okr));
                if (okr != KERN_SUCCESS) continue;

                @autoreleasepool {
                    if (want_p3) {
                        int r = phase3(c, t, &tot_timeouts, &consec);
                        if (r < 0) aborted = 1;
                    } else if (t->stage && strcmp(t->stage, "s56") == 0) {
                        int r = phase2(c, t, &tot_timeouts, &consec);
                        if (r < 0) aborted = 1;
                    } else {
                        // GPU：先按 A 表顺序预热（sel 19/42 依赖连接前置状态），再扫标量
                        if (t->stage && strcmp(t->stage, "gpu") == 0) warm_gpu(c, t->sel, &tot_timeouts);
                        int r = phase1(c, t, &tot_timeouts, &consec);
                        if (r < 0) aborted = 1;
                    }
                }
                IOServiceClose(c);
                consec = 0;
            }

            emit("{\"k\":\"@done\",\"t\":%llu,\"timeouts\":%d,\"aborted\":%d}",
                 (unsigned long long)(now_ms() - g_t0), tot_timeouts, aborted);
            g_hb_stop = 1;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
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
