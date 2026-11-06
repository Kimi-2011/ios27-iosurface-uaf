// main.m — mfbcontract：三个「像 IOVA 的返回值」控制性判定 + MFB 47 selector 成功契约 + dump。
//
// 三个 stage：
//   iova      目标 1：IOSurfaceRoot/32、IOMobileFramebuffer/77、AppleCLCD2/77
//             同进程连调 3 次 / 双连接 / 入参扫描（sin 值、sti 长度、soc、sst）/ 回显测试
//   ct        目标 2：MFB 47 个 selector 的组合搜索，命中 kr==0 即停
//             grid: sin 0..4 × sti {0,8,64,156,664,1760,3084,4096} × soc {0,1,2,4,8} × sst {0,64,4096}
//   dump      目标 3：对 ct 命中的 selector，用最大预填容量重跑，hexdump 512B + 对齐指针判读
//
// 硬约束：
//   * 任何 8 字节对齐的 0xfffffe.. 立刻单独记 @KV 并打 @kvstop
//   * 单 selector 连续超时 2 次即跳过，不阻塞全局
//   * 每次调用前写 @pre 语义的心跳 tag；不重启设备；不改 out/ 既有文件
//   * 所在进程一次跑一个 stage：某次调用打死内核只损失这一个 stage
//
// 指纹（装前 strings 校验，必须命中 >=1）：MFBCON-20261101-contract-9c4e17

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <mach/mach_time.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>

static const char *kFingerprint = "MFBCON-20261101-contract-9c4e17";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define CALL_TIMEOUT_S  3
#define SEL_TO_LIMIT    2          // 单 selector 连续超时上限（超过就跳过该 selector）
#define SO_CAP          16
#define ST_CAP_MIG      4096
#define ST_CAP          8192
#define DUMP_MAX        512
#define NLADDER         10

#define SENT64          0xA5A5A5A5A5A5A5A5ull
#define SENT8           0x5A

static const uint32_t L_SOC[NLADDER] = { 0, 1, 2, 8, 16,  0,  0,    0,   16,  0 };
static const size_t   L_SST[NLADDER] = { 0, 0, 0, 0,  0,  8, 64, 4096, 4096, 3176 };

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[128] = "-";
static uint64_t g_t0 = 0;
static const char *g_svc = "-";
static int        g_type = -1;

static int g_kv_hits = 0;   // 本轮 0xfffffe.. 命中次数

static io_connect_t conn_of(uint32_t sel);          // 前向声明（ct/dump 共用连接）
static io_service_t find_service_named(const char *name);

static uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}
static uint64_t now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

static void *hb_thread(void *arg) {
    const char *path = (const char *)arg;
    while (!g_hb_stop) {
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "%llu tag=%s\n", (unsigned long long)(now_ms() - g_t0), g_hb_tag);
            fclose(f);
        }
        usleep(200000);
    }
    return NULL;
}

static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void progress(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void progress(const char *fmt, ...) {
    if (!gLog) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(gLog, fmt, ap);
    va_end(ap);
    fprintf(gLog, "\n");
    fflush(gLog);
}

static int g_sync_next = 0;
static int g_sync_tick = 0;

static void emit(const char *fmt, ...) {
    if (!gNd) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(gNd, fmt, ap);
    va_end(ap);
    fputc('\n', gNd);
    if (g_sync_next || (++g_sync_tick % 64) == 0) { fflush(gNd); fsync(fileno(gNd)); }
    g_sync_next = 0;
}

static const char *kr_name(unsigned k) {
    switch (k) {
    case 0x00000000: return "SUCCESS";
    case 0x00000001: return "KERN_INVALID_ADDRESS";
    case 0x00000002: return "KERN_PROTECTION_FAILURE";
    case 0xE00002BC: return "kIOReturnError";
    case 0xE00002BD: return "kIOReturnNoMemory";
    case 0xE00002BE: return "kIOReturnNoResources";
    case 0xE00002BF: return "kIOReturnIPCError";
    case 0xE00002C0: return "kIOReturnNoDevice";
    case 0xE00002C1: return "kIOReturnNotPrivileged";
    case 0xE00002C2: return "kIOReturnBadArgument";
    case 0xE00002C7: return "kIOReturnUnsupported";
    case 0xE00002C8: return "kIOReturnNoPower";
    case 0xE00002D2: return "kIOReturnNotReady";
    case 0xE00002D6: return "kIOReturnNotPermitted";
    case 0xE00002E2: return "kIOReturnBadMessageID";
    case 0xE00002E3: return "kIOReturnOverrun";
    case 0xE00002EA: return "kIOReturnNotAttached";
    case 0xE00002F0: return "kIOReturnBusy";
    default: return "OTHER";
    }
}

// ---------------------------------------------------------------- Job
typedef struct {
    io_connect_t conn;
    uint32_t sel, sinCnt, soc;
    size_t   sst, stinLen;
    const uint64_t *sin;
    const uint8_t  *stin;
    IOReturn kr;
    uint32_t oc;
    size_t   sc;
    uint64_t sout[SO_CAP];
    uint8_t  bst[ST_CAP];
    uint64_t us;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int done;
} Job;

static void *job_run(void *p) {
    Job *j = (Job *)p;
    j->oc = j->soc;
    j->sc = j->sst;
    for (int i = 0; i < SO_CAP; i++) j->sout[i] = SENT64;
    memset(j->bst, SENT8, sizeof j->bst);
    uint64_t a = now_us();
    j->kr = (IOReturn)IOConnectCallMethod(
        j->conn, j->sel,
        j->sinCnt ? j->sin : NULL, j->sinCnt,
        j->stinLen ? j->stin : NULL, j->stinLen,
        (j->soc ? j->sout : NULL), &j->oc,
        (j->sst ? j->bst : NULL), &j->sc);
    j->us = now_us() - a;
    pthread_mutex_lock(&j->m);
    j->done = 1;
    pthread_cond_signal(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

// 0 = 有结果；1 = 超时（线程泄漏不回收）；2 = 线程没起来
static int call_to_in(io_connect_t conn, uint32_t sel, uint32_t soc, size_t sst,
                      const uint64_t *sin, uint32_t sinCnt,
                      const uint8_t *stin, size_t stinLen, Job **outJob) {
    if (sst > ST_CAP_MIG) sst = ST_CAP_MIG;
    if (soc > SO_CAP) soc = SO_CAP;
    Job *j = (Job *)calloc(1, sizeof(Job));
    if (!j) { *outJob = NULL; return 2; }
    j->conn = conn; j->sel = sel; j->soc = soc; j->sst = sst;
    j->sin = sin; j->sinCnt = sinCnt; j->stin = stin; j->stinLen = stinLen;
    pthread_mutex_init(&j->m, NULL);
    pthread_cond_init(&j->cv, NULL);
    pthread_t th;
    if (pthread_create(&th, NULL, job_run, j) != 0) {
        pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
        free(j); *outJob = NULL; return 2;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += CALL_TIMEOUT_S;
    int timedout = 0;
    pthread_mutex_lock(&j->m);
    while (!j->done) {
        if (pthread_cond_timedwait(&j->cv, &j->m, &ts) == ETIMEDOUT) { timedout = !j->done; break; }
    }
    int done = j->done;
    pthread_mutex_unlock(&j->m);
    if (timedout && !done) { pthread_detach(th); *outJob = j; return 1; }
    pthread_join(th, NULL);
    *outJob = j;
    return 0;
}

static int call_to(io_connect_t conn, uint32_t sel, uint32_t soc, size_t sst, Job **outJob) {
    return call_to_in(conn, sel, soc, sst, NULL, 0, NULL, 0, outJob);
}

static void job_free(Job *j) {
    if (!j) return;
    pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
    free(j);
}

// ---------------------------------------------------------------- 判读
// 严格两种真形态：内核 VA（0xfffffe.. / 0xffffff..）与带 PAC 的高字节。
// 0x00000030aec27220 这类**不是**内核 VA，必须与 dword 视图一起看，避免 8 字节窗口
// 把相邻两个 32 位字段拼成「假指针」。
static int scan_ptr64(const uint64_t v, const char **kind) {
    if (v == 0xFFFFFFFFFFFFFFFFull || v == 0x00000000FFFFFFFFull) return 0;
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFE0000000000ull) { *kind = "kernel_va"; return 1; }
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFF0000000000ull) { *kind = "kernel_va"; return 1; }
    if ((v >> 56) >= 0xF0) { *kind = "pac_or_hi"; return 1; }
    return 0;
}

// 低区判读：给报告用，不进 @ptr
static const char *lo_kind(uint64_t v) {
    if (v == 0) return "zero";
    if (v < 0x1000) return "small_int";
    if (v < 0x100000000ull) return (v & 0xFFF) ? "mid32_unaligned" : "mid32_page";
    if ((v >> 40) == 0) return (v & 0xFFF) ? "hi40_unaligned" : "hi40_page";
    return "very_high";
}

static int sent64_intact(const Job *j) {
    uint32_t m = j->soc > SO_CAP ? SO_CAP : j->soc;
    if (m == 0) return 1;
    for (uint32_t i = 0; i < m; i++) if (j->sout[i] != SENT64) return 0;
    return 1;
}
static int sent8_intact(const Job *j) {
    size_t n = j->sst > ST_CAP ? ST_CAP : j->sst;
    if (n == 0) return 1;
    for (size_t i = 0; i < n; i++) if (j->bst[i] != SENT8) return 0;
    return 1;
}

// ---------------------------------------------------------------- dump（目标 3）
static void dump_job(const Job *j, const char *tag) {
    uint32_t om = j->oc > SO_CAP ? SO_CAP : j->oc;
    for (uint32_t k = 0; k < SO_CAP; k++) {
        if (k >= om && j->sout[k] == SENT64) continue;
        emit("{\"k\":\"@so\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"i\":%u,"
             "\"v\":\"0x%016llx\",\"cls\":\"%s\",\"e\":\"le\"}",
             g_svc, g_type, j->sel, tag, k, (unsigned long long)j->sout[k], lo_kind(j->sout[k]));
    }

    int w8 = !sent8_intact(j);
    size_t dumpLen = 0;
    if (j->sc > 0 && w8)      dumpLen = j->sc > DUMP_MAX ? DUMP_MAX : j->sc;
    else if (j->sc > 0)       dumpLen = 32;
    else if (w8)              dumpLen = 64;

    for (size_t off = 0; off < dumpLen; off += 16) {
        size_t n2 = (dumpLen - off) >= 16 ? 16 : (dumpLen - off);
        char hex[2 * 16 + 1];
        for (size_t i = 0; i < n2; i++) sprintf(hex + 2 * i, "%02x", j->bst[off + i]);
        hex[2 * n2] = 0;
        emit("{\"k\":\"@h\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"off\":%zu,\"b\":\"%s\"}",
             g_svc, g_type, j->sel, tag, off, hex);
    }
    if (j->sc > DUMP_MAX)
        emit("{\"k\":\"@trunc\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"sc\":%zu,\"shown\":%u}",
             g_svc, g_type, j->sel, tag, j->sc, (unsigned)DUMP_MAX);

    size_t w8n = dumpLen < DUMP_MAX ? dumpLen : DUMP_MAX;

    // 8 字节对齐 qword 视图
    for (size_t off = 0; off + 8 <= w8n; off += 8) {
        uint64_t v; memcpy(&v, j->bst + off, 8);
        if (v == 0) continue;
        const char *kind = NULL;
        int isp = scan_ptr64(v, &kind);
        emit("{\"k\":\"@w8\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"off\":%zu,"
             "\"v\":\"0x%016llx\",\"e\":\"le\",\"ptr\":%d,\"kind\":\"%s\",\"cls\":\"%s\"}",
             g_svc, g_type, j->sel, tag, off, (unsigned long long)v, isp, isp ? kind : "-", lo_kind(v));
        if (isp && strcmp(kind, "kernel_va") == 0) g_kv_hits++;
    }
    // 4 字节对齐 dword 视图（严格 off%4==0）—— 防 0x0000feff / 0xfffe 假象
    for (size_t off = 0; off + 4 <= w8n; off += 4) {
        uint32_t v; memcpy(&v, j->bst + off, 4);
        if (v == 0) continue;
        if (v < 0x10000u) continue;
        emit("{\"k\":\"@w4\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"off\":%zu,"
             "\"v\":\"0x%08x\",\"e\":\"le\"}", g_svc, g_type, j->sel, tag, off, v);
    }

    // 内核指针扫描：严格 8 字节对齐，扫全长度
    int hits = 0;
    size_t scanN = j->sc > 0 ? (j->sc > ST_CAP ? ST_CAP : j->sc) : 0;
    for (size_t off = 0; off + 8 <= scanN; off += 8) {
        uint64_t v; memcpy(&v, j->bst + off, 8);
        if (v == 0) continue;
        const char *kind = NULL;
        if (scan_ptr64(v, &kind)) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"off\":%zu,"
                 "\"v\":\"0x%016llx\",\"kind\":\"%s\",\"e\":\"le\",\"align\":8}",
                 g_svc, g_type, j->sel, tag, off, (unsigned long long)v, kind);
            if (strcmp(kind, "kernel_va") == 0) g_kv_hits++;
            if (++hits > 48) break;
        }
    }
    for (uint32_t k = 0; k < SO_CAP; k++) {
        if (j->sout[k] == SENT64 || j->sout[k] == 0) continue;
        const char *kind = NULL;
        if (scan_ptr64(j->sout[k], &kind)) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\",\"off\":%ld,"
                 "\"v\":\"0x%016llx\",\"kind\":\"%s\",\"e\":\"le\",\"from\":\"so\"}",
                 g_svc, g_type, j->sel, tag, -(long)k, (unsigned long long)j->sout[k], kind);
            if (strcmp(kind, "kernel_va") == 0) g_kv_hits++;
        }
    }
    if (j->sc == 0 && j->oc == 0 && sent8_intact(j) && sent64_intact(j))
        emit("{\"k\":\"@zero\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tag\":\"%s\"}",
             g_svc, g_type, j->sel, tag);
}

// ---------------------------------------------------------------- 预热
// MFB 的 47 个 selector 里有依赖前序状态的（旧轮记录：AGX 需要 0..5,16,17 预热）。
// MFB 侧用 0,1,2,3 各一次作为最低限度预热，记录结果不判读。
static void warmup(io_connect_t conn) {
    static const uint32_t sels[] = { 0, 1, 2, 3 };
    for (size_t i = 0; i < sizeof(sels)/sizeof(sels[0]); i++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", sels[i]);
        Job *j = NULL;
        int r = call_to(conn, sels[i], 1, 0, &j);
        if (r != 0) { emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"r\":%d}",
                           g_svc, g_type, sels[i], r); continue; }
        emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"kr\":%u,\"krh\":\"0x%08X\","
             "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
             g_svc, g_type, sels[i], (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc);
        job_free(j);
    }
}

// ---------------------------------------------------------------- 目标 1：iova
static io_service_t find_service_named(const char *name) {
    io_iterator_t iter = 0;
    CFMutableDictionaryRef m = IOServiceMatching(name);
    if (!m) return 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS) return 0;
    io_service_t svc = IOIteratorNext(iter);
    IOObjectRelease(iter);
    return svc;
}

static void iova_call(io_connect_t conn, const char *svc, uint32_t sel, const char *tag,
                      uint32_t sinCnt, const uint64_t *sin, size_t stiLen, const uint8_t *sti,
                      uint32_t soc, size_t sst) {
    snprintf(g_hb_tag, sizeof g_hb_tag, "iova %s sel=%u %s", svc, sel, tag);
    Job *j = NULL;
    int r = call_to_in(conn, sel, soc, sst, sin, sinCnt, sti, stiLen, &j);
    if (r == 2) { emit("{\"k\":\"@iova\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"r\":2}", svc, sel, tag); return; }
    if (r == 1) { emit("{\"k\":\"@iova\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"r\":1,\"to\":1}", svc, sel, tag); return; }

    char vbuf[24];
    if (j->oc >= 1 && j->sout[0] != SENT64) snprintf(vbuf, sizeof vbuf, "0x%016llx", (unsigned long long)j->sout[0]);
    else snprintf(vbuf, sizeof vbuf, "UNWRITTEN");

    emit("{\"k\":\"@iova\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"v\":\"%s\","
         "\"sin\":%u,\"sin0\":\"0x%016llx\",\"sti\":%zu,\"soc\":%u,\"sst\":%zu,"
         "\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,"
         "\"v1\":\"0x%016llx\",\"v2\":\"0x%016llx\",\"v3\":\"0x%016llx\",\"cls\":\"%s\",\"us\":%llu}",
         svc, sel, tag, vbuf,
         sinCnt, (unsigned long long)(sinCnt ? sin[0] : 0), stiLen, soc, sst,
         (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc,
         (unsigned long long)j->sout[0], (unsigned long long)j->sout[1], (unsigned long long)j->sout[2],
         j->oc >= 1 ? lo_kind(j->sout[0]) : "none", (unsigned long long)j->us);

    // 哨兵完整性 + structOut 是否被写
    if (j->sc > 0) {
        emit("{\"k\":\"@iova_st\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"s8\":%d,\"sc\":%zu}",
             svc, sel, tag, sent8_intact(j), j->sc);
        if (!sent8_intact(j)) dump_job(j, tag);
    }
    job_free(j);
}

static void stage_iova(void) {
    struct { const char *svc; uint32_t sel; } tgt[3] = {
        { "IOSurfaceRoot",        32 },
        { "IOMobileFramebuffer",  77 },
        { "AppleCLCD2",           77 },
    };

    // 回显探针：一个真实 mmap 页地址 + 一个魔数
    size_t pg = 16384;
    void *mp = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint64_t mmap_addr = (mp == MAP_FAILED) ? 0 : (uint64_t)(uintptr_t)mp;
    emit("{\"k\":\"@mmap\",\"addr\":\"0x%016llx\",\"len\":%zu}", (unsigned long long)mmap_addr, pg);

    for (int t = 0; t < 3; t++) {
        const char *svcName = tgt[t].svc;
        uint32_t sel = tgt[t].sel;
        g_svc = svcName;

        io_service_t svc = find_service_named(svcName);
        io_connect_t c1 = 0, c2 = 0;
        kern_return_t k1 = (kern_return_t)-1, k2 = (kern_return_t)-1;
        if (svc) {
            k1 = IOServiceOpen(svc, mach_task_self(), 0, &c1);
            k2 = IOServiceOpen(svc, mach_task_self(), 0, &c2);
        }
        emit("{\"k\":\"@iova_open\",\"svc\":\"%s\",\"found\":%d,\"sel\":%u,\"k1\":%u,\"k1n\":\"%s\","
             "\"c1\":%u,\"k2\":%u,\"k2n\":\"%s\",\"c2\":%u}",
             svcName, svc ? 1 : 0, sel, (unsigned)k1, kr_name((unsigned)k1), (unsigned)c1,
             (unsigned)k2, kr_name((unsigned)k2), (unsigned)c2);
        if (svc) IOObjectRelease(svc);
        if (k1 != KERN_SUCCESS || !c1) { emit("{\"k\":\"@iova_abort\",\"svc\":\"%s\"}", svcName); continue; }

        // --- 1) 同连接连调 3 次（基础契约：sin=0 sti=0 soc=1 sst=0）
        for (int i = 0; i < 3; i++) {
            char tag[16]; snprintf(tag, sizeof tag, "rep%d", i + 1);
            iova_call(c1, svcName, sel, tag, 0, NULL, 0, NULL, 1, 0);
        }

        // --- 2) 第二连接
        if (k2 == KERN_SUCCESS && c2) {
            iova_call(c2, svcName, sel, "conn2_rep1", 0, NULL, 0, NULL, 1, 0);
            iova_call(c2, svcName, sel, "conn2_rep2", 0, NULL, 0, NULL, 1, 0);
        }

        // --- 3) 入参扫描
        uint8_t *stin = (uint8_t *)malloc(ST_CAP_MIG);
        memset(stin, 0xA5, ST_CAP_MIG);

        static const uint64_t svals[] = { 0, 1, 2, 3, 0x100, 0xFFFF, 0x100000000ull, 0xDEADBEEFCAFEBABEull };
        static const char  *stags[]  = { "sin0", "sin1", "sin2", "sin3", "sin100", "sinffff",
                                         "sin_4g", "sin_magic" };
        for (size_t i = 0; i < sizeof(svals)/sizeof(svals[0]); i++) {
            uint64_t s[4] = { svals[i], 0, 0, 0 };
            iova_call(c1, svcName, sel, stags[i], 1, s, 0, NULL, 1, 0);
        }
        // mmap 地址回显测试
        {
            uint64_t s[4] = { mmap_addr, 0, 0, 0 };
            iova_call(c1, svcName, sel, "sin_mmap", 1, s, 0, NULL, 1, 0);
        }
        // 2 / 3 / 4 个 scalarIn
        {
            uint64_t s2[4] = { 1, 2, 0, 0 };
            iova_call(c1, svcName, sel, "sin2_12", 2, s2, 0, NULL, 1, 0);
            uint64_t s3[4] = { 1, 2, 3, 0 };
            iova_call(c1, svcName, sel, "sin3_123", 3, s3, 0, NULL, 1, 0);
            uint64_t s4[4] = { 0xFFFFFFFFull, 0xFFFFFFFFull, 0xFFFFFFFFull, 0xFFFFFFFFull };
            iova_call(c1, svcName, sel, "sin4_ff", 4, s4, 0, NULL, 1, 0);
        }
        // structIn 长度
        static const size_t stis[] = { 8, 64, 4096 };
        for (size_t i = 0; i < sizeof(stis)/sizeof(stis[0]); i++) {
            char tag[24]; snprintf(tag, sizeof tag, "sti%zu", stis[i]);
            iova_call(c1, svcName, sel, tag, 0, NULL, stis[i], stin, 1, 0);
        }
        // 输出容量
        static const uint32_t socs[] = { 2, 4, 8 };
        for (size_t i = 0; i < sizeof(socs)/sizeof(socs[0]); i++) {
            char tag[16]; snprintf(tag, sizeof tag, "soc%u", socs[i]);
            iova_call(c1, svcName, sel, tag, 0, NULL, 0, NULL, socs[i], 0);
        }
        static const size_t ssts[] = { 64, 4096 };
        for (size_t i = 0; i < sizeof(ssts)/sizeof(ssts[0]); i++) {
            char tag[16]; snprintf(tag, sizeof tag, "sst%zu", ssts[i]);
            iova_call(c1, svcName, sel, tag, 0, NULL, 0, NULL, 1, ssts[i]);
        }

        // --- 4) 中间插入别的 selector 后再读，看是否被别的调用扰动
        {
            static const uint32_t others[] = { 4, 7, 8, 18, 25 };
            for (size_t i = 0; i < sizeof(others)/sizeof(others[0]); i++) {
                Job *j = NULL;
                int r = call_to(c1, others[i], 1, 0, &j);
                if (r == 0) {
                    emit("{\"k\":\"@iova_other\",\"svc\":\"%s\",\"sel\":%u,\"kr\":%u,\"oc\":%u,"
                         "\"v\":\"0x%016llx\"}", svcName, others[i], (unsigned)j->kr, j->oc,
                         (unsigned long long)j->sout[0]);
                    job_free(j);
                }
            }
            iova_call(c1, svcName, sel, "after_others", 0, NULL, 0, NULL, 1, 0);
        }

        // --- 5) 第三次尝试：关掉 conn2 后再读 c1
        if (k2 == KERN_SUCCESS && c2) { IOServiceClose(c2); }
        iova_call(c1, svcName, sel, "after_close2", 0, NULL, 0, NULL, 1, 0);

        free(stin);
        IOServiceClose(c1);
        progress("[iova] %s sel=%u done", svcName, sel);
    }
}

// ---------------------------------------------------------------- 目标 1b：iova2 机制定性
// 目的：把「值到底是什么」钉死。
//   MFB/CLCD2 sel 77：在调用前后各取一次 mach_absolute_time()，看返回值是否落在 [t0,t1]。
//     -> 落在区间内 = 单调时钟读数（时间戳），不是地址。
//   IOSurfaceRoot sel 32：对返回值做 mach_vm_region + proc_regionfilename，
//     判断它是不是**本进程自己的地址空间**里的映射（用户 VA / 我们自己映射的页）。
static int vmmap_probe(uint64_t addr, char *out, size_t outlen) {
    vm_address_t a = (vm_address_t)addr;
    vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &cnt, &obj);
    if (kr != KERN_SUCCESS) {
        snprintf(out, outlen, "NOT_IN_OUR_TASK(kr=0x%x)", (unsigned)kr);
        return 0;
    }
    snprintf(out, outlen, "region_start=0x%llx end=0x%llx size=0x%llx prot=%u/%u share=%u inh=%u",
             (unsigned long long)a, (unsigned long long)(a + sz), (unsigned long long)sz,
             (unsigned)info.protection, (unsigned)info.max_protection,
             (unsigned)info.shared, (unsigned)info.inheritance);
    return 1;
}

static void stage_iova2(void) {
    struct { const char *svc; uint32_t sel; } tgt[3] = {
        { "IOSurfaceRoot",        32 },
        { "IOMobileFramebuffer",  77 },
        { "AppleCLCD2",           77 },
    };

    struct mach_timebase_info tb;
    mach_timebase_info(&tb);
    emit("{\"k\":\"@tb\",\"numer\":%u,\"denom\":%u,\"mach_now\":%llu}",
         tb.numer, tb.denom, (unsigned long long)mach_absolute_time());

    size_t pg = 16384;
    void *mp = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint64_t mmap_addr = (mp == MAP_FAILED) ? 0 : (uint64_t)(uintptr_t)mp;
    uint64_t *mbuf = (uint64_t *)malloc(4096);
    emit("{\"k\":\"@addr\",\"mmap\":\"0x%016llx\",\"malloc\":\"0x%016llx\",\"self\":\"0x%016llx\","
         "\"tid\":\"0x%016llx\",\"stack\":\"0x%016llx\"}",
         (unsigned long long)mmap_addr, (unsigned long long)(uintptr_t)mbuf,
         (unsigned long long)(uintptr_t)&stage_iova2,
         (unsigned long long)(uintptr_t)pthread_self(),
         (unsigned long long)(uintptr_t)&tb);

    for (int t = 0; t < 3; t++) {
        const char *svcName = tgt[t].svc;
        uint32_t sel = tgt[t].sel;
        g_svc = svcName;
        io_service_t svc = find_service_named(svcName);
        io_connect_t c1 = 0;
        kern_return_t k1 = svc ? IOServiceOpen(svc, mach_task_self(), 0, &c1) : (kern_return_t)-1;
        emit("{\"k\":\"@iova2_open\",\"svc\":\"%s\",\"sel\":%u,\"found\":%d,\"k\":%u,\"c\":%u}",
             svcName, sel, svc ? 1 : 0, (unsigned)k1, (unsigned)c1);
        if (svc) IOObjectRelease(svc);
        if (k1 != KERN_SUCCESS || !c1) continue;

        // 8 发采样，每发夹在两次 mach_absolute_time 之间
        for (int i = 0; i < 8; i++) {
            snprintf(g_hb_tag, sizeof g_hb_tag, "iova2 %s sel=%u #%d", svcName, sel, i);
            uint64_t t0 = mach_absolute_time();
            uint64_t n0 = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            Job *j = NULL;
            int r = call_to(c1, sel, 1, 0, &j);
            uint64_t n1 = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            uint64_t t1 = mach_absolute_time();
            if (r != 0) {
                emit("{\"k\":\"@iova2\",\"svc\":\"%s\",\"sel\":%u,\"i\":%d,\"r\":%d}", svcName, sel, i, r);
                continue;
            }
            uint64_t v = (j->oc >= 1 && j->sout[0] != SENT64) ? j->sout[0] : 0;
            int in_mach = (v >= t0 && v <= t1) ? 1 : 0;
            int in_ns   = (v >= n0 && v <= n1) ? 1 : 0;
            // mach ticks -> ns 换算后再比
            long double ns = (long double)v * (long double)tb.numer / (long double)tb.denom;
            emit("{\"k\":\"@iova2\",\"svc\":\"%s\",\"sel\":%u,\"i\":%d,\"v\":\"0x%016llx\","
                 "\"t0\":%llu,\"t1\":%llu,\"n0\":%llu,\"n1\":%llu,\"us\":%llu,"
                 "\"in_mach_ticks\":%d,\"in_ns\":%d,\"as_ns\":%.0Lf,\"kr\":%u,\"oc\":%u}",
                 svcName, sel, i, (unsigned long long)v,
                 (unsigned long long)t0, (unsigned long long)t1,
                 (unsigned long long)n0, (unsigned long long)n1,
                 (unsigned long long)j->us, in_mach, in_ns, ns,
                 (unsigned)j->kr, j->oc);
            job_free(j);
        }

        // 最后一发：如果值是本进程地址空间里的地址，vm_region 会认领它
        Job *j = NULL;
        if (call_to(c1, sel, 1, 0, &j) == 0) {
            uint64_t v = (j->oc >= 1 && j->sout[0] != SENT64) ? j->sout[0] : 0;
            char reg[700];
            int inTask = v ? vmmap_probe(v, reg, sizeof reg) : 0;
            char regm[700], regb[700];
            vmmap_probe(mmap_addr, regm, sizeof regm);
            vmmap_probe((uint64_t)(uintptr_t)mbuf, regb, sizeof regb);
            emit("{\"k\":\"@ireg\",\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%016llx\",\"in_our_task\":%d,"
                 "\"reg\":\"%s\",\"mmap_reg\":\"%s\",\"malloc_reg\":\"%s\"}",
                 svcName, sel, (unsigned long long)v, inTask, reg, regm, regb);
            job_free(j);
        }
        IOServiceClose(c1);
        progress("[iova2] %s sel=%u done", svcName, sel);
    }
}

// ---------------------------------------------------------------- 目标 1c：iova3 收尾定性
// 1) 用 vm_read_overwrite 安全读 sel 32 返回的那个只读映射（不直接解引用，读错只回错误码）
// 2) 把 sel 77 的返回值与 mach_absolute_time / mach_continuous_time 逐发对比，求常量偏移
static void safe_read(uint64_t addr, void *buf, size_t len, size_t *got, kern_return_t *krr) {
    mach_vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)addr, (vm_size_t)len,
                                         (vm_address_t)(uintptr_t)buf, &out);
    *krr = kr; *got = (size_t)out;
}

static void stage_iova3(void) {
    struct { const char *svc; uint32_t sel; } tgt[3] = {
        { "IOSurfaceRoot",        32 },
        { "IOMobileFramebuffer",  77 },
        { "AppleCLCD2",           77 },
    };

    for (int t = 0; t < 3; t++) {
        const char *svcName = tgt[t].svc;
        uint32_t sel = tgt[t].sel;
        g_svc = svcName;
        io_service_t svc = find_service_named(svcName);
        io_connect_t c1 = 0, c2 = 0;
        kern_return_t k1 = svc ? IOServiceOpen(svc, mach_task_self(), 0, &c1) : (kern_return_t)-1;
        kern_return_t k2 = svc ? IOServiceOpen(svc, mach_task_self(), 0, &c2) : (kern_return_t)-1;
        emit("{\"k\":\"@iova3_open\",\"svc\":\"%s\",\"sel\":%u,\"k1\":%u,\"c1\":%u,\"k2\":%u,\"c2\":%u}",
             svcName, sel, (unsigned)k1, (unsigned)c1, (unsigned)k2, (unsigned)c2);
        if (svc) IOObjectRelease(svc);
        if (k1 != KERN_SUCCESS || !c1) continue;

        uint64_t last = 0;
        for (int i = 0; i < 12; i++) {
            io_connect_t c = (i & 1) && (k2 == KERN_SUCCESS) ? c2 : c1;
            snprintf(g_hb_tag, sizeof g_hb_tag, "iova3 %s sel=%u #%d", svcName, sel, i);
            uint64_t t0 = mach_absolute_time(), ct0 = mach_continuous_time();
            Job *j = NULL;
            int r = call_to(c, sel, 1, 0, &j);
            uint64_t ct1 = mach_continuous_time(), t1 = mach_absolute_time();
            if (r != 0) { emit("{\"k\":\"@iova3\",\"svc\":\"%s\",\"i\":%d,\"r\":%d}", svcName, i, r); continue; }
            uint64_t v = (j->oc >= 1 && j->sout[0] != SENT64) ? j->sout[0] : 0;
            long long d_abs = (long long)v - (long long)t0;
            long long d_ct  = (long long)v - (long long)ct0;
            emit("{\"k\":\"@iova3\",\"svc\":\"%s\",\"sel\":%u,\"i\":%d,\"conn\":%u,\"v\":\"0x%016llx\","
                 "\"t0\":%llu,\"t1\":%llu,\"ct0\":%llu,\"ct1\":%llu,\"d_abs\":%lld,\"d_ct\":%lld,"
                 "\"dprev\":%lld,\"us\":%llu}",
                 svcName, sel, i, (unsigned)((i & 1) ? 2 : 1), (unsigned long long)v,
                 (unsigned long long)t0, (unsigned long long)t1,
                 (unsigned long long)ct0, (unsigned long long)ct1, d_abs, d_ct,
                 (long long)((long long)v - (long long)last), (unsigned long long)j->us);
            last = v;

            if (i == 0) {
                vm_address_t a = (vm_address_t)v; vm_size_t sz = 0;
                vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
                mach_port_t obj = MACH_PORT_NULL;
                kern_return_t rk = vm_region_64(mach_task_self(), &a, &sz, VM_REGION_BASIC_INFO_64,
                                                (vm_region_info_t)&info, &cnt, &obj);
                if (rk == KERN_SUCCESS && a == (vm_address_t)v && info.protection != 0) {
                    uint8_t buf[256]; size_t got = 0; kern_return_t rkr;
                    safe_read(v, buf, sizeof buf, &got, &rkr);
                    emit("{\"k\":\"@ureg\",\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%016llx\",\"size\":\"0x%llx\","
                         "\"prot\":%u,\"maxprot\":%u,\"share\":%u,\"inh\":%u,\"map_rk\":0,\"read_kr\":%u,\"got\":%zu}",
                         svcName, sel, (unsigned long long)v, (unsigned long long)sz,
                         (unsigned)info.protection, (unsigned)info.max_protection,
                         (unsigned)info.shared, (unsigned)info.inheritance,
                         (unsigned)rkr, got);
                    if (rkr == KERN_SUCCESS && got) {
                        size_t n = got > 256 ? 256 : got;
                        for (size_t off = 0; off < n; off += 16) {
                            size_t n2 = (n - off) >= 16 ? 16 : (n - off);
                            char hex[33]; for (size_t q = 0; q < n2; q++) sprintf(hex + 2*q, "%02x", buf[off+q]);
                            hex[2*n2] = 0;
                            emit("{\"k\":\"@uh\",\"svc\":\"%s\",\"sel\":%u,\"off\":%zu,\"b\":\"%s\"}", svcName, sel, off, hex);
                        }
                        for (size_t off = 0; off + 8 <= n; off += 8) {
                            uint64_t q; memcpy(&q, buf + off, 8);
                            if (q == 0) continue;
                            const char *kind = NULL; int isp = scan_ptr64(q, &kind);
                            emit("{\"k\":\"@uw8\",\"svc\":\"%s\",\"sel\":%u,\"off\":%zu,\"v\":\"0x%016llx\","
                                 "\"ptr\":%d,\"kind\":\"%s\",\"cls\":\"%s\"}",
                                 svcName, sel, off, (unsigned long long)q, isp, isp ? kind : "-", lo_kind(q));
                            if (isp && strcmp(kind, "kernel_va") == 0) g_kv_hits++;
                        }
                    }
                } else {
                    emit("{\"k\":\"@ureg\",\"svc\":\"%s\",\"sel\":%u,\"v\":\"0x%016llx\",\"mapped\":0,"
                         "\"rk\":%u,\"start\":\"0x%llx\",\"size\":\"0x%llx\",\"prot\":%u}",
                         svcName, sel, (unsigned long long)v, (unsigned)rk,
                         (unsigned long long)a, (unsigned long long)sz, (unsigned)info.protection);
                }
            }
            job_free(j);
        }
        if (k2 == KERN_SUCCESS && c2) IOServiceClose(c2);
        IOServiceClose(c1);
        progress("[iova3] %s sel=%u done", svcName, sel);
    }
}

// ---------------------------------------------------------------- 目标 2：ct
typedef struct { uint32_t sel, sinCnt, soc; size_t sti, sst; } Hit;

static void stage_ct(const uint32_t *sels, int nsel) {
    static const uint32_t sinCnts[5] = { 0, 1, 2, 3, 4 };
    static const size_t   stLens[8]  = { 0, 8, 64, 156, 664, 1760, 3084, 4096 };
    static const uint32_t socs[5]    = { 0, 1, 2, 4, 8 };
    static const size_t   ssts[3]    = { 0, 64, 4096 };
    uint64_t zs[4] = { 0, 0, 0, 0 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP_MIG, 1);
    int nHit = 0, nMiss = 0, nCalls = 0, nTo = 0;

    for (int i = 0; i < nsel; i++) {
        uint32_t sel = sels[i];
        int found = 0, tried = 0, consec = 0, tos = 0, nTouch = 0;
        // 返回码直方图（去重 + 计数）
        unsigned codes[16]; int ccnt[16]; int nCodes = 0;

        for (int a = 0; a < 5 && !found; a++) {
            for (int b = 0; b < 8 && !found; b++) {
                for (int c = 0; c < 5 && !found; c++) {
                    for (int d = 0; d < 3 && !found; d++) {
                        uint32_t sinCnt = sinCnts[a];
                        size_t   stLen  = stLens[b];
                        uint32_t soc    = socs[c];
                        size_t   sst    = ssts[d];
                        snprintf(g_hb_tag, sizeof g_hb_tag, "ct sel=%u sin=%u sti=%zu soc=%u sst=%zu",
                                 sel, sinCnt, stLen, soc, sst);
                        Job *j = NULL;
                        int r = call_to_in(conn_of(sel), sel, soc, sst, zs, sinCnt, zin, stLen, &j);
                        nCalls++; tried++;
                        if (r == 2) continue;
                        if (r == 1) {
                            nTo++; tos++; consec++;
                            emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"type\":%d,\"st\":\"ct\",\"sel\":%u,"
                                 "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu}",
                                 g_svc, g_type, sel, sinCnt, stLen, soc, sst);
                            if (consec >= SEL_TO_LIMIT) {
                                emit("{\"k\":\"@hang\",\"svc\":\"%s\",\"type\":%d,\"st\":\"ct\",\"sel\":%u,"
                                     "\"tried\":%d}", g_svc, g_type, sel, tried);
                                found = 1;
                            }
                            continue;
                        }
                        consec = 0;

                        int known = 0;
                        for (int q = 0; q < nCodes; q++) if (codes[q] == (unsigned)j->kr) { ccnt[q]++; known = 1; break; }
                        if (!known && nCodes < 16) { codes[nCodes] = (unsigned)j->kr; ccnt[nCodes] = 1; nCodes++; }

                        // 「擦边」记录：返回码离开 C2/C7 说明入参校验通过了、handler 真跑了。
                        // 这些组合即使没 SUCCESS，也是该 selector 的真实契约形状（下一步可用它定向重试）。
                        if (j->kr != 0xE00002C2 && j->kr != 0xE00002C7) {
                            if (nTouch < 8) {
                                emit("{\"k\":\"@touch\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,"
                                     "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu,"
                                     "\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
                                     g_svc, g_type, sel, sinCnt, stLen, soc, sst,
                                     (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc);
                                nTouch++;
                            }
                        }

                        if (j->kr == 0) {
                            found = 1; nHit++;
                            emit("{\"k\":\"@hit\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tried\":%d,"
                                 "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu,\"oc\":%u,\"sc\":%zu,"
                                 "\"s64\":%d,\"s8\":%d,\"us\":%llu}",
                                 g_svc, g_type, sel, tried, sinCnt, stLen, soc, sst,
                                 j->oc, j->sc, sent64_intact(j), sent8_intact(j),
                                 (unsigned long long)j->us);
                            // 命中时的即时 dump（用该组合的容量）
                            dump_job(j, "hit");
                        }
                        job_free(j);
                    }
                }
            }
        }

        char hist[512]; hist[0] = 0;
        for (int q = 0; q < nCodes; q++) {
            char one[40];
            snprintf(one, sizeof one, "%s0x%08X:%d", q ? "," : "", codes[q], ccnt[q]);
            strncat(hist, one, sizeof(hist) - strlen(hist) - 1);
        }
        if (nCodes == 0) snprintf(hist, sizeof hist, "-");
        emit("{\"k\":\"@kscan\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"combos\":600,\"tried\":%d,"
             "\"hit\":%d,\"timeouts\":%d,\"codes\":\"%s\"}",
             g_svc, g_type, sel, tried, nHit && found ? 1 : 0, tos, hist);
        if (!nHit) nMiss++;
        progress("[%s] ct sel=%u hit=%d/%d calls=%d", g_svc, sel, nHit, i + 1, nCalls);
    }
    free(zin);
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"ct\",\"nsel\":%d,\"hit\":%d,"
         "\"miss\":%d,\"calls\":%d,\"timeouts\":%d}",
         g_svc, g_type, nsel, nHit, nMiss, nCalls, nTo);
    progress("[%s] ct done: hit=%d nsel=%d calls=%d to=%d", g_svc, nHit, nsel, nCalls, nTo);
}

// ---------------------------------------------------------------- 目标 2b：ct2 定向重试
// 22 个没拿到 kr==0 的 selector 已经知道「入参形状」（sin 个数）。这里只变**值**：
// 尤其是 sel 89 —— sin=1 时返回 KERN_INVALID_ADDRESS(0x1)，形态与 M2Scaler sel 7 一致，
// 说明它把 scalarIn[0] 当地址去翻译。给它一个**我们自己 mmap 的有效页地址**试一次。
//
// 安全边界：**只喂用户态地址**。>= 0xFFFF000000000000 的向量一律不发 ——
// 那会真的去解引用内核地址，和「不重启设备」的硬约束冲突。这条限制写进报告。
static void stage_ct2(const uint32_t *sels, int nsel) {
    static const size_t   ssts[2] = { 0, 4096 };
    static const uint32_t socs[4] = { 0, 1, 2, 4 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP_MIG, 1);

    size_t pg = 16384;
    void *mp = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uint64_t mmap_addr = (mp == MAP_FAILED) ? 0 : (uint64_t)(uintptr_t)mp;
    emit("{\"k\":\"@mmap\",\"addr\":\"0x%016llx\",\"len\":%zu}", (unsigned long long)mmap_addr, pg);

    int nHit = 0, nCalls = 0;
    for (int i = 0; i < nsel; i++) {
        uint32_t sel = sels[i];
        int found = 0, tried = 0, consec = 0, touched = 0;

        static const int nvec = 12;
        for (int v = 0; v < nvec && !found; v++) {
            uint64_t vs[4] = { 0, 0, 0, 0 };
            uint32_t sinCnt = 1;
            switch (v) {
            case 0: sinCnt = 1; vs[0] = 0; break;
            case 1: sinCnt = 1; vs[0] = 1; break;
            case 2: sinCnt = 1; vs[0] = 0x1000; break;
            case 3: sinCnt = 1; vs[0] = mmap_addr; break;                       // 有效用户页
            case 4: sinCnt = 1; vs[0] = 0x1000000000ull; break;                 // 用户 VA 区间内但未映射
            case 5: sinCnt = 1; vs[0] = 0xFFFFFFFFFFFFFFFFull; break;           // -1（不是地址）
            case 6: sinCnt = 2; vs[0] = 1;   vs[1] = 1; break;
            case 7: sinCnt = 2; vs[0] = 0;   vs[1] = 1; break;
            case 8: sinCnt = 2; vs[0] = 1;   vs[1] = 0; break;
            case 9: sinCnt = 2; vs[0] = 0x1000; vs[1] = 0x1000; break;
            case 10: sinCnt = 3; vs[0] = 1; vs[1] = 1; vs[2] = 1; break;
            case 11: sinCnt = 4; vs[0] = 0; vs[1] = 0; vs[2] = 1; vs[3] = 0; break;
            }
            for (int c = 0; c < 4 && !found; c++) {
                for (int d = 0; d < 2 && !found; d++) {
                    snprintf(g_hb_tag, sizeof g_hb_tag, "ct2 sel=%u v=%d soc=%u sst=%zu",
                             sel, v, socs[c], ssts[d]);
                    Job *j = NULL;
                    int r = call_to_in(conn_of(sel), sel, socs[c], ssts[d], vs, sinCnt, zin, 0, &j);
                    nCalls++; tried++;
                    if (r == 2) continue;
                    if (r == 1) {
                        consec++;
                        emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"type\":%d,\"st\":\"ct2\",\"sel\":%u}",
                             g_svc, g_type, sel);
                        if (consec >= SEL_TO_LIMIT) { found = 1; }
                        continue;
                    }
                    consec = 0;
                    if (j->kr != 0xE00002C2 && j->kr != 0xE00002C7) {
                        touched++;
                        emit("{\"k\":\"@touch2\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"v\":%d,"
                             "\"sin\":%u,\"sin0\":\"0x%016llx\",\"sin1\":\"0x%016llx\","
                             "\"soc\":%u,\"sst\":%zu,\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
                             g_svc, g_type, sel, v, sinCnt,
                             (unsigned long long)vs[0], (unsigned long long)vs[1],
                             socs[c], ssts[d], (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc);
                        if (j->kr == 0) {
                            found = 1; nHit++;
                            emit("{\"k\":\"@hit2\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"v\":%d,"
                                 "\"sin\":%u,\"sin0\":\"0x%016llx\",\"soc\":%u,\"sst\":%zu,"
                                 "\"oc\":%u,\"sc\":%zu}", g_svc, g_type, sel, v, sinCnt,
                                 (unsigned long long)vs[0], socs[c], ssts[d], j->oc, j->sc);
                            dump_job(j, "hit2");
                        }
                    }
                    job_free(j);
                }
            }
        }
        emit("{\"k\":\"@kscan2\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tried\":%d,\"hit\":%d,"
             "\"touched\":%d}", g_svc, g_type, sel, tried, found && nHit ? 1 : 0, touched);
        progress("[%s] ct2 sel=%u hit=%d touched=%d", g_svc, sel, nHit, touched);
    }
    free(zin);
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"ct2\",\"nsel\":%d,\"hit\":%d,\"calls\":%d}",
         g_svc, g_type, nsel, nHit, nCalls);
}

// ---------------------------------------------------------------- 目标 3：dump
// 对每个 (sel,sin,sti) 用容量阶梯 (soc,sst) 找一个 kr==0 且 (oc|sc) 最大的组合，然后 dump。
static void stage_dump(const Hit *hits, int nh) {
    static const uint32_t socs[5] = { 1, 2, 4, 8, 0 };
    static const size_t   ssts[3] = { 4096, 64, 0 };
    uint64_t zs[4] = { 0, 0, 0, 0 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP_MIG, 1);
    int nOk = 0;

    for (int i = 0; i < nh; i++) {
        uint32_t sel = hits[i].sel;
        uint32_t sinCnt = hits[i].sinCnt;
        size_t   sti = hits[i].sti;
        int best = -1; Job *bestj = NULL;
        uint32_t bsoc = 0; size_t bsst = 0;

        for (int c = 0; c < 5; c++) {
            for (int d = 0; d < 3; d++) {
                snprintf(g_hb_tag, sizeof g_hb_tag, "dump sel=%u soc=%u sst=%zu", sel, socs[c], ssts[d]);
                Job *j = NULL;
                int r = call_to_in(conn_of(sel), sel, socs[c], ssts[d], zs, sinCnt, zin, sti, &j);
                if (r != 0) continue;
                if (j->kr == 0) {
                    int score = (int)(j->oc + j->sc);
                    if (score > best) { if (bestj) job_free(bestj); bestj = j; best = score; bsoc = socs[c]; bsst = ssts[d]; }
                    else job_free(j);
                } else job_free(j);
            }
        }
        if (bestj) {
            nOk++;
            char tag[32]; snprintf(tag, sizeof tag, "d_soc%u_sst%zu", bsoc, bsst);
            emit("{\"k\":\"@dump\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"sin\":%u,\"sti\":%zu,"
                 "\"soc\":%u,\"sst\":%zu,\"oc\":%u,\"sc\":%zu}",
                 g_svc, g_type, sel, sinCnt, sti, bsoc, bsst, bestj->oc, bestj->sc);
            dump_job(bestj, tag);
            job_free(bestj);
        } else {
            emit("{\"k\":\"@dump_fail\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u}", g_svc, g_type, sel);
        }
        progress("[%s] dump sel=%u ok=%d", g_svc, sel, bestj ? 1 : 0);
    }
    free(zin);
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"dump\",\"nsel\":%d,\"ok\":%d}",
         g_svc, g_type, nh, nOk);
}

// ---------------------------------------------------------------- 参数
static int    g_argc = 0;
static char **g_argv = NULL;

static void build_argv(void) {
    NSArray *a = [[NSProcessInfo processInfo] arguments];
    g_argc = (int)a.count;
    g_argv = (char **)calloc((size_t)g_argc + 1, sizeof(char *));
    for (int i = 0; i < g_argc; i++) g_argv[i] = strdup([[a objectAtIndex:i] UTF8String]);
    g_argv[g_argc] = NULL;
}
static const char *kv(const char *key) {
    size_t n = strlen(key);
    for (int i = 2; i < g_argc; i++)
        if (strncmp(g_argv[i], key, n) == 0 && g_argv[i][n] == '=') return g_argv[i] + n + 1;
    return NULL;
}
static long kvl(const char *key, long dflt) {
    const char *v = kv(key);
    return v ? strtol(v, NULL, 10) : dflt;
}
static int parse_list(const char *csv, uint32_t *out, int cap) {
    if (!csv || !*csv || strcmp(csv, "-") == 0) return 0;
    int n = 0; const char *p = csv;
    while (*p && n < cap) {
        out[n++] = (uint32_t)strtoul(p, (char **)&p, 0);
        if (*p == ',') p++;
    }
    return n;
}

// 全局连接（ct/dump 用同一个 conn）
static io_connect_t g_conn = 0;
static io_connect_t conn_of(uint32_t sel) { (void)sel; return g_conn; }

// ---------------------------------------------------------------- App
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();
    gLog = fopen([[dir stringByAppendingPathComponent:@"mfbcon.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"mfbcon.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 mfbcon.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 mfbcon.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"mfbcontract: iova-control + 47-selector contract…";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"iova";
    NSString *svcNS = (g_argc > 2) ? [NSString stringWithUTF8String:g_argv[2]] : @"IOMobileFramebuffer";
    long      otype = (g_argc > 3) ? strtol(g_argv[3], NULL, 0) : 0;
    g_svc  = strdup(svcNS.UTF8String);
    g_type = (int)otype;

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"mfbcon.hb"] UTF8String]);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, hbPath) == 0) pthread_detach(hb);

    int wd = (int)kvl("wd", 900);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(wd * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        emit("{\"k\":\"@watchdog\",\"sec\":%d}", wd);
        g_hb_stop = 1;
        exit(3);
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            g_t0 = now_ms();
            emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                 "\"stage\":\"%s\",\"svc\":\"%s\",\"type\":%d,\"wd\":%d,\"timeout_s\":%d,"
                 "\"socap\":%d,\"sscap\":%d}",
                 kFingerprint, kBuildStamp,
                 [[[UIDevice currentDevice] systemVersion] UTF8String],
                 [[[UIDevice currentDevice] model] UTF8String],
                 stage.UTF8String, g_svc, (int)otype, wd, CALL_TIMEOUT_S, SO_CAP, ST_CAP_MIG);

            if ([stage isEqualToString:@"iova"]) {
                stage_iova();
            } else if ([stage isEqualToString:@"iova2"]) {
                stage_iova2();
            } else if ([stage isEqualToString:@"iova3"]) {
                stage_iova3();
            } else {
                io_service_t svc = find_service_named(g_svc);
                kern_return_t okr = (kern_return_t)-1;
                if (svc) okr = IOServiceOpen(svc, mach_task_self(), (uint32_t)otype, &g_conn);
                emit("{\"k\":\"@open\",\"svc\":\"%s\",\"found\":%d,\"type\":%d,\"kr\":%u,\"krn\":\"%s\",\"conn\":%u}",
                     g_svc, svc ? 1 : 0, (int)otype, (unsigned)okr, kr_name((unsigned)okr), (unsigned)g_conn);
                if (svc) IOObjectRelease(svc);

                if (okr == KERN_SUCCESS && g_conn) {
                    warmup(g_conn);

                    if ([stage isEqualToString:@"ct"]) {
                        uint32_t sels[512];
                        int nsel = parse_list(kv("sels"), sels, 512);
                        emit("{\"k\":\"@plan\",\"st\":\"ct\",\"nsel\":%d}", nsel);
                        stage_ct(sels, nsel);
                    } else if ([stage isEqualToString:@"ct2"]) {
                        uint32_t sels[512];
                        int nsel = parse_list(kv("sels"), sels, 512);
                        emit("{\"k\":\"@plan\",\"st\":\"ct2\",\"nsel\":%d}", nsel);
                        stage_ct2(sels, nsel);
                    } else if ([stage isEqualToString:@"dump"]) {
                        // ct=sel:sin:sti,sel:sin:sti,...
                        Hit hits[128]; int nh = 0;
                        const char *csv = kv("ct");
                        if (csv) {
                            const char *p = csv;
                            while (*p && nh < 128) {
                                uint32_t s = (uint32_t)strtoul(p, (char **)&p, 0);
                                if (*p != ':') break;
                                p++;
                                uint32_t sn = (uint32_t)strtoul(p, (char **)&p, 0);
                                if (*p != ':') break;
                                p++;
                                size_t st = (size_t)strtoul(p, (char **)&p, 0);
                                hits[nh].sel = s; hits[nh].sinCnt = sn; hits[nh].sti = st;
                                nh++;
                                if (*p == ',') p++;
                            }
                        }
                        emit("{\"k\":\"@plan\",\"st\":\"dump\",\"nsel\":%d}", nh);
                        stage_dump(hits, nh);
                    } else {
                        emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
                    }
                    IOServiceClose(g_conn);
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"open_failed\",\"svc\":\"%s\",\"kr\":%u}",
                         g_svc, (unsigned)okr);
                }
            }

            emit("{\"k\":\"@done\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"%s\",\"kv_hits\":%d,\"t\":%llu}",
                 g_svc, (int)otype, stage.UTF8String, g_kv_hits, (unsigned long long)(now_ms() - g_t0));
            g_hb_stop = 1;
            if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
            if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
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
