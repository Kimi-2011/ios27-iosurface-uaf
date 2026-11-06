// main.m — svcreenum：对任意可打开服务用【正确姿势】重新枚举 selector 面。
//
// 前一轮（out/SVC2-PROBE.md）的致命错误：
//   IOConnectCallMethod 的 scalarOutputCount / structOutputSize 是 in/out。
//   传 0 的后果不是「输出为空」，而是该 selector 从派发里被直接抹掉 -> 0xE00002C7 Unsupported
//   = 看起来「selector 不存在」。实测：AppleM2ScalerCSCDriver 用 (0,0) 只得 1 个 selector（11），
//   预填后得 12 个（0..11），且 sel 11 在 (0,4096) 下 kr==0 且 sc==664（内核真写了 664 字节）。
//
// 本轮做法（输出容量阶梯）：
//   (0,0) (1,0) (2,0) (8,0) (16,0) (0,8) (0,64) (0,4096) (16,4096) (0,3176)
//   每个组合独立调用；输出容量【每轮重新预填】（它是 in/out，会被写回）。
//   判读：任意一组容量下 kr != 0xE00002C7 ⇒ 该 selector 存在。
//         全部组合都 0xE00002C7 ⇒ 才算真不存在。
//         kr==0 且 (sc>0 || oc>0) ⇒ 内核真的写了输出，单独标出 + hexdump。
//
// 硬约束（都是上一轮踩出来的）：
//   1. 每轮预填 uint32_t soc=SOC; size_t sst=SST; 缓冲区填哨兵 0xA5 / 0x5A，
//      用来区分「内核真写了」与「只回写计数」。
//   2. 预热：新连接先按序打 sel 0,1,2,3 各一次（忽略结果），再正式扫。
//   3. 每次调用独立 pthread + 3s 超时；超时 detach 泄漏该线程与缓冲，主线程继续。
//      同一个 selector 连续 2 次超时 ⇒ @hang，跳过它剩下的容量组合，继续下一个 selector
//      （一个 selector 挂死不影响后面）。连续 4 个 selector 都挂 ⇒ @abort 熔断。
//   4. 调用前先落 @pre 并 fflush+fsync。
//   5. 指针判读严格 8 字节对齐；同时给出 4 字节对齐 LE 视图，避免「4 字节 0x0000feff 被
//      未对齐 8 字节窗口读成 0xfffe」那类误判。字节序显式标注为 le（arm64 iOS 小端）。
//
// 阶段：
//   exist   区间 [from,to] 全阶梯（默认 0..255）
//   dense   指定 sels 的加密网格 soc 0..8 × sst {0,1,4,8,16,64,156,664,4096}（救阶梯漏网）
//   warm    只预热
//
// 指纹（装前 strings 校验必须 >=1）：REENUM-20261101-svcladder-b7f2e1
// 只做 selector 存在性枚举 + 输出 dump。不跑竞态、不碰 harness/israce/、不改 out/ 既有文件。

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

static const char *kFingerprint = "REENUM-20261101-svcladder-b7f2e1";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define CALL_TIMEOUT_S   3
#define SEL_HANG_LIMIT   2     // 同一 selector 连续超时次数上限
#define SYS_HANG_LIMIT   4     // 连续这么多个 selector 都挂 -> 熔断

#define SO_CAP           16
#define ST_CAP           8192              // sst 最大 4096，留余量
#define DUMP_MAX         512               // 每段 dump 上限（任务书要求）

#define SENT64           0xA5A5A5A5A5A5A5A5ull
#define SENT8            0x5A

// ---- 输出容量阶梯（任务书给的 10 组，顺序固定）----
static const uint32_t L_SOC[10] = { 0, 1, 2, 8, 16,  0,  0,    0,   16,  0 };
static const size_t   L_SST[10] = { 0, 0, 0, 0,  0,  8, 64, 4096, 4096, 3176 };
#define NLADDER 10

// ---- dense 网格（救漏网：只认精确容量的 handler）----
static const size_t D_SST[9] = { 0, 1, 4, 8, 16, 64, 156, 664, 4096 };
#define ND_SST 9
#define ND_SOC 9   // 0..8

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[128] = "-";
static uint64_t g_t0 = 0;
static const char *g_svc = "-";
static int        g_type = -1;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}
static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
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
static void progress(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void progress(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fprintf(stderr, "%s\n", buf); fflush(stderr);
}

static int g_sync_next = 0;   // 下一条记录强制落盘（@pre 用）
static int g_sync_tick = 0;

static void emit(const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
    // 不往 stderr 逐行镜像：--console 管道每行 ~30ms，会把 2560 发调用拖成几分钟。
    // 记录只进设备端文件，控制台靠下面 progress() 每 16 个 selector 打一行。
    if (gLog) { fputs(buf, gLog); fflush(gLog); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd); }
    // fsync 在 iOS 上约 40ms/次，逐行 fsync 会把每次调用拖到 270ms。
    // 折中：@pre 前强制一次（panic 时能定位到挂在哪一发），其余每 64 行一次。
    if (g_sync_next || ++g_sync_tick >= 32) {
        int both = g_sync_next;
        g_sync_next = 0; g_sync_tick = 0;
        if (gNd)  fsync(fileno(gNd));
        if (both && gLog) fsync(fileno(gLog));
    }
}

static const char *kr_name(unsigned k) {
    switch (k) {
        case 0x00000000: return "SUCCESS";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002bd: return "kIOReturnNoMemory";
        case 0xe00002be: return "kIOReturnNoResources";
        case 0xe00002c0: return "kIOReturnNoDevice";
        case 0xe00002c1: return "kIOReturnNotPrivileged";
        case 0xe00002c2: return "kIOReturnBadArgument";
        case 0xe00002c3: return "kIOReturnLockedRead";
        case 0xe00002c4: return "kIOReturnLockedWrite";
        case 0xe00002c5: return "kIOReturnExclusiveAccess";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c8: return "kIOReturnVMError";
        case 0xe00002c9: return "kIOReturnInternalError";
        case 0xe00002ca: return "kIOReturnIOError";
        case 0xe00002cd: return "kIOReturnNotOpen";
        case 0xe00002d5: return "kIOReturnBusy";
        case 0xe00002d6: return "kIOReturnAborted";
        case 0xe00002d7: return "kIOReturnTimeout";
        case 0xe00002bf: return "kIOReturnIPCError";
        case 0xe00002e2: return "kIOReturnNotAttached";
        case 0xfffffecd: return "MIG_REMOTE_ERROR(-307)";
        default:         return "OTHER";
    }
}

// ---------------- 单次调用（独立线程 + 3s 超时） ----------------
typedef struct {
    io_connect_t conn;
    uint32_t sel;
    uint32_t soc;            // 预填容量（in）
    size_t   sst;            // 预填容量（in）
    const uint64_t *sin;     // scalarIn（全 0）
    uint32_t sinCnt;
    const uint8_t  *stin;    // structIn（全 0）
    size_t   stinLen;

    IOReturn kr;
    uint32_t oc;             // 调用后：内核实际写入的 scalarOut 个数
    size_t   sc;             // 调用后：内核实际写入的 structOut 字节数
    uint64_t sout[SO_CAP];
    uint8_t  bst[ST_CAP];
    uint64_t us;

    pthread_mutex_t m;
    pthread_cond_t  cv;
    int done;
} Job;

static void *job_run(void *p) {
    Job *j = (Job *)p;

    // ---- 关键：每轮重新预填容量 + 哨兵（in/out 会被内核写回）----
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

// MIG 层硬上限：structOut 容量 > 4096 直接 kIOReturnIPCError（0xE00002BF），根本没进派发。
// 所以容量必须夹到 4096；缓冲区留 8192 只是为了让哨兵扫描有富余。
#define ST_CAP_MIG  4096

// 0 = 有结果；1 = 超时（线程与 job 泄漏不回收）；2 = 线程没起来
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

    if (timedout && !done) {
        pthread_detach(th);
        *outJob = j;
        return 1;
    }
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

// ---------------- 哨兵 / 指针扫描 ----------------
static int sent64_intact(const Job *j) {
    // 只看容量范围内的
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
// 只认两种真形态：
//   kernel   : 0xfffffe..（arm64 iOS 内核线性映射）
//   pac_or_hi: 最高字节 >= 0xF0（带 PAC 的内核指针 / 高位标签）
// 注意：0x0000004001010101 这种是【两个 32 位字段被 8 字节窗口读到一起】，
//       不是指针；所以不再把 >=4GiB 的值当 user_va（上一轮的误判来源）。
static int scan_ptr64(const uint64_t v, const char **kind) {
    // 全 1 是「写了个 -1」，不是指针（IOMobileFramebuffer sel 80 就回吐 0xffffffffffffffff）
    if (v == 0xFFFFFFFFFFFFFFFFull || v == 0x00000000FFFFFFFFull) return 0;
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFE0000000000ull) { *kind = "kernel"; return 1; }
    if ((v >> 56) >= 0xF0) { *kind = "pac_or_hi"; return 1; }
    return 0;
}

// ---------------- 输出 dump（只对 kr==0） ----------------
static void dump_job(const Job *j) {
    // 标量输出：只打内核确实写过（!= 哨兵）或 oc 覆盖到的
    uint32_t om = j->oc > SO_CAP ? SO_CAP : j->oc;
    for (uint32_t k = 0; k < SO_CAP; k++) {
        if (k >= om && j->sout[k] == SENT64) continue;
        emit("{\"k\":\"@so\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"soc\":%u,\"sst\":%zu,\"i\":%u,"
             "\"v\":\"0x%016llx\",\"e\":\"le\"}",
             g_svc, g_type, j->sel, j->soc, j->sst, k, (unsigned long long)j->sout[k]);
    }

    // structOut hexdump：最多 512 字节，16 字节一行
    int w8 = !sent8_intact(j);
    size_t dumpLen = 0;
    if (j->sc > 0 && w8)      dumpLen = j->sc > DUMP_MAX ? DUMP_MAX : j->sc;
    else if (j->sc > 0)       dumpLen = 32;      // 容量被回写但内核没写字节
    else if (w8)              dumpLen = 64;
    for (size_t off = 0; off < dumpLen; off += 16) {
        size_t n2 = (dumpLen - off) >= 16 ? 16 : (dumpLen - off);
        char hex[2 * 16 + 1];
        for (size_t i = 0; i < n2; i++) sprintf(hex + 2 * i, "%02x", j->bst[off + i]);
        hex[2 * n2] = 0;
        emit("{\"k\":\"@h\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%zu,\"b\":\"%s\"}",
             g_svc, g_type, j->sel, off, hex);
    }
    if (j->sc > DUMP_MAX) emit("{\"k\":\"@trunc\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"sc\":%zu,\"shown\":%u}",
                               g_svc, g_type, j->sel, j->sc, (unsigned)DUMP_MAX);

    // 8 字节对齐 LE qword 视图（严格 off%8==0）
    size_t w8n = dumpLen < DUMP_MAX ? dumpLen : DUMP_MAX;
    for (size_t off = 0; off + 8 <= w8n; off += 8) {
        uint64_t v; memcpy(&v, j->bst + off, 8);
        if (v == 0) continue;
        const char *kind = NULL;
        int isp = scan_ptr64(v, &kind);
        if (isp)
            emit("{\"k\":\"@w8\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%zu,\"v\":\"0x%016llx\",\"e\":\"le\",\"ptr\":1,\"kind\":\"%s\"}",
                 g_svc, g_type, j->sel, off, (unsigned long long)v, kind);
        else
            emit("{\"k\":\"@w8\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%zu,\"v\":\"0x%016llx\",\"e\":\"le\",\"ptr\":0}",
                 g_svc, g_type, j->sel, off, (unsigned long long)v);
    }
    // 4 字节对齐 LE dword 视图（严格 off%4==0）—— 防止 0x0000feff 被读成 0xfffe
    for (size_t off = 0; off + 4 <= w8n; off += 4) {
        uint32_t v; memcpy(&v, j->bst + off, 4);
        if (v == 0) continue;
        if (v < 0x10000u) continue;   // 小值噪声太多，只记 >= 64KiB 的
        emit("{\"k\":\"@w4\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%zu,\"v\":\"0x%08x\",\"e\":\"le\"}",
             g_svc, g_type, j->sel, off, v);
    }

    // 内核指针扫描：严格 8 字节对齐，扫全 4096
    int hits = 0;
    size_t scanN = j->sc > 0 ? (j->sc > ST_CAP ? ST_CAP : j->sc) : 0;
    for (size_t off = 0; off + 8 <= scanN; off += 8) {
        uint64_t v; memcpy(&v, j->bst + off, 8);
        if (v == 0) continue;
        const char *kind = NULL;
        if (scan_ptr64(v, &kind)) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%zu,\"v\":\"0x%016llx\","
                 "\"kind\":\"%s\",\"e\":\"le\",\"align\":8}",
                 g_svc, g_type, j->sel, off, (unsigned long long)v, kind);
            if (++hits > 48) break;
        }
    }
    for (uint32_t k = 0; k < SO_CAP; k++) {
        if (j->sout[k] == SENT64 || j->sout[k] == 0) continue;
        const char *kind = NULL;
        if (scan_ptr64(j->sout[k], &kind))
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"off\":%ld,\"v\":\"0x%016llx\","
                 "\"kind\":\"%s\",\"e\":\"le\",\"from\":\"so\"}",
                 g_svc, g_type, j->sel, -(long)k, (unsigned long long)j->sout[k], kind);
    }

    if (j->sc == 0 && j->oc == 0 && sent8_intact(j) && sent64_intact(j))
        emit("{\"k\":\"@zero\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"soc\":%u,\"sst\":%zu}",
             g_svc, g_type, j->sel, j->soc, j->sst);
}

// ---------------- 预热 ----------------
static void warmup(io_connect_t conn) {
    static const uint32_t sels[] = { 0, 1, 2, 3 };
    for (size_t i = 0; i < sizeof(sels)/sizeof(sels[0]); i++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", sels[i]);
        Job *j = NULL;
        int r = call_to(conn, sels[i], SO_CAP, ST_CAP_MIG, &j);
        if (r != 0) { emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"r\":%d}",
                           g_svc, g_type, sels[i], r); continue; }
        emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
             g_svc, g_type, sels[i], (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc);
        job_free(j);
    }
}

// ---------------- 单个 selector 的阶梯扫描 ----------------
// 返回：1 = 存在（至少一组容量 kr != 0xE00002C7），0 = 全 Unsupported，-1 = 挂了
static int run_sel(io_connect_t conn, uint32_t sel, const uint32_t *socs, const size_t *ssts, int n,
                   int *consecSel, int *hangSels) {
    int exists = 0;
    IOReturn bestkr = 0xE00002C7; uint32_t bestSoc = 0; size_t bestSst = 0;
    int gotZero = 0;              // 有没有 kr==0
    int wroteBytes = 0;           // 有没有 oc/sc>0
    int timeouts = 0;
    int tried = 0;

    for (int i = 0; i < n; i++) {
        uint32_t soc = socs[i]; size_t sst = ssts[i];
        snprintf(g_hb_tag, sizeof g_hb_tag, "%s sel=%u soc=%u sst=%zu", g_svc, sel, soc, sst);
        g_sync_next = (i == 0) ? 1 : 0;   // 每个 selector 的第一发强制落盘
        emit("{\"k\":\"@pre\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"soc\":%u,\"sst\":%zu}",
             g_svc, g_type, sel, soc, sst);
        Job *j = NULL;
        int r = call_to(conn, sel, soc, sst, &j);
        tried++;
        if (r == 2) { emit("{\"k\":\"@threadfail\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u}", g_svc, g_type, sel); continue; }
        if (r == 1) {
            timeouts++; (*consecSel)++;
            emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"soc\":%u,\"sst\":%zu}",
                 g_svc, g_type, sel, soc, sst);
            if (*consecSel >= SEL_HANG_LIMIT) {
                emit("{\"k\":\"@hang\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tried\":%d,\"of\":%d}",
                     g_svc, g_type, sel, tried, n);
                (*hangSels)++;
                return -1;
            }
            continue;
        }
        *consecSel = 0;
        if (j->kr != 0xE00002C7) {
            if (!exists) { exists = 1; bestkr = j->kr; bestSoc = soc; bestSst = sst; }
            if (j->kr == 0) gotZero = 1;
        }
        if (j->oc > 0 || j->sc > 0) wroteBytes = 1;

        emit("{\"k\":\"@r\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"soc\":%u,\"sst\":%zu,"
             "\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d,\"us\":%llu}",
             g_svc, g_type, sel, soc, sst, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc, sent64_intact(j), sent8_intact(j), (unsigned long long)j->us);

        if (j->kr == 0) dump_job(j);
        job_free(j);
    }

    emit("{\"k\":\"@sel\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"combos\":%d,\"exists\":%d,"
         "\"bestkr\":\"0x%08X\",\"bestsoc\":%u,\"bestsst\":%zu,\"zero\":%d,\"wrote\":%d,\"timeouts\":%d}",
         g_svc, g_type, sel, n, exists, (unsigned)bestkr, bestSoc, bestSst, gotZero, wroteBytes, timeouts);
    return exists;
}

// ---------------- 阶段：exist（全阶梯） ----------------
static void stage_exist(io_connect_t conn, uint32_t from, uint32_t to) {
    int consecSel = 0, hangSels = 0, consecHungSels = 0;
    int nExist = 0, nNone = 0, nHang = 0, nWrote = 0;
    for (uint32_t sel = from; sel <= to; sel++) {
        int r = run_sel(conn, sel, L_SOC, L_SST, NLADDER, &consecSel, &hangSels);
        if (r == 1) nExist++;
        else if (r == 0) nNone++;
        else nHang++;
        if (r == -1) { if (++consecHungSels >= SYS_HANG_LIMIT) {
                emit("{\"k\":\"@abort\",\"svc\":\"%s\",\"type\":%d,\"why\":\"consec_hung_sel\",\"sel\":%u}",
                     g_svc, g_type, sel); break; } }
        else consecHungSels = 0;
        if ((sel - from) % 16 == 15)
            progress("[%s type=%d] sel=%u  exist=%d none=%d hang=%d", g_svc, g_type, sel, nExist, nNone, nHang);
    }
    progress("[%s type=%d] done range %u..%u : exist=%d none=%d hang=%d", g_svc, g_type, from, to, nExist, nNone, nHang);
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"from\":%u,\"to\":%u,\"exist\":%d,\"none\":%d,"
         "\"hang\":%d,\"wrote\":%d}", g_svc, g_type, from, to, nExist, nNone, nHang, nWrote);
}

// ---------------- 阶段：dense（加密网格） ----------------
static void stage_dense(io_connect_t conn, const uint32_t *sels, int nsel) {
    int consecSel = 0, hangSels = 0;
    uint32_t socs[ND_SOC * ND_SST];
    size_t   ssts[ND_SOC * ND_SST];
    int k = 0;
    for (int a = 0; a < ND_SOC; a++)
        for (int b = 0; b < ND_SST; b++) { socs[k] = (uint32_t)a; ssts[k] = D_SST[b]; k++; }
    for (int i = 0; i < nsel; i++) {
        run_sel(conn, sels[i], socs, ssts, k, &consecSel, &hangSels);
        if (consecSel >= SEL_HANG_LIMIT) consecSel = 0;
    }
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"dense\",\"nsel\":%d,\"grid\":%d}",
         g_svc, g_type, nsel, k);
}

// ---------------- 阶段：contract（输入契约 × 输出容量 稀疏网格） ----------------
// 为什么需要：IOSurfaceRoot / AGX type33 / IOHIDEventService / AppleJPEGDriver /
// IOMobileFramebuffer / AppleCLCD2 这些服务的 externalMethod 对「不认识的 selector」返回
// kIOReturnBadArgument 而不是 kIOReturnUnsupported —— C7 判据在这里失效（0..N 全 C2）。
// 唯一可观测信号变成：只要某一组 (scalarIn, structIn, scalarOut, structOut) 让返回离开 C2，
// 该 selector 就存在（handler 真的跑了）。
// 网格：sin 0..4 × sti {0,8,64,156,664,4096} × soc {0,1,2,4} × sst {0,4096} = 240 组/selector，
//       命中一组即停（early exit），因为目的只是存在性。
static void stage_contract(io_connect_t conn, const uint32_t *sels, int nsel, int *consec, int *tot) {
    static const uint32_t sinCnts[5] = { 0, 1, 2, 3, 4 };
    static const size_t   stLens[6]  = { 0, 8, 64, 156, 664, 4096 };
    static const uint32_t socs[4]    = { 0, 1, 2, 4 };
    static const size_t   ssts[2]    = { 0, 4096 };
    uint64_t zs[4] = { 0, 0, 0, 0 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP, 1);
    int nHit = 0, nTotal = 0, nMiss = 0;

    for (int i = 0; i < nsel; i++) {
        uint32_t sel = sels[i];
        int found = 0, tried = 0;
        for (int a = 0; a < 5 && !found; a++) {
            for (int b = 0; b < 6 && !found; b++) {
                for (int c = 0; c < 4 && !found; c++) {
                    for (int d = 0; d < 2 && !found; d++) {
                        uint32_t sinCnt = sinCnts[a];
                        size_t   stLen = stLens[b];
                        uint32_t soc = socs[c];
                        size_t   sst = ssts[d];
                        snprintf(g_hb_tag, sizeof g_hb_tag, "ct sel=%u sin=%u sti=%zu soc=%u sst=%zu",
                                 sel, sinCnt, stLen, soc, sst);
                        g_sync_next = 0;
                        Job *j = NULL;
                        int r = call_to_in(conn, sel, soc, sst, zs, sinCnt, zin, stLen, &j);
                        nTotal++; tried++;
                        if (r == 2) continue;
                        if (r == 1) {
                            (*tot)++; (*consec)++;
                            emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"type\":%d,\"st\":\"ct\",\"sel\":%u}", g_svc, g_type, sel);
                            if (*consec >= SEL_HANG_LIMIT) { emit("{\"k\":\"@hang\",\"svc\":\"%s\",\"type\":%d,\"st\":\"ct\",\"sel\":%u}", g_svc, g_type, sel); *consec = 0; found = 1; }
                            continue;
                        }
                        *consec = 0;
                        // contract 阶段是【辅助扫描】，逐组合落盘会把 2.8 万行 ndjson 的拷贝拖成几分钟。
                        // 所以每个 selector 只落一行 @ct（含命中契约）。容量阶梯（exist 阶段）仍是逐组合全记录。
                        if (j->kr != 0xE00002C2 && j->kr != 0xE00002C7) {
                            found = 1; nHit++;
                            emit("{\"k\":\"@ct\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"tried\":%d,"
                                 "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu,\"krh\":\"0x%08X\",\"krn\":\"%s\","
                                 "\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d}",
                                 g_svc, g_type, sel, tried + 1, sinCnt, stLen, soc, sst,
                                 (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc,
                                 sent64_intact(j), sent8_intact(j));
                            if (j->kr == 0) dump_job(j);
                        }
                        job_free(j);
                    }
                }
            }
        }
        if (!found) nMiss++;
        if ((i % 8) == 7) progress("[%s type=%d] ct sel=%u hit=%d/%d calls=%d", g_svc, g_type, sel, nHit, i + 1, nTotal);
    }
    free(zin);
    progress("[%s type=%d] contract done: hit=%d nsel=%d calls=%d", g_svc, g_type, nHit, nsel, nTotal);
    emit("{\"k\":\"@stat\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"contract\",\"nsel\":%d,\"hit\":%d,\"miss\":%d,\"calls\":%d}",
         g_svc, g_type, nsel, nHit, nMiss, nTotal);
}

// ---------------- 参数 ----------------
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
    int n = 0;
    const char *p = csv;
    while (*p && n < cap) {
        out[n++] = (uint32_t)strtoul(p, (char **)&p, 0);
        if (*p == ',') p++;
    }
    return n;
}

static io_service_t find_service(void) {
    io_iterator_t iter = 0;
    CFMutableDictionaryRef m = IOServiceMatching(g_svc);
    if (!m) return 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS) return 0;
    io_service_t svc = IOIteratorNext(iter);
    IOObjectRelease(iter);
    return svc;
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();
    gLog = fopen([[dir stringByAppendingPathComponent:@"svcreenum.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"svcreenum.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 svcreenum.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 svcreenum.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"svcreenum: capacity-ladder selector re-enum…";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"exist";
    NSString *svcNS = (g_argc > 2) ? [NSString stringWithUTF8String:g_argv[2]] : @"AppleM2ScalerCSCDriver";
    long      otype = (g_argc > 3) ? strtol(g_argv[3], NULL, 0) : 0;
    g_svc  = strdup(svcNS.UTF8String);
    g_type = (int)otype;

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"svcreenum.hb"] UTF8String]);
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

            io_service_t svc = find_service();
            io_connect_t conn = 0;
            kern_return_t okr = (kern_return_t)-1;
            if (svc) okr = IOServiceOpen(svc, mach_task_self(), (uint32_t)otype, &conn);
            emit("{\"k\":\"@open\",\"svc\":\"%s\",\"found\":%d,\"type\":%d,\"kr\":%u,\"krn\":\"%s\",\"conn\":%u}",
                 g_svc, svc ? 1 : 0, (int)otype, (unsigned)okr, kr_name((unsigned)okr), (unsigned)conn);
            if (svc) IOObjectRelease(svc);

            if (okr == KERN_SUCCESS && conn) {
                emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                     "\"svc\":\"%s\",\"type\":%d,\"stage\":\"%s\",\"wd\":%d,\"timeout_s\":%d,\"socap\":%d,\"sscap\":%d,\"nladder\":%d}",
                     kFingerprint, kBuildStamp,
                     [[[UIDevice currentDevice] systemVersion] UTF8String],
                     [[[UIDevice currentDevice] model] UTF8String],
                     g_svc, (int)otype, stage.UTF8String, wd, CALL_TIMEOUT_S, SO_CAP, ST_CAP_MIG, NLADDER);

                warmup(conn);

                uint32_t sels[1024];
                int nsel = parse_list(kv("sels"), sels, 1024);

                if ([stage isEqualToString:@"warm"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"warm\",\"done\":1}");
                } else if ([stage isEqualToString:@"exist"]) {
                    uint32_t from = (uint32_t)kvl("from", 0), to = (uint32_t)kvl("to", 255);
                    emit("{\"k\":\"@plan\",\"st\":\"exist\",\"from\":%u,\"to\":%u,\"socap\":%d,\"sscap\":%d}",
                         from, to, SO_CAP, ST_CAP_MIG);
                    if (nsel > 0) {
                        int consecSel = 0, hangSels = 0;
                        for (int i = 0; i < nsel; i++)
                            run_sel(conn, sels[i], L_SOC, L_SST, NLADDER, &consecSel, &hangSels);
                    } else {
                        stage_exist(conn, from, to);
                    }
                } else if ([stage isEqualToString:@"contract"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"contract\",\"nsel\":%d}", nsel);
                    {
                        int cs = 0, tt = 0;
                        stage_contract(conn, sels, nsel, &cs, &tt);
                    }
                } else if ([stage isEqualToString:@"dense"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"dense\",\"nsel\":%d}", nsel);
                    stage_dense(conn, sels, nsel);
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
                }

                emit("{\"k\":\"@done\",\"svc\":\"%s\",\"type\":%d,\"stage\":\"%s\",\"t\":%llu}",
                     g_svc, (int)otype, stage.UTF8String, (unsigned long long)(now_ms() - g_t0));
                IOServiceClose(conn);
            } else {
                emit("{\"k\":\"@fatal\",\"why\":\"open_failed\",\"svc\":\"%s\",\"type\":%d,\"kr\":%u}",
                     g_svc, (int)otype, (unsigned)okr);
            }

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
