// main.m — m2reenum：AppleM2ScalerCSCDriver 的 selector 面【用正确的 in/out 参数姿势】重新枚举。
//
// 前两轮的错误（本轮要修的东西）：
//   IOConnectCallMethod 的 outputCnt / outputStructCnt 是 in/out 参数，调用前必须预填容量。
//   前两轮一律传 0 ⇒ 凡声明 scalarOut>0 或 structOut>0 的 selector 全部假阴性（一律 BadArgument）。
//   证据：out/SVC2-PROBE.md 的 ndjson 里没有一条 kr==0 且 sto>0，@so/@h 段整体为空。
//
// 本轮三条硬约束：
//   1. 调用前预填：uint32_t soc=SO_CAP; size_t sst=ST_CAP; sout[SO_CAP]; bst[ST_CAP]
//      调用后 soc/sst 是内核【实际写入】的量。
//      哨兵：sout 填 0xA5A5..、bst 填 0x5A，用来区分「内核真写了」与「只回显计数」。
//   2. 预热：新连接第一发可能 BadArgument，先按序调 sel 0,1,2,3,4,5,8,11 各一次（忽略结果）。
//   3. 每次调用独立 pthread + 3s 超时；超时 detach 泄漏该线程与缓冲，主线程继续下一条；
//      连续 3 次超时即 @abort 熔断。整轮再加看门狗 + 200ms 心跳。
//
// 阶段（每个阶段一次独立进程；跑完看结果再决定下一步）：
//   warm  只做预热（可选，其它阶段内部也会先预热）
//   s1    sel 0..255，零入参（scalarIn=0, structIn 空），输出容量预填 SO_CAP/ST_CAP
//   s1b   对 s1 里 kr!=0 的 sel，扫输出容量组合 (soc,sst)，找「只认精确容量」的 handler
//   s2    对存在的 sel，扫 structIn 长度 {0,1,4,8,64,256,1024,4096} × scalarIn 个数 {0,1,2,4}
//   s3    对 kr==0 的 sel，零入参 + 预填容量取输出，hexdump sout/bst，扫内核指针/PAC
//
// 指纹（装前 strings 校验，必须命中 >=1）：M2RE-20261101-reenum-c4d81b
// 只做 AppleM2ScalerCSCDriver。不跑竞态、不碰 harness/israce/、不改 out/ 既有文件。

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

static const char *kFingerprint = "M2RE-20261101-reenum-c4d81b";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define SVC_NAME        "AppleM2ScalerCSCDriver"
#define OPEN_TYPE       0
#define CALL_TIMEOUT_S  3
#define MAX_CONSEC_TO   3       // 连续超时熔断

#define SO_CAP          16      // scalarOut 容量（任务书姿势）
#define ST_CAP          4096    // structOut 容量（4096 是 MIG 上限，4097 起 IPCError）

#define SENT64          0xA5A5A5A5A5A5A5A5ull
#define SENT8           0x5A

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[128] = "-";
static uint64_t g_t0 = 0;

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

static int g_log_fsync = 1;
static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
    fputs(buf, stderr); fflush(stderr);
    if (gLog) { fputs(buf, gLog); fflush(gLog); if (g_log_fsync) fsync(fileno(gLog)); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd)); }
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
    const uint64_t *sin;
    uint32_t sinCnt;
    const uint8_t *sIn;      // 可为 NULL
    size_t   sInLen;
    uint32_t soc;            // 预填容量（in）
    size_t   sst;            // 预填容量（in）
    uint8_t  useIn;          // structIn 是否为非零长度块

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

    // ---- 关键：预填容量 + 哨兵 ----
    j->oc = j->soc;
    j->sc = j->sst;
    for (int i = 0; i < SO_CAP; i++) j->sout[i] = SENT64;
    memset(j->bst, SENT8, sizeof j->bst);

    uint64_t a = now_us();
    j->kr = (IOReturn)IOConnectCallMethod(
        j->conn, j->sel,
        (j->sinCnt ? j->sin : NULL), j->sinCnt,
        (j->sInLen ? (void *)j->sIn : NULL), j->sInLen,
        (j->soc ? j->sout : NULL), &j->oc,
        (j->sst ? j->bst : NULL), &j->sc);
    j->us = now_us() - a;

    pthread_mutex_lock(&j->m);
    j->done = 1;
    pthread_cond_signal(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

// 0 = 有结果；1 = 超时（线程与 job 泄漏不回收）；2 = 线程没起来
static int call_to(io_connect_t conn, uint32_t sel,
                   const uint64_t *sin, uint32_t sinCnt,
                   const uint8_t *sIn, size_t sInLen,
                   uint32_t soc, size_t sst, int useIn, Job **outJob) {
    Job *j = (Job *)calloc(1, sizeof(Job));
    if (!j) { *outJob = NULL; return 2; }
    j->conn = conn; j->sel = sel;
    j->sin = sin; j->sinCnt = sinCnt;
    j->sIn = sIn; j->sInLen = sInLen;
    j->soc = soc; j->sst = sst; j->useIn = (uint8_t)useIn;
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

static void job_free(Job *j) {
    if (!j) return;
    pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
    free(j);
}

// ---------------- 哨兵 / 指针扫描 ----------------
static int sent64_intact(const Job *j) {
    for (int i = 0; i < SO_CAP; i++) if (j->sout[i] != SENT64) return 0;
    return 1;
}
static int sent8_intact(const Job *j, size_t n) {
    if (n > ST_CAP) n = ST_CAP;
    for (size_t i = 0; i < n; i++) if (j->bst[i] != SENT8) return 0;
    return 1;
}
static int scan_ptr64(const uint64_t v, const char **kind) {
    // 内核指针：0xfffffe...（arm64 iOS：0xfffffe00_xxxxxxxx 起）
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFE0000000000ull) { *kind = "kernel"; return 1; }
    if ((v >> 56) >= 0xF0) { *kind = "pac_hi"; return 1; }
    if (v >= 0x100000000ull && v < 0x10000000000ull) { *kind = "user_va"; return 1; }
    return 0;
}

// ---------------- 预热 ----------------
// AGX 那边的机制：全新连接第一发 BadArgument，预热后才 SUCCESS。这里按序全打一遍，结果只记不判。
static void warmup(io_connect_t conn) {
    static const uint32_t sels[] = { 0, 1, 2, 3, 4, 5, 8, 11 };
    for (size_t i = 0; i < sizeof(sels)/sizeof(sels[0]); i++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", sels[i]);
        Job *j = NULL;
        int r = call_to(conn, sels[i], NULL, 0, NULL, 0, SO_CAP, ST_CAP, 0, &j);
        if (r != 0) { emit("{\"k\":\"@warm\",\"sel\":%u,\"r\":%d}", sels[i], r); continue; }
        emit("{\"k\":\"@warm\",\"sel\":%u,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"us\":%llu}",
             sels[i], (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc, (unsigned long long)j->us);
        job_free(j);
    }
}

// ---------------- 阶段 1：存在性扫描 ----------------
static void stage_s1(io_connect_t conn, uint32_t from, uint32_t to, int *consec, int *tot) {
    for (uint32_t sel = from; sel <= to; sel++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "s1 sel=%u", sel);
        emit("{\"k\":\"@pre\",\"st\":\"s1\",\"sel\":%u}", sel);
        Job *j = NULL;
        int r = call_to(conn, sel, NULL, 0, NULL, 0, SO_CAP, ST_CAP, 0, &j);
        if (r == 1) {
            (*tot)++; (*consec)++;
            emit("{\"k\":\"@timeout\",\"st\":\"s1\",\"sel\":%u}", sel);
            if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s1\",\"sel\":%u,\"why\":\"consec_timeout\"}", sel); return; }
            continue;
        }
        if (r == 2) { emit("{\"k\":\"@threadfail\",\"st\":\"s1\",\"sel\":%u}", sel); continue; }
        *consec = 0;
        emit("{\"k\":\"@e\",\"sel\":%u,\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\","
             "\"oc\":%u,\"sc\":%zu,\"ocap\":%d,\"scap\":%d,\"s64\":%d,\"s8\":%d,\"us\":%llu}",
             sel, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc, SO_CAP, ST_CAP,
             sent64_intact(j), sent8_intact(j, ST_CAP),
             (unsigned long long)j->us);
        job_free(j);
    }
}

// ---------------- 阶段 1b：输出容量组合（找「只认精确容量」的 handler） ----------------
static void stage_s1b(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot) {
    static const uint32_t socs[4] = { 0, 16, 1, 8 };
    static const size_t   ssts[3] = { 0, 4096, 1 };
    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        for (int a = 0; a < 4; a++) {
            for (int b = 0; b < 3; b++) {
                if (a == 1 && b == 1) continue;                 // (16,4096) 已被 s1 覆盖
                uint32_t soc = socs[a]; size_t sst = ssts[b];
                snprintf(g_hb_tag, sizeof g_hb_tag, "s1b sel=%u soc=%u sst=%zu", sel, soc, sst);
                emit("{\"k\":\"@pre\",\"st\":\"s1b\",\"sel\":%u,\"soc\":%u,\"sst\":%zu}", sel, soc, sst);
                Job *j = NULL;
                int r = call_to(conn, sel, NULL, 0, NULL, 0, soc, sst, 0, &j);
                if (r == 1) {
                    (*tot)++; (*consec)++;
                    emit("{\"k\":\"@timeout\",\"st\":\"s1b\",\"sel\":%u,\"soc\":%u,\"sst\":%zu}", sel, soc, sst);
                    if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s1b\",\"sel\":%u}", sel); return; }
                    continue;
                }
                if (r == 2) continue;
                *consec = 0;
                emit("{\"k\":\"@e2\",\"sel\":%u,\"socap\":%u,\"sscap\":%zu,\"kr\":%u,\"krh\":\"0x%08X\","
                     "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"us\":%llu}",
                     sel, soc, sst, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                     j->oc, j->sc, (unsigned long long)j->us);
                job_free(j);
            }
        }
    }
}

// ---------------- 阶段 2：入参维度 ----------------
static void stage_s2(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot,
                     uint32_t soc, size_t sst) {
    static const size_t lens[8] = { 0, 1, 4, 8, 64, 256, 1024, 4096 };
    static const uint32_t cnts[4] = { 0, 1, 2, 4 };
    uint8_t *zero = (uint8_t *)calloc(ST_CAP, 1);
    uint64_t zs[4] = { 0, 0, 0, 0 };

    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        for (int a = 0; a < 8; a++) {
            for (int b = 0; b < 4; b++) {
                size_t len = lens[a]; uint32_t cnt = cnts[b];
                snprintf(g_hb_tag, sizeof g_hb_tag, "s2 sel=%u len=%zu cnt=%u", sel, len, cnt);
                emit("{\"k\":\"@pre\",\"st\":\"s2\",\"sel\":%u,\"len\":%zu,\"cnt\":%u}", sel, len, cnt);
                Job *j = NULL;
                int r = call_to(conn, sel, zs, cnt, zero, len, soc, sst, len ? 1 : 0, &j);
                if (r == 1) {
                    (*tot)++; (*consec)++;
                    emit("{\"k\":\"@timeout\",\"st\":\"s2\",\"sel\":%u,\"len\":%zu,\"cnt\":%u}", sel, len, cnt);
                    if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s2\",\"sel\":%u}", sel); free(zero); return; }
                    continue;
                }
                if (r == 2) continue;
                *consec = 0;
                emit("{\"k\":\"@s2\",\"sel\":%u,\"len\":%zu,\"cnt\":%u,\"kr\":%u,\"krh\":\"0x%08X\","
                     "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"us\":%llu}",
                     sel, len, cnt, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                     j->oc, j->sc, (unsigned long long)j->us);
                job_free(j);
            }
        }
    }
    free(zero);
}

// ---------------- 阶段 7：存在性 sweep（细 out 网格） ----------------
// s1 只用 (16,4096)。但 sel 5 在 (16,4096) 下同样报 Unsupported —— 所以「(16,4096) 报 Unsupported」
// 不足以证明不存在。s7 对 sel 区间逐个扫 out 网格，只有全网格都是 Unsupported 才判「不存在」。
static void stage_s7(io_connect_t conn, uint32_t from, uint32_t to, int *consec, int *tot) {
    static const uint32_t socs[7] = { 0, 1, 2, 3, 4, 8, 16 };
    static const size_t   ssts[2] = { 0, 4096 };
    g_log_fsync = 0;
    for (uint32_t sel = from; sel <= to; sel++) {
        int hits = 0; IOReturn best = 0xE00002C7; uint32_t hitSoc = 0; size_t hitSst = 0;
        for (int a = 0; a < 7 && !hits; a++) {
            for (int b = 0; b < 2 && !hits; b++) {
                uint32_t soc = socs[a]; size_t sst = ssts[b];
                if (soc == 0 && sst == 0) continue;      // (0,0) 全 Unsupported，跳过省时
                snprintf(g_hb_tag, sizeof g_hb_tag, "s7 sel=%u soc=%u sst=%zu", sel, soc, sst);
                emit("{\"k\":\"@pre\",\"st\":\"s7\",\"sel\":%u,\"soc\":%u,\"sst\":%zu}", sel, soc, sst);
                Job *j = NULL;
                int r = call_to(conn, sel, NULL, 0, NULL, 0, soc, sst, 0, &j);
                if (r == 1) {
                    (*tot)++; (*consec)++;
                    emit("{\"k\":\"@timeout\",\"st\":\"s7\",\"sel\":%u,\"soc\":%u,\"sst\":%zu}", sel, soc, sst);
                    if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s7\",\"sel\":%u}", sel); g_log_fsync = 1; return; }
                    continue;
                }
                if (r == 2) continue;
                *consec = 0;
                if (j->kr != 0xE00002C7) { hits = 1; best = j->kr; hitSoc = soc; hitSst = sst;
                    emit("{\"k\":\"@e7\",\"sel\":%u,\"soc\":%u,\"sst\":%zu,\"kr\":%u,\"krh\":\"0x%08X\","
                         "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d}",
                         sel, soc, sst, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                         j->oc, j->sc, sent64_intact(j), sent8_intact(j, ST_CAP));
                }
                job_free(j);
            }
        }
        if (!hits) emit("{\"k\":\"@none\",\"st\":\"s7\",\"sel\":%u}", sel);
    }
    g_log_fsync = 1;
}

// ---------------- 阶段 6：scalarIn × out 契约 交叉（补 s2/s5 的洞） ----------------
static void stage_s6(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot) {
    static const size_t   ssts[2] = { 0, 4096 };
    static const uint32_t socs[6] = { 0, 1, 2, 4, 8, 16 };
    static const size_t   inlens[2] = { 0, 8 };
    static const uint32_t cnts[3] = { 1, 2, 4 };
    uint64_t zs[4] = { 0, 1, 2, 3 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP, 1);
    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        for (int ci = 0; ci < 3; ci++) {
            uint32_t cnt = cnts[ci];
            for (int a = 0; a < 6; a++) {
                for (int b = 0; b < 2; b++) {
                    for (int c = 0; c < 2; c++) {
                        uint32_t soc = socs[a]; size_t sst = ssts[b], inlen = inlens[c];
                        snprintf(g_hb_tag, sizeof g_hb_tag, "s6 sel=%u cnt=%u soc=%u sst=%zu in=%zu", sel, cnt, soc, sst, inlen);
                        emit("{\"k\":\"@pre\",\"st\":\"s6\",\"sel\":%u,\"cnt\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu}", sel, cnt, soc, sst, inlen);
                        Job *j = NULL;
                        int r = call_to(conn, sel, zs, cnt, zin, inlen, soc, sst, inlen ? 1 : 0, &j);
                        if (r == 1) {
                            (*tot)++; (*consec)++;
                            emit("{\"k\":\"@timeout\",\"st\":\"s6\",\"sel\":%u,\"cnt\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu}", sel, cnt, soc, sst, inlen);
                            if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s6\",\"sel\":%u}", sel); free(zin); return; }
                            continue;
                        }
                        if (r == 2) continue;
                        *consec = 0;
                        emit("{\"k\":\"@e6\",\"sel\":%u,\"cnt\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu,\"kr\":%u,\"krh\":\"0x%08X\","
                             "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d}",
                             sel, cnt, soc, sst, inlen, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                             j->oc, j->sc, sent64_intact(j), sent8_intact(j, ST_CAP));
                        job_free(j);
                    }
                }
            }
        }
    }
    free(zin);
}

// ---------------- 阶段 5：幻方阵 soc×sst 细网格（找精确 out 契约） ----------------
static void stage_s5(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot) {
    // 教训：sel 5 只在 scalarOut==1 时可见，sel 0..10 在 (0/1/8/16)×(0/1/4096) 里全 BadArgument。
    // 输出计数是【精确匹配】的维度，必须细扫。
    static const size_t ssts[6] = { 0, 8, 16, 64, 664, 4096 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP, 1);
    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        for (uint32_t soc = 0; soc <= 8; soc++) {
            for (int b = 0; b < 6; b++) {
                size_t sst = ssts[b];
                for (int zinlen = 0; zinlen < 2; zinlen++) {   // structIn 0 / 8，内容全 0
                    size_t inlen = zinlen ? 8 : 0;
                    snprintf(g_hb_tag, sizeof g_hb_tag, "s5 sel=%u soc=%u sst=%zu in=%zu", sel, soc, sst, inlen);
                    emit("{\"k\":\"@pre\",\"st\":\"s5\",\"sel\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu}", sel, soc, sst, inlen);
                    Job *j = NULL;
                    int r = call_to(conn, sel, NULL, 0, zin, inlen, soc, sst, inlen ? 1 : 0, &j);
                    if (r == 1) {
                        (*tot)++; (*consec)++;
                        emit("{\"k\":\"@timeout\",\"st\":\"s5\",\"sel\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu}", sel, soc, sst, inlen);
                        if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s5\",\"sel\":%u}", sel); free(zin); return; }
                        continue;
                    }
                    if (r == 2) continue;
                    *consec = 0;
                    if (j->kr != 0xE00002C7) {
                        emit("{\"k\":\"@e5\",\"sel\":%u,\"soc\":%u,\"sst\":%zu,\"in\":%zu,\"kr\":%u,\"krh\":\"0x%08X\","
                             "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d}",
                             sel, soc, sst, inlen, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                             j->oc, j->sc, sent64_intact(j), sent8_intact(j, ST_CAP));
                    }
                    job_free(j);
                }
            }
        }
    }
    free(zin);
}

// ---------------- 阶段 4：structOut 容量阶梯（定 declared 尺寸） ----------------
static void stage_s4(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot,
                     uint32_t soc) {
    static const size_t lad[14] = { 0, 1, 8, 16, 32, 64, 128, 256, 512, 664, 700, 1024, 2048, 4096 };
    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        for (int a = 0; a < 14; a++) {
            size_t sst = lad[a];
            snprintf(g_hb_tag, sizeof g_hb_tag, "s4 sel=%u soc=%u sst=%zu", sel, soc, sst);
            emit("{\"k\":\"@pre\",\"st\":\"s4\",\"sel\":%u,\"soc\":%u,\"sst\":%zu}", sel, soc, sst);
            Job *j = NULL;
            int r = call_to(conn, sel, NULL, 0, NULL, 0, soc, sst, 0, &j);
            if (r == 1) {
                (*tot)++; (*consec)++;
                emit("{\"k\":\"@timeout\",\"st\":\"s4\",\"sel\":%u,\"sst\":%zu}", sel, sst);
                if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s4\",\"sel\":%u}", sel); return; }
                continue;
            }
            if (r == 2) continue;
            *consec = 0;
            emit("{\"k\":\"@e4\",\"sel\":%u,\"socap\":%u,\"sscap\":%zu,\"kr\":%u,\"krh\":\"0x%08X\","
                 "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d,\"us\":%llu}",
                 sel, soc, sst, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
                 j->oc, j->sc, sent64_intact(j), sent8_intact(j, ST_CAP),
                 (unsigned long long)j->us);
            job_free(j);
        }
    }
}

// ---------------- 阶段 3：输出 dump ----------------
static void hexdump_row(uint32_t sel, size_t off, const uint8_t *p, size_t n) {
    char hex[2 * 64 + 1];
    size_t hn = n > 64 ? 64 : n;
    for (size_t i = 0; i < hn; i++) sprintf(hex + 2 * i, "%02x", p[i]);
    hex[2 * hn] = 0;
    emit("{\"k\":\"@h\",\"sel\":%u,\"off\":%zu,\"b\":\"%s\"}", sel, off, hex);
}

static void stage_s3(io_connect_t conn, const uint32_t *sels, int n, int *consec, int *tot,
                     uint32_t soc, size_t sst) {
    for (int i = 0; i < n; i++) {
        uint32_t sel = sels[i];
        snprintf(g_hb_tag, sizeof g_hb_tag, "s3 sel=%u", sel);
        emit("{\"k\":\"@pre\",\"st\":\"s3\",\"sel\":%u}", sel);
        Job *j = NULL;
        int r = call_to(conn, sel, NULL, 0, NULL, 0, soc, sst, 0, &j);
        if (r == 1) {
            (*tot)++; (*consec)++;
            emit("{\"k\":\"@timeout\",\"st\":\"s3\",\"sel\":%u}", sel);
            if (*consec >= MAX_CONSEC_TO) { emit("{\"k\":\"@abort\",\"st\":\"s3\",\"sel\":%u}", sel); return; }
            continue;
        }
        if (r == 2) continue;
        *consec = 0;

        int s64 = sent64_intact(j);
        int s8  = sent8_intact(j, ST_CAP);
        emit("{\"k\":\"@s3\",\"sel\":%u,\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\","
             "\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d,\"us\":%llu}",
             sel, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
             j->oc, j->sc, s64, s8, (unsigned long long)j->us);

        // 标量输出：容量内全部打出来
        if (j->oc > 0 || !s64) {
            uint32_t m = j->oc > SO_CAP ? SO_CAP : j->oc;
            for (uint32_t k = 0; k < SO_CAP; k++) {
                if (k >= m && j->sout[k] == SENT64) continue;
                emit("{\"k\":\"@so\",\"sel\":%u,\"i\":%u,\"v\":\"0x%016llx\"}",
                     sel, k, (unsigned long long)j->sout[k]);
            }
        }

        // structOut：内核真写了才 dump
        size_t dumpLen = 0;
        if (j->sc > 0) {
            dumpLen = j->sc > 1024 ? 1024 : j->sc;
        } else if (!s8) {
            dumpLen = 64;
        }
        for (size_t off = 0; off < dumpLen; off += 16) {
            size_t n2 = (dumpLen - off) >= 16 ? 16 : (dumpLen - off);
            hexdump_row(sel, off, j->bst + off, n2);
        }
        if (j->sc > 1024) emit("{\"k\":\"@trunc\",\"sel\":%u,\"sc\":%zu,\"shown\":1024}", sel, j->sc);

        // 指针扫描（扫全 4096，不只 dump 的那段）
        int hits = 0;
        for (size_t off = 0; off + 8 <= ST_CAP; off += 8) {
            uint64_t v;
            memcpy(&v, j->bst + off, 8);
            if (v == 0) continue;
            const char *kind = NULL;
            if (scan_ptr64(v, &kind)) {
                emit("{\"k\":\"@ptr\",\"sel\":%u,\"off\":%zu,\"v\":\"0x%016llx\",\"kind\":\"%s\"}",
                     sel, off, (unsigned long long)v, kind);
                if (++hits > 32) break;
            }
        }
        for (uint32_t k = 0; k < SO_CAP; k++) {
            if (j->sout[k] == SENT64 || j->sout[k] == 0) continue;
            const char *kind = NULL;
            if (scan_ptr64(j->sout[k], &kind))
                emit("{\"k\":\"@ptr\",\"sel\":%u,\"off\":%ld,\"v\":\"0x%016llx\",\"kind\":\"%s\",\"from\":\"so\"}",
                     sel, -(long)k, (unsigned long long)j->sout[k], kind);
        }
        job_free(j);
    }
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
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(SVC_NAME), &iter) != KERN_SUCCESS)
        return 0;
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
    gLog = fopen([[dir stringByAppendingPathComponent:@"m2reenum.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"m2reenum.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 m2reenum.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 m2reenum.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"m2reenum: AppleM2ScalerCSCDriver selector re-enum…";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"s1";

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"m2reenum.hb"] UTF8String]);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, hbPath) == 0) pthread_detach(hb);

    int wd = (int)kvl("wd", 600);
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
            if (svc) okr = IOServiceOpen(svc, mach_task_self(), OPEN_TYPE, &conn);
            emit("{\"k\":\"@open\",\"svc\":\"" SVC_NAME "\",\"found\":%d,\"type\":%d,\"kr\":%u,\"krn\":\"%s\",\"conn\":%u}",
                 svc ? 1 : 0, OPEN_TYPE, (unsigned)okr, kr_name((unsigned)okr), (unsigned)conn);
            if (svc) IOObjectRelease(svc);

            if (okr == KERN_SUCCESS && conn) {
                emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                     "\"stage\":\"%s\",\"wd\":%d,\"timeout_s\":%d,\"socap\":%d,\"sscap\":%d}",
                     kFingerprint, kBuildStamp,
                     [[[UIDevice currentDevice] systemVersion] UTF8String],
                     [[[UIDevice currentDevice] model] UTF8String],
                     stage.UTF8String, wd, CALL_TIMEOUT_S, SO_CAP, ST_CAP);

                int consec = 0, tot = 0;

                // 预热（所有阶段共用；结果只记不判）
                warmup(conn);

                uint32_t sels[512];
                int nsel = parse_list(kv("sels"), sels, 512);

                if ([stage isEqualToString:@"warm"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"warm\",\"done\":1}");
                } else if ([stage isEqualToString:@"s1"]) {
                    uint32_t from = (uint32_t)kvl("from", 0), to = (uint32_t)kvl("to", 255);
                    emit("{\"k\":\"@plan\",\"st\":\"s1\",\"from\":%u,\"to\":%u,\"socap\":%d,\"sscap\":%d}",
                         from, to, SO_CAP, ST_CAP);
                    stage_s1(conn, from, to, &consec, &tot);
                } else if ([stage isEqualToString:@"s1b"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"s1b\",\"nsel\":%d}", nsel);
                    stage_s1b(conn, sels, nsel, &consec, &tot);
                } else if ([stage isEqualToString:@"s2"]) {
                    {
                        uint32_t soc = (uint32_t)kvl("soc", SO_CAP);
                        size_t   sst = (size_t)kvl("sst", ST_CAP);
                        emit("{\"k\":\"@plan\",\"st\":\"s2\",\"nsel\":%d,\"socap\":%u,\"sscap\":%zu}", nsel, soc, sst);
                        stage_s2(conn, sels, nsel, &consec, &tot, soc, sst);
                    }
                } else if ([stage isEqualToString:@"s7"]) {
                    uint32_t from = (uint32_t)kvl("from", 0), to = (uint32_t)kvl("to", 255);
                    emit("{\"k\":\"@plan\",\"st\":\"s7\",\"from\":%u,\"to\":%u}", from, to);
                    stage_s7(conn, from, to, &consec, &tot);
                } else if ([stage isEqualToString:@"s6"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"s6\",\"nsel\":%d}", nsel);
                    stage_s6(conn, sels, nsel, &consec, &tot);
                } else if ([stage isEqualToString:@"s5"]) {
                    emit("{\"k\":\"@plan\",\"st\":\"s5\",\"nsel\":%d}", nsel);
                    stage_s5(conn, sels, nsel, &consec, &tot);
                } else if ([stage isEqualToString:@"s4"]) {
                    uint32_t soc = (uint32_t)kvl("soc", SO_CAP);
                    emit("{\"k\":\"@plan\",\"st\":\"s4\",\"nsel\":%d,\"socap\":%u}", nsel, soc);
                    stage_s4(conn, sels, nsel, &consec, &tot, soc);
                } else if ([stage isEqualToString:@"s3"]) {
                    {
                        uint32_t soc = (uint32_t)kvl("soc", SO_CAP);
                        size_t   sst = (size_t)kvl("sst", ST_CAP);
                        emit("{\"k\":\"@plan\",\"st\":\"s3\",\"nsel\":%d,\"socap\":%u,\"sscap\":%zu}", nsel, soc, sst);
                        stage_s3(conn, sels, nsel, &consec, &tot, soc, sst);
                    }
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
                }

                emit("{\"k\":\"@done\",\"stage\":\"%s\",\"t\":%llu,\"timeouts\":%d}",
                     stage.UTF8String, (unsigned long long)(now_ms() - g_t0), tot);
                IOServiceClose(conn);
            } else {
                emit("{\"k\":\"@fatal\",\"why\":\"open_failed\",\"kr\":%u}", (unsigned)okr);
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
