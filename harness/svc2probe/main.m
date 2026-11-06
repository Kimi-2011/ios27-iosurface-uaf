// main.m — svc2probe：剩余 5 个可打开服务的「外方法面」真机探查。
//
// 目标服务（IOServiceOpen 已确证）：
//   IOHIDEventService        type 2   kext com.apple.iokit.IOHIDFamily            (4 张表)
//   AppleJPEGDriver          type 0   kext com.apple.driver.AppleJPEGDriver       (1 张表)
//   AppleM2ScalerCSCDriver   type 0   kext com.apple.iokit.IOMobileGraphicsFamily (3 张表)
//   IOMobileFramebuffer      type 0   同上
//   AppleCLCD2               type 0   同上
//
// 方法（照任务书）：
//   不知道 selector 属于哪张表，所以对每个 selector 索引 s，
//   把该 kext 每张表的第 s 条契约都试一遍（表内不足 s+1 条就跳过）。
//   契约按「声明值原样」传：scalarIn=si 个 0，structIn=sti 字节全 0，
//   scalarOut 容量=so，structOut 容量=sto；wildcard(4294967295) 传 0。
//   —— 派发校验是精确相等，开大一点就 kIOReturnBadArgument(0xE00002C2)。
//
// 阻塞防护（本文件的核心）：每次 IOConnectCallMethod 跑在独立 pthread 里，
// 主线程 pthread_cond_timedwait 等 3s，超时记 @timeout 并丢弃该线程（detach + 泄漏），
// 主线程继续下一个组合。同一个 stage 连续 3 次超时 -> @abort 该 stage。
// 心跳线程每 200ms 落一行 @hb（含当前 svc/s），挂死点即证据。
//
// 指纹（装前 strings 校验，必须命中 1）：SVC2PROBE-20261101-extmethod-d7b3e2
// 不碰 harness/israce/，不改 out/ 既有文件。

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

#include "contract.h"

static const char *kFingerprint = "SVC2PROBE-20261101-extmethod-d7b3e2";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

// 契约最大值（读 out/svc_selectors.txt 得来）：scalarIn 1048 / structIn 32776
//                                          scalarOut 255 / structOut 4096
#define SCALAR_CAP    1056
#define STRUCT_IN_CAP 32776
#define STRUCT_OUT_CAP 4096
#define HEX_MAX       512
#define CALL_TIMEOUT_S 3
#define MAX_TIMEOUTS_PER_STAGE 3

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[96] = "-";      // 当前 svc/s，心跳里带出去
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
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd));  }   // @pre 必须在调用前真的落盘
}

static const char *kr_name(unsigned k) {
    switch (k) {
        case 0x00000000: return "SUCCESS";
        // MIG 层（内核在进派发表之前就拒了）。4294966989 = 0xfffffecd = -307
        case 0xfffffed4: return "MIG_TYPE_ERROR";       // -300
        case 0xfffffed3: return "MIG_REPLY_MISMATCH";   // -301
        case 0xfffffed2: return "MIG_BAD_ID";           // -302
        case 0xfffffed1: return "MIG_BAD_ARGUMENTS";    // -303
        case 0xfffffed0: return "MIG_NO_REPLY";         // -304
        case 0xfffffecf: return "MIG_EXCEPTION";        // -305
        case 0xfffffece: return "MIG_ARRAY_TOO_LARGE";  // -306
        case 0xfffffecd: return "MIG_REMOTE_ERROR";     // -307
        case 0xfffffecc: return "MIG_SERVER_DIED";      // -308
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

// ---------------- 服务定义 ----------------
typedef struct {
    const char *key;     // 命令行参数
    const char *svc;     // IOService 名
    const char *kext;    // 契约归属 kext
    uint32_t    type;    // IOServiceOpen type
    const CTab *tabs;
    uint32_t    ntabs;
    uint32_t    smax;    // 最大表条数
} Svc;

static uint32_t maxn(const CTab *t, uint32_t n) {
    uint32_t m = 0;
    for (uint32_t i = 0; i < n; i++) if (t[i].n > m) m = t[i].n;
    return m;
}

static const Svc g_svcs[] = {
    { "hid",  "IOHIDEventService",      "com.apple.iokit.IOHIDFamily",
      2, TAB_IOHIDFamily,          TAB_IOHIDFamily_N,          0 },
    { "jpeg", "AppleJPEGDriver",        "com.apple.driver.AppleJPEGDriver",
      0, TAB_AppleJPEGDriver,      TAB_AppleJPEGDriver_N,      0 },
    { "msc",  "AppleM2ScalerCSCDriver", "com.apple.iokit.IOMobileGraphicsFamily",
      0, TAB_IOMobileGraphicsFamily, TAB_IOMobileGraphicsFamily_N, 0 },
    { "mfb",  "IOMobileFramebuffer",    "com.apple.iokit.IOMobileGraphicsFamily",
      0, TAB_IOMobileGraphicsFamily, TAB_IOMobileGraphicsFamily_N, 0 },
    { "clcd", "AppleCLCD2",             "com.apple.iokit.IOMobileGraphicsFamily",
      0, TAB_IOMobileGraphicsFamily, TAB_IOMobileGraphicsFamily_N, 0 },
};
static const int g_nsvc = (int)(sizeof(g_svcs) / sizeof(g_svcs[0]));

// ---------------- 单次调用（独立线程 + 超时） ----------------
typedef struct {
    io_connect_t conn;
    uint32_t     sel;
    uint32_t     si, so;
    size_t       sti, sto;
    IOReturn     kr;
    uint32_t     oc;
    size_t       sc;
    uint64_t    *sout;
    uint8_t     *bout;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int done;
} Job;

static void *job_run(void *p) {
    Job *j = (Job *)p;

    uint64_t *sin = (uint64_t *)calloc(SCALAR_CAP, sizeof(uint64_t));
    uint8_t  *bin = (uint8_t  *)calloc(STRUCT_IN_CAP ? STRUCT_IN_CAP : 1, 1);

    j->kr = (IOReturn)IOConnectCallMethod(
        j->conn, j->sel,
        sin, j->si,
        (j->sti ? bin : NULL), j->sti,
        (j->so  ? j->sout : NULL), &j->oc,
        (j->sto ? j->bout : NULL), &j->sc);

    free(sin);
    free(bin);

    pthread_mutex_lock(&j->m);
    j->done = 1;
    pthread_cond_signal(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

// 返回 0 = 有结果（res 有效）；1 = 超时（job 泄漏，不回收）
static int call_with_timeout(io_connect_t conn, uint32_t sel,
                             uint32_t si, size_t sti, uint32_t so, size_t sto,
                             Job **outJob) {
    Job *j = (Job *)calloc(1, sizeof(Job));
    j->conn = conn; j->sel = sel;
    j->si = si; j->sti = sti; j->so = so; j->sto = sto;
    j->sout = (uint64_t *)calloc(SCALAR_CAP, sizeof(uint64_t));
    j->bout = (uint8_t  *)calloc(STRUCT_OUT_CAP ? STRUCT_OUT_CAP : 1, 1);
    pthread_mutex_init(&j->m, NULL);
    pthread_cond_init(&j->cv, NULL);

    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&th, &at, job_run, j) != 0) {
        pthread_attr_destroy(&at);
        free(j->sout); free(j->bout); free(j);
        *outJob = NULL;
        return 2;                       // 线程都没起来
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
        // 内核调用不返回：内核线程收不回，用户线程也不 join（join 会自己挂死）。
        // detach 掉、job 结构故意泄漏 —— 保证主线程继续跑后面的组合。
        pthread_detach(th);
        *outJob = j;
        return 1;
    }

    pthread_join(th, NULL);
    *outJob = j;
    return 0;
}

// ---------------- 输出辅助 ----------------
static void hexdump(const char *svc, const char *tab, uint32_t s,
                    const uint8_t *b, size_t n) {
    if (n > HEX_MAX) n = HEX_MAX;
    if (n == 0) return;
    char line[64];
    for (size_t off = 0; off < n; off += 16) {
        size_t k = (n - off >= 16) ? 16 : (n - off);
        char *p = line;
        for (size_t i = 0; i < k; i++) p += sprintf(p, "%02x", b[off + i]);
        *p = 0;
        emit("{\"k\":\"@h\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"off\":%zu,\"b\":\"%s\"}",
             svc, tab, s, off, line);
    }
}

static int ascii_run(const uint8_t *b, size_t n, size_t off, char *out, size_t outn) {
    size_t j = 0;
    for (size_t i = off; i < n && b[i] >= 0x20 && b[i] < 0x7f; i++) {
        if (j + 1 < outn) out[j++] = (char)b[i];
    }
    out[j] = 0;
    return (int)j;
}

// 模式扫描：内核指针 / PAC / 16KB 页对齐 / 可打印 ASCII
static void scan_patterns(const char *svc, const char *tab, uint32_t s,
                          const uint8_t *b, size_t n) {
    if (n > HEX_MAX) n = HEX_MAX;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v = 0;
        memcpy(&v, b + off, 8);
        if (v == 0) continue;

        if ((v & 0xfffffe0000000000ull) == 0xfffffe0000000000ull) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"off\":%zu,"
                 "\"v\":\"0x%016llx\",\"cls\":\"kva\"}",
                 svc, tab, s, off, (unsigned long long)v);
        } else if ((v >> 56) >= 0xf0) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"off\":%zu,"
                 "\"v\":\"0x%016llx\",\"cls\":\"pac\"}",
                 svc, tab, s, off, (unsigned long long)v);
        } else if ((v & 0x3fff) == 0 && v >= 0x1000) {
            emit("{\"k\":\"@ptr\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"off\":%zu,"
                 "\"v\":\"0x%016llx\",\"cls\":\"page16k\"}",
                 svc, tab, s, off, (unsigned long long)v);
        }
    }
    // ASCII 串：长度 >= 6
    size_t off = 0;
    while (off < n) {
        char buf[128];
        int len = ascii_run(b, n, off, buf, sizeof buf);
        if (len >= 6) {
            emit("{\"k\":\"@ascii\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"off\":%zu,\"v\":\"%s\"}",
                 svc, tab, s, off, buf);
            off += (size_t)len;
        } else {
            off++;
        }
    }
}

// ---------------- 校准：MIG 层到底在哪一侧设限 ----------------
// 目的：把「契约不符 -> kIOReturnBadArgument」和「参数规模超出 io_connect_method
//       的 MIG 承载能力 -> MIG_REMOTE_ERROR(-307)」这两种拒绝彻底分开。
// 只用一个已确证能开的连接（IOHIDEventService type 2），sel 0。
static void calib(io_connect_t conn, const char *svc, int *tot_timeouts) {
    static const uint32_t kSi[] = {0, 1, 2, 3, 4, 8, 16, 17, 20, 32, 54, 55, 56, 128, 279, 1048};
    static const size_t   kSti[] = {0, 8, 55, 512, 2048, 4096, 8192, 32768, 32776, 65536};

    emit("{\"k\":\"@cal\",\"axis\":\"start\",\"svc\":\"%s\"}", svc);
    for (size_t i = 0; i < sizeof(kSi) / sizeof(kSi[0]); i++) {
        Job *j = NULL;
        int rc = call_with_timeout(conn, 0, kSi[i], 0, 0, 0, &j);
        if (rc == 1) {
            (*tot_timeouts)++;
            emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"si\",\"v\":%u,\"res\":\"TIMEOUT\"}",
                 svc, kSi[i]);
            continue;
        }
        if (rc == 2) { emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"si\",\"v\":%u,\"res\":\"thread_fail\"}", svc, kSi[i]); continue; }
        emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"si\",\"v\":%u,\"kr\":%u,\"krn\":\"%s\"}",
             svc, kSi[i], (unsigned)j->kr, kr_name((unsigned)j->kr));
        free(j->sout); free(j->bout); free(j);
    }
    for (size_t i = 0; i < sizeof(kSti) / sizeof(kSti[0]); i++) {
        Job *j = NULL;
        int rc = call_with_timeout(conn, 0, 0, kSti[i], 0, 0, &j);
        if (rc == 1) {
            (*tot_timeouts)++;
            emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"sti\",\"v\":%zu,\"res\":\"TIMEOUT\"}", svc, kSti[i]);
            continue;
        }
        if (rc == 2) { emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"sti\",\"v\":%zu,\"res\":\"thread_fail\"}", svc, kSti[i]); continue; }
        emit("{\"k\":\"@cal\",\"svc\":\"%s\",\"axis\":\"sti\",\"v\":%zu,\"kr\":%u,\"krn\":\"%s\"}",
             svc, kSti[i], (unsigned)j->kr, kr_name((unsigned)j->kr));
        free(j->sout); free(j->bout); free(j);
    }
    emit("{\"k\":\"@cal\",\"axis\":\"done\",\"svc\":\"%s\"}", svc);
}

// ---------------- 交叉扫描（x-sweep）----------------
// 第一轮只把「表第 s 条」当候选，等价于假设「静态表索引 == selector」。
// 实测发现输出侧是 capacity >= declared（MFB s=26 用 so=0 与 so=1 都 SUCCESS），
// 于是把输出缓冲一律开大，输入契约 (si,sti) 从「本表本行」解耦出来交叉试：
//   s × 该 kext 出现过的所有 (si,sti)（si>16 丢掉：MIG 层就拒，见 @cal）
// 输出统一 so=8 / sto=4096：一方面满足任何 declared，一方面让「写而不校验」的 handler
// 把多于声明量的字节落进我们的缓冲（EXTMETHOD-AUDIT 没定论的那一类正是这个）。
#define XSO 8
#define XSTO 4096

static void xsweep(const Svc *sv, uint32_t s_from, uint32_t s_to, int *tot_timeouts) {
    uint32_t ps[64], pt[64];
    int np = 0;
    for (uint32_t t = 0; t < sv->ntabs; t++) {
        for (uint32_t i = 0; i < sv->tabs[t].n; i++) {
            const CEnt *e = &sv->tabs[t].ent[i];
            uint32_t si  = (e->si  == WILD) ? 0 : e->si;
            uint32_t sti = (e->sti == WILD) ? 0 : e->sti;
            if (si > 16) continue;
            int dup = 0;
            for (int k = 0; k < np; k++) if (ps[k] == si && pt[k] == sti) { dup = 1; break; }
            if (!dup && np < 64) { ps[np] = si; pt[np] = sti; np++; }
        }
    }

    uint32_t smax = maxn(sv->tabs, sv->ntabs) + 8;
    if (s_to > smax) s_to = smax;

    emit("{\"k\":\"@xstage\",\"svc\":\"%s\",\"type\":%u,\"pairs\":%d,\"s_from\":%u,\"s_to\":%u,"
         "\"so\":%d,\"sto\":%d}", sv->svc, sv->type, np, s_from, s_to, XSO, XSTO);

    char plist[512]; plist[0] = 0; char *pp = plist;
    for (int k = 0; k < np; k++) pp += sprintf(pp, "%s[%u,%u]", k ? "," : "", ps[k], pt[k]);
    emit("{\"k\":\"@xpairs\",\"svc\":\"%s\",\"list\":\"%s\"}", sv->svc, plist);

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(sv->svc));
    if (!service) { emit("{\"k\":\"@xopen\",\"svc\":\"%s\",\"found\":0}", sv->svc); return; }
    io_connect_t conn = 0;
    kern_return_t okr = IOServiceOpen(service, mach_task_self(), sv->type, &conn);
    IOObjectRelease(service);
    emit("{\"k\":\"@xopen\",\"svc\":\"%s\",\"found\":1,\"type\":%u,\"kr\":%u,\"krn\":\"%s\"}",
         sv->svc, sv->type, (unsigned)okr, kr_name((unsigned)okr));
    if (okr != KERN_SUCCESS) return;

    int timeouts = 0;
    for (uint32_t s = s_from; s <= s_to; s++) {
        for (int k = 0; k < np; k++) {
            snprintf(g_hb_tag, sizeof g_hb_tag, "X %s/s%u/%u,%u", sv->svc, s, ps[k], pt[k]);
            emit("{\"k\":\"@xpre\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%u,\"so\":%d,\"sto\":%d}",
                 sv->svc, s, ps[k], pt[k], XSO, XSTO);

            Job *j = NULL;
            int rc = call_with_timeout(conn, s, ps[k], pt[k], XSO, XSTO, &j);
            if (rc == 1) {
                timeouts++; (*tot_timeouts)++;
                emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%u,\"so\":%d,"
                     "\"sto\":%d,\"wait\":%d,\"x\":1}",
                     sv->svc, s, ps[k], pt[k], XSO, XSTO, CALL_TIMEOUT_S);
                if (timeouts >= MAX_TIMEOUTS_PER_STAGE) {
                    emit("{\"k\":\"@abort\",\"svc\":\"%s\",\"reason\":\"超时熔断\",\"s\":%u}", sv->svc, s);
                    goto xfinish;
                }
                continue;
            }
            if (rc == 2) continue;

            unsigned kr = (unsigned)j->kr;
            emit("{\"k\":\"@xr\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%u,\"kr\":%u,"
                 "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
                 sv->svc, s, ps[k], pt[k], kr, kr_name(kr), j->oc, j->sc);

            if (kr == 0) {
                uint32_t shown = j->oc > 8 ? 8 : j->oc;
                char vals[256]; vals[0] = 0; char *vp = vals;
                for (uint32_t i = 0; i < shown; i++)
                    vp += sprintf(vp, "%s\"0x%016llx\"", i ? "," : "", (unsigned long long)j->sout[i]);
                emit("{\"k\":\"@xso\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%u,\"n\":%u,\"v\":[%s]}",
                     sv->svc, s, ps[k], pt[k], j->oc, vals);
                if (j->sc) {
                    emit("{\"k\":\"@xdump\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%u,"
                         "\"ret_sc\":%zu,\"dump\":%zu}", sv->svc, s, ps[k], pt[k], j->sc,
                         j->sc > HEX_MAX ? HEX_MAX : j->sc);
                    hexdump(sv->svc, "xpairsweep", s, j->bout, j->sc);
                    scan_patterns(sv->svc, "xpairsweep", s, j->bout, j->sc);
                }
            }
            free(j->sout); free(j->bout);
            pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
            free(j);
        }
    }
xfinish:
    emit("{\"k\":\"@xdone\",\"svc\":\"%s\",\"timeouts\":%d}", sv->svc, timeouts);
    IOServiceClose(conn);
}


// ---------------- 定向网格（grid）----------------
// 只在「静态行声明了 structOut / 大 structIn」的索引上做，范围小、风险可控：
//   si ∈ {0..4} × sti ∈ GRID_STI 列表，输出 so=8 / sto=4096
// 目的：如果某个真在用的入口因为静态表解码错位而没被第一轮命中，
//       它的输入契约会落在这个网格里；一旦 SUCCESS 且 sc>0，就是输出原语。
static const size_t kGridSti[] = {
    0, 4, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96,
    128, 136, 156, 176, 256, 512, 1024, 1760, 3084, 4096
};

static void gridsweep(const Svc *sv, uint32_t s_from, uint32_t s_to, int *tot_timeouts) {
    uint32_t smax = maxn(sv->tabs, sv->ntabs) + 8;
    if (s_to > smax) s_to = smax;

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(sv->svc));
    if (!service) { emit("{\"k\":\"@gopen\",\"svc\":\"%s\",\"found\":0}", sv->svc); return; }
    io_connect_t conn = 0;
    kern_return_t okr = IOServiceOpen(service, mach_task_self(), sv->type, &conn);
    IOObjectRelease(service);
    emit("{\"k\":\"@gopen\",\"svc\":\"%s\",\"type\":%u,\"kr\":%u,\"krn\":\"%s\",\"s_from\":%u,\"s_to\":%u}",
         sv->svc, sv->type, (unsigned)okr, kr_name((unsigned)okr), s_from, s_to);
    if (okr != KERN_SUCCESS) return;

    int timeouts = 0, hits = 0;
    for (uint32_t s = s_from; s <= s_to; s++) {
        for (uint32_t si = 0; si <= 4; si++) {
            for (size_t i = 0; i < sizeof(kGridSti) / sizeof(kGridSti[0]); i++) {
                snprintf(g_hb_tag, sizeof g_hb_tag, "G %s/s%u/%u,%zu", sv->svc, s, si, kGridSti[i]);
                emit("{\"k\":\"@gpre\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%zu,\"so\":%d,\"sto\":%d}",
                     sv->svc, s, si, kGridSti[i], XSO, XSTO);
                Job *j = NULL;
                int rc = call_with_timeout(conn, s, si, kGridSti[i], XSO, XSTO, &j);
                if (rc == 1) {
                    timeouts++; (*tot_timeouts)++;
                    emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%zu,"
                         "\"so\":%d,\"sto\":%d,\"wait\":%d,\"g\":1}",
                         sv->svc, s, si, kGridSti[i], XSO, XSTO, CALL_TIMEOUT_S);
                    if (timeouts >= MAX_TIMEOUTS_PER_STAGE) {
                        emit("{\"k\":\"@abort\",\"svc\":\"%s\",\"reason\":\"超时熔断\",\"s\":%u}", sv->svc, s);
                        goto gfinish;
                    }
                    continue;
                }
                if (rc == 2) continue;
                unsigned kr = (unsigned)j->kr;
                if (kr != 0xe00002c2) {              // 只把「不是 BadArgument」的记进主日志
                    hits++;
                    emit("{\"k\":\"@gr\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%zu,\"kr\":%u,"
                         "\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
                         sv->svc, s, si, kGridSti[i], kr, kr_name(kr), j->oc, j->sc);
                }
                if (kr == 0) {
                    if (j->oc) {
                        uint32_t shown = j->oc > 8 ? 8 : j->oc;
                        char vals[256]; vals[0] = 0; char *vp = vals;
                        for (uint32_t q = 0; q < shown; q++)
                            vp += sprintf(vp, "%s\"0x%016llx\"", q ? "," : "", (unsigned long long)j->sout[q]);
                        emit("{\"k\":\"@gso\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%zu,\"n\":%u,\"v\":[%s]}",
                             sv->svc, s, si, kGridSti[i], j->oc, vals);
                    }
                    if (j->sc) {
                        emit("{\"k\":\"@gdump\",\"svc\":\"%s\",\"s\":%u,\"si\":%u,\"sti\":%zu,"
                             "\"ret_sc\":%zu,\"dump\":%zu}", sv->svc, s, si, kGridSti[i], j->sc,
                             j->sc > HEX_MAX ? HEX_MAX : j->sc);
                        hexdump(sv->svc, "grid", s, j->bout, j->sc);
                        scan_patterns(sv->svc, "grid", s, j->bout, j->sc);
                    }
                }
                free(j->sout); free(j->bout);
                pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
                free(j);
            }
        }
    }
gfinish:
    emit("{\"k\":\"@gdone\",\"svc\":\"%s\",\"hits\":%d,\"timeouts\":%d}", sv->svc, hits, timeouts);
    IOServiceClose(conn);
}

// ---------------- 一个服务 ----------------
static void probe_service(const Svc *sv, uint32_t s_from, uint32_t s_to, int *tot_timeouts) {
    uint32_t smax = (sv->smax ? sv->smax : maxn(sv->tabs, sv->ntabs)) + 8;
    if (s_to > smax) s_to = smax;

    emit("{\"k\":\"@stage\",\"svc\":\"%s\",\"kext\":\"%s\",\"type\":%u,"
         "\"tabs\":%u,\"maxn\":%u,\"s_from\":%u,\"s_to\":%u}",
         sv->svc, sv->kext, sv->type, sv->ntabs,
         maxn(sv->tabs, sv->ntabs), s_from, s_to);

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(sv->svc));
    if (!service) {
        emit("{\"k\":\"@open\",\"svc\":\"%s\",\"found\":0,\"type\":%u}", sv->svc, sv->type);
        return;
    }
    io_connect_t conn = 0;
    kern_return_t okr = IOServiceOpen(service, mach_task_self(), sv->type, &conn);
    IOObjectRelease(service);
    emit("{\"k\":\"@open\",\"svc\":\"%s\",\"found\":1,\"type\":%u,\"kr\":%u,\"krn\":\"%s\",\"conn\":%u}",
         sv->svc, sv->type, (unsigned)okr, kr_name((unsigned)okr), (unsigned)conn);
    if (okr != KERN_SUCCESS) return;

    int timeouts = 0;

    for (uint32_t s = s_from; s <= s_to; s++) {
        for (uint32_t t = 0; t < sv->ntabs; t++) {
            const CTab *tb = &sv->tabs[t];
            if (s >= tb->n) continue;                      // 表内不足 s+1 条，跳过
            const CEnt *e = &tb->ent[s];

            uint32_t si  = (e->si  == WILD) ? 0 : e->si;
            uint32_t sti = (e->sti == WILD) ? 0 : e->sti;
            uint32_t so  = (e->so  == WILD) ? 0 : e->so;
            uint32_t sto = (e->sto == WILD) ? 0 : e->sto;

            snprintf(g_hb_tag, sizeof g_hb_tag, "%s/%s/s%u", sv->svc, tb->tab, s);

            emit("{\"k\":\"@pre\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"h\":\"%s\","
                 "\"si\":%u,\"sti\":%u,\"so\":%u,\"sto\":%u}",
                 sv->svc, tb->tab, s, e->handler, si, sti, so, sto);

            Job *j = NULL;
            int rc = call_with_timeout(conn, s, si, sti, so, sto, &j);

            if (rc == 1) {
                timeouts++;
                (*tot_timeouts)++;
                emit("{\"k\":\"@timeout\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,"
                     "\"si\":%u,\"sti\":%u,\"so\":%u,\"sto\":%u,\"wait\":%d,\"n_in_stage\":%d}",
                     sv->svc, tb->tab, s, si, sti, so, sto, CALL_TIMEOUT_S, timeouts);
                // job / 缓冲区故意泄漏：内核调用不返回，free 会踩在别人写的内存上
                if (timeouts >= MAX_TIMEOUTS_PER_STAGE) {
                    emit("{\"k\":\"@abort\",\"svc\":\"%s\",\"reason\":\"%d 次超时，停止该服务剩余 selector\","
                         "\"s\":%u}", sv->svc, timeouts, s);
                    goto finish;
                }
                continue;
            }
            if (rc == 2) {
                emit("{\"k\":\"@r\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"kr\":%u,"
                     "\"krn\":\"thread_fail\",\"oc\":0,\"sc\":0}", sv->svc, tb->tab, s, (unsigned)-1);
                continue;
            }

            unsigned kr = (unsigned)j->kr;
            emit("{\"k\":\"@r\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"kr\":%u,\"krn\":\"%s\","
                 "\"oc\":%u,\"sc\":%zu}",
                 sv->svc, tb->tab, s, kr, kr_name(kr), j->oc, j->sc);

            if (kr == 0) {
                // 记录标量输出
                uint32_t shown = j->oc > 8 ? 8 : j->oc;
                char vals[256]; vals[0] = 0; char *vp = vals;
                for (uint32_t i = 0; i < shown; i++)
                    vp += sprintf(vp, "%s\"0x%016llx\"", i ? "," : "",
                                  (unsigned long long)j->sout[i]);
                emit("{\"k\":\"@so\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,\"n\":%u,\"v\":[%s]}",
                     sv->svc, tb->tab, s, j->oc, vals);

                if (sto && j->sc) {
                    emit("{\"k\":\"@dump\",\"svc\":\"%s\",\"tab\":\"%s\",\"s\":%u,"
                         "\"declared_sto\":%u,\"ret_sc\":%zu,\"dump\":%zu}",
                         sv->svc, tb->tab, s, sto, j->sc, (j->sc > HEX_MAX ? HEX_MAX : j->sc));
                    hexdump(sv->svc, tb->tab, s, j->bout, j->sc);
                    scan_patterns(sv->svc, tb->tab, s, j->bout, j->sc);
                }
            }

            free(j->sout); free(j->bout);
            pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
            free(j);
        }
    }

finish:
    emit("{\"k\":\"@svcdone\",\"svc\":\"%s\",\"timeouts\":%d}", sv->svc, timeouts);
    IOServiceClose(conn);
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();
    gLog = fopen([[dir stringByAppendingPathComponent:@"svc2probe.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"svc2probe.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 svc2probe.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 svc2probe.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"svc2probe…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;  // 跑测期间不自动锁屏

    // 参数：svcKey s_from s_to watchdogSec
    NSArray *args = [[NSProcessInfo processInfo] arguments];
    NSString *want = (args.count > 1) ? args[1] : @"all";
    uint32_t s_from = (args.count > 2) ? (uint32_t)[args[2] intValue] : 0;
    uint32_t s_to   = (args.count > 3) ? (uint32_t)[args[3] intValue] : 4096;
    int wd          = (args.count > 4) ? [args[4] intValue] : 300;

    // 心跳文件
    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"svc2probe.hb"] UTF8String]);
    pthread_t hb;
    pthread_create(&hb, NULL, hb_thread, hbPath);
    pthread_detach(hb);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(wd * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        emit("{\"k\":\"@watchdog\",\"sec\":%d}", wd);
        if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
        if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
        exit(3);
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            (void)now_ms();
            struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
            g_t0 = now_ms();

            emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                 "\"want\":\"%s\",\"s_from\":%u,\"s_to\":%u,\"wd\":%d,\"rows\":%u,"
                 "\"timeout_s\":%d,\"max_timeouts_per_stage\":%d}",
                 kFingerprint, kBuildStamp,
                 [[[UIDevice currentDevice] systemVersion] UTF8String],
                 [[[UIDevice currentDevice] model] UTF8String],
                 [want UTF8String], s_from, s_to, wd, CONTRACT_ROWS,
                 CALL_TIMEOUT_S, MAX_TIMEOUTS_PER_STAGE);

            int tot_timeouts = 0;
            if ([want isEqualToString:@"cal"]) {
                // 校准：只用 IOHIDEventService type 2 这一个已知可开的连接
                io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault,
                                                             IOServiceMatching("IOHIDEventService"));
                io_connect_t c = 0;
                kern_return_t okr = s ? IOServiceOpen(s, mach_task_self(), 2, &c) : (kern_return_t)-1;
                if (s) IOObjectRelease(s);
                emit("{\"k\":\"@open\",\"svc\":\"IOHIDEventService(cal)\",\"found\":%d,\"type\":2,"
                     "\"kr\":%u,\"krn\":\"%s\"}", s ? 1 : 0, (unsigned)okr, kr_name((unsigned)okr));
                if (okr == KERN_SUCCESS) {
                    calib(c, "IOHIDEventService", &tot_timeouts);
                    IOServiceClose(c);
                }
            } else if ([want hasPrefix:@"g:"]) {
                NSString *sub = [want substringFromIndex:2];
                for (int i = 0; i < g_nsvc; i++) {
                    const char *key = g_svcs[i].key;
                    if (![sub isEqualToString:@"all"] &&
                        ![sub isEqualToString:[NSString stringWithUTF8String:key]]) continue;
                    @autoreleasepool { gridsweep(&g_svcs[i], s_from, s_to, &tot_timeouts); }
                }
            } else if ([want hasPrefix:@"x:"]) {
                // 交叉扫描：x:<svcKey>，可用 x:all 一次跑全部服务
                NSString *sub = [want substringFromIndex:2];
                for (int i = 0; i < g_nsvc; i++) {
                    const char *key = g_svcs[i].key;
                    if (![sub isEqualToString:@"all"] &&
                        ![sub isEqualToString:[NSString stringWithUTF8String:key]]) continue;
                    @autoreleasepool { xsweep(&g_svcs[i], s_from, s_to, &tot_timeouts); }
                }
            } else {
                for (int i = 0; i < g_nsvc; i++) {
                    if (![want isEqualToString:@"all"] &&
                        ![want isEqualToString:[NSString stringWithUTF8String:g_svcs[i].key]]) continue;
                    @autoreleasepool { probe_service(&g_svcs[i], s_from, s_to, &tot_timeouts); }
                }
            }

            emit("{\"k\":\"@done\",\"t\":%llu,\"timeouts\":%d}",
                 (unsigned long long)(now_ms() - g_t0), tot_timeouts);
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
