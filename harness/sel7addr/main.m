// main.m — sel7addr：AppleM2ScalerCSCDriver selector 7 的「用户输入是否被当成地址」判定。
//
// 已知（真机实测，out/M2SCALER-REENUM.md §7）：
//   sel 7 + structIn>0 + structOut 容量==0  ->  kr = 0x00000001 (KERN_INVALID_ADDRESS)
//   参数校验路径一律回 0xE00002C2 (BadArgument)，所以 0x1 不是校验失败，是 handler 里去做了
//   地址翻译并且失败了。
//
// 本轮只回答一件事：那个"地址"能不能是内核地址？
//   组 A  用户态地址（NULL / 未对齐 / 未映射 / 自己 mmap 的有效页）
//   组 B  内核态地址（3 个已知已映射 + 2 个大概率未映射）
//   组 C  对组 B 里返回码最特殊的地址，改 structOut 容量再看
//
// 硬约束：
//   * 只做 selector 7。不跑竞态、不碰 harness/israce/、不改 out/ 既有文件。
//   * 不读取返回的内存内容 —— 只记返回码 / 写入计数 / 哨兵完整性。
//   * 每个 stage 一次独立进程：某个地址把内核打死，只损失这一个 stage。
//   * 每次调用前写 @pre，调用后写 @a，全部 fflush+fsync。
//
// 指纹（装前 strings 校验，必须命中 >=1）：SEL7-20261101-addrprobe-b7e21c

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

static const char *kFingerprint = "SEL7-20261101-addrprobe-b7e21c";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define SVC_NAME        "AppleM2ScalerCSCDriver"
#define OPEN_TYPE       0
#define CALL_TIMEOUT_S  3
#define MAX_CONSEC_TO   3

#define SEL7            7
#define SO_CAP          16
#define ST_CAP          4096

#define SENT64          0xA5A5A5A5A5A5A5A5ull
#define SENT8           0x5A

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[128] = "-";
static uint64_t g_t0 = 0;

static uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}
static uint64_t now_us(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
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
static void emit(const char *fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
    fputs(buf, stderr); fflush(stderr);
    if (gLog) { fputs(buf, gLog); fflush(gLog); fsync(fileno(gLog)); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd)); }
}

static const char *kr_name(unsigned k) {
    switch (k) {
        case 0x00000000: return "SUCCESS";
        case 0x00000001: return "KERN_INVALID_ADDRESS";
        case 0x00000002: return "KERN_PROTECTION_FAILURE";
        case 0x00000003: return "KERN_NO_SPACE";
        case 0x00000004: return "KERN_INVALID_ARGUMENT";
        case 0x00000005: return "KERN_FAILURE";
        case 0x00000006: return "KERN_RESOURCE_SHORTAGE";
        case 0x0000000d: return "KERN_MEMORY_ERROR";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002bd: return "kIOReturnNoMemory";
        case 0xe00002be: return "kIOReturnNoResources";
        case 0xe00002c0: return "kIOReturnNoDevice";
        case 0xe00002c1: return "kIOReturnNotPrivileged";
        case 0xe00002c2: return "kIOReturnBadArgument";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c8: return "kIOReturnVMError";
        case 0xe00002c9: return "kIOReturnInternalError";
        case 0xe00002ca: return "kIOReturnIOError";
        case 0xe00002cd: return "kIOReturnNotOpen";
        case 0xe00002d5: return "kIOReturnBusy";
        case 0xe00002d6: return "kIOReturnAborted";
        case 0xe00002d7: return "kIOReturnTimeout";
        case 0xe00002bf: return "kIOReturnIPCError";
        default:         return "OTHER";
    }
}

// ---------------- 单次调用（独立线程 + 3s 超时） ----------------
typedef struct {
    io_connect_t conn;
    uint32_t sel;
    const uint8_t *sIn;
    size_t   sInLen;
    uint32_t soc;
    size_t   sst;

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
        NULL, 0,
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

static int call_to(io_connect_t conn, uint32_t sel,
                   const uint8_t *sIn, size_t sInLen,
                   uint32_t soc, size_t sst, Job **outJob) {
    Job *j = (Job *)calloc(1, sizeof(Job));
    if (!j) { *outJob = NULL; return 2; }
    j->conn = conn; j->sel = sel;
    j->sIn = sIn; j->sInLen = sInLen;
    j->soc = soc; j->sst = sst;
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

static void job_free(Job *j) {
    if (!j) return;
    pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
    free(j);
}

static int sent64_intact(const Job *j) {
    for (int i = 0; i < SO_CAP; i++) if (j->sout[i] != SENT64) return 0;
    return 1;
}
static int sent8_intact(const Job *j) {
    for (size_t i = 0; i < ST_CAP; i++) if (j->bst[i] != SENT8) return 0;
    return 1;
}

// ---------------- 预热（复现 m2reenum 的连接前置状态） ----------------
static void warmup(io_connect_t conn) {
    static const uint32_t sels[] = { 0, 1, 2, 3, 4, 5, 8, 11 };
    for (size_t i = 0; i < sizeof(sels)/sizeof(sels[0]); i++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", sels[i]);
        Job *j = NULL;
        int r = call_to(conn, sels[i], NULL, 0, SO_CAP, ST_CAP, &j);
        if (r != 0) { emit("{\"k\":\"@warm\",\"sel\":%u,\"r\":%d}", sels[i], r); continue; }
        emit("{\"k\":\"@warm\",\"sel\":%u,\"kr\":%u,\"krh\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
             sels[i], (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc);
        job_free(j);
    }
}

// ---------------- 核心：一次带地址的 sel 7 调用 ----------------
static int g_consec = 0;
static int g_abort  = 0;

// tag: 组内标签（A1/B3/...）；grp: A/B/C/D；addr: 塞进 structIn 的 u64
static void probe7(io_connect_t conn, const char *grp, const char *tag,
                   uint64_t addr, size_t inLen, uint32_t soc, size_t sst) {
    if (g_abort) return;

    uint8_t in[ST_CAP];
    memset(in, 0, sizeof in);
    if (inLen > sizeof in) inLen = sizeof in;
    // 小端 u64 写进去；inLen < 8 时按长度截断
    size_t cpy = inLen < 8 ? inLen : 8;
    memcpy(in, &addr, cpy);

    snprintf(g_hb_tag, sizeof g_hb_tag, "%s %s addr=0x%llx", grp, tag, (unsigned long long)addr);
    emit("{\"k\":\"@pre\",\"grp\":\"%s\",\"tag\":\"%s\",\"sel\":%d,\"addr\":\"0x%llx\","
         "\"inlen\":%zu,\"soc\":%u,\"sst\":%zu}",
         grp, tag, SEL7, (unsigned long long)addr, inLen, soc, sst);

    Job *j = NULL;
    int r = call_to(conn, SEL7, in, inLen, soc, sst, &j);
    if (r == 1) {
        g_consec++;
        emit("{\"k\":\"@timeout\",\"grp\":\"%s\",\"tag\":\"%s\",\"addr\":\"0x%llx\",\"soc\":%u,\"sst\":%zu}",
             grp, tag, (unsigned long long)addr, soc, sst);
        if (g_consec >= MAX_CONSEC_TO) {
            emit("{\"k\":\"@abort\",\"why\":\"consec_timeout\",\"grp\":\"%s\"}", grp);
            g_abort = 1;
        }
        return;
    }
    if (r == 2) { emit("{\"k\":\"@threadfail\",\"grp\":\"%s\",\"tag\":\"%s\"}", grp, tag); return; }
    g_consec = 0;

    emit("{\"k\":\"@a\",\"grp\":\"%s\",\"tag\":\"%s\",\"addr\":\"0x%llx\",\"inlen\":%zu,"
         "\"soc\":%u,\"sst\":%zu,\"kr\":%u,\"krh\":\"0x%X\",\"krn\":\"%s\","
         "\"oc\":%u,\"sc\":%zu,\"s64\":%d,\"s8\":%d,\"us\":%llu}",
         grp, tag, (unsigned long long)addr, inLen,
         soc, sst, (unsigned)j->kr, (unsigned)j->kr, kr_name((unsigned)j->kr),
         j->oc, j->sc, sent64_intact(j), sent8_intact(j),
         (unsigned long long)j->us);
    job_free(j);
}

// ---------------- 阶段 ----------------
// base：基准 + 两个对照，确认复现 KERN_INVALID_ADDRESS
static void stage_base(io_connect_t conn) {
    emit("{\"k\":\"@plan\",\"st\":\"base\"}");
    uint64_t zero = 0;
    // 3 次基准：structIn=8 全 0，structOut 容量 0
    probe7(conn, "BASE", "z1", zero, 8, 0, 0);
    probe7(conn, "BASE", "z2", zero, 8, 0, 0);
    probe7(conn, "BASE", "z3", zero, 8, 0, 0);
    // 对照：structIn=0 -> 应 BadArgument
    probe7(conn, "BASE", "ctl_in0", zero, 0, 0, 0);
    // 对照：structIn=8 + structOut 容量 8 -> 应 BadArgument
    probe7(conn, "BASE", "ctl_sst8", zero, 8, 0, 8);
}

// a：组 A 用户态地址
static void stage_a(io_connect_t conn) {
    emit("{" "\"k\":\"@plan\",\"st\":\"a\"}");

    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t pageAddr = 0, magic = 0x4142434445464748ull;
    if (page != MAP_FAILED) {
        pageAddr = (uint64_t)page;
        memcpy(page, &magic, 8);
    }
    emit("{\"k\":\"@mmap\",\"ok\":%d,\"page\":\"0x%llx\",\"magic\":\"0x%llx\"}",
         page != MAP_FAILED, (unsigned long long)pageAddr, (unsigned long long)magic);

    probe7(conn, "A", "A1_null",    0x0ull,              8, 0, 0);
    probe7(conn, "A", "A2_unalign", 0x1ull,              8, 0, 0);
    probe7(conn, "A", "A3_unmapped",0xdeadbeef000ull,    8, 0, 0);
    if (pageAddr) {
        probe7(conn, "A", "A4_valpage",     pageAddr,          8, 0, 0);
        probe7(conn, "A", "A5_valpage16",   pageAddr + 0x10,   8, 0, 0);
        probe7(conn, "A", "A6_valpageff0",  pageAddr + 0xff0,  8, 0, 0);
    } else {
        emit("{\"k\":\"@skip\",\"grp\":\"A\",\"why\":\"mmap_failed\"}");
    }
}

// b：组 B 单个内核地址，一次进程只打一个（addr= 传进来）
static void stage_b(io_connect_t conn, uint64_t addr, int reps) {
    emit("{\"k\":\"@plan\",\"st\":\"b\",\"addr\":\"0x%llx\",\"reps\":%d}",
         (unsigned long long)addr, reps);
    for (int i = 0; i < reps; i++) {
        char tag[32];
        snprintf(tag, sizeof tag, "B_rep%d", i + 1);
        probe7(conn, "B", tag, addr, 8, 0, 0);
    }
}

// c：组 C 同一地址，扫 structOut / scalarOut 容量
static void stage_c(io_connect_t conn, uint64_t addr) {
    static const size_t   ssts[5] = { 0, 1, 8, 64, 4096 };
    static const uint32_t socs[2] = { 0, 1 };
    emit("{\"k\":\"@plan\",\"st\":\"c\",\"addr\":\"0x%llx\"}", (unsigned long long)addr);
    for (int b = 0; b < 5; b++)
        for (int a = 0; a < 2; a++) {
            char tag[48];
            snprintf(tag, sizeof tag, "C_sst%zu_soc%u", ssts[b], socs[a]);
            probe7(conn, "C", tag, addr, 8, socs[a], ssts[b]);
        }
}


// ---------------- 崩溃捕获：SIGSEGV/SIGBUS 里把 fault 地址写出去 ----------------
#include <signal.h>
#include <sys/mman.h>

static int g_nd_fd = -1, g_log_fd = -1;

static void sig_handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    char b[192];
    int n = snprintf(b, sizeof b,
                     "{\"k\":\"@sig\",\"sig\":%d,\"faultaddr\":\"0x%llx\",\"code\":%d}\n",
                     sig, (unsigned long long)(uintptr_t)si->si_addr, si->si_code);
    if (n > 0) {
        if (g_nd_fd  >= 0) { ssize_t w = write(g_nd_fd, b, (size_t)n); (void)w; }
        if (g_log_fd >= 0) { ssize_t w = write(g_log_fd, b, (size_t)n); (void)w; }
    }
    _exit(9);
}

static void install_sig(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
}

// mincore：不碰内容就能知道这段还在不在映射里
static void mem_state(const char *tag, uint8_t *p, size_t len) {
    if (len > 16384) len = 16384;
    unsigned char vec[8];
    memset(vec, 0xEE, sizeof vec);
    errno = 0;
    int r = mincore(p, len, vec);
    int e = errno;
    emit("{\"k\":\"@mv\",\"tag\":\"%s\",\"rc\":%d,\"errno\":%d,\"vec0\":%d}", tag, r, e, r == 0 ? (int)vec[0] : -1);
}

// ---------------- 写探测：handler 会不会往我们给的页里写 ----------------
static void hexrow(const char *tag, size_t off, const uint8_t *p, size_t n) {
    char hex[2 * 64 + 1];
    size_t hn = n > 32 ? 32 : n;
    for (size_t i = 0; i < hn; i++) sprintf(hex + 2 * i, "%02x", p[i]);
    hex[2 * hn] = 0;
    emit("{\"k\":\"@w\",\"tag\":\"%s\",\"off\":%zu,\"n\":%zu,\"b\":\"%s\"}", tag, off, hn, hex);
}

static void ptrscan(const char *tag, size_t off, const uint8_t *p, size_t n) {
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t v;
        memcpy(&v, p + i, 8);
        if (v == 0) continue;
        int kk = ((v & 0xFFFFFF0000000000ull) == 0xFFFFFE0000000000ull);
        if (kk)
            emit("{\"k\":\"@ptrlike\",\"tag\":\"%s\",\"off\":%zu,\"v\":\"0x%016llx\"}",
                 tag, off + i, (unsigned long long)v);
    }
}

// 返回 0 = 页内容未变；1 = 变了（已 dump）
static int page_diff(const char *tag, const uint8_t *page, const uint8_t *pristine, size_t len) {
    size_t first = (size_t)-1, last = 0, cnt = 0;
    for (size_t i = 0; i < len; i++)
        if (page[i] != pristine[i]) { if (first == (size_t)-1) first = i; last = i; cnt++; }
    if (cnt == 0) {
        emit("{\"k\":\"@diff\",\"tag\":\"%s\",\"changed\":0,\"len\":%zu}", tag, len);
        return 0;
    }
    emit("{\"k\":\"@diff\",\"tag\":\"%s\",\"changed\":1,\"first\":%zu,\"last\":%zu,\"nbytes\":%zu,\"len\":%zu}",
         tag, first, last, cnt, len);
    // 完整 dump 变化区间（按 32 字节行，最多 64 行）
    size_t from = (first & ~(size_t)31);
    size_t to   = (last + 32) & ~(size_t)31;
    if (to > len) to = len;
    int rows = 0;
    for (size_t off = from; off < to && rows < 64; off += 32, rows++) {
        hexrow(tag, off, page + off, (to - off) >= 32 ? 32 : (to - off));
    }
    ptrscan(tag, from, page + from, to - from);
    return 1;
}

// 用 0xCD 铺满 + 若干 canary，得到一个「已知内容」的页
static void fill_canary(uint8_t *p, size_t len) {
    memset(p, 0xCD, len);
    static const size_t canary_off[] = { 0x0, 0x100, 0x400, 0x800, 0xc00, 0xff0 };
    uint64_t magic = 0x4142434445464748ull;
    for (size_t i = 0; i < sizeof(canary_off)/sizeof(canary_off[0]); i++) {
        if (canary_off[i] + 8 <= len) memcpy(p + canary_off[i], &magic, 8);
    }
}

// stage w：只传有效页地址，调用前后逐字节比对
static void stage_w(io_connect_t conn, int reps) {
    const size_t PLEN = 0x4000;                      // 4 页，溢出也能看到
    uint8_t *page = (uint8_t *)mmap(NULL, PLEN, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap_failed\"}"); return; }
    uint8_t *pristine = (uint8_t *)malloc(PLEN);
    fill_canary(page, PLEN);
    memcpy(pristine, page, PLEN);

    uint64_t base = (uint64_t)page;
    emit("{\"k\":\"@plan\",\"st\":\"w\",\"page\":\"0x%llx\",\"len\":%zu,\"reps\":%d,\"fill\":\"0xCD\",\"canary\":\"0x4142434445464748\"}",
         (unsigned long long)base, PLEN, reps);

    // W1: 页首，重复 reps 次（确定性）
    for (int i = 0; i < reps; i++) {
        char tag[32];
        snprintf(tag, sizeof tag, "W1_start_r%d", i + 1);
        probe7(conn, "W", tag, base, 8, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    // W2: 页内 +0x10
    {
        const char *tag = "W2_plus10";
        probe7(conn, "W", tag, base + 0x10, 8, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    // W3: 页内 +0xff0（canary 位置）
    {
        const char *tag = "W3_plusff0";
        probe7(conn, "W", tag, base + 0xff0, 8, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    // W4: 第二页页首
    {
        const char *tag = "W4_page2";
        probe7(conn, "W", tag, base + 0x1000, 8, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    // W5: 未映射地址对照 —— 不应该改动任何东西
    {
        const char *tag = "W5_ctrl_unmapped";
        probe7(conn, "W", tag, 0xdeadbeef000ull, 8, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    // W6: in=0 对照（BadArgument 路径）
    {
        const char *tag = "W6_ctrl_in0";
        probe7(conn, "W", tag, 0, 0, 0, 0);
        page_diff(tag, page, pristine, PLEN);
    }
    free(pristine);
}

// stage guard：三页布局 [PROT_NONE][RW:0xCD][PROT_NONE]
//   G1 页首        -> 基准
//   G2 页尾 -8     -> 往后写超过 8 字节就踩到 PROT_NONE
//   G3 页首 -8     -> 往回碰就踩到 PROT_NONE（确认是从给定地址开始）
//   G4 只读页页首   -> 写就 fault，只读则 SUCCESS
//   G5 PROT_NONE 页 -> 保护检查
static void stage_guard(io_connect_t conn) {
    const size_t PG = 4096;
    uint8_t *region = (uint8_t *)mmap(NULL, 3 * PG, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap_failed\"}"); return; }
    uint8_t *lo = region, *mid = region + PG, *hi = region + 2 * PG;
    fill_canary(mid, PG);
    uint8_t *pristine = (uint8_t *)malloc(PG);
    memcpy(pristine, mid, PG);

    mprotect(lo, PG, PROT_NONE);
    mprotect(hi, PG, PROT_NONE);

    // 只读页单独一页
    uint8_t *ro = (uint8_t *)mmap(NULL, PG, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ro != MAP_FAILED) { fill_canary(ro, PG); mprotect(ro, PG, PROT_READ); }

    emit("{\"k\":\"@plan\",\"st\":\"guard\",\"lo\":\"0x%llx\",\"mid\":\"0x%llx\",\"hi\":\"0x%llx\",\"ro\":\"0x%llx\"}",
         (unsigned long long)(uintptr_t)lo, (unsigned long long)(uintptr_t)mid,
         (unsigned long long)(uintptr_t)hi, (unsigned long long)(uintptr_t)ro);

    probe7(conn, "G", "G1_start",     (uint64_t)(uintptr_t)mid,        8, 0, 0);
    page_diff("G1_start", mid, pristine, PG);

    probe7(conn, "G", "G2_end8",      (uint64_t)(uintptr_t)(mid + PG - 8), 8, 0, 0);
    page_diff("G2_end8", mid, pristine, PG);

    probe7(conn, "G", "G3_pre8",      (uint64_t)(uintptr_t)(mid - 8),  8, 0, 0);
    page_diff("G3_pre8", mid, pristine, PG);

    if (ro != MAP_FAILED) {
        probe7(conn, "G", "G4_readonly", (uint64_t)(uintptr_t)ro, 8, 0, 0);
        // RO 页比对：只比较（若内核写了会 fault 或没写）
        uint8_t *rop = (uint8_t *)malloc(PG);
        memcpy(rop, ro, PG);
        fill_canary(rop, PG);
        page_diff("G4_readonly", ro, rop, PG);
        free(rop);
    }

    probe7(conn, "G", "G5_protnone",  (uint64_t)(uintptr_t)lo,  8, 0, 0);
    probe7(conn, "G", "G6_page2",     (uint64_t)(uintptr_t)(mid + PG), 8, 0, 0);
    page_diff("G6_page2", mid, pristine, PG);

    free(pristine);
}

// stage sweep：内核 VA 网。与 KASLR 无关的兜底判据 ——
//   只要内核文本/数据在某个 slide 上被映射，网眼（16MB）必然落进去；
//   若整张网都回 0x1，就说明「内核地址在这个 selector 上一律不可翻译」。
// 同时把 5 份 panic .ips 里 binaryImages 记录过的 kernelcache 装载地址逐个打一遍。
static void stage_sweep(io_connect_t conn) {
    static const uint64_t seeds[] = {
        0xfffffe000ab44000ull, 0xfffffe00095bba10ull, 0xfffffe000a87c660ull,
        0xfffffe000a149340ull, 0xfffffe000a3257c0ull,
    };
    emit("{\"k\":\"@plan\",\"st\":\"sweep\",\"from\":\"0xfffffe0007000000\",\"to\":\"0xfffffe004c000000\",\"step\":\"0x1000000\",\"seeds\":5}");
    for (size_t i = 0; i < sizeof(seeds)/sizeof(seeds[0]); i++) {
        char tag[32];
        snprintf(tag, sizeof tag, "S_seed%zu", i);
        probe7(conn, "S", tag, seeds[i], 8, 0, 0);
    }
    for (uint64_t a = 0xfffffe0007000000ull; a <= 0xfffffe004c000000ull; a += 0x1000000ull) {
        char tag[40];
        snprintf(tag, sizeof tag, "S_%llx", (unsigned long long)a);
        probe7(conn, "S", tag, a, 8, 0, 0);
    }
}


// stage gtest：一种内存布局一个进程（崩了只损失这一个 mode）
//   mode=plain|up|down|none|ro|end8|pre8
static void stage_gtest(io_connect_t conn, const char *mode) {
    const size_t PG = 4096;
    uint8_t *base = NULL;
    uint8_t *target = NULL;
    uint8_t *pristine = (uint8_t *)malloc(PG);
    fill_canary(pristine, PG);

    if (strcmp(mode, "plain") == 0 || strcmp(mode, "end8") == 0 || strcmp(mode, "pre8") == 0) {
        base = (uint8_t *)mmap(NULL, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap\"}"); return; }
        target = base + PG;
        fill_canary(target, PG);
        if (strcmp(mode, "end8") == 0) { mprotect(base + 2 * PG, PG, PROT_NONE); }
        if (strcmp(mode, "pre8") == 0) { mprotect(base, PG, PROT_NONE); }
    } else if (strcmp(mode, "up") == 0) {
        base = (uint8_t *)mmap(NULL, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap\"}"); return; }
        target = base;                       // 目标在第 0 页，保护页在上方 +0x2000
        fill_canary(target, PG);
        mprotect(base + 2 * PG, PG, PROT_NONE);
    } else if (strcmp(mode, "down") == 0) {
        base = (uint8_t *)mmap(NULL, 3 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap\"}"); return; }
        target = base + PG;                  // 目标在第 1 页，保护页在下方 -0x1000
        fill_canary(target, PG);
        mprotect(base, PG, PROT_NONE);
    } else if (strcmp(mode, "none") == 0 || strcmp(mode, "ro") == 0) {
        base = (uint8_t *)mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { emit("{\"k\":\"@fatal\",\"why\":\"mmap\"}"); return; }
        target = base;
        fill_canary(target, PG);
        mprotect(target, PG, (strcmp(mode, "none") == 0) ? PROT_NONE : PROT_READ);
    } else {
        emit("{\"k\":\"@fatal\",\"why\":\"bad_mode\",\"mode\":\"%s\"}", mode);
        return;
    }

    uint64_t addr = (uint64_t)(uintptr_t)target;
    if (strcmp(mode, "end8") == 0) addr = (uint64_t)(uintptr_t)(target + PG - 8);
    if (strcmp(mode, "pre8") == 0) addr = (uint64_t)(uintptr_t)(target - 8);

    emit("{\"k\":\"@plan\",\"st\":\"gtest\",\"mode\":\"%s\",\"base\":\"0x%llx\",\"target\":\"0x%llx\",\"addr\":\"0x%llx\"}",
         mode, (unsigned long long)(uintptr_t)base, (unsigned long long)(uintptr_t)target,
         (unsigned long long)addr);

    mem_state("before", target, PG);
    probe7(conn, "GT", mode, addr, 8, 0, 0);
    mem_state("after", target, PG);
    emit("{\"k\":\"@mark\",\"tag\":\"%s\",\"at\":\"read_page0\"}", mode);
    volatile uint8_t probe_read = target[0];
    emit("{\"k\":\"@readable\",\"tag\":\"%s\",\"off\":0,\"v\":%u}", mode, (unsigned)probe_read);
    if (strcmp(mode, "none") != 0) {
        page_diff(mode, target, pristine, PG);
    }
    emit("{\"k\":\"@mark\",\"tag\":\"%s\",\"at\":\"done\"}", mode);
}

// d（补充）：structIn 长度扫描，看「几个字节被当地址」
static void stage_len(io_connect_t conn, uint64_t addr) {
    static const size_t lens[7] = { 1, 2, 4, 8, 16, 32, 64 };
    emit("{\"k\":\"@plan\",\"st\":\"len\",\"addr\":\"0x%llx\"}", (unsigned long long)addr);
    for (int i = 0; i < 7; i++) {
        char tag[32];
        snprintf(tag, sizeof tag, "D_len%zu", lens[i]);
        probe7(conn, "D", tag, addr, lens[i], 0, 0);
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
static uint64_t kvx(const char *key, uint64_t dflt) {
    const char *v = kv(key);
    return v ? (uint64_t)strtoull(v, NULL, 0) : dflt;
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
    gLog = fopen([[dir stringByAppendingPathComponent:@"sel7addr.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"sel7addr.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 sel7addr.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 sel7addr.ndjson\n");
    if (gNd)  g_nd_fd  = fileno(gNd);
    if (gLog) g_log_fd = fileno(gLog);
    install_sig();

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"sel7addr: AppleM2ScalerCSCDriver selector 7 address probe";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"base";

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"sel7addr.hb"] UTF8String]);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, hbPath) == 0) pthread_detach(hb);

    int wd = (int)kvl("wd", 120);
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
                     "\"stage\":\"%s\",\"wd\":%d,\"timeout_s\":%d,\"sel\":%d}",
                     kFingerprint, kBuildStamp,
                     [[[UIDevice currentDevice] systemVersion] UTF8String],
                     [[[UIDevice currentDevice] model] UTF8String],
                     stage.UTF8String, wd, CALL_TIMEOUT_S, SEL7);

                warmup(conn);

                if ([stage isEqualToString:@"base"]) {
                    stage_base(conn);
                } else if ([stage isEqualToString:@"a"]) {
                    stage_a(conn);
                } else if ([stage isEqualToString:@"b"]) {
                    stage_b(conn, kvx("addr", 0), (int)kvl("reps", 2));
                } else if ([stage isEqualToString:@"c"]) {
                    stage_c(conn, kvx("addr", 0));
                } else if ([stage isEqualToString:@"w"]) {
                    stage_w(conn, (int)kvl("reps", 3));
                } else if ([stage isEqualToString:@"guard"]) {
                    stage_guard(conn);
                } else if ([stage isEqualToString:@"gtest"]) {
                    const char *m = kv("mode");
                    stage_gtest(conn, m ? m : "plain");
                } else if ([stage isEqualToString:@"sweep"]) {
                    stage_sweep(conn);
                } else if ([stage isEqualToString:@"len"]) {
                    stage_len(conn, kvx("addr", 0));
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
                }

                emit("{\"k\":\"@done\",\"stage\":\"%s\",\"t\":%llu,\"consec_to\":%d,\"abort\":%d}",
                     stage.UTF8String, (unsigned long long)(now_ms() - g_t0), g_consec, g_abort);
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
