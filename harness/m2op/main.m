// main.m — m2op：AppleM2ScalerCSCDriver selector 11 的【命令空间】探查。
//
// 已由真机实测确证（本轮直接当作前提，不重验）：
//   服务 AppleM2ScalerCSCDriver / IOServiceOpen type 0 -> KERN_SUCCESS
//   selector 11；scalarIn 必须为 0；scalarOut <= 8 且写回 0 字节；
//   structOut 必须为 0；structIn 长度 0..4096 任意全 SUCCESS，32776 -> kIOReturnIPCError。
//   ⇒ 长度不受约束的用户可控内核输入通道。
//
// 本进程只做一件事：把「首 4 字节 = opcode」这个假设下的 opcode 空间打出来。
//
// 阶段（每个阶段一次独立进程运行，跑完看结果再决定下一个）：
//   p1  opcode 0..1023，structIn 固定 64 B，buf[0..3]=opcode(LE u32)，其余 0
//   p2  对 p1 异常 opcode，把 opcode 分别放到偏移 0/4/8/16 各调一次
//   p3  长度阶梯 {0,1,2,3,4,8,16,32,64,128,256,1024,4096}，内容全 0（不放 opcode）
//   p4  对异常 opcode，随机化 opcode 之后的字节（固定 seed 可重放），各 200 次
//
// 记录纪律：每次调用【先落 @pre】再调；结果行立刻 fflush+fsync。
//           挂起 = 独立 pthread + 3s 超时，超时 detach 泄漏、记 @timeout、继续下一条。
//           心跳 200ms 一行 @hb，挂死点即证据。
//
// 指纹（装前 strings 校验，必须命中 >=1）：M2OP-20261101-sel11opcode-a91f4c
// 只做 selector 11。不碰 harness/israce/，不改 out/ 既有文件。

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

static const char *kFingerprint = "M2OP-20261101-sel11opcode-a91f4c";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define SVC_NAME       "AppleM2ScalerCSCDriver"
#define OPEN_TYPE      0
#define SEL            11
#define CALL_TIMEOUT_S 3
#define MAX_TIMEOUTS_PER_STAGE 8
#define SOCAP          8        // scalarOut 容量（确证 <=8 允许）
#define BUFLEN64       64

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static volatile int g_hb_stop = 0;
static int g_sentinel_intact = 1;
static char     g_hb_tag[96] = "-";
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

static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);
    fputs(buf, stderr); fflush(stderr);
    if (gLog) { fputs(buf, gLog); fflush(gLog); fsync(fileno(gLog)); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd));  }   // @pre 必须真的落盘
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
        case 0xe00002c3: return "kIOReturnLockedRead";
        case 0xe00002c4: return "kIOReturnLockedWrite";
        case 0xe00002e2: return "kIOReturnNotAttached";
        default:         return "OTHER";
    }
}

// ---------------- 单次调用（独立线程 + 3s 超时） ----------------
typedef struct {
    io_connect_t conn;
    const uint8_t *bin;
    size_t   len;
    int      useSO;
    IOReturn kr;
    uint32_t oc;
    size_t   sc;
    uint64_t sout[SOCAP];
    uint64_t us;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    int done;
} Job;

static void *job_run(void *p) {
    Job *j = (Job *)p;
    j->oc = j->useSO ? SOCAP : 0;
    j->sc = 0;
    for (int i = 0; i < SOCAP; i++) j->sout[i] = 0xA5A5A5A5A5A5A5A5ull;  // 哨兵：可区分「内核写了」与「只回显计数」
    uint64_t a = now_us();
    j->kr = (IOReturn)IOConnectCallMethod(
        j->conn, SEL,
        NULL, 0,                              // scalarIn 必须为 0
        (j->len ? (void *)j->bin : NULL), j->len,
        (j->useSO ? j->sout : NULL), &j->oc,
        NULL, &j->sc);                        // structOut 必须为 0
    j->us = now_us() - a;

    pthread_mutex_lock(&j->m);
    j->done = 1;
    pthread_cond_signal(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

// 0 = 有结果；1 = 超时（job 泄漏不回收）；2 = 线程没起来
static int call_to(io_connect_t conn, const uint8_t *bin, size_t len, int useSO, Job **outJob) {
    Job *j = (Job *)calloc(1, sizeof(Job));
    j->conn = conn; j->bin = bin; j->len = len; j->useSO = useSO;
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
        // 内核调用不返回：thread 不 join（会自己挂死），detach + 故意泄漏 job
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

// ---------------- 统一调用封装：先落 @pre，再调，再落结果 ----------------
// 返回 0 = 有结果（*krOut / *ocOut / *usOut 有效）；1 = 超时；2 = 线程失败
static int call_logged(const char *preRow,      /* 已格式化好的整行 @pre */
                       io_connect_t conn, const uint8_t *buf, size_t len, int useSO,
                       IOReturn *krOut, uint32_t *ocOut, uint64_t *usOut,
                       uint64_t *soutOut /* 可为 NULL，长度 SOCAP */) {
    emit("%s", preRow);        // @pre —— 必须在调用前落盘
    Job *j = NULL;
    int r = call_to(conn, buf, len, useSO, &j);
    if (r == 1) { emit("{\"k\":\"@timeout\",\"pre\":%s}", preRow + 1); return 1; }
    if (r == 2) { emit("{\"k\":\"@threadfail\",\"pre\":%s}", preRow + 1); return 2; }
    *krOut = j->kr; *ocOut = j->oc; *usOut = j->us;
    if (soutOut) memcpy(soutOut, j->sout, sizeof(uint64_t) * SOCAP);
    job_free(j);
    return 0;
}

// ---------------- 阶段 1 ----------------
static void stage_p1(io_connect_t conn, uint32_t from, uint32_t to, int useSO, int *tos) {
    uint8_t buf[BUFLEN64];
    char ctx[64];
    for (uint32_t op = from; op <= to; op++) {
        memset(buf, 0, sizeof buf);
        buf[0] = (uint8_t)(op & 0xff);
        buf[1] = (uint8_t)((op >> 8) & 0xff);
        buf[2] = (uint8_t)((op >> 16) & 0xff);
        buf[3] = (uint8_t)((op >> 24) & 0xff);
        snprintf(ctx, sizeof ctx, "p1/op=%u", op);
        snprintf(g_hb_tag, sizeof g_hb_tag, "p1 op=%u", op);

        IOReturn kr = 0; uint32_t oc = 0; uint64_t us = 0;
        uint64_t sv[SOCAP];
        char pre[160];
        snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"p1\",\"op\":%u}", op);
        int r = call_logged(pre, conn, buf, sizeof buf, useSO, &kr, &oc, &us, sv);
        if (r == 1) { (*tos)++; if (*tos >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"st\":\"p1\",\"op\":%u,\"why\":\"too_many_timeouts\"}", op); return; } continue; }
        if (r == 2) continue;
        g_sentinel_intact = 1;
        for (int i = 0; i < SOCAP; i++) if (sv[i] != 0xA5A5A5A5A5A5A5A5ull) { g_sentinel_intact = 0; break; }
        emit("{\"k\":\"@p1\",\"op\":%u,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"us\":%llu,"
             "\"sent\":%d,\"so\":[\"0x%016llx\",\"0x%016llx\",\"0x%016llx\",\"0x%016llx\","
             "\"0x%016llx\",\"0x%016llx\",\"0x%016llx\",\"0x%016llx\"]}",
             op, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc, (unsigned long long)us,
             g_sentinel_intact,
             (unsigned long long)sv[0], (unsigned long long)sv[1],
             (unsigned long long)sv[2], (unsigned long long)sv[3],
             (unsigned long long)sv[4], (unsigned long long)sv[5],
             (unsigned long long)sv[6], (unsigned long long)sv[7]);
    }
}

// ---------------- 阶段 2 ----------------
static void stage_p2(io_connect_t conn, const uint32_t *ops, int nops, int *tos) {
    static const uint32_t ats[4] = { 0, 4, 8, 16 };
    uint8_t buf[BUFLEN64];
    char ctx[64];
    for (int i = 0; i < nops; i++) {
        uint32_t op = ops[i];
        for (int k = 0; k < 4; k++) {
            uint32_t at = ats[k];
            memset(buf, 0, sizeof buf);
            if (at + 4 <= sizeof buf) {
                buf[at + 0] = (uint8_t)(op & 0xff);
                buf[at + 1] = (uint8_t)((op >> 8) & 0xff);
                buf[at + 2] = (uint8_t)((op >> 16) & 0xff);
                buf[at + 3] = (uint8_t)((op >> 24) & 0xff);
            }
            snprintf(ctx, sizeof ctx, "p2/op=%u/at=%u", op, at);
            snprintf(g_hb_tag, sizeof g_hb_tag, "p2 op=%u at=%u", op, at);

            IOReturn kr = 0; uint32_t oc = 0; uint64_t us = 0;
            char pre[160];
            snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"p2\",\"op\":%u,\"at\":%u}", op, at);
            int r = call_logged(pre, conn, buf, sizeof buf, 1, &kr, &oc, &us, NULL);
            if (r == 1) { (*tos)++; if (*tos >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"st\":\"p2\",\"op\":%u,\"at\":%u}", op, at); return; } continue; }
            if (r == 2) continue;
            emit("{\"k\":\"@p2\",\"op\":%u,\"at\":%u,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"us\":%llu}",
                 op, at, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc, (unsigned long long)us);
        }
    }
}

// ---------------- 阶段 3 ----------------
static void stage_p3(io_connect_t conn, const uint32_t *ops, int nops, int *tos,
                     const size_t *extlens, int next) {
    static const size_t lens[13] = { 0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1024, 4096 };
    const size_t *L = extlens ? extlens : lens;
    int NL = extlens ? next : 13;
    uint8_t *big = (uint8_t *)calloc(65536, 1);     // 内容全 0，不放 opcode
    char ctx[64];

    int passes = (nops > 0) ? nops : 1;             // nops==0 -> 只跑一次通用长度阶梯
    for (int i = 0; i < passes; i++) {
        long op = (nops > 0) ? (long)ops[i] : -1;
        for (int k = 0; k < NL; k++) {
            size_t len = L[k];
            snprintf(ctx, sizeof ctx, "p3/op=%ld/len=%zu", op, len);
            snprintf(g_hb_tag, sizeof g_hb_tag, "p3 op=%ld len=%zu", op, len);

            IOReturn kr = 0; uint32_t oc = 0; uint64_t us = 0;
            int r;
            char pre[160];
            if (nops > 0)
                snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"p3\",\"op\":%ld,\"len\":%zu}", op, len);
            else
                snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"p3\",\"len\":%zu}", len);
            r = call_logged(pre, conn, big, len, 1, &kr, &oc, &us, NULL);
            if (r == 1) { (*tos)++; if (*tos >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"st\":\"p3\"}"); free(big); return; } continue; }
            if (r == 2) continue;
            if (nops > 0)
                emit("{\"k\":\"@p3\",\"op\":%ld,\"len\":%zu,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"us\":%llu}",
                     op, len, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc, (unsigned long long)us);
            else
                emit("{\"k\":\"@p3\",\"len\":%zu,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"us\":%llu}",
                     len, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc, (unsigned long long)us);
        }
    }
    free(big);
}

// ---------------- 阶段 4 ----------------
static uint64_t xs64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    *s = x;
    return x * 2685821657736338717ull;
}

static void stage_p4(io_connect_t conn, const uint32_t *ops, int nops, int iters, int *tos) {
    uint8_t buf[BUFLEN64];
    char ctx[64];
    for (int i = 0; i < nops; i++) {
        uint32_t op = ops[i];
        // 固定 seed，可重放：seed = 0x9E3779B97F4A7C15 ^ (op * 2654435761)
        uint64_t seed = 0x9E3779B97F4A7C15ull ^ ((uint64_t)op * 2654435761ull);
        for (int it = 0; it < iters; it++) {
            memset(buf, 0, sizeof buf);
            buf[0] = (uint8_t)(op & 0xff);
            buf[1] = (uint8_t)((op >> 8) & 0xff);
            buf[2] = (uint8_t)((op >> 16) & 0xff);
            buf[3] = (uint8_t)((op >> 24) & 0xff);
            for (size_t o = 4; o < sizeof buf; o += 8) {
                uint64_t v = xs64(&seed);
                size_t n = (sizeof buf - o >= 8) ? 8 : (sizeof buf - o);
                memcpy(buf + o, &v, n);
            }
            snprintf(ctx, sizeof ctx, "p4/op=%u/it=%d", op, it);
            snprintf(g_hb_tag, sizeof g_hb_tag, "p4 op=%u it=%d", op, it);

            IOReturn kr = 0; uint32_t oc = 0; uint64_t us = 0;
            char pre[160];
            snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"p4\",\"op\":%u,\"it\":%d}", op, it);
            int r = call_logged(pre, conn, buf, sizeof buf, 1, &kr, &oc, &us, NULL);
            if (r == 1) { (*tos)++; if (*tos >= MAX_TIMEOUTS_PER_STAGE) { emit("{\"k\":\"@abort\",\"st\":\"p4\",\"op\":%u,\"it\":%d}", op, it); return; } continue; }
            if (r == 2) continue;
            emit("{\"k\":\"@p4\",\"op\":%u,\"it\":%d,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u,\"us\":%llu}",
                 op, it, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc, (unsigned long long)us);
        }
    }
}

// ---------------- 参数（从 NSProcessInfo 建一份 C argv） ----------------
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
    for (int i = 2; i < g_argc; i++) {
        if (strncmp(g_argv[i], key, n) == 0 && g_argv[i][n] == '=') return g_argv[i] + n + 1;
    }
    return NULL;
}
static long kvl(const char *key, long dflt) {
    const char *v = kv(key);
    return v ? strtol(v, NULL, 10) : dflt;
}
static int parse_ops(const char *csv, uint32_t *out, int cap) {
    if (!csv || !*csv || strcmp(csv, "-") == 0) return 0;
    int n = 0;
    const char *p = csv;
    while (*p && n < cap) {
        out[n++] = (uint32_t)strtoul(p, (char **)&p, 0);
        if (*p == ',') p++;
    }
    return n;
}

// ---------------- 打开服务 ----------------
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
    gLog = fopen([[dir stringByAppendingPathComponent:@"m2op.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"m2op.ndjson"] UTF8String], "w");
    if (!gLog) fprintf(stderr, "!! 打不开 m2op.log\n");
    if (!gNd)  fprintf(stderr, "!! 打不开 m2op.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"m2op sel11 opcode sweep…";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;   // 跑测期间不自动锁屏

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"p1";

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"m2op.hb"] UTF8String]);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, hbPath) == 0) pthread_detach(hb);

    int wd = (int)kvl("wd", 300);
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
                     "\"stage\":\"%s\",\"sel\":%d,\"wd\":%d,\"timeout_s\":%d,\"socap\":%d}",
                     kFingerprint, kBuildStamp,
                     [[[UIDevice currentDevice] systemVersion] UTF8String],
                     [[[UIDevice currentDevice] model] UTF8String],
                     stage.UTF8String, SEL, wd, CALL_TIMEOUT_S, SOCAP);

                int tos = 0;

                if ([stage isEqualToString:@"p1"]) {
                    // 先校准 scalarOut 容量：确证 <=8 允许且写回 0 字节。取能成功的那一档给整轮用。
                    uint8_t z[BUFLEN64]; memset(z, 0, sizeof z);
                    int force = (int)kvl("socap", -1);   // -1 = 自动；0/1 = 强制该档
                    int useSO = -1;
                    for (int cap = (force >= 0 ? force : 0); cap <= (force >= 0 ? force : 1) && useSO < 0; cap++) {
                        IOReturn kr = 0; uint32_t oc = 0; uint64_t us = 0;
                        char pre[160];
                        snprintf(pre, sizeof pre, "{\"k\":\"@pre\",\"st\":\"base\",\"socap\":%d}", cap ? SOCAP : 0);
                        int r = call_logged(pre, conn, z, sizeof z, cap, &kr, &oc, &us, NULL);
                        if (r != 0) continue;
                        emit("{\"k\":\"@base\",\"socap\":%d,\"len\":%zu,\"kr\":%u,\"krhex\":\"0x%08X\",\"krn\":\"%s\",\"oc\":%u}"
                             , cap ? SOCAP : 0, sizeof z, (unsigned)kr, (unsigned)kr, kr_name((unsigned)kr), oc);
                        if (kr == 0) useSO = cap;
                    }
                    if (useSO < 0) {
                        emit("{\"k\":\"@fatal\",\"why\":\"both_socap_rejected\"}");
                    } else {
                        emit("{\"k\":\"@cfg\",\"use_socap\":%d,\"len\":%d}", useSO ? SOCAP : 0, BUFLEN64);
                        stage_p1(conn, (uint32_t)kvl("from", 0), (uint32_t)kvl("to", 1023), useSO, &tos);
                    }
                } else if ([stage isEqualToString:@"p2"]) {
                    uint32_t ops[512];
                    int n = parse_ops(kv("ops"), ops, 512);
                    emit("{\"k\":\"@plan\",\"st\":\"p2\",\"nops\":%d}", n);
                    stage_p2(conn, ops, n, &tos);
                } else if ([stage isEqualToString:@"p3"]) {
                    uint32_t ops[512];
                    int n = parse_ops(kv("ops"), ops, 512);
                    emit("{\"k\":\"@plan\",\"st\":\"p3\",\"nops\":%d,\"mode\":\"%s\"}", n, n ? "per_op" : "generic");
                    size_t extlens[64]; int next = 0;
                    const char *lv = kv("lens");
                    if (lv && *lv) {
                        const char *q = lv;
                        while (*q && next < 64) { extlens[next++] = (size_t)strtoul(q, (char **)&q, 0); if (*q == ',') q++; }
                    }
                    stage_p3(conn, ops, n, &tos, next ? extlens : NULL, next);
                } else if ([stage isEqualToString:@"p4"]) {
                    uint32_t ops[512];
                    int n = parse_ops(kv("ops"), ops, 512);
                    int iters = (int)kvl("iters", 200);
                    emit("{\"k\":\"@plan\",\"st\":\"p4\",\"nops\":%d,\"iters\":%d}", n, iters);
                    stage_p4(conn, ops, n, iters, &tos);
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
                }

                emit("{\"k\":\"@done\",\"stage\":\"%s\",\"t\":%llu,\"timeouts\":%d}",
                     stage.UTF8String, (unsigned long long)(now_ms() - g_t0), tos);
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
