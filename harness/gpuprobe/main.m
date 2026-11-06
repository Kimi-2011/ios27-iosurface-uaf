// main.m — gpuprobe/GPU-DUMP：把 AGXAcceleratorG18P 用户客户端( type 1 )的
//          「成功 selector 的输出缓冲区」原样 dump 出来，找内核指针 / PAC 指针。
//
// 只做两件事：
//   测试 A：对 14 个已确证 SUCCESS 的 selector，按输出尺寸分配缓冲区，
//           IOConnectCallMethod 后把返回字节完整 hexdump（每 16B 一行，立即 fflush）。
//   测试 B：sel 8（handler 0xa02260c，输入输出双双 wildcard）用更大的 stIn/stOut 网格，
//           stIn 主序 {0x58,0x60,0x100,0x400} × stOut 次序 {0x80,0x200,0x800,0x1000}，
//           每次调用前先落 @preB 并 fsync。
//
// 绝对不调 sel 55（永久阻塞，三次复现）。
//
// 指纹（装前 strings 校验）: GPUDUMP-20261101-bufdump-c3f7a1
// 不改 harness/israce/，不改 svcprobe，不改 out/ 既有文件。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

static const char *kFingerprint = "GPUDUMP-20261101-bufdump-c3f7a1";
static const char *kBuildStamp  = __DATE__ " " __TIME__;
static const char *kServiceName = "AGXAcceleratorG18P";

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define SCALAR_CAP   64
#define STRUCT_CAP   4096
#define HEX_MIN      256      // 至少 dump 这么多字节
#define NSEL_FORBID  55       // 永远不碰

static FILE *gNd  = NULL;
static FILE *gLog = NULL;

static int      g_pass1Done = 0;
static int      g_passBDone = 0;
static volatile uint32_t g_cur_sel = 55;   // 开跑前先标成禁区，心跳不会误报别处
static volatile int      g_hb_stop = 0;
static uint64_t g_t0 = 0;
static int      g_wd_sec = 150;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

// 心跳：卡死时停在哪一刻就是证据。
static void *hb_thread(void *arg) {
    const char *path = (const char *)arg;
    FILE *f = fopen(path, "w");
    if (!f) return NULL;
    while (!g_hb_stop) {
        fprintf(f, "{\"k\":\"@hb\",\"t\":%llu,\"sel\":%u}\n",
                (unsigned long long)(now_ms() - g_t0), (unsigned)g_cur_sel);
        fflush(f);
        fsync(fileno(f));
        usleep(200000);
    }
    fclose(f);
    return NULL;
}

static void emit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void emit(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stderr);
    fflush(stderr);
    if (gLog) { fputs(buf, gLog); fflush(gLog); fsync(fileno(gLog)); }
    if (gNd)  { fputs(buf, gNd);  fflush(gNd);  fsync(fileno(gNd));  }
}

static const char *kr_name(IOReturn kr) {
    switch ((unsigned)kr) {
        case 0:           return "SUCCESS";
        case 0xe00002bc:  return "kIOReturnError";
        case 0xe00002bd:  return "kIOReturnNoMemory";
        case 0xe00002be:  return "kIOReturnNoResources";
        case 0xe00002c0:  return "kIOReturnNoDevice";
        case 0xe00002c1:  return "kIOReturnNotPrivileged";
        case 0xe00002c2:  return "kIOReturnBadArgument";
        case 0xe00002c5:  return "kIOReturnExclusiveAccess";
        case 0xe00002c6:  return "kIOReturnBadMessageID";
        case 0xe00002c7:  return "kIOReturnUnsupported";
        case 0xe00002c8:  return "kIOReturnVMError";
        case 0xe00002c9:  return "kIOReturnInternalError";
        case 0xe00002ca:  return "kIOReturnIOError";
        case 0xe00002cd:  return "kIOReturnNotOpen";
        case 0xe00002d4:  return "kIOReturnNoSpace";
        case 0xe00002d5:  return "kIOReturnBusy";
        case 0xe00002d6:  return "kIOReturnAborted";
        case 0xe00002d7:  return "kIOReturnTimeout";
        default:          return "OTHER";
    }
}

// ---------------- A 表：14 个已确证 SUCCESS 的 selector ----------------
// 全部字段取自 out/gpu_selectors.txt（派发表原文），不是猜的。
//   sel, dSIn, dStIn, dSOut, dStOut
// 关键：本 kext 的派发校验对 scalar 个数与 struct 长度都是「精确相等」——
//   实测把 scalarOut 容量开成 64 而声明是 0 → kIOReturnBadArgument(0xe00002c2)。
//   上一轮成功的 @sel 行里 oc 恒为 0，就是证据。所以必须按声明值原样传。
typedef struct { uint32_t sel; uint32_t dSIn; size_t dStIn; uint32_t dSOut; size_t dStOut; } AEnt;
static const AEnt g_A[] = {
    { 0,  0, 0, 0,   64}, { 1,  0, 0, 0,   64}, { 2,  0, 0, 0,  536},
    { 3,  0, 0, 0,    8}, { 4,  0, 0, 0,   32}, { 5,  0, 0, 0,   16},
    {16,  0, 0, 0,    8}, {17,  0, 0, 0,    4}, {19,  1, 0, 0,   24},
    {21,  0, 0, 0,   48}, {23,  0, 0, 1,    0}, {28,  0, 0, 2,    0},
    {41,  1, 0, 0,    0}, {42,  2, 0, 2,    0},
};
static const size_t g_An = sizeof(g_A) / sizeof(g_A[0]);

// --------------------------------------------------------------------
// 单次调用：把返回字节原样带走
// --------------------------------------------------------------------
typedef struct {
    IOReturn kr;
    uint32_t oc;          // 返回后被内核改写的 scalar 输出个数
    size_t   sc;          // 返回后被内核改写的 struct 输出字节数
    uint64_t sOut[SCALAR_CAP];
    uint8_t  bOut[STRUCT_CAP];
    size_t   bCap;        // 我们声明的 struct 输出容量
} Res;

static void do_call(io_connect_t c, uint32_t sel,
                    uint32_t scIn, size_t stIn,
                    uint32_t scOutCap, size_t stOutCap,
                    Res *res) {
    uint64_t in[SCALAR_CAP];
    uint8_t  sin[STRUCT_CAP];
    memset(in,  0, sizeof(in));
    memset(sin, 0, sizeof(sin));
    memset(res, 0, sizeof(*res));

    if (stIn > STRUCT_CAP)   stIn = STRUCT_CAP;
    if (stOutCap > STRUCT_CAP) stOutCap = STRUCT_CAP;

    uint32_t outCnt  = scOutCap;
    size_t   soutCnt = stOutCap;

    res->kr = IOConnectCallMethod(c, sel,
                                  in,  scIn,
                                  stIn ? sin : NULL, stIn,
                                  res->sOut, &outCnt,
                                  stOutCap ? res->bOut : NULL, &soutCnt);

    res->oc   = outCnt;
    res->sc   = soutCnt;
    res->bCap = stOutCap;
}

// 16 字节一行 hexdump；cap 之外的字节按 0 补（那些位置内核没写）
static void dump_bytes(const char *key, const char *ctx,
                       const uint8_t *p, size_t n, size_t cap) {
    for (size_t off = 0; off < n; off += 16) {
        char hex[40];
        size_t k = 0;
        for (size_t i = 0; i < 16; i++) {
            uint8_t v = (off + i < cap) ? p[off + i] : 0;
            k += (size_t)snprintf(hex + k, sizeof(hex) - k, "%02x", v);
        }
        emit("{\"k\":\"%s\",%s\"off\":%zu,\"b\":\"%s\"}\n", key, ctx, off, hex);
    }
}

static void dump_scalars(const char *key, const char *ctx, const uint64_t *s, uint32_t n) {
    if (n == 0) return;
    if (n > SCALAR_CAP) n = SCALAR_CAP;
    char hex[SCALAR_CAP * 16 + 8];
    size_t k = 0;
    for (uint32_t i = 0; i < n && k + 16 < sizeof(hex); i++) {
        k += (size_t)snprintf(hex + k, sizeof(hex) - k, "%016llx", (unsigned long long)s[i]);
    }
    emit("{\"k\":\"%s\",%s\"n\":%u,\"b\":\"%s\"}\n", key, ctx, n, hex);
}

// --------------------------------------------------------------------
// 测试 A
// --------------------------------------------------------------------
static void testA(io_connect_t c) {
    emit("{\"k\":\"@testA\",\"n\":%zu,\"note\":\"exact declared shape first; slack-probe after success\"}\n",
         g_An);

    for (size_t i = 0; i < g_An; i++) {
        uint32_t sel  = g_A[i].sel;
        uint32_t dScI = g_A[i].dSIn;
        size_t   dStI = g_A[i].dStIn;
        uint32_t dScO = g_A[i].dSOut;
        size_t   dStO = g_A[i].dStOut;

        if (sel == NSEL_FORBID) { emit("{\"k\":\"@skip\",\"sel\":%u}\n", sel); continue; }

        g_cur_sel = sel;
        emit("{\"k\":\"@preA\",\"t\":%llu,\"sel\":%u,\"try\":1,\"scIn\":%u,\"stIn\":%zu,"
             "\"scOut\":%u,\"stOut\":%zu}\n",
             (unsigned long long)(now_ms() - g_t0), sel, dScI, dStI, dScO, dStO);

        // 尝试 1：照派发表声明原样传（精确匹配）
        Res r; do_call(c, sel, dScI, dStI, dScO, dStO, &r);
        int used = 1;

        // 尝试 2：只在精确形状失败时，用「输出容量放宽」试探是不是尺寸校验
        if (r.kr != 0) {
            emit("{\"k\":\"@preA\",\"t\":%llu,\"sel\":%u,\"try\":2,\"scIn\":%u,\"stIn\":%zu,"
                 "\"scOut\":%d,\"stOut\":%d,\"prevKr\":%d}\n",
                 (unsigned long long)(now_ms() - g_t0), sel, dScI, dStI,
                 SCALAR_CAP, STRUCT_CAP, r.kr);
            Res r2; do_call(c, sel, dScI, dStI, SCALAR_CAP, STRUCT_CAP, &r2);
            r = r2; used = 2;
        }

        char ctx[80];
        snprintf(ctx, sizeof(ctx), "\"sel\":%u,\"try\":%d,", sel, used);
        emit("{\"k\":\"@s\",\"sel\":%u,\"kr\":%d,\"krh\":\"0x%x\",\"oc\":%u,\"sc\":%zu,"
             "\"try\":%d,\"scIn\":%u,\"stIn\":%zu,\"scOut\":%u,\"stOut\":%zu,\"name\":\"%s\"}\n",
             sel, r.kr, r.kr, r.oc, r.sc, used, dScI, dStI, dScO, dStO, kr_name(r.kr));

        // 至少 256B；sel 2 全 536B。声明之外的字节若不为 0 → 内核越界写
        size_t n = r.sc;
        if (n > STRUCT_CAP) n = STRUCT_CAP;
        if (n < HEX_MIN) n = HEX_MIN;
        dump_bytes("@h", ctx, r.bOut, n, (r.bCap > r.sc ? r.bCap : r.sc));
        dump_scalars("@o", ctx, r.sOut, r.oc);

        // 成功之后额外一格：scalar 个数保持精确，只把 struct 输出容量放大到 4096，
        // 判定 struct 输出到底是「>=」还是「精确相等」。只记 kr，不重复 hexdump。
        if (r.kr == 0 && dStO < STRUCT_CAP) {
            emit("{\"k\":\"@preA\",\"t\":%llu,\"sel\":%u,\"try\":3,\"scIn\":%u,\"stIn\":%zu,"
                 "\"scOut\":%u,\"stOut\":%d,\"note\":\"structOut slack probe\"}\n",
                 (unsigned long long)(now_ms() - g_t0), sel, dScI, dStI, dScO, STRUCT_CAP);
            Res r3; do_call(c, sel, dScI, dStI, dScO, STRUCT_CAP, &r3);
            emit("{\"k\":\"@s3\",\"sel\":%u,\"kr\":%d,\"krh\":\"0x%x\",\"oc\":%u,\"sc\":%zu,"
                 "\"scOut\":%u,\"stOut\":%d,\"name\":\"%s\"}\n",
                 sel, r3.kr, r3.kr, r3.oc, r3.sc, dScO, STRUCT_CAP, kr_name(r3.kr));
        }
    }
    g_pass1Done = 1;
    emit("{\"k\":\"@testAdone\",\"n\":%zu}\n", g_An);
}

// --------------------------------------------------------------------
// 测试 B：sel 8，handler 0xa02260c
// --------------------------------------------------------------------
static void testB(io_connect_t c) {
    static const size_t B_in[]  = { 0x58, 0x60, 0x100, 0x400 };
    static const size_t B_out[] = { 0x80, 0x200, 0x800, 0x1000 };
    const uint32_t SEL = 8;
    const size_t N_IN  = sizeof(B_in)  / sizeof(B_in[0]);
    const size_t N_OUT = sizeof(B_out) / sizeof(B_out[0]);

    emit("{\"k\":\"@testB\",\"sel\":%u,\"nin\":%zu,\"nout\":%zu,"
         "\"note\":\"stIn major, stOut minor, ascending from smallest legal\"}\n",
         SEL, N_IN, N_OUT);

    for (size_t a = 0; a < N_IN; a++) {
        for (size_t b = 0; b < N_OUT; b++) {
            size_t si = B_in[a], so = B_out[b];

            g_cur_sel = SEL;
            emit("{\"k\":\"@preB\",\"si\":%zu,\"so\":%zu}\n", si, so);

            // sel 8 派发声明：scalarIn=0, structIn=WILD, scalarOut=0, structOut=WILD。
            // scalarOut 必须精确传 0（传 64 会被派发校验直接 BadArgument）。
            Res r; do_call(c, SEL, 0, si, 0, so, &r);

            emit("{\"k\":\"@s8\",\"si\":%zu,\"so\":%zu,\"kr\":%d,\"krh\":\"0x%x\","
                 "\"oc\":%u,\"sc\":%zu,\"name\":\"%s\"}\n",
                 si, so, r.kr, r.kr, r.oc, r.sc, kr_name(r.kr));

            char ctx[64];
            snprintf(ctx, sizeof(ctx), "\"si\":%zu,\"so\":%zu,", si, so);
            size_t n = r.sc;
            if (n > STRUCT_CAP) n = STRUCT_CAP;
            if (n < HEX_MIN) n = HEX_MIN;
            dump_bytes("@h8", ctx, r.bOut, n, (r.bCap > r.sc ? r.bCap : r.sc));
            dump_scalars("@o8", ctx, r.sOut, r.oc);
        }
    }
    g_passBDone = 1;
    emit("{\"k\":\"@testBdone\",\"sel\":%u}\n", SEL);
}

// --------------------------------------------------------------------
static void sweep(void) {
    emit("{\"k\":\"@start\",\"fp\":\"%s\",\"build\":\"%s\",\"forbidSel\":%d}\n",
         kFingerprint, kBuildStamp, NSEL_FORBID);

    io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault,
                                                 IOServiceMatching(kServiceName));
    emit("{\"k\":\"@match\",\"svc\":\"%s\",\"port\":%u}\n", kServiceName, (unsigned)s);
    if (!s) {
        emit("{\"k\":\"@fatal\",\"why\":\"no service\"}\n");
        return;
    }

    io_connect_t c = 0;
    kern_return_t okr = IOServiceOpen(s, mach_task_self(), 1, &c);
    emit("{\"k\":\"@open\",\"type\":1,\"kr\":%d,\"krh\":\"0x%x\",\"conn\":%u}\n",
         okr, okr, (unsigned)c);
    if (okr != KERN_SUCCESS) {
        emit("{\"k\":\"@fatal\",\"why\":\"open failed\",\"kr\":%d}\n", okr);
        IOObjectRelease(s);
        return;
    }

    testA(c);
    testB(c);

    IOServiceClose(c);
    IOObjectRelease(s);
    emit("{\"k\":\"@done\",\"fp\":\"%s\"}\n", kFingerprint);
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel  *lab;
@end

@implementation AD

- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    NSString *dir = NSTemporaryDirectory();
    NSString *ndPath  = [dir stringByAppendingPathComponent:@"gpuprobe.ndjson"];
    NSString *logPath = [dir stringByAppendingPathComponent:@"gpuprobe.log"];

    gNd  = fopen(ndPath.UTF8String,  "w");
    gLog = fopen(logPath.UTF8String, "w");
    if (!gNd) fprintf(stderr, "!! 打不开 gpuprobe.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    self.lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.lab.text = @"gpudump…";
    self.lab.textColor = [UIColor greenColor];
    self.lab.numberOfLines = 0;
    [root.view addSubview:self.lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(g_wd_sec * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        fprintf(stderr, "!! watchdog %ds 到期（卡在 sel=%u 的内核调用里），强制退出\n",
                g_wd_sec, (unsigned)g_cur_sel);
        if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
        if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
        exit(3);
    });

    NSString *hbPath = [dir stringByAppendingPathComponent:@"gpuprobe.hb"];
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, (void *)strdup(hbPath.UTF8String)) == 0) {
        pthread_detach(hb);
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            sweep();
            g_hb_stop = 1;
            if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
            if (gNd)  { fflush(gNd);  fsync(fileno(gNd)); }
            dispatch_async(dispatch_get_main_queue(), ^{
                self.lab.text = g_pass1Done ? @"A done" : @"A INCOMPLETE";
            });
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ exit(0); });
        }
    });
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc >= 2) {
            long v = strtol(argv[1], NULL, 0);
            if (v > 0 && v <= 3600) g_wd_sec = (int)v;
        }
        g_t0 = now_ms();
        return UIApplicationMain(argc, argv, NULL, NSStringFromClass([AD class]));
    }
}
