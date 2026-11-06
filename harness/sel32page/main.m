// main.m — sel32page：IOSurfaceRoot sel 32 返回的那个 16 KiB 只读页，在什么条件下被内核填充。
//
// 契约（沿用 MFB-CONTRACT §1.4.2）：唯一合法入参 = (sin=0, sti=0, soc=1, sst=0)。
// 页面读取一律走 vm_read_overwrite（不直接解引用：该页可能被回收）。
//
// 指纹（装前 strings 校验，必须命中 >=1）：SEL32-20261101-pagefill-x7d2a9
//
// stage：
//   page   基线 → 步骤 1 创建 IOSurface → 步骤 2 创建+锁定 → 步骤 3 IOSurfaceRoot 其它 selector
//          → 步骤 4 IOMobileFramebuffer/AppleCLCD2 的 25 个成功 selector → 步骤 5 多连接
//          每步之后整页 dump + 与基线逐字节比对（nz / changed / first）
//   base   只做基线（3 发重复确认 VA 恒定）
//   multi  8 个 IOSurfaceRoot user client，每个连接一发 sel 32，比较 VA 与页内容
//
// 硬约束：不重启设备；不改 out/ 既有文件；不碰 harness/israce/；不跑竞态；不 git。
// 任何一步之后 nz > 0 立刻写完整 hexdump 并记 @FILL（不中断，继续跑完以便一次拿到全部证据）。

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/vm_map.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

static const char *kFingerprint = "SEL32-20261101-pagefill-x7d2a9";
static const char *kBuildStamp  = __DATE__ " " __TIME__;

#ifndef kIOMainPortDefault
#define kIOMainPortDefault MACH_PORT_NULL
#endif

#define CALL_TIMEOUT_S  3
#define SO_CAP          16
#define ST_CAP_MIG      4096
#define ST_CAP          8192

#define PAGE_SZ         0x4000
#define PAGE_CHUNK      0x1000

#define SENT64          0xA5A5A5A5A5A5A5A5ull

static FILE *gNd  = NULL;
static FILE *gLog = NULL;
static FILE *gPages = NULL;
static FILE *gIdx = NULL;

static volatile int g_hb_stop = 0;
static char     g_hb_tag[160] = "-";
static uint64_t g_t0 = 0;
static const char *g_svc = "-";
static int        g_type = -1;

// ---------------------------------------------------------------- 页状态
static uint8_t  g_base[PAGE_SZ];
static uint8_t  g_cur[PAGE_SZ];
static int      g_have_base = 0;
static uint64_t g_base_va = 0;
static uint64_t g_cur_va  = 0;
static int      g_kv_hits = 0;
static int      g_fill_steps = 0;      // nz>0 的探测次数
static int      g_bad_reads = 0;
static int      g_page_no = 0;
static kern_return_t g_last_read_kr = KERN_SUCCESS;

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
        if (f) { fprintf(f, "%llu tag=%s\n", (unsigned long long)(now_ms() - g_t0), g_hb_tag); fclose(f); }
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

static void emit(const char *fmt, ...) {
    if (!gNd) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(gNd, fmt, ap);
    va_end(ap);
    fputc('\n', gNd);
    if (g_sync_next) { fflush(gNd); fsync(fileno(gNd)); g_sync_next = 0; }
}

static void flush_now(void) {
    if (gNd)  { fflush(gNd); fsync(fileno(gNd)); }
    if (gPages) fflush(gPages);
    if (gIdx) fflush(gIdx);
}

static const char *kr_name(unsigned k) {
    switch (k) {
    case 0x00000000: return "SUCCESS";
    case 0x00000001: return "KERN_INVALID_ADDRESS";
    case 0x00000002: return "KERN_PROTECTION_FAILURE";
    case 0x00000003: return "KERN_NO_SPACE";
    case 0x00000004: return "KERN_INVALID_ARGUMENT";
    case 0x00000005: return "KERN_FAILURE";
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

static int scan_ptr64(const uint64_t v, const char **kind) {
    if (v == 0xFFFFFFFFFFFFFFFFull || v == 0x00000000FFFFFFFFull) return 0;
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFE0000000000ull) { *kind = "kernel_va"; return 1; }
    if ((v & 0xFFFFFF0000000000ull) == 0xFFFFFF0000000000ull) { *kind = "kernel_va"; return 1; }
    if ((v >> 56) >= 0xF0) { *kind = "pac_or_hi"; return 1; }
    return 0;
}
static const char *lo_kind(uint64_t v) {
    if (v == 0) return "zero";
    if (v < 0x1000) return "small_int";
    if (v < 0x100000000ull) return (v & 0xFFF) ? "mid32_unaligned" : "mid32_page";
    if ((v >> 40) == 0) return (v & 0xFFF) ? "hi40_unaligned" : "hi40_page";
    return "very_high";
}

// ---------------------------------------------------------------- Job（带超时的单发调用）
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
    memset(j->bst, 0x5A, sizeof j->bst);
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

// 0 = 有结果；1 = 超时；2 = 线程没起来
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

static void job_free(Job *j) {
    if (!j) return;
    pthread_mutex_destroy(&j->m); pthread_cond_destroy(&j->cv);
    free(j);
}

// ---------------------------------------------------------------- 页读取 / 比对 / dump
static int read_page_va(uint64_t va, uint8_t *buf) {
    memset(buf, 0, PAGE_SZ);
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)va, (vm_size_t)PAGE_SZ,
                                         (vm_address_t)(uintptr_t)buf, &got);
    g_last_read_kr = kr;
    if (kr == KERN_SUCCESS && got == PAGE_SZ) return 0;
    int bad = 0;
    for (size_t off = 0; off < PAGE_SZ; off += PAGE_CHUNK) {
        vm_size_t g2 = 0;
        kern_return_t k2 = vm_read_overwrite(mach_task_self(), (vm_address_t)(va + off),
                                             (vm_size_t)PAGE_CHUNK,
                                             (vm_address_t)(uintptr_t)(buf + off), &g2);
        if (k2 != KERN_SUCCESS || g2 != PAGE_CHUNK) { bad++; memset(buf + off, 0, PAGE_CHUNK); }
        else g_last_read_kr = KERN_SUCCESS;
    }
    if (bad) g_bad_reads++;
    return bad;
}

typedef struct {
    int have;
    uint64_t start; vm_size_t size; vm_prot_t prot, maxprot; vm_inherit_t inh;
    uint32_t share; kern_return_t rk;
} Reg;

static void region_of(uint64_t v, Reg *r) {
    memset(r, 0, sizeof *r);
    vm_address_t a = (vm_address_t)v; vm_size_t s = 0;
    vm_region_basic_info_data_64_t info;
    memset(&info, 0, sizeof info);
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    r->rk = vm_region_64(mach_task_self(), &a, &s, VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&info, &cnt, &obj);
    r->start = (uint64_t)a; r->size = s;
    r->prot = info.protection; r->maxprot = info.max_protection;
    r->inh = info.inheritance; r->share = (uint32_t)info.shared;
    r->have = (r->rk == KERN_SUCCESS && (uint64_t)a == v);
}

static void pages_append(const char *tag, uint64_t va, const uint8_t *buf) {
    if (!gPages) return;
    fwrite(buf, 1, PAGE_SZ, gPages);
    if (gIdx) fprintf(gIdx, "%d %s 0x%016llx\n", g_page_no, tag, (unsigned long long)va);
    fflush(gPages); if (gIdx) fflush(gIdx);
    fsync(fileno(gPages));
    g_page_no++;
}

// 整页 hexdump 落地（只在 nz>0 时调用）
static void write_hexdump_file(const char *tag, const uint8_t *buf, size_t n) {
    char path[512];
    snprintf(path, sizeof path, "%s/sel32hex_%s.txt",
             [NSTemporaryDirectory() UTF8String], tag);
    FILE *f = fopen(path, "w");
    if (!f) return;
    for (size_t off = 0; off < n; off += 16) {
        size_t n2 = (n - off) >= 16 ? 16 : (n - off);
        fprintf(f, "%08zx: ", off);
        for (size_t i = 0; i < 16; i++) {
            if (i < n2) fprintf(f, "%02x ", buf[off + i]);
            else fprintf(f, "   ");
            if (i == 7) fprintf(f, " ");
        }
        fprintf(f, " |");
        for (size_t i = 0; i < n2; i++) {
            unsigned char c = buf[off + i];
            fprintf(f, "%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        fprintf(f, "|\n");
    }
    fclose(f);
}

// 核心：读页 → 与基线比对 → 记录。dump_all=1 时即使全零也把整页 hexdump 写进 ndjson。
static void page_probe(const char *tag, uint64_t va) {
    if (!va) {
        emit("{\"k\":\"@diff\",\"tag\":\"%s\",\"va\":\"0x0000000000000000\",\"noread\":1,"
             "\"nz\":-1,\"changed\":-1,\"first\":-1}", tag);
        return;
    }
    int bad = read_page_va(va, g_cur);
    Reg r; region_of(va, &r);

    size_t nz = 0, changed = 0; long first = -1;
    for (size_t i = 0; i < PAGE_SZ; i++) {
        if (g_cur[i]) nz++;
        uint8_t ref = g_have_base ? g_base[i] : 0;
        if (g_cur[i] != ref) { changed++; if (first < 0) first = (long)i; }
    }
    if (nz > 0) g_fill_steps++;

    emit("{\"k\":\"@va\",\"tag\":\"%s\",\"v\":\"0x%016llx\",\"mapped\":%d,\"size\":\"0x%llx\","
         "\"prot\":%u,\"maxprot\":%u,\"share\":%u,\"inh\":%u,\"rk\":%u,\"is_base_va\":%d}",
         tag, (unsigned long long)va, r.have, (unsigned long long)r.size,
         (unsigned)r.prot, (unsigned)r.maxprot, r.share, (unsigned)r.inh,
         (unsigned)r.rk, (int)(va == g_base_va));

    emit("{\"k\":\"@diff\",\"tag\":\"%s\",\"va\":\"0x%016llx\",\"size\":\"0x%llx\",\"nz\":%zu,"
         "\"changed\":%zu,\"first\":%ld,\"read_kr\":%u,\"read_krn\":\"%s\",\"badchunks\":%d,"
         "\"partial\":%d,\"prot\":%u,\"inh\":%u}",
         tag, (unsigned long long)va, (unsigned long long)r.size, nz, changed, first,
         (unsigned)g_last_read_kr, kr_name((unsigned)g_last_read_kr), bad,
         bad ? 1 : 0, (unsigned)r.prot, (unsigned)r.inh);

    pages_append(tag, va, g_cur);

    if (nz == 0) return;

    g_sync_next = 1;
    emit("{\"k\":\"@FILL\",\"tag\":\"%s\",\"va\":\"0x%016llx\",\"nz\":%zu,\"changed\":%zu,"
         "\"first\":%ld}", tag, (unsigned long long)va, nz, changed, first);

    // 完整整页 hexdump（1024 行 × 16 B）
    write_hexdump_file(tag, g_cur, PAGE_SZ);
    for (size_t off = 0; off < PAGE_SZ; off += 16) {
        char hex[33];
        for (size_t i = 0; i < 16; i++) sprintf(hex + 2 * i, "%02x", g_cur[off + i]);
        hex[32] = 0;
        emit("{\"k\":\"@h\",\"tag\":\"%s\",\"off\":%zu,\"b\":\"%s\"}", tag, off, hex);
    }

    // 非零 qword 视图 + 指针判读（全 16 KiB，8 字节对齐）
    int nq = 0;
    for (size_t off = 0; off + 8 <= PAGE_SZ; off += 8) {
        uint64_t q; memcpy(&q, g_cur + off, 8);
        if (!q) continue;
        const char *kind = NULL;
        int isp = scan_ptr64(q, &kind);
        emit("{\"k\":\"@q8\",\"tag\":\"%s\",\"off\":%zu,\"v\":\"0x%016llx\",\"cls\":\"%s\","
             "\"ptr\":%d,\"kind\":\"%s\"}",
             tag, off, (unsigned long long)q, lo_kind(q), isp, isp ? kind : "-");
        if (isp && strcmp(kind, "kernel_va") == 0) {
            g_kv_hits++;
            emit("{\"k\":\"@ptr\",\"tag\":\"%s\",\"off\":%zu,\"v\":\"0x%016llx\",\"kind\":\"%s\","
                 "\"e\":\"le\",\"align\":8}", tag, off, (unsigned long long)q, kind);
        }
        if (++nq > 128) { emit("{\"k\":\"@qtrunc\",\"tag\":\"%s\",\"shown\":%d}", tag, nq); break; }
    }
    // dword 视图（防两个 32 位字段被 8 字节窗口拼成假指针）
    int nd = 0;
    for (size_t off = 0; off + 4 <= PAGE_SZ; off += 4) {
        uint32_t d; memcpy(&d, g_cur + off, 4);
        if (!d || d < 0x1000u) continue;
        emit("{\"k\":\"@w4\",\"tag\":\"%s\",\"off\":%zu,\"v\":\"0x%08x\",\"e\":\"le\"}", tag, off, d);
        if (++nd > 128) break;
    }
    emit("{\"k\":\"@fillsum\",\"tag\":\"%s\",\"nz\":%zu,\"q8\":%d,\"w4\":%d}", tag, nz, nq, nd);
}

// ---------------------------------------------------------------- sel 32
static uint64_t sel32_call(io_connect_t c, const char *tag, const char *why) {
    uint64_t zs[4] = { 0, 0, 0, 0 };
    snprintf(g_hb_tag, sizeof g_hb_tag, "sel32 %s", tag);
    Job *j = NULL;
    int r = call_to_in(c, 32, 1, 0, zs, 0, NULL, 0, &j);
    if (r != 0) {
        emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":32,\"tag\":\"%s\",\"why\":\"%s\","
             "\"r\":%d,\"to\":%d}", tag, why, r, r == 1 ? 1 : 0);
        job_free(j);
        return 0;
    }
    uint64_t v = (j->oc >= 1 && j->sout[0] != SENT64) ? j->sout[0] : 0;
    emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":32,\"tag\":\"%s\",\"why\":\"%s\","
         "\"kr\":%u,\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"v\":\"0x%016llx\",\"cls\":\"%s\",\"us\":%llu}",
         tag, why, (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc,
         (unsigned long long)v, lo_kind(v), (unsigned long long)j->us);
    job_free(j);

    if (v && v != g_cur_va) {
        emit("{\"k\":\"@va_chg\",\"tag\":\"%s\",\"old\":\"0x%016llx\",\"new\":\"0x%016llx\"}",
             tag, (unsigned long long)g_cur_va, (unsigned long long)v);
    }
    if (v) g_cur_va = v;
    return v;
}

// ---------------------------------------------------------------- IOSurface 私有 API
typedef struct __IOSurface *IOSurfaceRef_;
static IOSurfaceRef_ (*pCreate)(CFDictionaryRef);
static IOSurfaceRef_ (*pLookup)(uint32_t);
static uint32_t       (*pGetID)(IOSurfaceRef_);
static kern_return_t  (*pLock)(IOSurfaceRef_, uint32_t, uint32_t *);
static kern_return_t  (*pUnlock)(IOSurfaceRef_, uint32_t, uint32_t *);
static size_t         (*pGetAllocSize)(IOSurfaceRef_);
static void *         (*pGetBaseAddress)(IOSurfaceRef_);
static size_t         (*pGetWidth)(IOSurfaceRef_);
static size_t         (*pGetHeight)(IOSurfaceRef_);

static void loadIOSurface(void) {
    const char *paths[] = {
        "/System/Library/PrivateFrameworks/IOSurface.framework/IOSurface",
        "/System/Library/Frameworks/IOSurface.framework/IOSurface",
        NULL
    };
    void *h = NULL;
    const char *used = "-";
    for (int i = 0; paths[i] && !h; i++) { h = dlopen(paths[i], RTLD_LAZY); if (h) used = paths[i]; }
    if (!h) {
        emit("{\"k\":\"@iosf\",\"ok\":0,\"err\":\"%s\"}", dlerror() ? dlerror() : "dlopen");
        return;
    }
    pCreate        = (void *)dlsym(h, "IOSurfaceCreate");
    pLookup        = (void *)dlsym(h, "IOSurfaceLookup");
    pGetID         = (void *)dlsym(h, "IOSurfaceGetID");
    pLock          = (void *)dlsym(h, "IOSurfaceLock");
    pUnlock        = (void *)dlsym(h, "IOSurfaceUnlock");
    pGetAllocSize  = (void *)dlsym(h, "IOSurfaceGetAllocSize");
    pGetBaseAddress= (void *)dlsym(h, "IOSurfaceGetBaseAddress");
    pGetWidth      = (void *)dlsym(h, "IOSurfaceGetWidth");
    pGetHeight     = (void *)dlsym(h, "IOSurfaceGetHeight");
    emit("{\"k\":\"@iosf\",\"ok\":1,\"path\":\"%s\",\"create\":%d,\"lock\":%d,\"unlock\":%d,"
         "\"getid\":%d,\"getalloc\":%d,\"getbase\":%d}",
         used, !!pCreate, !!pLock, !!pUnlock, !!pGetID, !!pGetAllocSize, !!pGetBaseAddress);
}

// 活着的 surface（步骤之间不释放，给后续步骤留出「页被填充」的机会）
static IOSurfaceRef_ g_surf[32];
static int g_nsurf = 0;
static void keep_surf(IOSurfaceRef_ s) { if (s && g_nsurf < 32) g_surf[g_nsurf++] = s; }

static IOSurfaceRef_ mk_surf(int w, int h, int bpe, uint32_t pf, int hasAlloc, uint64_t alloc) {
    if (!pCreate) return NULL;
    const void *keys[5]; const void *vals[5]; int n = 0;
    CFNumberRef W = NULL, H = NULL, B = NULL, P = NULL, A = NULL;
    if (w > 0 && h > 0) {
        W = CFNumberCreate(NULL, kCFNumberIntType, &w);
        H = CFNumberCreate(NULL, kCFNumberIntType, &h);
        keys[n] = CFSTR("IOSurfaceWidth");  vals[n++] = W;
        keys[n] = CFSTR("IOSurfaceHeight"); vals[n++] = H;
        if (bpe > 0) {
            B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
            keys[n] = CFSTR("IOSurfaceBytesPerElement"); vals[n++] = B;
        }
        if (pf) {
            P = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);
            keys[n] = CFSTR("IOSurfacePixelFormat"); vals[n++] = P;
        }
    }
    if (hasAlloc) {
        A = CFNumberCreate(NULL, kCFNumberSInt64Type, &alloc);
        keys[n] = CFSTR("IOSurfaceAllocSize"); vals[n++] = A;
    }
    CFDictionaryRef d = CFDictionaryCreate(NULL, keys, vals, (CFIndex)n,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef_ s = pCreate(d);
    CFRelease(d);
    if (W) CFRelease(W); if (H) CFRelease(H); if (B) CFRelease(B);
    if (P) CFRelease(P); if (A) CFRelease(A);
    return s;
}

// ---------------------------------------------------------------- 预热
static void warmup(io_connect_t conn) {
    static const uint32_t sels[] = { 0, 1, 2, 3 };
    for (size_t i = 0; i < sizeof(sels) / sizeof(sels[0]); i++) {
        snprintf(g_hb_tag, sizeof g_hb_tag, "warm sel=%u", sels[i]);
        Job *j = NULL;
        int r = call_to_in(conn, sels[i], 1, 0, NULL, 0, NULL, 0, &j);
        if (r != 0) {
            emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"r\":%d}", g_svc, g_type, sels[i], r);
            continue;
        }
        emit("{\"k\":\"@warm\",\"svc\":\"%s\",\"type\":%d,\"sel\":%u,\"kr\":%u,\"krn\":\"%s\","
             "\"oc\":%u,\"sc\":%zu}", g_svc, g_type, sels[i], (unsigned)j->kr,
             kr_name((unsigned)j->kr), j->oc, j->sc);
        job_free(j);
    }
}

static io_service_t find_service_named(const char *name) {
    io_iterator_t iter = 0;
    CFMutableDictionaryRef m = IOServiceMatching(name);
    if (!m) return 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS) return 0;
    io_service_t svc = IOIteratorNext(iter);
    IOObjectRelease(iter);
    return svc;
}

// ---------------------------------------------------------------- 步骤 1：创建 IOSurface
typedef struct { const char *nm; int w, h, bpe; uint32_t pf; int hasAlloc; uint64_t alloc; } Cfg;

static const Cfg kCfgs[] = {
    { "16x16_bgra",     16,   16,   4, 0x42475241u, 0, 0 },
    { "64x64_bgra",     64,   64,   4, 0x42475241u, 0, 0 },
    { "1024x1024_bgra", 1024, 1024, 4, 0x42475241u, 0, 0 },
    { "1920x1080_bgra", 1920, 1080, 4, 0x42475241u, 0, 0 },
    { "16x16_420f",     16,   16,   2, 0x34323066u, 0, 0 },
    { "64x64_420f",     64,   64,   2, 0x34323066u, 0, 0 },
    { "1024x1024_420f", 1024, 1024, 2, 0x34323066u, 0, 0 },
    { "1024_bgra_a4k",  1024, 1024, 4, 0x42475241u, 1, 0x1000 },
    { "1024_bgra_a16k", 1024, 1024, 4, 0x42475241u, 1, 0x4000 },
    { "1024_bgra_a1m",  1024, 1024, 4, 0x42475241u, 1, 0x100000 },
    { "alloconly_16k",  0,    0,    0, 0,            1, 0x4000 },
    { "alloconly_1m",   0,    0,    0, 0,            1, 0x100000 },
};
#define NCFG ((int)(sizeof(kCfgs)/sizeof(kCfgs[0])))

static void step1_create(io_connect_t c1) {
    emit("{\"k\":\"@step\",\"id\":\"S1\",\"note\":\"IOSurfaceCreate x%d\",\"t\":%llu}",
         NCFG, (unsigned long long)(now_ms() - g_t0));
    for (int i = 0; i < NCFG; i++) {
        const Cfg *g = &kCfgs[i];
        char tag[96];
        snprintf(tag, sizeof tag, "s1_%s", g->nm);
        g_sync_next = 1;
        snprintf(g_hb_tag, sizeof g_hb_tag, "create %s", g->nm);
        IOSurfaceRef_ s = mk_surf(g->w, g->h, g->bpe, g->pf, g->hasAlloc, g->alloc);
        uint32_t id = 0; size_t asz = 0; void *ba = NULL;
        if (s) {
            if (pGetID) id = pGetID(s);
            if (pGetAllocSize) asz = pGetAllocSize(s);
            if (pGetBaseAddress) ba = pGetBaseAddress(s);
            keep_surf(s);
        }
        emit("{\"k\":\"@cre\",\"tag\":\"%s\",\"ok\":%d,\"w\":%d,\"h\":%d,\"bpe\":%d,"
             "\"pf\":\"0x%08x\",\"hasAlloc\":%d,\"alloc\":\"0x%llx\",\"id\":%u,"
             "\"allocsz\":\"0x%llx\",\"base\":\"0x%016llx\"}",
             tag, s ? 1 : 0, g->w, g->h, g->bpe, g->pf, g->hasAlloc,
             (unsigned long long)g->alloc, id, (unsigned long long)asz,
             (unsigned long long)(uintptr_t)ba);
        sel32_call(c1, tag, "after_create");
        page_probe(tag, g_cur_va);
    }
}

// ---------------------------------------------------------------- 步骤 2：创建 + 锁定
static void step2_lock(io_connect_t c1) {
    static const int pick[] = { 1, 2, 7, 8, 6 };   // 64x64_bgra / 1024x1024_bgra / 1024_bgra_a4k / a16k / 1024_420f
    emit("{\"k\":\"@step\",\"id\":\"S2\",\"note\":\"IOSurfaceCreate+IOSurfaceLock\",\"t\":%llu}",
         (unsigned long long)(now_ms() - g_t0));
    for (size_t k = 0; k < sizeof(pick) / sizeof(pick[0]); k++) {
        const Cfg *g = &kCfgs[pick[k]];
        char tag[96];
        snprintf(tag, sizeof tag, "s2_%s", g->nm);
        g_sync_next = 1;
        snprintf(g_hb_tag, sizeof g_hb_tag, "create+lock %s", g->nm);
        IOSurfaceRef_ s = mk_surf(g->w, g->h, g->bpe, g->pf, g->hasAlloc, g->alloc);
        kern_return_t lk = (kern_return_t)-1;
        uint32_t seed = 0x5EED5EED;
        if (s && pLock) lk = pLock(s, 0, &seed);
        uint32_t id = (s && pGetID) ? pGetID(s) : 0;
        emit("{\"k\":\"@lock\",\"tag\":\"%s\",\"ok\":%d,\"id\":%u,\"lock_kr\":%u,\"lock_krn\":\"%s\","
             "\"seed\":\"0x%08x\"}", tag, s ? 1 : 0, id, (unsigned)lk, kr_name((unsigned)lk), seed);
        keep_surf(s);
        sel32_call(c1, tag, "after_lock");
        page_probe(tag, g_cur_va);
        if (s && pUnlock && lk == KERN_SUCCESS) { uint32_t sd2 = 0; pUnlock(s, 0, &sd2); }
    }
}

// ---------------------------------------------------------------- 步骤 2b：全局 surface（kIOSurfaceIsGlobal）
// 「page 只在某个 surface 被全局注册进本 task 时才被填充」是步骤 1/2 之外最像的机制，
// 所以补一条：IsGlobal 创建 → 按 id 反查 → 锁定 → 读基址首 16 B 自证 → 全部释放 → 逐次回读该页。
static void step2b_global(io_connect_t c1) {
    emit("{\"k\":\"@step\",\"id\":\"S2b\",\"note\":\"kIOSurfaceIsGlobal round-trip\",\"t\":%llu}",
         (unsigned long long)(now_ms() - g_t0));
    if (!pCreate || !pLookup) { emit("{\"k\":\"@s6skip\",\"why\":\"no_sym\"}"); return; }

    const void *keys[4]; const void *vals[4]; int n = 0;
    int w = 64, h = 64, bpe = 4; int32_t pf = 0x42475241, glob = 1;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);
    CFNumberRef G = CFNumberCreate(NULL, kCFNumberSInt32Type, &glob);
    keys[n] = CFSTR("IOSurfaceWidth");  vals[n++] = W;
    keys[n] = CFSTR("IOSurfaceHeight"); vals[n++] = H;
    keys[n] = CFSTR("IOSurfaceBytesPerElement"); vals[n++] = B;
    keys[n] = CFSTR("IOSurfacePixelFormat"); vals[n++] = P;
    (void)G;
    CFDictionaryRef d = CFDictionaryCreate(NULL, keys, vals, (CFIndex)n,
                                          &kCFTypeDictionaryKeyCallBacks,
                                          &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef_ s = pCreate(d);
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);

    uint32_t id = (s && pGetID) ? pGetID(s) : 0;
    size_t asz = (s && pGetAllocSize) ? pGetAllocSize(s) : 0;
    void *ba = (s && pGetBaseAddress) ? pGetBaseAddress(s) : NULL;
    uint8_t head[16]; memset(head, 0, sizeof head);
    if (ba) memcpy(head, ba, sizeof head);     // 自证：这是真缓冲，不是那个零页
    char hex[33]; for (int i = 0; i < 16; i++) sprintf(hex + 2 * i, "%02x", head[i]); hex[32] = 0;
    emit("{\"k\":\"@glob\",\"tag\":\"s2b_create\",\"ok\":%d,\"id\":%u,\"allocsz\":\"0x%llx\","
         "\"base\":\"0x%016llx\",\"head\":\"%s\"}",
         s ? 1 : 0, id, (unsigned long long)asz, (unsigned long long)(uintptr_t)ba, hex);
    sel32_call(c1, "s2b_create", "after_global_create");
    page_probe("s2b_create", g_cur_va);

    IOSurfaceRef_ lk = (s && id && pLookup) ? pLookup(id) : NULL;
    emit("{\"k\":\"@glob\",\"tag\":\"s2b_lookup\",\"ok\":%d,\"id\":%u}", lk ? 1 : 0, id);
    sel32_call(c1, "s2b_lookup", "after_lookup");
    page_probe("s2b_lookup", g_cur_va);

    kern_return_t kr2 = (kern_return_t)-1; uint32_t seed = 0;
    if (lk && pLock) kr2 = pLock(lk, 0, &seed);
    emit("{\"k\":\"@glob\",\"tag\":\"s2b_lock\",\"lock_kr\":%u,\"seed\":\"0x%08x\"}",
         (unsigned)kr2, seed);
    sel32_call(c1, "s2b_lock", "after_global_lock");
    page_probe("s2b_lock", g_cur_va);

    if (lk && pUnlock) { uint32_t sd = 0; pUnlock(lk, 0, &sd); }
    if (lk) CFRelease(lk);
    if (s) CFRelease(s);
    emit("{\"k\":\"@glob\",\"tag\":\"s2b_released\"}");
    sel32_call(c1, "s2b_released", "after_release");
    page_probe("s2b_released", g_cur_va);
}

// ---------------------------------------------------------------- 步骤 3：IOSurfaceRoot 其它 selector
static void step3_sels(io_connect_t c1) {
    static const uint32_t sels[] = { 19, 36, 37, 38, 45 };
    static const size_t   stis[] = { 0, 64 };
    static const uint32_t socs[] = { 0, 1, 2, 4, 16 };
    static const size_t   ssts[] = { 0, 64, 4096 };
    uint64_t zs[4] = { 0, 0, 0, 0 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP_MIG, 1);
    int ncalls = 0;

    emit("{\"k\":\"@step\",\"id\":\"S3\",\"note\":\"IOSurfaceRoot sels 19/36/37/38/45 ladder\",\"t\":%llu}",
         (unsigned long long)(now_ms() - g_t0));

    for (size_t si = 0; si < sizeof(sels) / sizeof(sels[0]); si++) {
        uint32_t sel = sels[si];
        int okc = 0;
        for (uint32_t sinCnt = 0; sinCnt <= 1; sinCnt++) {
            for (size_t si2 = 0; si2 < sizeof(stis) / sizeof(stis[0]); si2++) {
                size_t sti = stis[si2];
                for (size_t c = 0; c < sizeof(socs) / sizeof(socs[0]); c++) {
                    for (size_t d = 0; d < sizeof(ssts) / sizeof(ssts[0]); d++) {
                        char tag[96];
                        snprintf(tag, sizeof tag, "s3_%u_%u_%zu_%u_%zu", sel, sinCnt, sti, socs[c], ssts[d]);
                        snprintf(g_hb_tag, sizeof g_hb_tag, "s3 sel=%u sin=%u", sel, sinCnt);
                        Job *j = NULL;
                        int r = call_to_in(c1, sel, socs[c], ssts[d], zs, sinCnt, zin, sti, &j);
                        ncalls++;
                        if (r != 0) {
                            emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":%u,\"tag\":\"%s\","
                                 "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu,\"r\":%d,\"to\":%d}",
                                 sel, tag, sinCnt, sti, socs[c], ssts[d], r, r == 1 ? 1 : 0);
                            job_free(j);
                            continue;
                        }
                        if (j->kr == 0) okc++;
                        emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":%u,\"tag\":\"%s\","
                             "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"sst\":%zu,\"kr\":%u,\"krn\":\"%s\","
                             "\"oc\":%u,\"sc\":%zu,\"v0\":\"0x%016llx\",\"us\":%llu}",
                             sel, tag, sinCnt, sti, socs[c], ssts[d], (unsigned)j->kr,
                             kr_name((unsigned)j->kr), j->oc, j->sc,
                             (unsigned long long)j->sout[0], (unsigned long long)j->us);
                        job_free(j);
                        // 每次调用后回读该页
                        sel32_call(c1, tag, "after_sel3_call");
                        page_probe(tag, g_cur_va);
                    }
                }
            }
        }
        emit("{\"k\":\"@s3sum\",\"sel\":%u,\"calls\":%d,\"kr0\":%d}", sel, ncalls, okc);
    }
    free(zin);
}

// ---------------------------------------------------------------- 步骤 4：MFB / CLCD2
typedef struct { uint32_t sel, sinCnt; size_t sti; uint32_t soc; } DHit;
// soc 严格照 MFB-CONTRACT §2.2：oc==0（纯动作型）→ soc=0；oc==1 → soc=1；sel 8 两个标量 → soc=2。
// 传错 soc 会让 handler 直接 BadArgument（第一版把纯动作型的 soc 也写成 1，12 个 selector 全被打回，
// 于是「调到了」其实是假的；这一版按表逐条给 soc）。
static const DHit kHits[] = {
    {  4, 0,   0, 1 }, {  7, 0,   0, 1 }, {  8, 0,   0, 2 }, { 12, 1,   0, 0 },
    { 13, 1,   0, 0 }, { 14, 2,   0, 1 }, { 18, 0,   0, 1 }, { 19, 1,   0, 0 },
    { 22, 1,   0, 0 }, { 25, 0,   0, 1 }, { 26, 0,   0, 0 }, { 31, 1,   0, 0 },
    { 33, 1,   0, 0 }, { 49, 1,   0, 1 }, { 51, 1,   0, 0 }, { 53, 2,   0, 0 },
    { 56, 0, 156, 0 }, { 77, 0,   0, 1 }, { 80, 0,   0, 1 }, { 81, 2,   0, 0 },
    { 82, 0,   0, 1 }, { 88, 1,   0, 0 }, { 91, 0,   0, 1 }, { 92, 0,   0, 1 },
    { 98, 0,   0, 1 },
};
#define NHIT ((int)(sizeof(kHits)/sizeof(kHits[0])))

static void step4_display(io_connect_t c1) {
    const char *svcs[2] = { "IOMobileFramebuffer", "AppleCLCD2" };
    uint64_t zs[4] = { 0, 0, 0, 0 };
    uint8_t *zin = (uint8_t *)calloc(ST_CAP_MIG, 1);

    emit("{\"k\":\"@step\",\"id\":\"S4\",\"note\":\"MFB/CLCD2 25 successful selectors\",\"t\":%llu}",
         (unsigned long long)(now_ms() - g_t0));

    for (int s = 0; s < 2; s++) {
        const char *nm = svcs[s];
        io_service_t port = find_service_named(nm);
        io_connect_t c = 0;
        kern_return_t okr = (kern_return_t)-1;
        if (port) okr = IOServiceOpen(port, mach_task_self(), 0, &c);
        emit("{\"k\":\"@open\",\"svc\":\"%s\",\"type\":0,\"found\":%d,\"kr\":%u,\"krn\":\"%s\",\"conn\":%u}",
             nm, port ? 1 : 0, (unsigned)okr, kr_name((unsigned)okr), (unsigned)c);
        if (port) IOObjectRelease(port);
        if (okr != KERN_SUCCESS || !c) continue;

        g_svc = nm; g_type = 0;
        warmup(c);

        int okc = 0;
        for (int i = 0; i < NHIT; i++) {
            uint32_t sel = kHits[i].sel;
            char tag[96];
            snprintf(tag, sizeof tag, "s4_%s_%u", s == 0 ? "mfb" : "clcd", sel);
            snprintf(g_hb_tag, sizeof g_hb_tag, "s4 %s sel=%u", nm, sel);
            Job *j = NULL;
            int r = call_to_in(c, sel, kHits[i].soc, 0, zs, kHits[i].sinCnt, zin, kHits[i].sti, &j);
            if (r == 0 && j->kr != 0) {
                // 一次回退：更大容量重试
                emit("{\"k\":\"@call\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"try\":1,"
                     "\"sin\":%u,\"sti\":%zu,\"soc\":%u,\"kr\":%u,\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu}",
                     nm, sel, tag, kHits[i].sinCnt, kHits[i].sti, kHits[i].soc,
                     (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc);
                job_free(j); j = NULL;
                uint32_t rsoc = kHits[i].soc ? 16 : 0;
                size_t   rsst = kHits[i].soc ? 4096 : 0;
                r = call_to_in(c, sel, rsoc, rsst, zs, kHits[i].sinCnt, zin, kHits[i].sti, &j);
            }
            if (r != 0) {
                emit("{\"k\":\"@call\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"r\":%d,\"to\":%d}",
                     nm, sel, tag, r, r == 1 ? 1 : 0);
                job_free(j);
            } else {
                if (j->kr == 0) okc++;
                emit("{\"k\":\"@call\",\"svc\":\"%s\",\"sel\":%u,\"tag\":\"%s\",\"sin\":%u,\"sti\":%zu,"
                     "\"soc\":%u,\"kr\":%u,\"krn\":\"%s\",\"oc\":%u,\"sc\":%zu,\"v0\":\"0x%016llx\","
                     "\"us\":%llu}", nm, sel, tag, kHits[i].sinCnt, kHits[i].sti, j->soc,
                     (unsigned)j->kr, kr_name((unsigned)j->kr), j->oc, j->sc,
                     (unsigned long long)j->sout[0], (unsigned long long)j->us);
                job_free(j);
            }
            sel32_call(c1, tag, "after_display_call");
            page_probe(tag, g_cur_va);
        }
        emit("{\"k\":\"@s4sum\",\"svc\":\"%s\",\"calls\":%d,\"kr0\":%d}", nm, NHIT, okc);
        IOServiceClose(c);
    }
    g_svc = "IOSurfaceRoot"; g_type = 0;
    free(zin);
}

// ---------------------------------------------------------------- 步骤 5：多连接
static void step5_multi(io_connect_t c1, int nconn, const char *pfx) {
    io_service_t svc = find_service_named("IOSurfaceRoot");
    if (!svc) {
        emit("{\"k\":\"@s5sum\",\"found\":0}");
        return;
    }
    emit("{\"k\":\"@step\",\"id\":\"S5\",\"note\":\"%d IOSurfaceRoot user clients\",\"n\":%d,"
         "\"t\":%llu}", nconn, nconn, (unsigned long long)(now_ms() - g_t0));

    io_connect_t cs[16];
    int n = nconn > 16 ? 16 : nconn;
    for (int i = 0; i < n; i++) {
        io_connect_t c = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &c);
        cs[i] = (kr == KERN_SUCCESS) ? c : 0;
        emit("{\"k\":\"@open\",\"svc\":\"IOSurfaceRoot\",\"conn_i\":%d,\"kr\":%u,\"krn\":\"%s\","
             "\"conn\":%u}", i, (unsigned)kr, kr_name((unsigned)kr), (unsigned)c);
    }
    IOObjectRelease(svc);

    uint64_t vas[16];
    for (int i = 0; i < n; i++) {
        char tag[96];
        snprintf(tag, sizeof tag, "%s_c%d", pfx, i);
        if (!cs[i]) { vas[i] = 0; continue; }
        // 每个连接单独一发 sel 32
        uint64_t zs[4] = { 0, 0, 0, 0 };
        Job *j = NULL;
        snprintf(g_hb_tag, sizeof g_hb_tag, "s5 c%d", i);
        int r = call_to_in(cs[i], 32, 1, 0, zs, 0, NULL, 0, &j);
        if (r != 0) { emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":32,\"tag\":\"%s\",\"r\":%d}", tag, r);
                      job_free(j); vas[i] = 0; continue; }
        uint64_t v = (j->oc >= 1 && j->sout[0] != SENT64) ? j->sout[0] : 0;
        emit("{\"k\":\"@call\",\"svc\":\"IOSurfaceRoot\",\"sel\":32,\"tag\":\"%s\",\"conn_i\":%d,"
             "\"kr\":%u,\"oc\":%u,\"v\":\"0x%016llx\",\"cls\":\"%s\"}",
             tag, i, (unsigned)j->kr, j->oc, (unsigned long long)v, lo_kind(v));
        job_free(j);
        vas[i] = v;
        page_probe(tag, v);
    }
    // VA 对比汇总
    int ndistinct = 0; uint64_t uniq[16];
    for (int i = 0; i < n; i++) {
        int seen = 0;
        for (int k = 0; k < ndistinct; k++) if (uniq[k] == vas[i]) seen = 1;
        if (!seen) uniq[ndistinct++] = vas[i];
    }
    char list[512]; list[0] = 0;
    for (int i = 0; i < n; i++) {
        char one[32]; snprintf(one, sizeof one, "%s0x%llx", i ? "," : "", (unsigned long long)vas[i]);
        strncat(list, one, sizeof(list) - strlen(list) - 1);
    }
    emit("{\"k\":\"@s5sum\",\"n\":%d,\"distinct\":%d,\"same_as_conn1\":%d,\"vas\":\"%s\"}",
         n, ndistinct, (int)(ndistinct == 1), list);

    // 顺带确认主连接（c1）的 VA 是否等于这些
    if (c1) {
        uint64_t v1 = sel32_call(c1, "s5_main", "after_multi");
        emit("{\"k\":\"@s5main\",\"v\":\"0x%016llx\",\"equals_c0\":%d}",
             (unsigned long long)v1, (int)(n ? v1 == vas[0] : 0));
        (void)v1;
    }
    for (int i = 0; i < n; i++) if (cs[i]) IOServiceClose(cs[i]);
}

// ---------------------------------------------------------------- 基线
static void stage_base(io_connect_t c1) {
    emit("{\"k\":\"@step\",\"id\":\"S0\",\"note\":\"baseline: sel32 x3 + full page dump\",\"t\":%llu}",
         (unsigned long long)(now_ms() - g_t0));
    uint64_t v1 = sel32_call(c1, "base_r1", "baseline");
    uint64_t v2 = sel32_call(c1, "base_r2", "baseline");
    uint64_t v3 = sel32_call(c1, "base_r3", "baseline");
    emit("{\"k\":\"@base_rep\",\"v1\":\"0x%016llx\",\"v2\":\"0x%016llx\",\"v3\":\"0x%016llx\","
         "\"stable\":%d}", (unsigned long long)v1, (unsigned long long)v2,
         (unsigned long long)v3, (int)(v1 == v2 && v2 == v3));
    if (!v1) return;

    g_cur_va = v1;
    g_base_va = v1;
    // 基线整页读到 g_base
    int bad = read_page_va(v1, g_base);
    Reg r; region_of(v1, &r);
    size_t nzb = 0;
    for (size_t i = 0; i < PAGE_SZ; i++) if (g_base[i]) nzb++;
    emit("{\"k\":\"@va\",\"tag\":\"base\",\"v\":\"0x%016llx\",\"mapped\":%d,\"size\":\"0x%llx\","
         "\"prot\":%u,\"maxprot\":%u,\"share\":%u,\"inh\":%u,\"rk\":%u,\"is_base_va\":1}",
         (unsigned long long)v1, r.have, (unsigned long long)r.size, (unsigned)r.prot,
         (unsigned)r.maxprot, r.share, (unsigned)r.inh, (unsigned)r.rk);
    emit("{\"k\":\"@basepage\",\"va\":\"0x%016llx\",\"size\":\"0x%llx\",\"nz\":%zu,"
         "\"read_kr\":%u,\"read_krn\":\"%s\",\"badchunks\":%d}",
         (unsigned long long)v1, (unsigned long long)r.size, nzb,
         (unsigned)g_last_read_kr, kr_name((unsigned)g_last_read_kr), bad);
    pages_append("base", v1, g_base);
    g_have_base = 1;
    // 基线也走一遍 page_probe（把 @diff 表的第一行补齐）
    page_probe("base_probe", v1);
}

// ---------------------------------------------------------------- main flow
static void stage_page(void) {
    io_service_t svc = find_service_named("IOSurfaceRoot");
    io_connect_t c1 = 0;
    kern_return_t okr = (kern_return_t)-1;
    if (svc) okr = IOServiceOpen(svc, mach_task_self(), 0, &c1);
    emit("{\"k\":\"@open\",\"svc\":\"IOSurfaceRoot\",\"type\":0,\"found\":%d,\"kr\":%u,\"krn\":\"%s\","
         "\"conn\":%u}", svc ? 1 : 0, (unsigned)okr, kr_name((unsigned)okr), (unsigned)c1);
    if (svc) IOObjectRelease(svc);
    if (okr != KERN_SUCCESS || !c1) {
        emit("{\"k\":\"@fatal\",\"why\":\"open_failed\",\"kr\":%u}", (unsigned)okr);
        return;
    }
    g_svc = "IOSurfaceRoot"; g_type = 0;

    stage_base(c1);
    loadIOSurface();
    step1_create(c1);
    step2_lock(c1);
    step2b_global(c1);
    step3_sels(c1);
    step4_display(c1);
    step5_multi(c1, 8, "s5");
    IOServiceClose(c1);
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

// ---------------------------------------------------------------- App
@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AD
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)o {
    NSString *dir = NSTemporaryDirectory();
    gLog   = fopen([[dir stringByAppendingPathComponent:@"sel32con.log"] UTF8String], "w");
    gNd    = fopen([[dir stringByAppendingPathComponent:@"sel32con.ndjson"] UTF8String], "w");
    gPages = fopen([[dir stringByAppendingPathComponent:@"sel32pages.bin"] UTF8String], "wb");
    gIdx   = fopen([[dir stringByAppendingPathComponent:@"sel32pages.idx"] UTF8String], "w");
    if (!gNd) fprintf(stderr, "!! 打不开 sel32con.ndjson\n");

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root = [UIViewController new];
    root.view.backgroundColor = [UIColor blackColor];
    UILabel *lab = [[UILabel alloc] initWithFrame:UIScreen.mainScreen.bounds];
    lab.text = @"sel32page: IOSurfaceRoot/32 16KiB page fill conditions…";
    lab.textColor = [UIColor greenColor];
    lab.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    lab.numberOfLines = 0;
    [root.view addSubview:lab];
    self.window.rootViewController = root;
    [self.window makeKeyAndVisible];
    [UIApplication sharedApplication].idleTimerDisabled = YES;

    build_argv();
    NSString *stage = (g_argc > 1) ? [NSString stringWithUTF8String:g_argv[1]] : @"page";

    static char hbPath[1024];
    snprintf(hbPath, sizeof hbPath, "%s", [[dir stringByAppendingPathComponent:@"sel32con.hb"] UTF8String]);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, hbPath) == 0) pthread_detach(hb);

    int wd = (int)kvl("wd", 900);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(wd * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        emit("{\"k\":\"@watchdog\",\"sec\":%d}", wd);
        g_hb_stop = 1;
        flush_now();
        exit(3);
    });

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            g_t0 = now_ms();
            emit("{\"k\":\"@meta\",\"fp\":\"%s\",\"build\":\"%s\",\"ios\":\"%s\",\"model\":\"%s\","
                 "\"stage\":\"%s\",\"wd\":%d,\"timeout_s\":%d,\"pagesz\":\"0x%x\"}",
                 kFingerprint, kBuildStamp,
                 [[[UIDevice currentDevice] systemVersion] UTF8String],
                 [[[UIDevice currentDevice] model] UTF8String],
                 stage.UTF8String, wd, CALL_TIMEOUT_S, PAGE_SZ);
            g_sync_next = 1;

            if ([stage isEqualToString:@"page"]) {
                stage_page();
            } else if ([stage isEqualToString:@"base"]) {
                io_service_t svc = find_service_named("IOSurfaceRoot");
                io_connect_t c1 = 0;
                kern_return_t okr = (kern_return_t)-1;
                if (svc) okr = IOServiceOpen(svc, mach_task_self(), 0, &c1);
                emit("{\"k\":\"@open\",\"svc\":\"IOSurfaceRoot\",\"found\":%d,\"kr\":%u}",
                     svc ? 1 : 0, (unsigned)okr);
                if (svc) IOObjectRelease(svc);
                g_svc = "IOSurfaceRoot"; g_type = 0;
                if (okr == KERN_SUCCESS && c1) { stage_base(c1); IOServiceClose(c1); }
            } else if ([stage isEqualToString:@"multi"]) {
                io_service_t svc = find_service_named("IOSurfaceRoot");
                io_connect_t c1 = 0;
                kern_return_t okr = (kern_return_t)-1;
                if (svc) okr = IOServiceOpen(svc, mach_task_self(), 0, &c1);
                if (svc) IOObjectRelease(svc);
                g_svc = "IOSurfaceRoot"; g_type = 0;
                if (okr == KERN_SUCCESS && c1) {
                    stage_base(c1);
                    step5_multi(c1, (int)kvl("n", 8), "multi");
                    IOServiceClose(c1);
                } else {
                    emit("{\"k\":\"@fatal\",\"why\":\"open_failed\",\"kr\":%u}", (unsigned)okr);
                }
            } else {
                emit("{\"k\":\"@fatal\",\"why\":\"unknown_stage\",\"stage\":\"%s\"}", stage.UTF8String);
            }

            emit("{\"k\":\"@done\",\"stage\":\"%s\",\"kv_hits\":%d,\"fill_steps\":%d,\"bad_reads\":%d,"
                 "\"pages\":%d,\"t\":%llu}",
                 stage.UTF8String, g_kv_hits, g_fill_steps, g_bad_reads, g_page_no,
                 (unsigned long long)(now_ms() - g_t0));
            g_hb_stop = 1;
            flush_now();
            if (gLog) { fflush(gLog); fsync(fileno(gLog)); }
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
