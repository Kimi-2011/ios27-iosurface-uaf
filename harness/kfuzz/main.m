// kfuzz —— 契约精确 + 内容随机的内核 user client fuzzer（生成物，勿手改）
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { const char *svc; uint32_t type; uint32_t sel;
                 uint32_t sIn, stIn, sOut, stOut; } tgt_t;
static const tgt_t T[] = {
    {"AGXAcceleratorG18P",1,26,1,12,1,0},
    {"AGXAcceleratorG18P",1,27,1,4,0,0},
    {"AGXAcceleratorG18P",1,38,0,24,0,0},
    {"AGXAcceleratorG18P",1,39,0,24,1,0},
    {"AGXAcceleratorG18P",1,82,1,12,1,0},
    {"AGXAcceleratorG18P",1,83,1,4,0,0},
    {"AGXAcceleratorG18P",1,94,0,24,0,0},
    {"AGXAcceleratorG18P",1,95,0,24,1,0},
    {"AppleJPEGDriver",0,1,0,88,0,88},
    {"AppleJPEGDriver",0,3,0,88,0,88},
    {"AppleJPEGDriver",0,8,0,4,0,0},
    {"IOMobileFramebuffer",0,3,0,136,0,0},
    {"IOMobileFramebuffer",0,5,0,1760,0,0},
    {"IOMobileFramebuffer",0,12,0,4,0,0},
    {"IOMobileFramebuffer",0,21,1,20,0,0},
    {"IOMobileFramebuffer",0,23,1,20,0,0},
    {"IOMobileFramebuffer",0,43,0,4,0,0},
    {"IOMobileFramebuffer",0,44,0,16,0,0},
    {"IOMobileFramebuffer",0,55,1,72,0,0},
    {"IOMobileFramebuffer",0,56,0,156,0,0},
    {"IOSurfaceRoot",0,2,0,12,0,3176},
    {"IOSurfaceRoot",0,3,0,12,0,4},
    {"IOSurfaceRoot",0,6,0,32,0,3176},
    {"IOSurfaceRoot",0,17,0,24,0,0},
    {"IOSurfaceRoot",0,18,0,24,0,0},
    {"IOSurfaceRoot",0,27,0,160,0,0},
    {"IOSurfaceRoot",0,62,0,12,0,3176},
    {"IOSurfaceRoot",0,63,0,12,0,4},
    {"IOSurfaceRoot",0,66,0,32,0,3176},
    {"IOSurfaceRoot",0,77,0,24,0,0},
    {"IOSurfaceRoot",0,78,0,24,0,0},
    {"IOSurfaceRoot",0,87,0,160,0,0},
};
static const int NT = (int)(sizeof(T)/sizeof(T[0]));

static uint64_t g_st;
static uint64_t rnd(void){ g_st ^= g_st<<13; g_st ^= g_st>>7; g_st ^= g_st<<17; return g_st; }

#define LOG(...) do{ fprintf(stderr,__VA_ARGS__); fflush(stderr); }while(0)

int main(int argc, char **argv){
  uint64_t seed   = (argc>1)? strtoull(argv[1],0,0) : 0x9e3779b97f4a7c15ULL;
  long rounds     = (argc>2)? atol(argv[2]) : 500;
  long start      = (argc>3)? atol(argv[3]) : 0;
  g_st = seed | 1;
  LOG("{\"k\":\"@meta\",\"nt\":%d,\"seed\":%llu,\"rounds\":%ld,\"start\":%ld}\n",
      NT,(unsigned long long)seed,rounds,start);

  io_connect_t conn[8]; const char *nm[8];
  memset(conn,0,sizeof(conn)); memset(nm,0,sizeof(nm));
  int nn=0;

  for(long it=start; it<start+rounds; it++){
    int ti = (int)(rnd() % (uint64_t)NT);
    tgt_t t = T[ti];
    int ci=-1;
    for(int i=0;i<nn;i++) if(nm[i] && !strcmp(nm[i],t.svc)){ci=i;break;}
    if(ci<0){
      for(int i=0;i<8;i++) if(!conn[i]){ nm[i]=t.svc; ci=i; break; }
      if(ci<0) continue;
      io_service_t s = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching(t.svc));
      if(!s){ LOG("{\"k\":\"@nosvc\",\"svc\":\"%s\"}\n",t.svc); nm[ci]=0; continue; }
      IOReturn ok = IOServiceOpen(s, mach_task_self(), t.type, &conn[ci]);
      IOObjectRelease(s);
      LOG("{\"k\":\"@open\",\"svc\":\"%s\",\"ty\":%u,\"kr\":%d}\n",t.svc,t.type,ok);
      if(ok){ conn[ci]=0; nm[ci]=0; continue; }
      if(ci>=nn) nn=ci+1;
    }

    uint64_t si[64]; memset(si,0,sizeof(si));
    void *ib = calloc(1, t.stIn);
    if(!ib) continue;
    int mode = (int)(it & 1);
    if(mode==0){ for(uint32_t k=0;k<t.stIn;k++) ((uint8_t*)ib)[k]=(uint8_t)rnd(); }
    else { for(uint32_t k=0;k+4<=t.stIn;k+=4){ uint32_t v=(uint32_t)(rnd()%0x1001); memcpy((uint8_t*)ib+k,&v,4);} }
    uint64_t ob_s[64]; memset(ob_s,0,sizeof(ob_s));
    uint64_t *ob = t.sOut? ob_s : NULL;
    uint32_t obc = t.sOut;
    void *os = t.stOut? calloc(1,t.stOut) : NULL;
    size_t osc = t.stOut;

    LOG("{\"k\":\"@pre\",\"it\":%ld,\"ti\":%d,\"svc\":\"%s\",\"sel\":%u,\"m\":%d}\n",it,ti,t.svc,t.sel,mode);

    IOReturn r = IOConnectCallMethod(conn[ci], t.sel,
        (t.sIn? si:NULL), t.sIn, ib, t.stIn,
        ob, &obc, os, &osc);

    LOG("{\"k\":\"@r\",\"it\":%ld,\"svc\":\"%s\",\"sel\":%u,\"kr\":%d,\"krh\":\"0x%x\"}\n",it,t.svc,t.sel,r,r);
    free(ib); if(os) free(os);
  }
  LOG("{\"k\":\"@done\",\"last\":%ld}\n", start+rounds-1);
  return 0;
}
