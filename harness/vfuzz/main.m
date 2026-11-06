#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <VideoToolbox/VideoToolbox.h>
#import <UIKit/UIKit.h>
#include <stdatomic.h>
#include <pthread.h>

static atomic_long g_iters, g_decoded, g_frameerr;
static NSArray *g_samples;
static CMVideoFormatDescriptionRef g_fmt;
static NSString *g_dir;
static volatile int g_stop;

static uint64_t xs(uint64_t *s){ uint64_t x=*s; x^=x<<13; x^=x>>7; x^=x<<17; *s=x; return x; }

static void *worker(void *arg){
    uint64_t seed = (uint64_t)(uintptr_t)arg * 2654435761u + 12345u;
    if(!seed) seed = 88172645463325252ULL;
    @autoreleasepool {
        NSDictionary *spec=@{(id)kCVPixelBufferPixelFormatTypeKey:@(kCVPixelFormatType_32BGRA)};
        VTDecompressionSessionRef sess=NULL;
        VTDecompressionOutputCallbackRecord cb={NULL,NULL};
        if(VTDecompressionSessionCreate(kCFAllocatorDefault,g_fmt,NULL,(__bridge CFDictionaryRef)spec,&cb,&sess)!=noErr||!sess){
            // fall back to handler-based session (no callback record)
            NSDictionary *spec2=@{(id)kCVPixelBufferPixelFormatTypeKey:@(kCVPixelFormatType_32BGRA)};
            VTDecompressionSessionCreate(kCFAllocatorDefault,g_fmt,NULL,(__bridge CFDictionaryRef)spec2,NULL,&sess);
        }
        if(!sess) return NULL;
        long local=0;
        while(!g_stop){
            @autoreleasepool {
                NSData *src=g_samples[xs(&seed)%g_samples.count];
                NSMutableData *m=[src mutableCopy];
                uint8_t *p=m.mutableBytes;
                /* parse AVCC length prefixes to find NAL payload ranges */
                NSUInteger off=0; NSMutableArray *ranges=[NSMutableArray array];
                while(off+4<=m.length){
                    uint32_t ln=((uint32_t)p[off]<<24)|((uint32_t)p[off+1]<<16)|((uint32_t)p[off+2]<<8)|p[off+3];
                    if(ln==0||off+4+ln>m.length) break;
                    [ranges addObject:@[@(off+5),@(ln-1)]];  /* skip NAL header byte */
                    off+=4+ln;
                }
                uint64_t mode=xs(&seed)%10;
                if(ranges.count==0){ /* fallback: mutate tail only */
                    if(m.length>8){ NSUInteger o=8+xs(&seed)%(m.length-8); p[o]^=(uint8_t)(1u<<(xs(&seed)%8)); }
                } else if(mode<7){
                    /* single bit flip inside a NAL payload, biased late (residual data) */
                    NSArray *r=ranges[xs(&seed)%ranges.count];
                    NSUInteger base=[r[0] unsignedIntegerValue], len=[r[1] unsignedIntegerValue];
                    if(len>0){ NSUInteger pos=base+(len*len)/(len+1) * (xs(&seed)%100)/100; if(pos>=base+len) pos=base+len-1;
                               p[pos]^=(uint8_t)(1u<<(xs(&seed)%8)); }
                } else if(mode<9){
                    /* two bit flips in the same NAL */
                    NSArray *r=ranges[xs(&seed)%ranges.count];
                    NSUInteger base=[r[0] unsignedIntegerValue], len=[r[1] unsignedIntegerValue];
                    if(len>2){ for(int k=0;k<2;k++){ NSUInteger pos=base+xs(&seed)%len; p[pos]^=(uint8_t)(1u<<(xs(&seed)%8)); } }
                } else {
                    /* structural: corrupt the length prefix of a random NAL (bounds handling) */
                    NSUInteger ni=xs(&seed)%ranges.count;
                    NSUInteger base=[ranges[ni][0] unsignedIntegerValue];
                    NSUInteger pre=base-4;
                    if(pre+4<=m.length){
                        uint32_t v=(uint32_t)(xs(&seed)%3==0 ? 0xFFFFFFFF : (xs(&seed)%0x10000));
                        p[pre]=(uint8_t)(v>>24); p[pre+1]=(uint8_t)(v>>16); p[pre+2]=(uint8_t)(v>>8); p[pre+3]=(uint8_t)v;
                    }
                }
                CMBlockBufferRef bb=NULL;
                if(CMBlockBufferCreateWithMemoryBlock(kCFAllocatorDefault,(void*)p,m.length,kCFAllocatorNull,NULL,0,m.length,0,&bb)==noErr&&bb){
                    CMSampleBufferRef sb=NULL;
                    CMSampleTimingInfo ti={CMTimeMake(1,30),kCMTimeZero,CMTimeMake(1,30)};
                    size_t sizes[1]={m.length};
                    if(CMSampleBufferCreate(kCFAllocatorDefault,bb,true,NULL,NULL,g_fmt,1,1,&ti,1,sizes,&sb)==noErr&&sb){
                        VTDecodeInfoFlags fl=0;
                        OSStatus st=VTDecompressionSessionDecodeFrameWithOutputHandler(sess,sb,0,&fl,
                            ^(OSStatus status, VTDecodeInfoFlags f, CVImageBufferRef img, CMTime pts, CMTime dur){
                                if(status==noErr&&img) atomic_fetch_add(&g_decoded,1);
                                else atomic_fetch_add(&g_frameerr,1);
                            });
                        if(st!=noErr) atomic_fetch_add(&g_frameerr,1);
                        CFRelease(sb);
                    }
                    CFRelease(bb);
                }
                atomic_fetch_add(&g_iters,1);
                if((++local % 256)==0) VTDecompressionSessionWaitForAsynchronousFrames(sess);
            }
        }
        VTDecompressionSessionWaitForAsynchronousFrames(sess);
        VTDecompressionSessionInvalidate(sess);
        CFRelease(sess);
    }
    return NULL;
}

static void runFuzz(void){
    @autoreleasepool {
        g_dir=NSTemporaryDirectory();
        NSString *prog=[g_dir stringByAppendingPathComponent:@"mt.txt"];
        // build seed video
        NSString *p=[g_dir stringByAppendingPathComponent:@"seed.mov"];
        [[NSFileManager defaultManager] removeItemAtPath:p error:nil];
        AVAssetWriter *w=[AVAssetWriter assetWriterWithURL:[NSURL fileURLWithPath:p] fileType:AVFileTypeQuickTimeMovie error:nil];
        NSDictionary *st=@{AVVideoCodecKey:AVVideoCodecTypeH264,AVVideoWidthKey:@64,AVVideoHeightKey:@64};
        AVAssetWriterInput *in=[AVAssetWriterInput assetWriterInputWithMediaType:AVMediaTypeVideo outputSettings:st];
        in.expectsMediaDataInRealTime=NO;
        NSDictionary *at=@{(id)kCVPixelBufferPixelFormatTypeKey:@(kCVPixelFormatType_32BGRA)};
        AVAssetWriterInputPixelBufferAdaptor *ad=[AVAssetWriterInputPixelBufferAdaptor assetWriterInputPixelBufferAdaptorWithAssetWriterInput:in sourcePixelBufferAttributes:at];
        [w addInput:in];[w startWriting];[w startSessionAtSourceTime:kCMTimeZero];
        for(int f=0;f<10;f++){
            while(!in.isReadyForMoreMediaData) usleep(2000);
            CVPixelBufferRef pb=NULL; CVPixelBufferCreate(kCFAllocatorDefault,64,64,kCVPixelFormatType_32BGRA,NULL,&pb);
            CVPixelBufferLockBaseAddress(pb,0);
            uint8_t *b=CVPixelBufferGetBaseAddress(pb); size_t s=CVPixelBufferGetBytesPerRow(pb);
            for(int y=0;y<64;y++)for(int x=0;x<64;x++){uint8_t*px=b+y*s+x*4;px[0]=(uint8_t)(x*4+f);px[1]=(uint8_t)(y*4);px[2]=(uint8_t)(f*23);px[3]=255;}
            CVPixelBufferUnlockBaseAddress(pb,0);
            [ad appendPixelBuffer:pb withPresentationTime:CMTimeMake(f,30)];
            CVPixelBufferRelease(pb);
        }
        [in markAsFinished];
        __block BOOL done=NO; [w finishWritingWithCompletionHandler:^{done=YES;}];
        for(int i=0;i<400&&!done;i++) usleep(5000);

        AVURLAsset *a=[AVURLAsset URLAssetWithURL:[NSURL fileURLWithPath:p] options:nil];
        AVAssetReader *r=[AVAssetReader assetReaderWithAsset:a error:nil];
        NSArray *tr=[a tracksWithMediaType:AVMediaTypeVideo];
        if(tr.count==0){ [@"no track" writeToFile:prog atomically:YES encoding:NSUTF8StringEncoding error:nil]; return; }
        AVAssetReaderTrackOutput *o=[AVAssetReaderTrackOutput assetReaderTrackOutputWithTrack:tr[0] outputSettings:nil];
        [r addOutput:o]; [r startReading];
        NSMutableArray *arr=[NSMutableArray array];
        while(r.status==AVAssetReaderStatusReading){
            CMSampleBufferRef sb=[o copyNextSampleBuffer]; if(!sb) break;
            CMVideoFormatDescriptionRef fd=CMSampleBufferGetFormatDescription(sb);
            if(fd&&!g_fmt) g_fmt=(CMVideoFormatDescriptionRef)CFRetain(fd);
            CMBlockBufferRef bb=CMSampleBufferGetDataBuffer(sb);
            if(bb){ size_t len=CMBlockBufferGetDataLength(bb); uint8_t *t=malloc(len);
                    CMBlockBufferCopyDataBytes(bb,0,len,t); [arr addObject:[NSData dataWithBytes:t length:len]]; free(t); }
            CFRelease(sb);
        }
        g_samples=[arr copy];
        NSString *st0=[NSString stringWithFormat:@"mt start samples=%lu\n",(unsigned long)g_samples.count];
        [st0 writeToFile:prog atomically:YES encoding:NSUTF8StringEncoding error:nil];
        if(!g_fmt||g_samples.count==0) return;

        int NT=8;
        pthread_t th[8];
        for(long i=0;i<NT;i++) pthread_create(&th[i],NULL,worker,(void*)(i+1));
        for(int t=0;t<600;t++){
            sleep(1);
            NSString *s=[NSString stringWithFormat:@"mt t=%ds iters=%ld decoded=%ld frameerr=%ld threads=%d\n",
                         t+1, atomic_load(&g_iters), atomic_load(&g_decoded), atomic_load(&g_frameerr), NT];
            [s writeToFile:prog atomically:YES encoding:NSUTF8StringEncoding error:nil];
            if(atomic_load(&g_iters)>20000000L) break;
        }
        g_stop=1;
        for(int i=0;i<NT;i++) pthread_join(th[i],NULL);
    }
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window=[[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc=[UIViewController new];
    vc.view.backgroundColor=[UIColor blackColor];
    UILabel *l=[[UILabel alloc] initWithFrame:CGRectMake(20,120,320,80)];
    l.text=@"VT fuzz x8"; l.textColor=[UIColor greenColor]; l.numberOfLines=2;
    [vc.view addSubview:l];
    self.window.rootViewController=vc; [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{ runFuzz(); });
    return YES;
}
@end
int main(int argc,char*argv[]){ @autoreleasepool { return UIApplicationMain(argc,argv,nil,@"AppDelegate"); } }
