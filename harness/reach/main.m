#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

static void probe(const char *svc){
    CFMutableDictionaryRef m=IOServiceMatching(svc);
    if(!m){ L(@" %-34s matching 失败", svc); return; }
    io_iterator_t it=0;
    kern_return_t kr=IOServiceGetMatchingServices(kIOMainPortDefault,m,&it);
    if(kr!=KERN_SUCCESS||!it){ L(@" %-34s 无实例 (kr=%d)", svc,(int)kr); return; }
    io_object_t o; int n=0, first=-1;
    while((o=IOIteratorNext(it))){ n++; if(first<0) first=(int)o; }
    if(n==0){ L(@" %-34s 无实例", svc); IOObjectRelease(it); return; }
    NSString *res=@"全部失败";
    for(uint32_t t=0;t<=8;t++){
        io_connect_t c=0;
        kern_return_t r=IOServiceOpen((io_object_t)first,mach_task_self(),t,&c);
        if(r==KERN_SUCCESS){ res=[NSString stringWithFormat:@"✅ 可开 type=%u",t]; if(c) IOServiceClose(c); break; }
        if(t==0){ res=[NSString stringWithFormat:@"❌ 首个错误 0x%x",r]; }
    }
    L(@" %-34s 实例=%d  %@", svc, n, res);
    if(first>=0) IOObjectRelease((io_object_t)first);
    IOObjectRelease(it);
}

int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/reach.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== 用户客户端可达性探测 pid=%d ===",getpid());
    const char *svcs[]={
        "AppleH16ANEInterface","AppleH11ANEInterface","AppleH13ANEInterface",
        "H1xANELoadBalancer","ANEClientHints","AppleT8150ANEHAL",
        "AppleHIDTransportHIDDevice","IOHIDSystem","AppleSPUHIDDevice",
        "AppleSEPKeyStore","AppleSEPManager",
        "IOSkywalkNetworkInterface","IOSkywalkLogicalLink",
        "AppleM2ScalerCSCDriver","AppleJPEGDriver","AppleCLCD2",
        "AppleUSBHostDevice","AppleUSBDevice",
        "AppleANS2NVMeController","AppleJPEGDriverUserClient",
    };
    for(unsigned i=0;i<sizeof(svcs)/sizeof(svcs[0]);i++) probe(svcs[i]);
    L(@"=== 结束 ===");
    fclose(g); }
    return 0; }
