#import <Foundation/Foundation.h>
#import <ModelIO/ModelIO.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/usd.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== USDZ PoC start pid=%d ===",getpid());
    L(@"canImport usdz=%d", (int)[MDLAsset canImportFileExtension:@"usdz"]);
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *all=[[[[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]
                   sortedArrayUsingSelector:@selector(compare:)] mutableCopy];
    for (NSString *n in all) {
        if (![n hasSuffix:@".usdz"]) continue;
        NSURL *u=[NSURL fileURLWithPath:[res stringByAppendingPathComponent:n]];
        L(@"--- %@ ---", n);
        @try {
            MDLAsset *a=[[MDLAsset alloc] initWithURL:u];
            if (!a) { L(@"  asset=nil"); continue; }
            NSUInteger cnt=[a count];
            L(@"  asset OK count=%lu", (unsigned long)cnt);
            for (NSUInteger i=0;i<cnt && i<3;i++)
                L(@"    [%lu] %@", (unsigned long)i, [[a objectAtIndex:i] class]);
        } @catch (NSException *e) { L(@"  EXC %@", e.reason); }
    }
    L(@"=== done 未崩溃 ===");
    fclose(g); }
    return 0; }
