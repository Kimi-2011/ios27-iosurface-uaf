#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

// 画进 WxH 上下文，返回墨迹包围盒（用于观测 dest rect 是否突变/塌缩）
static void drawOne(CGFontRef cg, CTFontRef f, double size, int mode,
                    int *bx, int *by, int *bw, int *bh, long *ink)
{
    size_t W=64,H=64;
    CGColorSpaceRef cs=CGColorSpaceCreateDeviceRGB();
    uint32_t *buf = calloc(W*H,4);
    CGContextRef ctx=CGBitmapContextCreate(buf,W,H,8,W*4,cs,kCGImageAlphaPremultipliedLast);
    if (mode==1) CGContextConcatCTM(ctx, CGAffineTransformMakeTranslation(3.0,3.0));
    if (mode==2) CGContextConcatCTM(ctx, CGAffineTransformMakeScale(0.001,0.001));
    UniChar ch='A'; CGGlyph gl=0;
    if (!CTFontGetGlyphsForCharacters(f,&ch,&gl,1)) { L(@"    cmap 失败"); }
    CGPoint p = CGPointMake(0,0);
    if (mode==3) p = CGPointMake(1024.0, 1024.0);
    L(@"    draw size=%.0f mode=%d glyph=%u", size, mode, gl);
    CTFontDrawGlyphs(f,&gl,&p,1,ctx);
    CGContextFlush(ctx);
    // 扫描 alpha
    int x0=1<<30,y0=1<<30,x1=-1,y1=-1; long n=0;
    for (size_t y=0;y<H;y++) for (size_t x=0;x<W;x++) {
        if ((buf[y*W+x]>>24)&0xff) { n++; if((int)x<x0)x0=x; if((int)x>x1)x1=x;
                                     if((int)y<y0)y0=y; if((int)y>y1)y1=y; }
    }
    *ink=n; *bx=x0;*by=y0;*bw=x1-x0+1;*bh=y1-y0+1;
    free(buf);
    CGContextRelease(ctx); CGColorSpaceRelease(cs);
}

int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/sbx.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== sbx PoC start pid=%d ===",getpid());
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *all=[[[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]
                   sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray *fonts=[NSMutableArray array];
    for (NSString *n in all) if ([n hasSuffix:@".ttf"]) [fonts addObject:[res stringByAppendingPathComponent:n]];
    double sizes[] = {64, 1024, 8192, 30000, 32000, 32760, 32768, 33000, 36000,
                      40000, 49152, 60000, 65536, 70000, 100000, 262144};
    int NS = sizeof(sizes)/sizeof(sizes[0]);
    for (NSString *p in fonts) {
        L(@"--- %@ ---", [p lastPathComponent]);
        NSData *d=[NSData dataWithContentsOfFile:p];
        CGDataProviderRef dp=CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
        CGFontRef cg=CGFontCreateWithDataProvider(dp);
        if (!cg) { L(@"  CGFont 失败"); CGDataProviderRelease(dp); continue; }
        for (int i=0;i<NS;i++) {
            CTFontRef f=CTFontCreateWithGraphicsFont(cg, sizes[i], NULL, NULL);
            if (!f) { L(@"  size=%.0f CTFont 失败", sizes[i]); continue; }
            L(@"  size 请求=%.0f 实际=%.3f", sizes[i], CTFontGetSize(f));
            for (int mode=0; mode<4; mode++) {
                int bx,by,bw,bh; long ink;
                @try { drawOne(cg,f,sizes[i],mode,&bx,&by,&bw,&bh,&ink); }
                @catch (NSException *e) { L(@"    ObjC 异常: %@", e); continue; }
                L(@"    mode=%d ink=%ld bbox=(%d,%d %dx%d)", mode, ink, bx,by,bw,bh);
            }
            CFRelease(f);
        }
        CGFontRelease(cg); CGDataProviderRelease(dp);
        L(@"  === %@ 完成 ===", [p lastPathComponent]);
    }
    L(@"=== sbx PoC done 未崩溃 ===");
    fclose(g); }
    return 0; }
