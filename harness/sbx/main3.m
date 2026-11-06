#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

static void probe(CTFontRef f, double size, double ctm, const char*tag) {
    size_t W=200,H=200;
    L(@"     probe enter");
    CGColorSpaceRef cs=CGColorSpaceCreateDeviceRGB();
    uint32_t *buf=calloc(W*H,4);
    CGContextRef ctx=CGBitmapContextCreate(buf,W,H,8,W*4,cs,kCGImageAlphaPremultipliedLast);
    CGContextConcatCTM(ctx, CGAffineTransformMakeScale(ctm,ctm));
    L(@"     ctx ok");
    UniChar ch='A'; CGGlyph gl=0;
    CTFontGetGlyphsForCharacters(f,&ch,&gl,1);
    L(@"     cmap ok");
    CGGlyph gls[1]={gl};
    L(@"  [%@] size=%.0f ctm=%.3f glyph=%u", tag,size,ctm,gl);
    CGPoint p=CGPointMake(4,4);
    L(@"    drawing...");
    CTFontDrawGlyphs(f,&gl,&p,1,ctx);
    L(@"    drawn");
    CGContextFlush(ctx);
    int x0=1<<30,y0=1<<30,x1=-1,y1=-1; long n=0;
    for(size_t y=0;y<H;y++)for(size_t x=0;x<W;x++)
        if((buf[y*W+x]>>24)&0xff){n++;if((int)x<x0)x0=x;if((int)x>x1)x1=x;if((int)y<y0)y0=y;if((int)y>y1)y1=y;}
    L(@"    ink=%ld box=(%d,%d) %dx%d", n, x0==1<<30?0:x0, y0==1<<30?0:y0, x1-x0+1, y1-y0+1);
    free(buf); CGContextRelease(ctx); CGColorSpaceRelease(cs);
}
int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/p3.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== path-id2 start ===");
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *names=@[@"sbix_png256_ppem256.ttf",@"wide_256x64_ppem256.ttf",
                     @"tall_64x256_ppem256.ttf",@"wide_256x64_ppem64.ttf"];
    for (NSString *n in names) {
        L(@"--- %@ ---", n);
        NSString *p=[res stringByAppendingPathComponent:n];
        if(![[NSFileManager defaultManager] fileExistsAtPath:p]){L(@"  missing");continue;}
        NSData *d=[NSData dataWithContentsOfFile:p];
        CGDataProviderRef dp=CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
        CGFontRef cg=CGFontCreateWithDataProvider(dp);
        if(!cg){L(@"  CGFont 失败");continue;}
        double sizes[3]={64,256,1024};
        for(int i=0;i<3;i++){
            L(@"  creating CTFont size=%.0f", sizes[i]);
            CTFontRef f=CTFontCreateWithGraphicsFont(cg,sizes[i],NULL,NULL);
            if(!f){L(@"   fail");continue;}
            L(@"  calling probe ctm=1");
            probe(f,sizes[i],1.0,"ctm1");
            L(@"  calling probe ctm=0.5");
            probe(f,sizes[i],0.5,"ctm.5");
            CFRelease(f);
        }
        CGFontRelease(cg); CGDataProviderRelease(dp);
        L(@"--- %@ done", n);
    }
    L(@"=== done ===");
    fclose(g);} return 0; }
