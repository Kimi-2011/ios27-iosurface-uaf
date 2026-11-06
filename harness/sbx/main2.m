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
    CGColorSpaceRef cs=CGColorSpaceCreateDeviceRGB();
    uint32_t *buf=calloc(W*H,4);
    CGContextRef ctx=CGBitmapContextCreate(buf,W,H,8,W*4,cs,kCGImageAlphaPremultipliedLast);
    CGContextConcatCTM(ctx, CGAffineTransformMakeScale(ctm,ctm));
    UniChar ch='A'; CGGlyph gl=0;
    CTFontGetGlyphsForCharacters(f,&ch,&gl,1);
    CGPoint p=CGPointMake(4,4);
    CTFontDrawGlyphs(f,&gl,&p,1,ctx);
    CGContextFlush(ctx);
    int x0=1<<30,y0=1<<30,x1=-1,y1=-1; long n=0;
    for(size_t y=0;y<H;y++)for(size_t x=0;x<W;x++)
        if((buf[y*W+x]>>24)&0xff){n++;if((int)x<x0)x0=x;if((int)x>x1)x1=x;if((int)y<y0)y0=y;if((int)y>y1)y1=y;}
    L(@"  [%@] size=%.0f ctm=%.3f glyph=%u ink=%ld bbox=(%d,%d) %dx%d", tag, size, ctm, gl, n,
      x0==1<<30?0:x0, y0==1<<30?0:y0, x1-x0+1, y1-y0+1);
    free(buf); CGContextRelease(ctx); CGColorSpaceRelease(cs);
}
int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/p2.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== path-id start ===");
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *all=[[[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]
                   sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *n in all) {
        if (![n hasPrefix:@"wide"] && ![n hasPrefix:@"tall"]) continue;
        L(@"--- %@ ---", n);
        NSData *d=[NSData dataWithContentsOfFile:[res stringByAppendingPathComponent:n]];
        CGDataProviderRef dp=CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
        CGFontRef cg=CGFontCreateWithDataProvider(dp);
        if(!cg){L(@"  CGFont 失败");continue;}
        double sizes[4]={256,64,32,1024};
        for(int i=0;i<4;i++){
            CTFontRef f=CTFontCreateWithGraphicsFont(cg,sizes[i],NULL,NULL);
            if(!f) continue;
            probe(f,sizes[i],1.0,"ctm1");
            probe(f,sizes[i],0.5,"ctm.5");
            CFRelease(f);
        }
        CGFontRelease(cg); CGDataProviderRelease(dp);
    }
    L(@"=== done ===");
    fclose(g);} return 0; }
