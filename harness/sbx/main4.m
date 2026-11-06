#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }
static void t(CTFontRef f, double size, double ctm){
    size_t W=300,H=300; CGColorSpaceRef cs=CGColorSpaceCreateDeviceRGB();
    uint32_t*buf=calloc(W*H,4);
    CGContextRef ctx=CGBitmapContextCreate(buf,W,H,8,W*4,cs,kCGImageAlphaPremultipliedLast);
    CGContextConcatCTM(ctx, CGAffineTransformMakeScale(ctm,ctm));
    UniChar ch='A'; CGGlyph gl=0; CTFontGetGlyphsForCharacters(f,&ch,&gl,1);
    L(@"   draw size=%.0f ctm=%.4f glyph=%u", size, ctm, gl);
    CGPoint p=CGPointMake(8,8);
    CTFontDrawGlyphs(f,&gl,&p,1,ctx); CGContextFlush(ctx);
    int x0=1<<30,y0=1<<30,x1=-1,y1=-1; long n=0;
    for(size_t y=0;y<H;y++)for(size_t x=0;x<W;x++)
      if((buf[y*W+x]>>24)&0xff){n++;if((int)x<x0)x0=x;if((int)x>x1)x1=x;if((int)y<y0)y0=y;if((int)y>y1)y1=y;}
    L(@"   ink=%-7ld box=%dx%d", n, x1<0?0:x1-x0+1, y1<0?0:y1-y0+1);
    free(buf);CGContextRelease(ctx);CGColorSpaceRelease(cs);
}
int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/p4.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== EBDT test start ===");
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *names=@[@"eb_nooutline.ttf",@"eb_64x64_ppem12.ttf"];
    double sizes[]={12,24,48,96,6144,12288,24576,49152};
    for (NSString *n in names){
        L(@"--- %@ ---", n);
        NSData*d=[NSData dataWithContentsOfFile:[res stringByAppendingPathComponent:n]];
        if(!d){L(@"  missing");continue;}
        CGDataProviderRef dp=CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
        CGFontRef cg=CGFontCreateWithDataProvider(dp);
        if(!cg){L(@"  CGFont 失败");CGDataProviderRelease(dp);continue;}
        for(int i=0;i<8;i++){
            CTFontRef f=CTFontCreateWithGraphicsFont(cg,sizes[i],NULL,NULL);
            if(!f){L(@"  size=%.0f CTFont 失败",sizes[i]);continue;}
            double ctm = sizes[i]>300 ? 300.0/sizes[i]*0.9 : 1.0;
            t(f,sizes[i],ctm);
            CFRelease(f);
        }
        CGFontRelease(cg);CGDataProviderRelease(dp);
        L(@"--- %@ ok", n);
    }
    L(@"=== done ==="); fclose(g);} return 0; }
