#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

static void testPDF(NSData *d, NSString *n) {
    CGDataProviderRef dp=CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
    CGPDFDocumentRef doc=CGPDFDocumentCreateWithProvider(dp);
    if (!doc) { L(@"  pdf=NULL"); CGDataProviderRelease(dp); return; }
    size_t pages=CGPDFDocumentGetNumberOfPages(doc);
    L(@"  pdf OK pages=%zu", pages);
    if (pages>0) {
        CGPDFPageRef pg=CGPDFDocumentGetPage(doc,1);
        L(@"    render page1 ...");
        CGColorSpaceRef cs=CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx=CGBitmapContextCreate(NULL,64,64,8,64*4,cs,kCGImageAlphaPremultipliedLast);
        CGContextDrawPDFPage(ctx,pg);
        CGContextFlush(ctx);
        L(@"    rendered");
        CGContextRelease(ctx); CGColorSpaceRelease(cs);
    }
    CGPDFDocumentRelease(doc); CGDataProviderRelease(dp);
}

int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/corpus.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); if(!g) return 1;
    L(@"=== corpus start pid=%d ===",getpid());
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSArray *all=[[[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]
                   sortedArrayUsingSelector:@selector(compare:)];
    L(@"文件 %lu 个",(unsigned long)all.count);
    for (NSString *n in all) {
        NSString *ext=[n pathExtension].lowercaseString;
        BOOL isPDF=[ext isEqualToString:@"pdf"];
        BOOL isImg=([ext isEqualToString:@"jpg"]||[ext isEqualToString:@"tif"]||[ext isEqualToString:@"png"]);
        if (!isPDF && !isImg) continue;
        NSData *d=[NSData dataWithContentsOfFile:[res stringByAppendingPathComponent:n]];
        L(@"--- %@ (%lu B) ---", n, (unsigned long)d.length);
        @try {
            if (isPDF) testPDF(d,n);
            else {
                CGImageSourceRef src=CGImageSourceCreateWithData((__bridge CFDataRef)d,NULL);
                if (!src) { L(@"  source=NULL"); continue; }
                L(@"  src OK count=%zu", CGImageSourceGetCount(src));
                for (size_t i=0;i<CGImageSourceGetCount(src) && i<3;i++) {
                    CGImageRef im=CGImageSourceCreateImageAtIndex(src,i,NULL);
                    L(@"    img[%zu]=%s", i, im?"OK":"NULL");
                    if (im) { L(@"      %zux%zu", CGImageGetWidth(im),CGImageGetHeight(im)); CFRelease(im); }
                }
                CFRelease(src);
            }
        } @catch (NSException *e) { L(@"  EXC %@", e.reason); }
    }
    L(@"=== corpus done 未崩溃 ===");
    fclose(g); }
    return 0; }
