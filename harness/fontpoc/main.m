// CoreText 光学尺寸 (CVE-2026-112656) 可达性验证 harness  —— 独立目录版
// 目标: TFont::SetOpticalSize -> TFont::SelectOpticalStyleFromOS2
// 日志: $TMPDIR/ctreach.log   (刻意与 fontpoc.log 区分，避免并行 session 混淆)
#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <stdlib.h>

static FILE *g;
static void L(NSString *f, ...) {
    va_list a; va_start(a, f);
    NSString *s = [[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g, "%s\n", s.UTF8String); fflush(g);
    fprintf(stderr, "%s\n", s.UTF8String); fflush(stderr); va_end(a);
}
static NSString *S(CFStringRef s) { return s ? (__bridge NSString *)s : @"(null)"; }

static uint32_t tag4(const char *t) {
    return ((uint32_t)(unsigned char)t[0] << 24) | ((uint32_t)(unsigned char)t[1] << 16) |
           ((uint32_t)(unsigned char)t[2] << 8) | (uint32_t)(unsigned char)t[3];
}

static void exercise(CTFontRef f) {
    if (!f) return;
    CGGlyph gl = 0x41;
    CGRect r = CGRectNull;
    CTFontGetBoundingRectsForGlyphs(f, kCTFontOrientationHorizontal, &gl, &r, 1);
    CTFontGetAdvancesForGlyphs(f, kCTFontOrientationHorizontal, &gl, NULL, 1);
    CTFontGetBoundingBox(f); CTFontGetUnitsPerEm(f); CTFontGetXHeight(f);
    CTFontGetUnderlinePosition(f);
    L(@"        asc=%.2f desc=%.2f cap=%.2f lead=%.2f rect=(%.2f,%.2f,%.2f,%.2f)",
      CTFontGetAscent(f), CTFontGetDescent(f), CTFontGetCapHeight(f), CTFontGetLeading(f),
      r.origin.x, r.origin.y, r.size.width, r.size.height);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, 32, 32, 8, 128, cs,
                                             (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGPoint pt = CGPointMake(2, 2);
    CTFontDrawGlyphs(f, &gl, &pt, 1, ctx);
    CGContextFlush(ctx);
    CGContextRelease(ctx); CGColorSpaceRelease(cs);
}

static NSString *psOf(CTFontRef f) {
    if (!f) return @"(nil)";
    CFStringRef ps = CTFontCopyPostScriptName(f);
    NSString *r = ps ? [S(ps) copy] : @"(nil)";
    if (ps) CFRelease(ps);
    return r;
}

int main(void) { @autoreleasepool {
    const char *td = getenv("TMPDIR");
    NSString *tmp = td ? [NSString stringWithUTF8String:td] : NSTemporaryDirectory();
    char lp[1024]; snprintf(lp, sizeof(lp), "%s/ctreach.log", tmp.UTF8String);
    g = fopen(lp, "w"); if (!g) return 1;
    L(@"=== CTREACH harness (SetOpticalSize reachability) ===");
    L(@"TMPDIR=%@ pid=%d", tmp, getpid());
    L(@"osversion: %@", [[NSProcessInfo processInfo] operatingSystemVersionString]);

    L(@"HB start");
    L(@"M1 before resourcePath");
    NSString *res = [[NSBundle mainBundle] resourcePath];
    L(@"M2 res=%@", res);
    NSError *e0 = nil;
    NSArray *raw = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:&e0];
    L(@"M3 raw=%lu err=%@", (unsigned long)raw.count, e0 ? [e0 description] : @"(nil)");
    L(@"P1 before sort");
    NSArray *all = nil;
    @try {
        all = [raw sortedArrayUsingSelector:@selector(compare)];
    } @catch (NSException *ex) {
        L(@"P-EXC sort: %@", ex);
        all = raw;
    }
    L(@"P2 sorted=%lu", (unsigned long)all.count);
    for (NSString *x in all) L(@"   item: %@", x);
    NSMutableArray *fonts = [NSMutableArray array];
    for (NSString *n in all) if ([n hasSuffix:@".ttf"]) [fonts addObject:n];
    L(@"字体数=%lu", (unsigned long)fonts.count);

    double sizes[6] = {1, 8, 17, 20, 96, 200};

    for (NSString *n in fonts) {
        NSData *d = [NSData dataWithContentsOfFile:[res stringByAppendingPathComponent:n]];
        if (!d) { L(@"--- %@ 读不到", n); continue; }
        L(@"");
        L(@"==== %@ (%lu B) ====", n, (unsigned long)d.length);
        L(@"  B0 file-read ok");

        NSString *dst = [tmp stringByAppendingPathComponent:n];
        [d writeToFile:dst atomically:YES];
        CFErrorRef err = NULL;
        BOOL reg = CTFontManagerRegisterFontsForURL((__bridge CFURLRef)[NSURL fileURLWithPath:dst],
                                                   kCTFontManagerScopeProcess, &err);
        if (err) { L(@"  register(Process)=%d err=%@", reg, S(CFErrorCopyDescription(err))); CFRelease(err); err = NULL; }
        else L(@"  register(Process)=%d err=(none)", reg);

        CGDataProviderRef dp = CGDataProviderCreateWithCFData((__bridge CFDataRef)d);
        CGFontRef cg = CGFontCreateWithDataProvider(dp);
        NSString *psName = nil;
        if (cg) {
            CFStringRef ps = CGFontCopyPostScriptName(cg);
            psName = ps ? [S(ps) copy] : nil;
            if (ps) CFRelease(ps);
        }
        L(@"  CGFont=%@ ps=%@", cg ? @"ok" : @"nil", psName ?: @"?");
        if (!cg || !psName) { if (cg) CGFontRelease(cg); CGDataProviderRelease(dp); continue; }

        CFErrorRef gerr = NULL;
        BOOL greg = CTFontManagerRegisterGraphicsFont(cg, &gerr);
        if (gerr) { L(@"  registerGraphicsFont=%d err=%@", greg, S(CFErrorCopyDescription(gerr))); CFRelease(gerr); gerr = NULL; }
        else L(@"  registerGraphicsFont=%d", greg);

        // 自检：CoreText 眼里这个字体是什么
        CTFontDescriptorRef pd =
            CTFontDescriptorCreateWithAttributes((__bridge CFDictionaryRef)
                @{(__bridge id)kCTFontNameAttribute : psName,
                  (__bridge id)kCTFontSizeAttribute : @(20)});
        CTFontRef base = CTFontCreateWithFontDescriptor(pd, 20, NULL);
        L(@"  基线 ps=%@", psOf(base));
        if (base) {
            CFArrayRef axes = CTFontCopyVariationAxes(base);
            L(@"    varAxes=%@", axes ? [NSString stringWithFormat:@"%@", (__bridge id)axes] : @"(none)");
            if (axes) CFRelease(axes);
            CFTypeRef ops = CTFontCopyAttribute(base, CFSTR("CTFontOpticalPointSizesAttribute"));
            L(@"    ### OpticalPointSizes(从字体读到的光学尺寸区间) = %@",
              ops ? [NSString stringWithFormat:@"%@", (__bridge id)ops] : @"(nil)");
            if (ops) CFRelease(ops);
            CFTypeRef osz = CTFontCopyAttribute(base, CFSTR("NSCTFontOpticalSizeAttribute"));
            L(@"    ### OpticalSizeAttr = %@", osz ? [NSString stringWithFormat:@"%@", (__bridge id)osz] : @"(nil)");
            if (osz) CFRelease(osz);
            const char *tags[4] = {"fvar", "STAT", "trak", "avar"};
            for (int t = 0; t < 4; t++) {
                CFDataRef tb = CTFontCopyTable(base, (CTFontTableTag)tag4(tags[t]), 0);
                L(@"    table %s = %@", tags[t],
                  tb ? [NSString stringWithFormat:@"present(%ld B)", (long)CFDataGetLength(tb)] : @"absent");
                if (tb) CFRelease(tb);
            }
        }
        if (base) CFRelease(base);
        CFRelease(pd);

        for (int i = 0; i < (int)(sizeof(sizes)/sizeof(sizes[0])); i++) {
            double sz = sizes[i];
            L(@"  --- size=%.0f ---", sz);

            CTFontRef a = CTFontCreateWithName((__bridge CFStringRef)psName, sz, NULL);
            L(@"    [A name-only     ] ps=%@", psOf(a)); exercise(a); if (a) CFRelease(a);

            CTFontDescriptorRef de1 = CTFontDescriptorCreateWithAttributes((__bridge CFDictionaryRef)
                @{(__bridge id)kCTFontNameAttribute : psName,
                  (__bridge id)kCTFontOpticalSizeAttribute : @(sz)});
            CTFontRef b = CTFontCreateWithFontDescriptor(de1, sz, NULL);
            L(@"    [B desc+optSize  ] ps=%@", psOf(b));
            if (b) exercise(b);
            if (b) CFRelease(b);
            CFRelease(de1);

            CTFontDescriptorRef de2 = CTFontDescriptorCreateWithAttributes((__bridge CFDictionaryRef)
                @{(__bridge id)kCTFontNameAttribute : psName,
                  (__bridge id)kCTFontOpticalSizeAttribute : @(sz),
                  (__bridge id)kCTFontVariationAttribute : @{(__bridge id)CFSTR("opsz") : @(sz)}});
            CTFontRef c = CTFontCreateWithFontDescriptor(de2, sz, NULL);
            L(@"    [C desc+opt+var  ] ps=%@", psOf(c)); exercise(c); if (c) CFRelease(c);
            CFRelease(de2);

            CTFontDescriptorRef de3 = CTFontDescriptorCreateWithAttributes((__bridge CFDictionaryRef)
                @{(__bridge id)kCTFontOpticalSizeAttribute : @(sz)});
            CTFontRef dd = CTFontCreateWithGraphicsFont(cg, sz, NULL, de3);
            L(@"    [D cg+optSize    ] ps=%@", psOf(dd)); exercise(dd); if (dd) CFRelease(dd);
            CFRelease(de3);

            CTFontRef e0 = CTFontCreateWithName((__bridge CFStringRef)psName, 20, NULL);
            if (e0) {
                CTFontDescriptorRef de4 = CTFontDescriptorCreateWithAttributes((__bridge CFDictionaryRef)
                    @{(__bridge id)kCTFontOpticalSizeAttribute : @(sz)});
                CTFontRef e = CTFontCreateCopyWithAttributes(e0, sz, NULL, de4);
                L(@"    [E copyWithAttrs ] ps=%@", psOf(e)); exercise(e); if (e) CFRelease(e);
                CFRelease(de4); CFRelease(e0);
            }
        }

        CGFontRelease(cg); CGDataProviderRelease(dp);
        L(@"  == %@ done ==", n);
    }

    L(@""); L(@"=== CTREACH 全部完成，未崩溃 ===");
    fclose(g);
    return 0;
}}
