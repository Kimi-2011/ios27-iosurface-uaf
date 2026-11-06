#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#include <stdio.h>
#include "server.h"
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

@interface WC : NSObject <WKNavigationDelegate, WKScriptMessageHandler>
@property (nonatomic,strong) WKWebView *wv;
@property (nonatomic,strong) NSArray *tests;
@property (nonatomic,assign) NSInteger idx;
@property (nonatomic,strong) NSString *cur;
@property (nonatomic,assign) int crashes;
- (void)next;
@end
@implementation WC
- (void)next {
    if(self.idx >= (NSInteger)self.tests.count){
        L(@"=== 全部跑完，崩溃 %d 次 ===", self.crashes); fclose(g); exit(0);
    }
    self.cur = self.tests[self.idx];
    NSString *u=[NSString stringWithFormat:@"http://127.0.0.1:%d/tests/%@", gPort, self.cur];
    L(@"[%ld/%lu] 载入 %@", (long)self.idx+1, (unsigned long)self.tests.count, self.cur);
    self.idx++;
    [self.wv loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:u]]];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,35*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        if(self.cur == nil) return;
        NSString *expect=self.cur;
        [self.wv evaluateJavaScript:@"(document.body&&document.body.textContent)||(document.getElementById('output')||{}).textContent||''"
                 completionHandler:^(id r,NSError *e){
            if(![expect isEqualToString:self.cur]) return;   // 已切换
            L(@"   结果: %@", [(r?:e.localizedDescription) description].length>200?
              [[(r?:@"") description] substringToIndex:200] : (r?:e.localizedDescription));
        }];
        self.cur=nil;
        [self next];
    });
}
- (void)webViewWebContentProcessDidTerminate:(WKWebView*)w {
    self.crashes++;
    L(@"★★★ 崩溃！测试=%@ (第 %d 次) ★★★", self.cur ?: @"(刚崩溃的那个)", self.crashes);
    self.cur=nil;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),dispatch_get_main_queue(),^{ [self next]; });
}
- (void)userContentController:(WKUserContentController*)c didReceiveScriptMessage:(WKScriptMessage*)m {
    L(@"   [js] %@", [[m.body description] substringToIndex:MIN(160,[[m.body description] length])]);
}
@end

@interface AD : UIResponder <UIApplicationDelegate>
@property (nonatomic,strong) UIWindow *window;
@end
@implementation AD
- (BOOL)application:(UIApplication*)app didFinishLaunchingWithOptions:(NSDictionary*)o{
    char lp[512]; snprintf(lp,sizeof(lp),"%s/wk.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); L(@"=== 批量扫描 pid=%d ===",getpid());
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root=[UIViewController new];
    self.window.rootViewController=root; [self.window makeKeyAndVisible];
    NSString *res=[[NSBundle mainBundle] resourcePath];
    // 收集 tests/
    NSMutableArray *names=[NSMutableArray array];
    NSMutableArray *allFiles=[NSMutableArray array];
    NSString *td=[res stringByAppendingPathComponent:@"tests"];
    for(NSString *n in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:td error:nil]){
        [allFiles addObject:n];
        if([n hasSuffix:@".html"] && ![n hasPrefix:@"t321669"]) [names addObject:n];  // 321669 已确认，跳过
    }
    [names sortUsingSelector:@selector(compare:)];
    L(@"测试数: %lu",(unsigned long)names.count);
    // HTTP 服务：/tests/<file> 与 /js-test.js
    NSMutableDictionary *files=[NSMutableDictionary dictionary];
    for(NSString *n in allFiles){
        files[[@"/tests/" stringByAppendingString:n]] =
          [NSString stringWithContentsOfFile:[td stringByAppendingPathComponent:n] encoding:NSUTF8StringEncoding error:nil] ?: @"";
    }
    files[@"/js-test.js"]=files[@"/tests/js-test.js"] ?: @"";
    int port=0;
    if(startHTTPServerMulti(files,&port)!=0){ L(@"HTTP失败"); fclose(g); exit(1); }
    gPort=port;
    WKUserContentController *ucc=[WKUserContentController new];
    WC *wc=[WC new]; wc.tests=names; wc.idx=0;
    [ucc addScriptMessageHandler:wc name:@"log"];
    NSString *bridge=@"window.__bridge=function(m){try{window.webkit.messageHandlers.log.postMessage(String(m));}catch(e){}};"
        "window.onerror=function(m,s,l){__bridge('ERR '+m+' @'+l);};";
    NSString *shimPath=[res stringByAppendingPathComponent:@"wptshim.js"];
    NSString *shim=[NSString stringWithContentsOfFile:shimPath encoding:NSUTF8StringEncoding error:nil];
    if(shim.length){
        bridge=[bridge stringByAppendingString:shim];
        L(@"WPT shim 已注入 (%lu 字节)",(unsigned long)shim.length);
    } else L(@"警告：wptshim.js 未找到");
    [ucc addUserScript:[[WKUserScript alloc] initWithSource:bridge
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:NO]];
    WKWebViewConfiguration *cfg=[WKWebViewConfiguration new];
    cfg.userContentController=ucc;
    WKWebView *wv=[[WKWebView alloc] initWithFrame:self.window.bounds configuration:cfg];
    wv.navigationDelegate=wc; wc.wv=wv;
    [root.view addSubview:wv];
    [wc next];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,300*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        L(@"=== 300s 超时，崩溃 %d 次 ===",wc.crashes); fclose(g); exit(0);
    });
    return YES;
}
@end
int main(int argc,char**argv){ @autoreleasepool { return UIApplicationMain(argc,argv,nil,NSStringFromClass([AD class])); } }
