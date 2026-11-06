#import <UIKit/UIKit.h>
#import <QuickLook/QuickLook.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }

@interface QLDS : NSObject <QLPreviewControllerDataSource, QLPreviewControllerDelegate>
@property (nonatomic,strong) NSArray *urls;
@end
@implementation QLDS
- (NSInteger)numberOfPreviewItemsInPreviewController:(QLPreviewController *)controller { return self.urls.count; }
- (id<QLPreviewItem>)previewController:(QLPreviewController *)controller previewItemAtIndex:(NSInteger)index { return self.urls[index]; }
- (void)previewControllerDidDismiss:(QLPreviewController *)controller { L(@"QL 已关闭"); }
- (void)previewController:(QLPreviewController *)controller didFailWithError:(NSError *)error { L(@"QL 失败: %@", error); }
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic,strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/ql.log",getenv("TMPDIR")?:"/tmp");
    g=fopen(lp,"w"); L(@"=== QL start pid=%d ===",getpid());
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *root=[UIViewController new];
    self.window.rootViewController=root;
    [self.window makeKeyAndVisible];
    NSString *res=[[NSBundle mainBundle] resourcePath];
    NSMutableArray *urls=[NSMutableArray array];
    for(NSString *n in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]){
        if([n hasSuffix:@".usdz"]) [urls addObject:[NSURL fileURLWithPath:[res stringByAppendingPathComponent:n]]];
    }
    L(@"usdz 文件 %lu 个", (unsigned long)urls.count);
    if(urls.count){
        QLDS *ds=[QLDS new]; ds.urls=urls;
        QLPreviewController *ql=[QLPreviewController new];
        ql.dataSource=ds; ql.delegate=ds;
        L(@"present QL …");
        [root presentViewController:ql animated:NO completion:^{ L(@"QL present 完成"); }];
        // 10 秒后检查是否存活
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_SEC),dispatch_get_main_queue(),^{
            L(@"=== 10 秒后 app 仍存活 ===");
            fclose(g); exit(0);
        });
    } else { L(@"无 usdz"); fclose(g); exit(0); }
    return YES;
}
@end

int main(int argc,char**argv){ @autoreleasepool { return UIApplicationMain(argc,argv,nil,NSStringFromClass([AppDelegate class])); } }
