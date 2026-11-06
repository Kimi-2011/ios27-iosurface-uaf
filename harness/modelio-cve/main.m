#import <Foundation/Foundation.h>
#import <ModelIO/ModelIO.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>
#include <stdio.h>
static FILE *g;
static void L(NSString *f, ...) { va_list a; va_start(a,f);
    NSString *s=[[NSString alloc] initWithFormat:f arguments:a];
    fprintf(g,"%s\n",s.UTF8String); fflush(g); va_end(a); }
static void walk(MDLObject *o,int d){
    if(d>6||!o)return;
    if([o isKindOfClass:[MDLMesh class]]){
        MDLMesh *mesh=(MDLMesh*)o;
        for(MDLSubmesh *sm in mesh.submeshes){
            MDLMaterial *m=sm.material;
            if(!m)continue;
            for(NSUInteger pi=0;pi<m.count;pi++){
                MDLMaterialProperty *p=m[pi];
                if(!p.URLValue)continue;
                L(@"%*s%@ prop %@ url=%@",d*2,"",m.name,p.name,p.URLValue.lastPathComponent);
                MDLURLTexture *ut=[[MDLURLTexture alloc] initWithURL:p.URLValue name:p.name];
                L(@"%*s  texel=%lu dims=(%d,%d)",d*2+2,"",(unsigned long)[ut texelDataWithTopLeftOrigin].length,ut.dimensions.x,ut.dimensions.y);
            }
            // textureSamplerValue 路线（内部已解好的）
            for(NSUInteger pi=0;pi<m.count;pi++){
                MDLMaterialProperty *p=m[pi];
                if(p.textureSamplerValue && p.textureSamplerValue.texture){
                    MDLTexture *t=p.textureSamplerValue.texture;
                    L(@"%*s%@ sampler %@ dims=(%d,%d) texel=%lu",d*2,"",m.name,p.name,
                      t.dimensions.x,t.dimensions.y,(unsigned long)[t texelDataWithTopLeftOrigin].length);
                }
            }
        }
    }
    for(MDLObject *c in o.children) walk(c,d+1);
}
int main(void){ @autoreleasepool {
    char lp[512]; snprintf(lp,sizeof(lp),"%s/mi.log",getenv("TMPDIR")?:"/tmp"); g=fopen(lp,"w"); if(!g)return 1;
    L(@"=== MDL 全面强制 pid=%d ===",getpid());
    NSString *res=[[NSBundle mainBundle] resourcePath];
    for(NSString *n in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:res error:nil]){
        if(![n hasSuffix:@".usdz"])continue;
        NSURL *u=[NSURL fileURLWithPath:[res stringByAppendingPathComponent:n]];
        L(@"--- %@ ---",n);
        @try{
            MDLAsset *a=[[MDLAsset alloc] initWithURL:u];
            L(@"MDLAsset count=%lu",(unsigned long)a.count);
            for(NSUInteger i=0;i<a.count;i++) walk([a objectAtIndex:i],1);
            // ★ 导出强制完整解析（含纹理采样）
            NSURL *tmp=[NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:@"out.obj"]];
            NSError *err=nil;
            BOOL ok=[a exportAssetToURL:tmp error:&err];
            L(@"export=%d err=%@",(int)ok,err?err.localizedDescription:@"无");
        }@catch(NSException *e){ L(@"EXC %@",e.reason); }
    }
    L(@"=== done 未崩溃 ==="); fclose(g); }
    return 0; }
