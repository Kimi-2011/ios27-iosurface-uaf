# 新方向：27.2 之后公开修复的 JSC 漏洞（27.0.1 必然未修补）

**日期**：2026-10-31 23:55

## 一、方向的理由

27.2 公告只覆盖**随 27.2 发布**的修复。本地 WebKit 克隆窗口是 **2026-09-02 → 10-31**，
而 27.0.1 早于此窗口后段发布 —— 因此窗口内**还有大量「修复已公开、27.0.1 尚未吃到」的 bug**，
它们不在公告里，却附带官方回归测试。这类目标：修复公开 → 有测试 → 27.0.1 必未修补。

## 二、窗口内 JSC 安全修复（13 条，节选关键）

| bug | 日期 | 问题 | 浏览器可跑？ |
|---|---|---|---|
| 321608 | 10-29 | Stale IC watchpoints 在 `CodeBlock::jettison()` 后存活于已释放 cell（**UAF**） | ❌ 需 `$vm.gc()` + 3 个编译选项 |
| 323478 | 10-28 | FinalizationRegistry 悬垂 unregister-token key（**UAF**） | ⚠️ 见下 |
| 319303 | 09-09 | 扁平化字典上自定义 accessor 被遮蔽 → stale IC（**类型混淆**） | ❌ 需 `$vm.createStaticCustomValue` |
| 324124 | 09-14 | 模块循环导入后 DFG 折叠出过期值 | 未测 |
| 323639 | 09-09 | 数组元素清除经 libc memset 与并发标记线程竞争 | 未测 |
| 318331 | 10-29 | DirectTailCall JIT 代码 UAF | ✅ 已测，有效阴性 |

## 三、323478 实测（前置条件已验证的有效阴性）

### 3.1 获得的通用能力：在 WKWebView 里强制 GC
JSC 的弱引用/finalization 只在 **VM 让出事件循环后**处理。同步代码里做多少分配压力都不会回收。
正确做法：
```js
function bigGC(mb){ var hold=[],n=mb|0;
  for(var i=0;i<n;i++) hold.push(new Float64Array(131072));  // 每个约1MB，持住
  var got=hold.length; hold=null; return got; }
bigGC(180);
await new Promise(r=>setTimeout(r,300));   // ← 关键：让出事件循环
```
实测：token 被回收（`tokenAlive=false`），8 个清理回调全部执行（`cbFired=8`）。

### 3.2 结果：未触发，原因已定位
```
PRECOND-OK: token 已回收
falseMatches=0 (300000 次 unregister({}))
VULN=not-observed
```
**原因**：`cbFired=8` 说明回调已投递，注册桶随之被清空。
而漏洞要求持仓**仍处于 pending**（原测试在 `jsc` 中回调只被调度、不投递）。
桶被排空后不存在悬垂 key，误匹配不可能发生。

→ 在浏览器里该 bug 状态不可达。**这是前置条件已验证的阴性，不是"没跑起来"。**

## 四、下一批候选（未测，按可跑性排序）

1. **324124** 模块循环导入 → DFG 折叠过期值（可能纯 JS）
2. **323639** 数组元素清除与并发标记竞争（可能纯 JS）
3. **324692** `CString::newUninitialized`
4. **323910** Wasm BreakpointManager 返回 HashMap 内 Breakpoint* 不保证失效

筛选原则：**先看测试是否有 `$vm` / `requireOptions` 硬依赖**，再决定投入。

---

## 五、边界结论（24:05）：有内存破坏潜力的几个都需要同步 GC

窗口内 7 条真 JSC 安全修复（已剔除混入的修订号误匹配）：

| bug | 复现依赖 | 浏览器可达 |
|---|---|---|
| 321608 stale IC watchpoint UAF | `$vm.gc()` **同步** full GC + sync sweep | ❌ |
| 319303 stale IC 类型混淆 | `$vm.createStaticCustomValue()` / `$vm.toCacheableDictionary()` | ❌ |
| 318331 DirectTailCall JIT UAF | `--zeroExecutableMemoryOnFree`（需 free 后填毒） | ❌ 已实测有效阴性 |
| 323478 FinalizationRegistry 悬垂 key | 回调须**保持 pending** | ❌ 已实测：回调投递后桶被排空 |
| 324692 CString::newUninitialized | 未查 | 待定 |
| 323910 Wasm BreakpointManager | 未查 | 待定 |
| 324124 模块循环 → DFG 陈旧折叠 | 纯 JS 模块 | ✅ 可跑（但属逻辑错误） |

### 为什么 321608 在浏览器里做不到

```js
if (mode) {
    g = 2;                              // jettison FTL CodeBlock（纯 JS 可做）
    $vm.gc();                           // ← 必须【同步】：此刻 probe 栈帧仍活
    Array.prototype[Symbol("z")] = 1;   // 紧接着触发失效 watchpoint
}
```
`$vm.gc()` 必须同步插入在 `probe` 执行中。而实测表明：
**浏览器里 JSC 的弱引用处理与清扫只在 VM 让出事件循环后才发生**
（`tokenAlive` 同步轮询始终为 true，`await` 之后才变 false）。
同步循环内部无法让出 → 这个时序点在 WKWebView 里不存在。

→ 这是**实测支撑的边界**，不是未经验证的推断。

## 六、方向评价

| 优点 | 限制 |
|---|---|
| 修复公开、有官方测试、27.0.1 必未修补 | 有内存破坏潜力的都需要 `jsc` shell 的同步 GC |
| 数量可观（窗口内 7 条 JSC） | 纯 JS 可跑的几条多为逻辑错误 |
| 完全不依赖公告 | 仍需 `$vm` 才能转成内存原语 |

**结论**：这个方向能持续产出"27.0.1 未修补"的确证，
但在没有 `jsc` shell 的前提下，仍然拿不到任意读写。
