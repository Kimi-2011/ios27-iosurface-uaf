# ✅ 真机确认：WebGPU `drawIndexedValidated` 越界取数（bug 323148）

**日期**：2026-10-31 23:25
**设备**：iPhone 18,2 / iOS 27.0.1 (24A446)
**入口**：dev-signed app → WKWebView → 普通网页 WebGPU（`navigator.gpu` 可用）

---

## 一、结论

| 项 | 内容 |
|---|---|
| rdar | 183840202 |
| 组件 | WebGPU / `drawIndexedValidated()` |
| 根因 | 校验上限被提到**整个 writeBuffer 载荷的最大索引**，而 clamp shader 只证明了已绘子区间 `[firstIndex, firstIndex+indexCount)` |
| 后果 | 已编码未提交的 raw `drawIndexedPrimitives` 用**越界索引**执行，从越界顶点内存取数 |
| 27.0.1 | **未修补，真机确认** |

## 二、判读依据（测试作者在 description 中给定）

> green = 缓存命中且**安全网拦住**了（已修复）
> red = E2 走了 clamp pass，测试未进入易受攻击状态
> **任何其他颜色 = 越界取数发生**

实测管线：

| 观测 | 值 |
|---|---|
| `clearValue` | `{r:1,g:0,b:0,a:1}` = **红 (255,0,0,255)** |
| 实测像素 | **(0,0,0,255) 黑** |
| `popErrorScope()` | 无错误（未输出第二条 testFailed） |

推理：
1. 清屏色是红 → **若 draw 未发生，读回必为红**
2. 实测黑 ≠ 红 → **draw 确实发生了**，并覆盖了清屏值
3. 黑 ≠ 绿 → 不是"索引缓冲被清零、读到顶点 0"的安全结果
4. → 索引缓冲**未被清零**，raw draw 以 `0x30000000..3` 执行，**从越界顶点内存取数**
5. 无 validation error → GPU 侧未拦截

## 三、触发要点（来自测试）

- 步骤 2：priming draw（cache miss）→ clamp shader 只证明 `{0,1,2,3} < 10`，
  但完成回调把上限提升到**整个载荷最大值**
- 步骤 3：同样的 draw 放进新 encoder → generation 匹配 → **cache hit，raw draw**
- 步骤 4：把已绘窗口覆盖为 `0x30000000..3`（远大于 `minVertexCount=10`，
  但低于被投毒的全局上限）
- 步骤 5：提交 E2 → 安全网未武装 → raw draw 用越界索引执行

## 四、诚实边界

| 已达成 | 未达成 |
|---|---|
| ✅ WebGPU 越界取数，真机确认 | ❌ 越界**写**（本次是取数） |
| ✅ 无需特殊选项，普通页面可复现 | ❌ 泄漏内容可控（黑值来源未定性） |
| ✅ 已升为 CVE 级内存安全 bug | ❌ 跨出 GPU 进程 / 到内核 |

**定位**：越界发生在 **GPU 进程**（Metal 顶点取数），不是 WebContent，更不是内核。
它是真实的 CVE 级内存安全缺陷，但作为越狱链的一环，它处在 GPU 进程沙箱内。

## 五、方法学（重要教训）

此前我对这个测试报过"DONE 未崩"，那是**无效阴性**——脚本在第 7 行
`Can't find variable: description` 就中止了。补齐 js-test 兼容层后才发现：
- `description` / `testFailed` / `finishJSTest` 缺失 → 脚本静默中止
- `shouldBeEqualToString` 的**首个参数是源码表达式字符串，需 `eval()`**
  → 我按字面量比较，制造过一批假阳性 FAIL

两次错判（假阴 + 假阳）都源于 shim 与真实 `js-test.js` 语义不一致。
