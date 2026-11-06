# iOS 27.2 安全性内容 — 整理版

> **来源**：[Apple 官方安全公告 149230](https://support.apple.com/en-us/149230)　
> **发布日期**：2026-10-26　
> **适用**：iPhone 11 及后续、iPad Pro 12.9-inch 第 4 代及后续等　
> **整理**：2026-11-01　**原始数据**：`out/advisory-27.2.json`

## 0. README（10 行速览）

1. 本文是 Apple 官方 iOS 27.2 安全公告的结构化中文化整理，**141 条记录 / 163 个 CVE / 65 个组件**。
2. 这些漏洞在 **iOS 27.0.1 上全部存在**——公告只列已修复项。
3. 其中 **24 条**直接影响内核内存或可执行代码，是越狱研究（S2 内核内存破坏）的一手目标清单。
4. 每条含四要素：**组件 / 影响 / 修复方式 / CVE 编号**。
5. **修复方式**是最强的技术先验：它决定补丁在汇编层的形态。
6. `bounds checking`/`input validation` → 新增 `cmp`+`b.cond`，静态差分可见。
7. `memory management`/`locking` → 新增函数调用，**条件分支差分看不见**，必须按调用目标差分。
8. 第 4 节列出与本项目**设备实测可达面**的交叉——只有可达的组件才是真靶子。
9. 第 5 节是已定位到补丁点的两个组件（AVE2 / DCP）。
10. CVE 编号可直接检索公开分析；Apple 通常 90 天后公开细节。

---

## 1. 统计摘要

| 指标 | 值 |
|---|---|
| 记录数 | 141 |
| 唯一 CVE | 163 |
| 受影响组件 | 65 |
| 影响内核内存/代码执行 | **24 条** |
| 影响进程内存 | 31 条 |
| 拒绝服务类 | 10 条 |
| 其它 | 76 条 |
| 涉及内核内存的唯一 CVE | **31 个** |

### 1.1 按修复方式分布

| 修复方式 | 条数 | 汇编层形态 | 静态差分可见性 |
|---|---:|---|---|
| 边界检查 | 39 | ✅ `cmp`+`b.hi` | — |
| 其它 | 23 | — | — |
| 输入校验 | 19 | ✅ 校验分支 | — |
| 内存管理(UAF) | 15 | ❌ 新增 `bl` 调用 | — |
| 状态管理 | 14 | ⚠️ 混合 | — |
| 内存处理 | 12 | ⚠️ 混合 | — |
| 增强校验 | 9 | ✅ 分支 | — |
| 状态处理 | 4 | ⚠️ 混合 | — |
| 数据脱敏 | 2 | — | — |
| 加锁(竞态) | 2 | ❌ 新增 `bl` 调用 | — |
| 访问控制 | 2 | ✅ 分支 | — |

---

## 2. 高价值目标（影响内核内存 / 代码执行）

> 这 24 条是本项目 S2 攻关的直接靶子。

| 组件 | 影响 | 修复方式 | CVE |
|---|---|---|---|
| **AVEVideoEncoder** | An app may be able to cause unexpected system termination or read kernel memory | 输入校验 | CVE-2026-112466 |
| **AVEVideoEncoder** | An app may be able to cause unexpected system termination or corrupt kernel memory | 边界检查 | CVE-2026-112470, CVE-2026-112469, CVE-2026-112468 |
| **AVEVideoEncoder** | An app may be able to cause unexpected system termination or corrupt kernel memory | 输入校验 | CVE-2026-112689 |
| **Apple Neural Engine** | An app may be able to cause unexpected system termination or corrupt kernel memory | 边界检查 | CVE-2026-112696 |
| **Apple Neural Engine** | An app may be able to cause unexpected system termination or write kernel memory | 边界检查 | CVE-2026-84494 |
| **Compression** | An app may be able to disclose kernel memory | 内存处理 | CVE-2026-113910 |
| **CoreAudio** | An app may be able to cause unexpected system termination or corrupt kernel memory | 输入校验 | CVE-2026-86969 |
| **CoreMedia** | Parsing a file may lead to an unexpected app termination or arbitrary code execution | 内存处理 | CVE-2026-112688 |
| **IOHIDFamily** | An attacker may be able to cause unexpected system termination or read kernel memory | 边界检查 | CVE-2026-112515 |
| **IOMobileFrameBuffer** | An app may be able to cause unexpected system termination or corrupt kernel memory | 状态处理 | CVE-2026-112459 |
| **IOStorageFamily** | An app may be able to cause unexpected system termination or read kernel memory | 边界检查 | CVE-2026-112554 |
| **IOSurface** | An app may be able to cause unexpected system termination or corrupt kernel memory | 加锁(竞态) | CVE-2026-112477 |
| **Kernel** | An app may be able to cause unexpected system termination or write kernel memory | 边界检查 | CVE-2026-112507 |
| **Kernel** | An attacker may be able to cause unexpected system termination or corrupt kernel memory | 内存管理(UAF) | CVE-2026-112514 |
| **Kernel** | An app may be able to cause unexpected system termination or corrupt kernel memory | 内存管理(UAF) | CVE-2026-112517 |
| **Kernel** | An app may be able to determine kernel memory layout | 状态管理 | CVE-2026-112665 |
| **Kernel** | An app may be able to cause unexpected system termination or corrupt kernel memory | 内存管理(UAF) | CVE-2026-65350, CVE-2026-112679 |
| **Kernel** | An app may be able to cause unexpected system termination or write kernel memory | 内存管理(UAF) | CVE-2026-84495, CVE-2026-112474 |
| **USB** | A malicious USB device may be able to cause unexpected system termination or read kernel memory | 边界检查 | CVE-2026-112479 |
| **WebKit** | Processing maliciously crafted web content may lead to arbitrary code execution | 内存处理 | CVE-2026-112659 |
| **WebKit** | Processing maliciously crafted web content may lead to arbitrary code execution | 内存管理(UAF) | CVE-2026-112697, CVE-2026-112655, CVE-2026-112651, CVE-2026-112623 |
| **WebKit Canvas** | Processing maliciously crafted web content may lead to arbitrary code execution | 内存管理(UAF) | CVE-2026-112637 |
| **WebKit JavaScript Bindings** | Processing maliciously crafted web content may lead to arbitrary code execution | 内存管理(UAF) | CVE-2026-112626 |
| **WebKit Process Model** | Processing maliciously crafted web content may lead to arbitrary code execution | 内存管理(UAF) | CVE-2026-112639 |

---

## 3. 全组件清单（按严重度）

### 🔴 AVEVideoEncoder　（4 条）

- **CVE-2026-112689**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：An out-of-bounds write issue was addressed with improved input validation.
- **CVE-2026-112470, CVE-2026-112469, CVE-2026-112468**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-112466**
  - 影响：An app may be able to cause unexpected system termination or read kernel memory
  - 修复：An out-of-bounds read was addressed with improved input validation.
- **CVE-2026-112705**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🔴 Apple Neural Engine　（2 条）

- **CVE-2026-112696**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-84494**
  - 影响：An app may be able to cause unexpected system termination or write kernel memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🔴 Compression　（1 条）

- **CVE-2026-113910**
  - 影响：An app may be able to disclose kernel memory
  - 修复：A memory initialization issue was addressed with improved memory handling.

### 🔴 CoreAudio　（5 条）

- **CVE-2026-86969**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：An out-of-bounds write was addressed with improved input validation.
- **CVE-2026-113912**
  - 影响：Processing a maliciously crafted media file may lead to unexpected app termination or corrupt process memory
  - 修复：An out-of-bounds access issue was addressed with improved bounds checking.
- **CVE-2026-113907**
  - 影响：An app may be able to cause unexpected system termination or corrupt process memory
  - 修复：A buffer overflow issue was addressed with improved memory handling.
- **CVE-2026-86972**
  - 影响：Processing a maliciously crafted audio file may lead to memory corruption
  - 修复：A buffer overflow was addressed with improved size validation.
- **CVE-2026-112638**
  - 影响：An attacker in radio range may be able to cause unexpected system termination
  - 修复：A heap buffer overflow was addressed with improved bounds checking.

### 🔴 CoreMedia　（4 条）

- **CVE-2026-112688**
  - 影响：Parsing a file may lead to an unexpected app termination or arbitrary code execution
  - 修复：A memory corruption issue was addressed with improved memory handling.
- **CVE-2026-86992**
  - 影响：Processing a maliciously crafted video file may lead to unexpected app termination
  - 修复：The issue was addressed with improved memory handling.
- **CVE-2026-112706**
  - 影响：An app may be able to access sensitive user data
  - 修复：A permissions issue was addressed with additional restrictions.
- **CVE-2026-86990**
  - 影响：A malicious app may be able to access the camera without user permission
  - 修复：An access issue was addressed with improved access restrictions.

### 🔴 IOHIDFamily　（1 条）

- **CVE-2026-112515**
  - 影响：An attacker may be able to cause unexpected system termination or read kernel memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### 🔴 IOMobileFrameBuffer　（1 条）

- **CVE-2026-112459**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：A race condition was addressed with improved state handling.

### 🔴 IOStorageFamily　（1 条）

- **CVE-2026-112554**
  - 影响：An app may be able to cause unexpected system termination or read kernel memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### 🔴 IOSurface　（1 条）

- **CVE-2026-112477**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：A race condition was addressed with improved locking.

### 🔴 Kernel　（14 条）

- **CVE-2026-65350, CVE-2026-112679**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-112517**
  - 影响：An app may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：A use after free issue was addressed with improved memory management.
- **CVE-2026-112514**
  - 影响：An attacker may be able to cause unexpected system termination or corrupt kernel memory
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-112507**
  - 影响：An app may be able to cause unexpected system termination or write kernel memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-84495, CVE-2026-112474**
  - 影响：An app may be able to cause unexpected system termination or write kernel memory
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-112665**
  - 影响：An app may be able to determine kernel memory layout
  - 修复：An information disclosure issue was addressed with improved state management.
- **CVE-2026-112606**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：A type confusion issue was addressed with improved memory handling.
- **CVE-2026-112516**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-112698**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：The issue was addressed with improved memory handling.
- **CVE-2026-112501**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：A race condition was addressed with improved state handling.
- **CVE-2026-112476**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112576**
  - 影响：An app may be able to cause unexpected changes to copy-on-write memory
  - 修复：A memory integrity issue was addressed with improved handling of copy-on-write pages.
- **CVE-2026-112624**
  - 影响：An app may be able to bypass Privacy preferences
  - 修复：This issue was addressed with improved checks.
- **CVE-2026-112522**
  - 影响：Processing a maliciously crafted file may lead to unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🔴 USB　（1 条）

- **CVE-2026-112479**
  - 影响：A malicious USB device may be able to cause unexpected system termination or read kernel memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### 🔴 WebKit　（16 条）

- **CVE-2026-112697, CVE-2026-112655, CVE-2026-112651, CVE-2026-112623**
  - 影响：Processing maliciously crafted web content may lead to arbitrary code execution
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-112659**
  - 影响：Processing maliciously crafted web content may lead to arbitrary code execution
  - 修复：A type confusion issue was addressed with improved memory handling.
- **CVE-2026-86974**
  - 影响：Processing maliciously crafted web content may lead to memory corruption
  - 修复：A type confusion issue was addressed with improved checks.
- **CVE-2026-112699, CVE-2026-112680**
  - 影响：Processing maliciously crafted web content may result in the disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112640**
  - 影响：Processing maliciously crafted web content may lead to memory corruption
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-113949**
  - 影响：Processing maliciously crafted web content may lead to memory corruption
  - 修复：A type confusion issue was addressed with improved state management.
- **CVE-2026-113904, CVE-2026-112599**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process crash
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-86986, CVE-2026-112693**
  - 影响：Processing maliciously crafted web content may lead to an unexpected Safari crash
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-86985**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process crash
  - 修复：This issue was addressed with improved input validation.
- **CVE-2026-112686**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process termination
  - 修复：A race condition was addressed with improved locking.
- **CVE-2026-112684**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process crash
  - 修复：This issue was addressed through improved state management.
- **CVE-2026-112673**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process termination
  - 修复：A type confusion issue was addressed with improved state handling.
- **CVE-2026-112669**
  - 影响：Processing maliciously crafted web content may lead to an unexpected Safari crash
  - 修复：A race condition was addressed with improved state handling.
- **CVE-2026-112695, CVE-2026-112666, CVE-2026-112654, CVE-2026-112653, CVE-2026-112615**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process termination
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-113952**
  - 影响：A website may be able to use a media format that should be restricted in Lockdown Mode
  - 修复：A logic issue was addressed with improved checks.
- **CVE-2026-113903**
  - 影响：Processing maliciously crafted web content may lead to unexpected memory modification
  - 修复：A use-after-free issue was addressed with improved memory management.

### 🔴 WebKit Canvas　（1 条）

- **CVE-2026-112637**
  - 影响：Processing maliciously crafted web content may lead to arbitrary code execution
  - 修复：A use-after-free issue was addressed with improved memory management.

### 🔴 WebKit JavaScript Bindings　（1 条）

- **CVE-2026-112626**
  - 影响：Processing maliciously crafted web content may lead to arbitrary code execution
  - 修复：A use-after-free issue was addressed with improved memory management.

### 🔴 WebKit Process Model　（2 条）

- **CVE-2026-112639**
  - 影响：Processing maliciously crafted web content may lead to arbitrary code execution
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-113897**
  - 影响：A remote attacker may be able to break out of Web Content sandbox
  - 修复：This issue was addressed by removing the vulnerable code.

### 🟠 AppleAVD　（3 条）

- **CVE-2026-112415**
  - 影响：An app may be able to cause unexpected system termination or corrupt process memory
  - 修复：An out-of-bounds write was addressed with improved input validation.
- **CVE-2026-112454**
  - 影响：Processing a maliciously crafted video file may lead to unexpected app termination or corrupt process memory
  - 修复：The issue was addressed with improved memory handling.
- **CVE-2026-112416**
  - 影响：Processing a maliciously crafted video file may lead to unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 Calendar　（2 条）

- **CVE-2026-112619**
  - 影响：Processing a maliciously crafted calendar invitation may lead to memory corruption
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-112678**
  - 影响：An app may be able to access sensitive user data
  - 修复：A permissions issue was addressed with additional restrictions.

### 🟠 ColorSync　（1 条）

- **CVE-2026-86988**
  - 影响：Processing a maliciously crafted image may result in disclosure of process memory
  - 修复：The issue was addressed with improved checks.

### 🟠 CoreGraphics　（2 条）

- **CVE-2026-112611, CVE-2026-112610**
  - 影响：Processing a maliciously crafted PDF file may lead to memory corruption
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-113950**
  - 影响：Processing a maliciously crafted font may lead to unexpected app termination or corrupt process memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 CoreText　（1 条）

- **CVE-2026-112656**
  - 影响：Processing a maliciously crafted font may result in the disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### 🟠 FontParser　（4 条）

- **CVE-2026-86970**
  - 影响：Processing a maliciously crafted font may result in the disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved input validation.
- **CVE-2026-112683**
  - 影响：Processing a maliciously crafted font may lead to unexpected app termination or corrupt process memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-112642**
  - 影响：Processing a maliciously crafted font may result in the disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112432**
  - 影响：An app may be able to access sensitive user data
  - 修复：A logging issue was addressed with improved data redaction.

### 🟠 IOKit　（1 条）

- **CVE-2026-65385**
  - 影响：A buffer overflow may result in memory corruption and unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 ImageIO　（7 条）

- **CVE-2026-112571**
  - 影响：Processing a maliciously crafted image may result in disclosure of process memory
  - 修复：A memory initialization issue was addressed with improved memory handling.
- **CVE-2026-112561, CVE-2026-112627**
  - 影响：Processing a maliciously crafted image may result in disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112488**
  - 影响：Processing a maliciously crafted image may corrupt process memory
  - 修复：A buffer overflow issue was addressed with improved memory handling.
- **CVE-2026-112632, CVE-2026-112630**
  - 影响：Processing a maliciously crafted image may result in disclosure of process memory
  - 修复：An uninitialized memory issue was addressed with improved memory handling.
- **CVE-2026-112625**
  - 影响：Processing a maliciously crafted image may result in memory corruption
  - 修复：An integer underflow was addressed with improved input validation.
- **CVE-2026-112634, CVE-2026-112629**
  - 影响：Processing a maliciously crafted image may lead to unexpected app termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112633, CVE-2026-112614**
  - 影响：Processing a maliciously crafted image may lead to unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 LinkPresentation　（1 条）

- **CVE-2026-112621**
  - 影响：Processing a maliciously crafted image may result in memory corruption
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 MediaRemote　（1 条）

- **CVE-2026-112687**
  - 影响：An attacker on the local network may be able to cause unexpected system termination or corrupt process memory
  - 修复：This issue was addressed by removing the vulnerable code.

### 🟠 Model I/O　（5 条）

- **CVE-2026-112565, CVE-2026-112449**
  - 影响：Processing a maliciously crafted 3D model may lead to memory corruption
  - 修复：An integer overflow was addressed with improved input validation.
- **CVE-2026-112485**
  - 影响：Processing a maliciously crafted 3D model may lead to memory corruption
  - 修复：The issue was addressed with improved memory handling.
- **CVE-2026-112461**
  - 影响：Processing a maliciously crafted 3D model may lead to memory corruption
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.
- **CVE-2026-112413**
  - 影响：Processing a maliciously crafted file may lead to unexpected app termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112486**
  - 影响：Processing a 3D model may lead to unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 SceneKit　（4 条）

- **CVE-2026-112425**
  - 影响：Processing a 3D model may result in disclosure of process memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112423**
  - 影响：Processing a maliciously crafted file may lead to a denial-of-service or potentially disclose memory contents
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112464**
  - 影响：Processing a maliciously crafted file may lead to heap corruption
  - 修复：An out-of-bounds write issue was addressed with improved input validation.
- **CVE-2026-86991**
  - 影响：Processing a maliciously crafted file may lead to unexpected process termination
  - 修复：A buffer overflow was addressed with improved bounds checking.

### 🟠 SpringBoard　（1 条）

- **CVE-2026-112646**
  - 影响：An app may be able to cause unexpected system termination or corrupt process memory
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### 🟠 Wi-Fi　（3 条）

- **CVE-2026-113909**
  - 影响：An attacker in physical proximity may be able to corrupt process memory
  - 修复：A memory corruption issue was addressed with improved input validation.
- **CVE-2026-112622**
  - 影响：An attacker in radio range may be able to cause unexpected system termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.
- **CVE-2026-112620**
  - 影响：An attacker in a privileged network position may be able to cause a denial-of-service
  - 修复：A denial-of-service issue was addressed with improved input validation.

### 🟡 HomeKit　（2 条）

- **CVE-2026-112596**
  - 影响：Processing a maliciously crafted video file may lead to unexpected system termination
  - 修复：An integer overflow was addressed with improved bounds checking.
- **CVE-2026-86978**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with improved checks.

### 🟡 SwiftUI　（1 条）

- **CVE-2026-112691**
  - 影响：An app may be able to cause unexpected system termination
  - 修复：An out-of-bounds write issue was addressed with improved input validation.

### ⚪ Accelerate Framework　（1 条）

- **CVE-2026-86971**
  - 影响：Processing a maliciously crafted image may lead to unexpected app termination
  - 修复：An out-of-bounds write issue was addressed with improved bounds checking.

### ⚪ AccessorySetupKit　（1 条）

- **CVE-2026-84493**
  - 影响：A malicious app may be able to access Bluetooth without user consent
  - 修复：An authentication issue was addressed with improved state management.

### ⚪ Accounts　（3 条）

- **CVE-2026-113898**
  - 影响：A malicious application may be able to bypass Privacy preferences
  - 修复：A logging issue was addressed with improved data redaction.
- **CVE-2026-112446**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with additional entitlement checks.
- **CVE-2026-112612**
  - 影响：An attacker with physical access to a trust-paired device may be able to read and write arbitrary files
  - 修复：A path handling issue was addressed with improved validation.

### ⚪ App Intents　（1 条）

- **CVE-2026-112692**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with additional entitlement checks.

### ⚪ App Store　（2 条）

- **CVE-2026-113914**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.
- **CVE-2026-112690**
  - 影响：A remote attacker may be able to break out of the WebContent sandbox
  - 修复：This issue was addressed with improved input validation.

### ⚪ Apple Intelligence　（1 条）

- **CVE-2026-86987**
  - 影响：A remote attacker may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved entitlement checks.

### ⚪ Audio　（1 条）

- **CVE-2026-112546**
  - 影响：Processing a maliciously crafted file may lead to unexpected app termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### ⚪ Bluetooth　（1 条）

- **CVE-2026-112566, CVE-2026-113906**
  - 影响：An attacker in physical proximity may be able to cause a denial-of-service
  - 修复：A null pointer dereference was addressed with improved validation.

### ⚪ CloudKit　（1 条）

- **CVE-2026-112701**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Contacts　（1 条）

- **CVE-2026-113908**
  - 影响：An app may be able to access sensitive user data
  - 修复：A privacy issue was addressed by removing sensitive data.

### ⚪ FileProvider　（1 条）

- **CVE-2026-113896**
  - 影响：An app may be able to access sensitive user data
  - 修复：A race condition was addressed with additional validation.

### ⚪ Files　（1 条）

- **CVE-2026-112618**
  - 影响：An app may be able to access sensitive user data
  - 修复：An access issue was addressed with improved access restrictions.

### ⚪ HFS　（1 条）

- **CVE-2026-112456**
  - 影响：Processing a maliciously crafted file may lead to heap corruption
  - 修复：An out-of-bounds write issue was addressed with improved input validation.

### ⚪ Heimdal　（1 条）

- **CVE-2026-112518**
  - 影响：An attacker in a privileged network position may be able to impersonate a Kerberos KDC
  - 修复：An issue with signature validation was addressed with improved checks.

### ⚪ Mail　（3 条）

- **CVE-2026-112500**
  - 影响：The user's original email address may be leaked when using the Hide My Email feature
  - 修复：A logic issue was addressed with improved restrictions.
- **CVE-2026-112671**
  - 影响：A remote attacker may be able to cause a denial-of-service
  - 修复：A resource exhaustion issue was addressed with improved input validation.
- **CVE-2026-112414**
  - 影响：Processing a maliciously crafted message may lead to a denial-of-service
  - 修复：A stack overflow was addressed with improved input validation.

### ⚪ Maps　（2 条）

- **CVE-2026-112707**
  - 影响：An app may be able to identify what other apps a user has installed
  - 修复：A privacy issue was addressed by moving sensitive data to a protected location.
- **CVE-2026-112607**
  - 影响：A remote attacker may be able to leak memory
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### ⚪ MediaAnalysis　（1 条）

- **CVE-2026-113915**
  - 影响：An app may be able to access sensitive user data
  - 修复：A race condition was addressed with additional validation.

### ⚪ Messages　（1 条）

- **CVE-2026-112682**
  - 影响：A remote attacker may be able to cause unexpected app termination
  - 修复：An input validation issue was addressed with improved input validation.

### ⚪ MobileGestalt　（1 条）

- **CVE-2026-86989**
  - 影响：An app may be able to fingerprint the user
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Photos Storage　（3 条）

- **CVE-2026-65397**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.
- **CVE-2026-112676**
  - 影响：An app may be able to access a user's Photos Library
  - 修复：This issue was addressed with additional entitlement checks.
- **CVE-2026-112660**
  - 影响：An app may be able to bypass certain Privacy preferences
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Power Management　（1 条）

- **CVE-2026-112681**
  - 影响：An app may be able to fingerprint the user
  - 修复：This issue was addressed with additional entitlement checks.

### ⚪ Quick Look　（1 条）

- **CVE-2026-86925**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ RealityKit　（1 条）

- **CVE-2026-112491**
  - 影响：Processing a maliciously crafted file may lead to unexpected app termination
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

### ⚪ ReplayKit　（1 条）

- **CVE-2026-112547**
  - 影响：An app may be able to access sensitive user data
  - 修复：A type confusion issue was addressed with improved checks.

### ⚪ Safety Check　（1 条）

- **CVE-2026-112609**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with improved checks.

### ⚪ Screen Time　（1 条）

- **CVE-2026-112616**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved access control.

### ⚪ Security　（2 条）

- **CVE-2026-113913**
  - 影响：Processing web content may disclose sensitive information
  - 修复：An input validation issue was addressed with improved input validation.
- **CVE-2026-112652**
  - 影响：An malicious app may be able to bypass certificate validation
  - 修复：A logic issue was addressed with improved state management.

### ⚪ Shortcuts　（1 条）

- **CVE-2026-112559, CVE-2026-112455**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Siri　（2 条）

- **CVE-2026-112658**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with improved input validation.
- **CVE-2026-112685**
  - 影响：An app may be able to access sensitive user data
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Spotlight　（3 条）

- **CVE-2022-26704**
  - 影响：An app may be able to gain elevated privileges
  - 修复：A validation issue existed in the handling of symlinks. This issue was addressed with improved validation of symlinks.
- **CVE-2026-112567**
  - 影响：A malicious application may be able to bypass Privacy preferences
  - 修复：This issue was addressed with improved checks.
- **CVE-2026-112628**
  - 影响：An app may be able to access sensitive user data
  - 修复：This issue was addressed with improved data access restriction.

### ⚪ System Preferences　（1 条）

- **CVE-2026-86968**
  - 影响：A malicious app may be able to access restricted system interfaces or launder launch attribution
  - 修复：An access issue was addressed with improved access control.

### ⚪ TextKit　（1 条）

- **CVE-2026-84605**
  - 影响：An app may be able to read the device's name
  - 修复：An authorization issue was addressed with improved state management.

### ⚪ Thread　（1 条）

- **CVE-2026-112595**
  - 影响：An attacker in physical proximity may be able to craft malicious network traffic to gain access to a Thread network
  - 修复：This issue was addressed with improved authentication.

### ⚪ WebRTC　（2 条）

- **CVE-2026-113901**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process crash
  - 修复：A use-after-free issue was addressed with improved memory management.
- **CVE-2026-86973**
  - 影响：Processing maliciously crafted web content may lead to an unexpected process crash
  - 修复：An out-of-bounds read was addressed with improved bounds checking.

---

## 4. 与本项目设备实测可达面的交叉

> 可达性来自 **iPhone 17 Pro Max / iOS 27.0.1 真机实测**：1,469 个 IOKit 服务逐个 `IOServiceOpen`（type 0..3），
> 结果 **85 个实例 / 17 个类**可打开。详见 `out/REACH-MEASURED.md`。

> **只有可达的组件才是真靶子。**

| 公告组件 | 设备实测可达 | 本项目审计状态 |
|---|---|---|
| **AVEVideoEncoder** | — 经 VideoToolbox，非 IOKit open | **补丁已定位**（3 个具名检查函数） |
| **Apple Neural Engine** | ✅ H1xANELoadBalancer type=1 | 审过；已证 26 个 selector handler 两版逐指令相同 → 补丁在驱动内部 |
| **Compression** | — 未测 | 未审 |
| **CoreAudio** | — 未测 | 未审 |
| **CoreMedia** | — 未测 | 未审 |
| **IOHIDFamily** | ✅ AppleSPUHIDDriver×27 / IOHIDEventDriver | 未审 |
| **IOMobileFrameBuffer** | ✅ AppleCLCD2 type=0,1,2,3 | **补丁已定位**（双管状态机全套） |
| **IOStorageFamily** | ⚠️ AppleEmbeddedNVMeTempSensor type=2 | 未审 |
| **IOSurface** | ✅ type=0 | 只审了属性路径；**竞态/加锁类未覆盖** |
| **Kernel** | ✅ 系统调用面 | 159 候选已三分类；**因 dChk 盲区，结论需重做** |
| **USB** | ⚠️ 未测 | 未审 |
| **WebKit** | ✅ WKWebView（S1 已有） | 未审 |
| **WebKit Canvas** | — 未测 | 未审 |
| **WebKit JavaScript Bindings** | — 未测 | 未审 |
| **WebKit Process Model** | — 未测 | 未审 |

### 4.1 关键结论

1. **可达性不是统一拦截**：`type=0` 只覆盖 7% 的可达面（6 vs 85），最易命中的是 `type=2`。
2. **实测可达且公告点名的真靶子**：`IOMobileFrameBuffer`(AppleCLCD2)、`IOSurface`、`IOHIDFamily`、`Apple Neural Engine`、`Kernel`。
3. **修复方式决定方法**：`memory management`/`locking` 类共 17 条，条件分支差分（dChk）**看不见**。本项目早期「无内核内存破坏原语」的结论因此不成立。
4. 组件名 ≠ kext 名。`IOMobileFrameBuffer`→`AppleMobileDispH18P-DCP`、`Apple Neural Engine`→`AppleH16ANEInterface`、`IOStorageFamily`→`IONVMeFamily`。

---

## 5. 已定位到补丁点的组件

### 5.1 AVEVideoEncoder（5 个 CVE，OOB write → 写内核内存）

27.0.1 → 27.2 新增三个**具名检查函数**（原始字节计数 0→1）：

| 符号 | 27.2 函数 VA | 长度 |
|---|---|---|
| `AVE_HEVC_CheckVPSExtBounds` | `0xfffffe00087c5bb8` | 310 |
| `AVE_Client_CheckMCTFInfo` | `0xfffffe00087c857c` | 737 |
| `AVE_Client_CheckLRMEInfo` | `0xfffffe00087c9100` | 571 |

断言字面表达式（bounds checking 的真身）：

```
pInfo->saHEVC_SPS[i].log2_max_pic_order_cnt_lsb_minus4 <= 12
pVPS->layer_id_in_nuh[i] < 64
pVPS->vps_max_layers_minus1 < 64
pInfo->saHEVC_RPS.strps.num_short_term_ref_pic_sets < 65 && (long_term_sps + long_term_pics) <= 16
pInfo->saHEVC_PPS[i].num_tile_columns_minus1 <= 256 && num_tile_rows_minus1 <= 256
pInfo->uPropCfg.sHEVC.iMCTFStrengthLevelNum >= 0 && <= min(2,64)
num_ref_frame <= max(16,15)
```

**用户可控输入**：MCTF/LRME 的 `x3` 客户端配置结构块——`[+0x68]-1<2`、`[+0x510]<8`、`[+0x768]<8`、`[+0x1888]≤6`、`[+0x27f8]≤15`、`[+0x2c10]≤16`。

**已否定的假设**：`num_tile_columns_minus1`/layer-set 那条线 27.0.1 已有等价上界检查，不通过本次补丁。

### 5.2 IOMobileFrameBuffer（1 个 CVE，race condition / 状态处理）

27.0.1 → 27.2 新增整套**双管（dual-pipe）配对状态机**：

| 符号 | 27.0.1 | 27.2 |
|---|---:|---:|
| `establish_dual_pipe_pairing` | 0 | 1 |
| `teardown_dual_pipe_pairing` | 0 | 1 |
| `establish_dual_pipe_shim_state` | 0 | 1 |
| `dual pipe: rejected swap_start on secondary fb` | 0 | 1 |
| `AED %s: peer pipe index %u invalid` | 0 | 1 |

可达性已实测：`AppleCLCD2` 用 **type 0/1/2/3 全部能打开**。

---

## 6. 数据来源与可复现性

| 产物 | 说明 |
|---|---|
| `out/advisory-27.2.json` | 结构化原始数据（141 条） |
| `out/ADVISORY-iOS-27.2.md` | 本文 |
| `out/reach.json` / `out/REACH-MEASURED.md` | 设备实测可达面 |
| `out/AVE2-PATCH-LOCATED.md` | AVE2 补丁定位细节 |
| `out/kc.27.0.1.full` / `out/kc.27.2.ga.full` | 双版本内核映像（已解压） |
| `out/v2701/` `out/v272/` | 8 个 kext 的双版本对照 |

抓取方式：`curl -sL https://support.apple.com/en-us/149230` → HTML 去标签 → 按 `组件 / Available for / Impact / Description / CVE` 结构解析。
注意 `WebKit Bugzilla:` 行会插在 Description 与 CVE 之间，解析器需跨过它继续收集 CVE，否则会漏掉 22 条。
