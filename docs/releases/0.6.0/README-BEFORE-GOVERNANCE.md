# 文档治理前的README快照

> Archived；2026-10-23治理前快照。下文的“当前/未真机”保留当时措辞，今日状态从 [验证索引](../../testing/CURRENT-STATUS.md) 获取。

# Android 代理证据诊断

独立 Android 工程，当前版本 **0.6.0**。目录保留导入时的 `0.1.0-source` 名称；当前版本以应用构建配置为准。它不是现有 Clash/Karing/sing-box 客户端的续写。

目标是：在不占用 Android VPN 槽位、不申请 root、不安装 CA 的条件下，为**本应用主动发起的实验请求**留下可复核的证据。探测成功不等于“全机绝无泄露”。

## 当前实现

用户已确认 [产品与开发基线](../../product/PRODUCT-SPEC.md)。0.6.0 增加网站分层诊断、自动网络画像、手机内置回环实验和失败复核，并修复超时与冲突建议问题。详见 [深度诊断](../../specs/NETWORK-DEEP-DIAGNOSTICS.md)、[本版验证](REVIEW.md) 与 [真机指南](TEST-GUIDE.md)。继续跳过模拟器，实体手机验收由用户执行。

- 网站入口支持 ChatGPT 和自定义 HTTPS URL，DNS / 连接 / TLS / HTTP / 正文分层记录。默认 GET、正常 TLS 验证、有界正文、暂时错误最多复核一次，不需要回显服务或预期出口 IP。
- Android 网络画像包括可见网络、接口、路由、地址、DNS、MTU、Private DNS、HTTP代理/PAC与系统能力。内置临时回环正常/超时/拒连实验，无需外部运行环境；可选自动执行当前 DNS 的 A/AAAA × UDP/TCP 四项。

- 中文 Material 3 Views 界面，Android 10 / API 29 起；日间/夜间主题、持久字段标签、字段旁错误、标准导航/按钮/卡片/对话框。包含 Material Components 1.13.0 及 AndroidX UI 依赖，无广告或遥测 SDK。
- 快速检查无需填写：默认检查系统对 `example.com` 的解析；点击并确认具体目标后才联网。公共 DNS 对照需要另行勾选明文 UDP/TCP，不会把所选公共服务误称为系统当前解析器。
- 概览、测试、修复采用三个稳定入口；报告是检查详情子页，返回原入口。概览说明功能与检查范围；专业测试按系统 DNS、DNS 连通对照、HTTPS 出口核验选择场景，只填配置不自动执行。未启用模块收起字段，错误定位到字段。
- 结果先显示系统 DNS、UDP、TCP、HTTPS 四项状态与下一步，再展开详细证据；明确区分未测、错误、响应截断、返回地址与策略匹配。
- 专业填写指南内置于应用，文档提供此次用户试测报告的限定解读；不会从脱敏占位符猜测域名、地址或故障根因。
- DNS 修复中心：本机读取小于等于 256 KiB 的 Mihomo YAML，审查结构，按解析器方案生成逐项修改预览，保存新副本后有界读回并核对 SHA-256 与结构。无法读回时仅标“已写入但未核对”，不允许冒充成功核验。保留原文件、节点、规则及未覆盖的 DNS 分流；不下载订阅、不直接控制客户端。
- 系统 DNS 辅助配置：复制所选 Private DNS 主机名，打开系统网络/VPN设置，由用户确认；不申请特权写设置。
- 保存当前实测为基线，按原计划再次确认后复测，比较可用性并导出双份脱敏/完整证据。网络变化、取消、缺失和演示数据不冒充改善。
- 可选系统 DNS 查询，保存地址、耗时及有限诊断码（DNS 响应码、Android resolver 错误、errno、固定异常类别），不记录异常原文；仍未知实际解析器、线上协议和缓存状态。
- 新增可独立运行的原始 DNS UDP / TCP 查询：指定数字 IPv4 / IPv6 目标、端口和 A / AAAA，逐协议记录响应码、截断、地址、耗时与错误。默认每项一次；专家可显式允许限定错误追加一次。固定 500 ms 等待计入原总预算，记录所有尝试，保留首次失败，不自动换目标或从 UDP 回退 TCP。
- HTTPS 回显请求：正常系统 TLS/主机名验证、不跟随重定向、严格 4 KiB JSON 契约、随机请求 ID、防缓存、关闭连接复用。
- 各项证据采用五态模型：符合、违反、观察不足、未执行、不适用。HTTPS 来源 IP 对照用户明确输入的列表；“不适用”用于明确排除的 IPv6 专项。
- 运行前后网络快照、VPN 能力、Private DNS、链路地址、系统配置的 DNS 地址；记录观察到的网络变化。
- 取消与有界等待：原有探测总预算 20 秒，启用原始 DNS 后总预算 60 秒；原始 DNS 每项默认 8 秒绝对截止，含连接与读取。单运行槽位，平台操作若未释放，禁止再次启动。
- 当前报告、一个对照基线、输入草稿和修复配置仅保留在进程内；用户主动选择导出。
- 完全离线、显著标注的虚构演示。它不是实测。
- 表单旋转后在同一进程内保留；导出 JSON schema 2，新增字段同样默认脱敏。

## 不包含

全机抓包、其他应用归属、VPN 转发、QUIC/STUN/WebRTC、HTTPS 强制 IPv6 及外层路径证明、直接代理控制、主动绑定底层网络、故障注入、DNS 加密路径证明、远程订阅读取、sing-box JSON 修复和自动漏洞判定。

用户要求中的全面评估尚未全部覆盖。本版是有清晰证据边界的第一阶段工具，后续实验见 [覆盖矩阵](../../testing/COVERAGE.md)。

## 构建

0.6.0 本地450项通过，0失败/跳过，Lint0错误/1提示。明细见 `verification/v0.6.0/verification-summary.json`；没有执行本版模拟器或实体手机检查。

需要 JDK 17、Android SDK Platform 35、Build Tools 35.0.0 和网络可用的 Google/Maven 仓库。当前结果见 [0.6.0 验证](REVIEW.md)；旧版报告保留历史记录。

1. 安装官方 Android Studio，使用 SDK Manager 安装上述 SDK；阅读并接受其许可。
2. 用 Android Studio 打开本目录，或设置 `ANDROID_HOME` 指向 SDK。
3. 执行：

```sh
./gradlew -I qa/include-tests.init.gradle :core:test :app:assembleDebug :app:lintDebug :app:testDebugUnitTest
```

Windows：

```bat
gradlew.bat -I qa/include-tests.init.gradle :core:test :app:assembleDebug :app:lintDebug :app:testDebugUnitTest
```

APK 输出：`app/build/outputs/apk/debug/app-debug.apk`。这是调试签名 APK，不是正式发布签名。工具不会自动安装到手机。

纯核心不依赖 Android API。`core` 包含数字 IP 解析、输入验证、严格回显解析、五态 evaluator、报告导出与合成 fixture；Android 交互只在 `app`。

## 使用

首次使用：保持待测代理设置，首页点“开始网站与网络诊断”，使用预设或填出问题的网址，选择代理状态后开始。也可先选“仅检查本机环境”。原 DNS 快速检查、严格出口验证与修复中心继续保留。

需要验证代理出口时，进入“测试”，选择“HTTPS 出口核验”：

1. 让待验证 VPN/代理保持现有设置，确认本工具是否被其分应用规则纳入。
2. 使用你拥有或获准测试的 HTTPS 服务，按 [端点契约](../../specs/ECHO-CONTRACT.md) 提供 `/v1/echo`。
3. 填写服务源地址，例如 `https://你控制的主机:8443`。不要填写路径、账号、订阅链接或令牌。
4. 可填写明确的预期来源 IP；确认是否信任该服务如实回显。未填写或未信任时只能记录观察，不能判定符合。
5. 系统 DNS 是独立开关，填写受控随机域名。DNS 成功不能判定隐私通过。
6. 查看本次运行实际使用的目标和策略、各项状态及局限。不要把 VPN 图标或来源 IP 匹配当作完整流量路径证明。
7. 导出前选择脱敏或完整证据。完整文件包含域名/IP/网络信息，不要直接公开；系统文件选择器可能包含云盘。

没有 HTTPS 回显服务时，可以关闭 HTTPS 和系统 DNS，只勾选原始 DNS UDP / TCP，填写获准测试的数字解析器地址、端口及域名。详见 [原始 DNS 实验](../../guides/RAW-DNS.md)。原始 DNS 是明文协议，但可由 VPN 接管并封装；收到响应不能单独说明是否发生旁路。

## 安全与证据边界

- 业务权限只有 `INTERNET`、`ACCESS_NETWORK_STATE`；AndroidX 另声明本应用签名级 `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`，不是用户授权或外部数据访问能力；没有 `VpnService`、前台服务、开机广播、导出控制服务或 root 调用。
- 不覆盖系统信任管理器或 HostnameVerifier；明文 HTTP 被禁止。
- 不跟随 3xx，不记录响应正文/请求头/异常原文。导入配置可能含凭据，只留在内存；修改预览隐藏原 DNS 值，导出的完整 YAML 仍含原凭据，不能当作脱敏报告分享。
- 来源 IP 仅是所选端点的声明。局域网实验可使用私网地址；并不自动把它称为公网出口。
- 没有观测到网络变化不代表证明网络绝对稳定。快照缺失、回调变化或前后快照字段变化均阻止来源策略得出符合/违反结论，即使网络编号相同。
- 取消是平台清理的尽力而为，不承诺已经发出的包能被撤回；OS DNS/连接阻塞时仍可能等到系统释放。界面先停止接收证据，运行槽位在资源释放前保持占用。
- 应用进程退出会丢失未导出的记录和输入。界面旋转保留运行、表单及待保存的冻结快照。内容只在进程内保留，saved state 只有随机导出请求身份；若整个进程被终止，需重新导出，系统选择器可能留下空文件。

## 文档

- [已确认产品与开发基线](../../product/PRODUCT-SPEC.md)
- [交互与视觉规范](../../specs/DESIGN-SYSTEM.md)
- [信息获取、冲突与重试规范](../../specs/EVIDENCE-ACQUISITION-SPEC.md)
- [修复工作流规范](../../specs/REPAIR-WORKFLOW-SPEC.md)

- [架构与判定](../../architecture/ARCHITECTURE.md)
- [端点契约与本地 fixture](../../specs/ECHO-CONTRACT.md)
- [实验覆盖与后续阶段](../../testing/COVERAGE.md)
- [安全与隐私](../../reference/SECURITY.md)
- [参考项目和依赖许可](../../reference/SOURCES-LICENSES.md)
- [构建与测试的实际结果](../0.1.0/BUILD-REPORT.md)
- [0.2.0 审查、修复与验证](../0.2.0/REVIEW.md)
- [0.3.0 优化、修复与验证](../0.3.0/REVIEW.md)
- [0.4.0 交互与诊断改进](../0.4.0/REVIEW.md)
- [0.5.0 Material 3 与 DNS 修复闭环](../0.5.0/REVIEW.md)
- [0.5.0 手机实测步骤与反馈建议](../0.5.0/TEST-GUIDE.md)
- [专业测试填写建议与初测解读](../0.4.0/TEST-GUIDE.md)
- [DNS 配置修复、系统设置与复测](../../guides/DNS-REPAIR.md)
- [原始 DNS 使用与证据边界](../../guides/RAW-DNS.md)

本项目源代码为本次独立编写，没有复制参考项目的 GPL/MPL/LGPL 代码；未选择或对外发布开源许可。依赖和构建工具保留各自许可，详见清单。

`fixtures/DEMO-*.json` 保留导入版 schema 1 的演示文件；应用内演示由当前导出器输出 schema 2。开发者可运行 `./gradlew :core:exportDemo` 更新文件。这些数据使用文档保留地址并带 `SYNTHETIC_FIXTURE` 标记，不能当作设备证据。
