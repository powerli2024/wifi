# 独立 QA 报告

> 此报告及 `qa/results` / `qa/logs` 为导入的 0.1.0 历史证据。0.2.0 新增/重跑结果在 `verification/v0.2.0`，汇总见 `docs/releases/0.2.0/REVIEW.md`；本段不将历史结果改写为当前结果。

验证时间：2026-10-20 05:25 UTC。对象：当前 AndroidProxyDiagnostics 0.1.0 工程及下述确切调试 APK。

## 结论

当前第一阶段实现通过已执行的自动化验证。没有发现能从错误、未知、取消、网络变化、DNS 成功或 IPv6 地址存在误推出“全机无泄露”的判定路径。

这不是 Android 真机验收，也不是 VPN、TLS 或 DNS 线上路径安全证明。调试 APK 可用于下一阶段受控设备测试，不应当作已经完成生产安全审计的正式发布版本。

## 实际执行与独立核验

| 验证层 | 结果 | 证据 |
|---|---:|---|
| 真实核心源码及实现者的 JUnit 测试 | 25 / 25 通过 | `results/core-junit/TEST-dev.proxyaudit.core.CoreTest.xml` |
| 独立对抗性 JUnit 测试 | 15 / 15 通过 | `results/core-junit/TEST-dev.proxyaudit.qa.IndependentAdversarialTest.xml` |
| 真实控制器源码 + 假 Android/网络 API 的 JVM 测试 | 9 / 9 通过 | `results/controller-junit/TEST-dev.proxyaudit.qa.ControllerConcurrencyTest.xml` |
| 进程内导出快照、唯一消费、取消、旧回调及恢复码独立 JVM 测试 | 9 / 9 通过 | `results/controller-junit/TEST-dev.proxyaudit.qa.ExportRetentionTest.xml` |
| 实现者执行的 Robolectric UI/生命周期模拟，独立复核 XML 与日志 | 18 / 18 通过，API 29/35 各 9 项 | `results/robolectric-junit/TEST-dev.proxyaudit.android.MainActivityTest.xml` |
| 回环 fixture 契约测试，独立重跑 | 3 / 3 通过 | `logs/loopback-fixture-tests.log` |
| Android lint，独立复核报告 | 0 个问题 | `logs/android-lint-final.txt` |
| 全量构建日志，独立复核 | BUILD SUCCESSFUL，56 个任务执行 | `logs/author-aggregate-build.log` |
| APK 元数据、Manifest、签名，独立执行工具检查 | 符合下述信息 | `logs/apk-*-final.txt` |

这些层次不能混称为真机测试。JVM 及回环测试没有访问公共诊断端点，没有安装到用户手机，没有关闭 TLS 校验。Robolectric 结果来自实现者实际构建输出，独立 QA 复核了测试代码、18 条用例记录和成功日志，没有把它表述成另一遍真机运行。

## 重点覆盖

- 五种结论明确区分：符合预定策略、违反预定策略、观察不足、未执行、不适用。来源 IP 匹配和不匹配均保留本应用/本次请求边界，不升级为全局泄露结论。
- 1,248 种执行状态/错误/TLS/HTTP 状态组合和 72 种前后网络状态组合。只有正常完成、无错误、正常 TLS、HTTP 200、匹配请求标识、明确且受信的策略、可用且未观察到变化的网络快照才可得到来源 IP 匹配。
- DNS 无论成功、失败、地址族或错误类别，都不会被认定为保密通过；IPv6 默认观察不足，只有用户明确排除才不适用。
- 严格 JSON 字段、类型、数字版本、转义后重复键、额外字段、畸形文本、重放/错 nonce、4 KiB 限制、严格数字 IPv4/IPv6 及映射等价。包含 15,000 次确定性畸形输入测试。
- 脱敏导出逐个检查 endpoint、DNS 主机、预期/实际来源地址、解析地址、前后网络 ID、本地地址、配置 DNS、Private DNS 名称；完整导出保留显式选择的数据。异常原文不进入状态或导出。
- 控制器取消先发布保守终态，阻塞清理期间拒绝新任务；晚到 DNS 回调和晚结束 worker 不替换已发布报告；64 个并发 start 仅一个获准；运行后修改调用者可变 IP 集合不改变冻结策略。
- 模拟 DNS 超时约 1 秒；真实等待 20 秒的总预算测试通过。模拟平台操作忽略读取超时时仍先发布“观察不足”，不声称系统网络资源已释放。
- 假 HTTPS 层验证重定向、错 nonce、响应过大、畸形 UTF-8、内容类型/编码错误、TLS/IO/超时异常均为保守错误。没有借此声称真实 TLS 或路由已经验证。
- 导出 JSON 在用户选定脱敏/完整版本时立即序列化并只留在进程内，后续报告变化及原集合修改不影响已批准快照；同一 ID 只能消费一次，64 个并发消费也只有一个取得内容。取消后重试不会复用 ID/请求码，旧 ID 不能清除新快照。
- 同进程旋转后保存请求保留；Robolectric 检查实际 shadow 输出流内容等于原脱敏快照且重复 callback 不会重复写入。Activity saved-state 只新增随机导出 ID 和请求码，不保存 JSON/IP/域名/策略。进程重建后先保留旧请求码高水位，旧结果不能用重置请求码选择新快照的目的地。
- 静态检查与 APK Manifest 检查确认没有 VpnService、额外导出服务、root/CA 路线或显式底层网络绑定；只有 INTERNET 和 ACCESS_NETWORK_STATE 权限。源码中保持正常 HTTPS 校验、禁止跳转与响应缓存、明确用户目标确认及系统文档选择器。

## 审查发现及处理

1. Endpoint 的私有构造函数原先可被 data-class 自动生成的公开 copy 绕开。实现者改为普通私有构造类。当前 UI 没有调用该绕过路径；属于 API 防御性修复。
2. requestUrl 原先接受任意 36 个十六进制/连字符，而不是 UUID 的固定 8-4-4-4-12 排列。已改为精确格式，独立回归通过。运行期本来就生成 UUID，因此没有观察到真实请求使用错误 nonce。
3. 配置的预期 IP 集合已冻结；独立模拟验证调用者中途修改原集合不会改变本次判定。
4. 原先 SAF 保存期间旋转会丢失待写内容。已修复为进程内冻结快照 + Activity 保存随机 ID/请求码，Robolectric 已验证旋转后写入正确、取消后可重试、重复及过期 callback 不误写。
5. 独立复审进一步发现进程重建后请求码从 21 重新开始，可能将旧 callback 对应到新导出。已增加恢复请求码保留/高水位推进；独立控制器回归及 API 29/35 的 UI 模拟均验证旧请求不能消费新内容。
6. 保留隐私边界：完整进程退出不持久化 JSON，未导出内容会丢失；旧结果不会被当作新内容写入。真实系统文档提供者、进程终止期间文件原子性及云盘仍未端到端验收。

## 确切 APK

- 路径：`app/build/outputs/apk/debug/app-debug.apk`
- 大小：2,540,400 字节。
- SHA-256：`5abb6c0fec4b1b1ff0dc63d965ed07e84df57a72f9e83bafeb6cb7379c649c68`
- applicationId：`dev.proxyaudit.android`；versionName：`0.1.0`；versionCode：1。
- 最低 API 29（Android 10），目标/编译 API 35（Android 15）。
- APK v2 签名验证通过；证书为 Android Debug。该调试签名不是生产发布身份。
- Manifest：debuggable=true、usesCleartextTraffic=false、allowBackup=false，并包含禁用云备份/设备迁移的数据提取规则。

所有独立核心、控制器/导出、Robolectric 与 fixture 套件合计 79 项非重复执行用例；这不是 79 次手机实验。

源码逐文件摘要保存在 `logs/production-source-sha256.txt`；控制器生成副本与实际源码摘要相同，见 `logs/controller-source-fingerprints.txt`。这些摘要仅用于对应本报告所测版本。

## 尚未执行

- 真机/模拟器安装和实际 Android UI 操作、系统权限/厂商差异、真实旋转中断网络、后台/前台切换及真实 SAF 文件写入。
- 真实证书链/主机名校验、真实 DNS/HTTPS 流量、VPN 开关、分应用代理、默认网络切换、取消后的实际 socket/DNS 释放。
- 网关/解析器/代理核心日志比对、IPv4/IPv6 强制路径、UDP/TCP 原始 DNS、QUIC、WebRTC、其他应用或全机流量。

下一步应在用户授权的受控 Android 设备和已获准的 HTTPS 端点完成端到端验收。不能用本报告的自动化通过替代这些实验。
