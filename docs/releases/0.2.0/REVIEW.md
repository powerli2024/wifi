# 0.2.0 审查、能力扩展与验证

> 类型：历史评审；状态：Archived；范围：对应版本的历史时点；维护：项目维护者；核对：2026-10-23。
> [文档导航](../../README.md) · [当前验证](../../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

日期：2026-10-20（Asia/Shanghai）。对象：用户提供的 `android-proxy-diagnostics-0.1.0-source`，在原目录审查扩展为 **0.2.0 / versionCode 2**。原始 ZIP 与旁边的代理客户端项目未修改。该目录不是 Git 仓库，本次没有创建提交或发布远程仓库。

## 交付与定位

- `dist/android-proxy-diagnostics-0.2.0-debug.apk`：当前调试 APK。
- `dist/android-proxy-diagnostics-0.2.0-source.zip`：源码、说明、测试和选定验证记录；不含 SDK、Gradle 缓存、测试模拟器、私钥或构建目录。
- `dist/SHA256SUMS.txt`：APK 与源码包摘要。根目录 `SOURCE-SHA256SUMS.txt` 对应当前源码包文件；旧版摘要留在 `verification/v0.1.0-source-sha256-original.txt`。

它已经能对本应用的 HTTPS、系统 DNS、指定目标 UDP/TCP DNS 留下证据，仍不是全机抓包/流量控制器，也不是自动认定代理“无泄露”的工具。

## 新增能力

1. **原始 DNS UDP / TCP**：可只启用其中一项或两项，不需要 HTTPS 服务。指定数字 IPv4 / IPv6 解析器、端口、域名、A / AAAA；每种协议分别记录执行状态、事务 ID、耗时、响应码、TC、地址和错误。
2. **有界网络操作**：一次查询、不重试、不自动回退；最多 4096 字节，响应关联与压缩指针校验，支持 CNAME 地址归属和 OPT 扩展 RCODE。原始 DNS 每项默认 8 秒绝对截止，可取消 socket。
3. **报告 schema 2**：添加配置、逐协议观察与 20/60 秒证据预算；新增 IP、域名、返回地址同样默认脱敏。已执行 DNS 隐私最多为“观察不足”。
4. **表单旋转恢复**：输入与开关只保留在当前进程，不写入 Bundle 或磁盘。整个进程关闭后仍会丢失。

数字 IPv6 目标表示请求的 socket 地址族，AAAA 表示记录类型；两者都不单独证明 VPN 外层使用 IPv6。实现范围、操作与兼容限制见 [RAW-DNS.md](../../guides/RAW-DNS.md)。

## 审查发现与修复

| 问题 | 影响与修复 | 验证 |
|---|---|---|
| 同网络编号的配置变化可能被忽略 | 原控制器只看网络编号和回调代数。回调迟到时，已经出现在快照里的 DNS/地址/能力变化仍可能被当作稳定网络；现在控制器与 evaluator 都比较完整前后快照 | 核心回归和暂停 HTTPS 后改快照的控制器回归均通过 |
| 开发回显服务的 TLS 握手阻塞 accept | 本地客户端连入后不发 ClientHello，可阻塞后续请求；改为有上限的工作槽，握手/HTTP 超时和 HTTP 绝对截止 | 真实回环 TLS 测试覆盖停滞握手、满槽恢复、慢速请求与信任拒绝 |
| 旋转丢失未提交表单 | 输入进程内保存并恢复，不持久化网络标识 | API29/35 框架生命周期测试通过 |
| IPv4-mapped IPv6 输入的目标族信息被提前折叠 | 新 UI 保留经过校验的字面目标，core 使用地址字节构造，不触发域名解析 | 核心地址测试和 UI 确认回归通过；不据此推断物理传输族 |

## 本次实际执行

构建：Windows、本机已安装 JDK 17（Oracle 17+35）、Gradle 8.13、AGP 8.9.2、Kotlin 2.1.20、compile/target SDK 35、min SDK 29。构建工具在本机已有 SDK 许可下补齐 Platform 35；Build Tools 35.0.0 已存在。

| 层次 | 实际结果 | 覆盖边界 |
|---|---:|---|
| 核心及独立对抗测试 | **65/65**（26 原核心及回归 + 24 原始 DNS + 15 独立对抗） | 验证/解析/判定/脱敏；主机回环 UDP/TCP、超时和取消 |
| Robolectric UI/生命周期 | **30/30**（15 场景 × API29/35） | 输入、确认、旋转、导出等框架模拟；不是实体设备 |
| 控制器/导出 harness | **21/21** | 假 Android API；新增两项使用主机回环 UDP，包含快照变化、并发、20秒预算 |
| Python 回显 fixture | **10/10** | 真实主机回环 TLS、协议契约、停滞客户端；测试证书只在测试 SSLContext 中受信任 |
| Android 模拟器 instrumentation | **4/4，0 跳过** | 独立新模拟器 Android16/API36：Launcher与离线演示、IPv4/A双协议、IPv6/AAAA双协议、取消及后续运行恢复，含脱敏导出检查 |
| Android lint | **0 errors，2 warnings** | `OldTargetApi`（目标仍为35）；`SetTextI18n`（DNS端口默认值53为字面值） |
| APK / 测试 APK 构建 | 成功 | 不等于正式发布签名或真实代理安全验收 |

共 126 项 JVM/主机测试执行和 4 项模拟器场景；不要将其表述为 130 次真实代理/手机泄露实验。测试依据在 `verification/v0.2.0`：`core-junit`、`ui-junit`、`controller-junit`、构建日志、fixture日志和 `device-smoke-report.json`。

模拟器为本任务单独新建，只在它上面安装应用与测试 APK；未安装到用户实体手机，也未复用或修改原有 AVD。运行界面截图为 `ui-launch.png` 和 `ui-raw-dns.png`，已检查可读性。设备测试报告带 `DEVICE_LOOPBACK_SMOKE` 标记，`userVpnEvidence=false`、`outerNetworkPathVerified=false`。

历史 `verification/` 根目录记录与 `qa/results`、`qa/logs` 仍对应导入的 0.1.0，不混入当前测试计数。QA 脚本的后续输出统一使用 `build/`，避免重跑覆盖历史快照。

## APK 身份

- 应用 ID：`dev.proxyaudit.android`；版本 `0.2.0`，最低 Android10/API29。
- SHA-256：`08cbaf01d9fadd372583d0520fa8b12d44b2791c145491b7ba1a0ea9ccc78f31`。
- 签名 v2 校验通过；调试证书 SHA-256：`25a59d6e08c311614cde03a3af822d12fac07561cbc355db0f11ee5edc72ccd4`。
- 运行依赖仍只有本项目 core、Kotlin stdlib、JetBrains annotations；instrumentation 仅在独立测试 APK 中。
- 权限仍为 `INTERNET`、`ACCESS_NETWORK_STATE`，无 VpnService、root、CA 安装、代理控制、遥测。

本机调试签名与导入的 0.1.0 APK 不同，已经安装旧版的设备可能无法直接覆盖升级。需要先导出旧版证据，再由设备使用者决定如何处理安装；本次没有卸载或清除用户设备数据。生产签名尚未配置。

## 尚未验证与后续优先级

未做实体手机、真实 Clash/FlClash/Karing/Hiddify 等客户端对照；未验证 Wi-Fi/蜂窝切换、真实 HTTPS 端点、系统 DNS 线上路径、原始 DNS 是否被代理接管、断线保护、跨应用流量或外层 IPv6。模拟器本地回环不会经过这些链路。

下一阶段先用本版原始 DNS 探针配合受控解析器/网关日志，跑“VPN关闭、开启、分应用排除、UDP/TCP分别接管”的对照，明确规则与实测是否一致；随后增加强制双栈 HTTPS、连续切网时间线及日志关联。调整其他代理配置仍需各客户端支持的接口或导入流程。
