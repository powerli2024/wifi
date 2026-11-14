# 架构与证据模型

> 类型：实现架构；状态：Active；范围：0.7.0源码现状或明确标注的目标要求；维护：项目维护者；核对：2026-10-23。
> [文档导航](../README.md) · [当前验证](../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

现状版本：0.7.0。变化与待验内容见 [本版记录](../releases/0.7.0/REVIEW.md)，实际测试数以[当前验证](../testing/CURRENT-STATUS.md)为准。更广目录见 [产品基线](../product/PRODUCT-SPEC.md)。

`app/DeepDiagnosticsSession` 与 `DeepDiagnosticsActivity`：网络画像、本机回环实验、网站诊断与可选当前DNS四项实验的进程级会话、取消/换网/整体截止和独立JSON导出。0.7.0 增加独立深度基线、原计划复测与双报告导出；Activity 以顶端定位、五阶段表和默认折叠详情展示，固定工具栏提供导出。

`app/DeepReportAnalysis` 与 `DeepReportComparisons`：根据已记录的 HTTP 代理、fake-IP 范围、AAAA 空回答、协议回答冲突和首次失败/后续成功解释现象；检查报告完整性、版本、计划和网络条件后再比较。来源解释不改写原始结果，不凭地址或 API 状态断言无泄露。

`app/NetworkInventory` 与 `DeviceSelfTest`：使用Android已提供的网络字段与短生命周期本机Socket环境，采集不执行PAC、不绑定底层网络；本机实验和公网结果分开。

`core/WebsiteDiagnostics`：OkHttp4.12.0默认平台DNS/代理/TLS，有界GET、逐次阶段事件、自动一次限定复核；全局唯一工作槽，迟到结果冻结。网站不套用/v1/echo契约，详细约束见 [深度诊断](../specs/NETWORK-DEEP-DIAGNOSTICS.md)。

`app/AppIdentity`：应用版本唯一来源为 `BuildConfig.VERSION_NAME`，在开始/生成运行报告时写入对应报告对象；已冻结报告不随之后的显示刷新改变版本。旧版专业报告写死 0.5.0 的缺陷已在源码修复，历史报告保留原值。

## 模块

下述 app/类名、core/类名为模块简称；完整源码分别位于 app/src/main/kotlin/dev/proxyaudit/android 与 core/src/main/kotlin/dev/proxyaudit/core。

`app/MainActivity`：Material 3 概览/测试/修复导航与报告子页、条件显示的输入、场景填表、目标确认、摘要和折叠证据、离线演示、系统 SAF 导出。

`app/DiagnosticsController`：进程内单运行槽位、冻结配置，按系统 DNS → HTTPS → 已选择的原始 DNS UDP / TCP 顺序探测。旧模式 20 秒等待预算，启用原始 DNS 后总预算 60 秒。DNS callback、网络 worker、deadline scheduler、清理 executor 分离，清理队列有界。

`app/NetworkMonitor`：被动注册默认网络 callback，只收网络状态。不会绑定进程或选择物理底层网络。任何已观察到的网络/能力/链路变化递增 generation。

`core`：不依赖 Android 框架；同时包含网络 I/O 和规则计算。提供不可变报告结构、纯数值 IP 规范化（不解析 DNS）、源地址验证、严格 flat JSON 解析、五态策略判定、确定性演示、JSON 导出。

`core/RawDnsProbe`：单次数字目标 UDP / TCP DNS，解析 A / AAAA 和相应 CNAME 链；标准 JVM socket 不显式绑定底层网络。资源注册与取消互斥，每项有单调时钟绝对截止；仅保留有界响应，不导出原始报文。

`core/QuickCheck`：只构造固定域名、默认系统解析的计划，不联网。公共 DNS 元数据明确区分原始探测目标、DoH 和 Android Private DNS 主机名。

`core/DiagnosticAdvisor` 与 `ReportComparison`：从观察生成保守建议；比较要求同版本、同计划和各次稳定观察。跨次 DNS 设置变化允许记录事实，但不进行因果归因。对照导出包含两个完整的既有报告对象。

`core/ReportPresentation`、`ProfessionalScenarios`、`SystemDnsDiagnostics`：分别构造显示摘要、无副作用的场景文案、有限系统DNS错误解释。不能从演示/缺失结果推导设备事实。0.5.0 以整份报告的来源优先约束显示，修复演示详情措辞回归。

`core/MihomoConfigDoctor`：受限 YAML 节点审查、允许字段原文补丁、重新解析验证；不执行或下载配置。

`app/RepairSession` 与内部 `RepairActivity`：进程内配置和预览、单任务后台文件处理、冻结文档选择请求、只向新副本导出并读回核对；手动导入确认与基线身份均仅进程内保留；系统设置导航不写全局设置。

`core/ProxyCooperationProbe`、`app/ProxyCooperationSession` 与内部 `ProxyCooperationActivity`：用户提供 HTTPS 控制 API origin 和可选 Secret，确认后有界读取版本和连接快照；会话保存结果，不保存 Secret 草稿。使用默认系统代理及正常平台 TLS，不接受普通 HTTP，不自动寻找端点。独立报告仅提供脱敏导出，未与网站请求进行自动关联。

`core/EvidenceEnvelope`：为专业、深度、代理协同报告增加共同来源外壳，包含 namespace/version、reportKind、appVersion、runId、origin、scope、sources、stopped、completeness 与解释策略。`crossSourceCorrelation=NOT_ESTABLISHED` 明示没有跨来源关联；原报告结构和各来源执行状态仍是解释依据。

## 专业诊断链的请求语义

- 系统 DNS 使用 `DnsResolver.query(null, name, FLAG_EMPTY, ...)`，由系统选择默认网络和 A/AAAA 查询，不自称一定发出了两种 RR。
- HTTPS 使用标准 `HttpsURLConnection` 和系统默认网络/代理行为。工具不强制“直连”，也不显式绑定底层网络。
- HTTPS可能独立触发域名解析，具体取决于默认代理与连接路径；HTTP代理可承接站点解析。关闭单独系统DNS复选框不代表HTTPS请求没有任何解析行为。
- 原始 DNS 使用数字目标构造地址字节，不调用 `getByName`；只关闭系统 DNS / HTTPS 时，可以只执行这组探针。A / AAAA 是记录类型，与 socket 目标地址族独立。
- 不捕获网卡包，也看不到 VPN 核心内部规则。只记录 API 观察和服务端声明。

## 专业诊断链 RunReport（schema 2）

schemaVersion=2、evidenceOrigin（ANDROID_RUNTIME / SYNTHETIC_FIXTURE）、唯一 runId、UTC 起止、单调时钟耗时、应用版本、Android API、固定 scope、实际策略和目标、前后网络快照、变化标志、系统 DNS/HTTPS/原始 DNS 结果、每个规则的 assessment、limitations。HTTPS 服务契约仍为 v1。

0.4.0 在系统DNS对象新增可空的 diagnosticStage、responseCode、resolverErrorCode、systemErrno、exceptionKind；数字/枚举可保留在脱敏导出，不输出异常原文。旧记录缺这些字段时只能显示未记录，不能从旧 DNS_FAILURE 或耗时反推出原因。

0.5.0 schema 2 加入 maxAttemptsPerProbe、attempts 和 stopReason。每次尝试有随机身份、探针类型、序号、单调时钟偏移、实际超时上限、独立结果、重试原因和实际等待。首个 HTTPS 尝试沿用 runId 契约，追加尝试用自己的 attemptId；按各自身份校验。聚合保留首次失败，全局停止单独记录。默认一次，专家可选最多两次；只有超时或 HTTPS 明确连接失败触发固定 500 ms 等待，不重试 TLS/解析/权限/协议响应错误。所有尝试共享原总预算。

导出没有“全局安全分数”。DNS 与 IPv6 专项不能因为 HTTPS 地址符合就被升级为通过。

## 专业回显来源 IP 规则优先级

1. 未启用或未开始 HTTPS：未执行。
2. 缺少端点/信任声明/预期 IP：观察不足。
3. 回调报告网络变化、快照缺失、网络 ID 未知，或前后快照任意字段不一致：观察不足。相同 ID 不覆盖可见配置变化。
4. 错误、取消、非 HTTP 200、TLS 未验证：观察不足。
5. schema / 请求 ID / IP 不合法：观察不足。
6. 数字来源 IP 在预期列表中：符合此项来源策略。
7. 不在列表：违反此项来源策略。

第 6/7 项仍然只是本应用该次 HTTPS 回显。受信端点可能撒谎，出口可能共享 NAT，代理可能转换地址族；无法单独证明实际 VPN 路径。

DNS 保密：执行过仍为观察不足，需要网关、解析器和核心日志。

原始 DNS 每项独立记录状态；NXDOMAIN 与截断是响应观察，不是传输失败，也不是隐私通过。包格式不合法为 `INVALID_DNS`，未进入的协议为 `NOT_STARTED`。

IPv6：只有用户明确排除范围才“不适用”；本版未实现强制 IPv6 路径验证，否则保持“观察不足”。

## 并发和退出

以下以专业控制器的运行/导出契约为基础；深度和只读协同使用各自的进程会话，并共同检查跨入口忙碌与探针资源释放状态。

- 连续点击只能产生一个 active token。运行期输入禁用；UI 重建不创建新任务。
- token 保存 runId 与配置，旧 callback 不会改写新任务。
- 超时/取消在短锁内冻结当时阶段及观察，先唤醒 DNS、提交资源清理，再在锁外采集终态网络快照。快照阻塞不能阻止清理启动。只有一个调用可认领报告发布，工作线程退出和发布完成同时满足后才释放运行槽。
- 原工作线程退出前不释放运行槽位。若平台网络操作长期阻塞，用户可以关闭应用进程；不能以额外无限线程掩盖阻塞。
- 导出快照在进程会话中保留，Activity 的导出 saved state 只保存随机请求 ID 和非重复请求码。深度 UI 另可保存展开分组名和报告 ID，不含网络字段或网址。旋转后可完成原快照的保存；取消清除，重复/迟到结果不消费其他任务。整个进程终止后不从磁盘恢复证据。
- 无后台重试、无定时自动运行、无持久日志或遥测。
- 输入草稿仅存在控制器内存；Activity 停止时保存、重建时恢复，不写入 Bundle / 磁盘。

## 诊断链与只读协同的边界

| 入口 | 执行器/报告 | 请求与预算 | 闭环 |
|---|---|---|---|
| 专业 DNS / 出口 | DiagnosticsController / RunReport schema 2 | HttpsURLConnection 严格回显4KiB；默认一次、显式最多两次；总20/60秒 | ReportComparison 与 RepairSession 基线联动 |
| 网站与网络 | DeepDiagnosticsSession / DeepReport schema 1，reportKind=NETWORK_DEEP_DIAGNOSTICS | OkHttp 普通网站GET，正文16KiB；网站15/30秒、总60秒；暂时错误自动最多两次 | 独立深度基线、原计划复测、条件比较、双报告导出；不与专业基线互换 |
| 代理只读协同 | ProxyCooperationSession / PROXY_READ_ONLY_COOPERATION schema 1 | HTTPS GET /version、/connections；每项3秒、总15秒；响应256KiB、最多100条连接 | 显式一次快照与脱敏导出；没有自动关联本应用请求或写配置 |

各 schemaVersion 属于不同报告种类，不能只按数字大小判断新旧。WebsiteReport 是深度报告中的网站子对象；NETWORK_DEEP_COMPARISON 内包含两份深度报告和比较条件。共享 EvidenceEnvelope 是兼容新增字段，没有替换原模式，也不是统一多后端事件流。现有顺序由代码固定，自适应实验规划仍未实现。

## 深度基线与代理 API 的具体约束

深度基线将报告与原完整网址/预算/原始 DNS 目标保留在进程中；保存基线、取得计划方法本身不触发网络。`saveBaseline` 先检查完整性，`retestPlan` 优先返回基线计划，UI 确认后调用原 `start`。两次报告按版本、计划、代理声明和可见网络条件比较，系统 DNS 改变可作为条件说明，但不能认定变化由该设置导致。比较导出在保存窗口打开前冻结两份报告，继续使用唯一票据和请求码防止旧回调串写。

控制 API 只允许两条固定 GET 路径，origin 不含账号、路径、查询或片段；Secret 只组成本次 Authorization。关闭自动跳转、Cookie、认证重试和自动重发，设置请求/总体截止及解析预算。响应必须满足兼容结构；只保留字段白名单与有界连接样本，不保留原始 JSON 或响应头。401/403/404、TLS、超时、非 JSON、重复 ID、缺字段及超限各自记录。没有普通 HTTP 降级、自定义信任或绕过主机名校验。

快照返回者由用户声明；TLS 只验证填写地址的服务器身份。连接列表可能包括其他应用、采样不完整、已经消失或尚未建立的连接；本版没有按 UID、连接、目标、请求 ID 和时间将它关联到网站实验，也不会修改核心配置、测速或断开连接。当前两个诊断入口与协同入口互斥，资源释放未结束时不能靠新线程重复启动。

后续完整事件、相关性与能力升级方案见 [事件与后端契约草案](EVENT-CONTRACT-DRAFT.md)。DNS 泄露仍需外层路径证据，API 快照可用与完整路径已验证分别记录。
