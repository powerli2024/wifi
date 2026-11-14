# 从理解项目到第一次检查

状态：Active；适用0.7.0源码；核对2026-10-23。完整目录只维护在[文档入口](docs/README.md)，实际验证与安装包状态以当前验证记录为准。

## 想搞懂项目

1. [产品基线](docs/product/PRODUCT-SPEC.md)：用户问题、证据范围和修复目标。
2. [当前架构](docs/architecture/ARCHITECTURE.md)：区分网站深度链、专业出口/DNS链和独立的代理只读快照。
3. [深度诊断契约](docs/specs/NETWORK-DEEP-DIAGNOSTICS.md)：从一次输入到分层结果。
4. [当前验证](docs/testing/CURRENT-STATUS.md)：源码、模拟测试和真机证据分别证明什么。
5. [观测策略研究](docs/architecture/OBSERVABILITY-STRATEGY.md)：后续怎样增加证据，而不是不断堆权限。

读源码先看 DeepDiagnosticsSession.execute，再看 WebsiteDiagnostics 的事件监听器，然后看 DeepReportComparisons 如何判断两次实验可否比较。需要理解出口政策与配置修改时，再读 Evaluator.egress 与 MihomoConfigDoctor.repair。ProxyCooperationProbe 展示怎样将外部 API 限定为两项只读调用；EvidenceEnvelope 统一来源字段，尚不关联不同来源中的请求。core 包含 I/O 探针和纯规则；app 承接 Android 系统、UI 和会话。

## 想直接使用

按[当前验证](docs/testing/CURRENT-STATUS.md)核对准备安装的版本，保持待测代理状态。首页进入“开始网站与网络诊断”，先选“仅检查本机环境”，再用 ChatGPT 预设或填写问题网址。网站诊断不要求回显服务或预期出口。0.7.0 顶部显示主要定位，阶段表显示最早失败位置，完整网站/网络/本机/DNS 证据按需展开，工具栏随时可导出已完成报告。

需要检查DNS协议时显式开启扩展；A/AAAA是记录类型，UDP/TCP是查询传输。需要核验出口时另进入专业测试，按[专业填写指南](docs/guides/PROFESSIONAL-TESTING.md)准备可信回显服务和预期出口。

先读结果中的已完成阶段，再看最早失败阶段；HTTP403仍可能有成功的TLS。代理代解析时没有本地DNS事件不一定是故障。完整结果、停止原因和每次尝试应一起保留。文件修复按[DNS修复指南](docs/guides/DNS-REPAIR.md)操作，保存副本不等于客户端已经应用。

需要比较改动前后时：完成一次诊断 → 保存本次为基线 → 只调整你要验证的设置 → 按基线原计划复测 → 查看比较条件与变化 → 导出两份报告。基线只保留在应用进程中；复测使用原完整网址、预算和原始 DNS 目标，修改表单或系统 DNS 不会静默改写原计划。条件冲突会阻止“同计划比较”，已确定失败也可成为基线，取消和缺测不能作为完整基线。

有合适的代理控制 API 时，可打开“代理只读协同”。填写其 HTTPS 来源地址及可选 Secret，确认后只读取版本和连接快照。当前不支持普通 HTTP 控制口；代理监听的 HTTP/SOCKS 端口也不是该 API。没有受信任的 HTTPS 控制 API 可继续使用其他诊断，无需为基本检查开放接口。快照可能包含其他应用连接，暂不自动匹配本次网站请求，不代表代理路径已验证。具体填写与失败处理见[0.7.0 实测指南](docs/releases/0.7.0/TEST-GUIDE.md)。

## 想参与开发

从[开发与验证命令](docs/guides/DEVELOPMENT.md)开始。0.7.0 已实现范围看[本版评审](docs/releases/0.7.0/REVIEW.md)；更大的观测路线看[问题账本](docs/governance/AUDIT.md)和[架构方案](docs/architecture/ADR-001-OBSERVATION-BACKENDS.md)。早期研究可能描述尚未落地的完整关联后端，不能把只读快照等同于整套提案已经实现。
