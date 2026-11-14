# 观测事件与后端契约草案

状态：Draft，完整事件契约未实现、不是当前JSON schema；2026-10-23；[文档导航](../README.md)。现有RunReport/schema2与NETWORK_DEEP_DIAGNOSTICS/schema1保持各自语义。

0.7.0已新增共同`evidenceEnvelope`（命名空间`dev.proxyaudit.evidence`、版本1），只记录报告类型、App版本、runId、来源、范围、来源列表、停止/完整性提示与“跨来源关联未建立”。代理只读快照也采用该最小外层；这不是下述ObservationEnvelope事件流，没有补造eventId、attempt引用、时间域或CorrelationEdge。GET /version与/connections已有实现及受控测试，真实代理API和跨后端关联仍待验证，自适应实验规划未实现。

## 模块职责

CapabilityBackend预检来源/权限/限制；ProbeExecutor执行固定计划；ObservationAdapter将原生记录包装为事件；EvidenceStore保留选定原件/摘要；Correlator输出有依据的关系；DiagnosticRules维护假设与下一实验；RepairExecutor独立处理有权限的动作。场景由这些能力组合，UI只展示计划、状态和证据。

## 最小数据实体

| 实体 | 必要字段/语义 |
|---|---|
| CapabilitySnapshot | backendId、backendKind、实际版本/来源、采集位置、支持字段/协议、权限/凭据状态、覆盖范围、限制、过期条件 |
| TestPlan | planId、用户问题、竞争假设、固定目标/协议、允许的网络变化、预算、敏感数据与副作用、信任来源 |
| Run / Attempt | runId、attemptId、执行顺序、clockDomain、单调起止/截止、UTC、实际退避与停止原因 |
| ObservationEnvelope | eventId、schemaNamespace/version、sourceRecordId、plan/run/attempt引用、来源版本、采集时间与事件时间、完整性、payload类型、证据引用 |
| Payload | 网络接口/环境、DNS、连接/包、TLS、HTTP、核心规则/链、应用归属、错误；按能力提供可选字段 |
| CorrelationEdge | 两端事件、关联规则版本、依据字段、时间窗口/误差、DIRECT_ID/MATCHED_CONDITIONS/AMBIGUOUS/UNRESOLVED及反证 |
| Finding | hypothesisId、支持/相反证据引用、观察/解析/推断类别、适用范围、未解决条件、下一实验 |
| RepairReceipt | plan/diff、原配置摘要、写入结果、读回结果、客户端加载证据、复测引用、恢复结果，分别表达不能互代 |

能力状态区分AVAILABLE、PERMISSION_DENIED、NOT_SUPPORTED、NOT_CONFIGURED、UNREACHABLE、UNKNOWN。字段缺失必须说明NOT_EXPOSED、REDACTED、NOT_COLLECTED或PARSE_ERROR，不能把null当false/零。完整性区分COMPLETE、PARTIAL、TRUNCATED、DROPPED、UNKNOWN；API快照应明确“不保证历史完整”。

## 时间与身份

本机耗时用单调时钟，UTC用于展示/跨设备参考；外部日志同时记录原时钟、偏差估计与采样窗口，没有估计时标UNKNOWN，不伪造毫秒同步。networkEpoch记录已观察到的条件变化，不保证未漏事件。

runId属于App，核心connectionId属于该核心运行实例，DNS事务ID属于一次协议交换；三个标识不相等。只有双方实际携带并验证的请求标识才可直接关联。元组+端口+网络代次+误差界内时窗可形成条件匹配，必须记录NAT/代理改写与复用；多个候选不强选。同目标IP或相近时间只能作为检索条件。

示例：HTTP代理socket对端为回环，核心记录目标站点外连。这是两个不同连接段，不能要求元组直接相等，也不能因为域名相同就断言属于一个请求。需要受控请求标识/入口映射或可复核的边界证据，否则保持候选。

## 事实、派生与推断

原始事实：某来源在某时点报告了某字段；解析派生：从受限原始数据解析地址/类型；推断：若干事件支持某假设。日志字段本身是来源的声明，不自动成为独立真实路径。保留transformVersion和sourceEventIds；原始完整数据只在用户选择时保留，默认去凭据/正文，低熵IP哈希不能当匿名化。

受控示意（不是当前导出样本）：

```json
{"schemaNamespace":"observation-envelope-draft","eventId":"example-e1","source":{"backendId":"proxy-api","version":"UNKNOWN"},"kind":"PROXY_CONNECTION_SNAPSHOT","completeness":"PARTIAL","correlation":{"state":"UNRESOLVED","reason":"No verified link to app attempt"}}
```

## 演进与验证

适配旧报告时unknown保持unknown，不补造nonce、socket本地端口或核心版本。深度与专业顶层类型同时保留，旧读者继续可读；新增外层采用明确命名空间，不覆盖旧schemaVersion。版本错位从构建源修正，只影响新报告。

序列化/迁移测试覆盖：缺失、未知枚举、部分结果、旧schema、时间域不一致、重复事件/ID、恶意超大数据、关联歧义、脱敏导致无法重算、取消/换网后迟到事件。只有这些约束与真实跨后端样本一起验证，才能把模型从Draft改为当前契约。
