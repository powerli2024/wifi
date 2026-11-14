# 项目文档导航

状态：Active；维护：项目维护者；核对2026-10-23。这里是唯一完整文档索引。规范描述要求，架构描述实现，研究草案描述候选方案，报告仅描述对应时间的执行结果。

## 第一次阅读

[入门路线](../START-HERE.zh-CN.md) → [产品基线](product/PRODUCT-SPEC.md) → [当前架构](architecture/ARCHITECTURE.md) → [深度诊断契约](specs/NETWORK-DEEP-DIAGNOSTICS.md) → [当前验证状态](testing/CURRENT-STATUS.md)。

## 当前权威文档

| 主题 | 唯一入口 | 职责 |
|---|---|---|
| 产品目标 | [PRODUCT-SPEC](product/PRODUCT-SPEC.md) | 已确认需求与阶段边界 |
| 当前实现 | [ARCHITECTURE](architecture/ARCHITECTURE.md) | 两条诊断链、独立只读协同、报告格式与已知缺口 |
| UI | [DESIGN-SYSTEM](specs/DESIGN-SYSTEM.md) | Material3与交互/可访问性验收要求 |
| 证据 | [EVIDENCE-ACQUISITION-SPEC](specs/EVIDENCE-ACQUISITION-SPEC.md) | 计划、尝试、冲突、时间和采集质量 |
| 修复 | [REPAIR-WORKFLOW-SPEC](specs/REPAIR-WORKFLOW-SPEC.md) | 候选、保存、应用、复测的区别 |
| 回显协议 | [ECHO-CONTRACT](specs/ECHO-CONTRACT.md) | 专业出口服务v1契约 |
| 网站协议 | [NETWORK-DEEP-DIAGNOSTICS](specs/NETWORK-DEEP-DIAGNOSTICS.md) | 网站、本机实验、DNS四项与0.7深度基线的实现约束 |
| 实测状态 | [CURRENT-STATUS](testing/CURRENT-STATUS.md) | 当前所有验证范围的汇总，链接原始/历史证据 |
| 覆盖范围 | [COVERAGE](testing/COVERAGE.md) | 旧L00–L17能力映射，不另立产品路线 |
| 数据与安全 | [SECURITY](reference/SECURITY.md) | 两条链各自输入/正文/预算及威胁边界 |
| 来源 | [SOURCES-LICENSES](reference/SOURCES-LICENSES.md) | 依赖、参考资料和原许可记录 |

## 使用、开发与验收

- [专业测试填写](guides/PROFESSIONAL-TESTING.md)、[DNS修复](guides/DNS-REPAIR.md)、[原始DNS](guides/RAW-DNS.md)。
- [开发命令](guides/DEVELOPMENT.md)、[QA工具说明](../qa/README.md)。
- [0.7.0 实现评审](releases/0.7.0/REVIEW.md)、[0.7.0 真机与填写指南](releases/0.7.0/TEST-GUIDE.md)：当前源码交付范围及待验收步骤，测试结果由当前验证索引汇总。
- [0.6网站验收步骤](releases/0.6.0/TEST-GUIDE.md)、[问题驱动实验矩阵](testing/EXPERIMENT-MATRIX.md)、[有限真机摘要](testing/DEVICE-2026-10-23.md)。

## 架构研究（完整方案尚未实现）

0.7.0 已实现共享来源外壳、独立深度基线与受限代理 API 只读快照；尚未完成下列研究中的统一事件流、跨来源请求关联、自适应实验选择或特权观测后端。具体实现以当前架构为准，研究草案不是 API 已落地证明。

- [观测策略](architecture/OBSERVABILITY-STRATEGY.md)：任务→证据缺口→候选实验→能力升级。
- [权限、能力与干扰矩阵](architecture/CAPABILITY-MATRIX.md)：官方与本地源码依据。
- [ADR-001](architecture/ADR-001-OBSERVATION-BACKENDS.md)：当前选择及下一最小实现提案。
- [事件与后端契约草案](architecture/EVENT-CONTRACT-DRAFT.md)：来源、时间、关联、完整性和迁移。

## 历史与治理

- [版本档案](releases/README.md)，包括旧失败、模拟器和发布前未真机记录；不能用今日状态回填历史。
- [治理规则](governance/GOVERNANCE.md)、[审计与待办](governance/AUDIT.md)、[本次迁移](governance/MIGRATION.md)、[机器清单](governance/migration-manifest.json)。
- [旧路径兼容索引](governance/COMPATIBILITY.md)中的页面只跳转，不是第二套规范。
- 输入原文：[prompt1](prompt1.txt)、[prompt2](prompt2.txt)；本次采用并执行的[整合prompt3](prompt3-architecture-and-docs.txt)。

## 状态和维护

Active表示作为当前职责入口维护，不等于所有需求均已实现；Draft表示未实施设计；Archived保留历史时点；Superseded仅指向替代位置；Unverified表示事实尚无验证。代码/接口、权限、预算、报告结构或验收变化时同步更新对应权威文档与验证索引，按[治理规则](governance/GOVERNANCE.md)检查引用和一致性。
