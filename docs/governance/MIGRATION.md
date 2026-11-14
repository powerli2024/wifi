# 2026-10-23 研究与文档迁移报告

状态：Archived（本次操作记录）；[文档导航](../README.md)。任务输入为原prompt1/2，本次采用[整合prompt3](../prompt3-architecture-and-docs.txt)。没有Git仓库；没有重置或覆盖用户代码。

## 完成结构与职责

```text
README.md / START-HERE.zh-CN.md  精简入口与阅读路线
docs/README.md                 唯一完整导航
docs/product/                  已确认需求
docs/architecture/             当前实现、能力研究、ADR与契约草案
docs/specs/                    UI、采集、修复、网站和回显契约
docs/guides/                   使用与开发步骤
docs/testing/                  当前证据索引、覆盖、真机摘要和实验计划
docs/releases/<version>/       历史评审与版本指南
docs/reference/                安全与来源
docs/governance/               治理规则、问题账本、清单和本报告
docs/*.md旧路径                仅兼容跳转
```

原28个维护材料逐一审计；21份Markdown实际移动，旧位置保留短跳转。prompt1/2与SOURCE-SHA256SUMS逐字节保留；README/START与QA入口按职责整理，治理前README另保留历史快照。没有删除独有历史内容，移动前逐一核对绝对路径边界、原SHA256和目标不存在。

原件备份：工程内 `.local/docs-governance-20261023-original/`（28份，含snapshot.json索引；不进入交付）。完整机器清单包含原标题/主题/读者/引用/独有价值/冲突/状态/操作/目标/依据/风险及摘要：[migration-manifest.json](migration-manifest.json)。

## 文件迁移清单

| 原路径 | 当前路径 | 操作/理由 | 独有信息/待决 |
|---|---|---|---|
| `docs/ARCHITECTURE.md` | `docs/architecture/ARCHITECTURE.md` | move_with_redirect：当前两条诊断链与证据模型 | 保留；无迁移待决 |
| `docs/BUILD-REPORT.md` | `docs/releases/0.1.0/BUILD-REPORT.md` | move_with_redirect：0.1构建与79项测试 | 保留；无迁移待决 |
| `docs/COVERAGE.md` | `docs/testing/COVERAGE.md` | move_with_redirect：L00-L17实现与验证范围 | 保留；无迁移待决 |
| `docs/DESIGN-SYSTEM.md` | `docs/specs/DESIGN-SYSTEM.md` | move_with_redirect：Material3与交互验收 | 保留；无迁移待决 |
| `docs/DNS-REPAIR.md` | `docs/guides/DNS-REPAIR.md` | move_with_redirect：导入、预览、保存与复测 | 保留；无迁移待决 |
| `docs/ECHO-CONTRACT.md` | `docs/specs/ECHO-CONTRACT.md` | move_with_redirect：严格HTTPS回显v1 | 保留；无迁移待决 |
| `docs/EVIDENCE-ACQUISITION-SPEC.md` | `docs/specs/EVIDENCE-ACQUISITION-SPEC.md` | move_with_redirect：采集质量、冲突、尝试与预算 | 保留；无迁移待决 |
| `docs/PRODUCT-SPEC.md` | `docs/product/PRODUCT-SPEC.md` | move_with_redirect：产品目标与已确认要求 | 保留；无迁移待决 |
| `docs/prompt1.txt` | `docs/prompt1.txt` | retain_exact：研究与治理的原始要求 | 保留；无迁移待决 |
| `docs/prompt2.txt` | `docs/prompt2.txt` | retain_exact：研究与治理的原始要求 | 保留；无迁移待决 |
| `docs/RAW-DNS.md` | `docs/guides/RAW-DNS.md` | move_with_redirect：原始DNS查询与结果边界 | 保留；无迁移待决 |
| `docs/REPAIR-WORKFLOW-SPEC.md` | `docs/specs/REPAIR-WORKFLOW-SPEC.md` | move_with_redirect：修复状态与生效验证 | 保留；无迁移待决 |
| `docs/SECURITY.md` | `docs/reference/SECURITY.md` | move_with_redirect：当前数据与网络防护边界 | 保留；无迁移待决 |
| `docs/SOURCES-LICENSES.md` | `docs/reference/SOURCES-LICENSES.md` | move_with_redirect：依赖与参考项目来源 | 保留；无迁移待决 |
| `docs/V0.2.0-REVIEW.md` | `docs/releases/0.2.0/REVIEW.md` | move_with_redirect：0.2.0交付时的变化与测试 | 保留；无迁移待决 |
| `docs/V0.3.0-REVIEW.md` | `docs/releases/0.3.0/REVIEW.md` | move_with_redirect：0.3.0交付时的变化与测试 | 保留；无迁移待决 |
| `docs/V0.4.0-REVIEW.md` | `docs/releases/0.4.0/REVIEW.md` | move_with_redirect：0.4.0交付时的变化与测试 | 保留；无迁移待决 |
| `docs/V0.4.0-TEST-GUIDE.md` | `docs/releases/0.4.0/TEST-GUIDE.md` | move_with_redirect：0.4.0专属测试步骤，不代表已执行 | 保留；无迁移待决 |
| `docs/V0.5.0-REVIEW.md` | `docs/releases/0.5.0/REVIEW.md` | move_with_redirect：0.5.0交付时的变化与测试 | 保留；无迁移待决 |
| `docs/V0.5.0-TEST-GUIDE.md` | `docs/releases/0.5.0/TEST-GUIDE.md` | move_with_redirect：0.5.0专属测试步骤，不代表已执行 | 保留；无迁移待决 |
| `docs/V0.6.0-NETWORK-DIAGNOSTICS.md` | `docs/specs/NETWORK-DEEP-DIAGNOSTICS.md` | move_with_redirect：0.6网站与网络深度诊断 | 保留；无迁移待决 |
| `docs/V0.6.0-REVIEW.md` | `docs/releases/0.6.0/REVIEW.md` | move_with_redirect：0.6.0交付时的变化与测试 | 保留；无迁移待决 |
| `docs/V0.6.0-TEST-GUIDE.md` | `docs/releases/0.6.0/TEST-GUIDE.md` | move_with_redirect：0.6.0专属测试步骤，不代表已执行 | 保留；无迁移待决 |
| `qa/INDEPENDENT-QA-REPORT.md` | `qa/INDEPENDENT-QA-REPORT.md` | links_only：0.1独立QA | 保留；无迁移待决 |
| `qa/README.md` | `qa/README.md` | update：阅读/构建/测试入口 | 保留；无迁移待决 |
| `README.md` | `README.md` | update：阅读/构建/测试入口 | 保留；无迁移待决 |
| `SOURCE-SHA256SUMS.txt` | `SOURCE-SHA256SUMS.txt` | retain_exact：原源码包的历史哈希 | 保留；无迁移待决 |
| `START-HERE.zh-CN.md` | `START-HERE.zh-CN.md` | update：阅读/构建/测试入口 | 保留；无迁移待决 |

## 研究与冲突处理

研究完成任务→证据缺口→来源/权限/干扰比较、模块/能力协商、ADR、统一事件草案和15项实验设计。主要建议是先补统一来源与只读代理协同，再按问题引入外部/特权后端；新增能力均明确未实现。

文档修正了旧HTTPS约束泛化、发布前/后真机混淆、已实施功能仍称待确认、双报告与修复闭环边界及依赖表遗漏。具体问题和依据见[AUDIT](AUDIT.md)。专业报告版本硬编码、深度基线未接入等代码问题只登记，不用文档整理掩盖。规范唯一入口、生命周期和同步规则见[GOVERNANCE](GOVERNANCE.md)。

## 验证结果

- 本地文档检查：62份Markdown，324个本地链接，0错误、0警告；外链109个仅登记，未批量联网验证。
- 文档工具自测：16项，0失败、0错误、0跳过。
- protectedProjectFiles：341项核对，341项未改变。
- externalEvidenceFiles：17项核对，17项未改变。
- retainedInputs：3项核对，3项未改变。
- originalDocumentBackups：28项核对，28项未改变。

机器结果：[链接与导航](../../verification/docs-governance-2026-10-23/links.json)、[工具自测](../../verification/docs-governance-2026-10-23/tool-tests.json)、[原件与受保护文件](../../verification/docs-governance-2026-10-23/preservation.json)、[当前摘要与旧路径扫描](../../verification/docs-governance-2026-10-23/final-consistency.json)。检查覆盖本地Markdown常见语法、大小写、相对路径、支持的锚点、导航和迁移目标；限制随结果列出，不等于完整CommonMark或技术语义证明。人工复核了双链预算、权限、只读API、研究/现状和历史范围。

没有改App源码、构建配置、运行时权限或历史APK/ZIP；没有新构建/手机/模拟器实验。纳入项目工具的新增代码是无依赖文档检查器与它的自测；本次迁移辅助脚本留在.local中，不作为App或发布依赖。历史verification和工程外17份原证据均按备份摘要核对；未将敏感真机JSON复制到源码。

## 尚待后续任务

代码欠账、真实API版本/端点、跨后端关联、全设备/DNS路径与高级权限实验见问题账本。这些需要实现或新实测，不能由本次整理宣称完成。L00–L17历史上游手册身份尚待补；本地完整证据不随源码包携带。无Git差异/提交可提供，审查使用原件、机器映射、当前摘要和上述报告。
