# 文档治理规则

状态：Active；适用本工程；维护：项目维护者；2026-10-23；[文档导航](../README.md)。

## 单一权威与职责

唯一完整导航是docs/README.md；根README概述项目，START-HERE只提供阅读路线。每个主题的权威入口列在导航表，其他文档用链接引用。产品规范是要求，当前架构是实现事实，研究Draft是候选，历史报告是时间限定证据；发生冲突时先核源码/实测和用户已确认决策，再修当前说明，不能修改历史来制造一致。

product放需求；architecture放实现与标注状态的研究；specs放可验收契约；guides放操作；testing放覆盖和证据索引；releases按版本保留历史；reference放安全与来源；governance放维护规则与审计。没有内容不建目录。既有稳定英文文件名保留，不只为大小写改名。

## 生命周期

| 状态 | 含义 | 转换要求 |
|---|---|---|
| Draft | 设计/提案未落地 | 经明确决策后才成为Active要求；实现与实测另记 |
| Active | 此主题当前维护入口 | 说明适用版本、实现范围与证据；不等于全部需求已完成 |
| Unverified | 某事实/能力缺少足够验证 | 补证据才转实测状态，不能靠润色移除不确定性 |
| Superseded | 被明确替代 | 保留目标链接；兼容页不复制规范正文 |
| Archived | 时间固定的历史材料 | 保留失败/未测/旧审批原意，只修可确定引用或追加导航 |

关键文档最少有标题、职责/状态、适用范围、维护角色及最后核查依据。责任写维护角色，不虚构个人owner。日期变化本身不证明技术仍正确。

## 变更与文档同步

| 变化 | 必须核对 |
|---|---|
| 新功能、权限、默认模式 | PRODUCT-SPEC、权限能力矩阵、SECURITY、操作指南 |
| 探针、重试、预算、报告字段 | ARCHITECTURE、对应契约、证据规范、兼容测试 |
| 修复/应用/恢复 | REPAIR-WORKFLOW-SPEC、修复指南、生效/失败验收 |
| UI/导航/无障碍 | DESIGN-SYSTEM、当前指南、真机覆盖 |
| 发布/新增实测 | 版本评审、CURRENT-STATUS；原始证据追加不覆盖 |
| 移动/改名 | 迁移映射、引用重算、旧入口、静态检查 |

## 检查命令与局限

在工程根执行：

```powershell
python tools/test_check_docs.py -v
python tools/check_docs.py --root . --migration-manifest docs/governance/migration-manifest.json --json verification/docs-governance-2026-10-23/links.json
```

工具支持常见Markdown链接/图片/引用、URL编码、本地路径精确大小写、简单标题锚点、docs索引可达性及迁移目标；忽略代码区和生成目录。合法导航循环允许。不是完整CommonMark解析器；远程链接只登记不抓取，代码中的路径和语义一致性要另查。具体限制随JSON输出。

原输入prompt、历史dist/verification、第三方许可、SOURCE-SHA256SUMS.txt及工程外手机原始数据不参与“整理就重写”。历史版本指南不作为当前唯一操作依据；有价值的独立背景保留，通过职责标签降低重复。

## 没有Git时如何审查与恢复

本次没有Git仓库。原维护文档逐字节保存在 `.local/docs-governance-20261023-original/`，snapshot.json记录摘要；该本地目录不进入源码发布。机器清单记录旧路径→新路径和原始摘要。恢复前先保存当前改动，按清单逐项比较与复制，不能用递归删除或全目录覆盖回滚。重新执行迁移脚本应拒绝已存在目标，避免覆盖后续修改。

迁移后的文件摘要与新增清单由验证结果保存；它与历史交付清单分开。未解决事项在[AUDIT](AUDIT.md)，不通过自动检查掩盖。
