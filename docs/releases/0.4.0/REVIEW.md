# 0.4.0 试用包与开发冻结记录

> 类型：历史评审；状态：Archived；范围：对应版本的历史时点；维护：项目维护者；核对：2026-10-23。
> [文档导航](../../README.md) · [当前验证](../../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

日期：2026-10-22。**当前为试用包，有已知界面回归未通过；不是完整验收通过的发布版。** 用户要求跳过 Android 模拟器检查，先完善开发文档并确认，再继续修改应用。后续应用代码已暂停；本轮仅构建冻结代码、记录验证结果和更新文档。用户将进行实体设备检查。

## 已写入当前代码的改动

- 原长页面拆为“首页 / 测试 / 结果”，首页包含快速 DNS、专业测试、修复入口及能力说明。原始 DNS 参数按选择展开。
- 专业测试提供系统 DNS、DNS 连通对照、HTTPS 出口核验三种填表建议；执行前仍须核对目标。未启用模块收起字段，非法输入在字段旁指出。
- 结果先显示系统 DNS、UDP DNS、TCP DNS、HTTPS 出口状态和下一步，详细证据可展开。保留基线比较、冻结导出、取消和进程内草稿。
- 系统 DNS 新增安全诊断信息：回调阶段、DNS responseCode、resolverErrorCode、systemErrno、固定 exceptionKind；不保存异常原文。报告 schema 2 使用新增可空字段兼容旧记录，HTTPS 契约仍为 v1。
- 新增纯核心摘要、场景建议及系统 DNS 诊断规则；默认网络行为未改，未新增权限或网络 SDK。

以上是用户要求暂停之前的改动。目标导航“概览 / 测试 / 修复”、完整 Material 3 组件迁移、自动重试、持久记录和更完整修复状态机仅为[下一阶段规划](../../product/PRODUCT-SPEC.md)，尚未实施。

## 当前验证结果

| 验证 | 结果 | 证据与限制 |
|---|---|---|
| APK构建 | 成功，versionName 0.4.0 / versionCode 4 | `verification/v0.4.0/build-tests-final.log` 中 assembleDebug 完成；后续 UI 测试失败使整次命令最终失败，不能将整次构建检查称全通过 |
| 核心 JVM | 146 / 146 通过 | `core-junit/`，不是真实 Android 网络路径 |
| Android框架模拟 | 70 / 72 通过，2失败 | `ui_framework-junit/`；同一演示文案测试在API29和API35各失败一次 |
| 控制器隔离测试 | 33 / 33 通过 | `controller-junit/`；含新增系统DNS错误码及取消后迟到回调 |
| 本地HTTPS开发服务 | 10 / 10 通过 | `tls-fixture-tests.log`；仅本地受控fixture |
| 静态分析 | 0 errors / 7 warnings | 1条target API提示，6条文本本地化提示；`lint.txt` |
| 源码约束 | 通过 | `source-guardrails.txt`；仅静态约束，不证明真实路由 |
| APK签名与清单 | 校验通过 | `apk-signature.txt`、`apk-badging.txt`；调试签名、min29、target35、仅INTERNET与ACCESS_NETWORK_STATE |
| 模拟器 / Android仪器测试 | **按用户要求跳过** | 本轮未在模拟器安装或运行该版本。先前启动的专用模拟器已关闭；历史0.3结果不沿用为0.4通过证据 |
| 用户实体手机 / 真实代理 / DNS路径 | 待用户执行 | 未安装或修改连接的实体设备；用户提供的0.3报告仅作为需求输入 |

本地测试总计 261 项，259通过、2失败、0跳过。这里的“0跳过”只指这些本地测试用例；模拟器检查整体是明确跳过。

第一轮测试日志保留为 `build-tests-initial.log`。最后一次重建加入系统 DNS 详情展示后，最终日志 `build-tests-final.log` 出现上述两项失败。以最终结果为准，不以早先全绿记录覆盖后续失败。

## 已知问题，确认方案后优先处理

1. **演示详情的观察措辞。** `demo_advice_cannot_be_saved_as_a_real_baseline` 在两个API配置失败：新详情函数输出“系统解析已返回地址”，不符合“演示建议不能以未限定的语句诊断当前设备”的断言。界面仍有显著虚构演示标签、核心摘要仍标演示，真实基线保存条件仍排除演示；但详细文案还需统一演示语境。此次冻结不修改测试以掩盖失败，也不继续改应用。
2. 字段有可见标签但尚未用 `labelFor` 关联输入框；TalkBack未验收，完整无障碍实现不能声称通过。
3. 预期IP帮助文案对“手机局域网IP”的排除过于绝对；受控LAN回显实验仍可能有合法的私网预期，需改为按场景解释。验证器仍允许严格数字私网地址。
4. 当前主题为原生平台Material Light加手工样式，尚无完整Material3组件、暗色、统一设计tokens、文字资源化、横屏/大字/实机视觉验收。
5. 当前报告和基线仅在进程内；没有历史数据库、自动重试、外部日志关联或配置实际生效读回。

## 交付与完整性

- `dist/android-proxy-diagnostics-0.4.0-debug.apk`：当前冻结试用包，调试签名与本工程0.3一致，可在签名匹配时覆盖安装；不自动安装。
- `dist/android-proxy-diagnostics-0.4.0-source.zip`：源码、文档及验证记录；规划文档标记待确认。排除本地SDK配置、临时依赖缓存、密钥和构建缓存。
- `dist/SHA256SUMS-0.4.0.txt`、`dist/package-validation-0.4.0.json`：最终文件哈希、字节数和真实检查状态。
- `SOURCE-SHA256SUMS.txt` 为本次源码清单，旧0.3清单保留在 `verification/v0.3.0-source-sha256-original.txt`。原0.3 APK和源码ZIP不修改。
- 用户原始试测JSON位于工程外，未改动，也未拷贝进源码包；指南记录其SHA-256以确定引用的文件。

实际设备测试建议从[专业填写指南](TEST-GUIDE.md)开始。不能把编译、JVM通过、UI模拟或本次文档推演当作真实代理防泄露验证。
