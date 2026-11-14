# Android 代理证据诊断

当前开发版本 **0.7.0**，Android 10/API29 起。目录名保留导入版本。工具通过 Android 网络画像、本机受控实验、网站 DNS/连接/TLS/HTTP 分层探测、专业 DNS/出口核验、代理只读快照及配置副本流程，帮助定位问题并保存证据。构建与报告的版本统一来自 Android BuildConfig。

- 第一次使用或理解源码：[开始阅读](START-HERE.zh-CN.md)。
- 全部规范、指南、研究与历史记录：[文档总入口](docs/README.md)。
- 已实现、已验证和剩余限制：[当前验证状态](docs/testing/CURRENT-STATUS.md)。
- 构建与文档检查：[开发指南](docs/guides/DEVELOPMENT.md)。

0.7.0 新增：更紧凑的分层报告、默认折叠详情与固定工具栏导出；进程内深度基线、原计划复测和双报告导出；用户明确提供控制 API 后的只读版本/连接快照。详见[本版变化](docs/releases/0.7.0/REVIEW.md)与[实测步骤](docs/releases/0.7.0/TEST-GUIDE.md)。本版最终本地测试560项通过，Lint 0错误/1条targetSdk提示；手机未连接，真机验收待执行。

代理协同当前只接受正常平台证书验证的 **HTTPS 控制 API origin**，只请求 `GET /version` 与 `GET /connections`；普通 HTTP 控制口和 HTTP/SOCKS 代理入口不适用。它不自动发现接口，不写配置，不关闭连接，也没有把连接快照直接关联到本应用网站实验。统一证据来源字段不表示已经实现完整事件关联、全机覆盖或 DNS 无泄露判定。

本版试用包：[0.7.0 APK](dist/android-proxy-diagnostics-0.7.0-debug.apk)、[源码包](dist/android-proxy-diagnostics-0.7.0-source.zip)、[SHA-256](dist/SHA256SUMS-0.7.0.txt)。[验证状态](docs/testing/CURRENT-STATUS.md)说明适用范围。历史dist与verification保留；当前工作目录根部原有SOURCE-SHA256SUMS.txt仍是0.6冻结清单，0.7源码ZIP内部附本次源码清单，两者不要混用。

用户原始报告与真机完整数据位于工程外。默认报告脱敏、完整配置可能含原凭据；权限与数据约束以[安全说明](docs/reference/SECURITY.md)为准。原有第三方许可保留，未新增对外开源许可。
