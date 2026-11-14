# 构建与验证

状态：Active；范围0.7.0源码；[文档导航](../README.md)。本页列出可复现命令，执行结果与测试数字由[当前验证](../testing/CURRENT-STATUS.md)和[0.7.0评审](../releases/0.7.0/REVIEW.md)记录。

需要JDK17、Android SDK Platform35/Build Tools35.0.0；Gradle8.13、AGP8.9.2、Kotlin2.1.20按仓库锁定。app是Android模块，core是JVM模块。工具环境安装与许可需按实际主机确认；不要把历史构建环境自动当成当前环境。

从工程根目录执行：

```powershell
.\gradlew.bat -I qa/include-tests.init.gradle :core:test :app:assembleDebug :app:lintDebug :app:testDebugUnitTest
python tools/test_check_docs.py -v
python tools/check_docs.py --root . --migration-manifest docs/governance/migration-manifest.json --json verification/docs-governance-2026-10-23/links.json
```

Gradle命令是构建/测试入口，不包含所有独立控制器与Python夹具检查；详见[QA说明](../../qa/README.md)。APK默认输出 app/build/outputs/apk/debug/app-debug.apk；dist 中各已交付版本为冻结文件，新版本另命名并核对版本、签名和 SHA-256。旧 SOURCE-SHA256SUMS.txt 不代表工作树当前内容。

0.7.0 的主要回归位置：`core/src/test` 中的 EvidenceEnvelopeTest、ProxyCooperationTest；`app/src/test` 中的 DeepReportAnalysisTest、DeepReportComparisonTest、DeepEvidenceEnvelopeTest、DeepDiagnosticsActivityTest 以及 ProxyCooperationSessionTest/ProxyCooperationActivityTest。它们验证来源外壳、报告规则、受控 API 和界面生命周期；测试中的假平台或注入信任不等于真实手机或生产 TLS 已通过。按实际编译发现的测试类选择目标，不在已有全套验证通过后无原因反复重跑。

独立控制器与已有 Python 受控夹具按 QA 说明补充；新增代理 API 测试使用本机受控服务，不接触用户 Secret 或真实控制端点。生产读取只接受系统信任的 HTTPS；不要为测试方便改生产 TrustManager、主机名校验或 Android 网络安全设置。

版本只修改 Android 构建配置中的 versionName/versionCode，业务层通过 `AppIdentity.version` 取得 `BuildConfig.VERSION_NAME`。专业、深度和协同报告应记录相同安装版本；历史报告不回填。EvidenceEnvelope 是附加来源元数据，保留既有 reportKind/schemaVersion 和原探针结果，不用外壳取代详细完整性判断。

深度基线与协同结果均在进程内；开发测试需覆盖取消、换网、未完成报告禁止保存基线、原计划复测不受新表单输入影响、冻结双报告导出与旧回调隔离。代理只读协同另检查固定 GET 白名单、无自动跳转/重发、Secret 脱敏、尺寸/时限、401/403/404及跨入口忙碌保护。API 快照尚未关联到本应用请求，测试不能以“API可达”断言代理路径正确。

模拟器继续按用户要求跳过。连接真机前明确目标设备和测试影响；已有[真机记录](../testing/DEVICE-2026-10-23.md)的仪器启动需要ADB前台辅助，不应把 am instrument 退出码当所有用例通过。需要新的设备测试时单独记录设备/客户端/网络/配置及逐项结果。

没有Git时使用治理前备份与哈希清单审查差异，不能执行git reset或虚构提交状态。源码包旧SOURCE-SHA256SUMS.txt仅对应原交付，本轮新增文件记录在迁移与验证清单。
