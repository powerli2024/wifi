# v0.1.0 构建与测试报告

> 类型：历史报告；状态：Archived；范围：对应版本的历史时点；维护：项目维护者；核对：2026-10-23。
> [文档导航](../../README.md) · [当前验证](../../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

> 历史记录：下文随 0.1.0 源码包导入，APK 摘要和测试数字只对应当时版本。当前 0.2.0 的本机结果见 [V0.2.0-REVIEW.md](../0.2.0/REVIEW.md)，不要用旧摘要验证新版 APK。

日期：2026-10-20。交付性质：独立工程第一阶段 MVP；调试/测试版，未发布应用商店或外部源码仓库。

## 已确认的交付

- Kotlin Android 应用（minSdk 29 / Android 10；targetSdk、compileSdk 35）。
- 中文界面：显式目标确认、系统 DNS、HTTPS 回显、网络快照、五态结果、取消、离线演示、用户主动 JSON 导出。
- 无 VpnService、root、CA 安装、系统代理修改或第三方遥测。
- 完整源码、带 SHA256 校验的 Gradle wrapper、受控本地 fixture、合成报告样例、实验覆盖/安全/来源文档。

## 真实构建结果

JDK：Eclipse Temurin 17.0.20.1+1。Gradle：8.13。AGP：8.9.2。Kotlin：2.1.20。

Android SDK Platform 35 revision 2；Build Tools 35.0.0；platform-tools 37.0.1。仅在云端构建目录安装，未改变用户手机或原 Windows 工程。

最终重新运行：

```sh
./gradlew :core:test :core:exportDemo :app:assembleDebug :app:lintDebug :app:testDebugUnitTest --rerun-tasks
```

对应的本次构建实际由相同 Gradle 8.13 分发包执行，56 个任务全部执行，BUILD SUCCESSFUL。另从空 wrapper 缓存真实下载、校验并启动 `./gradlew --version` 成功。wrapper 网络等待调整为 60 秒。

Android lint：**No issues found（0 errors / 0 warnings）**。

另外，把源码复制到不含 build/.gradle/local.properties 的全新目录，仅另行提供 SDK 路径，在同一工具/依赖缓存环境离线重跑 core 测试、APK 构建与 lint：48 个任务成功。重建 APK SHA-256 与交付 APK 完全一致。这验证源码没有隐含工作目录文件依赖，不泛化为任意机器均逐字节相同。

构建工具输出有不影响本次结果的环境/工具警告：metrics 设置目录不可写（未开启遥测）、新旧 SDK XML 元数据版本提示、Gradle 9 未来弃用提示。本工程锁定 Gradle 8.13；不宣称兼容任意更新版本。

## 自动测试结果

| 层次 | 结果 | 证明了什么 | 没有证明什么 |
|---|---|---|---|
| 核心原始单元测试 | 25/25 通过 | 数字 IP/域名/HTTPS origin 输入、严格 JSON、五态优先级、脱敏 | Android 网络行为 |
| 独立核心追加测试 | 15/15 通过；与原始合计 40/40 | 对抗性边界、规范化、UUID 等回归 | 实际端点可信性 |
| Robolectric 界面模拟 | 18/18 通过（9 流程 × API29/35） | 默认不运行、空目标拒绝、取消确认、离线演示/旋转、SAF intent、旋转后冻结快照写入、取消/重试/重复回调、清除 | 真机布局/实际文件提供者/真实路由 |
| 独立控制器/导出 JVM 模拟 | 18/18 通过 | 取消发布、20秒预算、资源未释放时拒绝再启、迟到结果、冻结策略、64并发启动、错误契约、冻结导出快照、取消/重试、旧请求码保留及一次性消费 | Android OS 真正终止网络操作、真实 TLS/VPN |
| 本地回环 fixture | 3/3 通过 | requestId 契约、真实 peer、忽略伪造转发头、无效请求 | Android 请求、公网/代理出口 |

以上为 **79 个非重复测试用例**，不是 79 次手机实验。详细证据在 `verification/` 与 `qa/`，独立 QA 报告保留各自范围。

## APK 检查

文件：`app-debug.apk`，调试签名。

- applicationId：`dev.proxyaudit.android`
- versionName：`0.1.0`；versionCode：`1`
- SHA-256：`5abb6c0fec4b1b1ff0dc63d965ed07e84df57a72f9e83bafeb6cb7379c649c68`
- 验证：APK Signature Scheme v2 通过；签发者为 Android Debug。
- 证书 SHA-256：`c9e5c7eafc31ce2318de3e511c1038b933dfd36e481edd4932807b991736270e`
- 权限仅 `INTERNET` 和 `ACCESS_NETWORK_STATE`。
- 明文 HTTP 禁止、备份关闭，并显式排除 Android 12+ 云端与设备迁移数据。
- APK 运行依赖只有本项目 core、Kotlin stdlib 2.1.20 和 JetBrains annotations 13.0。JUnit/Robolectric/模拟 API 不打入 APK。

调试密钥仅用于本次构建，不交付私钥，不是生产发布签名。重新构建时调试密钥、工具环境和时间可能不同，因此这里的“可重复构建步骤”不承诺逐字节同一 APK。

## 未执行 / 已知限制

- 未在实体 Android 手机安装、测试、抓包或操作用户设备。
- 未运行 Android Emulator；Robolectric 是 JVM 框架模拟，不冒称模拟器或真机。
- 未向真实第三方探测目标发出测试流量；只完成本机回环 fixture 与无外联网的模拟探针。
- 未验证 VPN 开关/分应用、真实受控 TLS 端点、Wi-Fi/蜂窝切换、IPv6 传输、UDP/QUIC/STUN、故障断流或 DNS 保密。
- 未完成真实系统 SAF 文件提供者/云盘交互和视觉设备验收；同进程 Activity 旋转后的保存已通过框架模拟输出流回归。整个进程终止时不恢复证据 payload，系统选择器可能留下空文件，需要重新导出。
- 取消后平台资源若暂未退出，界面先停止接收证据但不会开启第二次运行。这是诚实保守处理，不是已验证 OS 级停止。

后续第一步应是受控设备端到端测试，而不是对代理安全作全面结论。

## SDK 许可

已按用户明确许可下载、安装上述 Android SDK 组件，并接受 Google Android SDK 许可条款：[Android SDK License Agreement](https://developer.android.com/studio/terms)。没有接受其他账户/购买协议，没有创建云服务、上传仓库或部署公网端点。
