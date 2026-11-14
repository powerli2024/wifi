# 来源与许可清单

> 类型：来源清单；状态：Active；范围：0.6.0现状或明确标注的目标要求；维护：项目维护者；核对：2026-10-23。
> [文档导航](../README.md) · [当前验证](../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

核对日期：2026-10-21。0.3.0 基于用户提供的本目录工程审查扩展。参考项目用于理解功能与证据边界，没有复制其应用代码、TUN 转发栈或代理核心。

## GitHub 参考项目（不作为本版依赖）

| 项目 | 用途/取舍 | 官方许可入口 |
|---|---|---|
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | 参考连接记录、PCAP 证据和抓包交互；不复用其 VpnService，避免替换被测 VPN | [GPLv3](https://github.com/emanuele-f/PCAPdroid/blob/master/COPYING)；子组件需另审 |
| [NetGuard](https://github.com/M66B/NetGuard) | 参考应用规则、VPN 生命周期与 IPv4/IPv6 边界；本版无转发和防火墙 | [GPLv3](https://github.com/M66B/NetGuard/blob/master/LICENSE) |
| [Rethink](https://github.com/celzero/rethink-app) | 参考策略、DNS 事件与网络记录分离；本版不推断其他应用 UID | [Apache-2.0](https://github.com/celzero/rethink-app/blob/main/LICENSE) |
| [Firestack](https://github.com/celzero/firestack) | 后续独立转发内核候选；本版不需要且不集成 | [MPL-2.0](https://github.com/celzero/firestack/blob/n2/LICENSE) |
| [zdtun](https://github.com/emanuele-f/zdtun) | 后续用户态转发候选；本版不集成 | [LGPLv3](https://github.com/emanuele-f/zdtun/blob/master/COPYING) |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) | SOCKS/TUN 转发候选，不是分析器；本版不集成 | [MIT](https://github.com/heiher/hev-socks5-tunnel/blob/main/LICENSE) |

上传研究涉及的 ClashMetaForAndroid、clashmi、FlClash、hiddify-app、Karing、sing-box 等都是将来可被外部实验验证的对象，不是本项目继承或打包的组件。未把材料中的提交快照冒充本次重新拉取的代码版本。

若以后复用 GPL/LGPL/MPL 组件，需要对具体版本、链接/分发方式与传递依赖重新审查，不能沿用“参考”这一列作为复制授权。本清单是工程来源说明，不是法律意见。

## 官方平台依据

- [Android VPN 指南](https://developer.android.com/develop/connectivity/vpn)：活动 VPN 的互斥与平台边界。
- [DnsResolver](https://developer.android.com/reference/android/net/DnsResolver)：异步系统解析与 CancellationSignal。
- [读取网络状态](https://developer.android.com/develop/connectivity/network-ops/reading-network-state)：默认网络 callback 与变化可见性。
- [NetworkCapabilities](https://developer.android.com/reference/android/net/NetworkCapabilities)：网络能力不是实际业务流量路径证明。
- [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection)：标准 TLS 请求。
- [网络安全配置](https://developer.android.com/privacy-and-security/security-config)：正常系统信任与明文控制。
- [Storage Access Framework](https://developer.android.com/training/data-storage/shared/documents-files)：用户选择导出位置。
- [RFC 8484 §8](https://www.rfc-editor.org/rfc/rfc8484#section-8)：DoH 传输保密不等于流量必经代理。
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)：DNS 报文、压缩和 UDP/TCP 传输。
- [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html)：OPT 记录和扩展响应码。

## 本项目直接依赖与工具

| 名称 | 固定版本 | 用途 | 许可 |
|---|---|---|---|
| Kotlin JVM/Android 与 stdlib | 2.1.20 | 编译与 APK 运行库 | [Apache-2.0](https://github.com/JetBrains/kotlin/blob/v2.1.20/license/LICENSE.txt) |
| SnakeYAML | 2.7 | APK 内受限 YAML 节点解析；不构造任意对象 | [Apache-2.0](https://github.com/snakeyaml/snakeyaml/blob/master/LICENSE.txt)；版本元数据见 [Maven Central](https://repo.maven.apache.org/maven2/org/yaml/snakeyaml/2.7/snakeyaml-2.7.pom) |
| Material Components Android | 1.13.0 | Material 3 Views UI | [Apache-2.0](https://github.com/material-components/material-components-android/blob/1.13.0/LICENSE) |
| AndroidX | 按 runtime-dependencies.log 锁定 | AppCompat/Activity/生命周期等 UI 传递库 | [Apache-2.0](https://github.com/androidx/androidx/blob/androidx-main/LICENSE.txt) |
| Kotlin Coroutines / JSpecify | 1.6.4 / 1.0.0 | UI 传递库与注解 | [Coroutines](https://github.com/Kotlin/kotlinx.coroutines/blob/1.6.4/LICENSE.txt)、[JSpecify](https://github.com/jspecify/jspecify/blob/main/LICENSE)，Apache-2.0 |
| Android Gradle Plugin | 8.9.2 | 构建 | Apache-2.0；具体发布元数据见 Google Maven |
| Gradle / wrapper | 8.13 | 构建与 wrapper 引导 | [Apache-2.0](https://github.com/gradle/gradle/blob/v8.13.0/LICENSE) |
| Android SDK | Platform35 / Build Tools35.0.0 | API 与打包工具 | [Google Android SDK Agreement](https://developer.android.com/studio/terms) 及组件第三方许可 |
| JDK | 17 | 本机0.2.0使用已安装Oracle JDK17；0.1.0历史使用Temurin17.0.20.1+1 | 各发行版自己的许可；不打入APK或源码包 |
| JUnit | 4.13.2 | 仅测试 | [EPL-1.0](https://github.com/junit-team/junit4/blob/r4.13.2/LICENSE-junit.txt) |
| Robolectric | 4.14.1 | 仅本地 Android 框架模拟测试，不打入 APK | [MIT](https://github.com/robolectric/robolectric/blob/robolectric-4.14.1/LICENSE) |
| Python 标准库 | 环境提供 | 本地回环 fixture 测试 | PSF License |
| cryptography | 本机测试50.0.2 | 仅fixture测试临时生成证书，不是生产服务/APK依赖 | Apache-2.0 OR BSD-3-Clause，见安装包元数据 |

传递依赖清单由 Gradle dependency report 保存于 `verification/`。测试依赖不会自动作为运行依赖打入 APK；最终以 APK 内容和依赖报告为准。

## 0.1.0 历史工具下载校验

- Gradle 8.13 bin ZIP：SHA256 `20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78`，来自官方 distributions 的同名 `.sha256`。
- Android command line tools Linux 15859902：SHA256 `4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583`，来自 Android Studio 官方下载页。
- Temurin JDK17.0.20.1+1 Linux x64：SHA256 `3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`，来自 Adoptium 官方资产元数据。

上述仅用于本次构建的工具不会打入源码交付包。源码包包含 Gradle wrapper JAR 和校验锁定的 wrapper properties。

## 0.6.0 已核实的依赖增量

依据工程 core/build.gradle.kts、APK内 THIRD_PARTY_NOTICES.txt 与 verification/v0.6.0/runtime-dependencies.log，补充下列清单遗漏；不修改现有版权或许可证正文。

| 依赖 | 版本 | 用途与已随包声明 |
|---|---|---|
| [OkHttp](https://github.com/square/okhttp) | 4.12.0 | 网站探测运行依赖，Apache-2.0 |
| [Okio](https://github.com/square/okio) | 3.6.0 | 传递运行依赖，Apache-2.0 |
| MockWebServer / okhttp-tls | 4.12.0 | 仅测试，未作为运行依赖打包 |

2026-10-23 新架构研究的官方来源与本地快照约束单独见 [能力矩阵](../architecture/CAPABILITY-MATRIX.md)。原下载摘要和参考许可证链接为历史信息，不表示本轮重新验证其全部远程内容。
