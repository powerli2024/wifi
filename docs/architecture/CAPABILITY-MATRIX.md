# 权限、采集能力与干扰矩阵

状态：Draft（技术可行性研究，含0.7.0实现标注）；核查2026-10-23；[文档导航](../README.md)。实现与实测状态逐项列出，官方API存在不等于本项目/本机可用。

## 采集与授权

| 能力/用户任务 | 数据与位置 | 授权/依赖及版本条件 | 对原代理的影响 | 当前证据 |
|---|---|---|---|---|
| 普通网络画像 | Android默认/可见网络、接口、路由、DNS、MTU、系统代理 | INTERNET、ACCESS_NETWORK_STATE为普通清单权限；项目minAPI29，字段按系统可见性 | 被动读取；不是包路径 | 已实现，有限真机记录 |
| 网站/DNS探针 | 本应用DNS、socket、TLS、HTTP及原始DNS结果 | 普通网络能力；平台DNS/TLS与默认代理；系统可能延迟取消 | 产生请求、日志、缓存和计费流量；不主动绑定底层 | 已实现，部分正/负例真机 |
| Clash/Mihomo兼容API只读协同 | 后端版本、活跃连接数量、有界ID/元组/host/chains/rule；不保留进程字段或原始JSON | 用户提供HTTPS origin与可选Secret，明确确认后读取；平台TLS校验，不是Android运行时权限 | 不替换VPN；两项GET会产生API请求，不持续采样 | 0.7.0已接入/version与/connections并做受控测试；真实代理API未测，未关联本应用 |
| 自有VpnService | 本工具TUN实际接收的IP包 | 系统VPN用户授权、服务声明、转发实现；UID查询API29+另受VPN身份约束 | 同一用户/资料的新VPN会替换已有服务，改变被测对象 | 官方支持；未实现 |
| ADB主机协作 | shell可见状态/日志、调试App、受控USB端点/文件 | USB或无线调试信任；shell权限与生产构建/厂商限制 | 可不替换VPN；命令本身可改变环境，需记录 | 已做USB受控TLS/取消实验；非全设备抓包 |
| Root/系统捕获 | 指定接口包、可得进程辅助信息 | Root授权、采集工具、SELinux与设备内核共同决定 | 不必替换VPN；抓包位置/负载可能影响实验 | 未实现/未实测 |
| 外部网关 | 经过该网关/接口的包与时序 | 用户控制网关/镜像设备、捕获许可、过滤器与时钟校准 | 可保持App权限；改路由会改变条件，蜂窝可能完全不覆盖 | 尚无完整关联闭环 |
| 受控回显/权威DNS | 服务端来源地址、requestId、nonce查询和递归器来源 | 自有或获准服务、日志访问与明确保留范围 | 增加目标/域名；缓存和递归链影响观察 | 回显契约/夹具已有；权威DNS关联未实现 |

VpnService互斥与TUN范围依据[Android VPN](https://developer.android.com/develop/connectivity/vpn)。API29的[getConnectionOwnerUid](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress))受活动VPN/权限约束，仅TCP/UDP；普通诊断App不能泛查其他应用UID。[网络owner UID](https://developer.android.com/reference/android/net/NetworkCapabilities#getOwnerUid())也受隐私过滤。[LinkProperties](https://developer.android.com/reference/android/net/LinkProperties)是配置，HTTP代理字段不能证明所有App遵循它。

## 可见深度、盲区与降级

| 后端 | 应用归属与协议内容 | 盲区/错误风险 | 成本/隐私 | 不可用时与验证方法 |
|---|---|---|---|---|
| 普通API/探针 | 本应用请求身份明确；客户端可见TLS协商；正文只计数 | 其他App、实际DNS线上路径、VPN外层不可见 | 有界请求；完整导出含网络标识 | 缺字段记原因；用内置正/负例和同计划复核 |
| 代理API | 核心声明的规则/链；当前不采集UID，不是系统背书 | 单次快照最多保留100条；短连接可能漏采；兼容层字段语义不同 | Secret可能同时有写权限；连接元数据敏感；当前不持续采样 | 无接口继续基础模式；合成API已测，真实API及受控关联待验 |
| 自有VPN | 有条件的UID映射与IP/TCP/UDP元数据 | 排除应用、其他资料、绑定/绕行；加密内容不可自动解密 | 全量包敏感、转发与功耗高、改变路径 | 可改用外部网关/代理证据；需覆盖正对照与丢包统计 |
| ADB | shell提供的可见字段；debuggable本应用可提取自身数据 | 调试授权不保证tcpdump、root、他App私有目录或完整日志 | 设备控制范围广；日志须限量/脱敏 | 只读命令白名单、能力预检；无权限不升级为故障 |
| Root/网关 | 采集点可见包；UID需另外来源关联 | 内层/外层不同，丢包/时钟误差；网关通常无Android UID | 大量敏感流量、存储/CPU成本 | 受控已知流量验证接口、过滤器、丢失；不全量默认常开 |
| 受控服务 | 请求ID/服务来源、DNS权威侧递归器 | 端点可能撒谎、共享NAT、缓存；不能单独证明设备第一跳 | 服务端也保留日志；随机域名具关联性 | 记录服务版本与可信来源；与独立采集点对照 |

[ADB官方说明](https://developer.android.com/tools/adb)与[adbd源码](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/daemon/restart_service.cpp)区分调试通道和root能力；[SELinux](https://source.android.com/docs/security/features/selinux)同样限制root进程。厂商/系统差异要以实际设备能力检测，不能写“授权后必有全量包”。

抓到IP包不等于HTTPS明文。[Android网络安全配置](https://developer.android.com/privacy-and-security/security-config)允许应用采用不同信任及固定策略；用户CA不保证目标接受。TLS1.3证书消息也在加密握手部分，依据[RFC8446协议说明](https://www.rfc-editor.org/rfc/rfc8446#section-2)；抓包解析器不能承诺总能提取证书/域名/正文。受控解密仅作为自有调试客户端的单独实验，不要求全局关闭验证。

## 代理只读边界与本地源码核查

按端点白名单定义被动读取，不以HTTP方法决定是否只读。0.7.0只实现GET /version和GET /connections，每项3秒、总预算15秒、每响应256KiB；/rules、/proxies仍是按诊断问题评估的后续候选。/delay、healthcheck、/dns/query会触发主动请求，当前不调用，也不能混入后台采集。[官方API](https://wiki.metacubex.one/api/)、[路由/鉴权](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/hub/route/server.go)、[DNS查询](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/hub/route/dns.go)支持此区别。

Secret在所核路由中没有独立只读角色。客户端白名单是本工具的行为限制，不能降低泄漏密钥的真实权限。禁止把密钥放URL、日志和报告；禁重定向。/connections是活跃列表/定期快照，漏掉短连接不等于旁路，依据[连接源码](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/hub/route/connections.go)与[Tracker](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/tunnel/statistic/tracker.go)。

共同`evidenceEnvelope`已提供最小来源、范围和关联未建立标注；没有实现完整事件草案、跨后端关联器或自适应实验选择。以下源码研究仍用于后续兼容核验，不能替代真实API验收。

以下是本地工作区参考源码，使用项目根外路径仅作研究记录，未复制入App；它们不是源码包的构建依赖：

| 快照与位置 | 已核事实 | 限定 |
|---|---|---|
| ClashMetaForAndroid/core/src/main/golang/native/config/process.go:19-21,44-46 | 清空导入配置的external-controller/TLS，再应用覆盖 | 订阅内地址不等于最终控制口 |
| ClashMetaForAndroid/design/src/main/java/com/github/kr328/clash/design/OverrideSettingsDesign.kt:144-179 | 覆盖设置有控制地址与Secret | 需用户提供实际启用信息 |
| ClashMetaForAndroid/service/src/main/java/com/github/kr328/clash/service/clash/module/TunModule.kt:27-36,49-65 | API29+UID查询；HTTP入站为随机回环地址/端口 | 可解释真机回环代理的可能来源，不证明手机必运行此提交；入站不是控制API |
| sing-box/experimental/clashapi/connections.go:32-36,62-103 | 过滤DNS出站，rulePayload为空，归属字段可能来自包名/UID | 不能按“Clash兼容”假定与Mihomo语义完全相同 |

CMFA本地父提交3cc102aab3f251ef460a3b6e2835b6c1eb581e73；Mihomo gitlink=88dcbf7f1614a67c3b36b848ee3592dfa92ada36，但该子模块目录未初始化。官方Meta分支源码已核读，固定gitlink raw获取未成功；未把官方当前分支当作手机精确版本。后续适配必须补实际核心版本、固定源码身份与兼容实验。
