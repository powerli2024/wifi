# 0.5.0 实现与验证记录

> 类型：历史评审；状态：Archived；范围：对应版本的历史时点；维护：项目维护者；核对：2026-10-23。
> [文档导航](../../README.md) · [当前验证](../../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

日期：2026-10-22。基线已获用户确认。当前为调试签名试用交付，真实设备与代理实验待用户验收；本轮不运行模拟器。

## 本次实现

- 采用 Material Components 1.13.0 / Material3 DayNight：概览、测试、修复三目的地；报告子页返回原入口；标准工具栏、底部导航、按钮、卡片、复选框、对话框与有持久标签的输入框。默认场景直接填充，覆盖自定义值才确认；执行前集中确认计划。
- 修复 v0.4 演示详情里“系统解析已返回地址”的语义回归；演示优先于观察摘要与修复建议。受控局域网预期 IP 的说明不再一概禁止私网地址。
- DNS 建议按来源、执行阶段、系统诊断码、同域条件、原始协议响应和网络稳定性分流。未知系统错误、权限/参数错误、NXDOMAIN、取消与缺证据不会直接建议更换解析器。
- 专业计划默认每项一次，明确启用时限定错误最多两次。固定 500 ms 退避、每次可用超时都计入原 20/60 秒总预算；不切换目标/协议，不回退，不挑选成功覆盖首次失败。报告 schema 2 加入 attempts、maxAttemptsPerProbe、stopReason，逐次脱敏。
- 配置副本写入关闭后有界读回，核对 SHA-256、字节数并重新解析；未核对与核对失败有独立状态。用户手动导入声明单独记录，生成时绑定当前基线；更换方案、源文件或预览使旧核验失效。恢复卡可离线读取，但未自动备份或直接修改客户端。
- 交叉审查修复：第二次尝试取消/切网/超时时不覆盖首次失败；接纳结果前检查绝对总预算及已观察到的网络变化，迟到结果不能绕过停止。

## 验证范围

最终本地结果：**362 项通过，0 失败、0 跳过**。核心 184 项、控制器 46 项、Android 框架模拟 122 项（MainActivity 70 / RepairActivity 14 / RepairSession 38）、TLS fixture 10 项。APK 构建和 v2 签名验证通过，版本 0.5.0 / code 5；与 0.4.0 调试证书一致。Lint 为 **0 错误、1 提示**：targetSdk 保持 35，新版 Android 兼容性由实际设备验证，本轮未擅自扩大目标 API 升级范围。

清单中的两条 `tools:node="remove"` 被 Lint 当成需要查找类的组件引用；只对这两条移除指令标注 MissingClass 排除，并通过有效 Manifest 检查确认组件确实不存在，没有全局关闭检查。初轮构建/测试日志保留排错过程；最终结果以 `final-android-checks.log`、`controller-tests.log` 和最终 JUnit XML 为准。

最终测试计数与签名/哈希以 `verification/v0.5.0/verification-summary.json` 和 `dist/package-validation-0.5.0.json` 为准；失败必须修复后重新记录，不沿用旧版通过数。包括 core JVM、控制器假平台/回环、本地 Robolectric API29/35、TLS fixture、Lint 和有效 Manifest 检查。Robolectric 是本地框架模拟测试，不是 Android 模拟器，也不证明实际网络路径。

本轮未进行 Android 模拟器、手机安装、真实代理客户端配置导入、物理 IPv6、DoH/DoT 路径和全机 DNS 泄露实验。视觉、TalkBack、大字体、厂商文件提供者与实际网络表现按 [实测指南](TEST-GUIDE.md) 由用户验收。

## 依赖、权限与交付边界

新增 Material/AndroidX UI 依赖及传递库，版本树保存在 `verification/v0.5.0/runtime-dependencies.log`；许可说明随 APK 资源和源码交付。Material 官方 Views 库处于维护阶段，本次按已批准方案渐进迁移，后续大功能再评估 Compose。[官方说明](https://github.com/material-components/material-components-android/blob/master/docs/getting-started.md)

业务权限保持 INTERNET/ACCESS_NETWORK_STATE。有效 Manifest 额外只有 AndroidX 本应用签名级 DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION；自动 Startup 初始化提供者和 ProfileInstaller 广播接收器已从合并清单移除，无新增服务、后台自动探测或运行时敏感权限。

SAF 提供者可能阻塞；取消为协作请求，真实 IO 返回前仍占用工作槽。源文件不被本应用覆盖，但不能防止恶意提供者伪装任意别名。文件核验、用户导入确认和复测改善均非实际客户端生效/无泄露的完整证明。未实现日志导入、持久历史、独立 DoH/DoT 探针、自动恢复或跨应用检测。

本机构建使用 JDK17、Gradle8.13、AGP8.9.2、SDK35，并在这次 Gradle 进程使用 Windows 系统证书库以访问官方仓库；未关闭 TLS 验证或更改全局证书配置。源码不包含本地缓存、调试私钥或用户报告。
