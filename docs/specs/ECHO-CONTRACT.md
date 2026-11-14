# 受控 HTTPS 回显服务 v1

> 类型：协议契约；状态：Active；范围：0.6.0现状或明确标注的目标要求；维护：项目维护者；核对：2026-10-23。
> [文档导航](../README.md) · [当前验证](../testing/CURRENT-STATUS.md)。文内反引号文件路径若无说明均相对项目根。

## 请求

只接受源地址 `https://host[:port]`；路径固定为：

```text
GET /v1/echo?requestId=<随机 UUID>
Accept: application/json
Accept-Encoding: identity
Cache-Control: no-store
Connection: close
```

证书必须由 Android 系统信任且匹配主机名。工具不安装 CA、不忽略错误、不跳过主机名验证。不支持需要 Cookie、OAuth、Authorization 或查询令牌的端点。

## 响应

HTTP **200**，Content-Type `application/json`，无压缩编码，UTF-8，最多 4096 字节，恰好三个键：

```json
{"schemaVersion":1,"requestId":"请求中的完整UUID","observedSourceIp":"203.0.113.7"}
```

`schemaVersion` 必须是数字 token `1`（字符串 `"1"`、`1.0`、`1e0` 均拒绝）。requestId 必须匹配。IP 必须是严格数字 IPv4/IPv6；域名、zone id、前导零 IPv4、重复字段、额外字段、数组、null、畸形 UTF-8 或 JSON 均拒绝。IPv4-mapped IPv6 统一转为 IPv4 后比较。

服务端必须从实际连接的 peer address 得到来源 IP。不要无条件信任客户端提供的 X-Forwarded-For。若服务位于反向代理后，必须单独正确配置并验证可信代理链，否则会回显反向代理的 IP。客户端无法审计这个选择，因此必须让用户明确决定是否信任端点。

不接受 3xx 跳转。401、429、500、TLS 失败、204/空响应都只是“没有足够证据”，不是泄露或正确阻断证明。

## 本地开发 fixture

`tools/echo_fixture.py` 是仅绑定回环接口的开发服务，不是生产部署工具。它默认不启动，不包含公共端点、证书、私钥或用户数据。启动必须提供自己的证书文件和私钥：

```sh
python3 tools/echo_fixture.py --cert /path/to/cert.pem --key /path/to/key.pem --port 8443
```

只监听 `127.0.0.1`。端点使用实际 peer IP，拒绝不符合契约的请求，关闭连接，不记录 URL/请求日志。服务端时间不作为证据判断条件。

0.2.0 修复握手阻塞：最多 8 个活动工作槽，TLS 握手放在工作线程中，握手 3 秒超时；HTTP 处理有 5 秒绝对截止及读写超时。额外连接立即关闭，服务仍不接受任意 bind 参数。

`tools/test_echo_fixture.py` 在本机回环使用真实 TLS 测试契约与停滞客户端。测试通过 `cryptography` 临时生成证书，并仅在测试进程的 SSLContext 信任它；未安装 CA，也未修改 Android 信任。生产 fixture 只需 Python 标准库，测试还需 `cryptography`。这些结果不证明 Android 路由、VPN 或公网证书链已实测。

本地回环自签名证书不会被应用默认接受，这是预期安全行为。需要手机端到端测试时，由实验负责人提供已经具有有效证书的受控端点；不要为方便测试关闭应用 TLS 校验。`adb reverse` 等测试连接仍需对证书主机名和信任作正确设置。
