# APP 密钥绑定（OpenRF APP 身份确认）· 实现规范

> 面向 APP 开发（Rust / .NET / JS 均可）。照本文实现后，服务端可以**密码学地确认**
> 连接来自持有 APP 私钥的真实 APP，而不是"看 clientid 猜"。
>
> 本仓库参考实现：`cert_gen.py` 的 `build_app_signature_mqtt()`；服务端校验：
> `api_server.py` 的 `verify_app_mqtt_signature()`。

---

## 0. 为什么需要它

MQTT 上的身份来自**用户证书**（每台设备一份）。但证书是"持有即可用"的载体：
一旦被拷走，用任何 MQTT 客户端都能冒充该呼号。APP 密钥（烧在 APP 里的 Ed25519 私钥）
是**第二把锁**：服务端用 `config.dmrid.app_pubkey` 验签，只有真 APP 签得出来。

```
用户证书（每设备一份）  → 证明"你是谁"（呼号/UID）
APP 私钥（每 APP 一份）→ 证明"你用的是我的 APP"
两者都有              → 才是"本 APP"（服务端 client_attrs.app_verified = "1"）
```

## 1. 现有机制（HTTP 侧，已在用）

```
message = "FMO-APP-auth:{timestamp}:{callsign}:{userPubkeyB64}"
app_signature = base64url(Ed25519_sign(APP_SEED, UTF8(message)))
```
用于 `/api/cert/bind` 等 HTTP 接口。**问题**：这条签名没有绑定连接，
抓包后可被重放到另一条 MQTT 连接上。

## 2. 新增机制（MQTT 侧，本文要实现）

把 **clientid** 与 **用户证书公钥** 一起签进消息，使签名**只对这一条连接有效**：

```
message = "FMO-APP-mqtt:{timestamp}:{callsign}:{userPubkeyB64}:{clientid}"
app_signature = base64url(Ed25519_sign(APP_SEED, UTF8(message)))
```

逐字段含义（**务必逐字节一致**）：

| 字段 | 取值 | 说明 |
|---|---|---|
| 前缀 | `FMO-APP-mqtt` | 固定字面量 |
| `{timestamp}` | unix 秒（十进制，无前导零） | 服务端允许 ±`app_timestamp_window`（默认 **300** 秒），另加 5 秒时钟偏移容差 |
| `{callsign}` | **大写**呼号 | 就是 MQTT CONNECT 的 username，转大写后拼接 |
| `{userPubkeyB64}` | 用户证书里的 `subject.publicKey` | base64url（无 padding），32 字节 Ed25519 公钥 |
| `{clientid}` | MQTT CONNECT 的 clientid | **原样**，不做大小写转换、不加引号 |

分隔符是半角冒号 `:`，共 4 个冒号，**没有末尾冒号**。

### 2.1 base64url 编码约定

URL-safe 字母表（`-` `_` 替代 `+` `/`），**去掉末尾 `=`**。解码时兼容有无 padding。

- Python：`base64.urlsafe_b64encode(data).rstrip(b'=')`
- Rust：`base64::engine::general_purpose::URL_SAFE_NO_PAD`
- .NET：`WebEncoders.Base64UrlEncode`
- JS：`btoa(...).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')`

## 3. 要放进 MQTT password 的字段

MQTT CONNECT 的 `password` 原本就是 `base64url(JSON)`（内含 `certPackage` / `proof` 等）。
**只需在同一个 JSON 里多放两个字段**（向后兼容，老字段一个都不用改）：

```json
{
  "certPackage": { "intermediateCert": {...}, "userCert": {...} },
  "proof": { "signature": "..." },
  "targetUrl": "...", "targetPort": 1883, "...": "...",

  "app_timestamp": 1791050000,
  "app_signature": "H4AHq0IC3R28czvOss0YGZHQOE9B_MwIroEXN8GYBBGzKy73VM1t9XbSFO3awVtZHDoxHE1Hk_tzqHXDmfNwDQ"
}
```
> 兼容别名：服务端也接受 `appTimestamp` / `appSignature`（驼峰）。推荐用下划线形式。
> 服务端同时兼容 `FMO-APP-auth` 旧式签名（只证明是真 APP、未绑定连接），
> 但**强制模式只认 `FMO-APP-mqtt`**。

## 4. 黄金测试向量（用来验证你的实现）

固定输入，任何人算出来必须完全一致：

```
APP_SEED (测试用)   = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8     (32 字节 0x00..0x1f)
APP_PUBKEY (测试用) = A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
userPubkeyB64       = qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo     (32 字节 0xAA)
callsign            = bh6bhg          → 消息里用大写 BH6BHG
clientid            = FMO-BH6BHG-1075-B373
timestamp           = 1791050000

拼接后的消息 =
FMO-APP-mqtt:1791050000:BH6BHG:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo:FMO-BH6BHG-1075-B373

期望 app_signature =
H4AHq0IC3R28czvOss0YGZHQOE9B_MwIroEXN8GYBBGzKy73VM1t9XbSFO3awVtZHDoxHE1Hk_tzqHXDmfNwDQ
```

### 4.1 最小参考实现（Python）

```python
import base64, json, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

APP_SEED = bytes.fromhex("...")            # 32 字节；烧进 APP，服务端只存公钥

def build_app_signature_mqtt(timestamp, callsign, user_pubkey_b64, clientid) -> str:
    msg = "FMO-APP-mqtt:%d:%s:%s:%s" % (
        int(timestamp), str(callsign).strip().upper(),
        str(user_pubkey_b64).strip(), str(clientid))
    sig = Ed25519PrivateKey.from_private_bytes(APP_SEED).sign(msg.encode("utf-8"))
    return b64url(sig)
```

### 4.2 .NET / Rust / JS 关键点

- 私钥一律是 **32 字节 seed**（不是 PKCS#8 整包）：.NET 用 `Ed25519`（.NET 9+）或 libsodium；
  Rust `ed25519-dalek::SigningKey::from_bytes(&seed)`；JS `@noble/ed25519`。
- 签名是 **64 字节**，`base64url` 后 86 个字符。
- 时间戳取**服务端可接受的真实时间**（手机时钟要对时；偏差 >300 秒会被拒）。

## 5. 服务端行为

| 情况 | `client_attrs` | 观察模式 (`require_client_signature=false`) | 强制模式 (`=true`) |
|---|---|---|---|
| `FMO-APP-mqtt` 签名正确 | `app_verified="1"`, `app_sig="bound"` | 放行 | 放行 |
| 旧式 `FMO-APP-auth` 签名正确 | `app_verified="1"`, `app_sig="legacy"` | 放行 | **拒绝**（未绑定连接） |
| 有签名但错/被篡改/重放/过期 | `app_verified="0"`, `app_sig="invalid"` | 放行（留证） | 拒绝 |
| 没有签名 | `app_verified="0"`, `app_sig="none"` | 放行 | 拒绝 |

* 服务端要求 EMQX 认证器请求体带 `clientid`：
  `{"username":"${username}","password":"${password}","clientid":"${clientid}"}`
  （`bas_emqx_auth.py` 已按此写入；缺失时只剩未绑定的 legacy 路径）
* 用户公钥由服务端从 `certPackage.userCert.subject.publicKey` 自行读取，**不需要 APP 额外传**。

## 6. 上线步骤（重要：分两阶段，避免把所有人拒之门外）

1. **阶段一（观察）**：服务端把 APP 公钥填进 `config.dmrid.app_pubkey`，
   `require_client_signature=false`。此时任何连接都能进，日志/审计里会记录
   `app_verified` 与 `app_sig`，可统计"有多少连接带了有效 APP 签名"。
2. **阶段二（APP 发版）**：APP 按本文实现，MQTT CONNECT 时带上 `app_timestamp`/`app_signature`。
   观察 `app_sig=bound` 覆盖率 → 达到 100% 后。
3. **阶段三（强制）**：把 `require_client_signature` 设为 `true`（或在审计界面里切换）。
   此后没有有效 `FMO-APP-mqtt` 签名的连接一律拒绝。

> 回滚：把 `require_client_signature` 改回 `false` 即可立刻放行（无需改 APP、无需重启 EMQX）。

## 7. 常见失败原因（服务端拒绝时的 reason 会写明）

| 现象 | 原因 |
|---|---|
| `app_timestamp 超出 300 秒时间窗` | APP 时钟不准，或签名缓存过久（每次连接都要重新签） |
| `签名存在但校验失败` | 消息拼接不一致（最常见：callsign 没转大写、clientid 被改写、base64url 带了 padding、多/少冒号） |
| `服务端未配置 dmrid.app_pubkey` | 服务端还没填公钥（联系管理员，对应阶段一） |
| `password 不是合法的 base64url(JSON)` | password 整体编码有误 |

## 8. 安全边界（要说清楚）

- APP 私钥烧在客户端里，**能被逆向提取**。它提高门槛（只有真 APP 的密钥能签），
  但**不是不可破解的**：拿到 APP 私钥的人可以伪造签名。因此它是"第二把锁"，
  不能替代用户证书、吊销、以及"同 uid 不同公网 IP"这类行为检测。
- 对**用户证书**的防护：证书被拷走后仍可用（它只证明"持有证书"）。
  相关缓解：证书吊销、缩短有效期、UID+IP 维度的异常检测。
