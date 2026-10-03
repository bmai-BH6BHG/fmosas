# 国服 ID（DMRID）绑定 · APP 端派生规范对照文档

> 面向 APP 开发（Rust / .NET / JS 等任意语言）。本文给出「国服 ID（呼号）+ 密码 → Ed25519 私钥 → 证书 + MQTT 凭证」的**逐字节精确规范**与**黄金测试向量**，保证各端派生的密钥与分系统 Python 端完全一致。
>
> 服务端参考实现：`cert_gen.py`（`derive_keypair` / `build_key_proof` / `build_app_signature` / `build_mqtt_credentials`）。

---

## 0. 核心流程图

```
呼号 + 国服密码
   │  ① derive_keypair：KDF 派生 seed（32B）→ 公钥 pub（32B）
   ▼
seed / pub
   │  ② build_key_proof：签名证明「持有 pub 对应私钥」
   │  ③ build_app_signature：用 APP 私钥签名，证明「请求来自真实 APP」
   │  ④ POST /api/cert/bind {callsign, pubkey, key_proof, app_timestamp, app_signature}
   ▼
分系统返回 cert_root / cert_int / cert_user / uid / fingerprint / token
   │  ⑤ build_mqtt_credentials：用 seed 对 12 元素 CBOR TBS 签名，构造 MQTT password
   ▼
MQTT CONNECT（username=呼号，password=base64url(JSON)）→ broker → /auth → allow
```

---

## 1. 编码约定（务必逐字节一致）

### 1.1 base64url（无 padding）

- 使用 **URL-safe** 字母表（`-` `_` 替代 `+` `/`），**去掉末尾 `=`**。
- 解码时兼容有无 padding。

```
Python:  base64.urlsafe_b64encode(data).rstrip('=')
Rust:    base64::engine::general_purpose::URL_SAFE_NO_PAD
.NET:    WebEncoders / Convert（需自行替换字符并去 pad）
JS:      用 @noble/hashes 的 utils 或手写 base64url
```

### 1.2 CBOR 编码（签名/指纹的 TBS 序列化，必须与 Rust `cbor_head_write` 一致）

| 类型 | major | 说明 |
|---|---|---|
| 无符号整数 | 0 | 负数 major=1，编码 `-1 - n` |
| 字节串 | 2 | bytes |
| 文本串 | 3 | UTF-8 字符串 |
| 数组 | 4 | list/tuple |
| 布尔 | — | `false = 0xF4`，`true = 0xF5` |

**头部（head）编码**：

```
head = (major << 5) | info
  value < 24          -> info = value                        （1 字节）
  value <= 0xFF       -> info = 24, + 1 字节 value           （2 字节）
  value <= 0xFFFF     -> info = 25, + 2 字节 big-endian      （3 字节）
  value <= 0xFFFFFFFF-> info = 26, + 4 字节 big-endian      （5 字节）
  else                -> info = 27, + 8 字节 big-endian      （9 字节）
```

**数组编码**：一个数组 = `head(4, 元素个数)` + 每个元素依次 CBOR 编码。

> 参考实现：`cert_gen.py::_cbor_head` / `cbor_encode` / `cbor_tbs`。

### 1.3 Ed25519

- 使用**标准 Ed25519**（不是 Ed25519ph / Ed25519ctx）。
- 私钥 = 32 字节 seed；公钥 = 32 字节（seed 单向推导）。
- 签名 = 64 字节；签名后 base64url。

---

## 2. 原语 ①：派生密钥 `derive_keypair`

```
输入:  identifier = 呼号（大写，如 "BG2XFM"）
       password   = 国服密码明文
       salt       = UTF8("FMO-DMRID-v1:" + identifier)
       seed(32B)  = PBKDF2-HMAC-SHA256(password, salt, iterations=600000, dkLen=32)
       pub(32B)   = Ed25519(seed).public_key
输出:  (seed, pub)
```

- 默认算法 **PBKDF2-HMAC-SHA256 / 600000 次**；可选 `scrypt`（n=32768, r=8, p=1）。
- **确定性**：同一呼号 + 同一密码，任何语言/平台必得同一 seed/pub（换设备可重建身份）。
- 更换算法/参数必须升级 salt 前缀版本号（`FMO-DMRID-v1` → `v2`）。

### 各语言实现要点

```rust
// Rust（pbkdf2 0.12 + ed25519-dalek 2.x + base64 0.22）
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use ed25519_dalek::SigningKey;

let salt = format!("FMO-DMRID-v1:{}", callsign).into_bytes();
let mut seed = [0u8; 32];
pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 600_000, &mut seed);
let signing = SigningKey::from_bytes(&seed);          // 32B seed
let pubkey = signing.verifying_key().to_bytes();      // 32B pub
```

```csharp
// C# / .NET 6+（Ed25519 用 BouncyCastle 或 NSec）
var salt = Encoding.UTF8.GetBytes("FMO-DMRID-v1:" + callsign);
var seed = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000,
                                     HashAlgorithmName.SHA256, 32);
// BouncyCastle:
var sk = new Org.BouncyCastle.Math.EC.Rfc8032.Ed25519PrivateKeyParameters(seed, 0);
var pub = sk.GeneratePublicKey().GetEncoded();        // 32B pub
```

```js
// JavaScript / TypeScript（Node 或浏览器，推荐 @noble/hashes + @noble/ed25519）
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/ed25519';

const salt = new TextEncoder().encode(`FMO-DMRID-v1:${callsign}`);
const seed = pbkdf2(sha256, new TextEncoder().encode(password), salt,
                    { c: 600000, dkLen: 32 });
const pub = await ed25519.getPublicKey(seed);         // 32B pub
```

---

## 3. 原语 ②：绑定持有证明 `build_key_proof`

```
msg        = UTF8("FMO-DMRID-bind:" + 呼号大写)
signature  = Ed25519_sign(seed, msg)                  # 64B
key_proof  = base64url(signature)
```

作用：向分系统证明「我确实持有 pub 对应的私钥」，服务端用 `pub` 验签即可，无需接触 seed。

---

## 4. 原语 ③：APP 签名 `build_app_signature`

```
msg            = UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")
signature      = Ed25519_sign(app_seed, msg)          # 64B
app_signature  = base64url(signature)
```

- `app_seed`：APP 的 Ed25519 私钥 seed（`python gen_app_key.py` 生成的 `APP_SEED`，烧进 APP 写死）。
- `callsign`：呼号大写；`pubkey_b64`：本次要绑定的派生公钥（base64url）。
- `timestamp`：Unix 秒，须与请求体 `app_timestamp` 一致，且与服务器时间差 ≤ `app_timestamp_window`（默认 300 秒）。
- 作用：向分系统证明「请求来自持有 APP 私钥的真实客户端」，服务端用 `config.dmrid.app_pubkey`（`APP_PUBKEY`）验签。**公钥不是秘密**，无共享密钥分发问题。

---

## 5. 原语 ④：MQTT 凭证 `build_mqtt_credentials`

### 5.1 username

明文呼号（如 `BG2XFM`），**不做任何编码**。

### 5.2 password

```
password = base64url( UTF8( JSON.stringify({
  "certPackage": {
    "intermediateCert": <cert_int 对象>,   // 分系统 /api/cert/bind 返回，原样放入
    "userCert":         <cert_user 对象>
  },
  "targetCallsign":   "",                  // 可为空字符串
  "targetUID":        0,
  "role":             "user",
  "targetUrl":        "<服务器地址>",
  "targetPort":       1883,
  "serverFingerprint": "<base64url>",       // 用户证书指纹，见下
  "timestamp":        <整数秒>,
  "proof": { "signature": "<base64url>" }   // 见 5.3
}) ) )
```

- 用 JSON **compact**（无空格）后 base64url（`cert_gen.py` 用 `separators=(",", ":")`，但宽松解析下有无空格均可）。
- `serverFingerprint` = 用户证书指纹的 base64url（即 `/api/cert/bind` 返回的 `fingerprint`）。

### 5.3 proof 签名（12 元素 CBOR TBS）

**关键：`timestamp` 在 password JSON 里和 proof TBS 里必须用同一个值。**

先算用户证书指纹（9 元素 TBS）：

```
user_tbs = ["FMO", 4, "userCert",
            issuerSn, callsign, uid, pubkey(32B), iat, exp]
user_fp  = SHA256( CBOR(user_tbs) )          # 32B 原始字节
```

- `issuerSn / callsign / uid / pubkey / iat / exp` 全部取自 `cert_user`：
  - `cert_user.issuerSn` → issuerSn
  - `cert_user.subject.callsign` → callsign（大写）
  - `cert_user.subject.uid` → uid
  - `cert_user.subject.publicKey` → base64url **解码**成 32B 字节
  - `cert_user.iat` / `cert_user.exp` → iat / exp

再算 proof 签名（12 元素 TBS）：

```
proof_tbs = ["FMO", 4, "serverAuthorizerReqHttp",
             targetUID,            // int
             targetCallsign,       // 大写字符串
             targetUID,            // int（与上同值）
             role,                 // "user"
             targetUrl,            // 字符串
             targetPort,           // int
             serverFingerprint,    // 32B 原始字节（base64url 解码）
             timestamp,            // int
             user_fp]              // 32B 原始字节

proof.signature = base64url( Ed25519_sign(seed, CBOR(proof_tbs)) )
```

> 注意：`serverFingerprint` 在 **password JSON 里是 base64url 字符串**，在 **proof TBS 里是解码后的 32B 原始字节**。两处别混。

---

## 6. 黄金测试向量（各端自测用）

统一输入：

| 项 | 值 |
|---|---|
| 呼号（identifier） | `BG2XFM` |
| 密码（password） | `Test@123456` |
| KDF | PBKDF2-HMAC-SHA256, 600000 次 |

### 6.1 派生

```
SALT_ASCII    = FMO-DMRID-v1:BG2XFM
SALT_HEX      = 464d4f2d444d5249442d76313a42473258464d
SEED_HEX      = 3a77b4c07e04910041a674d659d665f597d9fc9dd623f30c11de94de49415c69
SEED_B64URL   = One0wH4EkQBBpnTWWdZl9ZfZ_J3WI_MMEd6U3klBXGk
PUB_HEX       = e0c1e7f1cc7e2a3796871d6a1dc303fc7c94baf6f2ce345bb08bc2983410a5e2
PUB_B64URL    = 4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI
KEYPROOF_B64  = BQCG4-I0VwdGEj0pDbIUHYFUPPJBYHy41FXn9FHGpz-GJVt4PmMp1Ii-UP6WI3XQkfC82lwW-dSjFJsMawkBAg
```

### 6.2 用户证书指纹（固定字段，验证 CBOR + SHA256）

固定 `user_tbs`：`["FMO", 4, "userCert", 1001, "BG2XFM", 1001, pub, 1700000000, 2015360000]`
（`pub` 用上面 6.1 的 PUB_B64URL 解码后的 32 字节）

```
USER_TBS_CBOR_HEX = 8963464d4f046875736572436572741903e96642473258464d1903e95820e0c1e7f1cc7e2a3796871d6a1dc303fc7c94baf6f2ce345bb08bc2983410a5e21a6553f1001a781ff400
USER_FP_HEX       = e58a6be03bb8c560af3e5bbef99ebf1496bb4bef1c7785e32aeb58d7054c9b11
USER_FP_B64URL    = 5Ypr4Du4xWCvPlu--Z6_FJa7S-8cd4XjKutY1wVMmxE
```

### 6.3 proof 签名（固定字段，验证 12 元素 TBS 签名）

固定 `proof_tbs`（targetUID=0, targetCallsign="", role="user", targetUrl="127.0.0.1", targetPort=1883, serverFingerprint=user_fp, timestamp=1700000000）：

```
PROOF_TBS_CBOR_HEX = 8c63464d4f0477736572766572417574686f72697a6572526571487474700060006475736572693132372e302e302e3119075b5820e58a6be03bb8c560af3e5bbef99ebf1496bb4bef1c7785e32aeb58d7054c9b111a6553f1005820e58a6be03bb8c560af3e5bbef99ebf1496bb4bef1c7785e32aeb58d7054c9b11
PROOF_SIG_B64URL  = aDKApbL3IyH2qm1_wJp_kDTJqpsKc2s6lKfhARvpBZ7pJzdnad2QEk0vTiGlgoI8DAI43K2rTj5yHSBT-ru8Cw
```

### 6.4 APP 签名（固定字段，验证 APP 鉴权签名）

固定输入：

```
app_seed     = LlC44l7IPTvVlvMhTnuYP9zzLnUJbfY1koiRZThOOuo   (base64url，对应私钥)
app_pubkey   = IvYZ3WOGz4Cbvn7dDi783o5k1JycYYVSpY7ahe8LA5Q   (base64url，服务端配置)
timestamp    = 1700000000
callsign     = BG2XFM
pubkey_b64   = 4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI   (上面 6.1 的 PUB_B64URL)
```

```
SIGN_MSG     = FMO-APP-auth:1700000000:BG2XFM:4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI
APP_SIG_B64  = aJOcqF3T-cFjcUmIpNkENX3OD3H2vtN0mpq7IRBty8Ft0pf8eutiIWkk2o2V3Q_6KZc5k5L1_16RNZyK0LZiBw
```

> 自测方法：用你的语言实现 `derive_keypair`，断言 `SEED_HEX` / `PUB_B64URL` 与上表一致；再实现 CBOR + 签名，断言 `USER_FP_HEX` / `PROOF_SIG_B64URL` 一致；再用 APP 私钥实现 `build_app_signature`，断言 `APP_SIG_B64` 一致，即说明与分系统完全兼容。

---

## 7. HTTP 绑定流程（APP 侧时序）

```
① seed, pub = derive_keypair(callsign, password)
② key_proof  = build_key_proof(seed, callsign)
③ ts = 当前 Unix 秒
   app_signature = build_app_signature(app_seed, ts, callsign, pub_b64)

④ POST /api/cert/bind
   Content-Type: application/json
   {
     "callsign":       "BG2XFM",
     "pubkey":         "<PUB_B64URL>",
     "key_proof":      "<KEYPROOF_B64>",
     "app_timestamp":  <ts>,
     "app_signature":  "<APP_SIGNATURE_B64>"
   }
   （默认简化模式：不需要传 password；APP 已在国服侧登录，分系统只查呼号是否存在）

⑤ 响应（ok=true 时）：
   { ok, token, callsign, uid, fingerprint,
     guoji_id, dmr_id, derived: true,
     cert_root, cert_int, cert_user, cert_devicekey: null }

⑥ 缓存 cert_int + cert_user（cert_root 可选）；seed 可由密码随时重派生，无需持久化。

⑦ MQTT CONNECT：
   username = callsign
   password = build_mqtt_credentials(cert_int, cert_user, seed,
               targetUrl=服务器地址, targetPort=1883, role="user",
               targetCallsign="", targetUID=0, serverFingerprint=fingerprint)
```

- 绑定是**幂等**的：同呼号同 pubkey 重复调用返回同一证书；换 pubkey（如换密码派生）则吊销旧证重签。
- 之后 MQTT 认证纯走证书，**不再依赖国服后端在线**。

---

## 8. 常见坑（务必检查）

1. **base64url 忘了去 padding**：`=` 必须去掉，否则服务端解码长度错。
2. **CBOR 头部写错**：`value <= 0xFF` 时是 `info=24 + 1 字节`，不是 `info=value`；`<= 0xFFFF` 是 `25 + 2 字节 big-endian`。
3. **salt 前缀拼错**：必须是 `FMO-DMRID-v1:`（含冒号），版本号一变密钥全变。
4. **PBKDF2 参数**：HMAC 用 SHA256，输出 32 字节，迭代 600000。
5. **Ed25519 变体**：必须标准 Ed25519，别用 Ed25519ph / Ed25519ctx；seed 直接 `from_bytes`，不要做额外哈希。
6. **proof TBS 元素顺序**：12 个元素，`targetUID` 出现两次（第 4、6 位），别漏。
7. **serverFingerprint 两处形态不同**：JSON 里 base64url 字符串，TBS 里 32B 原始字节。
8. **timestamp 一致性**：password JSON 与 proof TBS 用同一个整数秒。
9. **APP 签名消息格式**：严格 `FMO-APP-auth:{ts}:{callsign}:{pubkey_b64}`（冒号分隔，无多余空格），`ts` 与请求体 `app_timestamp` 一致，且与服务器时间差 ≤ 300 秒，否则 403「APP 签名无效或已过期」。
10. **字符串编码**：全部 UTF-8；呼号/目标呼号一律大写。

---

*服务端参考实现：`cert_gen.py`（`derive_keypair` / `build_key_proof` / `build_app_signature` / `build_mqtt_credentials`，含 `_cbor_head` / `cbor_encode` / `ed25519_sign`）、`gen_app_key.py`（APP 密钥对生成）。*
