# APP 端接入改动指南（国服 ID 绑定）

> 本文是**给 APP 开发者的落地清单**：告诉你要改什么、新增哪几个函数、怎么调、怎么自测。
> 逐字节规范和黄金向量见 `dmrid_kdf_spec.md`；接口细节见 `dmrid_bind_api.md`。

---

## 0. 一句话总结

你的 APP **已经有**国服登录 + MQTT 证书认证（`buildMqttPassword`）。这次只需：

> **新增 3 个小函数 + 1 次 HTTP 调用**，把「国服密码」变成「派生证书」，其余**全部复用**。

---

## 1. 现状盘点（复用 vs 新增）

| 能力 | 状态 | 说明 |
|---|---|---|
| 国服登录（呼号+密码 → JWT） | ✅ 已有 | 不动 |
| Ed25519 签名 / 验签 | ✅ 已有 | 不动 |
| CBOR 编码 | ✅ 已有 | 不动（`cbor_head_write` / `CborWriter`） |
| base64url 编解码 | ✅ 已有 | 不动 |
| `buildMqttPassword`（MQTT 证书凭证） | ✅ 已有 | 复用，见 §6 |
| **`derive_keypair`（密码派生密钥）** | 🆕 新增 | §3 |
| **`build_key_proof`（持有证明）** | 🆕 新增 | §4 |
| **`build_app_signature`（APP 签名）** | 🆕 新增 | §5 |
| **`POST /api/cert/bind` 调用** | 🆕 新增 | §6 |

---

## 2. 准备：APP 密钥对（一次性）

已经给你生成好了，**这两个值直接抄进代码**：

```
APP_SEED   = -zbIIPI-9Q1mecFCbXGdTm7rL3D8gSC64s16mmE06i0   ← 烧进 APP（写死，绝不上传）
APP_PUBKEY = 4LL2krXOFvViFvbdP3pvTJK2pZXMIRNWQ6nz8jp5gr0   ← 已写入服务端 config.dmrid.app_pubkey
```

- `APP_SEED`：APP 的 Ed25519 私钥 seed（32 字节，base64url），**烧进 APP 代码**。
- `APP_PUBKEY`：对应公钥，服务端已配置好。
- 想自己换一对：服务端跑 `python gen_app_key.py`，重新生成后换 config + 换 APP 里的 seed。

---

## 3. 新增函数 ① `derive_keypair(callsign, password)`

把「呼号 + 国服密码」确定性派生成 Ed25519 密钥对：

```
salt = UTF8("FMO-DMRID-v1:" + callsign大写)
seed = PBKDF2-HMAC-SHA256(password, salt, iterations=600000, dkLen=32)
pub  = Ed25519(seed).公钥   # 32 字节
返回 (seed, pub)
```

```rust
// Rust
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use ed25519_dalek::SigningKey;

let salt = format!("FMO-DMRID-v1:{}", callsign).into_bytes();
let mut seed = [0u8; 32];
pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 600_000, &mut seed);
let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
```

```csharp
// C# / .NET
var salt = Encoding.UTF8.GetBytes("FMO-DMRID-v1:" + callsign);
var seed = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
// Ed25519 用 BouncyCastle / NSec，由 seed 得 pub
```

```js
// JS（@noble/hashes + @noble/ed25519）
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/ed25519';
const salt = new TextEncoder().encode(`FMO-DMRID-v1:${callsign}`);
const seed = pbkdf2(sha256, new TextEncoder().encode(password), salt, { c: 600000, dkLen: 32 });
const pub  = await ed25519.getPublicKey(seed);
```

---

## 4. 新增函数 ② `build_key_proof(seed, callsign)`

证明「我持有 pub 对应的私钥」：

```
signature = Ed25519_sign(seed, UTF8("FMO-DMRID-bind:" + callsign大写))
返回 base64url(signature)
```

---

## 5. 新增函数 ③ `build_app_signature(app_seed, timestamp, callsign, pubkey_b64)`

APP 鉴权签名（服务端用 APP 公钥验签）：

```
message    = UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")
signature  = Ed25519_sign(app_seed, message)
返回 base64url(signature)
```

- `timestamp`：当前 Unix 秒，必须与请求体 `app_timestamp` 一致，且与服务器时间差 ≤ 300 秒。

---

## 6. 绑定调用 `POST /api/cert/bind`

```rust
// 伪代码（任何语言同理）
let (seed, pub) = derive_keypair(callsign, password);
let pub_b64     = base64url(pub);
let key_proof   = build_key_proof(seed, callsign);
let ts          = now_unix_seconds();
let app_sig     = build_app_signature(APP_SEED, ts, callsign, pub_b64);

let resp = http_post("https://<分系统>:35928/api/cert/bind", json!({
    "callsign":       callsign,
    "pubkey":         pub_b64,
    "key_proof":      key_proof,
    "app_timestamp":  ts,
    "app_signature":  app_sig,
}));
// 注：默认简化模式不需要传 password（APP 已在国服侧登录）
```

**成功响应**（`ok=true`）：

```json
{
  "ok": true, "token": "…", "callsign": "BG2XFM", "uid": 1001,
  "fingerprint": "…", "guoji_id": 4601234, "dmr_id": null,
  "derived": true,
  "cert_root": {…}, "cert_int": {…}, "cert_user": {…},
  "cert_devicekey": null
}
```

- 缓存 `cert_int` + `cert_user` + `fingerprint`（`cert_root` 可选）。
- **不需要存 devicekey**——seed 随时可用密码重派生。
- 幂等：重复绑定返回同一证书；换密码派生则旧证被吊销、重签。

---

## 7. MQTT 接入（复用已有的 `buildMqttPassword`）

绑定成功后，用**派生出的 seed** + 返回的证书，调你**已有的** `buildMqttPassword`：

```
username = callsign
password = buildMqttPassword(
    cert_int, cert_user,
    deviceSeed = seed,               // 用派生 seed 替代原来从 devicekey 文件读的 seed
    targetUrl = <服务器地址>, targetPort = 1883,
    role = "user", targetCallsign = "", targetUID = 0,
    serverFingerprint = fingerprint   // 绑定响应里的 fingerprint
)
MQTT CONNECT(username, password)
```

> 这一步和你现有的证书登录**完全一样**，唯一区别是 `deviceSeed` 不再是下发下来的 JSON，而是 `derive_keypair` 派生的 seed。

---

## 8. 自测（黄金向量）

用下面固定输入跑你的实现，输出对得上就说明和分系统 100% 兼容：

| 输入 | 值 |
|---|---|
| callsign | `BG2XFM` |
| password | `Test@123456` |
| KDF | PBKDF2-HMAC-SHA256, 600000 |

期望输出（完整见 `dmrid_kdf_spec.md` §6）：

```
SEED_B64URL   = One0wH4EkQBBpnTWWdZl9ZfZ_J3WI_MMEd6U3klBXGk
PUB_B64URL    = 4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI
KEYPROOF_B64  = BQCG4-I0VwdGEj0pDbIUHYFUPPJBYHy41FXn9FHGpz-GJVt4PmMp1Ii-UP6WI3XQkfC82lwW-dSjFJsMawkBAg
```

APP 签名自测（用 §2 的 APP_SEED，timestamp=1700000000，pubkey_b64 用上面的 PUB_B64URL）：

```
SIGN_MSG     = FMO-APP-auth:1700000000:BG2XFM:4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI
APP_SIG_B64  = （用你的 APP_SEED 签名，服务端会用 app_pubkey 验签；格式对即可）
```

---

## 9. 上线检查清单

- [ ] APP 代码里烧入 `APP_SEED`（§2）
- [ ] 实现 `derive_keypair` / `build_key_proof` / `build_app_signature`
- [ ] 国服登录成功后，调 `POST /api/cert/bind`（§6）
- [ ] 绑定成功拿 `cert_int`/`cert_user`/`fingerprint`，用派生 seed 调 `buildMqttPassword`（§7）
- [ ] 服务端 `config.dmrid`：`enabled=true`、`app_pubkey=4LL2krXOFvViFvbdP3pvTJK2pZXMIRNWQ6nz8jp5gr0`、`dev_mode=false`
- [ ] 用 §8 黄金向量自测通过

---

*配套：`dmrid_kdf_spec.md`（逐字节规范 + 全部黄金向量）、`dmrid_bind_api.md`（接口参考）、`gen_app_key.py`（密钥对生成）。*
