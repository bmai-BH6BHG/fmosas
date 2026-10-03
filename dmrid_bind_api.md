# 国服 ID（DMRID）绑定 · API 文档

> 面向 APP 开发。本文件是「国服 ID 绑定」功能的**完整 API 参考**：认证方式、绑定接口、配置、错误码、完整示例。
> 配套文档：密码派生规范见 `dmrid_kdf_spec.md`（密钥派生 + CBOR 签名 + 黄金向量）；全系统接口见 `API.md`。

---

## 1. 概述

让用户**无需保存/传输任何证书文件**，只要记住「国服 ID（呼号）+ 密码」即可完全接入（绑定 → 登录 → MQTT 通联）。

原理：

```
呼号 + 国服密码
   │  derive_keypair（KDF 派生，客户端本地，密码不出网络）
   ▼
Ed25519 私钥 seed → 公钥 pubkey
   │  POST /api/cert/bind（APP 签名鉴权 + 查国服呼号存在）
   ▼
证书链 + 私钥签名（MQTT CONNECT）
   │  broker → POST /auth → 证书验证
   ▼
allow + ACL → 通联
```

关键点：

- 分系统**不接触密码**：APP 已在国服侧登录，分系统只向国服查询「呼号是否存在」。
- MQTT 认证**仍走证书**：绑定后通联用证书链 + proof 私钥签名，密码不进入 MQTT 报文。
- 绑定接口用 **APP 私钥签名**鉴权（非对称），服务端只存 APP 公钥。

---

## 2. 认证方式（APP 签名）

绑定接口要求 APP 用其 **Ed25519 私钥**对请求签名，服务端用 **APP 公钥**验签。私钥烧进 APP，公钥只存在服务端（非秘密，无需分发）。

| 项 | 值 |
|---|---|
| APP 私钥（seed，32B） | 构建时生成，**烧进 APP**（`gen_app_key.py` 的 `APP_SEED`） |
| 服务端公钥（32B） | `config.dmrid.app_pubkey`（`gen_app_key.py` 的 `APP_PUBKEY`） |
| 签名算法 | Ed25519 |
| 签名消息 | `UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")` |
| 防重放 | 校验 `app_timestamp` 与服务器时间差 ≤ `app_timestamp_window`（默认 300 秒） |

**密钥对生成**：

```bash
python gen_app_key.py
# APP_SEED    → 烧进 APP 代码
# APP_PUBKEY  → 填进 config.json 的 dmrid.app_pubkey
```

> 换密钥：重新运行生成，新 PUBKEY 填 config、新 SEED 烧进 APP，旧 APP 立即失效。

---

## 3. 绑定接口 `POST /api/cert/bind`

**Base URL**：分系统公网 API 口（默认 `http://<分系统>:35928`）

### 3.1 请求

**请求头**

| 头 | 必填 | 说明 |
|---|---|---|
| `Content-Type` | 是 | `application/json; charset=utf-8` |

**请求体**（JSON）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `callsign` | string | 是 | 呼号，4-10 位大写字母数字，服务端自动转大写 |
| `pubkey` | string | 是 | 派生出的 Ed25519 公钥（32 字节，base64url 无 padding） |
| `key_proof` | string | 是 | 持有证明签名 `Ed25519_sign(seed, UTF8("FMO-DMRID-bind:" + callsign))`，base64url |
| `app_timestamp` | int | 是 | Unix 秒，签名时间戳 |
| `app_signature` | string | 是 | `Ed25519_sign(app_seed, UTF8("FMO-APP-auth:{ts}:{callsign}:{pubkey_b64}"))`，base64url |
| `password` | string | 否 | 国服密码；仅 `config.dmrid.verify_password=true` 时必填 |

> `pubkey` / `key_proof` 由 `derive_keypair` / `build_key_proof` 得到；`app_signature` 由 `build_app_signature` 得到，见 `dmrid_kdf_spec.md`。

### 3.2 成功响应（HTTP 200）

```json
{
  "ok": true,
  "message": "绑定成功，已用国服账号派生密钥签发证书",
  "token": "a1b2c3...（分系统登录 token，可直接用于 heartbeat / cert/mine）",
  "callsign": "BG2XFM",
  "uid": 1001,
  "fingerprint": "用户证书指纹(64hex)",
  "guoji_id": 4601234,
  "dmr_id": null,
  "derived": true,
  "cert_root":  { "...": "根CA证书JSON" },
  "cert_int":   { "...": "中间CA证书JSON" },
  "cert_user":  { "...": "用户证书JSON" },
  "cert_devicekey": null
}
```

- `cert_devicekey` 恒为 `null`：私钥由客户端用密码派生，**服务器不生成、不持有**。
- `guoji_id` 为国际 ID（国服 ID）；简化模式下 `dmr_id` 为 `null`。
- **幂等**：同呼号同公钥重复绑定返回同一证书；换公钥则吊销旧证重签（UID 稳定不变）。

### 3.3 错误响应

统一格式 `{"ok": false, "error": "..."}`，HTTP 状态码如下：

| 状态码 | error | 触发条件 |
|---|---|---|
| 403 | `APP 签名无效或已过期` | 缺失/错误 `app_signature`，或时间戳超窗 |
| 403 | `key_proof 验证失败（公钥与私钥不匹配…）` | `key_proof` 与 `pubkey` 不匹配 |
| 403 | `账号状态为 …，未通过审核` / `该账号已被限制使用` | 仅 `verify_password=true` 时 |
| 400 | `呼号格式不正确（需 4-10 位大写字母和数字）` | 呼号非法 |
| 400 | `缺少 pubkey 或 key_proof` / `pubkey 必须为 32 字节 Ed25519 公钥` | 参数缺失/非法 |
| 404 | `该呼号未识别到国服 ID（国际 ID），无法绑定` | 国服查不到该呼号 |
| 401 | `国服账号或密码错误` | 仅 `verify_password=true` 时 |
| 502 | `无法连接国服后端…` | 国服不可达 |
| 503 | `国服ID绑定未启用` / `CA 未初始化` / `证书模块未加载` | 分系统未就绪 |

### 3.4 curl 示例

```bash
# ts 用当前 Unix 秒；app_signature 由 APP 用其私钥对消息
#   "FMO-APP-auth:{ts}:BG2XFM:{pubkey}" 签名后 base64url
curl -X POST http://127.0.0.1:35928/api/cert/bind \
  -H "Content-Type: application/json" \
  -d '{
    "callsign": "BG2XFM",
    "pubkey": "4MHn8cx-KjeWhx1qHcMD_HyUuvbyzjRbsIvCmDQQpeI",
    "key_proof": "BQCG4-I0VwdGEj0pDbIUHYFUPPJBYHy41FXn9FHGpz-GJVt4PmMp1Ii-UP6WI3XQkfC82lwW-dSjFJsMawkBAg",
    "app_timestamp": 1700000000,
    "app_signature": "aJOcqF3T-cFjcUmIpNkENX3OD3H2vtN0mpq7IRBty8Ft0pf8eutiIWkk2o2V3Q_6KZc5k5L1_16RNZyK0LZiBw"
  }'
```

---

## 4. 绑定后的接入

绑定成功拿到 `cert_int` / `cert_user` / `fingerprint`，之后：

1. **HTTP 接口**：用返回的 `token` 调 `POST /api/heartbeat`、`GET /api/cert/mine`、`GET /api/users` 等（`Authorization: Bearer <token>` 或 `?token=`）。
2. **MQTT 通联**：用派生 seed 构造凭证（`build_mqtt_credentials`），见 `dmrid_kdf_spec.md` §4。服务端 `/auth` 验证书链 + proof 签名，之后纯走证书，不依赖国服在线。

---

## 5. 配置 `config.dmrid`

```json
{
  "dmrid": {
    "enabled": true,
    "base_url": "https://dmriapi.radiowo.com",
    "timeout": 10,
    "app_pubkey": "IvYZ3WOGz4Cbvn7dDi783o5k1JycYYVSpY7ahe8LA5Q",
    "app_timestamp_window": 300,
    "verify_password": false,
    "kdf_algorithm": "pbkdf2",
    "kdf_pbkdf2_iterations": 600000,
    "kdf_scrypt_n": 32768,
    "kdf_scrypt_r": 8,
    "kdf_scrypt_p": 1,
    "dev_mode": false
  }
}
```

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | false | 是否启用绑定 |
| `base_url` | 国服生产地址 | 国服后端 Base URL（不含 `/api`） |
| `timeout` | 10 | 国服请求超时（秒） |
| `app_pubkey` | "" | APP 签名公钥（base64url）；留空时生产拒绝所有绑定（仅 `dev_mode` 放行） |
| `app_timestamp_window` | 300 | APP 签名时间戳允许窗口（秒） |
| `verify_password` | false | `false`=仅查呼号存在（简化）；`true`=额外校验国服密码 |
| `dev_mode` | false | 本地自测：跳过真实国服查询，按呼号合成 guojiId；**严禁生产开启** |

---

## 6. 完整时序

```
APP                         分系统(35928)                国服后端
 │ ① 登录国服（呼号+密码）────────────────────────────────────►│
 │◄────────────────────────── 返回 JWT + guojiId + dmrId ──────│
 │
 │ ② seed,pub = derive_keypair(callsign, password)
 │ ③ key_proof = build_key_proof(seed, callsign)
 │ ④ app_signature = build_app_signature(app_seed, ts, callsign, pub)
 │
 │ ⑤ POST /api/cert/bind (callsign/pubkey/key_proof/app_timestamp/app_signature)
 │──────────────────────────►│
 │                            │ ⑥ 验 APP 签名（失败→403）
 │                            │ ⑦ 校验 key_proof（失败→403）
 │                            │ ⑧ GET /api/auth/callsign-lookup?callsign=…
 │                            │────────────────────────────►│
 │                            │◄── 存在 guojiId / 不存在 404 ──│
 │                            │ ⑨ 签发证书（cert_int + cert_user）
 │◄──── 证书包 + token ────────│
 │
 │ ⑩ MQTT CONNECT（证书 + proof 签名）
 │──────────────────────────►│ ⑪ /auth 证书链验证 → allow
 │◄──────── allow + ACL ──────│
```

---

## 7. 安全说明

1. **APP 私钥是简化模式下的信任锚**：只有烧了正确 APP 私钥的客户端能绑定；请妥善保管 APP 私钥，泄露则换密钥（重生成密钥对 → 换 config 公钥 + 换 APP seed）。
2. **密码派生密钥强度取决于密码**：弱密码可被离线爆破，务必强密码 + 高成本 KDF（PBKDF2 60 万次 / scrypt）。
3. **服务器绝不派生/持有 seed**：私钥只在客户端本地派生；忘记密码 = 私钥永久丢失，需「重置 → 吊销旧证 → 重新绑定」。
4. **国服身份校验只在绑定这一次**：之后 MQTT 纯走证书，不依赖国服在线。

---

*对应源码：`api_server.py`（`/api/cert/bind`、`app_signature_ok`、`get_app_pubkeys`、`dmrid_lookup`、`dmrid_login`）、`sas_server.py`（`issue_user_cert_for_pubkey`）、`cert_gen.py`（`derive_keypair` / `build_key_proof` / `build_app_signature` / `build_mqtt_credentials`）、`gen_app_key.py`（APP 密钥对生成）。*
