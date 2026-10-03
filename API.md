# FMO 分系统 API 文档

> 面向 APP 开发 / AI 编程系统对接。
> 适用版本：fmo-subsystem（api_server.py + sas_server.py + sync_engine.py + monitor.py）
> 默认端口：公网 API `35928`（config.json `port`），管理端口 `35929`（= API 端口 + 1，自动派生），MQTT broker `1883`

---

## 1. 系统架构概览

```
APP ──HTTP──> 分系统 公网API口 (35928，白名单) ──> 用户库 (users.db) / SAS库 (sas.db) / CA (ca/)
 │           管理后台 ──HTTP──> 管理口 (35929 = API口+1，仅内网)      │
 │                                     ├── 上报/拉取 ──> 总系统 master (35930 公网口)
 │                                     ├── P2P 同步 ───> 兄弟分系统
 │                                     └── 监控抄收 <── MQTT broker
 └──MQTT──> broker (1883) ──POST /auth──> 分系统 API ──> SAS 认证 (证书链验证)
```

- **注册/登录/证书**：走 HTTP API。
- **语音通联**：走 MQTT。APP 用证书构造 CONNECT 凭证，broker 回调 `/auth` 验证。
- **数据同步**：分系统自动与总系统/兄弟分系统同步用户、证书、信任链、语音段，APP 无感知。

### 1.1 双端口部署（公网/内网分离）

分系统同时监听两个端口，**管理端口 = API 端口 + 1**（写死派生，无配置项）：

| 端口 | 用途 | 暴露建议 |
|---|---|---|
| API 端口（默认 35928） | APP 注册/登录/证书/心跳 + 系统间同步（白名单） | 可映射公网 |
| 管理端口（API+1，默认 35929） | 管理后台 `/admin` + 全部管理 API + 证书包下载 | **仅内网，勿映射公网** |

- 公网口仅放行：GET `/`、`/index.html`、`/api/health`、`/api/users`、`/api/stats`、`/api/config`、`/api/cert/mine`、`/api/sync/status`、`/uploads/*`；POST `/api/register`、`/api/login`、`/api/heartbeat`、`/auth`、`/api/cert/bind`、`/api/sync/peer`、`/api/sync/report`。
- 其余路径（含全部 DELETE、管理 API、`/admin`）在公网口一律 `403 {"ok": false, "error": "该接口仅内网管理端口提供"}`。
- APP 只需对接公网口；管理后台访问 `http://内网IP:35929/admin`。

---

## 2. 通用约定

| 项 | 说明 |
|---|---|
| 响应格式 | 全部 JSON，`ok: true/false` 表示成败，失败带 `error` 字段 |
| CORS | 已开放 `*`（APP/WebView 可直接跨域调用） |
| 字符编码 | UTF-8 |
| 呼号规范 | 大写字母+数字，4-10 位（如 `BH1ACG`），服务端自动转大写 |
| token | 登录成功后下发，32 位十六进制字符串，随用户记录存储，重新登录会刷新 |
| token 传递 | `Authorization: Bearer <token>` 头（推荐）或 `?token=<token>` 查询参数 |

**错误响应示例**

```json
{"ok": false, "error": "密码错误"}
```

HTTP 状态码语义：`400` 参数错误 / `401` 未认证 / `403` 鉴权拒绝 / `404` 不存在 / `500` 服务器错误 / `503` 依赖服务不可用（SAS 未初始化等）。

---

## 3. APP 对接核心流程（4 步）

```
① POST /api/register   注册（multipart，含可选证件照）→ 自动签发证书
② POST /api/login      登录 → 拿 token
③ GET  /api/cert/mine  凭 token 拉取完整证书包（root/int/user/devicekey）
④ MQTT CONNECT         用证书包构造 username/password → 接入语音网络
之后：POST /api/heartbeat  周期心跳保活（建议 10s 间隔，>15s 判离线）
```

> 证书在注册时自动签发；若注册时 CA 未就绪，`/api/cert/mine` 会在首次调用时自动补签（幂等），APP 无需关心签发时机。

---

## 4. APP 端点详述

### 4.1 注册 `POST /api/register`

**请求**：`multipart/form-data`

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| name | text | 是 | 姓名 |
| callsign | text | 是 | 呼号（如 BH1ACG），全局唯一 |
| phone | text | 是 | 手机号 |
| password | text | 是 | 密码，至少 6 位（服务端 SHA-256 存储） |
| cert_photo | file | 否 | 操作证书照片，jpg/png，≤5MB |
| device_cert | file | 否 | 设备证书照片，jpg/png，≤5MB |

**成功响应**

```json
{"ok": true, "message": "注册成功", "cert_issued": true}
```

`cert_issued=false` 表示注册成功但证书暂未签发（CA 未初始化），后续调 `/api/cert/mine` 会自动补签。

**常见错误**：`该呼号已注册` / `呼号格式不正确（如 BH1ACG）` / `密码不能为空且至少 6 位` / `操作证书图片超过 5MB 限制`

---

### 4.2 登录 `POST /api/login`

**请求** `application/json`

```json
{"callsign": "BH1ACG", "password": "123456"}
```

**响应**

```json
{"ok": true, "token": "a1b2c3...", "name": "张三", "callsign": "BH1ACG"}
```

**常见错误**：`呼号不存在` / `密码错误`

> 每次登录生成新 token 覆盖旧 token（同一台分系统内单端登录语义）。

> **账号全网互通**：任一分系统注册的账号（含密码）经同步出现在所有分系统，可在任意一台登录；
> token 由各系统独立签发、互不影响（在甲站登录不会挤掉乙站上的会话）。

---

### 4.3 拉取本人证书包 `GET /api/cert/mine`

**认证**：Bearer token 或 `?token=`

**响应**

```json
{
  "ok": true,
  "callsign": "BH1ACG",
  "uid": 1001,
  "fingerprint": "用户证书指纹(64hex)",
  "cert_root":   { "...": "根CA证书JSON" },
  "cert_int":    { "...": "中间CA证书JSON" },
  "cert_user":   { "...": "用户证书JSON" },
  "cert_devicekey": { "...": "设备密钥JSON(含seed私钥)" }
}
```

- **幂等**：已有有效证书直接返回；没有且 CA 可用时自动分配 UID 并签发。
- `uid` 为系统自动分配（全分系统内唯一递增，范围默认 1-200000）。
- `cert_devicekey` 含私钥 seed，**必须仅存本地，不得上传**。

**常见错误**：`401 token 无效或已过期` / `503 证书不可用: SAS 服务或 CA 未初始化`

---

### 4.4 心跳 `POST /api/heartbeat`

**请求** `application/json`

```json
{"token": "a1b2c3...", "device_info": "Android 14 / NRL-Plus 1.2.0"}
```

**响应**

```json
{"ok": true, "timestamp": 1757900000.0}
```

- 建议每 10 秒一次；服务端以 15 秒阈值判定在线。
- 心跳同时刷新同步时间戳，在线状态会随增量同步上报总系统。

---

### 4.5 用户列表 `GET /api/users`

**响应**

```json
{
  "ok": true,
  "users": [
    {
      "id": 1,
      "name": "张三",
      "callsign": "BH1ACG",
      "phone": "138****0000",
      "cert_photo_path": "uploads/xxx.jpg",
      "device_cert_path": null,
      "last_heartbeat": 1757900000.0,
      "created_at": 1757800000.0,
      "subsystem_id": "sub-001",
      "online": true,
      "cert_uid": 1001,
      "cert_fingerprint": "abc123..."
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| subsystem_id | 用户归属分系统 ID；本机注册用户为本分系统 ID，同步来的远端用户为来源分系统 ID（老库可能为 null） |
| online | `last_heartbeat` 距今 ≤15 秒 |
| cert_uid / cert_fingerprint | 该呼号最新有效证书的 UID/指纹；无有效证书为 null（含已吊销） |

> 列表包含从总系统/兄弟分系统同步来的全部用户，APP 可据此展示全网台站目录。

---

### 4.6 统计 `GET /api/stats`

```json
{"ok": true, "total": 128, "online": 5}
```

### 4.7 健康检查 `GET /api/health`

```json
{"ok": true, "service": "fmo-subsystem", "time": 1757900000.0}
```

### 4.8 服务信息 `GET /api/config`

```json
{
  "ok": true,
  "config": {
    "app_domain": "app.example.com",
    "app_port": 35928,
    "app_use_port": true,
    "subsystem_id": "sub-001",
    "name": "FMO注册系统-默认",
    "domain": "register.example.com"
  }
}
```

APP 可据此显示当前接入的分系统名称/ID。

### 4.9 上传文件访问 `GET /uploads/<filename>`

用户注册时上传的证件照，`cert_photo_path` 字段即为此路径（相对根路径）。

---

## 5. MQTT 语音接入协议

语音通联走 MQTT（broker 默认 `1883`，地址由部署方提供）。**CONNECT 凭证按以下规范构造**：

### 5.1 username

明文呼号（如 `BH1ACG`），**不做任何 base64 编码**。

### 5.2 password

与官方/APP 统一的老 FMO 格式（对应 `FmoCert.buildMqttPassword`）：

```
base64url( JSON.stringify({
  "certPackage": {
    "intermediateCert": <cert_int 对象>,
    "userCert":         <cert_user 对象>
  },
  "targetCallsign":   "<目标服务器呼号，可空>",
  "targetUID":        <目标服务器UID，可为 0>,
  "role":             "user",
  "targetUrl":        "<目标服务器地址>",
  "targetPort":       1883,
  "serverFingerprint":"<目标服务器指纹，base64url>",
  "timestamp":        1757800000,
  "proof": { "signature": "<base64url>" }
}) )
```

- base64url 编码**有无 padding 均可**（服务端兼容）。
- `proof.signature`（**必填**）：用 `cert_devicekey.seed` 对应的私钥，对以下 **12 元素数组的 CBOR 编码**做 Ed25519 签名，再 base64url。用于证明持有私钥，防证书盗用：

```
["FMO", 4, "serverAuthorizerReqHttp",
 targetUID, targetCallsign(大写), targetUID, role,
 targetUrl, targetPort, serverFingerprint(原始字节),
 timestamp, userCert指纹(原始字节)]
```

- 服务器为**宽松模式**：只验签名本身有效，不强制目标字段指向本机，因此任何一台服务器都接受指向其他服务器的 proof（跨服互登不受限）。

### 5.3 服务端验证流程（broker 回调 `POST /auth`）

依次校验：password 解析 → 证书链签名（User Cert ← Int CA ← 根公钥）→ 有效期 → 呼号匹配（username == 证书呼号）→ proof 验签（12 元素 CBOR TBS）→ 吊销列表 → 根 CA 信任判定（按根公钥比对，**任一来源即可**）：

| 来源 | 说明 |
|---|---|
| a. 本机 CA | 分系统自己签发的证书 |
| b. 内置官方根 | BG5ESN（ESN 体系天然互认，不经 master、无需配置） |
| c. roots 目录接种 | 第三方根（如江苏），手动放置根证书 JSON 或运行官方 `add-root.sh --url <对方/api/ca/root.json>`，重启生效 |
| d. trust_chain 信任链表 | master 自动同步下发的分系统互认 |

返回 `{result: "allow", acl: [...], client_attrs: {callsign, uid}}` 或 `{result: "deny", reason: "..."}`。

### 5.4 授权 topic（ACL）

| topic | 权限 | 用途 |
|---|---|---|
| `fmo/broadcast/#` | subscribe | 全员广播 |
| `fmo/+/presence` | subscribe | 在线状态 |
| `fmo/{callsign}/#` | publish + subscribe | 本人呼号频道（点对点语音） |
| `fmo/uid/{uid}/#` | publish + subscribe | 本人 UID 频道 |
| `fmo/group/{callsign}/#` | publish + subscribe | 群组呼叫 |

---

## 6. 证书数据结构

证书为 JSON 对象（Ed25519 签名体系），APP 只需原样传递，无需解析。`/api/cert/mine` 返回的用户证书实际结构：

```json
{
  "issuerSn": 1001,
  "subject": { "callsign": "BH1ACG", "uid": 1001, "publicKey": "<base64url>" },
  "iat": 1757800000,
  "exp": 1855400000,
  "signatureAlgorithm": "Ed25519",
  "signature": "<base64url>"
}
```

> 官方体系（ESN 等）签发的证书可能额外带 `type`/`sn`/`issuer` 等字段，服务端均兼容；APP 原样塞进 `certPackage.userCert` 即可，不要增删字段。

- `cert_user.subject.callsign` / `cert_user.subject.uid`：身份标识。
- `cert_devicekey` 结构：`{"seed": "<base64url 私钥种子>", "pubKey": "<base64url 公钥>"}`，seed 用于 MQTT proof 签名。
- 有效期：`iat`/`exp` 为 Unix 秒。默认签发 10 年。
- `fingerprint`（64 位 hex）：用户证书指纹，吊销/认证均以此为准。

---

## 7. 语音监控 API（瀑布图数据源）

> 管理后台瀑布图使用的接口，APP 如需实现通联监听/回放可直接复用。

### 7.1 监控状态 `GET /api/monitor/status`

```json
{"ok": true, "monitor": {"state": "connected", "mqtt": "127.0.0.1:1883", "...": "..."}}
```

### 7.2 语音段列表 `GET /api/monitor/segments?since=<ts>&limit=<n>`

| 参数 | 默认 | 上限 | 说明 |
|---|---|---|---|
| since | 0 | - | Unix 秒，只返回此后的段（增量拉取） |
| limit | 200 | 1000 | 条数 |

```json
{
  "ok": true,
  "segments": [
    {
      "id": 42,
      "callsign": "BH1ACG",
      "session": "会话标识",
      "start_ts": 1757900000.0,
      "end_ts": 1757900002.35,
      "duration_ms": 2350,
      "codec": "opus",
      "frames": 118
    }
  ],
  "now": 1757900001.0
}
```

> 段记录含**说话人呼号**（callsign）与起止时间，APP 瀑布图直接按时间轴显示"谁在说话、说了多久"，再按 `id` 拉音频播放。

### 7.3 语音段音频 `GET /api/monitor/audio?id=<segment_id>`

- 成功：二进制音频流，`Content-Type: application/octet-stream`，响应头 `X-Codec` 指示编码（如 `opus`）。
- 失败：`404 {"ok": false, "error": "语音段不存在"}`

### 7.4 信标列表 `GET /api/monitor/beacons?since=<ts>&limit=<n>`

```json
{
  "ok": true,
  "beacons": [
    {
      "id": 7,
      "callsign": "BH1ACG",
      "freq1": 439.5,
      "freq2": 431.5,
      "tele_ts": 1757899995.0,
      "created_at": 1757900000.0
    }
  ],
  "now": 1757900001.0
}
```

`limit` 默认 50，上限 200；按 `created_at` 倒序返回（最新在前）。`freq1`/`freq2` 为信标频率，`tele_ts` 为遥测时间戳。

---

## 8. 管理类 API（管理后台使用，APP 一般不需要）

> 以下接口全部仅在**管理端口**（API 端口 + 1）可用，公网口访问一律 403。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/cert/issue` | 手动签发证书 `{callsign, uid, validity_years?}`（uid 1-200000） |
| POST | `/api/cert/auto-issue` | 一键签发（幂等）`{callsign}`，自动分配 UID |
| POST | `/api/cert/revoke` | 吊销 `{fingerprint}` 或 `{callsign}`（吊销该呼号最新有效证书），**同步全系统** |
| GET | `/api/cert/list?limit=` | 已签发证书列表（不含证书体，默认 200 上限 1000） |
| GET | `/api/cert/bundle?callsign=` 或 `?fingerprint=` | 下载证书四件套 ZIP 压缩包（见 8.1） |
| GET | `/api/ca/info` | 本地 Root/Int CA 信息 + 信任链统计 |
| POST | `/api/ca/init` | 初始化 CA `{force?}`（已存在不 force 时幂等返回） |
| POST | `/api/ca/renew` | CA 轮换（已签发证书将失效，慎用） |
| POST | `/api/trust/add` | 添加信任 CA |
| GET | `/api/trust/list` | 信任链列表 |
| DELETE | `/api/trust/{id}` | 删除信任 CA |
| DELETE | `/api/user/{callsign}` | 删除账号：吊销该呼号全部证书 + 软删除用户，删除状态**同步全系统**（见 8.2） |
| GET | `/api/sync/status` | 同步状态（subsystem_id/mode/peers/各方向最近同步时间与计数） |
| GET | `/api/sas/config` | SAS 配置查询 |
| POST | `/api/sas/config` | SAS 配置更新（白名单/UID 范围/有效期等） |
| GET/POST | `/api/config` | 分系统基础配置（app_domain/app_port 等） |

### 8.1 证书套打包下载 `GET /api/cert/bundle`

管理后台"⬇ 证书包"按钮使用；用于将用户证书四件套一次性导出（如线下转交用户导入 APP）。

| 参数 | 说明 |
|---|---|
| callsign | 查该呼号**最新未吊销**证书 |
| fingerprint | 按指纹精确查（含已吊销存档） |

两者至少提供一个。

**成功响应**：`Content-Type: application/zip`，`Content-Disposition: attachment; filename="<呼号>_certs.zip"`，ZIP 内含 4 个 JSON 文件：

| 文件 | 内容 |
|---|---|
| cert_root.json | 根 CA 证书 |
| cert_int.json | 中间 CA 证书 |
| cert_user.json | 用户证书 |
| cert_devicekey.json | 设备密钥（含私钥 seed，**须安全转交本人**） |

**错误**：`404 该呼号暂无已签发证书` / `404 证书不存在` / `503 CA 未初始化`。

> 与 `/api/cert/mine` 的区别：`cert/mine` 是 APP 凭用户 token 自助拉取（JSON 响应，公网口可用）；`bundle` 是管理员从管理后台代下载（ZIP 附件，仅管理口）。

### 8.2 删除账号 `DELETE /api/user/{callsign}`

管理后台用户列表"删除"按钮使用。一次删除 = 两件事，均经同步传播到总系统与全部分系统：

1. **吊销证书**：该呼号名下全部未吊销证书置 `revoked=1`（MQTT/证书登录即刻失效）；
2. **软删除用户**：users 行置 `deleted=1`（墓碑），APP 登录立即返回"呼号不存在"。

**响应**

```json
{"ok": true, "callsign": "BH1ACG", "revoked_certs": 2, "message": "账户已删除，2 张证书已吊销，删除状态将同步到全系统"}
```

**错误**：`404 用户不存在` / `用户已被删除`。

> 删除后呼号仍被墓碑占用，同名呼号不能重新注册；如需彻底释放呼号，由管理员直接清库。

---

## 9. 系统间同步协议（参考）

> 分系统 ↔ 总系统、分系统 ↔ 分系统的数据同步。APP 不直接使用，列出以便理解数据流向。

### 9.1 分系统 → 总系统

| 方向 | 路径 | 说明 |
|---|---|---|
| 上报 | POST `{master}/api/subsystem/report` | 增量/全量上报 users/certificates/trust_chain/ca_info；users 全量含本机持有的**全部账号**（含远端同步副本、deleted 墓碑），携带 password_hash（token 是本机会话凭证，绝不上报） |
| 拉取 | POST `{master}/api/sync/pull` | 从总系统拉取数据；users 每个呼号只下发 last_modified 最新的一行（不回传本机自己上报的行），带 password_hash，`subsystem_id` 为账号**真实归属**分系统 |
| 语音上报 | POST `{master}/api/voice/report` | 语音段/信标同步到总系统监控 |

### 9.2 分系统 ↔ 分系统 / 总系统 → 分系统

| 路径 | 说明 |
|---|---|
| POST `/api/sync/peer` | 接收兄弟分系统 P2P 推送 |
| POST `/api/sync/report` | 接收总系统全量推送（总系统管理后台"立即下发"触发） |

**sync_token 鉴权**：当 config.json 配置了 `sync_token` 时，以上两个接收端点会校验请求体中的 `sync_token` 字段，不匹配返回 `403 {"ok": false, "error": "invalid sync_token"}`。发送方（上报/拉取/P2P）均自动携带该字段，正常部署无需额外处理。

### 9.3 总系统管理面新增（master admin 端口，默认 35931）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/sync/push` | 立即向分系统推送全量数据；body `{}` 推全部，`{"subsystem_id": "sub-x"}` 推指定 |
| GET | `/api/trust/cert?id=<trust_id>` | 重新下载已签发的信任证书 JSON（含已撤销存档） |
| POST | `/api/trust/issue` | 签发信任证书，支持 `validity_years`（1-50 年，缺省 10 年） |
| GET | `/api/users/matrix` | 账号覆盖矩阵：每个账号 × 每台分系统的上报状态（ok/stale/missing/已删），用于排查"哪个账号在哪台没报上来或数据落后" |

### 9.4 数据合并语义

- 用户按呼号合并，last_modified 新者赢；`subsystem_id` 记录账号**真实归属**分系统（取胜者行内归属），不随副本倒手改变。
- **账号密码全网同步**：password_hash 随上报/下发传播，一次注册全系统可登录；空密码行不会覆盖已有密码（防旧版对端稀释密码）。
- 总系统按（上报方, 呼号）逐行存档每个分系统的视角；下发时按呼号去重只发最新行，且不回传拉取方自己上报的行（防回环）。
- **缺失 ≠ 删除**：某分系统没报某账号，总系统只在覆盖矩阵标"未报"，**不**生成删除墓碑；删除只经显式 `deleted=1` 墓碑行传播（防止"还没同步到"被误判成删除而扩散全网）。
- 证书按指纹合并；吊销状态全网传播。
- 根 CA 互认走"目录登记 + 接种"：master 登记各分系统上报的根 CA（校验自签名后入目录），全量下发；分系统 merge 时再校验一次自签名后接种进 trust_chain（见 9.5）。
- 接收推送后分系统会记录 `sync_log`（direction=`peer_in`）并更新同步状态页。

### 9.5 服务器间证书互认（根接种，江苏 add-root 模式的自动版）

信任一个根 CA **不需要任何第三方背书签名**：只要根证书结构正确且 Ed25519 自签名有效即可接种。

| 场景 | 操作 |
|---|---|
| 别人信任我们 | 对方运行官方 `add-root.sh --url http://<本机>:8080/api/ca/root.json`，或手动把该 JSON 放进对方 roots 目录 |
| 我们信任第三方（如江苏） | 把对方根证书 JSON 放进本机 roots 目录（config `trust.rootsDir`，默认 `roots/`），重启生效；与官方 add-root.sh 放置的文件格式一致 |
| 分系统 ↔ 主系统体系内 | **全自动**：master 登记各分系统根 CA 并全量下发，分系统收到后自验签名接种，等价于自动跑了一遍 add-root.sh |
| ESN 官方体系 | 根公钥内置硬编码（BG5ESN），天然互认，无需任何配置 |

本系统根证书公开下载端点：`GET /api/ca/root.json`（SAS 端口 8080，无需鉴权，根证书本身即公开信息）。

---

## 10. 错误处理建议（APP 侧）

| 场景 | 建议 |
|---|---|
| `401 token 无效` | 跳转重新登录 |
| 注册返回 `cert_issued=false` | 提示"证书签发中"，进入主界面后调 `/api/cert/mine` 重试 |
| `/api/cert/mine` 返回 `503` | 分系统 CA 未就绪，提示联系管理员并稍后重试 |
| MQTT deny `证书已被吊销` | 清除本地证书，引导用户联系管理员 |
| MQTT deny `Root CA 不受信任` | 分系统间信任链未建立，提示联系管理员 |
| 心跳失败 | 静默重试；连续失败提示网络异常 |

---

## 11. 国服 ID（DMRID）绑定：账号密码派生证书

> 目标：让用户**无需保存/传输任何证书文件**，只要记得「国服 ID（呼号）+ 密码」即可完全接入（绑定 → 登录 → MQTT 通联）。
> 原理：用国服账号密码通过 KDF **确定性地派生一把 Ed25519 私钥**，再由分系统把其公钥签进用户证书；MQTT 认证仍走证书链 + proof 私钥签名，密码不进入 MQTT 报文。

### 11.1 密钥派生规范（跨平台必须逐字节一致）

| 项 | 值 |
|---|---|
| identifier | 呼号（大写，UTF-8） |
| password | 国服密码明文（UTF-8） |
| salt | `UTF8("FMO-DMRID-v1:" + identifier)` |
| seed | `KDF(password, salt)`，长度 32 字节 |
| pubkey | Ed25519 公钥（由 seed 推导） |

- 默认算法 **PBKDF2-HMAC-SHA256，600000 次迭代**（`config.dmrid.kdf_algorithm=pbkdf2`）；可选 `scrypt`（n=32768, r=8, p=1）。
- 更换算法/参数必须同时升级 salt 前缀版本号（`FMO-DMRID-v1` → `v2`），避免新旧密钥冲突。
- 参考实现见 `cert_gen.py::derive_keypair` / `build_key_proof` / `build_mqtt_credentials`。

### 11.2 绑定接口 `POST /api/cert/bind`

**请求** `application/json`（公网口可用）

**请求头**

| 头 | 必填 | 说明 |
|---|---|---|
| `Content-Type` | 是 | `application/json; charset=utf-8` |

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| callsign | text | 是 | 呼号（4-10 位大写字母数字） |
| pubkey | text | 是 | 派生出的 Ed25519 公钥（32B，base64url） |
| key_proof | text | 是 | `Ed25519_sign(seed, UTF8("FMO-DMRID-bind:" + callsign))` 的 base64url |
| app_timestamp | int | 是 | Unix 秒（APP 签名时间戳） |
| app_signature | text | 是 | `Ed25519_sign(app_seed, UTF8("FMO-APP-auth:{ts}:{callsign}:{pubkey_b64}"))` 的 base64url |
| password | text | 否 | 国服密码；仅 `config.dmrid.verify_password=true` 时必填并校验 |

> **APP 签名鉴权**：APP 用其 Ed25519 私钥（`gen_app_key.py` 的 `APP_SEED`）签名，服务端用 `config.dmrid.app_pubkey` 验签；缺失/错误/超窗一律 403。
> 默认**简化模式**（`verify_password=false`）：分系统只调用国服 `GET /api/auth/callsign-lookup` 确认「该呼号存在国服 ID」，不校验密码（APP 已在国服侧完成登录）。

**成功响应**

```json
{
  "ok": true,
  "message": "绑定成功，已用国服账号派生密钥签发证书",
  "token": "…（分系统登录 token，可直接用于 heartbeat / cert/mine）",
  "callsign": "BG2XFM", "uid": 1001, "fingerprint": "…",
  "guoji_id": 4601234, "dmr_id": 8600201,
  "derived": true,
  "cert_root": { "…": "根CA证书JSON" },
  "cert_int":  { "…": "中间CA证书JSON" },
  "cert_user": { "…": "用户证书JSON" },
  "cert_devicekey": null
}
```

- `cert_devicekey` 恒为 `null`：私钥由客户端用密码派生，**服务器不生成、不持有**。
- **幂等**：同呼号同公钥重复绑定返回同一证书；换公钥则吊销旧证重签（UID 稳定不变）。
- 之后 MQTT 认证流程与普通证书完全一致（见 5.3 节）：客户端用派生 seed 构造 proof，服务端验证书链 + proof 签名。

**错误**

| 状态码 | message |
|---|---|
| 403 | `APP 签名无效或已过期` / `key_proof 验证失败（公钥与私钥不匹配…）` / `账号状态为 …，未通过审核` / `该账号已被限制使用` |
| 400 | `呼号格式不正确（需 4-10 位大写字母和数字）` / `缺少 pubkey 或 key_proof` / `pubkey 必须为 32 字节 Ed25519 公钥` |
| 404 | `该呼号未识别到国服 ID（国际 ID），无法绑定` |
| 401 | `国服账号或密码错误`（仅 `verify_password=true` 时，转自国服后端） |
| 502 | `无法连接国服后端…`（国服不可达） |
| 503 | `国服ID绑定未启用` / `CA 未初始化` / `证书模块未加载` |

### 11.3 配置 `config.dmrid`

```json
{
  "dmrid": {
    "enabled": true,
    "base_url": "https://dmriapi.radiowo.com",
    "timeout": 10,
    "app_pubkey": "APP 公钥（gen_app_key.py 的 APP_PUBKEY，base64url）",
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

- `enabled`：是否启用国服 ID 绑定（默认 false）。
- `app_pubkey`：APP 签名公钥（Ed25519，base64url），绑定接口验签用；留空时生产环境一律拒绝绑定（fail-closed，仅 `dev_mode` 放行）。用 `python gen_app_key.py` 生成。
- `app_timestamp_window`：APP 签名时间戳允许窗口（秒，默认 300）。
- `verify_password`：`false`=仅查呼号存在（简化，推荐）；`true`=额外校验国服密码（强校验）。
- `dev_mode`：本地自测用，跳过真实国服查询并按呼号合成 guojiId；**严禁生产开启**。

### 11.4 安全说明

1. **APP 私钥是信任锚**：简化模式下分系统只验证「APP 签名 + 呼号存在」。APP 私钥烧进 APP、服务端只存公钥（非秘密），无需分发共享密钥；APP 私钥泄露则重新生成密钥对（换 config 公钥 + 换 APP seed）。
2. 密码派生密钥的强度**取决于密码本身**：弱密码可被离线爆破（拿 pubkey 试字典比对），务必使用强密码 + 高成本 KDF。
3. 服务器**绝不派生/持有 seed**，私钥只在客户端本地由密码派生；忘记密码 = 私钥永久丢失，需「重置 → 吊销旧证 → 重新绑定」。
4. 国服身份校验仅发生在绑定这一次；之后 MQTT 认证纯走证书，不依赖国服后端在线。
5. 分系统会把 `guoji_id` / `dmr_id` 写入用户记录并随同步全网传播，便于全局目录展示国服 ID。

---

*文档对应源码：api_server.py / sas_server.py / sync_engine.py / monitor.py / cert_gen.py（fmo-subsystem-deploy）*
