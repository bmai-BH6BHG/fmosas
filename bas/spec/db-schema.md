# FAS 数据库与数据模型契约（.NET → Python 重写依据）

**来源**：`C:\Users\Administrator\AppData\Local\Temp\fas-clone`（仓库 `BG5ESN/fmo-audit-service`，程序集 `fmo-audit-service` v2.0.22，net10.0，`Microsoft.Data.Sqlite` 10.0.10 + `SQLitePCLRaw.bundle_e_sqlite3` 3.0.5）
**核心文件**：`Database.cs`(1158 行)、`Models.cs`、`AppSettings.cs`、`AuthService.cs`、`CollectorService.cs`、`TopicIngestService.cs`、`TopicEndpoints.cs`、`BlacklistEndpoints.cs`、`EmqxClient.cs`、`Program.cs`

**先说结论（与任务书假设不符的三处，以源码为准）**

1. **没有** `clients` / `leaderboard` 表。排行榜**不落库**，是查询时对 `minute_stats` 做 `GROUP BY COALESCE(username, clientid)` 实时聚合。全库只有 **7 张表**：`minute_stats`、`topic_stats`、`health_snapshots`、`settings`、`admin_user`、`blacklist_audit`、`audit_packets`。
2. **没有**独立的 `blacklist` 表。黑名单只有一张**追加型流水表** `blacklist_audit`；"当前生效黑名单"是**查询时用窗口函数推导**的（没有任何定时解封任务）。
3. **没有**单独的 host health 表（宿主机与 EMQX 指标合并在 `health_snapshots`）、**没有**单独的 10 秒分桶表（`topic_stats` 本身就是 10 秒粒度原始表，1m/5m/1h 全部是*查询时*降采样，无预聚合/物化视图）。
4. 所有业务时间戳都是 **TEXT 类型的"服务器本地时间"**（`DateTime.Now`），不是 Unix 时间戳；唯一以 **Unix 秒**存储的是包头内的 `pkt_ts` / `stream_begin`（uint32 原值字符串）。

**本 spec 的验证情况**：第 1 节 SQL 已从本文档中提取并在 **SQLite 3.53.1** 上 `executescript` 通过——建出 7 张表 + 6 个显式索引（+4 个 PRIMARY KEY 自动索引），`minute_stats(12 列, PK clientid+ts)`、`topic_stats(7 列, PK topic+clientid+ts)`、`audit_packets(17 列, PK id)` 等列数/PK 与源码一致；第 5 节 `rowid` 分批清理语句可执行，且已确认裸 `DELETE ... LIMIT` 报 `near "LIMIT": syntax error`（印证源码注释）；第 6 节 1m/5m/1h 桶表达式实测 `12:34:56→12:34:00/12:30:00/12:00:00`、`12:59:59→12:55:00`（截断而非四舍五入）；第 6 节排行榜 SQL 实测按呼号聚合（`MIN(uid)` 生效、匿名行回退 clientid）；第 8 节生效黑名单窗口查询实测正确排除已过期条目。

---

## 1. 完整建表 SQL

### 结论

7 张表 + 6 个索引，全部由 `Database.Init()` 中一条**多语句 CommandText** 用 `CREATE TABLE IF NOT EXISTS` 建立（`Database.cs:34-127`）。`PRIMARY KEY`/索引是幂等去重的唯一保证。紧随其后是 `PRAGMA user_version` 驱动的迁移循环（当前 `SchemaVersion = 1`，只有基线，无 ALTER 分支），最后在同一条连接上执行 WAL/性能 PRAGMA。

**数据库文件路径**（`Program.cs:49-58`、`CliConfigure.cs:23-30`）：
- 环境变量 `EMQX_MONITOR_DB` 优先；
- 否则 `%LOCALAPPDATA%\EmqxMonitor\emqx-monitor-server.db`（Linux 即 `~/.local/share/EmqxMonitor/...`）；
- 安装脚本 systemd/计划任务场景为 `/opt/fmo-fas/fmo-audit-service.db`（`CliConfigure.cs:53-56`）。

### 证据：`Database.cs:13-28`（连接串、保留期、schema 版本）

```csharp
public class Database
{
    private readonly string _connStr;
    private readonly object _lock = new();

    /// <summary>数据保留时长（30 天）</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(30);

    /// <summary>schema 版本（PRAGMA user_version）。加字段/索引：版本 +1 并在 MigrateTo 加 ALTER</summary>
    private const int SchemaVersion = 1;

    public Database(string dbPath)
    {
        _connStr = $"Data Source={dbPath}";
        Init();
    }
```

### 证据：`Database.cs:34-127` —— 原文照抄（可直接执行；Python 重写请保持字节级一致）

```sql
CREATE TABLE IF NOT EXISTS minute_stats (
    clientid    TEXT    NOT NULL,
    username    TEXT,
    uid         TEXT,               -- 用户编号(client_attrs.uid)
    ts          TEXT    NOT NULL,   -- 'yyyy-MM-dd HH:mm:00' 分钟级
    send_oct    INTEGER NOT NULL DEFAULT 0,
    recv_oct    INTEGER NOT NULL DEFAULT 0,
    send_msg    INTEGER NOT NULL DEFAULT 0,
    recv_msg    INTEGER NOT NULL DEFAULT 0,
    send_pkt    INTEGER NOT NULL DEFAULT 0,
    recv_pkt    INTEGER NOT NULL DEFAULT 0,
    ip_address  TEXT,
    reconnect   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (clientid, ts)
);
CREATE INDEX IF NOT EXISTS idx_min_ts ON minute_stats(ts);
CREATE INDEX IF NOT EXISTS idx_min_user_ts ON minute_stats(username, ts);

CREATE TABLE IF NOT EXISTS topic_stats (
    topic     TEXT    NOT NULL,
    username  TEXT,
    uid       TEXT,               -- 用户编号(client_attrs.uid)
    clientid  TEXT    NOT NULL,
    ts        TEXT    NOT NULL,   -- 'yyyy-MM-dd HH:mm:SS' 10秒粒度
    msg_count INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (topic, clientid, ts)
);
CREATE INDEX IF NOT EXISTS idx_topic_ts ON topic_stats(ts);
CREATE INDEX IF NOT EXISTS idx_topic_user_ts ON topic_stats(topic, username, ts);

CREATE TABLE IF NOT EXISTS health_snapshots (
    ts                TEXT    PRIMARY KEY,   -- 'yyyy-MM-dd HH:mm:00'
    host_cpu_pct      REAL,
    host_mem_used_pct REAL,
    host_disk_used_pct REAL,
    host_net_recv_kbps REAL,
    host_net_send_kbps REAL,
    emqx_node         TEXT,
    emqx_cpu_pct      REAL,
    emqx_mem_used_pct REAL,
    emqx_connections  INTEGER,
    emqx_msg_rate     REAL,
    emqx_alarms       TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_user (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,   -- PBKDF2: iterations.salt_b64.hash_b64
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS blacklist_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT    NOT NULL,      -- 'ban' | 'unban'
    as_type    TEXT    NOT NULL,      -- 粒度: username（预留 clientid/peerhost）
    who        TEXT    NOT NULL,      -- 呼号
    reason     TEXT,                  -- 拉黑原因
    until      TEXT,                  -- 到期 'yyyy-MM-dd HH:mm:ss'（NULL = 永久）
    operator   TEXT    NOT NULL,      -- 操作管理员
    created_at TEXT    NOT NULL       -- 操作时间 'yyyy-MM-dd HH:mm:ss'
);
CREATE INDEX IF NOT EXISTS idx_bl_who ON blacklist_audit(who, created_at);

CREATE TABLE IF NOT EXISTS audit_packets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,   -- 接收时间 'yyyy-MM-dd HH:mm:ss.SSS'
    topic         TEXT    NOT NULL,
    clientid      TEXT    NOT NULL,
    conn_callsign TEXT,               -- 连接身份 callsign（client_attrs.callsign）
    conn_uid      TEXT,               -- 连接身份 uid
    pkt_callsign  TEXT,               -- 包头声明呼号
    pkt_uid       TEXT,               -- 包头声明 UID
    verdict       TEXT    NOT NULL,   -- KICK / WARN / FAIL（PASS 不落库，由 topic_stats 聚合）
    len           INTEGER,
    frame_num     INTEGER,
    crc_ok        INTEGER,
    smeter        INTEGER,
    srv_uid       TEXT,
    pkt_ts        TEXT,               -- 包内 timestamp 原值（uint32 字符串）
    stream_begin  TEXT,
    ban           INTEGER NOT NULL DEFAULT 0   -- 是否触发自动拉黑
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_packets(ts);
CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_packets(verdict, ts);
```

> 注意源码里的 SQL 是 C# raw string literal（`"""`），缩进会被原样保留（每行前有 12 个空格）；SQLite 忽略前置空白，语义不受影响。上表已去除缩进。

### 证据：`Database.cs:129-172` —— 迁移机制（`PRAGMA user_version`）

```csharp
        // ---- schema 迁移：user_version 逐版本升级。新表结构放基线 CREATE；
        //      老库缺列/新索引在 MigrateTo 里 ALTER（加字段 = SchemaVersion+1 + MigrateTo 加分支）----
        var ver = GetUserVersion(conn);
        while (ver < SchemaVersion)
        {
            ver++;
            MigrateTo(conn, ver);
            SetUserVersion(conn, ver);
        }
```
`MigrateTo` 只有 `case 1: break;`（基线）与 `default: throw new InvalidOperationException($"未知的 schema 版本: {version}")`（`Database.cs:160-172`）。`GetUserVersion` = `PRAGMA user_version`，`SetUserVersion` = `PRAGMA user_version = {v}`（`Database.cs:145-157`）。

### 证据：`Database.cs:139-143` —— WAL 与连接参数

```csharp
        // WAL + 性能（单进程读写，NORMAL 足够安全）
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;";
        pragma.ExecuteNonQuery();
```

**关键实现事实（Python 重写必须知道）**：`Open()`（`Database.cs:174-179`）只做 `new SqliteConnection(_connStr); conn.Open();`，**不重复执行任何 PRAGMA**。也就是说：
- `journal_mode=WAL` 是**写进数据库文件的持久属性**，只在一次 `Init()` 时设置，之后永久生效（即使换成 Python 打开也仍是 WAL）；
- `synchronous=NORMAL` 与 `busy_timeout=5000` 是**连接级**参数，只对 `Init()` 那一根连接生效。后续每个方法都新建连接（`using var conn = Open();`）→ **这些连接的 `synchronous` 回到默认 FULL、`busy_timeout` 回到默认 0**。Microsoft.Data.Sqlite 默认开启连接池（`Pooling=true`），`Init()` 的连接归还池后可能被后续请求复用，所以实际行为"部分生效"，属于隐式偶发。
- 连接串没有 `Cache=Shared`、没有 `Mode=ReadWriteCreate` 显式声明、没有 `Foreign Keys=True`（本来就无外键）。

---

## 2. 每个字段的业务含义与单位

### 结论

单位口径：`*_oct` = **字节**；`*_msg`/`msg_count` = **消息条数**；`*_pkt` = **MQTT 包数**；`*_kbps` = **KiB/s（源码除以 1024）**；`*_pct` = **百分比 0–100（REAL）**；`emqx_msg_rate` = **条/秒**；`len` = **整包字节数**；`smeter` = **0–255 的原始单字节**。时间戳：除 `pkt_ts`/`stream_begin` 外**全部是 TEXT 本地时间**，`audit_packets.ts` 精确到毫秒，其余到秒/分。

### `minute_stats` —— 每分钟每 clientid 的增量（核心底座，保留 30 天）

| 字段 | 类型 | 含义 / 单位 | 来源与写入时机 |
|---|---|---|---|
| `clientid` | TEXT NOT NULL | EMQX clientid（主键之一） | `CollectorService.cs:144` |
| `username` | TEXT NULL | **呼号**：`client_attrs.callsign ?? username`（`callsign` 优先，认证时服务端写入，比 username 可靠） | `CollectorService.cs:152`；`Models.cs:130-131` |
| `uid` | TEXT NULL | 用户编号 `client_attrs.uid`（EMQX 可能给数字，容错归一为字符串） | `CollectorService.cs:153`；`Models.cs:134-135, 143-186` |
| `ts` | TEXT NOT NULL | 分钟桶，**本地时间**，`'yyyy-MM-dd HH:mm:00'`（秒恒为 00） | `CollectorService.cs:114` |
| `send_oct` | INTEGER 默认 0 | 该分钟**服务端发出字节增量** | EMQX `send_oct` 差分 |
| `recv_oct` | INTEGER 默认 0 | 该分钟**服务端收到字节增量** | EMQX `recv_oct` 差分 |
| `send_msg` | INTEGER 默认 0 | 该分钟**发出消息条数增量**（MQTT PUBLISH 计数） | EMQX `send_msg` |
| `recv_msg` | INTEGER 默认 0 | 该分钟**收到消息条数增量** | EMQX `recv_msg` |
| `send_pkt` | INTEGER 默认 0 | 该分钟**发出 MQTT 包数增量**（含 CONNECT/PINGREQ 等控制包） | EMQX `send_pkt`；**重连判定的唯一依据** |
| `recv_pkt` | INTEGER 默认 0 | 该分钟**收到 MQTT 包数增量** | EMQX `recv_pkt` |
| `ip_address` | TEXT NULL | 客户端 IP（EMQX 原值字符串） | `CollectorService.cs:161` |
| `reconnect` | INTEGER 默认 0 | **0/1 重连标记**；仅当 `send_pkt` 差分 < 0（计数器归零）时为 1，且该分钟 `send_pkt` 记 0 | `CollectorService.cs:159, 324-335` |

### `topic_stats` —— 规则引擎消息事件，10 秒粒度（保留 30 天）

| 字段 | 类型 | 含义 / 单位 | 来源 |
|---|---|---|---|
| `topic` | TEXT NOT NULL | MQTT 主题原始字符串（主键之一） | webhook `topic` |
| `username` | TEXT NULL | 呼号：`client_attrs.callsign` 覆盖 `username`；`"undefined"`（Erlang atom 序列化）归一为 NULL | `TopicEndpoints.cs:30-43` |
| `uid` | TEXT NULL | `client_attrs.uid`（数字则取 `GetRawText()`） | `TopicEndpoints.cs:38-41` |
| `clientid` | TEXT NOT NULL | clientid（主键之一） | webhook `clientid` |
| `ts` | TEXT NOT NULL | **10 秒桶**，本地时间 `'yyyy-MM-dd HH:mm:ss'`，秒 ∈ {00,10,20,30,40,50} | `TopicIngestService.cs:66-68` |
| `msg_count` | INTEGER 默认 0 | 该 10 秒桶内**消息条数**（每收 1 条 +1） | `TopicIngestService.cs:73` |
| `bytes` | INTEGER 默认 0 | 该 10 秒桶内**payload 字节数合计**；payload 是 base64 字符串时取解码后长度，解码失败则退化为**字符串字符数**（近似） | `TopicEndpoints.cs:45-56` |

### `health_snapshots` —— 每分钟健康快照（保留 30 天）

| 字段 | 类型 | 含义 / 单位 |
|---|---|---|
| `ts` | TEXT PRIMARY KEY | 分钟桶，本地 `'yyyy-MM-dd HH:mm:00'` |
| `host_cpu_pct` | REAL NULL | 宿主机 CPU 使用率 **%**（Linux 由 `/proc/stat` idle+iowait 差分；Windows 用 `% Processor Time`） |
| `host_mem_used_pct` | REAL NULL | 宿主机内存使用率 **%**（Linux `1 - MemAvailable/MemTotal`；Windows `% Committed Bytes In Use`） |
| `host_disk_used_pct` | REAL NULL | 第一个就绪固定盘使用率 **%**（`DriveInfo`） |
| `host_net_recv_kbps` | REAL NULL | 宿主机**接收速率 KiB/s**（Linux `Δrx/1024/秒`） |
| `host_net_send_kbps` | REAL NULL | 宿主机**发送速率 KiB/s** |
| `emqx_node` | TEXT NULL | EMQX 节点名（如 `emqx@127.0.0.1`） |
| `emqx_cpu_pct` | REAL NULL | **实为 EMQX 节点的系统 1 分钟负载 `load1`**（EMQX 5.x 无 CPU% 字段），单位是"load 值"不是百分比 |
| `emqx_mem_used_pct` | REAL NULL | EMQX 节点内存占用 **%** = `clamp(100*MemoryUsed/MemoryTotal, 0, 100)` |
| `emqx_connections` | INTEGER NULL | **当前在线客户端数**（取自 `LastClientCount`，即 FMO 客户端总数，**不是** EMQX 全局连接数） |
| `emqx_msg_rate` | REAL NULL | **消息速率 条/秒** = `Δ(recv+sent)/Δ秒`（用 UTC 计时差），仅当本轮总量 ≥ 上轮时有值，否则为 NULL |
| `emqx_alarms` | TEXT NULL | 活跃告警的 JSON 文本（空则存 NULL） |

### `settings` / `admin_user`

- `settings.key` TEXT PK、`settings.value` **TEXT NOT NULL**（清空时写 `""`，**永不写 NULL**）→ 见第 3 节。
- `admin_user.id INTEGER PRIMARY KEY CHECK (id = 1)`：**全表强制只有一行**，靠 `CHECK` + `ON CONFLICT(id)` upsert 实现"单管理员"。
  - `username` TEXT NOT NULL：管理员名（`Setup` 时 `.Trim()` 后存，`AuthService.cs:41`）。
  - `password_hash` TEXT NOT NULL：格式 `"iterations.salt_b64.hash_b64"`。
  - `created_at` TEXT NOT NULL：**UTC** 时间 `'yyyy-MM-dd HH:mm:ss'`（`Database.cs:241` 用 `DateTime.UtcNow`，是全库唯一的 UTC 存储点；且 upsert 改密码时会**被改写为当前时间**，不是原始创建时间）。

### `blacklist_audit`（保留策略：**永不清除**）

| 字段 | 含义 |
|---|---|
| `id` | AUTOINCREMENT 流水号；排序并列时的第二排序键（`ORDER BY created_at DESC, id DESC`） |
| `action` | `'ban'` 或 `'unban'`（无 CHECK 约束，纯约定） |
| `as_type` | 粒度，目前**恒为** `'username'`（注释预留 `clientid`/`peerhost`） |
| `who` | 呼号（`ban` 端点仅 `.Trim()`，未统一大小写；见第 8 节） |
| `reason` | 拉黑原因；`unban` 时为 NULL |
| `until` | 到期**本地**时间 `'yyyy-MM-dd HH:mm:ss'`；**NULL = 永久**；`unban` 行也为 NULL |
| `operator` | 操作者：管理员用户名（`ctx.User.Identity?.Name ?? "?"`）、或系统值 `'身份控制'`、`'auto-uid-dup'` |
| `created_at` | 操作时间**本地** `'yyyy-MM-dd HH:mm:ss'`（调用方传 `DateTime.Now`） |

### `audit_packets` —— 包头审计异常事件（保留 30 天）

| 字段 | 类型 | 含义 / 单位 |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | 查询排序键（`ORDER BY id DESC`），也是清理时的 `rowid` |
| `ts` | TEXT NOT NULL | **接收时间（本地）`'yyyy-MM-dd HH:mm:ss.SSS'`**，全库唯一带毫秒的时间戳 |
| `topic` | TEXT NOT NULL | 事件来源主题 |
| `clientid` | TEXT NOT NULL | 发包方 clientid |
| `conn_callsign` | TEXT NULL | **连接身份**呼号（`client_attrs.callsign`，原样） |
| `conn_uid` | TEXT NULL | **连接身份** UID（原样） |
| `pkt_callsign` | TEXT NULL | **包头声明**呼号：解析值 `Trim().ToUpperInvariant()` |
| `pkt_uid` | TEXT NULL | **包头声明** UID：`uint32` 转十进制字符串 |
| `verdict` | TEXT NOT NULL | `KICK` / `WARN` / `FAIL`（`PASS` 不落库） |
| `len` | INTEGER NULL | 包总长**字节**；FAIL 时记 `raw.Length`（可能是 <72 或 >1400） |
| `frame_num` | INTEGER NULL | 包头 `uint16` 帧号（原值） |
| `crc_ok` | INTEGER NULL | 0/1：`CRC32(raw[64:]) == checkSum`（**仅参考展示，不据此判 FAIL**） |
| `smeter` | INTEGER NULL | 包头 `smeter` 原始**单字节**（0–255，信号强度表） |
| `srv_uid` | TEXT NULL | 包头 `srvUID` uint32 十进制字符串 |
| `pkt_ts` | TEXT NULL | **包内 `timestamp` uint32 原值字符串 —— Unix 秒（不是毫秒）**，设备侧时间，与 `ts` 无关 |
| `stream_begin` | TEXT NULL | **包内 `streamBeginUTC` uint32 原值字符串 —— Unix 秒（UTC）** |
| `ban` | INTEGER NOT NULL DEFAULT 0 | 0/1：该事件是否**成功触发自动拉黑**（只有 KICK 且 EMQX 调用成功才为 1） |

### 证据：单位与时间来源

- 增量与差分：`CollectorService.cs:148-163`（`Delta(prev.SendOct, c.SendOct, ...)` 等），`CollectorService.cs:324-335`（`Delta`：`d < 0` → `reconnect = true; return 0`）。
- 本地时间落库：`CollectorService.cs:113-114`（`var now = DateTime.Now; // 服务器本地时间存储（管理员查询/对照投诉时间直观）`）。
- 唯一 UTC 写入：`Database.cs:241`（`DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")`）。
- KiB/s：`HostHealthCollector.cs:148`（`Math.Max(0, drx / 1024.0 / secs)`）、`HostHealthCollector.cs:185-186`（Windows `rx / 1024.0`）。
- load1 冒充 CPU：`CollectorService.cs:216`（`EmqxCpuPct = node?.Load1, // EMQX 5.x 无 CPU%，用系统 1 分钟负载（load1）代替`）。
- 消息速率：`CollectorService.cs:189-201`（`msgRate = (total - lt) / secs`，`secs` 用 `DateTime.UtcNow`）。
- 毫秒时间戳：`TopicEndpoints.cs:222`（`var ts = now.ToString("yyyy-MM-dd HH:mm:ss.fff");`）。
- 包内 Unix 秒：`FmoRawParser.cs:53-54`（`streamBegin`/`timestamp` 均为 `ReadUInt32LittleEndian`），`TopicEndpoints.cs:301-302`（`.ToString()` 存原文）。
- smeter 单字节：`FmoRawParser.cs:58`（`var smeter = raw[40];`）。

> 无外键约束（全库 0 个 `FOREIGN KEY`）、无 `CHECK` 约束（除 `admin_user.id = 1`）、无唯一约束（除各表 PRIMARY KEY）、无触发器、无视图、无生成列。

---

## 3. `settings` 表键名全清单

### 结论

共 **12 个键**，全部经 `AppSettings` 强类型访问（`AppSettings.cs`），值统一存字符串：布尔用 `"1"`/`"0"`，字符串直接存。**默认值语义有两套**：getter 里 `?? 默认` / `== "1"` / `!= "0"`——即"缺失"与"显式写入空串"行为不同。**没有任何键存 NULL**（`value NOT NULL`）。

### 全清单表（键 / 默认值 / 类型语义 / 写入时机 / 证据行）

| 键名 | 缺省（未设置）时的行为 | 值域 | 写入时机 | 证据 |
|---|---|---|---|---|
| `emqx_url` | `""` | EMQX base URL（保存时 `Trim().TrimEnd('/')`） | 网页 `POST /api/config` 保存连接；CLI `--configure`；`POST /api/config/disconnect` 清空为 `""` | `AppSettings.cs:16`；`Program.cs:302,313`；`CliConfigure.cs:49` |
| `emqx_api_key` | `""` | API Key 明文 | 同上三条路径 | `AppSettings.cs:17`；`Program.cs:303,314` |
| `emqx_api_secret` | `""` | API Secret **明文** | 同上三条路径 | `AppSettings.cs:18`；`Program.cs:304,315` |
| `identity_control` | **`true`（启用）**：`GetSetting("identity_control") != "0"` → 缺失/空串都等于启用 | `"1"`/`"0"` | `POST /api/identity-control`（网页开关）；启动时读入 `topicIngest.IdentityControlEnabled` | `AppSettings.cs:22-26`；`Program.cs:80`；`BlacklistEndpoints.cs:95-100` |
| `trust_proxy` | **`false`**：`== "1"` 才为真 | `"1"`/`"0"` | 无任何端点写入！**只能手工写库**；另一条等效路径是环境变量 `EMQX_MONITOR_TRUST_PROXY=1` | `AppSettings.cs:28-32`；`Program.cs:216-218` |
| `wizard_done` | **`false`**：`== "1"` 才为真 | `"1"`/`"0"` | **仅** `POST /api/config` 在 EMQX 连接验证成功后置 `"1"`；CLI `--configure` **不写**（保持 false） | `AppSettings.cs:34-38`；`Program.cs:305` |
| `ingest_token` | **不存在时首次读取即生成**：16 随机字节 → `Convert.ToHexString` = **32 位大写十六进制**，并立即持久化 | 32 位 HEX（大写） | 生成：`AppSettings.IngestToken` getter 首次访问（`/api/topic-config`、启用主题统计、CLI `--configure`）；**无轮换端点**（要换 token 只能删库/手工改） | `AppSettings.cs:40-53`；`TopicEndpoints.cs:16,81,95`；`CliConfigure.cs:60` |
| `topic_enabled` | **`false`**：`== "1"` 才为真 | `"1"`/`"0"` | `POST /api/topic-config` enable=true → `"1"`（**无论 EMQX 侧配置是否完整，只要调用成功就置 1**）；disable → `"0"`；CLI `--configure` → `"1"` | `AppSettings.cs:56-60`；`TopicEndpoints.cs:99,131`；`CliConfigure.cs:74` |
| `topic_name` | **`"FMO/RAW"`** | MQTT 主题 | `POST /api/topic-config`（空值回退 `"FMO/RAW"`）；CLI `--configure` 硬编码 `"FMO/RAW"` | `AppSettings.cs:62`；`TopicEndpoints.cs:89,100`；`CliConfigure.cs:61,75` |
| `topic_webhook_url` | `""` | webhook URL（保存时 `TrimEnd('/')`） | 同上；默认值 `http://{本机出口IP}:{port}/api/ingest` | `AppSettings.cs:63`；`TopicEndpoints.cs:94,101` |
| `topic_pending` | **NULL**（未设置）/ `""`（被显式清空） | 待确认步骤的文本报告（集群场景） | 启用时写入配置报告；`/api/topic-test` 或最终状态 `Ok` 时置 `""`（setter 把 null 转 `""`）；停用时置 `""` | `AppSettings.cs:64`；`TopicEndpoints.cs:102,106,132,146`；`CliConfigure.cs:77,84` |
| `topic_failed` | 同 `topic_pending` | 失败步骤报告文本 | 同上 | `AppSettings.cs:65`；`TopicEndpoints.cs:103,106,133`；`CliConfigure.cs:78,85` |

### 关键语义与坑

- **读取方式**：`GetSetting` 用 `SELECT value FROM settings WHERE key = $k`，无行则返回 **null**（`Database.cs:183-193`）；写入用 upsert（`Database.cs:195-209`）：
  ```sql
  INSERT INTO settings (key, value) VALUES ($k, $v)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value
  ```
- `TopicPending`/`TopicFailed` 的 **setter 会把 null 写成 `""`**（`value ?? ""`），所以库里出现的是空串而非 NULL。
- `identity_control` 是"默认最高保护"：**任何非 `"0"` 值（含空串、`"true"`、乱码）= 启用**。Python 重写必须逐字复制这个 `!= "0"` 判定，不要用 `== "1"`。
- `trust_proxy` 影响登录锁定的维度：关闭时用 TCP 对端 IP（伪造 `X-Forwarded-For` 无法绕过锁定）；开启时信任 `X-Forwarded-For` 的**第一段**（`Program.cs:211-226`）。
- 密钥（`emqx_api_secret`、`ingest_token`）在库中**明文**，依赖文件系统权限保护。

### 证据：`AppSettings.cs:9-66`（全文即键清单）

```csharp
public class AppSettings
{
    private readonly Database _db;
    public AppSettings(Database db) => _db = db;

    public string EmqxUrl { get => _db.GetSetting("emqx_url") ?? ""; set => _db.SetSetting("emqx_url", value); }
    public string EmqxApiKey { get => _db.GetSetting("emqx_api_key") ?? ""; set => _db.SetSetting("emqx_api_key", value); }
    public string EmqxApiSecret { get => _db.GetSetting("emqx_api_secret") ?? ""; set => _db.SetSetting("emqx_api_secret", value); }

    /// <summary>身份控制开关（默认启用 = 最高保护）</summary>
    public bool IdentityControlEnabled
    {
        get => _db.GetSetting("identity_control") != "0";
        set => _db.SetSetting("identity_control", value ? "1" : "0");
    }
    ...
```

---

## 4. 管理员账号与会话

### 结论

- **密码哈希**：PBKDF2-HMAC-**SHA256**，迭代 **100 000**，盐 **16 字节**（`RandomNumberGenerator.GetBytes`），派生密钥 **32 字节**，存储格式 `"{iterations}.{salt_base64}.{hash_base64}"`（标准 Base64，非 URL-safe）；校验用 `FixedTimeEquals` 常数时间比较，**逐次从存储串解析迭代数与盐**（所以迭代数可平滑升级）。
- **管理员只有 1 个**：`admin_user.id = 1` 唯一行，改密码即 upsert 覆盖；用户名 3+ 字符、密码 8+ 字符。
- **登录锁定是纯内存实现（不落库，重启即清零）**：
  - 单键维度 = **`"{username}|{ip}"` 组合**（同用户名 + 同 IP），连续失败 **5 次**→ 锁 **5 分钟**；锁定期间返回"已锁定至 HH:mm:ss"；
  - 全局兜底维度 = **全站**：**1 分钟滑窗内累计 60 次失败** → 全局锁 **60 秒**（防伪造 XFF 绕过）；
  - 字典容量上限 **10 000**，超限惰性清理，仍超限则**整表清空**；
  - 登录成功即删除该键计数；`ChangePassword` 先走一次完整 `Login`（失败计入锁定）。
- **会话 = ASP.NET Core Cookie 认证票据**（非服务器端 session）：Cookie 名取框架默认 **`.AspNetCore.Cookies`**；有效期 **24 小时**、**`SlidingExpiration = false`**（绝对过期，不续期）；`HttpOnly = true`；`Secure` 策略 = `SameAsRequest`（**HTTPS 请求才带 Secure，HTTP 直连不带**）；`SameSite` 未显式设置 → **Lax**；`LoginPath = /login.html`；载荷由 **ASP.NET Core Data Protection 加密+认证**（默认 AES-256-CBC + HMAC-SHA256，密钥环存用户 profile），**只含一个名为 `ClaimTypes.Name` 的声明（用户名）**。

### 证据：`AuthService.cs:9-27`（算法参数与锁定策略）

```csharp
public class AuthService
{
    private const int Iterations = 100_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    // 锁定策略：按 (用户名+IP) 组合 5 次失败锁 5 分钟；另有全局限流兜底（防 XFF 伪造绕过）
    private const int MaxFailPerKey = 5;
    private static readonly TimeSpan LockDuration = TimeSpan.FromMinutes(5);
    // 全局限流：1 分钟窗口内全站最多 60 次登录失败，超限全局锁 60 秒（不依赖 IP 可信性）
    private const int GlobalFailMax = 60;
    private static readonly TimeSpan GlobalWindow = TimeSpan.FromMinutes(1);
    // 锁定字典容量上限（防内存膨胀）
    private const int MaxAttemptEntries = 10_000;
```

### 证据：`AuthService.cs:128-153`（哈希与校验）

```csharp
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string stored)
    {
        try
        {
            var parts = stored.Split('.');
            if (parts.Length != 3) return false;
            var iterations = int.Parse(parts[0]);
            var salt = Convert.FromBase64String(parts[1]);
            var expected = Convert.FromBase64String(parts[2]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch { return false; }
    }
```

### 证据：`AuthService.cs:47-95`（登录流程与两套锁定）

```csharp
    public string? Login(string username, string password, string ip)
    {
        lock (_lock)
        {
            TrimExpired();   // 惰性清理过期条目，防字典膨胀
            var key = $"{username}|{ip}";   // IP+用户名双键：伪造 XFF 无法锁死他人

            // 全局限流检查（不依赖 IP，防 XFF 伪造绕过锁定）
            var now = DateTime.UtcNow;
            if (now - _global.WindowStart > GlobalWindow)
                _global = (0, now, null);   // 窗口重置
            if (_global.LockedUntil is { } glUntil && glUntil > now)
                return $"尝试过于频繁，请稍后再试（全局限流）";
            if (_global.Count >= GlobalFailMax)
            {
                _global.LockedUntil = now.AddSeconds(60);
                return "尝试过于频繁，已临时限流 60 秒";
            }

            // 单键锁定检查
            if (_attempts.TryGetValue(key, out var a) && a.LockedUntil is { } until)
            {
                if (until > DateTime.UtcNow)
                    return $"尝试次数过多，已锁定至 {until.ToLocalTime():HH:mm:ss}，请稍后再试";
                _attempts.Remove(key);   // 锁定过期，清掉重来
            }

            var admin = _db.GetAdmin();
            if (admin == null) return "系统未初始化";
            if (admin.Value.Username != username || !VerifyPassword(password, admin.Value.PasswordHash))
            {
                var (cnt, _) = _attempts.TryGetValue(key, out var cur) ? cur : (0, null);
                cnt++;
                if (cnt >= MaxFailPerKey)
                {
                    _attempts[key] = (0, DateTime.UtcNow.Add(LockDuration));
                    _global.Count++;
                    return $"连续失败 {MaxFailPerKey} 次，账号锁定 5 分钟";
                }
                _attempts[key] = (cnt, null);
                _global.Count++;
                return $"用户名或密码错误（剩余 {MaxFailPerKey - cnt} 次机会）";
            }

            _attempts.Remove(key);
            return null;
        }
    }
```

行为细节（重写必须一致）：
- 第 5 次失败时把计数**重置为 0** 并存 `LockedUntil`；锁定过期后条目被删除 → 再失败从 1 重新计。
- 错误消息包含**剩余次数**（`5 - cnt`）与**锁定到几点**（`until.ToLocalTime():HH:mm:ss`）——前端文案依赖它。
- 计数在**锁定与未锁定两条分支都** `_global.Count++`（包括最后一次触发锁定的失败）。
- 全局窗口按"首次失败时间"起算的**固定窗口**（非滑动），窗口过期时同时清掉 `LockedUntil`（意味着全局锁最长受窗口边界约束）。
- 时钟源：锁定用 **UTC**（`DateTime.UtcNow`），单键锁定提示显示本地时间。

### 证据：`AuthService.cs:98-112`（重置与改密）

```csharp
    public void ResetFailures(string username, string ip)
    {
        lock (_lock) _attempts.Remove($"{username}|{ip}");
    }

    public string? ChangePassword(string currentUser, string oldPassword, string newPassword, string ip)
    {
        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 8) return "新密码至少 8 个字符";
        var loginErr = Login(currentUser, oldPassword, ip);
        if (loginErr != null) return loginErr;
        _db.CreateAdmin(currentUser, HashPassword(newPassword));
        ResetFailures(currentUser, ip);
        return null;
    }
```

### 证据：`Program.cs:111-123`（Cookie 参数）

```csharp
// Cookie 认证：24h 会话，HttpOnly + Secure（HTTPS 反代下防明文嗅探；HTTP 直连仍可用）
// 注：SameSite 用默认 Lax——实测 Strict 会导致登录 Cookie 不下发（框架兼容问题），
// 且 Lax + X-Frame-Options: DENY 已挡住跨站 POST 与点击劫持
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/login.html";
        o.ExpireTimeSpan = TimeSpan.FromHours(24);
        o.SlidingExpiration = false;
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });
```

### 证据：`Program.cs:244-278`（登录/登出/改密端点）与 `Program.cs:139-201`（门控）

```csharp
app.MapPost("/api/login", async (LoginRequest req, HttpContext ctx) =>
{
    ...
    var err = auth.Login(req.Username, req.Password, ClientIp(ctx));
    if (err != null) return Results.Json(new { ok = false, error = err });

    var claims = new[] { new Claim(ClaimTypes.Name, req.Username.Trim()) };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
    auth.ResetFailures(req.Username.Trim(), ClientIp(ctx));
    return Results.Json(new { ok = true });
});

app.MapPost("/api/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Json(new { ok = true });
});
```

未初始化 → 非 `/api/*` 重定向 `/setup.html`，`/api/*` 返回 401；未登录 → 重定向 `/login.html`，`/api/*` 401。静态资源（`.css`/`.js`/`/favicon.ico`）与 `/api/ingest` **免认证**（`Program.cs:146-158`）。`/api/ingest` 靠 `X-Ingest-Token` 头 + `FixedTimeEquals` 常数时间校验（`TopicEndpoints.cs:16-21`）。

> 注：`admin_user.created_at` 存 UTC（`Database.cs:241`），而登录锁定用的是进程内 UTC 时钟，两者不同源，事件排序不要依赖它们比较。

---

## 5. 数据保留与清理

### 结论

- **保留 30 天**（`Database.Retention = TimeSpan.FromDays(30)`），**只清理 4 张表**：`minute_stats`、`health_snapshots`、`topic_stats`、`audit_packets`。
- **永不清理**：`settings`、`admin_user`、`blacklist_audit`（README `:93` 明确"配置、管理员、黑名单留痕不清理"；`CleanupExpired` 的表清单里确实没有这三张）。
- **触发时机**：不是独立定时器，而是**挂在采集循环内部**——采集服务 60 秒一个 tick，`CollectAsync()` 成功走到健康快照之后，判断 `now - _lastCleanupAt > 10 分钟` 才执行一次。**若 `GetClientsAsync` 返回错误，函数在 `CollectorService.cs:119-125` 提前 return，本轮清理被跳过**；`IsConfigured=false` 时整个 tick 也跳过。
- **清理语句**：`rowid` 子查询分批删除，每批 **20 000 行**，每表最多 **200 批**（即单次清理每表上限 400 万行）。注释解释了为什么不能用 `DELETE ... LIMIT`：SQLite 默认不支持该语法。
- **连接参数**：`journal_mode=WAL`（持久）、`synchronous=NORMAL`、`busy_timeout=5000`，但只在 `Init()` 连接上设置（见第 1 节）。

### 证据：`Database.cs:19`（保留期）

```csharp
    /// <summary>数据保留时长（30 天）</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromDays(30);
```

### 证据：`Database.cs:974-997`（清理实现，原文照抄）

```csharp
    /// <summary>删除 30 天前的增量与健康数据（分批删除，避免长事务锁库）</summary>
    public void CleanupExpired(DateTime now)
    {
        var cutoff = now.Add(-Retention).ToString("yyyy-MM-dd HH:mm:00");
        lock (_lock)
        {
            using var conn = Open();
            foreach (var table in new[] { "minute_stats", "health_snapshots", "topic_stats", "audit_packets" })
            {
                // 分批删：每批 20000 行，直到删不动
                // 注意：SQLite 默认不支持 DELETE ... LIMIT（语法错误），必须用 rowid 子查询分批
                for (var i = 0; i < 200; i++)
                {
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = $"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE ts < $cutoff LIMIT 20000)";
                    cmd.Parameters.AddWithValue("$cutoff", cutoff);
                    var affected = cmd.ExecuteNonQuery();
                    if (affected == 0) break;
                }
            }
        }
    }
```

### 证据：`CollectorService.cs:223-228`（10 分钟节流触发）

```csharp
            // ---- 3) 过期清理（每 10 分钟）----
            if (now - _lastCleanupAt > TimeSpan.FromMinutes(10))
            {
                _db.CleanupExpired(now);
                _lastCleanupAt = now;
            }
```
`_lastCleanupAt` 初值 `DateTime.MinValue`（`CollectorService.cs:32`）→ **首次成功采集必做一次全量清理**。定时器间隔：`new PeriodicTimer(TimeSpan.FromSeconds(60))`（`CollectorService.cs:79`）。

### 附：手动数据管理（`Database.cs:928-972`，`Program.cs:424-456`）

- `CountRows()` → `SELECT COUNT(*)` 分别统计 `minute_stats/topic_stats/health_snapshots/audit_packets`。
- `ClearAllData()` → `DELETE FROM` 上述 4 张表（保留 settings/admin_user；**注意它也不删 `blacklist_audit`**），对应 `POST /api/admin/clear-data`。
- `ClearAll()` → `DELETE FROM` **6 张表**：`minute_stats, topic_stats, health_snapshots, settings, admin_user, blacklist_audit`，对应 `POST /api/admin/reset`（会先删 EMQX 规则、清内存凭据与聚合缓冲）。
  - ⚠️ **源码不一致（重写需决策）**：`ClearAll()` 的清单里**漏了 `audit_packets`**，即"完全重置"后 KICK/WARN/FAIL 事件仍在库里，而 `/api/admin/stats` 仍会显示它有数据。Python 重写建议显式包含 `audit_packets`，或在迁移说明中记录该差异。

### 证据：`README.md:15,23,93`

```markdown
- **主题统计**：FMO/RAW 发包时间轴（10 秒粒度，可切 1 分钟/5 分钟/1 小时），每桶 Top 呼号——配合投诉时间点反查干扰源
技术特性：单文件自包含二进制（内置 .NET 运行时 + SQLite），零依赖；主题统计 10 秒 / 呼号统计 1 分钟精度，保留 30 天自动清理；支持 EMQX 5.1+，不支持 6.x 商业版本
- 统计与审计数据保留 30 天自动清理；配置、管理员、黑名单留痕不清理
```

---

## 6. 统计口径

### 6.1 排行榜聚合维度

**结论**：按 **`COALESCE(username, clientid)`** 聚合——即**优先呼号**（`client_attrs.callsign`，退回 MQTT `username`），无身份客户端**回退用 clientid 当名字**，并用 `has_username` 标记该行是否匿名。

```sql
SELECT COALESCE(username, clientid) AS name,
       MIN(uid)              AS uid,
       SUM(send_oct + recv_oct) AS total_oct,
       SUM(send_msg + recv_msg) AS total_msg,
       SUM(send_pkt + recv_pkt) AS total_pkt,
       COUNT(DISTINCT clientid) AS device_count,
       SUM(reconnect)           AS reconnect_count,
       MAX(CASE WHEN username IS NOT NULL THEN 1 ELSE 0 END) AS has_username
FROM minute_stats
WHERE ts BETWEEN $from AND $to
GROUP BY name
ORDER BY {orderCol} DESC
LIMIT $limit
```

- **证据**：`Database.cs:349-363`（`QueryLeaderboard`），`orderCol` 白名单映射在 `Database.cs:339-344`：`"msg"→total_msg`、`"pkt"→total_pkt`、其它→`total_oct`（默认按字节）。
- `IsAnonymous = has_username == 0`（`Database.cs:380`）。`uid` 取 `MIN(uid)` ⇒ 同呼号多 UID 时**只保留字典序最小编号**（有损）。
- 上限：API 把 `limit` 夹到 `1..1000`（`Program.cs:325`）；CSV 导出固定 5000（`Program.cs:353`）。
- 时间范围：`WebHelpers.ParseRange` 要求入参 `yyyy-MM-ddTHH:mm`（本地时间），跨度 **≤31 天**，然后格式化为 `'yyyy-MM-dd HH:mm:00'` 做 TEXT 比较（`WebHelpers.cs:9-17`）。
- **主题排行榜**同一套路，但多一层主题前缀匹配：`topic = $topic OR topic LIKE $topic || '/%'`（`Database.cs:546,584,637,665`），`order`：`"bytes"→total_bytes`，否则 `total_msg`（`Database.cs:532`）。
- 明细接口 `QueryClientDetail` 按 `COALESCE(username, clientid) = $name` 拉每个 clientid 的分钟序列（`Database.cs:394-402`）。

### 6.2 `topic_stats` 分桶粒度与降采样（**全部查询时聚合，无预聚合**）

**结论**：**落库粒度固定 10 秒**（`TopicIngestService.Ingest` 把秒向下取整到 10 的倍数）。1 分钟 / 5 分钟 / 1 小时**不是**预聚合表，而是**每次查询用 SQL 字符串函数把 `ts` 截断成桶键**后 `GROUP BY`——库里始终只有 10 秒行。

| bucket 参数 | SQL 桶表达式 | 说明 |
|---|---|---|
| `10s` | `ts` | 原始 10 秒行 |
| `1m` | `substr(ts,1,16) \|\| ':00'` | 截到分钟（`'yyyy-MM-dd HH:mm'` 拼 `:00`） |
| `5m` | `substr(ts,1,14) \|\| printf('%02d', CAST(substr(ts,15,2) AS INTEGER)/5*5) \|\| ':00'` | 分钟字段整数除 5 再乘 5（**整形截断**，非四舍五入） |
| `1h` | `substr(ts,1,13) \|\| ':00:00'` | 截到小时 |

- **证据**：`Database.cs:613-621`（`bucketExpr` 定义），`Database.cs:630-640`（每桶 `SUM(msg_count)`、`SUM(bytes)`、`COUNT(DISTINCT COALESCE(username, clientid))`），`Database.cs:653-669`（**每桶 Top8 呼号**用 `ROW_NUMBER() OVER (PARTITION BY bucketExpr ORDER BY SUM(msg_count) DESC, COALESCE(username, clientid))` 在 SQL 层截断），`Database.cs:683-717`（C# 内存补零）。
- **补零（诚实时间轴）**：查询后在 C# 里按桶步长遍历 `[start, toDt]`，无数据的桶填 `0`/空 TopUsers（`Database.cs:470-480` 亦然——健康查询缺档填 `Ts` 非空的空行）。桶起点对齐：`5m` 对齐 5 的倍数分钟、`1h` 对齐整点、`10s` 对齐 10 秒（`Database.cs:694-701`）。
- **保护**：补零后行数 > **40 000** 直接报错，要求缩小范围或换粗粒度（`TopicEndpoints.cs:190-193`）。
- `bucket` 参数白名单：仅接受 `"10s" | "5m" | "1h"`，其余（含非法值）回退 `"1m"`（`TopicEndpoints.cs:190`）；但 `Database.QueryTopicTimeline` 的 `switch` 默认分支也是 `ts`（`10s`）——两层默认值不同，值得注意。

**重连标记判定**：仅由**客户端累计计数器差分变负**得出，`Delta()`：

```csharp
    private static long Delta(long prev, long cur, out bool reconnect)
    {
        var d = cur - prev;
        if (d < 0)
        {
            reconnect = true;
            return 0;
        }
        reconnect = false;
        return d;
    }
```
- **证据**：`CollectorService.cs:324-335`；调用点 `CollectorService.cs:159`（`SendPkt = Delta(prev.SendPkt, c.SendPkt, out var rc)`）——**只有 `send_pkt` 参与重连判定**，其余 5 个计数器虽然也算 `out _` 但**丢弃**了标记（它们同样会被 clamp 到 0）。
- 语义：MQTT `send_pkt` 在同一 clientid 重连后从 0 重新累计 → 差分为负 = 该 clientid 发生过重连（clean_start 重连）；`reconnect` 只写 1 到**发生归零的那一分钟**，该分钟 `send_pkt` 记 0（避免负值入库，也**丢失了负值绝对值**）。

**"在线不足 1 分钟为何不记录"**：`_prev` 是"上一轮累计计数器"基线。**首次出现的 clientid 只写基线、不产出行**：

```csharp
                foreach (var c in result.Clients)
                {
                    var key = c.ClientId;
                    var isNew = !_prev.ContainsKey(key);
                    var prev = isNew ? default : _prev[key];
                    if (!isNew)
                    {
                        rows.Add(new MinuteStatRow { ... });
                    }
                    _prev[key] = (c.SendOct, c.RecvOct, c.SendMsg, c.RecvMsg, c.SendPkt, c.RecvPkt);
                }
```
- **证据**：`CollectorService.cs:141-167`；设计意图见类头注释 `CollectorService.cs:8-11`：
  ```csharp
  /// 增量三坑：
  ///  - 离线客户端从 API 消失，必须在在线时算好 delta 落库
  ///  - 重连后计数器归零 → delta 为负 → clamp 0 + 标记 reconnect
  ///  - 新出现的客户端首分钟不计（避免把历史累计算进第一分钟）
  ```
  即：EMQX 返回的是**自连接起的累计值**，首轮没有可信基线，若直接当增量会把这台设备"连接以来"的全部历史流量灌进第一分钟 → 所以**新 clientid 的第一个采集周期只建立基线，不落库**，实际可统计窗口从"第 2 分钟"起（因此单次在线 <1 分钟（<1 个采集周期）的客户端**完全不会出现在 `minute_stats`**，也就不会进入排行榜）。
- 内存基线防膨胀：当 `_prev.Count > 在线数 * 5` 时，只保留当前在线的 clientid（`CollectorService.cs:169-175`）——离线设备重连会被当"新客户端"重新走首分钟逻辑。
- 采集节拍：`PeriodicTimer(60s)`（`CollectorService.cs:79`），且用 `_collecting` 互锁防止定时循环与手动 `CollectNowAsync()` 并发（`CollectorService.cs:75, 96-107`）。
- 在线列表缓存 `/api/online` 直接读 `collector.LastClients`（60 秒新鲜度，不重复打 EMQX），`updated_at` 是本地时间串（`Program.cs:386-413`）。

### 6.3 uid 重复（克隆/多开）判定与自动拉黑（属于"统计口径"里的身份异常路径）

- 按 `uid` 分组找 `count > 1`（uid 空的不参与）；**连续 3 个采集周期**（≈3 分钟）仍重复才确认（`DupUidConfirmCycles = 3`），避免 EMQX keepalive 窗口内新旧 clientid 短暂并存被误判；中间某轮不再重复即**撤销跟踪**（`CollectorService.cs:27-28, 243-295`）。
- 确认后对组内**所有呼号**（去重、忽略大小写、`callsign ?? username`）逐个 `BanAsync(who, reason, null)` = **永久**，然后 `AddBlacklistEvent("ban","username",who,reason,null,"auto-uid-dup",now)`；reason 形如：
  `身份控制: UID 重复登录（uid={uid} 呼号={a/b} clientid={id1,id2} 持续{rounds}轮）`（`CollectorService.cs:299-318`）。
- 已在本黑名单的呼号跳过（`QueryActiveBlacklist` 做忽略大小写比对，`CollectorService.cs:254, 275, 306`）。

---

## 7. 审计事件模型

### 结论

审计只针对 **`FMO/RAW` 的 MQTT payload 包头**（64 字节定长小端头；明文不加密不签名——"包头是声明，身份真相在连接认证侧 `client_attrs`"）。事件类型 4 种，**只落 3 种**：

| verdict | 触发条件 | 落库字段 | 是否处置 |
|---|---|---|---|
| `PASS` | 包头解析合法 **且** 连接有身份 **且** `pkt_callsign == conn_callsign` **且** `pkt_uid == conn_uid` | **不落库**（仅由 `topic_stats` 聚合体现流量） | 放行 |
| `WARN` | 包头解析合法，但**连接无身份**（`conn_callsign` 与 `conn_uid` 都空）→ 无法比对 | 全字段（含解析出的包内值），`ban=0` | 仅记录（不拉黑） |
| `KICK` | 包头解析合法，连接有身份，但**呼号或 UID 任一不匹配** | 全字段；若自动拉黑成功则 `ban=1` | 身份控制开启且 `conn_callsign` 非空 → **按连接身份呼号永久拉黑 + 踢下线 + 黑名单留痕**；否则仅记录 |
| `FAIL` | 包头非法：包长 <72、>1400(MTU)、或 `head.len != 实际包长`、或 `len < 72` | **只填** `ts/topic/clientid/verdict/len=raw.Length`，其余为 NULL | 仅记录；**60 秒窗口最多 100 条**（防刷库放大），超限丢弃 |

### "谁 / 何时 / 原因"如何留痕

- **何时**：`audit_packets.ts` = webhook **接收时间（本地，毫秒精度）**；`pkt_ts`/`stream_begin` 是**设备侧声明的 Unix 秒**，只作证据不作排序。
- **谁（声明方）**：`pkt_callsign` + `pkt_uid`（包头声明，呼号已 `Trim().ToUpperInvariant()`）。
- **谁（真实方）**：`conn_callsign` + `conn_uid`（连接认证侧 `client_attrs`） + `clientid` + `topic`。
- **原因**：`audit_packets` **没有 reason 列**；原因只体现在"哪两个字段不匹配"。真正的"谁执行的处置 + 原因文本"写在 **`blacklist_audit.reason` + `blacklist_audit.operator`**（自动处置的 operator 是 `'身份控制'` / `'auto-uid-dup'`，人工的是管理员用户名）。两者靠 `who`（呼号）与时间关联，**没有外键**。
- 自动拉黑失败不影响审计落库（try/catch 包住 EMQX 调用与留痕，`TopicEndpoints.cs:259-282`）。

### 证据：`TopicEndpoints.cs:216-310`（核心判定，原文照抄关键段）

```csharp
        var parsed = FmoRawParser.Parse(raw);
        var ts = now.ToString("yyyy-MM-dd HH:mm:ss.fff");

        if (!parsed.Ok)
        {
            // FAIL：非法包（长度/len 不符/超 MTU），降级仅记录，不处置；限流防刷库放大
            if (!topicIngest.FailThrottled())
            {
                try { db.WriteAuditPacket(new AuditPacketRow { Ts = ts, Topic = topic ?? "", ClientId = clientid ?? "", Verdict = "FAIL", Len = raw.Length }); }
                catch (Exception ex) { Console.Error.WriteLine($"[Audit] FAIL 落库失败: {ex.Message}"); }
            }
            return;
        }

        var pktCallsign = parsed.Callsign.Trim().ToUpperInvariant();
        var pktUid = parsed.Uid.ToString();
        var connCs = (connCallsign ?? "").Trim().ToUpperInvariant();
        var connU = connUid ?? "";

        string verdict;
        if (string.IsNullOrEmpty(connCs) && string.IsNullOrEmpty(connU))
        {
            verdict = "WARN";   // 连接无身份（匿名）→ 无法比对，仅记录
        }
        else
        {
            var csOk = !string.IsNullOrEmpty(pktCallsign) && pktCallsign == connCs;
            var uidOk = !string.IsNullOrEmpty(pktUid) && pktUid == connU;
            verdict = csOk && uidOk ? "PASS" : "KICK";
        }

        if (verdict == "PASS") return;   // 放行（topic_stats 已聚合）

        // 异常事件：KICK（可自动拉黑）/ WARN
        var ban = false;
        if (verdict == "KICK" && topicIngest.IdentityControlEnabled && !string.IsNullOrEmpty(connCs))
        {
            var reason = $"身份控制: 包头声明 {pktCallsign}(UID {pktUid}) 与连接身份 {connCs}{(connU.Length > 0 ? $"(UID {connU})" : "")} 不符";
            ...
                var (err, _) = await emqx.BanAsync(connCs, reason, null);
                if (err == null)
                {
                    ban = true;
                    ...
                        db.AddBlacklistEvent("ban", "username", connCs, reason, null, "身份控制", now);
```

### 证据：包头格式与合法性校验（`FmoRawParser.cs:5-16, 38-88`）

```csharp
/// <summary>
/// FMO/RAW 包头解析器（fmo-raw-header-audit 文档）。
/// MQTT payload 前 64 字节为固定包头（小端）：version(2) flags(4) UID(4) callsign[12] streamBeginUTC(4)
/// timestamp(4) len(4) frameNum(2) checkSum(4) smeter(1) srvUID(4) reserved(19)。
/// 合法性校验（对应固件 isValidPacket）：长度 ≥72、head.len == 实际长度、≤1400(MTU)、CRC32(raw[64:]) == checkSum。
/// 包头明文不加密不签名——包头是声明，身份真相在连接认证侧（client_attrs）。
/// </summary>
public static class FmoRawParser
{
    public const int HeadSize = 64;
    public const int MinValidLen = 72;      // 64 包头 + 8 首帧头
    public const int MaxLen = 1400;         // MTU
```
```csharp
        if (len != (uint)raw.Length)
            return new Result { Ok = false, Error = $"len 字段({len})与包长({raw.Length})不符" };
        if (len < MinValidLen)
            return new Result { Ok = false, Error = "len 字段小于 72" };

        // CRC32 只覆盖 offset 64 之后的帧区——设备端已核验 CRC，此处不据此判 FAIL，
        // 仅计算结果供审计展示用（crcOk）
        var crc = Crc32.Compute(raw[HeadSize..]);
        var crcOk = crc == checkSum;
```
字段偏移（小端，均为 `ReadUInt16/32LittleEndian`）：`version u16@0`、`flags u32@2`、`uid u32@6`、`callsign[12]@10`（首个 `\0` 截断、ASCII）、`streamBegin u32@22`、`timestamp u32@26`、`len u32@30`、`frameNum u16@34`、`checkSum u32@36`、`smeter u8@40`、`srvUID u32@41`。

### 证据：FAIL 限流（`TopicIngestService.cs:30-48`）

```csharp
    // FAIL 事件落库限流：60 秒窗口最多 100 条（防攻击者用非法包刷库放大）
    private int _failCount;
    private DateTime _failWindowStart = DateTime.UtcNow;

    public bool FailThrottled()
    {
        lock (_lock)
        {
            if (DateTime.UtcNow - _failWindowStart > TimeSpan.FromSeconds(60))
            {
                _failWindowStart = DateTime.UtcNow;
                _failCount = 0;
            }
            if (_failCount >= 100) return true;
            _failCount++;
            return false;
        }
    }
```

### 审计事件查询（`Database.cs:854-923`，`BlacklistEndpoints.cs:103-110`）

```sql
SELECT ts, topic, clientid, conn_callsign, conn_uid, pkt_callsign, pkt_uid,
       verdict, len, frame_num, crc_ok, smeter, srv_uid, pkt_ts, stream_begin, ban
FROM audit_packets
WHERE ts BETWEEN $from AND $to
  AND verdict = $v          -- 仅当 verdict 非空时拼接（白名单式条件拼接）
ORDER BY id DESC LIMIT $n
```
状态栏计数：`SELECT verdict, COUNT(*) FROM audit_packets WHERE ts BETWEEN $from AND $to GROUP BY verdict`（`Database.cs:910-914`）。`limit` 夹到 `1..1000`（`BlacklistEndpoints.cs:107`）。

### 审计触发的前提条件（容易漏）

- **必须有 payload**：`payload` 缺失（或非字符串类型）→ `raw == null` → **完全不做审计**（`TopicEndpoints.cs:220`：`if (raw == null || raw.Length == 0) return;`）。
- `payload` 不是合法 base64 时 `raw` 保持 null、`bytes` 退化为字符串长度 → **不审计、只统计**（`TopicEndpoints.cs:50-55`）。
- webhook 必须先通过 `X-Ingest-Token` 常数时间校验（`TopicEndpoints.cs:16-21`）与 `application/json` 内容类型检查（`:22-23`）。

---

## 8. 黑名单模型

### 结论

- **数据模型 = 一张追加型流水表 `blacklist_audit`**（无 UPDATE、无 DELETE；每次操作 INSERT 一条）。**没有**"当前黑名单"实体表，也**没有**过期解封定时任务。
- **永久 vs 临时**：`until IS NULL` = 永久；非空 = 到期时间（本地 `'yyyy-MM-dd HH:mm:ss'`）。永久在 EMQX 侧存 `"infinity"`，临时存**带本地偏移的 RFC3339**（如 `2026-03-01T12:00:00+08:00`），由 **EMQX 自己到期自动解除**。
- **"当前生效"是查询时推导**（窗口函数取每个 `who` 最新一条操作，`action='ban'` 且未到期）：
  ```sql
  SELECT who, reason, until, operator, created_at FROM (
      SELECT who, action, reason, until, operator, created_at,
             ROW_NUMBER() OVER (PARTITION BY who ORDER BY created_at DESC, id DESC) AS rn
      FROM blacklist_audit
  ) WHERE rn = 1 AND action = 'ban' AND (until IS NULL OR until > $cutoff)
  ORDER BY created_at DESC
  ```
  - **过期自动解除 = 纯查询过滤**（`until > $cutoff` 是 TEXT 字典序比较，依赖固定零填充格式）。**没有任何后台任务扫描并写"解封"流水**。
  - `$cutoff = now.ToString("yyyy-MM-dd HH:mm:ss")`，`now` 由调用方传 `DateTime.Now`（本地），`BlacklistEndpoints.cs:69`。
- **last-write-wins 语义**：`ban → unban → ban` 序列能正确表达"当前在禁"；`unban` 后再无新操作的呼号不出现。
- **历史留痕**：`QueryBlacklistHistory` 直接 `ORDER BY created_at DESC, id DESC LIMIT n`（默认 200，夹 `1..1000`）返回**全部 ban/unban 流水**，包含 `operator` 与 `reason` —— 这是"谁、何时、原因"的唯一载体。
- **权威执行在 EMQX**，本地只留痕：EMQX API 失败**不写流水**（`BlacklistEndpoints.cs:38-41, 57-61`）；`ALREADY_EXISTS` 视为成功、`NOT_FOUND` 解封视为成功（幂等，`EmqxClient.cs:335, 349`）。
- **三方来源对照**：`/api/blacklist/active` 返回 `local`（本地推导，含操作人/时间/到期）+ `emqx_only`（EMQX 上有、本地无 → 可能是 Dashboard 手工拉黑，前端标"来源: EMQX"）+ `emqx_reachable`（`BlacklistEndpoints.cs:67-81`）。
- 拉黑为 **username（呼号）粒度**：`as` 字段恒为 `"username"`，`as_type` 列也恒为 `"username"`（预留 clientid/peerhost 未实现）。
- 拉黑动作 = ① `POST /api/v5/banned`（拒绝新连接）+ ② 查该 username 在线 clientid → `POST /api/v5/clients/kickout/bulk` 踢下线（**banned 不会自动踢已连接**），返回被踢数 `kicked`（`EmqxClient.cs:330-342`）。拉黑/解封后立即 `CollectNowAsync()` 刷新在线缓存（`BlacklistEndpoints.cs:43, 62`）。
- **`blacklist_audit` 不参与 30 天清理、不设上限** → 长期会增长（尤其 uid-dup 自动拉黑）。

### 证据：`EmqxClient.cs:329-350`（EMQX 侧永久/临时与幂等）

```csharp
    /// <summary>移入黑名单并且断开链接 -- 基于用户名</summary>
    public async Task<(string? Error, int Kicked)> BanAsync(string who, string? reason, string? untilRfc3339)
    {
        // 1) 写入 EMQX banned（拒绝新连接）；ALREADY_EXISTS = 已在黑名单，幂等视为成功
        var body = JsonSerializer.Serialize(new Dictionary<string, object?> { ["as"] = "username", ["who"] = who, ["reason"] = reason, ["until"] = untilRfc3339 ?? "infinity" });
        var resp = await DoRequestAsync(HttpMethod.Post, "/api/v5/banned", body);
        if (!resp.Ok && resp.Error != "ALREADY_EXISTS") return (resp.Error, 0);

        // 2) 查该呼号在线 clientid → 踢下线（banned 不自动踢已连接）
        var clients = await GetClientsByUsernameAsync(who);
        if (clients.Count == 0) return (null, 0);
        var kick = await DoRequestAsync(HttpMethod.Post, "/api/v5/clients/kickout/bulk", JsonSerializer.Serialize(clients));
        return kick.Ok ? (null, clients.Count) : ($"踢下线失败: {kick.Error}", 0);
    }

    /// <summary>移出黑名单 -- 基于用户名</summary>
    public async Task<string?> UnbanAsync(string who)
    {
        var resp = await DoRequestAsync(HttpMethod.Delete, $"/api/v5/banned/username/{Uri.EscapeDataString(who)}");
        if (resp.Ok) return null;
        return resp.Error == "NOT_FOUND" ? null : resp.Error; // 已不在黑名单 = 已解封
    }
```

### 证据：`BlacklistEndpoints.cs:15-45`（拉黑端点：到期时间换算 + 留痕）

```csharp
            // 到期时间：本地 yyyy-MM-ddTHH:mm → RFC3339（含 +08:00 偏移，EMQX 自动转 UTC 存储）
            string? untilRfc = null, untilLocal = null;
            if (!string.IsNullOrWhiteSpace(req.Until))
            {
                if (!DateTime.TryParseExact(req.Until, "yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var until))
                    return Results.Json(new { ok = false, error = "到期时间格式应为 yyyy-MM-ddTHH:mm" });
                if (until <= DateTime.Now)
                    return Results.Json(new { ok = false, error = "到期时间必须晚于当前时间" });
                var offset = TimeZoneInfo.Local.GetUtcOffset(until);
                untilRfc = until.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ssK").Replace("+00:00", $"{(offset >= TimeSpan.Zero ? "+" : "-")}{offset:hh\\:mm}");
                untilLocal = until.ToString("yyyy-MM-dd HH:mm:ss");
            }

            var (err, kicked) = await emqx.BanAsync(who, req.Reason?.Trim() is { Length: > 0 } r ? r : null, untilRfc);
            if (err != null)
                return Results.Json(new { ok = false, error = $"拉黑失败: {err}" });

            db.AddBlacklistEvent("ban", "username", who, req.Reason?.Trim(), untilLocal,
                ctx.User.Identity?.Name ?? "?", DateTime.Now);
```

要点：
- 输入是**本地时间 `yyyy-MM-ddTHH:mm`**（分钟精度），必须晚于当前；转 RFC3339 时**手工拼本地偏移**（用 `.Replace` 把 `+00:00` 换成实际偏移；偏移为 0 时结果仍是 `+00:00`）。
- `untilLocal` 落库存**本地** `'yyyy-MM-dd HH:mm:ss'`；`untilRfc` **不落库**（只发 EMQX）。
- `who` 只 `.Trim()`，**不做大小写归一**（`BlacklistEndpoints.cs:17`）；而 `reason` 为空时存 NULL。
- 人工操作者可能为 `"?"`（理论上已登录，兜底值）。

### 证据：`Database.cs:746-814`（生效推导与历史）

见上文 SQL（`Database.cs:757-764`、`Database.cs:790-795`）。注意 `QueryActiveBlacklist` 的注释明确了设计意图：

```csharp
    /// <summary>
    /// 当前生效黑名单（本地推导）：每个呼号最新一条操作是 ban、未被解封、且未到期。
    /// 纯本地推导 → 排行榜标记不依赖 EMQX 连通性；EMQX 侧 banned 列表才是权威执行。
    /// </summary>
```

### 附：`/api/identity-control`（身份控制总开关）

- `GET /api/identity-control` → `{ ok, enabled }`（读内存 `topicIngest.IdentityControlEnabled`）。
- `POST /api/identity-control` `{ enabled: bool }` → 同时写内存与 `settings.identity_control`（`BlacklistEndpoints.cs:88-100`）。
- 语义：**关闭 = 降级为仅标记提醒**（KICK 仍落 `audit_packets`，但不自动拉黑）。

---

## 9. Python / SQLite 重写注意点

### 9.1 时间单位与格式（最高风险项）

1. **全库业务时间是"无时区的本地时间字符串"**，格式必须**逐字符固定零填充**：
   - 分钟桶 `yyyy-MM-dd HH:mm:00`（`minute_stats.ts`、`health_snapshots.ts`、`settings` 无关）；
   - 10 秒桶 `yyyy-MM-dd HH:mm:ss`（`topic_stats.ts`）；
   - 审计事件 `yyyy-MM-dd HH:mm:ss.SSS`（`audit_packets.ts`，唯一带毫秒）；
   - 黑名单 `yyyy-MM-dd HH:mm:ss`；
   - `admin_user.created_at` 是**例外，UTC**。
   - Python 用 `datetime.now().strftime("%Y-%m-%d %H:%M:%S")` 等价；**绝不要**改成 ISO `T` 分隔、加 `Z`/偏移、或用 `datetime.isoformat()`——所有 `BETWEEN`/`<`/`>` 都是**TEXT 字典序**比较，格式一变（如非零填充、缺秒）即静默错算。
2. **`pkt_ts` / `stream_begin` 是设备侧 Unix 秒（uint32 十进制字符串）**，不是毫秒、不是本地时间、**不参与任何 SQL 过滤**；不要把它们和 `ts` 混在一列语义里，也不要做时区转换。
3. 排序/分页依赖 `id`（自增）而非时间：`audit_packets` 用 `ORDER BY id DESC`；`blacklist_audit` 用 `ORDER BY created_at DESC, id DESC`——**同秒多事件时 `id` 是唯一稳定序**，Python 侧必须保持 `INTEGER PRIMARY KEY AUTOINCREMENT`（用了普通 `INTEGER PRIMARY KEY` 时删除后 rowid 可能被复用，会破坏"最新一条"语义）。
4. `topic_stats` 的 10 秒取整是**向下取整**（`second // 10 * 10`），不是就近；`5m` 桶是**分钟整除 5**（截断，非四舍五入）。照抄即可，但要在 Python 里用整数除法（`//`），别用 `/` 产生浮点。
5. 保留期 cutoff 格式为 `'yyyy-MM-dd HH:mm:00'`，而 `topic_stats.ts` 带秒 → 同一分钟内 `:01`–`:59` 的行会比 cutoff 晚 1 分钟才被清理（无害，但要知道边界不是严格的 30×24h）。

### 9.2 SQLite 连接与并发

1. **PRAGMA 必须每个连接都设**（.NET 版只在 `Init()` 连接上设，靠连接池"碰巧"生效，属于隐性缺陷）：
   ```python
   con = sqlite3.connect(db_path, timeout=5.0, isolation_level=None)
   con.execute("PRAGMA journal_mode=WAL")        # 持久属性，设一次即可，但重复设无害
   con.execute("PRAGMA synchronous=NORMAL")
   con.execute("PRAGMA busy_timeout=5000")
   ```
   注意 Python `sqlite3.connect(timeout=...)` 与 `busy_timeout` 是两套机制，建议显式设 `busy_timeout`。
2. **单写者模型**：原实现用**一个进程级 `lock (_lock)`** 串行化**所有** DB 访问（读也串行）——这是它避免 `SQLITE_BUSY` 的主要手段。Python 迁移建议保持"所有写操作走同一把 `threading.Lock` + 单连接（或每线程连接 + 锁）"，不要引入多写线程。WAL 允许多读单写，但**写-写并发会直接抛 `database is locked`**。
3. **事务与批量**：原实现每批 `BeginTransaction()` + 逐行 `ExecuteNonQuery`。Python 用 `executemany` 提速；显式用 `BEGIN IMMEDIATE` 可在 WAL 下更早拿到写锁，避免"读事务升级为写事务"时出现 `SQLITE_BUSY`（无法用 busy_timeout 重试的经典场景）。
4. **两种写入语义不同，别混**：
   - `minute_stats`：`INSERT OR REPLACE`（按 PK `(clientid, ts)` 整行覆盖，重跑同分钟不双计）；
   - `topic_stats`：`ON CONFLICT(topic, clientid, ts) DO UPDATE SET msg_count = msg_count + excluded.msg_count, bytes = bytes + excluded.bytes`（**累加**）——UPSERT 累加意味着**任何重放/重试都会双计**，Python 若在 webhook 侧加重试必须自己做幂等键。
   - `insert or replace` 会**删除+插入**（rowid 变化、未列出的列回默认值）；本实现所有列都显式列出，所以安全。
5. **清理必须分批且用 rowid 子查询**：`DELETE FROM t WHERE rowid IN (SELECT rowid FROM t WHERE ts < ? LIMIT 20000)`。`DELETE ... LIMIT` 在标准 SQLite 编译下是语法错误。每表最多 200 批。**不要**把 4 张表包在一个大事务里（原实现是每表每批独立事务，靠"删不动就 break"收敛），否则长事务会阻塞采集写入。
6. **`health_snapshots` 的主键是 `ts`（TEXT）**：它是 rowid 表 + 唯一索引，所以 `rowid` 分批删除对它同样有效；但不要在建表时加 `WITHOUT ROWID` —— 那会让清理语句直接失效。
7. **`PRAGMA user_version` 迁移协议**：现值为 **1**。Python 重写应当**先读 `user_version`**：等于 1 视为兼容现有库直接使用；大于 1 必须报错退出（.NET 原版行为是 `throw InvalidOperationException`）；新建库要显式 `PRAGMA user_version = 1`，否则以后无法区分。
8. **没有 `VACUUM`/auto_vacuum**：清理后**文件不会变小**，`page_size`/`freelist` 会保留。长期运行的 Python 版若加 `VACUUM`，注意它需要独占锁且耗时与库大小成正比，务必放到低峰或改为 `PRAGMA incremental_vacuum` + 建库时 `auto_vacuum=INCREMENTAL`。

### 9.3 事务内的业务逻辑（语义一致性）

1. **`TopicIngestService.Flush()` 先清空内存缓冲再写库，写失败只打日志**（`TopicIngestService.cs:85-107`）→ **数据永久丢失**（无重试、无 WAL 于内存）。Python 重写建议"先写库成功再清缓冲"，或至少把失败的批留在缓冲里重试。定时器 **10 秒**；进程退出前再 `Flush()` 一次（`TopicIngestService.cs:123-125`）——Python 需注册 `atexit`/信号处理做同样的 final flush。
2. **清理任务挂在采集成功路径上**：Python 若把清理做成独立定时器会更稳；但要保持"30 天 + 4 张表 + 分批"契约。另注意原实现**清理失败会抛异常并被采集的外层 catch 吞掉**（`CollectorService.cs:235-240`），即 `LastCollectOk=false`，会丢失该轮的健康快照写入之前的状态标记——重写时把清理与采集解耦可避免"清理出错 → 采集状态假故障"。
3. **内存态必须一起移植**（否则口径漂移）：
   - `_prev` 客户端累计计数器基线（含 `> 5×在线数` 的裁剪规则）；
   - `_dupUidTrack` uid 重复的 3 轮确认计数；
   - FAIL 限流窗口（100/60s，固定窗口）；
   - 登录失败计数与锁定（.NET 侧**不持久化、重启清零**；Python 要保持同等语义还是改成持久化，是一个需要显式决策的产品选择——若持久化，需新增表，属于 schema 变更）；
   - `_lastCleanupAt`、`_lastMsgTotal/_lastMsgAt`（消息速率差分基线，用 UTC）。
4. **增量三坑必须逐条保留**：离线客户端消失（必须在线时算 delta）、重连归零（clamp 0 + 标记 `reconnect`，仅 `send_pkt`）、**新 clientid 首轮只建基线不落库**。任何"顺手也把首轮记下来"的改动都会污染排行榜总量。
5. **排行榜没有索引优化**：`GROUP BY COALESCE(username, clientid)` 无法命中 `idx_min_user_ts(username, ts)` → 31 天范围会是全表扫描。Python 版本若在意性能，可考虑**表达式索引** `CREATE INDEX ... ON minute_stats(COALESCE(username, clientid), ts)`（属于 schema 变更，需 `user_version` +1）或增加物化汇总表——**但这会改变契约，需与调用方约定**。
6. **`INSERT OR REPLACE` + 并发读**：WAL 下读不阻塞写，但 `or replace` 的删除+插入会产生更多 WAL 帧；批量 60 秒一次的写入量 = 在线客户端数（`Limit` 默认分页；见 `EmqxClient` 的客户端分页参数），量级可控。
7. **API 层等价约束**：请求体上限 1 MiB（`Program.cs:67-68`）；时间范围 ≤31 天（`WebHelpers.cs:15`）；时间轴补零点数 >40 000 报错（`TopicEndpoints.cs:192-193`）；`limit` 夹取范围各不相同（排行榜 1–1000、审计 1–1000、黑名单历史 1–1000、CSV 固定 5000）；CSV 带 UTF-8 BOM 且做公式注入转义（`WebHelpers.cs:20-25`）。这些都要在 Python 侧照搬，否则前端行为不一致。
8. **鉴权与凭据**：
   - 密码哈希 → `hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)`，输出与校验必须用**标准 Base64 + `"."` 分隔**，并用 `hmac.compare_digest` 常数时间比较；**能直接复用 .NET 写入的既有哈希**（格式自描述，迭代数从串里读）。
   - **Cookie 无法跨运行时互通**：ASP.NET Core Data Protection 票据是加密+签名的私有格式，Python 无法校验也无法签发兼容值。迁移时**所有会话失效、需重新登录**（或改为 Python 自己的签名 cookie/服务端 session 表）。`ingest_token`（`X-Ingest-Token` 头）与 EMQX 规则引擎绑定，**迁移后 token 不变即可继续收数**（token 存在库里，直接复用）。
   - `settings` 里 `emqx_api_secret` 与 `ingest_token` **明文**存储，重写时至少要保证 DB 文件权限（0600）；不要在日志里回显（原版 `/api/topic-config` 会把 `ingest_token` 返回给已登录管理员，属有意设计）。
9. **`GET /api/online` 的时间与缓存语义**：`updated_at` 是采集时间（本地 `yyyy-MM-dd HH:mm:ss`），数据最多旧 60 秒；`username == "undefined"`（Erlang atom）与 `client_attrs.callsign` 优先规则要在 Python 里一致（`Program.cs:398-412`，`TopicEndpoints.cs:31`）。
10. **`emqx_connections` 不是 EMQX 全局连接数**，而是"FMO 客户端在线数"（`CollectorService.cs:218`）——仪表盘文案别写错。
11. **已知源码缺陷清单（重写时决策，不要无意识复制）**：
    - `ClearAll()` 漏删 `audit_packets`（第 5 节）；
    - 清理触发依赖采集成功（第 5 节）；
    - 增量 flush 失败丢数据（9.3.1）；
    - PRAGMA 只在 Init 连接生效（9.2.1）；
    - `reconnect` 只由 `send_pkt` 判定，其它计数器的负差分被静默 clamp（6.2）；
    - `blacklist_audit` 无清理、无容量上限（第 8 节）；
    - `topic_stats` 桶 `bucket` 的两层默认值不一致（6.2）；
    - `untilRfc` 偏移为 0 时仍输出 `+00:00`（第 8 节，EMQX 可解析，无害）。
