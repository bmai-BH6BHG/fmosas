# FAS 审计核心逻辑契约（身份核对与自动处置 → Python 重写用）

来源仓库：`BG5ESN/fmo-audit-service`，本地克隆 `C:\Users\Administrator\AppData\Local\Temp\fas-clone`。

本文件覆盖的核心文件：`FmoRawParser.cs`(116 行)、`TopicEndpoints.cs`(347 行，重点 `/api/ingest` 与
`RunIdentityAuditAsync`)、`CollectorService.cs`(336 行)、`Models.cs`(232 行，`TolerantStringDictConverter`
与身份字段)、`BlacklistEndpoints.cs`(112 行)、`TopicIngestService.cs`(126 行)、`Database.cs`(1158 行，
schema / 落库 / 查询)、`EmqxClient.cs`(696 行，`BanAsync`)、`Program.cs`、`wwwroot/audit.html`、
`wwwroot/app.js`、测试 `fmo-audit-service.Tests/CoreLogicTests.cs` + `ConverterAndWebTests.cs`。

> 行号均为克隆仓库中的行号。
> 一句话总纲：**包头是明文声明，不带签名不加密；身份真相在连接认证侧（`client_attrs`）**。
> 审计做的就是逐包比对「声明身份」与「连接身份」，不一致 = 伪造 → 立即拉黑连接身份。

```
FmoRawParser.cs:10  /// 包头明文不加密不签名——包头是声明，身份真相在连接认证侧（client_attrs）。
```

---

## 0. 端到端数据流（先建立整体坐标）

### 结论

| 阶段 | 触发 | 组件 | 产出 |
|---|---|---|---|
| 消息上云 | 设备 publish 到 `FMO/RAW/#` | EMQX 规则引擎 `fas-auth-rule` | SELECT `clientid, username, topic, base64_encode(payload) as payload, qos, timestamp, client_attrs` |
| 投递 | 规则动作 `webhook:fas-auth-bridge` | EMQX bridge（`max_retries=2`，POST，头 `x-ingest-token`） | HTTP POST `/api/ingest` |
| 接收+审计 | 每个 webhook 请求 | `TopicEndpoints` `/api/ingest` 同步 await | ①`TopicIngestService.Ingest` 内存聚合 → ②`RunIdentityAuditAsync` 逐包判决 |
| 落库 | 每 10 秒 | `TopicIngestService.Flush` | `topic_stats` UPSERT 累加 |
| 处置 | 判决 KICK 且身份控制开 | `EmqxClient.BanAsync` | EMQX `banned` + `kickout/bulk` + `blacklist_audit` |
| 留证 | 判决 KICK/WARN/FAIL | `db.WriteAuditPacket` | `audit_packets` |
| 补充采集 | 每 60 秒 | `CollectorService` | `minute_stats` / `health_snapshots` + uid 重复检测自动拉黑 |

关键时序：**`Ingest` 先于审计执行**，所以被 KICK 的包**照样进 `topic_stats`**（主题统计里能看到攻击者的发包量）。
`PASS` 不写 `audit_packets`——正常情况下库里不该有"正常包"的行。

### 证据

`TopicEndpoints.cs:57-61` — ingest 与审计的调用顺序（先聚合，后判决）

```csharp
if (!string.IsNullOrEmpty(topic) && !string.IsNullOrEmpty(clientid))
{
    ingest.Ingest(topic, username, uid, clientid, bytes, DateTime.Now);
    await RunIdentityAuditAsync(raw, topic, username, uid, clientid, DateTime.Now, topicIngest, db, emqx, collector);
}
```

`EmqxClient.cs:382,429` — 规则 SQL 与 bridge body 模板（决定 `/api/ingest` 收到哪些字段）

```csharp
sql = $"SELECT clientid, username, topic, base64_encode(payload) as payload, qos, timestamp, client_attrs FROM \"{topic}/#\"",
body = "{\"topic\":\"${topic}\",\"username\":\"${username}\",\"clientid\":\"${clientid}\",\"payload\":\"${payload}\",\"qos\":\"${qos}\",\"client_attrs\":${client_attrs}}",
```

`Database.cs:114` + `wwwroot/audit.html:75` — PASS 不落库的语义（前端空表提示原文）

```
verdict       TEXT    NOT NULL,   -- KICK / WARN / FAIL（PASS 不落库，由 topic_stats 聚合）
该时间段内没有异常审计事件（包头身份与连接身份一致 = 正常放行，不记录）
```

---

## 1. FMO/RAW 包头解析（64 字节定长头，小端）

### 1.1 结论：逐字段布局

包头 **固定 64 字节**，全部整数 **小端（little-endian）**，字段偏移累加恰好 = 64。
`reserved` 19 字节解析器**完全忽略**。

| # | 字段 | 偏移 | 长度 | 类型 | 字节序 | 解析语义 / 备注 |
|---|---|---|---|---|---|---|
| 1 | `version` | 0 | 2 | uint16 | 小端 | 协议版本，测试向量/构造器用 `2` |
| 2 | `flags` | 2 | 4 | uint32 | 小端 | 位标志位域；FAS **只读出原值，不做任何解释** |
| 3 | `UID` | 6 | 4 | uint32 | 小端 | 台站用户编号；判决时转**十进制字符串**比较 |
| 4 | `callsign` | 10 | 12 | ASCII 定长 | — | 遇第一个 `0x00` 截断；再 `Trim()`；**不主动大写**（注释称发送侧已大写） |
| 5 | `streamBeginUTC` | 22 | 4 | uint32 | 小端 | 流开始时间（uint32 秒）；落库为字符串原值，不做时间转换 |
| 6 | `timestamp` | 26 | 4 | uint32 | 小端 | 包内时间戳（uint32 秒）；同上，只存字符串 |
| 7 | `len` | 30 | 4 | uint32 | 小端 | **整包总长**（含 64 字节头）。必须等于实际收到字节数，否则非法包 |
| 8 | `frameNum` | 34 | 2 | uint16 | 小端 | 包序号（帧序号） |
| 9 | `checkSum` | 36 | 4 | uint32 | 小端 | 帧区 CRC32 声明值；**只与实算值比对后展示，不据此判非法** |
| 10 | `smeter` | 40 | 1 | uint8 | — | S 表值，原样落库 |
| 11 | `srvUID` | 41 | 4 | uint32 | 小端 | 服务器 UID，落库为字符串 |
| 12 | `reserved` | 45 | 19 | 字节数组 | — | 保留区，**完全未解析**（Python 侧同样忽略即可，但边界必须按 45..64 理解） |
| — | 帧区 | 64 | `len-64` | bytes | — | CRC32 只覆盖这一段；首帧头 8 字节（64..72）也从未被 FAS 解析 |

**关于 "packet type"**：本包头**没有**独立的 packet type 字段，FAS 也**从不解析帧区**。语义上最接近"包类型"的
只有 `version`（协议版本）与 `flags`（位域）。测试与解析器唯一涉及的"序号"是 `frameNum`。
不要凭猜测给 `flags` 赋位含义——源码里没有任何位定义。

**长度约束**：`raw.Length ∈ [72, 1400]`。
- 下界 72 = 64 包头 + 8 首帧头（`MinValidLen`），即**帧区至少 8 字节**；
- 上界 1400 = MTU（`MaxLen`）。

### 1.2 结论：合法性校验（= 固件 `isValidPacket` 的镜像）

按代码顺序（顺序重要，因为 `Error` 文案与短路顺序都进日志/行为）：

| 序 | 条件 | 结果 |
|---|---|---|
| 1 | `raw.Length < 72` | `Ok=false, Error="包长不足 72 字节"` |
| 2 | `raw.Length > 1400` | `Ok=false, Error="超过 MTU 1400"` |
| 3 | `len 字段 != raw.Length` | `Ok=false, Error="len 字段({len})与包长({raw.Length})不符"` |
| 4 | `len 字段 < 72` | `Ok=false, Error="len 字段小于 72"` — **实际不可达**（走得到这里必有 `raw.Length>=72`，而条件 3 已保证 `len==raw.Length`）→ 死代码，但 Python 端口保留同序判断即可 |
| 5 | CRC32(raw[64:]) != checkSum | **`Ok=true`**，仅 `CrcOk=false` — 设计语义：CRC 只覆盖帧区且设备端已核验，服务端不据此判 FAIL |

### 1.3 结论：CRC 算法（**与源码注释矛盾，以测试向量为准**）

- 实现 = **标准 CRC-32 / zlib 语义**：初值 `0xFFFFFFFF`，反射多项式 `0xEDB88320`，最终异或 `0xFFFFFFFF`。
  等价于 Python `zlib.crc32(data) & 0xFFFFFFFF`；等价于 ESP32 `crc32_le`。
- ⚠️ `Crc32` 类的 XML 注释写的是"初值 0，无最终异或"——**注释是错的**，实现与测试向量均为 zlib 标准。
- 输入：**帧区** `raw[64:]`（不含 64 字节包头）。
- 标准向量：`CRC32("123456789") = 0xCBF43926`；`CRC32(空) = 0x00000000`。

### 1.4 证据：原文照抄的解析代码

`FmoRawParser.cs:38-43` — 前置长度校验

```csharp
public static Result Parse(ReadOnlySpan<byte> raw)
{
    if (raw.Length < MinValidLen)
        return new Result { Ok = false, Error = "包长不足 72 字节" };
    if (raw.Length > MaxLen)
        return new Result { Ok = false, Error = "超过 MTU 1400" };
```

`FmoRawParser.cs:45-54` — 字段读取（前半，**小端** + callsign 零截断）

```csharp
var version = BinaryPrimitives.ReadUInt16LittleEndian(raw[0..2]);
var flags = BinaryPrimitives.ReadUInt32LittleEndian(raw[2..6]);
var uid = BinaryPrimitives.ReadUInt32LittleEndian(raw[6..10]);
var callsign = raw[10..22];
// 12 字节定长，按第一个 \0 截断
var csEnd = callsign.IndexOf((byte)0);
if (csEnd < 0) csEnd = callsign.Length;
var cs = System.Text.Encoding.ASCII.GetString(callsign[..csEnd]).Trim();
var streamBegin = BinaryPrimitives.ReadUInt32LittleEndian(raw[22..26]);
var timestamp = BinaryPrimitives.ReadUInt32LittleEndian(raw[26..30]);
```

`FmoRawParser.cs:55-59` — 字段读取（后半，到偏移 45 为止）

```csharp
var len = BinaryPrimitives.ReadUInt32LittleEndian(raw[30..34]);
var frameNum = BinaryPrimitives.ReadUInt16LittleEndian(raw[34..36]);
var checkSum = BinaryPrimitives.ReadUInt32LittleEndian(raw[36..40]);
var smeter = raw[40];
var srvUid = BinaryPrimitives.ReadUInt32LittleEndian(raw[41..45]);
```

`FmoRawParser.cs:61-70` — 合法性校验 + CRC 只标不判

```csharp
if (len != (uint)raw.Length)
    return new Result { Ok = false, Error = $"len 字段({len})与包长({raw.Length})不符" };
if (len < MinValidLen)
    return new Result { Ok = false, Error = "len 字段小于 72" };

// CRC32 只覆盖 offset 64 之后的帧区——设备端已核验 CRC，此处不据此判 FAIL，
// 仅计算结果供审计展示参考（crcOk）
var crc = Crc32.Compute(raw[HeadSize..]);
var crcOk = crc == checkSum;
```

`FmoRawParser.cs:109-115` — CRC32 实现（zlib 语义）

```csharp
public static uint Compute(ReadOnlySpan<byte> data)
{
    var crc = 0xFFFFFFFFu;   // 标准 CRC-32 初值（zlib 语义）
    foreach (var b in data)
        crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;   // 最终异或
}
```

### 1.5 输入字节 → 期望解析结果（向量来自测试文件）

向量构造器就是测试里的 `BuildPacket`（`CoreLogicTests.cs:27-44`），参数：`frame=[1..8]`、`uid=12345`、
`callsign="BG5ESN"`、`version=2`、`flags=0xDEADBEEF`、`streamBegin=1700000000`、`timestamp=1700000100`、
`frameNum=7`、`smeter=9`、`srvUID=999`、`checkSum=CRC32(frame)`、`len=raw.Length`。
下表的十六进制已用 `zlib.crc32` 独立复算确认（与 .NET 实现逐字节一致）。

**向量 V1（合法包，72 字节）**

```
输入 hex（72 字节）：
0200efbeadde3930000042473545534e00000000000000f1536564f15365480000000700c588ca3f09e7030000000000000000000000000000000000000000000102030405060708
```

| 期望字段 | 期望值 | 来源断言 |
|---|---|---|
| `Ok` | `true` | `CoreLogicTests.cs:50` |
| `Version` | `2` | `:57` |
| `Flags` | `0xDEADBEEF` | `:58` |
| `Uid` | `12345` (`0x3039`) | `:51` |
| `Callsign` | `"BG5ESN"`（`42 47 35 45 53 4E 00*6`） | `:52` |
| `StreamBeginUtc` | `1700000000` (`0x6553F100`，LE 字节 `00 f1 53 65`) | `:59` |
| `Timestamp` | `1700000100` (`0x6553F164`，LE 字节 `64 f1 53 65`) | `:60` |
| `Len` | `72` | `:53` |
| `FrameNum` | `7` | `:54` |
| `CheckSum` 字段 | `0x3FCA88C5` | `:39` |
| `CrcOk` | `true`（`CRC32(01..08)=0x3FCA88C5`） | `:61` |
| `Smeter` | `9` | `:56` |
| `SrvUid` | `999` | `:55` |

字段切分（便于逐字节核对）：

```
00-01 0200              version = 2
02-05 efbeadde          flags   = 0xDEADBEEF
06-09 39300000          uid     = 12345
10-21 42473545534e000000000000  callsign = "BG5ESN" + 6×NUL
22-25 00f15365          streamBeginUTC = 1700000000 (0x6553F100)
26-29 64f15365          timestamp      = 1700000100 (0x6553F164)
30-33 48000000          len            = 72
34-35 0700              frameNum       = 7
36-39 c588ca3f          checkSum       = 0x3FCA88C5
40    09                smeter         = 9
41-44 e7030000          srvUID         = 999
45-63 00 ×19            reserved（未解析）
64-71 0102030405060708  帧区（CRC 覆盖范围）
```

**向量 V2（12 字节呼号区零截断，仅呼号不同）**

```
输入 hex（72 字节）：
0200efbeadde3930000042473541414100000000000000f1536564f15365480000000700c588ca3f09e7030000000000000000000000000000000000000000000102030405060708
```

| 期望字段 | 期望值 |
|---|---|
| `Ok` | `true` |
| `Callsign` | `"BG5AAA"`（呼号区 `424735414141000000000000` = `"BG5AAA"` + 6×NUL，按首个 `\0` 截断） |
| 其余字段 | 与 V1 完全相同（`Uid=12345, Len=72, FrameNum=7, CrcOk=true, …`） |

**向量 V3～V5（负向/边界，来自测试）**

| 输入 | 期望 | 断言位置 |
|---|---|---|
| `new byte[71]` | `Ok=false`（"包长不足 72 字节"） | `CoreLogicTests.cs:64-69` |
| `new byte[1401]` | `Ok=false`（"超过 MTU 1400"） | `:71-76` |
| V1 但 `len` 字段改写成 `100` | `Ok=false`，`Error` 含 `"len"` | `:78-84` |
| V1 但 `raw[36] ^= 0xFF`（破坏 checkSum） | **`Ok=true`**，`CrcOk=false` | `:95-104` |
| `CRC32("123456789")` | `0xCBF43926` | `:9-15` |
| `CRC32(空)` | `0` | `:17-21` |

`CoreLogicTests.cs:29-42` — 向量构造器（Python 侧可直接照抄成 fixture）

```csharp
frame ??= [1, 2, 3, 4, 5, 6, 7, 8];
var raw = new byte[64 + frame.Length];
BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(0, 2), 2);                    // version
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(2, 4), 0xDEADBEEF);           // flags
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(6, 4), uid ?? 12345u);         // UID
Encoding.ASCII.GetBytes(callsign).CopyTo(raw.AsSpan(10));                          // callsign[12]
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(22, 4), 1700000000u);          // streamBeginUTC
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(26, 4), 1700000100u);          // timestamp
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(30, 4), lenOverride ?? (uint)raw.Length); // len
BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(34, 2), 7);                    // frameNum
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(36, 4), Crc32.Compute(frame)); // checkSum
raw[40] = 9;                                                                       // smeter
BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(41, 4), 999u);                 // srvUid
```

---

## 2. 身份核对判决表（逐包，`RunIdentityAuditAsync`）

### 2.1 结论：四个变量、先归一化再比较

进入判决前，四个值的**精确**构造方式（这是最容易在重写时走样的地方）：

| 变量 | 来源 | 归一化 |
|---|---|---|
| `connCallsign`（形参） | `/api/ingest` 的 `username`，**已被 `client_attrs.callsign` 覆盖** | 无（原样存入 `conn_callsign` 列） |
| `connUid`（形参） | `/api/ingest` 的 `uid`（仅来自 `client_attrs.uid`） | 无 |
| `connCs`（判决用） | `connCallsign` | `Trim()` + `ToUpperInvariant()` |
| `connU`（判决用） | `connUid` | `?? ""`（**不 Trim、不大写**） |
| `pktCallsign` | 包头 `callsign`（已零截断+Trim） | 再次 `Trim()` + `ToUpperInvariant()` |
| `pktUid` | 包头 `UID` (uint32) | `.ToString()` → **十进制字符串，永不为空**（`uid=0` → `"0"`） |

判决逻辑（原文）：**匿名 → WARN；否则 呼号相符 && uid 相符 → PASS；其余一律 KICK**。

```
TopicEndpoints.cs:240-250
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
```

因为 `pktUid` **恒非空**，`uidOk` 实际退化为 `pktUid == connU`。
因为 `csOk` 要求 `pktCallsign` 非空，**包头呼号为空（全 0/全空白）必然 KICK**。

### 2.2 判决表（完整，无省略）

前置说明：
- "自动拉黑"列的三重门槛 = `verdict==KICK` **且** `topicIngest.IdentityControlEnabled==true` **且** `connCs != ""`；
  拉黑目标是 `connCs`（大写后的连接呼号/username），时长**永久**。
- "踢下线"总是伴随拉黑一起发生（`BanAsync` 内部第 2 步），**不存在只禁连不踢的连接**；
  若 `connCs` 对应的在线 clientid 数为 0，则踢 0 个（`kicked=0`）但仍算成功。
- "落库"指写 `audit_packets`；`PASS` 与"未审计"两类不写该表。

| # | 连接身份（client_attrs / username） | 包头声明 | 内部判定 | 事件 | 自动拉黑 | 踢下线 | `audit_packets` 留痕 |
|---|---|---|---|---|---|---|---|
| **A. 未进入判决（无 raw 或前置门控）** |||||||
| A1 | 任意 | — | `payload` 字段缺失或非 JSON 字符串 → `raw=null` | 无 | 否 | 否 | **不写**（仅 `topic_stats` 计 1 条 msg，bytes=0） |
| A2 | 任意 | — | `payload=""` → base64 解出空数组 → `raw.Length==0` | 无 | 否 | 否 | **不写**（`topic_stats` bytes=0） |
| A3 | 任意 | — | `payload` 非法 base64 → `catch` → `raw` 仍为 `null`，`bytes=字符串长度` | 无 | 否 | 否 | **不写**（`topic_stats` 按字符数计字节） |
| A4 | 任意 | 任意 | `topic` 为空 或 `clientid` 为空 | 无 | 否 | 否 | **不写**，且 `topic_stats` 也不写（整个记账被跳过） |
| **B. 解析失败 → FAIL（降级，只记录不处置）** |||||||
| B1 | 任意 | 包长 <72 | `parsed.Ok=false` | **FAIL** | 否 | 否 | 写 `verdict='FAIL'`，`len=raw.Length`，`conn_*/pkt_*` 全 NULL，`ban=0`；**受 100 条/60 秒限流**，超限连行都不写 |
| B2 | 任意 | 包长 >1400 | 同上 | **FAIL** | 否 | 否 | 同上 |
| B3 | 任意 | `len` 字段 ≠ 实际包长 | 同上 | **FAIL** | 否 | 否 | 同上 |
| B4 | 任意 | `len<72` | 死代码（不可达） | — | — | — | — |
| **C. 匿名连接 → WARN（不处置）** |||||||
| C1 | `client_attrs` 缺失，`username` 缺失 | 任意合法包 | `connCs=="" && connU==""` | **WARN** | 否 | 否 | 写 `verdict='WARN'`，`conn_callsign`/`conn_uid` 为 NULL，`pkt_*` 与包字段完整，`ban=0` |
| C2 | `client_attrs` 缺失，`username=="undefined"`（Erlang atom） | 任意合法包 | 同上（`undefined` 先被归一为 `null`） | **WARN** | 否 | 否 | 同上 |
| C3 | `client_attrs.callsign` 存在但为空串 `""`，`username` 缺失 | 任意合法包 | 同上（空串不覆盖 username） | **WARN** | 否 | 否 | 同上 |
| C4 | `client_attrs={}`（空对象），`username` 缺失 | 任意合法包 | 同上 | **WARN** | 否 | 否 | 同上 |
| **D. 连接身份存在 → 逐组合判决** |||||||
| D1 | callsign=`BG5ESN`，uid=`12345` | callsign=`BG5ESN`，UID=`12345` | `csOk && uidOk` | **PASS** | 否 | 否 | **不写**（仅 `topic_stats`） |
| D2 | callsign=`BG5ESN`，uid=`12345` | callsign=`bg5esn`，UID=`12345` | 双方大写后相等 → 同 D1 | **PASS** | 否 | 否 | **不写** |
| D3 | callsign=`BG5ESN`，uid **缺失**（`client_attrs` 无 uid → `connU=""`） | callsign=`BG5ESN`，UID=`12345` | `csOk=true, uidOk=false` | **KICK** | **是（永久）** | 是（`username=BG5ESN` 全部连接） | 写 `verdict='KICK'`、`ban=1`、`conn_uid=NULL`；另写 `blacklist_audit` 1 行 |
| D4 | callsign=`BG5ESN`，uid=`99999` | callsign=`BG5ESN`，UID=`12345` | `csOk=true, uidOk=false` | **KICK** | **是（永久）** | 是 | 同上 |
| D5 | callsign=`BG5ESN`，uid=`12345` | callsign=`BG5XXX`，UID=`12345` | `csOk=false, uidOk=true`（**仅 uid 相同**） | **KICK** | **是（永久）** | 是 | 同上 |
| D6 | callsign=`BG5ESN`，uid=`12345` | callsign=`BG5XXX`，UID=`99999` | 两者都不符 | **KICK** | **是（永久）** | 是 | 同上 |
| D7 | callsign=`BG5ESN`，uid=`12345` | callsign **为空**（12 字节全 0 或全空白），UID=`12345` | `csOk=false`（`pktCallsign==""`） | **KICK** | **是（永久）** | 是 | 同上（`pkt_callsign=''`） |
| D8 | `client_attrs.callsign` 缺失、`username="bg5esn"`（退回 MQTT username），uid **缺失** | callsign=`BG5ESN`，UID=`12345` | `connCs="BG5ESN"`（判决用大写）、`csOk=true`、`connU=""`→`uidOk=false` | **KICK** | **是（永久）**，`who="BG5ESN"` | 是 | 同上；`conn_callsign` 存的是**原样 username**（`bg5esn`，未大写） |
| D9 | `client_attrs.callsign` 缺失、`username` 缺失，**但 uid 存在** `uid="12345"` | 任意合法包 | `connCs==""`、`connU="12345"` → **不进匿名分支**；`csOk=false` | **KICK** | **否**（拉黑门槛要求 `connCs!=""`） | 否 | 写 `verdict='KICK'`、`ban=0`（UI 显示"仅记录（身份控制关闭或拉黑失败）"） |
| D10 | ✅ D9 但 `client_attrs.uid` 是 **JSON null** | 任意合法包 | ingest 侧 `GetRawText()` → `connU="null"`（字面量）→ 仍非空 → 同上 | **KICK** | **否** | 否 | 同上（注意：**不会**被判成匿名 WARN） |
| D11 | callsign/uid 组合匹配 | 匹配 | 本应 PASS | **PASS** | 否 | 否 | 不写 |
| **E. 处置被开关/故障降级（verdict 仍为 KICK）** |||||||
| E1 | 任意非空 `connCs` | 不匹配 | `IdentityControlEnabled == false` | **KICK** | **否**（开关关闭 = 仅记录） | 否 | `ban=0` |
| E2 | 任意非空 `connCs` | 不匹配 | EMQX 未配置 / URL 异常 / 抛异常（`catch`） | **KICK** | 否 | 否 | `ban=0`，异常写 stderr |
| E3 | 任意非空 `connCs` | 不匹配 | `POST /banned` 失败（非 `ALREADY_EXISTS`，如 401/超时/`BAD_API_KEY_OR_SECRET`） | **KICK** | 否 | 否 | `ban=0`，**不写** `blacklist_audit` |
| E4 | 任意非空 `connCs` | 不匹配 | `/banned` **成功**但 `kickout/bulk` 失败 | **KICK** | **EMQX 侧已拉黑，但本地判定为失败** → `ban=0` | 否 | `ban=0`，**不写** `blacklist_audit`（幽灵拉黑：本地无痕、EMQX 已禁连） |
| E5 | 任意非空 `connCs`，该呼号**已在 EMQX 黑名单** | 不匹配 | `ALREADY_EXISTS` 视为成功 → 继续踢 | **KICK** | 视为"是" | 是（踢当前在线者） | `ban=1`，且**再写一行** `blacklist_audit`（重复留痕，KICK 路径无去重） |

### 2.3 证据

`TopicEndpoints.cs:29-44` — 连接身份的提取与归一（含 `undefined`、callsign 覆盖 username、uid 原始文本）

```csharp
var username = root.TryGetProperty("username", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString() : null;
if (username == "undefined") username = null;   // EMQX 无用户名客户端的 Erlang undefined atom 序列化
string? callsign = null, uid = null;
if (root.TryGetProperty("client_attrs", out var ca) && ca.ValueKind == JsonValueKind.Object)
{
    if (ca.TryGetProperty("callsign", out var cs) && cs.ValueKind == JsonValueKind.String)
        callsign = cs.GetString();
    if (ca.TryGetProperty("uid", out var cu))
        uid = cu.ValueKind == JsonValueKind.String ? cu.GetString() : cu.GetRawText();
}
if (!string.IsNullOrEmpty(callsign)) username = callsign;
```

`TopicEndpoints.cs:220-233` — 无 payload 短路 + FAIL 限流落库

```csharp
if (raw == null || raw.Length == 0) return;   // 无 payload（文本统计模式）不审计
var parsed = FmoRawParser.Parse(raw);
var ts = now.ToString("yyyy-MM-dd HH:mm:ss.fff");

if (!parsed.Ok)
{
    // FAIL：非法包（长度/len 不符/超 MTU），降级仅记录，不处置；限流防刷库放大
    if (!topicIngest.FailThrottled())
    {
        try { db.WriteAuditPacket(new AuditPacketRow { Ts = ts, Topic = topic ?? "", ClientId = clientid ?? "", Verdict = "FAIL", Len = raw.Length }); }
```

`TopicEndpoints.cs:235-252` — 归一化与判决

```csharp
var pktCallsign = parsed.Callsign.Trim().ToUpperInvariant();
var pktUid = parsed.Uid.ToString();
var connCs = (connCallsign ?? "").Trim().ToUpperInvariant();
var connU = connUid ?? "";
...
if (verdict == "PASS") return;   // 放行（topic_stats 已聚合）
```

`TopicEndpoints.cs:255-261` — 拉黑三重门槛与 reason 文案

```csharp
var ban = false;
if (verdict == "KICK" && topicIngest.IdentityControlEnabled && !string.IsNullOrEmpty(connCs))
{
    var reason = $"身份控制: 包头声明 {pktCallsign}(UID {pktUid}) 与连接身份 {connCs}{(connU.Length > 0 ? $"(UID {connU})" : "")} 不符";
    try
    {
        var (err, _) = await emqx.BanAsync(connCs, reason, null);
```

`TopicEndpoints.cs:284-304` — 落库字段（注意 `conn_callsign` 存原样、`pkt_callsign` 存大写）

```csharp
db.WriteAuditPacket(new AuditPacketRow
{
    Ts = ts,
    Topic = topic ?? "",
    ClientId = clientid ?? "",
    ConnCallsign = connCallsign,
    ConnUid = connUid,
    PktCallsign = pktCallsign,
    PktUid = pktUid,
    Verdict = verdict,
    ...
    Ban = ban,
});
```

---

## 3. 自动拉黑的完整动作序列

### 3.1 结论：`BanAsync` = 「写 banned」+「批量踢在线连接」，两步都不可省

| 步 | 动作 | 接口 | 说明 |
|---|---|---|---|
| 1 | 拒绝新连接 | `POST /api/v5/banned`，body `{"as":"username","who":<who>,"reason":<reason>,"until":"infinity"}` | **直到时间 = 永久**（自动路径永远传 `until=null` → 序列化为 `"infinity"`） |
| 1b | `ALREADY_EXISTS` 处理 | — | `!resp.Ok && resp.Error != "ALREADY_EXISTS"` 才失败；即**已存在视为成功**（幂等） |
| 2 | 踢已在线连接（banned **不会**自动踢已连接的） | `GET /api/v5/clients?username=<who>&limit=10000` | 拿到该 username 的所有 clientid |
| 2b | 空集短路 | — | `clients.Count == 0` → 返回 `(null, 0)`：**成功，踢 0 个** |
| 3 | 批量踢下线 | `POST /api/v5/clients/kickout/bulk`，body = clientid 的 JSON 数组 | 失败 → 返回 `("踢下线失败: ...", 0)` = 整体失败 |
| 4 | 返回值 | `(string? Error, int Kicked)` | `Error==null` 才算成功 |

**时长**：自动路径 **永久**（`until="infinity"`）。临时拉黑只存在于**手动** `/api/blacklist/ban`（可传 `Until`，
格式 `yyyy-MM-ddTHH:mm` 本地时间 → RFC3339 带本地偏移），不传到期时间同样 = 永久。

**粒度**：`as="username"`（呼号粒度），**不是 clientid**。一次拉黑会踢掉同 username 的所有连接。

**失败处理**：**没有重试、没有 pending 标记、没有重试队列**。两个自动调用点的差异：

| 调用点 | 失败时 | 是否留痕 |
|---|---|---|
| 身份审计 KICK（`TopicEndpoints`） | `Console.Error.WriteLine`，`ban=false`，**仍写** `audit_packets` | **不写** `blacklist_audit`（EMQX 侧可能已拉黑 → 幽灵拉黑，见 E4） |
| uid 重复（`CollectorService`） | `_log.LogWarning`，`continue` 到下一个呼号 | **不写** `blacklist_audit`；下一轮采集若仍重复会**自然重试**（无退避） |

`Pending`/`Failed` 标记（`settings.TopicPending`/`TopicFailed`）**只服务于主题统计规则引擎的四件套配置步骤**
（超时→pending，真失败→failed），**与拉黑无关**；注意 `ToApiResult` 连超时/真失败都无法区分，一律进 failed。

**去重**：
- **身份审计 KICK 路径：没有去重**。同一 `clientid`/呼号反复违规 → 每个 KICK 包都会：`POST /banned`（大概率 `ALREADY_EXISTS`）
  + `GET /clients?username=` + `POST /kickout/bulk` + **追加一行 `blacklist_audit`** + 追加一行 `audit_packets`。
  实际上被踢+被禁后很难再发包，所以重复量受限，但**代码层面无幂等保护**。
- **uid 重复路径：有去重** —— 先读本地推导的活跃黑名单，组内呼号全部已拉黑就整组跳过并停止跟踪；
  逐个呼号前再查一次 `alreadyBanned.Contains(who)`。注意这个集合是**每轮开始时读一次**，
  同一轮里两个不同 uid 组共享同一呼号时仍可能重复拉黑同一呼号（写两行流水）。

### 3.2 三个调用点对照

| 调用点 | 传参 | 留痕 operator | 留痕 until | 事后刷新 |
|---|---|---|---|---|
| 身份审计 KICK `TopicEndpoints.cs:261` | `BanAsync(connCs, reason, null)` | `"身份控制"` | `NULL`（永久） | `_ = collector.CollectNowAsync()`（fire-and-forget） |
| uid 重复 `CollectorService.cs:308` | `BanAsync(who, reason, null)` | `"auto-uid-dup"` | `NULL`（永久） | 无（注释：被踢者下一轮自然消失） |
| 手动 `BlacklistEndpoints.cs:36` | `BanAsync(who, reason, untilRfc)` | `ctx.User.Identity?.Name ?? "?"` | 可空（NULL=永久） | `_ = collector.CollectNowAsync()` |

顺序铁律（留痕只在 EMQX 成功后）：**先 EMQX 执行 → 成功才写本地流水**。
`BlacklistEndpoints.cs:12` 原文：*"权威执行在 EMQX（banned API），本地 blacklist_audit 留痕；EMQX 操作失败不写流水。"*
uid 重复路径在 EMQX 成功后还会把 `uid/clientid/持续轮数` 写进 reason 文本，作为事后审计证据。

### 3.3 证据

`EmqxClient.cs:330-342` — BanAsync 全文

```csharp
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
```

`CollectorService.cs:300-318` — uid 重复的拉黑+留痕（永久 + 证据进 reason）

```csharp
const string baseReason = "身份控制: UID 重复登录";
foreach (var (uid, callsigns, clientIds, rounds) in confirmed)
{
    var detail = $"uid={uid} 呼号={string.Join("/", callsigns)} clientid={string.Join(",", clientIds)} 持续{rounds}轮";
    foreach (var who in callsigns)
    {
        if (alreadyBanned.Contains(who)) continue;
        var reason = $"{baseReason}（{detail}）";
        var (err, kicked) = await _emqx.BanAsync(who, reason, null); // null = 永久拉黑
        if (err != null) { _log.LogWarning("uid-dup 拉黑 {Who} 失败: {Error}", who, err); continue; }
        _db.AddBlacklistEvent("ban", "username", who, reason, null, "auto-uid-dup", now);
```

`BlacklistEndpoints.cs:36-44` — 手动拉黑（唯一支持临时时长与操作人的入口）

```csharp
var (err, kicked) = await emqx.BanAsync(who, req.Reason?.Trim() is { Length: > 0 } r ? r : null, untilRfc);
if (err != null)
    return Results.Json(new { ok = false, error = $"拉黑失败: {err}" });

db.AddBlacklistEvent("ban", "username", who, req.Reason?.Trim(), untilLocal, ctx.User.Identity?.Name ?? "?", DateTime.Now);
_ = collector.CollectNowAsync();
```

`EmqxClient.cs:604-606` — pending 只属于规则引擎配置（与拉黑无关）

```csharp
if (r.Error!.Contains("超时"))
{
    pending.Add(stepName);
    return null;
}
```

---

## 4. 重复 uid / 多连接疑似泄露检测

### 4.1 结论：算法

| 项 | 值 |
|---|---|
| 触发时机 | **每轮采集（60 秒一次）开始时**，在算增量之前：`DetectAndBanDuplicateUidsAsync(result.Clients, now)` |
| 判定输入 | 本轮 EMQX `/api/v5/clients` 返回的**在线**客户端列表 |
| 分组键 | `client_attrs.uid`（**字符串精确比较，`StringComparer.Ordinal`，区分大小写**） |
| 重复定义 | 同一 uid 在**同一轮快照**里出现 **≥2** 个在线客户端（= ≥2 个 clientid） |
| 排除 | `uid` 为空/null 的客户端**不参与**（匿名无身份可比） |
| 连续确认 | 同一 uid **连续 3 轮**仍重复才处置（`DupUidConfirmCycles = 3`）；**不是 N 轮内的累计**，中间一旦不重复立即清零 |
| 计数存放 | **纯内存字典** `_dupUidTrack: uid → (FirstSeen, Count)`。**没有数据库表**；进程重启即归零；`持续N轮` 只是写进 reason 文本 |
| 跟踪清理 | ①本轮不再重复 → 立即 `Remove`（"正常重连恢复后无痕"）；②组内呼号已全部在活跃黑名单 → `Remove` 并跳过；③确认处置后 → `Remove`（避免下轮重复触发） |
| 确认后动作 | 对该 uid 组内**每个不同的非空呼号**（`Distinct(OrdinalIgnoreCase)`）：若未在黑名单 → `BanAsync(who, reason, null)` = **永久拉黑 + 踢该 username 全部连接** → 成功则写 `blacklist_audit`（`operator="auto-uid-dup"`，`until=NULL`） |
| 组内无呼号 | `callsigns.Count == 0` → `continue`，**不跟踪不处置** |
| 为什么 3 轮 | 规避 EMQX keepalive 窗口（默认 60 s）内设备重连时"旧连接未过期 + 新连接已建立"的短暂并存被误判为克隆 → 3×60 s ≈ **连续 3 分钟重复**才算泄露 |

### 4.2 为什么是"永久"

1. 代码层面：`BanAsync(who, reason, **null**)` → body 里 `until = untilRfc3339 ?? "infinity"` → EMQX 永久条目。
2. 语义层面（README 原文）：*"包头与连接身份不一致=伪造，**多个相同身份同时登陆=泄露**，立即自动拉黑该连接身份
   （踢下线 + 禁连 + 留痕）"*，以及 *"开放网络里攻击成本趋近于零，默认最高保护是唯一正确的选择"*。
3. 安全推理：uid 重复意味着**凭证/身份已被共享或泄露**，泄露的是"呼号+UID"这个长期身份，不是某一次连接；
   临时封禁到期后攻击者用同一泄露凭证即可回来，所以只有永久封禁才有意义。
   （人类操作员仍可在黑名单页手动解封——`/api/blacklist/unban`。）

### 4.3 证据

`CollectorService.cs:129-137` — 每轮采集先做 uid 重复检测，异常不影响采集

```csharp
// uid 重复检测 + 自动拉黑
try
{
    await DetectAndBanDuplicateUidsAsync(result.Clients, now);
}
catch (Exception ex)
{
    _log.LogWarning(ex, "uid-dup 检测异常");
}
```

`CollectorService.cs:22-28` — 跟踪结构在内存 + 3 轮常量 + 注释里的理由

```csharp
// uid 重复观察跟踪：uid → (首次发现时间, 连续观察轮数)。连续 3 轮仍重复才处置，
// 避免 EMQX keepalive 窗口（默认 60s）内设备重连的新旧 clientid 短暂并存被误判为克隆。
private readonly Dictionary<string, (DateTime FirstSeen, int Count)> _dupUidTrack = new();
private const int DupUidConfirmCycles = 3;
```

`CollectorService.cs:246-251` — 分组与去重集合的大小写策略

```csharp
var dupGroups = clients.Where(c => !string.IsNullOrEmpty(c.Uid))
    .GroupBy(c => c.Uid!)
    .Where(g => g.Count() > 1)
    .ToList();
var dupUids = dupGroups.Select(g => g.Key).ToHashSet(StringComparer.Ordinal);
```

`CollectorService.cs:260-290` — 观测计数、达轮数确认、清理

```csharp
// 清理：不再重复的 uid 撤销跟踪——正常重连恢复后无痕
foreach (var uid in _dupUidTrack.Keys.Where(k => !dupUids.Contains(k)).ToList())
    _dupUidTrack.Remove(uid);
...
if (callsigns.Count == 0) continue;
// 组内呼号已全部拉黑 → 不再跟踪
if (callsigns.All(alreadyBanned.Contains)) { _dupUidTrack.Remove(uid); continue; }
_dupUidTrack.TryGetValue(uid, out var t);
var count = t.Count + 1;
var firstSeen = t.Count == 0 ? now : t.FirstSeen;
_dupUidTrack[uid] = (firstSeen, count);
if (count < DupUidConfirmCycles)
{
    _log.LogInformation("uid-dup uid={Uid} 发现重复连接，观察 {Count}/{Cycles} 轮（{ClientIds}）", ...);
    continue;
}
confirmed.Add((uid, callsigns, g.Select(c => c.ClientId).ToList(), count));
```

`EmqxClient.cs:340` — 批量踢下线（"永久"由 `EmqxClient.cs:333` 的 `until:"infinity"` 表达）

```csharp
var kick = await DoRequestAsync(HttpMethod.Post, "/api/v5/clients/kickout/bulk", JsonSerializer.Serialize(clients));
```

（`until:"infinity"` 见 `EmqxClient.cs:333`；"泄露→永久"的语义见 `README.md:11`。）

---

## 5. 采集轮询（CollectorService）

### 5.1 结论：轮询参数与每轮动作

| 项 | 值 |
|---|---|
| 周期 | **60 秒**（`PeriodicTimer(TimeSpan.FromSeconds(60))`）；首个 tick 在启动 60 s 后，**不会立即采集** |
| 门控 | `if (IsConfigured) await CollectAsync();` —— 未配置 EMQX 则本轮什么都不做 |
| 手动触发 | `CollectNowAsync()`：`Interlocked.Exchange(ref _collecting, 1)` 防重入（定时循环与手动触发不并发）；正在采集则**忽略本次** |
| 时间基准 | `DateTime.Now`（**服务器本地时间**，不转 UTC）→ `ts = "yyyy-MM-dd HH:mm:00"`（截到分钟） |
| 每轮步骤 | ①`GET /clients?limit=1000` → ②**uid 重复检测+自动拉黑** → ③逐客户端算增量并写 `minute_stats` → ④健康采集（宿主机 + `GET /nodes` 取第一个 + `GET /metrics` 算速率 + `GET /alarms?activated=true`）写 `health_snapshots` → ⑤每 10 分钟清理 30 天前数据 |
| 失败短路 | `/clients` 出错 → 记 `LastCollectOk=false`/`LastError`/`LastStatus` 并 **return**：本轮不写健康、不清理、不更新缓存 |
| 在线列表缓存 | `LastClients`（在线页 `/api/online` 直接读，60 s 内新鲜）+ `LastClientsAt` |
| 分页 | **只取第一页 `limit=1000`，不翻页**（`meta.hasnext` 被忽略）→ >1000 在线客户端会被静默截断（同时影响增量、uid 重复检测、在线页） |

### 5.2 结论：增量与"重连标记"

`Delta(prev, cur)`：`d = cur - prev`；`d < 0` → `reconnect=true, 返回 0`（clamp 不减计）；否则返回 `d`。

| 规则 | 行为 |
|---|---|
| 新出现的 clientid（`_prev` 里没有） | **本分钟不写任何行**（避免把 EMQX 的历史累计值当成第一分钟增量），但**立即把当前计数器存进 `_prev`** 作为基线 |
| 已知 clientid | 6 个计数器各算 delta（send/recv × oct/msg/pkt）写一行 |
| 计数器归零（重连） | delta 为负 → 该字段计 0；**`reconnect` 列只由 `send_pkt` 的 delta 决定**（代码里只有 SendPkt 那个 `out var rc`，其余 5 个的 out 被丢弃） |
| 同分钟重跑 | `INSERT OR REPLACE INTO minute_stats`（PK = `clientid, ts`）→ 覆盖而非累加，避免双计 |
| 内存防膨胀 | `_prev.Count > 在线数 × 5 && 在线数 > 0` → 清掉所有不在线的 clientid（离线设备重连后重新走"新客户端"逻辑） |
| 落库字段 | `username = c.Callsign ?? c.Username`（**呼号优先 `client_attrs.callsign`**）；注意这里**没有**把 username `"undefined"` 归一为 NULL（`/api/online` 展示层的 `NormalizeUser` 才做），所以 `minute_stats.username` 可能是字面量 `"undefined"` |
| 离线检测 | 没有独立逻辑：离线 = 从 `/clients` 消失 = 本轮不再产生 `minute_stats` 行；`reconnect` 与"客户端消失再出现"共同表达离线事实；排行榜用 `SUM(reconnect)` 展示"重连次数" |

### 5.3 结论：首次运行的初始化行为

`_prev` 空、`_lastCleanupAt = DateTime.MinValue`、`_lastMsgTotal = null`、状态字段默认：

- 第一轮：**所有客户端都被视为"新"→ `minute_stats` 一行都不写**（这是设计，见 README "客户端在线不足 1 分钟可能不被排行榜记录"）。
  但 `_prev` 会被填满、`LastClients` 立即可用、`health_snapshots` 会写（msgRate 因 `_lastMsgTotal==null` 为 `null`）。
- 第一轮就会执行过期清理（`now - MinValue > 10min`）。
- `ResetState()`（`/api/admin/reset` 调用）：清 `_prev`、状态、缓存，`_lastMsgTotal=null` → 回到"首次运行"语义。

### 5.4 证据

`CollectorService.cs:77-92` — 60 秒定时循环与门控

```csharp
protected override async Task ExecuteAsync(CancellationToken ct)
{
    using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
    while (!ct.IsCancellationRequested)
    {
        try { await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { break; }
        if (IsConfigured) await CollectAsync();
    }
}
```

`CollectorService.cs:96-107` — 手动触发防重入

```csharp
public async Task CollectNowAsync()
{
    if (!IsConfigured || Interlocked.Exchange(ref _collecting, 1) != 0) return;
    try { await CollectAsync(); }
    finally { Interlocked.Exchange(ref _collecting, 0); }
}
```

`CollectorService.cs:113-125` — 分钟时间戳与失败短路

```csharp
var now = DateTime.Now; // 服务器本地时间存储（管理员查询/对照投诉时间直观）
var ts = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0).ToString("yyyy-MM-dd HH:mm:00");
var result = await _emqx.GetClientsAsync();
if (result.Error != null)
{
    LastCollectOk = false;
    LastError = result.Error;
    LastStatus = $"采集失败: {result.Error}";
    _log.LogWarning("EMQX 采集失败: {Error}", result.Error);
    return;
}
```

`CollectorService.cs:141-167` — 增量核心（新客户端跳过、delta 落库、基线更新）

```csharp
foreach (var c in result.Clients)
{
    var key = c.ClientId;
    var isNew = !_prev.ContainsKey(key);
    var prev = isNew ? default : _prev[key];
    if (!isNew)
    {
        rows.Add(new MinuteStatRow
        {
            ClientId = key,
            Username = c.Callsign ?? c.Username,
            Uid = c.Uid,
            Ts = ts,
            SendOct = Delta(prev.SendOct, c.SendOct, out _),
            ...
```

`CollectorService.cs:324-335` — Delta / 重连标记

```csharp
private static long Delta(long prev, long cur, out bool reconnect)
{
    var d = cur - prev;
    if (d < 0) { reconnect = true; return 0; }
    reconnect = false;
    return d;
}
```

`CollectorService.cs:169-181` — 防膨胀、落库、缓存

```csharp
// 防膨胀：若历史 clientid 数远超当前在线数，重建只保留在线的（离线设备重连会重新走新客户端逻辑）
if (_prev.Count > result.Clients.Count * 5 && result.Clients.Count > 0)
{
    var cur = new HashSet<string>(result.Clients.Select(c => c.ClientId));
    foreach (var k in _prev.Keys.Where(k => !cur.Contains(k)).ToList())
        _prev.Remove(k);
}
...
_db.WriteMinuteStats(rows);
```

`Database.cs:248-265` — 同分钟覆盖（幂等键 = `clientid + ts`）

```csharp
/// <summary>写入一批分钟增量行（单事务；同分钟重跑用 INSERT OR REPLACE 覆盖，避免双计）</summary>
...
INSERT OR REPLACE INTO minute_stats
    (clientid, username, uid, ts, send_oct, recv_oct, send_msg, recv_msg,
     send_pkt, recv_pkt, ip_address, reconnect)
```

`Database.cs:983-995` — 30 天保留 + 分批删除

```csharp
foreach (var table in new[] { "minute_stats", "health_snapshots", "topic_stats", "audit_packets" })
{
    // 分批删：每批 20000 行，直到删不动
    // 注意：SQLite 默认不支持 DELETE ... LIMIT（语法错误），必须用 rowid 子查询分批
    for (var i = 0; i < 200; i++)
    {
        cmd.CommandText = $"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE ts < $cutoff LIMIT 20000)";
```

`EmqxClient.cs:169-171` — 单页 limit=1000

```csharp
public async Task<ClientsResult> GetClientsAsync(int limit = 1000)
{
    var resp = await DoRequestAsync(HttpMethod.Get, $"/api/v5/clients?limit={limit}");
```

---

## 6. topic 统计（TopicIngestService + `topic_stats`）

### 6.1 结论：每次 webhook 到达如何写库

`/api/ingest` **不直接写库**。流程是「同步进内存聚合 + 每 10 秒批量 UPSERT」：

| 步骤 | 行为 |
|---|---|
| 1. 校验 | `X-Ingest-Token` 与 `settings.IngestToken` 用 `CryptographicOperations.FixedTimeEquals` 常量时间比较；token 未配置/不匹配 → **401** `{"ok":false,"error":"invalid token"}` |
| 2. Content-Type | 非 JSON → **400** `bad content type` |
| 3. 解析 | `JsonDocument.ParseAsync(ctx.Request.Body)`（**必须同步 await 读 body**；注释明确：异步 `Task.Run` 读 `Request.Body` 在响应返回后不可读） |
| 4. 聚合 | `Ingest(topic, username, uid, clientid, bytes, DateTime.Now)`：`topic`/`clientid` 为空或 `bytes<0` → 返回 false，不入聚合；否则按 **10 秒桶**累加 |
| 5. 响应 | 无论审计结果如何都返回 `{"ok":true}`（异常只写 stderr）—— **EMQX bridge 不会因审计失败而重投** |
| 6. 落库 | `PeriodicTimer(10s)` → `Flush()`：锁内取出并清空字典 → 单事务 `WriteTopicStats` |

### 6.2 结论：10 秒分桶怎么对齐

- **向下取整（floor）**：`sec = now.Second / 10 * 10`（整数除法）→ 秒只能是 `00/10/20/30/40/50`。
- **时区**：用 `DateTime.Now`（**服务器本地时间**），**没有任何 UTC/时区换算**；跨时区部署会串桶。
- **格式**：`"yyyy-MM-dd HH:mm:ss"`（文本存储，SQL 里用字符串比较/`substr` 切桶）。
- **注意**：`ts` 字符串的秒位是 `SS`（10 秒粒度），而查询端点用 `ParseRange` 生成的边界是分钟粒度（`HH:mm:00`）。
  两者都是补零 `yyyy-MM-dd HH:mm:SS` 格式，**字符串 BETWEEN 可用**，但会**漏掉区间末分钟里 `SS>00` 的桶**。

### 6.3 结论：每桶 Top 呼号怎么算

**写入时不算，查询时算**（`QueryTopicTimeline`，两条 SQL）：

1. **每桶总量 + 去重人数**：`GROUP BY bucket_ts` → `SUM(msg_count)`、`SUM(bytes)`、`COUNT(DISTINCT COALESCE(username, clientid))`。
2. **每桶 Top 8 呼号**：窗口函数
   `ROW_NUMBER() OVER (PARTITION BY <bucket> ORDER BY SUM(msg_count) DESC, COALESCE(username, clientid))`，
   外层 `WHERE rn <= 8`（SQL 层截断行数，不是取回后在内存排）。
   → **并列时按呼号升序**决定谁进 Top8。
3. 桶表达式（`bucket` 参数，**只接受 `10s`/`5m`/`1h`，其余一律 `1m`**）：

| bucket | 表达式 | 说明 |
|---|---|---|
| `10s` | `ts` | 原始桶，粒度本身就是 10 秒 |
| `1m` | `substr(ts,1,16) \|\| ':00'` | 取到分钟位，秒补 `:00`（兼容旧的分钟级数据 `SS=00`） |
| `5m` | `substr(ts,1,14) \|\| printf('%02d', CAST(substr(ts,15,2) AS INTEGER)/5*5) \|\| ':00'` | 分钟整除 5 向下取整（SQLite 整数除法） |
| `1h` | `substr(ts,1,13) \|\| ':00:00'` | 取到小时位 |

4. **补零**：按 `from` 对齐桶边界（`5m`→分钟/5*5，`1h`→整点，`10s`→秒/10*10）生成完整序列，
   无数据桶填 `MsgCount=0,Bytes=0,UserCount=0,TopUsers=[]`；补零后 >40000 点直接报错拒绝（前端提示缩小范围）。

呼号聚合口径统一为 **`COALESCE(username, clientid)`**（无 username 就用 clientid 兜底，前端标 `IsAnonymous`）；
`uid` 用 `MIN(uid)`/`MAX(uid)` 取值（同 name 多 uid 时取极值，不是集合）。

### 6.4 结论：写入并发与批处理策略

- **单写者模型**：`Database` 内部 `private readonly object _lock`，**每个方法都 `lock (_lock)`**，
  且每次调用新开连接（`Open()`）。采集线程、ingest flush 线程、HTTP 审计写入全部串行化。
- SQLite 参数：`PRAGMA journal_mode=WAL; synchronous=NORMAL; busy_timeout=5000;`（单进程读写，NORMAL 足够）。
- **批处理**：内存字典按 `(topic, username, uid, clientid, ts10s)` 聚合 → 每 10 秒一次**单事务**逐行 UPSERT。
  设计意图（注释）：*"每秒几百~几千条消息事件时，10 秒批量写远优于逐条写"*。
- **UPSERT 是累加**：`ON CONFLICT(topic, clientid, ts) DO UPDATE SET msg_count = msg_count + excluded.msg_count, bytes = bytes + excluded.bytes`。
  因此 **bridge `max_retries=2` 造成的重复投递会重复计数**（没有消息 ID 去重）。
- **幂等键**：唯一约束/主键 = `(topic, clientid, ts)`；`topic_stats` 主键**不含 username/uid**，
  所以同一 clientid 在同一分钟内换了 username/uid，仍会并进同一行，而 **username/uid 取"首次插入那一笔"的值**
  （冲突分支只累加计数字段，不更新 username/uid）。
- **失败丢数据**：`Flush` 先把字典 `Clear()` 再写库，写库异常只打 stderr → **这批聚合数据永久丢失**，无重试。
- 退出时最后 `Flush()` 一次（`ExecuteAsync` 循环外）。

### 6.5 证据

`TopicEndpoints.cs:14-23` — token 常量时间校验 + Content-Type

```csharp
app.MapPost("/api/ingest", async (HttpContext ctx, TopicIngestService ingest) =>
{
    var token = settings.IngestToken;
    var got = ctx.Request.Headers["X-Ingest-Token"].FirstOrDefault();
    if (string.IsNullOrEmpty(token) || got == null
        || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(got), System.Text.Encoding.UTF8.GetBytes(token)))
        return Results.Json(new { ok = false, error = "invalid token" }, statusCode: 401);
    if (!ctx.Request.HasJsonContentType())
        return Results.Json(new { ok = false, error = "bad content type" }, statusCode: 400);
```

`TopicEndpoints.cs:45-56` — base64 payload 与字节数估算

```csharp
long bytes = 0;
byte[]? raw = null;
if (root.TryGetProperty("payload", out var p) && p.ValueKind == JsonValueKind.String)
{
    var s = p.GetString()!;
    try { raw = Convert.FromBase64String(s); bytes = raw.Length; }
    catch { bytes = s.Length; }   // 非 base64 则按字符数近似
}
```

`TopicIngestService.cs:62-78` — 10 秒桶对齐（floor + 本地时间）

```csharp
public bool Ingest(string topic, string? username, string? uid, string clientId, long bytes, DateTime now)
{
    if (string.IsNullOrEmpty(topic) || string.IsNullOrEmpty(clientId) || bytes < 0) return false;
    // 10 秒颗粒度取整（yyyy-MM-dd HH:mm:SS，秒 = 0/10/20/30/40/50）
    var sec = now.Second / 10 * 10;
    var ts = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, sec)
        .ToString("yyyy-MM-dd HH:mm:ss");
    lock (_lock)
    {
        var key = (topic, username, uid, clientId, ts);
        _agg.TryGetValue(key, out var cur);
        _agg[key] = (cur.Msg + 1, cur.Bytes + bytes);
```

`TopicIngestService.cs:81-107` — Flush：先清空后写库（失败即丢）

```csharp
public void Flush()
{
    List<TopicStatRow> rows;
    lock (_lock)
    {
        if (_agg.Count == 0) return;
        rows = _agg.Select(kv => new TopicStatRow { ... }).ToList();
        _agg.Clear();
    }
    try { _db.WriteTopicStats(rows); }
    catch (Exception ex) { Console.Error.WriteLine($"[TopicIngest] 落库失败: {ex.Message}"); }
}
```

`Database.cs:497-503` — UPSERT 累加（幂等键 `(topic, clientid, ts)`）

```csharp
INSERT INTO topic_stats (topic, username, uid, clientid, ts, msg_count, bytes)
VALUES ($topic, $user, $uid, $cid, $ts, $msg, $bytes)
ON CONFLICT(topic, clientid, ts) DO UPDATE SET
    msg_count = msg_count + excluded.msg_count,
    bytes = bytes + excluded.bytes
```

`Database.cs:614-621` — 桶表达式

```csharp
var bucketExpr = bucket switch
{
    "10s" => "ts",
    "1m" => "substr(ts,1,16) || ':00'",
    "5m" => "substr(ts,1,14) || printf('%02d', CAST(substr(ts,15,2) AS INTEGER)/5*5) || ':00'",
    "1h" => "substr(ts,1,13) || ':00:00'",
    _ => "ts"
};
```

`Database.cs:659-667` — 每桶 Top8 呼号

```csharp
ROW_NUMBER() OVER (
    PARTITION BY {bucketExpr}
    ORDER BY SUM(msg_count) DESC, COALESCE(username, clientid)
) AS rn
FROM topic_stats
...
) WHERE rn <= 8
```

`Database.cs:141` — 写库串行化与 WAL

```csharp
pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;";
```

---

## 7. 边界与容错

### 7.1 结论：`client_attrs.uid` 是数字 / 字符串 / null

**存在两条不同的归一化路径，规则不同——这是重写最危险的坑。**

**路径 A：`GET /api/v5/clients`（采集侧，模型 `EmqxClientInfo.ClientAttrs`，走 `TolerantStringDictConverter`）**

| JSON 输入 | 归一结果 | 备注 |
|---|---|---|
| `"uid":"12345"` | `"12345"` | 原样 |
| `"uid":12345` | `"12345"` | `reader.GetRawText()`（数字原始文本） |
| `"uid":12345.0` | `"12345.0"` | 原始文本保留小数点 → 与包头 `"12345"` **不相等** |
| `"uid":true` / `false` | `"true"` / `"false"` | 硬编码小写字面量 |
| `"uid":null` | `""`（**空串**） | 空串 → `Uid` 属性返回 `""` → 被 `!string.IsNullOrEmpty(c.Uid)` 排除，**不参与 uid 重复检测** |
| `"uid":{...}` / `[...]` | 原始 JSON 文本 | `_ => GetRawText` |
| 键不存在 | 字典无该键 → `Uid` 返回 **`null`** | 与 `""` 效果相近（都进不了重复检测），但 `minute_stats.uid` 存 NULL |
| `client_attrs` 整体为 `null` | `ClientAttrs == null` → `Callsign`/`Uid` 均 `null` | 测试 `attrs为null_返回null` |
| `client_attrs` 缺失 | `null` | 测试 `无attrs字段_返回null` |
| `client_attrs:{}` | 空字典（非 null） | `Callsign`/`Uid` → `null` |
| `client_attrs` 不是对象 | **抛 `JsonException("client_attrs 应为 JSON 对象")`** | 会让整个 `/clients` 反序列化失败 → **整轮采集崩**（`GetClientsAsync` 无 try/catch，异常冒到 `CollectAsync` 的兜底 catch → `LastCollectOk=false`） |
| 嵌套值不是合法键值对 | 抛 `JsonException("client_attrs 应为键值对对象")` | 同上 |

`Write` 方向：所有值都写成 JSON 字符串（数字也会变字符串）。

**路径 B：`POST /api/ingest`（审计侧，手写解析，**不走 converter**）**

| JSON 输入 | 归一结果 | 备注 |
|---|---|---|
| `"uid":"12345"` | `"12345"` | 原样 |
| `"uid":12345` | `"12345"` | `cu.GetRawText()` |
| `"uid":null` | **字符串 `"null"`**（4 个字符） | ⚠️ 与路径 A 不同！导致 `connU="null"` 非空 → **不判匿名 WARN，而判 KICK（但 `connCs==""` 时又不拉黑）** |
| `"uid":true` | `"true"` | |
| `uid` 键不存在 / `client_attrs` 不是对象 | `null` → `connU=""` | |
| `client_attrs` 不是对象（数组/字符串/数字） | 整块跳过（`ValueKind != Object`）→ `callsign`/`uid` 均 null → 若 username 也为空则 **WARN** | 不抛异常（与路径 A 不同） |

### 7.2 结论：其余边界

| 边界 | 行为 |
|---|---|
| **呼号大小写** | 判决**大小写不敏感**（双方 `ToUpperInvariant()`）；但 `blacklist_audit.who`、`audit_packets.pkt_callsign` 存的是**大写后**的值，`audit_packets.conn_callsign` 存**原样**（未大写未 Trim） |
| 呼号空白 | 两侧都 `Trim()`：包头解析时一次、判决时再一次；连接身份侧判决时 Trim（但落库的 `conn_callsign` 未 Trim） |
| **callisgn 非 ASCII 字节** | .NET `Encoding.ASCII.GetString` 把 >0x7F 的字节**替换成 `'?'`**（不是抛异常、不是 UTF-8 解码）。Python 必须用 `errors='replace'` 才能等价（Python 默认 utf-8 会解出完全不同的字符串） |
| 空 `clientid` | `/api/ingest` 里 `!string.IsNullOrEmpty(clientid)` 整块跳过 → **既不统计也不审计**（静默丢弃，不报错） |
| 空 `topic` | 同上，整块跳过 |
| `payload` 缺失 | `raw=null`、`bytes=0` → 仍算 1 条 msg（0 字节），不审计 |
| 非 base64 payload | `catch` 吞掉 → `bytes = 字符串长度`，`raw=null` → 不审计（**不报错、不回滚统计**） |
| **超大包** | ①全局 Kestrel `MaxRequestBodySize = 1_048_576`（1 MB）→ 更大 body 直接 413；②`FmoRawParser` 判 `>1400` → FAIL，不处置；③FAIL 落库限流 100 条/60 秒窗口（**全局**，非按 clientid） |
| FAIL 限流细节 | 窗口起点 = 窗口内第一次调用时间；`_failCount >= 100` 返回 true 跳过落库；超限的包**永久无痕**（下一窗口重新计 100） |
| **重复包** | **没有内容级去重**。可能的去重键只有时间桶：`topic_stats` = `(topic, clientid, ts10s)`（重复投递**累加**，不去重）；`minute_stats` = `(clientid, ts分钟)`（`INSERT OR REPLACE` 覆盖）；`audit_packets` **无唯一键**（自增 id）→ 每个 KICK/WARN 包各一行，FAIL 受 100/60s 限流 |
| 无效 JSON body | `catch` → stderr `[Ingest] 解析失败: ...` → 仍返回 `{"ok":true}` |
| 大范围查询 | `ParseRange`：格式必须 `yyyy-MM-ddTHH:mm`、结束≥开始、跨度 ≤31 天；时间轴补零后 >40000 点报错 |
| `client_attrs` 含超长值 | 无长度校验，原样入库 |

### 7.3 证据

`Models.cs:143-170` — converter 的全部规则

```csharp
public sealed class TolerantStringDictConverter : JsonConverter<Dictionary<string, string>>
{
    public override Dictionary<string, string> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("client_attrs 应为 JSON 对象");
        var dict = new Dictionary<string, string>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject) break;
            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException("client_attrs 应为键值对对象");
            var key = reader.GetString()!;
            reader.Read();
            dict[key] = reader.TokenType switch
            {
                JsonTokenType.String => reader.GetString()!,
                JsonTokenType.Number => GetRawText(ref reader),
                JsonTokenType.True => "true",
                JsonTokenType.False => "false",
                JsonTokenType.Null => string.Empty,
                _ => GetRawText(ref reader)
            };
```

`Models.cs:129-135` — 身份字段取值（缺失 → null）

```csharp
/// <summary>呼号（client_attrs.callsign，可能为 null）</summary>
public string? Callsign
    => ClientAttrs is { } attrs && attrs.TryGetValue("callsign", out var c) ? c : null;

/// <summary>用户编号（client_attrs.uid，可能为 null）</summary>
public string? Uid
    => ClientAttrs is { } attrs && attrs.TryGetValue("uid", out var u) ? u : null;
```

`ConverterAndWebTests.cs:20-61` — converter 的 6 个已验证向量

```csharp
[Fact] public void 数字uid_归一为字符串()  // {"callsign":"BG5AAA","uid":12345} → "12345"
[Fact] public void 字符串uid_原样保留()    // {"uid":"12345"} → "12345"
[Fact] public void 无attrs字段_返回null()  // {} → null
[Fact] public void attrs为null_返回null()  // {"client_attrs":null} → null
[Fact] public void 空对象_返回空字典()      // {"client_attrs":{}} → 空字典
[Fact] public void 布尔值_归一为字符串()    // {"flag":true} → "true"
```

`Program.cs:66-68` — 1MB body 上限（超大包第一道闸）

```csharp
// 全局请求体上限 1MB：所有 POST 端点 body 都很小，防 ingest webhook 超大 body 内存炸弹（Kestrel 默认 30MB）
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(o =>
    o.Limits.MaxRequestBodySize = 1_048_576);
```

`TopicIngestService.cs:30-48` — FAIL 限流窗口

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

`WebHelpers.cs:9-17` — 查询区间解析（31 天上限、分钟粒度输出）

```csharp
if (!DateTime.TryParseExact(from, "yyyy-MM-ddTHH:mm", ...) || !DateTime.TryParseExact(to, "yyyy-MM-ddTHH:mm", ...))
    return ("", "", "时间格式应为 yyyy-MM-ddTHH:mm");
if (t < f) return ("", "", "结束时间不能早于开始时间");
if (t - f > TimeSpan.FromDays(31)) return ("", "", "时间跨度不能超过 31 天");
return (f.ToString("yyyy-MM-dd HH:mm:00"), t.ToString("yyyy-MM-dd HH:mm:00"), null);
```

---

## 8. 事件与数据的对应关系

### 8.1 结论：一次 KICK 在库里留下什么

```
时间线（本地时间）：
T+0.000s  POST /api/ingest 命中 KICK
T+0      topic_stats      ← Ingest 先执行：该包已计入 (topic, clientid, ts10s) 的 msg_count/bytes
T+0..N   EMQX banned      ← POST /api/v5/banned（外部系统，本地无副本，只能在黑名单页对照查询）
T+0..N   EMQX kickout     ← POST /api/v5/clients/kickout/bulk（无本地记录）
T+0..N   blacklist_audit  ← 1 行（仅 EMQX 两步都成功时）
T+0..N   audit_packets    ← 1 行（无论拉黑成功与否都写）
T+0      CollectorNowAsync ← fire-and-forget 触发一次 60s 采集，刷新在线列表缓存
T+≤60s   minute_stats     ← 该客户端被踢前最后一次采集可能留下 1 行（无 KICK 关联字段）
```

| 表 | 一次 KICK 产生的行 | 关键列 |
|---|---|---|
| `audit_packets` | **每包 1 行**（无去重、无限流） | `ts`(带毫秒) / `topic` / `clientid` / `conn_callsign`(原样) / `conn_uid` / `pkt_callsign`(大写) / `pkt_uid`(十进制串) / `verdict='KICK'` / `len` / `frame_num` / `crc_ok` / `smeter` / `srv_uid` / `pkt_ts` / `stream_begin` / `ban` |
| `blacklist_audit` | **0 或 1 行**（仅 `BanAsync` 返回成功） | `action='ban'`、`as_type='username'`、`who=大写后的连接呼号`、`reason`、`until=NULL`(永久)、`operator='身份控制'`、`created_at` |
| `topic_stats` | **≥1 行**（KICK 前已聚合） | 攻击者的发包量照样进主题统计——反查干扰源的依据 |
| `minute_stats` | 0~1 行 | 排行榜底座；**没有** verdict/ban 字段，无法从排行榜直接看出谁被 KICK 过 |
| EMQX `banned` + kickout | 外部状态 | 权威执行；`/api/blacklist/active` 用 `emqx_only` 字段暴露"EMQX 有、本地无记录"的手动拉黑 |

`WARN` 与 `FAIL` 只写 `audit_packets`（`ban=0`），**不写** `blacklist_audit`。
`PASS` 什么都不写（只在 `topic_stats`/`minute_stats` 里体现流量）。

### 8.2 结论：前端"身份审计"页按什么条件查

| 项 | 值 |
|---|---|
| 页面 | `/audit.html`（导航"身份审计"） |
| 接口 | `GET /api/audit-packets?from=<yyyy-MM-ddTHH:mm>&to=<同>&verdict=<KICK\|WARN\|FAIL\|空>&limit=300` |
| 默认范围 | 近 7 天（快捷：近1小时 / 今天 / 近7天 / 近30天） |
| 默认筛选 | `verdict=""` = **全部异常**（等价于不过滤）；另有"身份不符"KICK / "未知身份" WARN / "非法包" FAIL 三个 chip |
| 服务端 | `ParseRange` 转成 `"yyyy-MM-dd HH:mm:00"` → `WHERE ts BETWEEN $from AND $to [AND verdict=$v] ORDER BY id DESC LIMIT $n`；`limit` 默认 200，clamp 到 1..1000（页面传 300） |
| 顶部计数 | `CountAuditVerdicts`：`SELECT verdict, COUNT(*) ... GROUP BY verdict` → 显示 "KICK n · WARN n · FAIL n" |
| 自动刷新 | 每 30 s（页面可见且勾选"自动刷新"时）；状态栏另有 `/api/identity-control` 显示"身份控制已启用/已关闭" |
| 列 | 判定 / 时间 / 连接身份（实际连接者，空则显示"匿名"）/ 包头声明（payload 自称）/ clientid / 包长 / 帧数 / S表 / CRC(✓✗) / 处置 |
| "处置"列文案 | `ban=1` → "已自动拉黑"；`verdict=='KICK' && ban==0` → "仅记录（身份控制关闭或拉黑失败）"；其余 → "-" |
| 空表文案 | "该时间段内没有异常审计事件（包头身份与连接身份一致 = 正常放行，不记录）" |
| ⚠️ 时间边界陷阱 | `audit_packets.ts` 带毫秒（`yyyy-MM-dd HH:mm:ss.fff`），而 `to` 是 `HH:mm:00` → 字符串比较下**区间最后一分钟的行全部被排除**（`"...:00.123" > "...:00"`）。同理 `topic_stats` 末分钟里 `SS>00` 的桶也会被漏掉 |

### 8.3 证据

`BlacklistEndpoints.cs:103-110` — 查询端点

```csharp
app.MapGet("/api/audit-packets", (string from, string to, string? verdict, int? limit, Database database) =>
{
    var (f, t, err) = WebHelpers.ParseRange(from, to);
    if (err != null) return Results.Json(new { ok = false, error = err });
    var rows = database.QueryAuditPackets(f, t, verdict, Math.Clamp(limit ?? 200, 1, 1000));
    var counts = database.CountAuditVerdicts(f, t);
    return Results.Json(new { ok = true, from = f, to = t, rows, counts });
});
```

`Database.cs:860-874` — 查询 SQL（倒序、按 verdict 可选过滤）

```csharp
var sql = """
    SELECT ts, topic, clientid, conn_callsign, conn_uid, pkt_callsign, pkt_uid,
           verdict, len, frame_num, crc_ok, smeter, srv_uid, pkt_ts, stream_begin, ban
    FROM audit_packets
    WHERE ts BETWEEN $from AND $to
    """;
if (!string.IsNullOrEmpty(verdict))
    sql += " AND verdict = $v";
sql += " ORDER BY id DESC LIMIT $n";
```

`TopicEndpoints.cs:262-270` — 成功后留痕（`until=null` = 永久，operator = "身份控制"）

```csharp
if (err == null)
{
    ban = true;
    try
    {
        db.AddBlacklistEvent("ban", "username", connCs, reason, null, "身份控制", now);
        _ = collector.CollectNowAsync();   // 即时刷新在线列表
    }
    catch (Exception ex) { Console.Error.WriteLine($"[Audit] 拉黑留痕失败: {ex.Message}"); }
}
```

`Database.cs:757-763` — "当前生效黑名单"是**本地推导**（最新一条操作是 ban 且未到期）

```sql
SELECT who, reason, until, operator, created_at FROM (
    SELECT who, action, reason, until, operator, created_at,
           ROW_NUMBER() OVER (PARTITION BY who ORDER BY created_at DESC, id DESC) AS rn
    FROM blacklist_audit
) WHERE rn = 1 AND action = 'ban' AND (until IS NULL OR until > $cutoff)
```

`wwwroot/app.js:953,970` — 前端查询与"处置"列文案

```javascript
const d = await api(`/api/audit-packets?from=${encodeURIComponent(f)}&to=${encodeURIComponent(t)}${verdict ? `&verdict=${verdict}` : ''}&limit=300`);
const disp = r.ban ? '已自动拉黑' : (r.verdict === 'KICK' ? '仅记录（身份控制关闭或拉黑失败）' : '-');
```

---

## 9. Python 重写注意点

### 9.1 字节序与解析

1. **全部小端**。用 `struct.unpack_from('<H', raw, 0)` / `'<I'`；不要用 `int.from_bytes(..., 'big')`（默认就是 big，最易踩）。
2. **CRC32 用 `zlib.crc32(raw[64:]) & 0xFFFFFFFF`**。源码 `Crc32` 类的注释"初值 0 / 无最终异或"是**错的**；
   以 `0xCBF43926`（"123456789"）与 `CRC32(空)==0` 两个向量为验收标准。
3. **callsign 解码**：先按第一个 `0x00` 截断 12 字节区，再 `bytes.decode('ascii', errors='replace').strip()`。
   .NET `Encoding.ASCII` 把 >0x7F 映射为 `'?'`；Python 默认 utf-8 会得到完全不同的字符串 → **必须显式 `errors=`**。
4. **判空顺序照抄**：长度下界 → 长度上界 → `len` 字段一致 → （不可达的 `len<72`）。
   顺序变化会改变错误文案与 FAIL 分类（错误文案会进 stderr/日志，运维据此排查）。
5. **CRC 不参与合法性**：`crc_ok` 只是展示字段。别把 CRC 失败升级成 FAIL——那会改变判决表（D/E 组行为）。
6. **帧区完全不解析**。不要为了"packet type"去猜帧头位域；包头里也没有 packet type 字段。
7. **defensive 解析**：任何越界/解码异常都不能冒泡到 ingest handler（否则 EMQX 会认为投递失败）。
   一律 `try/except` 包住，失败 → FAIL 分支（且记住 FAIL 不处置）。

### 9.2 身份归一（最容易走样的地方）

8. **三条不同的 uid 来源规则必须分别实现**：
   - EMQX `/clients` → `client_attrs`：string 原样；number/bool/object → 原始 JSON 文本；**null → `""`**；键缺失 → `None`。
   - `/api/ingest` 手写解析：string 原样；**其它一律 `GetRawText()`（null → 字面量 `"null"`）**；`client_attrs` 非对象 → 整块忽略。
   - `pkt_uid`：`str(uid_uint32)`，**永不为空**（`0` → `"0"`）→ 不要写 `if pkt_uid:` 之类的多余判空。
9. **callsign 覆盖 username**：只要 `client_attrs.callsign` 非空，用来判决/拉黑的"连接呼号"就是它，不是 MQTT username；
   否则退回 username（并归一 `"undefined"` → 匿名）。**拉黑目标 = 这个值的 Trim+upper 结果**。
10. **大小写策略不对称**：呼号比较大写化（不敏感）；uid 比较**原始字符串精确相等**（`"012345"`≠`"12345"`，
    `"12345 "`≠`"12345"`，`12345.0`≠`12345`）。uid 分组用大小写敏感（Ordinal），呼号去重/黑名单匹配用不敏感。
11. **落库要区分"原样"与"大写"**：`conn_callsign` 存原样（未 Trim 未大写），`pkt_callsign` 存大写，
    `blacklist_audit.who` 存大写。前端按这些值做展示与对照，改了口径会破坏存量数据的可比性。
12. **`connCs == "" && connU == ""` 才是 WARN**。只看 callsign 会漏掉 uid null→"null" 这条分支（D10）。

### 9.3 并发与写库

13. **单写者**：原实现是进程内单锁 + 每调用新连接 + WAL + `busy_timeout=5000`。
    Python（`sqlite3`）建议：**一个专用写连接 + 一把 `threading.Lock`**，或独立写线程；
    设 `PRAGMA journal_mode=WAL`、`synchronous=NORMAL`、`busy_timeout=5000`；注意 `check_same_thread=False` 的误用风险。
14. **批处理**：保持"内存聚合 + 定时批量事务 UPSERT"的形状；逐条写在高频 webhook 下会打爆 SQLite。
15. **Flush 失败不能丢数据**：原实现先 `Clear()` 再写库 → 写失败即永久丢。Python 版应"写成功后再移除"或保留副本重试。
16. **不要在同一次请求里同步做 3 次 EMQX HTTP**：原实现 KICK 路径 `await` 了 `POST /banned` + `GET /clients` + `POST /kickout/bulk`
    才返回 200，webhook 会被拖慢（EMQX bridge 有超时/重试）。Python 版应把处置丢进队列由 worker 执行（返回 200 后再处置），
    但**判决与审计落库**要保持"同一请求内完成"以便留证。
17. **KICK 路径无去重**：务必在 Python 版补上（例：按 `(connCs, pkt_callsign, pkt_uid)` 或 `clientid` 做短 TTL 去重；
    或拉黑前先查本地活跃黑名单，像 uid-dup 路径那样）。否则每个违规包 = 3 次 HTTP + 2 行写库。
18. **`ALREADY_EXISTS` 是成功**；EMQX 的 `until="infinity"` 才是永久（别用 `None`/`0`/空串，语义不同）。
19. **幽灵拉黑**：原实现把"banned 成功 + kickout 失败"整体判为失败 → 不留痕但 EMQX 已禁连。
    Python 版建议拆成两个独立结果：`banned_ok` 与 `kicked_ok`，分别留痕（`audit_packets.ban` 与 `blacklist_audit` 才不会说谎）。

### 9.4 时间与分桶

20. **全部用服务器本地时间（naive）**：`datetime.now()`，**绝不要** `utcnow()`（否则桶与查询区间全部错位）。
21. **桶下取整**：分钟 = `replace(second=0, microsecond=0)`；10 秒 = `replace(second=second//10*10, microsecond=0)`。
    格式字符串严格保持 `"%Y-%m-%d %H:%M:00"`（分钟）/ `"%Y-%m-%d %H:%M:%S"`（10 秒）/ `"%Y-%m-%d %H:%M:%S.%f"[:23]`（审计毫秒）。
22. **字符串 BETWEEN 的边界缺陷**：`audit_packets.ts` 带毫秒而查询上界是 `HH:mm:00` → 末分钟全漏；
    `topic_stats` 末分钟 `SS>00` 的桶也漏。Python 版建议把区间改成**半开区间** `[from, to + 1 单位)`，
    或额外存一个整数 epoch 列做范围过滤（存量文本列保留以兼容）。
23. **保留 30 天清理**：`DELETE ... WHERE rowid IN (SELECT rowid ... LIMIT 20000)` 分批——
    SQLite 不支持 `DELETE ... LIMIT`，Python 版照抄 rowid 子查询写法；每 10 分钟最多跑一次。
24. **时区展示**：EMQX 返回的 `connected_at` 是 RFC3339（带偏移），与本地时间列不是一套口径；手动拉黑的
    `until` 是"本地 `yyyy-MM-ddTHH:mm` → RFC3339 带本地偏移"（`BlacklistEndpoints.cs:31-33`），别当 UTC。

### 9.5 幂等与去重

25. **三张表的"幂等键"各不相同**，照抄别创新：
    - `minute_stats`：`(clientid, ts)` + `INSERT OR REPLACE`（同分钟重跑覆盖，避免双计）
    - `topic_stats`：`(topic, clientid, ts10s)` + `ON CONFLICT ... DO UPDATE SET msg_count = msg_count + excluded.msg_count`
      （**累加**，重复投递会双计；要真幂等需引入 EMQX 侧消息 ID/去重键，当前协议不带）
    - `audit_packets`：**无唯一键**，每次写都新增行（只有 FAIL 有全局 100/60s 限流）
26. **`topic_stats.username/uid` 是"首次写入者优先"**（冲突分支只累加计数，不更新身份列）。
    若 Python 版要求"同一 bucket 内身份以最新为准"，必须显式改冲突分支——这会改变存量语义，需产品确认。
27. **`minute_stats.reconnect` 只反映 `send_pkt` 回落**，其余 5 个计数器的回落被静默丢弃。
28. **新客户端首分钟不落库**是**有意设计**（防历史累计值污染）；重建 `_prev` 基线逻辑要保留，
    否则重启后第一个 60 秒会把 EMQX 的历史累计值当成增量写进排行榜。
29. **uid 重复/N 轮确认状态在内存里**：原实现没有表。若 Python 版要跨重启保持"连续 3 轮"，需要新建表
    （`uid_dup_track(uid, first_seen, count, last_round)`）——这属于增强，必须在 spec 里标注为"行为变更"。
30. **`GET /clients?limit=1000` 不翻页**：Python 版应对齐或实现 `meta.hasnext` 翻页；若翻页，
    uid 重复检测与增量统计的输入集合会变大（行为差异要点明）。同时 `kickout` 用的是
    `GET /clients?username=<who>&limit=10000`（同样不翻页）。
31. **`client_attrs` 反序列化必须容错**（数字 uid 是常态）：Python 里直接 `dict[str, str]` 校验会整轮采集崩；
    用 `str(v) if v is not None else ""` 之类逐值归一，并严格区分"null → `""`"与"缺失 → `None`"。
32. **常量时间 token 比较**：用 `hmac.compare_digest`，保持 401/400 的响应体与状态码一致（EMQX bridge 靠状态码决定重试）。
33. **空 clientid / 空 topic 静默丢弃**（不报错、不写统计、不审计）——EMQX 侧配置错误时会表现为"完全没有数据"，
    Python 版建议至少打一条限频日志便于排障，但**不要**改成返回错误（会触发 bridge 重试风暴）。
