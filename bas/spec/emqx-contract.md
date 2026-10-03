# EMQX 对接契约（FAS / fmo-audit-service → Python 重写用）

来源仓库：`BG5ESN/fmo-audit-service`，本地克隆 `C:\Users\Administrator\AppData\Local\Temp\fas-clone`。
核心文件：`EmqxClient.cs`(696 行)、`TopicIngestService.cs`(126 行)、`TopicEndpoints.cs`(347 行)、
`CollectorService.cs`(336 行)、`Models.cs`、`BlacklistEndpoints.cs`、`AppSettings.cs`、`CliConfigure.cs`、`Program.cs`。

全部 EMQX 调用集中在一个类里：`EmqxClient`（`EmqxClient.cs`）。Python 侧对应的就是一个 `EmqxClient` 类
+ 一个 `TopicIngestService` + 一个 FastAPI 路由 `/api/ingest`。

> 行号均为克隆仓库中的行号（与 GitHub 主干可能存在小幅偏移）。

---

## 1. EMQX REST API 调用总览：base URL、认证、超时

### 结论

| 项 | 值 |
|---|---|
| 协议/版本 | **只有 EMQX 5.x**（`version.StartsWith("5.")` 才算 supported） |
| 版本前缀 | 所有 REST 业务接口固定前缀 **`/api/v5`**，硬编码在每个调用点 |
| 连通性探测 | **`GET /status`（无 `/api/v5` 前缀、无认证）** |
| base URL 来源 | 用户在配置页/环境变量 `EMQX_URL` 填写，形如 `http://192.168.1.100:18083`；**源码里没有硬编码 18083**，只在 README 示例里出现 |
| base URL 规范化 | `SetCredentials`：不以 `http://`/`https://` 开头 → 前面补 `http://`；再 `.Trim().TrimEnd('/')`。**不改写端口** |
| URL 拼接 | `$"{_baseUrl}{path}"` — 纯字符串拼接，`path` 自带前导 `/`，无 `UriBuilder`、无 `Path.Combine` |
| 认证 | **HTTP Basic**：`Authorization: Basic base64("<apiKey>:<apiSecret>")`。注意 secret 字段存的是 **已拼好的 `key:secret` 整串** |
| Content-Type | 请求体为 JSON 时 `StringContent(jsonBody, Encoding.UTF8, "application/json")` |
| 错误解析 | 非 2xx 时先尝试解析 body 为 `{code, message}`，有 `code` 就用 `code`（如 `BAD_API_KEY_OR_SECRET`），否则退化为 `HTTP_{statusCode}` |
| HttpClient 超时 | `Timeout = 15s`（全局），`ConnectTimeout = 10s`，**`Proxy = null, UseProxy = false`（显式禁用代理）** |
| 单请求超时 | `CancellationTokenSource(timeoutSeconds)`，`DoRequestAsync` 默认 **60 秒**；探测 `/status` 与 `GET /clients` 也走默认 60s |
| 实际生效超时 | 15s（HttpClient）与 60s（CTS）取**先到者** → 实际约 15 秒 |
| 超时错误语义 | `TaskCanceledException` → 错误串 `"请求超时"`；`UriFormatException` → `"未配置 EMQX 连接（URL 无效）"`；`HttpRequestException` → `"网络错误: {msg}"` |
| 无凭据 | `_baseUrl`/`_apiSecret` 任一为空直接返回错误 `"未配置 EMQX 连接（URL 无效）"`，不发请求 |
| 幂等判定 | `ResourceExists(r, name)` = `r.Ok && body 含字面量 "name":"{name}"` |

认证串的拼装发生在**调用方**，不在 `EmqxClient` 内部：

```
Program.cs:88   emqx.SetCredentials(savedUrl, $"{savedKey}:{savedSecret}");
Program.cs:299  var err = await emqx.ConfigureAsync(req.EmqxUrl, $"{req.ApiKey.Trim()}:{req.ApiSecret.Trim()}");
```

### 证据

`EmqxClient.cs:15` — HttpClient 与超时/代理
```csharp
private readonly HttpClient _http = new(new SocketsHttpHandler { Proxy = null, UseProxy = false, ConnectTimeout = TimeSpan.FromSeconds(10) }) { Timeout = TimeSpan.FromSeconds(15) };
```

`EmqxClient.cs:9-12` — 认证方式注释（5.8 实测）
```csharp
/// EMQX v5 REST API 客户端。
/// 认证：API Key（key:secret）走 HTTP Basic Auth（5.8 实测，Dashboard 账号无效）。
```

`EmqxClient.cs:58-65` — base URL 规范化
```csharp
public void SetCredentials(string baseUrl, string apiSecret)
{
    ClearCredentials();
    if (!baseUrl.StartsWith("http://") && !baseUrl.StartsWith("https://"))
        baseUrl = "http://" + baseUrl.Trim().TrimEnd('/');
    _baseUrl = baseUrl;
    _apiSecret = apiSecret;
}
```

`EmqxClient.cs:83-93` — 拼接 + Basic 认证 + 每请求超时
```csharp
private async Task<ApiResult> DoRequestAsync(HttpMethod method, string path, string? jsonBody = null, int timeoutSeconds = 60)
{
    if (string.IsNullOrEmpty(_baseUrl) || string.IsNullOrEmpty(_apiSecret))
        return new ApiResult("未配置 EMQX 连接（URL 无效）", null);
    try
    {
        using var req = new HttpRequestMessage(method, $"{_baseUrl}{path}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(_apiSecret)));
```

`EmqxClient.cs:95-107` — 错误码解析
```csharp
if (!resp.IsSuccessStatusCode)
{
    try
    {
        var err = JsonSerializer.Deserialize<EmqxError>(body);
        if (err?.Code != null) return new ApiResult(err.Code, body);
    }
    catch { }
    return new ApiResult($"HTTP_{(int)resp.StatusCode}", body);
}
```

`EmqxClient.cs:29-53` — 两步配置验证：先无认证探 `/status`，再带 key 验 `/clients?limit=1`
```csharp
SetCredentials(baseUrl, apiSecret);
// 第 1 步：无认证探测 /status，确认地址可达且是 EMQX
var reachable = await ProbeStatusAsync();
...
// 第 2 步：带 key 验证 clients 接口
var test = await GetClientsAsync(limit: 1);
```

`EmqxClient.cs:40-50` — 错误码 → 中文提示映射（Python 侧建议保留同语义）
```csharp
return test.Error switch
{
    "BAD_API_KEY_OR_SECRET" => "API Key 错误：请检查 key:secret 是否正确（Dashboard → 管理 → API 密钥）",
    "HTTP_401" => "认证失败（401）：请检查 API Key",
    "HTTP_404" => "地址不对：EMQX REST API 路径应为 /api/v5（检查 EMQX 版本是否为 5.x）",
    _ => $"连接失败：{test.Error}"
};
```

`EmqxClient.cs:142-146` — `/status` 探测（注意：**不在 `/api/v5` 下**）
```csharp
private async Task<string?> ProbeStatusAsync()
{
    var resp = await DoRequestAsync(HttpMethod.Get, "/status");
    return resp.Ok ? null : $"地址可达但响应异常（HTTP {resp.Error}）：{_baseUrl}/status";
}
```

### 完整调用清单（方法 + 完整路径）

| # | 方法 | 完整路径 | 调用点 |
|---|---|---|---|
| 1 | GET | `/status` | `EmqxClient.cs:144` |
| 2 | GET | `/api/v5/nodes` | `:152`（取版本）、`:207`（取节点指标） |
| 3 | GET | `/api/v5/clients?limit={limit}` | `:171`（默认 `limit=1000`） |
| 4 | GET | `/api/v5/clients/{Uri.EscapeDataString(clientId)}` | `:191` |
| 5 | GET | `/api/v5/clients?username={Uri.EscapeDataString(username)}&limit=10000` | `:290` |
| 6 | POST | `/api/v5/clients/kickout/bulk` | `:340` |
| 7 | GET | `/api/v5/banned?limit=1000` | `:315` |
| 8 | POST | `/api/v5/banned` | `:334` |
| 9 | DELETE | `/api/v5/banned/username/{Uri.EscapeDataString(who)}` | `:347` |
| 10 | GET | `/api/v5/metrics` | `:234` |
| 11 | GET | `/api/v5/alarms?activated=true` | `:264` |
| 12 | GET | `/api/v5/rules` | `:355`（按 name 找 id） |
| 13 | POST | `/api/v5/rules` | `:387` |
| 14 | PUT | `/api/v5/rules/{ruleId}` | `:405` |
| 15 | DELETE | `/api/v5/rules/{ruleId}` | `:414` |
| 16 | GET | `/api/v5/rules/{ruleId}` | `:566` |
| 17 | POST | `/api/v5/bridges` | `:433` |
| 18 | PUT | `/api/v5/bridges/webhook:{bridgeName}` | `:453` |
| 19 | DELETE | `/api/v5/bridges/webhook:{bridgeName}` | `:461` |
| 20 | GET | `/api/v5/bridges/webhook:{bridgeName}` | `:471` |
| 21 | GET | `/api/v5/connectors/http:{bridgeName}` | `:541` |
| 22 | GET | `/api/v5/connectors` | `:619`（自检） |
| 23 | GET | `/api/v5/bridges` | `:620`（自检） |

> 关键点：bridge/connector 的路径里冒号是**类型前缀**，`webhook:{name}` / `http:{name}`，
> 冒号**不能** URL 编码成 `%3A`。clientid、username、who 三个变量才做 `EscapeDataString`。

---

## 2. 连接列表（clients）与分页

### 结论

- **单页拉取，没有分页循环**。`GetClientsAsync(limit)` 只发一次请求，默认 `limit=1000`；`meta.hasnext` 被反序列化但**从不判断**。
- 响应外壳：`{ "data": [ ... ], "meta": { "count", "limit", "page", "hasnext" } }` → `ClientsResponse.Data`。
- 判在线：**不看任何 `connected` 字段**，语义是「出现在 `/clients` 列表里 = 在线」（`GetClientsAsync` 返回的 `result.Clients.Count` 直接就是在线数）。
  模型里虽然定义了 `connected`，采集/统计路径从不读它。离线客户端会从 API 消失 —— 这是增量算法三坑的第一坑。
- 按 username 查 clientid 用的是 `limit=10000`（黑名单踢下线前置查询），同样不分页。
- `client_attrs` 是**容错字典**：EMQX 可能把 `uid` 存成 JSON 数字，默认 `Dictionary<string,string>` 会抛异常导致整次采集崩溃，所以写了 `TolerantStringDictConverter`（number→原始文本、bool→`"true"`/`"false"`、null→空串）。
- 派生字段：`Callsign` = `client_attrs["callsign"]`，`Uid` = `client_attrs["uid"]`；**呼号优先 client_attrs，username 是退路**。

### 读取的字段（`Models.cs:88-136` 的 `[JsonPropertyName]` 全量）

`clientid`、`username`、`connected`、`connected_at`、`created_at`、`ip_address`、`port`、`keepalive`、
`recv_pkt`、`send_pkt`、`recv_cnt`、`send_cnt`、`recv_msg`、`send_msg`、`recv_oct`、`send_oct`、
`recv_msg.qos0`、`recv_msg.qos1`、`recv_msg.qos2`、`send_msg.qos0`、`send_msg.qos1`、`send_msg.qos2`、
`recv_msg.dropped`、`send_msg.dropped`、`inflight_cnt`、`mqueue_len`、`subscriptions_cnt`、
`node`、`proto_ver`、`clean_start`、`client_attrs`。

**实际参与落库的只有**：`clientid`、`client_attrs.callsign`/`uid`（→ Username/Uid）、`send_oct`、`recv_oct`、
`send_msg`、`recv_msg`、`send_pkt`、`recv_pkt`、`ip_address`（`CollectorService.cs:148-163`）。

### 证据

`EmqxClient.cs:169-176` — 单页拉取
```csharp
public async Task<ClientsResult> GetClientsAsync(int limit = 1000)
{
    var resp = await DoRequestAsync(HttpMethod.Get, $"/api/v5/clients?limit={limit}");
    if (resp.Ok)
    {
        var result = JsonSerializer.Deserialize<ClientsResponse>(resp.Body!);
        return new ClientsResult { Clients = result?.Data ?? [] };
```

`Models.cs:73-85` — 响应外壳（`hasnext` 被定义但无人使用）
```csharp
public class ClientsResponse
{
    [JsonPropertyName("data")] public List<EmqxClientInfo> Data { get; set; } = [];
    [JsonPropertyName("meta")] public ClientsMeta? Meta { get; set; }
}
public class ClientsMeta
{
    [JsonPropertyName("count")] public long Count { get; set; }
    [JsonPropertyName("limit")] public int Limit { get; set; }
    [JsonPropertyName("page")] public int Page { get; set; }
    [JsonPropertyName("hasnext")] public bool HasNext { get; set; }
}
```

`CollectorService.cs:116-127` + `:179-181` — 在线数 = 列表长度，无过滤
```csharp
var result = await _emqx.GetClientsAsync();
if (result.Error != null) { ... return; }
var rows = new List<MinuteStatRow>(result.Clients.Count);
...
LastClientCount = result.Clients.Count;
LastClients = result.Clients; // 缓存在线列表（在线页读取；60s 内新鲜）
```

`CollectorService.cs:141-166` — 只读累计计数器做差
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
            IpAddress = c.IpAddress,
            Reconnect = rc,
```

`EmqxClient.cs:287-290` — 按 username 查 clientid（`limit=10000`，不分页）
```csharp
public async Task<List<string>> GetClientsByUsernameAsync(string username)
{
    var list = new List<string>();
    var resp = await DoRequestAsync(HttpMethod.Get, $"/api/v5/clients?username={Uri.EscapeDataString(username)}&limit=10000");
```

`Models.cs:138-142` — client_attrs 容错的原因
```csharp
/// client_attrs 容错字典转换器：EMQX 可能把 uid 存成 JSON 数字，而模型字段是 string，
/// 默认 Dictionary<string,string> 反序列化遇到数字会抛 JsonException，导致整个 /clients 采集崩溃。
```

`Models.cs:124-136` — 派生字段
```csharp
[JsonPropertyName("client_attrs")]
[JsonConverter(typeof(TolerantStringDictConverter))]
public Dictionary<string, string>? ClientAttrs { get; set; }

public string? Callsign
    => ClientAttrs is { } attrs && attrs.TryGetValue("callsign", out var c) ? c : null;
public string? Uid
    => ClientAttrs is { } attrs && attrs.TryGetValue("uid", out var u) ? u : null;
```

`CollectorService.cs:9-11` — 增量算法三坑（Python 必须复刻）
```
///  - 离线客户端从 API 消失，必须在在线时算好 delta 落库
///  - 重连后计数器归零 → delta 为负 → clamp 0 + 标记 reconnect
///  - 新出现的客户端首分钟不计（避免把历史累计算进第一分钟）
```

---

## 3. 黑名单（banned）

### 结论

- 粒度固定 **`as=username`**（拉黑的是呼号，不是 clientid）。
- 【拉黑】`POST /api/v5/banned`，body：`{"as":"username","who":<呼号>,"reason":<原因或null>,"until":<RFC3339 或 "infinity">}`。
  `until` 为 `null` 时**显式写成字符串 `"infinity"`**（永久）。
- `ALREADY_EXISTS` 视为成功（幂等）。
- 【踢下线】EMQX 的 banned **不会自动断开已连接会话**，所以必须第二步主动踢：
  `GET /api/v5/clients?username=<who>&limit=10000` 取 clientid 列表 → `POST /api/v5/clients/kickout/bulk`，
  body 是**裸 JSON 字符串数组**（`JsonSerializer.Serialize(List<string>)`），例如 `["cid1","cid2"]`。
- 【解封】`DELETE /api/v5/banned/username/{who}`；`NOT_FOUND` 视为成功（幂等）。
- 【查询】`GET /api/v5/banned?limit=1000`，**只保留 `as=="username"` 且 `who` 非空**的条目。
- 【集群语义】`by` 字段读取但不用于判断；没有 `node` 字段处理。真正需要注意的是：
  banned 是集群级资源，而**踢下线是逐节点的动作**，「拉黑成功但踢失败」在同一集群里是可能的中间态
  （代码把它报成 `踢下线失败: {err}`，`kicked` 归 0，但 banned 已生效 —— 不回滚）。
- `until` 的生成在 `BlacklistEndpoints.cs:23-34`：前端传本地 `yyyy-MM-ddTHH:mm`，后端转 UTC 但**把本地时区偏移拼回去**
  （形如 `2026-01-01T00:00:00+08:00`），交给 EMQX 自己转 UTC 存储。

### 证据

`EmqxClient.cs:330-342` — 拉黑 + 踢下线两步
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

`EmqxClient.cs:345-350` — 解封幂等
```csharp
public async Task<string?> UnbanAsync(string who)
{
    var resp = await DoRequestAsync(HttpMethod.Delete, $"/api/v5/banned/username/{Uri.EscapeDataString(who)}");
    if (resp.Ok) return null;
    return resp.Error == "NOT_FOUND" ? null : resp.Error; // 已不在黑名单 = 已解封
}
```

`EmqxClient.cs:312-327` — 查询并过滤
```csharp
var resp = await DoRequestAsync(HttpMethod.Get, "/api/v5/banned?limit=1000");
...
if (doc.RootElement.TryGetProperty("data", out var data)) list.AddRange(from b in data.EnumerateArray() let asType = GetStringProp(b, "as") let who = GetStringProp(b, "who") where asType == "username" && !string.IsNullOrEmpty(who) select new BannedEntry { Who = who, Reason = GetStringProp(b, "reason"), Until = GetStringProp(b, "until"), By = GetStringProp(b, "by") });
```

`Models.cs:37-44` — 条目模型（`until` 注释明确 `"infinity"` = 永久）
```csharp
public class BannedEntry
{
    public string Who { get; init; } = "";
    public string? Reason { get; init; }
    public string? Until { get; init; } // RFC3339 或 "infinity"（永久）
    public string? By { get; init; }
}
```

`BlacklistEndpoints.cs:25-34` — until 的时区处理
```csharp
if (!DateTime.TryParseExact(req.Until, "yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var until))
    return Results.Json(new { ok = false, error = "到期时间格式应为 yyyy-MM-ddTHH:mm" });
if (until <= DateTime.Now)
    return Results.Json(new { ok = false, error = "到期时间必须晚于当前时间" });
var offset = TimeZoneInfo.Local.GetUtcOffset(until);
untilRfc = until.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ssK").Replace("+00:00", $"{(offset >= TimeSpan.Zero ? "+" : "-")}{offset:hh\\:mm}");
```

### 两条自动拉黑业务路径（Python 需一并复刻）

1. **包头身份不符 KICK**：`TopicEndpoints.cs:256-282`，调用 `emqx.BanAsync(connCs, reason, null)`（永久），
   失败只打日志不阻断审计落库。触发条件：`verdict=="KICK" && IdentityControlEnabled && connCs 非空`。
2. **UID 重复登录**：`CollectorService.cs:244-321`，**连续 3 轮**（`DupUidConfirmCycles = 3`，约 3 分钟）观察同一 uid 出现多连接才处置，
   避免 EMQX keepalive 窗口（默认 60s）内新旧 clientid 短暂并存被误判。组内呼号已全部在黑名单则不再跟踪。
   理由串模板：`$"身份控制: UID 重复登录（uid={uid} 呼号={...} clientid={...} 持续{rounds}轮）"`。

---

## 4. 节点与指标（健康面板）

### 结论

| 用途 | 方法 + 路径 | 读取字段（JSON 路径） |
|---|---|---|
| EMQX 版本 | `GET /api/v5/nodes` | 取数组首元素（或 `{data:[...]}` 首元素）的 **`version`** |
| 节点指标 | `GET /api/v5/nodes` | `node`、`load1`、`memory_total`、`memory_used` |
| 集群消息计数 | `GET /api/v5/metrics` | **`messages.received`**、**`messages.sent`**（字面量里带点号，是扁平键） |
| 活跃告警 | `GET /api/v5/alarms?activated=true` | `data[].activated == true` 且 `data[].name` 非空 → 去重后逗号拼接 |
| 连接数 | 不查 EMQX 端点 | 直接用本轮 `clients` 列表长度 `LastClientCount` |
| 消息速率 | 本地差分 | `(recv+sent)` 两轮差分 / 秒；**单调不减才计算**（计数器归零→丢弃本轮） |
| EMQX 内存占用率 | 本地算 | `100 * memory_used / memory_total`，clamp 0..100 |
| EMQX CPU | **没有 CPU 字段** | 用 `load1` 代替，落库字段名仍叫 `EmqxCpuPct` |

**响应外壳兼容性**（重要）：`/nodes` 和 `/metrics` 都写了「裸数组 或 `{data:[...]}`」双兼容。
`/metrics` 甚至做了第三层兼容（数组→首元素；`{data:[...]}`→首元素）。
`/alarms` 只认 `{data:[...]}`。

`memory_total`/`memory_used` 是**带单位的字符串**（`"4.69G"` / `"512M"` / `"1234"`），
由 `ParseMemSize` 用正则 `^([\d.]+)\s*([KMGTP]?B?)$` 解析成字节数，支持 `""/B/K/KB/M/MB/G/GB/T/TB`。

自检端点（`CheckCompatibilityAsync`）探测 4 条路径：
`/api/v5/clients?limit=1`、`/api/v5/nodes`、`/api/v5/connectors`、`/api/v5/bridges`；
`404` → "API 不存在——EMQX 版本过低"，其它失败 → "访问失败: {err}（检查 API Key/网络）"。

**没有用到** `/api/v5/stats`、`/api/v5/brokers`、`/api/v5/subscriptions`、`/api/v5/topics` —— 这些在源码里零出现。

### 证据

`EmqxClient.cs:203-229` — 节点解析
```csharp
var resp = await DoRequestAsync(HttpMethod.Get, "/api/v5/nodes");
if (!resp.Ok) return list;
using var doc = JsonDocument.Parse(resp.Body!);
if (!TryGetRootArray(doc.RootElement, out var nodes)) return list;
foreach (var node in nodes)
{
    list.Add(new NodeInfo
    {
        Node = GetStringProp(node, "node"),
        Load1 = node.TryGetProperty("load1", out var l1) && l1.TryGetDouble(out var ld) ? ld : null,
        MemoryTotal = node.TryGetProperty("memory_total", out var mt) ? ParseMemSize(mt) : null,
        MemoryUsed = node.TryGetProperty("memory_used", out var mu) ? ParseMemSize(mu) : null,
    });
}
```

`EmqxClient.cs:232-253` — metrics 三层兼容 + 点号键
```csharp
var resp = await DoRequestAsync(HttpMethod.Get, "/api/v5/metrics");
...
// 数组根（多节点）取第一个；兼容 {data:...} 包装
JsonElement root = doc.RootElement;
if (root.ValueKind == JsonValueKind.Array) { if (!root.EnumerateArray().Any()) return (null, null); root = root[0]; }
else if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array && d.GetArrayLength() > 0) root = d[0];
long? recv = root.TryGetProperty("messages.received", out var mr) && mr.TryGetInt64(out var mrr) ? mrr : null;
long? sent = root.TryGetProperty("messages.sent", out var ms) && ms.TryGetInt64(out var mss) ? mss : null;
```

`EmqxClient.cs:262-279` — 告警
```csharp
var resp = await DoRequestAsync(HttpMethod.Get, "/api/v5/alarms?activated=true");
...
if (a.TryGetProperty("activated", out var act) && act.ValueKind == JsonValueKind.True && a.TryGetProperty("name", out var name) && name.GetString() is { Length: > 0 } n)
    names.Add(n);
...
return string.Join(", ", names.Distinct());
```

`CollectorService.cs:184-221` — 健康快照组装（速率差分 + load1 当 CPU）
```csharp
var health = _health.Collect();
var node = (await _emqx.GetNodesAsync()).FirstOrDefault();
var (recv, sent) = await _emqx.GetMessageCountsAsync();
var alarms = await _emqx.GetActiveAlarmsAsync();
double? msgRate = null;
if (recv.HasValue && sent.HasValue)
{
    var total = recv.Value + sent.Value;
    if (_lastMsgTotal is { } lt && total >= lt)
    {
        var secs = (DateTime.UtcNow - _lastMsgAt).TotalSeconds;
        if (secs > 0) msgRate = (total - lt) / secs;
    }
    _lastMsgTotal = total;
    _lastMsgAt = DateTime.UtcNow;
}
...
EmqxCpuPct = node?.Load1, // EMQX 5.x 无 CPU%，用系统 1 分钟负载（load1）代替
```

`EmqxClient.cs:663-681` — 带单位内存字符串解析
```csharp
var m = System.Text.RegularExpressions.Regex.Match(s.Trim(), @"^([\d.]+)\s*([KMGTP]?B?)$",
    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
...
return m.Groups[2].Value.ToUpperInvariant() switch
{
    "" or "B" => (long)v,
    "K" or "KB" => (long)(v * 1024),
    "M" or "MB" => (long)(v * 1024 * 1024),
    "G" or "GB" => (long)(v * 1024 * 1024 * 1024),
```

`EmqxClient.cs:643-660` — 双外壳兼容工具（Python 需同款 helper）
```csharp
private static bool TryGetRootArray(JsonElement root, out JsonElement.ArrayEnumerator arr)
{
    if (root.ValueKind == JsonValueKind.Array) { arr = root.EnumerateArray(); return true; }
    if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array) { arr = d.EnumerateArray(); return true; }
    arr = default;
    return false;
}
```

---

## 5. 规则引擎与 bridge（FAS 收数据的关键路径）

### 结论：资源命名与前置假设

- 两个**硬编码**名：`TopicBridgeName = "fas-auth-bridge"`、`TopicRuleName = "fas-auth-rule"`（`EmqxClient.cs:21-22`）。
- 用 **EMQX 5.x 的 bridges API**（`type: "webhook"`），**不显式建 connector**。
  源码注释明确：`POST /bridges` 会自动建一个 `type=http`、name 同 bridge 的 backing connector。
  因此链路检查查的是 `GET /api/v5/connectors/http:{bridgeName}`。
- 没有用到 EMQX 5.8+ 的 `/api/v5/actions`（源码里 `V6` 字段恒 `false`，`Models.cs:49-50` 说明是废弃残留）。
- **幂等 upsert 策略**：
  - bridge：`GET /api/v5/bridges/webhook:{name}` 成功且非 null → PUT 更新；否则 POST 创建。
  - rule：`GET /api/v5/rules` 列表按 `name` 线性查找 → 找到 id 则 PUT `/rules/{id}`；否则 POST 创建。
- **顺序强依赖**：先 bridge，后 rule。**bridge 失败则 rule 直接跳过**，failed 里加一条 `"规则：跳过（依赖桥接未就绪）"`。
- **删除顺序相反**：先删 rule，再删 bridge（自动 connector 随 bridge 被 EMQX 清理）。

### 【请求体原文】Bridge 创建 body（`POST /api/v5/bridges`）

```json
{
  "type": "webhook",
  "name": "fas-auth-bridge",
  "description": "FAS topic bridge",
  "url": "<webhookUrl>",
  "method": "post",
  "headers": { "content-type": "application/json", "x-ingest-token": "<ingestToken>" },
  "body": "{\"topic\":\"${topic}\",\"username\":\"${username}\",\"clientid\":\"${clientid}\",\"payload\":\"${payload}\",\"qos\":\"${qos}\",\"client_attrs\":${client_attrs}}",
  "enable": true,
  "max_retries": 2
}
```

> 注意 `body` 是**字符串化 JSON 模板**，字段值为 EMQX 占位符。
> `client_attrs` 前后**故意不加引号**（其余 5 个都加），所以它必须渲染成 JSON 对象/数组，否则整条 body 非法。
> `payload` 已在规则 SQL 里 `base64_encode`，所以这里是 base64 字符串。
> headers 的键是**小写** `content-type` / `x-ingest-token`。

### 【请求体原文】Rule 创建/更新 body（`POST /api/v5/rules` / `PUT /api/v5/rules/{ruleId}`）

同一个模板，创建走 POST、更新走 PUT，两个方法体**字面完全相同**：

```json
{
  "name": "fas-auth-rule",
  "sql": "SELECT clientid, username, topic, base64_encode(payload) as payload, qos, timestamp, client_attrs FROM \"<topic>/#\"",
  "actions": ["webhook:fas-auth-bridge"],
  "enable": true,
  "description": "FAS topic rule"
}
```

> SQL 原文（C# 插值后的形态）：
> `SELECT clientid, username, topic, base64_encode(payload) as payload, qos, timestamp, client_attrs FROM "FMO/RAW/#"`
> 注意 `FROM` 里的主题带**双引号**且加 `/#` 通配。`topic` 默认 `FMO/RAW`（`AppSettings.cs:62`、`CliConfigure.cs:61`）。
> `actions` 数组元素是 **`"webhook:" + bridgeName`**（bridge 类型前缀，**不是** `http:`）。
> 规则 body 里**没有** `timestamp` 输出字段声明——`timestamp` 是 SELECT 出来的列，不是规则配置项。

### 分步日志：步骤名 → 代码位置 → pending/failed 归属

「分步日志」就是 `SetupTopicRuleAsync` 里的 `pending` / `failed` 两个集合，步骤名是**中文字面量**：

| 步骤名 | 触发函数 | 路径 | 成功 | 超时 | 真失败 |
|---|---|---|---|---|---|
| `更新桥接` | `UpsertBridgeAsync` → `UpdateBridgeAsync` | `PUT /api/v5/bridges/webhook:{n}` | 静默 | → `pending` | → `failed` |
| `创建桥接` | `UpsertBridgeAsync` → `CreateBridgeAsync` | `POST /api/v5/bridges` | 静默 | → `pending` | → `failed` |
| `更新规则` | `UpsertRuleAsync` → `UpdateRuleAsync` | `PUT /api/v5/rules/{id}` | 静默 | → `pending` | → `failed` |
| `创建规则` | `UpsertRuleAsync` → `CreateRuleAsync` | `POST /api/v5/rules` | 静默 | → `pending` | → `failed` |
| `规则：跳过（依赖桥接未就绪）` | `SetupTopicRuleAsync` | — | — | — | → `failed` |

- **pending 语义**：「超时 = 状态未知」（集群下请求超时但实际可能成功），**不中断**，只记名待确认。
  判定靠字符串包含：`r.Error!.Contains("超时")`。
- **failed 语义**：真失败，**不中断**（尽力配置），最后统一报告。格式 `"{步骤名}失败: {错误码}"`。
- **回滚**：`SetupTopicRuleAsync` **没有任何回滚**。bridge 成功、rule 失败时 bridge 留在 EMQX 上；
  只有整条链路失败才由调用方决定是否 `RemoveTopicRuleAsync()`（`Program.cs:441-446` 的完全重置路径）。
- **权威状态以查询为准**：`SetupTopicRuleAsync` 返回值注释明确「集群环境下请求状态不可靠，最终以 `GetTopicRuleStatusAsync` 实际查询为准」。
  `POST /api/topic-config` 启用分支里，若 `status.Ok` 就把 pending/failed 清空（`TopicEndpoints.cs:105-106`）。

**⚠️ 已知缺陷（Python 重写应修掉）**：`ToApiResult<T>` 把 `BridgeInfo?/RuleInfo?` 转成 `ApiResult`，
**null 一律变成 `"创建/更新失败"`**，丢掉了底层错误码 —— 于是 `StepAsync` 永远匹配不到 `"超时"`，
**pending 分支实际上是死代码**（`EmqxClient.cs:586-595` 的注释自己承认了这一点）。
Python 侧应让原子 CRUD 返回 `(info, error)` 元组，才能恢复「超时→pending」语义。

### 链路状态判定（`GET /api/topic-test` / 「测试连接」）

`GetTopicRuleStatusAsync` 四件套：
1. connector：`GET /api/v5/connectors/http:{bridgeName}`，存在性靠 **body 含 `"name":"fas-auth-bridge"`**；读 `status`、`status_reason`。
2. bridge：`GET /api/v5/bridges/webhook:{bridgeName}` 非 null。
3. rule：`GET /api/v5/rules` 找 id → `GET /api/v5/rules/{id}` 读 **`enable`**（bool）。

**`Ok` 的完整条件（缺一不可）**：
`ConnectorExists && ConnectorStatus == "connected" && MiddlewareExists && RuleExists && RuleEnabled == true`

> connector 存在但 `disconnected`（EMQX 连不到 webhook）也算链路不通 —— 这是设计上刻意保留的判据。

### 证据

`EmqxClient.cs:21-23` — 硬编码名与 headers 模板
```csharp
private const string TopicBridgeName = "fas-auth-bridge";
private const string TopicRuleName = "fas-auth-rule";
private static Dictionary<string, string> BridgeHeaders(string token) => new() { ["content-type"] = "application/json", ["x-ingest-token"] = token };
```

`EmqxClient.cs:377-390` — Rule SQL 原文 + `webhook:` action
```csharp
private async Task<RuleInfo?> CreateRuleAsync(string ruleName, string bridgeName, string topic)
{
    var ruleBody = JsonSerializer.Serialize(new
    {
        name = ruleName,
        sql = $"SELECT clientid, username, topic, base64_encode(payload) as payload, qos, timestamp, client_attrs FROM \"{topic}/#\"",
        actions = new[] { "webhook:" + bridgeName },
        enable = true,
        description = "FAS topic rule"
    });
    var resp = await DoRequestAsync(HttpMethod.Post, "/api/v5/rules", ruleBody);
```

`EmqxClient.cs:477-482` — connector 自动生成的关键假设
```csharp
// 复用上面的原子 CRUD（Create/Update/Delete Bridge + Create/Update/Delete Rule），
// connector 无需显式建：POST /bridges 会自动建 type=http、name 同 bridge 的 backing connector，
// 其 status 随 bridge 联动，GetTopicRuleStatusAsync 查这个自动 connector(http:{bridgeName}) 即可。
```

`EmqxClient.cs:419-435` — Bridge body 原文
```csharp
private async Task<BridgeInfo?> CreateBridgeAsync(string bridgeName, string hookUrl, string token)
{
    var bridgeBody = JsonSerializer.Serialize(new
    {
        type = "webhook",
        name = bridgeName,
        description = "FAS topic bridge",
        url = hookUrl,
        method = "post",
        headers = BridgeHeaders(token),
        body = "{\"topic\":\"${topic}\",\"username\":\"${username}\",\"clientid\":\"${clientid}\",\"payload\":\"${payload}\",\"qos\":\"${qos}\",\"client_attrs\":${client_attrs}}",
        enable = true,
        max_retries = 2
    });
    var resp = await DoRequestAsync(HttpMethod.Post, "/api/v5/bridges", bridgeBody);
```

`EmqxClient.cs:453` / `:461` / `:471` / `:541` — 冒号类型前缀路径
```csharp
var resp = await DoRequestAsync(HttpMethod.Put, $"/api/v5/bridges/webhook:{bridgeName}", bridgeBody);
var resp = await DoRequestAsync(HttpMethod.Delete, $"/api/v5/bridges/webhook:{bridgeName}");
var resp = await DoRequestAsync(HttpMethod.Get, $"/api/v5/bridges/webhook:{bridgeName}");
var conn = await DoRequestAsync(HttpMethod.Get, $"/api/v5/connectors/http:{TopicBridgeName}");
```

`EmqxClient.cs:488-509` — 编排顺序 + 跳过语义
```csharp
// 1) 桥接：存在则更新，否则创建。存在性以 GET 单资源成功为准（GetBridgeAsync != null）。
var bridgeStep = await UpsertBridgeAsync(pending, TopicBridgeName, webhookUrl, token);
if (!string.IsNullOrEmpty(bridgeStep)) failed.Add(bridgeStep);

// 2) 规则；桥接失败则跳过（依赖未就绪）
if (!string.IsNullOrEmpty(bridgeStep)) { failed.Add("规则：跳过（依赖桥接未就绪）"); }
else { var ruleErr = await UpsertRuleAsync(pending, TopicRuleName, TopicBridgeName, topic); if (ruleErr != null) failed.Add(ruleErr); }

return (null, pending.Count > 0 ? string.Join("、", pending) : null, failed.Count > 0 ? string.Join("；", failed) : null);
```

`EmqxClient.cs:597-609` — 超时→pending / 失败→failed
```csharp
private static async Task<string?> StepAsync(List<string> pending, string stepName, Func<Task<ApiResult>> op)
{
    var r = await op();
    if (r.Ok) return null;
    if (r.Error!.Contains("超时")) { pending.Add(stepName); return null; }
    return $"{stepName}失败: {r.Error}";
}
```

`EmqxClient.cs:586-595` — 自己承认的缺陷：超时语义被吞
```csharp
/// ⚠️ 失败时丢失 DoRequestAsync 的具体错误码/超时分类——原子 CRUD 内部吞了 resp。
/// 这意味着"超时"和"真失败"在此无法区分，统一进 failed。若需保留超时→pending 语义，
/// 应让原子 CRUD 返回 (info, error) 元组而非裸 info。当前为简化首版，统一进 failed。
private static async Task<ApiResult> ToApiResult<T>(Task<T?> op) where T : class
{
    var info = await op;
    return info == null ? new ApiResult("创建/更新失败", null) : new ApiResult(null, null);
}
```

`EmqxClient.cs:536-583` — 四件套状态查询
```csharp
var conn = await DoRequestAsync(HttpMethod.Get, $"/api/v5/connectors/http:{TopicBridgeName}");
status.ConnectorExists = ResourceExists(conn, TopicBridgeName);
if (status.ConnectorExists && conn.Body != null) { ... status.ConnectorStatus = GetStringProp(root, "status"); status.ConnectorReason = GetStringProp(root, "status_reason"); }
...
// Ok 必须包含 connector 连接状态：exists 但 disconnected（EMQX 连不到 webhook）= 链路不通
status.Ok = status is { ConnectorExists: true, ConnectorStatus: "connected", MiddlewareExists: true, RuleExists: true, RuleEnabled: true };
```

`EmqxClient.cs:512-517` — 删除顺序 rule → bridge
```csharp
public async Task<string?> RemoveTopicRuleAsync()
{
    var err = await DeleteRuleAsync(TopicRuleName);
    if (err != null) return err;
    return await DeleteBridgeAsync(TopicBridgeName);
}
```

`EmqxClient.cs:134` — `ResourceExists` 的字面量匹配
```csharp
private static bool ResourceExists(ApiResult r, string name) => r.Ok && !string.IsNullOrEmpty(r.Body) && r.Body!.Contains($"\"name\":\"{name}\"");
```

---

## 6. webhook 接收端 `/api/ingest` 期望的 body 形状

### 结论

- 路由：**`POST /api/ingest`**（FAS 自己监听的口，默认 `http://0.0.0.0:9527`，见 `Program.cs:46,65`）。
- 认证：请求头 **`X-Ingest-Token`**，与 `settings.IngestToken` 做 `CryptographicOperations.FixedTimeEquals` 常量时间比较。
  token 为 32 位大写十六进制（16 随机字节 `Convert.ToHexString`），首次读取时生成并持久化到 `settings.ingest_token`。
  校验失败 → `401 {"ok":false,"error":"invalid token"}`；**token 为空也 401**。
- Content-Type 必须 JSON → 否则 `400 {"ok":false,"error":"bad content type"}`。
- 成功恒返回 `200 {"ok":true}`（**解析异常也只打日志，仍返回 ok:true** —— 不让 EMQX 重投）。

**期望的 body 字段**（即 §5 里 bridge `body` 模板渲染出来的形状）：

| 字段 | 类型 | 用途 |
|---|---|---|
| `topic` | string | 聚合键之一；为空则**整条丢弃** |
| `username` | string \| `"undefined"` | **`"undefined"` 要归一成 null**（Erlang atom 序列化产物） |
| `clientid` | string | 聚合键之一；为空则**整条丢弃** |
| `payload` | string（base64） | `Convert.FromBase64String` 解出原始包 → 字节长度作为计费量；解码失败则退化为**字符串字符数** |
| `qos` | string | 模板里发了，**ingest 侧不读取** |
| `client_attrs` | **JSON object** | 读 `client_attrs.callsign`（呼号）与 `client_attrs.uid` |
| `timestamp` | — | SQL 选出了但**bridge body 模板没有包含它**，ingest 侧不读取 |

> **`client_attrs` 的位置和形状**：顶层字段，值是对象（模板里 `${client_attrs}` 无引号）。
> `uid` 可能是字符串也可能是**数字**：代码用 `cu.ValueKind == String ? GetString() : GetRawText()` 兜住。
> **呼号优先级**：`client_attrs.callsign` 非空时**覆盖** `username`（`TopicEndpoints.cs:43`）。

**时间戳与计数单位**：
- ingest **不读** EMQX 传来的时间戳，用**服务端 `DateTime.Now`**（本地时间，非 UTC）。
- 落库时间戳按 **10 秒颗粒度取整**：`sec = now.Second / 10 * 10` → `yyyy-MM-dd HH:mm:ss`（秒只能是 0/10/20/30/40/50）。
- **单位是「字节」不是「bit」**：`bytes = raw.Length`（base64 解码后长度）。每来一条事件，该 key 的 `MsgCount += 1`、`Bytes += bytes`。
- **聚合键 = (topic, username, uid, clientid, ts10s)**；内存缓冲，**每 10 秒**（`PeriodicTimer(10s)`）`Flush()` 批量 UPSERT 累加进 `topic_stats`。
- `bytes < 0` 或 `topic`/`clientid` 空 → `Ingest` 返回 false 丢弃。

**审计副链路**：`RunIdentityAuditAsync`（`TopicEndpoints.cs:217-310`）在 payload 非空时解 FMO/RAW 包头，
比对包头呼号/UID 与连接身份，产出 `PASS`/`KICK`/`WARN`/`FAIL` 四种 verdict：
- 连接身份为空（匿名）→ `WARN` 仅记录；
- 包头与连接**都匹配** → `PASS` 仅统计；
- 不匹配 → `KICK`，若 `IdentityControlEnabled` 则**永久拉黑该呼号**（`BanAsync(connCs, reason, null)`）；
- 包头非法（长度/len 不符/超 MTU）→ `FAIL` 仅记录，**带限流**：60 秒窗口最多 100 条（防非法包刷库放大）。

### 证据

`TopicEndpoints.cs:14-23` — 路由 + token 常量时间校验
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

`TopicEndpoints.cs:29-56` — 字段读取 + `"undefined"` 归一 + `client_attrs` 位置 + base64 计字节
```csharp
var topic = root.TryGetProperty("topic", out var t) ? t.GetString() : null;
var username = root.TryGetProperty("username", out var u) && u.ValueKind == JsonValueKind.String ? u.GetString() : null;
if (username == "undefined") username = null;   // EMQX 无用户名客户端的 Erlang undefined atom 序列化
// 呼号优先 client_attrs.callsign（认证时服务端写入的属性，比 username 可靠）
string? callsign = null, uid = null;
if (root.TryGetProperty("client_attrs", out var ca) && ca.ValueKind == JsonValueKind.Object)
{
    if (ca.TryGetProperty("callsign", out var cs) && cs.ValueKind == JsonValueKind.String) callsign = cs.GetString();
    if (ca.TryGetProperty("uid", out var cu)) { uid = cu.ValueKind == JsonValueKind.String ? cu.GetString() : cu.GetRawText(); }
}
if (!string.IsNullOrEmpty(callsign)) username = callsign;
var clientid = root.TryGetProperty("clientid", out var c) ? c.GetString() : null;
long bytes = 0;
byte[]? raw = null;
if (root.TryGetProperty("payload", out var p) && p.ValueKind == JsonValueKind.String)
{
    var s = p.GetString()!;
    try { raw = Convert.FromBase64String(s); bytes = raw.Length; }
    catch { bytes = s.Length; }   // 非 base64 则按字符数近似
}
```

`TopicIngestService.cs:62-78` — 10 秒颗粒度 + 累加
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

`TopicIngestService.cs:17,81-107` — 10 秒批量落库
```csharp
private readonly PeriodicTimer _timer = new(TimeSpan.FromSeconds(10));
...
public void Flush()
{
    ...
    _db.WriteTopicStats(rows);
```

`AppSettings.cs:41-53` — token 生成
```csharp
public string IngestToken
{
    get
    {
        var t = _db.GetSetting("ingest_token");
        if (string.IsNullOrEmpty(t))
        {
            t = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            _db.SetSetting("ingest_token", t);
        }
        return t;
    }
}
```

`TopicEndpoints.cs:226-231` — FAIL 限流
```csharp
if (!topicIngest.FailThrottled())
{
    try { db.WriteAuditPacket(new AuditPacketRow { Ts = ts, Topic = topic ?? "", ClientId = clientid ?? "", Verdict = "FAIL", Len = raw.Length }); }
    catch (Exception ex) { Console.Error.WriteLine($"[Audit] FAIL 落库失败: {ex.Message}"); }
}
```

---

## 7. 断开 / 踢客户端

### 结论

- **只有一处踢客户端调用**：`POST /api/v5/clients/kickout/bulk`，body 是**裸 JSON 字符串数组**。
- 它是**批量**接口，被当成「按 username 批量踢」用：先 `GET /api/v5/clients?username=X&limit=10000` 拿 clientid 列表，再整体 POST。
- 用法只有两种，都在 `BanAsync` 里被顺带调用（**没有任何独立暴露的「踢客户端」API 端点**）：
  1. 手工拉黑（`POST /api/blacklist/ban`）；
  2. 自动处置：包头身份不符 KICK、UID 重复登录。
- **没有用到** `POST /api/v5/clients/{clientid}/kickout`（单体踢）—— 源码零出现。
- 踢失败**不回滚**已写入的 banned，只返回 `("踢下线失败: {err}", 0)`。
- 踢成功后，被踢客户端**不会立即**从在线列表消失，靠下一次采集（或 `CollectNowAsync()` 即时刷新）自然消失。

### 证据

`EmqxClient.cs:337-341` — 唯一的 kickout 调用
```csharp
// 2) 查该呼号在线 clientid → 踢下线（banned 不自动踢已连接）
var clients = await GetClientsByUsernameAsync(who);
if (clients.Count == 0) return (null, 0);
var kick = await DoRequestAsync(HttpMethod.Post, "/api/v5/clients/kickout/bulk", JsonSerializer.Serialize(clients));
return kick.Ok ? (null, clients.Count) : ($"踢下线失败: {kick.Error}", 0);
```

`BlacklistEndpoints.cs:42-44` — 拉黑后即时刷新在线缓存
```csharp
// 拉黑后即时刷新在线列表缓存（被踢的客户端立即从"在线"消失）
_ = collector.CollectNowAsync();
return Results.Json(new { ok = true, who, kicked, until = untilLocal });
```

`CollectorService.cs:320` — 为什么不在自动路径里刷新
```csharp
// 被踢客户端下一轮采集自然从 LastClients 消失，无需额外刷新（原 fire-and-forget 会在定时路径并发启动第二次采集，已删除）
```

---

## 8. 硬编码路径前缀、默认端口、版本兼容

### 结论

**路径/名称硬编码清单**

| 常量 | 值 | 位置 |
|---|---|---|
| v5 API 前缀 | `/api/v5` | 每个调用点字面量，无统一常量 |
| 探测端点 | `/status`（**无 v5 前缀、无认证**） | `EmqxClient.cs:144` |
| bridge 名 | `fas-auth-bridge` | `EmqxClient.cs:21` |
| rule 名 | `fas-auth-rule` | `EmqxClient.cs:22` |
| bridge 类型前缀 | `webhook:` | `:453/:461/:471` 路径；`:383` action |
| connector 类型前缀 | `http:` | `:541` |
| 默认主题 | `FMO/RAW` | `AppSettings.cs:62`、`CliConfigure.cs:61`、`TopicEndpoints.cs:89` |
| ingest 头 | `X-Ingest-Token`（接收）/ `x-ingest-token`（bridge headers，小写） | `TopicEndpoints.cs:17` / `EmqxClient.cs:23` |
| 保留主题通配 | `"{topic}/#"` | `EmqxClient.cs:382,400` |
| 规则描述 | `FAS topic rule`；bridge 描述 `FAS topic bridge` | `:385,403` / `:425,445` |

**端口**

| 端口 | 含义 | 来源 |
|---|---|---|
| **18083** | EMQX Dashboard/REST API 默认口 | **只在 README/docs 示例里**：`README.md:48` `http://192.168.1.100:18083`。源码**不写死**，全靠用户填 `EMQX_URL` |
| **9527** | FAS 自己监听的口，也是 webhook `/api/ingest` 的口 | `Program.cs:46` 默认值，环境变量 `EMQX_MONITOR_PORT` 覆盖，`Program.cs:65` `UseUrls($"http://0.0.0.0:{port}")` |

**Webhook URL 的自动构造**（三处，同一模板）：
`http://{GetLanIp()}:{port}/api/ingest`，`GetLanIp()` 用 `UdpClient("8.8.8.8", 80)` 触发路由选择取本机出口 IP
（不发包），失败退 `127.0.0.1`。多网卡场景 `GET /api/topic-config` 还会返回 `local_ips` 全量非回环 IPv4 供人工挑。
用户可在 `POST /api/topic-config` 里传 `webhook_url` 覆盖，覆盖时 `.Trim().TrimEnd('/')`。

**版本兼容处理（源码里到底做了什么）**

1. **支持判定**：`supported = version.StartsWith("5.")`，只认 5.x；不支持时建议文案 `"当前 EMQX 版本不在支持范围。请升级到 EMQX 5.x"`。
2. **版本来源**：`GET /api/v5/nodes` 首元素的 `version` 字段，**进程内缓存**于 `_version`（`ClearCredentials` 时清空）。
   取不到时返回 `null`，上层显示 `"未知"`。
3. **能力探测**（比版本号更可靠）：`CheckCompatibilityAsync` 逐条探 4 个 API，
   **把 404 解释为「EMQX 版本过低」**而不是网络故障。
4. **6.x / 5.8+ actions 的痕迹**：`TopicRuleStatus.V6` **恒为 `false`**，
   `Models.cs:49-50` 注释说明「已废弃，恒 false；保留供前端 app.js 的 s.v6 判断兼容，当前仅支持 5.x bridge」。
   `TopicEndpoints.cs:119,155` 里 `kind = status.V6 ? "action" : "bridge"` 因此**永远输出 `"bridge"`**。
   → **Python 重写只实现 bridge 路径即可，不需要 actions 分支**。
5. **响应外壳兼容**（代替版本判断）：`/nodes`、`/metrics` 双外壳（裸数组 / `{data:[...]}`），
   `TryGetRootArray` 是统一 helper。
6. **`stop`/`restart` 等管理端点**：零使用。
7. 清理提示文案里的资源名与真实资源名**不一致**（历史遗留）：
   `Program.cs:445` 报错说「可稍后手动在 EMQX 删除 emqx-monitor-* 资源」，但实际创建的是 `fas-auth-*`。

### 证据

`EmqxClient.cs:611-630` — 版本判定 + 能力探测
```csharp
public async Task<CompatibilityReport> CheckCompatibilityAsync()
{
    var version = await GetEmqxVersionAsync() ?? "未知";
    var checks = new List<CompatCheck>
    {
        await ProbeApiAsync("客户端列表", "/api/v5/clients?limit=1"),
        await ProbeApiAsync("节点/健康", "/api/v5/nodes"),
        await ProbeApiAsync("规则引擎-连接器", "/api/v5/connectors"),
        await ProbeApiAsync("规则引擎-桥接", "/api/v5/bridges")
    };
    var supported = version.StartsWith("5.");
```

`EmqxClient.cs:148-166` — 版本字段 + 缓存
```csharp
public async Task<string?> GetEmqxVersionAsync()
{
    if (_version != null) return _version;
    var resp = await DoRequestAsync(HttpMethod.Get, "/api/v5/nodes");
    if (!resp.Ok) return null;
    using var doc = JsonDocument.Parse(resp.Body!);
    var root = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement[0] : doc.RootElement;
    _version = GetStringProp(root, "version") ?? "";
```

`Models.cs:47-50` — V6 恒 false
```csharp
public class TopicRuleStatus
{
    /// <summary>是否为 6.x（已废弃，恒 false；保留供前端 app.js 的 s.v6 判断兼容，当前仅支持 5.x bridge）</summary>
    public bool V6 { get; set; }
```

`Models.cs:188-200` — Rule 响应字段（`GET /api/v5/rules/{id}` 与 `POST/PUT` 返回）
```csharp
public class RuleInfo
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("name")] public string Name { get; init; } = "";
    [JsonPropertyName("sql")] public string? Sql { get; init; }
    [JsonPropertyName("actions")] public List<string> Actions { get; init; } = [];
    [JsonPropertyName("from")] public List<string> From { get; init; } = [];
    [JsonPropertyName("enable")] public bool Enable { get; init; }
    [JsonPropertyName("description")] public string? Description { get; init; }
    [JsonPropertyName("metadata")] public JsonElement? Metadata { get; init; }
```

`Models.cs:229-231` — bridge 运行时状态字段（**仅 GET 返回**）
```csharp
[JsonPropertyName("status")] public string? Status { get; init; } // connected / disconnected / connecting / inconsistent
[JsonPropertyName("status_reason")] public string? StatusReason { get; init; }
[JsonPropertyName("node_status")] public JsonElement? NodeStatus { get; init; }
```

`Program.cs:46,65` — FAS 自身端口
```csharp
var port = int.TryParse(Environment.GetEnvironmentVariable("EMQX_MONITOR_PORT"), out var envPort) ? envPort : 9527;
...
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");
```

`TopicEndpoints.cs:94` — webhook URL 默认模板
```csharp
var webhookUrl = string.IsNullOrWhiteSpace(req.WebhookUrl) ? $"http://{GetLanIp()}:{port}/api/ingest" : req.WebhookUrl.Trim().TrimEnd('/');
```

`Program.cs:66-68` — 全局 body 上限 1MB（会限制 ingest 大包）
```csharp
// 全局请求体上限 1MB：所有 POST 端点 body 都很小，防 ingest webhook 超大 body 内存炸弹（Kestrel 默认 30MB）
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(o =>
    o.Limits.MaxRequestBodySize = 1_048_576);
```

---

## 9. Python 重写必须注意的坑

### 认证与连接

1. **Basic 的密码是 `key:secret` 整串，不是 secret**。存 `/api/config` 时分成两个字段，用时拼接。
   Python 直接 `base64.b64encode(f"{key}:{secret}".encode())`，或让 `httpx` 的
   `auth=(api_key, f"{key}:{secret}")` 处理 —— 但**别**写成 `auth=(key, secret)`，那是最常见的移植错误。
   建议 Python 侧显式拼 `Authorization: Basic ...`，避免库差异。
2. **Dashboard 账号无效**（源码 5.8 实测结论），必须用 Dashboard → 管理 → API 密钥创建的 key/secret。
3. **`/status` 无认证、无 `/api/v5` 前缀**。用 `f"{base}/status"` 探活，别探 `/api/v5/status`（不存在）。
4. **base URL 规范化**：补 `http://` 前缀（无 scheme 时）、去掉尾部 `/`。**不要**自作聪明补 `:18083` —— 用户可能用反代/非默认口。
   若用户填了带 `/api/v5` 的 URL，源码不检测也不去重，会拼成 `.../api/v5/api/v5/clients` → 404。Python 侧建议主动 strip 掉尾部的 `/api/v5`。
5. **禁用代理**：源码 `Proxy = null, UseProxy = false`，因为 EMQX 常在内网。Python `httpx.Client(trust_env=False)` 才等价。
   否则 `HTTP_PROXY` 环境变量会把内网请求带偏。
6. **超时**：源码意图 60s，实际被 HttpClient 的 15s 压住。Python 建议明确 `timeout=httpx.Timeout(connect=10, read=15)`，
   并把 `ConnectTimeout`/`ConnectError`/`ReadTimeout` 分开映射到 `"网络错误"` / `"请求超时"`，**这不是同一类错误**（见坑 12）。

### 集群与状态一致性

7. **集群下写操作返回状态不可靠**。源码注释反复强调「集群环境下请求状态不可靠，最终以 `GetTopicRuleStatusAsync` 实际查询为准」。
   Python 侧应保留「配置 → 独立查询复核」两段式，**不要**把 POST/PUT 的返回当作最终结论。
8. **「超时」≠「失败」**：集群下请求超时但操作可能已生效 → 必须记 `pending`，让 `GET /api/topic-test` 复核后再清标记。
   **C# 原版因为 `ToApiResult` 吞错误码导致 pending 分支实际失效**（`EmqxClient.cs:586-595`），Python 侧要修掉：
   让 `create_bridge/update_bridge/create_rule/update_rule` 返回 `(info, error)`，`StepAsync` 才能分辨超时。
9. **banned 是集群级、踢下线是逐节点动作**。可能出现「banned 已生效但某节点连接仍在」。不要因为 kick 失败就回滚 banned。
10. **uid 重复检测的 3 轮确认不能去掉**：EMQX keepalive 默认 60s，设备重连时新旧 clientid 会短暂并存（采集周期也是 60s）。
    去掉确认轮数会大面积误封正常重连的设备。跟踪表在 `uid` 不再重复时要**主动清理**，否则永久误判。

### 分页与上限（最容易踩）

11. **源码完全没有分页循环**：`GetClientsAsync(limit=1000)` 只拿第一页，`meta.hasnext` 读了但不用。
    - 在线 > 1000 时**数据静默丢失**（少算消息/字节），Python 必须实现 while hasnext 翻页
      （EMQX 5.x 分页参数是 `page` + `limit`，`meta.hasnext` 为真时 `page += 1`）。
    - `GetClientsByUsernameAsync` 用 `limit=10000`：单个呼号 1 万个连接时同样截断。
    - 翻页时注意别把「同一客户端跨页重复」算两次 delta —— 用 `clientid` 去重。
12. **`limit` 有服务端上限**（EMQX 5.x 通常 ≤ 10000）。想要更多就翻页，别指望调大 `limit`。
13. **`/banned?limit=1000` 同样不分页** → 黑名单超 1000 条时前端「EMQX 侧对照」会漏。

### URL 编码与路径构造

14. **变量才编码，类型前缀的冒号不要编码**：
    - 编码：`clientid`、`username`（query 参数）、`who`（path 段）→ 用 `urllib.parse.quote(safe='')`。
      C# 的 `Uri.EscapeDataString` 比 `quote` **多转义**一些字符（如 `!`、`'`、`(`、`)`、`*`），
      呼号里一般不含这些，但 clientid 可能含 `|`、`/`、空格 —— `quote(safe='')` 是对的。
    - **不要编码**：路径里的 `webhook:{name}` 和 `http:{name}` 冒号。若用 `requests` 传 `params` 或自己做 `quote`，
      很容易把 `:` 变成 `%3A` → EMQX 返回 404。
    - 主题 `FMO/RAW` 在 SQL 里是**双引号包裹**的标识符（`FROM "FMO/RAW/#"`），不是 URL 参数，**不要**做 URL 编码。
      主题名若含 `"` 会破坏 SQL —— Python 侧应校验/转义。
15. **`client_attrs` 数字陷阱**：EMQX 可能把 `uid` 存成 JSON number。
    Python 的 `dict[str,str]` 类型注解不会报错，但后续 `==` 比较会 `1 != "1"` 静默失配 →
    **必须显式归一**：`str(v) if not isinstance(v, str) else v`，`bool` 要单独处理（`True` → `"true"`，对齐 C# 行为），
    `None` → `""`。这是原版专门写了一个 `JsonConverter` 才解决的问题。
16. **`client_attrs` 缺失/为 null 很常见**（未认证客户端）→ 所有读取都要 `.get()` 兜底，否则整个采集循环崩。
17. **`username` 可能是字面量 `"undefined"`**（Erlang atom 经 JSON 序列化）→ 必须归一成 `None`，否则会凭空多出一个叫 "undefined" 的呼号。

### 计数、时间与单位

18. **时间用服务器本地时间，不是 UTC**。ingest 用 `DateTime.Now`，采集用 `DateTime.Now` 写 `yyyy-MM-dd HH:mm:00`。
    只有消息速率的差分用 `UtcNow`（因为只算差值）。Python 用 `datetime.now()`，**不要**用 `time.time()` 或 `utcnow()` 混用。
19. **单位是字节（octet）不是 bit**，字段名 `recv_oct`/`send_oct` 会误导人。ingest 的 `bytes` 是 base64 解码后长度。
20. **10 秒颗粒度是本地计算出来的**：`sec = now.second // 10 * 10`，EMQX 传来的 `timestamp` 被丢弃。
    Python 侧若改成读 EMQX timestamp 会与历史数据不一致（时区/秒取整都不同）。
21. **delta 必须 clamp 到 0 并标记 reconnect**：客户端重连后累计计数器归零，`cur - prev` 为负。
    直接存负数会污染排行和总量。
22. **新出现的 clientid 首轮不落库**（只建立基线），否则会把「从进程启动以来的历史累计」当成第一分钟增量，产生巨量尖峰。
    这条与「离线客户端从列表消失」叠加后，意味着**必须维护跨轮 `clientid → 计数器` 字典**。
23. **`/metrics` 的 `messages.received`/`messages.sent` 是带点号的扁平键**，Python 不要按 `root["messages"]["received"]` 取。
    同时它是**多节点数组**，取首元素只是近似 —— 若真实集群多节点，应按节点求和（原版只取第一个节点，是已知的数据低估）。
24. **告警名去重后逗号拼接**成单个字符串存一列（`", "` 分隔），不是数组。

### 接收端安全

25. **`/api/ingest` 的 token 比较必须常量时间**（`hmac.compare_digest`），且**长度不等时会抛异常**：
    C# 的 `FixedTimeEquals` 对长度不等返回 false，Python 的 `hmac.compare_digest` 对 `str` 含非 ASCII 会报错、
    对长度不等返回 False。用 `hmac.compare_digest(got.encode(), token.encode())` 更稳。**token 为空必须直接 401**。
26. **ingest 恒返回 200 `{"ok":true}`，即使内部解析失败**（只记日志）。这是刻意的：返回 4xx/5xx 会让 EMQX 规则引擎重投，
    放大故障。Python 侧保留此语义，但**要保留日志**，否则数据静默丢失无法排查。
27. **必须同步读 body**：源码注释「异步 Task.Run 读 Request.Body 在响应返回后不可读」。
    Python/FastAPI 侧同理 —— 不要在 `BackgroundTasks` 里读 `request.body()`。
28. **1MB 全局 body 上限**（`Program.cs:67-68`）：FMO/RAW 大包 + base64 膨胀 33%，
    MTU 级别包没问题，但若有人把大文件发到这个主题会 413。Python 侧应显式设 `max_body_size` 并对超限返回明确错误。
29. **FAIL 事件限流 60s/100 条**：防攻击者用非法包刷爆 `audit_packets`。Python 必须复刻，否则这是一个可被利用的写入放大面。

### 幂等与清理

30. **`ALREADY_EXISTS`（拉黑）与 `NOT_FOUND`（解封、删 bridge）都要当成功**。EMQX 的错误用 `code` 字段表达，
    Python 侧要解析 body 的 `code` 而不是只看 HTTP status（EMQX 可能 400 + code=`ALREADY_EXISTS`）。
    删 bridge 时源码检查的是 `resp.Error.Contains("404") || Contains("NOT_FOUND")`，说明两种形态都出现过。
31. **删除顺序 rule → bridge**，创建顺序 bridge → rule。反了会留下孤儿 bridge 或 rule 引用不存在的 bridge。
    自动生成的 connector 不需要手动删，EMQX 随 bridge 一起清理；但**不要**试图 `DELETE /api/v5/connectors/http:{name}`，
    backing connector 是 bridge 的附属物。
32. **`ResourceExists` 用字符串包含 `"name":"{name}"` 判定**，对 JSON 空白敏感。
    Python 侧应改用 `json.loads(body).get("name") == name`，更健壮（但要注意单资源 GET 返回**裸对象**、
    列表 GET 返回 `{data:[...]}`，两种外壳都要处理）。
33. **规则幂等靠 name 线性查找**：`GET /api/v5/rules` 列表里遍历比对 `name`。
    同名多条时只取第一条。Python 侧建议同样的策略，或直接按 name 做 upsert 并记录 id 缓存。
34. **自检的错误归因**：404 → 「版本过低」，401 → 「认证/API Key」，其它 → 「网络」。Python 侧保留这个三分法，
    否则运维排障时会误导（把「密钥错」当成「版本不对」）。

### 版本与兼容

35. **只实现 EMQX 5.x bridge 路径**。`V6`/actions 是死代码，`kind` 永远输出 `"bridge"`。
    Python 侧不必为 6.x 写分支，但建议在 `/api/check` 里保留 `version` 解析与 `supported = version.startswith("5.")`，
    这样升级 EMQX 6 时能明确报出「不支持」而不是诡异 404。
36. **`/api/v5/nodes` 取版本时首元素可能是任意节点**，集群内版本应一致；不一致时源码取巧。Python 侧若做严格校验应检查所有节点。
37. **`memory_total`/`memory_used` 是带单位字符串**，正则 `^([\d.]+)\s*([KMGTP]?B?)$` 不匹配时返回 `None`（不要抛异常）。
    Python 侧还有个隐藏坑：某些 JSON 库会把 `"4.69G"` 当字符串没问题，但如果 EMQX 某版本返回纯数字，
    `el.GetString()` 在 C# 里会返回 null/抛异常 —— Python 侧要同时接受 `str` 和 `int/float`。
