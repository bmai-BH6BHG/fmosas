# BAS 融合架构（目录与模块边界）

> 目标：把 **FAS（.NET，4098 行 C#）的审计能力用 Python 重写进分系统**，形成单一系统 BAS：
> 单进程、单端口、单登录、单 SQLite、单 systemd 服务，不再依赖 .NET / 45MB 二进制 / 第二个 9527 端口。

## 1. 进程与端口

| 项 | 融合前 | 融合后（BAS） |
|---|---|---|
| 进程 | `api_server.py`（Py）+ `fmo-audit-service`（.NET） | 仅 `api_server.py`（Py） |
| systemd | `fmo-subsystem` + `fmo-fas` | 仅 `fmo-subsystem`（兼容旧名 `fmo-bas`） |
| 端口 | 35928 公网 + 35929 管理 + 9527 审计 | 35928 公网 + 35929 管理（审计页面走管理口 `/admin`） |
| 数据库 | `{domain}_users.db`、`{domain}_sas.db`、`fmo-audit-service.db` | `{domain}_users.db`、`{domain}_sas.db`、`{domain}_audit.db` |
| 登录 | 分系统管理后台（localStorage API 地址）；FAS 独立管理员 | 一套管理员（BAS Admin），管理口统一鉴权 |

> 公网口（35928）仍只放行 APP/同步/`/auth` 白名单；审计与黑名单等管理类接口只在管理口（35929）。

## 2. 模块布局（新增文件，均置于仓库根，与现有扁平结构一致）

| 文件 | 职责 | 对应 FAS 源码 |
|---|---|---|
| `bas_fmo_parser.py` | FMO/RAW 64 字节包头解析 + CRC32 | `FmoRawParser.cs`（116 行） |
| `bas_audit_db.py` | 审计库 schema、分桶统计、保留清理、管理员与会话、黑名单留痕 | `Database.cs`（1158 行）、`AuthService.cs` |
| `bas_emqx.py` | EMQX REST 客户端：clients/banned/nodes/metrics、规则引擎 bridge、踢客户端 | `EmqxClient.cs`（696 行） |
| `bas_collector.py` | 轮询采集：探活、增量、排行榜、重连标记、重复身份检测、自动处置 | `CollectorService.cs`（336 行） |
| `bas_ingest.py` | webhook 接收与逐包身份判决（KICK/WARN/FAIL）+ 主题分桶 | `TopicEndpoints.cs`、`TopicIngestService.cs` |
| `bas_health.py` | 主机资源 + EMQX 节点健康采集 | `HostHealthCollector.cs` |
| `bas_endpoints.py` | 全部 `/api/*` 路由与页面渲染挂载（并入 ApiHandler） | `Program.cs` 路由段 |
| `admin/bas.html` 等 | 审计界面（导航并入现有管理后台） | `wwwroot/*`（重写，风格对齐） |

**不改动的部分**：`sas_server.py`（SAS 认证与证书链，已是 `client_attrs` 来源）、`sync_engine.py`、
`monitor.py`、注册/登录接口。BAS 只是在同一进程内新增审计子系统。

## 3. 数据流（融合后）

```
APP ──MQTT──► EMQX ──HTTP 认证──► :35928 /auth (SAS, 已有)
                                    └─ 返回 client_attrs{callsign,uid} —— 身份唯一真相
EMQX 规则引擎(FMO/RAW) ──webhook──► :35929 /api/ingest  (X-Ingest-Token)
                                    └─ bas_ingest: 解析 64B 包头 → 判决
                                        ├─ 一致 → 正常计数
                                        ├─ 不一致 → KICK(事件留痕) + EMQX 拉黑
                                        └─ 非法包 → FAIL 留痕
EMQX REST ──轮询──► bas_emqx → bas_collector → bas_audit_db（在线/排行榜/重复身份检测）
管理口 :35929 /admin/bas/* ──► 审计界面（在线、主题统计、黑名单、健康、设置）
```

## 4. 迁移与兼容

* 上游 `fmo-audit-service.db` 若存在，安装时可选导入（settings/blacklist/统计表结构对齐后再迁移）。
* 旧 FAS 服务单元（`fmo-fas`）在融合安装时自动停用并删除，避免占用 9527 与重复拉黑。
* 保留 `FAS_UPDATE_URL` 语义：BAS 的 OTA 升级元数据由本项目发布源提供，默认不再指向 `bg5esn.com`。

## 5. 验收基线（对照上游，不能走样）

| 能力 | 验收方式 |
|---|---|
| 包头解析 | 移植 `CoreLogicTests.cs` 全部用例（合法包字段、<72、>1400、len 不符、零截断、CRC 仅标记） |
| CRC32 | zlib 标准向量 `"123456789" → 0xCBF43926`、空 → 0 |
| 版本比较 | `UpdateServiceVersionTests` 5 组向量 |
| client_attrs 容错 | 移植 `ConverterAndWebTests.cs`（数字/布尔/null/缺失） |
| 身份判决 | 契约测试覆盖判决表全部分支（一致/呼号不符/uid 不符/无属性/非法包） |
| 自动拉黑 | 端到端：伪造包头 → 断言产生 KICK 事件 + 调用拉黑 + 留痕 |
| 分桶统计 | 10 秒对齐、粒度切换（10s/1m/5m/1h）聚合值一致 |
| 单进程 | `ps` 只有 python；`ss -lntp` 只有 35928/35929 |
