# FAS（fmo-audit-service）Web 界面与路由契约

> 目的：把 FAS（.NET 8 Minimal API + 嵌入式 wwwroot 静态页）的**界面与路由契约**抽取出来，供 FMO 分系统（Python，`api_server.py` + `admin/index.html`）并入时照抄语义、重写实现。
>
> 源码：`C:\Users\Administrator\AppData\Local\Temp\fas-clone`（仓库 BG5ESN/fmo-audit-service）
> 审计对象：`Program.cs`(479 行)、`BlacklistEndpoints.cs`、`TopicEndpoints.cs`、`UpdateEndpoints.cs`、`WebHelpers.cs`、`AuthService.cs`、`AppSettings.cs`、`Models.cs`、`Database.cs`(行对象)、`wwwroot/*`(11 个 HTML + style.css 199 行 + app.js 1482 行)
> 本文只读源码得出，未修改任何源码文件，唯一产出为本文件。
>
> **约定**：`文件:行号` 指上述源码；`app.js 函数名` 指 `wwwroot/app.js` 内的函数。JSON 字段名按 app.js 实际读取的写法给出（服务端 C# PascalCase 属性经 System.Text.Json Web 默认策略输出为 camelCase，源码里已写死的下划线名如 `is_anonymous` 原样输出）。

---

## 0. 总体结论

**结论**

- FAS 是一个**多页应用（MPA）**：11 个独立 HTML 页面，全部共用一份 `/style.css` + `/app.js`；`app.js` 用 `location.pathname` 分派到各页初始化函数（`app.js:6`、`app.js:196/341/472/822/900/999/1062/1070`）。
- 认证是 **Cookie 会话 + 全站中间件门控**，不是每端点特性；35 个 JSON 端点里只有 2 个（`/api/setup`、`/api/login`）+ 1 个 webhook（`/api/ingest`）能在未登录时到达（`Program.cs:140-201`）。
- 前端**没有任何分页**：全部靠服务端 `limit`（前端固定 200/300）+ 客户端渲染；排序由 `order`/`verdict`/`bucket` 等 query 参数切换（`app.js:257/547/953`）。
- 全站自动刷新是 **30 秒**（不是 60 秒）；60 秒是**服务端采集周期**与**文案**（`app.js:332/807/890/994`；`CollectorService.cs:79`）。
- 页面语言：**浅色 Metro 白底灰框直角扁平**（`style.css:1-2`，`border-radius: 0 !important`），与分系统 `admin/index.html` 的**深色霓虹科技风**（`#0a0e1a` / `#00e5ff`）风格相反——并入时必须重绘，不能直抄 CSS。

**证据**：`Program.cs:60-209`（嵌入式 wwwroot、中间件顺序）；`wwwroot/style.css:1-2`；`app.js:2,6`。

---

## 1. 完整路由表与认证门控

### 1.1 结论

**认证门控规则（4 条放行线 + 2 种拒绝）**，按顺序判断（`Program.cs:140-201`）：

1. **静态资源白名单（无需任何认证）**：路径以 `.css` 结尾、以 `.js` 结尾、或等于 `/favicon.ico` → 直接放行（`Program.cs:147-151`）。
   - 注意：这是**字符串后缀**判断，`/anything.css`、`/api/x.js` 都会被放行；`.html` **不在**白名单，所以每个 HTML 页面都受门控保护。
2. **Webhook 白名单**：`path == "/api/ingest"` → 放行，token 校验在端点内（`Program.cs:154-158`；`TopicEndpoints.cs:14-23`）。
3. **未初始化（DB 里还没有管理员）**：
   - 只放行 `/setup.html` 与 `/api/setup`（`Program.cs:160-166`）；
   - 其他 `/api/*` → **401 JSON** `{ok:false,error:"系统未初始化，请先设置管理员账号"}`（`Program.cs:167-172`）；
   - 其他一切 → **302 跳 `/setup.html`**（`Program.cs:173-174`）。
4. **已初始化但未登录**：
   - 只放行 `/login.html` 与 `/api/login`（`Program.cs:177-182`）；
   - 其他 `/api/*` → **401 JSON** `{ok:false,error:"未登录"}`（`Program.cs:184-189`）；
   - 其他一切 → **302 跳 `/login.html`**（`Program.cs:190-191`）。
5. **已登录**：访问 `/login.html` 或 `/setup.html` → **302 跳 `/`**（`Program.cs:195-199`）；其余放行。

其他全局行为：
- 中间件顺序：`UseForwardedHeaders` → `UseAuthentication` → 安全响应头 → 门控 → `UseAuthorization` → `UseDefaultFiles/UseStaticFiles`（`Program.cs:127-209`）。因此 `/` 的路由解析（default file → `index.html`）发生在门控**之后**，未登录访问 `/` 会被 302 到登录页。
- 安全响应头：`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`（`Program.cs:131-137`）。
- 全局请求体上限 1 MB `MaxRequestBodySize = 1_048_576`（`Program.cs:67-68`）。
- Cookie：24 小时，`SlidingExpiration=false`，`HttpOnly=true`，`SecurePolicy=SameAsRequest`，`LoginPath=/login.html`，SameSite 用默认 Lax（`Program.cs:114-122`）。
- `/api/ingest` 的 token 来源：`settings.ingest_token`（首次读取随机生成 32 位十六进制并持久化，`AppSettings.cs:41-53`），请求头名 **`X-Ingest-Token`**，用 `CryptographicOperations.FixedTimeEquals` 定长比较；token 为空或缺失或不匹配 → 401 `{ok:false,error:"invalid token"}`；非 JSON Content-Type → 400 `{ok:false,error:"bad content type"}`（`TopicEndpoints.cs:16-23`）。

### 1.2 页面与静态资源（14 条）

| # | 方法 | 路径 | 类型 | 认证要求 | 用途 | 证据 |
|---|------|------|------|----------|------|------|
| 1 | GET | `/` | 页面（default file → `index.html`） | 需登录（未登录 302 `/login.html`） | 排行榜首页 | `Program.cs:173-199,208`；`index.html:1-78` |
| 2 | GET | `/index.html` | 页面 | 需登录 | 排行榜（`app.js` 识别 `/` 与 `/index.html` 两种写法） | `app.js:196` |
| 3 | GET | `/topics.html` | 页面 | 需登录 | 主题统计 | `topics.html:1-92`；`app.js:472` |
| 4 | GET | `/online.html` | 页面 | 需登录 | 在线客户端列表 | `online.html:1-58`；`app.js:822` |
| 5 | GET | `/audit.html` | 页面 | 需登录 | 身份审计（包头身份一致性事件） | `audit.html:1-81`；`app.js:900` |
| 6 | GET | `/blacklist.html` | 页面 | 需登录 | 黑名单（生效 + 操作历史） | `blacklist.html:1-79`；`app.js:999` |
| 7 | GET | `/health.html` | 页面 | 需登录 | 健康（宿主机 + EMQX 曲线） | `health.html:1-65`；`app.js:341` |
| 8 | GET | `/settings.html` | 页面 | 需登录（未初始化时是唯一可进的页） | 配置（EMQX / 主题统计 / 身份控制 / 自检 / 数据管理 / 密码 / OTA / 运行信息） | `settings.html:1-202`；`app.js:1070` |
| 9 | GET | `/help.html` | 页面 | 需登录 | 说明（纯静态文案，无 API） | `help.html:1-84`；`app.js:1062-1066` |
| 10 | GET | `/login.html` | 页面 | 未登录时放行；已登录 302 `/` | 登录（内联脚本，不加载 app.js） | `Program.cs:179`；`login.html:27-48` |
| 11 | GET | `/setup.html` | 页面 | 未初始化时放行；已登录 302 `/` | 初始化管理员（内联脚本） | `Program.cs:162,195`；`setup.html:31-48` |
| 12 | GET | `/style.css` | 静态资源 | **无需认证**（`.css` 白名单） | 全站样式 | `Program.cs:147`；`style.css:1-199` |
| 13 | GET | `/app.js` | 静态资源 | **无需认证**（`.js` 白名单） | 全站前端逻辑 | `Program.cs:147`；`app.js:1-1482` |
| 14 | GET | `/favicon.ico` | 静态资源 | **无需认证**（显式白名单） | 站点图标（wwwroot 无此文件，实际 404） | `Program.cs:147` |

### 1.3 JSON API / Webhook（35 条，按路径排序）

| # | 方法 | 路径 | 类型 | 认证要求 | 请求（query / body） | 响应关键字段 | 用途 | 证据 |
|---|------|------|------|----------|----------------------|--------------|------|------|
| 1 | GET | `/api/admin/clear-data` → **POST** | JSON API | 需登录 | 无 | `ok`、`cleared{minute_stats,topic_stats,health_snapshots,audit_packets}` | 一键清空统计数据（保留管理员与 EMQX 配置） | `Program.cs:431-435` |
| 2 | POST | `/api/admin/reset` | JSON API | 需登录 | 无 | `ok`、`error` | 完全重置：删管理员+配置+数据、移除 EMQX 规则引擎 | `Program.cs:438-456` |
| 3 | GET | `/api/admin/stats` | JSON API | 需登录 | 无 | `ok`、`minute_stats`、`topic_stats`、`health_snapshots`、`audit_packets` | 各表数据量 | `Program.cs:424-428` |
| 4 | GET | `/api/audit-packets` | JSON API | 需登录 | `from`,`to`(必需,`yyyy-MM-ddTHH:mm`)；`verdict`(可选 `KICK`/`WARN`/`FAIL`)；`limit`(默认 200，夹取 1..1000) | `ok`、`from`、`to`、`rows[]`、`counts{KICK,WARN,FAIL}` | 包头审计事件列表 | `BlacklistEndpoints.cs:103-110` |
| 5 | POST | `/api/blacklist/ban` | JSON API | 需登录 | body `{who, reason, until}`，`until` 为本地 `yyyy-MM-ddTHH:mm` 或 null（永久） | `ok`、`who`、`kicked`(踢下线数)、`until`、`error` | 拉黑呼号 + 立即踢下线 + 留痕 | `BlacklistEndpoints.cs:15-45` |
| 6 | GET | `/api/blacklist/active` | JSON API | 需登录 | 无 | `ok`、`local[]{who,reason,until,operator,createdAt}`、`emqx_only[]{who,reason,until,by}`、`emqx_reachable` | 当前生效黑名单（本地推导 + EMQX 对照） | `BlacklistEndpoints.cs:67-81` |
| 7 | GET | `/api/blacklist/history` | JSON API | 需登录 | `limit`(默认 200，夹取 1..1000) | `ok`、`rows[]{action,asType,who,reason,until,operator,createdAt}` | 黑名单操作流水（倒序） | `BlacklistEndpoints.cs:84-85` |
| 8 | POST | `/api/blacklist/unban` | JSON API | 需登录 | body `{who}` | `ok`、`who`、`error` | 解封 + 留痕 | `BlacklistEndpoints.cs:48-64` |
| 9 | POST | `/api/change-password` | JSON API | 需登录 | body `{oldPassword,newPassword}` | `ok`、`error` | 修改管理员密码（旧密码走登录校验，失败计入锁定） | `Program.cs:272-278`；`AuthService.cs:104-112` |
| 10 | GET | `/api/check` | JSON API | 需登录 | 无 | `ok`、`version`、`supported`、`suggested_upgrade`、`checks[]{name,path,ok,note}`、`error` | EMQX 版本 + 关键 API 兼容性自检 | `Program.cs:370-383` |
| 11 | GET | `/api/config` | JSON API | 需登录 | 无 | `ok`、`configured`、`emqx_url`、`listen_port`、`data_retention_days`、`status`、`online_clients`、`last_collect_ok` | 读取运行配置（**不含** API Key/Secret） | `Program.cs:282-292` |
| 12 | POST | `/api/config` | JSON API | 需登录 | body `{emqxUrl,apiKey,apiSecret}` 全非空 | `ok`、`error` | 保存并测试 EMQX 连接；成功即置 `wizard_done=1` | `Program.cs:294-308` |
| 13 | POST | `/api/config/disconnect` | JSON API | 需登录 | 无 | `ok` | 断开监控并清空 EMQX 凭据 | `Program.cs:310-317` |
| 14 | GET | `/api/export.csv` | JSON API（CSV 文本） | 需登录 | `from`,`to`(必需)；`order`(`oct`默认/`msg`/`pkt`) | `text/csv; charset=utf-8`，带 BOM；表头 `排名,呼号,设备数,总字节,总消息,总包数,重连次数`；**上限固定 5000 行**；范围非法时返回 JSON `{ok:false,error}` | 排行榜 CSV 导出 | `Program.cs:349-362`；`WebHelpers.cs:20-25` |
| 15 | GET | `/api/health` | JSON API | 需登录 | `from`,`to` | `ok`、`from`、`to`、`rows[]` | 健康快照时间序列（宿主机 + EMQX） | `Program.cs:339-345` |
| 16 | POST | `/api/identity-control` | JSON API | 需登录 | body `{enabled:bool}` | `ok`、`enabled` | 身份控制开关（关闭=仅记录不自动拉黑） | `BlacklistEndpoints.cs:95-100` |
| 17 | GET | `/api/identity-control` | JSON API | 需登录 | 无 | `ok`、`enabled` | 读取身份控制开关（默认 true） | `BlacklistEndpoints.cs:88-92` |
| 18 | POST | `/api/ingest` | Webhook | **无需登录**，需 `X-Ingest-Token` 定长匹配 | body（EMQX 规则引擎事件 JSON）`{topic,username,clientid,payload(base64),client_attrs{callsign,uid}}` | `ok`；token 错→401 `{ok:false,error:"invalid token"}`；非 JSON→400 | 主题统计消息事件入口（含身份审计） | `TopicEndpoints.cs:14-68` |
| 19 | GET | `/api/leaderboard` | JSON API | 需登录 | `from`,`to`(必需)；`order`(`oct`默认/`msg`/`pkt`)；`limit`(默认 100，夹取 1..1000) | `ok`、`from`、`to`、`order`、`rows[]` | 呼号流量排行榜 | `Program.cs:321-327` |
| 20 | GET | `/api/leaderboard/{name}` | JSON API | 需登录 | 路径 `name`(呼号或匿名 clientid)；`from`,`to` | `ok`、`name`、`from`、`to`、`rows[]` | 某呼号下 clientid 小时段明细 | `Program.cs:329-335` |
| 21 | POST | `/api/login` | JSON API | 未登录时放行；已登录也可到达 | body `{username,password}` | `ok`、`error`；成功时下发认证 Cookie | 管理员登录 | `Program.cs:251-264` |
| 22 | POST | `/api/logout` | JSON API | 需登录 | 无 | `ok` | 退出登录（清 Cookie） | `Program.cs:266-270` |
| 23 | GET | `/api/online` | JSON API | 需登录 | 无 | `ok`、`collecting`、`updated_at`、`total`、`rows[]` | 当前在线客户端（**读采集器 60s 缓存，不打 EMQX**） | `Program.cs:386-413`；`CollectorService.cs:79,180-181` |
| 24 | POST | `/api/setup` | JSON API | **仅未初始化时放行**；已初始化且已登录 → 返回“系统已初始化…” | body `{username,password}` | `ok`、`error` | 创建首个管理员 | `Program.cs:244-249`；`AuthService.cs:34-44` |
| 25 | GET | `/api/status` | JSON API | 需登录 | 无 | `ok`、`version`、`initialized`、`configured`、`collecting`、`wizard_done`、`last_status`、`last_collect_ok`、`last_error`、`online_clients` | 服务状态（页头状态条 / 引导判断 / 登录后跳转） | `Program.cs:230-242` |
| 26 | POST | `/api/topic-config` | JSON API | 需登录 | body `{enable:bool, topic, webhookUrl}`（`enable:false` 时后两者可省） | `ok`、`enabled`、`topic`、`webhook_url`、`pending`、`failed`、`status{ok,connector{exists,state,reason},middleware{exists,kind},rule{exists,enabled}}`、`hint`、`error` | 启用/停用主题统计（自动配置 EMQX 规则引擎四件套） | `TopicEndpoints.cs:87-136` |
| 27 | GET | `/api/topic-config` | JSON API | 需登录 | 无 | `ok`、`enabled`、`topic`、`webhook_url`、`ingest_url`、`local_ips[]`、`total_ingested`、`last_ingest_at`、`ingest_token`、`pending`、`failed` | 主题统计状态（含 webhook 地址与本机 IP 列表） | `TopicEndpoints.cs:71-84` |
| 28 | GET | `/api/topic-export.csv` | JSON API（CSV 文本） | 需登录 | `from`,`to`(必需)；`order`(`msg`默认/`bytes`) | `text/csv; charset=utf-8` BOM；表头 `排名,呼号,设备数,消息数,字节数,主题`；上限 5000 行 | 主题统计排行 CSV | `TopicEndpoints.cs:198-212` |
| 29 | GET | `/api/topic-leaderboard` | JSON API | 需登录 | `from`,`to`；`order`(`msg`默认/`bytes`)；`limit`(默认 100，夹取 1..1000) | `ok`、`topic`、`from`、`to`、`order`、`rows[]` | 主题（FMO/RAW）发包排行 | `TopicEndpoints.cs:165-172` |
| 30 | GET | `/api/topic-leaderboard/{name}` | JSON API | 需登录 | 路径 `name`；`from`,`to` | `ok`、`name`、`topic`、`from`、`to`、`rows[]` | 某呼号在主题上的 clientid 明细 | `TopicEndpoints.cs:175-182` |
| 31 | GET | `/api/topic-test` | JSON API | 需登录 | 无 | `ok`、`status{ok,v6,connector{...},middleware{exists,kind},rule{...}}`、`dashboard_hint`、`error` | 测试主题统计链路（EMQX 侧真实状态） | `TopicEndpoints.cs:139-162` |
| 32 | GET | `/api/topic-timeline` | JSON API | 需登录 | `from`,`to`(必需)；`bucket`(`10s`/`1m`/`5m`/`1h`，其他值归一为 `1m`) | `ok`、`topic`、`from`、`to`、`bucket`、`rows[]`；补零后 >40000 点 → `{ok:false,error:"时间范围过大（补零后超过 4 万点）…"}` | 全员发包时间轴（含每桶 Top8 呼号） | `TopicEndpoints.cs:185-195`；`Database.cs:611-720` |
| 33 | POST | `/api/update/apply` | JSON API | 需登录 | 无 | `ok`、`started`、`error` | 启动自更新（Docker 模式直接拒绝） | `UpdateEndpoints.cs:30-59` |
| 34 | GET | `/api/update/check` | JSON API | 需登录 | 无 | `ok`、`current`、`latest`、`has_update`、`update_mode`(`self`/`docker`/`manual`)、`docker_hint`、`error` | 检查更新 | `UpdateEndpoints.cs:11-27`；`UpdateService.cs:47-52` |
| 35 | GET | `/api/update/progress` | JSON API | 需登录 | 无 | `ok`、`stage`(`idle`/`checking`/`downloading`/`extracting`/`preparing`/`ready`/`done`/`error`)、`percent`、`bytes_read`、`total_bytes`、`message` | 更新进度（前端 300ms 轮询） | `UpdateEndpoints.cs:62-74`；`UpdateService.cs:91-217` |

**行对象字段（服务端 → camelCase）：**

| 行类型 | 字段 | 证据 |
|--------|------|------|
| `LeaderboardRow`（`/api/leaderboard`、`/api/leaderboard/{name}` 汇总） | `name`,`uid`,`totalOct`,`totalMsg`,`totalPkt`,`deviceCount`,`reconnectCount`,`isAnonymous` | `Database.cs:1088-1099`；`app.js:279-284` |
| `ClientDetailRow`（`/api/leaderboard/{name}`） | `clientId`,`uid`,`ts`,`sendOct`,`recvOct`,`sendMsg`,`recvMsg`,`sendPkt`,`recvPkt`,`ipAddress`,`reconnect` | `Database.cs:1145-1158`；`app.js:310-312` |
| `TopicLeaderboardRow` | `name`,`uid`,`totalMsg`,`totalBytes`,`deviceCount`,`isAnonymous` | `Database.cs:1031-1040`；`app.js:760-763` |
| `TopicDetailRow` | `topic`,`clientId`,`uid`,`ts`,`msgCount`,`bytes` | `Database.cs:1043-1051`；`app.js:786-788` |
| `TopicTimelineRow` | `ts`,`msgCount`,`bytes`,`userCount`,`topUsers[]{name,uid,msg}` | `Database.cs:1001-1016`；`app.js:601,668-672` |
| `HealthSnapshotRow` | `ts`,`hostCpuPct`,`hostMemUsedPct`,`hostDiskUsedPct`,`hostNetRecvKbps`,`hostNetSendKbps`,`emqxNode`,`emqxCpuPct`,`emqxMemUsedPct`,`emqxConnections`,`emqxMsgRate`,`emqxAlarms` | `Database.cs:1071-1085`；`app.js:374-393` |
| `BlacklistActiveRow` | `who`,`reason`,`until`,`operator`,`createdAt` | `Database.cs:1102-1109`；`app.js:74` |
| `BlacklistHistoryRow` | `action`,`asType`,`who`,`reason`,`until`,`operator`,`createdAt` | `Database.cs:1112-1121`；`app.js:1041-1049` |
| `AuditPacketRow` | `ts`,`topic`,`clientId`,`connCallsign`,`connUid`,`pktCallsign`,`pktUid`,`verdict`,`len`,`frameNum`,`crcOk`,`smeter`,`srvUid`,`pktTs`,`streamBegin`,`ban` | `Database.cs:1124-1142`；`app.js:970-981` |
| `/api/online` 行（匿名对象，源码即下划线命名） | `name`,`uid`,`is_anonymous`,`clientid`,`ip`,`connected_at`,`send_oct`,`recv_oct`,`send_msg`,`recv_msg` | `Program.cs:396-409`；`app.js:874-883` |

---

## 2. 每个页面的功能清单

### 2.0 所有内页共用的顶栏（结论优先）

**结论**：11 个页面里除 login/setup 外，9 个页面（含 help）顶栏完全一致：左侧标题 `FMO Audit Service`，中间 8 个导航标签，右侧状态条 `#collect-status` + `退出登录`（`logout`）。导航标签顺序固定为 **排行榜(`/`) / 主题统计(`/topics.html`) / 在线(`/online.html`) / 身份审计(`/audit.html`) / 黑名单(`/blacklist.html`) / 健康(`/health.html`) / 配置(`/settings.html`) / 说明(`/help.html`)**，当前页加 `class="active"`。状态条 30 秒刷新一次（`refreshStatus`，读 `/api/status`）：`collecting=false` 显示“未连接 EMQX”；否则显示 `last_status`（如“采集正常 HH:mm:ss，在线 N”），并按 `last_collect_ok` 上绿/红（`app.js:31-44`；`CollectorService.cs:122,233`）。

**证据**：`index.html:10-26`（其余页 `topics.html:10-26`、`online.html:10-26`、`audit.html:10-26`、`blacklist.html:10-26`、`health.html:10-26`、`settings.html:10-26`、`help.html:10-26` 逐字相同）。

---

### 2.1 排行榜 `index.html`（`/`）

**结论**：呼号流量排行榜，是**唯一支持点开明细 + 行内拉黑**的主页；默认时间范围“今天 00:00 → 现在”，查询上限 200 行，无分页。

**控件与默认值**

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 筛选栏 | 时间范围 chip：`今天` / `昨天` / `近7天` / `近30天` / `自定义`(`active`) | `data-range`；点非 custom 会改写 `#from`/`#to`；点自定义不改时间也不自动查询 | `index.html:29-37`；`app.js:209-234` |
| 筛选栏 | `#from` / `#to`（`datetime-local`） | 初始 = 今天 `T00:00` → 当前 `HH:mm`（注意 active 显示的是“自定义”） | `app.js:201-207` |
| 筛选栏 | 排序 chip：`字节量`(`active`,`oct`) / `消息数`(`msg`) / `包数`(`pkt`) | 点选后**立即查询** | `index.html:38-41`；`app.js:235-242` |
| 筛选栏 | 按钮 `查询`(`#query`) | 手动查询，查询期间 disabled | `app.js:244,251-266` |
| 筛选栏 | 按钮 `导出 CSV`(`#export`) | `location.href = /api/export.csv?from=&to=&order=`（浏览器原生下载） | `app.js:245-249` |
| 筛选栏 | 复选框 `自动刷新`(`#auto-refresh`，默认勾选) | 30 秒一次 `query()`；`document.hidden` 时不刷 | `index.html:44-46`；`app.js:332-336` |
| 状态条 | `#range-desc`、`#total-rows`、`#query-time` | 显示服务端归一化后的区间、`共 N 个呼号`、`查询耗时 Nms` | `app.js:260-262` |
| 表格 | 8 列：`排名`/`呼号`/`设备数`/`总字节`/`总消息`/`总包数`/`重连次数`/`操作` | 排名前三着色 `rank-top1/2/3`；字节经 `fmtBytes`；数字经 `fmtNum` 千分位；重连>0 红字 | `index.html:60-67`；`app.js:272-284`；`style.css:113-118` |
| 表格 | 呼号单元格（`.name-cell`） | 点击 → 展开/收起 `clientid` 明细行（`colspan=8`） | `app.js:285,291-323` |
| 表格 | 操作列 | 已拉黑 → `解封`按钮；未拉黑 → `拉黑`；匿名（`isAnonymous`）→ 灰字 `匿名`（不可拉黑） | `app.js:83-89` |
| 空态 | `#empty` | `该时间段内没有客户端流量数据` | `index.html:72` |
| 明细行 | 表头 `clientid / 发送字节 / 接收字节 / 发送消息 / 接收消息 / 发送包 / 接收包 / 重连` | 客户端按 `clientid` 聚合，按（发送+接收字节）倒序 | `app.js:300-320` |

**调用**：`/api/leaderboard`（`query`）、`/api/leaderboard/{name}`（`toggleDetail`）、`/api/export.csv`（`export`）、`/api/blacklist/active`（`getBlacklistActive`）、`/api/status`（`refreshStatus`/`ensureWizard`）、`/api/logout`。

**证据**：`app.js:198-337`。

---

### 2.2 主题统计 `topics.html`

**结论**：两块内容——(a) 全员发包**时间轴**（Canvas 手绘，可缩放/平移/hover）；(b) 主题发包排行榜（含拉黑）。时间轴与排行榜共用同一时间范围，**自动刷新只刷时间轴与状态，不刷排行榜**。

**控件与默认值**

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 筛选栏 | `统计主题` + `#topic-name`（`mono`） | 加载 `/api/topic-config` 后显示 `${topic} /#` | `topics.html:29-30`；`app.js:491-493` |
| 筛选栏 | 时间范围 chip：`今天` / `昨天` / `近7天`(`active`) / `近30天` | 默认区间 = 近 7 天；点选即 `query()` | `app.js:484-486,507-518` |
| 筛选栏 | `#from` / `#to` | 近 7 天 → 现在 | `app.js:485-486` |
| 筛选栏 | 排序 chip：`消息数`(`active`,`msg`) / `字节数`(`bytes`) | 点选即 `query()` | `app.js:519-526` |
| 筛选栏 | `查询` / `导出 CSV` | 导出 `/api/topic-export.csv?from=&to=&order=` | `app.js:535-540` |
| 筛选栏 | 统计周期 chip：`10秒`(`10s`) / `1分钟`(`1m`) / `5分钟`(`active`,`5m`) / `1小时`(`1h`) | **只重新加载时间轴**（`loadTimeline()`），不重查排行榜 | `index.html` 对应 `topics.html:45-49`；`app.js:527-534` |
| 筛选栏 | 复选框 `自动刷新`（默认勾选） | 30 秒：`loadTimeline(true)` + 刷新 `/api/topic-config` 的接收计数文案 | `app.js:806-817` |
| 图表 | 卡片标题 `全员发包时间轴（悬停查看该时间点详情）`，`<canvas id="timeline-canvas">`（内联高度 200px）+ 绝对定位 `#timeline-tooltip` | 绘制细节见 §4.4 | `topics.html:56-62`；`app.js:570-747` |
| 状态条 | `#range-desc`、`#total-rows`、`#ingest-status` | ingest 文案：已启用 → `已启用（已接收 N 条，最近 TS）`；有 pending → 红字 `已启用但 X 待确认（配置页点「测试连接」）`；未启用 → 红字 `未启用主题统计（配置页开启）` | `app.js:494-503` |
| 表格 | 6 列：`排名`/`呼号`/`设备数`/`消息数`/`字节数`/`操作` | 同排行榜：前三着色、可展开明细、可拉黑/解封 | `topics.html:72-85`；`app.js:749-767` |
| 明细行 | `clientid / 主题 / 消息数 / 字节数` | 按 `clientid` 聚合、按消息数倒序，主题用 `Set` 去重后逗号连接 | `app.js:777-795` |
| 空态 | `#empty` | `该时间段内没有消息数据（确认已在配置页启用主题统计，且 EMQX 规则引擎在转发）` | `topics.html:86` |

**证据**：`app.js:474-818`。

---

### 2.3 在线 `online.html`

**结论**：纯列表页，**没有筛选栏、没有时间范围、没有导出**；服务端 60 秒采集一次，前端 30 秒拉一次缓存。

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 状态条 | `#online-summary` | 未连接 EMQX → 红字 `未连接 EMQX`（`collecting=false`）；否则 `在线 N 个客户端` | `app.js:854-860` |
| 状态条 | `#online-updated` | `（数据更新于 {updated_at}，每 60 秒采集一次）`，灰 #999 12px | `app.js:861-863` |
| 状态条 | 复选框 `自动刷新`（默认勾选） | 30 秒 `load()`，`document.hidden` 跳过 | `online.html:32-34`；`app.js:890-894` |
| 表格 | 7 列：`呼号`/`clientid`/`IP 地址`/`连接时间`/`发送`/`接收`/`操作` | 呼号列匿名时回退显示 `clientid`，有 uid 时追加 `（uid）`，已拉黑加红底 `已拉黑` 徽标 | `online.html:40-48`；`app.js:872-885` |
| 表格 | `连接时间` 单元格 | 显示本地 `yyyy-MM-dd HH:mm:ss`，`title` 属性 = 在线时长（`刚连接` / `N 分钟` / `N 小时 M 分`） | `app.js:830-847,880` |
| 排序 | 客户端排序：匿名置底，其余按 `name||clientid` 用 `localeCompare(...,'zh')` | — | `app.js:868-871` |
| 空态 | `#empty` | `当前没有在线客户端（或尚未连接 EMQX）` | `online.html:52` |

**证据**：`app.js:824-896`；`Program.cs:386-413`。

---

### 2.4 身份审计 `audit.html`

**结论**：展示包头身份不一致事件；**此页只读**（开关在配置页），带判决类型筛选与三类计数。

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 筛选栏 | 时间范围：`近1小时` / `今天` / `近7天`(`active`) / `近30天` | 默认近 7 天；点选即 `query()` | `audit.html:30-33`；`app.js:908-933` |
| 筛选栏 | 类型 chip：`全部异常`(`active`, verdict 空) / `身份不符`(`KICK`) / `未知身份`(`WARN`) / `非法包`(`FAIL`) | 空值时不带 `verdict` 参数 | `audit.html:39-42`；`app.js:934-941,953` |
| 筛选栏 | `查询`；复选框 `自动刷新`（默认勾选） | 30 秒 `query()` | `app.js:942,990-994` |
| 状态条 | `#range-desc`、`#total-rows`、`#ic-status` | 计数文案 `KICK n · WARN n · FAIL n（显示 N 条）`；开关文案 `身份控制已启用（伪造即自动拉黑）` / `身份控制已关闭（仅记录提醒，不自动拉黑）` | `app.js:913-920,957` |
| 表格 | 10 列：`判定`/`时间`/`连接身份（实际连接者）`/`包头声明（payload 自称）`/`clientid`/`包长`/`帧数`/`S表`/`CRC`/`处置` | 判定中文映射 `KICK→身份不符(#c62828)`、`WARN→未知身份(#e65100)`、`FAIL→非法包(#999)`；CRC 用 ✓/✗（绿/红）；连接/包头身份为空显示灰字 `匿名`/`-` | `audit.html:61-70`；`app.js:944-945,968-982` |
| 处置列 | `r.ban` → 红字 `已自动拉黑`；`verdict==='KICK' && !ban` → `仅记录（身份控制关闭或拉黑失败）`；否则 `-` | — | `app.js:970,981` |
| 空态 | `#empty` | `该时间段内没有异常审计事件（包头身份与连接身份一致 = 正常放行，不记录）` | `audit.html:75` |

**证据**：`app.js:902-995`。

---

### 2.5 黑名单 `blacklist.html`

**结论**：上下两张表（当前生效 / 操作历史）+ 一个手动拉黑按钮；生效表把“本地留痕”和“EMQX 侧手动拉黑”合并展示并标来源。

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 状态条 | `#bl-status` | 未连接 EMQX → 红字 `未连接 EMQX（黑名单操作不可用，仅展示本地记录）`；否则 `当前生效 N 个[，EMQX 侧另有 M 个手动拉黑]` | `app.js:1008-1015` |
| 状态条 | 按钮 `手动拉黑呼号`(`#bl-add`) | 打开拉黑弹窗，`who` 为空 → 弹窗多一个呼号输入框 | `blacklist.html:31`；`app.js:1054` |
| 卡片 1 | 标题 `当前生效黑名单（EMQX 拒绝连接，到期自动解除）`；6 列：`呼号`/`原因`/`到期时间`/`操作人`/`拉黑时间`/`操作` | 数据 = `local` + `emqx_only` 拼接；`emqx_only` 行加红底 `EMQX` 徽标、操作人回退 `EMQX 手动`、操作列显示灰字 `请到 EMQX 解封`（不给解封按钮） | `blacklist.html:36-50`；`app.js:1016-1033` |
| 卡片 2 | 标题 `操作历史（拉黑/解封留痕）`；6 列：`操作`/`呼号`/`原因`/`封禁到期`/`操作人`/`时间` | `action==='ban'` → 红字 `拉黑`，否则绿字 `解封`；`until` 为空时 ban 显示 `永久`、unban 显示 `-` | `blacklist.html:56-70`；`app.js:1036-1051` |
| 空态 | `#active-empty` `当前没有生效中的黑名单`；`#history-empty` `暂无操作记录` | — | `blacklist.html:51,71` |

**调用**：`load()` 内顺序请求 `/api/blacklist/active` → `/api/blacklist/history`（无 limit 参数，走默认 200）；无自动刷新（仅 `refreshStatus` 30s）。

**证据**：`app.js:1001-1058`。

---

### 2.6 健康 `health.html`

**结论**：3 张 Canvas 折线卡 + 1 张按需出现的告警卡；**只有手动查询与范围 chip，无自动刷新**（`initHealth` 里没有 auto-refresh 定时器）。

| 区域 | 控件 | 默认 / 行为 | 证据 |
|------|------|-------------|------|
| 筛选栏 | 时间范围：`今天`/`昨天`/`近7天`(`active`)/`近30天` + `#from`/`#to` | 初始近 7 天；点 chip **立即 `query()`** | `health.html:29-39`；`app.js:344-364` |
| 筛选栏 | `查询`(`#query`) | 手动刷新 | `app.js:364` |
| 图表 1 | `宿主机 CPU / 内存 / 磁盘（%）` → `#host-cpu` + `#legend-host` | 三条线：`CPU %` `#d32f2f` / `内存 %` `#1565c0` / `磁盘 %` `#2e7d32` | `health.html:42-46`；`app.js:376-380` |
| 图表 2 | `宿主机网络（KB/s）` → `#host-net` + `#legend-net` | `下行 KB/s` `#1565c0` / `上行 KB/s` `#e65100` | `app.js:382-385` |
| 图表 3 | `EMQX 连接数 / 消息速率（条/s）` → `#emqx-basic` + `#legend-emqx` | `连接数` `#2e7d32` / `消息速率 条/s` `#6a1b9a` / `节点负载 load1` `#e65100`（**`emqxCpuPct` 实际是 EMQX 节点 load1**，见 `CollectorService.cs:216`） | `app.js:387-391` |
| 图表 4 | `#alarm-card`（默认 `display:none`）→ 标题 `活跃告警`，`#alarm-list` | 当 `emqxAlarms` 有值时显示，把各快照的告警按 `,` 拆开去重后以 `；` 连接 | `health.html:57-60`；`app.js:393-400` |
| 空态 | 无表格、无 `#empty`；无数据时曲线区无提示 | — | `health.html:41-61` |

**证据**：`app.js:343-468`。

---

### 2.7 配置 `settings.html`

**结论**：单页 9 个卡片，是唯一有写操作的页面。字段、默认值与流程如下。

| 卡片 | 字段/控件 | 默认值 / 行为 | 调用的 API | 证据 |
|------|-----------|---------------|------------|------|
| 首次使用引导横幅 `#wizard-banner` | 文案 3 步：`1. 管理员账号（完成）→ 2. 连接 EMQX（下方）→ 3. 启用主题统计（下方）` | 仅当 `!wizard_done && !configured` 时显示（默认 `hidden`） | `GET /api/status` | `settings.html:29-35`；`app.js:1410-1417` |
| `EMQX 连接（步骤 2）` | `#emqx-url` 文本框，placeholder `http://服务器IP:18083`，label `EMQX 地址（如 http://192.168.1.100:18083）` | 载入 `/api/config` 的 `emqx_url`（Secret **不回填**） | `GET /api/config` | `settings.html:41-43`；`app.js:1209-1210` |
| 同上 | `#api-key`（label `API Key`，autocomplete off） | 空，每次需重填 | — | `settings.html:45-46` |
| 同上 | `#api-secret`（password，label `API Secret`） | 空 | — | `settings.html:48-50` |
| 同上 | 密钥获取说明块 | `EMQX Dashboard → 系统设置 → API 密钥 → 创建`；`角色选择 administrator`；`⚠️ Dashboard 的登录账号（admin）不能调用 API，必须使用 API 密钥` | — | `settings.html:52-57` |
| 同上 | `保存并连接`(`#save-config`) / `断开监控`(`#disconnect`) / `#config-msg` / `#config-info` | 保存前校验三项非空 → `正在测试连接…` → 成功 `连接成功，开始采集（1 分钟后出数据）`；失败用 `d.error`；已连接时 `#config-info` = `已连接 EMQX（API Secret 不显示，如需修改请重新填写）` | `POST /api/config`；`POST /api/config/disconnect` | `app.js:1215,1219-1236` |
| `主题统计（规则引擎消息统计）` | 只读 kv：`状态：` `#topic-status`、`已接收消息：` `#topic-total` + `（最后接收 #topic-last）`、`Webhook 地址：` `#topic-webhook`（mono）、`#topic-pending-row`（橙色，展示 `pending`/`failed` 报告） | 未启用时 `未启用`（#999） | `GET /api/topic-config` | `settings.html:70-73`；`app.js:1249-1265,1302-1310` |
| 同上 | `#topic-name` 输入，label `统计主题（规则引擎按 主题/# 匹配，含子主题）`，placeholder `FMO/RAW` | 回填 `/api/topic-config.topic`（后端默认 `FMO/RAW`） | — | `settings.html:74-77`；`app.js:1280` |
| 同上 | `#topic-webhook-url` 输入，placeholder `http://服务器IP:9527/api/ingest` | 回填 `webhook_url || ingest_url` | — | `settings.html:78-81`；`app.js:1281` |
| 同上 | `#ip-quick-pick` IP 快捷按钮组 | 由 `local_ips` 动态生成，按钮文字 `IP:port`，点击填入 `http://IP:port/api/ingest` 并提示 `已填入 IP:port（EMQX 节点需能访问该地址）` | `GET /api/topic-config` | `settings.html:82`；`app.js:1285-1301` |
| 同上 | 数据流向说明块 | “主题统计由 EMQX 规则引擎**主动上报**…Webhook 地址必须对 EMQX 所有节点可见”；分同局域网/异地集群/公网三种建议 | — | `settings.html:83-88` |
| 同上 | `启用主题统计`(`#topic-enable`) / `停用`(`#topic-disable`) / `测试连接`(`#topic-test`) / `#topic-msg` / `#topic-test-result` / `#topic-info` | 启用前会做**内网 vs 公网网段智能提示**（webhook 私网 + EMQX 公网 → 直接中止并提示）；成功后渲染四件套报告 `连接器 emqx-monitor-bridge` / `动作|桥接 emqx-monitor-ingest-action|emqx-monitor-bridge` / `规则 emqx-monitor-topic-rule`；成功文案 `已启用，统计主题 {topic} /#（1 分钟后出数据）` | `GET /api/config`、`POST /api/topic-config`、`GET /api/topic-test`、`GET /api/topic-config` | `settings.html:89-96`；`app.js:1314-1407` |
| `身份控制（包头身份一致性，默认启用）` | `#ic-status`、说明段落、`启用身份控制`(`#ic-enable`) / `关闭（仅提醒）`(`#ic-disable`) / `#ic-msg` | 状态文案 `已启用（伪造即自动拉黑）`（绿）/ `已关闭（仅记录提醒）`（红）；说明含 `对 FMO/RAW 每个数据包解包头…不一致视为身份伪造，立即自动拉黑该连接身份（踢下线 + 禁连 + 留痕）` 与 `关闭后降级为仅记录提醒（身份审计页可见），不自动拉黑。开放网络默认最高保护，建议保持启用。` | `GET/POST /api/identity-control` | `settings.html:100-112`；`app.js:1076-1104` |
| `兼容性自检（EMQX 版本 + API）` | `运行自检`(`#check-run`) / `#check-msg` / `#check-result` | 成功 `检测完成：EMQX {version}`，逐项 `✓/✗ 名称 路径 … 备注`；不支持时红字显示 `suggested_upgrade`；脚注 `支持 EMQX 5.x（5.1+）…` | `GET /api/check` | `settings.html:114-124`；`app.js:1420-1436` |
| `数据管理` | kv `呼号增量：` `#stat-minutes` `主题统计：` `#stat-topics` `健康快照：` `#stat-health` | 载入 `/api/admin/stats`（`audit_packets` 返回但页面不展示） | `GET /api/admin/stats` | `settings.html:129`；`app.js:1439-1447` |
| 同上 | `清空全部统计数据`(`#clear-data`，红框) / `#clear-msg` | **二次确认**：① `确定清空全部统计数据？此操作不可恢复（保留管理员账号和 EMQX 配置）。` ② `再次确认：清空后 30 天内的历史数据将全部丢失。`；成功文案含三类行数 | `POST /api/admin/clear-data` | `settings.html:130-134`；`app.js:1449-1463` |
| 同上 | `重置审计监控工具`(`#reset-tool`，红框，虚线上分隔) / `#reset-msg` | **三次确认**（见 §4.7）；成功后 800ms 跳 `/setup.html` | `POST /api/admin/reset` | `settings.html:135-139`；`app.js:1466-1480` |
| `修改管理员密码` | `#old-pw`(password) / `#new-pw`(password，label `新密码（至少 8 个字符）`) / `修改密码`(`#change-pw`) / `#pw-msg` | 校验：旧密码非空 + 新密码 ≥8；成功清空两个输入并提示 `密码已修改` | `POST /api/change-password` | `settings.html:144-158`；`app.js:1238-1246` |
| `版本与更新（OTA）` | `#up-current`、`#up-latest-row`、`#up-mode-row`、`#up-docker-hint`、`#up-check`、`#up-apply`（默认隐藏）、`#up-msg`、`#up-progress-box`（含 `#up-stage-text`、`#up-progress-fill`、`#up-progress-text`、`#up-steps`）、外链 `查看版本更新说明 ↗` | 进页自动 `upCheck()`；模式中文映射 `self→裸机/服务部署（支持自更新）`/`docker→Docker 容器（不支持自更新）`/`manual→手动部署`；步骤条 `下载 解压 替换 重启`；`up-apply` 仅在 `has_update && mode!=='docker'` 时显示 | `GET /api/update/check`、`POST /api/update/apply`、`GET /api/update/progress`（300ms 轮询） | `settings.html:161-186`；`app.js:1106-1205` |
| `运行信息` | `#run-port`、`#run-retention`、`#run-clients`、`#run-status` + 脚注 | `listen_port`、`{data_retention_days} 天`、`status || (last_collect_ok ? '采集中' : '未采集')`、`online_clients`；脚注 `采集精度：1 分钟。增量数据仅在客户端在线时记录，离线期间无流量数据。` | `GET /api/config` | `settings.html:188-197`；`app.js:1211-1214` |

**证据**：`app.js:1072-1481`。

---

### 2.8 说明 `help.html`

**结论**：**零 API 的纯文案页**（但加载 app.js 以复用顶栏状态条与退出登录）。5 个卡片：`为什么有 FMO 4.0`、`为什么还需要审计工具`、`工具做什么`、`管理员操作说明`、`技术说明`。内容要点：三层 PKI 信任链、包头明文不带签名、`认证` 与 `责任` 两个维度、身份控制默认启用=最高保护、6 个工具的逐条说明、拉黑/解封/开关/审计事件解读/数据保留 30 天/备份=复制 db 文件、故障排查时间精度（主题统计 10 秒 / 呼号统计 1 分钟 / 在线列表 60 秒采集）、包头前 64 字节字段清单、`CRC 由设备端核验，审计侧仅展示参考，不据此判定`、`数据按服务器本地时间存储，请确保服务器时区为 Asia/Shanghai`。

**证据**：`help.html:28-80`；`app.js:1062-1066`。

---

### 2.9 登录 `login.html`

**结论**：独立卡片（360px，居中，`.auth-wrap` 上下 60px padding），**内联脚本、不加载 app.js**。

| 控件 | 行为 | 证据 |
|------|------|------|
| `#username`（label `用户名`，autocomplete=username） | — | `login.html:14-17` |
| `#password`（type=password，autocomplete=current-password，回车提交） | `keydown` Enter → 点提交 | `login.html:18-21,47` |
| `#submit`（`登录`，100% 宽） | 前端校验非空（`请输入用户名和密码`）→ `POST /api/login` | `login.html:22,29-46` |
| `#msg`（`.form-msg err`） | 失败显示 `d.error`（如“用户名或密码错误（剩余 4 次机会）”“连续失败 5 次，账号锁定 5 分钟”“尝试过于频繁，请稍后再试（全局限流）”）；网络异常 `网络错误：{message}` | `login.html:23,44-45` |
| 登录成功跳转 | 再 `GET /api/status`，`wizard_done || configured` → `/`，否则 → `/settings.html`（首次引导）；status 请求失败兜底 → `/` | `login.html:37-43` |
| 页标题 | `FMO Audit Service - 登录` | `login.html:12` |

**证据**：`login.html:1-50`。

---

### 2.10 初始化 `setup.html`

**结论**：同上样式，内联脚本。

| 控件 | 行为 | 证据 |
|------|------|------|
| `#username`（label `用户名（至少 3 个字符）`） | 前端校验 `u.length < 3` → `用户名至少 3 个字符` | `setup.html:15-16,37` |
| `#password`（label `密码（至少 8 个字符）`） | `< 8` → `密码至少 8 个字符` | `setup.html:19-20,38` |
| `#password2`（label `确认密码`，回车提交） | 不一致 → `两次输入的密码不一致` | `setup.html:23-24,39,47` |
| `#submit`（`创建管理员`，100% 宽） | `POST /api/setup {username,password}`；成功 → 绿字 `创建成功，正在进入…`，跳 `/login.html` | `setup.html:26,40-44` |
| `#msg` | 失败显示 `d.error`（如 `系统已初始化，不能重复设置管理员`） | `setup.html:27,44` |
| 卡片标题 | `初始化管理员账号` | `setup.html:12` |

**证据**：`setup.html:1-50`；`AuthService.cs:34-44`。

---

## 3. app.js 的 API 调用清单

**结论**：app.js 内共 **24 处 fetch 调用点**（含 1 处退出登录的裸 `fetch`），全部经 `api()` 包装；`api()` 只做一件事：**HTTP 401 → 立即跳 `/login.html` 并抛错**，其余情况返回 `r.json()`（`app.js:10-14`）。页面内无重试、无防抖、无 AbortController。

| # | app.js 函数（定义行） | 方法 + 路径 | 请求体 / 查询参数 | 期望响应字段（**加粗 = 代码实际读取**） |
|---|----------------------|-------------|-------------------|------------------------------------------|
| 1 | `refreshStatus` (`app.js:31`) | GET `/api/status` | — | **collecting**、**last_collect_ok**、**last_status**（页头状态）；`ensureWizard` 另读 **wizard_done**、**configured**（`app.js:50`）；`initSettings` 引导横幅同（`app.js:1413`）；`login.html` 读 `wizard_done`/`configured` |
| 2 | `logout` 点击处理器 (`app.js:58`) | POST `/api/logout` | — | 不解析响应（裸 `fetch`），随后跳 `/login.html` |
| 3 | `getBlacklistActive` (`app.js:68`) | GET `/api/blacklist/active` | — | **local[]**（**who**、**reason**、**until**、**operator**、**createdAt**）、**emqx_only[]**（**who**、**reason**、**until**）、**emqx_reachable**；客户端 60s 缓存（`blMap`/`blMapAt`），`blInvalidate()` 强制失效 |
| 4 | `openBanModal` → `#ban-ok` (`app.js:161`) | POST `/api/blacklist/ban` | body `{who, reason, until}`；`until` = `yyyy-MM-ddTHH:mm`（本地，来自 1/6/24 小时换算或自定义 datetime-local）或 `null`（永久） | **ok**、**kicked**、**who**、**error**（成功文案区分 `kick > 0`） |
| 5 | `doUnban` (`app.js:182`) | POST `/api/blacklist/unban` | body `{who}` | **ok**、**error** |
| 6 | `initLeaderboard.query` (`app.js:257`) | GET `/api/leaderboard` | `from`、`to`（`yyyy-MM-ddTHH:mm`）、`order`(oct/msg/pkt)、`limit=200` | **ok**、**from**、**to**、**rows[]**：**name**、**uid**、**deviceCount**、**totalOct**、**totalMsg**、**totalPkt**、**reconnectCount**、**isAnonymous**、`error` |
| 7 | `initLeaderboard.toggleDetail` (`app.js:297`) | GET `/api/leaderboard/{name}` | 路径 `name`（`encodeURIComponent`）；`from`、`to` | **rows[]**：**clientId**、**uid**、**sendOct**、**recvOct**、**sendMsg**、**recvMsg**、**sendPkt**、**recvPkt**、**reconnect**、**ipAddress**（`ipAddress` 仅存入聚合对象未渲染） |
| 8 | `#export` (`app.js:248`) | GET `/api/export.csv` | `from`、`to`、`order`（`location.href` 触发下载） | CSV 文本（不进 JSON 解析路径） |
| 9 | `initHealth.query` (`app.js:368`) | GET `/api/health` | `from`、`to` | **ok**、**rows[]**：**ts**、**hostCpuPct**、**hostMemUsedPct**、**hostDiskUsedPct**、**hostNetRecvKbps**、**hostNetSendKbps**、**emqxConnections**、**emqxMsgRate**、**emqxCpuPct**（当 load1 用）、**emqxAlarms**；`error` |
| 10 | `initTopics` 配置读取 IIFE (`app.js:491`) | GET `/api/topic-config` | — | **topic**、**enabled**、**pending**、**total_ingested**、**last_ingest_at** |
| 11 | `initTopics.query` (`app.js:547`) | GET `/api/topic-leaderboard` | `from`、`to`、`order`(msg/bytes)、`limit=200` | **ok**、**from**、**to**、**topic**、**rows[]**：**name**、**uid**、**deviceCount**、**totalMsg**、**totalBytes**、**isAnonymous** |
| 12 | `initTopics.loadTimeline` (`app.js:564`) | GET `/api/topic-timeline` | `from`、`to`、`bucket`(10s/1m/5m/1h) | **ok**、**bucket**、**rows[]**：**ts**、**msgCount**、**bytes**、**userCount**、**topUsers[]**（**name**、**uid**、**msg**） |
| 13 | `initTopics.toggleDetail` (`app.js:774`) | GET `/api/topic-leaderboard/{name}` | 路径 `name`；`from`、`to` | **rows[]**：**clientId**、**uid**、**topic**、**msgCount**、**bytes** |
| 14 | `#export`（主题页）(`app.js:539`) | GET `/api/topic-export.csv` | `from`、`to`、`order` | CSV 文本 |
| 15 | `initTopics` 自动刷新 (`app.js:811`) | GET `/api/topic-config` | — | **enabled**、**total_ingested**、**last_ingest_at** |
| 16 | `initOnline.load` (`app.js:850`) | GET `/api/online` | — | **collecting**、**updated_at**、**total**、**rows[]**：**name**、**uid**、**is_anonymous**、**clientid**、**ip**、**connected_at**、**send_oct**、**recv_oct**（`send_msg`/`recv_msg` 返回但未渲染） |
| 17 | `initAudit` 开关状态 IIFE (`app.js:915`) | GET `/api/identity-control` | — | **enabled** |
| 18 | `initAudit.query` (`app.js:953`) | GET `/api/audit-packets` | `from`、`to`、`verdict`（为空则整段省略）、`limit=300` | **ok**、**from**、**to**、**rows[]**：**ts**、**verdict**、**connCallsign**、**connUid**、**pktCallsign**、**pktUid**、**clientId**、**len**、**frameNum**、**smeter**、**crcOk**、**ban**；**counts**：**KICK**、**WARN**、**FAIL** |
| 19 | `initBlacklist.load` (`app.js:1007`) | GET `/api/blacklist/active` | — | **emqx_reachable**、**local[]**（**who**、**reason**、**until**、**operator**、**createdAt**）、**emqx_only[]**（**who**、**reason**、**until**） |
| 20 | `initBlacklist.load` (`app.js:1036`) | GET `/api/blacklist/history` | —（默认 limit=200） | **rows[]**：**action**、**who**、**reason**、**until**、**operator**、**createdAt** |
| 21 | `initSettings` 开关状态 IIFE (`app.js:1079`) + `setIc` (`app.js:1090`) | GET / POST `/api/identity-control` | POST body `{enabled}` | **enabled**、**ok**、**error** |
| 22 | `initSettings.upCheck` (`app.js:1113`) | GET `/api/update/check` | — | **current**、**latest**、**has_update**、**update_mode**、**docker_hint**、**error** |
| 23 | `initSettings` 更新执行 (`app.js:1166`) + 轮询 (`app.js:1172`) | POST `/api/update/apply`；GET `/api/update/progress` | —（轮询 300ms） | apply：**ok**、**error**；progress：**stage**、**percent**、**bytes_read**、**total_bytes**、**message** |
| 24 | `initSettings` 配置读取 IIFE (`app.js:1209`) | GET `/api/config` | — | **emqx_url**、**listen_port**、**data_retention_days**、**status**、**last_collect_ok**、**online_clients**、**configured** |
| 25 | `#save-config` (`app.js:1227`) | POST `/api/config` | body `{emqxUrl, apiKey, apiSecret}` | **ok**、**error** |
| 26 | `#disconnect` (`app.js:1234`) | POST `/api/config/disconnect` | — | **ok** |
| 27 | `#change-pw` (`app.js:1243`) | POST `/api/change-password` | body `{oldPassword, newPassword}` | **ok**、**error** |
| 28 | `initSettings` 主题配置 IIFE (`app.js:1279`) | GET `/api/topic-config` | — | **topic**、**webhook_url**、**ingest_url**、**local_ips[]**、**enabled**、**pending**、**failed**、**total_ingested**、**last_ingest_at** |
| 29 | `#topic-enable` 前置检查 (`app.js:1321`) | GET `/api/config` | — | **emqx_url**（用于内网/公网对比提示） |
| 30 | `#topic-enable` (`app.js:1338`) | POST `/api/topic-config` | body `{enable:true, topic, webhookUrl}` | **ok**、**topic**、**webhook_url**、**pending**、**failed**、**status**（**ok** + **connector.exists/state/reason** + **middleware.exists/kind** + **rule.exists/enabled**）、**hint**、**error** |
| 31 | `#topic-disable` (`app.js:1366`) | POST `/api/topic-config` | body `{enable:false}` | **ok**、**error** |
| 32 | `#topic-test` (`app.js:1384`) | GET `/api/topic-test` | — | **ok**、**status**（同上的四件套，读 `v6` 决定“动作/桥接”文案）、**dashboard_hint**、**error** |
| 33 | `#topic-test` 成功后 (`app.js:1401`) | GET `/api/topic-config` | — | **enabled**、**pending**、**failed** |
| 34 | 引导横幅 IIFE (`app.js:1412`) | GET `/api/status` | — | **wizard_done**、**configured** |
| 35 | `#check-run` (`app.js:1426`) | GET `/api/check` | — | **ok**、**version**、**supported**、**suggested_upgrade**、**checks[]**（**name**、**path**、**ok**、**note**）、**error** |
| 36 | `loadStats` (`app.js:1441`) | GET `/api/admin/stats` | — | **minute_stats**、**topic_stats**、**health_snapshots**（`audit_packets` 未用） |
| 37 | `#clear-data` (`app.js:1456`) | POST `/api/admin/clear-data` | — | **ok**、**cleared.minute_stats**、**cleared.topic_stats**、**cleared.health_snapshots**、**error** |
| 38 | `#reset-tool` (`app.js:1474`) | POST `/api/admin/reset` | — | **ok**、**error** |
| 39 | 更新重连探测 (`app.js:1197`) | GET `/api/update/check` | —（`credentials:'same-origin'`，成功后 `location.reload()`） | 仅探测是否 200 |

**证据**：`app.js` 上表行号；`Program.cs` / `TopicEndpoints.cs` / `BlacklistEndpoints.cs` / `UpdateEndpoints.cs` 对应行。

---

## 4. 关键交互细节

### 4.1 登录与会话保持

**结论**：服务端 Cookie 24 小时、不滑动续期；前端**没有任何 token/refresh 逻辑**，唯一失效处理是 `api()` 的 401 跳转。失败锁定是双层的：`(用户名|IP)` 键 5 次失败锁 5 分钟；全站 1 分钟窗口 60 次失败 → 全局锁 60 秒（不依赖 IP，防 XFF 伪造）；锁定字典上限 10000 条并惰性清理。

**证据**：`Program.cs:114-122`；`app.js:10-14`；`AuthService.cs:15-27,47-95`；客户端 IP 解析（受 `trust_proxy` 控制，环境变量 `EMQX_MONITOR_TRUST_PROXY=1` 或 settings `trust_proxy=1`）`Program.cs:214-226`。

### 4.2 自动刷新间隔

**结论**：**前端统一 30 秒**，且都检查 `document.hidden` 与 `#auto-refresh` 勾选（勾选框存在时）。60 秒是**服务端采集周期**与文案。

| 页面 | 自动刷新的内容 | 间隔 | 证据 |
|------|----------------|------|------|
| 全站 | `refreshStatus()`（页头状态文本） | 30s | `app.js:328/467/803/826/989/1003/1074/1065` |
| 排行榜 | `query()`（含排行榜 + 黑名单缓存） | 30s | `app.js:332-336` |
| 主题统计 | **只** `loadTimeline(true)` + 刷新 ingest 文案（**排行榜不自动刷**） | 30s | `app.js:807-817` |
| 在线 | `load()`（读 60s 服务端缓存） | 30s | `app.js:890-894`；`Program.cs:385`；`CollectorService.cs:79` |
| 身份审计 | `query()` | 30s | `app.js:990-994` |
| 黑名单 | 无（仅状态条 30s） | — | `app.js:1001-1058` |
| 健康 | 无 | — | `app.js:343-468` |
| 配置 | 无（OTA 进度 300ms 轮询） | 300ms | `app.js:1203` |
| 黑名单生效缓存 | `getBlacklistActive` 客户端缓存 60s | 60s | `app.js:68-80` |

### 4.3 时间范围与粒度切换如何传参

**结论**：时间统一以 `datetime-local` 的**本地无时区字符串** `yyyy-MM-ddTHH:mm` 传给 `from`/`to`；服务端解析后**秒归零**并回传归一化值（`yyyy-MM-dd HH:mm:00`），前端把它显示在 `#range-desc`；跨度 >31 天或 `to < from` 直接报错。

- 服务端约束：格式必须 `yyyy-MM-ddTHH:mm`，否则 `时间格式应为 yyyy-MM-ddTHH:mm`；`t < f` → `结束时间不能早于开始时间`；`t - f > 31 天` → `时间跨度不能超过 31 天`（`WebHelpers.cs:9-17`）。
- 快捷范围只在**前端**换算：今天=当日 00:00→now；昨天=昨日 00:00→23:59；近 7/30 天=now-7/30 天同刻→now（`app.js:209-225`，健康页 `app.js:352-363`，主题页 `app.js:507-518`，审计页含 `1h` 分支 `app.js:927`）。
- **粒度（bucket）只在主题时间轴使用**：`data-bucket` ∈ `10s|1m|5m|1h`，原样作为 `bucket` 传参；服务端白名单只认 `10s|5m|1h`，其他（含 `1m`）归一为 `1m`（`TopicEndpoints.cs:190`）；DB 桶表达式：`10s`=原始 ts、`1m`=截断到分钟、`5m`=分钟向下取 5 的倍数、`1h`=截断到小时（`Database.cs:614-621`）。
- **时间轴必须补零**：服务端按桶步长生成完整序列（起点对齐桶边界），无数据桶填 0，`TopUsers=[]`；补零后 >40000 点即拒绝并提示缩小范围或换粗粒度（`Database.cs:683-718`；`TopicEndpoints.cs:192-193`）。
- 切换 bucket 只调 `loadTimeline()`（不重查排行榜）；切换时间范围 chip 或排序 chip 会重查（`app.js:507-534`）。

### 4.4 时间轴（Canvas）绘制与 hover

**结论**：手写 Canvas 折线 + 面积填充 + 缩放/平移/hover，无第三方库。

- 画布：`#timeline-canvas`，CSS 高 200px（`topics.html:59`），按 `devicePixelRatio` 放大后 `ctx.scale(dpr,dpr)`（`app.js:574-578`）。
- 边距：`padL=52, padR=12, padT=10, padB=24`（`app.js:581`）。
- Y 轴：5 条水平网格（i=0..4），标签 `max*(1-i/4)`，≥1000 显示为 `k`（1 位小数），否则取整；`max = 可见窗口内 msgCount 最大值 × 1.1`（最小 1）（`app.js:599-622`）。
- X 轴：在**可见窗口**内均匀取 6 个标签；`10s` 桶显示 `ts.slice(11,19)`（HH:mm:ss），其他桶显示 `ts.slice(5,16)`（MM-dd HH:mm）（`app.js:624-632`）。
- 折线/面积：线 `#1565c0` 宽 1.5；面积同色 `rgba(21,101,192,0.08)` 闭合到基线（`app.js:641-654`）。
- **hover 显示什么**：命中最近的桶后 (a) 画红点（`#c62828`，r=4）与红色竖线 `rgba(198,40,40,0.4)`；(b) tooltip（绝对定位 `#timeline-tooltip`，白底 1px `#333` 边框，12px，`min-width:170px`）内容为：**加粗 `ts`** → 换行 `发言 {userCount} 人 · 消息 {msgCount} 条 · {fmtBytes(bytes)}`；若该桶有 `topUsers`，追加一条分隔线与 `max-height:150px;overflow-y:auto` 的列表，每行 `呼号（UID）` + 加粗 `{msg} 包`；若 `userCount > topUsers.length` 追加灰字 `… 共 N 人发言`（`app.js:656-682`）。tooltip 水平居中于锚点并做左右/上下边界回弹（`app.js:673-679`）。
- 交互：**滚轮缩放**（上滚 ×1.6，下滚 ÷1.6，以鼠标位置为锚点，最小可见 5 桶；`passive:false` + `preventDefault`，`app.js:688-705`）；**拖拽平移**（位移换算成桶数并夹取，`app.js:708-735`）；**双击复位全量视图**并清空 `viewState`（`app.js:738-742`）；鼠标离开清 hover（`app.js:736`）。
- 自动刷新时**保持用户窗口**：`viewState{vs,ve}` 记录可见索引区间，`loadTimeline(true)` 时若 `keepView` 则沿用（全量视图时不记录，保持跟随新数据）（`app.js:586-589,702,723,746`）。
- 空数据：居中绘制 `该时间段无数据` 并隐藏 tooltip（`app.js:634-639`）。
- ⚠️ 迁移注意：`wheel` 用 `addEventListener` 且位于 `drawTimeline` 内部，每次重绘都会**再挂一个监听器**（`onmousemove/onmousedown/...` 是赋值不会累积）。Python 端重写时应用可移除的监听或只绑定一次。

**证据**：`app.js:570-747`；`topics.html:55-63`；`style.css:143-151`。

### 4.5 CSV 导出如何触发

**结论**：不是 XHR，而是**直接改 `location.href` 导航**到 GET 端点，靠浏览器原生下载；Cookie 由同源导航自动携带。**导出沿用当前 `order`，但无视 `limit=200`（服务端固定 5000）**。两处导出：

- 排行榜：`/api/export.csv?from=&to=&order=`（`app.js:245-249`），表头 `排名,呼号,设备数,总字节,总消息,总包数,重连次数`，`text/csv; charset=utf-8`，**带 UTF-8 BOM**（`Program.cs:349-362`）。
- 主题统计：`/api/topic-export.csv?from=&to=&order=`（`app.js:536-540`），表头 `排名,呼号,设备数,消息数,字节数,主题`（`TopicEndpoints.cs:198-212`）。
- 两处导出在时间范围非法时返回的是 **JSON 错误体**（`{ok:false,error}`），浏览器会把它当文件/文本显示——迁移时可改为先校验再下载。
- CSV 注入防护：`WebHelpers.Csv` 对以 `= + - @ \t \r` 开头的值前缀 `'`，并对含逗号/引号的值加引号转义（`WebHelpers.cs:19-25`）。

### 4.6 分页与排序

**结论**：**没有分页**（没有页码、没有 offset/cursor、没有“加载更多”）。只有服务端 `limit` + `ORDER BY`，前端渲染全量返回行。

| 场景 | 前端 limit | 服务端默认/上限 | 排序方式 | 证据 |
|------|-----------|------------------|----------|------|
| 排行榜 | 200 | 默认 100 / 夹取 1..1000 | `order` → `total_oct`(默认) / `total_msg` / `total_pkt` DESC | `app.js:257`；`Program.cs:325`；`Database.cs:339-344` |
| 呼号明细 | 无 limit 参数 | 无限制（该呼号该时段全部分钟行） | SQL `ORDER BY clientid, ts`；**前端再按 (sendOct+recvOct) DESC 聚合排序** | `Database.cs:394-401`；`app.js:314` |
| 主题排行 | 200 | 同上 | `order` → `total_msg`(默认) / `total_bytes` DESC | `TopicEndpoints.cs:170` |
| 主题明细 | 无 | 无 | SQL 顺序；前端按 `msgCount` DESC 聚合 | `app.js:790` |
| 审计事件 | 300 | 默认 200 / 夹取 1..1000 | SQL 顺序（无 order 参数），可加 `verdict` 过滤 | `app.js:953`；`BlacklistEndpoints.cs:107` |
| 黑名单历史 | 无（默认 200） | 默认 200 / 夹取 1..1000 | 倒序 | `BlacklistEndpoints.cs:85` |
| 在线列表 | 无 | — | 前端：匿名置底 + `localeCompare(...,'zh')` | `app.js:868-871` |
| 健康 | 无 | — | SQL `ORDER BY ts` | `Database.cs:444` |
| 时间轴 | 无（`bucket` 控制点数） | 补零后 >40000 拒绝 | 时间升序 | `TopicEndpoints.cs:192` |

### 4.7 黑名单操作确认框

**结论**：拉黑用**自定义模态框**（非 `confirm`），解封用原生 `confirm`，两类高危数据操作使用 2/3 次原生 `confirm`。

- 拉黑弹窗（`openBanModal`，`app.js:102-177`）：
  - `who` 为空时（黑名单页“手动拉黑呼号”）多一个输入 `#ban-who`（placeholder `如 BG5ABC`）；
  - 标题：`手动拉黑呼号` / `拉黑呼号 {who}`；
  - 原因：`<textarea id="ban-reason" placeholder="如：伪造数据包干扰信道">`，label `原因（留痕，建议填写）`；
  - 时长单选 `name="ban-dur"`：`永久`(value `""`，默认选中) / `1小时`(`1`) / `6小时`(`6`) / `24小时`(`24`) / `自定义`(`custom`)；选“自定义”才显示 `#ban-until`(`datetime-local`)；
  - 按钮：`取消`(`#ban-cancel`)、`拉黑并踢下线`(`#ban-ok`)；点遮罩或取消即清空 `#modal-root`；
  - 校验：呼号为空 → `请输入呼号`；自定义但未选时间 → `请选择自定义到期时间`；提交中 `#ban-ok` disabled 且提示 `正在拉黑…`；
  - 成功文案：`已拉黑 {who}，踢下线 {kicked} 个在线客户端` 或 `已拉黑 {who}（当前无在线客户端）`，随后 `blInvalidate()` + 1.2 秒后关闭并 `refreshAfterBl()`。
  - `until` 由小时数换算成本地 `yyyy-MM-ddTHH:mm`（`app.js:152-156`）。
- 解封（`doUnban`，`app.js:180`）：`confirm('确认解封 {who}？解封后该呼号可重新连接 EMQX。')` → POST → `blInvalidate()` + `refreshAfterBl()`；失败 `alert(d.error)`。
- `refreshAfterBl` 由各页在初始化时赋值：排行榜/主题=重查（主题同时重载时间轴）、在线=重载、黑名单=重载（`app.js:192,329,804,827,1004`）。
- 服务端侧确认语义：拉黑成功后**服务端自己**触发一次 `CollectNowAsync()` 刷新在线缓存（`BlacklistEndpoints.cs:43,62`）。
- 重置工具三次确认文案（`app.js:1469-1471`）：
  1. `确定重置审计监控工具？将删除管理员账号、EMQX 配置与全部数据，恢复到首次安装状态。`
  2. `再次确认：重置后必须重新设置管理员账号并重新连接 EMQX，且 EMQX 上的规则引擎会被移除。`
  3. `最后一次确认：所有历史数据（30 天）将永久丢失。`
- 清空数据两次确认（`app.js:1452-1453`）；OTA 更新一次确认 `确认更新到最新版本？更新期间服务将自动重启，页面会短暂中断。`（`app.js:1136`）。

### 4.8 身份控制的开关

**结论**：默认**启用**（最高保护）。开关持久化在 `settings.identity_control`（缺省视为 `1`），同时写入内存 `TopicIngestService.IdentityControlEnabled`；两个入口都是 `GET/POST /api/identity-control`，无权限差异、无二次确认。

- 持久化语义：`get => _db.GetSetting("identity_control") != "0"`，即**任何非 "0" 值（含未设置）都是启用**（`AppSettings.cs:22-26`）；启动时从 settings 恢复到内存（`Program.cs:79-80`）。
- 启用时的处置：`verdict == "KICK" && IdentityControlEnabled && connCallsign 非空` → 用连接呼号调 `emqx.BanAsync(connCs, reason, null)`（**永久封禁**，`until=null`），成功则 `ban=true`、写留痕（`action="ban"`,`as_type="username"`,`operator="身份控制"`）并即时刷新在线缓存；失败只写 stderr（`TopicEndpoints.cs:255-282`）。
- 判定规则（`TopicEndpoints.cs:235-252`）：连接侧呼号与 UID **都**为空 → `WARN`（仅记录）；否则包头呼号 == 连接呼号 **且** 包头 UID == 连接 UID → `PASS`（不落库，因为已在 topic_stats 聚合）；否则 `KICK`。`FAIL` 来自 `FmoRawParser.Parse` 失败（长度/len 不符），**限流** 60 秒窗口最多 100 条（`TopicIngestService.cs:34-48`）。
- 关闭后：KICK 仍落库，但审计页处置列显示 `仅记录（身份控制关闭或拉黑失败）`（`app.js:970`）。

### 4.9 设置页各字段与保存/测试连接流程

**结论**：三个“测试/连接”流程彼此独立：

1. **EMQX 连接**：`保存并连接` → 前端校验三项非空（否则 `请填写地址、API Key、API Secret`）→ 提示 `正在测试连接…` 并禁用按钮 → `POST /api/config`（服务端先 `emqx.ConfigureAsync` 实测，成功才落库并置 `wizard_done=1`、`collector.IsConfigured=true`）→ 成功 `连接成功，开始采集（1 分钟后出数据）`；失败显示 `EMQX 地址、API Key、API Secret 不能为空` 或 EMQX 返回的 `error`（`Program.cs:294-308`；`app.js:1219-1231`）。`API Secret` 永不回显，`#api-key` 也不回显（`Program.cs:282-292`）。
2. **主题统计**：`启用` 前先读 `/api/config` 做**内网/公网智能提示**（私网 webhook + 公网 EMQX → 中止并给出警示文案，不发送请求）；随后 `POST /api/topic-config{enable:true,topic,webhookUrl}`（服务端在 EMQX 上尽力创建 connector+action/bridge+rule，失败不阻塞），立即 `enabled=true`，返回 `pending`/`failed`/`status`/`hint`；前端据此决定绿色成功文案 `已启用，统计主题 {topic} /#（1 分钟后出数据）` 或橙色异常报告，并渲染四件套状态（`app.js:1314-1361`；`TopicEndpoints.cs:87-136`）。
   - `测试连接`：`GET /api/topic-test` 重新查询 EMQX 侧四件套真实状态；`status.ok` 时服务端会清 `topic_pending`；前端成功后再拉一次 `/api/topic-config` 刷新 pending 报告（`app.js:1377-1407`；`TopicEndpoints.cs:139-162`）。
   - `停用`：`POST /api/topic-config{enable:false}` → 移除 EMQX 规则引擎，成功文案 `已停用，规则引擎已从 EMQX 移除`（`app.js:1363-1374`）。
3. **兼容性自检**：`运行自检` → `GET /api/check` → 成功 `检测完成：EMQX {version}` + 逐项 `✓/✗ {name} {path} … {note}`；`supported=false` 时红字 `⚠ {suggested_upgrade}`（`app.js:1420-1436`）。
4. **改密**：旧密码非空 + 新密码 ≥8（`请填写旧密码，新密码至少 8 个字符`），否则不请求（`app.js:1238-1246`）。
5. **运行信息**：进页拉一次 `/api/config` 填充端口/保留天数/采集状态/在线数（`app.js:1207-1217`）。

### 4.10 健康页图表数据来源

**结论**：单一数据源 `GET /api/health?from&to` → `rows[]`（服务端来自 `health_snapshots` 表，**每个采集周期 60 秒写一行**），前端把它拆成 3 张折线 + 1 张告警文本卡。**图上没有 hover、没有 tooltip、没有缩放**（与主题时间轴不同）。

- 写入侧：每次采集写 `Ts`、宿主机 CPU/内存/磁盘/上下行 KB/s、EMQX 节点名、`EmqxCpuPct = node.Load1`（EMQX 5.x 无 CPU 百分比）、`EmqxMemUsedPct = memUsed/memTotal`、`EmqxConnections = 在线客户端数`、`EmqxMsgRate = (本次收+发消息总数增量)/秒`、`EmqxAlarms`（`CollectorService.cs:183-221`）。
- 绘制：`drawLine(canvasId, legendId, ts, series, unit)`（`app.js:404-462`）——图例仅列出有非空数据的序列；Y 轴 4 等分网格（共 5 条线，标签 ≥1000 转 `k`）；Y 上限 = 所有序列非空值最大值 × 1.1（最小 1）；X 轴最多 6 个标签，取 `ts.slice(5,16)`（`MM-dd HH:mm`）；折线 `lineWidth 1.5`，遇到 `null` 断线；网格 `#e5e5e5`、轴文字 `#999` 10px sans-serif。
- 告警：把每行的 `emqxAlarms` 按 `,`（正则 `,\s*`）拆分、去重，用 `；` 连接；有值才显示 `#alarm-card`（`app.js:393-400`）。
- `emqxNode`、`emqxMemUsedPct`、`srvUid` 等返回但未渲染。

**证据**：`app.js:373-462`；`health.html:41-61`；`Database.cs:431-459`。

---

## 5. 视觉与布局（用于在分系统管理后台做风格一致的新页面）

**结论**：FAS 是 **Metro / 白底灰框直角扁平** 设计语言——纯白背景、`#333` 主文字、`#ccc` 边框、**全局强制 0 圆角**、无阴影、无渐变、无动画（唯一 transition 在分系统侧）。所有页面共用一条顶部横向导航与"筛选栏 / 状态条 / 内容"三段式结构。

### 5.1 色板（`style.css` 提取）

| 用途 | 色值 | 证据 |
|------|------|------|
| 页面底色 | `#fff` | `style.css:6` |
| 主文字 | `#333` | `style.css:7` |
| 标题/强调文字 | `#000` | `style.css:22,102,146` |
| 弱化文字 | `#666`（标签）/ `#999`（次要说明、空态） | `style.css:33,49,179` |
| 边框（强） | `#ccc` | `style.css:18,45,52` |
| 边框（弱/表格内线） | `#e5e5e5` | `style.css:107` |
| 面（表头/筛选栏/状态条/卡头） | `#f5f5f5` / `#fafafa` | `style.css:31,46,97,135,146` |
| 主色/链接/焦点 | `#1565c0` | `style.css:34,114,172` |
| 成功 | `#2e7d32` | `style.css:36` |
| 危险/错误 | `#c62828` | `style.css:37,116` |
| 警告 | `#e65100` | `style.css:117` |
| 排名第 3 | `#f9a825` | `style.css:118` |
| 图表备用色 | `#d32f2f`、`#6a1b9a`（仅 JS 内联） | `app.js:377,389` |

### 5.2 字体与字号

- 字体栈：`"Segoe UI", "Microsoft YaHei", sans-serif`（`style.css:5`）；等宽：`Consolas, "Courier New", monospace`（`.mono`，`style.css:171`）。
- 基准 14px（`style.css:8`）；顶栏标题 16px/600；导航 13px；表头 12px/600；单元格 13px；筛选标签 12px；状态条 12px；图表轴文字 10px sans-serif；明细表头 11px、明细单元 12px；模态标题 14px；auth 卡片标题 15px。
- 数字列 `.num` 右对齐 + `font-variant-numeric: tabular-nums`（`style.css:113`）。

### 5.3 布局与间距

| 区块 | 关键度量 | 证据 |
|------|----------|------|
| `.topbar` | `display:flex; align-items:center; gap:18px; padding:10px 16px; border-bottom:1px solid #ccc; flex-wrap:wrap` | `style.css:13-21` |
| `.topbar-nav a` | `padding:5px 14px; font-size:13px; border:1px solid transparent`；hover `background:#f5f5f5`；**active = `border-color:#333` + `font-weight:600` + `color:#000`**（即"1px 方框高亮"，不是下划线） | `style.css:24-32` |
| `.topbar-right` | `margin-left:auto; gap:12px; font-size:12px; color:#666`；链接 `#1565c0` | `style.css:33-35` |
| `.filter-bar` | `gap:10px; padding:10px 16px; border-bottom:1px solid #ccc; background:#fafafa; flex-wrap:wrap` | `style.css:40-48` |
| `.chip`（范围/排序/粒度按钮） | `border:1px solid #ccc; background:#fff; padding:4px 12px; font-size:12px`；hover `#f0f0f0`；**active = 反色 `background:#333; color:#fff`** | `style.css:50-59` |
| `.btn` | `border:1px solid #333; padding:6px 18px; font-size:13px`；`.btn-primary` 反色（`#333`底白字，hover `#555`）；`.btn-small` `3px 10px/12px`；`:disabled opacity:.5` | `style.css:78-91` |
| `.table-wrap` | `padding:0 16px 24px; overflow-x:auto`（移动端 `0 8px 16px`） | `style.css:94,198` |
| `table` | `width:100%; border-collapse:collapse; margin-top:12px; min-width:768px`（宽表横向滚动） | `style.css:95` |
| `th` / `td` | th `background:#f5f5f5; border:1px solid #ccc; padding:8px 10px; white-space:nowrap`；td `border:1px solid #e5e5e5; padding:7px 10px`；`tbody tr:hover background:#fafafa` | `style.css:96-112` |
| `.detail-row` / `.detail-box` | 明细行 `background:#fafafa; padding:0`；明细盒 `padding:10px 16px 14px; border-top:1px dashed #ccc`；`.detail-table min-width:640px` | `style.css:120-127` |
| `.stats-bar` | `gap:20px; padding:8px 16px; border-bottom:1px solid #ccc; background:#fafafa; font-size:12px; color:#666`；`.stat-spacer{flex:1}` 把右侧内容推到行尾 | `style.css:130-141` |
| `.chart-box` / `.chart-card` | box `padding:12px 16px 20px`；card `border:1px solid #ccc; margin-top:12px`；卡头 `.chart-title` `font-size:13px/600; padding:8px 12px; border-bottom:1px solid #ccc; background:#fafafa`；画布区 `padding:10px 12px`；`canvas{display:block;width:100%;height:180px}`（主题时间轴内联覆盖为 200px） | `style.css:143-151`；`topics.html:59` |
| `.legend` | `gap:16px; padding:0 12px 10px; font-size:12px; color:#666`；色块 `.legend-swatch 10×10px` | `style.css:149-151` |
| `.auth-wrap/.auth-card` | wrap `justify-content:center; padding:60px 16px`；card `border:1px solid #ccc; width:360px`；标题条 15px/600 + `#fafafa` 底 | `style.css:154-157` |
| `.form-row` | `margin-bottom:12px`；label `display:block; font-size:12px; color:#666; margin-bottom:4px` | `style.css:158-159` |
| `.form-msg` | `font-size:12px; margin-top:8px; min-height:16px`；`.err #c62828` / `.ok #2e7d32` | `style.css:160-162` |
| `.config-section` | 与 `.chart-card` 同构：1px `#ccc` 边框 + `#fafafa` 标题条 + `padding:14px 16px` 内容 | `style.css:163-165` |
| 模态 `.modal-mask/.modal` | 遮罩 `rgba(0,0,0,.35)`，`padding:10vh 16px 16px`，`z-index:100`；模态 `border:1px solid #333; width:420px`（**无圆角无阴影**）；底部按钮区右对齐 `gap:8px` | `style.css:183-189` |
| `.page` | `max-width:1400px; margin:0 auto`（排行榜/审计等表格页未实际加该类，仅设置页用 `max-width:720px` 的 `.chart-box` 内联约束） | `style.css:170`；`settings.html:28` |
| 响应式 | 仅一条 `@media (max-width:640px)`：缩小 topbar 间距、标题 14px、表格内边距 | `style.css:195-199` |
| 全局 | `* { margin:0; padding:0; box-sizing:border-box; border-radius:0 !important; }` | `style.css:2` |

### 5.4 视觉元素清单（复刻时要保留的"零件"）

- 导航：横向 8 标签，active = 1px `#333` 方框 + 加粗。
- chip：两种状态（默认灰框白底 / active 反色黑底白字），同时用于时间范围、排序、粒度、IP 快捷按钮。
- 表格：表头 `#f5f5f5` 灰底黑字 12px，单元格 1px `#e5e5e5` 细线，行 hover `#fafafa`，数字列右对齐等宽数字。
- 徽标：`.ban-badge`（红底白字 `已拉黑`/`EMQX`，`padding:1px 6px`，11px）、`.reconnect-badge`（红字重连次数）、排名前三色（`#c62828`/`#e65100`/`#f9a825`）。
- 状态文字：`.status-ok #2e7d32` / `.status-err #c62828`，用于页头状态条与审计页开关提示。
- 图表：卡片式（`#ccc` 边框 + `#fafafa` 标题条），图例为 10×10 色块 + 名称，画布白底无网格填充。
- 进度条（仅 OTA）：`height:6px; background:#e5e5e5; border:1px solid #ccc`，填充 `#333` + `transition:width .2s`（`settings.html:179-181`）。
- 提示块：`background:#fafafa; border:1px solid #e5e5e5; padding:8px 10px`，正文 12px `#666`，关键词 `<b>` 转 `#333`（`settings.html:52-57,83-88`）。
- 空态：居中 30px padding + `#999` 13px 文案。

---

## 6. 文案（必须保留的中文标签 / 提示语）

**结论**：以下是语义关键、迁移时**不应意译或弱化**的文案（尤其身份控制与自动拉黑相关）。按页面分组，格式 `文案`（出处）。

### 6.1 导航与全局

- `FMO Audit Service`（顶栏标题，全页，`index.html:11`）
- 导航：`排行榜` / `主题统计` / `在线` / `身份审计` / `黑名单` / `健康` / `配置` / `说明`（`index.html:13-20`）
- `退出登录`（`index.html:24`）
- 页头状态：`未连接 EMQX`；服务端状态文本 `采集正常 HH:mm:ss，在线 N` / `采集失败: …` / `采集异常: …`（`app.js:41`；`CollectorService.cs:122,233,239`）
- 401 与引导：`未登录`、`系统未初始化，请先设置管理员账号`（`Program.cs:170,187`）

### 6.2 身份控制 / 自动拉黑（最高优先级，不得改写语义）

- **`身份控制（包头身份一致性，默认启用）`**（配置页卡片标题，`settings.html:101`）
- **`身份控制（最高保护）`**（说明页，`help.html:44`）
- **`自动拉黑`**（说明页标题语境：`身份控制自动拉黑标记 operator=身份控制`，`help.html:55`）
- `对 FMO/RAW 每个数据包解包头，比对包头声明的呼号/UID 与连接身份（认证服务端写入）。不一致视为身份伪造，立即自动拉黑该连接身份（踢下线 + 禁连 + 留痕）。`（`settings.html:104`）
- `关闭后降级为仅记录提醒（身份审计页可见），不自动拉黑。开放网络默认最高保护，建议保持启用。`（`settings.html:105`）
- `身份控制已启用（伪造即自动拉黑）` / `身份控制已关闭（仅记录提醒，不自动拉黑）`（审计页，`app.js:917-918`）
- `已启用（伪造即自动拉黑）` / `已关闭（仅记录提醒）`（配置页，`app.js:1081-1082,1098-1099`）
- `身份控制已启用` / `已关闭（仅记录提醒，不自动拉黑）`（保存成功提示，`app.js:1096`）
- `启用身份控制` / `关闭（仅提醒）`（按钮，`settings.html:107-108`）
- 说明页原则句：`因此审计工具默认启用身份控制（最高保护）：包头与连接身份不一致 = 伪造，立即自动拉黑该连接身份（踢下线 + 禁连 + 留痕）。开放网络里攻击成本趋近于零，默认最高保护是唯一正确的选择。`（`help.html:44`）
- `KICK 身份不符 = 伪造（自动拉黑）；WARN 未知身份 = 匿名连接无法比对（仅记录）；FAIL 非法包 = 包头不合法（长度/len 字段不符，仅记录）`（`help.html:66`）
- 自动拉黑原因模板：`身份控制: 包头声明 {pktCallsign}(UID {pktUid}) 与连接身份 {connCs}(UID {connU}) 不符`（`TopicEndpoints.cs:258`）
- 审计页处置列：`已自动拉黑` / `仅记录（身份控制关闭或拉黑失败）`（`app.js:970`）

### 6.3 排行榜页

- `时间范围` / `今天` / `昨天` / `近7天` / `近30天` / `自定义` / `至` / `排序` / `字节量` / `消息数` / `包数` / `查询` / `导出 CSV` / `自动刷新`（`index.html:29-46`）
- 统计：`共 N 个呼号`、`查询耗时 Nms`、`{from} 至 {to}`（`app.js:260-262`）
- 表头：`排名`/`呼号`/`设备数`/`总字节`/`总消息`/`总包数`/`重连次数`/`操作`（`index.html:60-67`）
- 空态：`该时间段内没有客户端流量数据`（`index.html:72`）
- 明细标题：`呼号 {name} — clientid 明细（N 行）`；明细表头 `clientid/发送字节/接收字节/发送消息/接收消息/发送包/接收包/重连`（`app.js:301-303`）
- 弹窗：`请输入起止时间`（`app.js:253`）

### 6.4 主题统计页

- `统计主题`、`{topic} /#`、`时间范围`、`今天/昨天/近7天/近30天`、`起始`、`至`、`排序`、`消息数`、`字节数`、`查询`、`导出 CSV`、`统计周期`、`10秒`、`1分钟`、`5分钟`、`1小时`、`自动刷新`（`topics.html:29-52`）
- 图表标题：`全员发包时间轴（悬停查看该时间点详情）`（`topics.html:57`）
- tooltip：`发言 N 人 · 消息 N 条 · {bytes}`、`… 共 N 人发言`、`{name}（{uid}）` + `{msg} 包`、`该时间段无数据`（`app.js:636,668-672`）
- ingest 状态：`已启用（已接收 N 条，最近 {ts}）`、`已启用但 {pending} 待确认（配置页点「测试连接」）`、`未启用主题统计（配置页开启）`（`app.js:497-502`）
- 表头：`排名/呼号/设备数/消息数/字节数/操作`（`topics.html:76-81`）
- 空态：`该时间段内没有消息数据（确认已在配置页启用主题统计，且 EMQX 规则引擎在转发）`（`topics.html:86`）
- 明细表头：`clientid/主题/消息数/字节数`（`app.js:780`）

### 6.5 在线页

- 统计：`在线 N 个客户端`、`未连接 EMQX`、`（数据更新于 {updated_at}，每 60 秒采集一次）`（`app.js:856-863`）
- 表头：`呼号/clientid/IP 地址/连接时间/发送/接收/操作`（`online.html:41-47`）
- 在线时长：`刚连接` / `N 分钟` / `N 小时 M 分`（`app.js:843-846`）
- 空态：`当前没有在线客户端（或尚未连接 EMQX）`（`online.html:52`）

### 6.6 身份审计页

- 类型筛选：`全部异常` / `身份不符` / `未知身份` / `非法包`（`audit.html:39-42`）
- 计数：`KICK n · WARN n · FAIL n（显示 N 条）`（`app.js:957`）
- 表头：`判定/时间/连接身份（实际连接者）/包头声明（payload 自称）/clientid/包长/帧数/S表/CRC/处置`（`audit.html:61-70`）
- 空态：`该时间段内没有异常审计事件（包头身份与连接身份一致 = 正常放行，不记录）`（`audit.html:75`）

### 6.7 黑名单页

- `手动拉黑呼号`（按钮）、`当前生效黑名单（EMQX 拒绝连接，到期自动解除）`、`操作历史（拉黑/解封留痕）`（`blacklist.html:31,36,56`）
- 表头：`呼号/原因/到期时间/操作人/拉黑时间/操作`；`操作/呼号/原因/封禁到期/操作人/时间`（`blacklist.html:41-46,61-66`）
- 状态：`未连接 EMQX（黑名单操作不可用，仅展示本地记录）`、`当前生效 N 个[，EMQX 侧另有 M 个手动拉黑]`、`EMQX 手动`、`请到 EMQX 解封`、`永久`、`拉黑`、`解封`（`app.js:1011-1047`）
- 空态：`当前没有生效中的黑名单`、`暂无操作记录`（`blacklist.html:51,71`）
- 弹窗：`手动拉黑呼号`/`拉黑呼号 {who}`、`呼号（username）`、`如 BG5ABC`、`原因（留痕，建议填写）`、`如：伪造数据包干扰信道`、`封禁时长（到期自动解除）`、`永久/1小时/6小时/24小时/自定义`、`取消`、`拉黑并踢下线`、`请输入呼号`、`请选择自定义到期时间`、`正在拉黑…`、`已拉黑 {who}，踢下线 {kicked} 个在线客户端`、`已拉黑 {who}（当前无在线客户端）`（`app.js:106-167`）
- 解封确认：`确认解封 {who}？解封后该呼号可重新连接 EMQX。`（`app.js:180`）
- 服务端错误：`呼号不能为空`、`未配置 EMQX 连接，无法执行拉黑/解封`、`拉黑失败: …`、`解封失败: …`、`到期时间格式应为 yyyy-MM-ddTHH:mm`、`到期时间必须晚于当前时间`（`BlacklistEndpoints.cs:19-58`）

### 6.8 健康页

- 卡片标题：`宿主机 CPU / 内存 / 磁盘（%）`、`宿主机网络（KB/s）`、`EMQX 连接数 / 消息速率（条/s）`、`活跃告警`（`health.html:43,48,53,58`）
- 图例名：`CPU %`、`内存 %`、`磁盘 %`、`下行 KB/s`、`上行 KB/s`、`连接数`、`消息速率 条/s`、`节点负载 load1`（`app.js:377-390`）

### 6.9 配置页

- 引导：`首次使用引导（3 步）`、`1. 管理员账号（完成）→ 2. 连接 EMQX（下方）→ 3. 启用主题统计（下方）`、`连接成功并自检通过后自动完成引导。`（`settings.html:30-33`）
- EMQX：`EMQX 连接（步骤 2）`、`EMQX 地址（如 http://192.168.1.100:18083）`、`http://服务器IP:18083`、`API Key`、`API Secret`、`API 密钥获取方法`、`EMQX Dashboard → 系统设置 → API 密钥 → 创建 → 密钥名字随便填 → 点击确定`、`创建后立即复制 API KEY 与 Secret KEY——Secret KEY 只显示一次，丢失需重新创建`、`角色选择 administrator（如自定义权限需包含：客户端、连接、黑名单等范围）`、**`⚠️ Dashboard 的登录账号（admin）不能调用 API，必须使用 API 密钥`**、`保存并连接`、`断开监控`、`正在测试连接…`、`连接成功，开始采集（1 分钟后出数据）`、`已断开监控`、`请填写地址、API Key、API Secret`、`已连接 EMQX（API Secret 不显示，如需修改请重新填写）`（`settings.html:38-63`；`app.js:1215,1223-1235`）
- 主题统计：`主题统计（规则引擎消息统计）`、`状态：`、`未启用`/`已启用`/`已启用（部分步骤待确认）`/`已启用（配置有异常）`、`已接收消息：`、`（最后接收 -）`、`Webhook 地址：`、`统计主题（规则引擎按 主题/# 匹配，含子主题）`、`FMO/RAW`、`Webhook 地址（EMQX 规则引擎主动上报到本工具的接口，必须对 EMQX 所有节点可见）`、`http://服务器IP:9527/api/ingest`、`数据流向`、`主题统计由 EMQX 规则引擎主动上报到本工具（Webhook 推送），而非本工具去 EMQX 查询——因此 Webhook 地址必须对 EMQX 所有节点可见。`、`同局域网`/`异地集群`/`公网地址` 三条建议、`启用主题统计`、`停用`、`测试连接`、`启用后自动在 EMQX 上创建规则引擎（连接器 emqx-monitor-bridge + 规则），只统计该主题下的消息，其他主题不采集。`、`已启用，统计主题 {topic} /#（1 分钟后出数据）`、`已停用，规则引擎已从 EMQX 移除`、`正在配置 EMQX 规则引擎…`、`正在测试…`、`✅ 链路正常，主题统计工作正常`/`✅ 链路正常`、`❌ 链路不完整`、`⚠️ 以下步骤响应超时（集群同步慢，资源可能已创建成功）：`、`❌ 以下步骤配置失败（主题统计仍已启用，数据照常接收）：`、`请点击「测试连接」验证实际状态，或到 EMQX Dashboard → 集成 → 连接器/规则 查看。`、`已填入 {ip}:{port}（EMQX 节点需能访问该地址）`、内网/公网警示 `⚠️ Webhook 是内网地址（{whHost}），而 EMQX 地址是公网（{emqxHost}）——异地节点可能无法上报。请确认 Webhook 地址对所有 EMQX 节点可见，或改用上方公网地址。`（`settings.html:68-96`；`app.js:1249-1359,1382-1404`）
- `连接器 emqx-monitor-bridge`、`动作|桥接 emqx-monitor-ingest-action|emqx-monitor-bridge`、`规则 emqx-monitor-topic-rule`、`存在且已启用`/`存在但未启用`/`不存在`（`app.js:1271-1273,1392-1394`）
- 自检：`兼容性自检（EMQX 版本 + API）`、`运行自检`、`正在检测…`、`检测完成：EMQX {version}`、`检测失败`、`支持 EMQX 5.x（5.1+）。不支持的版本会提示升级建议。`（`settings.html:115-122`；`app.js:1423-1434`）
- 数据管理：`数据管理`、`呼号增量：`、`主题统计：`、`健康快照：`、`清空全部统计数据`、`清空后从当前时刻重新统计（保留管理员账号与 EMQX 配置），30 天内无法恢复。`、`重置审计监控工具`、`完全重置：删除管理员账号、EMQX 配置与全部数据，恢复首次安装状态（需重新设置管理员）。EMQX 上的规则引擎将一并移除。`、确认框三条文案（见 §4.7）、`已清空（呼号增量 N / 主题 N / 健康 N 行），从当前时刻重新统计`、`重置完成，正在跳转首次设置…`（`settings.html:127-139`；`app.js:1452-1477`）
- 密码：`修改管理员密码`、`旧密码`、`新密码（至少 8 个字符）`、`修改密码`、`请填写旧密码，新密码至少 8 个字符`、`密码已修改`、`修改失败`（`settings.html:144-156`；`app.js:1242-1245`）
- OTA：`版本与更新（OTA）`、`当前版本：加载中…`、`最新版本：`、`部署模式：`、`检查更新`、`立即更新`、`查看版本更新说明 ↗`、`正在检查更新…`、`正在下载新版本…`、`解压更新包…`、`生成替换脚本…`、`已就绪，服务即将重启…`、`服务正在重启…`、`重启超时，请手动刷新页面`、`已是最新版本`、`发现新版本 v{latest}，可立即更新`、`确认更新到最新版本？更新期间服务将自动重启，页面会短暂中断。`、步骤词 `下载 解压 替换 重启`、模式中文 `裸机/服务部署（支持自更新）`/`Docker 容器（不支持自更新）`/`手动部署`（`settings.html:162-184`；`app.js:1107,1111-1200`）
- 运行信息：`运行信息`、`监听端口：`、`数据保留：`、`采集状态：`、`在线客户端：`、`采集精度：1 分钟。增量数据仅在客户端在线时记录，离线期间无流量数据。`、`{N} 天`、`采集中`/`未采集`（`settings.html:189-195`；`app.js:1211-1214`）

### 6.10 登录 / 初始化页

- `FMO Audit Service - 登录`、`用户名`、`密码`、`登录`、`请输入用户名和密码`、`网络错误：{message}`（`login.html:12-45`）
- `初始化管理员账号`、`用户名（至少 3 个字符）`、`密码（至少 8 个字符）`、`确认密码`、`创建管理员`、`用户名至少 3 个字符`、`密码至少 8 个字符`、`两次输入的密码不一致`、`创建成功，正在进入…`（`setup.html:12-44`）
- 服务端：`请输入用户名和密码`、`用户名或密码错误（剩余 N 次机会）`、`连续失败 5 次，账号锁定 5 分钟`、`尝试过于频繁，请稍后再试（全局限流）`、`尝试过于频繁，已临时限流 60 秒`、`尝试次数过多，已锁定至 HH:mm:ss，请稍后再试`、`系统已初始化，不能重复设置管理员`、`系统未初始化`、`新密码至少 8 个字符`（`Program.cs:254`；`AuthService.cs:38-108`）

### 6.11 帮助页长文案（要点句，建议整段保留）

- `让"身份可信"和"网络开放"同时成立`、`呼号是考试授予、受国际承认、终身绑定的法定身份`、`三层 PKI 信任链（Root CA → 中间机构 → 用户证书）`、`先有台站、先有呼号，再自然形成通联`（`help.html:32-34`）
- `认证可信 ≠ 数据可信——数据包里的包头是明文声明，不带签名`、`攻击者用自己的合法身份连上服务器，然后在数据包包头里写入别人的呼号/UID——冒充他人广播`、`FMO 4.0 把认证（技术：证书链可验证）与责任（治理：行为归属具体个人）分为两个独立维度`（`help.html:41-43`）
- `管理员操作说明`：`拉黑`：`排行榜 / 主题统计 / 在线列表 → 呼号行「拉黑」→ 原因 + 时长（永久或临时，到期自动解除）。立即踢下线并禁止重连`；`解封`：`黑名单页 → 「解封」。误伤有后悔药，留痕可追溯`；`身份控制开关（设置页）：默认启用。关闭 = 允许伪造包通过（仅记录不处置）——这是管理员自行选择，关闭后网络身份不可信，风险自负`；`数据：保留 30 天自动清理；备份直接复制 db 文件；清空/重置在配置页`（`help.html:63-67`）
- `技术说明`：`数据精度：主题统计 10 秒 / 呼号统计 1 分钟 / 在线列表 60 秒采集`、`包头审计：FMO/RAW payload 前 64 字节（version/flags/UID/callsign/len/frameNum/checkSum/smeter/srvUID），包头明文不加密——包头是声明，连接身份是真相`、`CRC 由设备端核验，审计侧仅展示参考，不据此判定`、`数据按服务器本地时间存储，请确保服务器时区为 Asia/Shanghai`（`help.html:74-77`）

### 6.12 空态与错误文案汇总（服务端）

- 时间：`时间格式应为 yyyy-MM-ddTHH:mm`、`结束时间不能早于开始时间`、`时间跨度不能超过 31 天`（`WebHelpers.cs:13-15`）
- 时间轴：`时间范围过大（补零后超过 4 万点）。请缩小时间范围或使用更粗的统计周期（如 1 小时）`（`TopicEndpoints.cs:193`）
- 主题：`请先在 EMQX 连接配置中保存连接`、`未配置 EMQX 连接`（`TopicEndpoints.cs:93,142`）
- 主题启用异常 hint：`主题统计已启用（数据照常接收）。配置存在异常，请到 EMQX Dashboard → 集成 → 连接器/规则 查看，或修复后重新启用/点「测试连接」。`（`TopicEndpoints.cs:123`）；`dashboard_hint`：`链路不完整。请到 EMQX Dashboard → 集成 → 连接器/规则 查看真实状态，或重新启用主题统计`（`TopicEndpoints.cs:160`）
- Webhook：`invalid token`、`bad content type`（`TopicEndpoints.cs:21,23`）
- 更新：`容器内不支持自更新，请使用 docker pull 更新镜像`、`当前为 Docker 部署，不支持自更新。请使用: docker pull 新镜像 && docker compose up -d`（`UpdateEndpoints.cs:23,33`）
- 重置失败：`清理 EMQX 规则引擎失败: {err}（可稍后手动在 EMQX 删除 emqx-monitor-* 资源）`（`Program.cs:445`）

---

## 7. 与分系统管理后台的冲突点

### 7.1 结论

1. **导航必须重组**：FAS 是 8 个平级页面 + 独立登录页；分系统 `admin/index.html` 是**单文件 SPA-ish 标签页**，现有标签为 `注册系统`(**`data-page="register"`**)、`SAS 配置`(**`data-page="sas"`**)、**`语音监控`(`data-page="monitor"`)**（注意：实际是 **3 个**标签，不是 2 个，`admin/index.html:703-705`）。并入后建议：一级标签保持 3 个不变（或把 FAS 收成 1 个新一级标签），FAS 的 8 个页面降为**二级子标签**。
2. **风格必须重绘**：FAS 白底直角 Metro（`#fff`/`#333`/`#ccc`/圆角 0）与 admin 深色霓虹（`#0a0e1a`/`#00e5ff`/`border-radius:8-10px`/发光边框）相反；且 admin 已有 `.table-wrap`、`.stats-bar`、`.stat-card`、`.nav-tab`、`.sas-card` 等类名，**与 FAS 的 `style.css` 同名类冲突**（例如两边都有 `.table-wrap`、`.stats-bar`，但一个是浅色直角、一个是深色圆角；`.nav-tab` 在 admin 是标签，FAS 用 `.topbar-nav a`）。直接引入 FAS 的 style.css 会污染/被污染。
3. **同名不同义的 API**（Python 端已存在，必须改名或加前缀，`api_server.py` 侧证据见 §7.3）。
4. **同名不同义的概念**：`在线用户/当前在线` vs `在线客户端`；`呼号` 的两种含义；`黑名单` vs `白名单/吊销`；`身份审计` vs `认证规则`；`主题统计时间轴` vs `语音监控瀑布图`；`/api/health` vs `/api/health`。

### 7.2 导航组织建议（结论）

**方案 A（推荐）**：保留 admin 现有三个一级标签，新增第 4 个一级标签 **`审计监控`**：

```
注册系统 | SAS 配置 | 语音监控 | 审计监控
                                   ├─ 排行榜
                                   ├─ 主题统计
                                   ├─ 在线客户端   ← 改名，避免与"注册系统"的"当前在线"混淆
                                   ├─ 身份审计
                                   ├─ 黑名单
                                   ├─ 健康
                                   ├─ 连接配置     ← 原"配置"，避免与"SAS 配置"字面撞车
                                   └─ 说明
```

理由：`注册系统` 与 `SAS 配置` 是**面向业务与 CA 治理**的入口，FAS 的 8 页是**面向运行监控/审计**的一族，混在同一层会让"配置"歧义（EMQX 连接配置 vs SAS 配置），也会让"在线"歧义（已注册用户的在线状态 vs EMQX 在线客户端）。

**方案 B（更省事，但导航变长）**：一级标签直接展开为 `注册系统 / SAS 配置 / 语音监控 / 审计监控-排行榜 / 审计监控-主题统计 / …` —— 不推荐，8 个新标签会让 nav 溢出（admin 已有 `@media` 里 `overflow-x:auto` 的兜底，`admin/index.html:669-670`）。

**方案 C**：把"主题统计时间轴"并入现有 `语音监控` 标签（两者都是同一 MQTT 主题的观察窗口，一个看音量/音频段，一个看消息计数），把 `健康` 并入新的 `系统状态`，FAS 原 8 页压缩为 5 页。适合希望减少标签数量的场景，但会损失"时间轴按 10 秒/1 分钟/5 分钟/1 小时聚合"的独立入口语义。

### 7.3 同名但语义不同的清单

| 名称 | FAS 语义 | 分系统 admin 语义 | 冲突处理 | 证据 |
|------|----------|-------------------|----------|------|
| `在线用户` / `当前在线` | —（FAS 不叫这个） | 已注册账户的在线状态（`u.online`，来自用户库/心跳） | FAS 侧一律称 **`在线客户端`**，字段用 `clientid` | `admin/index.html:691,994,981` |
| `在线客户端` | EMQX 当前连接的 MQTT 客户端（`clientid`/`IP`/`connected_at`/累计收发字节） | —（admin 无此概念） | 保持 FAS 命名，避免与"在线用户"并列时被误读 | `online.html:41-47`；`Program.cs:396-409` |
| `呼号` | MQTT `client_attrs.callsign` 或 `username`，可能为空 → 回退显示 `clientid`（匿名） | 注册用户账号标识（唯一、绑定证书/白名单） | FAS 行需保留 `isAnonymous`/`is_anonymous` 标记，UI 上区分"匿名客户端" | `Program.cs:398-402`；`Database.cs:1088-1099`；`app.js:83-89` |
| `黑名单` | EMQX `banned` 按 **username** 粒度拒绝连接 + 本地 `blacklist_audit` 留痕，含"身份控制"自动拉黑 | admin 只有 **`呼号白名单`**（SAS 认证规则）与**证书吊销**（`/api/cert/revoke`） | 两者是**不同执行层**（认证/证书层 vs EMQX 连接层），UI 上要写清"黑名单在 EMQX 层执行"，并在帮助页解释与白名单/吊销的关系 | `BlacklistEndpoints.cs:12-45`；`admin/index.html:870-872,1574-1579` |
| `健康` | 历史快照时间序列（60 秒/点）：宿主机 CPU/内存/磁盘/网速 + EMQX 连接数/消息速率/告警 | `/api/health` 是**服务存活探针**（`{'ok':true}` 类） | 必须改名，如 `/api/audit/health-series` 与页面 `系统状态-历史曲线` | `Program.cs:339-345`；`api_server.py:964` |
| `配置` | EMQX 连接（URL/API Key/Secret）+ 主题统计 + 身份控制 + 数据管理 + OTA | `/api/config` 是 SAS/APP 配置（登录地址等），页面标签叫 `SAS 配置` | FAS 侧改名 `连接配置` / `EMQX 连接`；API 加前缀 | `Program.cs:282-317`；`api_server.py:947,1043`；`admin/index.html:704` |
| `身份审计` | 逐包比对包头声明 vs 连接身份（KICK/WARN/FAIL），可自动拉黑 | `SAS 配置` 里的 `认证规则配置`（白名单/证书规则）是**连接前**的准入 | 作为"责任层"，与"认证层"并列解释（help.html 已有该论述，可直接复用） | `TopicEndpoints.cs:216-310`；`help.html:41-44`；`admin/index.html:863` |
| `主题统计`（时间轴） | 按 10s/1m/5m/1h 聚合的**消息计数**曲线，hover 显示该桶 Top 呼号 | `语音监控` 是音频段瀑布图 + 实时音频（`/api/monitor/*`，`MON.api='/api/monitor'`） | 二者都看 FMO/RAW，建议同一区域内以子标签区分"计数/音频"，不要合并成一张图 | `topics.html:56-62`；`admin/index.html:912,1860-1861` |
| `/api/status` | FAS 服务状态（version/initialized/configured/collecting/wizard_done/…） | admin 用 `/api/stats`（计数）与 `/api/monitor/status` | 命名不冲突但易混；FAS 侧建议 `/api/audit/status` | `Program.cs:230-242`；`api_server.py:942,969` |
| `/api/login` | FAS 管理员 Cookie 会话（单管理员、PBKDF2、锁定策略） | APP/用户登录（`/api/login`，返回用户会话/token） | **同名路径直接冲突**，必须加前缀 | `Program.cs:251-264`；`api_server.py:1035` |
| `/api/config`（POST） | 写 EMQX 凭据 | 写 SAS/APP 配置 | 同上，必须加前缀 | `Program.cs:294`；`api_server.py:1043` |
| `/api/ingest` | EMQX 规则引擎 webhook（`X-Ingest-Token`） | 无 | 需与 Python 服务的公网/内网监听策略对齐（python `api_server.py` 对写接口做了路径白名单，`api_server.py:770-781`） | `TopicEndpoints.cs:14-23`；`api_server.py:770-781` |
| 单文件 SPA vs MPA | 11 个独立 HTML，靠 `location.pathname` 分派 | 1 个 `admin/index.html`，靠 `.nav-tab[data-page]` 显隐切换 | 并入时**统一走 admin 的标签页机制**（同一 DOM，无整页跳转），避免用户被踢出登录态与重复加载 | `app.js:6`；`admin/index.html:1286-1330` |

### 7.4 其他工程冲突点

- **两套认证并存**：admin 页面只在管理端口（`port+1`）暴露、`/admin` 由 Python 直接吐 HTML，没有登录（`api_server.py:893-894,1050-1063,2471-2476`）；FAS 是 Cookie 会话 + 全站门控。并入后需要决定：审计页面走"管理端口即信任"，还是保留 FAS 的管理员登录。
- **静态资源托管方式**：FAS 用 `EmbeddedFileProvider`（单文件发布内嵌 wwwroot，`Program.cs:206-209`），Python 是磁盘文件（`os.path.join(BASE_DIR,'admin','index.html')`）。新增页面要落到磁盘并纳入 Python 的静态服务分支。
- **响应体上限**：FAS 全局 1 MB（`Program.cs:67-68`），Python 端需确认 `Content-Length` 处理，尤其 `/api/ingest`。
- **安全头**：FAS 全站发 `X-Frame-Options: DENY`（`Program.cs:131-137`）。若分系统要把审计页嵌进 iframe 会被拒——并入时应改为同页标签而非 iframe。

---

## 8. 并入 Python 后的实现建议

### 8.1 可以合并 / 可以砍掉的

| 项 | 建议 | 理由 |
|----|------|------|
| `login.html` + `setup.html` + `/api/login` + `/api/setup` + `/api/logout` + `/api/change-password` | **可以砍掉**，改为沿用分系统"管理端口即信任"的现状 | 管理端口已不对外（`api_server.py:2471-2495` 打印"管理端口: N（内网，勿映射公网）"）。若必须保留多用户审计，再单独设计，不要照搬 FAS 的单管理员 Cookie 会话 |
| `help.html` | **合并进一个"说明/帮助"抽屉或模态** | 纯静态文案，无需独立页面与路由；内容可原样搬运（尤其 §6.11 的身份控制论述） |
| `topics.html` 的排行榜表格 | **与 `index.html` 排行榜合并为一个页面 + 数据源切换（呼号流量 / 主题消息）** | 两张表列结构几乎一致（前者多"字节/包数"，后者多"字节"少"包数"），同一次查询范围内展示，用户对比成本更低。若担心语义混淆，退一步：保留两个子标签但共享时间范围控件状态 |
| `settings.html` 的 OTA 卡片 + `/api/update/*` 三个端点 | **建议直接砍掉** | Python 分系统有自己的部署方式（`install.sh`/`build_release.sh`/systemd），跨生态自更新会引入进程退出/重启语义（`UpdateEndpoints.cs:54-55`）与 Docker 判定（`UpdateService.cs:30-52`），收益低风险高 |
| `settings.html` 的"数据管理（清空/重置）" | **保留但降级**：放进"危险操作"折叠区，保留 2/3 次确认 | 契约里这是真实运维需求（`Program.cs:424-456`），且确认文案已经过设计 |
| `health.html` 的三条曲线 + 告警 | **合并进新的"系统状态"页**，与 FAS 的 `/api/status` 服务状态、EMQX 连接状态并列 | 运维视角下"服务活着吗/资源够吗/EMQX 报警了吗"是同一屏的事 |
| 黑名单页 | **必须独立成页（或独立子标签）** | 唯一有写操作 + 留痕 + 与 EMQX 强耦合（`banned` API）+ 需要"本地 vs EMQX 侧"对照（`BlacklistEndpoints.cs:66-81`），塞进别的页面会削弱"谁被拉黑/谁拉黑的"可核查性 |
| 身份审计页 | **必须独立成页** | 逐包事件的表格（10 列，含 CRC/S表/帧数），需要独立的类型筛选与计数行；与黑名单是"发现"与"处置"两个动作，混排会破坏"先看证据再拉黑"的流程 |
| 在线客户端页 | **可独立成子标签，但不要与"注册系统的当前在线"同屏** | 两者数据源、刷新节奏、含匿名行完全不同（§7.3） |
| 主题统计时间轴（缩放/平移/双击复位） | **可以显著简化**：改用现成图表库的 `dataZoom`（或直接给 4 个粒度 chip + 时间范围即可，不提供自由缩放） | 手写 Canvas 的 wheel/drag/dblclick 交互代码量大（`app.js:570-747` 约 180 行），且现有实现有"wheel 监听器随重绘累积"的缺陷；Python 端用 ECharts/uPlot 一行配置即可获得同等体验 |
| 自动刷新 | **保留 30 秒 + `document.hidden` 跳过 + 勾选框** | 这是用户可预期的行为；注意 FAS 的"主题统计自动刷新不刷排行榜"是刻意的（避免打断用户正在看的排行），新实现要明确取舍 |
| 分页 | **无需引入** | 契约里前端上限 200/300 行、导出 5000 行、时间轴 4 万点上限（`TopicEndpoints.cs:192`）已足够；真要做，也只需"加载更多"而非页码 |
| CSV 导出 | **保留为普通 `<a download>` 或按钮触发下载**，但**务必保留 BOM 与公式注入防护** | Excel 中文兼容（`\uFEFF`）与安全（前缀 `'`）都是硬需求（`Program.cs:355`；`WebHelpers.cs:19-25`）；Python 端用 `csv` 模块 + `io.StringIO`，注意 `newline=''` 与 `utf-8-sig` |

### 8.2 必须独立、必须保留语义的

1. **身份控制开关 + 自动拉黑链路**：`GET/POST` 开关（默认 `true`，缺省即启用）、KICK 判定（包头呼号+UID 双比对）、自动 `BanAsync(连接呼号, reason, until=null)`、留痕 `operator="身份控制"`、成功后即时刷新在线列表（`TopicEndpoints.cs:255-282`）。文案必须含"身份控制（最高保护）""立即自动拉黑""踢下线 + 禁连 + 留痕"（§6.2）。
2. **黑名单写操作与留痕**：`ban`/`unban` 的 `who` 粒度（**username**，不是 clientid）、`until` 本地时间格式 `yyyy-MM-ddTHH:mm` 且必须晚于当前、失败不写流水、成功后即时刷新在线缓存（`BlacklistEndpoints.cs:15-64`）。
3. **在线列表"读缓存不查 EMQX"**：FAS 由采集循环 60 秒写入 `LastClients`，`/api/online` 只读内存（`Program.cs:385-388`；`CollectorService.cs:79,180-181`）。Python 端必须保持这个"查询不触发上游请求"的性质，否则 EMQX 会被前端刷新打爆。响应里要带 `updated_at` 让用户知道数据新鲜度。
4. **时间轴补零的诚实性**：缺数据的桶填 0 而不是跳过（`Database.cs:683-717` 注释即写明"时间轴必须诚实——空时段显示 0，而不是压缩拼接"）。
5. **`/api/ingest` 的定长 token 比较**：Python 用 `hmac.compare_digest(got, token)`，Header 名保持 `X-Ingest-Token`；token 持久化、随机 32 hex；Content-Type 必须 JSON（`TopicEndpoints.cs:16-23`）。**不要**把 `/api/ingest` 放进需要登录的门控里——它是给 EMQX 规则引擎调的。
6. **时间范围解析规则**：`%Y-%m-%dT%H:%M` 严格解析、秒归零、`to>=from`、跨度 ≤31 天（`WebHelpers.cs:9-17`）；错误消息保持中文原文，前端会直接显示。

### 8.3 更简单的实现方式（可替代 FAS 的复杂处）

| FAS 做法 | 更简单的做法 | 备注 |
|----------|--------------|------|
| 手写 Canvas 折线（`drawLine`/`drawTimeline`，共约 240 行 JS） | ECharts / uPlot / Chart.js；时间轴用 `dataZoom: 'inside'` 得到滚轮缩放 + 拖拽，`tooltip.formatter` 复刻 hover 内容 | 悬停内容字段已在 §4.4 明确，可直接喂 `topics[]` |
| `location.href` 导航下载 CSV | `fetch` + `Blob` + `URL.createObjectURL`，或 `<a download>` | 顺便解决"范围非法时浏览器显示 JSON"的问题：先 `fetch` 判断 `content-type` |
| 自定义模态框拉黑弹窗（`openBanModal`） | admin 已有自己的"自定义确认模态框"与 Toast（`admin/index.html:1215-1248`），直接复用 | 但字段必须完整：`who`（可空=手动输入）、`reason` 多行、时长 `永久/1/6/24/自定义` |
| 每页 `refreshStatus()` 30s 拉 `/api/status` | 在 admin 顶栏做**一个全局轮询**，推给所有子页 | 减少 8 倍请求量 |
| 客户端 60s 黑名单缓存（`blMap`） | 由全局状态管理（一个 store）+ 操作后失效 | 语义保留（列表页要即时反映拉黑状态） |
| `setInterval` + `document.hidden` 手动判断 | 统一一个 `useVisiblePolling` 之类的小工具函数 | 保留"页面隐藏不刷"的行为 |
| 服务端四件套状态报告（connector/action|bridge/rule） | Python 端若不复用 EMQX 规则引擎，可改为"直接订阅 MQTT 主题计数"（Python 可自建 MQTT 客户端） | 这是最大的一处架构可简化点：FAS 的 `/api/ingest` + 规则引擎 + 四件套自检占了 settings 页近半复杂度（`TopicEndpoints.cs:87-212`）。若分系统已有 MQTT 连接（`admin/index.html` 的 `MON.api` 与"语音监控"已连 MQTT，`api_server.py:2509` 打印"语音监控: 已启动（MQTT …）"），**可以直接在 Python 侧订阅 FMO/RAW 计数**，省掉 webhook 与 token，也省掉"Webhook 地址必须对 EMQX 所有节点可见"的部署陷阱 | 

### 8.4 Python 侧契约速查（重命名后的建议映射）

| FAS 路径 | Python 建议路径 | 说明 |
|----------|-----------------|------|
| `GET /api/status` | `GET /api/audit/status` | 保留 `collecting`/`configured`/`last_status`/`online_clients` 字段名 |
| `GET /api/online` | `GET /api/audit/online` | **字段名必须原样**：`collecting`、`updated_at`、`total`、`rows[].{name,uid,is_anonymous,clientid,ip,connected_at,send_oct,recv_oct}` |
| `GET /api/leaderboard` | `GET /api/audit/leaderboard` | `from`/`to`/`order`(oct,msg,pkt)/`limit`；`rows[].{name,uid,totalOct,totalMsg,totalPkt,deviceCount,reconnectCount,isAnonymous}` |
| `GET /api/leaderboard/{name}` | `GET /api/audit/leaderboard/{name}` | 明细字段见 §1.3 |
| `GET /api/topic-leaderboard[/{name}]` | `GET /api/audit/topic/leaderboard[/{name}]` | |
| `GET /api/topic-timeline` | `GET /api/audit/topic/timeline` | `bucket` ∈ `10s|1m|5m|1h`；返回补零序列 |
| `GET /api/audit-packets` | `GET /api/audit/packets` | `verdict`、`limit`、`counts{KICK,WARN,FAIL}` |
| `GET /api/blacklist/active|history`、`POST /api/blacklist/ban|unban` | 保持同名前缀（Python 无冲突） | |
| `GET|POST /api/identity-control` | `GET|POST /api/audit/identity-control` | 语义不可弱化 |
| `GET|POST /api/topic-config`、`GET /api/topic-test`、`POST /api/ingest` | `/api/audit/topic-config`、`/api/audit/topic-test`、`/api/audit/ingest` | 若保留 webhook 模式；token 头仍用 `X-Ingest-Token` |
| `GET /api/export.csv`、`GET /api/topic-export.csv` | `GET /api/audit/export.csv`、`GET /api/audit/topic-export.csv` | 保留 BOM + 表头中文原文 |
| `GET /api/health` | `GET /api/audit/health-series` | **必须改名**（Python 已有 `/api/health`，`api_server.py:964`） |
| `GET|POST /api/config`、`POST /api/config/disconnect` | `GET|POST /api/audit/emqx-config` | **必须改名**（Python `/api/config` 是 SAS 配置，`api_server.py:947,1043`） |
| `/api/update/*`、`/api/admin/*` | 建议不实现 OTA；`/api/admin/clear-data`、`/api/admin/reset` 可保留为 `/api/audit/admin/*` | |
| `GET /api/check` | `GET /api/audit/check` | 若不再用 EMQX 规则引擎，可整块删除 |

### 8.5 数据层落点（Python 侧）

需要 5 张表（语义照抄 FAS 的 `Database.cs`，可按 Python 习惯改名）：

| 表 | 关键列 | 写入方 | 证据 |
|----|--------|--------|------|
| `minute_stats` | 主键维度 `clientid`，`username`、`uid`、`ts='yyyy-MM-dd HH:mm:00'`，`send_oct`/`recv_oct`/`send_msg`/`recv_msg`/`send_pkt`/`recv_pkt`、`ip_address`、`reconnect` | 采集循环 60 秒（EMQX `/clients` 增量差分） | `CollectorService.cs:178`；`Database.cs:1054-1068` |
| `topic_stats` | `topic`、`username`、`uid`、`clientid`、`ts`（**10 秒粒度**）、`msg_count`、`bytes` | ingest 内存聚合 + 每 10 秒批量落库（UPSERT 累加） | `TopicIngestService.cs:15-107`；`Database.cs:1019-1028` |
| `health_snapshots` | `ts`、`host_cpu_pct`、`host_mem_used_pct`、`host_disk_used_pct`、`host_net_recv_kbps`、`host_net_send_kbps`、`emqx_node`、`emqx_cpu_pct`(=load1)、`emqx_mem_used_pct`、`emqx_connections`、`emqx_msg_rate`、`emqx_alarms` | 采集循环 60 秒 | `CollectorService.cs:207-221` |
| `audit_packets` | `ts`（毫秒）、`topic`、`clientid`、`conn_callsign`、`conn_uid`、`pkt_callsign`、`pkt_uid`、`verdict`、`len`、`frame_num`、`crc_ok`、`smeter`、`srv_uid`、`pkt_ts`、`stream_begin`、`ban` | ingest + 包头解析；FAIL 限流 60s/100 条 | `TopicEndpoints.cs:222-309` |
| `blacklist_audit` | `action`('ban'/'unban')、`as_type`('username')、`who`、`reason`、`until`、`operator`、`created_at` | ban/unban 与自动拉黑 | `Database.cs:724-744` |
| `settings` | K/V：`emqx_url`、`emqx_api_key`、`emqx_api_secret`、`identity_control`、`trust_proxy`、`wizard_done`、`ingest_token`、`topic_enabled`、`topic_name`、`topic_webhook_url`、`topic_pending`、`topic_failed` | — | `AppSettings.cs:16-65` |

数据保留：**30 天**，每 10 分钟清理一次（`Database.cs:19`；`CollectorService.cs:224-228`），对应配置页 `数据保留：{N} 天` 与 help 页 `保留 30 天自动清理；备份直接复制 db 文件`。

---

## 附录 A：核对清单（迁移完成后逐项自检）

- [ ] 35 个 API 端点全部有对端（或明确标注"已砍"及其替代）。
- [ ] 门控 4 条放行线 + 2 种拒绝行为一致（`.css`/`.js`/`favicon.ico` 免认证；`X-Ingest-Token`；未初始化只放行 setup；未登录只放行 login；已登录访问 login/setup 回首页）。
- [ ] app.js 读取的**每个字段名**都在 Python 响应里存在（尤其 `isAnonymous`/`is_anonymous`、`kicked`、`counts.KICK`、`topRows[].msg`、`allNames` 见 §3 加粗项）。
- [ ] 时间参数 `%Y-%m-%dT%H:%M`、秒归零、31 天上限、bucket 白名单 `10s/1m/5m/1h`。
- [ ] 时间轴补零 + 4 万点保护 + hover 内容（ts / 人数 / 消息数 / 字节 / Top 呼号 / "… 共 N 人发言"）。
- [ ] CSV：UTF-8 BOM、中文表头、5000 行上限、公式注入前缀 `'`。
- [ ] 8 个页面 ×（控件 / 表格列 / 空态文案）与 §2 一致；8 个导航标签与 active 态保留。
- [ ] 关键文案（§6.2 身份控制族）逐字保留。
- [ ] 视觉：并入 admin 深色主题而非照抄 FAS 浅色 CSS；避免 `.table-wrap`/`.stats-bar` 同名类互相污染。
- [ ] 导航：FAS 8 页降为二级子标签；`在线客户端`/`连接配置` 改名到位。
