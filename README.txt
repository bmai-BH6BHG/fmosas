============================================================
  FMO 注册系统 - 分系统部署包（前后端分离版）
============================================================

零、FUS 一键安装（认证 SAS + 审计 FAS 一体，推荐）
------------------------------------------------------------
一条命令完成：扫描旧 SAS/FAS → 备份 → 卸载旧系统 → 安装新 FUS → 接管 EMQX 认证 → 联合自检

  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-install.sh | sudo bash

只看本机原有系统（只读扫描，不做任何改动，不需要 sudo）:
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-install.sh | bash -s -- --scan-only

卸载:
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-uninstall.sh | sudo bash
  彻底删除加 --purge

装完的入口:
  认证/APP : http://<公网IP>:35928        审计界面: http://<内网IP>:35929/admin/bas
  注册后台 : http://<内网IP>:35929/admin

身份控制默认 warn 模式：只留证不封人；确认无误封后再到审计界面切 ban。


零、一键部署（推荐，网络拉取，服务器上无需上传本目录）
------------------------------------------------------------
发布源：GitHub Release
  仓库     : https://github.com/bmai-BH6BHG/fmosas
  固定入口 : https://github.com/bmai-BH6BHG/fmosas/releases/latest/download
  （latest/download 永远指向最新版 Release，发新版本客户端命令不用改）

【装到一台服务器上】一条命令，全自动：
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo bash

  脚本会自动：下载部署包 → 校验 SHA256 → 装依赖(cryptography) →
  生成 config.json（自动填本机 IP、自动分配端口、自动生成 subsystem_id）
  → 同步代码 → 注册开机自启 → 本机 /api/health 自检。

  卸载（保留数据）:
    curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash
  彻底删除:
    curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash -s -- --purge

【发布新版本】推一个标签即可（.github/workflows/release.yml 自动打包并创建 Release）：
  git tag v1.0.0
  git push origin v1.0.0

  本地手工打包也行，产出 dist/release-upload/（7 个文件，Release 附件区或
  对象存储都用这一份）：
    bash build_release.sh

  注意：上传/附件用的 install.sh 必须用 dist/release-upload/ 里那份
  （已注入真实分发地址），不要用仓库根目录那份占位版本。

详细说明（首次推送、发版步骤、参数、默认行为、故障排查）见 INSTALL.md
与 .github/RELEASE_GUIDE.md。
下面第一～十一章为手动部署方式，仍然有效，可作为一键脚本的参考手册。


一、概述
------------------------------------------------------------
本部署包是 FMO APP 注册系统的分系统，采用前后端分离架构：

  - 后端 API 服务（api_server.py）
      * 暴露到公网，供 APP（用户手机）通过公网调用
      * 接口：注册 / 登录 / 心跳 / 用户列表 / 统计 / 证书图片
      * 后台线程定期往【总系统】上报本分系统的用户数据

  - 前端管理页面（admin/index.html）
      * 不暴露公网，仅内网管理使用
      * 独立 HTML 文件，浏览器直接打开即可
      * 通过页面顶部输入框配置后端 API 地址

  - 上报总系统
      * 每 N 秒（config.json 的 report_interval）POST 一次
      * 目标：{master_url}/api/subsystem/report
      * 失败不影响主服务运行，仅打印日志


二、目录结构
------------------------------------------------------------
fmo-subsystem-deploy/
├── install.sh               # ★ 一键安装脚本（curl 网络拉取式，自动下载部署包）
├── uninstall.sh             # ★ 一键卸载脚本（默认保留数据，--purge 彻底删除）
├── build_release.sh         # ★ 打包脚本（生成 tar.gz + SHA256 校验清单）
├── INSTALL.md               # ★ 一键部署中文文档（推荐先读）
├── CONTRACT.md              #   一键部署改造的接口契约（维护者用）
├── dist/                    # ★ 打包产物目录
│   ├── VERSION              #   版本号 + 分发地址（上传前改这里）
│   └── release-upload/      #   ★★ 要上传到对象存储的全部文件（7 个，整个传上去）
├── api_server.py            # 后端 API 服务（主程序）
├── sas_server.py            # SAS 认证服务模块（被 api_server 导入）
├── sync_engine.py           # 分布式同步引擎模块（含 UDAC 排行上报 / 事件下发）
├── monitor.py               # 语音/信标监控线程（MQTT）
├── bridge.py                # ★ 互联桥接（集群内自动互通、成员互相校验、防回环）
├── udac.py                  # ★ UDAC 中心（信任评分 + 策略引擎 PDP + 执行点 PEP + 决策审计）
├── cert_gen.py              # Ed25519 证书生成工具
├── gen_app_key.py           # 生成 APP 签名密钥对
├── diagnose.py              # CA 上报链路诊断脚本
├── fix_bridge_acl.sh        # ★ 桥接 ACL 修复（单向语音时在对端那台跑）
├── admin/
│   ├── index.html           # 管理后台（SAS / FAS / 语音监控 / 上报地址；内网用）
│   ├── bridge.html|.js      # ★ 互联桥接页（加入集群 / broker 地址 / 链路状态）
│   └── udac.html|.js        # ★ UDAC 页（概览 / 排行 / 决策 / 策略 / 事件）
├── udac.db                  # UDAC 决策/事件/策略/排行快照（运行时数据，不随包发布）
├── config.json              # 配置文件（分系统ID/名称/域名/总系统地址等）
├── config.default.json      # 配置模板（一键安装时作为新配置的起点）
├── start.sh                 # Linux 启动脚本
├── fmo-subsystem.service    # systemd 服务文件（参考样板，一键脚本会重新生成）
├── requirements.txt         # 依赖说明（唯一第三方依赖 cryptography）
├── .gitignore               # Git 忽略规则
├── README.txt               # 本文档
└── uploads/                 # 用户上传的证书图片目录（运行时自动写入）


三、配置文件 config.json 说明
------------------------------------------------------------
{
  "subsystem_id":   "sub-001",                    // 分系统唯一 ID（上报用）
  "name":           "FMO注册系统-默认",            // 分系统名称（上报用）
  "domain":         "register.example.com",        // 分系统域名（上报用）
  "api_url":        "https://register.example.com:35928",  // 对外 API 地址（上报用）
  "port":           35928,                         // 本服务监听端口
  "master_url":     "http://127.0.0.1:35930",      // 总系统地址（上报目标）
  "report_interval": 30                            // 上报间隔（秒）
}

部署时请按实际环境修改：
  - subsystem_id : 总系统分配的唯一 ID
  - name / domain / api_url : 本分系统的对外信息
  - port : 监听端口
  - master_url : 总系统的内网/公网地址
  - report_interval : 上报频率（建议 30 秒，最低 5 秒）


四、API 接口列表
------------------------------------------------------------
所有接口均带 CORS 头（Access-Control-Allow-Origin: *），APP 可直接跨域调用。

  1. POST /api/register
     - Content-Type: multipart/form-data
     - 字段: name, callsign, phone, password, cert_photo(文件), device_cert(文件)
     - 返回: {"ok": true, "message": "注册成功"}

  2. POST /api/login
     - Content-Type: application/json
     - body: {"callsign": "BG7TEST", "password": "xxx"}
     - 返回: {"ok": true, "token": "...", "name": "...", "callsign": "..."}

  3. POST /api/heartbeat
     - Content-Type: application/json
     - body: {"token": "...", "device_info": "..."}
     - 返回: {"ok": true, "timestamp": 1787390874.48}

  4. GET /api/users
     - 返回所有用户列表（含在线状态）

  5. GET /api/stats
     - 返回 {"ok": true, "total": 150, "online": 23}

  6. GET /uploads/<filename>
     - 返回证书图片

  7. GET /api/health
     - 健康检查（便于总系统/监控探活）

  8. GET /
     - 不再返回管理后台 HTML，仅返回 JSON 提示（前后端分离）


五、上报协议
------------------------------------------------------------
本分系统每 report_interval 秒向总系统 POST 一次：

  POST {master_url}/api/subsystem/report
  Content-Type: application/json

  body:
  {
    "subsystem_id": "sub-001",
    "name": "FMO注册系统-默认",
    "domain": "register.example.com",
    "api_url": "https://register.example.com:35928",
    "total_users": 150,
    "online_users": 23,
    "users": [
      {
        "callsign": "BG7TEST",
        "name": "TestUser",
        "phone": "13800138000",
        "online": true,
        "last_heartbeat": 1787390874.48,
        "created_at": 1787390670.01
      }
    ],
    "timestamp": 1787390874.48
  }

上报使用 Python 标准库 urllib.request，无第三方依赖。
上报失败仅打印日志，不影响主服务运行。


六、部署步骤（Linux）
------------------------------------------------------------
1. 上传整个 fmo-subsystem-deploy 目录到服务器，例如 /opt/fmo-subsystem/

2. 修改 config.json，填入本分系统的实际信息

3. 给启动脚本加执行权限：
     chmod +x /opt/fmo-subsystem/start.sh

4. 手动启动测试：
     cd /opt/fmo-subsystem
     ./start.sh 35928
     或
     python3 -u api_server.py --port 35928

5. （可选）安装为 systemd 服务（开机自启）：
     cp /opt/fmo-subsystem/fmo-subsystem.service /etc/systemd/system/
     systemctl daemon-reload
     systemctl enable fmo-subsystem
     systemctl start fmo-subsystem
     systemctl status fmo-subsystem
     journalctl -u fmo-subsystem -f   # 查看日志

6. 防火墙放行端口（如需公网访问 API）：
     # iptables
     iptables -A INPUT -p tcp --dport 35928 -j ACCEPT
     # 或 firewalld
     firewall-cmd --permanent --add-port=35928/tcp
     firewall-cmd --reload
     # 或 ufw
     ufw allow 35928/tcp

7. 公网映射（nginx / 云厂商端口映射）：
     将公网 35928 端口映射到本服务 35928 端口
     注意：admin/index.html 不需要映射公网，仅内网访问


七、管理后台使用
------------------------------------------------------------
管理页由管理端口（公网口 + 1，默认 35929）直接提供，**只在内网访问，不要映射公网**：

  http://<内网IP>:35929/admin          FUS 门户（SAS / FAS 入口）
  http://<内网IP>:35929/admin/sas      SAS 配置（认证服务）
  http://<内网IP>:35929/admin/fus      FAS（认证审计）
  http://<内网IP>:35929/admin/bridge   互联桥接（加入集群 / 本机 broker 地址 / 链路状态）
  http://<内网IP>:35929/admin/udac     UDAC（信任评分 / 动态授权 / 策略 / 决策审计）
  http://<内网IP>:35929/admin/index.html  总管理页（SAS 配置 / 语音监控 / 上报地址）

注意（这一版的变化）：
  * 「注册系统」页与 APP 登录地址配置**已从分系统移除** —— 用户注册/管理统一在**总系统**做；
  * MQTT 地址配置入口挪到「语音监控」页（生效位置不变，SAS/监控仍按它接入）；
  * FMO 台站扫描页（/admin/stations）**已移除**，扫描与汇总在总系统做；
  * 页面由服务直接提供，不需要像早期那样手动打开本地 HTML 文件。


八、依赖说明
------------------------------------------------------------
本服务仅使用 Python 3 标准库，无任何第三方依赖。

需要的 Python 版本: Python 3.6+

使用的标准库模块:
  http.server, socketserver, sqlite3, json, hashlib, os, time,
  uuid, base64, re, sys, argparse, threading,
  urllib.request, urllib.error, urllib.parse

数据库: SQLite3（Python 自带 sqlite3 模块，无需单独安装）


九、与原 user_server.py 的差异
------------------------------------------------------------
1. 前后端分离
   - 原: GET / 返回管理后台 HTML（前后端耦合）
   - 新: GET / 仅返回 JSON 提示，管理后台独立为 admin/index.html

2. CORS 支持
   - 原: 仅 API 响应有 CORS 头
   - 新: 所有响应（含图片）统一加 CORS 头，便于 APP 跨域调用

3. 上报总系统
   - 原: 无上报功能
   - 新: 后台线程每 30 秒上报一次到总系统

4. 配置外置
   - 原: 端口等配置硬编码
   - 新: 通过 config.json 配置

5. 健康检查
   - 新增 GET /api/health 端点

6. API 接口完全保留
   - register / login / heartbeat / users / stats / uploads 全部保留
   - APP 已有的调用无需修改


十、日志说明
------------------------------------------------------------
启动后控制台输出示例：

  [CONFIG] 配置加载成功: subsystem_id=sub-001, name=FMO注册系统-默认
  ============================================================
    FMO 分系统后端 API 服务已启动（前后端分离版）
    监听地址: http://0.0.0.0:35928
    ...
    总系统地址: http://127.0.0.1:35930
    上报间隔: 30 秒
  ============================================================
  [REPORT] 上报线程已启动，间隔 30 秒，目标: http://127.0.0.1:35930
  [REPORT] 上报成功 -> http://127.0.0.1:35930/api/subsystem/report HTTP 200, 用户数=0, 在线=0

如果总系统未启动，会看到：
  [REPORT] 上报失败 URLError: http://127.0.0.1:35930/api/subsystem/report, 原因: [Errno 111] Connection refused
  （主服务不受影响，继续运行）


十一、互联桥接与集群（多站语音互通）
------------------------------------------------------------
加入同一个集群的分系统之间会自动发现、互相校验身份、互为语音中继（无主节点，
任意一条链路断了其它链路照常工作）。页面：

  http://<内网IP>:35929/admin/bridge

  * 集群在【总系统】上创建（总系统管理页 → 集群管理，像建群组一样），
    各分系统在自己的桥接页选一个加入；
  * 原本那套全局互联原样保留为【主集群】（默认、不可改名/删除；没选过的都在里面）
    → 升级后什么都不选，行为与以前完全一致；
  * 只有【同一个集群内】的分系统之间才会建立链路；
  * 成员身份互相校验（节点名片 + 与总服务器名册比对），不是谁自称就算；
  * 成员只算【真的加入了】（桥接开关已打开）的台站；旧版本没有该功能的台站
    不会被算作成员，也不会出现在名册里（名册里没有它 = 不会去连它）。

  config.json 相关项：
    "bridge": { "enabled": true, "cluster": "主集群",
                "broker": "", "broker_port": 0, ... }

  【本机 broker 地址】（可选，桥接页里能改）
    桥接要把本机语音放到"本机 broker"上、对端连过来拉，所以它得知道这个地址。
    默认自动用管理页「APP 登录与 MQTT 地址配置」里那个地址（SAS 也按它接入），
    所以"本机 broker 就在那个地址"的机器什么都不用填；
    只有本机 broker 不在那个地址时，才在「互联桥接」页单独填：

      * 留空 = 回到管理页那个 MQTT 地址设置；
      * 填了 = 只对桥接生效（不动监控/SAS 的地址）；
      * 页面会显示当前地址【以及它是从哪来的】
        （"桥接设置" / "SAS/MQTT 地址设置" / "默认值"）；
      * 改完立刻生效：桥接断开重连到新地址，不用重启服务。

    （早期版本在进程启动那一刻把地址取下来就固定了：启动时还没配好、或后来在配置页
      改了地址，桥接都还按旧值走 —— 界面显示的 broker 与实际不符，也就连不上。）


十二、UDAC：统一动态授权与信任控制中心（★ 新增）
------------------------------------------------------------
SAS 判完"身份可信"就结束了；但身份可信不等于"现在这一刻还能继续信"：
证书可能刚被吊销、这台机器凌晨三点突然狂发消息、跟它之间的桥接丢包 30%……
UDAC 就是管这一段的：只读消费 SAS 的身份/证书状态与桥接健康度、音质，
输出 0-100 信任分与动态授权决策。

页面：http://<内网IP>:35929/admin/udac（只在内网，勿映射公网）

三个部分：
  * 信任评分 udac-trust-score
      0-100 多维加权：身份 30% / 行为 25% / 桥接健康 15% / 音质 10% / 上下文 / 数据。
      含 7 天冷启动观察期与历史信任衰减（半衰期 24h）。
  * 策略引擎 udac-policy（PDP）
      版本化"策略即代码"（JSON 结构化条件：trust_min / hour_from / hour_to / scope，
      **不 eval 任意表达式**）；支持灰度发布 / 提升 / 回滚 / 仿真试运行。
  * 执行点 udac-pep（PEP）
      挂在 /auth 认证路径：SAS 放行 → 信任评分 → 策略评估 → 与信任分阈值表取更严者 → 审计。

动作从宽到严：
  allow → rate_limit → degrade → step_up → disconnect → quarantine → deny
      deny / disconnect / quarantine = 直接拒绝新接入；
      其余通过 client_attrs（udac_action / udac_score）交给 EMQX 限权；
      **已建立的会话不会被中断**（不给现网通话"突然掉线"）；
      决策与事件只追加落库（udac.db），可回放追溯；原始认证审计仍归 FAS。

【直通】这些接入不评分、直接通过（★ 重点）
  有几类接入已经在别处验证过了，再拿"证书记录/吊销/冷启动/时段"去给它们扣分降权只会
  帮倒忙 —— 实测给 APP 账号算成 48-52 分判 step_up、给桥接判 rate_limit（桥接还因此
  连不上）。现在它们直接放行、不参与评分，决策里带「直通」标记：

    直通类型            判据                                     为什么
    APP 接入            app_verified=1（APP 私钥签名校验通过）    已过 SAS 身份 + APP 签名两道
    APP 接入（第二次）  clientid 形如 FMO-<呼号>-<uid>-<随机>      同一个 APP 会接入两次
                        且 SAS 身份已通过                        （先 user、再 super），其中
                                                                 super 那次**不带签名**，
                                                                 只凭签名认不出来
    内部客户端          app_exempt=1（面板/服务账号豁免签名）     属信任豁免的内部客户端
    MQTT 互联桥接       clientid FMO-BRIDGE-* 或呼号 SERVER       FUS 内部组件之间的语音互通，
                                                                 身份已由证书链 + 集群名片
                                                                 双重校验；一旦被 fail-closed
                                                                 拒掉，表现就是"桥接连不上"

  普通用户仍然照常评分与策略门控（没有被顺手放过）：例如没有证书记录的呼号会拿到
  rate_limit，策略命中该拒的照拒。

【性能】别让"风控"变成"卡顿"（★ 都是踩过坑之后加的）
  * udac.db 用 WAL（journal_mode=WAL + busy_timeout + synchronous=NORMAL）：
    认证路径每次连接都要写决策/事件，回滚日志模式下"写"会锁整库、所有读被堵住 ——
    实测 UDAC 接口 2 秒、排行 60 秒超时、管理页整片卡死、数据加载不出来。
  * 排行读快照：ranking() 默认不重算，只读 trust_snapshot；快照由后台线程每 5 分钟刷新
    （以前页面每几秒请求一次就把几百个呼号全量重算一遍）。
  * 认证路径给 UDAC 加硬超时（0.45 秒）：UDAC 卡住时按"本次未参与"继续，绝不拖住 /auth
    —— 否则 EMQX 等不到认证响应会判连接失败，现象是桥接 CONNACK 超时、老是连不上。

  修复前后实测（同一台 NAS）：
    /api/udac/ranking              60 秒超时  →  2 ms
    /api/udac/status                  2041 ms  →  2.5 ms
    /api/udac/decisions               2682 ms  →  3.6 ms
    UDAC 页一次完整刷新（5 个接口）  >60 秒     →  24.5 ms
    本机 broker 连接        反复 CONNACK 超时  →  connected

接口：
  GET  /api/udac/status              概览（决策数 / P99 / 等级分布 / 桥接与音质输入）
  GET  /api/udac/ranking?limit=      台站信任排行（读快照，毫秒级）
  GET  /api/udac/decisions?limit=    决策审计（exempt=1 即「直通」）
  GET  /api/udac/events?limit=       只追加事件流
  GET  /api/udac/policy              当前策略 + 所有版本
  POST /api/udac/policy              发布策略版本（可指定灰度百分比）
  POST /api/udac/policy/promote      灰度提升
  POST /api/udac/policy/rollback     回滚
  POST /api/udac/simulate            策略试运行（不写审计）

本机排行还会随同步上报给总系统，汇总成全局台站信任排行；总系统下发的全量扫描事件
也会喂给本机 UDAC 中心。

排障：
  现象                                   原因 / 处理
  UDAC 页卡、数据加载不出来              多半是 udac.db 落回回滚日志模式、或排行在全量
                                          重算。确认 /opt/fmo-subsystem/udac.db-wal 存在，
                                          PRAGMA journal_mode 应为 wal
  桥接 CONNACK 超时 / 连不上             UDAC 拖住了 /auth。看日志有无"UDAC 决策超时"；
                                          新版有 0.45 秒硬超时兜底，桥接本身也走直通
  APP 账号被 step_up、只有 50 分左右     该账号被当普通用户评分了。升级到含「直通」的版本
  "无该呼号证书记录" 导致 rate_limit     若是 APP/服务账号，本应走直通；若是普通用户，
                                          说明它的证书确实不在 SAS 里


十三、上报地址自动化（APP 该连哪台，机器自己知道）（★ 新增）
------------------------------------------------------------
以前要在管理页手填"上报地址"、点保存、还得记得上传总系统；填错或忘改，APP 与对端就
连到错的地方（本机 127.0.0.1 这种内网地址尤其致命）。现在全自动：

  * 分系统向总系统问一句"你看到的我是什么 IP"（GET /api/myip），以它为准 ——
    不需要任何第三方服务，也不受本机多网卡/内网地址干扰；
  * 拿到之后直接写进配置并立即上报总系统，没有"填 → 保存 → 上传"三步；
  * 后台线程每 10 分钟自动扫一次，而且地址真的变了才写盘/上报（幂等，不折腾）；
  * 只有公网 IP 会被采用：两端都校验，内网/回环地址一律不采信
    （踩过：走 127.0.0.1 去问，总系统看到的当然是 127.0.0.1，写进上报地址就把 APP
     和对端全带偏了）；
  * 总系统这条路不通时，才退回外部回显服务。

「语音监控」页有「上报地址（自动）」面板：显示当前地址、可一键重扫；
也可直接调 POST /api/config/auto-address。


十四、语音录音库（一直在录 · 随时回听）（★ 新增）
------------------------------------------------------------
从**服务启动那一刻**起，本机收到的语音就在往库里写 —— 包括互联桥接从别的节点转来的
声音。一次连续发言存成"一段"，带时间、呼号、时长、编码、来源，页面上随时可翻查回听。

入口：管理页「语音监控」→「📼 录音库」
      http://<内网IP>:35929/admin/sas  →  语音监控

能做什么：
  * 按日期翻查（可加呼号、来源：全部 / 本机收的 / 桥接转来的）
  * 24 小时分布条：一眼看出哪段时间有声音，点某小时只看那一段
  * 逐条回听（▶ 播放）、连续回听（▶ 顺序播放本区间，随时 ■ 停止）
  * 单条下载（标准 .ogg，任何播放器可放）
  * 整段导出：把区间内所有段合并成**一个** Ogg 文件（段间自动补 1.2 秒停顿）
  * 删除区间：弹窗二次确认，防误删

保留策略（不会再"过几秒就没了"）—— config.json 的 monitor 段：
    retention_days         默认 0 = **永久保留**（从部署那一刻起一直留着）
                           设成 N 则只留 N 天
    max_db_mb              默认 2048：容量上限，语音总量超了删**最老**的段（保护磁盘）
    beacon_retention_days  默认 30：信标单独保留天数（元数据、掉得快，不跟语音一起堆）

页面顶部直接显示：全库段数 / 总时长 / 占用大小 / 最早录音时间 / 当前保留策略。

接口（内网管理口）：
    GET  /api/monitor/recordings?from=&to=&callsign=&origin=&limit=&offset=
                                         分页列表（只回元数据，不含音频）
    GET  /api/monitor/timeline?from=&to=&bucket=3600
                                         时间轴：每桶的段数与时长
    GET  /api/monitor/rec_stats          总览（总量 + 保留策略）+ 区间统计
    GET  /api/monitor/audio?id=          单段音频（Opus 自动封装为 Ogg）
    GET  /api/monitor/export?from=&to=   区间合并导出成一个 Ogg
    POST /api/monitor/delete_range       删除区间（body 需带 confirm: true）

    origin：不传 = 全部；local = 只看本机收的；bridge = 只看桥接转来的。

说明：段与段之间的停顿用 Ogg 的 granule 跳变表示（合法，播放器会自动补静音），
      不伪造静音包 —— 伪造包在部分解码器上会直接报错。


十五、一键升级（只升级系统，不动配置与数据）
------------------------------------------------------------
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-upgrade.sh -o fus-upgrade.sh
  sudo bash fus-upgrade.sh

  * 不动：config.json、所有数据库（*_users.db / *_sas.db / voice.db / 审计库）、
    ca/、已签发的证书与信任链、uploads/；
  * 升级前自动备份，替换后做语法自检 + 服务健康检查，失败自动回滚；
  * 子命令：--check 只检查、--rollback 回滚、--list-backups 看备份。


十六、桥接延迟与音质（桥接页那几个数怎么读）（★ 新增）
------------------------------------------------------------
桥接页健康度里的数各自测的是不同东西：

  本机 broker 延迟   到本机 broker 的 PING 往返（<5ms）
  桥接延迟           对端语音帧"到达本机 → 重播出去"（含抖动缓冲）
                     —— "听起来慢不慢"主要看它，良好 ≈ 抖动缓冲 + 30ms
  单向延迟估算       对端单程(RTT/2) + 抖动缓冲 + 重播排队（<350ms 良好）
  链路抖动           **同一段发言内**帧到达间隔的波动（<30ms 为佳）
  疑似丢包           同一段发言内帧间隔骤增的比例（<1%）
  音质 MOS           由抖动+丢包估算，取最差一条成员链路（≥3.5 良好）
  抖动缓冲           吸收网络抖动的缓冲时长，默认 80ms，设置里可调

两个踩过的坑（已修）：
  * 静默被算成抖动/丢包：旧实现用"距上一帧的间隔"算抖动，于是"这次发言结束、
    20 秒后对方开口"这个正常静默被算成 20 秒抖动，指标报 抖动 19608ms、丢包虚高、
    MOS 算成 1.0，还被 UDAC 拿去当桥接健康度给节点扣分。
    现在只在**同一次连续发言内**统计，静默会重置基线。
  * 重播被读超时压住：本机连接的读循环是"读一次包才排空一次重播队列"，默认 5 秒
    读超时会让"该 80ms 释放"的帧被压住几百毫秒~数秒。现在读超时 0.05s，
    实测重播延迟 79.5ms（峰值 129ms）。

另外：迟到超过 2 秒的帧直接丢弃 —— 宁可断一下，也不放几秒前的旧语音。

顺带修掉一个会**静默丢语音**的收包解析 bug：若"包首部"与"包体"分两个 TCP 段到达，
旧实现已把首部消费掉，超时返回后包体留在缓冲区 → 整个字节流解析错位、后续包全被丢弃。
现在改成"凑齐一个完整包才消费缓冲区"，半包原样保留、下次继续拼。


十七、单向语音排障（我这边过得去、对面的声音过不来）
------------------------------------------------------------
最常见原因：对端 EMQX 的 ACL 没放行桥接主题 FMO/BRIDGE/#

  * 桥接是各自去订阅对方的语音主题（FMO/BRIDGE/<节点>/<频道>）；
  * 对端 ACL 若是收紧版（最后一条是 {deny, all}.）而里面只放行了 FMO/RAW、FMO/TELE，
    我们订阅它的主题会被拒（SUBACK=0x80）→ 拿不到它的集群名片，也收不到它的声音；
  * 这条规则属于部署时配的 EMQX 授权，不在代码里，所以升级 FUS 补不上，
    必须在【对端那一台】上跑一次：

  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-fix-acl.sh -o fus-fix-acl.sh
  sudo bash fus-fix-acl.sh --check   # 先看现状，不改动
  sudo bash fus-fix-acl.sh           # 修复：自动备份 → 在 deny-all 之前插一条 allow → 重载 EMQX

  （脚本自动识别 docker / 原生 EMQX；已经放行就不动；找不到配置时只打印手工步骤。）

其它常见现象：
  rc=5 连接被拒绝（对端不认我方证书）
        对端没把总系统下发的信任背书落进它的 sas.db.trust_chain（版本旧或同步已停）。
        用总系统的 /api/trust/roots 拿到我方根公钥，填进对端配置的 trust.extraRootPubkeys，
        或让它升级。
  SUBACK=0x80 / ACL 拒绝订阅
        见上，在对端跑 fus-fix-acl.sh。
  对方未加入集群
        对端桥接没开（在它自己的桥接页点【加入集群】）。
  名册里少了某台
        那台没加入、或长时间没上报（换域名留下的僵尸登记会被自动剔除）；
        它加入 / 恢复上报后会自己回来。


十八、安全注意事项
------------------------------------------------------------
1. API 服务默认监听 0.0.0.0，请确保只在需要时映射公网端口
2. admin/index.html 不要映射公网，仅内网管理使用
3. 建议公网访问使用 HTTPS（通过 nginx 反向代理加 TLS）
4. users.db 和 uploads/ 包含用户敏感数据，不要提交到 Git（已在 .gitignore 忽略）
5. 密码使用 SHA256 哈希存储，不存明文


============================================================
  由 BH6BHG 提供
============================================================