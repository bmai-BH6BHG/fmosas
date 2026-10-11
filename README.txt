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
├── sync_engine.py           # 分布式同步引擎模块（被 api_server 导入）
├── monitor.py               # 语音/信标监控线程（MQTT）
├── cert_gen.py              # Ed25519 证书生成工具
├── gen_app_key.py           # 生成 APP 签名密钥对
├── diagnose.py              # CA 上报链路诊断脚本
├── admin/
│   └── index.html           # 前端管理页面（内网用，不暴露公网）
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
admin/index.html 是独立 HTML 文件，不通过 API 服务暴露。

使用方式（任选其一）：

  方式 A：浏览器直接打开本地文件
    双击 admin/index.html 用浏览器打开
    在页面顶部"后端 API 地址"输入框填入 API 地址
    例如: http://127.0.0.1:35928 或 https://register.example.com:35928
    点击"保存并刷新"

  方式 B：通过 URL 参数自动填充 API 地址
    file:///.../admin/index.html?api=http://127.0.0.1:35928
    或
    http://内网IP/admin/index.html?api=http://127.0.0.1:35928

  方式 C：内网用另一个 HTTP 服务托管 admin 目录
    例如: python3 -m http.server 8080 --directory admin
    然后浏览器访问 http://内网IP:8080/?api=http://127.0.0.1:35928

API 地址会保存在浏览器 localStorage，下次打开自动恢复。


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


十二、一键升级（只升级系统，不动配置与数据）
------------------------------------------------------------
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-upgrade.sh -o fus-upgrade.sh
  sudo bash fus-upgrade.sh

  * 不动：config.json、所有数据库（*_users.db / *_sas.db / voice.db / 审计库）、
    ca/、已签发的证书与信任链、uploads/；
  * 升级前自动备份，替换后做语法自检 + 服务健康检查，失败自动回滚；
  * 子命令：--check 只检查、--rollback 回滚、--list-backups 看备份。


十三、单向语音排障（我这边过得去、对面的声音过不来）
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


十四、安全注意事项
------------------------------------------------------------
1. API 服务默认监听 0.0.0.0，请确保只在需要时映射公网端口
2. admin/index.html 不要映射公网，仅内网管理使用
3. 建议公网访问使用 HTTPS（通过 nginx 反向代理加 TLS）
4. users.db 和 uploads/ 包含用户敏感数据，不要提交到 Git（已在 .gitignore 忽略）
5. 密码使用 SHA256 哈希存储，不存明文


============================================================
  由 BH6BHG 提供
============================================================