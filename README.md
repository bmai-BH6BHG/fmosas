# fmosas — FMO 对讲系统 · 分系统（区域注册节点）

分系统是 FMO 对讲系统的**区域注册节点**，部署在各地区/机构的服务器上，为 APP 用户提供
注册、登录、心跳上报服务，并作为 **SAS 认证服务**（Ed25519 证书链）与**分布式同步节点**
与总系统及其他分系统协同。

## 一键部署（推荐）

Linux / 群晖 DSM，一条命令，全自动（下载 → SHA256 校验 → 装依赖 → 生成配置 → 注册开机自启 → 自检）：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo bash
```

卸载（默认保留数据库 / CA / 上传图片）：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash
```

彻底删除（含数据，删除前会校验目录）：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash -s -- --purge
```

## 一键升级（只升级系统，不动配置与数据）

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-upgrade.sh -o fus-upgrade.sh
sudo bash fus-upgrade.sh
```

* **不动**：`config.json`、所有数据库（`*_users.db` / `*_sas.db` / `voice.db` / 审计库）、
  `ca/`、已签发的证书与信任链、`uploads/`；
* 升级前自动备份，替换后做语法自检 + 服务健康检查，**失败自动回滚**；
* 子命令：`--check`（只检查）、`--rollback`（回滚）、`--list-backups`（看备份）。

装完：

| 用途 | 地址 |
|------|------|
| APP 调用（公网） | `http://<域名或IP>:35928` |
| FUS 门户（内网，勿映射公网） | `http://<内网IP>:35929/admin` |
| SAS 系统（认证服务） | `http://<内网IP>:35929/admin/sas` |
| FAS 系统（审计服务） | `http://<内网IP>:35929/admin/fus` |
| **互联桥接（多站语音互通）** | `http://<内网IP>:35929/admin/bridge` |
| 健康检查 | `http://127.0.0.1:35928/api/health` |

## 互联桥接与集群（多站语音互通）

加入**同一个集群**的分系统之间会自动发现、互相校验身份、互为语音中继（**无主节点**，
任意一条链路断了其它链路照常工作）。不需要逐个添加服务器。

* **集群由总系统创建**（总系统管理页 →「集群管理」，像建群组一样），
  各分系统在**自己的**「互联桥接」页选一个加入；
* 原本那套全局互联原样保留为 **「主集群」**（默认、不可改名/删除；没选过的分系统都在里面）
  → **升级后什么都不选，行为与以前完全一致**；
* 只有**同一个集群内**的分系统之间才会建立链路；
* 成员身份是**互相校验**的（节点名片 + 与总服务器名册比对），不是谁自称就算；
* 成员的认定以"**是否真的加入**（桥接开关已打开）"为准，旧版本没有该功能的台站
  不会被算作成员、也不会出现在名册里。

### 单向语音：我这边过得去，对面的声音过不来

几乎都是**对端 EMQX 的 ACL 没放行桥接主题**。桥接是"各自去订阅对方的语音主题"，
若对端 ACL 是收紧版（最后一条 `{deny, all}.`）、里面只放行了 `FMO/RAW`、`FMO/TELE`
这些老主题而**没有 `FMO/BRIDGE/#`**，我们订阅它的主题会被拒（`SUBACK=0x80`）
→ 拿不到它的集群名片，也收不到它的声音。

这条规则属于**部署时配的 EMQX 授权，不在代码里**，所以升级 FUS 补不上，
要在**对端那一台**上跑一次：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-fix-acl.sh -o fus-fix-acl.sh
sudo bash fus-fix-acl.sh --check   # 先看现状，不改动
sudo bash fus-fix-acl.sh           # 修复：自动备份 → 在 deny-all 之前插入放行规则 → 重载 EMQX
```

脚本自动识别 docker / 原生两种 EMQX 安装，**已放行就不动**（幂等），
找不到配置文件时只打印手工步骤、绝不乱改。

### 排障速查

| 现象 | 原因 / 处理 |
|------|-------------|
| 对端显示 `rc=5 连接被拒绝（对端不认我方证书）` | 对端没把我们总系统下发的信任背书落进它的 `sas.db.trust_chain`（版本旧或同步停了）。用总系统的 `/api/trust/roots` 拿到我方根公钥，填进对端配置的 `trust.extraRootPubkeys`，或让它升级 |
| 对端显示 `SUBACK=0x80 / ACL 拒绝订阅` | 对端 ACL 没放行 `FMO/BRIDGE/#` → 跑上面的 `fus-fix-acl.sh` |
| 对端显示 `对方未加入集群` | 对端桥接没开（在它自己的桥接页点「加入集群」） |
| 名册里少了某台 | 那台没加入、或长时间没上报（僵尸登记会被自动剔除）；让它加入/恢复上报即自动回来 |
| 界面上"已加入"但一直没声音 | 看对端的 `rx_frames` 是否在涨；涨说明在收它的语音 |

## 其他命令

```bash
# 写 APP 密钥（国服 ID 绑定鉴权）
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-set-appkey.py -o fus-set-appkey.py
sudo python3 fus-set-appkey.py

# 体检
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/fus-diagnose.py -o fus-diagnose.py
sudo python3 fus-diagnose.py
```

## 手动部署

```bash
python3 -m pip install "cryptography>=41.0"
python3 -u api_server.py            # 端口读 config.json（默认 35928）
sudo bash install.sh                # 注册 systemd 开机自启（群晖用计划任务）
```

## 目录结构

```
api_server.py           # 主程序：API + SAS 认证 + 同步引擎（公网口 35928 / 管理口 35929）
sas_server.py           # SAS 认证服务模块（Ed25519 证书链验证与签发）
sync_engine.py          # 分布式同步引擎（上报总系统 / 从总系统拉取 / P2P）
monitor.py              # 语音/信标监控线程（MQTT 抄收 + 上报）
bridge.py               # ★ 互联桥接（集群内自动互通、成员互相校验、防回环）
cert_gen.py             # Ed25519 证书生成工具
gen_app_key.py          # 生成 APP 签名密钥对（国服 ID 绑定鉴权）
bas_*.py                # 内嵌审计子系统（EMQX 客户端/身份判定/策略/诊断）
admin/index.html        # 管理后台（内网访问）
admin/bridge.html|.js   # ★ 互联桥接页（加入集群 / 选集群 / 成员与链路状态）
config.json             # 运行配置（端口 / 域名 / 总系统地址 / 桥接与所属集群）
config.default.json     # 配置模板（一键安装的新配置起点）
install.sh              # ★ curl 一键安装脚本（自包含，零参数）
uninstall.sh            # ★ 一键卸载脚本
upgrade.sh              # ★ 一键升级脚本（只换代码，保留配置与数据）
fix_bridge_acl.sh       # ★ 桥接 ACL 修复（单向语音时在对端那台跑）
build_release.sh        # ★ 打包脚本（tar.gz + SHA256 + dist/release-upload/）
dist/VERSION            # 版本号 + 分发地址
.github/workflows/release.yml   # 打标签自动发版
```

## 发布新版本

```bash
git tag v1.0.0
git push origin v1.0.0
```

`.github/workflows/release.yml` 会自动打包、校验并创建 Release；
详细步骤见 [.github/RELEASE_GUIDE.md](.github/RELEASE_GUIDE.md)。

## 文档

* [INSTALL.md](INSTALL.md) — 一键部署：发布、参数、默认行为、故障排查
* [部署教程.md](部署教程.md) — 架构、配置项、API、SAS 认证、分布式同步
* [API.md](API.md) — 接口清单
* [dmrid_bind_api.md](dmrid_bind_api.md) / [dmrid_kdf_spec.md](dmrid_kdf_spec.md) — 国服 ID 绑定接口与 KDF 规格

## 安全

* `ca/ca_private.json`（CA 私钥）、`*_users.db`、`*_sas.db`、`voice.db`、审计库、`uploads/`
  均为运行时敏感数据，已在 `.gitignore` 排除，发布包中也不包含。
* 管理端口（公网口 + 1）只在内网使用，不要做端口映射。
* APP 私钥 `APP_SEED` 只烧进 APP，不要写进 `config.json` 或上传服务器。

## 许可

[Boost Software License 1.0](LICENSE) — 由 BH6BHG 提供。
