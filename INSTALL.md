# FMO 分系统 · 网络一键部署（curl）

> 由 BH6BHG 提供 ｜ 适用于群晖 DSM 7、Ubuntu / Debian / CentOS / Alpine 等 Linux

---

## 零、BAS 一键安装（推荐：认证 + 审计一体）

**BAS = SAS（认证）+ FAS（审计）融为一体的单一服务**：一个进程、一个端口、一次登录、一个数据库，
审计能力已用 Python 内嵌，不再需要 .NET 运行时、不再占用 9527、也不再有"FAS 把 SAS 合法呼号拉黑"的问题。

一条命令（会自动做完整迁移）：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-install.sh | sudo bash
```

它会按顺序执行：

1. **扫描**本机原有的 SAS（分系统认证）与 FAS（.NET 审计）：服务单元、安装目录、数据库、CA 私钥、端口
2. **备份**旧数据（数据库 / CA 私钥 / 配置 → `/var/backups/fmo-bas/bas-migrate-<时间>.tar.gz`）
3. **卸载**旧系统（含清理 EMQX 上旧 FAS 的规则与桥接；SAS 的 `/auth` 端点保留不动）
4. **安装**新 BAS（单进程，含内嵌审计模块）
5. **识别 MQTT(EMQX)** 并把客户端认证指向本服务端口（默认 `35928/auth`；改动前备份认证链，可回滚）
6. 重启并用 `/api/health`、`/auth`、审计界面做**联合自检**

**先只看不动手**（只读扫描，不需要 sudo）：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-install.sh | bash -s -- --scan-only
```

装完：

| 用途 | 地址 |
|---|---|
| APP 调用 / EMQX 认证钩子 | `http://<公网IP>:35928`（认证 URL：`http://<IP>:35928/auth`） |
| 审计界面（内网） | `http://<内网IP>:35929/admin/bas` |
| 注册系统 / SAS 配置 | `http://<内网IP>:35929/admin` |

卸载：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall-bas.sh | sudo bash            # 保留数据
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall-bas.sh | sudo bash -s -- --purge  # 彻底删除
```

> **身份控制默认是 `warn` 模式**：逐包核对身份、可疑事件全部留证并进入「待审救援」队列，
> **不会自动封人**。观察一段时间确认无误封后，再到审计界面 → 设置 → 身份控制策略里切到 `ban`。

常用参数：`--scan-only`（只扫描）`--keep-old`（不卸载旧系统）`--no-backup`（跳过备份）
`--purge`（卸载旧 FAS 时删低权用户）`--yes`（不交互）。

---

## 一、只装分系统（认证端）

如果只要原来的分系统（不含审计界面），用下面这个入口。

本项目的部署方式已改为**网络拉取一键部署**：服务器上不需要预先上传任何文件，
只要一条 `curl` 命令，脚本会自动下载部署包、校验 SHA256、安装依赖、生成配置、
注册开机自启并自检。

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo bash
```

> 上面 `https://github.com/bmai-BH6BHG/fmosas/releases/latest/download` 是**分发根地址（BASE）**，需替换为你自己的静态目录地址
> （群晖 Web Station / Nginx / 对象存储均可）。本项目默认写入的就是群晖地址
> `https://github.com/bmai-BH6BHG/fmosas/releases/latest/download`；分发目录实际放在别处时，
> 只需在 `dist/VERSION` 里改 `RELEASE_BASE_URL=` 后重新 `bash build_release.sh`，
> 详见「二、部署前：把包上传到分发源」。

---

## 一、最短路径

### 1. 安装（一条命令）

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo bash
```

脚本全自动完成，**不需要任何参数**：

| 步骤 | 内容 |
|------|------|
| 1/8 | 检查 `curl`/`wget`、`tar`、`python3`，缺失时代尝试用 apt/yum/apk 安装 |
| 2/8 | 下载 `fmo-subsystem-<版本>.tar.gz` 到临时目录 |
| 3/8 | **强制 SHA256 校验**（不一致立即中止） |
| 4/8 | 解包并校验关键文件 |
| 5/8 | 定位 `python3`，安装/校验 `cryptography` 依赖 |
| 6/8 | 生成或增量更新 `config.json`（保留你已有的配置与数据） |
| 7/8 | 同步代码到安装目录并注册开机自启（systemd / 群晖计划任务） |
| 8/8 | 本机 `/api/health` 自检，打印访问地址与日志命令 |

### 2. 装完立刻验证

```bash
# 本机健康检查（应返回 {"ok": true, "service": "fmo-subsystem", ...}）
curl -s http://127.0.0.1:35928/api/health

# 看服务状态与日志（systemd 环境）
systemctl status fmo-subsystem
journalctl -u fmo-subsystem -f
```

### 3. 卸载（一条命令）

```bash
# 只卸载程序与服务，保留数据库 / CA / 上传图片
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash

# 连数据一起删（删除前会校验目录并打印绝对路径）
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash -s -- --purge
```

---

## 二、发布（GitHub Release）

本项目的发布源是 **GitHub Release**：

```
仓库      : https://github.com/bmai-BH6BHG/fmosas
固定入口  : https://github.com/bmai-BH6BHG/fmosas/releases/latest/download
```

`releases/latest/download` 永远指向**最新一次已发布**的 Release，所以发新版本时客户端命令不用改。

### 首次：把源码推上去（一次性）

```bash
cd <本目录>
git init
git add -A
git status --short      # 确认列表里没有 ca_private.json / *.db / uploads/*.png
git commit -m "FMO 分系统：一键部署（curl 网络拉取版）"
git branch -M main
git remote add origin https://github.com/bmai-BH6BHG/fmosas.git
git push -u origin main
```

`.gitignore` 已排除 `ca/`（含 CA 私钥）、`*_users.db`、`*_sas.db`、`voice.db`、
`uploads/*`、`__pycache__/`、`dist/release-upload/` 等敏感与运行时文件。

### 发版：推一个标签即可（自动）

仓库内已放好流水线 [`.github/workflows/release.yml`](.github/workflows/release.yml)：

```bash
git tag v1.0.0
git push origin v1.0.0
```

流水线会自动完成：写版本号 → `bash build_release.sh`（注入 GitHub 地址 + 版本号）→
`bash -n` 语法检查 → `sha256sum -c` 资产校验 → 创建 Release `v1.0.0` 并上传全部资产。
也可以在仓库 **Actions → release → Run workflow** 手动填版本号触发。

> 标签必须以 `v` 开头（`v1.0.0`），流水线会把 `v` 去掉作为版本号。

### 备选：本地打包 + 网页手动上传

对象存储 / 自建静态站也支持。打包会直接产出「需要上传的文件夹」：

```bash
bash build_release.sh https://你的分发地址
# 产出 dist/release-upload/（7 个文件），整个上传到分发地址根目录：
#   install.sh                            （包内这份已注入分发地址，必须传这份）
#   uninstall.sh
#   fmo-subsystem-1.0.0.tar.gz             + .sha256
#   fmo-subsystem.tar.gz                   + .sha256   （无版本号回退通道）
#   VERSION
```

GitHub Release 也用同一份文件夹：**Draft a new release** → Tag 填 `v1.0.0` →
把 7 个文件拖进附件区 → Publish（`dist/MANIFEST.txt`、`checksums.txt` 可选留档）。

### 更新版本

改 [dist/VERSION](dist/VERSION) 的 `VERSION=1.0.1` → `git commit/push` →
`git tag v1.0.1 && git push origin v1.0.1`。旧 Release 可以保留，
`install.sh` 按版本号精确取包，取不到时回退到无版本号的 `fmo-subsystem.tar.gz`。

> **打包安全**：`build_release.sh` 会强制排除 `ca/`（含 CA 私钥）、`*.db`（用户数据）、
> `uploads/` 里的图片等运行时/敏感文件，并在打包后用 `tar tzf` 自检；每台服务器安装后
> 都会**生成自己独立的 CA**，不会共用同一个私钥。
>
> 更细的发布步骤（含 GitHub 网页操作、常见问题）见
> [`.github/RELEASE_GUIDE.md`](.github/RELEASE_GUIDE.md)。

---

## 三、默认行为（零配置时会怎样）

不传任何参数时，`install.sh` 按下面规则自动决定，全部可被环境变量覆盖：

| 项目 | 默认行为 |
|------|----------|
| 安装目录 | `FMO_DIR` → `/opt/fmo-subsystem`（可写时）→ 群晖 `/volume1/fmo-subsystem` → `$HOME/fmo-subsystem` |
| 公网 API 端口 | `35928`；被占用时自动向上寻找，且保证「端口」和「端口+1」同时空闲 |
| 内网管理端口 | 自动 = 公网端口 + 1（源码写死，安装脚本会一并预留） |
| 对外域名/地址 | 自动探测本机 IPv4，写入 `config.json` 的 `domain` 与 `api_url` |
| 分系统 ID | 为空或 `sub-001` 时，按「主机名 + MAC」确定性生成 `sub-xxxxxxxx`（重复安装结果一致） |
| 总系统地址 | 沿用包内 `config.default.json` 的 `master_url`（默认 `http://bh6bhg.synology.me:35930`） |
| 开机自启 | 有 systemd 就注册 `fmo-subsystem.service`；群晖无 systemd 时打印计划任务配置指引 |
| 防火墙 | 只在检测到 ufw/firewalld 时放行**公网端口**；管理端口不放行 |

### 可选环境变量（想改默认值时用）

```bash
# 例：装到 /volume2/fmo、公网口 36000、对外域名 abc.example.com、总系统换地址
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo \
  FMO_DIR=/volume2/fmo \
  FMO_PORT=36000 \
  FMO_DOMAIN=abc.example.com \
  FMO_MASTER=http://master.example.com:35930 \
  bash
```

| 变量 | 作用 |
|------|------|
| `FMO_BASE_URL` | 覆盖下载根地址（分发地址变更时用，脚本内已有默认值） |
| `FMO_DIR` | 覆盖安装目录 |
| `FMO_PORT` | 覆盖公网 API 端口（管理端口自动 = 端口+1） |
| `FMO_DOMAIN` | 覆盖对外域名（影响数据库命名 `{domain}_users.db` 与上报） |
| `FMO_MASTER` | 覆盖总系统地址 `master_url` |
| `FMO_NO_SERVICE=1` | 只部署代码，不注册开机自启（调试用） |

> `sudo` 环境下 `VAR=值` 需要像上面那样放在 `sudo` 之后、`bash` 之前；
> 也可以先 `export FMO_PORT=36000` 再执行命令。

---

## 四、装完之后

| 用途 | 地址 | 说明 |
|------|------|------|
| APP 调用（公网） | `http://<域名或IP>:35928` | 只放行 APP 必需接口 + 分系统间同步，管理接口一律 403 |
| 管理后台（内网） | `http://<内网IP>:35929/admin` | **不要映射到公网** |
| 健康检查 | `/api/health` | 两个端口都放行，便于探活 |

上线还需要两步人工确认（脚本无法代做）：

1. **路由器/云厂商端口映射**：把公网 `35928` 映射到服务器 `35928`；`35929` 保持内网。
2. **APP 签名公钥**（仅国服 ID 绑定功能需要）：
   ```bash
   cd /opt/fmo-subsystem
   python3 gen_app_key.py        # 打印 APP_SEED 与 APP_PUBKEY
   ```
   把 `APP_PUBKEY` 填入 `config.json` 的 `dmrid.app_pubkey`，`APP_SEED` 烧进 APP；
   改完 `systemctl restart fmo-subsystem`。

管理后台第一次打开时，在顶部「后端 API 地址」填内网地址（如 `http://127.0.0.1:35928`），
点「保存并刷新」；该地址会记在浏览器本地，下次自动恢复。

---

## 五、升级与重装

再次执行同一条 `curl` 命令即为**升级**：

* 代码以包内版本为准覆盖更新；
* `config.json` **原地增量更新**：只补齐/修正端口、域名等，保留你已配置的
  `dmrid.app_pubkey`、`peers`、`monitor`、`subsystem_id` 等字段；
* 数据库（`*_users.db`、`*_sas.db`）、`ca/`、`uploads/`、`roots/` **不会被删除或覆盖**；
* 自启服务重新加载，安装结束仍会做一次健康自检。

升级前建议备份：

```bash
systemctl stop fmo-subsystem
cp -a /opt/fmo-subsystem /opt/fmo-subsystem-backup-$(date +%Y%m%d)
systemctl start fmo-subsystem
```

---

## 六、常见问题

**Q1：`curl: command not found` / `tar: command not found`**
安装脚本会尝试用 apt/yum/apk 自动补装；若系统没有包管理器（如精简版 DSM），
先用套件中心或 `opkg` 安装 `curl`（或用 `wget -qO- <URL> | bash`）。

**Q2：提示 `未找到 python3`**
群晖：套件中心安装 **Python 3** 套件后重跑命令（脚本会自动发现
`/var/packages/Python*/target/usr/bin/python3`）。
其它系统：`apt install python3 python3-pip` / `yum install python3`。

**Q3：SHA256 校验失败**
说明下载到了损坏或错误的文件：确认 `FMO_BASE_URL` 指向正确目录、CDN/反向代理没有改动文件、
上传用的是 `build_release.sh` 生成的 `.tar.gz` 与 `.sha256` 配对文件。重新上传后重试。

**Q4：端口被占用，服务起不来**
脚本会自动避让端口；若仍失败，看日志确认实际端口：
```bash
journalctl -u fmo-subsystem -n 50
grep '"port"' /opt/fmo-subsystem/config.json
```
也可指定端口重装：`... | sudo FMO_PORT=36200 bash`。

**Q5：装完 `/api/health` 探测失败**
依次检查：`systemctl status fmo-subsystem`（是否 running）→ `journalctl -u fmo-subsystem -n 80`
（Python 报错）→ `python3 -c "import cryptography"`（依赖是否装好）→
`grep '"port"' config.json` 与探测端口是否一致。

**Q6：群晖没有 systemd 怎么办**
脚本会生成 `start.sh` 并打印 DSM 计划任务指引：控制面板 → 任务计划 → 新增「触发的任务」→
开机时执行 `bash <安装目录>/start.sh`。也可以用 `FMO_NO_SERVICE=1` 只部署代码。

**Q7：升级会不会覆盖我的数据/CA**
不会。数据库、`ca/`、`uploads/`、`roots/`、`config.json` 都在排除清单外（见 `build_release.sh`），
升级只替换程序与前端文件。

**Q8：想彻底清干净**
```bash
curl -fsSL <BASE>/uninstall.sh | sudo bash -s -- --purge
```

---

## 七、安全提示

1. `install.sh` / `uninstall.sh` 都会以 root 执行，请确保从**自己的 HTTPS 分发地址**获取；
   需要更高保证时可先下载、核对 SHA256 再执行：
   ```bash
   curl -fsSLO https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh
   sha256sum install.sh   # 与发布页登记的值比对
   sudo bash install.sh
   ```
2. 管理端口（公网口 + 1）**只在内网放行**，不要做端口映射。
3. `ca/ca_private.json` 是本分系统 CA 私钥，发布包里**不含**它；每台服务器独立生成，请单独备份。
4. `*.db` 与 `uploads/` 含用户隐私数据，不要提交到 Git、不要放进发布包。
5. APP 私钥 `APP_SEED` 只烧进 APP，绝不写进 `config.json` 或上传到服务器。

---

## 八、相关文档

* [README.txt](README.txt) — 部署包说明与接口列表
* [部署教程.md](部署教程.md) — 完整的架构、配置项、API、SAS、同步说明
* [API.md](API.md) — 接口细节
* [dmrid_bind_api.md](dmrid_bind_api.md) / [dmrid_kdf_spec.md](dmrid_kdf_spec.md) — 国服 ID 绑定接口与 KDF 规格
* [CONTRACT.md](CONTRACT.md) — 本次一键部署改造的接口契约（开发/维护者用）

---

> 由 BH6BHG 提供
