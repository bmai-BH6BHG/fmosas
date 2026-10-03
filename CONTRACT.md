# FMO 分系统 — curl 一键部署改造契约（BUILD CONTRACT）

> 本文件是本次改造的唯一接口约定。所有脚本必须严格遵守，禁止自行发明路径/文件名/URL。
> 目标：把"上传目录 + bash install.sh"改成网络拉取的一键部署：
> `curl -fsSL <分发地址>/install.sh | sudo bash`

---

## 0. 落地后的修订记录（Lead，交付时生效）

与初版契约的差异，以下为最终实现，以本节为准：

1. 分发包**额外包含** `CONTRACT.md` 与 `dist/VERSION`（共 27 个条目）；其余包含/排除清单不变。
2. `dist/VERSION` 只放行自身，`dist/` 其余产物仍严格排除；打包自检规则对 `dist/VERSION` 单独豁免。
3. `build_release.sh` 除注入 `DEFAULT_BASE_URL` 外，还会把 `dist/VERSION` 的版本号注入包内
   `install.sh` 的 `DEFAULT_VERSION` 行（行数不变校验），避免版本漂移；并新增硬断言：
   staging 缺少任何必需文件即中止打包（防止静默出残缺包；该断言曾捕获 `dist/VERSION` 被
   `$STAGE/dist` 剪枝误删的问题）。
4. 打包额外产出 **`dist/release-upload/`**（★ 需要上传的全部 7 个文件：`install.sh`、
   `uninstall.sh`、`fmo-subsystem-<版本>.tar.gz(.sha256)`、`fmo-subsystem.tar.gz(.sha256)`、
   `VERSION`），并做"关键文件齐全 + 无敏感文件"自检后再打印上传清单。
   其中 `fmo-subsystem.tar.gz` 是同一包的无版本号副本，供安装脚本回退使用。
5. 安装脚本的回退通道由 `${BASE}/latest/fmo-subsystem.tar.gz` 改为**平铺**的
   `${BASE}/fmo-subsystem.tar.gz`，以兼容 GitHub/Gitee Release 与对象存储的平铺资产目录。
6. 分发源确定为**对象存储**（阿里云 OSS / 腾讯 COS / Cloudflare R2，公共读），地址写在
   `dist/VERSION` 的 `RELEASE_BASE_URL=`，当前为占位值
   `https://github.com/bmai-BH6BHG/fmosas/releases/latest/download`。
   依据：2026-10 实测 `bh6bhg.synology.me` 的 443/5000/5001 均未开放、80 返回 403，
   唯一可达的 35928 是 FMO API（公网白名单会 403 掉静态路径），无法承载发布文件。
   仓库内 `install.sh` 保持占位地址不变，只有打包产物被注入。
7. 验收由 Lead 用本地静态站实跑：真实包 + `curl | bash` 安装、`/api/health` 与 `/admin`
   探活、二次安装幂等、SHA256 负向失败、"版本包 404 → 无版本号包回退"、systemd 单元内容、
   卸载与 `--purge` 幂等。

---

## 1. 交付物清单（全部放在仓库根目录 / dist/）

| 路径 | 作用 | 归属 |
|------|------|------|
| `dist/VERSION` | 版本号 + 分发根地址 | Lead（已完成） |
| `install.sh` | 一键安装脚本（唯一入口，自包含） | teammate install-script |
| `uninstall.sh` | 一键卸载脚本（同样 curl 执行） | teammate packaging |
| `build_release.sh` | 打包 + SHA256 校验清单 | teammate packaging |
| `INSTALL.md` | 中文安装文档 | Lead |
| `dist/`（构建产物目录） | `fmo-subsystem-<VER>.tar.gz`、`checksums.txt`、`MANIFEST.txt` | build_release.sh 生成 |
| `dist/release-upload/` | ★ 需要上传到分发源的全部 7 个文件 | build_release.sh 生成 |

> `dist/` 下只允许出现构建产物与 `VERSION`；请把 `dist/` 加入 `.gitignore` 的构建产物忽略项。

---

## 2. 分发地址与 URL 约定

* 分发根地址（RELEASE_BASE_URL）由 `dist/VERSION` 的 `RELEASE_BASE_URL=` 决定；构建时 `build_release.sh`
  会把它注入 `install.sh` 的 `DEFAULT_BASE_URL` 占位行。
* 若 `RELEASE_BASE_URL` 为空，`DEFAULT_BASE_URL` 必须保留占位符：
  `https://example.com/fmo-subsystem`（并在脚本头部用注释醒目提示"部署前替换"）。
* 运行期覆盖：`FMO_BASE_URL` 环境变量优先级最高。
* **主下载地址（唯一权威）**：
  `${BASE}/fmo-subsystem-${VERSION}.tar.gz`
  `${BASE}/fmo-subsystem-${VERSION}.tar.gz.sha256`（内容：`<64位hex>  <tarball 文件名>`）
* 可选回退（仅在主地址 404 时尝试一次，失败则报错退出）：
  `${BASE}/latest/fmo-subsystem.tar.gz` + `.sha256`
* 打包格式：`.tar.gz`，解包后**必须**是"源码平铺在根目录"（含 `api_server.py`、`admin/index.html`、
  `config.default.json` 等），即 `tar tzf` 的第一层就是这些文件；**不允许**多一层 `fmo-subsystem/`
  前缀导致路径变化——如需前缀，解包后自行 `cd` 亦可，但必须在契约内保持一致。
  → 决定：**平铺（无外层目录）**。`install.sh` 用 `tar -xzf ... -C "$TMP"` 后直接使用 `$TMP`。

---

## 3. 安装行为的硬性要求

### 3.1 零参数
* `bash install.sh` 与 `curl -fsSL ... | bash` 都必须全自动完成，**不接受任何位置参数**。
* 唯一可选的调整手段是环境变量（见 `dist/VERSION` 注释）：`FMO_BASE_URL`、`FMO_DIR`、`FMO_PORT`、
  `FMO_DOMAIN`、`FMO_MASTER`、`FMO_NO_SERVICE`。未设置时全部自动推断。

### 3.2 运行时事实（来自源码，必须遵守，禁止臆造）
* 主程序：`api_server.py`，`BASE_DIR = dirname(abspath(__file__))`，所有路径都相对它，
  因此安装目录 = 源码目录，`WorkingDirectory` 必须是它。
* 启动：`python3 -u api_server.py`（无需 `--port`；端口从 `config.json` 的 `port` 读取）。
* **双端口**：公网 API 口 = `config.port`，内网管理口 = `config.port + 1`（源码写死 `port + 1`）。
  安装时必须确保两个端口都可用，否则服务起不来。
* 健康检查：`GET http://127.0.0.1:<port>/api/health` → `{"ok": true, "service": "fmo-subsystem", ...}`，
  该路径在**两个端口**都放行。
* 管理后台：`http://127.0.0.1:<port+1>/admin`（公网口访问 `/admin` 返回 403，这是设计如此）。
* 数据库文件名基于 `config.domain` 自动生成（`<domain>_users.db` / `<domain>_sas.db`），
  无需安装脚本预先创建；但 `uploads/`、`ca/`、`roots/` 目录需要存在（源码多数会自建，安装脚本仍应
  `mkdir -p` 保证权限正确）。
* 依赖：`cryptography>=41.0`（唯一第三方依赖）；其余全标准库。Python 3.8+。
* Python 解释器查找顺序：`python3` → `python` → 群晖套件路径
  `/var/packages/Python*/target/usr/bin/python3`、`/var/packages/python3*/target/usr/bin/python3`
  → `/usr/local/bin/python3`、`/usr/bin/python3`。

### 3.3 安装目录选择（自动，无交互）
1. `FMO_DIR` 已设置 → 用它；
2. `/opt` 存在且可写 → `/opt/fmo-subsystem`；
3. 群晖（存在 `/volume1`）且可写 → `/volume1/fmo-subsystem`；
4. 否则 → `$HOME/fmo-subsystem`。

### 3.4 安装流程（顺序固定）
1. 前置检查：`curl`/`wget` 至少一个、`tar`、`gzip`、`python3`；缺失且能用 apt/yum/apk 安装则自动装，
   否则中文报错退出（退出码非 0）。
2. 解析 `BASE_URL`、`VERSION`，下载 tarball 到干净临时目录（`mktemp -d`，退出时清理）。
3. **强制 SHA256 校验**：有 `.sha256` 就校验，不一致立即失败退出；取不到 `.sha256` 时给出醒目警告后继续。
4. 解包，校验 `api_server.py`、`admin/index.html`、`config.default.json` 存在。
5. 定位 python3 并确保 `cryptography`（已装跳过；否则 pip → `--break-system-packages` → apt/yum/apk）。
6. 生成/更新配置：
   * 目标目录已有 `config.json` → **原地更新，绝不覆盖用户已有配置**（保留 `dmrid.app_pubkey`、
     `peers`、`monitor`、`subsystem_id` 等），仅更新 `port`、`domain`、`api_url`，
     并在 `master_url` 仍为空/默认时才写入 `FMO_MASTER`；
   * 没有 → 以包内 `config.default.json` 为模板生成。
   * 字段值：`port` = `FMO_PORT` 或自动探测（默认 35928，被占用则向上找同时空出 port 与 port+1 的端口对）；
     `domain` = `FMO_DOMAIN` 或本机 IPv4；`api_url` = `http://<domain>:<port>`；
     `subsystem_id` 为空/`sub-001` 时用 Python uuid5 按"主机名+MAC"确定性生成（与源码
     `generate_subsystem_id()` 同算法），保证重复安装得到同一个 ID。
   * 由于源码启动时也会自动补齐 `subsystem_id`，安装脚本生成与否都不能报错。
7. 同步代码到安装目录（`cp -a` 保留权限），保留用户数据文件（`*_users.db`、`*_sas.db`、`ca/`、
   `uploads/`、`roots/`、`config.json` 不被包内容覆盖）。
8. 注册开机自启：
   * systemd 可用（`systemctl` + `/run/systemd/system` 存在）→ 写
     `/etc/systemd/system/fmo-subsystem.service`（`Restart=always`、`RestartSec=5`、
     `WorkingDirectory=<DIR>`、`ExecStart=<PY> -u <DIR>/api_server.py`、`PYTHONUNBUFFERED=1`），
     `daemon-reload` + `enable` + `restart`；
   * 群晖无 systemd → 生成 `<DIR>/start.sh` 并打印"DSM 控制面板→计划任务"的注册指引（不静默失败）；
   * `FMO_NO_SERVICE=1` → 跳过。
9. 防火墙：仅当 ufw/firewalld 存在时放行**公网口**；**不要**放行管理口（更不要删除/清空已有规则）。
10. 自检：最多等 ~20 秒轮询 `/api/health`，成功打印汇总（安装目录、公网口、管理口后台地址、
    日志命令、卸载一行命令）；失败则打印 `journalctl`/日志排查提示并以非 0 退出。

### 3.5 幂等与升级
* 重复执行 = 升级：不丢数据、不重复追加 systemd 配置、端口不变（沿用已有 `config.json.port`）。
* 输出必须步骤化、中文、`[1/8]` 形式；出错时给出可执行的中文修复建议。

### 3.6 兼容性底线
* `#!/usr/bin/env bash` + `set -euo pipefail`；兼容 bash 4.2（群晖自带 bash 4.3，勿用 bash 5 语法、
  勿用 `mapfile`、勿用关联数组之外的高版本特性；避免依赖 `hostname -I`）。
* 所有变量引用加引号；临时文件用 `mktemp`；不使用 `eval`；不静默 `rm -rf` 未校验的路径。
* 不修改、不删除用户已有的 `users.db`/`sas.db`/`ca/`/`uploads/`。

---

## 4. 卸载脚本约定（`uninstall.sh`）

* 一行执行：`curl -fsSL <BASE>/uninstall.sh | sudo bash`（也支持 `bash uninstall.sh`、`bash uninstall.sh --purge`）。
* 默认**保留数据**（`*_users.db`、`*_sas.db`、`ca/`、`uploads/`、`roots/`、`config.json`）：
  停止+禁用+删除 systemd 单元（或群晖启动脚本），打印"数据保留在 `<DIR>`，彻底删除请加 `--purge`"。
* `--purge`：删除安装目录（删除前必须校验目标目录确实是 FMO 安装目录：存在 `api_server.py`），
  并二次打印将被删除的绝对路径。
* 幂等：未安装时打印说明并以 0 退出；`FMO_DIR` 可覆盖目录。

---

## 5. 打包脚本约定（`build_release.sh`）

* 用法：`bash build_release.sh [RELEASE_BASE_URL]`；`RELEASE_BASE_URL` 也可从 `dist/VERSION` 读取。
* 输出到 `dist/`：`fmo-subsystem-<VERSION>.tar.gz`、`fmo-subsystem-<VERSION>.tar.gz.sha256`、
  `checksums.txt`、`MANIFEST.txt`。
* **必须排除**（运行时/敏感产物，绝不进包）：`*.db`、`*.db-journal/-wal/-shm`、`ca/`（含
  `ca_private.json` 私钥）、`uploads/` 内文件、`__pycache__/`、`*.pyc`、`logs/`、`*.log`、`.git/`、
  `dist/`、`*.bak`、`*.tmp`、`roots/*`（信任链运行时数据）以及旧打包产物。
* **必须包含**：`api_server.py`、`sas_server.py`、`sync_engine.py`、`monitor.py`、`cert_gen.py`、
  `gen_app_key.py`、`diagnose.py`、`dmrid_bind_demo.py`、`dmrid_http_test.py`、`admin/index.html`、
  `config.default.json`、`config.json`、`requirements.txt`、`start.sh`、`fmo-subsystem.service`、
  `install.sh`、`uninstall.sh`、`README.txt`、`API.md`、`部署教程.md`、`INSTALL.md`、
  `dmrid_*.md`、`uploads/.gitkeep`。
* `checksums.txt` 至少包含 tarball 的 SHA256（`sha256sum` 兼容格式）；`MANIFEST.txt` 列出包内每个文件
  的大小 + SHA256（便于审计）。
* 打包后**自检**：`tar tzf` 列出内容，若命中排除规则中的敏感名（`*_private*`、`*.db`、`ca_private`）
  则报错并以非 0 退出。
* 若传入/读到 `RELEASE_BASE_URL`，用 `sed` 把 `install.sh` 的
  `DEFAULT_BASE_URL="..."` 行替换为真实地址（仅替换该行，不产生其它 diff）。
* 自包含 python3 脚本可作为 `tar` 的回退实现（Windows/Git Bash 无 python3 时用 tar）。

---

## 6. 验收标准（Lead 会逐条执行）

1. `bash -n install.sh uninstall.sh build_release.sh` 全部通过。
2. `bash build_release.sh` 在仓库根目录成功产出 `dist/fmo-subsystem-<VERSION>.tar.gz` + `.sha256`，
   且 `tar tzf` 中**不含** `*.db`、`ca/`、`uploads/*.png`、`__pycache__`。
3. 用 `file://` 或本地 `python3 -m http.server` 起静态站验证：`FMO_BASE_URL=<本地地址>` 全自动安装
   能在 Linux 上跑通（Lead 在受限环境用桩验证：解包→生成配置→启动 `api_server.py`→
   `/api/health` 返回 `ok:true`；端口+1 的 `/admin` 返回 HTML）。
4. `install.sh` 二次执行（升级路径）不破坏已有 `config.json`/数据库。
5. `uninstall.sh` 幂等；`--purge` 前校验目标目录。
6. 文档 `INSTALL.md` 给出可直接复制的 curl 一行命令、参数表、故障排查。

---

## 7. 写作范围（避免冲突）

* `teammate install-script`：只写 `install.sh`。
* `teammate packaging`：只写 `uninstall.sh`、`build_release.sh`、`dist/.gitignore`、根 `.gitignore` 增补。
* `Lead`：`INSTALL.md`、`dist/VERSION`、`README.txt`/`部署教程.md` 增补、最终验收。
* 任何人不得改 `api_server.py`/`sas_server.py`/`sync_engine.py`/`monitor.py`/`cert_gen.py`/`admin/index.html`
  的现有逻辑（本次只改部署方式）。如发现必须改源码才能一键部署，先报给 Lead。
