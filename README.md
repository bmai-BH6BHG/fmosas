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

装完：

| 用途 | 地址 |
|------|------|
| APP 调用（公网） | `http://<域名或IP>:35928` |
| FUS 门户（内网，勿映射公网） | `http://<内网IP>:35929/admin` |
| SAS 系统（认证服务） | `http://<内网IP>:35929/admin/sas` |
| FAS 系统（审计服务） | `http://<内网IP>:35929/admin/fus` |
| 健康检查 | `http://127.0.0.1:35928/api/health` |

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
cert_gen.py             # Ed25519 证书生成工具
gen_app_key.py          # 生成 APP 签名密钥对（国服 ID 绑定鉴权）
admin/index.html        # 管理后台（内网访问）
config.json             # 运行配置（端口 / 域名 / 总系统地址等）
config.default.json     # 配置模板（一键安装的新配置起点）
install.sh              # ★ curl 一键安装脚本（自包含，零参数）
uninstall.sh            # ★ 一键卸载脚本
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

* `ca/ca_private.json`（CA 私钥）、`*_users.db`、`*_sas.db`、`voice.db`、`uploads/` 均为运行时敏感数据，
  已在 `.gitignore` 排除，发布包中也不包含。
* 管理端口（公网口 + 1）只在内网使用，不要做端口映射。
* APP 私钥 `APP_SEED` 只烧进 APP，不要写进 `config.json` 或上传服务器。

## 许可

[Boost Software License 1.0](LICENSE) — 由 BH6BHG 提供。
