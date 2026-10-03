# 发布指南（GitHub Release 一键部署）

> 仓库：https://github.com/bmai-BH6BHG/fmosas
> 分发地址（固定，永远指向最新 Release）：
> `https://github.com/bmai-BH6BHG/fmosas/releases/latest/download`

---

## 一、一次性准备：把源码推上去

本仓库当前只有 `LICENSE` 和一个空的 `README.md`，需要把源码推上去。
`.gitignore` 已排除所有敏感/运行时文件（`ca/`、`*.db`、`uploads/*`、`dist/release-upload/`），
推送前建议再核一遍：

```bash
cd <本目录>
git init
git add -A
git status --short          # ← 检查这里不要出现 ca_private.json / *.db / uploads/*.png
git commit -m "FMO 分系统：一键部署（curl 网络拉取版）"
git branch -M main
git remote add origin https://github.com/bmai-BH6BHG/fmosas.git
git push -u origin main
```

推送需要 GitHub 账号凭据（HTTPS 用 Personal Access Token，或已登录的 Git Credential Manager）。
本机目前**没有配置 GitHub 凭据**，所以这一步需要你自己执行——我无法代你认证。

---

## 二、发一个版本（二选一）

### 方式 A（推荐）：打标签，让 GitHub Actions 自动发版

仓库里已放好流水线 `.github/workflows/release.yml`，你只需推一个标签：

```bash
git tag v1.0.0
git push origin v1.0.0
```

它会自动：
1. 把 `dist/VERSION` 的版本号改成 `1.0.0`；
2. `bash build_release.sh https://github.com/bmai-BH6BHG/fmosas/releases/latest/download`
   （把地址与版本号注入包内 `install.sh`）；
3. `bash -n` 语法检查 + `sha256sum -c` 资产校验；
4. 创建 Release `v1.0.0` 并上传全部资产。

也可以在仓库 **Actions → release → Run workflow** 手动填版本号触发。

> 标签名必须是 `v` 开头（如 `v1.0.0`），工作流会把 `v` 去掉当作版本号。

### 方式 B：本地打包 + 网页手动上传

```bash
bash build_release.sh https://github.com/bmai-BH6BHG/fmosas/releases/latest/download
```

然后 GitHub → Releases → *Draft a new release* → Tag 填 `v1.0.0` →
把 **`dist/release-upload/` 里的 7 个文件** 拖进附件区 → Publish。

两种方式产出的 Release 资产完全一致：

| 资产 | 作用 |
|---|---|
| `install.sh` | 一键安装（包里这份已注入 Release 地址） |
| `uninstall.sh` | 一键卸载 |
| `fmo-subsystem-1.0.0.tar.gz` | 部署包本体 |
| `fmo-subsystem-1.0.0.tar.gz.sha256` | 校验 |
| `fmo-subsystem.tar.gz` | 无版本号副本（回退通道） |
| `fmo-subsystem.tar.gz.sha256` | 校验 |
| `VERSION` | 版本标记（安装脚本优先读它） |
| `MANIFEST.txt` / `checksums.txt` | 发布留档（可只留一个） |

---

## 三、客户端安装

```bash
# 安装（永远取最新 Release）
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo bash

# 固定某个版本（把地址换成对应 tag）
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/download/v1.0.0/install.sh | sudo bash

# 卸载（默认保留数据库 / CA / 上传图片）
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/uninstall.sh | sudo bash
```

---

## 四、发布新版本

1. 改 `dist/VERSION` 里的 `VERSION=1.0.1`（如果走方式 A，工作流也会按标签名自动改）；
2. `git commit` + `git push`；
3. `git tag v1.0.1 && git push origin v1.0.1`。

客户端**不用改命令**：`releases/latest/download` 永远指向最新版。

---

## 五、常见问题

**Q：GitHub 在国内访问不稳定怎么办？**
`install.sh` 支持覆盖分发地址，可临时切到镜像/对象存储：

```bash
curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/install.sh | sudo \
  FMO_BASE_URL=https://你的镜像或对象存储地址 bash
```

**Q：Release 存在但下载 404？**
确认 Release 是 **Published** 而不是草稿，且资产名与上表一致（`latest/download` 只认已发布的 Release）。
也可以先用浏览器打开 `…/releases/latest/download/VERSION` 验证。

**Q：为什么包里要放两份 tar.gz？**
`fmo-subsystem-<版本>.tar.gz` 是按版本号精确取的主通道；
`fmo-subsystem.tar.gz` 是无版本号副本，主通道取不到时自动回退。
GitHub Release 的资产是平铺的，所以两者放在同一层。
