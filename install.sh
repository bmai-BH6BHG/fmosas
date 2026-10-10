#!/usr/bin/env bash
# ==========================================================================
#  FMO 分系统 · 网络拉取式一键安装脚本（自包含，可直接 curl | bash 执行）
#
#  用法（推荐，零参数）：
#      curl -fsSL <分发地址>/install.sh | sudo bash
#  也可：
#      bash install.sh
#
#  分发地址（下面 DEFAULT_BASE_URL）默认就是本项目 Release 的下载地址，
#  开箱即用。若要用镜像/自建分发站，在执行时用 FMO_BASE_URL=<地址> 覆盖，
#  或构建时由 build_release.sh 注入。
#
#  可选环境变量（唯一调整手段，全部可省略，脚本自动推断）：
#      FMO_BASE_URL    覆盖下载根地址
#      FMO_DIR         覆盖安装目录（默认 /opt/fmo-subsystem → /volume1/... → $HOME/...）
#      FMO_PORT        覆盖公网 API 端口（管理端口固定 = 该端口 + 1）
#      FMO_DOMAIN      覆盖对外域名/地址（默认沿用已有配置，否则取本机 IPv4）
#      FMO_MASTER      覆盖总系统地址（仅当现有 master_url 为空/还是默认值时才写入）
#      FMO_NO_SERVICE=1  只部署文件，不注册开机自启、不启动服务
#
#  本脚本不读取仓库内的其它文件（只使用下载包内的 config.default.json 等），
#  因此不能依赖“脚本自身所在目录”。
# ==========================================================================
set -euo pipefail

# ↓↓↓ 分发地址 = 本项目 Release 的下载地址（既是上传地址也是下载地址）。
#      latest/download 永远指向最新一次 Release，因此发新版**不用改这里**。
#      build_release.sh 若传了别的地址，会在打包时注入覆盖（不动仓库文件）。
DEFAULT_BASE_URL="https://github.com/bmai-BH6BHG/fmosas/releases/latest/download"
# ↓↓↓ 兜底版本号；若分发站根目录存在 VERSION 文件，则以该文件为准（契约 §2）↓↓↓
DEFAULT_VERSION="1.0.0"

SERVICE_NAME="fmo-subsystem"
PKG_PREFIX="fmo-subsystem"
DEFAULT_PORT=35928

# ---------------------------------------------------------------- 输出工具
step() { printf '\n[%s] %s\n' "$1" "$2"; }
say()  { printf '  %s\n' "$*"; }
warn() { printf '  [警告] %s\n' "$*" >&2; }
err()  { printf '  [错误] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------- 临时目录
TMP_ROOT=""
TMP_MARKER=""
cleanup() {
    if [ -n "${TMP_ROOT:-}" ] && [ -n "${TMP_MARKER:-}" ] \
       && [ -d "$TMP_ROOT" ] && [ -f "$TMP_MARKER" ]; then
        rm -rf "$TMP_ROOT"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 安装包内的目录/文件（用户数据），升级时必须保留
KEEP_NAMES="config.json ca uploads roots logs dist .git"

echo "======================================"
echo "  FMO 分系统 一键安装（网络拉取版）"
echo "======================================"

# ==========================================================================
# 0. root / 环境判定（不阻塞 Git Bash、Windows 等非 Linux 环境的测试）
# ==========================================================================
BASE_URL="${FMO_BASE_URL:-$DEFAULT_BASE_URL}"
# 去掉尾部斜杠
while [ "${BASE_URL%/}" != "$BASE_URL" ]; do BASE_URL="${BASE_URL%/}"; done
[ -n "$BASE_URL" ] || die "分发地址为空（FMO_BASE_URL / DEFAULT_BASE_URL）"

IS_ROOT=0
[ "$(id -u 2>/dev/null || echo 1)" = "0" ] && IS_ROOT=1

OS_KIND="$(uname -s 2>/dev/null || echo unknown)"
IS_WIN=0
case "$OS_KIND" in
    MINGW*|MSYS*|CYGWIN*|Windows*|Windows_NT*) IS_WIN=1 ;;
esac

if [ "$BASE_URL" != "$DEFAULT_BASE_URL" ]; then
    say "已用 FMO_BASE_URL 覆盖分发地址：$BASE_URL"
fi

if [ "$IS_ROOT" != 1 ]; then
    if [ "$IS_WIN" = 1 ]; then
        say "[提示] 当前为 Windows / Git Bash 环境：跳过 root 提权，仅做可写目录内的部署测试"
    elif command -v sudo >/dev/null 2>&1; then
        SELF_FILE=""
        case "$0" in
            */*) [ -f "$0" ] && SELF_FILE="$0" ;;
        esac
        if [ -n "$SELF_FILE" ]; then
            say "[提示] 需要 root 权限，正在通过 sudo 重新执行本脚本 ..."
            exec sudo -E bash "$SELF_FILE" "$@"
        else
            err "需要 root 权限执行本脚本（当前脚本来自管道，无法自动提权）。"
            err "请改用： curl -fsSL ${BASE_URL}/install.sh | sudo bash"
            exit 1
        fi
    else
        warn "未检测到 sudo，将以非 root 用户继续；开机自启(systemd)和防火墙配置会被跳过。"
    fi
fi

# ==========================================================================
# 1/8 前置检查与依赖
# ==========================================================================
step "1/8" "环境检查与依赖（curl/wget、tar、gzip、python3）"

install_pkgs() {
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q "$@"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q "$@"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache "$@"
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install "$@"
    else
        return 1
    fi
}

HAVE_CURL=0
HAVE_WGET=0
command -v curl >/dev/null 2>&1 && HAVE_CURL=1
command -v wget >/dev/null 2>&1 && HAVE_WGET=1
if [ "$HAVE_CURL" = 0 ] && [ "$HAVE_WGET" = 0 ]; then
    say "未找到 curl / wget，尝试自动安装 ..."
    install_pkgs curl >/dev/null 2>&1 || install_pkgs wget >/dev/null 2>&1 || true
    command -v curl >/dev/null 2>&1 && HAVE_CURL=1
    command -v wget >/dev/null 2>&1 && HAVE_WGET=1
    [ "$HAVE_CURL" = 1 ] || [ "$HAVE_WGET" = 1 ] || \
        die "缺少 curl 和 wget，无法下载安装包。请先安装：apt install -y curl（或 yum install -y curl）"
fi

if ! command -v tar >/dev/null 2>&1; then
    say "未找到 tar，尝试自动安装 ..."
    install_pkgs tar >/dev/null 2>&1 || true
    command -v tar >/dev/null 2>&1 || die "缺少 tar，无法解包。请先安装：apt install -y tar"
fi

if ! command -v gzip >/dev/null 2>&1; then
    say "未找到 gzip，尝试自动安装 ..."
    install_pkgs gzip >/dev/null 2>&1 || true
    command -v gzip >/dev/null 2>&1 || die "缺少 gzip，无法解压 .tar.gz。请先安装：apt install -y gzip"
fi

if [ "$HAVE_CURL" = 1 ]; then say "下载工具：curl"; else say "下载工具：wget"; fi
say "解包工具：tar + gzip 已就绪"

# ---------------------------------------------------------------- 下载函数
fetch() {   # fetch <url> <输出文件> ；失败返回非 0
    if [ "$HAVE_CURL" = 1 ]; then
        curl -fsSL --connect-timeout 20 --retry 2 --retry-delay 2 -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

http_get() {  # http_get <url> ；成功输出响应体
    if [ "$HAVE_CURL" = 1 ]; then
        curl -fsS --max-time 3 "$1" 2>/dev/null || true
    elif [ "$HAVE_WGET" = 1 ]; then
        wget -q -O - --timeout=3 "$1" 2>/dev/null || true
    else
        return 0
    fi
}

# ---------------------------------------------------------------- 定位 python
python_ok() {  # python_ok <可执行文件>
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[0] == 3 and sys.version_info[1] >= 7 else 1)' >/dev/null 2>&1
}

resolve_python() {
    local cand=""
    for cand in python3 python; do
        cand="$(command -v "$cand" 2>/dev/null || true)"
        if [ -n "$cand" ] && [ -x "$cand" ] && python_ok "$cand"; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    # 群晖套件路径 / 常见系统路径
    local p=""
    for p in /var/packages/Python*/target/usr/bin/python3 \
             /var/packages/python3*/target/usr/bin/python3 \
             /usr/local/bin/python3 /usr/bin/python3 /usr/local/bin/python; do
        if [ -x "$p" ] && python_ok "$p"; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

PY="$(resolve_python || true)"
if [ -z "$PY" ]; then
    say "未找到可用的 Python 3，尝试自动安装 ..."
    install_pkgs python3 >/dev/null 2>&1 || true
    PY="$(resolve_python || true)"
fi
[ -n "$PY" ] || die "未找到 Python 3.7+。请先安装（群晖：套件中心安装 Python3；Linux：apt install -y python3）"

say "Python 解释器：$PY ($("$PY" --version 2>&1 | tr -d '\r'))"

# ==========================================================================
# 临时工作目录
# ==========================================================================
TMP_ROOT="$(mktemp -d 2>/dev/null || mktemp -d -t fmo-install)" || die "无法创建临时目录（mktemp 失败）"
[ -n "$TMP_ROOT" ] && [ -d "$TMP_ROOT" ] || die "临时目录创建异常"
TMP_MARKER="$TMP_ROOT/.fmo-install-tmp"
: > "$TMP_MARKER"
say "临时目录：$TMP_ROOT"

# ==========================================================================
# 2/8 解析分发地址 / 版本并下载
# ==========================================================================
step "2/8" "解析分发地址与版本，下载安装包"
say "分发地址：$BASE_URL"

# 版本号：优先取分发站根的 VERSION 文件（内容形如 VERSION=1.0.0），否则用内置兜底值
SITE_VERSION=""
if fetch "$BASE_URL/VERSION" "$TMP_ROOT/VERSION.site" 2>/dev/null; then
    SITE_VERSION="$(sed -n 's/^[[:space:]]*VERSION=//p' "$TMP_ROOT/VERSION.site" 2>/dev/null | head -n 1 | tr -d '\r' | sed "s/[\"']//g" || true)"
    case "$SITE_VERSION" in
        *[!0-9A-Za-z._-]*) SITE_VERSION="" ;;
    esac
fi
if [ -n "$SITE_VERSION" ]; then
    say "分发站版本：$SITE_VERSION"
else
    say "分发站无 VERSION 文件，使用脚本内置版本：$DEFAULT_VERSION"
fi

TARBALL_URL=""
TARBALL_VERSION=""

try_tarball() {  # try_tarball <版本号|latest>
    local v="$1" url=""
    if [ "$v" = "latest" ]; then
        # 回退通道：不带版本号的包，与版本包同级放置。
        # 这样 GitHub / Gitee Release 的平铺资产目录也能直接用（Release 下没有 latest/ 子目录）。
        url="$BASE_URL/${PKG_PREFIX}.tar.gz"
    else
        url="$BASE_URL/${PKG_PREFIX}-${v}.tar.gz"
    fi
    if fetch "$url" "$TMP_ROOT/pkg.tar.gz" 2>/dev/null && [ -s "$TMP_ROOT/pkg.tar.gz" ]; then
        TARBALL_URL="$url"
        TARBALL_VERSION="$v"
        return 0
    fi
    rm -f "$TMP_ROOT/pkg.tar.gz" 2>/dev/null || true
    return 1
}

if [ -n "$SITE_VERSION" ] && try_tarball "$SITE_VERSION"; then
    :
elif [ "$DEFAULT_VERSION" != "$SITE_VERSION" ] && try_tarball "$DEFAULT_VERSION"; then
    :
elif try_tarball latest; then
    warn "主地址（版本包）不可用，已回退到无版本号包通道：$TARBALL_URL"
else
    err "下载安装包失败。已尝试："
    err "  $BASE_URL/${PKG_PREFIX}-${SITE_VERSION:-$DEFAULT_VERSION}.tar.gz"
    err "  $BASE_URL/${PKG_PREFIX}.tar.gz"
    err "提示：若用 GitHub/Gitee Release，请把 install.sh 换成 releases/latest/download/install.sh"
    die "请检查网络、分发地址是否正确（可用 FMO_BASE_URL 覆盖）"
fi

PKG_SIZE="$(wc -c < "$TMP_ROOT/pkg.tar.gz" 2>/dev/null | tr -d ' ' || echo 0)"
say "已下载：$TARBALL_URL（${PKG_SIZE} 字节）"

# ==========================================================================
# 3/8 SHA256 强制校验
# ==========================================================================
step "3/8" "SHA256 完整性校验"

compute_sha256() {  # compute_sha256 <文件> ；输出小写 hex
    local f="$1" out=""
    if command -v sha256sum >/dev/null 2>&1; then
        out="$(sha256sum "$f" 2>/dev/null | sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n 1 || true)"
    fi
    if [ -z "$out" ] && command -v shasum >/dev/null 2>&1; then
        out="$(shasum -a 256 "$f" 2>/dev/null | sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n 1 || true)"
    fi
    if [ -z "$out" ] && command -v openssl >/dev/null 2>&1; then
        out="$(openssl dgst -sha256 "$f" 2>/dev/null | sed -n 's/^.*[= ]\([0-9a-fA-F]\{64\}\)$/\1/p' | head -n 1 || true)"
    fi
    if [ -z "$out" ]; then
        out="$("$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$f" 2>/dev/null || true)"
    fi
    printf '%s' "$out" | tr 'A-F' 'a-f'
}

ACTUAL_SHA="$(compute_sha256 "$TMP_ROOT/pkg.tar.gz")"
[ -n "$ACTUAL_SHA" ] || die "无法计算安装包 SHA256（缺少 sha256sum/shasum/openssl，且 Python 计算失败）"
say "实际 SHA256：$ACTUAL_SHA"

SHA_URL="$TARBALL_URL.sha256"
EXPECT_SHA=""
if fetch "$SHA_URL" "$TMP_ROOT/pkg.sha256" 2>/dev/null && [ -s "$TMP_ROOT/pkg.sha256" ]; then
    EXPECT_SHA="$(sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' "$TMP_ROOT/pkg.sha256" | head -n 1 || true)"
    EXPECT_SHA="$(printf '%s' "$EXPECT_SHA" | tr 'A-F' 'a-f')"
    if [ -z "$EXPECT_SHA" ]; then
        warn "校验文件 $SHA_URL 内容格式无法识别（应为 64 位 hex），已跳过逐字节比对"
    fi
else
    warn "取不到校验文件 $SHA_URL"
    warn "!! 无法验证安装包完整性，仍将继续安装；建议手工核对发布页公布的 SHA256 !!"
fi

if [ -n "$EXPECT_SHA" ]; then
    if [ "$EXPECT_SHA" != "$ACTUAL_SHA" ]; then
        err "SHA256 校验失败，安装包可能损坏或被篡改，安装中止！"
        err "  期望：$EXPECT_SHA"
        err "  实际：$ACTUAL_SHA"
        err "  文件：$TARBALL_URL"
        exit 1
    fi
    say "SHA256 校验通过（与 $SHA_URL 一致）"
fi

# ==========================================================================
# 4/8 解包与内容校验
# ==========================================================================
step "4/8" "解包安装包并校验内容"

if tar -tzf "$TMP_ROOT/pkg.tar.gz" 2>/dev/null | grep -q '\.\./'; then
    die "安装包内含非法的上级目录路径（../），出于安全考虑中止安装"
fi

SRC="$TMP_ROOT/src"
mkdir -p "$SRC"
tar -xzf "$TMP_ROOT/pkg.tar.gz" -C "$SRC" || die "解包失败（tar 返回非 0），安装包可能已损坏"

# 契约要求“源码平铺在根目录”；这里兼容“多一层目录”的包
if [ ! -f "$SRC/api_server.py" ]; then
    for d in "$SRC"/*/; do
        if [ -f "${d}api_server.py" ]; then
            SRC="${d%/}"
            say "检测到包内多一层目录，已自动进入：$(basename "$SRC")"
            break
        fi
    done
fi

[ -f "$SRC/api_server.py" ]        || die "安装包内缺少 api_server.py，包内容不完整"
[ -f "$SRC/admin/index.html" ]     || die "安装包内缺少 admin/index.html，包内容不完整"
[ -f "$SRC/admin/portal.html" ]    || die "安装包内缺少 admin/portal.html，包内容不完整"
[ -f "$SRC/config.default.json" ]  || die "安装包内缺少 config.default.json，包内容不完整"
say "包内容校验通过：api_server.py / admin/index.html / admin/portal.html / config.default.json"

# ==========================================================================
# 5/8 Python 依赖 cryptography
# ==========================================================================
step "5/8" "检查并安装 Python 依赖 cryptography"

if "$PY" -c "import cryptography" >/dev/null 2>&1; then
    CRYPTO_VER="$("$PY" -c 'import cryptography;print(cryptography.__version__)' 2>/dev/null || echo unknown)"
    say "cryptography 已就绪（$CRYPTO_VER），跳过安装"
else
    say "正在安装 cryptography（唯一第三方依赖）..."
    "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
    "$PY" -m pip install "cryptography>=41.0" >/dev/null 2>&1 \
        || "$PY" -m pip install --break-system-packages "cryptography>=41.0" >/dev/null 2>&1 \
        || install_pkgs python3-cryptography >/dev/null 2>&1 \
        || true
    if "$PY" -c "import cryptography" >/dev/null 2>&1; then
        say "cryptography 安装成功"
    else
        err "cryptography 安装失败（国服ID绑定 / SAS 证书签发将不可用）。"
        err "手动修复： $PY -m pip install \"cryptography>=41.0\""
        err "群晖可执行： $PY -m pip install --break-system-packages cryptography"
        exit 1
    fi
fi

# ==========================================================================
# 6/8 安装目录 + 端口 + 生成/合并 config.json
# ==========================================================================
step "6/8" "确定安装目录、端口与 config.json"

# ---- 6.1 安装目录选择（契约 §3.3）----
if [ -n "${FMO_DIR:-}" ]; then
    DIR="$FMO_DIR"
    say "安装目录：使用 FMO_DIR 指定值"
elif [ -d /opt ] && [ -w /opt ]; then
    DIR="/opt/fmo-subsystem"
    say "安装目录：/opt 可写"
elif [ -d /volume1 ] && [ -w /volume1 ]; then
    DIR="/volume1/fmo-subsystem"
    say "安装目录：群晖 /volume1 可写"
else
    DIR="$HOME/fmo-subsystem"
    say "安装目录：回退到用户主目录"
fi
# 转为绝对路径（避免相对路径在管道执行时落到不可预期的 cwd）
case "$DIR" in
    /*) : ;;
    *)  DIR="$(pwd)/$DIR" ;;
esac
mkdir -p "$DIR" 2>/dev/null || die "无法创建安装目录：$DIR（请用 FMO_DIR 指定一个可写目录，或用 sudo 运行）"
[ -w "$DIR" ] || die "安装目录不可写：$DIR（请用 sudo 运行或用 FMO_DIR 指定可写目录）"
say "安装目录：$DIR"

# 目录权限/占位目录（源码多数自建，这里保证存在且权限正确）
mkdir -p "$DIR/uploads" "$DIR/ca" "$DIR/roots" 2>/dev/null || true

# ---- 6.2 端口探测（公网口 = port，管理口 = port + 1，两端口必须同时可用）----
PORT_PROBE="$("$PY" - "$DEFAULT_PORT" "${FMO_PORT:-}" "$DIR/config.json" <<'PYEOF'
import json, os, socket, sys

def parse_port(v):
    try:
        n = int(str(v).strip())
    except Exception:
        return 0
    return n if 1 <= n <= 65534 else 0

default_port = parse_port(sys.argv[1]) or 35928
explicit = parse_port(sys.argv[2]) if len(sys.argv) > 2 else 0
cfg_path = sys.argv[3] if len(sys.argv) > 3 else ""

existing = 0
if cfg_path and os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r", encoding="utf-8-sig") as f:
            existing = parse_port(json.load(f).get("port"))
    except Exception:
        existing = 0

def in_use(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)
    try:
        s.connect(("127.0.0.1", p))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def bindable(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def pair_free(p):
    if p < 1 or p > 65534:
        return False
    return bindable(p) and bindable(p + 1) and not in_use(p) and not in_use(p + 1)

port, status = 0, "AUTO"
if explicit:
    port, status = explicit, ("EXPLICIT" if pair_free(explicit) else "EXPLICIT_BUSY")
elif existing:
    # 升级：沿用已有端口（契约 §3.5），本机自己占着端口属正常现象
    port, status = existing, ("REUSE_EXISTING" if pair_free(existing) else "REUSE_EXISTING_BUSY")
else:
    if pair_free(default_port):
        port = default_port
    else:
        p = default_port + 1
        while p <= 65534 and not pair_free(p):
            p += 1
        port = p if p <= 65534 else default_port
    status = "AUTO" if port == default_port else "AUTO_MOVED"

print(port)
print(status)
print(existing)
PYEOF
)" || die "端口探测失败"

PORT="$(printf '%s\n' "$PORT_PROBE" | sed -n '1p' | tr -d '\r')"
PORT_STATUS="$(printf '%s\n' "$PORT_PROBE" | sed -n '2p' | tr -d '\r')"
EXISTING_PORT="$(printf '%s\n' "$PORT_PROBE" | sed -n '3p' | tr -d '\r')"
case "$PORT" in
    ''|*[!0-9]*) die "端口解析异常：'$PORT'（可用 FMO_PORT=<1-65534> 指定）" ;;
esac

case "$PORT_STATUS" in
    EXPLICIT)            say "端口：使用 FMO_PORT=$PORT（该端口与 $((PORT + 1)) 均空闲）" ;;
    EXPLICIT_BUSY)       warn "FMO_PORT=$PORT 或管理口 $((PORT + 1)) 已被占用，服务可能启动失败" ;;
    REUSE_EXISTING)      say "端口：沿用已有 config.json 的 port=$PORT（幂等升级，端口不变）" ;;
    REUSE_EXISTING_BUSY) say "端口：沿用已有 config.json 的 port=$PORT（当前被占用，稍后会重启本服务释放）" ;;
    AUTO)                say "端口：自动探测到空闲端口对 $PORT / $((PORT + 1))" ;;
    AUTO_MOVED)          say "端口：默认 $DEFAULT_PORT 被占用，自动改用空闲端口对 $PORT / $((PORT + 1))" ;;
esac
ADMIN_PORT=$((PORT + 1))

# ---- 6.3 生成 / 增量合并 config.json（绝不覆盖用户数据）----
CFG_OUT="$("$PY" - "$DIR/config.json" "$SRC/config.default.json" "$PORT" "${FMO_DOMAIN:-}" "${FMO_MASTER:-}" <<'PYEOF'
import json, os, shutil, socket, sys, uuid

cfg_path = sys.argv[1]
tpl_path = sys.argv[2]
new_port = int(sys.argv[3])
fmo_domain = (sys.argv[4] if len(sys.argv) > 4 else "").strip()
fmo_master = (sys.argv[5] if len(sys.argv) > 5 else "").strip()

PLACEHOLDER_DOMAINS = ("", "127.0.0.1", "localhost", "register.example.com")

def load_json(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}

tpl = {}
if os.path.exists(tpl_path):
    try:
        tpl = load_json(tpl_path)
    except Exception as e:
        sys.stderr.write("模板 config.default.json 解析失败：%s\n" % e)

cfg = {}
created = False
if os.path.exists(cfg_path):
    try:
        cfg = load_json(cfg_path)
    except Exception as e:
        # 解析失败：备份坏文件，绝不当场丢弃用户数据
        bad = cfg_path + ".bad"
        try:
            shutil.copy2(cfg_path, bad)
        except Exception:
            bad = "(备份失败)"
        sys.stderr.write("已有 config.json 解析失败：%s；原文件已备份为 %s\n" % (e, bad))
        cfg = {}
        created = True
else:
    created = True

old_port = 0
try:
    old_port = int(cfg.get("port") or 0)
except Exception:
    old_port = 0
old_api_url = str(cfg.get("api_url") or "").strip()

# 用模板补齐“缺失”的键（不覆盖任何已有值，含 dmrid/peers/monitor/subsystem_id）
def deep_fill(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
        elif isinstance(dst.get(k), dict) and isinstance(v, dict):
            deep_fill(dst[k], v)

deep_fill(cfg, tpl)

# ---- domain：FMO_DOMAIN > 已有非占位值 > 本机 IPv4 ----
def local_ip():
    ip = ""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = ""
    if not ip or ip.startswith("127."):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            finally:
                s.close()
        except Exception:
            pass
    if not ip or ip.startswith("127."):
        ip = "127.0.0.1"
    return ip

domain_source = "auto"
old_domain = str(cfg.get("domain") or "").strip()
if fmo_domain:
    domain = fmo_domain
    domain_source = "FMO_DOMAIN"
elif old_domain not in PLACEHOLDER_DOMAINS:
    domain = old_domain
    domain_source = "existing"
else:
    domain = local_ip()

cfg["port"] = new_port
cfg["domain"] = domain
cfg["api_url"] = "http://%s:%d" % (domain, new_port)

# ---- master_url：仅在为空/默认时才写入 FMO_MASTER ----
master_written = "no"
if fmo_master:
    cur = str(cfg.get("master_url") or "").strip()
    defaults = {"", "http://127.0.0.1:35930", str(tpl.get("master_url") or "").strip()}
    if cur in defaults:
        cfg["master_url"] = fmo_master
        master_written = "yes"

# ---- subsystem_id：空 或 sub-001 时按源码同算法确定性生成 uuid5(主机名+MAC) ----
sub_id = str(cfg.get("subsystem_id") or "").strip()
sub_generated = "no"
if not sub_id or sub_id == "sub-001":
    hostname = socket.gethostname()
    mac = ""
    try:
        mac = uuid.getnode().to_bytes(6, "big").hex()
    except Exception:
        mac = ""
    cfg["subsystem_id"] = "sub-" + uuid.uuid5(uuid.NAMESPACE_DNS, "%s|%s" % (hostname, mac)).hex[:8]
    sub_generated = "yes"

# ---- 目录类配置兜底（仅补空值）----
trust = cfg.get("trust")
if not isinstance(trust, dict):
    trust = {}
    cfg["trust"] = trust
if not str(trust.get("rootsDir") or "").strip():
    trust["rootsDir"] = "roots"
if not str(cfg.get("ca_dir") or "").strip():
    cfg["ca_dir"] = "ca"

# ---- 写回（原子替换，保留原文件权限）----
tmp_path = cfg_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=4, ensure_ascii=False)
    f.write("\n")
try:
    st = os.stat(cfg_path)
    os.chmod(tmp_path, st.st_mode & 0o777)
except Exception:
    pass
os.replace(tmp_path, cfg_path)

dmrid = cfg.get("dmrid") if isinstance(cfg.get("dmrid"), dict) else {}
pubkey = str(dmrid.get("app_pubkey") or "").strip()

print("CFG_STATUS=%s" % ("created" if created else "updated"))
print("CFG_PORT=%d" % new_port)
print("CFG_DOMAIN=%s" % domain)
print("CFG_DOMAIN_SOURCE=%s" % domain_source)
print("CFG_API_URL=%s" % cfg["api_url"])
print("CFG_SUBSYSTEM_ID=%s" % cfg["subsystem_id"])
print("CFG_SUB_GENERATED=%s" % sub_generated)
print("CFG_MASTER_WRITTEN=%s" % master_written)
print("CFG_APP_PUBKEY=%s" % ("ok" if pubkey else "empty"))
PYEOF
)" || die "生成/合并 config.json 失败"

cfg_val() { printf '%s\n' "$CFG_OUT" | sed -n "s/^$1=//p" | head -n 1 | tr -d '\r'; }
CFG_STATUS="$(cfg_val CFG_STATUS)"
[ -n "$CFG_STATUS" ] || die "config.json 合并过程异常（无输出）"
say "config.json：$([ "$CFG_STATUS" = "created" ] && echo "新建（以包内 config.default.json 为模板）" || echo "原地增量更新（保留已有配置）")"
say "  domain     : $(cfg_val CFG_DOMAIN)  [来源: $(cfg_val CFG_DOMAIN_SOURCE)]"
say "  api_url    : $(cfg_val CFG_API_URL)"
say "  port       : $(cfg_val CFG_PORT)  管理口: $ADMIN_PORT"
say "  subsystem_id: $(cfg_val CFG_SUBSYSTEM_ID)$([ "$(cfg_val CFG_SUB_GENERATED)" = "yes" ] && echo "（本次按主机名+MAC 确定性生成）")"
[ "$(cfg_val CFG_MASTER_WRITTEN)" = "yes" ] && say "  master_url : 已按 FMO_MASTER 写入"
if [ "$(cfg_val CFG_APP_PUBKEY)" = "empty" ]; then
    warn "dmrid.app_pubkey 为空，国服ID绑定（APP 签名校验）将被拒绝。"
    warn "修复：执行  sudo fus-set-appkey   即可写入官方 APP 公钥（无需自己生成密钥）。"
fi

# ==========================================================================
# 7/8 同步源码（保留用户数据；start.sh 已存在则不覆盖）
# ==========================================================================
SRC_PWD="$(cd "$SRC" && pwd -P)"
DIR_PWD="$(cd "$DIR" && pwd -P)"
if [ "$SRC_PWD" = "$DIR_PWD" ]; then
    say "源码目录与安装目录相同，跳过文件同步"
else
    # ======================================================================
    step "7/8" "同步源码到安装目录（保留用户数据）"
    for entry in "$SRC"/* "$SRC"/.[!.]*; do
        [ -e "$entry" ] || continue
        name="$(basename "$entry")"
        skip=0
        for keep in $KEEP_NAMES; do
            [ "$name" = "$keep" ] && skip=1
        done
        case "$name" in
            *.db|*.db-journal|*.db-wal|*.db-shm|*.log|*.bak|*.tmp) skip=1 ;;
        esac
        if [ "$skip" = 1 ]; then
            if [ -e "$DIR/$name" ]; then
                say "保留已有：$name"
            elif [ "$name" = "ca" ] || [ "$name" = "uploads" ] || [ "$name" = "roots" ] || [ "$name" = "logs" ]; then
                mkdir -p "$DIR/$name" 2>/dev/null || true
            fi
            continue
        fi
        if [ -d "$entry" ] && [ -d "$DIR/$name" ]; then
            cp -a "$entry"/. "$DIR/$name"/ || die "复制目录失败：$name"
        else
            cp -a "$entry" "$DIR/" || die "复制文件失败：$name"
        fi
    done
    # 再确认一次关键文件（防止包内结构异常导致漏拷）
    [ -f "$DIR/api_server.py" ] || die "同步后安装目录缺少 api_server.py"
    [ -f "$DIR/admin/index.html" ] || die "同步后安装目录缺少 admin/index.html"
    [ -f "$DIR/admin/portal.html" ] || die "同步后安装目录缺少 admin/portal.html（FUS 门户）"
    chmod +x "$DIR/start.sh" 2>/dev/null || true
    chmod +x "$DIR/install.sh" "$DIR/uninstall.sh" 2>/dev/null || true
    say "源码已同步到：$DIR（config.json / *_users.db / *_sas.db / ca/ / uploads/ / roots/ 均未被覆盖）"
fi

# ==========================================================================
# 注册 APP 密钥写入命令：fus-set-appkey / bas-set-appkey
#   给"装了系统但没部署 APP 密钥对"的人一条命令搞定，不用知道 config.json 结构。
# ==========================================================================
install_appkey_cmd() {
    [ -f "$DIR/set_appkey.py" ] || { warn "未找到 set_appkey.py，跳过注册 fus-set-appkey"; return 0; }
    if [ "$IS_ROOT" != 1 ]; then
        say "非 root：跳过注册全局命令（可直接运行：$PY $DIR/set_appkey.py）"
        return 0
    fi
    # ★ 必须同时装到 /usr/bin：sudo 会重置 PATH 为 secure_path，
    #   而多数系统的 secure_path 里**没有** /usr/local/bin
    #   （真实问题：装好命令后用 sudo fus-set-appkey 提示 command not found）。
    INSTALLED=""
    for BINDIR in /usr/local/bin /usr/bin; do
        [ -d "$BINDIR" ] || continue
        for CMDNAME in fus-set-appkey bas-set-appkey; do
            cat > "$BINDIR/$CMDNAME" <<EOF
#!/bin/sh
# FMO/FUS：写入 APP 签名公钥（由 install.sh 自动生成，勿手改）
exec ${PY} "${DIR}/set_appkey.py" "\$@"
EOF
            chmod 0755 "$BINDIR/$CMDNAME" 2>/dev/null || true
        done
        INSTALLED="$INSTALLED $BINDIR"
    done
    say "已注册命令：fus-set-appkey（别名 bas-set-appkey）→ $PY $DIR/set_appkey.py"
    say "           安装位置：$INSTALLED"
    return 0
}
install_appkey_cmd

# ==========================================================================
# 注册一键升级命令：fus-upgrade / bas-upgrade
#   **只升级系统**，不动 config.json / *.db / ca/ 等用户数据。
# ==========================================================================
install_upgrade_cmd() {
    [ -f "$DIR/upgrade.sh" ] || { warn "未找到 upgrade.sh，跳过注册 fus-upgrade"; return 0; }
    if [ "$IS_ROOT" != 1 ]; then
        say "非 root：跳过注册（可直接运行：bash $DIR/upgrade.sh）"
        return 0
    fi
    for BINDIR in /usr/local/bin /usr/bin; do
        [ -d "$BINDIR" ] || continue
        for CMDNAME in fus-upgrade bas-upgrade; do
            cat > "$BINDIR/$CMDNAME" <<EOF
#!/bin/sh
# FMO/FUS：一键升级（只升级系统，不动配置与数据）
exec bash "${DIR}/upgrade.sh" "\$@"
EOF
            chmod 0755 "$BINDIR/$CMDNAME" 2>/dev/null || true
        done
    done
    say "已注册命令：fus-upgrade（别名 bas-upgrade）→ bash $DIR/upgrade.sh"
    return 0
}
install_upgrade_cmd

# ==========================================================================
# 8/8 注册开机自启 / 防火墙 / 自检
# ==========================================================================
step "8/8" "配置开机自启、防火墙与安装后自检"

SERVICE_STARTED=0
if [ "${FMO_NO_SERVICE:-0}" = "1" ]; then
    say "FMO_NO_SERVICE=1：跳过 systemd 注册与启动"
elif [ "$IS_ROOT" = 1 ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ "$IS_ROOT" = 1 ]; then RUN_USER="root"; else RUN_USER="$(id -un 2>/dev/null || echo root)"; fi
    cat > "$UNIT" <<EOF
[Unit]
Description=FMO Subsystem API Server (public ${PORT} / admin ${ADMIN_PORT})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${DIR}
ExecStart=${PY} -u ${DIR}/api_server.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || die "systemctl daemon-reload 失败"
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || warn "systemctl enable 失败（可稍后手动 enable）"
    if systemctl restart "$SERVICE_NAME"; then
        SERVICE_STARTED=1
        say "systemd 服务已注册并启动：$UNIT"
    else
        err "systemd 服务启动失败。排查： journalctl -u $SERVICE_NAME -n 50 --no-pager"
        exit 1
    fi
else
    # 无 systemd（群晖 DSM / Windows 测试环境 / 非 root 容器）
    if [ -f "$DIR/start.sh" ]; then
        say "已存在启动脚本：$DIR/start.sh"
    else
        cat > "$DIR/start.sh" <<EOF
#!/bin/bash
# FMO 分系统 启动脚本（由 install.sh 生成；DSM 计划任务 / 手动启动均可）
set -e
cd "${DIR}"
exec "${PY}" -u "${DIR}/api_server.py"
EOF
        chmod +x "$DIR/start.sh" 2>/dev/null || true
        say "已生成启动脚本：$DIR/start.sh"
    fi
    if [ "$IS_WIN" = 1 ]; then
        say "当前为 Windows/Git Bash 环境：不注册开机自启。手动启动命令："
        say "  cd \"$DIR\" && \"$PY\" -u \"$DIR/api_server.py\""
    elif [ -d /volume1 ] || [ -f /etc/synoinfo.conf ]; then
        echo "  ----------------------------------------------------------------"
        echo "  群晖 DSM 未启用 systemd，请手动注册开机自启（复制以下操作）："
        echo "    DSM 控制面板 → 任务计划 → 新增 → 触发的任务 → 开机自动启动"
        echo "        任务名称：FMO 分系统"
        echo "        用户账号：root"
        echo "        命令：     cd \"$DIR\" && \"$PY\" -u \"$DIR/api_server.py\""
        echo "    （或选择“用户定义的脚本”，脚本内容同上）"
        echo "    保存后选中该任务 → 运行，即可立即启动。"
        echo "  也可以手动启动： bash \"$DIR/start.sh\""
        echo "  ----------------------------------------------------------------"
    else
        say "未检测到 systemd（或非 root）：不注册开机自启。手动启动命令："
        say "  cd \"$DIR\" && \"$PY\" -u \"$DIR/api_server.py\""
    fi
fi

# ---- 防火墙：只放行公网口（契约 §3.4-9）----
if [ "$IS_ROOT" = 1 ]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        if ufw allow "${PORT}/tcp" >/dev/null 2>&1; then
            say "防火墙：已放行 ufw ${PORT}/tcp（管理口 ${ADMIN_PORT} 未放行）"
        else
            warn "ufw 放行 ${PORT}/tcp 失败，请手动执行： ufw allow ${PORT}/tcp"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        if firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1; then
            say "防火墙：已放行 firewalld ${PORT}/tcp（管理口 ${ADMIN_PORT} 未放行）"
        else
            warn "firewalld 放行失败，请手动执行： firewall-cmd --permanent --add-port=${PORT}/tcp && firewall-cmd --reload"
        fi
    else
        say "防火墙：未检测到启用中的 ufw/firewalld，跳过（未修改任何规则）"
    fi
else
    say "防火墙：非 root，跳过（如需放行： ufw allow ${PORT}/tcp）"
fi

# ---- 安装后自检：探测 /api/health（服务已启动则最多轮询约 20 秒）----
HEALTH_URL="http://127.0.0.1:${PORT}/api/health"
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}/admin"
HEALTH_OK=0
BODY=""

probe_health() {
    BODY="$(http_get "$HEALTH_URL" | head -c 4000 || true)"
    if printf '%s' "$BODY" | tr -d ' \r\n\t' | grep -q '"ok":true' \
       && printf '%s' "$BODY" | grep -q 'fmo-subsystem'; then
        return 0
    fi
    return 1
}

if probe_health; then
    # 服务已在运行（全新安装刚启动 / 升级时旧进程仍在跑），立即通过
    HEALTH_OK=1
elif [ "$SERVICE_STARTED" = 1 ]; then
    START_TS="$(date +%s 2>/dev/null || true)"
    case "$START_TS" in
        ''|*[!0-9]*) START_TS="" ;;
    esac
    i=0
    while [ "$i" -lt 20 ]; do
        i=$((i + 1))
        sleep 1
        if probe_health; then
            HEALTH_OK=1
            break
        fi
        if [ -n "$START_TS" ]; then
            NOW_TS="$(date +%s 2>/dev/null || true)"
            case "$NOW_TS" in
                ''|*[!0-9]*) NOW_TS="" ;;
            esac
            if [ -n "$NOW_TS" ] && [ "$((NOW_TS - START_TS))" -ge 20 ]; then
                break
            fi
        fi
    done
fi

if [ "$HEALTH_OK" = 1 ]; then
    say "自检通过：$HEALTH_URL → $(printf '%s' "$BODY" | head -c 200)"
    # FUS 各入口都要能出 HTML：门户 → SAS → FAS → 互联桥接
    for _u in "/admin" "/admin/sas" "/admin/fus" "/admin/bridge"; do
        _BODY="$(http_get "http://127.0.0.1:${ADMIN_PORT}${_u}" | head -c 4000 || true)"
        if printf '%s' "$_BODY" | grep -qi '<html\|<!doctype'; then
            say "  页面可访问：http://127.0.0.1:${ADMIN_PORT}${_u}"
        else
            warn "  管理口 ${ADMIN_PORT} 的 ${_u} 未返回 HTML，请检查是否被占用或端口未监听。"
        fi
    done
else
    if [ "$SERVICE_STARTED" = 1 ]; then
        err "服务自检失败：约 20 秒内 $HEALTH_URL 未返回 {\"ok\":true}。"
        err "排查命令： journalctl -u $SERVICE_NAME -n 80 --no-pager"
        err "          tail -n 80 \"$DIR\"/*.log 2>/dev/null"
        err "常见原因：端口 $PORT / $ADMIN_PORT 被占用、Python 依赖缺失、config.json 非法。"
        exit 1
    fi
    warn "服务未启动（FMO_NO_SERVICE=1 或环境无 systemd），跳过存活判定。"
    warn "手动启动后可用以下命令自检： curl -fsS $HEALTH_URL"
fi

# ---------------------------------------------------------------- 汇总
echo ""
echo "======================================"
if [ "${FMO_NO_SERVICE:-0}" = "1" ]; then
    echo "  FMO 分系统 部署完成（未注册开机自启）"
else
    echo "  FMO 分系统 安装完成"
fi
echo "--------------------------------------"
echo "  安装目录 : $DIR"
echo "  公网 API : $PORT          （路由器只需映射此端口）"
echo "  FUS 门户 : http://<本机IP>:$ADMIN_PORT/admin        （内网访问，勿映射公网）"
echo "  SAS 系统 : http://<本机IP>:$ADMIN_PORT/admin/sas"
echo "  FAS 系统 : http://<本机IP>:$ADMIN_PORT/admin/fus"
echo "  互联桥接 : http://<本机IP>:$ADMIN_PORT/admin/bridge  （与其他 FUS 系统语音互传，无主、可自选）"
echo "  健康检查 : $HEALTH_URL"
echo "  配置文件 : $DIR/config.json"
if [ "$SERVICE_STARTED" = 1 ]; then
    echo "  查看日志 : journalctl -u $SERVICE_NAME -f"
    echo "  重启服务 : systemctl restart $SERVICE_NAME"
else
    echo "  启动命令 : cd \"$DIR\" && \"$PY\" -u \"$DIR/api_server.py\""
fi
echo "  升级方式 : 再次执行同一条安装命令即可（幂等，保留数据与配置）"
echo "  卸载命令 : curl -fsSL $BASE_URL/uninstall.sh | sudo bash"
echo "======================================"
exit 0
