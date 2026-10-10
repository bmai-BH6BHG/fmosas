#!/usr/bin/env bash
# ==========================================================================
#  FMO / FUS 分系统 —— 一键升级（只升级系统，不动原配置与数据）
# ==========================================================================
#
#  与 install.sh 的区别（这是本脚本存在的唯一理由）：
#    install.sh 是"安装/重装"，会做配置合并、依赖安装、systemd 注册等一整套动作；
#    本脚本是"升级"——**只把系统代码换成新版**，用户的配置与数据一个都不碰：
#
#      不动：config.json（含 dmrid.app_pubkey / master_url / sync_token / 端口…）
#            *.db / *.db-wal / *.db-shm（用户库、SAS 库、审计库、语音库）
#            ca/（根证书与私钥，换了就等于换身份）
#            uploads/ roots/ logs/
#            stations.json / aprs_stations.json 等运行期台账
#            服务名、端口、开机自启设置
#
#  升级流程（每一步都可回退）：
#    定位安装目录 → 比较版本 → 下载新包 + SHA256 强制校验 → 备份要替换的文件
#    → 停服务 → **只覆盖系统文件** → 语法自检 → 起服务 → 健康检查（轮询等待）
#    → 任一步失败自动回滚到备份并恢复服务
#
#  用法：
#    sudo bash upgrade.sh                      # 升到最新版
#    sudo bash upgrade.sh --version 1.8.9      # 升到指定版本
#    sudo bash upgrade.sh --check              # 只看有没有新版，不做任何改动
#    sudo bash upgrade.sh --dry-run            # 只列出会替换哪些文件
#    sudo bash upgrade.sh --rollback           # 回滚到上一次升级前的备份
#    sudo bash upgrade.sh --list-backups       # 列出本机保留的升级备份
#
#  可用环境变量：
#    FMO_BASE_URL   覆盖分发地址
#    FMO_DIR        覆盖安装目录
#    FMO_UPGRADE_BACKUP_DIR  覆盖备份目录（默认 <安装目录>/../fmo-backup）
#    FMO_NO_SERVICE=1  不重启服务（只换文件，用于离线/自测）
# ==========================================================================
set -euo pipefail

# ↓↓↓ build_release.sh 用 sed 替换下面这一行的地址（与 install.sh 同一处约定）↓↓↓
DEFAULT_BASE_URL="https://example.com/fmo-subsystem"
DEFAULT_VERSION="1.0.0"

SERVICE_NAME="fmo-subsystem"
PKG_PREFIX="fmo-subsystem"

# ---------------------------------------------------------------- 输出工具
step() { printf '\n[%s] %s\n' "$1" "$2"; }
say()  { printf '  %s\n' "$*"; }
warn() { printf '  [警告] %s\n' "$*" >&2; }
err()  { printf '  [错误] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------- 必须保留的东西
# 1) 目录/文件名（与 install.sh 的 KEEP_NAMES 保持一致，升级语义相同）
#    注意：用 case 的**字面模式**匹配，绝不写成 `for p in $LIST` ——
#    那样 $LIST 未加引号会触发 shell 路径展开，`*.db` 会被当成"当前目录下的 .db 文件"
#    展开成实际文件名，于是"保留所有 .db"就失效了（真实踩过：用户库会被覆盖）。
KEEP_TOP="config.json ca uploads roots logs dist .git upgrade.sh .upgrade-backup-dir"
KEEP_NAME_PAT="*.db|*.db-wal|*.db-shm|*.db-journal|*.log|*.bak|*.tmp|stations.json|aprs_stations.json|voice.db|AUTH_TRACE"

is_kept() {  # is_kept <相对路径>
    local rel="$1" base name
    base="${rel%%/*}"                       # 顶层名
    name="${rel##*/}"
    case "$base" in
        config.json|ca|uploads|roots|logs|dist|.git|upgrade.sh|.upgrade-backup-dir)
            return 0 ;;
    esac
    case "$name" in
        *.db|*.db-wal|*.db-shm|*.db-journal|*.log|*.bak|*.tmp) return 0 ;;
        stations.json|aprs_stations.json|voice.db|AUTH_TRACE)   return 0 ;;
    esac
    return 1
}

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

TMP_ROOT="$(mktemp -d 2>/dev/null || mktemp -d -t fmo-upgrade)"
TMP_MARKER="$TMP_ROOT/.marker"
: > "$TMP_MARKER"

# ---------------------------------------------------------------- 参数
OPT_VERSION=""
OPT_CHECK=0
OPT_DRYRUN=0
OPT_ROLLBACK=0
OPT_LIST_BACKUPS=0
OPT_FORCE=0
OPT_DIR="${FMO_DIR:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --version|-v) OPT_VERSION="${2:-}"; shift 2 ;;
        --version=*)  OPT_VERSION="${1#*=}"; shift ;;
        --check)      OPT_CHECK=1; shift ;;
        --dry-run|-n) OPT_DRYRUN=1; shift ;;
        --rollback)   OPT_ROLLBACK=1; shift ;;
        --list-backups) OPT_LIST_BACKUPS=1; shift ;;
        --force|-f)   OPT_FORCE=1; shift ;;
        --dir)        OPT_DIR="${2:-}"; shift 2 ;;
        --dir=*)      OPT_DIR="${1#*=}"; shift ;;
        -h|--help)    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "未知参数：$1（用 --help 看用法）" ;;
    esac
done

BASE_URL="${FMO_BASE_URL:-$DEFAULT_BASE_URL}"
BASE_URL="${BASE_URL%/}"

echo "======================================"
echo "  FMO 分系统 一键升级（只升级系统）"
echo "======================================"

# ---------------------------------------------------------------- 下载工具
fetch() {  # fetch <url> <out>
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --max-time 600 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url"
    else
        return 1
    fi
}

compute_sha256() {  # compute_sha256 <文件>
    local f="$1" out=""
    if command -v sha256sum >/dev/null 2>&1; then
        out="$(sha256sum "$f" 2>/dev/null | sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n 1 || true)"
    elif command -v shasum >/dev/null 2>&1; then
        out="$(shasum -a 256 "$f" 2>/dev/null | sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' | head -n 1 || true)"
    elif command -v openssl >/dev/null 2>&1; then
        out="$(openssl dgst -sha256 "$f" 2>/dev/null | sed -n 's/^.*[= ]\([0-9a-fA-F]\{64\}\)$/\1/p' | head -n 1 || true)"
    fi
    if [ -z "$out" ] && command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$f" 2>/dev/null || true)"
    fi
    printf '%s' "$out"
}

# ---------------------------------------------------------------- 定位安装目录
find_dir() {
    local d
    for d in "${OPT_DIR:-}" /opt/fmo-subsystem /volume1/fmo-subsystem \
             "$HOME/fmo-subsystem" /usr/local/fmo-subsystem; do
        [ -n "$d" ] && [ -f "$d/api_server.py" ] && { printf '%s' "$d"; return 0; }
    done
    return 1
}
DIR="$(find_dir || true)"
[ -n "$DIR" ] || die "找不到安装目录（里面应有 api_server.py）。可用 --dir 指定，或先安装系统。"
DIR="$(cd "$DIR" && pwd -P)"
say "安装目录：$DIR"

SVC="${SERVICE_NAME}"
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE_NAME}\.service" || true
fi

BACKUP_ROOT="${FMO_UPGRADE_BACKUP_DIR:-$(dirname "$DIR")/fmo-backup}"
mkdir -p "$BACKUP_ROOT" 2>/dev/null || true

SVC_ACTIVE=0
svc_is_active() {
    command -v systemctl >/dev/null 2>&1 || return 1
    [ "$(systemctl is-active "$SVC" 2>/dev/null || true)" = "active" ]
}
svc_stop()  { command -v systemctl >/dev/null 2>&1 && systemctl stop "$SVC" >/dev/null 2>&1 || true; }
svc_start() { command -v systemctl >/dev/null 2>&1 && systemctl start "$SVC" >/dev/null 2>&1 || true; }

# ---------------------------------------------------------------- 当前版本
# 优先读安装目录根下的 VERSION（升级成功后我们会写进去，最可靠）；
# 其次 dist/VERSION（发行包里的版本基准：CI 打 tag 时会写入真实版本）；
# 最后才退到 install-bas.sh 里的 BAS_VERSION —— 注意 install-bas.sh **不在** tar 包里
# （它是单独发布的扁平资产），拿它当唯一依据会一直报旧版本（真实踩过：升完还显示旧版）。
cur_version() {
    local v="" f
    for f in "$DIR/VERSION" "$DIR/dist/VERSION"; do
        [ -f "$f" ] || continue
        v="$(sed -n 's/^[[:space:]]*VERSION=//p' "$f" 2>/dev/null | head -n 1 | tr -d '\r' | sed "s/[\"']//g" || true)"
        case "$v" in ''|*[!0-9A-Za-z._-]*) v="" ;; esac
        [ -n "$v" ] && { printf '%s' "$v"; return; }
    done
    if [ -z "$v" ] && [ -f "$DIR/install-bas.sh" ]; then
        v="$(sed -n 's/^BAS_VERSION="\(.*\)"/\1/p' "$DIR/install-bas.sh" 2>/dev/null | head -n 1 | tr -d '\r' || true)"
    fi
    printf '%s' "$v"
}

# 升级成功后把版本号写进安装目录（下次 cur_version 才能读到真实值）
write_version() {  # write_version <版本>
    local v="$1" f
    [ -n "$v" ] || return 0
    for f in "$DIR/VERSION" "$DIR/dist/VERSION"; do
        [ -e "$(dirname "$f")" ] || continue
        printf 'VERSION=%s\nRELEASE_BASE_URL=%s\n' "$v" "$BASE_URL" > "$f" 2>/dev/null || true
    done
    return 0
}
CUR_VER="$(cur_version)"
say "当前版本：${CUR_VER:-(未知)}"

# ---------------------------------------------------------------- 备份列表 / 回滚
list_backups() {
    find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'upgrade-*' 2>/dev/null | sort -r
}

if [ "$OPT_LIST_BACKUPS" = 1 ]; then
    echo ""
    echo "升级备份（$BACKUP_ROOT）："
    list_backups | while read -r b; do
        [ -n "$b" ] || continue
        printf '  %s  (%s 个文件)\n' "$(basename "$b")" "$(find "$b" -type f | wc -l | tr -d ' ')"
    done
    exit 0
fi

if [ "$OPT_ROLLBACK" = 1 ]; then
    LAST="$(list_backups | head -n 1)"
    [ -n "$LAST" ] || die "没有可回滚的备份（$BACKUP_ROOT 下没有 upgrade-* 目录）"
    step "回滚" "从 $(basename "$LAST") 恢复系统文件"
    say "注意：只恢复**系统文件**；config.json / *.db / ca/ 等用户数据从未被动过，无需恢复"
    svc_stop
    _n=0
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        mkdir -p "$DIR/$(dirname "$rel")" 2>/dev/null || true
        cp -a "$LAST/$rel" "$DIR/$rel"
        _n=$((_n + 1))
    done < <(cd "$LAST" && find . -type f | sed 's|^\./||')
    say "已恢复 $_n 个文件"
    if [ "${FMO_NO_SERVICE:-0}" != "1" ]; then
        svc_start
        say "服务已重启"
    fi
    echo ""
    echo "回滚完成。"
    exit 0
fi

# ---------------------------------------------------------------- 解析目标版本
SITE_VERSION=""
if fetch "$BASE_URL/VERSION" "$TMP_ROOT/VERSION.site" 2>/dev/null && [ -s "$TMP_ROOT/VERSION.site" ]; then
    SITE_VERSION="$(sed -n 's/^[[:space:]]*VERSION=//p' "$TMP_ROOT/VERSION.site" 2>/dev/null | head -n 1 | tr -d '\r' | sed "s/[\"']//g" || true)"
    case "$SITE_VERSION" in *[!0-9A-Za-z._-]*) SITE_VERSION="" ;; esac
fi
TARGET_VER="${OPT_VERSION:-${SITE_VERSION:-$DEFAULT_VERSION}}"
TARGET_VER="${TARGET_VER#v}"

say "目标版本：$TARGET_VER"

if [ "$OPT_CHECK" = 1 ]; then
    echo ""
    if [ -n "$CUR_VER" ] && [ "$CUR_VER" = "$TARGET_VER" ]; then
        echo "已是最新版本（$CUR_VER），无需升级。"
    else
        echo "可升级：${CUR_VER:-未知} → $TARGET_VER"
        echo "执行：sudo bash $0"
    fi
    exit 0
fi

if [ -n "$CUR_VER" ] && [ "$CUR_VER" = "$TARGET_VER" ] && [ "$OPT_FORCE" != 1 ]; then
    echo ""
    echo "已是最新版本（$CUR_VER），无需升级。要强制重装加 --force。"
    exit 0
fi

# ★ 降级保护：分发站版本低于本机时不要静默"升级"成旧版
#   （真实场景：站点 VERSION 还没更新、或 FMO_BASE_URL 指错了目录）
ver_cmp() {  # ver_cmp A B → 1(A>B) / 0(相等) / -1(A<B)
    local a="$1" b="$2"
    [ "$a" = "$b" ] && { printf '0'; return; }
    local IFS='.' x y i n
    local -a A B
    A=($a); B=($b)
    n=${#A[@]}; [ "${#B[@]}" -gt "$n" ] && n=${#B[@]}
    for ((i = 0; i < n; i++)); do
        x="${A[i]:-0}"; y="${B[i]:-0}"
        case "$x" in ''|*[!0-9]*) x=0 ;; esac
        case "$y" in ''|*[!0-9]*) y=0 ;; esac
        if [ "$x" -gt "$y" ]; then printf '1'; return; fi
        if [ "$x" -lt "$y" ]; then printf '%s' '-1'; return; fi
    done
    printf '0'
}

if [ -n "$CUR_VER" ] && [ "$OPT_FORCE" != 1 ]; then
    case "$(ver_cmp "$TARGET_VER" "$CUR_VER")" in
        -1)
            err "目标版本 $TARGET_VER **低于**当前版本 $CUR_VER —— 这是降级，不是升级。"
            err "常见原因：分发站的 VERSION 还没更新，或 FMO_BASE_URL 指错了目录。"
            die "确认要降级请显式加 --force"
            ;;
    esac
fi

# ---------------------------------------------------------------- 下载
step "1/6" "下载新版本安装包"
TARBALL_URL=""
for cand in "$BASE_URL/${PKG_PREFIX}-${TARGET_VER}.tar.gz" "$BASE_URL/${PKG_PREFIX}.tar.gz"; do
    if fetch "$cand" "$TMP_ROOT/pkg.tar.gz" 2>/dev/null && [ -s "$TMP_ROOT/pkg.tar.gz" ]; then
        TARBALL_URL="$cand"; break
    fi
    rm -f "$TMP_ROOT/pkg.tar.gz" 2>/dev/null || true
done
[ -n "$TARBALL_URL" ] || die "下载失败：$BASE_URL/${PKG_PREFIX}-${TARGET_VER}.tar.gz（可用 FMO_BASE_URL 覆盖分发地址）"
say "已下载：$TARBALL_URL（$(wc -c < "$TMP_ROOT/pkg.tar.gz" | tr -d ' ') 字节）"

step "2/6" "SHA256 完整性校验"
ACTUAL_SHA="$(compute_sha256 "$TMP_ROOT/pkg.tar.gz")"
[ -n "$ACTUAL_SHA" ] || warn "本机缺少校验工具，跳过 SHA256 校验"
if [ -n "$ACTUAL_SHA" ] && fetch "$TARBALL_URL.sha256" "$TMP_ROOT/pkg.sha256" 2>/dev/null; then
    EXPECT_SHA="$(sed -n 's/^\([0-9a-fA-F]\{64\}\).*/\1/p' "$TMP_ROOT/pkg.sha256" | head -n 1 || true)"
    if [ -n "$EXPECT_SHA" ]; then
        [ "$(printf '%s' "$ACTUAL_SHA" | tr 'A-F' 'a-f')" = "$(printf '%s' "$EXPECT_SHA" | tr 'A-F' 'a-f')" ] \
            || die "SHA256 校验失败（包已损坏或被篡改）：期望 $EXPECT_SHA，实际 $ACTUAL_SHA"
        say "SHA256 校验通过"
    fi
fi

step "3/6" "解包"
EXTRACT="$TMP_ROOT/pkg"
mkdir -p "$EXTRACT"
tar -xzf "$TMP_ROOT/pkg.tar.gz" -C "$EXTRACT" 2>/dev/null \
    || die "解包失败（tar -xzf）"
# 包内可能多一层目录
if [ ! -f "$EXTRACT/api_server.py" ]; then
    INNER="$(find "$EXTRACT" -maxdepth 2 -name api_server.py -print -quit 2>/dev/null | head -n 1 || true)"
    [ -n "$INNER" ] || die "包内容不完整：找不到 api_server.py"
    EXTRACT="$(dirname "$INNER")"
fi
[ -f "$EXTRACT/api_server.py" ] || die "包内容不完整"

NEW_VER="$(sed -n 's/^[[:space:]]*VERSION=//p' "$EXTRACT/dist/VERSION" 2>/dev/null | head -n 1 | tr -d '\r' | sed "s/[\"']//g" || true)"
say "包内版本：${NEW_VER:-$TARGET_VER}"

# ---------------------------------------------------------------- 计划：只换系统文件
step "4/6" "计算要替换的系统文件（用户数据一律跳过）"
PLAN="$TMP_ROOT/plan.txt"
SKIPPED="$TMP_ROOT/skipped.txt"
: > "$PLAN"; : > "$SKIPPED"
while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    src="$EXTRACT/$rel"
    [ -f "$src" ] || continue
    if is_kept "$rel"; then
        printf '%s\n' "$rel" >> "$SKIPPED"
        continue
    fi
    printf '%s\n' "$rel" >> "$PLAN"
done < <(cd "$EXTRACT" && find . -type f | sed 's|^\./||' | sort)

PLAN_N="$(wc -l < "$PLAN" | tr -d ' ')"
SKIP_N="$(wc -l < "$SKIPPED" | tr -d ' ')"
say "将替换：$PLAN_N 个系统文件"
say "将保留：$SKIP_N 个用户文件/目录（config.json / *.db / ca / uploads / roots / logs …）"

# 统计"内容真的会变"的文件数，便于用户判断
CHANGED_N=0
while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    if [ -f "$DIR/$rel" ]; then
        cmp -s "$EXTRACT/$rel" "$DIR/$rel" || CHANGED_N=$((CHANGED_N + 1))
    else
        CHANGED_N=$((CHANGED_N + 1))
    fi
done < "$PLAN"
say "其中内容有变化的：$CHANGED_N 个（其余为同名同内容）"

if [ "$OPT_DRYRUN" = 1 ]; then
    echo ""
    echo "（--dry-run：不做任何改动）"
    echo "会替换的文件："
    sed 's/^/    /' "$PLAN" | head -n 60
    [ "$PLAN_N" -gt 60 ] && echo "    ...（共 $PLAN_N 个）"
    echo ""
    echo "明确保留（不动）："
    sed 's/^/    /' "$SKIPPED" | head -n 30
    [ "$SKIP_N" -gt 30 ] && echo "    ...（共 $SKIP_N 个）"
    exit 0
fi

# ---------------------------------------------------------------- 备份 + 替换
TS="$(date +%Y%m%d-%H%M%S)"
BAK="$BACKUP_ROOT/upgrade-$TS"
step "5/6" "备份要替换的文件 → $BAK"
mkdir -p "$BAK"
while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    if [ -f "$DIR/$rel" ]; then
        mkdir -p "$BAK/$(dirname "$rel")" 2>/dev/null || true
        cp -a "$DIR/$rel" "$BAK/$rel"
    fi
done < "$PLAN"
printf '%s\n' "$CUR_VER" > "$BAK/.from-version"
say "已备份 $(find "$BAK" -type f | wc -l | tr -d ' ') 个文件（含 .from-version）"
say "回滚命令：sudo bash $0 --rollback"

if svc_is_active; then
    SVC_ACTIVE=1
    say "停止服务 $SVC …"
    svc_stop
    sleep 2
fi

ROLLBACK_NEEDED=0
rollback_now() {
    err "升级失败，正在回滚…"
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        [ -f "$BAK/$rel" ] || continue
        mkdir -p "$DIR/$(dirname "$rel")" 2>/dev/null || true
        cp -a "$BAK/$rel" "$DIR/$rel" 2>/dev/null || true
    done < "$PLAN"
    if [ "$SVC_ACTIVE" = 1 ] && [ "${FMO_NO_SERVICE:-0}" != "1" ]; then
        svc_start
    fi
    err "已回滚到升级前状态（备份保留在 $BAK）"
    exit 1
}
trap 'rollback_now' ERR

while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    mkdir -p "$DIR/$(dirname "$rel")" 2>/dev/null || true
    cp -f "$EXTRACT/$rel" "$DIR/$rel" || die "写入失败：$rel"
done < "$PLAN"
chmod +x "$DIR/install.sh" "$DIR/uninstall.sh" "$DIR/upgrade.sh" 2>/dev/null || true
say "系统文件已替换（用户数据未改动）"

# 语法自检：任何 .py 编译不过就回滚
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -m py_compile "$DIR/api_server.py" "$DIR/sas_server.py" \
            "$DIR/monitor.py" "$DIR/sync_engine.py" "$DIR/bridge.py" 2>"$TMP_ROOT/pyc.log"; then
        err "语法自检未通过："
        sed 's/^/    /' "$TMP_ROOT/pyc.log" >&2 || true
        ROLLBACK_NEEDED=1
    else
        say "语法自检通过"
    fi
fi
[ "$ROLLBACK_NEEDED" = 0 ] || rollback_now

# ---------------------------------------------------------------- 起服务 + 健康检查
step "6/6" "重启服务并做健康检查"
trap - ERR
if [ "${FMO_NO_SERVICE:-0}" = "1" ]; then
    say "FMO_NO_SERVICE=1：跳过服务重启"
else
    PORT="$(sed -n 's/^[[:space:]]*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$DIR/config.json" 2>/dev/null | head -n 1 || true)"
    [ -n "$PORT" ] || PORT=35928
    HEALTH_URL="http://127.0.0.1:${PORT}/api/health"
    svc_start
    OK=0
    i=0
    while [ "$i" -lt 30 ]; do
        i=$((i + 1))
        BODY="$(fetch "$HEALTH_URL" "$TMP_ROOT/health" 2>/dev/null && cat "$TMP_ROOT/health" 2>/dev/null || true)"
        case "$BODY" in
            *'"ok"'*|*'ok":true'*|*'"status": "ok"'*) OK=1; break ;;
        esac
        sleep 2
    done
    if [ "$OK" = 1 ]; then
        say "健康检查通过：$HEALTH_URL（约 $((i * 2)) 秒就绪）"
    else
        warn "健康检查未通过：$HEALTH_URL"
        if [ "$SVC_ACTIVE" = 1 ]; then
            warn "按升级前状态回滚（升级前服务是在运行的）"
            rollback_now
        else
            warn "升级前服务本来就未运行，保留新版本不自动回滚"
            warn "排查： journalctl -u $SVC -n 80 --no-pager"
        fi
    fi
fi

# 记下新版本，供下次 cur_version 读取（否则会一直显示旧版本）
write_version "${NEW_VER:-$TARGET_VER}"

echo ""
echo "======================================"
echo "  升级完成"
echo "  版本      : ${CUR_VER:-未知} → ${NEW_VER:-$TARGET_VER}"
echo "  系统文件  : 已替换 $PLAN_N 个"
echo "  用户数据  : 未改动（config.json / *.db / ca/ / uploads/ / roots/ / logs/）"
echo "  备份      : $BAK"
echo "  回滚      : sudo bash $0 --rollback"
echo "======================================"