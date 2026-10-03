#!/usr/bin/env bash
# ============================================================================
#  FMO 分系统 发布打包脚本
#
#  用法:
#    bash build_release.sh [RELEASE_BASE_URL]
#
#    RELEASE_BASE_URL 也可来自环境变量，或 dist/VERSION 的 RELEASE_BASE_URL=；
#    优先级：命令行参数 > 环境变量 > dist/VERSION。留空则保留 install.sh 内的
#    占位默认地址（需人工替换），并在输出中醒目提示。
#
#  产物（dist/）:
#    fmo-subsystem-<VERSION>.tar.gz          发布包（解包后源码平铺在根目录）
#    fmo-subsystem-<VERSION>.tar.gz.sha256   <64位hex>  <tarball 文件名>
#    checksums.txt                           sha256sum 兼容格式（tarball）
#    MANIFEST.txt                            包内每个文件的大小 + SHA256
#
#  排除（运行时/敏感产物，绝不进包）：*.db、*.db-journal/-wal/-shm、ca/（含
#  ca_private.json 私钥）、uploads/ 内文件（保留 .gitkeep）、__pycache__/、*.pyc、
#  logs/、*.log、.git/、dist/、*.bak、*.tmp、roots/（信任链运行时数据）、旧产物。
#
#  打包后自检：tar tzf 列表命中敏感名（*_private*、*.db、ca_private 等）→ 报错
#  并非 0 退出，同时删除已生成的包；并复核必需文件存在、解包后为平铺结构。
# ============================================================================
set -euo pipefail

die()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN ] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------ tar/sha 回退实现 -----------------------------
PY=""
for CAND in python3 python; do
    if have "$CAND" && "$CAND" -c 'import sys' >/dev/null 2>&1; then
        PY="$CAND"
        break
    fi
done

sha256_of() {
    local f="$1"
    if have sha256sum; then
        sha256sum "$f" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$f" | awk '{print $1}'
    elif [ -n "$PY" ]; then
        "$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$f"
    else
        return 1
    fi
}

file_size() { wc -c < "$1" | tr -d '[:space:]'; }

fmo_tar_create() {
    local out="$1" stage="$2" list="$3"
    rm -f -- "$out"
    if have tar && tar -czf "$out" -C "$stage" -T "$list" 2>/dev/null && [ -s "$out" ]; then
        return 0
    fi
    if [ -n "$PY" ]; then
        "$PY" - "$out" "$stage" "$list" <<'PYEOF'
import os, sys, tarfile
out, stage, listf = sys.argv[1], sys.argv[2], sys.argv[3]
names = []
with open(listf, "r", encoding="utf-8") as fh:
    for line in fh:
        n = line.rstrip("\n")
        if n:
            names.append(n)
if not names:
    raise SystemExit("file list is empty")
with tarfile.open(out, "w:gz") as tf:
    for n in names:
        tf.add(os.path.join(stage, n), arcname=n)
PYEOF
        return $?
    fi
    return 1
}

fmo_tar_list() {
    local t="$1"
    if have tar && tar tzf "$t" >/dev/null 2>&1; then
        tar tzf "$t"
        return 0
    fi
    if [ -n "$PY" ]; then
        "$PY" - "$t" <<'PYEOF'
import sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as tf:
    for m in tf.getmembers():
        print(m.name)
PYEOF
        return $?
    fi
    return 1
}

fmo_tar_extract() {
    local t="$1" dest="$2"
    mkdir -p "$dest"
    if have tar && tar -xzf "$t" -C "$dest" 2>/dev/null; then
        return 0
    fi
    if [ -n "$PY" ]; then
        "$PY" - "$t" "$dest" <<'PYEOF'
import sys, tarfile
with tarfile.open(sys.argv[1], "r:gz") as tf:
    tf.extractall(sys.argv[2])
PYEOF
        return $?
    fi
    return 1
}

# ------------------------------ 定位仓库根目录 -------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPO="$SCRIPT_DIR"
cd "$REPO"
DIST="$REPO/dist"

echo "======================================"
echo "  FMO 分系统 发布打包"
echo "  仓库根目录: $REPO"
echo "======================================"

[ -f "$DIST/VERSION" ] || die "缺少版本文件: $DIST/VERSION"
[ -f "$REPO/api_server.py" ] || die "仓库根目录缺少 api_server.py，$REPO 似乎不是发布仓库"
if ! have tar && [ -z "$PY" ]; then
    die "需要 tar 或 python3/python 之一（打包与自检）"
fi

# ------------------------------ [1/8] 版本与地址 -----------------------------
VERSION="$(awk '
    /^[[:space:]]*VERSION[[:space:]]*=/ {
        sub(/^[^=]*=[[:space:]]*/, ""); gsub(/\r/, ""); gsub(/[[:space:]]+$/, "");
        print; exit
    }' "$DIST/VERSION")"
FILE_BASE_URL="$(awk '
    /^[[:space:]]*RELEASE_BASE_URL[[:space:]]*=/ {
        sub(/^[^=]*=[[:space:]]*/, ""); gsub(/\r/, ""); gsub(/[[:space:]]+$/, "");
        print; exit
    }' "$DIST/VERSION")"

BASE_URL="${1:-${RELEASE_BASE_URL:-$FILE_BASE_URL}}"
VERSION="${VERSION%\"}"; VERSION="${VERSION#\"}"
BASE_URL="${BASE_URL%\"}"; BASE_URL="${BASE_URL#\"}"
BASE_URL="${BASE_URL%/}"

case "$VERSION" in
    "") die "无法从 dist/VERSION 读取 VERSION=，请检查该文件" ;;
    *[!A-Za-z0-9._-]*) die "VERSION 含非法字符（只允许字母数字._-）: '$VERSION'" ;;
esac

echo "[1/8] 版本: $VERSION"
if [ -n "$BASE_URL" ]; then
    echo "      分发根地址: $BASE_URL"
else
    echo "      分发根地址: <未设置> → 保留 install.sh 内的占位 DEFAULT_BASE_URL（部署前必须替换）"
fi

# ------------------------------ [2/8] 预检查 ---------------------------------
echo "[2/8] 预检查（必需文件 + shell 语法）..."
for F in api_server.py sas_server.py sync_engine.py monitor.py cert_gen.py \
         gen_app_key.py diagnose.py dmrid_bind_demo.py dmrid_http_test.py \
         config.default.json config.json requirements.txt start.sh \
         fmo-subsystem.service install.sh uninstall.sh uploads/.gitkeep \
         CONTRACT.md dist/VERSION; do
    [ -e "$REPO/$F" ] || die "缺少必需文件: $F（契约第 5 节必须包含）"
done
[ -e "$REPO/admin/index.html" ] || die "缺少必需文件: admin/index.html"
for S in install.sh uninstall.sh build_release.sh; do
    if ! bash -n "$REPO/$S"; then
        die "$S 语法检查未通过（bash -n）"
    fi
done
echo "      必需文件齐全，bash -n 通过"

# ------------------------------ [3/8] 清理旧产物 ----------------------------
echo "[3/8] 清理 dist/ 旧构建产物 ..."
OLD=0
for P in "$DIST"/fmo-subsystem-*.tar.gz "$DIST"/fmo-subsystem-*.tar.gz.sha256 \
         "$DIST/fmo-subsystem.tar.gz" "$DIST/fmo-subsystem.tar.gz.sha256" \
         "$DIST/checksums.txt" "$DIST/MANIFEST.txt"; do
    if [ -e "$P" ]; then
        rm -f -- "$P"
        OLD=$((OLD + 1))
    fi
done
if [ -d "$DIST/release-upload" ]; then
    rm -rf -- "$DIST/release-upload"
    OLD=$((OLD + 1))
fi
echo "      已清理旧产物: $OLD 个（dist/VERSION 与源码不受影响）"

# ------------------------------ [4/8] 准备纯净 staging ----------------------
echo "[4/8] 准备打包内容（排除敏感/运行时文件）..."
WORK="$(mktemp -d)"
trap 'if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then rm -rf -- "$WORK"; fi' EXIT
STAGE="$WORK/stage"
mkdir -p "$STAGE"

MISSING=""
copy_path() {
    local rel="$1" req="$2"
    if [ -e "$REPO/$rel" ]; then
        mkdir -p "$STAGE/$(dirname "$rel")"
        cp -a "$REPO/$rel" "$STAGE/$rel"
    else
        MISSING="$MISSING $rel"
    fi
    return 0
}

# 代码（契约必须包含）
for F in api_server.py sas_server.py sync_engine.py monitor.py cert_gen.py \
         gen_app_key.py diagnose.py dmrid_bind_demo.py dmrid_http_test.py; do
    copy_path "$F" 1
done
# BAS：内嵌审计子系统（Python 重写 FAS，无 .NET 依赖）
for F in bas_fmo_parser.py bas_emqx.py bas_identity.py bas_audit_db.py \
         bas_audit.py bas_http.py bas_migrate.py bas_emqx_auth.py bas_diagnose.py; do
    copy_path "$F" 1
done
copy_path tests 0
copy_path admin 1
for F in config.default.json config.json requirements.txt start.sh \
         fmo-subsystem.service install.sh uninstall.sh uploads/.gitkeep; do
    copy_path "$F" 1
done
# 文档（缺失只告警，不阻断打包；Lead 负责增补）
copy_path README.txt 0
copy_path API.md 0
copy_path INSTALL.md 0
copy_path 部署教程.md 0
copy_path CONTRACT.md 0
copy_path APP-APPKEY-BINDING.md 0
# 注意：dist/VERSION 必须在下面的 "rm -rf ... $STAGE/dist" 剪枝之后放入 staging，
#       否则会被一并删除（发布包需要它，客户端安装脚本会优先读取站根 VERSION）。
for F in "$REPO"/dmrid_*.md; do
    if [ -e "$F" ]; then
        copy_path "$(basename "$F")" 0
    fi
done

# 兜底剪枝：即使上游目录混入运行时产物也绝不进包
find "$STAGE" -type d -name '__pycache__' -prune -exec rm -rf -- {} + 2>/dev/null || true
find "$STAGE" -type f -name '*.pyc' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*.db' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*.db-*' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*.log' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*.bak' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*.tmp' -delete 2>/dev/null || true
find "$STAGE" -type f -name '*_private*' -delete 2>/dev/null || true
if [ -d "$STAGE/uploads" ]; then
    find "$STAGE/uploads" -type f ! -name '.gitkeep' -delete 2>/dev/null || true
    find "$STAGE/uploads" -mindepth 1 -type d -exec rm -rf -- {} + 2>/dev/null || true
fi
rm -rf -- "$STAGE/ca" "$STAGE/roots" "$STAGE/logs" "$STAGE/dist" "$STAGE/.git" "$STAGE/.github"
find "$STAGE" -mindepth 1 -type d -empty -delete 2>/dev/null || true

# 剪枝之后再放入版本文件（避免被上面的 dist/ 剪枝误删）
if [ -e "$REPO/dist/VERSION" ]; then
    mkdir -p "$STAGE/dist"
    cp -a "$REPO/dist/VERSION" "$STAGE/dist/VERSION"
else
    MISSING="$MISSING dist/VERSION"
fi

# 硬断言：凡是 copy_path 失败/被剪枝的必需文件都必须让打包失败，避免静默出残缺包
if [ -n "$MISSING" ]; then
    die "以下文件应进包但未成功 staging，已中止打包：$MISSING"
fi
[ -f "$STAGE/dist/VERSION" ] || die "staging 缺少 dist/VERSION（包内 install.sh 版本兜底依赖它）"

LEAK="$(find "$STAGE" -type f \( -name '*.db' -o -name '*.db-*' -o -name '*_private*' \
        -o -name '*.pyc' -o -name '*.log' -o -name '*.bak' -o -name '*.tmp' \) -print 2>/dev/null || true)"
if [ -n "$LEAK" ]; then
    die "staging 中仍存在敏感/运行时文件，已中止打包：$LEAK"
fi

find "$STAGE" -type f | sed "s|^$STAGE/||" | LC_ALL=C sort > "$WORK/files.txt"
FILECOUNT="$(wc -l < "$WORK/files.txt" | tr -d '[:space:]')"
if [ "$FILECOUNT" -eq 0 ]; then
    die "staging 为空，打包中止"
fi
echo "      待打包文件: $FILECOUNT 个"

# ------------------------------ [5/8] 注入分发地址（仅改包内 install.sh）-----
echo "[5/8] 注入 DEFAULT_BASE_URL（只替换 install.sh 的该行，不动仓库文件）..."
INJECTED="no"
if [ -n "$BASE_URL" ]; then
    if grep -qE '^[[:space:]]*DEFAULT_BASE_URL=' "$STAGE/install.sh"; then
        cp -a "$STAGE/install.sh" "$WORK/install.sh.before"
        ESC="$(printf '%s' "$BASE_URL" | sed 's/[&|\\]/\\&/g')"
        sed "s|^[[:space:]]*DEFAULT_BASE_URL=.*|DEFAULT_BASE_URL=\"$ESC\"|" \
            "$WORK/install.sh.before" > "$WORK/install.sh.after"
        cat "$WORK/install.sh.after" > "$STAGE/install.sh"
        BEFORE_LINES="$(wc -l < "$WORK/install.sh.before" | tr -d '[:space:]')"
        AFTER_LINES="$(wc -l < "$STAGE/install.sh" | tr -d '[:space:]')"
        if grep -qF "DEFAULT_BASE_URL=\"$BASE_URL\"" "$STAGE/install.sh" && \
           [ "$BEFORE_LINES" = "$AFTER_LINES" ]; then
            INJECTED="yes"
            echo "      已注入: DEFAULT_BASE_URL=\"$BASE_URL\"（行数未变: $AFTER_LINES 行）"
        else
            warn "注入后校验未通过（行数前 $BEFORE_LINES / 后 $AFTER_LINES），请人工检查包内 install.sh"
            INJECTED="unverified"
        fi
    else
        warn "包内 install.sh 未找到 DEFAULT_BASE_URL=\"...\" 占位行，已跳过地址注入；"
        warn "分发包将沿用 install.sh 内既有地址，可能导致客户端下载不到发布包。"
        INJECTED="skipped"
    fi
else
    echo "      未提供 RELEASE_BASE_URL：保留 install.sh 内的占位地址"
fi

# ---- 版本号同步（仅改包内 install.sh 的 DEFAULT_VERSION，避免与 dist/VERSION 漂移）----
INJECTED_VERSION="no"
if grep -qE '^[[:space:]]*DEFAULT_VERSION=' "$STAGE/install.sh"; then
    PKG_VERSION="$(sed -n 's/^[[:space:]]*DEFAULT_VERSION=[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' \
        "$STAGE/install.sh" | head -n 1)"
    if [ "$PKG_VERSION" = "$VERSION" ]; then
        echo "      DEFAULT_VERSION 已与 dist/VERSION 一致（$VERSION）"
        INJECTED_VERSION="same"
    else
        cp -a "$STAGE/install.sh" "$WORK/install.sh.beforever"
        sed "s|^[[:space:]]*DEFAULT_VERSION=.*|DEFAULT_VERSION=\"$VERSION\"|" \
            "$WORK/install.sh.beforever" > "$WORK/install.sh.afterver"
        cat "$WORK/install.sh.afterver" > "$STAGE/install.sh"
        BVER_LINES="$(wc -l < "$WORK/install.sh.beforever" | tr -d '[:space:]')"
        AVER_LINES="$(wc -l < "$STAGE/install.sh" | tr -d '[:space:]')"
        if grep -qF "DEFAULT_VERSION=\"$VERSION\"" "$STAGE/install.sh" && \
           [ "$BVER_LINES" = "$AVER_LINES" ]; then
            echo "      DEFAULT_VERSION 已同步为 dist/VERSION 的版本: $PKG_VERSION -> $VERSION"
            INJECTED_VERSION="yes"
        else
            warn "DEFAULT_VERSION 注入后校验未通过（行数前 $BVER_LINES / 后 $AVER_LINES），请人工检查"
            INJECTED_VERSION="unverified"
        fi
    fi
else
    warn "包内 install.sh 未找到 DEFAULT_VERSION=\"...\" 行，无法同步版本号；"
    warn "分发站根目录建议同时上传 VERSION 文件，客户端会优先读取它。"
fi

# ------------------------------ [6/8] 打包 -----------------------------------
TARNAME="fmo-subsystem-${VERSION}.tar.gz"
OUT="$DIST/$TARNAME"
mkdir -p "$DIST"
echo "[6/8] 打包: dist/$TARNAME"
if ! fmo_tar_create "$OUT" "$STAGE" "$WORK/files.txt"; then
    die "打包失败（tar 与 python 回退均不可用）"
fi
[ -s "$OUT" ] || die "打包失败: $OUT 为空"
TARBYTES="$(file_size "$OUT")"

# 同时产出"无版本号包"：安装脚本在版本包取不到时会回退到 ${PKG}.tar.gz，
# GitHub/Gitee Release 的资产是平铺的（没有 latest/ 子目录），因此必须同级提供这一份。
OUT_FLAT="$DIST/fmo-subsystem.tar.gz"
cp -a "$OUT" "$OUT_FLAT"
[ -s "$OUT_FLAT" ] || die "生成无版本号包失败: $OUT_FLAT"

# ------------------------------ [7/8] 自检 -----------------------------------
echo "[7/8] 打包后自检（tar tzf 敏感名 + 必需文件 + 平铺结构）..."
if ! fmo_tar_list "$OUT" > "$WORK/listing.txt"; then
    rm -f -- "$OUT"
    die "无法读取刚生成的 tarball，已删除"
fi
TOTAL="$(wc -l < "$WORK/listing.txt" | tr -d '[:space:]')"

# dist/ 目录本身不进包，但 dist/VERSION 是版本基准、必须进包，故从敏感规则中排除该路径
SENSITIVE_RE='(^|/)ca$|(^|/)ca/|ca_private|_private|\.db$|\.db-|__pycache__|\.pyc$|(^|/)logs?/|\.log$|(^|/)roots/|(^|/)\.git/|\.bak$|\.tmp$'
BAD="$(grep -E "$SENSITIVE_RE" "$WORK/listing.txt" || true)"
BAD_DIST="$(grep -E '^dist/' "$WORK/listing.txt" | grep -v -x 'dist/VERSION' || true)"
BAD="$(printf '%s\n%s' "$BAD" "$BAD_DIST" | grep -v '^$' || true)"
UPLOADS_BAD="$(grep -E '^uploads/' "$WORK/listing.txt" | grep -v -x 'uploads/\.gitkeep' || true)"
PREFIXED="$(grep -E '^fmo-subsystem/' "$WORK/listing.txt" || true)"

if [ -n "$BAD" ] || [ -n "$UPLOADS_BAD" ] || [ -n "$PREFIXED" ]; then
    echo "[ERROR] 自检失败，包内命中敏感文件或结构不符：" >&2
    if [ -n "$BAD" ]; then printf '  敏感名: %s\n' "$BAD" >&2; fi
    if [ -n "$UPLOADS_BAD" ]; then printf '  uploads 内文件: %s\n' "$UPLOADS_BAD" >&2; fi
    if [ -n "$PREFIXED" ]; then printf '  出现外层目录前缀(应为平铺): %s\n' "$PREFIXED" >&2; fi
    rm -f -- "$OUT"
    echo "[ERROR] 已删除不安全的 tarball: $OUT" >&2
    exit 1
fi

for NEED in api_server.py admin/index.html config.default.json install.sh uninstall.sh uploads/.gitkeep; do
    if ! grep -qxF "$NEED" "$WORK/listing.txt"; then
        rm -f -- "$OUT"
        die "自检失败：包内缺少必需文件 $NEED（已删除 tarball）"
    fi
done
echo "      包内条目: $TOTAL（恰好等于待打包文件数 $FILECOUNT 时结构完整）"

# 解包复核：确认平铺结构且与 staging 完全一致
EXTRACT="$WORK/extract"
if ! fmo_tar_extract "$OUT" "$EXTRACT"; then
    rm -f -- "$OUT"
    die "解包复核失败（tar 与 python 回退均不可用），已删除 tarball"
fi
for NEED in api_server.py admin/index.html config.default.json install.sh uninstall.sh; do
    if [ ! -f "$EXTRACT/$NEED" ]; then
        rm -f -- "$OUT"
        die "解包后根目录缺少 $NEED，不是平铺结构（已删除 tarball）"
    fi
done
if have diff; then
    (cd "$STAGE" && find . -type f | LC_ALL=C sort) > "$WORK/list.stage.txt"
    (cd "$EXTRACT" && find . -type f | LC_ALL=C sort) > "$WORK/list.extract.txt"
    if ! diff -q "$WORK/list.stage.txt" "$WORK/list.extract.txt" >/dev/null; then
        rm -f -- "$OUT"
        die "解包后文件清单与打包内容不一致（已删除 tarball）"
    fi
fi
GOT="$(cd "$EXTRACT" && find . -type f | wc -l | tr -d '[:space:]')"
echo "      解包复核通过：$GOT 个文件平铺在根目录（api_server.py / admin/index.html / config.default.json 均就位）"

# ------------------------------ [8/8] 校验清单与 MANIFEST --------------------
echo "[8/8] 生成 SHA256 校验文件与 MANIFEST ..."
HASH="$(sha256_of "$OUT" || true)"
case "$HASH" in
    ""|*[!0-9a-f]*) rm -f -- "$OUT"; die "计算 SHA256 失败（sha256sum/shasum/python 均不可用）" ;;
esac
if [ "${#HASH}" -ne 64 ]; then
    rm -f -- "$OUT"
    die "SHA256 长度异常（${#HASH}），已删除 tarball"
fi

printf '%s  %s\n' "$HASH" "$TARNAME" > "$DIST/$TARNAME.sha256"
printf '%s  %s\n' "$HASH" "$TARNAME" > "$DIST/checksums.txt"
# 无版本号包的校验文件（内容文件名与自身文件名一致，便于 sha256sum -c 直接使用）
printf '%s  %s\n' "$HASH" "fmo-subsystem.tar.gz" > "$DIST/fmo-subsystem.tar.gz.sha256"

{
    echo "# FMO 分系统 发布清单（MANIFEST.txt）"
    echo "# 生成时间      : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# 版本          : $VERSION"
    echo "# 分发根地址    : ${BASE_URL:-<未设置，包内 install.sh 保留占位地址>}"
    echo "# 地址注入      : $INJECTED"
    echo "# 版本号注入    : $INJECTED_VERSION"
    echo "# 包文件名      : $TARNAME"
    echo "# 包大小(字节)  : $TARBYTES"
    echo "# 包 SHA256     : $HASH"
    echo "# 文件数        : $FILECOUNT"
    echo "# 排除项        : *.db *.db-journal/-wal/-shm ca/(含 ca_private.json) uploads/(除 .gitkeep)"
    echo "#                 __pycache__/ *.pyc logs/ *.log .git/ roots/ *.bak *.tmp 旧发布产物"
    echo "#                 （dist/VERSION 作为版本基准单独进包，不属于 dist 剪枝范围）"
    echo "#"
    printf '# %-64s %12s  %s\n' "SHA256" "SIZE(byte)" "PATH"
    while IFS= read -r REL; do
        if [ -n "$REL" ]; then
            printf '%s  %12s  %s\n' "$(sha256_of "$STAGE/$REL")" "$(file_size "$STAGE/$REL")" "$REL"
        fi
    done < "$WORK/files.txt"
} > "$DIST/MANIFEST.txt"

# ------------------------------ 组装"需要上传"的专属文件夹 --------------------
# dist/ 是构建目录（含 MANIFEST 等留档文件）；下面这个文件夹才是"要传到分发地址"的全部内容。
UPLOAD="$DIST/release-upload"
rm -rf -- "$UPLOAD"
mkdir -p "$UPLOAD"
cp -a "$STAGE/install.sh"              "$UPLOAD/install.sh"
cp -a "$STAGE/uninstall.sh"            "$UPLOAD/uninstall.sh"
cp -a "$OUT"                           "$UPLOAD/$TARNAME"
cp -a "$DIST/$TARNAME.sha256"          "$UPLOAD/$TARNAME.sha256"
cp -a "$OUT_FLAT"                      "$UPLOAD/fmo-subsystem.tar.gz"
cp -a "$DIST/fmo-subsystem.tar.gz.sha256" "$UPLOAD/fmo-subsystem.tar.gz.sha256"
cp -a "$REPO/dist/VERSION"             "$UPLOAD/VERSION"

# BAS 子渠道：bas/ 下的文件进 <BASE>/bas/（一键安装脚本 + 旧系统扫描/迁移模块）
mkdir -p "$UPLOAD/bas"
MISSING_BAS=""
for BF in install-bas.sh uninstall-bas.sh bas_migrate.py bas_emqx_auth.py bas_diagnose.py VERSION; do
    # 单一来源：优先取仓库根的当前文件（bas/ 只是打包产物目录，不再手工同步，
    # 否则会出现"根目录已修好、bas/ 里还是旧版"的静默旧包事故）
    if [ -f "$REPO/$BF" ]; then
        cp -a "$REPO/$BF" "$UPLOAD/bas/$BF"
        if [ -f "$REPO/bas/$BF" ] && ! cmp -s "$REPO/$BF" "$REPO/bas/$BF"; then
            # 顺手同步回 bas/，避免下次有人误用旧副本
            cp -a "$REPO/$BF" "$REPO/bas/$BF"
        fi
    elif [ -f "$REPO/bas/$BF" ]; then
        cp -a "$REPO/bas/$BF" "$UPLOAD/bas/$BF"
        echo "      [BAS] 注意：$BF 只存在于 bas/（根目录没有），已按 bas/ 打包"
    else
        MISSING_BAS="$MISSING_BAS $BF"
    fi
done
# 上传的脚本必须是 LF（否则 Linux 上 bash 会报 bad interpreter）
for BF in install-bas.sh uninstall-bas.sh bas_emqx_auth.py; do
    if [ -f "$UPLOAD/bas/$BF" ]; then
        if grep -q $'\r' "$UPLOAD/bas/$BF" 2>/dev/null; then
            tr -d '\r' < "$UPLOAD/bas/$BF" > "$UPLOAD/bas/$BF.lf" && mv "$UPLOAD/bas/$BF.lf" "$UPLOAD/bas/$BF"
            echo "      [BAS] 已把 $BF 的 CRLF 转为 LF"
        fi
        chmod +x "$UPLOAD/bas/$BF"
    fi
done
# BAS 安装脚本里的分发地址注入（与 install.sh 同规则：只替换占位行，行数不变）
if [ -n "$BASE_URL" ] && [ -f "$UPLOAD/bas/install-bas.sh" ]; then
    if grep -qE '^[[:space:]]*DEFAULT_BASE_URL=' "$UPLOAD/bas/install-bas.sh"; then
        ESC_BAS="$(printf '%s' "$BASE_URL" | sed 's/[&|\\]/\\&/g')"
        sed "s|^[[:space:]]*DEFAULT_BASE_URL=.*|DEFAULT_BASE_URL=\"$ESC_BAS\"|" \
            "$UPLOAD/bas/install-bas.sh" > "$UPLOAD/bas/install-bas.sh.new"
        cat "$UPLOAD/bas/install-bas.sh.new" > "$UPLOAD/bas/install-bas.sh"
        rm -f "$UPLOAD/bas/install-bas.sh.new"
        if grep -qF "DEFAULT_BASE_URL=\"$BASE_URL\"" "$UPLOAD/bas/install-bas.sh"; then
            echo "      [BAS] 已注入地址: DEFAULT_BASE_URL=\"$BASE_URL\""
        else
            warn "[BAS] 地址注入校验失败，请人工检查 bas/install-bas.sh"
        fi
    else
        warn "[BAS] install-bas.sh 未找到 DEFAULT_BASE_URL= 行，跳过注入"
    fi
fi
if [ -n "$MISSING_BAS" ]; then
    warn "BAS 渠道缺少文件（未进上传目录）:$MISSING_BAS"
    warn "  提示：bas/ 下应包含 install-bas.sh / uninstall-bas.sh / bas_migrate.py / VERSION"
fi

# 上传文件夹自检：关键文件齐全、且不含任何敏感/运行时文件
for NEED in install.sh uninstall.sh "$TARNAME" "$TARNAME.sha256" fmo-subsystem.tar.gz fmo-subsystem.tar.gz.sha256 VERSION; do
    [ -s "$UPLOAD/$NEED" ] || die "上传文件夹缺少 $NEED，已中止"
done
UP_BAD="$(find "$UPLOAD" -type f \( -name '*.db' -o -name '*.db-*' -o -name '*_private*' \
          -o -name '*.pyc' -o -name '*.log' -o -name '*.bak' -o -name '*.tmp' \) -print 2>/dev/null || true)"
if [ -n "$UP_BAD" ]; then
    die "上传文件夹内出现敏感/运行时文件，已中止：$UP_BAD"
fi
UP_FILES="$(find "$UPLOAD" -type f | wc -l | tr -d '[:space:]')"
UP_BYTES="$(find "$UPLOAD" -type f -exec cat {} + 2>/dev/null | wc -c | tr -d '[:space:]')"

# ------------------------------ 汇总 -----------------------------------------
echo ""
echo "======================================"
echo "  打包完成"
echo "  版本        : $VERSION（包内 install.sh DEFAULT_VERSION 同步结果: $INJECTED_VERSION）"
if [ -n "$BASE_URL" ]; then
    echo "  分发根地址  : $BASE_URL"
else
    echo "  分发根地址  : <未设置> → 部署前必须替换 install.sh 的 DEFAULT_BASE_URL 占位地址"
fi
echo ""
echo "  ★ 需要上传的文件夹: dist/release-upload/  （$UP_FILES 个文件，约 $((UP_BYTES / 1024)) KB）"
echo "      把它里面的内容整个传到分发地址根目录即可，不要多传也不要少传："
for F in install.sh uninstall.sh "$TARNAME" "$TARNAME.sha256" fmo-subsystem.tar.gz fmo-subsystem.tar.gz.sha256 VERSION; do
    printf '        %8s  %s\n' "$(file_size "$UPLOAD/$F")" "$F"
done
echo "      bas/ 子目录（BAS = SAS + FAS 融合，单独一条命令）："
for F in install-bas.sh uninstall-bas.sh bas_migrate.py bas_emqx_auth.py VERSION; do
    [ -f "$UPLOAD/bas/$F" ] && printf '        %8s  bas/%s\n' "$(file_size "$UPLOAD/bas/$F")" "$F"
done
echo ""
echo "  （dist/ 下的 MANIFEST.txt / CONTRACT.md 等为留档文件，不必上传，已在包内）"
echo "  包 SHA256   : $HASH"
echo "  文件数      : $FILECOUNT（自检 + 解包复核均通过）"
echo ""
echo "  客户端安装（上传完成后）："
if [ -n "$BASE_URL" ]; then
    echo "    FMO 分系统      : curl -fsSL $BASE_URL/install.sh | sudo bash"
    echo "    BAS 一键安装    : curl -fsSL $BASE_URL/bas/install-bas.sh | sudo bash"
    echo "      （自动扫描旧 SAS/FAS → 备份 → 卸载 → 安装新 BAS）"
    echo "  客户端卸载："
    echo "    curl -fsSL $BASE_URL/uninstall.sh | sudo bash"
else
    echo "    curl -fsSL <分发地址>/install.sh | sudo bash"
fi
echo "======================================"
exit 0
