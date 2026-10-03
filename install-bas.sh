#!/usr/bin/env bash
# ============================================================
#  BAS 一键安装（FMO 认证 + 审计一体，纯 Python，无 .NET）
#
#  用法（推荐一行）:
#    curl -fsSL <BASE>/install-bas.sh | sudo bash
#
#  它做的事:
#    1) 扫描本机**原有的 SAS（分系统认证）与 FAS（.NET 审计）**
#    2) 备份旧数据（数据库 / CA 私钥 / 配置 → tar.gz）
#    3) 安全停用并卸载旧系统（含清理 EMQX 上旧 FAS 的规则与桥接）
#    4) 安装新的 BAS：单进程、单端口、单登录、单库，审计能力内嵌
#    5) 把旧 FAS 的 EMQX 配置迁移到 BAS
#    6) 联合自检
#
#  常用参数:
#    --scan-only       只看扫描结果，什么都不改（先跑这个最安全）
#    --keep-old        不卸载旧系统，只装新的（调试用）
#    --no-backup       跳过备份（不推荐）
#    --purge           卸载旧系统时同时删除旧 FAS 低权用户 fmo-audit
#    --yes             不询问，直接按默认执行
#    --mode sas|fas|both   安装范围（默认 both；新 BAS 两者一体，通常不用改）
#
#  可用环境变量:
#    FMO_BASE_URL 覆盖下载根地址      FMO_DIR 分系统安装目录
#    FMO_PORT     公网 API 端口（默认 35928，审计界面在 端口+1 的 /admin/bas）
#    EMQX_URL / EMQX_API_KEY / EMQX_API_SECRET   安装时顺带配置 EMQX（可选）
#    BAS_BACKUP_DIR  备份目录（默认 /var/backups/fmo-bas）
#    BAS_SCAN_ONLY=1 / BAS_NO_BACKUP=1 / BAS_KEEP_OLD=1  等价于对应参数
# ============================================================
set -euo pipefail

BAS_VERSION="1.6.0"
DEFAULT_BASE_URL="https://example.com/fmo-bas"
BASE_URL="${FMO_BASE_URL:-$DEFAULT_BASE_URL}"

SCAN_ONLY="${BAS_SCAN_ONLY:-0}"
NO_BACKUP="${BAS_NO_BACKUP:-0}"
KEEP_OLD="${BAS_KEEP_OLD:-0}"
PURGE=0
ASSUME_YES=0
MODE="both"

for a in "$@"; do
    case "$a" in
        --scan-only) SCAN_ONLY=1 ;;
        --no-backup) NO_BACKUP=1 ;;
        --keep-old)  KEEP_OLD=1 ;;
        --purge)     PURGE=1 ;;
        --yes|-y)    ASSUME_YES=1 ;;
        --mode=*)    MODE="${a#--mode=}" ;;
        --mode)      MODE="" ;;
        sas|fas|both|all) MODE="$a" ;;
        -h|--help) sed -n '2,30p' "$0" 2>/dev/null || true; exit 0 ;;
        *) ;;
    esac
done
case "$MODE" in
    ""|all) MODE="both" ;;
    sas|fas|both) ;;
    *) echo "[错误] 未知模式: $MODE（可选 sas/fas/both）" >&2; exit 2 ;;
esac

SUBSYS_PORT="${FMO_PORT:-35928}"
BACKUP_DIR="${BAS_BACKUP_DIR:-/var/backups/fmo-bas}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { printf "${CYAN}%s${NC}\n" "$*"; }
ok()   { printf "${GREEN}%s${NC}\n" "$*"; }
warn() { printf "${YELLOW}%s${NC}\n" "$*"; }
err()  { printf "${RED}%s${NC}\n" "$*"; }
die()  { err "$*"; exit 1; }

PY=""
find_python() {
    local p
    for p in python3 python /usr/local/bin/python3 /usr/bin/python3 \
             /var/packages/Python*/target/usr/bin/python3; do
        if command -v "$p" >/dev/null 2>&1 && \
           "$p" -c 'import sys;sys.exit(0 if sys.version_info>=(3,6) else 1)' >/dev/null 2>&1; then
            PY="$(command -v "$p" 2>/dev/null || echo "$p")"
            return 0
        fi
    done
    return 1
}

TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

echo "======================================"
echo "  BAS 一键安装 v${BAS_VERSION}"
echo "  认证(SAS) + 审计(FAS) 一体 · 纯 Python"
echo "  分发地址: $BASE_URL"
echo "======================================"

if [ "$(id -u)" -ne 0 ] && [ "$SCAN_ONLY" != "1" ]; then
    die "需要 root：curl -fsSL $BASE_URL/install-bas.sh | sudo bash
      （只先看扫描结果的话，可不加 sudo 直接跑 --scan-only）"
fi
for c in curl tar mktemp; do
    command -v "$c" >/dev/null 2>&1 || die "缺少命令: $c"
done
find_python || die "未找到 python3（BAS 需要 Python 3.6+）"
TMP="$(mktemp -d)"

# ══════════════════════════════════════════════════════════════
# 1) 扫描原有 SAS / FAS
# ══════════════════════════════════════════════════════════════
info ""
info "[1/7] 扫描本机原有的 SAS / FAS ..."
curl -fsSL "$BASE_URL/bas-migrate.py" -o "$TMP/bas_migrate.py" 2>/dev/null \
    || die "下载扫描模块失败（$BASE_URL/bas-migrate.py）"

SCAN_JSON="$TMP/scan.json"
"$PY" "$TMP/bas_migrate.py" --json > "$SCAN_JSON" 2>"$TMP/scan.err" || {
    cat "$TMP/scan.err" >&2
    die "扫描失败"
}
"$PY" "$TMP/bas_migrate.py" --scan-only | sed 's/^/    /'

SAS_FOUND="$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1],encoding="utf-8"))["sas"]["found"] else 0)' "$SCAN_JSON")"
FAS_FOUND="$("$PY" -c 'import json,sys;print(1 if json.load(open(sys.argv[1],encoding="utf-8"))["fas"]["found"] else 0)' "$SCAN_JSON")"

if [ "$SCAN_ONLY" = "1" ]; then
    echo ""
    info "== 仅扫描模式：未做任何改动 =="
    info "要执行迁移+安装，去掉 --scan-only 重跑即可。"
    exit 0
fi

# ══════════════════════════════════════════════════════════════
# 2) 迁移旧系统（备份 → 卸载）
# ══════════════════════════════════════════════════════════════
if [ "$KEEP_OLD" = "1" ]; then
    warn "[2/7] --keep-old：跳过卸载旧系统（新 BAS 可能与管理端口/规则冲突）"
elif [ "$SAS_FOUND" = "0" ] && [ "$FAS_FOUND" = "0" ]; then
    info ""
    info "[2/7] 未发现旧系统，无需迁移"
else
    info ""
    info "[2/7] 迁移：备份旧数据 → 卸载旧 SAS / FAS"
    if [ "$NO_BACKUP" = "1" ]; then
        warn "      已指定 --no-backup：旧数据不会备份，直接删除！"
        if [ "$ASSUME_YES" != "1" ]; then
            printf "      确认继续？(yes/no) "; read -r ans
            [ "$ans" = "yes" ] || die "用户取消"
        fi
    fi
    MIG_ARGS=("$TMP/bas_migrate.py" --migrate --backup-dir "$BACKUP_DIR")
    [ "$NO_BACKUP" = "1" ] && MIG_ARGS+=(--no-backup)
    [ "$PURGE" = "1" ] && MIG_ARGS+=(--purge)
    if ! "$PY" "${MIG_ARGS[@]}" | sed 's/^/    /'; then
        warn "      迁移过程有错误（见上），继续安装新 BAS；旧数据备份若已生成可手工恢复"
    fi
    ok "      旧系统已处理完毕"
fi

# ══════════════════════════════════════════════════════════════
# 3) 安装新的 BAS（下载分系统包并安装；审计模块随包一起落地）
# ══════════════════════════════════════════════════════════════
info ""
info "[3/7] 安装 BAS 主程序（分系统 + 内嵌审计）..."
SUBSYS_INSTALL_URL="$BASE_URL/install.sh"
curl -fsSL "$SUBSYS_INSTALL_URL" -o "$TMP/install.sh" \
    || die "下载安装脚本失败（$SUBSYS_INSTALL_URL）"
# 分系统安装脚本负责：下载包 → SHA256 校验 → 装 cryptography →
# 生成/合并 config.json → 同步代码（含 bas_*.py 审计模块）→ 注册 systemd → 自检
if FMO_BASE_URL="$BASE_URL" FMO_PORT="$SUBSYS_PORT" bash "$TMP/install.sh"; then
    ok "      主程序安装完成"
else
    die "主程序安装失败，已中止"
fi

# 定位安装目录（与分系统安装脚本的规则一致）
INSTALL_DIR=""
for d in "${FMO_DIR:-}" /opt/fmo-subsystem /volume1/fmo-subsystem "$HOME/fmo-subsystem"; do
    [ -n "$d" ] && [ -f "$d/api_server.py" ] && INSTALL_DIR="$d" && break
done
[ -n "$INSTALL_DIR" ] || die "找不到安装目录（api_server.py 不存在）"
info "      安装目录: $INSTALL_DIR"

# 审计模块必须随包存在（新 BAS 的审计能力靠它们，不再需要 .NET）
for m in bas_audit.py bas_audit_db.py bas_emqx.py bas_http.py bas_identity.py bas_fmo_parser.py; do
    [ -f "$INSTALL_DIR/$m" ] || die "缺少审计模块 $m —— 发布包不完整，请重新打包"
done
ok "      审计模块齐全（${INSTALL_DIR}/bas_*.py）"

# ══════════════════════════════════════════════════════════════
# 4) 迁移旧 FAS 的 EMQX 配置到 BAS
# ══════════════════════════════════════════════════════════════
info ""
info "[4/7] 迁移 EMQX 配置并建立收数链路..."
OLD_EMQX="$("$PY" -c '
import json,sys
r=json.load(open(sys.argv[1],encoding="utf-8"))
c=(r.get("fas") or {}).get("emqx_settings") or {}
print("%s|%s|%s|%s" % (c.get("emqx_url",""), c.get("emqx_api_key",""), c.get("emqx_api_secret",""), c.get("topic_name","FMO/RAW")))
' "$SCAN_JSON")"
IFS='|' read -r OLD_URL OLD_KEY OLD_SECRET OLD_TOPIC <<< "$OLD_EMQX"

CFG_URL="${EMQX_URL:-$OLD_URL}"
CFG_KEY="${EMQX_API_KEY:-$OLD_KEY}"
CFG_SECRET="${EMQX_API_SECRET:-$OLD_SECRET}"
CFG_TOPIC="${OLD_TOPIC:-FMO/RAW}"

if [ -z "$CFG_URL" ] || [ -z "$CFG_KEY" ] || [ -z "$CFG_SECRET" ]; then
    warn "      没有可用的 EMQX 配置（旧 FAS 没存，或未提供 EMQX_URL/KEY/SECRET）"
    warn "      装好后打开审计界面 → 设置，填 EMQX 地址与 API 密钥即可"
else
    info "      使用 EMQX: $CFG_URL（主题 $CFG_TOPIC）"
    if "$PY" - "$INSTALL_DIR" "$CFG_URL" "$CFG_KEY" "$CFG_SECRET" "$CFG_TOPIC" "$SUBSYS_PORT" <<'PYEOF'
import sys, os, json, urllib.request, time
install_dir, url, key, secret, topic, port = sys.argv[1:7]
sys.path.insert(0, install_dir)
os.chdir(install_dir)
from bas_audit_db import AuditDB
from bas_audit import AuditService
import glob
dbs = glob.glob(os.path.join(install_dir, "*_audit.db"))
db = AuditDB(dbs[0] if dbs else os.path.join(install_dir, "bas_audit.db"))
svc = AuditService(db, config={"admin_port": int(port) + 1})
res = svc.configure_emqx(url=url, key=key, secret=secret, enabled_topic=True, topic_name=topic)
print("      EMQX 可达: %s" % res.get("reachable"))
print("      webhook: %s" % res.get("webhook_url"))
for s in res.get("steps", []):
    print("      %s: %s" % (s.get("step"), s.get("detail")))
sys.exit(0 if res.get("ok") else 3)
PYEOF
    then
        ok "      EMQX 收数链路已建立"
    else
        warn "      EMQX 自动配置未完全成功（不影响认证功能）；可在审计界面→设置里重试"
    fi
fi

# ══════════════════════════════════════════════════════════════
# 5) 识别 MQTT(EMQX) 并把客户端认证指向本服务端口
# ══════════════════════════════════════════════════════════════
info ""
info "[5/7] 识别 MQTT(EMQX) 并把客户端认证指向本服务 ..."
curl -fsSL "$BASE_URL/bas-emqx-auth.py" -o "$TMP/bas_emqx_auth.py" 2>/dev/null || \
    cp "$INSTALL_DIR/bas_emqx_auth.py" "$TMP/bas_emqx_auth.py" 2>/dev/null || true

# 认证 URL：用本机地址 + 分系统公网端口（EMQX 与分系统同机场景）
AUTH_URL="http://$(hostname -I 2>/dev/null | awk '{print $1}'):$SUBSYS_PORT/auth"
[ "$AUTH_URL" = "http://:${SUBSYS_PORT}/auth" ] && AUTH_URL="http://127.0.0.1:$SUBSYS_PORT/auth"

if [ -z "$CFG_URL" ] || [ -z "$CFG_KEY" ] || [ -z "$CFG_SECRET" ]; then
    warn "      没有 EMQX API 凭据，跳过认证接管（装好后可在审计界面→设置 里一键切换）"
else
    info "      目标认证 URL: $AUTH_URL"
    # 先 dry-run 展示将要做的改动
    "$PY" "$TMP/bas_emqx_auth.py" --emqx-url "$CFG_URL" --key "$CFG_KEY" --secret "$CFG_SECRET" \
        --target-url "$AUTH_URL" 2>&1 | sed 's/^/      /' || true
    # 再真正执行（只动"认证"，不碰"授权"；有备份可回滚）
    if "$PY" "$TMP/bas_emqx_auth.py" --emqx-url "$CFG_URL" --key "$CFG_KEY" --secret "$CFG_SECRET" \
            --target-url "$AUTH_URL" --apply 2>&1 | sed 's/^/      /'; then
        ok "      EMQX 客户端认证已指向 $AUTH_URL"
    else
        warn "      认证接管未完全成功；客户端可能连不上，请在 EMQX Dashboard → 访问控制 → 认证 检查"
    fi
fi

# ══════════════════════════════════════════════════════════════
# 6) 重启服务
# ══════════════════════════════════════════════════════════════
info ""
info "[6/7] 重启服务..."
SVC=""
for s in fmo-subsystem fmo-bas; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${s}\.service"; then SVC="$s"; break; fi
done
if [ -n "$SVC" ]; then
    systemctl restart "$SVC" && ok "      已重启 $SVC" || warn "      重启失败，请查看 journalctl -u $SVC"
    sleep 3
else
    warn "      未发现 systemd 服务单元（可能用了 DSM 计划任务），请手工启动"
fi

# ══════════════════════════════════════════════════════════════
# 6) 联合自检
# ══════════════════════════════════════════════════════════════
info ""
info "[7/7] 联合自检 ..."
FAIL=0
health() {
    curl -fsS "http://127.0.0.1:$1/api/health" 2>/dev/null | grep -q '"ok"'
}
if health "$SUBSYS_PORT"; then ok "      公网口 $SUBSYS_PORT 健康检查通过"; else err "      公网口 $SUBSYS_PORT 无响应"; FAIL=$((FAIL+1)); fi
if health "$((SUBSYS_PORT+1))"; then ok "      管理口 $((SUBSYS_PORT+1)) 健康检查通过"; else err "      管理口无响应"; FAIL=$((FAIL+1)); fi
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d '{}' "http://127.0.0.1:$SUBSYS_PORT/auth" 2>/dev/null || echo 000)"
case "$CODE" in
    200|400|401) ok "      SAS /auth 可用（HTTP $CODE，EMQX 认证钩子就绪）" ;;
    *) err "      SAS /auth 异常（HTTP $CODE）"; FAIL=$((FAIL+1)) ;;
esac
BASRS="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((SUBSYS_PORT+1))/admin/bas" 2>/dev/null || echo 000)"
if [ "$BASRS" = "200" ]; then ok "      审计界面可用（/admin/bas）"; else err "      审计界面异常（HTTP $BASRS）"; FAIL=$((FAIL+1)); fi

# ---- 身份链路诊断：client_attrs 是否真的会下发（这是身份审计能否生效的前提）----
DIAG="$INSTALL_DIR/bas_diagnose.py"
[ -f "$DIAG" ] || DIAG="$TMP/bas_diagnose.py"
if [ ! -f "$DIAG" ]; then
    curl -fsSL "$BASE_URL/bas-diagnose.py" -o "$TMP/bas_diagnose.py" 2>/dev/null && DIAG="$TMP/bas_diagnose.py"
fi
if [ -f "$DIAG" ]; then
    info "      身份链路诊断（client_attrs 下发）..."
    DIAG_JSON="$("$PY" "$DIAG" --diagnose --json --base-dir "$INSTALL_DIR" \
                 --sas-url "http://127.0.0.1:$SUBSYS_PORT/auth" 2>/dev/null || true)"
    if [ -z "$DIAG_JSON" ]; then
        warn "      诊断未能运行（可稍后手工执行：$PY $DIAG --diagnose --base-dir $INSTALL_DIR）"
    else
        # EMQX 尚未配置属于正常状态（可留到界面里配），不算安装失败
        DIAG_STATE="$("$PY" - "$DIAG_JSON" <<'PYEOF' 2>/dev/null || echo unknown
import json, sys
try:
    r = json.loads(sys.argv[1])
except Exception:
    print("unknown"); raise SystemExit
codes = {f.get("code") for f in (r.get("findings") or [])}
if r.get("ok"):
    print("ok")
elif codes & {"EMQX_CFG_MISSING", "EMQX_UNREACHABLE"}:
    print("unconfigured")     # 还没配 EMQX，属正常
else:
    print("problem")
PYEOF
)"
        case "$DIAG_STATE" in
            ok)
                ok "      client_attrs 链路正常（EMQX 会把 SAS 下发的身份挂到连接上）" ;;
            unconfigured)
                warn "      尚未配置 EMQX（或 EMQX 不可达）：装好后到审计界面→设置 填地址与密钥，"
                warn "      然后点「运行诊断」即可；未配置期间身份审计只做统计与留证。" ;;
            *)
                "$PY" "$DIAG" --diagnose --base-dir "$INSTALL_DIR" \
                    --sas-url "http://127.0.0.1:$SUBSYS_PORT/auth" 2>&1 | sed 's/^/      /'
                warn "      身份链路有问题：拿不到连接身份时，身份审计只能留证、不能判定伪造。"
                FAIL=$((FAIL+1)) ;;
        esac
    fi
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo ""
echo "======================================"
echo "  BAS 安装完成"
echo "  认证(SAS): http://<公网IP>:$SUBSYS_PORT        （APP 注册/登录、EMQX 认证 /auth）"
echo "  审计界面 : http://${IP:-<内网IP>}:$((SUBSYS_PORT+1))/admin/bas"
echo "  策略模式 : warn（只告警留证，不会自动封人；确认无误封后再去界面切 ban）"
if [ "$SAS_FOUND" = "1" ] || [ "$FAS_FOUND" = "1" ]; then
    echo "  旧系统   : 已卸载（备份在 $BACKUP_DIR）"
    echo "             SAS=$( [ "$SAS_FOUND" = "1" ] && echo 发现 || echo 无 )  FAS=$( [ "$FAS_FOUND" = "1" ] && echo 发现 || echo 无 )"
fi
echo ""
echo "  首次使用：EMQX → 认证(Authentication) → HTTP 认证，URL 填"
echo "            http://<本机IP>:$SUBSYS_PORT/auth （注意是「认证」不是「授权」）"
echo "  日志     : journalctl -u ${SVC:-fmo-subsystem} -f"
echo "  再跑一次 : 可安全重跑（幂等）"
echo "  卸载     : curl -fsSL $BASE_URL/bas-uninstall.sh | sudo bash"
echo "======================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
