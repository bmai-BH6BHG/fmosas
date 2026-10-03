#!/usr/bin/env bash
# ============================================================
#  BAS 卸载（认证 + 审计一体）
#
#  用法:
#    curl -fsSL <BASE>/bas/uninstall-bas.sh | sudo bash                # 保留数据
#    curl -fsSL <BASE>/bas/uninstall-bas.sh | sudo bash -s -- --purge  # 连数据一起删
#    bash uninstall-bas.sh [--purge] [--keep-data] [--keep-emqx]
#
#  默认：停服务 + 移除 systemd 单元 + 移除管理命令，**保留**数据库/CA/上传/配置。
#  --purge    ：额外删除安装目录与审计库（删除前逐项校验）
#  --keep-emqx：不清理 EMQX 上本服务创建的规则与桥接
#
#  环境变量: FMO_DIR 覆盖安装目录
# ============================================================
set -uo pipefail

SUBSYS_SERVICE="fmo-subsystem"
BAS_SERVICE="fmo-bas"
INSTALL_DIR="${FMO_DIR:-/opt/fmo-subsystem}"
BAS_CLI="/usr/local/bin/bas"

PURGE=0
KEEP_EMQX=0
for a in "$@"; do
    case "$a" in
        --purge|-p) PURGE=1 ;;
        --keep-emqx) KEEP_EMQX=1 ;;
        --keep-data) PURGE=0 ;;
        -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "[警告] 忽略未知参数: $a" >&2 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { printf "${GREEN}%s${NC}\n" "$*"; }
warn() { printf "${YELLOW}%s${NC}\n" "$*"; }
err()  { printf "${RED}%s${NC}\n" "$*"; }
info() { printf "${CYAN}%s${NC}\n" "$*"; }

[ "$(id -u)" -eq 0 ] || { err "需要 root：curl -fsSL <BASE>/bas/uninstall-bas.sh | sudo bash"; exit 1; }

echo "======================================"
echo "  BAS 卸载   模式: $( [ "$PURGE" = "1" ] && echo 彻底删除 || echo 保留数据 )"
echo "======================================"

# 1) 停止并移除服务单元
for svc in "$SUBSYS_SERVICE" "$BAS_SERVICE"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || \
       [ -f "/etc/systemd/system/${svc}.service" ]; then
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
        ok "已移除服务单元 $svc"
    fi
done
pkill -f "$INSTALL_DIR/api_server.py" 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true

# 2) 清理 EMQX 上本服务的规则与桥接（否则 EMQX 会往已下线服务反复投递）
if [ "$KEEP_EMQX" = "0" ] && [ -f "$INSTALL_DIR/bas_emqx.py" ]; then
    info "清理 EMQX 上的规则与桥接 ..."
    PY="$(command -v python3 || command -v python || true)"
    if [ -n "$PY" ]; then
        "$PY" - "$INSTALL_DIR" <<'PYEOF' 2>/dev/null || warn "  EMQX 清理跳过（可能未配置或不可达）"
import glob, os, sys
d = sys.argv[1]
sys.path.insert(0, d)
os.chdir(d)
from bas_audit_db import AuditDB
from bas_emqx import EmqxClient
f = glob.glob(os.path.join(d, "*_audit.db"))
if not f:
    print("  没有审计库，跳过"); raise SystemExit(0)
db = AuditDB(f[0])
url, key, sec = (db.get_setting("emqx_url", ""), db.get_setting("emqx_api_key", ""),
                 db.get_setting("emqx_api_secret", ""))
if not (url and key and sec):
    print("  未配置 EMQX，跳过"); raise SystemExit(0)
cli = EmqxClient(url, key, sec)
ok1, e1 = cli.teardown_topic_rule()
print("  规则清理: %s%s" % ("成功" if ok1 else "失败", (" " + str(e1)) if e1 else ""))
PYEOF
    fi
fi

# 3) 数据处置
if [ "$PURGE" = "1" ]; then
    if [ -d "$INSTALL_DIR" ]; then
        [ -f "$INSTALL_DIR/api_server.py" ] || { err "目录里没有 api_server.py，拒绝删除: $INSTALL_DIR"; exit 1; }
        case "$INSTALL_DIR" in
            /|/opt|/usr|/etc|/var|"") err "拒绝删除可疑路径: $INSTALL_DIR"; exit 1 ;;
        esac
        warn "即将删除（含用户数据库与 CA 私钥）: $INSTALL_DIR"
        warn "二次确认绝对路径: $(cd "$INSTALL_DIR" 2>/dev/null && pwd || echo "$INSTALL_DIR")"
        rm -rf -- "$INSTALL_DIR"
        ok "已删除 $INSTALL_DIR"
    else
        info "目录不存在: $INSTALL_DIR"
    fi
else
    ok "数据保留在 $INSTALL_DIR（*_users.db / *_sas.db / *_audit.db / ca/ / uploads/ / config.json）"
fi

# 4) 移除管理命令
if [ -f "$BAS_CLI" ]; then
    rm -f "$BAS_CLI" && ok "已移除管理命令 $BAS_CLI"
fi

echo ""
echo "======================================"
if [ "$PURGE" = "1" ]; then
    ok "BAS 已彻底卸载"
else
    ok "BAS 服务已移除，数据保留"
    echo "  彻底删除数据: 同上命令加 --purge"
    echo "  数据位置    : $INSTALL_DIR"
fi
echo "======================================"
