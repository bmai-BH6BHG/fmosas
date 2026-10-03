#!/usr/bin/env bash
# ============================================================================
#  FMO 分系统 一键卸载（通用 Linux / 群晖 DSM）
#
#  用法（三选一）：
#    1) 一行命令（推荐）: curl -fsSL <分发地址>/uninstall.sh | sudo bash
#    2) 默认卸载（保留数据）: bash uninstall.sh
#    3) 彻底卸载（连安装目录一起删）: bash uninstall.sh --purge
#
#  默认行为：停止服务 → 取消开机自启 → 删除 systemd 单元
#            （无 systemd 的群晖环境则删除启动脚本 start.sh）
#            → 保留全部用户数据并打印数据位置。
#  --purge ：在默认行为之后删除整个安装目录。
#            删除前必须校验目标目录内存在 api_server.py（确认是 FMO 安装目录），
#            并连续两次打印将被删除的绝对路径；校验不通过则拒绝删除并非 0 退出。
#
#  环境变量：FMO_DIR=/path/to/fmo-subsystem  覆盖安装目录（默认自动探测）
#             FMO_FORCE_PURGE=1             允许 --purge 删除含 .git 的目录
#  幂等：未安装时打印说明并以 0 退出；重复执行同样安全。
#  兼容：bash 4.2+（群晖自带 bash 4.3），不使用 eval，不删除未校验的路径。
# ============================================================================
set -euo pipefail

SERVICE="fmo-subsystem"
UNIT="/etc/systemd/system/${SERVICE}.service"
PURGE=0
ASSUME_YES=0

usage() {
    cat <<'USAGE'
FMO 分系统 一键卸载

用法:
  curl -fsSL <分发地址>/uninstall.sh | sudo bash   # 一行命令（默认保留数据）
  bash uninstall.sh                                # 默认：停服务 + 删自启，保留数据
  bash uninstall.sh --purge                        # 彻底删除安装目录（先校验）

参数:
  --purge        删除安装目录（删除前校验目录内存在 api_server.py 并打印绝对路径）
  -y, --yes      跳过交互确认（非交互环境本就跳过）
  -h, --help     显示本帮助

环境变量:
  FMO_DIR=/path/to/fmo-subsystem   覆盖安装目录（默认自动探测）
  FMO_FORCE_PURGE=1                确认 --purge 可删除含 .git 的目录

默认保留的数据: config.json、ca/、uploads/、roots/、*_users.db、*_sas.db
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1 ;;
        -y|--yes) ASSUME_YES=1 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*)
            echo "[ERROR] 未知参数: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            echo "[ERROR] 不支持的位置参数: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# 0. 自动提权 root（curl | sudo bash 时本脚本已是 root，直接跳过）
# ---------------------------------------------------------------------------
REEXEC_ARGS=""
if [ "$PURGE" -eq 1 ]; then REEXEC_ARGS="$REEXEC_ARGS --purge"; fi
if [ "$ASSUME_YES" -eq 1 ]; then REEXEC_ARGS="$REEXEC_ARGS --yes"; fi

if [ "$(id -u)" -ne 0 ]; then
    if [ -f "$0" ] && command -v sudo >/dev/null 2>&1; then
        echo "[INFO] 需要 root 权限，正在通过 sudo 重新执行 ..."
        if [ -n "${FMO_DIR:-}" ]; then
            exec sudo -E env "FMO_DIR=$FMO_DIR" bash "$0" $REEXEC_ARGS
        else
            exec sudo -E bash "$0" $REEXEC_ARGS
        fi
    fi
    echo "[ERROR] 需要 root 权限才能停止服务并删除开机自启项。"
    echo "        请改用: curl -fsSL <分发地址>/uninstall.sh | sudo bash"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. 定位安装目录
#    优先级: FMO_DIR > systemd 单元 WorkingDirectory > 约定安装路径 > 脚本所在目录
# ---------------------------------------------------------------------------
is_install_dir() {
    [ -n "${1:-}" ] && [ -f "$1/api_server.py" ]
}

SELF_DIR=""
if [ -f "$0" ]; then
    SELF_DIR="$(cd "$(dirname "$0")" && pwd -P)"
fi

DIR=""
DIR_SRC=""
if [ -n "${FMO_DIR:-}" ]; then
    DIR="$FMO_DIR"
    DIR_SRC="环境变量 FMO_DIR"
else
    if [ -f "$UNIT" ]; then
        UD="$(awk '
            /^[[:space:]]*WorkingDirectory[[:space:]]*=/ {
                sub(/^[^=]*=[[:space:]]*/, ""); gsub(/\r/, ""); gsub(/[[:space:]]+$/, "");
                print; exit
            }' "$UNIT")"
        if [ -n "$UD" ] && [ -d "$UD" ]; then
            DIR="$UD"
            DIR_SRC="systemd 单元 $UNIT"
        fi
    fi
    if [ -z "$DIR" ]; then
        for CAND in /opt/fmo-subsystem /volume1/fmo-subsystem "${HOME:-/root}/fmo-subsystem"; do
            if [ -d "$CAND" ] && is_install_dir "$CAND"; then
                DIR="$CAND"
                DIR_SRC="约定安装路径"
                break
            fi
        done
    fi
    if [ -z "$DIR" ] && [ -n "$SELF_DIR" ] && is_install_dir "$SELF_DIR"; then
        DIR="$SELF_DIR"
        DIR_SRC="脚本所在目录"
    fi
fi

HAS_SYSTEMD=0
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=1
fi

# 规范化安装目录：去掉末尾多余斜杠（"/" 原样保留，交由 --purge 的危险路径校验拒绝）
if [ -n "$DIR" ]; then
    TRIMMED="${DIR%/}"
    if [ -n "$TRIMMED" ]; then
        DIR="$TRIMMED"
    fi
fi

echo "======================================"
echo "  FMO 分系统 一键卸载"
if [ -n "$DIR" ]; then
    echo "  安装目录: $DIR"
    echo "  目录来源: ${DIR_SRC:-自动探测}"
else
    echo "  安装目录: 未找到（仅清理服务自启项）"
fi
echo "======================================"

# 幂等：既没有安装目录、也没有 systemd 单元 → 未安装，直接成功退出
if [ -z "$DIR" ] && [ ! -f "$UNIT" ] && [ "$PURGE" -eq 0 ]; then
    echo "[INFO] 未检测到 FMO 安装："
    echo "       - systemd 单元不存在: $UNIT"
    echo "       - 约定安装目录不存在: /opt/fmo-subsystem、/volume1/fmo-subsystem、\$HOME/fmo-subsystem"
    echo "[INFO] 无需卸载，退出（幂等）。如需指定目录请用 FMO_DIR=/实际/安装目录 重试。"
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. 停止服务
# ---------------------------------------------------------------------------
echo "[1/3] 停止正在运行的 FMO 服务 ..."
STOPPED=0
if [ "$HAS_SYSTEMD" -eq 1 ] && [ -f "$UNIT" ]; then
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    echo "      已执行: systemctl stop $SERVICE"
    STOPPED=1
fi
if [ -n "$DIR" ] && [ -d "$DIR" ] && command -v pkill >/dev/null 2>&1; then
    if pkill -f -- "$DIR/api_server.py" >/dev/null 2>&1; then
        echo "      已终止残留进程: $DIR/api_server.py"
        STOPPED=1
    fi
fi
if [ "$STOPPED" -eq 0 ]; then
    echo "      未发现运行中的服务（可能已停止）"
fi

# ---------------------------------------------------------------------------
# 3. 取消开机自启并删除服务单元 / 群晖启动脚本
# ---------------------------------------------------------------------------
echo "[2/3] 取消开机自启并删除服务单元 ..."
if [ -f "$UNIT" ]; then
    if [ "$HAS_SYSTEMD" -eq 1 ]; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    fi
    rm -f -- "$UNIT"
    if [ "$HAS_SYSTEMD" -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    fi
    echo "      已删除: $UNIT"
else
    echo "      未发现服务单元 $UNIT（无需删除）"
fi

if [ "$HAS_SYSTEMD" -eq 0 ] && [ -n "$DIR" ] && [ -d "$DIR" ] && [ -f "$DIR/start.sh" ]; then
    if [ -n "$SELF_DIR" ] && [ "$DIR" = "$SELF_DIR" ]; then
        echo "      [提示] 当前目录即脚本所在目录（疑似源码目录），已保留 $DIR/start.sh"
        echo "             群晖请到 DSM 控制面板 → 计划任务 中删除 FMO 启动任务"
    else
        rm -f -- "$DIR/start.sh"
        echo "      已删除群晖启动脚本: $DIR/start.sh"
        echo "      [提示] 如已在 DSM 控制面板 → 计划任务 注册过启动项，请一并删除"
    fi
fi

# ---------------------------------------------------------------------------
# 4. --purge：校验后彻底删除安装目录
# ---------------------------------------------------------------------------
if [ "$PURGE" -eq 1 ]; then
    echo "[3/3] --purge 彻底删除安装目录 ..."

    if [ -z "$DIR" ] || [ ! -e "$DIR" ]; then
        echo "      目标目录不存在，无需删除: ${DIR:-<未检测到>}"
        echo "      卸载完成（幂等，无残留）。"
        exit 0
    fi
    if [ ! -d "$DIR" ]; then
        echo "[ERROR] 目标不是目录，拒绝删除: $DIR" >&2
        exit 1
    fi

    # 解析真实绝对路径（后续所有校验与删除都基于它）
    ABS="$(cd "$DIR" && pwd -P)"

    # 安全底线 1：必须是绝对路径，且深度 >= 2（拒绝 /opt、/usr、/ 这类系统根级路径）
    case "$ABS" in
        /*) : ;;
        *)
            echo "[ERROR] 解析到的路径不是绝对路径，拒绝删除: '$ABS'" >&2
            exit 1
            ;;
    esac
    SLASHES="$(printf '%s' "$ABS" | tr -cd '/' | wc -c | tr -d '[:space:]')"
    if [ -z "$ABS" ] || [ "$SLASHES" -lt 2 ]; then
        echo "[ERROR] 目标路径过浅（疑似系统根目录），拒绝删除: '$ABS'" >&2
        exit 1
    fi

    # 安全底线 2：拒绝系统级/危险路径
    case "$ABS" in
        "/"|"/opt"|"/usr"|"/usr/local"|"/etc"|"/var"|"/home"|"/root"|"/volume1"|"/tmp"|\
        "/bin"|"/sbin"|"/boot"|"/dev"|"/proc"|"/sys"|"/mnt"|"/media"|"/srv")
            echo "[ERROR] 目标路径过于危险，拒绝删除: $ABS" >&2
            exit 1
            ;;
    esac

    # 安全底线 3（契约硬性要求）：目标目录必须确实是 FMO 安装目录
    if [ ! -f "$DIR/api_server.py" ]; then
        echo "[ERROR] 目标目录内未找到 api_server.py，无法确认是 FMO 安装目录，拒绝删除:" >&2
        echo "        $ABS" >&2
        exit 1
    fi

    # 安全底线 4：疑似 git 源码仓库需要显式确认
    if [ -e "$ABS/.git" ] && [ "${FMO_FORCE_PURGE:-0}" != "1" ]; then
        echo "[ERROR] 目标目录包含 .git（疑似源码仓库），拒绝 --purge: $ABS" >&2
        echo "        确认要删除请设置 FMO_FORCE_PURGE=1 后重试。" >&2
        exit 1
    fi

    echo "      将被删除的绝对路径（第 1 次提示）: $ABS"
    echo "      将被删除的绝对路径（第 2 次确认）: $ABS"

    if [ "$ASSUME_YES" -eq 0 ] && [ -t 0 ]; then
        printf '      确认删除请输入 yes 后回车: '
        ANSWER=""
        read -r ANSWER || ANSWER=""
        if [ "$ANSWER" != "yes" ]; then
            echo "      已取消删除（服务已卸载，数据保留在 $ABS）"
            exit 0
        fi
    fi

    echo "      正在删除 ..."
    rm -rf -- "$ABS"
    if [ -e "$ABS" ]; then
        echo "[ERROR] 删除失败，请手动检查: $ABS" >&2
        exit 1
    fi

    echo "      已彻底删除: $ABS"
    echo ""
    echo "======================================"
    echo "  卸载完成（含数据）：安装目录已删除"
    echo "======================================"
    exit 0
fi

# ---------------------------------------------------------------------------
# 5. 默认模式：保留数据
# ---------------------------------------------------------------------------
echo "[3/3] 保留用户数据（默认行为）"
if [ -n "$DIR" ] && [ -d "$DIR" ]; then
    KEEP=""
    if [ -f "$DIR/config.json" ]; then KEEP="$KEEP config.json"; fi
    for D in ca uploads roots; do
        if [ -d "$DIR/$D" ]; then KEEP="$KEEP $D/"; fi
    done
    DBS="$( { ls "$DIR" 2>/dev/null | grep -E '_(users|sas)\.db$' || true; } )"
    if [ -n "$DBS" ]; then
        KEEP="$KEEP $(printf '%s' "$DBS" | tr '\n' ' ')"
    fi
    echo "      数据保留在: $DIR"
    echo "      保留内容  :${KEEP:- （当前目录下未发现数据文件）}"
else
    echo "      未找到安装目录，无数据需要保留"
fi

echo ""
echo "======================================"
echo "  卸载完成：服务已停止，开机自启已移除"
if [ -n "$DIR" ]; then
    echo "  数据保留在 : $DIR"
    echo "  彻底删除   : bash uninstall.sh --purge"
    echo "               或 curl -fsSL <分发地址>/uninstall.sh | sudo bash -s -- --purge"
fi
echo "  重复执行本脚本是安全的（幂等）"
echo "======================================"
exit 0
