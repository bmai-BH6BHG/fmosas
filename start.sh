#!/bin/bash
# FMO 分系统后端 API 服务启动脚本
# 用法: ./start.sh [port]
#   默认端口 35928（也可由 config.json 的 port 字段决定）
set -e

PORT=${1:-35928}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================"
echo "  FMO 分系统后端 API 服务启动"
echo "  工作目录: $SCRIPT_DIR"
echo "  监听端口: $PORT"
echo "======================================"

# 优先使用 python3，回退 python
if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "[ERROR] 未找到 python3 / python，请先安装 Python 3"
    exit 1
fi

exec "$PY" -u api_server.py --port "$PORT"