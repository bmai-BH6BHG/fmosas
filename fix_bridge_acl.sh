#!/usr/bin/env bash
# ============================================================================
#  FUS 互联桥接 ACL 修复（在**需要修的那台服务器**上运行）
# ----------------------------------------------------------------------------
#  作用：给本机 EMQX 的 ACL 放行桥接主题 FMO/BRIDGE/#。
#
#  为什么需要它：
#    互联桥接是"各自去订阅对方的语音主题"（FMO/BRIDGE/<节点>/<频道>）。
#    EMQX 的 ACL 如果是"收紧版"（最后一条是 {deny, all}.），而里面只放行了
#    FMO/RAW、FMO/TELE 这些老主题、**没有 FMO/BRIDGE/#**，那么：
#      对方连得上你，但**订阅你的语音主题会被拒**（SUBACK=0x80）
#      → 对方永远拿不到你的集群名片，也听不到你的声音
#      → 表现就是"**我的声音过得去，他的声音过不来**"（单向语音）
#    这条规则属于部署时要配的 ACL，**不在 FUS 代码里**，所以升级 FUS 不会补上，
#    必须单独修一次。
#
#  安全性：
#    * 改动前先备份 acl.conf（.bak-<时间戳>）；
#    * 已经放行过就什么都不做（幂等）；
#    * 只在最后那条 {deny, all}. 之前插入一条 allow，不动其它任何规则；
#    * 自动识别 docker / 原生两种安装；两种都找不到时只打印手工步骤，绝不乱改。
#
#  用法：  sudo bash fus-fix-acl.sh            # 修复 + 重载
#          sudo bash fus-fix-acl.sh --check    # 只看现状，不改
# ============================================================================
set -u

RULE='{allow, all, all, ["FMO/BRIDGE/#"]}.'
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { echo "[ACL] $*"; }

# ---------- 1) 找到生效的 acl.conf ----------
# 这台机器上可能同时存在多个（docker 挂载的、原生的、备份的）。
# 取"EMQX 实际在用的那个"：优先看容器挂载，其次看原生安装路径。
find_acl_files() {
  local out=""
  # docker 版：找 emqx 容器的挂载
  if command -v docker >/dev/null 2>&1; then
    local cid
    cid=$(docker ps -q --filter "name=emqx" 2>/dev/null | head -1)
    if [ -n "$cid" ]; then
      out="$out $(docker inspect "$cid" \
        --format '{{range .Mounts}}{{if eq .Destination "/opt/emqx/etc"}}{{.Source}}/acl.conf{{end}}{{end}}' \
        2>/dev/null)"
    fi
  fi
  # 原生版 / 常见路径
  for f in /opt/emqx/etc/acl.conf /usr/local/emqx/etc/acl.conf \
           /volume1/docker/emqx/etc/acl.conf /etc/emqx/acl.conf; do
    [ -f "$f" ] && out="$out $f"
  done
  echo "$out" | tr ' ' '\n' | sed '/^$/d' | sort -u
}

# 重启/重载 EMQX，让新 ACL 生效
reload_emqx() {
  if command -v docker >/dev/null 2>&1; then
    local cid
    cid=$(docker ps -q --filter "name=emqx" 2>/dev/null | head -1)
    if [ -n "$cid" ]; then
      log "重载 EMQX（docker restart ${cid:0:12}）…"
      docker restart "$cid" >/dev/null 2>&1 && { log "已重启 EMQX"; return 0; }
    fi
  fi
  if command -v emqx >/dev/null 2>&1; then
    if emqx ctl conf reload >/dev/null 2>&1; then
      log "已执行 emqx ctl conf reload"
      return 0
    fi
    emqx restart >/dev/null 2>&1 && { log "已重启 EMQX"; return 0; }
  fi
  log "★ 没能自动重载 EMQX —— 请手工重启它让新规则生效"
  return 1
}

FILES=$(find_acl_files)
if [ -z "$FILES" ]; then
  log "★ 没找到 acl.conf。请手工在 EMQX 的 acl.conf 里、最后一条 {deny, all}. 之前加上："
  log "    $RULE"
  log "  然后重启 EMQX。"
  exit 1
fi

CHANGED=0
for f in $FILES; do
  echo "----------------------------------------"
  log "检查 $f"
  if grep -q 'FMO/BRIDGE' "$f" 2>/dev/null; then
    log "  已经放行 FMO/BRIDGE —— 无需改动 ✓"
    grep -n 'FMO/BRIDGE' "$f" | sed 's/^/    /'
    continue
  fi
  log "  ★ 未放行 FMO/BRIDGE —— 对方订阅本机桥接主题会被拒（单向语音的原因）"
  if [ "$CHECK_ONLY" = "1" ]; then
    continue
  fi
  cp -f "$f" "$f.bak-$(date +%Y%m%d-%H%M%S)" && log "  已备份"
  if grep -q '^{deny, all}\.' "$f" 2>/dev/null; then
    # 在最后那条 deny-all 之前插入放行规则（保持它仍是最后一条）
    awk -v rule="$RULE" '
      /^\{deny, all\}\./ && !done { print rule; done=1 }
      { print }
    ' "$f" > "$f.new" && mv -f "$f.new" "$f"
  else
    # 没有收尾 deny-all（宽松 ACL）→ 直接追加，宽松 ACL 本来就允许
    printf '%s\n' "$RULE" >> "$f"
  fi
  log "  已加入：$RULE"
  CHANGED=1
done

if [ "$CHANGED" = "1" ] && [ "$CHECK_ONLY" = "0" ]; then
  echo "----------------------------------------"
  reload_emqx
  echo
  log "修复完成。请让对方等 1~2 分钟后重连；必要时让对方在它的桥接页点一次「刷新列表」。"
  log "验证：对方那台的互联系表里，你这台应变成 member=True 并开始有收帧。"
else
  echo "----------------------------------------"
  [ "$CHECK_ONLY" = "1" ] && log "仅检查模式，未做任何改动。"
fi
