#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第三方台账站证书外泄监测（watchdog）

背景（真实事故，2026-11）：
  第三方台账站 fmo.panyong.top/fmo-statistics 会抄收 FMO 协议里的 userCert 广播，
  把各站自签证书收进它的库。我们的 CA 原本 sn=1/1001 与官方 ESN 撞号，
  于是它用官方 CA 验我们的证书必然失败 → 整批判成 unknown_ca / bad_signature，
  在「未验签」页公开点名（BH6BHG / BG8KOE / BH6RGQ 等十余个呼号）。

  我们已做两件事止血：
    ① 关闭对外证书探测（不再把证书递给陌生站点）
    ② 把本机 CA 换成唯一 sn 号段（900000001 / 900001001）
  但只要有任何一条老链路还在广播，那些证书就会重新出现在对方站点上。
  本工具定期核对「我们签发的指纹 vs 对方站点收录的指纹」，一旦发现重合就告警。

判定方式：
  指纹（SHA-256 / base64url / 43 字符）是证书的唯一标识，比呼号或 issuer_sn 可靠。
  用本机 sas 库里的全部指纹去比对对方 /api/unverified 与 /api/stations/<id> 的
  指纹集合，交集非空 = 我们的证书被收录了。

用法：
  python3 tools/leak_watch.py check              # 检查一次，有命中则退出码 2
  python3 tools/leak_watch.py check --json       # 机器可读
  python3 tools/leak_watch.py daemon --interval 3600 \
      --alert-cmd '/opt/fmo-subsystem/tools/notify_admin.sh'   # 常驻循环
  python3 tools/leak_watch.py install-cron       # 装成每小时检查一次

退出码：0 = 干净；2 = 发现外泄；1 = 检查失败（网络/解析）。
"""
import argparse
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("FMO_SUBSYS", "/opt/fmo-subsystem")
DEFAULT_TARGET = "https://fmo.panyong.top/fmo-statistics"
UA = "fmo-leak-watch/1.0 (+local audit; read-only)"
TIMEOUT = 20
STATE_FILE = os.path.join(BASE, "leak_watch_state.json")


# ---------------------------------------------------------------- 本机指纹

def db_path():
    sid = ""
    try:
        with open(os.path.join(BASE, "config.json"), "r", encoding="utf-8-sig") as f:
            sid = str(json.load(f).get("subsystem_id") or "").strip()
    except Exception:  # noqa: BLE001
        pass
    cand = os.path.join(BASE, "%s_sas.db" % sid) if sid else ""
    if cand and os.path.exists(cand):
        return cand
    for fn in sorted(os.listdir(BASE)):
        if fn.endswith("_sas.db"):
            return os.path.join(BASE, fn)
    raise SystemExit("找不到 sas 数据库（%s）" % BASE)


def local_certs():
    """返回 {指纹: {callsign, uid, revoked, issuer_sn}}"""
    p = db_path()
    out = {}
    conn = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    try:
        for cs, uid, cj, fp, rev in conn.execute(
                "SELECT callsign, uid, cert_user_json, fingerprint, revoked FROM certificates"):
            isn = ""
            try:
                isn = str((json.loads(cj) or {}).get("issuerSn") or "")
            except Exception:  # noqa: BLE001
                pass
            out[fp] = {"callsign": cs, "uid": uid,
                       "revoked": bool(rev), "issuer_sn": isn}
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------- 对方站点

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                              "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def remote_certs(target, max_pages=40):
    """
    抓对方站点收录的证书指纹。
    说明：/api/unverified 返回未验签的；已验签的在 /api/stations 明细里。
    我们真正关心的是"我们的证书出现在任何一栏"，所以两处都看。
    """
    found = {}

    # ---- 1) 未验签列表（分页） ----
    offset = 0
    page = 200
    for _ in range(max_pages):
        try:
            j = _get("%s/api/unverified?limit=%d&offset=%d" % (target, page, offset))
        except Exception:  # noqa: BLE001
            break
        items = j.get("items") or []
        if not items:
            break
        for it in items:
            fp = str(it.get("fingerprint") or "").strip()
            if fp:
                found[fp] = {
                    "callsign": it.get("callsign"),
                    "uid": it.get("uid"),
                    "issuer_sn": it.get("issuer_sn"),
                    "verify_status": it.get("verify_status"),
                    "last_seen": it.get("last_seen"),
                    "where": "unverified",
                }
        if len(items) < page:
            break
        offset += page

    # ---- 2) 设备明细（已验签的也在里面） ----
    # 只查我们自己的呼号，避免把几千个台站全抓一遍。
    mine_calls = sorted({v["callsign"] for v in local_certs().values() if v["callsign"]})
    for cs in mine_calls:
        try:
            j = _get("%s/api/stations?q=%s&limit=50" % (target, cs))
        except Exception:  # noqa: BLE001
            continue
        for st in (j.get("items") or []):
            sid = st.get("id")
            if sid is None:
                continue
            try:
                d = _get("%s/api/stations/%s" % (target, sid))
            except Exception:  # noqa: BLE001
                continue
            for c in (d.get("certs") or []):
                fp = str(c.get("fingerprint") or "").strip()
                if fp and fp not in found:
                    found[fp] = {
                        "callsign": c.get("callsign"),
                        "uid": c.get("uid"),
                        "issuer_sn": c.get("issuer_sn"),
                        "verify_status": c.get("verify_status"),
                        "last_seen": c.get("last_seen") or d.get("last_seen"),
                        "where": "stations",
                    }
    return found


# ---------------------------------------------------------------- 检查

def check(target=DEFAULT_TARGET, as_json=False, quiet=False):
    t0 = time.time()
    local = local_certs()
    try:
        remote = remote_certs(target)
    except Exception as e:  # noqa: BLE001
        if as_json:
            print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        else:
            print("检查失败（网络/接口）: %s" % e)
        return 1, None

    hits = []
    for fp, r in remote.items():
        if fp in local:
            l = local[fp]
            hits.append({
                "fingerprint": fp,
                "callsign": l["callsign"],
                "uid": l["uid"],
                "issuer_sn": l["issuer_sn"],
                "our_revoked": l["revoked"],
                "remote_verify_status": r.get("verify_status"),
                "remote_callsign": r.get("callsign"),
                "remote_uid": r.get("uid"),
                "last_seen": r.get("last_seen"),
                "where": r.get("where"),
            })
    hits.sort(key=lambda x: (x["callsign"] or "", x["fingerprint"]))

    new_hits, known = [], []
    prev = {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            prev = json.load(f) or {}
    except Exception:  # noqa: BLE001
        prev = {}
    prev_fps = set(prev.get("hit_fingerprints") or [])
    for h in hits:
        (known if h["fingerprint"] in prev_fps else new_hits).append(h)

    result = {
        "ok": True,
        "checked_at": int(time.time()),
        "target": target,
        "our_certs": len(local),
        "remote_certs_seen": len(remote),
        "hits": len(hits),
        "new_hits": len(new_hits),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "hit_list": hits,
        "new_hit_list": new_hits,
    }
    # 状态文件同时供管理界面 /api/security/leak-status 读取：
    #   hit_fingerprints 用于"是否新增"判断，
    #   hit_list / target 供界面展示明细。
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "hit_fingerprints": [h["fingerprint"] for h in hits],
                "hit_list": hits,
                "target": target,
                "checked_at": result["checked_at"],
            }, f, ensure_ascii=False)
    except Exception:  # noqa: BLE001
        pass

    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif not quiet:
        print("=" * 70)
        print(" 证书外泄监测")
        print("=" * 70)
        print("  目标站点 : %s" % target)
        print("  本机证书 : %d 张" % len(local))
        print("  对方收录 : %d 张（本次扫到）" % len(remote))
        print("  命中     : %d 张（其中新增 %d）" % (len(hits), len(new_hits)))
        print("-" * 70)
        if hits:
            for h in hits:
                tag = "【新】" if h in new_hits else "      "
                print("  %s %-10s uid=%-7s issuer_sn=%-11s %s"
                      % (tag, h["callsign"], h["uid"], h["issuer_sn"],
                         h.get("remote_verify_status") or ""))
                print("       指纹: %s" % h["fingerprint"])
                if h.get("last_seen"):
                    print("       对方最后见到: %s" % h["last_seen"])
        else:
            print("  干净：对方站点没有收录我们的任何证书")
        print("=" * 70)
    return (2 if hits else 0), result


# ---------------------------------------------------------------- 通知

def alert(msg, cmd=None):
    """发通知：优先用传入的命令（消息走 stdin），否则写日志 + stderr。"""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "[%s] %s" % (stamp, msg)
    print(line, file=sys.stderr if not cmd else sys.stdout)
    if cmd:
        try:
            subprocess.run(shlex.split(cmd), input=msg.encode("utf-8"),
                           timeout=30, check=False)
        except Exception as e:  # noqa: BLE001
            print("[告警推送失败] %s: %s" % (cmd, e), file=sys.stderr)
    # 无论是否推送成功，都落一份告警日志，便于事后查
    try:
        with open(os.path.join(BASE, "leak_watch_alerts.log"), "a",
                  encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:  # noqa: BLE001
        pass


def daemon(interval, target, alert_cmd):
    alert("证书外泄监测已启动（每 %d 秒检查一次，目标 %s）" % (interval, target), alert_cmd)
    last_state = None
    while True:
        try:
            code, res = check(target=target, quiet=True)
            if code == 2 and res:
                nh = res.get("new_hit_list") or []
                if nh:
                    lines = ["发现 %d 张新证书被第三方台账站收录：" % len(nh)]
                    for h in nh[:20]:
                        lines.append("  %s uid=%s issuer_sn=%s 指纹=%s"
                                     % (h["callsign"], h["uid"], h["issuer_sn"],
                                        h["fingerprint"][:20]))
                    lines.append("")
                    lines.append("站点: %s" % target)
                    alert("\n".join(lines), alert_cmd)
                elif last_state != "hit":
                    alert("对方站点仍收录我方 %d 张证书（无新增）" % res.get("hits", 0),
                          alert_cmd)
                last_state = "hit"
            elif code == 0:
                if last_state == "hit":
                    alert("外泄已清除：对方站点不再收录我方证书", alert_cmd)
                last_state = "clean"
            else:
                last_state = "error"
        except Exception as e:  # noqa: BLE001
            alert("监测异常: %s" % e, alert_cmd)
        time.sleep(max(60, int(interval)))


def install_cron(interval_min=60):
    """装成 cron 任务（每小时检查；发现新外泄才发通知）。"""
    script = os.path.abspath(__file__)
    log = os.path.join(BASE, "leak_watch.log")
    line = ("*/%d * * * * root /usr/bin/python3 %s daemon --interval %d "
            "--once-alert >> %s 2>&1" % (interval_min, script, interval_min * 60, log))
    cron = "/etc/cron.d/fmo-leak-watch"
    try:
        with open(cron, "w", encoding="utf-8") as f:
            f.write("# FMO 证书外泄监测（自动化）\nSHELL=/bin/bash\nPATH=/usr/local/sbin:"
                    "/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n" + line + "\n")
        os.chmod(cron, 0o644)
        print("已安装 cron: %s" % cron)
        print("  %s" % line)
    except Exception as e:  # noqa: BLE001
        print("安装 cron 失败（可能需要 root）: %s" % e)
        print("可手动加入 crontab：")
        print("  %s" % line)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description="第三方台账站证书外泄监测")
    ap.add_argument("--target", default=DEFAULT_TARGET, help="台账站根地址")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="检查一次")
    c.add_argument("--json", action="store_true")

    d = sub.add_parser("daemon", help="常驻循环检查")
    d.add_argument("--interval", type=int, default=3600, help="间隔秒，默认 3600")
    d.add_argument("--alert-cmd", default=os.environ.get("FMO_ALERT_CMD", ""),
                   help="告警命令（消息走 stdin），如 notify_admin.sh")
    d.add_argument("--once-alert", action="store_true", help="仅在有新外泄时告警")

    i = sub.add_parser("install-cron", help="安装每分钟/每小时定时任务")
    i.add_argument("--interval-min", type=int, default=60)

    args = ap.parse_args()
    if args.cmd == "check":
        code, _ = check(target=args.target, as_json=args.json)
        sys.exit(code)
    elif args.cmd == "daemon":
        daemon(args.interval, args.target, args.alert_cmd)
    elif args.cmd == "install-cron":
        sys.exit(install_cron(args.interval_min))


if __name__ == "__main__":
    main()
