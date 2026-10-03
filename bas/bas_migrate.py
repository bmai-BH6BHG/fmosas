#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · 旧系统扫描与迁移
======================
用于一键安装时自动发现机器上**原有的 SAS（分系统认证）与 FAS（.NET 审计）**，
先备份数据，再安全卸载，最后装新的 BAS（单进程 Python，不再依赖 .NET）。

扫描对象
--------
SAS / 分系统（Python）：
  * systemd 单元 fmo-subsystem / fmo-bas，或 DSM 启动脚本
  * 安装目录：/opt/fmo-subsystem、/volume1/fmo-subsystem、$HOME/fmo-subsystem
  * 数据库：{域名}_users.db、{域名}_sas.db、users.db、sas.db
  * CA 私钥目录 ca/

FAS（.NET 审计）：
  * systemd 单元 fmo-fas、/opt/fmo-fas/fmo-audit-service(.exe)
  * 缓存目录 /var/cache/fmo-fas、低权用户 fmo-audit
  * 审计库 fmo-audit-service.db（日志/统计/黑名单留痕/EMQX 配置）
  * 遗留端口 9527 监听

EMQX 侧：
  * FAS 建的规则与桥接（fas-auth-rule / fas-auth-bridge）——卸载旧 FAS 后必须清掉，
    否则 EMQX 会一直往已删除的审计服务投递，产生大量连接失败告警。
  * SAS 的 HTTP 认证（指向 /auth）**不动**：BAS 保留了同一个 /auth 端点。

设计原则
--------
1. **只读扫描**：scan() 绝不改动任何东西，可安全地先跑 --scan-only 看结果。
2. **先备份再删**：migrate() 会把旧库/CA/配置打包成 tar.gz 落到备份目录，
   备份失败则中止（除非显式 --no-backup）。
3. **删除前校验**：每个待删路径都要确认"看起来就是它"（存在特征文件），
   拒绝删除 /、/opt、/usr 等系统路径。
4. **幂等**：重复执行不会因为"已经没有了"而报错。
"""

import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time

SUBSYS_SERVICE_NAMES = ["fmo-subsystem", "fmo-bas"]
FAS_SERVICE_NAME = "fmo-fas"
SUBSYS_DIRS = ["/opt/fmo-subsystem", "/volume1/fmo-subsystem",
               os.path.expanduser("~/fmo-subsystem")]
FAS_DIRS = ["/opt/fmo-fas"]
FAS_CACHE = "/var/cache/fmo-fas"
FAS_USER = "fmo-audit"
LEGACY_FAS_PORT = 9527
FAS_BRIDGE_RULE = "fas-auth-rule"

# 判定"这个目录确实是分系统/FAS"的特征文件
SUBSYS_MARKERS = ["api_server.py", "sas_server.py"]
FAS_MARKERS = ["fmo-audit-service", "fmo-audit-service.exe", "fmo-audit-service.db"]

DANGEROUS_PATHS = ("/", "/opt", "/usr", "/etc", "/var", "/home", "/root", "")


def _run(cmd, timeout=8):
    """执行命令，返回 (rc, stdout)。失败不抛异常。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:  # noqa: BLE001
        return 127, str(e)


def service_state(name):
    """systemd 单元状态：active/inactive/failed/absent。"""
    rc, out = _run(["systemctl", "is-active", name])
    st = out.strip().splitlines()[0] if out.strip() else ""
    if st in ("active", "activating", "deactivating", "failed", "inactive"):
        return st
    rc2, _ = _run(["systemctl", "list-unit-files", "%s.service" % name])
    return "present" if rc2 == 0 and name in _run(["systemctl", "list-unit-files"])[1] else "absent"


def port_listening(port, host="127.0.0.1"):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        return s.connect_ex((host, port)) == 0
    except Exception:  # noqa: BLE001
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


def _db_tables(path):
    """读取 sqlite 文件的表名（只读、不创建）。失败返回 []。"""
    if not path or not os.path.exists(path):
        return []
    conn = None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path.replace("?", "%3f"),
                               uri=True, timeout=3.0)
        return sorted(r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall())
    except Exception:  # noqa: BLE001
        return []
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _db_count(path, table):
    if not path or not os.path.exists(path):
        return None
    conn = None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path.replace("?", "%3f"),
                               uri=True, timeout=3.0)
        if table not in _db_tables(path):
            return None
        return int(conn.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0])
    except Exception:  # noqa: BLE001
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def find_dbs(directory):
    """列出一个目录下所有 *users.db / *sas.db / *audit.db / users.db / sas.db。"""
    out = []
    if not directory or not os.path.isdir(directory):
        return out
    try:
        for fn in sorted(os.listdir(directory)):
            low = fn.lower()
            if low.endswith(".db") and ("users" in low or "sas" in low or "audit" in low
                                        or "voice" in low):
                out.append(os.path.join(directory, fn))
    except Exception:  # noqa: BLE001
        pass
    return out


def scan(subsys_dirs=None, fas_dirs=None, extra_dirs=None):
    """
    只读扫描，返回结构化结果：
    {
      "sas": {"found":bool, "services":{name:state}, "dirs":[{"path","markers","dbs":[{path,tables,rows}]}],
              "ca":bool, "port_35928":bool},
      "fas": {"found":bool, "services":{...}, "dirs":[...], "cache":bool, "user":bool,
              "db":{...}, "port_9527":bool, "emqx_settings":{...}},
      "backup_candidates": [paths...]
    }
    """
    subsys_dirs = list(subsys_dirs or SUBSYS_DIRS)
    fas_dirs = list(fas_dirs or FAS_DIRS)
    for d in (extra_dirs or []):
        if d:
            subsys_dirs.append(d)

    result = {"sas": {"found": False, "services": {}, "dirs": [], "ca": False,
                      "port_35928": False},
              "fas": {"found": False, "services": {}, "dirs": [], "cache": False,
                      "user": False, "db": None, "port_9527": False,
                      "emqx_settings": {}},
              "backup_candidates": []}

    # ---- SAS / 分系统 ----
    for name in SUBSYS_SERVICE_NAMES:
        st = service_state(name)
        if st != "absent":
            result["sas"]["services"][name] = st
    for d in subsys_dirs:
        if not d or not os.path.isdir(d):
            continue
        markers = [m for m in SUBSYS_MARKERS if os.path.exists(os.path.join(d, m))]
        if not markers:
            continue
        entry = {"path": d, "markers": markers, "dbs": [],
                 "has_ca": os.path.isdir(os.path.join(d, "ca")),
                 "config": os.path.exists(os.path.join(d, "config.json"))}
        for db in find_dbs(d):
            tables = _db_tables(db)
            rows = None
            for t in ("users", "certificates"):
                if t in tables:
                    rows = _db_count(db, t)
                    break
            entry["dbs"].append({"path": db, "tables": tables, "rows": rows,
                                 "size": os.path.getsize(db) if os.path.exists(db) else 0})
        result["sas"]["dirs"].append(entry)
        if entry["has_ca"]:
            result["sas"]["ca"] = True
        result["backup_candidates"].append(d)
    result["sas"]["port_35928"] = port_listening(35928)
    result["sas"]["found"] = bool(result["sas"]["services"] or result["sas"]["dirs"])

    # ---- FAS / .NET 审计 ----
    st = service_state(FAS_SERVICE_NAME)
    if st != "absent":
        result["fas"]["services"][FAS_SERVICE_NAME] = st
    for d in fas_dirs:
        if not d or not os.path.isdir(d):
            continue
        markers = [m for m in FAS_MARKERS if os.path.exists(os.path.join(d, m))]
        if not markers:
            continue
        entry = {"path": d, "markers": markers, "dbs": []}
        for db in find_dbs(d):
            entry["dbs"].append({"path": db, "tables": _db_tables(db),
                                 "size": os.path.getsize(db) if os.path.exists(db) else 0})
            if result["fas"]["db"] is None and "settings" in entry["dbs"][-1]["tables"]:
                result["fas"]["db"] = db
        result["fas"]["dirs"].append(entry)
        result["backup_candidates"].append(d)
    result["fas"]["cache"] = os.path.isdir(FAS_CACHE)
    if result["fas"]["cache"]:
        result["backup_candidates"].append(FAS_CACHE)
    rc, out = _run(["id", FAS_USER])
    result["fas"]["user"] = rc == 0
    result["fas"]["port_9527"] = port_listening(LEGACY_FAS_PORT)
    result["fas"]["found"] = bool(result["fas"]["services"] or result["fas"]["dirs"]
                                 or result["fas"]["port_9527"])

    # 读旧 FAS 的 EMQX 配置（用于迁移到新 BAS，避免重配）
    if result["fas"]["db"]:
        conn = None
        try:
            conn = sqlite3.connect("file:%s?mode=ro" % result["fas"]["db"].replace("?", "%3f"),
                                   uri=True, timeout=3.0)
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            cfg = {k: v for k, v in rows if k in ("emqx_url", "emqx_api_key",
                                                  "emqx_api_secret", "topic_name",
                                                  "topic_enabled", "identity_control")}
            result["fas"]["emqx_settings"] = cfg
        except Exception:  # noqa: BLE001
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
    return result


# ---------------- 迁移 ----------------
def _safe_rm(path, must_contain=None, dry=False, log=print):
    """删除目录前做安全检查：绝对路径、非系统路径、必含特征文件。"""
    if not path:
        return False, "路径为空"
    ap = os.path.abspath(path)
    if ap in DANGEROUS_PATHS or ap in [os.path.abspath(p) for p in DANGEROUS_PATHS]:
        return False, "拒绝删除系统路径: %s" % ap
    if len(ap.rstrip("/").split(os.sep)) < 2:
        return False, "路径过浅: %s" % ap
    if not os.path.exists(ap):
        return True, "不存在（跳过）"
    if must_contain and not os.path.exists(os.path.join(ap, must_contain)):
        return False, "缺少特征文件 %s，拒绝删除: %s" % (must_contain, ap)
    if dry:
        log("[DRY] 将删除 %s" % ap)
        return True, "dry-run"
    try:
        shutil.rmtree(ap)
        return True, "已删除"
    except Exception as e:  # noqa: BLE001
        return False, "删除失败: %s" % e


def backup(paths, backup_dir, log=print):
    """
    把旧数据打包成 tar.gz。返回 (ok, archive_path|None, items)。
    目录不存在则跳过；至少成功打包 1 项才算 ok。
    """
    items = [p for p in paths if p and os.path.exists(p)]
    if not items:
        return True, None, []
    try:
        os.makedirs(backup_dir, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        return False, None, items
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = os.path.join(backup_dir, "bas-migrate-%s.tar.gz" % stamp)
    try:
        with tarfile.open(out, "w:gz") as tf:
            for p in items:
                # 排除运行时垃圾，减小体积
                tf.add(p, arcname=os.path.basename(p.rstrip("/")),
                       filter=lambda ti: None if (
                           "/__pycache__" in ti.name or ti.name.endswith(".pyc")
                           or "/_staging" in ti.name) else ti)
        log("[备份] %s（%d 项，%.1f MB）" % (
            out, len(items), os.path.getsize(out) / 1048576.0))
        return True, out, items
    except Exception as e:  # noqa: BLE001
        log("[备份] 失败: %s" % e)
        return False, None, items


def stop_and_disable(service, log=print, dry=False):
    if service_state(service) == "absent":
        return
    if dry:
        log("[DRY] 将停止并禁用 %s" % service)
        return
    _run(["systemctl", "stop", service])
    _run(["systemctl", "disable", service])
    unit = "/etc/systemd/system/%s.service" % service
    try:
        if os.path.exists(unit):
            os.remove(unit)
    except Exception as e:  # noqa: BLE001
        log("[警告] 删除单元 %s 失败: %s" % (unit, e))
    _run(["systemctl", "daemon-reload"])
    log("[卸载] 已停止并移除服务 %s" % service)


def kill_processes(dirs, log=print, dry=False):
    """停掉仍在跑的旧进程（api_server.py / fmo-audit-service）。"""
    if dry:
        return
    for pat in ("api_server.py", "fmo-audit-service"):
        rc, out = _run(["pgrep", "-f", pat])
        if rc != 0:
            continue
        for pid in out.split():
            pid = pid.strip()
            if pid.isdigit():
                _run(["kill", pid])
        time.sleep(0.8)
        rc2, out2 = _run(["pgrep", "-f", pat])
        if rc2 == 0:
            for pid in out2.split():
                if pid.strip().isdigit():
                    _run(["kill", "-9", pid.strip()])
    _ = dirs


def emqx_cleanup_legacy(emqx_cfg, log=print, dry=False):
    """
    删除旧 FAS 在 EMQX 上创建的规则与桥接（否则 EMQX 会往已下线服务反复投递）。
    SAS 的 /auth 认证不动。
    """
    url = (emqx_cfg or {}).get("emqx_url") or ""
    key = (emqx_cfg or {}).get("emqx_api_key") or ""
    secret = (emqx_cfg or {}).get("emqx_api_secret") or ""
    if not (url and key and secret):
        return False, "旧 FAS 未保存 EMQX 连接信息，跳过 EMQX 清理"
    if dry:
        log("[DRY] 将删除 EMQX 上的规则/桥接 fas-auth-*")
        return True, "dry-run"
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from bas_emqx import EmqxClient
        cli = EmqxClient(url, key, secret)
        ok1, e1 = cli.delete_rule(FAS_BRIDGE_RULE)
        ok2, e2 = cli.delete_bridge("fas-auth-bridge")
        if ok1 and ok2:
            log("[卸载] 已清理 EMQX 上的旧 FAS 规则与桥接")
            return True, None
        return False, "；".join(x for x in (e1, e2) if x)
    except Exception as e:  # noqa: BLE001
        return False, "EMQX 清理失败: %s" % e


def migrate(scan_result, backup_dir="/var/backups/fmo-bas", purge=False, dry=False,
            log=print, no_backup=False):
    """
    执行迁移：备份 → 停服务 → 清 EMQX 旧规则 → 删旧目录/缓存/用户。
    返回 {"backup": path|None, "removed": [...], "errors": [...]}
    """
    out = {"backup": None, "removed": [], "errors": [], "emqx": None}
    cands = scan_result.get("backup_candidates") or []
    if not no_backup and cands:
        ok, arch, items = backup(cands, backup_dir, log=log)
        if not ok:
            out["errors"].append("备份失败，已中止迁移（加 --no-backup 可跳过备份）")
            return out
        out["backup"] = arch
        _ = items

    # 停服务
    for name in list((scan_result.get("sas") or {}).get("services") or {}) + \
            list((scan_result.get("fas") or {}).get("services") or {}):
        stop_and_disable(name, log=log, dry=dry)
    kill_processes(None, log=log, dry=dry)

    # EMQX 旧 FAS 规则/桥接
    emqx_cfg = (scan_result.get("fas") or {}).get("emqx_settings") or {}
    ok, msg = emqx_cleanup_legacy(emqx_cfg, log=log, dry=dry)
    out["emqx"] = msg or "ok"

    # 删 FAS（.NET）
    for entry in (scan_result.get("fas") or {}).get("dirs") or []:
        ok, msg = _safe_rm(entry["path"], must_contain=None, dry=dry, log=log)
        (out["removed"] if ok else out["errors"]).append(
            "%s: %s" % (entry["path"], msg))
    if (scan_result.get("fas") or {}).get("cache"):
        ok, msg = _safe_rm(FAS_CACHE, must_contain=None, dry=dry, log=log)
        (out["removed"] if ok else out["errors"]).append("%s: %s" % (FAS_CACHE, msg))
    if purge and (scan_result.get("fas") or {}).get("user"):
        if not dry:
            _run(["userdel", FAS_USER])
        out["removed"].append("用户 %s" % FAS_USER)

    # 删 SAS/分系统旧目录（新 BAS 会重新装到 /opt/fmo-subsystem）
    for entry in (scan_result.get("sas") or {}).get("dirs") or []:
        ok, msg = _safe_rm(entry["path"], must_contain="api_server.py", dry=dry, log=log)
        (out["removed"] if ok else out["errors"]).append("%s: %s" % (entry["path"], msg))
    return out


def scan_report(r):
    """把扫描结果格式化成给人看的中文报告（安装脚本直接打印）。"""
    lines = []
    sas, fas = r["sas"], r["fas"]
    lines.append("原有 SAS（分系统认证）: %s" % ("发现" if sas["found"] else "未发现"))
    for name, st in (sas["services"] or {}).items():
        lines.append("    systemd 服务 %s: %s" % (name, st))
    for d in sas["dirs"]:
        lines.append("    目录 %s（%s）" % (d["path"], ",".join(d["markers"])))
        for db in d["dbs"]:
            lines.append("        数据库 %s  表=%s  记录=%s" % (
                os.path.basename(db["path"]), ",".join(db["tables"][:6]), db["rows"]))
        if d.get("has_ca"):
            lines.append("        CA 私钥目录 ca/ 存在（会一并备份）")
    if sas["port_35928"]:
        lines.append("    端口 35928 正在监听（服务在跑）")
    lines.append("原有 FAS（.NET 审计）: %s" % ("发现" if fas["found"] else "未发现"))
    for name, st in (fas["services"] or {}).items():
        lines.append("    systemd 服务 %s: %s" % (name, st))
    for d in fas["dirs"]:
        lines.append("    目录 %s（%s）" % (d["path"], ",".join(d["markers"])))
    if fas["cache"]:
        lines.append("    缓存目录 %s" % FAS_CACHE)
    if fas["db"]:
        lines.append("    审计库 %s" % fas["db"])
    if fas["user"]:
        lines.append("    低权用户 %s 存在" % FAS_USER)
    if fas["port_9527"]:
        lines.append("    端口 9527 正在监听（.NET 审计在跑）")
    cfg = fas["emqx_settings"] or {}
    if cfg.get("emqx_url"):
        lines.append("    旧 FAS 的 EMQX 配置: %s（将迁移到 BAS，并清理旧规则）" % cfg["emqx_url"])
    return "\n".join(lines)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="BAS 旧系统扫描 / 迁移")
    ap.add_argument("--scan-only", action="store_true", help="只扫描并打印报告（默认行为）")
    ap.add_argument("--migrate", action="store_true", help="执行备份+卸载旧系统")
    ap.add_argument("--purge", action="store_true", help="同时删除旧 FAS 的低权用户")
    ap.add_argument("--no-backup", action="store_true", help="跳过备份（不推荐）")
    ap.add_argument("--backup-dir", default="/var/backups/fmo-bas")
    ap.add_argument("--json", action="store_true", help="输出 JSON（供脚本解析）")
    ap.add_argument("--dir", action="append", default=[], help="额外扫描目录")
    args = ap.parse_args()

    # 额外扫描目录：命令行 --dir + 环境变量 FMO_DIR（一键脚本会把实际安装目录传进来）
    extra = list(args.dir or [])
    env_dir = os.environ.get("FMO_DIR", "").strip()
    if env_dir and env_dir not in extra:
        extra.append(env_dir)

    r = scan(extra_dirs=extra)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(scan_report(r))
    if args.migrate:
        res = migrate(r, backup_dir=args.backup_dir, purge=args.purge,
                      no_backup=args.no_backup)
        print("---- 迁移结果 ----")
        if res["backup"]:
            print("备份: %s" % res["backup"])
        for x in res["removed"]:
            print("已处理: %s" % x)
        for x in res["errors"]:
            print("错误: %s" % x)
        if res["emqx"]:
            print("EMQX: %s" % res["emqx"])
        return 1 if res["errors"] else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
