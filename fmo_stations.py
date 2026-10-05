# -*- coding: utf-8 -*-
"""
FMO 站点目录（可以进入的中继 / 服务器）
=======================================
「FMO 房间」在网络里就是一个个 **FMO 站**（中继/服务器）。每个站在 MQTT 上
广播一张二进制「站点名片」`FMO/SERVER_INFO`：站号 + 呼号 + 站名 + 简介。
用户拿证书连上某个站的 broker 就等于「进入」该站。

本模块负责把三路数据合并成一份站点列表（任一路不可用都不影响其余）：

  1. **MQTT 抄收**（实时、最可信）：monitor 累积的 SERVER_INFO 站点名片。
     多站共用一个 broker 时会自动逐个出现。
  2. **总系统登记**：总系统的 subsystems 表登记了全网各站（站名、域名、用户数）。
     优先走 HTTP API；API 不可用时（实测总系统 /api/subsystems 会挂住）
     退化为**只读**直连总系统 SQLite（同机部署时可用）。
  3. **本机自身**：永远在列表里，标为「本机」。

⚠️ 只读：直连总系统库一律用 `mode=ro`，绝不写对方的库。
"""

import json
import os
import sqlite3
import time

# 总系统库的常见位置（同机部署时用；也可用 config.master_db_path 显式指定）
MASTER_DB_CANDIDATES = [
    "/volume1/homes/fmo-master-deploy/127.0.0.1_master.db",
    "/opt/fmo-master/127.0.0.1_master.db",
    "/opt/fmo-master/master.db",
]

OFFLINE_AFTER_SEC = 1800.0      # 超过该时长没有上报 → 视为离线


def _now():
    return time.time()


def parse_mqtt_name(raw):
    """把总系统库里存的 mqtt_name（站点名片）解成结构化字段。

    库里可能存成 bytes 或已解码的 str；统一转回字节后交给 monitor.parse_server_info。
    解析失败返回 {}（不抛异常——总系统数据脏不该让页面挂掉）。
    """
    if raw is None:
        return {}
    try:
        if isinstance(raw, str):
            data = raw.encode("utf-8", "surrogateescape")
        else:
            data = bytes(raw)
    except Exception:
        return {}
    if not data:
        return {}
    try:
        from monitor import parse_server_info
    except Exception:
        return {}
    info = parse_server_info(data)
    return info or {}


def find_master_db(explicit=None):
    """定位总系统库（只读用途）。找不到返回 ''。"""
    cands = []
    if explicit:
        cands.append(explicit)
    cands.extend(MASTER_DB_CANDIDATES)
    for p in cands:
        try:
            if p and os.path.isfile(p):
                return p
        except Exception:
            continue
    return ""


def read_master_subsystems(db_path):
    """
    只读读取总系统的 subsystems 表 → 站点列表。
    打不开或表不存在时返回 []（调用方据此降级）。
    """
    if not db_path:
        return []
    out = []
    try:
        uri = "file:%s?mode=ro" % db_path.replace("?", "%3f").replace("#", "%23")
        conn = sqlite3.connect(uri, uri=True, timeout=3.0)
        conn.row_factory = sqlite3.Row
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(subsystems)")}
            if not cols:
                return []
            rows = conn.execute("SELECT * FROM subsystems").fetchall()
        finally:
            conn.close()
    except Exception:
        return []

    for r in rows:
        d = dict(r)
        info = parse_mqtt_name(d.get("mqtt_name"))
        last_report = 0.0
        try:
            last_report = float(d.get("last_report") or 0)
        except Exception:
            last_report = 0.0
        try:
            total = int(d.get("total_users") or 0)
        except Exception:
            total = 0
        try:
            online = int(d.get("online_users") or 0)
        except Exception:
            online = 0
        out.append({
            "subsystem_id": d.get("subsystem_id") or "",
            "callsign": (info.get("callsign") or "").upper(),
            "name": info.get("name") or d.get("name") or "",
            "desc": info.get("desc") or "",
            "station_no": info.get("station_no"),
            "domain": d.get("domain") or "",
            "api_url": d.get("api_url") or "",
            "total_users": total,
            "online_users": online,
            "last_report": last_report,
            "source": "master",
        })
    return out


def _default_port(api_url):
    """从 api_url 里取端口，取不到用 35928。"""
    try:
        tail = str(api_url).rsplit(":", 1)[-1].split("/")[0]
        n = int(tail)
        if 0 < n < 65536:
            return n
    except Exception:
        pass
    return 35928


def entry_url(station):
    """「进入」地址：APP 连这个站用的地址。"""
    api = str(station.get("api_url") or "").strip()
    if api:
        return api.rstrip("/")
    dom = str(station.get("domain") or "").strip()
    if not dom:
        return ""
    if dom.startswith("http://") or dom.startswith("https://"):
        return dom.rstrip("/")
    return "http://%s:%d" % (dom, _default_port(api))


def merge_stations(master_rows, mqtt_stations, self_info=None,
                   now=None):
    """
    合并三路数据 → 站点列表（去重键：呼号；无呼号时退回域名）。

    master_rows   : read_master_subsystems() 的结果
    mqtt_stations : monitor.stations() 的结果（实时抄收的名片）
    self_info     : {'callsign','name','desc','domain','api_url'} 本机站点
    """
    now = now or _now()
    merged = {}

    def key_of(cs, dom, sid):
        if cs:
            return "cs:" + cs.upper()
        if dom:
            return "dom:" + dom.lower()
        return "sid:" + (sid or "?")

    for row in master_rows or []:
        k = key_of(row.get("callsign"), row.get("domain"), row.get("subsystem_id"))
        merged[k] = dict(row)

    for st in mqtt_stations or []:
        cs = (st.get("callsign") or "").upper()
        k = key_of(cs, "", "")
        cur = merged.get(k)
        live = {
            "callsign": cs,
            "name": st.get("name") or "",
            "desc": st.get("desc") or "",
            "station_no": st.get("station_no"),
            "last_seen": st.get("last_seen"),
            "mqtt_live": True,
            "source": "mqtt",
        }
        if cur:
            # 实时抄收的站名/简介优先（总系统登记可能落后）
            if live["name"]:
                cur["name"] = live["name"]
            if live["desc"]:
                cur["desc"] = live["desc"]
            if live["station_no"] is not None:
                cur["station_no"] = live["station_no"]
            cur["last_seen"] = live["last_seen"]
            cur["mqtt_live"] = True
            cur["source"] = "master+mqtt"
        else:
            merged[k] = live

    if self_info:
        cs = (self_info.get("callsign") or "").upper()
        k = key_of(cs, self_info.get("domain"), self_info.get("subsystem_id"))
        cur = merged.get(k)
        if cur:
            cur["is_self"] = True
            if not cur.get("name") and self_info.get("name"):
                cur["name"] = self_info["name"]
            if not cur.get("desc") and self_info.get("desc"):
                cur["desc"] = self_info["desc"]
            if self_info.get("domain"):
                cur["domain"] = self_info["domain"]
            if self_info.get("api_url"):
                cur["api_url"] = self_info["api_url"]
        else:
            merged[k] = {
                "callsign": cs,
                "name": self_info.get("name") or "",
                "desc": self_info.get("desc") or "",
                "domain": self_info.get("domain") or "",
                "api_url": self_info.get("api_url") or "",
                "source": "self",
                "is_self": True,
            }

    out = []
    for st in merged.values():
        last_report = st.get("last_report") or 0
        online = False
        if last_report:
            try:
                online = (now - float(last_report)) < OFFLINE_AFTER_SEC
            except Exception:
                online = False
        st["online"] = bool(online)
        st["entry_url"] = entry_url(st)
        out.append(st)

    # 排序：本机最前 → 在线优先 → 用户数多优先 → 站号 → 名字
    out.sort(key=lambda s: (
        0 if s.get("is_self") else 1,
        0 if s.get("online") else 1,
        -(int(s.get("total_users") or 0)),
        s.get("station_no") if isinstance(s.get("station_no"), int) else 999,
        s.get("name") or "",
    ))
    return out


def build_station_payload(config, mqtt_stations=None, self_info=None,
                          master_db_path=None, now=None):
    """组装页面/接口用的完整响应（含数据源状态，方便排障）。"""
    cfg = config or {}
    db = find_master_db(master_db_path or cfg.get("master_db_path"))
    master_rows = read_master_subsystems(db) if db else []
    stations = merge_stations(master_rows, mqtt_stations, self_info, now=now)
    return {
        "ok": True,
        "generated_at": now or _now(),
        "stations": stations,
        "sources": {
            "mqtt_live": len([s for s in stations if s.get("mqtt_live")]),
            "master_db": db or "",
            "master_rows": len(master_rows),
            "self": bool(self_info),
            "note": ("" if db else
                     "未找到总系统库：只显示本机 MQTT 抄收到的站点。"
                     "可在 config.json 配置 master_db_path 指向总系统库。"),
        },
    }


# ============================================================
#  台站扫描：主动探测每个站，通了才算「可以通过」
# ============================================================
# 「能不能进这个站」最终要靠**实际探测**：站点名片谁都会广播，但站是不是活着、
# 端口通不通，只有打一次健康接口才知道。
#
# 探测目标：<进入地址>/api/health（各站公网 API 口都有这个探活端点，
# 返回 {"ok": true}）。判定通过 = HTTP 200 且响应体含 "ok"。
#
# 安全：本接口只在管理口(35929)暴露；目标地址来自总系统登记表/本机，
# 仍强制 http(s) 协议、限制响应体大小与超时，避免被当成任意请求跳板。

SCAN_TIMEOUT = 3.0            # 单站探测超时（秒）
SCAN_WORKERS = 8              # 并发数
SCAN_MAX_BYTES = 4096         # 只读响应体前若干字节
SCAN_PATH = "/api/health"


def _probe_once(url, timeout):
    import urllib.error
    import urllib.request
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "FUS-station-scan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(SCAN_MAX_BYTES).decode("utf-8", "replace")
            code = getattr(r, "status", None) or r.getcode()
        ms = int((time.time() - t0) * 1000)
        passed = (code == 200) and ('"ok"' in body.replace(" ", "")
                                    or '"ok":true' in body.replace(" ", ""))
        return {"ok": bool(passed), "code": code, "ms": ms,
                "error": "" if passed else "响应异常"}
    except urllib.error.HTTPError as e:
        return {"ok": False, "code": e.code,
                "ms": int((time.time() - t0) * 1000),
                "error": "HTTP %s" % e.code}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "code": 0,
                "ms": int((time.time() - t0) * 1000),
                "error": _short_err(e)}


def _short_err(e):
    s = str(e) or e.__class__.__name__
    for k, v in (("timed out", "超时"), ("Connection refused", "拒绝连接"),
                 ("Name or service not known", "域名解析失败"),
                 ("No route to host", "无法路由"),
                 ("Network is unreachable", "网络不可达")):
        if k in s:
            return v
    return s[:60]


def probe_station(station, timeout=SCAN_TIMEOUT):
    """探测单个站是否「可以通过」。返回 (ok, detail)。"""
    url = station.get("entry_url") or ""
    if not url:
        return False, {"ok": False, "code": 0, "ms": 0, "error": "无进入地址"}
    if not url.startswith(("http://", "https://")):
        return False, {"ok": False, "code": 0, "ms": 0, "error": "地址协议不支持"}
    detail = _probe_once(url.rstrip("/") + SCAN_PATH, timeout)
    return bool(detail.get("ok")), detail


def scan_stations(stations, timeout=SCAN_TIMEOUT, workers=SCAN_WORKERS,
                  only_reachable=True):
    """
    并发扫描全部台站。返回 (stations_with_scan, summary)。

    每站写入 station['scan'] = {ok, code, ms, error}，
    station['reachable'] = bool（只有探测通过才算通过）。
    only_reachable=True 时结果里只保留探测通过的站（「通过就显示」）。
    """
    items = list(stations or [])
    if not items:
        return [], {"total": 0, "passed": 0, "failed": 0, "elapsed_ms": 0}
    t0 = time.time()

    def job(st):
        ok, detail = probe_station(st, timeout)
        out = dict(st)
        out["reachable"] = ok
        out["scan"] = detail
        return out

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
            scanned = list(ex.map(job, items))
    except Exception:  # noqa: BLE001
        scanned = [job(st) for st in items]      # 退化为串行，仍有结果

    passed = [s for s in scanned if s.get("reachable")]
    failed = [s for s in scanned if not s.get("reachable")]
    # 通过的在前，其次按在线/用户数
    passed.sort(key=lambda s: (0 if s.get("is_self") else 1,
                               -(int(s.get("total_users") or 0))))
    summary = {
        "total": len(scanned),
        "passed": len(passed),
        "failed": len(failed),
        "elapsed_ms": int((time.time() - t0) * 1000),
    }
    if only_reachable:
        return passed, summary
    return passed + failed, summary
