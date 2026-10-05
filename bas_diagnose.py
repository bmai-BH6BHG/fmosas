#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FUS 链路自检（单文件，可直接 curl 下来运行，无需依赖）
======================================================
解决两个现象：
  ① 不管谁连进来，审计端都拿不到身份信息（client_attrs 没下发）
  ② 身份验证系统能看到呼号，但排行榜/在线列表看不到这个人

用法（在部署服务器上，root 或有读权限的账号）：
  curl -fsSL https://github.com/bmai-BH6BHG/fmosas/releases/latest/download/bas-diagnose.py | python3 - --base-dir /opt/fmo-subsystem
  或本地已装：python3 bas_diagnose.py --diagnose --base-dir /opt/fmo-subsystem

它会查：
  1) EMQX 版本（client_attrs 需 ≥5.7.0；acl 需 ≥5.8.0）
  2) EMQX 的 HTTP 认证器：URL 是否指向本服务 /auth、method、请求体是否带 username/password
  3) **真实在线客户端的 client_attrs 是否为空**（最直接证据：拉 /clients 看 attrs）
  4) 是否有别的认证器排在前面抢跑；认证是否绑在别的监听器上
  5) FUS 审计库近 24 小时的身份事件分布（无身份/伪造/非法包）
  6) 分系统 /auth 是否可达、是否被白名单 403

退出码：0 = 链路正常；1 = 有问题（输出里带【修法】）
"""

import base64
import glob
import json
import os
import socket
import sqlite3
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


# ---------------------------------------------------------------- 基础
def _req(method, url, data=None, headers=None, timeout=8):
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = data if isinstance(data, (bytes, bytearray)) else json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def _jget(status, text):
    try:
        return json.loads(text) if text else None
    except Exception:  # noqa: BLE001
        return None


class Emqx(object):
    def __init__(self, url, key, secret, timeout=8):
        u = str(url or "").strip()
        if u and "://" not in u:
            u = "http://" + u
        self.base = u.rstrip("/")
        self.key = key or ""
        self.secret = secret or ""
        self.timeout = timeout

    def _auth(self):
        raw = ("%s:%s" % (self.key, self.secret)).encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def get(self, path, auth=True, timeout=None):
        headers = self._auth() if auth else {}
        return _req("GET", self.base + path, headers=headers,
                    timeout=timeout or self.timeout)

    def version(self):
        st, tx = self.get("/api/v5/nodes")
        d = _jget(st, tx)
        rows = d if isinstance(d, list) else (d or {}).get("data", [])
        if rows and isinstance(rows[0], list):
            rows = rows[0]
        return (rows[0].get("version", "") if rows else ""), st, tx[:160]

    def ping(self):
        st, _ = self.get("/status", auth=False, timeout=5)
        return st == 200


def ver_tuple(v):
    try:
        p = [int(x) for x in str(v).split(".")[:3]]
        while len(p) < 3:
            p.append(0)
        return (p[0], p[1])
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- 配置读取
def read_cfg(base_dir):
    """从审计库/配置文件读 EMQX 连接信息与端口。"""
    out = {"emqx_url": "", "key": "", "secret": "", "port": 35928, "topic": "FMO/RAW"}
    dbs = glob.glob(os.path.join(base_dir, "*_audit.db"))
    for db in dbs:
        try:
            conn = sqlite3.connect("file:%s?mode=ro" % db.replace("?", "%3f"),
                                   uri=True, timeout=3)
            rows = dict(conn.execute("SELECT key, value FROM settings").fetchall())
            conn.close()
            out["emqx_url"] = out["emqx_url"] or rows.get("emqx_url", "")
            out["key"] = out["key"] or rows.get("emqx_api_key", "")
            out["secret"] = out["secret"] or rows.get("emqx_api_secret", "")
            out["topic"] = rows.get("topic_name") or out["topic"]
        except Exception:  # noqa: BLE001
            continue
    cfg = os.path.join(base_dir, "config.json")
    if os.path.exists(cfg):
        try:
            with open(cfg, encoding="utf-8-sig") as f:
                out["port"] = int(json.load(f).get("port", 35928))
        except Exception:  # noqa: BLE001
            pass
    return out


# ---------------------------------------------------------------- 检查项
def check_sas_auth(port, sas_url=None):
    """SAS /auth 可达性 + 空请求响应形状。"""
    url = sas_url or ("http://127.0.0.1:%d/auth" % port)
    st, tx = _req("POST", url, data={})
    return {"url": url, "status": st, "body": tx[:300]}


def check_emqx_authn(emqx):
    """
    认证器清单：URL / method / body 模板 / precondition / 监听器绑定。
    注意：列表接口往往不含 method/body/precondition，必须逐项拉详情；
    详情拉不到时**不能据此误报**（用 have_detail 标记）。
    """
    res = {"chains": [], "items": []}

    def _fetch_detail(aid):
        st, tx = emqx.get("/api/v5/authentication/" + urllib.parse.quote(str(aid), safe=""))
        d = _jget(st, tx)
        return d if isinstance(d, dict) else None

    st, tx = emqx.get("/api/v5/authentication")
    d = _jget(st, tx)
    # ⚠️ EMQX 5.8.9 实测：/api/v5/authentication 返回**裸数组**（不是 {"data":[...]}）
    if isinstance(d, list):
        rows = d
    elif isinstance(d, dict):
        rows = d.get("data") or []
    else:
        rows = []
    for a in (rows or []):
        if not isinstance(a, dict):
            continue
        det = {"scope": "global", "id": a.get("id"),
               "backend": a.get("backend") or a.get("type"),
               "url": a.get("url"), "method": None, "body_keys": None,
               "headers": None, "precondition": None, "have_detail": False}
        if a.get("id"):
            d2 = _fetch_detail(a["id"])
            if d2 is not None:
                det["have_detail"] = True
                det["method"] = d2.get("method") or a.get("method")
                det["url"] = d2.get("url") or det["url"]
                det["body_keys"] = sorted((d2.get("body") or {}).keys())
                det["headers"] = sorted((d2.get("headers") or {}).keys())
                det["precondition"] = d2.get("precondition")
        res["items"].append(det)

    # 监听器级认证链
    st3, tx3 = emqx.get("/api/v5/listeners")
    d3 = _jget(st3, tx3)
    lst_rows = d3 if isinstance(d3, list) else ((d3 or {}).get("data") or [])
    for l in lst_rows:
        if not isinstance(l, dict):
            continue
        lid = l.get("id") or ""
        if not lid:
            continue
        st4, tx4 = emqx.get("/api/v5/listeners/%s/authentication" % urllib.parse.quote(lid, safe=""))
        d4 = _jget(st4, tx4)
        chain = d4 if isinstance(d4, list) else ((d4 or {}).get("data") or [])
        if chain:
            res["chains"].append({"listener": lid, "running": l.get("running"),
                                  "items": [{"id": c.get("id"), "backend": c.get("backend"),
                                             "url": c.get("url")} for c in chain]})
    return res


def check_live_clients(emqx, sample=20):
    """
    最直接的证据：真实在线客户端的 client_attrs 是否为空。
    返回 {total, with_callsign, without, samples:[...]}
    """
    out = {"total": 0, "with_callsign": 0, "without": 0, "samples": [], "error": None}
    st, tx = emqx.get("/api/v5/clients?limit=200")
    d = _jget(st, tx)
    if not d:
        out["error"] = "HTTP %s %s" % (st, tx[:120])
        return out
    rows = d.get("data", d if isinstance(d, list) else [])
    out["total"] = len(rows)
    for c in rows:
        attrs = c.get("client_attrs") or {}
        cs = (attrs.get("callsign") or "") if isinstance(attrs, dict) else ""
        if cs:
            out["with_callsign"] += 1
        else:
            out["without"] += 1
        if len(out["samples"]) < sample:
            out["samples"].append({
                "clientid": c.get("clientid"), "username": c.get("username"),
                "client_attrs": attrs if isinstance(attrs, dict) else str(attrs)[:60],
                "ip": c.get("ip_address"),
            })
    return out


def check_audit_db(base_dir):
    dbs = glob.glob(os.path.join(base_dir, "*_audit.db"))
    if not dbs:
        return {"found": False}
    out = {"found": True, "db": dbs[0], "scenes": {}, "recent": []}
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % dbs[0].replace("?", "%3f"), uri=True, timeout=3)
        out["scenes"] = dict(conn.execute(
            "SELECT scene, COUNT(*) FROM audit_packets GROUP BY scene").fetchall())
        out["recent"] = [list(r) for r in conn.execute(
            "SELECT ts, verdict, scene, conn_callsign, pkt_callsign, clientid "
            "FROM audit_packets ORDER BY id DESC LIMIT 5").fetchall()]
        out["stats_rows"] = dict(conn.execute(
            "SELECT 'minute_stats', COUNT(*) FROM minute_stats UNION ALL "
            "SELECT 'topic_stats', COUNT(*) FROM topic_stats").fetchall())
        conn.close()
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


# ---------------------------------------------------------------- MQTT 监听器认证探测
#
# 为什么需要它：光看 EMQX 配置容易误判，最直接的判据是"用错误凭据能不能连上"。
#   CONNACK rc=4/5 → 认证链在工作（拒绝了不存在的账号）
#   CONNACK rc=0   → 错误凭据也被接受 = 该监听器**没启用认证**（匿名放行）
#                    → 客户端不经过 SAS，连接上永远不会有 client_attrs
#   无 CONNACK     → 端口需要 TLS（8883）或不是 MQTT

_PROBE_RC = {0: "accepted（被接受）", 1: "unacceptable protocol version",
             2: "identifier rejected", 3: "server unavailable",
             4: "bad user name or password", 5: "not authorized（认证拒绝）"}


def _mqtt_str(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def _mqtt_connect(clientid, username, password, keepalive=10, proto=4):
    """构造 MQTT 3.1.1 CONNECT（足够短，剩余长度单字节）"""
    flags = 0x02                                    # clean session
    payload = _mqtt_str(clientid)
    if username is not None:
        flags |= 0x80
        payload += _mqtt_str(username)
    if password is not None:
        flags |= 0x40
        payload += _mqtt_str(password)
    body = _mqtt_str("MQTT") + bytes([proto, flags]) + struct.pack("!H", keepalive) + payload
    return bytes([0x10, len(body)]) + body


def mqtt_auth_probe(host="127.0.0.1", port=1883, timeout=6, tls=False):
    """
    用**故意错误的凭据**连一次 MQTT，据 CONNACK 判断该监听器是否启用了认证。
    返回 {"port","connected","connack_rc","verdict","raw","error"}
    verdict: auth_enforced / anonymous / no_connack / not_mqtt / unreachable
    """
    out = {"port": port, "connected": False, "connack_rc": None, "verdict": "unreachable",
           "raw": "", "error": None}
    s = None
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        out["connected"] = True
        s.sendall(_mqtt_connect("bas-probe-%d" % int(time.time()),
                                "PROBE_NO_SUCH_USER", "probe-invalid-credential"))
        try:
            data = s.recv(16)
        except socket.timeout:
            data = b""
            out["error"] = "等待 CONNACK 超时"
        out["raw"] = data.hex()
        if data and (data[0] >> 4) == 2 and len(data) >= 4:
            out["connack_rc"] = data[3]
            out["verdict"] = "anonymous" if data[3] == 0 else "auth_enforced"
        elif data:
            out["verdict"] = "not_mqtt"
            out["error"] = "非 CONNACK 响应: %s" % data.hex()
        else:
            out["verdict"] = "no_connack"
            if not out["error"]:
                out["error"] = "对端未回 CONNACK 就关闭了连接"
    except ssl.SSLError as e:
        out["verdict"] = "no_connack"
        out["error"] = "TLS 握手失败（该端口需要 TLS）: %s" % e
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
    return out


def check_mqtt_listeners(host="127.0.0.1", ports=(1883, 8083)):
    """
    探测常用明文 MQTT 监听器是否启用了认证。8083 是 WebSocket，
    用裸 TCP CONNECT 探测会拿不到 CONNACK（属正常），会标注出来。
    """
    results = []
    for p in ports:
        r = mqtt_auth_probe(host, p)
        r["kind"] = "tcp" if p == 1883 else ("ws" if p in (8083, 8084) else "?")
        results.append(r)
    return results


# ---------------------------------------------------------------- 聚合入口
def diagnose(emqx_url=None, key=None, secret=None, sas_url=None, base_dir=None,
             audit_db=None, do_probe=True):
    """
    身份链路诊断的**聚合入口**（管理后台「运行诊断」按钮走的就是它）。

    回答一个核心问题：**为什么 client_attrs 没下发 / 身份信息缺失**，
    以及"认证链会不会把所有人的收发权限都拒掉"。

    返回 {"ok": bool, "findings": [...], "facts": {...}}
      findings[]: {level: fatal|warn|info, code, title, detail, fix}
      facts{}   : 与前端约定一致
        emqx_url / emqx_version / emqx_reachable / http_authn_count
        authn_detail[{id,method,body_keys}] / other_authn[{backend}]
        audit_scenes_24h / sas_url / live_clients / mqtt_listeners
    """
    base_dir = base_dir or "/opt/fmo-subsystem"
    cfg = read_cfg(base_dir)
    emqx_url = str(emqx_url or cfg.get("emqx_url") or "").strip()
    key = key or cfg.get("key") or ""
    secret = secret or cfg.get("secret") or ""
    sas_url = sas_url or ("http://127.0.0.1:%d/auth" % cfg.get("port", 35928))
    findings = []
    facts = {
        "base_dir": base_dir, "sas_url": sas_url,
        "emqx_url": emqx_url or "-", "emqx_version": "", "emqx_reachable": False,
        "http_authn_count": 0, "authn_detail": [], "other_authn": [],
        "audit_scenes_24h": {}, "live_clients": {}, "mqtt_listeners": [],
    }

    def add(level, code, title, detail="", fix=""):
        findings.append({"level": level, "code": code, "title": title,
                         "detail": detail, "fix": fix})

    # ---------- 1) 分系统 /auth 可达性 ----------
    sas = check_sas_auth(cfg.get("port", 35928), sas_url)
    facts["sas"] = {"status": sas.get("status"), "body": (sas.get("body") or "")[:200]}
    if sas.get("status") in (200, 400, 401):
        add("info", "SAS_OK", "分系统 /auth 可达", "HTTP %s" % sas.get("status"))
    elif sas.get("status") == 403:
        add("fatal", "SAS_403", "/auth 被公网白名单拒绝", (sas.get("body") or "")[:160],
            "EMQX 必须访问公网口（默认 35928）的 /auth，不是管理口 35929")
    else:
        add("fatal", "SAS_UNREACHABLE", "分系统 /auth 连不上",
            "%s → HTTP %s %s" % (sas_url, sas.get("status"), (sas.get("body") or "")[:120]),
            "确认 fmo-subsystem 在跑、端口正确；否则所有客户端都认证不了")

    # ---------- 2) ★ /auth 对"授权探测"必须回 ignore ----------
    # EMQX 的授权源(authz)也打这个端点，只带 username 不带 password。
    # 若这里回 deny → EMQX 会拒绝**所有**客户端的 publish/subscribe
    # （现象：能连上，但谁的话都传不出去、也收不到）。
    st_p, tx_p = _req("POST", sas_url, data={"username": "DIAG_AUTHZ_PROBE"})
    probe_result = ""
    try:
        probe_result = str((_jget(st_p, tx_p) or {}).get("result") or "")
    except Exception:  # noqa: BLE001
        probe_result = ""
    facts["authz_probe"] = {"status": st_p, "result": probe_result,
                            "body": (tx_p or "")[:200]}
    if st_p in (200, 400, 401):
        if probe_result == "ignore":
            add("info", "AUTHZ_PROBE_IGNORE",
                "/auth 对授权探测返回 ignore（正确）",
                "EMQX 的授权源会继续用后面的 ACL 判定，收发权限正常")
        elif probe_result == "deny":
            add("fatal", "AUTHZ_PROBE_DENY",
                "/auth 对「只有 username、没有 password」的请求回了 deny",
                "EMQX 的授权源打的就是这个端点 → 会把**所有已认证客户端**的 "
                "publish/subscribe 全部拒掉",
                "让 /auth 在缺少 password 时返回 {\"result\":\"ignore\"}"
                "（那是授权探测，不是认证请求）")
        else:
            add("warn", "AUTHZ_PROBE_UNKNOWN",
                "/auth 对授权探测返回了非预期结果", "result=%r body=%s"
                % (probe_result, (tx_p or "")[:120]),
                "期望 ignore（放行给后续 ACL）；若 EMQX 配了授权源指向 /auth，请核对")

    # ---------- 3) EMQX 可达 / 版本 ----------
    emqx = Emqx(emqx_url, key, secret)
    if not (emqx_url and key and secret):
        add("fatal", "EMQX_CFG_MISSING", "没有 EMQX API 凭据",
            "审计库里 emqx_url / emqx_api_key / emqx_api_secret 为空",
            "在管理后台填写 EMQX 地址与 API 密钥后重跑诊断")
    else:
        try:
            ver, st_v, tx_v = emqx.version()
            facts["emqx_version"] = ver or ""
            facts["emqx_reachable"] = (st_v == 200)
            if st_v == 200:
                add("info", "EMQX_OK", "EMQX API 可达", "版本 %s" % (ver or "未知"))
                vt = ver_tuple(ver)
                if vt and vt < (5, 7):
                    add("fatal", "EMQX_VER_TOO_OLD",
                        "EMQX 版本过低，不支持 client_attrs",
                        "当前 %s；client_attrs 需要 ≥5.7，acl 需要 ≥5.8" % ver,
                        "升级 EMQX 到 5.8.x（本系统按 5.8.9 验证）")
            else:
                add("fatal", "EMQX_UNREACHABLE", "EMQX API 连不上",
                    "%s/api/v5/nodes → HTTP %s %s" % (emqx_url, st_v, (tx_v or "")[:120]),
                    "核对地址（含端口，默认 18083）、API 密钥是否被重建后失效")
        except Exception as e:  # noqa: BLE001
            add("fatal", "EMQX_UNREACHABLE", "EMQX API 请求异常", str(e),
                "核对地址与 API 密钥")

    # ---------- 4) 认证器链（有没有 HTTP 认证、body 全不全、有没有抢跑） ----------
    if facts["emqx_reachable"]:
        try:
            authn = check_emqx_authn(emqx) or {}
            items = authn.get("items") or []
            http_items, other_items = [], []
            for a in items:
                backend = str(a.get("backend") or "")
                url = str(a.get("url") or "")
                if backend == "http" or url:
                    http_items.append(a)
                    facts["authn_detail"].append({
                        "id": a.get("id"), "method": a.get("method"),
                        "url": url, "body_keys": list(a.get("body_keys") or []),
                        "have_detail": bool(a.get("have_detail")),
                    })
                else:
                    other_items.append(a)
                    facts["other_authn"].append({"id": a.get("id"), "backend": backend})
            facts["http_authn_count"] = len(http_items)
            if not http_items:
                add("fatal", "HTTP_AUTHN_MISSING",
                    "没有指向本系统 /auth 的 HTTP 认证器",
                    "在线客户端的 client_attrs 会全部为空（没经过 SAS）",
                    "EMQX Dashboard → 访问控制 → 认证，新建 HTTP 认证："
                    "URL=%s、Method=POST、Body=%s、mechanism=password_based、"
                    "ssl={\"enable\": false}（不要填 type/listener_id）"
                    % (sas_url, '{"username":"${username}","password":"${password}",'
                                '"clientid":"${clientid}","peerhost":"${peerhost}"}'))
            else:
                for a in facts["authn_detail"]:
                    bk = a.get("body_keys") or []
                    if not a.get("have_detail"):
                        add("warn", "AUTHN_DETAIL_MISSING",
                            "认证器 %s 拉不到详情，无法核对请求体" % a.get("id"),
                            "列表接口不含 method/body，请到 Dashboard 里核对")
                        continue
                    if "username" not in bk or "password" not in bk:
                        add("warn", "AUTHN_BODY_INCOMPLETE",
                            "认证器 %s 的请求体缺少 username/password" % a.get("id"),
                            "body键=%s" % bk,
                            "Body 至少要包含 username 与 password，否则认证必失败")
                    elif "clientid" not in bk or "peerhost" not in bk:
                        add("warn", "AUTHN_BODY_NO_CLIENTID",
                            "认证器 %s 的请求体没有 clientid/peerhost" % a.get("id"),
                            "body键=%s" % bk,
                            "建议补上：{\"username\":\"${username}\","
                            "\"password\":\"${password}\",\"clientid\":\"${clientid}\","
                            "\"peerhost\":\"${peerhost}\"}（APP 签名校验与来源 IP 诊断需要）")
            if other_items:
                add("warn", "AUTHN_OTHER_PRESENT",
                    "同一认证链里还有其它认证器",
                    "其它: %s" % ", ".join(str(x.get("backend")) for x in other_items),
                    "顺序在前的认证器若先通过，客户端就不会经过 SAS → client_attrs 为空；"
                    "建议只保留 HTTP 认证器，或把内置库排到后面")
        except Exception as e:  # noqa: BLE001
            add("warn", "AUTHN_READ_FAIL", "读取认证器配置失败", str(e))

    # ---------- 5) 真实在线客户端的 client_attrs（最直接的证据） ----------
    if facts["emqx_reachable"]:
        try:
            live = check_live_clients(emqx)
            facts["live_clients"] = {
                "total": live.get("total"), "with_callsign": live.get("with_callsign"),
                "without": live.get("without"),
            }
            total = int(live.get("total") or 0)
            without = int(live.get("without") or 0)
            if total and without == total:
                add("fatal", "CLIENTS_NO_ATTRS",
                    "全部 %d 个在线连接都没有身份属性" % total,
                    "样本: %s" % json.dumps(live.get("samples", [])[:5], ensure_ascii=False),
                    "先修上一条 HTTP 认证器问题，然后让客户端**重连**"
                    "（旧连接的属性不会补发）")
            elif without:
                add("warn", "CLIENTS_PARTIAL_ATTRS",
                    "%d/%d 个在线连接没有身份属性" % (without, total),
                    "这些连接多半是在认证链修好之前连上的",
                    "让它们重连即可拿到 client_attrs；"
                    "在此之前它们会被「只许本 APP」规则记入待审（默认不封）")
            elif total:
                add("info", "CLIENTS_ATTRS_OK",
                    "%d 个在线连接都带身份属性" % total, "链路正常")
        except Exception as e:  # noqa: BLE001
            add("warn", "CLIENTS_READ_FAIL", "读取在线客户端失败", str(e))

    # ---------- 6) MQTT 监听器是否真的启用了认证（错误凭据能连上=没启用） ----------
    if do_probe:
        try:
            probes = check_mqtt_listeners("127.0.0.1", (1883, 8083))
            facts["mqtt_listeners"] = [
                {"port": p.get("port"), "verdict": p.get("verdict"),
                 "connack_rc": p.get("connack_rc")} for p in probes]
            for p in probes:
                if p.get("verdict") == "anonymous":
                    add("fatal", "MQTT_AUTH_DISABLED",
                        "监听器 %s 没有启用客户端认证" % p.get("port"),
                        "用错误凭据也能连上（CONNACK rc=0）→ 客户端根本没过 SAS，"
                        "client_attrs 必为空",
                        "给该监听器挂上 HTTP 认证器（见上面的修法），然后重启监听器")
        except Exception as e:  # noqa: BLE001
            add("warn", "MQTT_PROBE_FAIL", "MQTT 监听器探测失败", str(e))

    # ---------- 7) 审计库近况（谁在被判"非本 APP"） ----------
    try:
        ad = check_audit_db(base_dir) or {}
        facts["audit_scenes_24h"] = ad.get("scenes") or {}
        na = int((ad.get("scenes") or {}).get("non_app_client") or 0)
        if na:
            add("warn", "AUDIT_NON_APP",
                "近 24h 有 %d 条「非本 APP 客户端」记录" % na,
                "该规则默认只留证不封禁；若你的策略把它设成了 ban，请注意它只按 clientid 封",
                "确认这些连接确实不是自家 APP 后再收紧策略")
    except Exception as e:  # noqa: BLE001
        add("warn", "AUDIT_READ_FAIL", "读取审计库失败", str(e))

    ok = not any(f["level"] == "fatal" for f in findings)
    if ok:
        add("info", "ALL_OK", "身份链路未发现致命问题",
            "共 %d 项检查，%d 条提示" % (len(findings), sum(
                1 for f in findings if f["level"] != "info")))
    return {"ok": ok, "findings": findings, "facts": facts}


# ---------------------------------------------------------------- 主流程
def main():
    args = sys.argv[1:]
    base_dir = "/opt/fmo-subsystem"
    sas_url = ""
    emqx_url = ""
    key = ""
    secret = ""
    mqtt_host = ""
    mqtt_ports = [1883, 8083]
    no_probe = False
    as_json = "--json" in args
    for i, a in enumerate(args):
        if a == "--base-dir" and i + 1 < len(args):
            base_dir = args[i + 1]
        elif a == "--sas-url" and i + 1 < len(args):
            sas_url = args[i + 1]
        elif a == "--emqx-url" and i + 1 < len(args):
            emqx_url = args[i + 1]
        elif a == "--key" and i + 1 < len(args):
            key = args[i + 1]
        elif a == "--secret" and i + 1 < len(args):
            secret = args[i + 1]
        elif a == "--mqtt-host" and i + 1 < len(args):
            mqtt_host = args[i + 1]
        elif a == "--mqtt-ports" and i + 1 < len(args):
            try:
                mqtt_ports = [int(x) for x in str(args[i + 1]).split(",") if x.strip()]
            except ValueError:
                pass
        elif a == "--no-probe":
            no_probe = True

    cfg = read_cfg(base_dir)
    emqx_url = emqx_url or cfg["emqx_url"]
    key = key or cfg["key"]
    secret = secret or cfg["secret"]
    sas = check_sas_auth(cfg["port"], sas_url)
    report = {"base_dir": base_dir, "sas": sas, "cfg": {k: v for k, v in cfg.items()
                                                       if k != "secret"},
              "findings": []}

    def add(level, code, title, detail="", fix=""):
        report["findings"].append({"level": level, "code": code, "title": title,
                                   "detail": detail, "fix": fix})

    # SAS
    if sas["status"] in (200, 400, 401):
        add("info", "SAS_OK", "分系统 /auth 可达", "HTTP %d" % sas["status"])
    elif sas["status"] == 403:
        add("fatal", "SAS_403", "/auth 被公网白名单拒绝", sas["body"][:160],
            "EMQX 必须访问公网口（默认 35928）的 /auth，不是管理口 35929")
    else:
        add("fatal", "SAS_UNREACHABLE", "分系统 /auth 连不上",
            "%s → HTTP %s %s" % (sas["url"], sas["status"], sas["body"][:120]),
            "确认 fmo-subsystem 在跑、端口正确")

    # ---- MQTT 监听器认证探测：先做，因为它不依赖 EMQX API ----
    # 这是"身份信息为什么缺失"最直接的判据：错误凭据能连上 = 认证没启用。
    def probe_listeners():
        if no_probe:
            return
        try:
            host = mqtt_host or "127.0.0.1"
            probes = check_mqtt_listeners(host, tuple(mqtt_ports))
            report["mqtt_listeners"] = probes
            tcp = [p for p in probes if p["kind"] == "tcp"]
            for p in tcp:
                if p["verdict"] == "anonymous":
                    add("fatal", "MQTT_AUTH_DISABLED",
                        "%s:%d 监听器**没有启用客户端认证**（用错误凭据也能连上）" % (
                            host, p["port"]),
                        "回包 CONNACK rc=0（accepted），原始响应=%s" % (p["raw"] or "-"),
                        "这就是身份信息缺失的根因：客户端根本没经过 SAS → 连接上没有 "
                        "client_attrs。修法：EMQX Dashboard → 访问控制 → 认证 → 在监听器 "
                        "tcp:default 下新建 HTTP 认证：URL=http://<EMQX内网IP>:%d/auth、"
                        'Method=POST、Body={"username":"${username}","password":"${password}"}、'
                        "Precondition 留空" % cfg["port"])
                elif p["verdict"] == "auth_enforced":
                    add("info", "MQTT_AUTH_ENFORCED",
                        "%s:%d 已启用认证（正确拒绝了错误凭据）" % (host, p["port"]),
                        "CONNACK rc=%s（%s）" % (p["connack_rc"], _PROBE_RC.get(p["connack_rc"], "")))
                elif p["verdict"] == "no_connack" and not (p.get("error") or "").startswith("TLS"):
                    add("warn", "MQTT_NO_CONNACK",
                        "%s:%d 未返回 CONNACK" % (host, p["port"]), p.get("error") or "",
                        "可能认证后端异常（SAS 不可达导致链路崩），请查 EMQX 日志")
                elif p["verdict"] == "unreachable":
                    add("info", "MQTT_PORT_CLOSED", "%s:%d 未监听/不可达" % (host, p["port"]))
        except Exception as e:  # noqa: BLE001
            add("warn", "MQTT_PROBE_FAIL", "MQTT 监听器探测失败", str(e))

    probe_listeners()

    if not (emqx_url and key and secret):
        add("fatal", "EMQX_CFG_MISSING", "没有 EMQX API 凭据",
            "审计库里 emqx_url/api_key/api_secret 为空",
            "审计界面→设置 填 EMQX 地址与 API 密钥；安装时可用 EMQX_URL/EMQX_API_KEY/EMQX_API_SECRET")
        _print(report, as_json)
        return 1

    emqx = Emqx(emqx_url, key, secret)
    report["emqx_url"] = emqx_url
    if not emqx.ping():
        add("fatal", "EMQX_UNREACHABLE", "EMQX 不可达", emqx_url,
            "确认地址含 http:// 与 Dashboard 端口（默认 18083）")
        _print(report, as_json)
        return 1

    ver, st, snippet = emqx.version()
    report["emqx_version"] = ver
    vt = ver_tuple(ver)
    if vt and vt < (5, 7):
        add("fatal", "EMQX_VER_TOO_OLD",
            "EMQX %s 低于 5.7.0 → 不会保存认证响应里的 client_attrs" % ver,
            "这是「谁进来都缺身份」的最直接原因：SAS 认证虽然通过（所以身份验证系统能看到呼号），"
            "但 EMQX 5.7 以下会忽略响应里的 client_attrs 字段，连接上就不会有身份属性。",
            "升级 EMQX 到 5.8+（推荐最新的 5.8/5.9 小版本）。升级后客户端重新连接即可带上属性。")
    elif vt:
        add("info", "EMQX_VER_OK", "EMQX %s 支持 client_attrs（acl 需 5.8+）" % ver)

    authn = check_emqx_authn(emqx)
    report["authn"] = authn
    # 先看真实在线客户端的身份属性 —— 后面判断"其它认证器是否有害"要用到
    live = check_live_clients(emqx)
    report["live_clients"] = live
    http_items = [i for i in authn["items"] if str(i.get("backend", "")).lower() == "http"]
    if not http_items:
        add("fatal", "NO_HTTP_AUTHN", "EMQX 上没有指向本服务的 HTTP 认证器",
            "当前认证器: %s" % [i.get("backend") for i in authn["items"]],
            "在 EMQX Dashboard → 访问控制 → 认证 创建 Password-Based + HTTP Server，"
            "URL=http://<本机IP>:%d/auth" % cfg["port"])
    for it in http_items:
        url = str(it.get("url") or "")
        keys = it.get("body_keys")
        if not url.rstrip("/").endswith("/auth"):
            add("warn", "AUTHN_URL_ODD", "HTTP 认证 URL 不是 /auth", "url=%s" % url,
                "SAS 端点是 /auth")
        if it.get("have_detail"):
            if str(it.get("method") or "").lower() != "post":
                add("warn", "AUTHN_METHOD", "认证 method 不是 POST", str(it.get("method")),
                    "改 POST")
            if not keys:
                add("fatal", "AUTHN_BODY_EMPTY", "HTTP 认证请求体为空",
                    "认证器 %s 没有 body 模板" % it.get("id"),
                    'body 设为 {"username":"${username}","password":"${password}"}')
            elif not ({"username", "password"} <= set(keys)):
                add("fatal", "AUTHN_BODY_FIELDS", "HTTP 认证请求体缺少 username/password",
                    "现有键: %s" % keys, 'body 必须含 "username" 与 "password" 两个键')
            else:
                add("info", "AUTHN_BODY_OK", "HTTP 认证请求体正确", "键=%s" % keys)
            if it.get("precondition"):
                add("warn", "AUTHN_PRECONDITION", "HTTP 认证器设了 precondition",
                    str(it["precondition"]),
                    "precondition 不成立的客户端会跳过这个认证器，"
                    "也就拿不到 client_attrs；确认它对该监听器/用户名为 true（或清空）")
        else:
            add("warn", "AUTHN_DETAIL_UNAVAILABLE",
                "无法读取该 HTTP 认证器的详情（无法核验 body/precondition）",
                "认证器 %s（url=%s）" % (it.get("id"), url),
                "在 EMQX Dashboard → 访问控制 → 认证 里手工确认：Method=POST、"
                'Body={"username":"${username}","password":"${password}"}、Precondition 为空')
    others = [i for i in authn["items"] if str(i.get("backend", "")).lower() not in ("http", "")]
    attrs_ok = bool(live.get("with_callsign")) if isinstance(live, dict) else False
    if others:
        # 若在线客户端确实拿到了 client_attrs，说明链路是通的 —— 此时其它后端无害，只提示
        if attrs_ok:
            add("info", "OTHER_AUTHN_HARMLESS",
                "认证链里还有其它后端，但链路已验证可用（客户端已带身份）",
                ", ".join("%s(%s)" % (i.get("id"), i.get("backend")) for i in others))
        else:
            add("warn", "OTHER_AUTHN", "认证链里还有其它后端（可能先命中）",
                ", ".join("%s(%s)" % (i.get("id"), i.get("backend")) for i in others),
                "EMQX 按顺序试；前面的先放行就不会经过 SAS，也就没有身份属性。"
                "建议只留指向 SAS 的 HTTP 认证")
    if authn["chains"]:
        report["listener_chains"] = authn["chains"]

    # （live 已在前面获取）
    if live["error"]:
        add("warn", "CLIENTS_READ_FAIL", "读取在线客户端失败", live["error"])
    elif live["total"] == 0:
        add("warn", "NO_ONLINE_CLIENT", "当前没有在线客户端",
            "", "让一个 APP 连上来再跑一次，才能验证 client_attrs 是否真的下发")
    elif live["with_callsign"] == 0:
        add("fatal", "ATTRS_NOT_ON_CLIENT",
            "在线 %d 个客户端，**没有一个带 callsign 属性**" % live["total"],
            "样例: %s" % json.dumps(live["samples"][:3], ensure_ascii=False),
            "这就是「身份信息缺失 + 排行榜/在线看不到人」的直接原因。"
            "按上面 EMQX_VER_TOO_OLD / AUTHN_* 的结论修，然后让客户端重连。")
    else:
        add("info", "ATTRS_OK",
            "在线 %d 个客户端中 %d 个带 callsign 属性" % (live["total"], live["with_callsign"]))

    # ---- MQTT 监听器认证探测已在前面完成（不依赖 EMQX API）----

    adb = check_audit_db(base_dir)
    report["audit_db"] = adb
    if adb.get("found"):
        miss = sum(v for k, v in (adb.get("scenes") or {}).items()
                   if k in ("both_missing", "attr_missing"))
        if miss:
            add("warn", "AUDIT_ATTR_MISSING", "审计库里有 %d 条无身份记录" % miss,
                "场景分布: %s" % (adb.get("scenes"),),
                "修好链路后这些是历史数据，新连接才会正常")

    _print(report, as_json)
    fatal = [f for f in report["findings"] if f["level"] == "fatal"]
    return 1 if fatal else 0


def _print(r, as_json):
    if as_json:
        print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
        return
    icon = {"fatal": "✗ 必须修", "warn": "! 建议修", "info": "✓"}
    print("=" * 70)
    print("  FUS 链路自检（身份属性下发 + 在线/排行榜可见性）")
    print("=" * 70)
    for f in r["findings"]:
        print("")
        print("%s  [%s] %s" % (icon.get(f["level"], "?"), f["code"], f["title"]))
        if f["detail"]:
            print("     现象: %s" % f["detail"])
        if f["fix"]:
            print("     修法: %s" % f["fix"])
    print("")
    print("-" * 70)
    print("EMQX: %s   版本=%s" % (r.get("emqx_url", "-"), r.get("emqx_version", "-")))
    lv = r.get("live_clients") or {}
    if lv:
        print("在线客户端: %s 个（带 callsign %s / 不带 %s）" % (
            lv.get("total"), lv.get("with_callsign"), lv.get("without")))
        for s in (lv.get("samples") or [])[:5]:
            print("   · clientid=%-24s username=%-10s attrs=%s" % (
                s.get("clientid"), s.get("username"), s.get("client_attrs")))
    adb = r.get("audit_db") or {}
    if adb.get("found"):
        print("审计库: %s" % adb.get("db"))
        print("  场景分布: %s" % adb.get("scenes"))
        print("  统计行数: %s" % adb.get("stats_rows"))
    print("-" * 70)
    print("结论: %s" % ("链路正常" if not any(f["level"] == "fatal" for f in r["findings"])
                       else "有问题，按上面【修法】处理"))


if __name__ == "__main__":
    if "--diagnose" in sys.argv or len(sys.argv) == 1 or sys.argv[1].startswith("--"):
        sys.exit(main())
    sys.exit(main())
