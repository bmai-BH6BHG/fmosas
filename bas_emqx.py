#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · EMQX REST 客户端（移植自 FAS 的 EmqxClient.cs，并修正其已知缺陷）

移植要点（对照 bas/spec/emqx-contract.md）：
  * 认证：Authorization: Basic base64("<apiKey>:<apiSecret>")（Key 与 Secret 拼成一个串）
  * base URL：无 scheme 自动补 http://，末尾去 '/'；业务接口全在 /api/v5 下
  * 探活：GET /status（不带 /api/v5、不带认证）
  * 拉黑：POST /api/v5/banned {as:"username", who, reason, until}
          until=None 时显式传字符串 "infinity"；ALREADY_EXISTS 视为成功
          banned 不会自动踢已连接 → 第二步 GET /api/v5/clients?username=W 取 clientid，
          再 POST /api/v5/clients/kickout/bulk（body 是裸 JSON 字符串数组）
          解封 DELETE /api/v5/banned/username/{who}，NOT_FOUND 视为成功
  * 规则引擎：POST/PUT /api/v5/bridges/webhook:<name>（EMQX 自动生成 http connector，
          链路检查 GET /api/v5/connectors/http:<name>）；bridge body 模板里的
          ${client_attrs} 前后**故意不加引号**（它本身已是 JSON 片段）
          rule SQL：SELECT clientid, username, topic, base64_encode(payload) as payload,
                    qos, timestamp, client_attrs FROM "FMO/RAW/#"
  * pending/failed：原版因 ToApiResult 吞掉错误码而成为死代码；这里用 (info, error, pending)
    元组如实返回——超时 = 状态未知（集群下可能已生效），其它 = 明确失败

相对原版的修正：
  1. 分页：原版只取第一页（limit=1000），在线超 1000 就静默丢数据 → 本实现自动翻页
  2. 集群：原版 /metrics 只取首节点 → 本实现按节点求和
  3. 保留内存单位字符串（"4.69G"）解析与 load1 顶替 CPU% 的语义
"""

import base64
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 15          # 对齐原版 HttpClient 15s
PAGE_LIMIT = 1000             # EMQX 单页上限
MAX_PAGES = 50                # 翻页保护：最多 5 万条
BRIDGE_NAME = "fas-auth-bridge"
RULE_NAME = "fas-auth-rule"
RULE_DESC = "FAS topic rule"

_MEM_RE = re.compile(r"^\s*([\d.]+)\s*([KMGTP]?B?)\s*$", re.IGNORECASE)
_MEM_UNITS = {"": 1, "B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3,
              "TB": 1024 ** 4, "PB": 1024 ** 5,
              "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4, "P": 1024 ** 5}


def parse_byte_size(text):
    """解析 '4.69G' / '512MB' / '1024' → 字节数；无法解析返回 None。"""
    if text is None:
        return None
    if isinstance(text, bool):
        return None
    if isinstance(text, (int, float)):
        return int(text)
    m = _MEM_RE.match(str(text))
    if not m:
        return None
    try:
        val = float(m.group(1))
    except ValueError:
        return None
    return int(val * _MEM_UNITS.get(m.group(2).upper(), 1))


def get_lan_ip():
    """取本机对外网卡 IP（不发包，仅触发路由选择）。对齐原版 GetLanIp。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:  # noqa: BLE001
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:  # noqa: BLE001
            return "127.0.0.1"
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


def normalize_base_url(url):
    u = str(url or "").strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    return u.rstrip("/")


class EmqxError(Exception):
    def __init__(self, message, code=None, kind="error"):
        Exception.__init__(self, message)
        self.code = code
        self.kind = kind      # timeout / network / http / not_configured


def rfc3339(epoch_or_str):
    """
    把时间转成 EMQX `until` 要求的 RFC3339 格式（**必须带时区**）。

    实测 EMQX 5.8.9：
      "2026-10-05T03:00:00+08:00"  → 200 ✓
      "2026-10-05 03:00:00"        → 400 matched_no_union_member
      "infinity"                   → 200 ✓（永久）
    传数字表示"多少小时之后"，传字符串则：
      - "infinity" / 空 → 原样返回
      - 已是 RFC3339 → 原样返回
      - 旧格式 "YYYY-MM-DD HH:MM:SS" → 补本地时区
    """
    if epoch_or_str in (None, ""):
        return "infinity"
    if isinstance(epoch_or_str, (int, float)):
        epoch = time.time() + float(epoch_or_str) * 3600.0
    else:
        s = str(epoch_or_str).strip()
        if s.lower() == "infinity":
            return "infinity"
        if "T" in s and ("+" in s[10:] or s.endswith("Z")):
            return s
        # 旧格式（无时区）→ 解析成 epoch 再补时区
        try:
            epoch = time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
        except Exception:  # noqa: BLE001
            try:
                epoch = time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%S"))
            except Exception:  # noqa: BLE001
                return "infinity"
    lt = time.localtime(epoch)
    base = time.strftime("%Y-%m-%dT%H:%M:%S", lt)
    off = time.strftime("%z", lt)          # +0800
    if off:
        off = off[:3] + ":" + off[3:]      # +08:00
    return base + off


def is_ip_like(value):
    """判断是否像 IP 地址（EMQX 的 peerhost 封禁必须给合法 IP）"""
    s = str(value or "").strip()
    if not s:
        return False
    if ":" in s:                            # IPv6
        return all(c in "0123456789abcdefABCDEF:." for c in s)
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


class EmqxClient(object):
    """EMQX 5.x REST 客户端。无状态 + 每请求独立 opener，线程安全。"""

    def __init__(self, base_url, api_key, api_secret, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.base_url = normalize_base_url(base_url)
        self.api_key = str(api_key or "")
        self.api_secret = str(api_secret or "")
        self.timeout = timeout
        self.verify_tls = verify_tls
        ctx = None if verify_tls else ssl._create_unverified_context()  # noqa: SLF001
        # 对齐原版 UseProxy=false：不读环境代理
        handlers = [urllib.request.ProxyHandler({})]
        handlers.append(urllib.request.HTTPSHandler(context=ctx) if ctx
                        else urllib.request.HTTPSHandler())
        self._opener = urllib.request.build_opener(*handlers)

    # ---------------- 基础请求 ----------------
    def configured(self):
        return bool(self.base_url and self.api_key and self.api_secret)

    def _auth_header(self):
        raw = ("%s:%s" % (self.api_key, self.api_secret)).encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def request(self, method, path, body=None, raw_body=None, auth=True, timeout=None):
        """
        返回 (status, text)；HTTP 4xx/5xx 也返回（不抛），网络/超时抛 EmqxError。
        path 里若含 ':类型前缀'（如 /api/v5/bridges/webhook:name），冒号必须原样保留。
        """
        if not self.base_url:
            raise EmqxError("未配置 EMQX 连接（URL 无效）", kind="not_configured")
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json"}
        if raw_body is not None:
            data = raw_body if isinstance(raw_body, (bytes, bytearray)) else str(raw_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = self._auth_header()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=timeout or self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except socket.timeout:
            raise EmqxError("请求超时", kind="timeout")
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, socket.timeout):
                raise EmqxError("请求超时", kind="timeout")
            raise EmqxError("网络错误: %s" % reason, kind="network")

    def _json(self, method, path, body=None, raw_body=None, expect=(200, 201, 204),
              ok_codes=None, as_text=False):
        """as_text=True 时返回 (status, text)，不解析 JSON。"""
        status, text = self.request(method, path, body=body, raw_body=raw_body)
        if as_text:
            return status, text
        allow = set(expect) | set(ok_codes or ())
        data = None
        if text:
            try:
                data = json.loads(text)
            except ValueError:
                data = None
        if status not in allow:
            msg = text[:300] if text else "HTTP %d" % status
            raise EmqxError("HTTP %d: %s" % (status, msg), code=status)
        return data

    # ---------------- 探活与版本 ----------------
    def ping(self):
        """GET /status（无认证）。返回 (ok, 说明)。"""
        if not self.base_url:
            return False, "未配置 EMQX 地址"
        try:
            status, _ = self.request("GET", "/status", auth=False,
                                     timeout=min(self.timeout, 8))
        except EmqxError as e:
            return False, str(e)
        if status == 200:
            return True, "ok"
        return False, "HTTP %d" % status

    def version(self):
        """取 EMQX 版本（/api/v5/nodes 首元素 version），失败返回 ''。"""
        try:
            nodes = self.list_nodes()
        except EmqxError:
            return ""
        return str((nodes[0].get("version") if nodes else "") or "")

    def is_supported_version(self):
        return self.version().startswith("5.")

    # ---------------- 列表（含翻页修正） ----------------
    @staticmethod
    def _unwrap_list(payload):
        """兼容三种外壳：裸数组 / {data:[...]} / [[...]]（多节点）。"""
        if payload is None:
            return []
        if isinstance(payload, list):
            if payload and isinstance(payload[0], list):
                return payload[0]
            return payload
        if isinstance(payload, dict):
            d = payload.get("data")
            if isinstance(d, list):
                return d
            if isinstance(d, dict):
                return [d]
        return []

    def _paged(self, path_base, query=None, key="data", limit=PAGE_LIMIT, max_pages=MAX_PAGES):
        """
        自动翻页（原版缺失的能力）。EMQX 5.x 用 ?limit=&page=，meta.hasnext/has_next 判续页。
        """
        out = []
        page = 1
        q = dict(query or {})
        q["limit"] = str(limit)
        while page <= max_pages:
            q["page"] = str(page)
            qs = urllib.parse.urlencode(q)
            payload = self._json("GET", "%s?%s" % (path_base, qs))
            rows = payload.get(key) if isinstance(payload, dict) else payload
            if rows is None:
                rows = []
            if isinstance(rows, dict):
                rows = [rows]
            out.extend(rows)
            meta = payload.get("meta") if isinstance(payload, dict) else None
            has_next = None
            if isinstance(meta, dict):
                has_next = meta.get("hasnext")
                if has_next is None:
                    has_next = meta.get("has_next")
            if has_next is None:
                has_next = len(rows) >= limit      # 无 meta 时按满页推断，避免死循环
            if not has_next or not rows:
                break
            page += 1
        return out

    # ---------------- clients ----------------
    def list_clients(self, limit=PAGE_LIMIT, fields=None):
        """
        在线客户端全量（自动翻页）。
        语义：出现在 /clients 列表里 = 在线（原版定义了 connected 字段但从不读）。
        """
        q = {}
        if fields:
            q["fields"] = ",".join(fields)
        raw = self._paged("/api/v5/clients", q, key="data", limit=limit)
        return [self._normalize_client(c) for c in raw if isinstance(c, dict)]

    @staticmethod
    def _normalize_client(c):
        """统一字段名与类型；client_attrs 数值/布尔按 C# TolerantStringDictConverter 归一。"""
        attrs = c.get("client_attrs")
        norm_attrs = {}
        if isinstance(attrs, dict):
            for k, v in attrs.items():
                if v is None:
                    norm_attrs[str(k)] = ""
                elif isinstance(v, bool):
                    norm_attrs[str(k)] = "true" if v else "false"
                elif isinstance(v, (int, float)):
                    norm_attrs[str(k)] = str(v)
                else:
                    norm_attrs[str(k)] = str(v)
        return {
            "clientid": c.get("clientid") or "",
            "username": c.get("username") or "",
            "ip_address": c.get("ip_address") or "",
            "connected_at": c.get("connected_at") or "",
            "connected": c.get("connected", True),
            "recv_msg": int(c.get("recv_msg") or 0),
            "send_msg": int(c.get("send_msg") or 0),
            "recv_pkt": int(c.get("recv_pkt") or 0),
            "send_pkt": int(c.get("send_pkt") or 0),
            "recv_oct": int(c.get("recv_oct") or 0),
            "send_oct": int(c.get("send_oct") or 0),
            "proto_name": c.get("proto_name") or "",
            "proto_ver": c.get("proto_ver"),
            "keepalive": int(c.get("keepalive") or 0),
            "client_attrs": norm_attrs,
            "callsign": norm_attrs.get("callsign", ""),
            "uid": norm_attrs.get("uid", ""),
            "expiry_interval": c.get("expiry_interval"),
            "heap_size": c.get("heap_size"),
            "subscriptions_cnt": c.get("subscriptions_cnt"),
        }

    def clients_by_username(self, username, limit=10000):
        rows = self._paged("/api/v5/clients", {"username": username},
                           key="data", limit=min(limit, PAGE_LIMIT))
        return [self._normalize_client(c) for c in rows if isinstance(c, dict)]

    # ---------------- banned（黑名单） ----------------
    def list_banned(self, limit=PAGE_LIMIT):
        return self._paged("/api/v5/banned", None, key="data", limit=limit)

    def ban(self, who, reason="", as_type="username", until=None):
        """
        拉黑（幂等）。until 支持：
          数字  → 多少小时之后失效（自动转 RFC3339，带本地时区）
          None  → "infinity"（永久；慎用）
          字符串 → RFC3339 / "infinity" / 旧格式（自动补时区）
        as_type ∈ username / clientid / peerhost（peerhost 必须是合法 IP）。
        返回 (ok, error)；ALREADY_EXISTS 视为成功。
        """
        if as_type == "peerhost" and not is_ip_like(who):
            return False, "peerhost 必须是合法 IP，收到: %r" % (who,)
        body = {"as": as_type, "who": who, "reason": reason or "",
                "until": rfc3339(until)}
        try:
            self._json("POST", "/api/v5/banned", body=body, expect=(200, 201, 204))
            return True, None
        except EmqxError as e:
            if e.code == 400 and "ALREADY_EXISTS" in str(e):
                return True, None
            return False, str(e)

    def unban(self, who, as_type="username"):
        path = "/api/v5/banned/%s/%s" % (as_type, urllib.parse.quote(str(who), safe=""))
        try:
            self._json("DELETE", path, expect=(200, 204))
            return True, None
        except EmqxError as e:
            if e.code == 404:
                return True, None       # 不存在 = 已解封
            return False, str(e)

    def unban_strict(self, who, as_type="username"):
        """
        像 unban 一样解封，但**明确区分"真的删掉了"与"本来就没有"**。
        返回 (ok, existed, err)
          ok      : 请求成功（含本来就是 404）
          existed : True=确实删掉了一条封禁；False=该维度本来就没有
        用途：解封时要把三个维度都试一遍，并如实告诉用户到底解掉了什么
        （真实事故：按 clientid 封的，界面只按 username 解 → 显示成功、实际没解）
        """
        path = "/api/v5/banned/%s/%s" % (as_type, urllib.parse.quote(str(who), safe=""))
        try:
            self._json("DELETE", path, expect=(200, 204))
            return True, True, None
        except EmqxError as e:
            if e.code == 404:
                return True, False, None
            return False, False, str(e)

    def kick_clients(self, clientids):
        """批量踢下线：body 是裸 JSON 字符串数组。返回 (ok, error)。"""
        if not clientids:
            return True, None
        try:
            self._json("POST", "/api/v5/clients/kickout/bulk",
                       raw_body=json.dumps(list(clientids)), expect=(200, 204), as_text=True)
            return True, None
        except EmqxError as e:
            return False, str(e)

    def ban_username(self, username, reason="", until=None):
        """
        拉黑并踢下线（两步法，对齐原版 BanAsync）：
          1) POST /banned → 2) GET /clients?username= → POST /clients/kickout/bulk
        踢失败**不回滚** banned。
        返回 (ok, error, kicked_count)
        """
        ok, err = self.ban(username, reason, "username", until)
        if not ok:
            return False, err, 0
        kicked = 0
        try:
            rows = self.clients_by_username(username)
            ids = [r["clientid"] for r in rows if r.get("clientid")]
            if ids:
                k_ok, k_err = self.kick_clients(ids)
                if k_ok:
                    kicked = len(ids)
                else:
                    return True, "已拉黑但踢下线失败: %s" % k_err, 0
        except EmqxError as e:
            return True, "已拉黑但查询在线客户端失败: %s" % e, 0
        return True, None, kicked

    # ---------------- 节点 / 指标 / 告警 ----------------
    def list_nodes(self):
        return self._unwrap_list(self._json("GET", "/api/v5/nodes"))

    def metrics(self):
        """
        /api/v5/metrics：键是带点号的扁平键（messages.received 等）。
        原版只取首节点；本实现按节点求和（多节点更准）。返回 (聚合dict, 节点数)
        """
        payload = self._json("GET", "/api/v5/metrics")
        nodes = payload if isinstance(payload, list) else [payload]
        agg = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for k, v in node.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    agg[k] = agg.get(k, 0) + v
        return agg, len(nodes)

    def alarms(self, activated_only=True):
        q = {"activated": "true"} if activated_only else None
        rows = self._paged("/api/v5/alarms", q, key="data", limit=100)
        names = []
        for a in rows:
            if not isinstance(a, dict):
                continue
            if activated_only and not a.get("activated"):
                continue
            nm = a.get("name") or a.get("message") or ""
            if nm and nm not in names:
                names.append(nm)
        return rows, ", ".join(names)

    def node_health(self):
        """汇总 EMQX 侧健康信息（供审计界面健康页）。"""
        out = {"ok": False, "error": None, "version": "", "nodes": 0,
               "connections": 0, "alive": 0, "alarms": "", "metrics": {}}
        try:
            nodes = self.list_nodes()
            out["nodes"] = len(nodes)
            out["version"] = str((nodes[0].get("version") if nodes else "") or "")
            for n in nodes:
                if isinstance(n, dict):
                    if n.get("node_status") == "running":
                        out["alive"] += 1
                    out["connections"] += int(n.get("connections") or 0)
            m, ncnt = self.metrics()
            out["metrics"] = m
            if not out["nodes"]:
                out["nodes"] = ncnt
            _, alarms = self.alarms(True)
            out["alarms"] = alarms
            out["ok"] = True
        except EmqxError as e:
            out["error"] = str(e)
        return out

    # ---------------- 规则引擎：bridge + rule ----------------
    def _bridge_path(self, name=BRIDGE_NAME):
        # 冒号是类型前缀，绝不能被编码成 %3A
        return "/api/v5/bridges/webhook:%s" % urllib.parse.quote(name, safe="")

    def _connector_path(self, name=BRIDGE_NAME):
        return "/api/v5/connectors/http:%s" % urllib.parse.quote(name, safe="")

    def _bridge_get(self, name=BRIDGE_NAME):
        try:
            return self._json("GET", self._bridge_path(name), as_text=True)
        except EmqxError as e:
            return (e.code or 0), str(e)

    def get_bridge(self, name=BRIDGE_NAME):
        status, text = self._bridge_get(name)
        if status == 200 and ('"name":"%s"' % name) in text.replace(" ", ""):
            try:
                return json.loads(text)
            except ValueError:
                return {}
        return None

    def get_connector(self, name=BRIDGE_NAME):
        status, text = self._json("GET", self._connector_path(name), as_text=True)
        if status == 200:
            try:
                return json.loads(text)
            except ValueError:
                return {}
        return None

    def _bridge_body(self, webhook_url, token, name=BRIDGE_NAME):
        # 注意：client_attrs 前后**故意不加引号**（EMQX 模板里它已是 JSON 片段）
        body_tmpl = ('{"topic":"${topic}","username":"${username}","clientid":"${clientid}",'
                     '"payload":"${payload}","qos":"${qos}","client_attrs":${client_attrs}}')
        return {
            "type": "webhook",
            "name": name,
            "enable": True,
            "url": webhook_url,
            "method": "post",
            "headers": {"content-type": "application/json", "x-ingest-token": token},
            "body": body_tmpl,
            "max_retries": 2,
            "resource_opts": {"health_check_interval": "15s"},
        }

    def upsert_bridge(self, webhook_url, token, name=BRIDGE_NAME):
        """创建/更新 bridge。返回 (info, error, pending)。pending=True 表示状态未知（超时）。"""
        body = self._bridge_body(webhook_url, token, name)
        exists = self.get_bridge(name) is not None
        step = "更新桥接" if exists else "创建桥接"
        try:
            if exists:
                self._json("PUT", self._bridge_path(name), body=body, expect=(200, 201, 204))
            else:
                self._json("POST", "/api/v5/bridges", body=body, expect=(200, 201, 204))
            return self.get_bridge(name), None, False
        except EmqxError as e:
            if e.kind == "timeout":
                return None, "%s超时（状态未知）" % step, True
            return None, "%s失败: %s" % (step, e), False

    def get_rule(self, name=RULE_NAME):
        status, text = self._json("GET", "/api/v5/rules/%s" % urllib.parse.quote(name, safe=""),
                                  as_text=True)
        if status == 200:
            try:
                return json.loads(text)
            except ValueError:
                return {}
        return None

    def upsert_rule(self, topic="FMO/RAW", name=RULE_NAME, bridge=BRIDGE_NAME):
        """创建/更新规则（依赖 bridge 先就绪）。返回 (info, error, pending)。"""
        sql = ('SELECT clientid, username, topic, base64_encode(payload) as payload, '
               'qos, timestamp, client_attrs FROM "%s/#"' % topic)
        body = {"name": name, "sql": sql, "actions": ["webhook:%s" % bridge],
                "enable": True, "description": RULE_DESC}
        exists = self.get_rule(name) is not None
        step = "更新规则" if exists else "创建规则"
        try:
            if exists:
                self._json("PUT", "/api/v5/rules/%s" % urllib.parse.quote(name, safe=""),
                           body=body, expect=(200, 201, 204))
            else:
                self._json("POST", "/api/v5/rules", body=body, expect=(200, 201, 204))
            return self.get_rule(name), None, False
        except EmqxError as e:
            if e.kind == "timeout":
                return None, "%s超时（状态未知）" % step, True
            return None, "%s失败: %s" % (step, e), False

    def delete_rule(self, name=RULE_NAME):
        try:
            self._json("DELETE", "/api/v5/rules/%s" % urllib.parse.quote(name, safe=""),
                       expect=(200, 204))
            return True, None
        except EmqxError as e:
            if e.code == 404:
                return True, None
            return False, str(e)

    def delete_bridge(self, name=BRIDGE_NAME):
        try:
            self._json("DELETE", self._bridge_path(name), expect=(200, 204))
            return True, None
        except EmqxError as e:
            if e.code == 404:
                return True, None
            return False, str(e)

    def setup_topic_rule(self, webhook_url, token, topic="FMO/RAW"):
        """
        分步配置（对齐原版"分步日志 + pending/failed"，但修正其死代码问题）：
          1) 创建/更新 bridge  2) 检查 connector 连接状态  3) 创建/更新 rule（bridge 未就绪则跳过）
        返回 {ok, steps, pending, failed, bridge_connected}
        """
        steps = []
        pending = []
        failed = []

        _info, err, is_pending = self.upsert_bridge(webhook_url, token)
        if is_pending:
            pending.append("创建桥接")
            steps.append({"step": "桥接", "ok": False, "pending": True, "detail": err})
        elif err:
            failed.append(err)
            steps.append({"step": "桥接", "ok": False, "detail": err})
        else:
            steps.append({"step": "桥接", "ok": True, "detail": "已就绪"})

        connected = False
        if not err and not is_pending:
            conn = self.get_connector()
            if conn:
                connected = str(conn.get("status", "")).lower() in ("connected", "running")
                steps.append({"step": "连接器", "ok": connected,
                              "detail": "status=%s" % conn.get("status")})

        if err or is_pending:
            steps.append({"step": "规则", "ok": False, "detail": "规则：跳过（依赖桥接未就绪）"})
        else:
            _r_info, r_err, r_pending = self.upsert_rule(topic=topic)
            if r_pending:
                pending.append("创建规则")
                steps.append({"step": "规则", "ok": False, "pending": True, "detail": r_err})
            elif r_err:
                failed.append(r_err)
                steps.append({"step": "规则", "ok": False, "detail": r_err})
            else:
                steps.append({"step": "规则", "ok": True, "detail": "已就绪"})

        return {"ok": not failed and not pending, "steps": steps, "pending": pending,
                "failed": failed, "bridge_connected": connected}

    def teardown_topic_rule(self):
        """删除顺序与创建相反：先 rule 后 bridge。返回 (ok, errors)"""
        errs = []
        ok1, e1 = self.delete_rule()
        if not ok1:
            errs.append(e1)
        ok2, e2 = self.delete_bridge()
        if not ok2:
            errs.append(e2)
        return (not errs), errs


class EmqxPoller(object):
    """带缓存的轮询器：把 EMQX 状态缓存下来供 Web 页面读取（避免每个请求都打 EMQX）。"""

    def __init__(self, client, interval=5):
        self.client = client
        self.interval = interval
        self._lock = threading.Lock()
        self._clients = []
        self._node_health = {}
        self._last_ok = 0.0
        self._last_error = None
        self._version = ""

    def poll_once(self):
        try:
            clients = self.client.list_clients()
            health = self.client.node_health()
            with self._lock:
                self._clients = clients
                self._node_health = health
                self._last_ok = time.time()
                self._last_error = None
                if health.get("version"):
                    self._version = health["version"]
            return True, None
        except EmqxError as e:
            with self._lock:
                self._last_error = str(e)
            return False, str(e)

    def snapshot(self):
        with self._lock:
            return {"clients": list(self._clients), "health": dict(self._node_health),
                    "last_ok": self._last_ok, "last_error": self._last_error,
                    "version": self._version}

    def online_count(self):
        with self._lock:
            return len(self._clients)
