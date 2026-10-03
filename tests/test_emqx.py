#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_emqx 测试：用本地桩 EMQX 验证真实 HTTP 行为
==============================================
覆盖：Basic 认证拼串、探活、**自动翻页**（原版缺失）、
banned 两步法（拉黑 + kickout/bulk 裸数组）、解封幂等、
bridge/rule 路径里的冒号不被编码、body 模板中 client_attrs 不加引号、
client_attrs 数值/布尔归一（1 != "1" 陷阱）、节点指标聚合、字节单位解析。
"""

import base64
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests import ROOT  # noqa: F401
from bas_emqx import (
    EmqxClient, EmqxError, parse_byte_size, get_lan_ip,
    BRIDGE_NAME, RULE_NAME,
)

EXPECTED_AUTH = "Basic " + base64.b64encode(b"key123:secret456").decode()


class StubState(object):
    def __init__(self):
        self.requests = []      # (method, path, headers, body)
        self.ban_calls = []
        self.kick_calls = []
        self.bridge = None
        self.rule = None
        self.connector_status = "connected"


STATE = StubState()


def _clients_page(page, total=2500, per=1000):
    start = (page - 1) * per
    end = min(start + per, total)
    rows = []
    for i in range(start, end):
        rows.append({
            "clientid": "cid-%04d" % i,
            "username": "BG5ESN",
            "ip_address": "10.0.0.%d" % (i % 250 + 1),
            "connected_at": "2026-10-03T10:00:00.000Z",
            "recv_msg": i, "send_msg": i * 2,
            "recv_oct": i * 10, "send_oct": i * 20,
            "client_attrs": {"callsign": "BG5ESN", "uid": 12345 + i},
            "proto_name": "MQTT", "proto_ver": 5, "keepalive": 60,
        })
    return {"data": rows, "meta": {"page": page, "limit": per, "count": len(rows),
                                   "hasnext": end < total}}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, obj=None, raw=None):
        body = raw if raw is not None else (json.dumps(obj or {}).encode())
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        STATE.requests.append(("GET", self.path, dict(self.headers), b""))
        path = self.path.split("?")[0]
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        if path == "/status":
            return self._send(200, {"status": "ok"})
        # 业务接口必须带正确 Basic
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            return self._send(401, {"code": "UNAUTHORIZED"})
        if path == "/api/v5/nodes":
            return self._send(200, [{"node": "emqx@127.0.0.1", "version": "5.8.0",
                                     "node_status": "running", "connections": 2500,
                                     "load1": 0.42, "memory_total": "4.69G", "memory_used": "1.2G"}])
        if path == "/api/v5/metrics":
            return self._send(200, [{"messages.received": 1000, "messages.sent": 2000},
                                    {"messages.received": 500, "messages.sent": 700}])
        if path == "/api/v5/alarms":
            return self._send(200, {"data": [{"name": "high_system_memory_usage", "activated": True},
                                             {"name": "old_alarm", "activated": False}]})
        if path == "/api/v5/clients":
            m = re.search(r"page=(\d+)", q)
            page = int(m.group(1)) if m else 1
            total = 2500
            if "username=" in q:
                uname = re.search(r"username=([^&]+)", q).group(1)
                rows = [{"clientid": "cid-0001", "username": uname, "client_attrs": {}}]
                return self._send(200, {"data": rows, "meta": {"hasnext": False}})
            return self._send(200, _clients_page(page, total))
        if path == "/api/v5/banned":
            return self._send(200, {"data": [{"as": "username", "who": "BG9BAD",
                                              "until": "infinity", "reason": "test"}]})
        if path.startswith("/api/v5/bridges/webhook:"):
            if STATE.bridge is None:
                return self._send(404, {"code": "NOT_FOUND"})
            return self._send(200, STATE.bridge)
        if path.startswith("/api/v5/connectors/http:"):
            return self._send(200, {"name": BRIDGE_NAME, "status": STATE.connector_status})
        if path.startswith("/api/v5/rules/"):
            if STATE.rule is None:
                return self._send(404, {"code": "NOT_FOUND"})
            return self._send(200, STATE.rule)
        return self._send(404, {"code": "NOT_FOUND", "path": path})

    def do_POST(self):
        body = self._read_body()
        STATE.requests.append(("POST", self.path, dict(self.headers), body))
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            return self._send(401, {"code": "UNAUTHORIZED"})
        path = self.path.split("?")[0]
        if path == "/api/v5/banned":
            data = json.loads(body or b"{}")
            STATE.ban_calls.append(data)
            if data.get("who") == "ALREADY":
                return self._send(400, {"code": "ALREADY_EXISTS"})
            return self._send(200, {"as": data.get("as"), "who": data.get("who")})
        if path == "/api/v5/clients/kickout/bulk":
            STATE.kick_calls.append(json.loads(body or b"[]"))
            return self._send(200, {"data": []})
        if path == "/api/v5/bridges":
            STATE.bridge = json.loads(body)
            STATE.bridge["name"] = BRIDGE_NAME
            return self._send(201, STATE.bridge)
        if path == "/api/v5/rules":
            STATE.rule = json.loads(body)
            return self._send(201, STATE.rule)
        return self._send(404, {"code": "NOT_FOUND"})

    def do_PUT(self):
        body = self._read_body()
        STATE.requests.append(("PUT", self.path, dict(self.headers), body))
        if self.headers.get("Authorization") != EXPECTED_AUTH:
            return self._send(401, {"code": "UNAUTHORIZED"})
        path = self.path.split("?")[0]
        if path.startswith("/api/v5/bridges/webhook:"):
            STATE.bridge = json.loads(body)
            STATE.bridge["name"] = BRIDGE_NAME
            return self._send(200, STATE.bridge)
        if path.startswith("/api/v5/rules/"):
            STATE.rule = json.loads(body)
            return self._send(200, STATE.rule)
        return self._send(404, {"code": "NOT_FOUND"})

    def do_DELETE(self):
        STATE.requests.append(("DELETE", self.path, dict(self.headers), b""))
        path = self.path.split("?")[0]
        if path == "/api/v5/banned/username/NOPE":
            return self._send(404, {"code": "NOT_FOUND"})
        if path == "/api/v5/banned/username/BG9BAD":
            return self._send(204)
        return self._send(204)


class EmqxClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.t = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        STATE.requests.clear(); STATE.ban_calls.clear(); STATE.kick_calls.clear()
        STATE.bridge = None; STATE.rule = None; STATE.connector_status = "connected"
        self.c = EmqxClient("127.0.0.1:%d" % self.port, "key123", "secret456")

    # ---- 基础 ----
    def test_base_url_normalized(self):
        self.assertEqual("http://127.0.0.1:18083", EmqxClient("127.0.0.1:18083", "a", "b").base_url)
        self.assertEqual("https://x/y", EmqxClient("https://x/y/", "a", "b").base_url)

    def test_ping_no_auth(self):
        ok, why = self.c.ping()
        self.assertTrue(ok, why)
        paths = [p for (m, p, h, b) in STATE.requests if p == "/status"]
        self.assertTrue(paths)
        hdr = [h for (m, p, h, b) in STATE.requests if p == "/status"][0]
        self.assertIsNone(hdr.get("Authorization"))

    def test_basic_auth_is_key_colon_secret(self):
        self.c.list_nodes()
        hdrs = [h for (m, p, h, b) in STATE.requests if p == "/api/v5/nodes"]
        self.assertEqual(EXPECTED_AUTH, hdrs[0].get("Authorization"))

    def test_version_and_supported(self):
        self.assertEqual("5.8.0", self.c.version())
        self.assertTrue(self.c.is_supported_version())

    # ---- 分页（原版缺陷修正）----
    def test_clients_auto_pagination(self):
        rows = self.c.list_clients()
        self.assertEqual(2500, len(rows), "必须翻页取全量（原版只取第一页 1000）")
        pages = sorted({re.search(r"page=(\d+)", p).group(1)
                        for (m, p, h, b) in STATE.requests if p.startswith("/api/v5/clients")})
        self.assertEqual(["1", "2", "3"], pages)

    def test_client_attrs_normalized(self):
        rows = self.c.list_clients()
        first = rows[0]
        self.assertEqual("BG5ESN", first["callsign"])
        self.assertEqual("12345", first["uid"])           # 数值 → 字符串（1 != "1" 陷阱）
        self.assertIsInstance(first["uid"], str)
        self.assertEqual(2500, len(rows))

    def test_clients_by_username(self):
        rows = self.c.clients_by_username("BG5ESN")
        self.assertEqual(1, len(rows))

    # ---- 黑名单两步法 ----
    def test_ban_two_step(self):
        ok, err, kicked = self.c.ban_username("BG8XYZ", "身份控制测试")
        self.assertTrue(ok, err)
        self.assertEqual(1, len(STATE.ban_calls))
        ban = STATE.ban_calls[0]
        self.assertEqual("username", ban["as"])
        self.assertEqual("BG8XYZ", ban["who"])
        self.assertEqual("infinity", ban["until"])        # 永久必须显式 infinity
        self.assertEqual([[ "cid-0001" ]], STATE.kick_calls, "拉黑后必须踢下线（裸数组 body）")
        self.assertEqual(1, kicked)

    def test_ban_already_exists_is_success(self):
        ok, err = self.c.ban("ALREADY", "dup")
        self.assertTrue(ok, err)

    def test_unban_idempotent(self):
        ok, err = self.c.unban("NOPE")
        self.assertTrue(ok, err)                          # 404 视为已解封
        ok2, err2 = self.c.unban("BG9BAD")
        self.assertTrue(ok2, err2)

    def test_temporary_ban_until_passthrough(self):
        self.c.ban("BG7TMP", "temp", until="2026-11-01T00:00:00Z")
        self.assertEqual("2026-11-01T00:00:00Z", STATE.ban_calls[0]["until"])

    # ---- 规则引擎 ----
    def test_bridge_rule_setup_and_colon_path(self):
        res = self.c.setup_topic_rule("http://10.0.0.5:35929/api/ingest", "TOKEN123", "FMO/RAW")
        self.assertTrue(res["ok"], res)
        # 冒号不能被编码
        paths = [p for (m, p, h, b) in STATE.requests]
        self.assertIn("/api/v5/bridges", paths)
        get_paths = [p for (m, p, h, b) in STATE.requests if p.startswith("/api/v5/bridges/webhook:")]
        self.assertTrue(get_paths, "检查 bridge 必须用 webhook: 前缀且冒号原样")
        self.assertFalse(any("%3A" in p or "%3a" in p for p in paths), "冒号被编码会 404")

        # bridge body 关键字段
        sent = STATE.bridge
        self.assertEqual("webhook", sent["type"])
        self.assertEqual("post", sent["method"])
        self.assertEqual("TOKEN123", sent["headers"]["x-ingest-token"])
        self.assertIn("${client_attrs}", sent["body"])
        self.assertNotIn('"${client_attrs}"', sent["body"], "client_attrs 前后不能加引号")
        self.assertEqual(2, sent["max_retries"])
        self.assertEqual("http://10.0.0.5:35929/api/ingest", sent["url"])

        # rule SQL
        sql = STATE.rule["sql"]
        self.assertIn('base64_encode(payload) as payload', sql)
        self.assertIn('client_attrs', sql)
        self.assertIn('FROM "FMO/RAW/#"', sql)
        self.assertEqual(["webhook:%s" % BRIDGE_NAME], STATE.rule["actions"])

    def test_setup_rule_skipped_when_bridge_not_connected(self):
        res = self.c.setup_topic_rule("http://10.0.0.5:35929/api/ingest", "T", "FMO/RAW")
        self.assertTrue(res["bridge_connected"])
        self.assertEqual(["桥接", "连接器", "规则"], [s["step"] for s in res["steps"]])

    def test_teardown_order_rule_then_bridge(self):
        self.c.setup_topic_rule("http://x/api/ingest", "T")
        STATE.requests.clear()
        ok, errs = self.c.teardown_topic_rule()
        self.assertTrue(ok, errs)
        dels = [p for (m, p, h, b) in STATE.requests if m == "DELETE"]
        self.assertTrue(dels[0].startswith("/api/v5/rules/"), "先删规则")
        self.assertTrue(dels[1].startswith("/api/v5/bridges/"), "后删桥接")

    def test_upsert_updates_existing_rule(self):
        self.c.setup_topic_rule("http://x/api/ingest", "T")
        STATE.requests.clear()
        self.c.setup_topic_rule("http://x/api/ingest", "T2")
        self.assertTrue(any(m == "PUT" and p.startswith("/api/v5/bridges/") for (m, p, h, b) in STATE.requests))
        self.assertTrue(any(m == "PUT" and p.startswith("/api/v5/rules/") for (m, p, h, b) in STATE.requests))

    # ---- 健康与工具 ----
    def test_health_aggregates_nodes_and_metrics(self):
        h = self.c.node_health()
        self.assertTrue(h["ok"], h)
        self.assertEqual(1, h["nodes"])
        self.assertEqual(2500, h["connections"])
        self.assertEqual("5.8.0", h["version"])
        self.assertIn("high_system_memory_usage", h["alarms"])
        self.assertNotIn("old_alarm", h["alarms"])
        self.assertEqual(1500, h["metrics"]["messages.received"], "多节点应求和")

    def test_parse_byte_size(self):
        self.assertEqual(int(4.69 * 1024 ** 3), parse_byte_size("4.69G"))
        self.assertEqual(512 * 1024 ** 2, parse_byte_size("512MB"))
        self.assertEqual(1024, parse_byte_size("1024"))
        self.assertEqual(1024, parse_byte_size(1024))
        self.assertIsNone(parse_byte_size("n/a"))

    def test_get_lan_ip_returns_ipv4(self):
        ip = get_lan_ip()
        self.assertRegex(ip, r"^\d+\.\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
