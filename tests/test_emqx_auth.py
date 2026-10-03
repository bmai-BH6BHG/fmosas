#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_emqx_auth 测试：识别 MQTT + 把 EMQX 客户端认证指向 BAS 端口
==============================================================
用桩 EMQX 模拟 5.x 的认证链接口，验证：
  * 能列出认证链、认出"像 SAS 的 http 认证"
  * 切换后目标 URL 生效；旧项被删除
  * **幂等**：已指向目标时不重复改动
  * **dry-run 不动线上配置**
  * 改动前有备份，可回滚
  * 非 SAS 的认证后端一律不碰
"""

import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests import ROOT  # noqa: F401
import bas_emqx_auth as ea
from bas_emqx import EmqxClient

STATE = {
    "listeners": [
        {"id": "tcp:default", "type": "tcp", "running": True, "current_connections": 12},
        {"id": "ws:default", "type": "ws", "running": True, "current_connections": 0},
    ],
    "global": [
        {"id": "password_based:http:old_sas", "type": "password_based", "backend": "http",
         "mechanism": "password_based", "url": "http://127.0.0.1:35000/auth", "enable": True},
    ],
    "tcp:default": [],
    "requests": [],
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        path = self.path.split("?")[0]
        STATE["requests"].append(("GET", path))
        if path == "/status":
            return self._send(200, {"status": "ok"})
        if path == "/api/v5/listeners":
            return self._send(200, {"data": STATE["listeners"]})
        if path == "/api/v5/authentication":
            return self._send(200, {"data": STATE["global"]})
        if path.startswith("/api/v5/listeners/") and path.endswith("/authentication"):
            lid = path[len("/api/v5/listeners/"):-len("/authentication")]
            return self._send(200, {"data": STATE.get(lid, [])})
        return self._send(404, {"code": "NOT_FOUND"})

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._body()
        STATE["requests"].append(("POST", path, body))
        if path == "/api/v5/authentication":
            lid = body.get("listener_id")
            target = STATE["global"] if not lid else STATE.setdefault(lid, [])
            new = dict(body)
            new["id"] = "password_based:http:new_%d" % (len(target) + 1)
            target.append(new)
            return self._send(200, new)
        return self._send(404, {"code": "NOT_FOUND"})

    def do_DELETE(self):
        path = self.path.split("?")[0]
        STATE["requests"].append(("DELETE", path))
        aid = path.rsplit("/", 1)[-1]
        for key in ["global"] + [l["id"] for l in STATE["listeners"]]:
            lst = STATE.get(key, [])
            for i, a in enumerate(lst):
                if a.get("id") == aid:
                    lst.pop(i)
                    return self._send(204, {})
        return self._send(404, {"code": "NOT_FOUND"})


class SasStub(BaseHTTPRequestHandler):
    """假的 SAS /auth：对任何请求都回 deny（证明"服务活着"）"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = json.dumps({"result": "deny", "reason": "缺少 username 或 password"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EmqxAuthSwitchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sas = ThreadingHTTPServer(("127.0.0.1", 0), SasStub)
        cls.sas_port = cls.sas.server_address[1]
        threading.Thread(target=cls.sas.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()
        cls.sas.shutdown(); cls.sas.server_close()

    def target_url(self):
        return "http://127.0.0.1:%d/auth" % self.sas_port

    def setUp(self):
        STATE["global"] = [
            {"id": "password_based:http:old_sas", "type": "password_based", "backend": "http",
             "mechanism": "password_based", "url": "http://127.0.0.1:35000/auth", "enable": True},
        ]
        STATE["tcp:default"] = []
        STATE["requests"] = []
        self.cli = EmqxClient("127.0.0.1:%d" % self.port, "key", "secret")
        self.dbdir = tempfile.mkdtemp(prefix="bas-authn-")

    def tearDown(self):
        shutil.rmtree(self.dbdir, ignore_errors=True)

    # ---------------- 识别 ----------------
    def test_detect_mqtt_on_open_port(self):
        # 绑定任意端口 → 只验证"能发现端口开放"；标准 MQTT/Dashboard 端口才有语义标签
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            d = ea.detect_mqtt(ports=[port])
            self.assertTrue(d["found"])
            self.assertIn(port, d["open_ports"])
            self.assertIsNone(d["dashboard"])
        finally:
            s.close()

    def test_detect_mqtt_nothing(self):
        d = ea.detect_mqtt(ports=[59991, 59992])
        self.assertFalse(d["found"])
        self.assertIn("未在本机发现", d["note"])

    def test_guess_url_from_dashboard_port(self):
        d = {"host": "127.0.0.1", "open_ports": [1883, 18083], "dashboard": 18083}
        self.assertEqual("http://127.0.0.1:18083", ea.guess_emqx_url(d))

    def test_list_and_inspect_chain(self):
        chains = ea.list_authenticators(self.cli)
        scopes = [c["scope"] for c in chains]
        self.assertIn("global", scopes)
        info = ea.inspect(self.cli)
        self.assertEqual(1, info["http_count"])
        self.assertEqual(1, info["sas_like_count"], "应认出这是 SAS 认证")
        self.assertFalse(info["target_active"])

    # ---------------- 切换 ----------------
    def test_switch_points_to_new_port(self):
        target = self.target_url()
        r = ea.switch_auth(self.cli, target, dry_run=False)
        self.assertEqual([], r["errors"], r["errors"])
        self.assertTrue(r["ok"], r)
        # 旧项被删、新项指向目标
        urls = [a.get("url") for a in STATE["global"]]
        self.assertIn(target, urls, "新认证必须指向目标 URL")
        self.assertNotIn("http://127.0.0.1:35000/auth", urls, "旧 SAS 认证必须被移除")
        # 新认证 body 必须带 username/password（否则 SAS 拿不到凭据）
        posts = [b for (m, p, *rest) in [(x[0], x[1], x[2] if len(x) > 2 else None)
                                         for x in STATE["requests"]] if m == "POST" for b in [rest[0]] if b]
        self.assertTrue(posts)
        body = posts[0].get("body") or {}
        self.assertEqual("${username}", body.get("username"))
        self.assertEqual("${password}", body.get("password"))
        self.assertEqual("post", posts[0].get("method"))
        self.assertIsInstance(posts[0].get("ssl"), dict, "ssl 必须是对象")
        self.assertIs(False, posts[0]["ssl"].get("enable"), "ssl.enable 必须是布尔 false")
        self.assertEqual("password_based", posts[0].get("mechanism"), "必须带 mechanism 字段")
        self.assertNotIn("type", posts[0], "不能带 type（EMQX 会报 unknown_fields）")
        self.assertNotIn("listener_id", posts[0], "不能带 listener_id（EMQX 会报 unknown_fields）")

    def test_preflight_blocks_change_when_target_down(self):
        """
        ★ 安全阀：目标认证服务不可达时，**绝不能删掉线上配置**
        （这正是之前把用户服务器搞挂的原因：删了旧认证、新建又失败）
        """
        before = json.dumps(STATE["global"], sort_keys=True)
        r = ea.switch_auth(self.cli, "http://127.0.0.1:59998/auth", dry_run=False)
        self.assertFalse(r["ok"])
        self.assertTrue(any("预检" in e for e in r["errors"]), r["errors"])
        self.assertEqual(before, json.dumps(STATE["global"], sort_keys=True),
                         "预检失败时配置必须原封不动")
        self.assertFalse(any(m == "DELETE" for (m, *_) in STATE["requests"]),
                         "绝不能发删除请求")

    def test_dry_run_changes_nothing(self):
        before = json.dumps(STATE["global"], sort_keys=True)
        r = ea.switch_auth(self.cli, self.target_url(), dry_run=True)
        self.assertEqual([], r["errors"])
        self.assertTrue(any("[DRY]" in x for x in r["changed"]))
        self.assertEqual(before, json.dumps(STATE["global"], sort_keys=True),
                         "dry-run 绝不能改线上配置")
        self.assertFalse(any(m == "DELETE" for (m, *_) in STATE["requests"]))

    def test_idempotent_when_already_target(self):
        target = self.target_url()
        ea.switch_auth(self.cli, target, dry_run=False)
        STATE["requests"] = []
        r = ea.switch_auth(self.cli, target, dry_run=False)
        self.assertTrue(r["ok"])
        self.assertTrue(any("跳过" in x for x in r["skipped"]))
        self.assertFalse(any(m == "POST" for (m, *_) in STATE["requests"]),
                         "已指向目标时不应再新建")

    def test_keeps_non_sas_authenticators(self):
        STATE["global"].append({"id": "password_based:built_in:x", "type": "password_based",
                                "backend": "built_in_database", "mechanism": "password_based",
                                "enable": True})
        r = ea.switch_auth(self.cli, self.target_url(), dry_run=False)
        self.assertEqual([], r["errors"])
        backends = [a.get("backend") for a in STATE["global"]]
        self.assertIn("built_in_database", backends, "非 SAS 认证必须保留")

    def test_rollback_when_create_fails(self):
        """
        ★ 建失败必须自动回滚：模拟"能删但建不上"，验证旧配置被恢复、服务不处于无认证状态
        """
        orig_json = self.cli._json
        calls = {"n": 0}

        def flaky(method, path, **kw):
            if method == "POST" and path == "/api/v5/authentication":
                calls["n"] += 1
                if calls["n"] == 1:          # 只让"新建"失败一次，回滚要能成功
                    raise ea.EmqxError("HTTP 400: schema validation failed (模拟建失败)")
            return orig_json(method, path, **kw)

        self.cli._json = flaky
        try:
            r = ea.switch_auth(self.cli, self.target_url(), dry_run=False)
        finally:
            self.cli._json = orig_json
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("rolled_back"), "必须回滚: %s" % r)
        # 认证链里必须仍有可用认证（回滚恢复的那条）
        self.assertTrue(STATE["global"], "回滚后不能处于无认证状态！")
        self.assertIn("回滚恢复", " ".join(r["changed"]))

    def test_backup_saved_to_db_and_rollback(self):
        from bas_audit_db import AuditDB
        db = AuditDB(os.path.join(self.dbdir, "audit.db"))
        r = ea.switch_auth(self.cli, self.target_url(), dry_run=False, db=db)
        self.assertTrue(r["backup"], "必须返回备份")
        saved = db.get_setting("emqx_authn_backup")
        self.assertIn("old_sas", saved, "备份里应含旧认证项")
        self.assertIn("emqx_authn_backup_at", db.all_settings())
        # 回滚：删除现在的、按备份重建
        rr = ea.restore_auth(self.cli, saved, dry_run=False)
        self.assertEqual([], rr["errors"], rr["errors"])
        self.assertTrue(any(a.get("url") == "http://127.0.0.1:35000/auth"
                            for a in STATE["global"]),
                        "回滚后应恢复原认证: %s" % STATE["global"])

    def test_switch_reports_error_when_emqx_unreachable(self):
        cli = EmqxClient("127.0.0.1:59999", "k", "s")
        r = ea.switch_auth(cli, self.target_url(), dry_run=False)
        self.assertFalse(r["ok"])
        self.assertTrue(r["errors"])

    def test_target_url_hint_detects_already_active(self):
        """inspect 传入目标 URL 提示时，应能判断"已经指向目标"。"""
        target = self.target_url()
        STATE["global"] = [
            {"id": "password_based:http:new", "type": "password_based", "backend": "http",
             "mechanism": "password_based", "url": target, "enable": True},
        ]
        info = ea.inspect(self.cli, sas_url_hint=target)
        self.assertTrue(info["target_active"], info["items"])
        self.assertEqual(1, info["sas_like_count"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
