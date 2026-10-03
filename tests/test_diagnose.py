#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_diagnose 测试：client_attrs 下发失败的各类根因都能被认出来
==============================================================
覆盖：EMQX 版本过低 / HTTP 认证请求体为空 / body 缺 username|password /
      authn URL 不是 /auth / method 不是 POST / 存在其它认证器抢跑 /
      SAS /auth 不可达 / 403 / 正常链路
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests import ROOT  # noqa: F401
import bas_diagnose as dg

EMQX_STATE = {
    "version": "5.8.0",
    "authn": [
        {"id": "password_based:http:sas", "type": "password_based", "backend": "http",
         "mechanism": "password_based", "url": "http://127.0.0.1:35928/auth", "enable": True},
    ],
    "detail": {
        "password_based:http:sas": {
            "method": "post",
            "body": {"username": "${username}", "password": "${password}"},
        }
    },
}
SAS_STATE = {"status": 200, "body": '{"result":"deny","reason":"username 为空（应为明文呼号）"}'}


class EmqxStub(BaseHTTPRequestHandler):
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

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/status":
            return self._send(200, {"status": "ok"})
        if p == "/api/v5/nodes":
            return self._send(200, [{"version": EMQX_STATE["version"], "node_status": "running"}])
        if p == "/api/v5/listeners":
            return self._send(200, {"data": []})
        if p == "/api/v5/authentication":
            return self._send(200, {"data": EMQX_STATE["authn"]})
        if p.startswith("/api/v5/authentication/"):
            aid = p.rsplit("/", 1)[-1]
            det = EMQX_STATE["detail"].get(aid)
            if det is None:
                return self._send(404, {})
            item = dict(EMQX_STATE["authn"][0])
            item.update(det)
            return self._send(200, item)
        return self._send(404, {})


class SasStub(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        code = SAS_STATE["status"]
        body = SAS_STATE["body"].encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DiagnoseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.emqx = ThreadingHTTPServer(("127.0.0.1", 0), EmqxStub)
        cls.sas = ThreadingHTTPServer(("127.0.0.1", 0), SasStub)
        cls.emqx_port = cls.emqx.server_address[1]
        cls.sas_port = cls.sas.server_address[1]
        threading.Thread(target=cls.emqx.serve_forever, daemon=True).start()
        threading.Thread(target=cls.sas.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.emqx.shutdown(); cls.emqx.server_close()
        cls.sas.shutdown(); cls.sas.server_close()

    def setUp(self):
        EMQX_STATE["version"] = "5.8.0"
        EMQX_STATE["authn"] = [
            {"id": "password_based:http:sas", "type": "password_based", "backend": "http",
             "mechanism": "password_based", "url": "http://127.0.0.1:35928/auth", "enable": True}]
        EMQX_STATE["detail"] = {"password_based:http:sas": {
            "method": "post", "body": {"username": "${username}", "password": "${password}"}}}
        SAS_STATE["status"] = 200
        SAS_STATE["body"] = '{"result":"deny","reason":"username 为空（应为明文呼号）"}'
        self.emqx_url = "http://127.0.0.1:%d" % self.emqx_port
        self.sas_url = "http://127.0.0.1:%d/auth" % self.sas_port

    def _diag(self):
        return dg.diagnose(self.emqx_url, "key", "secret", self.sas_url, base_dir=".")

    def _codes(self, r):
        return {f["code"] for f in r["findings"]}

    # ---------------- 正常链路 ----------------
    def test_healthy_chain(self):
        r = self._diag()
        codes = self._codes(r)
        self.assertTrue(r["ok"], r["findings"])
        self.assertIn("AUTHN_BODY_OK", codes)
        self.assertIn("EMQX_VER_OK", codes)
        self.assertIn("SAS_OK", codes)
        self.assertNotIn("EMQX_VER_TOO_OLD", codes)

    # ---------------- A. 版本过低 ----------------
    def test_detects_old_emqx_version(self):
        EMQX_STATE["version"] = "5.6.1"
        r = self._diag()
        self.assertFalse(r["ok"])
        self.assertIn("EMQX_VER_TOO_OLD", self._codes(r))
        # 5.7 支持 client_attrs 但不支持 acl
        EMQX_STATE["version"] = "5.7.0"
        r2 = self._diag()
        self.assertNotIn("EMQX_VER_TOO_OLD", self._codes(r2))

    # ---------------- B. 请求体问题 ----------------
    def test_detects_missing_body_template(self):
        EMQX_STATE["detail"]["password_based:http:sas"] = {"method": "post", "body": {}}
        r = self._diag()
        self.assertFalse(r["ok"])
        self.assertIn("AUTHN_BODY_EMPTY", self._codes(r))

    def test_detects_body_missing_password(self):
        EMQX_STATE["detail"]["password_based:http:sas"] = {
            "method": "post", "body": {"username": "${username}"}}
        r = self._diag()
        self.assertFalse(r["ok"])
        self.assertIn("AUTHN_BODY_MISSING_FIELDS", self._codes(r))

    def test_detects_wrong_method(self):
        EMQX_STATE["detail"]["password_based:http:sas"] = {
            "method": "get", "body": {"username": "${username}", "password": "${password}"}}
        r = self._diag()
        self.assertIn("AUTHN_METHOD", self._codes(r))

    def test_detects_odd_authn_url(self):
        EMQX_STATE["authn"][0]["url"] = "http://127.0.0.1:35929/admin"
        r = self._diag()
        self.assertIn("AUTHN_URL_ODD", self._codes(r))

    # ---------------- C. 其它认证器抢跑 ----------------
    def test_detects_other_authn(self):
        EMQX_STATE["authn"].append({
            "id": "password_based:built_in_database:x", "type": "password_based",
            "backend": "built_in_database", "mechanism": "password_based", "enable": True})
        r = self._diag()
        self.assertIn("OTHER_AUTHN_PRESENT", self._codes(r))

    # ---------------- 完全没有 HTTP 认证 ----------------
    def test_detects_no_http_authn(self):
        EMQX_STATE["authn"] = [{"id": "password_based:built_in_database:x",
                                "type": "password_based", "backend": "built_in_database",
                                "mechanism": "password_based", "enable": True}]
        r = self._diag()
        self.assertFalse(r["ok"])
        self.assertIn("NO_HTTP_AUTHN", self._codes(r))

    # ---------------- D. SAS 侧问题 ----------------
    def test_detects_sas_unreachable(self):
        r = dg.diagnose(self.emqx_url, "key", "secret", "http://127.0.0.1:59999/auth")
        self.assertFalse(r["ok"])
        self.assertIn("SAS_UNREACHABLE", self._codes(r))

    def test_detects_sas_forbidden_403(self):
        SAS_STATE["status"] = 403
        r = self._diag()
        self.assertFalse(r["ok"])
        self.assertIn("SAS_FORBIDDEN", self._codes(r))

    # ---------------- E. EMQX 不可达 / 缺凭据 ----------------
    def test_detects_emqx_unreachable(self):
        r = dg.diagnose("http://127.0.0.1:59998", "key", "secret", self.sas_url)
        self.assertFalse(r["ok"])
        self.assertIn("EMQX_UNREACHABLE", self._codes(r))

    def test_detects_missing_credentials(self):
        r = dg.diagnose("", "", "", self.sas_url)
        self.assertFalse(r["ok"])
        self.assertIn("EMQX_CFG_MISSING", self._codes(r))

    # ---------------- F. 审计库取证 ----------------
    def test_reads_audit_scenes(self):
        import os
        import sqlite3
        import tempfile
        tmp = tempfile.mkdtemp(prefix="bas-diag-")
        db = os.path.join(tmp, "x_audit.db")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE audit_packets(id INTEGER PRIMARY KEY, ts TEXT, scene TEXT,"
                  " verdict TEXT, clientid TEXT, reason TEXT)")
        c.execute("INSERT INTO audit_packets(ts, scene, verdict) VALUES(datetime('now','localtime'),"
                  "'both_missing','WARN')")
        c.commit(); c.close()
        r = dg.diagnose(self.emqx_url, "key", "secret", self.sas_url, audit_db=db)
        self.assertIn("ATTR_MISSING_CONFIRMED", self._codes(r))
        self.assertEqual(1, r["facts"]["audit_scenes_24h"].get("both_missing"))

    def test_report_text_contains_fix(self):
        EMQX_STATE["version"] = "5.4.0"
        r = self._diag()
        import io
        buf = io.StringIO()
        dg.print_report(r, log=lambda m: buf.write(str(m) + "\n"))
        out = buf.getvalue()
        self.assertIn("EMQX_VER_TOO_OLD", out)
        self.assertIn("修法", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
