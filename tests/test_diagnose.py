#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_diagnose（自检脚本）测试
============================
用桩 EMQX 验证：能识别 EMQX 版本过低 / 认证请求体问题 / precondition /
其它认证器 / **在线客户端 client_attrs 为空**（"谁进来都缺身份"的直接证据）。
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests import ROOT, BAS_DIAGNOSE  # noqa: F401
import bas_diagnose as bd

STATE = {
    "version": "5.8.0",
    "authn": [{"id": "password_based:http:sas", "type": "password_based", "backend": "http",
               "mechanism": "password_based", "url": "http://127.0.0.1:35928/auth",
               "enable": True}],
    "detail": {"password_based:http:sas": {
        "method": "post", "body": {"username": "${username}", "password": "${password}"}}},
    "clients": [],
    "listeners": [{"id": "tcp:default", "type": "tcp", "running": True}],
}


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
            return self._send(200, [{"version": STATE["version"], "node_status": "running"}])
        if p == "/api/v5/listeners":
            return self._send(200, {"data": STATE["listeners"]})
        if p == "/api/v5/authentication":
            return self._send(200, {"data": STATE["authn"]})
        if p.startswith("/api/v5/authentication/"):
            aid = urllib.parse.unquote(p.rsplit("/", 1)[-1])
            det = STATE["detail"].get(aid)
            if det is None:
                return self._send(404, {})
            item = dict(STATE["authn"][0])
            item.update(det)
            return self._send(200, item)
        if p == "/api/v5/clients":
            return self._send(200, {"data": STATE["clients"], "meta": {"hasnext": False}})
        if p.startswith("/api/v5/listeners/") and p.endswith("/authentication"):
            return self._send(200, {"data": []})
        return self._send(404, {})


class SasStub(BaseHTTPRequestHandler):
    """假的 SAS /auth：回 deny（证明服务活着）"""

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


def run_self_check(base_dir, emqx_url, sas_url):
    """真实执行一次脚本（模拟用户 curl 下来跑），返回 (exit, stdout)"""
    cmd = [sys.executable, BAS_DIAGNOSE, "--diagnose", "--base-dir", base_dir,
           "--emqx-url", emqx_url, "--key", "k", "--secret", "s",
           "--sas-url", sas_url, "--mqtt-ports", "1884"]
    p = subprocess.run(cmd, capture_output=True, timeout=60,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")


class DiagnoseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), EmqxStub)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.sas = ThreadingHTTPServer(("127.0.0.1", 0), SasStub)
        cls.sas_port = cls.sas.server_address[1]
        threading.Thread(target=cls.sas.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.sas.shutdown()
        cls.sas.server_close()

    def setUp(self):
        STATE["version"] = "5.8.0"
        STATE["authn"] = [{"id": "password_based:http:sas", "type": "password_based",
                           "backend": "http", "mechanism": "password_based",
                           "url": "http://127.0.0.1:35928/auth", "enable": True}]
        STATE["detail"] = {"password_based:http:sas": {
            "method": "post", "body": {"username": "${username}", "password": "${password}"}}}
        STATE["clients"] = []
        self.tmp = tempfile.mkdtemp(prefix="bas-diag-")
        # 造一个审计库（含 EMQX 配置），模拟已部署环境
        db = os.path.join(self.tmp, "x_audit.db")
        c = sqlite3.connect(db)
        c.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)")
        c.executemany("INSERT INTO settings VALUES(?,?)", [
            ("emqx_url", "http://127.0.0.1:%d" % self.port),
            ("emqx_api_key", "k"), ("emqx_api_secret", "s"), ("topic_name", "FMO/RAW")])
        c.execute("CREATE TABLE audit_packets(id INTEGER PRIMARY KEY, ts TEXT, scene TEXT,"
                  " verdict TEXT, conn_callsign TEXT, pkt_callsign TEXT, clientid TEXT)")
        c.execute("CREATE TABLE minute_stats(clientid TEXT, ts TEXT)")
        c.execute("CREATE TABLE topic_stats(topic TEXT, clientid TEXT, ts TEXT)")
        c.commit(); c.close()
        with open(os.path.join(self.tmp, "config.json"), "w") as f:
            json.dump({"port": 35928}, f)
        self.url = "http://127.0.0.1:%d" % self.port
        self.sas_url = "http://127.0.0.1:%d/auth" % self.sas_port

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------------- 基本读取 ----------------
    def test_read_cfg_from_audit_db(self):
        cfg = bd.read_cfg(self.tmp)
        self.assertEqual("k", cfg["key"])
        self.assertEqual(35928, cfg["port"])
        self.assertIn(str(self.port), cfg["emqx_url"])

    def test_version_tuple(self):
        self.assertEqual((5, 8), bd.ver_tuple("5.8.0"))
        self.assertEqual((5, 6), bd.ver_tuple("5.6.1"))
        self.assertLess(bd.ver_tuple("5.6.1"), (5, 7))

    # ---------------- ★ 最直接的证据：在线客户端没有 callsign ----------------
    def test_detects_attrs_missing_on_live_clients(self):
        STATE["clients"] = [
            {"clientid": "cid-1", "username": "BG5ESN", "ip_address": "10.0.0.1",
             "client_attrs": {}},
            {"clientid": "cid-2", "username": "BG9XXX", "ip_address": "10.0.0.2",
             "client_attrs": {}},
        ]
        live = bd.check_live_clients(bd.Emqx(self.url, "k", "s"))
        self.assertEqual(2, live["total"])
        self.assertEqual(0, live["with_callsign"])
        self.assertEqual(2, live["without"])

        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("ATTRS_NOT_ON_CLIENT", out)
        self.assertIn("没有一个带 callsign 属性", out)

    def test_attrs_ok_on_live_clients(self):
        STATE["clients"] = [
            {"clientid": "cid-1", "username": "BG5ESN",
             "client_attrs": {"callsign": "BG5ESN", "uid": "12345"}}]
        live = bd.check_live_clients(bd.Emqx(self.url, "k", "s"))
        self.assertEqual(1, live["with_callsign"])
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(0, code, out)
        self.assertIn("ATTRS_OK", out)

    # ---------------- 版本过低 ----------------
    def test_detects_old_version(self):
        STATE["version"] = "5.6.1"
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("EMQX_VER_TOO_OLD", out)
        self.assertIn("5.7.0", out)

    # ---------------- 认证请求体 ----------------
    def test_detects_empty_body(self):
        STATE["detail"]["password_based:http:sas"] = {"method": "post", "body": {}}
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("AUTHN_BODY_EMPTY", out)

    def test_detects_missing_password_key(self):
        STATE["detail"]["password_based:http:sas"] = {
            "method": "post", "body": {"user": "${username}", "pass": "${password}"}}
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("AUTHN_BODY_FIELDS", out)

    def test_detects_wrong_method_and_url(self):
        STATE["authn"][0]["url"] = "http://127.0.0.1:35929/admin"
        STATE["detail"]["password_based:http:sas"] = {
            "method": "get", "body": {"username": "${username}", "password": "${password}"}}
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertIn("AUTHN_URL_ODD", out)
        self.assertIn("AUTHN_METHOD", out)

    def test_detects_precondition(self):
        STATE["detail"]["password_based:http:sas"] = {
            "method": "post", "body": {"username": "${username}", "password": "${password}"},
            "precondition": "clientid =~ 'x'"}
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertIn("AUTHN_PRECONDITION", out)

    def test_detects_other_authn(self):
        STATE["authn"].append({"id": "password_based:built_in_database:x",
                               "type": "password_based", "backend": "built_in_database",
                               "mechanism": "password_based", "enable": True})
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertIn("OTHER_AUTHN", out)

    def test_detects_no_http_authn(self):
        STATE["authn"] = [{"id": "password_based:built_in_database:x",
                           "type": "password_based", "backend": "built_in_database",
                           "mechanism": "password_based", "enable": True}]
        code, out = run_self_check(self.tmp, self.url, self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("NO_HTTP_AUTHN", out)

    # ---------------- 缺配置 / 不可达 ----------------
    def test_reports_missing_emqx_cfg(self):
        db = os.path.join(self.tmp, "x_audit.db")
        c = sqlite3.connect(db)
        c.execute("UPDATE settings SET value='' WHERE key IN ('emqx_url','emqx_api_key')")
        c.commit(); c.close()
        code, out = run_self_check(self.tmp, "", self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("EMQX_CFG_MISSING", out)

    def test_reports_emqx_unreachable(self):
        code, out = run_self_check(self.tmp, "http://127.0.0.1:59997", self.sas_url)
        self.assertEqual(1, code, out)
        self.assertIn("EMQX_UNREACHABLE", out)

    def test_audit_scene_summary(self):
        db = os.path.join(self.tmp, "x_audit.db")
        c = sqlite3.connect(db)
        c.execute("INSERT INTO audit_packets(ts, scene, verdict) VALUES('2026-01-01 00:00:00',"
                  "'both_missing','WARN')")
        c.commit(); c.close()
        adb = bd.check_audit_db(self.tmp)
        self.assertTrue(adb["found"])
        self.assertEqual(1, adb["scenes"].get("both_missing"))

    def test_json_output_parsable(self):
        STATE["clients"] = [{"clientid": "c1", "username": "BG5ESN", "client_attrs": {}}]
        cmd = [sys.executable, BAS_DIAGNOSE, "--diagnose", "--json", "--base-dir", self.tmp,
               "--emqx-url", self.url, "--key", "k", "--secret", "s"]
        p = subprocess.run(cmd, capture_output=True, timeout=60,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        r = json.loads((p.stdout or b"").decode("utf-8"))
        self.assertIn("findings", r)
        self.assertEqual(1, r["live_clients"]["total"])

    # ---------------- 无需参数也能跑（curl 管道场景） ----------------
    def test_runs_with_no_args(self):
        cmd = [sys.executable, BAS_DIAGNOSE]
        p = subprocess.run(cmd, capture_output=True, timeout=60,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        out = (p.stdout or b"").decode("utf-8", "replace")
        self.assertIn("BAS 链路自检", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
