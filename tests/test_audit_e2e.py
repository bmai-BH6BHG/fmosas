#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS 端到端测试：token 校验 → 逐包身份判决 → 拉黑/待审 → 采集与重复身份
========================================================================
最关键的一条验收：**SAS 的合法用户在默认策略下不会被误封**
（这正是上游 FAS 部署后把 SAS 呼号全部禁用的那个问题）。
"""

import base64
import json
import os
import shutil
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests import ROOT  # noqa: F401
from bas_fmo_parser import crc32, HEAD_SIZE
from bas_audit_db import AuditDB, now_text
from bas_audit import AuditService
from bas_identity import PASS, WARN, KICK


def build_packet(callsign="BG5ESN", uid=12345, frame=b"\x01\x02\x03\x04\x05\x06\x07\x08"):
    raw = bytearray(HEAD_SIZE + len(frame))
    struct.pack_into("<H", raw, 0, 2)
    struct.pack_into("<I", raw, 2, 0xDEADBEEF)
    struct.pack_into("<I", raw, 6, uid)
    raw[10:22] = callsign.encode()[:12].ljust(12, b"\x00")
    struct.pack_into("<I", raw, 22, 1700000000)
    struct.pack_into("<I", raw, 26, 1700000100)
    struct.pack_into("<I", raw, 30, len(raw))
    struct.pack_into("<H", raw, 34, 7)
    struct.pack_into("<I", raw, 36, crc32(frame))
    raw[40] = 9
    struct.pack_into("<I", raw, 41, 999)
    raw[HEAD_SIZE:] = frame
    return bytes(raw)


# ---------------- 桩 EMQX ----------------
class StubState(object):
    def __init__(self):
        self.clients = []
        self.bans = []
        self.kicks = []
        self.requests = []


STUB = StubState()


class EmqxHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, obj=None):
        b = json.dumps(obj or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?")[0]
        STUB.requests.append(("GET", self.path))
        if path == "/status":
            return self._send(200, {"status": "ok"})
        if self.headers.get("Authorization") != "Basic a2V5OnNlY3JldA==":   # key:secret
            return self._send(401, {"code": "UNAUTHORIZED"})
        if path == "/api/v5/clients":
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            if "username=" in q:
                uname = q.split("username=")[1].split("&")[0]
                rows = [c for c in STUB.clients if c.get("username") == uname]
            else:
                rows = STUB.clients
            return self._send(200, {"data": rows, "meta": {"hasnext": False}})
        if path == "/api/v5/nodes":
            return self._send(200, [{"version": "5.8.0", "node_status": "running",
                                     "connections": len(STUB.clients), "load1": 0.2}])
        if path == "/api/v5/metrics":
            return self._send(200, [{"messages.received": 10, "messages.sent": 20}])
        if path == "/api/v5/alarms":
            return self._send(200, {"data": []})
        return self._send(404, {})

    def do_POST(self):
        body = self._body()
        path = self.path.split("?")[0]
        STUB.requests.append(("POST", self.path))
        if path == "/api/v5/banned":
            STUB.bans.append(json.loads(body or b"{}"))
            return self._send(200, {})
        if path == "/api/v5/clients/kickout/bulk":
            STUB.kicks.append(json.loads(body or b"[]"))
            return self._send(200, {})
        return self._send(404, {})

    def do_DELETE(self):
        path = self.path.split("?")[0]
        STUB.requests.append(("DELETE", self.path))
        if "/api/v5/banned/" in path:
            return self._send(204, {})
        return self._send(404, {})


class AuditServiceE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="bas-e2e-")
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), EmqxHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        STUB.clients = []; STUB.bans = []; STUB.kicks = []; STUB.requests = []
        self.db = AuditDB(os.path.join(self.tmp, "e2e-%d.db" % len(os.listdir(self.tmp))))
        self.db.set_setting("emqx_url", "127.0.0.1:%d" % self.port)
        self.db.set_setting("emqx_api_key", "key")
        self.db.set_setting("emqx_api_secret", "secret")
        # SAS 交叉校验桩：只有 BG5ESN / BG9XXX 是合法呼号
        self.sas = {
            "BG5ESN": {"uid": 12345, "revoked": False},
            "BG9XXX": {"uid": 999, "revoked": False},
            "BG0REV": {"uid": 1, "revoked": True},
        }
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.svc.sas_lookup = lambda cs: self.sas.get((cs or "").upper())
        self.svc.policy.sas_lookup = self.svc.sas_lookup
        # SAS 库里已有注册记录（默认场景）
        self.svc.sas_has_any = lambda: True
        self.svc.policy.sas_has_any = self.svc.sas_has_any

    def _webhook(self, callsign, uid, pkt_callsign, pkt_uid, token=None, clientid="cid-1"):
        body = {
            "topic": "FMO/RAW/BG5ESN",
            "username": callsign,
            "clientid": clientid,
            "payload": base64.b64encode(build_packet(pkt_callsign, pkt_uid)).decode(),
            "qos": 0,
            "client_attrs": {"callsign": callsign, "uid": uid},
        }
        tok = token if token is not None else self.db.get_ingest_token()
        return self.svc.ingest(tok, body)

    # ---------------- token 与格式 ----------------
    def test_ingest_rejects_bad_token(self):
        code, body = self._webhook("BG5ESN", "12345", "BG5ESN", 12345, token="WRONG")
        self.assertEqual(401, code)
        self.assertFalse(body["ok"])
        self.assertEqual(1, self.svc.stats()["auth_rejected"])

    def test_ingest_accepts_valid_token(self):
        code, body = self._webhook("BG5ESN", "12345", "BG5ESN", 12345)
        self.assertEqual(200, code)
        self.assertTrue(body["ok"])

    def test_ingest_tolerates_non_dict(self):
        code, _ = self.svc.ingest(self.db.get_ingest_token(), "not-a-dict")
        self.assertEqual(400, code)

    # ---------------- ★ 核心：合法用户不被误封 ----------------
    def test_legit_sas_user_passes_by_default(self):
        """合法呼号 + 身份一致 → PASS，不落库、不拉黑、不进待审。"""
        self._webhook("BG5ESN", "12345", "BG5ESN", 12345)
        self.assertEqual([], STUB.bans, "合法用户绝不能被拉黑")
        self.assertEqual(0, self.db.stats_summary()["audit_packets"], "PASS 不落库")
        self.assertEqual(0, len(self.db.list_quarantine("pending")))
        self.assertEqual(PASS, PASS)

    def test_legit_user_with_uid_mismatch_is_not_banned_by_default(self):
        """
        ★ 这正是上游 FAS 的误封根因：呼号一致但 UID 不一致。
        默认策略（warn + auto_ban=false）下：只留证 + 入待审，**不拉黑**。
        """
        self._webhook("BG5ESN", "12345", "BG5ESN", 999)
        self.assertEqual([], STUB.bans, "UID 不一致在默认策略下不得拉黑")
        rows = self.db.query_audit_packets()
        self.assertEqual(1, len(rows))
        self.assertEqual("uid_mismatch", rows[0]["scene"])
        self.assertEqual(WARN, rows[0]["verdict"], "默认降级为 WARN")
        self.assertEqual(0, rows[0]["ban"])

    def test_uid_as_number_vs_string_no_false_kick(self):
        """EMQX 可能把 uid 下发成 number，包内是 int → 必须归一后比较（1 != "1" 陷阱）。"""
        self._webhook("BG5ESN", 12345, "BG5ESN", 12345)    # uid 传 number
        self.assertEqual([], STUB.bans)
        self.assertEqual(0, self.db.stats_summary()["audit_packets"])

    def test_partial_attr_missing_is_not_kick(self):
        """只拿到 uid、没有 callsign（属性下发半截）→ 默认 WARN，不 KICK（上游会误判 KICK）。"""
        body = {
            "topic": "FMO/RAW/BG5ESN", "username": "undefined", "clientid": "cid-1",
            "payload": base64.b64encode(build_packet("BG5ESN", 12345)).decode(),
            "client_attrs": {"uid": "12345"},     # 故意没有 callsign
        }
        code, _ = self.svc.ingest(self.db.get_ingest_token(), body)
        self.assertEqual(200, code)
        self.assertEqual([], STUB.bans, "半边身份缺失不得拉黑")
        rows = self.db.query_audit_packets()
        self.assertEqual(1, len(rows))
        self.assertEqual("attr_missing", rows[0]["scene"])
        self.assertEqual(WARN, rows[0]["verdict"])

    def test_no_client_attrs_is_warn_only(self):
        """
        连接完全没有身份（无 client_attrs、username 为空、clientid 里也提不出呼号）
        → 只告警留证。注意：只要 username/clientid 能推出呼号，就会走降级身份路径。
        """
        body = {
            "topic": "FMO/RAW/unknown", "username": "", "clientid": "device-9527",
            "payload": base64.b64encode(build_packet("BG5ESN", 12345)).decode(),
        }
        self.svc.ingest(self.db.get_ingest_token(), body)
        self.assertEqual([], STUB.bans)
        rows = self.db.query_audit_packets()
        self.assertEqual(1, len(rows))
        self.assertEqual("both_missing", rows[0]["scene"])
        self.assertIn("BG5ESN", rows[0]["reason"])   # 记下包内声明身份

    def test_username_fallback_marks_degraded_and_passes(self):
        """没有 client_attrs 但有 username → 降级身份取 username，呼号一致即 PASS。"""
        body = {
            "topic": "FMO/RAW/BG5ESN", "username": "BG5ESN", "clientid": "device-1",
            "payload": base64.b64encode(build_packet("BG5ESN", 12345)).decode(),
        }
        self.svc.ingest(self.db.get_ingest_token(), body)
        self.assertEqual([], STUB.bans)
        self.assertEqual(0, len(self.db.query_audit_packets()), "身份一致 → PASS 不落库")
        self.assertGreaterEqual(self.svc.stats().get("degraded_identity", 0), 1,
                                "应记录降级身份计数，便于发现 EMQX 没下发 client_attrs")

    # ---------------- 伪造：默认只入待审，切 ban 后才真封 ----------------
    def test_forged_callsign_quarantined_by_default(self):
        """呼号被冒充 → KICK + 留证 + 入待审，但默认不执行拉黑。"""
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)
        self.assertEqual([], STUB.bans)
        rows = self.db.query_audit_packets()
        self.assertEqual(1, len(rows))
        self.assertEqual(KICK, rows[0]["verdict"])
        self.assertEqual("forged", rows[0]["scene"])
        quar = self.db.list_quarantine("pending")
        self.assertEqual(1, len(quar))
        self.assertEqual("forged", quar[0]["scene"])

    def test_forged_callsign_banned_in_ban_mode(self):
        """显式切到 ban 模式 + auto_ban → 真拉黑（两步：banned + kickout）。"""
        self.svc.set_policy("mode", "ban")
        self.svc.set_policy("auto_ban", "true")
        STUB.clients = [{"clientid": "cid-1", "username": "BG5ESN", "client_attrs": {}}]
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)
        self.assertEqual(1, len(STUB.bans), "ban 模式下应执行拉黑")
        self.assertEqual("BG5ESN", STUB.bans[0]["who"])
        # ★ 封禁必须有期限：默认 ban_hours=24，绝不再出现 infinity（误封可自愈）
        self.assertNotEqual("infinity", STUB.bans[0]["until"], "不得再永久封禁")
        self.assertTrue(STUB.bans[0]["until"], "应有到期时间")
        self.assertEqual([["cid-1"]], STUB.kicks, "拉黑后必须踢下线")

    def test_whitelist_protects_admin(self):
        self.svc.set_policy("mode", "ban")
        self.svc.set_policy("auto_ban", "true")
        self.svc.set_policy("ban_whitelist", "BG5ESN")
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)
        self.assertEqual([], STUB.bans, "白名单呼号不得被自动封")

    def test_empty_sas_db_must_not_mass_kick(self):
        """
        ★ 新装环境安全阀：SAS 库里还没有任何注册用户时，
        "SAS 里查不到呼号"不能作为伪造证据，否则每个连接都会被判 KICK。
        """
        self.svc.sas_has_any = lambda: False
        self.svc.policy.sas_has_any = self.svc.sas_has_any
        # 连接呼号在（空的）SAS 里查不到 + 包头声明另一个呼号
        self._webhook("BG0NOPE", "1", "BG1FAKE", 2)
        rows = self.db.query_audit_packets()
        self.assertEqual(1, len(rows), "仍应留证")
        self.assertEqual("sas_unavailable", rows[0]["scene"])
        # 但场景降级为 WARN（sas 不可用 → 不封）
        self.assertEqual(WARN, rows[0]["verdict"], "空 SAS 库时不得判 KICK")
        self.assertEqual([], STUB.bans)

    def test_empty_sas_db_blocks_ban_even_in_ban_mode(self):
        """即使显式开了 ban 模式，SAS 库为空时也不得封人（ban_when_sas_unavailable 默认关）。"""
        self.svc.set_policy("mode", "ban")
        self.svc.set_policy("auto_ban", "true")
        self.svc.sas_has_any = lambda: False
        self.svc.policy.sas_has_any = self.svc.sas_has_any
        STUB.clients = [{"clientid": "cid-1", "username": "BG5ESN", "client_attrs": {}}]
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)
        self.assertEqual([], STUB.bans, "SAS 库为空时宁可不封")

    def test_sas_unknown_forged_is_high_confidence(self):
        """SAS 里查不到的"连接呼号" → 高置信度伪造（仍按策略决定是否封）。"""
        self._webhook("BG0NOPE", "1", "BG0NOPE", 1)   # 用不存在的呼号连接，包内身份一致
        # 该场景本身是 PASS（包内=连接）→ 无事件；伪造场景如下
        self._webhook("BG0NOPE", "1", "BG1FAKE", 2)   # 包里声明别的呼号
        rows = self.db.query_audit_packets(verdict=KICK)
        self.assertEqual(1, len(rows))
        self.assertEqual("sas_unknown", rows[0]["scene"])
        self.assertGreaterEqual(rows[0]["confidence"], 0.9)

    def test_revoked_cert_is_kick(self):
        """SAS 中证书已吊销的连接 → KICK（高置信度）。"""
        self._webhook("BG0REV", "1", "BG5ESN", 12345)
        rows = self.db.query_audit_packets(verdict=KICK)
        self.assertEqual(1, len(rows))
        self.assertGreaterEqual(rows[0]["confidence"], 0.9)

    # ---------------- FAIL（非法包）只留证 ----------------
    def test_bad_packet_is_fail_only(self):
        body = {
            "topic": "FMO/RAW/BG5ESN", "username": "BG5ESN", "clientid": "cid-1",
            "payload": base64.b64encode(b"\x00" * 40).decode(),   # 不足 72 字节
            "client_attrs": {"callsign": "BG5ESN", "uid": "12345"},
        }
        self.svc.ingest(self.db.get_ingest_token(), body)
        self.assertEqual([], STUB.bans, "非法包不得拉黑")
        rows = self.db.query_audit_packets(verdict=WARN)
        self.assertEqual(1, len(rows))
        self.assertEqual("bad_packet", rows[0]["scene"])

    # ---------------- 主题统计 ----------------
    def test_topic_stats_written_when_enabled(self):
        self.db.set_setting("topic_enabled", "1")
        self._webhook("BG5ESN", "12345", "BG5ESN", 12345)
        self._webhook("BG5ESN", "12345", "BG5ESN", 12345)
        rows = self.db.topic_timeline("FMO/RAW/BG5ESN", since="2000-01-01 00:00:00",
                                      until="2100-01-01 00:00:00")
        self.assertTrue(rows)
        self.assertEqual(2, rows[0]["msgs"], "同一 10 秒桶应累加")
        self.assertGreater(rows[0]["bytes"], 0)

    # ---------------- 采集 ----------------
    def test_collect_baseline_then_delta(self):
        STUB.clients = [{"clientid": "c1", "username": "BG5ESN",
                         "client_attrs": {"callsign": "BG5ESN", "uid": "12345"},
                         "recv_oct": 100, "send_oct": 200, "recv_msg": 1, "send_msg": 2,
                         "recv_pkt": 3, "send_pkt": 4, "ip_address": "10.0.0.1"}]
        ok, err = self.svc.collect_once()
        self.assertTrue(ok, err)
        self.assertEqual(0, self.db.stats_summary()["minute_stats"], "首轮只建基线")

        STUB.clients[0]["recv_oct"] = 300
        STUB.clients[0]["send_oct"] = 500
        STUB.clients[0]["send_pkt"] = 10
        ok, err = self.svc.collect_once()
        self.assertTrue(ok, err)
        lb = self.db.leaderboard(since="2000-01-01 00:00:00", until="2100-01-01 00:00:00")
        self.assertEqual(1, len(lb))
        self.assertEqual(500, lb[0]["bytes"], "只统计增量（300+500 - 100+200）")

    def test_collect_reconnect_flag_on_counter_reset(self):
        STUB.clients = [{"clientid": "c1", "username": "BG5ESN", "recv_pkt": 5, "send_pkt": 5,
                         "client_attrs": {}}]
        self.svc.collect_once()
        STUB.clients[0]["send_pkt"] = 1        # 计数器归零 = 重连
        self.svc.collect_once()
        import sqlite3
        conn = sqlite3.connect(self.db.path)
        try:
            row = conn.execute("SELECT reconnect FROM minute_stats ORDER BY ts DESC LIMIT 1").fetchone()
        finally:
            conn.close()
        self.assertEqual(1, row[0], "send_pkt 负差分必须标记重连")

    def test_duplicate_uid_from_app_is_allowed(self):
        """
        ★ 现场要求：从本 APP 上来的连接，**即使 uid 相同（多设备/多开）也允许登录**。
        clientid 形如 FMO-<呼号>-<uid>-<hex> 且带 SAS 证书身份 → 一律放行，绝不封。
        """
        STUB.clients = [
            {"clientid": "FMO-BG5ESN-12345-AAAA", "username": "BG5ESN",
             "client_attrs": {"callsign": "BG5ESN", "uid": "12345"}},
            {"clientid": "FMO-BG5ESN-12345-BBBB", "username": "BG5ESN",
             "client_attrs": {"callsign": "BG5ESN", "uid": "12345"}},
            {"clientid": "FMO-BG5ESN-12345-CCCC", "username": "BG5ESN",
             "client_attrs": {"callsign": "BG5ESN", "uid": "12345"}},
        ]
        for _ in range(5):
            self.svc.collect_once()
        self.assertEqual([], STUB.bans, "本 APP 多设备被误封: %s" % STUB.bans)
        rows = self.db.query_audit_packets()
        self.assertTrue(rows, "应留一条「本 APP 多设备」记录（便于统计多开）")
        self.assertEqual("dup_identity", rows[0]["scene"])
        self.assertEqual(PASS, rows[0]["verdict"], "本 APP 多设备必须判 PASS（放行）")

    def test_non_app_client_is_banned(self):
        """不是本 APP 上来的（无证书身份 / clientid 非 APP 形态）→ 封死。"""
        STUB.clients = [{"clientid": "hacker-9527", "username": "BADGUY",
                         "client_attrs": {}}]
        for _ in range(3):
            self.svc.collect_once()
        self.assertTrue(STUB.bans, "非本 APP 连接必须被处置")
        self.assertEqual("BADGUY", STUB.bans[0]["who"])

    def test_cleanup_runs_in_collect_path(self):
        self.db.upsert_minute_stat({"clientid": "old", "ts": "2020-01-01 00:00:00"})
        self.svc._last_cleanup = 0
        STUB.clients = []
        self.svc.collect_once()
        import sqlite3
        conn = sqlite3.connect(self.db.path)
        try:
            n = conn.execute("SELECT COUNT(*) FROM minute_stats").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(0, n, "采集路径内应按间隔触发清理")

    # ---------------- 待审放行（误封救援） ----------------
    def test_quarantine_release_unbans(self):
        self.svc.set_policy("mode", "ban")
        self.svc.set_policy("auto_ban", "true")
        STUB.clients = [{"clientid": "cid-1", "username": "BG5ESN", "client_attrs": {}}]
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)
        self.assertEqual(1, len(STUB.bans))
        # 用户申诉：一键放行
        # 先手动入一条待审（ban 模式下不进待审队列，这里模拟申诉场景）
        self.db.add_quarantine({"conn_callsign": "BG5ESN", "scene": "forged",
                                "reason": "误判申诉", "confidence": 0.9})
        q = self.db.list_quarantine("pending")[0]
        ok, err = self.svc.release_quarantine(q["id"], "admin")
        self.assertTrue(ok, err)
        self.assertEqual("released", self.db.list_quarantine("released")[0]["status"])
        # 解封流水已记录
        hist = self.db.blacklist_history("BG5ESN")
        self.assertTrue(any(h["action"] == "unban" for h in hist))

    # ---------------- 策略持久化 ----------------
    def test_policy_persists_and_reloads(self):
        self.svc.set_policy("uid_mismatch_verdict", "kick")
        self.svc.set_policy("ban_whitelist", "BG1AAA, BG2BBB")
        svc2 = AuditService(self.db, config={"admin_port": 35929})
        self.assertEqual("kick", svc2.policy.cfg["uid_mismatch_verdict"])
        self.assertEqual(["BG1AAA", "BG2BBB"], svc2.policy.cfg["ban_whitelist"])

    def test_ban_mode_still_respects_rate_limit(self):
        """ban 模式下触发自动封禁限流后，超出的只留证不封（防刷）。"""
        self.svc.set_policy("mode", "ban")
        self.svc.set_policy("auto_ban", "true")
        self.svc.set_policy("ban_rate_limit_per_hour", "1")
        STUB.clients = [{"clientid": "cid-1", "username": "BG5ESN", "client_attrs": {}}]
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)      # 第 1 次 → 封
        self._webhook("BG5ESN", "12345", "BG9BAD", 777)      # 第 2 次 → 限流
        self.assertEqual(1, len(STUB.bans), "限流后不得再次封禁")


if __name__ == "__main__":
    unittest.main(verbosity=2)
