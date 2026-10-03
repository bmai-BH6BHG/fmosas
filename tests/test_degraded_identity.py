#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
client_attrs 缺失时的降级身份（username / clientid 兜底）测试
============================================================
现场现象：EMQX 不下发 client_attrs → 连接身份为空 → 审计只能"留证"，
排行榜/在线列表看不到人。

本测试锁定降级行为：
  * username 兜底：连接身份取 username
  * clientid 兜底：从 FMO-BH8GDV-4-5817 这类 clientid 里提取呼号
  * **降级身份绝不自动封人**（即使呼号不符、即使策略是 ban）
  * 仍能完成"包内声明 vs 连接身份"的核对并留证
"""

import base64
import os
import shutil
import struct
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_fmo_parser import crc32, HEAD_SIZE
from bas_audit_db import AuditDB
from bas_audit import AuditService, _callsign_from_clientid
from bas_identity import IdentityPolicy, WARN, KICK, PASS


def packet(callsign="BH8GDV", uid=4):
    frame = bytes([1, 2, 3, 4, 5, 6, 7, 8])
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


class CallsignFromClientIdTests(unittest.TestCase):
    def test_extracts_from_app_clientid(self):
        """实测 APP 的 clientid 形如 FMO-BH8GDV-4-5817"""
        self.assertEqual("BH8GDV", _callsign_from_clientid("FMO-BH8GDV-4-5817"))
        self.assertEqual("BG5ESN", _callsign_from_clientid("fmo_bg5esn_1_2"))
        self.assertEqual("BH1ACG", _callsign_from_clientid("BH1ACG-4-1234"))

    def test_no_callsign_returns_empty(self):
        self.assertEqual("", _callsign_from_clientid("device-1234"))
        self.assertEqual("", _callsign_from_clientid(""))
        self.assertEqual("", _callsign_from_clientid(None))

    def test_does_not_match_inside_longer_token(self):
        """不能把 FMORAW 之类误认成呼号"""
        self.assertEqual("", _callsign_from_clientid("FMORAW-SERVER-01"))


class DegradedPolicyTests(unittest.TestCase):
    """策略层：degraded=True 时绝不封人"""

    def setUp(self):
        self.bans = []
        self.p = IdentityPolicy(
            policy={"mode": "ban", "auto_ban": True},
            sas_lookup=lambda cs: {"uid": 4, "revoked": False},
            ban_recorder=lambda cs, r, h: (self.bans.append(cs), True)[1],
            sas_has_any=lambda: True)

    def test_uid_mismatch_degraded_is_warn_only(self):
        """呼号一致但 UID 不一致 + 降级身份 → 只告警，绝不封"""
        from bas_fmo_parser import parse
        raw = packet("BH8GDV", 999)
        d = self.p.decide(raw, parse(raw), "BH8GDV", "4", degraded=True)
        self.assertEqual(WARN, d.verdict)
        self.assertFalse(d.ban)
        self.assertEqual([], self.bans, "降级身份不得封人")
        self.assertIn("降级来源", d.reason)

    def test_callsign_mismatch_degraded_is_warn_only(self):
        from bas_fmo_parser import parse
        raw = packet("BG9BAD", 4)
        d = self.p.decide(raw, parse(raw), "BH8GDV", "4", degraded=True)
        self.assertEqual(WARN, d.verdict)
        self.assertFalse(d.ban)
        self.assertEqual([], self.bans)

    def test_verified_identity_still_bans(self):
        """对照：非降级（client_attrs 可信）时，呼号不符仍按策略封人"""
        from bas_fmo_parser import parse
        raw = packet("BG9BAD", 4)
        d = self.p.decide(raw, parse(raw), "BH8GDV", "4", degraded=False)
        self.assertEqual(KICK, d.verdict)
        self.assertTrue(d.ban)
        self.assertEqual(["BH8GDV"], self.bans)

    def test_match_passes_even_when_degraded(self):
        from bas_fmo_parser import parse
        raw = packet("BH8GDV", 4)
        d = self.p.decide(raw, parse(raw), "BH8GDV", "4", degraded=True)
        self.assertEqual(PASS, d.verdict)
        # PASS 时也保留来源说明（便于事后区分"证书身份"与"降级身份"）
        self.assertIn("降级来源", d.reason)

    def test_both_missing_reports_packet_identity(self):
        """连接无身份时，原因里要带上包内声明的身份（便于取证）"""
        from bas_fmo_parser import parse
        raw = packet("BH8GDV", 4)
        d = self.p.decide(raw, parse(raw), "", "")
        self.assertEqual(WARN, d.verdict)
        self.assertEqual("both_missing", d.scene)
        self.assertIn("BH8GDV", d.reason, "必须记下包内声明身份")


class IngestFallbackTests(unittest.TestCase):
    """端到端：webhook 不带 client_attrs 时，用 username / clientid 兜底"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-degraded-")
        self.db = AuditDB(os.path.join(self.tmp, "a.db"))
        self.db.set_setting("topic_enabled", "1")
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.svc.sas_lookup = lambda cs: {"uid": 4, "revoked": False}
        self.svc.policy.sas_lookup = self.svc.sas_lookup
        self.svc.sas_has_any = lambda: True
        self.svc.policy.sas_has_any = self.svc.sas_has_any
        self.bans = []
        self.svc.policy.ban_recorder = lambda cs, r, h: (self.bans.append(cs), True)[1]
        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ingest(self, *, attrs_missing=True, clientid="FMO-BH8GDV-4-5817",
                username="BH8GDV", pkt_callsign="BH8GDV", pkt_uid=4):
        body = {
            "topic": "FMO/RAW/BH8GDV", "username": username, "clientid": clientid,
            "payload": base64.b64encode(packet(pkt_callsign, pkt_uid)).decode(),
        }
        if not attrs_missing:
            body["client_attrs"] = {"callsign": "BH8GDV", "uid": "4"}
        return self.svc.ingest(self.db.get_ingest_token(), body)

    def test_username_fallback_marks_degraded(self):
        code, j = self._ingest()
        self.assertEqual(200, code, j)
        # 降级身份计数必须 >0：这是"EMQX 没下发 client_attrs"的可观测信号
        self.assertGreaterEqual(self.svc.stats().get("degraded_identity", 0), 1)
        src = self.svc.stats().get("identity_sources") or {}
        self.assertTrue(any("username" in k for k in src), src)

    def test_clientid_fallback_when_username_undefined(self):
        """username 是 EMQX 的 'undefined' 时，从 clientid 提取呼号"""
        code, _ = self._ingest(username="undefined")
        self.assertEqual(200, code)
        src = self.svc.stats().get("identity_sources") or {}
        self.assertTrue(any("clientid" in k for k in src), src)

    def test_degraded_forgery_is_recorded_but_not_banned(self):
        """包内声明别人呼号 + 降级身份 → 留证 + 待审，但**不封人**"""
        self._ingest(pkt_callsign="BG9BAD", pkt_uid=777)
        self.assertEqual([], self.bans, "降级身份绝不封人")
        rows = self.db.query_audit_packets()
        self.assertTrue(rows, "应留证")
        self.assertEqual(WARN, rows[0]["verdict"])
        self.assertIn("降级来源", rows[0]["reason"])
        self.assertEqual(0, rows[0]["ban"])
        self.assertTrue(self.db.list_quarantine("pending"), "应进待审救援队列")

    def test_verified_forgery_still_bans(self):
        """对照：带 client_attrs 时仍按策略封人（功能没被削弱）"""
        self._ingest(attrs_missing=False, pkt_callsign="BG9BAD", pkt_uid=777)
        self.assertEqual(["BH8GDV"], self.bans)

    def test_audit_row_records_packet_identity(self):
        """两个身份都要落库，便于事后证明"包内声明的谁" """
        self._ingest(pkt_callsign="BG9BAD", pkt_uid=777)
        row = self.db.query_audit_packets()[0]
        self.assertEqual("BG9BAD", row["pkt_callsign"])
        self.assertEqual("777", str(row["pkt_uid"]))
        self.assertEqual("BH8GDV", row["conn_callsign"], "降级身份也要记录")

    def test_topic_stats_still_counted_without_attrs(self):
        self._ingest()
        rows = self.db.topic_timeline("FMO/RAW/BH8GDV", since="2000-01-01 00:00:00",
                                      until="2100-01-01 00:00:00")
        self.assertTrue(rows, "无 client_attrs 也必须计入主题统计")
        self.assertEqual("BH8GDV", rows[0]["name"], "统计里应能显示呼号（来自兜底）")

    def test_leaderboard_visible_via_fallback(self):
        """排行榜要有这个人才行（用户反馈：排行榜里看不到他）"""
        self._ingest()
        # 手动喂一条分钟统计（模拟采集轮询写入），确认按兜底呼号可聚合
        self.db.upsert_minute_stat({"clientid": "FMO-BH8GDV-4-5817", "ts": "2026-10-04 00:53:00",
                                    "username": "BH8GDV", "callsign": "BH8GDV",
                                    "uid": "4", "recv_oct": 100, "send_oct": 200})
        lb = self.db.leaderboard(since="2026-10-01 00:00:00", until="2026-10-05 00:00:00")
        self.assertTrue(lb)
        self.assertEqual("BH8GDV", lb[0]["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
