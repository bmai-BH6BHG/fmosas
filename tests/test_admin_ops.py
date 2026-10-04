#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
后台管理能力测试（扩充 BAS 审计）
=================================
覆盖：
  * 白名单增删（只影响自动封禁，管理员手动封禁不受限）
  * 审计事件清理（按天数 / 按场景）
  * 踢下线（只踢不封）
  * 按 IP 封禁（非法 IP 必须拒绝）
  * 连接登记清理
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService


class _FakeEmqx(object):
    def __init__(self):
        self.kicked = []
        self.bans = []

    def kick_clients(self, ids):
        self.kicked.extend(ids)
        return True, None

    def ban(self, who, reason="", as_type="username", until=None):
        self.bans.append((as_type, who, until))
        return True, None

    def list_clients(self, limit=1000, fields=None):
        return []

    def unban(self, who, as_type="username"):
        return True, None

    def unban_strict(self, who, as_type="username"):
        return True, False, None


class AdminOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-admin-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.emqx = _FakeEmqx()
        self.svc.emqx = self.emqx

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------------- 白名单 ----------------
    def test_whitelist_add_remove(self):
        self.assertEqual([], self.svc.whitelist_list())
        ok, _ = self.svc.whitelist_add("bh6bhg")
        self.assertTrue(ok)
        self.assertEqual(["BH6BHG"], self.svc.whitelist_list(), "呼号应大写归一")
        ok, msg = self.svc.whitelist_add("BH6BHG")
        self.assertTrue(ok)
        self.assertEqual(["BH6BHG"], self.svc.whitelist_list(), "重复加入不叠加")
        self.svc.whitelist_remove("BH6BHG")
        self.assertEqual([], self.svc.whitelist_list())

    def test_whitelist_persists_across_reload(self):
        self.svc.whitelist_add("BH6BHG")
        self.svc.reload_policy()
        self.assertIn("BH6BHG", self.svc.whitelist_list(), "白名单要落库持久化")

    def test_whitelist_blocks_auto_ban_only(self):
        """白名单内的呼号不会被自动封禁（手动封禁不受限）"""
        self.svc.whitelist_add("BH6BHG")
        self.assertTrue(self.svc.policy.in_whitelist("BH6BHG"))

    # ---------------- 踢下线 ----------------
    def test_kick_client(self):
        ok, err = self.svc.kick_client("FMO-BH6BHG-1-ABCD")
        self.assertTrue(ok, err)
        self.assertEqual(["FMO-BH6BHG-1-ABCD"], self.emqx.kicked)
        self.assertEqual([], self.emqx.bans, "踢下线不得顺带封禁")

    def test_kick_requires_clientid(self):
        ok, err = self.svc.kick_client("")
        self.assertFalse(ok)

    # ---------------- 按 IP 封禁 ----------------
    def test_ban_ip_valid(self):
        ok, err = self.svc.ban_ip("112.251.207.117", 24, "测试")
        self.assertTrue(ok, err)
        self.assertIn(("peerhost", "112.251.207.117"), [(a, w) for a, w, _u in self.emqx.bans])

    def test_ban_ip_rejects_garbage(self):
        for bad in ("", "not-an-ip", "999.1.1.1", "BH6BHG"):
            ok, err = self.svc.ban_ip(bad)
            self.assertFalse(ok, "%r 不该被接受" % bad)
        self.assertEqual([], self.emqx.bans)

    def test_ban_ip_default_hours_is_finite(self):
        self.svc.ban_ip("203.0.113.7")
        _t, _w, until = self.emqx.bans[0]
        self.assertNotEqual("infinity", str(until), "手动封 IP 也要有期限")

    # ---------------- 审计清理 ----------------
    def test_prune_audit_packets_by_days(self):
        for _ in range(3):
            self.db.write_audit_packet({
                "ts": "2000-01-01 00:00:00", "topic": "", "clientid": "c1",
                "conn_callsign": "BH6BHG", "verdict": "KICK", "scene": "fake_cert",
                "reason": "旧事件", "confidence": 0.9,
            })
        self.db.write_audit_packet({
            "ts": "2099-01-01 00:00:00", "topic": "", "clientid": "c2",
            "conn_callsign": "BH6FWE", "verdict": "PASS", "scene": "pass",
            "reason": "新事件", "confidence": 1.0,
        })
        n = self.db.prune_audit_packets(days=30)
        self.assertEqual(3, n, "只清 30 天前的")
        self.assertEqual(1, self.db.count_audit_packets(), "新事件必须留着")

    def test_prune_audit_by_scene(self):
        for scene in ("fake_cert", "pass"):
            self.db.write_audit_packet({
                "ts": "2000-01-01 00:00:00", "topic": "", "clientid": scene,
                "conn_callsign": "X", "verdict": "KICK", "scene": scene,
                "reason": scene, "confidence": 1.0,
            })
        n = self.db.prune_audit_packets(days=30, scene="fake_cert")
        self.assertEqual(1, n)
        self.assertEqual(1, self.db.count_audit_packets("fake_cert") + 1, 2)

    def test_count_by_scene(self):
        self.db.write_audit_packet({
            "ts": "2099-01-01 00:00:00", "topic": "", "clientid": "c",
            "conn_callsign": "X", "verdict": "KICK", "scene": "fake_cert",
            "reason": "x", "confidence": 1.0,
        })
        self.assertEqual(1, self.db.count_audit_packets("fake_cert"))
        self.assertEqual(1, self.db.count_audit_packets())

    # ---------------- 连接登记清理 ----------------
    def test_prune_client_seen(self):
        self.db.add_client_seen("BH6BHG", "1", "cid-1", "1.1.1.1",
                                ts="2000-01-01 00:00:00.000")
        self.db.add_client_seen("BH6FWE", "405", "cid-2", "2.2.2.2")
        n = self.db.prune_client_seen(days=7)
        self.assertEqual(1, n)
        rows = self.db.recent_clients(minutes=60 * 24 * 365 * 30)
        self.assertEqual(["BH6FWE"], [r["callsign"] for r in rows])


if __name__ == "__main__":
    unittest.main(verbosity=2)
