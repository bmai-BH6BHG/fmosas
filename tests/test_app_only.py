#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
「只许本 APP 上来」规则测试
==========================
现场要求：
  * 从本 APP 上来的（clientid 形如 FMO-<呼号>-<uid>-<hex> 且带 SAS 证书身份）
    —— **即使 UID 一样（多设备/多开）也允许登录**，绝不封
  * 不是本 APP 上来的（含"伪造成 FMO- 形态但没有证书身份"的冒充者）—— 封死
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService
from bas_emqx import EmqxClient
from bas_identity import IdentityPolicy, PASS, WARN


def app_client(cid, cs, uid):
    """按 EmqxClient 真实归一化后的形态构造（uid/callsign 会被提到顶层）"""
    return EmqxClient._normalize_client({
        "clientid": cid, "username": cs,
        "client_attrs": {"callsign": cs, "uid": uid}})


def anon_client(cid, username=""):
    return EmqxClient._normalize_client({
        "clientid": cid, "username": username, "client_attrs": {}})


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.p = IdentityPolicy()

    def test_app_client_with_cert_is_app(self):
        ok, exempt, _why = self.p.client_is_app(app_client("FMO-BH6BHG-1075-B373", "BH6BHG", "1075"))
        self.assertTrue(ok)
        self.assertFalse(exempt)

    def test_same_uid_multiple_devices_still_app(self):
        """同一 uid 的两个不同 clientid（多设备/多开）都算本 APP"""
        a, _, _ = self.p.client_is_app(app_client("FMO-BH6BHG-1075-B373", "BH6BHG", "1075"))
        b, _, _ = self.p.client_is_app(app_client("FMO-BH6BHG-1075-FB08", "BH6BHG", "1075"))
        self.assertTrue(a and b)

    def test_spoofed_clientid_without_cert_is_not_app(self):
        """★ 关键：clientid 装成 APP 形态，但没有证书身份 → 不算本 APP（要封）"""
        ok, exempt, why = self.p.client_is_app({"clientid": "FMO-BH6BHG-1075-AAAA",
                                                "client_attrs": {}})
        self.assertFalse(ok)
        self.assertFalse(exempt)
        self.assertIn("client_attrs", why)

    def test_random_clientid_not_app(self):
        ok, exempt, _ = self.p.client_is_app(anon_client("hacker-1234"))
        self.assertFalse(ok)
        self.assertFalse(exempt)

    def test_internal_clients_exempt(self):
        for cid in ("FMO-MONITOR-sub-1", "fmo-web-ptt-abc"):
            _, exempt, _ = self.p.client_is_app(anon_client(cid))
            self.assertTrue(exempt, cid)

    def test_app_only_verdict_values(self):
        self.assertEqual("ban", self.p.app_only_verdict())
        self.p.cfg["app_only_verdict"] = "off"
        self.assertEqual("off", self.p.app_only_verdict())
        self.p.cfg["app_only_verdict"] = "garbage"
        self.assertEqual("warn", self.p.app_only_verdict())


class EnforceTests(unittest.TestCase):
    """采集器里的实际处置（用桩 EMQX 的 clients 列表驱动）"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-apponly-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.bans = []
        self.svc.policy.ban_recorder = lambda cs, r, h: (self.bans.append((cs, h)), True)[1]
        self.svc.policy.cfg["app_only_verdict"] = "ban"
        self.svc.policy.cfg["app_confirm_rounds"] = 2
        self.svc.policy.cfg["ban_hours"] = 24

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, clients, rounds=1):
        for _ in range(rounds):
            self.svc._enforce_app_only(clients)

    def test_app_clients_never_banned(self):
        """★ 本 APP 多设备（同 uid 两条连接）连续多轮，绝不封"""
        clients = [app_client("FMO-BH6BHG-1075-B373", "BH6BHG", "1075"),
                   app_client("FMO-BH6BHG-1075-FB08", "BH6BHG", "1075")]
        self._run(clients, rounds=5)
        self.assertEqual([], self.bans, "APP 多设备被误封: %s" % self.bans)

    def test_non_app_client_banned_after_confirm_rounds(self):
        """非本 APP 的连接：连续 2 轮确认后封禁"""
        clients = [anon_client("hacker-1234", "BADUSER")]
        self._run(clients, rounds=1)
        self.assertEqual([], self.bans, "第 1 轮不应立即封（防抖）")
        self._run(clients, rounds=1)
        self.assertEqual(1, len(self.bans), "第 2 轮应封: %s" % self.bans)
        self.assertEqual("BADUSER", self.bans[0][0])
        self.assertEqual(24, self.bans[0][1], "封禁必须有期限（不再是 infinity）")

    def test_spoofed_fmo_clientid_is_banned(self):
        """伪造成 FMO- 形态但没有证书身份 → 封"""
        clients = [anon_client("FMO-BH6BHG-1075-EVIL", "BH6BHG")]
        self._run(clients, rounds=2)
        self.assertEqual(["BH6BHG"], [b[0] for b in self.bans])

    def test_exempt_internal_clients_not_banned(self):
        clients = [anon_client("fmo-web-ptt-pwza"), anon_client("FMO-MONITOR-sub-1")]
        self._run(clients, rounds=5)
        self.assertEqual([], self.bans)

    def test_off_mode_does_nothing(self):
        self.svc.policy.cfg["app_only_verdict"] = "off"
        self._run([anon_client("hacker-1", "X")], rounds=5)
        self.assertEqual([], self.bans)

    def test_audit_row_written_for_non_app(self):
        self._run([anon_client("hacker-1234", "BADUSER")], rounds=2)
        rows = self.db.query_audit_packets()
        self.assertTrue(rows)
        self.assertEqual("non_app_client", rows[0]["scene"])

    def test_dup_identity_all_app_is_passed(self):
        """★ 重复身份检测：全是本 APP → 判定 PASS（放行），不封"""
        self.svc.policy.ban_recorder = lambda cs, r, h: (self.bans.append(cs), True)[1]
        clients = [app_client("FMO-BH6BHG-1075-B373", "BH6BHG", "1075"),
                   app_client("FMO-BH6BHG-1075-FB08", "BH6BHG", "1075"),
                   app_client("FMO-BH6BHG-1075-8F43", "BH6BHG", "1075")]
        for _ in range(5):
            self.svc._detect_duplicate_identity(clients)
        self.assertEqual([], self.bans, "本 APP 同 uid 多连接被误封: %s" % self.bans)
        rows = self.db.query_audit_packets()
        self.assertTrue(any(r["scene"] == "dup_identity" and r["verdict"] == PASS
                            for r in rows), [dict(r) for r in rows])


if __name__ == "__main__":
    unittest.main(verbosity=2)
