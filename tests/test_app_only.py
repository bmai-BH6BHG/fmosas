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
        """默认必须是 warn（只留证）：证据太弱，默认封禁会误伤固件与自家 APP"""
        self.assertEqual("warn", self.p.app_only_verdict())
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
        self.bans = []          # [(who, as_type, hours)]
        # 新的实现走 _ban_any（只用 clientid），桩住它来观察"到底按什么维度封"
        self.svc._ban_any = lambda who, reason, hours, as_type="username": (
            self.bans.append((who, as_type, hours)), True)[1]
        self.svc.policy.cfg["app_only_verdict"] = "ban"
        self.svc.policy.cfg["app_confirm_rounds"] = 2
        self.svc.policy.cfg["ban_hours"] = 24
        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True

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

    def test_default_verdict_is_record_only(self):
        """★ 默认（warn）：只留证 + 待审，不封任何人"""
        self.svc.policy.cfg["app_only_verdict"] = "warn"
        self._run([anon_client("hacker-1234", "BADUSER")], rounds=3)
        self.assertEqual([], self.bans, "默认档位绝不能封禁")

    def test_non_app_client_banned_by_clientid_not_callsign(self):
        """★ 回归：封禁只能按 **clientid**，绝不能按"自称的呼号"

        真实事故：这条规则曾按 username 封 → 合法固件 BH6FWE 与用户自己的 APP
        BH6BHG 全被按呼号封掉（客户端的呼号是自己填的，按它封 = 栽赃）。
        """
        clients = [anon_client("hacker-1234", "BADUSER")]
        self._run(clients, rounds=1)
        self.assertEqual([], self.bans, "第 1 轮不应立即封（防抖）")
        self._run(clients, rounds=1)
        self.assertEqual(1, len(self.bans), "第 2 轮应封: %s" % self.bans)
        who, as_type, hours = self.bans[0]
        self.assertEqual("hacker-1234", who, "必须按 clientid 封")
        self.assertEqual("clientid", as_type, "封禁维度必须是 clientid")
        self.assertEqual(24, hours, "封禁必须有期限（不是 infinity）")
        self.assertNotIn("BADUSER", [b[0] for b in self.bans],
                         "★ 绝不能按自称呼号封")

    def test_spoofed_fmo_clientid_is_banned_by_clientid(self):
        """伪造成 FMO- 形态但没有证书身份 → 封 clientid（不碰呼号）"""
        clients = [anon_client("FMO-BH6BHG-1075-EVIL", "BH6BHG")]
        self._run(clients, rounds=2)
        self.assertEqual(["FMO-BH6BHG-1075-EVIL"], [b[0] for b in self.bans])
        self.assertNotIn("BH6BHG", [b[0] for b in self.bans])

    def test_ban_requires_auto_ban_on(self):
        """★ 回归：auto_ban 关着时必须只留证 —— 本次事故正是这条守卫被绕过"""
        self.svc.policy.cfg["auto_ban"] = False
        self._run([anon_client("hacker-1234", "BADUSER")], rounds=3)
        self.assertEqual([], self.bans, "auto_ban 关闭时不得封禁")

    def test_ban_requires_ban_mode(self):
        """★ 回归：mode=warn 时必须只留证"""
        self.svc.policy.cfg["mode"] = "warn"
        self._run([anon_client("hacker-1234", "BADUSER")], rounds=3)
        self.assertEqual([], self.bans, "warn 模式不得封禁")

    def test_whitelisted_callsign_not_banned(self):
        self.svc.policy.cfg["ban_whitelist"] = ["BADUSER"]
        self._run([anon_client("hacker-1234", "BADUSER")], rounds=3)
        self.assertEqual([], self.bans, "白名单呼号不得被封")

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
