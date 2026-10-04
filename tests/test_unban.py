#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解封测试（真实事故回归）
========================
事故：反滥用按 **clientid / peerhost** 封禁，而解封只按 **username** 删 →
EMQX 返回 404 → 旧代码把 404 当成功 → 界面显示"已解封"，封禁还在，**用户怎么也连不回来**。

修正后：
  * 不指定维度时，依次尝试 username / clientid / peerhost，并如实报告解掉了哪个
  * 支持按维度精确解封
  * 支持一键清空（按每条自己的维度删）
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService


class FakeEmqx(object):
    """带真实"封禁名单"语义的桩：DELETE 不存在的条目返回 404"""

    def __init__(self, bans=None):
        # bans: {"username": {...}, "clientid": {...}, "peerhost": {...}}
        self.bans = bans or {}
        self.calls = []

    def unban_strict(self, who, as_type="username"):
        self.calls.append((as_type, who))
        entries = self.bans.get(as_type) or {}
        if who in entries:
            entries.pop(who)
            return True, True, None
        return True, False, None          # 404 → 本来就没有

    def unban(self, who, as_type="username"):
        ok, existed, err = self.unban_strict(who, as_type)
        return ok, err

    def list_banned(self, limit=10000):
        out = []
        for a, entries in self.bans.items():
            for who in list(entries):
                out.append({"as": a, "who": who})
        return out

    def ban(self, who, reason="", as_type="username", until=None):
        self.bans.setdefault(as_type, {})[who] = reason
        return True, None

    def ban_username(self, username, reason="", until=None):
        self.bans.setdefault("username", {})[username] = reason
        return True, None, 1

    def kick_clients(self, ids):
        return True, None

    def list_clients(self, limit=1000, fields=None):
        return []


class UnbanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-unban-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _svc_with(self, bans):
        em = FakeEmqx(bans)
        self.svc.emqx = em
        return em

    # ---------------- ★ 核心回归：不指定维度要能解掉 clientid 封禁 ----------------
    def test_unban_without_type_removes_clientid_ban(self):
        em = self._svc_with({"clientid": {"FMO-BH6BHG-687-3B2C": "假证书"}})
        ok, err, detail = self.svc.unban("FMO-BH6BHG-687-3B2C")
        self.assertTrue(ok, err)
        self.assertEqual({}, em.bans["clientid"], "clientid 封禁必须被解掉")
        self.assertIn("clientid", detail)

    def test_unban_without_type_removes_peerhost_ban(self):
        em = self._svc_with({"peerhost": {"223.160.149.169": "反复假证书"}})
        ok, err, detail = self.svc.unban("223.160.149.169")
        self.assertTrue(ok, err)
        self.assertEqual({}, em.bans["peerhost"])
        self.assertIn("peerhost", detail)

    def test_unban_without_type_removes_username_ban(self):
        em = self._svc_with({"username": {"BG9BAD": "伪造"}})
        ok, _err, detail = self.svc.unban("BG9BAD")
        self.assertTrue(ok)
        self.assertEqual({}, em.bans["username"])
        self.assertIn("username", detail)

    def test_unban_reports_all_dimensions_removed(self):
        em = self._svc_with({"username": {"X": "a"}, "clientid": {"X": "b"}})
        ok, _err, detail = self.svc.unban("X")
        self.assertTrue(ok)
        self.assertIn("username", detail)
        self.assertIn("clientid", detail)

    def test_unban_when_nothing_banned(self):
        em = self._svc_with({})
        ok, err, detail = self.svc.unban("NOBODY")
        self.assertTrue(ok, err)
        self.assertIn("本来就没有", detail)

    def test_unban_explicit_type_only(self):
        em = self._svc_with({"username": {"X": "a"}, "clientid": {"X": "b"}})
        ok, _err, detail = self.svc.unban("X", "admin", "clientid")
        self.assertTrue(ok)
        self.assertEqual({"X": "a"}, em.bans["username"], "指定维度时不该动其它维度")
        self.assertEqual({}, em.bans["clientid"])

    def test_unban_empty_who(self):
        self._svc_with({})
        ok, err, _d = self.svc.unban("")
        self.assertFalse(ok)

    # ---------------- 一键清空 ----------------
    def test_unban_all_clears_every_dimension(self):
        em = self._svc_with({
            "username": {"A": "x"},
            "clientid": {"B": "y", "C": "z"},
            "peerhost": {"203.0.113.9": "w"},
        })
        ok, err, detail = self.svc.unban_all()
        self.assertTrue(ok, err)
        self.assertEqual({}, {k: v for k, v in em.bans.items() if v}, "名单必须清空")
        self.assertIn("已解封", detail)

    def test_unban_all_on_empty(self):
        em = self._svc_with({})
        ok, err, detail = self.svc.unban_all()
        self.assertTrue(ok, err)
        self.assertIn("已解封 0", detail)

    # ---------------- 待审放行也要能解 clientid ----------------
    def test_release_quarantine_unbans_clientid_too(self):
        em = self._svc_with({"clientid": {"cid-9": "假证书"}})
        self.db.add_quarantine({"conn_callsign": "BH6BHG", "clientid": "cid-9",
                                "scene": "fake_cert", "reason": "误判申诉"})
        q = self.db.list_quarantine("pending")[0]
        ok, err = self.svc.release_quarantine(q["id"], "admin")
        self.assertTrue(ok, err)
        self.assertEqual({}, em.bans["clientid"], "放行时必须连 clientid 封禁一起解掉")


if __name__ == "__main__":
    unittest.main(verbosity=2)
