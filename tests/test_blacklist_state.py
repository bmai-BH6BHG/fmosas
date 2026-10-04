#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
黑名单状态与界面刷新
====================
真实故障：两个呼号在 EMQX 里已经解封了，界面却一直显示"拉黑中"。

两个原因：
  1) `active_blacklist()` 只按 who 分组 → 同一个 who 在别的维度解封后，
     仍被旧的 ban 行遮住（必须按 (who, as_type) 分组）
  2) 审计表是**历史流水**，不是权威状态 —— 在 EMQX 侧直接解封（或封禁自然到期）时
     这里不会自动产生 unban 行，于是永远显示"生效中"
     → 接口必须拿 EMQX 的实时名单核对，把对不上的标为"已失效"
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB


class ActiveBlacklistStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-bl-")
        self.db = AuditDB(self.tmp + "/a.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ban(self, who, as_type="username", until="2999-01-01T00:00:00+08:00"):
        self.db.add_blacklist_event("ban", who, "测试", until, "admin", as_type)

    def _unban(self, who, as_type="username"):
        self.db.add_blacklist_event("unban", who, "手动解封", None, "admin", as_type)

    def _active(self):
        return {(r["who"], r["as_type"]) for r in self.db.active_blacklist()}

    # ---------------- 基本语义 ----------------
    def test_ban_then_unban_is_not_active(self):
        self._ban("BH6BHG")
        self.assertEqual({("BH6BHG", "username")}, self._active())
        self._unban("BH6BHG")
        self.assertEqual(set(), self._active(), "解封后不得再显示为生效中")

    def test_expired_ban_is_not_active(self):
        self._ban("BG9XXX", until="2000-01-01T00:00:00+08:00")
        self.assertEqual(set(), self._active(), "已到期应自动视为解封")

    # ---------------- ★ 回归：必须按 (who, as_type) 分组 ----------------
    def test_partitions_by_as_type(self):
        """同一呼号在 clientid 维度解封，不得影响 username 维度的生效状态"""
        self._ban("BH6BHG", "username")
        self._ban("BH6BHG", "clientid")
        self.assertEqual({("BH6BHG", "username"), ("BH6BHG", "clientid")}, self._active())
        self._unban("BH6BHG", "clientid")
        self.assertEqual({("BH6BHG", "username")}, self._active(),
                         "★ 只解了 clientid 维度，username 维度应仍然生效")

    def test_unban_all_dimensions_clears(self):
        self._ban("BH6BHG", "username")
        self._ban("BH6BHG", "clientid")
        self._ban("BH6BHG", "peerhost")
        for t in ("username", "clientid", "peerhost"):
            self._unban("BH6BHG", t)
        self.assertEqual(set(), self._active())

    def test_multiple_callsigns_independent(self):
        self._ban("BH6BHG")
        self._ban("BH6FWE")
        self._unban("BH6BHG")
        self.assertEqual({("BH6FWE", "username")}, self._active(),
                         "解封一个不应影响另一个")


class StaleReconcileTests(unittest.TestCase):
    """接口层核对逻辑（用与 bas_http 相同的判定方式）"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-stale-")
        self.db = AuditDB(self.tmp + "/a.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_stale_detected_when_missing_in_emqx(self):
        self.db.add_blacklist_event("ban", "BH6BHG", "测试", None, "admin", "username")
        rows = self.db.active_blacklist()
        live = set()          # EMQX 里已经什么都没有了（手动解封/到期）
        active = [r for r in rows
                  if (r["as_type"], r["who"]) in live]
        stale = [r for r in rows
                 if (r["as_type"], r["who"]) not in live]
        self.assertEqual([], active)
        self.assertEqual(1, len(stale), "EMQX 中不存在的记录应被标为已失效")

    def test_sync_writes_unban_and_clears(self):
        self.db.add_blacklist_event("ban", "BH6BHG", "测试", None, "admin", "username")
        for r in self.db.active_blacklist():
            if (r["as_type"], r["who"]) not in set():
                self.db.add_blacklist_event("unban", r["who"],
                                            "同步：EMQX 中已无此封禁", None, "admin",
                                            r["as_type"])
        self.assertEqual([], self.db.active_blacklist(), "同步后不应再生效")


if __name__ == "__main__":
    unittest.main(verbosity=2)
