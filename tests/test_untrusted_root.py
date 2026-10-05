#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
未信任根台账测试
================
背景：客户端拿「本机不认识的根 CA」签发的证书来登录会被拒，但拒绝原因里
曾经只有根公钥的**前 20 个字符**，管理员既核对不了来源、也复制不出完整值
去加白 —— 出现「看得见问题、修不了」。本次修复要求：

  * sas_server 的拒绝原因与返回值带**完整**公钥
  * 审计层把完整公钥入 untrusted_roots 台账（含次数、自称呼号数）
  * 「根不受信任」仍然**只留证不封禁**（防误封，不能被这次改动破坏）
  * /api/bas/health 能列出这些根
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService

FULL_ROOT = "jjKr29sdbJm6HGtI3HdA_-8xQ2mNb7vKc1pLw0dRt5YsZ9aE"
OTHER_ROOT = "P1BHAVNjSzzWVSxB0xpFoD--Q6YnBhgL37S1B-ePcaU"


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


class UntrustedRootLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-uroot-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.emqx = _FakeEmqx()
        self.svc.emqx = self.emqx

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reject(self, cs="BG3TCD", cid="FMO-BG3TCD-1217-1E47", ip="120.207.129.81",
                root=FULL_ROOT):
        return self.svc.record_auth_rejection(
            cs, cid, ip, "根 CA 不受信任（公钥=%s）" % root, root_pubkey=root)

    # ---------- 台账 ----------
    def test_full_key_is_recorded_not_truncated(self):
        r = self._reject()
        self.assertEqual(FULL_ROOT, r.get("untrusted_root"))
        rows = self.db.list_untrusted_roots()
        self.assertEqual(1, len(rows))
        self.assertEqual(FULL_ROOT, rows[0]["root_pubkey"])
        self.assertEqual(len(FULL_ROOT), len(rows[0]["root_pubkey"]))
        self.assertEqual(1, rows[0]["hits"])

    def test_repeated_hits_accumulate_and_track_callsigns(self):
        self._reject(cid="cid-1")
        self._reject(cid="cid-2")
        self._reject(cs="BG3TXX", cid="cid-3")     # 换了个自称呼号
        rows = self.db.list_untrusted_roots()
        self.assertEqual(1, len(rows), "同一根只应有一条，累计次数")
        self.assertEqual(3, rows[0]["hits"])
        self.assertEqual(2, rows[0]["distinct_cs"], "自称呼号去重数应递增")
        self.assertEqual("BG3TXX", rows[0]["last_callsign"])

    def test_different_roots_are_separate_rows(self):
        self._reject(root=FULL_ROOT)
        self._reject(root=OTHER_ROOT)
        rows = self.db.list_untrusted_roots()
        self.assertEqual(2, len(rows))
        self.assertEqual({FULL_ROOT, OTHER_ROOT},
                         {r["root_pubkey"] for r in rows})

    def test_first_ts_is_kept_across_hits(self):
        self._reject()
        first = self.db.list_untrusted_roots()[0]["first_ts"]
        self._reject()
        row = self.db.list_untrusted_roots()[0]
        self.assertEqual(first, row["first_ts"], "首次出现时间不应被后续命中覆盖")

    def test_empty_root_key_is_ignored(self):
        self.svc.record_auth_rejection("BG3TCD", "cid", "1.2.3.4",
                                       "根 CA 不受信任（公钥=...）", root_pubkey="")
        self.assertEqual([], self.db.list_untrusted_roots())

    # ---------- 防误封不能被破坏 ----------
    def test_untrusted_root_still_never_bans(self):
        """「根不受信任」默认只留证：clientid / IP / 呼号一个都不封。"""
        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True
        r = self._reject()
        self.assertFalse(r.get("banned_clientid"))
        self.assertFalse(r.get("banned_peerhost"))
        self.assertEqual([], self.emqx.bans, "不应有任何封禁动作")
        self.assertEqual([], self.emqx.kicked)

    def test_ledger_written_even_though_no_ban(self):
        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True
        self._reject()
        self.assertEqual(1, len(self.db.list_untrusted_roots()),
                         "soft 路径也必须入台账，否则最需要线索时反而没记录")

    def test_other_rejection_still_bans_clientid(self):
        """真伪造（proof 验签失败）仍应封 clientid，不能被本次改动削弱。"""
        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True
        r = self.svc.record_auth_rejection(
            "BG3TCD", "FMO-x-1", "1.2.3.4", "proof 签名验证失败")
        self.assertTrue(r.get("banned_clientid"))
        self.assertEqual("", r.get("untrusted_root"))

    # ---------- 其它 ----------
    def test_prune_keeps_recent(self):
        self._reject()
        n = self.db.prune_untrusted_roots(days=90)
        self.assertEqual(0, n, "90 天内的不该被清")
        self.assertEqual(1, len(self.db.list_untrusted_roots()))

    def test_health_payload_includes_roots(self):
        import inspect
        from bas_http import BasHttp
        src = inspect.getsource(BasHttp._dispatch)
        self.assertIn("untrusted_roots", src,
                      "/api/bas/health 必须带出未信任根清单")


class SasFullKeyTests(unittest.TestCase):
    def test_denied_reason_carries_full_key(self):
        """sas_server 不再把根公钥截断成 20 字符。"""
        import inspect
        import sas_server
        src = inspect.getsource(sas_server.authenticate)
        self.assertNotIn("root_pub_b64[:20]", src, "根公钥不得再截断")
        self.assertIn("untrusted_root_pubkey", src,
                      "deny 返回值要带完整公钥供审计层入账")


if __name__ == "__main__":
    unittest.main(verbosity=2)