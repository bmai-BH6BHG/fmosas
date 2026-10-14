#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests/test_sys_identity_exempt.py —— 系统身份永不被封（真实事故回归）。

事故：审计规则「包头呼号 != 连接呼号」把 SERVER 封了，而 SERVER 是
桥接/监控/DMR 网关的公共身份 —— 一封 → 全站语音中断。
"""
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from bas_audit import AuditService  # noqa: E402


class SysIdentityExemptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = AuditService.__new__(AuditService)   # 不跑 __init__

    def test_detects_sys_identities(self):
        f = AuditService._is_sys_identity
        for w in ("SERVER", "server", " SERVER ", "MASTER", "DMRGW", "BH6BHG"):
            self.assertTrue(f(w), "应识别为系统身份: %r" % w)
        for w in ("BG4QBI", "BH8GPV", "", None, "SERVERX9"):
            self.assertFalse(f(w), "不应识别为系统身份: %r" % w)

    def test_ban_any_refuses_sys_identity(self):
        """系统身份必须封不动（否则一封全站断）。"""
        for who in ("SERVER", "MASTER", "DMRGW"):
            ok = self.svc._ban_any(who, "测试", 1, as_type="username")
            self.assertFalse(ok, "_ban_any 竟然封了系统身份 %s" % who)

    def test_ban_recorder_refuses_sys_identity(self):
        for who in ("SERVER", "MASTER"):
            ok = self.svc._ban_recorder(who, "测试", 1)
            self.assertFalse(ok, "_ban_recorder 竟然封了系统身份 %s" % who)


if __name__ == "__main__":
    unittest.main(verbosity=2)
