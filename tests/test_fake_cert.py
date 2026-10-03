#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
假证书 / 认证失败的反滥用处置测试
==================================
现场要求：**盗用呼号、假证书都要封**。但必须避免一个陷阱：
  攻击者可以拿**别人的呼号**配假证书连接 —— 如果按呼号封，
  等于帮攻击者把无辜用户封掉（栽赃）。

因此本测试锁定：
  * 假证书（根不受信任/验签失败/吊销）→ 留证(scene=fake_cert) + 封 clientid
  * 同一 IP 反复尝试到阈值 → 封 IP（短时）
  * **绝不按呼号封**（除非显式打开 fake_cert_callsign_ban）
  * 非凭证类失败（如少字段）→ 只记录不处置
"""

import shutil
import tempfile
import time
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService, KICK


class FakeEmqx(object):
    """记录所有封禁/踢人调用的桩"""

    def __init__(self):
        self.bans = []          # (who, as_type, reason, until)
        self.kicks = []

    def ban(self, who, reason="", as_type="username", until=None):
        self.bans.append((who, as_type, reason, until))
        return True, None

    def ban_username(self, username, reason="", until=None):
        self.bans.append((username, "username", reason, until))
        self.kicks.append([username])
        return True, None, 1

    def kick_clients(self, ids):
        self.kicks.append(list(ids))
        return True, None

    def list_clients(self, limit=1000, fields=None):
        return []


class FakeCertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-fakecert-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})
        self.emqx = FakeEmqx()
        self.svc.emqx = self.emqx
        self.svc.policy.cfg.update({
            "fake_cert_ban_clientid": True,
            "fake_cert_callsign_ban": False,
            "fake_cert_ip_ban_after": 3,
            "fake_cert_window_sec": 300,
            "fake_cert_ip_ban_hours": 1,
            "ban_hours": 24,
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _types(self):
        return [(w, t) for (w, t, _r, _u) in self.emqx.bans]

    # ---------------- 假证书 → 封 clientid，不碰呼号 ----------------
    def test_fake_root_ca_bans_clientid_not_callsign(self):
        r = self.svc.record_auth_rejection(
            "BH6BHG", "evil-client-1", "203.0.113.9", "根 CA 不受信任（公钥=abc...）")
        self.assertTrue(r["recorded"])
        self.assertTrue(r["banned_clientid"])
        self.assertIn(("evil-client-1", "clientid"), self._types())
        self.assertNotIn(("BH6BHG", "username"), self._types(),
                         "★ 绝不能按呼号封 —— 攻击者可拿别人呼号栽赃")

    def test_bad_proof_bans_clientid(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-2", "198.51.100.7",
                                           "proof 签名验证失败")
        self.assertTrue(r["banned_clientid"])
        self.assertNotIn(("BG5ESN", "username"), self._types())

    def test_revoked_cert_bans_clientid(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-3", "198.51.100.8", "证书已被吊销")
        self.assertTrue(r["banned_clientid"])

    def test_audit_row_written(self):
        self.svc.record_auth_rejection("BG5ESN", "c-4", "198.51.100.9", "根 CA 不受信任")
        rows = self.db.query_audit_packets()
        self.assertTrue(rows)
        self.assertEqual("fake_cert", rows[0]["scene"])
        self.assertEqual(KICK, rows[0]["verdict"])
        self.assertIn("BG5ESN", rows[0]["reason"])
        self.assertIn("198.51.100.9", rows[0]["reason"])

    # ---------------- 非凭证类失败：不处置 ----------------
    def test_missing_fields_not_punished(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-5", "198.51.100.10",
                                           "缺少 username 或 password")
        self.assertFalse(r["recorded"])
        self.assertFalse(r["banned_clientid"])
        self.assertEqual([], self.emqx.bans)
        self.assertEqual([], self.db.query_audit_packets())

    def test_real_world_ca_exception_reason_is_attack(self):
        """实测原因串：Int CA 验证异常: 'sn'（必须被判为凭证类攻击）"""
        r = self.svc.record_auth_rejection("BH6BHG", "c-ca", "203.0.113.77",
                                           "Int CA 验证异常: 'sn'")
        self.assertTrue(r["recorded"])
        self.assertTrue(r["banned_clientid"])

    def test_server_side_error_not_punished(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-6", "198.51.100.11",
                                           "认证异常: 内部错误")
        self.assertFalse(r["recorded"])
        self.assertEqual([], self.emqx.bans)

    # ---------------- 同 IP 反复尝试 → 封 IP ----------------
    def test_repeated_attempts_ban_peerhost(self):
        for i in range(3):
            r = self.svc.record_auth_rejection("BG5ESN", "c-%d" % i, "203.0.113.50",
                                               "根 CA 不受信任")
        self.assertTrue(r["banned_peerhost"], "第 3 次应触发封 IP")
        self.assertIn(("203.0.113.50", "peerhost"), self._types())

    def test_peerhost_counter_resets_after_ban(self):
        for i in range(3):
            self.svc.record_auth_rejection("BG5ESN", "c-%d" % i, "203.0.113.51",
                                           "根 CA 不受信任")
        n_before = len([1 for (w, t) in self._types() if t == "peerhost"])
        self.svc.record_auth_rejection("BG5ESN", "c-x", "203.0.113.51", "根 CA 不受信任")
        n_after = len([1 for (w, t) in self._types() if t == "peerhost"])
        self.assertEqual(n_before, n_after, "封完应重置计数，不要连续重复封")

    def test_old_attempts_outside_window_ignored(self):
        """窗口外的旧记录不应累积到阈值"""
        self.svc.policy.cfg["fake_cert_window_sec"] = 1
        self.svc.record_auth_rejection("BG5ESN", "c-1", "203.0.113.60", "根 CA 不受信任")
        self.svc.record_auth_rejection("BG5ESN", "c-2", "203.0.113.60", "根 CA 不受信任")
        time.sleep(1.2)
        r = self.svc.record_auth_rejection("BG5ESN", "c-3", "203.0.113.60", "根 CA 不受信任")
        self.assertFalse(r["banned_peerhost"], "窗口已过期，不应触发封 IP")

    # ---------------- 显式开启按呼号封（默认关）----------------
    def test_callsign_ban_only_when_explicitly_enabled(self):
        self.svc.policy.cfg["fake_cert_callsign_ban"] = True
        self.svc.record_auth_rejection("BG5ESN", "c-6", "198.51.100.11", "根 CA 不受信任")
        self.assertIn(("BG5ESN", "username"), self._types())

    def test_clientid_ban_can_be_disabled(self):
        self.svc.policy.cfg["fake_cert_ban_clientid"] = False
        r = self.svc.record_auth_rejection("BG5ESN", "c-7", "198.51.100.12", "根 CA 不受信任")
        self.assertTrue(r["recorded"])
        self.assertFalse(r["banned_clientid"])
        self.assertEqual([], self.emqx.bans)

    def test_ban_until_is_finite(self):
        """封禁必须有到期时间（不再 infinity）"""
        self.svc.record_auth_rejection("BG5ESN", "c-8", "198.51.100.13", "根 CA 不受信任")
        _w, _t, _r, until = self.emqx.bans[0]
        self.assertTrue(until)
        self.assertNotEqual("infinity", until)

    # ---------------- 盗用呼号（包内身份不符）→ 真封 ----------------
    def test_forged_callsign_bans_when_ban_mode(self):
        """验证过证书的连接，包内呼号与连接呼号不符 → ban 模式下真封"""
        import base64
        import struct
        from bas_fmo_parser import crc32, HEAD_SIZE

        def pkt(cs, uid):
            # 载荷必须够 8 字节，使总长达到最小合法长度 72（HEAD_SIZE=64）
            frame = bytes([1, 2, 3, 4, 5, 6, 7, 8])
            raw = bytearray(HEAD_SIZE + len(frame))
            struct.pack_into("<H", raw, 0, 2)
            struct.pack_into("<I", raw, 6, uid)
            raw[10:22] = cs.encode()[:12].ljust(12, b"\x00")
            struct.pack_into("<I", raw, 30, len(raw))
            struct.pack_into("<I", raw, 36, crc32(frame))
            raw[HEAD_SIZE:] = frame
            return bytes(raw)

        self.assertTrue(__import__("bas_fmo_parser").parse(pkt("BG9BAD", 4)).ok,
                        "测试包必须是合法包，否则会走 bad_packet 分支")

        self.svc.policy.cfg["mode"] = "ban"
        self.svc.policy.cfg["auto_ban"] = True
        self.svc.policy.ban_recorder = lambda cs, r, h: (
            self.emqx.bans.append((cs, "username", r, h)), True)[1]
        self.svc.policy.sas_lookup = lambda cs: {"uid": 4, "revoked": False}
        self.svc.policy.sas_has_any = lambda: True
        body = {"topic": "FMO/RAW/BH6BHG", "username": "BH6BHG", "clientid": "cid-1",
                "client_attrs": {"callsign": "BH6BHG", "uid": "4"},
                "payload": base64.b64encode(pkt("BG9BAD", 4)).decode()}
        code, _j = self.svc.ingest(self.db.get_ingest_token(), body)
        self.assertEqual(200, code)
        self.assertIn(("BH6BHG", "username"), self._types(),
                      "盗用呼号（包内声明别人）必须被封")


if __name__ == "__main__":
    unittest.main(verbosity=2)
