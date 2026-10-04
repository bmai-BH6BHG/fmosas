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
            # 这些用例测的是"封禁路径本身"，必须先打开全局闸门；
            # 闸门关闭时的行为由 BanGateTests 覆盖（warn/auto_ban=0 一律不封）
            "mode": "ban",
            "auto_ban": True,
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _types(self):
        return [(w, t) for (w, t, _r, _u) in self.emqx.bans]

    # ---------------- 根 CA 不受信任：默认只留证（很可能是跨服合法证书）----------------
    def test_untrusted_root_records_but_does_not_ban(self):
        """
        ★ 真实事故回归：本条曾把 12 个真实用户 clientid + 1 个整段公网 IP 封掉。
        "根不受信任" ≠ 伪造 —— 可能只是本机还没信任那个跨服 CA。
        """
        r = self.svc.record_auth_rejection(
            "BH6BHG", "evil-client-1", "203.0.113.9", "根 CA 不受信任（公钥=abc...）")
        self.assertTrue(r["recorded"], "必须留证")
        self.assertFalse(r["banned_clientid"], "默认不得封 clientid")
        self.assertFalse(r["banned_peerhost"], "默认不得封 IP")
        self.assertEqual([], self.emqx.bans)
        self.assertIn("只留证", r["note"])

    def test_untrusted_root_bans_when_opted_in(self):
        self.svc.policy.cfg["fake_cert_untrusted_root_verdict"] = "ban"
        r = self.svc.record_auth_rejection("BH6BHG", "c-ur", "203.0.113.10",
                                           "proof 签名验证失败")
        self.assertTrue(r["banned_clientid"])
        self.assertIn(("c-ur", "clientid"), self._types())

    # ---------------- 真伪造（proof 验签失败）→ 封 clientid，不碰呼号 ----------------
    def test_bad_proof_bans_clientid_not_callsign(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-2", "198.51.100.7",
                                           "proof 签名验证失败")
        self.assertTrue(r["banned_clientid"])
        self.assertIn(("c-2", "clientid"), self._types())
        self.assertNotIn(("BG5ESN", "username"), self._types(),
                         "★ 绝不能按呼号封 —— 攻击者可拿别人呼号栽赃")

    def test_revoked_cert_bans_clientid(self):
        r = self.svc.record_auth_rejection("BG5ESN", "c-3", "198.51.100.8", "证书已被吊销")
        self.assertTrue(r["banned_clientid"])

    def test_audit_row_written(self):
        self.svc.record_auth_rejection("BG5ESN", "c-4", "198.51.100.9", "proof 签名验证失败")
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
                                               "proof 签名验证失败")
        self.assertTrue(r["banned_peerhost"], "第 3 次应触发封 IP")
        self.assertIn(("203.0.113.50", "peerhost"), self._types())

    def test_peerhost_counter_resets_after_ban(self):
        for i in range(3):
            self.svc.record_auth_rejection("BG5ESN", "c-%d" % i, "203.0.113.51",
                                           "proof 签名验证失败")
        n_before = len([1 for (w, t) in self._types() if t == "peerhost"])
        self.svc.record_auth_rejection("BG5ESN", "c-x", "203.0.113.51", "proof 签名验证失败")
        n_after = len([1 for (w, t) in self._types() if t == "peerhost"])
        self.assertEqual(n_before, n_after, "封完应重置计数，不要连续重复封")

    def test_old_attempts_outside_window_ignored(self):
        """窗口外的旧记录不应累积到阈值"""
        self.svc.policy.cfg["fake_cert_window_sec"] = 1
        self.svc.record_auth_rejection("BG5ESN", "c-1", "203.0.113.60", "proof 签名验证失败")
        self.svc.record_auth_rejection("BG5ESN", "c-2", "203.0.113.60", "proof 签名验证失败")
        time.sleep(1.2)
        r = self.svc.record_auth_rejection("BG5ESN", "c-3", "203.0.113.60", "proof 签名验证失败")
        self.assertFalse(r["banned_peerhost"], "窗口已过期，不应触发封 IP")

    # ---------------- 显式开启按呼号封（默认关）----------------
    def test_callsign_ban_only_when_explicitly_enabled(self):
        self.svc.policy.cfg["fake_cert_callsign_ban"] = True
        self.svc.record_auth_rejection("BG5ESN", "c-6", "198.51.100.11", "proof 签名验证失败")
        self.assertIn(("BG5ESN", "username"), self._types())

    def test_clientid_ban_can_be_disabled(self):
        self.svc.policy.cfg["fake_cert_ban_clientid"] = False
        r = self.svc.record_auth_rejection("BG5ESN", "c-7", "198.51.100.12", "proof 签名验证失败")
        self.assertTrue(r["recorded"])
        self.assertFalse(r["banned_clientid"])
        self.assertEqual([], self.emqx.bans)

    def test_ban_until_is_finite(self):
        """封禁必须有到期时间（不再 infinity）"""
        self.svc.record_auth_rejection("BG5ESN", "c-8", "198.51.100.13", "proof 签名验证失败")
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


class BanGateTests(unittest.TestCase):
    """★ 统一封禁闸门：mode=warn 或 auto_ban 关闭时，**任何**路径都不得封人。

    真实事故（三次同类）：各规则自己调封禁，绕过 mode/auto_ban ——
    用户明明设了 warn / 关掉自动封禁，系统还在封人（连自家预检探针都被封）。
    """

    def _svc(self):
        import tempfile, shutil
        from bas_audit_db import AuditDB
        from bas_audit import AuditService
        tmp = tempfile.mkdtemp(prefix="bas-gate-")
        self.addCleanup(shutil.rmtree, tmp, True)
        svc = AuditService(AuditDB(tmp + "/a.db"), config={"admin_port": 35929})
        self.bans = []
        svc._ban_any = lambda who, reason, hours, as_type="username": (
            self.bans.append((who, as_type)), True)[1]
        svc._ban_recorder = lambda cs, r, h: (self.bans.append((cs, "username")), True)[1]
        return svc

    def test_warn_mode_never_bans_on_fake_cert(self):
        svc = self._svc()
        svc.set_policy("mode", "warn")
        svc.set_policy("auto_ban", "true")      # 即便开了 auto_ban
        svc.record_auth_rejection("BH6BHG", "cid-x", "203.0.113.5", "proof 签名验证失败")
        self.assertEqual([], self.bans, "warn 模式不得封禁")

    def test_auto_ban_off_never_bans_on_fake_cert(self):
        svc = self._svc()
        svc.set_policy("mode", "ban")
        svc.set_policy("auto_ban", "false")     # 即便模式是 ban
        svc.record_auth_rejection("BH6BHG", "cid-x", "203.0.113.6", "proof 签名验证失败")
        self.assertEqual([], self.bans, "auto_ban 关闭时不得封禁")

    def test_ban_mode_and_auto_ban_does_ban_clientid(self):
        svc = self._svc()
        svc.set_policy("mode", "ban")
        svc.set_policy("auto_ban", "true")
        svc.record_auth_rejection("BH6BHG", "cid-x", "203.0.113.7", "proof 签名验证失败")
        self.assertIn(("cid-x", "clientid"), self.bans, "两个开关都开且证据充分时应封 clientid")

    def test_own_preflight_probe_is_never_banned(self):
        svc = self._svc()
        svc.set_policy("mode", "ban")
        svc.set_policy("auto_ban", "true")
        # 预检探针：客户端名 bas-probe-*，用户名 BAS_PREFLIGHT
        svc.record_auth_rejection("BAS_PREFLIGHT", "bas-probe-123", "127.0.0.1", "password 解析失败")
        self.assertEqual([], self.bans, "自家预检探针绝不能被封（真实事故）")

    def test_ip_ban_also_gated(self):
        svc = self._svc()
        svc.set_policy("mode", "warn")
        svc.set_policy("fake_cert_ip_ban_after", "1")
        for i in range(3):
            svc.record_auth_rejection("BH6BHG", "cid-%d" % i, "203.0.113.9", "proof 签名验证失败")
        self.assertEqual([], self.bans, "warn 模式下连 IP 也不能封")


class SasCrossCheckSemanticsTests(unittest.TestCase):
    """
    本机 SAS/用户库**不是权威**（现场：国服派生证书不在本机表里；
    本机表还把在用的 BH6BHG 记成 uid=0/revoked=1）。
    因此本机查询结果永远不能单独导致封禁。
    """

    def _policy(self, lookup):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy(policy={"mode": "ban", "auto_ban": True})
        self.bans = []
        p.sas_lookup = lookup
        p.sas_has_any = lambda: True
        p.ban_recorder = lambda cs, r, h: (self.bans.append(cs), True)[1]
        return p

    @staticmethod
    def _pkt(callsign, uid):
        import struct
        from bas_fmo_parser import crc32, HEAD_SIZE
        frame = bytes([1, 2, 3, 4, 5, 6, 7, 8])
        raw = bytearray(HEAD_SIZE + len(frame))
        struct.pack_into("<H", raw, 0, 2)
        struct.pack_into("<I", raw, 6, uid)
        raw[10:22] = callsign.encode()[:12].ljust(12, b"\x00")
        struct.pack_into("<I", raw, 30, len(raw))
        struct.pack_into("<I", raw, 36, crc32(frame))
        raw[HEAD_SIZE:] = frame
        return bytes(raw)

    def _decide(self, lookup, pkt_cs, pkt_uid, conn_cs="BH6BHG", conn_uid="1075"):
        from bas_fmo_parser import parse
        p = self._policy(lookup)
        raw = self._pkt(pkt_cs, pkt_uid)
        return p.decide(raw, parse(raw), conn_cs, conn_uid, "cid", degraded=False)

    # ---- 合法连接：本机库说什么都不该封 ----
    def test_unknown_in_local_db_is_not_forgery(self):
        """★ 国服/信任链证书不在本机表 → 身份一致必须 PASS，绝不封"""
        d = self._decide(lambda cs: None, "BH6BHG", 1075)
        self.assertEqual("PASS", d.verdict)
        self.assertFalse(d.ban)
        self.assertEqual([], self.bans)

    def test_local_revoked_record_is_not_trusted(self):
        """★ 本机表把在用的号记成 revoked=1（旧数据）→ 不得据此封"""
        d = self._decide(lambda cs: {"uid": 0, "revoked": True}, "BH6BHG", 1075)
        self.assertEqual("PASS", d.verdict)
        self.assertFalse(d.ban)
        self.assertEqual([], self.bans)

    def test_local_uid_zero_mismatch_is_not_ban(self):
        """本机表 uid=0 与包内 1075 不同（旧数据）→ 不得据此封"""
        d = self._decide(lambda cs: {"uid": 0, "revoked": False}, "BH6BHG", 1075)
        self.assertEqual("PASS", d.verdict)
        self.assertFalse(d.ban)

    # ---- 真伪造：包内声明别的呼号 → 必须封 ----
    def test_real_forgery_still_banned(self):
        d = self._decide(lambda cs: None, "BG9BAD", 1075)
        self.assertEqual(KICK, d.verdict)
        self.assertTrue(d.ban)
        self.assertEqual(["BH6BHG"], self.bans)

    def test_forgery_reason_mentions_local_db_is_reference_only(self):
        d = self._decide(lambda cs: None, "BG9BAD", 1075)
        self.assertIn("已验签证书", d.reason)
        self.assertIn("不作为伪造证据", d.reason)

    # ---- 可选开关：只有在管理员明确要求时才按本机库升级判定 ----
    def test_opt_in_kick_on_unknown(self):
        from bas_fmo_parser import parse
        p = self._policy(lambda cs: None)
        p.cfg["sas_unknown_verdict"] = "kick"
        raw = self._pkt("BG9BAD", 1075)
        d = p.decide(raw, parse(raw), "BH6BHG", "1075", "cid", degraded=False)
        self.assertEqual("sas_unknown", d.scene)

    def test_defaults_are_conservative(self):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy()
        self.assertEqual("warn", str(p.cfg.get("sas_unknown_verdict")).lower())
        self.assertEqual("warn", str(p.cfg.get("sas_local_revoked_verdict")).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
