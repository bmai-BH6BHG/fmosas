#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
审计豁免机制测试
================
某些**内部发布者**会把别人的报文原样转发（桥接/回响类节点）：
包内呼号必然 ≠ 连接身份，若不豁免就会被判「盗用呼号」并封掉这个内部节点。

产品默认**不豁免任何人**（列表为空），由部署方按需在策略里登记身份。
"""

import base64
import shutil
import struct
import tempfile
import unittest
from binascii import crc32

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService
from bas_fmo_parser import HEAD_SIZE


def _packet(callsign="BH6BHG", uid=1075):
    """构造一个合法的最小 FMO/RAW 帧（32 字节包头 + 8 字节帧）"""
    frame = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    raw = bytearray(HEAD_SIZE + len(frame))
    struct.pack_into("<H", raw, 0, 2)
    struct.pack_into("<I", raw, 6, uid)
    raw[10:22] = callsign.encode()[:12].ljust(12, b"\x00")
    struct.pack_into("<I", raw, 30, len(raw))
    struct.pack_into("<I", raw, 36, crc32(frame))
    raw[HEAD_SIZE:] = frame
    return bytes(raw)


class AuditExemptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-exempt-")
        self.db = AuditDB(self.tmp + "/a.db")
        self.svc = AuditService(self.db, config={"admin_port": 35929})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ingest(self, username, clientid, callsign="BH6BHG", uid="1075"):
        root = {
            "topic": "FMO/RAW", "username": username, "clientid": clientid,
            "client_attrs": {"callsign": username, "uid": uid},
            "payload": base64.b64encode(_packet(callsign, int(uid))).decode(),
        }
        self.svc._handle_ingest(root)

    # ---------------- 默认不豁免 ----------------
    def test_default_ignores_nobody(self):
        self.assertFalse(self.svc._audit_ignored("FMO-ECHO-1", "ECHO"))
        self.assertFalse(self.svc._audit_ignored("FMO-BH6BHG-1-ABCD", "BH6BHG"))

    def test_normal_client_not_ignored(self):
        self.assertFalse(self.svc._audit_ignored("FMO-BH6BHG-1-ABCD", "BH6BHG"))

    # ---------------- 显式登记后豁免 ----------------
    def test_username_exempt(self):
        self.svc.set_policy("audit_ignore_usernames", "ECHO")
        self.assertTrue(self.svc._audit_ignored("FMO-ECHO-123", "ECHO"))

    def test_clientid_prefix_exempt(self):
        self.svc.set_policy("audit_ignore_clientid_prefixes", "FMO-ECHO")
        self.assertTrue(self.svc._audit_ignored("FMO-ECHO-99999", None))

    def test_exempt_requires_exact_username(self):
        self.svc.set_policy("audit_ignore_usernames", "ECHO")
        self.assertFalse(self.svc._audit_ignored("x", "ECHO2"))

    # ---------------- 整条 ingest 路径 ----------------
    def test_ingest_from_exempt_identity_is_skipped(self):
        """被豁免身份发来的包：不落审计、不触发任何处置"""
        self.svc.set_policy("audit_ignore_usernames", "ECHO")
        self.svc.set_policy("audit_ignore_clientid_prefixes", "FMO-ECHO")
        # 包内呼号是 BH6BHG，连接身份是 ECHO → 正常会被判「盗用呼号」
        self._ingest("ECHO", "FMO-ECHO-1")
        self.assertEqual([], self.db.query_audit_packets(),
                         "被豁免身份必须完全跳过（不落审计）")

    def test_without_exempt_it_would_be_flagged(self):
        """对照：不豁免时，同样的包确实会被判伪造（证明豁免是有意义的）"""
        self._ingest("ECHO", "FMO-ECHO-1")
        rows = self.db.query_audit_packets()
        self.assertTrue(rows, "未豁免时应产生审计记录")
        self.assertEqual("forged", rows[0]["scene"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
