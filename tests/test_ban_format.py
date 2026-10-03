#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EMQX 封禁 API 格式测试（真机踩坑固化）
======================================
实测 EMQX 5.8.9：
  * until 必须是 RFC3339 带时区（"2026-10-05T03:00:00+08:00"）或 "infinity"；
    写成 "2026-10-05 03:00:00" 会被 400 拒绝 —— 这曾导致**所有限时封禁静默失败**。
  * as 支持 username / clientid / peerhost，但 peerhost 必须是合法 IP。
"""

import unittest

from tests import ROOT  # noqa: F401
from bas_emqx import rfc3339, is_ip_like, EmqxClient


class UntilFormatTests(unittest.TestCase):
    def test_hours_converted_to_rfc3339_with_tz(self):
        s = rfc3339(24)
        self.assertIn("T", s)
        self.assertRegex(s, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$",
                         "必须是 RFC3339 带时区，EMQX 才接受")

    def test_infinity_passthrough(self):
        self.assertEqual("infinity", rfc3339(None))
        self.assertEqual("infinity", rfc3339(""))
        self.assertEqual("infinity", rfc3339("infinity"))

    def test_legacy_format_upgraded(self):
        """旧格式（空格分隔、无时区）必须被升级为 RFC3339，否则 EMQX 400"""
        s = rfc3339("2026-10-05 03:00:00")
        self.assertEqual("2026-10-05T03:00:00", s[:19])
        self.assertIn("T", s)
        self.assertNotIn(" ", s)
        self.assertRegex(s[19:], r"^[+-]\d{2}:\d{2}$")

    def test_rfc3339_passthrough(self):
        s = "2026-10-05T03:00:00+08:00"
        self.assertEqual(s, rfc3339(s))

    def test_garbage_falls_back_to_infinity(self):
        self.assertEqual("infinity", rfc3339("not-a-date"))

    def test_no_space_separated_output(self):
        """回归：绝不能输出空格分隔的格式（真机上被 400 拒过）"""
        for v in (1, 24, 720, "2026-10-05 03:00:00"):
            self.assertNotIn(" ", rfc3339(v))


class IpLikeTests(unittest.TestCase):
    def test_valid_ipv4(self):
        for ip in ("192.168.1.136", "0.0.0.0", "255.255.255.255"):
            self.assertTrue(is_ip_like(ip), ip)

    def test_invalid(self):
        for bad in ("", "p6", "999.1.1.1", "192.168.1", "abc"):
            self.assertFalse(is_ip_like(bad), bad)

    def test_valid_ipv6(self):
        self.assertTrue(is_ip_like("2001:db8::1"))


class BanCallTests(unittest.TestCase):
    """不真连 EMQX，用假 _json 捕获请求体"""

    def _cli(self):
        cli = EmqxClient("127.0.0.1:18083", "k", "s")
        self.sent = []

        def fake_json(method, path, **kw):
            self.sent.append((method, path, kw.get("body")))
            return {}

        cli._json = fake_json
        return cli

    def test_ban_sends_rfc3339(self):
        cli = self._cli()
        ok, err = cli.ban("someone", "test", "clientid", 24)
        self.assertTrue(ok, err)
        body = self.sent[-1][2]
        self.assertEqual("clientid", body["as"])
        self.assertNotIn(" ", body["until"])
        self.assertIn("T", body["until"])

    def test_ban_infinity_when_no_hours(self):
        cli = self._cli()
        cli.ban("someone", "test", "username", None)
        self.assertEqual("infinity", self.sent[-1][2]["until"])

    def test_peerhost_requires_valid_ip(self):
        cli = self._cli()
        ok, err = cli.ban("not-an-ip", "test", "peerhost", 1)
        self.assertFalse(ok)
        self.assertIn("合法 IP", err)
        self.assertEqual([], self.sent, "非法 IP 不应发出请求")

    def test_peerhost_with_ip_ok(self):
        cli = self._cli()
        ok, err = cli.ban("203.0.113.9", "test", "peerhost", 1)
        self.assertTrue(ok, err)
        self.assertEqual("peerhost", self.sent[-1][2]["as"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
