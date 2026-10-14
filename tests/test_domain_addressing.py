#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
互联/上报「用域名不用 IP」的测试。

锁定用户口径：
  1. 手动填了域名 → 自动地址扫描**绝不覆盖**（"设好了又被变回来"的根治）
  2. 填的是 IP → 也不覆盖（只提示），不再偷偷改成扫到的 IP
  3. 没填 → 才自动兜底填 IP（并提示换域名）
  4. 域名解析助手 resolve_host：IP 原样返回、域名能解析、坏域名给明确错误
  5. 桥接：域名候选要能互联；DNS 失败时 last_error 里能看到"域名解析失败"
  6. 界面：卡片显示 域名 / IP·会变 徽标
"""
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import api_server  # noqa: E402
import bridge as B  # noqa: E402


class DomainFirstTests(unittest.TestCase):
    """auto_apply_public_address：域名优先，绝不被自动扫描覆盖。"""

    def setUp(self):
        self._saved = dict(api_server.CONFIG)
        self._saved_ip_fn = api_server._master_observed_ip
        self._saved_path = api_server.CONFIG_PATH
        # 假装总系统看到的公网 IP 是 1.2.3.4（会变的动态 IP）
        api_server._master_observed_ip = lambda timeout=8: ("1.2.3.4", "测试")
        api_server.CONFIG_PATH = os.path.join(REPO, "tests", "_tmp_cfg_never.json")

    def tearDown(self):
        api_server.CONFIG.clear()
        api_server.CONFIG.update(self._saved)
        api_server._master_observed_ip = self._saved_ip_fn
        api_server.CONFIG_PATH = self._saved_path
        try:
            os.remove(os.path.join(REPO, "tests", "_tmp_cfg_never.json"))
        except OSError:
            pass

    def test_manual_domain_is_never_overwritten(self):
        """★ 用户核心诉求：填好的域名不能被系统改回 IP。"""
        api_server.CONFIG['app_domain'] = 'fs.example.com'
        api_server.CONFIG['app_port'] = 35928
        r = api_server.auto_apply_public_address()
        self.assertTrue(r.get('ok'))
        self.assertEqual(api_server.CONFIG['app_domain'], 'fs.example.com',
                         "域名被自动扫描覆盖了（用户报的「设好了又被变回来」）")
        self.assertFalse(r.get('changed'))

    def test_manual_ip_replaced_when_domain_available(self):
        """
        ★ 新的需求（用户明确要求）：几台分系统都是**动态 IP**，IP 一变就联系不上，
        必须用域名上报；配置里已经有域名（mqtt_host 等）时，IP 要**主动换成域名**。

        旧行为是"填了 IP 也绝不改、只提示" —— 结果动态 IP 一直被上报出去，
        桥接/互联随 IP 变化断掉（真实事故）。
        """
        api_server.CONFIG.clear()
        api_server.CONFIG.update({'app_domain': '9.9.9.9', 'app_port': 35928,
                                  'app_use_port': True,
                                  'mqtt_host': 'fs.example.com'})
        r = api_server.auto_apply_public_address()
        self.assertEqual(api_server.CONFIG['app_domain'], 'fs.example.com',
                         "有域名可用时应改用域名（动态 IP 不可靠）")
        self.assertTrue(r.get('changed'))

    def test_manual_ip_kept_when_no_domain(self):
        """确实一个域名都没有时，才保留 IP（用户允许："除非它没有域名"）。"""
        api_server.CONFIG.clear()
        api_server.CONFIG.update({'app_domain': '9.9.9.9', 'app_port': 35928,
                                  'app_use_port': True})
        r = api_server.auto_apply_public_address()
        self.assertEqual(api_server.CONFIG['app_domain'], '9.9.9.9')
        self.assertFalse(r.get('changed'))

    def test_empty_falls_back_to_ip_with_hint(self):
        """没填才兜底填 IP，并明确提示改用域名。"""
        api_server.CONFIG['app_domain'] = ''
        api_server.CONFIG['app_port'] = 35928
        r = api_server.auto_apply_public_address()
        self.assertEqual(api_server.CONFIG['app_domain'], '1.2.3.4')
        self.assertIn('域名', str(r.get('note') or ''))

    def test_looks_like_ip(self):
        f = api_server._looks_like_ip
        self.assertTrue(f('1.2.3.4'))
        self.assertTrue(f('2001:db8::1'))
        self.assertFalse(f('fs.example.com'))
        self.assertFalse(f('my-nas.synology.me'))
        self.assertFalse(f(''))

    def test_host_is_domain(self):
        self.assertTrue(api_server.host_is_domain('fs.example.com'))
        self.assertFalse(api_server.host_is_domain('1.2.3.4'))


class ResolveHostTests(unittest.TestCase):
    def test_ip_passthrough(self):
        ip, err = api_server.resolve_host('127.0.0.1')
        self.assertEqual(ip, '127.0.0.1')
        self.assertEqual(err, '')

    def test_localhost_domain_resolves(self):
        ip, err = api_server.resolve_host('localhost', retries=1)
        self.assertTrue(ip, "localhost 应能解析（err=%s）" % err)

    def test_bad_domain_gives_clear_error(self):
        ip, err = api_server.resolve_host('no-such-host-xyz-12345.invalid',
                                          retries=1)
        self.assertEqual(ip, '')
        self.assertIn('域名解析失败', err)

    def test_empty(self):
        ip, err = api_server.resolve_host('')
        self.assertEqual(ip, '')
        self.assertIn('为空', err)


class BridgeDomainTests(unittest.TestCase):
    """桥接侧：域名候选可互联；DNS 失败原因可见。"""

    def test_peer_records_domain_flag(self):
        p = B.normalize_peer({"host": "fs.example.com", "port": 1883})
        self.assertTrue(p.get("host_is_domain"))
        p2 = B.normalize_peer({"host": "1.2.3.4", "port": 1883})
        self.assertFalse(p2.get("host_is_domain"))

    def test_host_is_domain_helper(self):
        self.assertTrue(B._host_is_domain("fs.example.com"))
        self.assertFalse(B._host_is_domain("1.2.3.4"))
        self.assertFalse(B._host_is_domain(""))
        self.assertTrue(B._host_is_domain("a.b.c.d.example.org"))

    def test_resolve_cached_ip_passthrough(self):
        self.assertEqual(B._resolve_host_cached("10.0.0.5"), ("10.0.0.5", ""))

    def test_resolve_cached_bad_domain(self):
        ip, err = B._resolve_host_cached("no-such-host-abc-98765.invalid")
        self.assertEqual(ip, "")
        self.assertIn("域名解析失败", err)

    def test_link_reports_dns_failure(self):
        """链路连接前会预解析域名，失败时 last_error 必须能看出是 DNS。"""
        src = io.open(os.path.join(REPO, "bridge.py"), encoding="utf-8").read()
        self.assertIn("域名解析失败", src)
        self.assertIn("_resolve_host_cached", src)
        # 预解析必须发生在建连之前
        i_res = src.index("_resolve_host_cached(ph)")
        i_conn = src.index("client.connect()")
        self.assertLess(i_res, i_conn, "域名解析应在连接之前，否则排查看不到原因")


class UiDomainTests(unittest.TestCase):
    def test_bridge_js_shows_domain_badge(self):
        js = io.open(os.path.join(REPO, "admin", "bridge.js"),
                     encoding="utf-8").read()
        self.assertIn("host_is_domain", js, "卡片要区分域名/IP")
        self.assertIn("IP·会变", js)

    def test_bridge_html_guides_domain(self):
        h = io.open(os.path.join(REPO, "admin", "bridge.html"),
                    encoding="utf-8").read()
        self.assertIn("推荐用域名", h)
        self.assertIn("请优先填域名", h)


class ReportDomainTests(unittest.TestCase):
    def test_sync_report_prefers_domain(self):
        src = io.open(os.path.join(REPO, "sync_engine.py"), encoding="utf-8").read()
        self.assertIn("_is_ip_literal_local", src, "上报要有 IP/域名判定")
        self.assertIn("上报地址当前是 IP", src, "用 IP 上报要提示")

    def test_is_ip_literal_local(self):
        import sync_engine as S
        f = S._is_ip_literal_local
        self.assertTrue(f("1.2.3.4"))
        self.assertFalse(f("fs.example.com"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
