#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
上报地址必须**域名优先**（用户要求）。

背景：几台分系统全是**动态 IP**，IP 一变就联系不上；而配置里其实早就有域名
（mqtt_host / bridge.advertise_broker / domain），旧逻辑却只顾着打日志
"建议改用域名"，从不动手 → 动态 IP 一直被上报出去 → 桥接/互联随 IP 变化断掉。
"""
import io
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import api_server as A  # noqa: E402


class PickDomainTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(A.CONFIG)
        A.CONFIG.clear()

    def tearDown(self):
        A.CONFIG.clear()
        A.CONFIG.update(self._saved)

    def test_picks_domain_from_mqtt_host(self):
        """★ 核心：app_domain 是动态 IP，但 mqtt_host 有域名 → 挑出域名。"""
        A.CONFIG.update({'app_domain': '137.131.34.215',
                         'mqtt_host': 'www.shuangyayahome.top'})
        self.assertEqual(A._pick_domain_from_config(),
                         ['www.shuangyayahome.top'])

    def test_picks_domain_from_advertise_broker(self):
        A.CONFIG.update({'app_domain': '113.248.128.16',
                         'bridge': {'advertise_broker': 'www.bg8hvh.cn'}})
        self.assertEqual(A._pick_domain_from_config(), ['www.bg8hvh.cn'])

    def test_ignores_ip_and_localhost_and_lan(self):
        """IP 字面量 / localhost / 127.0.0.1 / 内网单标签 一律不算域名。"""
        A.CONFIG.update({'domain': '192.168.50.31',
                         'mqtt_host': '127.0.0.1',
                         'bridge': {'broker': 'localhost',
                                    'advertise_broker': 'nas'}})
        self.assertEqual(A._pick_domain_from_config(), [])

    def test_strips_scheme_and_port(self):
        A.CONFIG.update({'domain': 'http://bh6bhg.synology.me:35928'})
        self.assertEqual(A._pick_domain_from_config(), ['bh6bhg.synology.me'])

    def test_dedup_and_order(self):
        A.CONFIG.update({'domain': 'a.example.com',
                         'mqtt_host': 'a.example.com',
                         'bridge': {'advertise_broker': 'b.example.com'}})
        self.assertEqual(A._pick_domain_from_config(),
                         ['a.example.com', 'b.example.com'])


class LiveReportAddressTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(A.CONFIG)
        A.CONFIG.clear()

    def tearDown(self):
        A.CONFIG.clear()
        A.CONFIG.update(self._saved)

    def test_ip_is_replaced_by_domain(self):
        """★ 上报地址是 IP 时，必须改用配置里的域名。"""
        A.CONFIG.update({'app_domain': '8.137.104.16', 'app_port': 35928,
                         'app_use_port': True,
                         'mqtt_host': 'www.bg8hvh.cn'})
        r = A._live_report_address()
        self.assertEqual(r['domain'], 'www.bg8hvh.cn')
        self.assertEqual(r['api_url'], 'http://www.bg8hvh.cn:35928')

    def test_existing_domain_kept(self):
        A.CONFIG.update({'app_domain': 'bh6bhg.synology.me', 'app_port': 35928,
                         'app_use_port': True})
        r = A._live_report_address()
        self.assertEqual(r['domain'], 'bh6bhg.synology.me')

    def test_no_domain_falls_back_to_ip(self):
        """确实没有域名时才用 IP（用户允许："除非它没有域名"）。"""
        A.CONFIG.update({'app_domain': '120.237.183.186', 'app_port': 35928,
                         'app_use_port': True})
        r = A._live_report_address()
        self.assertEqual(r['domain'], '120.237.183.186')


class AutoApplyTests(unittest.TestCase):
    def setUp(self):
        self._saved = dict(A.CONFIG)
        self._saved_path = A.CONFIG_PATH
        self.tmp = tempfile.mkdtemp(prefix='domprio_')
        A.CONFIG_PATH = os.path.join(self.tmp, 'config.json')
        A.CONFIG.clear()

    def tearDown(self):
        A.CONFIG_PATH = self._saved_path
        A.CONFIG.clear()
        A.CONFIG.update(self._saved)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ip_replaced_by_domain_and_persisted(self):
        """★ 核心：当前是动态 IP → 主动改成域名、写盘、并标记 changed。"""
        A.CONFIG.update({'app_domain': '137.131.34.215', 'app_port': 35928,
                         'app_use_port': True,
                         'mqtt_host': 'www.shuangyayahome.top'})
        r = A.auto_apply_public_address()
        self.assertTrue(r['ok'], r)
        self.assertTrue(r['changed'], r)
        self.assertEqual(A.CONFIG['app_domain'], 'www.shuangyayahome.top')
        with io.open(A.CONFIG_PATH, encoding='utf-8') as f:
            saved = json.load(f)
        self.assertEqual(saved['app_domain'], 'www.shuangyayahome.top')

    def test_existing_domain_never_touched(self):
        A.CONFIG.update({'app_domain': 'bh6bhg.synology.me', 'app_port': 35928})
        r = A.auto_apply_public_address()
        self.assertFalse(r['changed'])
        self.assertEqual(A.CONFIG['app_domain'], 'bh6bhg.synology.me')

    def test_no_domain_keeps_ip(self):
        A.CONFIG.update({'app_domain': '120.237.183.186', 'app_port': 35928})
        r = A.auto_apply_public_address()
        self.assertFalse(r['changed'])
        self.assertEqual(A.CONFIG['app_domain'], '120.237.183.186')


if __name__ == '__main__':
    unittest.main(verbosity=2)
