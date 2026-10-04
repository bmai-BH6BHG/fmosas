#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在线页：实时 + 按用户聚合
=========================
真实问题：界面"在线客户端"看着不实时、且显示的"人"比实际少。
三个原因：
  1) 页面展示的是**连接**，同一个人多设备就多行（BH6BHG 的 APP+固件、BG4OHH 两台）
     → 要按**呼号聚合**才看得出"在线用户数"
  2) 后端读的是**轮询快照**，滞后一个轮询周期 → 要直查 EMQX 实时列表
  3) 前端**没有自动刷新**（"60 秒刷新"只是文案）→ 在线页 5 秒自动刷新
"""

import shutil
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB
from bas_audit import AuditService


class FakeEmqxLive(object):
    def __init__(self, clients):
        self._clients = clients
        self.calls = 0

    def list_clients(self, limit=1000, fields=None):
        self.calls += 1
        return list(self._clients)


def _c(cid, cs, uid, ip="1.1.1.1", sec=10, kind_attrs=None):
    attrs = {"callsign": cs, "uid": str(uid)}
    if kind_attrs:
        attrs.update(kind_attrs)
    import datetime
    ca = (datetime.datetime.now(datetime.timezone.utc)
          - datetime.timedelta(seconds=sec)).isoformat()
    return {"clientid": cid, "username": cs, "client_attrs": attrs,
            "ip_address": ip, "connected_at": ca, "subscriptions_cnt": 6,
            "recv_msg": 1, "send_msg": 2, "recv_oct": 10, "send_oct": 20}


class OnlineUsersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-online-")
        self.svc = AuditService(AuditDB(self.tmp + "/a.db"), config={"admin_port": 35929})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_groups_by_callsign(self):
        """★ 同一呼号多设备必须合并成一个人"""
        self.svc.emqx = FakeEmqxLive([
            _c("c1", "BH6BHG", 1), _c("c2", "BH6BHG", 1075),
            _c("c3", "BG4OHH", 36), _c("c4", "BG4OHH", 36),
            _c("c5", "BH6FWE", 405),
        ])
        clients = self.svc.online_clients()
        users = self.svc.online_users(clients)
        self.assertEqual(5, len(clients), "连接数")
        self.assertEqual(3, len(users), "用户数（按呼号合并）")
        by = {u["callsign"]: u for u in users}
        self.assertEqual(2, by["BH6BHG"]["conns"])
        self.assertEqual("1,1075", by["BH6BHG"]["uids"], "多设备 UID 都要列出")
        self.assertEqual(2, by["BG4OHH"]["conns"])
        self.assertEqual(1, by["BH6FWE"]["conns"])

    def test_queries_emqx_live_not_snapshot(self):
        """★ 必须是直查 EMQX（实时），不是读轮询快照"""
        fake = FakeEmqxLive([_c("c1", "BH6BHG", 1)])
        self.svc.emqx = fake
        self.svc.online_clients()
        self.assertGreaterEqual(fake.calls, 1, "应调用 EMQX 实时接口")

    def test_online_seconds_and_kind(self):
        self.svc.emqx = FakeEmqxLive([
            _c("c1", "BH6BHG", 1, sec=3725, kind_attrs={"app_verified": "1"}),
            _c("c2", "SERVER", 200000, ip="127.0.0.1"),
        ])
        clients = self.svc.online_clients()
        app = [c for c in clients if c["callsign"] == "BH6BHG"][0]
        srv = [c for c in clients if c["callsign"] == "SERVER"][0]
        self.assertEqual("APP", app["kind"])
        self.assertEqual("内部", srv["kind"])
        self.assertIn(app["online_text"], ("1:02:05", "1:02:04", "1:02:06"))
        self.assertTrue(app["uid"] == "1")

    def test_internal_prefix_is_internal(self):
        self.svc.emqx = FakeEmqxLive([_c("FMO-MONITOR-sub-1", "SERVER", 200000)])
        c = self.svc.online_clients()[0]
        self.assertEqual("内部", c["kind"])

    def test_falls_back_to_snapshot_when_emqx_fails(self):
        class Boom(object):
            def list_clients(self, *a, **k):
                raise RuntimeError("EMQX 挂了")
        self.svc.emqx = Boom()
        snap = {"clients": [_c("c1", "BH6BHG", 1)]}
        self.svc.poller = type("P", (), {"snapshot": lambda self=None: snap})()
        out = self.svc.online_clients()
        self.assertEqual(1, len(out), "EMQX 失败时应退回快照，页面不空")


if __name__ == "__main__":
    unittest.main(verbosity=2)
