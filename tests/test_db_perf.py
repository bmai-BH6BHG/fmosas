#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库"每次操作新建连接"性能回归测试
====================================
真实事故（FUS 服务"莫名其妙断连、所有证书都进不来、界面卡"）：

    SQLite 在**最后一个连接关闭时**会对 WAL 做一次 checkpoint。而项目里多处是
    「每次操作新建连接 → 用完 close()」，于是**每一次写入的 close 都是最后一个连接**
    → 每次都全量 checkpoint。NAS 上实测每次写入约 1 秒：
        无保活连接：中位 1058 ms/次
        加一条常开：中位 0.4 ms/次（约快 2500 倍）
    认证路径里有两次写（note_client_seen + record_auth_ok）→ 约 2 秒，
    把 EMQX 的 5 秒认证 HTTP 超时打满 → EMQX 判 not_authorized →
    **对的证书也一起被拒**；监控那边每收一个信标写一次 → 读循环被堵死 → 掉线。

修复方式（两条，都保留）：
  1. 常驻连接复用（AuditDB / VoiceStore）
  2. 占位保活连接（SyncEngine / api_server.get_db），不改任何调用点

本测试断言**机制**而不是耗时（耗时随机器变，机制是确定的）。
"""

import os
import shutil
import sqlite3
import tempfile
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import AuditDB, _SharedConn
from monitor import VoiceStore


class AuditDBReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-dbperf-")
        self.db = AuditDB(os.path.join(self.tmp, "a.db"))

    def tearDown(self):
        try:
            self.db.dispose()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_conn_is_reused_not_recreated(self):
        c1 = self.db._conn()
        raw1 = c1._raw
        c1.close()                     # close() 必须是空操作
        c2 = self.db._conn()
        self.assertIs(raw1, c2._raw, "必须复用同一条底层连接（否则每次写都触发 WAL checkpoint）")
        self.assertIsInstance(c2, _SharedConn)

    def test_close_is_noop(self):
        c = self.db._conn()
        c.close()
        # 关掉之后底层连接仍可用，说明 close 是空操作
        self.assertIsNotNone(self.db._shared)
        self.db._conn().execute("SELECT 1")

    def test_writes_work_after_reuse(self):
        self.db.add_client_seen("BH6TEST", "1", "cid-1", "1.2.3.4")
        self.db.add_client_seen("BH6TEST", "1", "cid-2", "1.2.3.4")
        self.db.write_audit_packet({"ts": "2026-01-01 00:00:00", "scene": "auth_ok",
                                    "verdict": "PASS", "conn_callsign": "BH6TEST"})
        rows = self.db.query_audit_packets(limit=10)
        self.assertTrue(rows)
        # recent_clients 按**呼号聚合**：两个 clientid 同呼号 → 1 行、hits=2
        rec = self.db.recent_clients(minutes=60, limit=10)
        self.assertEqual(1, len(rec))
        self.assertEqual(2, rec[0]["hits"])

    def test_dispose_closes_shared(self):
        self.db._conn()
        self.assertIsNotNone(self.db._shared)
        self.db.dispose()
        self.assertIsNone(self.db._shared)


class VoiceStoreReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-voice-")
        self.store = VoiceStore(os.path.join(self.tmp, "voice.db"))

    def tearDown(self):
        try:
            self.store.dispose()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_conn_is_reused(self):
        c1 = self.store._conn()
        raw1 = c1._raw
        c1.close()
        c2 = self.store._conn()
        self.assertIs(raw1, c2._raw, "VoiceStore 必须复用连接")

    def test_beacon_roundtrip(self):
        self.store.add_beacon("BH6TEST", 145.5, 145.5, 1)
        got = self.store.beacons_since(since=0, limit=5)
        self.assertEqual(1, len(got))
        self.assertEqual("BH6TEST", got[0]["callsign"])

    def test_synchronous_is_normal(self):
        """必须是 NORMAL：FULL 会让每次 commit 都 fsync（实测差约 1000 倍）"""
        c = self.store._conn()
        # PRAGMA synchronous: 0=OFF 1=NORMAL 2=FULL 3=EXTRA
        self.assertEqual(1, c._raw.execute("PRAGMA synchronous").fetchone()[0])

    def test_stats(self):
        st = self.store.stats()
        self.assertIn("beacons", st)
        self.assertIn("segments", st)


class KeepaliveTests(unittest.TestCase):
    """SyncEngine / api_server 用"占位保活连接"消除每次 close 的 checkpoint。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-keep-")
        self.db_path = os.path.join(self.tmp, "sub_users.db")
        # 不预建表：交给 SyncEngine 自己迁移建表（它要求的列比测试里手写的多）
        c = sqlite3.connect(self.db_path)
        c.close()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sync_engine_keeps_placeholder_connection(self):
        import sync_engine
        eng = sync_engine.SyncEngine({"subsystem_id": "sub-test"}, self.db_path,
                                     mode="subsystem", base_dir=self.tmp)
        try:
            conn = eng.get_db()
            conn.execute("UPDATE users SET last_heartbeat=1 WHERE id=1")
            conn.commit()
            conn.close()
            self.assertIn(eng.db_path, eng._keepalive,
                          "get_db() 必须留下占位保活连接，否则每次 close 都触发 WAL checkpoint")
        finally:
            eng.close_keepalive()

    def test_api_server_ensures_keepalive(self):
        import api_server
        p = os.path.join(self.tmp, "api_users.db")
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, last_heartbeat REAL)")
        c.execute("INSERT INTO users(id, last_heartbeat) VALUES(1, 0)")
        c.commit()
        c.close()
        saved = api_server.DB_PATH
        try:
            api_server.DB_PATH = p
            api_server._KEEPALIVE_CONNS.pop(p, None)
            conn = api_server.get_db()
            conn.execute("UPDATE users SET last_heartbeat=2 WHERE id=1")
            conn.commit()
            conn.close()
            self.assertIn(p, api_server._KEEPALIVE_CONNS,
                          "api_server.get_db() 必须留下保活连接")
        finally:
            k = api_server._KEEPALIVE_CONNS.pop(p, None)
            if k is not None:
                try:
                    k.close()
                except Exception:
                    pass
            api_server.DB_PATH = saved


class NoPerOpConnectionInHotPathTests(unittest.TestCase):
    """静态检查：热路径代码里不应再出现"裸 sqlite3.connect + 立即 close"的写法。"""

    def test_audit_db_uses_shared_conn(self):
        src = open(os.path.join(ROOT, "bas_audit_db.py"), encoding="utf-8").read()
        self.assertIn("_SharedConn", src)
        self.assertIn("check_same_thread=False", src)
        # 只应有一处真正 connect（_raw_conn），而不是散落各处
        self.assertEqual(1, src.count("sqlite3.connect(self.path"),
                         "AuditDB 只应有 _raw_conn 一处新建连接")

    def test_voice_store_uses_shared_conn(self):
        src = open(os.path.join(ROOT, "monitor.py"), encoding="utf-8").read()
        self.assertIn("_SharedConn", src)
        self.assertEqual(1, src.count("sqlite3.connect(self.db_path"),
                         "VoiceStore 只应有一处新建连接")

    def test_api_server_get_db_has_keepalive(self):
        src = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("_ensure_keepalive", src)
        self.assertIn("_KEEPALIVE_CONNS", src)

    def test_sync_engine_has_keepalive(self):
        src = open(os.path.join(ROOT, "sync_engine.py"), encoding="utf-8").read()
        self.assertIn("_ensure_keepalive", src)
        self.assertIn("_keepalive", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
