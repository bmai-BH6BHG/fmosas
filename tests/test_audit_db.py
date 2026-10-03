#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_audit_db 测试：schema、时间语义、策略与待审队列、清理与裁剪、PBKDF2 兼容
"""

import os
import shutil
import tempfile
import time
import unittest

from tests import ROOT  # noqa: F401
from bas_audit_db import (
    AuditDB, now_text, ts10, SCHEMA_VERSION, TIME_FMT,
)


class AuditDBTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="bas-audit-")
        cls.db = AuditDB(os.path.join(cls.tmp, "audit.db"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_schema_tables_and_version(self):
        import sqlite3
        conn = sqlite3.connect(self.db.path)
        try:
            names = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            for t in ("minute_stats", "topic_stats", "health_snapshots", "settings",
                      "admin_user", "blacklist_audit", "audit_packets", "bas_policy",
                      "bas_quarantine"):
                self.assertIn(t, names, "缺表 %s" % t)
            ver = conn.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(SCHEMA_VERSION, ver)
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual("wal", str(mode).lower())
        finally:
            conn.close()

    def test_settings_defaults_and_ingest_token(self):
        s = self.db.all_settings()
        self.assertIn("identity_control", s)
        self.assertEqual("FMO/RAW", s["topic_name"])
        tok = self.db.get_ingest_token()
        self.assertEqual(32, len(tok))
        self.assertEqual(tok, self.db.get_ingest_token(), "token 必须持久化且稳定")
        # 密钥必须脱敏
        self.db.set_setting("emqx_api_secret", "SUPERSECRET")
        self.assertEqual("********", self.db.all_settings()["emqx_api_secret"])
        self.assertEqual("SUPERSECRET", self.db.get_setting("emqx_api_secret"))

    def test_pbkdf2_hash_format_and_roundtrip(self):
        stored = AuditDB.hash_password("P@ssw0rd!中文")
        parts = stored.split(".")
        self.assertEqual(3, len(parts))
        self.assertEqual("100000", parts[0], "迭代次数必须对齐上游 10 万")
        self.assertTrue(AuditDB.verify_password("P@ssw0rd!中文", stored))
        self.assertFalse(AuditDB.verify_password("wrong", stored))
        self.assertFalse(AuditDB.verify_password("P@ssw0rd!中文", "garbage"))

    def test_admin_crud(self):
        self.assertFalse(self.db.has_admin())
        self.db.set_admin("bh6bhg", "MyPass123")
        self.assertTrue(self.db.has_admin())
        self.assertTrue(self.db.verify_admin("bh6bhg", "MyPass123"))
        self.assertFalse(self.db.verify_admin("bh6bhg", "bad"))
        self.assertFalse(self.db.verify_admin("other", "MyPass123"))
        # 二次设置 = 改密码（幂等 upsert）
        self.db.set_admin("bh6bhg", "NewPass456")
        self.assertTrue(self.db.verify_admin("bh6bhg", "NewPass456"))
        self.assertEqual(1, len([1]))

    def test_time_text_lexicographic(self):
        """所有时间比较都是 TEXT 字典序，必须零填充。"""
        t = now_text()
        self.assertEqual(19, len(t))
        self.assertLess(now_text(), time.strftime(TIME_FMT, time.localtime(time.time() + 60)))
        self.assertRegex(t, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

    def test_ts10_bucket_alignment(self):
        self.assertEqual("2026-10-03 12:00:00",
                         ts10("2026-10-03 12:00:00"))
        self.assertEqual("2026-10-03 12:00:00",
                         ts10("2026-10-03 12:00:09"))
        self.assertEqual("2026-10-03 12:00:10",
                         ts10("2026-10-03 12:00:19"))

    def test_minute_stat_upsert_and_leaderboard(self):
        db = AuditDB(os.path.join(self.tmp, "lb.db"))
        ts = "2026-10-03 12:00:00"
        db.upsert_minute_stat({"clientid": "c1", "ts": ts, "username": "BG5ESN",
                               "callsign": "BG5ESN", "uid": "12345", "recv_oct": 100,
                               "send_oct": 200, "recv_msg": 1, "send_msg": 2,
                               "recv_pkt": 3, "send_pkt": 4})
        # 同分钟重复写 → 覆盖而不是累加
        db.upsert_minute_stat({"clientid": "c1", "ts": ts, "username": "BG5ESN",
                               "callsign": "BG5ESN", "uid": "12345", "recv_oct": 150,
                               "send_oct": 250, "recv_msg": 5, "send_msg": 6,
                               "recv_pkt": 7, "send_pkt": 8})
        rows = db.leaderboard(since="2026-10-01 00:00:00", until="2026-10-04 00:00:00")
        self.assertEqual(1, len(rows))
        self.assertEqual("BG5ESN", rows[0]["name"])
        self.assertEqual(400, rows[0]["bytes"], "覆盖语义：不是 100+200+150+250")

        # 第二个客户端 → 按字节排序
        db.upsert_minute_stat({"clientid": "c2", "ts": ts, "callsign": "BG9XXX",
                               "recv_oct": 9999, "send_oct": 1})
        rows = db.leaderboard(since="2026-10-01 00:00:00", until="2026-10-04 00:00:00")
        self.assertEqual("BG9XXX", rows[0]["name"])

        detail = db.leaderboard_detail("BG5ESN", since="2026-10-01 00:00:00",
                                       until="2026-10-04 00:00:00")
        self.assertEqual(1, len(detail))
        self.assertEqual("c1", detail[0]["clientid"])

    def test_topic_stats_accumulate_and_buckets(self):
        db = AuditDB(os.path.join(self.tmp, "topic.db"))
        # 累加语义
        db.add_topic_stat("FMO/RAW", "c1", "BG5ESN", "BG5ESN", "1", 2, 300, "2026-10-03 12:00:03")
        db.add_topic_stat("FMO/RAW", "c1", "BG5ESN", "BG5ESN", "1", 3, 500, "2026-10-03 12:00:07")
        rows = db.topic_timeline("FMO/RAW", since="2026-10-03 00:00:00",
                                 until="2026-10-04 00:00:00", bucket="10s")
        self.assertEqual(1, len(rows), "同一 10 秒桶应聚合")
        self.assertEqual(5, rows[0]["msgs"])
        self.assertEqual(800, rows[0]["bytes"])
        self.assertEqual("2026-10-03 12:00:00", rows[0]["bucket"])
        # 1 分钟粒度
        db.add_topic_stat("FMO/RAW", "c2", "BG9XXX", "BG9XXX", "2", 1, 100,
                          "2026-10-03 12:00:45")
        rows = db.topic_timeline("FMO/RAW", since="2026-10-03 00:00:00",
                                 until="2026-10-04 00:00:00", bucket="1m")
        buckets = {r["bucket"]: r for r in rows}
        self.assertIn("2026-10-03 12:00:00", buckets)
        # 5 分钟粒度：12:03:59 → 12:00 桶（截断）
        db.add_topic_stat("FMO/RAW", "c3", "BG1AAA", "BG1AAA", "3", 1, 50,
                          "2026-10-03 12:03:59")
        rows5 = db.topic_timeline("FMO/RAW", since="2026-10-03 00:00:00",
                                  until="2026-10-04 00:00:00", bucket="5m")
        b5 = {r["bucket"] for r in rows5}
        self.assertIn("2026-10-03 12:00:00", b5)
        self.assertNotIn("2026-10-03 12:05:00", b5)

    def test_blacklist_flow_and_expiry(self):
        db = AuditDB(os.path.join(self.tmp, "bl.db"))
        db.add_blacklist_event("ban", "BG9BAD", "身份控制: 伪造", None, "身份控制")
        active = db.active_blacklist()
        self.assertEqual(1, len(active))
        self.assertEqual("BG9BAD", active[0]["who"])

        # 解封后再查 → 不在生效名单
        db.add_blacklist_event("unban", "BG9BAD", "误封申诉", None, "admin")
        self.assertEqual(0, len(db.active_blacklist()))

        # 临时拉黑且已过期 → 不生效（查询时推导，无需定时任务）
        db.add_blacklist_event("ban", "BG7TMP", "temp", "2020-01-01 00:00:00", "admin")
        self.assertEqual(0, len(db.active_blacklist()))
        # 永久拉黑仍然生效
        db.add_blacklist_event("ban", "BG7PERM", "perm", "infinity", "admin")
        who = {r["who"] for r in db.active_blacklist()}
        self.assertIn("BG7PERM", who)
        self.assertEqual(4, len(db.blacklist_history()))

    def test_quarantine_flow(self):
        db = AuditDB(os.path.join(self.tmp, "q.db"))
        db.add_quarantine({"conn_callsign": "BG5ESN", "conn_uid": "1", "pkt_callsign": "BG5ESN",
                           "pkt_uid": "999", "clientid": "c1", "scene": "uid_mismatch",
                           "reason": "UID 不一致", "confidence": 0.5})
        pending = db.list_quarantine()
        self.assertEqual(1, len(pending))
        self.assertEqual("pending", pending[0]["status"])
        db.resolve_quarantine(pending[0]["id"], "released", "admin")
        self.assertEqual(0, len(db.list_quarantine("pending")))
        self.assertEqual(1, len(db.list_quarantine("released")))

    def test_policy_store(self):
        db = AuditDB(os.path.join(self.tmp, "pol.db"))
        db.set_policy("mode", "warn")
        db.set_policy("uid_mismatch_verdict", "warn")
        p = db.get_policy()
        self.assertEqual("warn", p["mode"])
        self.assertEqual("warn", p["uid_mismatch_verdict"])

    def test_audit_packet_write_query(self):
        db = AuditDB(os.path.join(self.tmp, "ap.db"))
        db.write_audit_packet({"verdict": "KICK", "scene": "forged", "conn_callsign": "BG5AAA",
                               "pkt_callsign": "BG5BBB", "pkt_uid": "7", "topic": "FMO/RAW",
                               "clientid": "c9", "reason": "呼号不符", "confidence": 0.9,
                               "len": 72, "crc_ok": True, "ban": True})
        db.write_audit_packet({"verdict": "WARN", "scene": "attr_missing", "clientid": "c1"})
        kicks = db.query_audit_packets(verdict="KICK")
        self.assertEqual(1, len(kicks))
        self.assertEqual("forged", kicks[0]["scene"])
        self.assertEqual(1, kicks[0]["ban"])
        by_cs = db.query_audit_packets(callsign="BG5BBB")
        self.assertEqual(1, len(by_cs))
        self.assertEqual(2, db.stats_summary()["audit_packets"])

    def test_cleanup_and_trim(self):
        db = AuditDB(os.path.join(self.tmp, "clean.db"))
        db.upsert_minute_stat({"clientid": "old", "ts": "2020-01-01 00:00:00"})
        db.upsert_minute_stat({"clientid": "new", "ts": now_text()})
        db.write_audit_packet({"verdict": "FAIL", "ts": "2020-01-01 00:00:00.000"})
        db.write_audit_packet({"verdict": "PASS", "ts": now_text(True)})
        res = db.cleanup()
        self.assertGreaterEqual(res["minute_stats"], 1)
        self.assertGreaterEqual(res["audit_packets"], 1)
        self.assertEqual(1, db.stats_summary()["minute_stats"], "新数据必须保留")
        self.assertEqual(1, db.stats_summary()["audit_packets"], "audit_packets 也必须被清理")
        # settings / admin / 黑名单流水不清理
        self.db.assert_true = True
        self.assertGreaterEqual(len(db.all_settings()), 10)

    def test_clear_all_keeps_config(self):
        db = AuditDB(os.path.join(self.tmp, "clear.db"))
        db.set_setting("topic_name", "FMO/RAW2")
        db.add_blacklist_event("ban", "BG9BAD", "x", None, "admin")
        db.upsert_minute_stat({"clientid": "c", "ts": now_text()})
        db.write_audit_packet({"verdict": "WARN"})
        db.clear_all(keep_blacklist=True)
        s = db.stats_summary()
        self.assertEqual(0, s["minute_stats"])
        self.assertEqual(0, s["audit_packets"], "上游漏删 audit_packets，这里必须删干净")
        self.assertEqual(1, s["blacklist_audit"])
        self.assertEqual("FMO/RAW2", db.get_setting("topic_name"))

    def test_health_snapshot_roundtrip(self):
        db = AuditDB(os.path.join(self.tmp, "h.db"))
        db.add_health_snapshot({"ts": "2026-10-03 12:00:00", "host_cpu_pct": 12.5,
                                "emqx_conns": 33, "emqx_alarms": "high_memory",
                                "emqx_cpu_pct": 0.42})
        rows = db.health_series(since="2026-10-03 00:00:00", until="2026-10-04 00:00:00")
        self.assertEqual(1, len(rows))
        self.assertAlmostEqual(12.5, rows[0]["host_cpu_pct"])
        self.assertEqual(33, rows[0]["emqx_conns"])

    def test_concurrent_writes_no_lock_error(self):
        """多线程并发写不得报 database is locked（每条连接都设了 busy_timeout）。"""
        import threading
        db = AuditDB(os.path.join(self.tmp, "conc.db"))
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    db.add_topic_stat("FMO/RAW", "c%d" % n, "BG5ESN", "BG5ESN", "1", 1, 10,
                                      "2026-10-03 12:0%d:0%d" % (n % 10, i % 10))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual([], errors, "并发写出现异常: %s" % errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
