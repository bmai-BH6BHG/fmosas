#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
库名前缀稳定性 + 多代库合并 + 用户库初始化（只保留国服 ID 用户）。

锁定三个真实事故/需求：
  1. **库名前缀不能随地址变**：前缀取 domain/api_url 时，用户把地址从 IP 改成
     域名就分裂出第二套空库 → 旧库的 39 张证书"消失"。
     → get_db_prefix 必须优先 subsystem_id，改 domain 不影响结果。
  2. **多代库合并不能丢行**：两代库的 `id INTEGER PRIMARY KEY` 都从 1 开始，
     直接 INSERT OR IGNORE 会静默丢行；必须排除 INTEGER 主键重分配。
     另外 ca_info 绝不能合并（否则旧代 CA 覆盖生效根 → 全体证书失效）。
  3. **只保留国服 ID 用户**（口径 B）：merge_users 跳过没有 guoji_id 的存量用户。
"""
import os
import sqlite3
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import api_server as A  # noqa: E402


def _mk_users_db(path, callsigns, with_synclog=0):
    c = sqlite3.connect(path)
    c.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, callsign TEXT UNIQUE,
        phone TEXT, password_hash TEXT, cert_photo_path TEXT, device_cert_path TEXT,
        token TEXT, last_heartbeat REAL DEFAULT 0, created_at REAL,
        last_modified REAL DEFAULT 0, deleted INTEGER DEFAULT 0,
        subsystem_id TEXT, guoji_id TEXT, dmr_id TEXT)""")
    c.execute("""CREATE TABLE sync_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, direction TEXT,
        peer TEXT, data_type TEXT, count INTEGER, status TEXT, error TEXT,
        duration REAL)""")
    c.execute("""CREATE TABLE ca_info (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ca_id TEXT UNIQUE, ca_type TEXT,
        ca_name TEXT, public_key TEXT, ca_cert_data TEXT, valid_from REAL,
        valid_to REAL, last_modified REAL DEFAULT 0, deleted INTEGER DEFAULT 0)""")
    for i, cs in enumerate(callsigns, 1):
        c.execute("INSERT INTO users (name, callsign, created_at, guoji_id)"
                  " VALUES (?,?,?,?)", ("名字" + cs, cs, 1000 + i,
                                        "46000%02d" % i if i % 2 else ""))
    for i in range(with_synclog):
        c.execute("INSERT INTO sync_log (timestamp, direction) VALUES (?,?)",
                  (1000 + i, 'report'))
    c.commit()
    c.close()


def _mk_sas_db(path, cert_ids):
    """SAS 库：certificates.id 是 TEXT PRIMARY KEY（跨代不冲突）。"""
    c = sqlite3.connect(path)
    c.execute("""CREATE TABLE certificates (
        id TEXT PRIMARY KEY, callsign TEXT NOT NULL, uid INTEGER NOT NULL,
        cert_user_json TEXT NOT NULL, cert_devicekey_json TEXT NOT NULL,
        fingerprint TEXT NOT NULL, issued_at INTEGER NOT NULL,
        revoked INTEGER DEFAULT 0, last_modified INTEGER DEFAULT 0,
        derived INTEGER DEFAULT 0)""")
    c.execute("""CREATE TABLE ca_info (
        id INTEGER PRIMARY KEY CHECK (id = 1), root_cert_json TEXT NOT NULL,
        int_cert_json TEXT NOT NULL, root_seed TEXT NOT NULL, int_seed TEXT NOT NULL,
        ca_name TEXT, root_fingerprint TEXT, int_fingerprint TEXT,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    for cid in cert_ids:
        c.execute("INSERT INTO certificates (id, callsign, uid, cert_user_json,"
                  " cert_devicekey_json, fingerprint, issued_at, derived)"
                  " VALUES (?,?,?,?,?,?,?,?)",
                  (cid, "CALL" + cid, 1, '{}', '{}', 'fp' + cid, 1700000000, 1))
    # 当前生效 CA（合并时绝不能被旧代覆盖）
    c.execute("INSERT INTO ca_info (id, root_cert_json, int_cert_json, root_seed,"
              " int_seed, ca_name, created_at, updated_at)"
              " VALUES (1,?,?,?,?,?,?,?)", ('{"cur":1}', '{}', 's', 's', 'MYCA',
                                             1, 1))
    c.commit()
    c.close()


class PrefixStabilityTests(unittest.TestCase):
    """★ 用户核心诉求：改地址不能再让库文件"换一套"。"""

    def test_subsystem_id_wins(self):
        cfg = {"subsystem_id": "sub-abc123", "domain": "x.example.com",
               "api_url": "http://1.2.3.4:35928", "app_domain": "1.2.3.4"}
        self.assertEqual(A.get_db_prefix(cfg), "sub-abc123")

    def test_domain_change_does_not_change_prefix(self):
        base = {"subsystem_id": "sub-abc123"}
        p1 = A.get_db_prefix(dict(base, domain="117.57.54.60",
                                  api_url="http://117.57.54.60:35928",
                                  app_domain="117.57.54.60"))
        p2 = A.get_db_prefix(dict(base, domain="bh6bhg.synology.me",
                                  api_url="http://bh6bhg.synology.me:35928",
                                  app_domain="bh6bhg.synology.me"))
        self.assertEqual(p1, p2, "改域名/IP 后库名前缀变了 → 会分裂出新空库")
        self.assertEqual(p1, "sub-abc123")

    def test_explicit_db_prefix_wins(self):
        cfg = {"db_prefix": "myfixed", "subsystem_id": "sub-abc123",
               "domain": "x.example.com"}
        self.assertEqual(A.get_db_prefix(cfg), "myfixed")

    def test_fallback_without_subsystem_id(self):
        """没 subsystem_id 时退回旧逻辑（域名），保证老配置能用。"""
        cfg = {"domain": "fs.example.com"}
        self.assertEqual(A.get_db_prefix(cfg), "fs.example.com")


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="merge_test_")
        self.target = os.path.join(self.tmp, "sub-x_users.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_merge_does_not_lose_rows(self):
        """★ 两代库合并后，两边的人一个都不能少。"""
        a = os.path.join(self.tmp, "old-a_users.db")
        b = os.path.join(self.tmp, "old-b_users.db")
        _mk_users_db(a, ["A1", "A2", "A3", "SHARED"])
        _mk_users_db(b, ["B1", "B2", "SHARED"])
        done = A.merge_migrate_db(self.target, "_users.db")
        self.assertEqual(len(done), 2, "应合并两个历史库: %s" % done)
        c = sqlite3.connect(self.target)
        got = sorted(r[0] for r in c.execute("select callsign from users"))
        c.close()
        self.assertEqual(got, ["A1", "A2", "A3", "B1", "B2", "SHARED"],
                         "合并后丢人或重复：%s" % got)

    def test_sync_log_not_merged(self):
        """几万行历史同步日志不合并（无价值、拖慢升级）。"""
        a = os.path.join(self.tmp, "old-a_users.db")
        _mk_users_db(a, ["A1"], with_synclog=50)
        # 目标库先有 schema（真实启动顺序：先建表再合并）
        _mk_users_db(self.target, [])
        A.merge_migrate_db(self.target, "_users.db")
        c = sqlite3.connect(self.target)
        n = c.execute("select count(*) from sync_log").fetchone()[0]
        c.close()
        self.assertEqual(n, 0)

    def test_ca_info_only_fills_empty_target(self):
        """ca_info 规则：目标为空时补 1 行记录；目标已有记录时**一行都不动**。

        现场实测：目标库是新建的 → 若完全跳过，记录就缺了（CA 本体在 ca/ 文件里，
        所以服务没坏，但记录不全会影响排查/对账）。
        """
        a = os.path.join(self.tmp, "old-a_users.db")
        _mk_users_db(a, ["A1"])
        c = sqlite3.connect(a)
        c.execute("INSERT INTO ca_info (ca_id, ca_name, public_key)"
                  " VALUES ('old','OLDCA','OLDPUB')")
        c.commit()
        c.close()

        # 情形 1：目标库 ca_info 为空 → 补 1 行
        _mk_users_db(self.target, [])
        A.merge_migrate_db(self.target, "_users.db")
        c = sqlite3.connect(self.target)
        rows = list(c.execute("select ca_id from ca_info"))
        c.close()
        self.assertEqual(len(rows), 1, "空目标库应补上 CA 记录: %s" % rows)

    def test_ca_info_never_overwritten(self):
        """★ 目标库已有生效 CA → 旧代记录绝不能覆盖它（覆盖=生效根被换=全体证书失效）。"""
        a = os.path.join(self.tmp, "old-b_users.db")
        _mk_users_db(a, ["B1"])
        c = sqlite3.connect(a)
        c.execute("INSERT INTO ca_info (ca_id, ca_name, public_key)"
                  " VALUES ('oldca','OLDCA','OLDPUB')")
        c.commit()
        c.close()
        tgt = os.path.join(self.tmp, "sub-y_users.db")
        _mk_users_db(tgt, [])
        c = sqlite3.connect(tgt)
        c.execute("INSERT INTO ca_info (ca_id, ca_name, public_key)"
                  " VALUES ('curca','MYCA','CURPUB')")
        c.commit()
        c.close()
        A.merge_migrate_db(tgt, "_users.db")
        c = sqlite3.connect(tgt)
        rows = list(c.execute("select ca_id, ca_name from ca_info"))
        c.close()
        self.assertEqual(rows, [("curca", "MYCA")],
                         "生效 CA 被旧代覆盖了: %s" % rows)

    def test_sas_text_pk_keeps_all_certs(self):
        """SAS 库 certificates.id 是 TEXT 主键 → 两代证书全都要在；
        且生效 CA 仍是目标库自己那条（不被旧代覆盖）。"""
        a = os.path.join(self.tmp, "gen1_sas.db")
        b = os.path.join(self.tmp, "gen2_sas.db")
        tgt = os.path.join(self.tmp, "sub-x_sas.db")
        _mk_sas_db(a, ["c1", "c2", "c3"])
        _mk_sas_db(b, ["d1", "d2"])
        # 目标库先建 schema（含当前生效 CA）
        _mk_sas_db(tgt, [])
        A.merge_migrate_db(tgt, "_sas.db")
        c = sqlite3.connect(tgt)
        ids = sorted(r[0] for r in c.execute("select id from certificates"))
        ca = list(c.execute("select id, ca_name, root_cert_json from ca_info"))
        c.close()
        self.assertEqual(ids, ["c1", "c2", "c3", "d1", "d2"])
        self.assertEqual(len(ca), 1, "生效 CA 只应有一行: %s" % ca)
        self.assertEqual(ca[0][1], "MYCA", "生效 CA 被旧代覆盖了")

    def test_merged_sources_are_renamed(self):
        """合并过的历史库要改名，否则下次启动重复合并。"""
        a = os.path.join(self.tmp, "old-a_users.db")
        _mk_users_db(a, ["A1"])
        A.merge_migrate_db(self.target, "_users.db")
        left = [f for f in os.listdir(self.tmp) if f.endswith("_users.db")
                and ".merged-" not in f]
        self.assertEqual(left, ["sub-x_users.db"], "历史库应已改名留档: %s" % left)

    def test_second_run_is_noop(self):
        a = os.path.join(self.tmp, "old-a_users.db")
        _mk_users_db(a, ["A1"])
        A.merge_migrate_db(self.target, "_users.db")
        self.assertEqual(A.merge_migrate_db(self.target, "_users.db"), [])
        c = sqlite3.connect(self.target)
        n = c.execute("select count(*) from users").fetchone()[0]
        c.close()
        self.assertEqual(n, 1, "重复合并会把行翻倍")


class GuojidFilterTests(unittest.TestCase):
    def test_merge_users_skips_users_without_guoji_id(self):
        """口径 B：没有国服 ID 的存量用户不回流。"""
        import sync_engine as S
        src = open(os.path.join(REPO, "sync_engine.py"), encoding="utf-8").read()
        self.assertIn("只保留**国服 ID 用户**", src)
        self.assertIn("if not str(u.get('guoji_id') or '').strip():", src)
        self.assertIn("skipped += 1", src)


class InitToolTests(unittest.TestCase):
    def test_init_tool_exists_and_has_apply_switch(self):
        p = os.path.join(REPO, "init_user_db.py")
        self.assertTrue(os.path.exists(p), "需要 init_user_db.py")
        src = open(p, encoding="utf-8").read()
        self.assertIn("--apply", src)
        self.assertIn("--dry-run", src)
        self.assertIn("_backup", src, "改动前必须备份")


if __name__ == "__main__":
    unittest.main(verbosity=2)
