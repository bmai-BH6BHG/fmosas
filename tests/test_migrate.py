#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bas_migrate 测试：旧 SAS / FAS 的扫描识别、备份、卸载安全阀
============================================================
用临时目录伪造"旧的 SAS 与 FAS 安装"，验证：
  * 能找到两者的目录与服务、读出各自数据库里的关键信息
  * 能读出旧 FAS 库里保存的 EMQX 配置（迁移用）
  * 备份成 tar.gz 且内容完整；备份失败必须中止
  * 删除前有安全阀（缺特征文件/系统路径 → 拒绝）
"""

import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from tests import ROOT  # noqa: F401
import bas_migrate as m


def make_subsys(dirpath):
    os.makedirs(dirpath, exist_ok=True)
    for f in ("api_server.py", "sas_server.py", "config.json"):
        with open(os.path.join(dirpath, f), "w") as fh:
            fh.write("x")
    os.makedirs(os.path.join(dirpath, "ca"), exist_ok=True)
    with open(os.path.join(dirpath, "ca", "ca_private.json"), "w") as fh:
        fh.write('{"root_seed":"SECRET"}')
    for name, table, n in (("bh6bhg.synology.me_users.db", "users", 42),
                           ("bh6bhg.synology.me_sas.db", "certificates", 7)):
        c = sqlite3.connect(os.path.join(dirpath, name))
        if table == "users":
            c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, callsign TEXT)")
            c.executemany("INSERT INTO users(callsign) VALUES(?)",
                          [("BG%dAAA" % i,) for i in range(n)])
        else:
            c.execute("CREATE TABLE certificates(id TEXT PRIMARY KEY, callsign TEXT, uid INT)")
            c.executemany("INSERT INTO certificates VALUES(?,?,?)",
                          [("c%d" % i, "BG%dAAA" % i, i) for i in range(n)])
        c.commit()
        c.close()


def make_fas(dirpath, with_emqx=True):
    os.makedirs(dirpath, exist_ok=True)
    # 注意：先建二进制可执行文件占位，**不要**预写 fmo-audit-service.db（否则 sqlite 打不开）
    with open(os.path.join(dirpath, "fmo-audit-service"), "w") as fh:
        fh.write("x")
    c = sqlite3.connect(os.path.join(dirpath, "fmo-audit-service.db"))
    c.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)")
    rows = [("identity_control", "1"), ("topic_name", "FMO/RAW")]
    if with_emqx:
        rows += [("emqx_url", "http://127.0.0.1:18083"),
                 ("emqx_api_key", "OLDKEY"), ("emqx_api_secret", "OLDSECRET")]
    c.executemany("INSERT INTO settings VALUES(?,?)", rows)
    c.execute("CREATE TABLE audit_packets(id INTEGER PRIMARY KEY, verdict TEXT)")
    c.commit()
    c.close()


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bas-migrate-")
        self.subsys = os.path.join(self.tmp, "fmo-subsystem")
        self.fas = os.path.join(self.tmp, "fmo-fas")
        self.backup = os.path.join(self.tmp, "backups")
        self._orig = {
            "SUBSYS_DIRS": m.SUBSYS_DIRS, "FAS_DIRS": m.FAS_DIRS,
            "FAS_CACHE": m.FAS_CACHE, "service_state": m.service_state,
            "port_listening": m.port_listening, "_run": m._run,
        }
        m.service_state = lambda name: {"fmo-subsystem": "active",
                                        "fmo-fas": "active"}.get(name, "absent")
        m.port_listening = lambda port, host="127.0.0.1": port in (35928, 9527)
        m._run = lambda cmd, timeout=8: (1, "")     # id/pgrep 都不存在
        m.FAS_CACHE = os.path.join(self.tmp, "cache-fmo-fas")

    def tearDown(self):
        m.SUBSYS_DIRS = self._orig["SUBSYS_DIRS"]
        m.FAS_DIRS = self._orig["FAS_DIRS"]
        m.FAS_CACHE = self._orig["FAS_CACHE"]
        m.service_state = self._orig["service_state"]
        m.port_listening = self._orig["port_listening"]
        m._run = self._orig["_run"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scan(self):
        return m.scan(subsys_dirs=[self.subsys], fas_dirs=[self.fas])

    # ---------------- 扫描 ----------------
    def test_detects_both_legacy_systems(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        r = self._scan()
        self.assertTrue(r["sas"]["found"])
        self.assertTrue(r["fas"]["found"])
        self.assertEqual("active", r["sas"]["services"]["fmo-subsystem"])
        self.assertEqual("active", r["fas"]["services"]["fmo-fas"])
        self.assertTrue(r["sas"]["ca"], "必须发现 CA 私钥目录（要一起备份）")
        self.assertTrue(r["sas"]["port_35928"])
        self.assertTrue(r["fas"]["port_9527"])

    def test_reads_db_row_counts(self):
        make_subsys(self.subsys)
        r = self._scan()
        entry = r["sas"]["dirs"][0]
        by_name = {os.path.basename(d["path"]): d for d in entry["dbs"]}
        users = by_name["bh6bhg.synology.me_users.db"]
        self.assertIn("users", users["tables"])
        self.assertEqual(42, users["rows"], "应能读出用户数（报告里给人看）")
        certs = by_name["bh6bhg.synology.me_sas.db"]
        self.assertIn("certificates", certs["tables"])

    def test_reads_legacy_emqx_settings(self):
        make_fas(self.fas)
        r = self._scan()
        cfg = r["fas"]["emqx_settings"]
        self.assertEqual("http://127.0.0.1:18083", cfg.get("emqx_url"))
        self.assertEqual("OLDKEY", cfg.get("emqx_api_key"))
        self.assertEqual("OLDSECRET", cfg.get("emqx_api_secret"))
        self.assertEqual("FMO/RAW", cfg.get("topic_name"))

    def test_empty_machine_reports_nothing(self):
        r = m.scan(subsys_dirs=[os.path.join(self.tmp, "nope")],
                   fas_dirs=[os.path.join(self.tmp, "nope2")])
        # 服务桩仍报告 active，这里只验证目录维度不误报
        self.assertEqual([], r["sas"]["dirs"])
        self.assertEqual([], r["fas"]["dirs"])

    def test_report_is_human_readable(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        rep = m.scan_report(self._scan())
        self.assertIn("原有 SAS", rep)
        self.assertIn("原有 FAS", rep)
        self.assertIn("CA 私钥目录", rep)
        self.assertIn("18083", rep)

    # ---------------- 备份 ----------------
    def test_backup_contains_everything(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        r = self._scan()
        ok, arch, items = m.backup(r["backup_candidates"], self.backup, log=lambda *_: None)
        self.assertTrue(ok, "备份必须成功")
        self.assertTrue(os.path.exists(arch))
        import tarfile
        with tarfile.open(arch) as tf:
            names = tf.getnames()
        joined = "\n".join(names)
        self.assertIn("api_server.py", joined, "分系统代码应在备份里")
        self.assertIn("ca_private.json", joined, "CA 私钥必须备份（否则无法恢复身份）")
        self.assertIn("bh6bhg.synology.me_users.db", joined, "用户库必须备份")
        self.assertIn("fmo-audit-service.db", joined, "旧审计库必须备份")

    def test_backup_no_candidates_is_ok(self):
        ok, arch, items = m.backup([], self.backup, log=lambda *_: None)
        self.assertTrue(ok)
        self.assertIsNone(arch)

    # ---------------- 卸载安全阀 ----------------
    def test_safe_rm_refuses_system_paths(self):
        for bad in ("/", "/opt", "/usr", "/etc"):
            ok, msg = m._safe_rm(bad, must_contain=None, log=lambda *_: None)
            self.assertFalse(ok, "必须拒绝删除 %s" % bad)
            self.assertIn("拒绝", msg)

    def test_safe_rm_requires_marker_file(self):
        d = os.path.join(self.tmp, "not-subsys")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "random.txt"), "w") as f:
            f.write("x")
        ok, msg = m._safe_rm(d, must_contain="api_server.py", log=lambda *_: None)
        self.assertFalse(ok, "缺特征文件必须拒绝")
        self.assertTrue(os.path.exists(d), "拒绝时目录不能被删")

    def test_safe_rm_deletes_when_marker_matches(self):
        d = os.path.join(self.tmp, "real-subsys")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "api_server.py"), "w") as f:
            f.write("x")
        ok, _ = m._safe_rm(d, must_contain="api_server.py", log=lambda *_: None)
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(d))

    # ---------------- 迁移全流程 ----------------
    def test_migrate_backs_up_then_removes(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        os.makedirs(m.FAS_CACHE, exist_ok=True)
        r = self._scan()
        res = m.migrate(r, backup_dir=self.backup, log=lambda *_: None)
        self.assertEqual([], res["errors"], "不应有错误: %s" % res["errors"])
        self.assertTrue(res["backup"] and os.path.exists(res["backup"]), "必须先有备份")
        self.assertFalse(os.path.exists(self.subsys), "旧分系统目录应被删除")
        self.assertFalse(os.path.exists(self.fas), "旧 FAS 目录应被删除")
        self.assertFalse(os.path.exists(m.FAS_CACHE), "旧缓存应被删除")
        # 备份里仍能找回数据
        import tarfile
        with tarfile.open(res["backup"]) as tf:
            self.assertIn("ca_private.json", "\n".join(tf.getnames()))

    def test_migrate_aborts_when_backup_fails(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        r = self._scan()
        orig = m.backup
        m.backup = lambda *a, **k: (False, None, [])
        try:
            res = m.migrate(r, backup_dir=self.backup, log=lambda *_: None)
        finally:
            m.backup = orig
        self.assertTrue(res["errors"], "备份失败必须报错")
        self.assertTrue(os.path.exists(self.subsys), "备份失败时绝不能删数据")
        self.assertTrue(os.path.exists(self.fas))

    def test_migrate_no_backup_flag_allows_removal(self):
        make_fas(self.fas)
        r = self._scan()
        res = m.migrate(r, backup_dir=self.backup, no_backup=True, log=lambda *_: None)
        self.assertEqual([], res["errors"])
        self.assertIsNone(res["backup"])
        self.assertFalse(os.path.exists(self.fas))

    def test_migrate_is_idempotent(self):
        make_subsys(self.subsys)
        make_fas(self.fas)
        r = self._scan()
        first = m.migrate(r, backup_dir=self.backup, log=lambda *_: None)
        self.assertEqual([], first["errors"])
        res2 = m.migrate(r, backup_dir=self.backup, log=lambda *_: None)
        self.assertEqual([], res2["errors"], "清理过的系统再跑不应报错")
        # 第二次每一项都应是"不存在（跳过）"，不应真的再删东西
        for item in res2["removed"]:
            self.assertIn("不存在", item, "二次执行不应产生删除动作: %s" % item)

    def test_migrate_emqx_cleanup_skipped_without_config(self):
        make_fas(self.fas, with_emqx=False)
        r = self._scan()
        res = m.migrate(r, backup_dir=self.backup, no_backup=True, log=lambda *_: None)
        self.assertIn("未保存 EMQX", res["emqx"] or "")

    def test_scan_json_serializable(self):
        """安装脚本用 --json 解析扫描结果，必须可序列化。"""
        make_subsys(self.subsys)
        make_fas(self.fas)
        s = json.dumps(self._scan(), ensure_ascii=False)
        self.assertIn("emqx_settings", s)
        self.assertIn("backup_candidates", s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
