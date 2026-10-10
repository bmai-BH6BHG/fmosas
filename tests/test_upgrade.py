#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键升级脚本测试（upgrade.sh）
================================
用户要求：一个**独立的升级入口**，只升级系统、**不改变原配置**。

本测试锁定这个不变量：
  * upgrade.sh 的保留名单必须覆盖所有用户数据（config.json / *.db / ca / uploads / roots / logs）
  * 具备版本比较、SHA256 校验、备份、回滚、健康检查
  * install.sh / install-bas.sh 必须注册 fus-upgrade 命令（且装到 /usr/bin，sudo 才找得到）
  * build_release.sh 与发版工作流必须把它发布出去（否则别人拿不到）

另外用**真目录**跑一次升级的"计划"逻辑，断言用户数据一个都没进替换清单。
"""

import io
import os
import re
import subprocess
import sys
import tempfile
import unittest

from tests import ROOT

BASH = r"C:\Program Files\Git\bin\bash.exe"
if not os.path.exists(BASH):
    BASH = "bash"


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class UpgradeScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = read("upgrade.sh")

    def test_syntax_ok(self):
        r = subprocess.run([BASH, "-n", os.path.join(ROOT, "upgrade.sh")],
                           capture_output=True)
        self.assertEqual(0, r.returncode, r.stderr.decode()[:300])

    def test_keeps_user_data(self):
        """★ 核心不变量：用户数据必须在保留规则里。"""
        for must in ("config.json", "ca", "uploads", "roots", "logs"):
            self.assertIn(must, self.src, "保留规则缺少 %s" % must)
        # 数据库/日志等按**字面模式**保留（case 模式，不做路径展开）
        for pat in ("*.db", "*.db-wal", "*.db-shm", "*.log", "*.bak"):
            self.assertIn(pat, self.src, "保留规则缺少 %s" % pat)
        self.assertIn("stations.json", self.src)
        self.assertIn("aprs_stations.json", self.src)

    def test_does_not_run_install_style_config_merge(self):
        """升级不该做配置合并/依赖安装/systemd 注册 —— 那是 install.sh 的活。"""
        self.assertNotIn("config.default.json", self.src.split("KEEP_NAMES", 1)[0],
                         "升级脚本不该引用 config 模板去合并配置")
        for forbidden in ("pip install", "systemctl enable", "FMO_MASTER"):
            self.assertNotIn(forbidden, self.src,
                             "升级脚本不该做 %s（那是安装的事）" % forbidden)

    def test_has_safety_features(self):
        for token in ("compute_sha256", "rollback_now", "--rollback", "--dry-run",
                      "--check", "--list-backups", "py_compile", "svc_stop",
                      "svc_start"):
            self.assertIn(token, self.src, "缺少 %s" % token)
        self.assertIn("health", self.src, "缺少健康检查")

    def test_version_compare_and_idempotent(self):
        self.assertIn("CUR_VER", self.src)
        self.assertIn("TARGET_VER", self.src)
        self.assertIn("已是最新版本", self.src)
        self.assertIn("--force", self.src)

    def test_version_compare(self):
        """
        ver_cmp 必须正确判断大小 —— 否则可能把系统"升级"成更旧的版本
        （真实场景：分发站 VERSION 还没更新 / FMO_BASE_URL 指错目录）。
        """
        src = self.src
        start = src.index("ver_cmp()")
        end = src.index("\n}", start) + 2
        fn = src[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "v.sh")
            with io.open(script, "w", encoding="utf-8", newline="\n") as f:
                f.write("#!/usr/bin/env bash\n" + fn + "\n"
                        'for p in "$@"; do set -- $p; echo "$1 $2 $(ver_cmp "$1" "$2")";'
                        " done\n")
            r = subprocess.run([BASH, script,
                                "1.8.9 1.8.8", "1.8.8 1.8.8", "1.8.7 1.8.8",
                                "2.0 1.9.9", "1.0.0 1.8.7", "1.10.0 1.9.0",
                                "1.8.10 1.8.9"],
                               capture_output=True)
            out = r.stdout.decode("utf-8", "replace")
            got = {}
            for line in out.splitlines():
                parts = line.split()
                if len(parts) == 3:
                    got[(parts[0], parts[1])] = parts[2]
        self.assertEqual("1", got.get(("1.8.9", "1.8.8")))
        self.assertEqual("0", got.get(("1.8.8", "1.8.8")))
        self.assertEqual("-1", got.get(("1.8.7", "1.8.8")))
        self.assertEqual("1", got.get(("2.0", "1.9.9")))
        self.assertEqual("-1", got.get(("1.0.0", "1.8.7")))
        self.assertEqual("1", got.get(("1.10.0", "1.9.0")), "1.10 应大于 1.9（不能按字符串比）")
        self.assertEqual("1", got.get(("1.8.10", "1.8.9")))

    def test_reads_version_from_install_dir(self):
        """
        cur_version 必须优先读安装目录根下的 VERSION，其次 dist/VERSION，
        最后才退到 install-bas.sh —— install-bas.sh 不在 tar 包里（单独发布），
        把它当唯一依据会一直报旧版本（真实踩过：升完还显示 1.8.7）。
        """
        src = self.src
        start = src.index("cur_version()")
        end = src.index("\n}", start) + 2
        fn = src[start:end]
        self.assertIn('"$DIR/VERSION"', fn)
        self.assertIn('"$DIR/dist/VERSION"', fn)
        self.assertIn("install-bas.sh", fn)
        # 顺序：根 VERSION 在前
        self.assertLess(fn.index('"$DIR/VERSION"'), fn.index('install-bas.sh'))

    def test_writes_version_after_success(self):
        """升级成功后必须写回版本号，否则下次仍显示旧版本。"""
        self.assertIn("write_version", self.src)
        self.assertIn('write_version "${NEW_VER:-$TARGET_VER}"', self.src)

    def test_downgrade_guard(self):
        self.assertIn("ver_cmp", self.src)
        self.assertIn("这是降级，不是升级", self.src)
        self.assertIn("--force", self.src)

    def test_help_works(self):
        r = subprocess.run([BASH, os.path.join(ROOT, "upgrade.sh"), "--help"],
                           capture_output=True)
        out = r.stdout.decode("utf-8", "replace")
        self.assertIn("只升级系统", out)
        self.assertIn("--rollback", out)
        self.assertIn("--dry-run", out)

    def test_list_backups_on_empty_dir_is_safe(self):
        """没有备份时必须干净退出（不能报错崩掉）。"""
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["FMO_UPGRADE_BACKUP_DIR"] = tmp
            env["FMO_DIR"] = ROOT       # 指向真实目录（有 api_server.py）
            r = subprocess.run([BASH, os.path.join(ROOT, "upgrade.sh"),
                                "--list-backups"],
                               capture_output=True, env=env)
            self.assertEqual(0, r.returncode, r.stderr.decode()[:300])

    def test_keeps_user_data_in_source(self):
        """源码层面确认保留规则用 case 字面模式（不是会触发路径展开的 for 循环）。"""
        self.assertIn("is_kept()", self.src)
        body = self.src.split("is_kept()", 1)[1].split("\n}", 1)[0]
        self.assertIn("case \"$base\" in", body)
        self.assertIn("*.db|", body, "保留规则里必须有 *.db 字面模式")
        # ★ 不得再用 `for p in $LIST` 这种会触发 glob 的写法
        self.assertNotIn("for p in $KEEP_PATTERNS", self.src)
        self.assertNotIn("for k in $KEEP_NAMES", self.src)

    def test_is_kept_logic_excludes_data(self):
        """
        直接抽脚本里**真实的 is_kept 函数**跑（不是测试里重写的副本）：
        断言用户数据一个都不进替换清单。
        ★ 这条曾抓出真 bug：`for p in $KEEP_PATTERNS` 里未加引号的变量会被
          shell 按当前目录展开，`*.db` 变成实际文件名 → 用户数据库会被覆盖。
        """
        src = self.src
        start = src.index("is_kept()")
        end = src.index("\n}", start) + 2
        func = src[start:end]
        self.assertIn("case", func)

        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "probe.sh")
            with io.open(script, "w", encoding="utf-8", newline="\n") as f:
                f.write("#!/usr/bin/env bash\n" + func + "\n" +
                        'for f in "$@"; do\n'
                        '  if is_kept "$f"; then echo "KEEP $f";'
                        ' else echo "REPLACE $f"; fi\n'
                        'done\n')
            files = [
                "api_server.py", "bridge.py", "config.default.json",
                "install.sh", "upgrade.sh", "admin/index.html",
                "config.json", "voice.db", "stations.json",
                "ca/cert_root.json", "uploads/x.txt", "192.168.1.7_audit.db",
                "aprs_stations.json", "AUTH_TRACE", "x.log", "y.bak",
                "sub_users.db", "sub_sas.db-wal", "some.db-shm",
            ]
            r = subprocess.run([BASH, script] + files, capture_output=True)
            out = r.stdout.decode("utf-8", "replace")
            keep = {l.split(" ", 1)[1] for l in out.splitlines()
                    if l.startswith("KEEP ")}
            repl = {l.split(" ", 1)[1] for l in out.splitlines()
                    if l.startswith("REPLACE ")}

            for must_keep in ("config.json", "voice.db", "stations.json",
                              "ca/cert_root.json", "uploads/x.txt",
                              "192.168.1.7_audit.db", "aprs_stations.json",
                              "AUTH_TRACE", "x.log", "y.bak", "upgrade.sh",
                              "sub_users.db", "sub_sas.db-wal", "some.db-shm"):
                self.assertIn(must_keep, keep,
                              "升级会覆盖用户数据 %s（必须保留）" % must_keep)
            for must_replace in ("api_server.py", "bridge.py",
                                 "config.default.json", "install.sh",
                                 "admin/index.html"):
                self.assertIn(must_replace, repl,
                              "系统文件 %s 应当被升级" % must_replace)


class InstallerAndPackagingTests(unittest.TestCase):
    def test_installers_register_upgrade_command(self):
        for name in ("install.sh", "install-bas.sh"):
            src = read(name)
            self.assertIn("fus-upgrade", src, "%s 未注册 fus-upgrade" % name)
            self.assertIn("upgrade.sh", src, "%s 未引用 upgrade.sh" % name)
            self.assertIn("/usr/bin", src,
                          "%s 未装到 /usr/bin（sudo 下会找不到）" % name)

    def test_build_release_requires_and_ships_upgrade(self):
        src = read("build_release.sh")
        self.assertIn("upgrade.sh", src)
        self.assertGreaterEqual(src.count("upgrade.sh"), 3,
                                "必需文件检查 / 打包 / 上传目录 三处都要有")
        self.assertIn("$UPLOAD/upgrade.sh", src)

    def test_release_publishes_flat_assets(self):
        src = read(".github/workflows/release.yml")
        self.assertIn("fus-upgrade.sh", src)
        self.assertIn("bas-upgrade.sh", src)
        self.assertIn("out/upgrade.sh", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
