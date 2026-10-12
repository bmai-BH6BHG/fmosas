#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fus-set-appkey（APP 密钥写入命令）测试
======================================
★ 安全事件后的重写（重要）：

  旧版本把 **APP 私钥 seed** 与公钥硬编码在这个测试文件里，而这个文件又被
  `build_release.sh` 打进发行包 → 等于把 APP 私钥随源码/发版包公开
  （仓库是 public）。现在：

    * 测试用**现场推导**的假密钥对（`TEST_SEED` 由固定字节生成，不是任何真实密钥），
      仓库里不再出现任何真实 APP 密钥；
    * 工具不再内置"官方公钥"：不给 `--pubkey`/`--seed` 就必须报错；
    * 新增**守卫测试**：扫全仓库，发现"疑似 APP 私钥/私钥文件/GitHub Token"就失败，
      防止以后再把密钥写回代码或文档里。

本测试锁定：
  * 无参数时必须报错退出、且不动配置（不再偷偷写入某把内置公钥）
  * --pubkey / --seed 推导 / hex 输入 / --append / --dry-run / --show / --verify
  * 只改 dmrid.app_pubkey，其它配置原样保留；写前备份；值没变不重复备份
  * base64url 以 "-" 开头时命令行不被 argparse 误判
  * api_server 与 config.default.json **都不含**内置 APP 公钥
  * 仓库里不得存在 APP 私钥
"""

import base64
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import ROOT

# ---------------------------------------------------------------- 测试用假密钥
# 只测试用：由固定字节现场编码，**不是任何真实密钥**。
# 特意让第一个字节的高 6 位 = 62（'-'），这样 base64url 以 '-' 开头，
# 覆盖"值以 '-' 开头时不得被 argparse 当成选项"的兼容性。
TEST_SEED = base64.urlsafe_b64encode(bytes([0xF8] + [7] * 31)).decode().rstrip("=")
assert TEST_SEED.startswith("-"), TEST_SEED


def load_mod():
    """按路径加载 set_appkey.py（它不是包内模块，用 importlib 直取）"""
    path = os.path.join(ROOT, "set_appkey.py")
    spec = importlib.util.spec_from_file_location("set_appkey_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MOD = None


def _pub():
    """测试 seed 推导出的公钥（现场算，不在仓库里写字面量）。"""
    global _MOD
    if _MOD is None:
        _MOD = load_mod()
    pub, err = _MOD.seed_to_pubkey(TEST_SEED)
    assert not err, err
    return pub


TEST_PUB = None      # 延迟到用时再算（见 pub()）
TEST_PUB_HEX = None


class SetAppKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_mod()
        cls.pub, err = cls.mod.seed_to_pubkey(TEST_SEED)
        assert not err, err
        cls.pub_hex = base64.urlsafe_b64decode(cls.pub + "===").hex()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-appkey-")
        self.cfg = os.path.join(self.tmp, "config.json")
        self.base = {
            "subsystem_id": "sub-983bee49",
            "api_url": "http://example.com:35928",
            "dmrid": {"enabled": True, "verify_password": False,
                      "app_timestamp_window": 300},
        }
        self.write(self.base)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, obj):
        with open(self.cfg, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)

    def read(self):
        with open(self.cfg, encoding="utf-8") as f:
            return json.load(f)

    def run_cmd(self, *args):
        return self.mod.main(["--config", self.cfg] + list(args))

    # ---------------- 不再内置任何公钥 ----------------

    def test_no_builtin_pubkey_constant(self):
        """工具里不得再内置任何 APP 公钥常量"""
        for name in ("OFFICIAL_APP_PUBKEY", "OFFICIAL_APP_PUBKEY_HEX"):
            self.assertFalse(hasattr(self.mod, name),
                             "不应再内置 %s（安全事件：内置密钥随源码公开）" % name)

    def test_no_args_errors_and_does_not_touch_config(self):
        """★ 无参数时必须报错（不再偷偷写内置公钥），且配置不变"""
        before = self.read()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.run_cmd()
        self.assertEqual(2, rc, "无参数应报错并要求 --pubkey")
        self.assertEqual(before, self.read(), "报错时不能改动配置")
        self.assertIn("--pubkey", buf.getvalue() + "", "错误提示要告诉用户怎么给公钥")

    # ---------------- 写入行为 ----------------

    def test_custom_pubkey_b64(self):
        rc = self.run_cmd("--pubkey", self.pub)
        self.assertEqual(0, rc)
        self.assertEqual(self.pub, self.read()["dmrid"]["app_pubkey"])

    def test_custom_pubkey_hex(self):
        rc = self.run_cmd("--pubkey", self.pub_hex)
        self.assertEqual(0, rc)
        self.assertEqual(self.pub, self.read()["dmrid"]["app_pubkey"])

    def test_other_config_preserved(self):
        self.run_cmd("--pubkey", self.pub)
        got = self.read()
        self.assertEqual(self.base["subsystem_id"], got["subsystem_id"])
        self.assertEqual(self.base["api_url"], got["api_url"])
        self.assertEqual(True, got["dmrid"]["enabled"])
        self.assertEqual(300, got["dmrid"]["app_timestamp_window"])

    def test_backup_created(self):
        self.run_cmd("--pubkey", self.pub)
        baks = [f for f in os.listdir(self.tmp) if ".bak-appkey-" in f]
        self.assertEqual(1, len(baks), "写前必须备份 config.json")
        with open(os.path.join(self.tmp, baks[0]), encoding="utf-8") as f:
            self.assertNotIn(self.pub, f.read())

    def test_idempotent_no_second_backup(self):
        self.run_cmd("--pubkey", self.pub)
        self.run_cmd("--pubkey", self.pub)      # 第二次：值没变，不该再备份
        baks = [f for f in os.listdir(self.tmp) if ".bak-appkey-" in f]
        self.assertEqual(1, len(baks))

    def test_seed_derives_pubkey(self):
        rc = self.run_cmd("--seed", TEST_SEED)
        self.assertEqual(0, rc)
        self.assertEqual(self.pub, self.read()["dmrid"]["app_pubkey"])
        # 默认**不**保存私钥
        self.assertNotIn("app_seed", self.read()["dmrid"])

    def test_store_seed_opt_in(self):
        rc = self.run_cmd("--seed", TEST_SEED, "--store-seed")
        self.assertEqual(0, rc)
        self.assertEqual(TEST_SEED, self.read()["dmrid"]["app_seed"])

    def test_append_keeps_old_key(self):
        other = base64.urlsafe_b64encode(b"\x02" * 32).decode().rstrip("=")
        self.run_cmd("--pubkey", self.pub)
        rc = self.run_cmd("--pubkey", other, "--append")
        self.assertEqual(0, rc)
        keys = self.read()["dmrid"]["app_pubkey"]
        self.assertIsInstance(keys, list)
        self.assertEqual([self.pub, other], keys)

    def test_append_duplicate_is_noop(self):
        self.run_cmd("--pubkey", self.pub)
        self.run_cmd("--pubkey", self.pub, "--append")
        self.assertEqual(self.pub, self.read()["dmrid"]["app_pubkey"])

    def test_dry_run_does_not_write(self):
        before = self.read()
        rc = self.run_cmd("--pubkey", self.pub, "--dry-run")
        self.assertEqual(0, rc)
        self.assertEqual(before, self.read())
        self.assertEqual([], [f for f in os.listdir(self.tmp)
                              if ".bak-appkey-" in f])

    def test_creates_missing_dmrid_section(self):
        self.write({"subsystem_id": "x"})
        rc = self.run_cmd("--pubkey", self.pub)
        self.assertEqual(0, rc)
        self.assertEqual(self.pub, self.read()["dmrid"]["app_pubkey"])

    def test_bad_pubkey_returns_usage_error(self):
        rc = self.run_cmd("--pubkey", "AAAA")
        self.assertEqual(2, rc)
        self.assertNotIn("app_pubkey", self.read().get("dmrid", {}))

    # ---------------- show / verify ----------------

    def test_verify_fails_when_unset(self):
        self.assertEqual(1, self.run_cmd("--verify"))

    def test_verify_passes_after_install(self):
        self.run_cmd("--pubkey", self.pub)
        self.assertEqual(0, self.run_cmd("--verify"))

    def test_verify_checks_seed_pairing(self):
        self.run_cmd("--pubkey", self.pub)
        self.assertEqual(0, self.run_cmd("--verify", "--seed", TEST_SEED))
        other_seed = base64.urlsafe_b64encode(b"\x07" * 32).decode().rstrip("=")
        self.assertEqual(1, self.run_cmd("--verify", "--seed", other_seed))

    def test_show_lists_keys(self):
        self.run_cmd("--pubkey", self.pub)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_cmd("--show", "--json")
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(self.pub, payload["app_pubkey"])
        # 不再报"官方/非官方"
        self.assertNotIn("is_official", payload)

    # ---------------- 命令行兼容 ----------------

    def test_dash_leading_value_is_not_treated_as_option(self):
        """seed 以 '-' 开头时，必须能直接跟在 --seed 后面"""
        norm = self.mod.normalize_argv(["--seed", TEST_SEED, "--dry-run"])
        self.assertIn("--seed=" + TEST_SEED, norm)
        self.assertIn("--dry-run", norm)
        self.assertEqual(0, self.run_cmd("--seed", TEST_SEED, "--dry-run"))

    def test_json_output_is_valid(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_cmd("--pubkey", self.pub, "--json")
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["changed"])


class NoBuiltinKeyTests(unittest.TestCase):
    """★ 安全回归：任何地方都不得再内置 APP 密钥"""

    def test_api_server_has_no_builtin_app_pubkey(self):
        import api_server
        self.assertEqual("", api_server.DMRID_DEFAULT.get("app_pubkey", ""),
                         "api_server 不得内置 APP 公钥（必须由部署者写入）")
        saved = api_server.CONFIG.get("dmrid")
        try:
            api_server.CONFIG["dmrid"] = {}
            self.assertEqual([], api_server.get_app_pubkeys(),
                             "未配置时必须没有公钥（fail-closed）")
        finally:
            if saved is None:
                api_server.CONFIG.pop("dmrid", None)
            else:
                api_server.CONFIG["dmrid"] = saved

    def test_config_default_json_has_no_pubkey(self):
        p = os.path.join(ROOT, "config.default.json")
        with open(p, encoding="utf-8-sig") as f:
            cfg = json.load(f)
        self.assertEqual("", (cfg.get("dmrid") or {}).get("app_pubkey", ""),
                         "分发模板里不得带 APP 公钥")

    def test_repo_contains_no_app_seed_literal(self):
        """
        ★★ 守卫：全仓库扫一遍，发现"疑似 APP 私钥字面量"就失败。

        背景：私钥 seed 曾被硬编码在测试与文档里、并随发版包公开。
        模式在运行时拼接，避免守卫文件自身命中。
        """
        kw = "seed"
        pat = re.compile(
            r"(?i)(app[_-]?%s|official[_-]?%s|private[_-]?%s)\s*[:=]\s*[\"']"
            r"([A-Za-z0-9_\-]{40,})[\"']" % (kw, kw, kw))
        me = os.path.basename(__file__)
        bad = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__", "dist", "venv",
                                        ".venv", "node_modules", "ca", "roots",
                                        "uploads", "logs")]
            for fn in filenames:
                if fn == me or not fn.endswith((".py", ".json", ".md", ".txt", ".sh")):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, encoding="utf-8", errors="replace") as f:
                        txt = f.read()
                except Exception:  # noqa: BLE001
                    continue
                for m in pat.finditer(txt):
                    bad.append("%s: %s" % (os.path.relpath(fp, ROOT), m.group(0)[:60]))
        self.assertEqual([], bad, "仓库里不得出现 APP 私钥字面量：\n" + "\n".join(bad))

    def test_repo_contains_no_private_key_files_or_tokens(self):
        """私钥文件标记与 GitHub Token 也不许出现（标记运行时拼接，避免本文件自命中）"""
        markers = ["BEGIN " + "PRIVATE KEY",
                   "BEGIN OPENSSH " + "PRIVATE KEY",
                   "BEGIN RSA " + "PRIVATE KEY"]
        me = os.path.basename(__file__)
        bad = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", "__pycache__", "dist", "venv",
                                        ".venv", "node_modules", "ca", "roots",
                                        "uploads", "logs")]
            for fn in filenames:
                if fn == me or not fn.endswith((".py", ".json", ".md", ".txt", ".sh", ".yml", ".yaml")):
                    continue
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, encoding="utf-8", errors="replace") as f:
                        txt = f.read()
                except Exception:  # noqa: BLE001
                    continue
                for marker in markers:
                    if marker in txt:
                        bad.append("%s: %s" % (os.path.relpath(fp, ROOT), marker))
                if re.search(r"(?i)ghp" + r"_[A-Za-z0-9]{20,}", txt):
                    bad.append("%s: GitHub Token" % os.path.relpath(fp, ROOT))
        self.assertEqual([], bad, "仓库里不得出现私钥/令牌：\n" + "\n".join(bad))


class PackagingTests(unittest.TestCase):
    """命令必须随发行包发布，别人才能用；同时 tests/ 不得进包"""

    def test_in_build_release_required_and_copied(self):
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("set_appkey.py", src)
        self.assertGreaterEqual(src.count("set_appkey.py"), 2)

    def test_tests_dir_is_not_packaged(self):
        """★ tests/ 不再进发行包（里面容易写测试用密钥，且用户不需要）"""
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertNotIn('copy_path tests', src,
                         "tests/ 不得打进发行包")

    def test_build_scans_package_for_secrets(self):
        """打包时要**扫内容**，发现疑似密钥就让打包失败"""
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertTrue("SEED" in src or "PRIVATE KEY" in src,
                        "build_release.sh 需要加密钥内容自检")

    def test_release_publishes_flat_assets(self):
        p = os.path.join(ROOT, ".github", "workflows", "release.yml")
        src = open(p, encoding="utf-8").read()
        self.assertIn("fus-set-appkey.py", src)
        self.assertIn("bas-set-appkey.py", src)

    def test_build_puts_set_appkey_into_upload_dir(self):
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("$UPLOAD/set_appkey.py", src)

    def test_installers_register_command(self):
        for name in ("install.sh", "install-bas.sh"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            self.assertIn("fus-set-appkey", src, "%s 未注册命令" % name)
            self.assertIn("set_appkey.py", src, "%s 未引用脚本" % name)

    def test_installers_also_install_to_usr_bin(self):
        for name in ("install.sh", "install-bas.sh"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            self.assertIn("/usr/bin", src,
                          "%s 未把命令装到 /usr/bin（sudo 下会找不到）" % name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
