#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fus-set-appkey（APP 密钥写入命令）测试
======================================
背景：有人装了本系统但没部署 APP 密钥对，导致 APP 签名校验失败、绑定被拒。
现在提供一条命令 `sudo fus-set-appkey` 写入官方 APP 公钥。

本测试锁定：
  * 官方公钥常量正确（与 APP 里的私钥 seed 推导出的公钥一致）
  * 默认写入 / --pubkey / --seed 推导 / hex 输入 / --append / --dry-run
  * 只改 dmrid.app_pubkey，其它配置原样保留；写前备份
  * --show / --verify 的判定
  * base64url 以 "-" 开头时命令行不被 argparse 误判
  * api_server 的内置默认值就是官方公钥
"""

import base64
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

from tests import ROOT

# 官方 APP 密钥对（用户提供；私钥在 APP 内，公钥公开）
OFFICIAL_SEED = "-zbIIPI-9Q1mecFCbXGdTm7rL3D8gSC64s16mmE06i0"
OFFICIAL_PUB = "4LL2krXOFvViFvbdP3pvTJK2pZXMIRNWQ6nz8jp5gr0"
OFFICIAL_PUB_HEX = ("e0b2f692b5ce16f56216f6dd3f7a6f4c92b6a595cc21"
                    "135643a9f3f23a7982bd")


def load_mod():
    """按路径加载 set_appkey.py（它不是包内模块，用 importlib 直取）"""
    path = os.path.join(ROOT, "set_appkey.py")
    spec = importlib.util.spec_from_file_location("set_appkey_mod", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SetAppKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_mod()

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

    # ---------------- 常量正确性 ----------------

    def test_official_pubkey_matches_seed(self):
        """内置公钥必须与官方 seed 推导出的公钥一致（否则 APP 会被拒）"""
        derived, err = self.mod.seed_to_pubkey(OFFICIAL_SEED)
        self.assertEqual("", err)
        self.assertEqual(OFFICIAL_PUB, derived)
        self.assertEqual(OFFICIAL_PUB, self.mod.OFFICIAL_APP_PUBKEY)

    def test_official_pubkey_hex_consistent(self):
        b = base64.urlsafe_b64decode(OFFICIAL_PUB + "===")
        self.assertEqual(32, len(b))
        self.assertEqual(OFFICIAL_PUB_HEX, b.hex())
        self.assertEqual(OFFICIAL_PUB_HEX, self.mod.OFFICIAL_APP_PUBKEY_HEX)

    def test_pubkey_normalizer_accepts_b64_and_hex(self):
        self.assertEqual((OFFICIAL_PUB, ""),
                         self.mod.norm_pubkey(OFFICIAL_PUB))
        self.assertEqual((OFFICIAL_PUB, ""),
                         self.mod.norm_pubkey(OFFICIAL_PUB_HEX))
        self.assertEqual((OFFICIAL_PUB, ""),
                         self.mod.norm_pubkey(OFFICIAL_PUB_HEX.upper()))

    def test_pubkey_normalizer_rejects_bad_input(self):
        for bad in ("", "not-base64!!", "AAAA", OFFICIAL_PUB_HEX[:62]):
            want, err = self.mod.norm_pubkey(bad)
            self.assertEqual("", want)
            self.assertTrue(err, "非法公钥必须报错: %r" % bad)

    # ---------------- 写入行为 ----------------

    def test_default_writes_official_pubkey(self):
        rc = self.run_cmd()
        self.assertEqual(0, rc)
        self.assertEqual(OFFICIAL_PUB, self.read()["dmrid"]["app_pubkey"])

    def test_other_config_preserved(self):
        self.run_cmd()
        got = self.read()
        self.assertEqual(self.base["subsystem_id"], got["subsystem_id"])
        self.assertEqual(self.base["api_url"], got["api_url"])
        self.assertEqual(True, got["dmrid"]["enabled"])
        self.assertEqual(300, got["dmrid"]["app_timestamp_window"])

    def test_backup_created(self):
        self.run_cmd()
        baks = [f for f in os.listdir(self.tmp) if ".bak-appkey-" in f]
        self.assertEqual(1, len(baks), "写前必须备份 config.json")
        with open(os.path.join(self.tmp, baks[0]), encoding="utf-8") as f:
            self.assertNotIn(OFFICIAL_PUB, f.read())

    def test_idempotent_no_second_backup(self):
        self.run_cmd()
        self.run_cmd()          # 第二次：值没变，不该再备份
        baks = [f for f in os.listdir(self.tmp) if ".bak-appkey-" in f]
        self.assertEqual(1, len(baks))

    def test_seed_derives_official_pubkey(self):
        rc = self.run_cmd("--seed", OFFICIAL_SEED)
        self.assertEqual(0, rc)
        self.assertEqual(OFFICIAL_PUB, self.read()["dmrid"]["app_pubkey"])
        # 默认**不**保存私钥
        self.assertNotIn("app_seed", self.read()["dmrid"])

    def test_store_seed_opt_in(self):
        rc = self.run_cmd("--seed", OFFICIAL_SEED, "--store-seed")
        self.assertEqual(0, rc)
        self.assertEqual(OFFICIAL_SEED, self.read()["dmrid"]["app_seed"])

    def test_custom_pubkey_b64(self):
        other = base64.urlsafe_b64encode(b"\x01" * 32).decode().rstrip("=")
        rc = self.run_cmd("--pubkey", other)
        self.assertEqual(0, rc)
        self.assertEqual(other, self.read()["dmrid"]["app_pubkey"])

    def test_custom_pubkey_hex(self):
        other = base64.urlsafe_b64encode(b"\x03" * 32).decode().rstrip("=")
        raw_hex = base64.urlsafe_b64decode(other + "===").hex()
        rc = self.run_cmd("--pubkey", raw_hex)
        self.assertEqual(0, rc)
        self.assertEqual(other, self.read()["dmrid"]["app_pubkey"])

    def test_append_keeps_old_key(self):
        other = base64.urlsafe_b64encode(b"\x02" * 32).decode().rstrip("=")
        self.run_cmd()                              # 先写官方公钥
        rc = self.run_cmd("--pubkey", other, "--append")
        self.assertEqual(0, rc)
        keys = self.read()["dmrid"]["app_pubkey"]
        self.assertIsInstance(keys, list)
        self.assertEqual([OFFICIAL_PUB, other], keys)

    def test_append_duplicate_is_noop(self):
        self.run_cmd()
        self.run_cmd("--append")                    # 追加同一个官方公钥
        self.assertEqual(OFFICIAL_PUB, self.read()["dmrid"]["app_pubkey"])

    def test_dry_run_does_not_write(self):
        before = self.read()
        rc = self.run_cmd("--dry-run")
        self.assertEqual(0, rc)
        self.assertEqual(before, self.read())
        self.assertEqual([], [f for f in os.listdir(self.tmp)
                             if ".bak-appkey-" in f])

    def test_creates_missing_dmrid_section(self):
        self.write({"subsystem_id": "x"})
        rc = self.run_cmd()
        self.assertEqual(0, rc)
        self.assertEqual(OFFICIAL_PUB, self.read()["dmrid"]["app_pubkey"])

    def test_bad_pubkey_returns_usage_error(self):
        rc = self.run_cmd("--pubkey", "AAAA")
        self.assertEqual(2, rc)
        # 出错时不能改坏配置
        self.assertNotIn("app_pubkey", self.read().get("dmrid", {}))

    # ---------------- show / verify ----------------

    def test_verify_fails_when_unset(self):
        self.assertEqual(1, self.run_cmd("--verify"))

    def test_verify_passes_after_install(self):
        self.run_cmd()
        self.assertEqual(0, self.run_cmd("--verify"))

    def test_verify_checks_seed_pairing(self):
        self.run_cmd()                               # 写入官方公钥
        self.assertEqual(0, self.run_cmd("--verify", "--seed", OFFICIAL_SEED))
        # 换一个不配对的 seed → 必须失败
        other_seed = base64.urlsafe_b64encode(b"\x07" * 32).decode().rstrip("=")
        self.assertEqual(1, self.run_cmd("--verify", "--seed", other_seed))

    def test_show_reports_official(self):
        self.run_cmd()
        payload = None
        # --show --json 拿结构化结果
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_cmd("--show", "--json")
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["is_official"])
        self.assertEqual(OFFICIAL_PUB, payload["official"])

    # ---------------- 命令行兼容 ----------------

    def test_dash_leading_value_is_not_treated_as_option(self):
        """官方 seed 以 '-' 开头，必须能直接跟在 --seed 后面"""
        norm = self.mod.normalize_argv(["--seed", OFFICIAL_SEED, "--dry-run"])
        self.assertIn("--seed=" + OFFICIAL_SEED, norm)
        self.assertIn("--dry-run", norm)
        # 端到端也走一遍
        self.assertEqual(0, self.run_cmd("--seed", OFFICIAL_SEED, "--dry-run"))

    def test_json_output_is_valid(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.run_cmd("--json")
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["is_official"])
        self.assertTrue(payload["changed"])


class ApiServerDefaultTests(unittest.TestCase):
    """api_server 的内置默认值应当就是官方公钥（新装即用）"""

    def test_default_app_pubkey_is_official(self):
        import api_server
        self.assertEqual(OFFICIAL_PUB, api_server.DMRID_DEFAULT["app_pubkey"])
        # 未在 config 里配置时，get_app_pubkeys 应返回官方公钥
        saved = api_server.CONFIG.get("dmrid")
        try:
            api_server.CONFIG["dmrid"] = {}
            keys = api_server.get_app_pubkeys()
            self.assertEqual([OFFICIAL_PUB], keys)
        finally:
            if saved is None:
                api_server.CONFIG.pop("dmrid", None)
            else:
                api_server.CONFIG["dmrid"] = saved

    def test_config_default_json_has_official_pubkey(self):
        p = os.path.join(ROOT, "config.default.json")
        with open(p, encoding="utf-8-sig") as f:
            cfg = json.load(f)
        self.assertEqual(OFFICIAL_PUB, (cfg.get("dmrid") or {}).get("app_pubkey"))


class PackagingTests(unittest.TestCase):
    """命令必须随发行包发布，别人才能用"""

    def test_in_build_release_required_and_copied(self):
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("set_appkey.py", src)
        # 必需文件检查 + 打包复制 两处都要有
        self.assertGreaterEqual(src.count("set_appkey.py"), 2)

    def test_release_publishes_flat_assets(self):
        p = os.path.join(ROOT, ".github", "workflows", "release.yml")
        src = open(p, encoding="utf-8").read()
        self.assertIn("fus-set-appkey.py", src)
        self.assertIn("bas-set-appkey.py", src)

    def test_build_puts_set_appkey_into_upload_dir(self):
        """
        发版工作流会 `cp out/set_appkey.py up/...`（out = dist/release-upload）。
        build_release.sh 必须真的把它放进上传目录，否则那一步 cp 直接失败、发版挂掉。
        """
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("$UPLOAD/set_appkey.py", src)

    def test_installers_register_command(self):
        for name in ("install.sh", "install-bas.sh"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            self.assertIn("fus-set-appkey", src, "%s 未注册命令" % name)
            self.assertIn("set_appkey.py", src, "%s 未引用脚本" % name)

    def test_installers_also_install_to_usr_bin(self):
        """
        必须同时装到 /usr/bin：sudo 会把 PATH 重置为 secure_path，
        而它通常**不含** /usr/local/bin —— 只装 /usr/local/bin 会导致
        `sudo fus-set-appkey` 报 command not found（真实踩过的坑）。
        """
        for name in ("install.sh", "install-bas.sh"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            self.assertIn("/usr/bin", src,
                          "%s 未把命令装到 /usr/bin（sudo 下会找不到）" % name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
