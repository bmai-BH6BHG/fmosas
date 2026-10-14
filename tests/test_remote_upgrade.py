#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
远程升级机制（总系统下发指令 → 分系统 pull 时自行执行）。

用户需求："想个办法，可以通过调用某个端口，或者是在分系统中装什么东西
          可以控制它远程升级"

设计要点（本测试锁定）：
  * 走**现有 pull 通道**下发，不新开公网端口 ✓
  * 分系统只认来自 **master** 的指令（peer 同步来的忽略，防横向伪造）✓
  * 幂等：同一 id 只执行一次 ✓
  * 目标版本与本机相同 → 跳过 ✓
  * 包地址必须命中**允许清单**（https + 官方 releases 域名）✓
  * 执行是**延迟 + 脱离会话**的（否则会把自己等死）✓
"""
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)


class FUSSideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = io.open(os.path.join(REPO, "sync_engine.py"),
                          encoding="utf-8").read()

    def test_handles_ops_command_only_from_master(self):
        """只处理 master 来的指令（peer 来的丢弃，防横向伪造）。"""
        self.assertIn("if source == 'master' and data.get('ops_command'):", self.src)

    def test_has_delay_before_execute(self):
        """必须延迟执行：升级脚本会重启服务，立刻执行会掐断本次 pull。"""
        self.assertIn("OPS_DELAY_S", self.src)
        self.assertIn("time.sleep(self.OPS_DELAY_S)", self.src)

    def test_detached_execution(self):
        """必须脱离会话（start_new_session），否则重启会连带杀掉升级脚本。"""
        self.assertIn("start_new_session=True", self.src)

    def test_base_url_allowlist(self):
        """包地址白名单：只认官方 releases / https，防被指向恶意包。"""
        self.assertIn("OPS_ALLOWED_BASE", self.src)
        self.assertIn("https://github.com/bmai-BH6BHG/fmosas/releases/", self.src)

    def test_idempotent_by_command_id(self):
        """同一指令 id 只执行一次。"""
        self.assertIn("last_upgrade_cmd", self.src)
        # 幂等 key 按指令类型选：升级 / 重启各自幂等
        self.assertIn("_key = 'last_restart_cmd' if ctype == 'restart'", self.src)
        self.assertIn("if self._ops_state_get(_key) == cmd_id:", self.src)

    def test_skips_when_already_target_version(self):
        """已是目标版本就不再折腾。"""
        self.assertIn("已是目标版本", self.src)

    def test_target_filter(self):
        """支持 all 或指定 subsystem_id（只升某几台）。"""
        self.assertIn("target not in ('all', '*')", self.src)

    def test_supports_restart(self):
        """支持 restart 指令（同步线程卡住时远程救命用）。"""
        self.assertIn("ctype not in ('upgrade', 'restart')", self.src)
        self.assertIn("systemctl restart fmo-subsystem", self.src)

    def test_uses_official_upgrade_script(self):
        """复用官方 upgrade.sh（内建 sha256 校验 + 重启）。"""
        self.assertIn("upgrade.sh", self.src)
        self.assertIn("FMO_BASE_URL", self.src)


class MasterSideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = io.open(os.path.join(MASTER_DIR, "master_server.py"),
                          encoding="utf-8").read()

    def test_ops_table_and_api(self):
        for need in ("master_ops_command", "def set_ops_command",
                     "def get_ops_command", "def clear_ops_command",
                     "/api/ops/upgrade", "/api/ops/command", "/api/ops/clear"):
            self.assertIn(need, self.src, "总系统缺少: %s" % need)

    def test_pull_response_carries_command(self):
        self.assertIn('result["ops_command"] = _ops', self.src)

    def test_command_is_idempotent_id(self):
        self.assertIn("ops-%s' % time.strftime", self.src)


MASTER_DIR = os.environ.get("FMO_MASTER_DIR", r"D:\fmo-master-deploy")

if __name__ == "__main__":
    unittest.main(verbosity=2)
