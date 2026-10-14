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

    def test_detach_from_service_cgroup(self):
        """
        ★ 关键回归：升级/重启必须脱离本服务 cgroup。

        真实事故：升级脚本执行到"停止服务"时，systemd（KillMode=control-group）
        把同 cgroup 的脚本一起杀掉 → 服务 inactive、版本没变、节点失联。
        群晖没有 systemd-run，所以必须写**临时 systemd unit** 再 start。
        """
        self.assertIn('def _launch_detached', self.src)
        self.assertIn("systemd-run", self.src)          # 有则优先
        self.assertIn("'/etc/systemd/system/%s.service'", self.src)  # 群晖可用方案
        self.assertIn("'start', '--no-block'", self.src)  # 立即返回，不等它跑完
        self.assertIn("Type=oneshot", self.src)
        # 清理必须用 ExecStopPost（成功/失败都执行）；ExecStartPost 失败时不跑，
        # 会残留 failed unit（真实踩过）
        self.assertIn("ExecStopPost=", self.src)
        self.assertNotIn("ExecStartPost=", self.src)
        # systemd 单元环境极简：必须显式给 HOME/PATH，否则 upgrade.sh 的
        # `set -u` 会在 `HOME: unbound variable` 处中止（真实事故）
        self.assertIn("'HOME': '/root'", self.src)
        # 升级与重启都走这条通道
        self.assertIn("_launch_detached(", self.src)
        self.assertIn("unit_prefix='fus-upgrade'", self.src)
        self.assertIn("unit_prefix='fus-restart'", self.src)

    def test_no_more_bare_popen_for_ops(self):
        """不允许再出现"直接 Popen 跑升级脚本"的写法（会在停服务时被杀）。"""
        self.assertNotIn("_runner = _detached_runner", self.src)


class BridgeInfoEndpointTests(unittest.TestCase):
    """② /api/bridge/info 必须真的可达（否则免证书探测永远失败）。"""

    @classmethod
    def setUpClass(cls):
        cls.api = io.open(os.path.join(REPO, 'api_server.py'),
                          encoding='utf-8').read()

    def test_handled_inside_bridge_router(self):
        """
        必须在 _handle_bridge_routes 开头处理，且**在 _BRIDGE 判空之前** ——
        否则桥接模块异常时探测直接 503，或落到"未知的桥接接口"404。
        """
        i = self.api.find('def _handle_bridge_routes')
        self.assertGreater(i, 0)
        block = self.api[i:i + 2500]
        self.assertIn("path == '/api/bridge/info'", block)
        # info 出现在 svc = _BRIDGE 之前
        self.assertLess(block.find("path == '/api/bridge/info'"),
                        block.find('svc = _BRIDGE'))

    def test_returns_bridge_token_flag(self):
        i = self.api.find("path == '/api/bridge/info'")
        block = self.api[i:i + 900]
        self.assertIn("'bridge_token': bool(_sec)", block)

    def test_public_whitelist_keeps_readonly_only(self):
        """公网只放行只读能力声明；且旧插错位置的那份 handler 已删除。"""
        self.assertEqual(self.api.count("path == '/api/bridge/info'"), 1,
                         'info 处理应只有一处（重复会导致路由不可达）')


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
