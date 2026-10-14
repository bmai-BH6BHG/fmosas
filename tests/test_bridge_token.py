#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
桥接免证书互认（用户要求）：
  桥接不再依赖证书，只验证「它是 FUS 系统 + 在总服务器名册里有记录」就放行。

机制：
  1. 总系统生成 bridge_secret（settings 表），随 pull 下发 bridge_auth.secret
  2. 分系统把密钥存进配置，对端连接用
        username = SERVER（不变，ACL/审计不受影响）
        password = FMO-BRIDGE:<本机节点id>:<密钥>
  3. 对端 /auth 快速通道：
        * 密钥正确（只有 pull 过总系统的 FUS 才有 → 等价"注册在册"）
        * 对方节点 id 在本机缓存的**总系统名册**里（= 总服务器有记录）
        → 放行；缺密钥时回退证书认证（老节点不受影响）
"""
import io
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import api_server as A  # noqa: E402
import bridge as B  # noqa: E402
import sync_engine as S  # noqa: E402


class BridgeAuthUnitTests(unittest.TestCase):
    """_bridge_auth：核心判定（不依赖 self）。"""

    def setUp(self):
        self._saved = dict(A.CONFIG)
        self._saved_roster = A._bridge_roster_source
        self._saved_bridge = A._BRIDGE
        A.CONFIG['subsystem_id'] = 'sub-ME'
        A.CONFIG['bridge_secret'] = 'SECRET123'

    def tearDown(self):
        A.CONFIG.clear()
        A.CONFIG.update(self._saved)
        A._bridge_roster_source = self._saved_roster
        A._BRIDGE = self._saved_bridge

    def _call(self, username, password, clientid, roster=None):
        A._bridge_roster_source = lambda: (roster if roster is not None else [])
        return A.ApiHandler._bridge_auth(None, username, password, clientid)

    def test_not_bridge_client(self):
        """普通客户端：交给证书认证，不拦。"""
        is_b, allow, reason, attrs = self._call('BH6BHG', 'somedata', 'FMO-APP-1')
        self.assertFalse(is_b)

    def test_local_bridge_allowed(self):
        """本机自己的本地桥接连接（clientid 带 -LOCAL）应直接放行。

        真实形态（线上日志实测）：
            clientid=FMO-BRIDGE-sub-983bee49-LOCAL
            password=FMO-BRIDGE:sub-983bee49:<密钥>
        """
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-ME:SECRET123', 'FMO-BRIDGE-sub-ME-LOCAL')
        self.assertTrue(is_b)
        self.assertTrue(allow, reason)
        self.assertEqual(attrs.get('callsign'), 'SERVER')
        self.assertEqual(attrs.get('uid'), '200000')
        self.assertEqual(attrs.get('bridge_local'), '1')

    def test_local_without_local_suffix_allowed(self):
        """clientid 不带 -LOCAL，但令牌里就是本机 sid → 同样放行。"""
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-ME:SECRET123', 'FMO-BRIDGE-sub-ME')
        self.assertTrue(is_b)
        self.assertTrue(allow, reason)
        self.assertEqual(attrs.get('bridge_local'), '1')

    def test_peer_in_roster_allowed(self):
        """对端节点 id 在总服务器名册里 → 放行（这是核心用例）。"""
        roster = [{'subsystem_id': 'sub-PEER', 'name': '邻居台', 'host': 'x'}]
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-PEER:SECRET123',
            'FMO-BRIDGE-sub-PEER', roster=roster)
        self.assertTrue(is_b)
        self.assertTrue(allow, reason)
        self.assertEqual(attrs.get('bridge_member'), '1')
        self.assertEqual(attrs.get('bridge_sid'), 'sub-PEER')

    def test_peer_not_in_roster_denied(self):
        """★ 名册里没有它 → 拒绝（无法确认是已注册的 FUS）。"""
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-UNKNOWN:SECRET123',
            'FMO-BRIDGE-sub-UNKNOWN', roster=[])
        self.assertTrue(is_b)
        self.assertFalse(allow)
        self.assertIn('名册', reason)

    def test_wrong_secret_denied(self):
        """密钥不对 → 拒绝（防外部冒充）。"""
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-PEER:WRONG',
            'FMO-BRIDGE-sub-PEER', roster=[{'subsystem_id': 'sub-PEER'}])
        self.assertTrue(is_b)
        self.assertFalse(allow)
        self.assertIn('密钥', reason)

    def test_missing_secret_falls_back(self):
        """本机还没拿到密钥 → 回退证书认证（老节点不受影响）。"""
        A.CONFIG['bridge_secret'] = ''
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'FMO-BRIDGE:sub-PEER:X', 'FMO-BRIDGE-sub-PEER')
        self.assertTrue(is_b)
        self.assertFalse(allow)
        self.assertEqual(reason, 'BACKWARD_COMPAT')

    def test_cert_style_password_falls_back(self):
        """clientid 是桥接、但密码还是证书格式 → 回退证书认证。"""
        is_b, allow, reason, attrs = self._call(
            'SERVER', 'eyJjZXJ0UGFja2FnZSI6e319', 'FMO-BRIDGE-sub-PEER')
        self.assertTrue(is_b)
        self.assertEqual(reason, 'BACKWARD_COMPAT')


class BridgeCredentialsTests(unittest.TestCase):
    """bridge.credentials(use_token=True) 应产出桥接令牌。"""

    def test_token_password_format(self):
        cfg = {'subsystem_id': 'sub-AAA', 'bridge': {}, 'bridge_secret': 'SEC9'}
        svc = B.VoiceBridge.__new__(B.VoiceBridge)
        svc._cfg = {'bridge_secret': 'SEC9'}
        svc.config = cfg
        svc.node_id = 'sub-AAA'
        self.assertEqual(svc.bridge_token_password(), 'FMO-BRIDGE:sub-AAA:SEC9')
        u, p = svc.credentials('h', 1883, use_token=True)
        self.assertEqual(u, 'SERVER')
        self.assertEqual(p, 'FMO-BRIDGE:sub-AAA:SEC9')

    def test_no_secret_no_token(self):
        svc = B.VoiceBridge.__new__(B.VoiceBridge)
        svc._cfg = {}
        svc.config = {}
        svc.node_id = 'sub-AAA'
        self.assertEqual(svc.bridge_token_password(), '')

    def test_peer_link_uses_token(self):
        """对端链路优先走令牌（免证书）。"""
        src = io.open(os.path.join(REPO, 'bridge.py'), encoding='utf-8').read()
        self.assertIn("use_token=(_mode == 'token')", src)

    def test_graceful_fallback_to_cert(self):
        """★ 关键：对端未升级时令牌会被拒，必须自动回退证书，不能把能连的搞断。"""
        src = io.open(os.path.join(REPO, 'bridge.py'), encoding='utf-8').read()
        self.assertIn("modes = ['token', 'cert']", src)
        self.assertIn("回退证书重试", src)
        self.assertIn("'rc=5' in _m", src)
        self.assertIn("_cred_mode", src)

    def test_priority_decided_by_capability_probe(self):
        """
        ★ 核心回归：**不能无脑令牌优先**。
        对旧版本先发令牌会被它计一次认证失败，紧接着的证书重试被连带拒绝，
        把本来能连的台搞断（真实事故：渝东北FMO connected → error）。
        必须先探测对端能力：
            支持 → 令牌优先（免证书）
            不支持 → 证书优先（不发令牌，零回归）
        """
        src = io.open(os.path.join(REPO, 'bridge.py'), encoding='utf-8').read()
        self.assertIn('peer_supports_token', src)
        self.assertIn("if self.svc.peer_supports_token(", src)
        self.assertIn("modes = ['cert', 'token']", src)
        # 探测要有缓存，避免每次连接都打一次 HTTP
        self.assertIn('_TOKEN_CAP_TTL', src)
        self.assertIn('_token_cap', src)

    def test_bridge_info_endpoint_is_public(self):
        """能力声明端点必须在公网白名单里（否则对端探不到）。"""
        src = io.open(os.path.join(REPO, 'api_server.py'), encoding='utf-8').read()
        self.assertIn("'/api/bridge/info'", src)
        self.assertIn("'bridge_token': bool(_bk_sec)", src)

    def test_roster_candidate_carries_api_url(self):
        """名册候选要带 api_url，探测才有目标。"""
        src = io.open(os.path.join(REPO, 'bridge.py'), encoding='utf-8').read()
        self.assertIn('"api_url": str(c.get("api_url") or "").strip(),', src)

    def test_probe_failure_means_no_token(self):
        """探测不通（旧版本/超时）→ 判定不支持 → 不发令牌。"""
        svc = B.VoiceBridge.__new__(B.VoiceBridge)
        svc._token_cap = {}
        svc.log = lambda *a, **k: None
        # 指向一个必然连不上的地址（端口 1，本地无服务）
        self.assertFalse(svc.peer_supports_token('http://127.0.0.1:1', 'h'))
        # 结果被缓存（第二次直接命中缓存，不再发起请求）
        self.assertFalse(svc.peer_supports_token('http://127.0.0.1:1', 'h'))

    def test_local_link_keeps_cert(self):
        """本机 broker 的本地连接保持证书方案（缩小改动面）。"""
        src = io.open(os.path.join(REPO, 'bridge.py'), encoding='utf-8').read()
        self.assertIn('creds = self.credentials(self.broker_host, self.broker_port)',
                      src)


class SyncSecretTests(unittest.TestCase):
    """分系统应保存总系统下发的桥接密钥。"""

    def test_sync_engine_saves_bridge_auth(self):
        src = io.open(os.path.join(REPO, 'sync_engine.py'), encoding='utf-8').read()
        self.assertIn("data.get('bridge_auth')", src)
        self.assertIn("self.config['bridge_secret']", src)
        self.assertIn('save_config_fn', src)

    def test_api_injects_save_config_fn(self):
        src = io.open(os.path.join(REPO, 'api_server.py'), encoding='utf-8').read()
        self.assertIn('engine.save_config_fn = _save_bridge_secret', src)


class MasterSecretTests(unittest.TestCase):
    """总系统侧：密钥生成 + 随 pull 下发。"""

    @classmethod
    def setUpClass(cls):
        master_dir = os.environ.get('FMO_MASTER_DIR', r'D:\fmo-master-deploy')
        cls.src = io.open(os.path.join(master_dir, 'master_server.py'),
                          encoding='utf-8').read()

    def test_master_has_secret_helpers(self):
        for need in ('def get_bridge_secret', 'def ensure_settings_table',
                     'def get_setting', 'def set_setting'):
            self.assertIn(need, self.src, '总系统缺少: %s' % need)

    def test_pull_carries_bridge_auth(self):
        self.assertIn('result["bridge_auth"] = {', self.src)
        self.assertIn('"secret": _sec', self.src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
