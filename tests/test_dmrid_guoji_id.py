#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证书下发口径：**只验证国服 ID**（用国服登录接口），国际 ID 不再作为门槛。

背景（真实现场）：
  国服 GET /api/auth/callsign-lookup 只在「国际 ID 被识别」时才返回 guojiId；
  未识别时返回 {"guojiId": null, "requiresDocuments": true}。
  旧代码判定 `guojiId is None → 404`，等于**把国际 ID 当准入条件**。
  用户要求：只要账号有国服 ID 就下发证书。

当前口径（本测试锁定）：
  1. dmrid.verify_password 默认 True → 走国服登录接口（呼号+密码）
  2. 登录成功即取 guojiId（兼容 guojiIds 数组）
  3. 黑名单（blacklisted / isDisabled）仍拒绝；
     **approved 以外的状态一律放行**（不再要求审核通过）
  4. 绑定流程里唯一的身份门槛是「有 guojiId」——没有就 403
  5. 源码里不再存在 approved 审核门
"""
import io
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import api_server  # noqa: E402


class _FakeResp:
    """假 urllib 响应：dmrid_login 只用 getcode()/read()/上下文管理。"""

    def __init__(self, payload, code=200):
        self._body = json.dumps(payload).encode("utf-8")
        self._code = code

    def getcode(self):
        return self._code

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen_factory(payload):
    """返回一个假的 urlopen（dmrid_login 只用 getcode()/read()）。"""

    def _fake(req, timeout=None):
        return _FakeResp(payload)

    return _fake


class DefaultsTests(unittest.TestCase):
    def test_verify_password_default_true(self):
        """默认必须走登录校验（= 只认国服 ID），否则又回到"验证国际 ID"的老路。"""
        self.assertIs(api_server.DMRID_DEFAULT["verify_password"], True)

    def test_config_default_file_true(self):
        p = os.path.join(REPO, "config.default.json")
        cfg = json.loads(io.open(p, encoding="utf-8").read())
        self.assertIs(cfg["dmrid"]["verify_password"], True)

    def test_no_approved_gate_in_source(self):
        """绑定流程不能再有"非 approved 一律拒绝"这道门。"""
        src = io.open(os.path.join(REPO, "api_server.py"), encoding="utf-8").read()
        self.assertNotIn("未通过审核，无法接入", src,
                         "approved 审核门应已移除（口径：有国服 ID 就发证）")
        self.assertIn("该账号没有国服 ID，无法签发证书", src,
                      "缺少「必须有国服 ID」这道唯一门槛")


class LoginResultTests(unittest.TestCase):
    """dmrid_login 的结果处理：黑名单拦、其余放行、guojiIds 数组兼容。"""

    def setUp(self):
        self._saved_cfg = dict(api_server.CONFIG.get("dmrid") or {})
        api_server.CONFIG["dmrid"] = {
            "enabled": True, "dev_mode": False,
            "base_url": "https://example.invalid", "timeout": 5,
        }
        self._saved_open = api_server.urllib.request.urlopen

    def tearDown(self):
        api_server.urllib.request.urlopen = self._saved_open
        if self._saved_cfg:
            api_server.CONFIG["dmrid"] = self._saved_cfg
        else:
            api_server.CONFIG.pop("dmrid", None)

    def _login(self, user):
        api_server.urllib.request.urlopen = lambda req, timeout=None: _FakeResp(
            {"code": 200, "data": {"user": user}})
        return api_server.dmrid_login("BH6BHG", "pw")

    def test_guoji_ids_array_fills_guoji_id(self):
        """国服只给 guojiIds 数组时，要能取出国服 ID（否则绑不了）。"""
        ok, res = self._login({"callsign": "BH6BHG", "guojiIds": [4603047, 4619333]})
        self.assertTrue(ok, res)
        self.assertEqual(res["user"]["guojiId"], 4603047)

    def test_pending_status_allowed(self):
        """pending/unknown 等状态不再拦（只要有国服 ID）。"""
        ok, res = self._login({"callsign": "BH6BHG", "guojiId": 4603047,
                               "status": "pending"})
        self.assertTrue(ok, res)
        self.assertEqual(res["user"]["guojiId"], 4603047)

    def test_blacklisted_still_rejected(self):
        """黑名单必须继续拦（这是保留的唯一状态门槛）。"""
        ok, res = self._login({"callsign": "BH6BHG", "guojiId": 4603047,
                               "status": "blacklisted"})
        self.assertFalse(ok)
        self.assertEqual(res["code"], 403)

    def test_isDisabled_still_rejected(self):
        ok, res = self._login({"callsign": "BH6BHG", "guojiId": 4603047,
                               "isDisabled": True})
        self.assertFalse(ok)
        self.assertEqual(res["code"], 403)


class BindFlowPolicyTests(unittest.TestCase):
    """源码级锁定绑定流程的判定顺序与口径。"""

    @classmethod
    def setUpClass(cls):
        cls.src = io.open(os.path.join(REPO, "api_server.py"),
                          encoding="utf-8").read()

    def test_login_path_requires_password_with_clear_error(self):
        self.assertIn("需要国服账号密码用于校验", self.src,
                      "缺密码时应给出明确报错（说明为什么需要密码）")
        self.assertIn("if verify_password and not password:", self.src)

    def test_guoji_id_is_the_only_identity_gate(self):
        seg = self.src[self.src.index("# ★ 唯一的身份门槛"):]
        seg = seg[:seg.index("return") + 200] if "return" in seg else seg
        self.assertIn("if not guoji_id:", seg)

    def test_lookup_error_no_longer_blames_international_id(self):
        """callsign-lookup 的报错不该再让人以为是"国际 ID"的问题。"""
        self.assertNotIn("该呼号未识别到国服 ID（国际 ID）", self.src)
        self.assertIn("该呼号在国服没有可用的国服 ID", self.src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
