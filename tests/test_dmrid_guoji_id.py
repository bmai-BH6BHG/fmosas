#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证书下发口径：**只验证国服 ID（dmrId），不再验证国际 ID（guojiId）**。

字段定义（用户确认，2026-10-14）：
    dmrId   （860 开头）= **国服 ID**  → 唯一发证门槛 ✓
    guojiId （460 开头）= 国际 ID      → 不参与判定 ✗

用户原话：
    "证书下发那一块，只需要验证国服 id 就行了，不再验证国际 id，有国服 id 就能下发"
    "dmrId 才是国服 ID"

历史坑（必须防止回退）：
  * 曾把 guojiId 当门槛 → 等于拿"国际 ID"卡人，账号没有国际 ID 就发不了证 ✗
  * 国服 callsign-lookup 只回国际 ID，**本就拿不到 dmrId**，
    因此简化模式下不能因"没有 dmrId"而拒绝 —— 查询成功即视为账号存在 ✓
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


class SourcePolicyTests(unittest.TestCase):
    """源码级锁定正确口径（防再次改反）。"""

    @classmethod
    def setUpClass(cls):
        cls.src = io.open(os.path.join(REPO, "api_server.py"),
                          encoding="utf-8").read()

    def test_lookup_does_not_gate_on_guoji_id(self):
        """★ dmrid_lookup 绝不能因为 guojiId（国际 ID）为空就拒绝。"""
        self.assertNotIn(
            "payload.get('code') != 200 or guoji_id is None", self.src,
            "又拿 guojiId（国际 ID）当门槛了")

    def test_lookup_returns_dmr_id(self):
        """返回体要带出 dmrId（国服 ID），不能恒为 None。"""
        self.assertIn("'guojiId': guoji_id, 'dmrId': dmr_id_lookup", self.src)

    def test_main_gate_uses_dmr_id(self):
        """主路径门槛只看 dmrId（国服 ID）。"""
        self.assertIn("have_id = bool(dmr_id)", self.src,
                      "门槛应基于 dmr_id（国服 ID）")
        self.assertIn("dmrId", self.src)

    def test_no_guoji_only_gate(self):
        """不能存在"必须有 guojiId 才发证"的写法。"""
        self.assertNotIn("if not guoji_id:", self.src,
                         "又变成用 guojiId（国际 ID）当门槛了")
        self.assertNotIn("该账号没有国服 ID，无法签发证书", self.src,
                         "旧文案对应的是把 guojiId 当国服 ID 的错误实现")

    def test_dmr_id_documented_as_guoji_id(self):
        """注释里要写清楚 dmrId = 国服 ID，避免下次再搞反。"""
        self.assertIn("dmrId（860 开头）= 国服 ID", self.src)


class LookupBehaviorTests(unittest.TestCase):
    """真实调用 dmrid_lookup，验证"没有国际 ID 也能通过"。"""

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

    def _lookup(self, payload):
        api_server.urllib.request.urlopen = lambda req, timeout=None: _FakeResp(payload)
        return api_server.dmrid_lookup("BH6BHG")

    def test_guoji_id_null_still_passes(self):
        """★ 核心：只回国际 ID（guojiId 有值、dmrId 无）时也必须通过。

        国服 callsign-lookup 的真实返回就是这样 —— 若这里被拒，
        等于又拿国际 ID 当门槛了。
        """
        ok, res = self._lookup({
            "code": 200,
            "data": {"callsign": "BH6BHG", "guojiId": 4603047,
                     "guojiIds": [4603047], "requiresDocuments": False},
        })
        self.assertTrue(ok, res)
        self.assertEqual(res["callsign"], "BH6BHG")

    def test_guoji_id_none_still_passes_when_lookup_ok(self):
        """国际 ID 未识别（guojiId=null）但查询成功 → 仍放行，不卡人。"""
        ok, res = self._lookup({
            "code": 200,
            "data": {"callsign": "XX9ZZZ", "guojiId": None,
                     "guojiIds": [], "requiresDocuments": True},
        })
        self.assertTrue(ok, res)

    def test_dmr_id_carried_through(self):
        """返回体要能带出 dmrId（国服 ID）供主路径判定。"""
        ok, res = self._lookup({
            "code": 200,
            "data": {"callsign": "BH6BHG", "dmrId": 8601234},
        })
        self.assertTrue(ok, res)
        self.assertEqual(res["dmrId"], 8601234)

    def test_http_error_rejected(self):
        ok, res = self._lookup({"code": 404, "message": "not found"})
        self.assertFalse(ok)
        self.assertEqual(res["code"], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
