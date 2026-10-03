#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APP 密钥绑定（MQTT 连接级签名）测试
====================================
锁定服务端校验行为：
  * FMO-APP-mqtt 连接绑定式签名 → ok/bound（最强）
  * 旧式 FMO-APP-auth 签名      → ok/legacy（能证明是真 APP，但未绑定连接）
  * 签名被重放到别的 clientid    → invalid（这正是绑定 clientid 的意义）
  * 篡改签名 / 过期时间戳        → invalid
  * 没带签名                    → none（观察模式放行、强制模式拒绝）
  * 黄金测试向量与规范文档一致   → 防止 APP 端与服务端拼接口径漂移
"""

import json
import time
import unittest

from tests import ROOT  # noqa: F401
import api_server as api
import cert_gen as cg

# 与 APP-APPKEY-BINDING.md 第 4 节完全一致的黄金向量
GOLDEN = {
    "seed": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "pub": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    "user_pub": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo",
    "callsign": "bh6bhg",
    "clientid": "FMO-BH6BHG-1075-B373",
    "ts": 1791050000,
    "sig": "H4AHq0IC3R28czvOss0YGZHQOE9B_MwIroEXN8GYBBGzKy73VM1t9XbSFO3awVtZHDoxHE1Hk_tzqHXDmfNwDQ",
}


def pw_json(sig, ts, user_pub, extra=None):
    body = {"certPackage": {"userCert": {"subject": {"publicKey": user_pub}}},
            "app_timestamp": ts}
    if sig:
        body["app_signature"] = sig
    if extra:
        body.update(extra)
    return cg.b64url_encode(json.dumps(body).encode("utf-8"))


class GoldenVectorTests(unittest.TestCase):
    def test_build_app_signature_mqtt_matches_golden(self):
        sig = cg.build_app_signature_mqtt(GOLDEN["seed"], GOLDEN["ts"],
                                          GOLDEN["callsign"], GOLDEN["user_pub"],
                                          GOLDEN["clientid"])
        self.assertEqual(GOLDEN["sig"], sig,
                         "黄金向量不一致 —— 拼接格式改动会破坏 APP 兼容性！")

    def test_golden_pubkey_matches_seed(self):
        self.assertEqual(GOLDEN["pub"],
                         cg.b64url_encode(cg.pubkey_from_seed(cg.b64url_decode(GOLDEN["seed"]))))

    def test_message_layout(self):
        """消息必须是 FMO-APP-mqtt:{ts}:{CS}:{pub}:{clientid}（4 个冒号）"""
        msg = "%s:%d:%s:%s:%s" % (cg.APP_MQTT_AUTH_PREFIX, GOLDEN["ts"],
                                  GOLDEN["callsign"].upper(), GOLDEN["user_pub"],
                                  GOLDEN["clientid"])
        self.assertEqual(4, msg.count(":"))
        self.assertTrue(msg.startswith("FMO-APP-mqtt:"))
        self.assertIn(":BH6BHG:", msg, "呼号必须转大写")


class VerifyAppSignatureTests(unittest.TestCase):
    """直接测服务端校验函数（不依赖真实 EMQX）"""

    def setUp(self):
        self._saved = dict(api.CONFIG.get("dmrid") or {})
        api.CONFIG.setdefault("dmrid", {})
        api.CONFIG["dmrid"]["app_pubkey"] = GOLDEN["pub"]
        api.CONFIG["dmrid"]["app_timestamp_window"] = 300
        api.CONFIG["dmrid"]["dev_mode"] = False

    def tearDown(self):
        api.CONFIG["dmrid"].clear()
        api.CONFIG["dmrid"].update(self._saved)

    def _sign(self, ts, callsign=None, pub=None, cid=None):
        return cg.build_app_signature_mqtt(
            GOLDEN["seed"], ts, callsign or GOLDEN["callsign"],
            pub or GOLDEN["user_pub"], cid or GOLDEN["clientid"])

    def test_valid_bound_signature(self):
        ts = int(time.time())
        r = api.verify_app_mqtt_signature(pw_json(self._sign(ts), ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertTrue(r["ok"], r)
        self.assertEqual("bound", r["mode"])

    def test_replay_to_other_connection_rejected(self):
        """★ 把签名重放到另一条连接（clientid 不同）必须失败"""
        ts = int(time.time())
        r = api.verify_app_mqtt_signature(pw_json(self._sign(ts), ts, GOLDEN["user_pub"]),
                                          "FMO-BH6BHG-1075-EVIL", GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertEqual("invalid", r["mode"])

    def test_tampered_signature_rejected(self):
        ts = int(time.time())
        bad = self._sign(ts)[:-4] + "AAAA"
        r = api.verify_app_mqtt_signature(pw_json(bad, ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertEqual("invalid", r["mode"])

    def test_expired_timestamp_rejected(self):
        ts = int(time.time()) - 3600
        r = api.verify_app_mqtt_signature(
            pw_json(self._sign(ts), ts, GOLDEN["user_pub"]),
            GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertIn("时间窗", r["reason"])

    def test_no_signature_is_none(self):
        ts = int(time.time())
        r = api.verify_app_mqtt_signature(pw_json(None, ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertFalse(r["present"])
        self.assertEqual("none", r["mode"])

    def test_legacy_http_style_signature(self):
        """APP 未改造前可直接复用 HTTP 式签名（弱一档）"""
        ts = int(time.time())
        msg = "%s:%d:%s:%s" % (cg.APP_AUTH_PREFIX, ts, GOLDEN["callsign"].upper(),
                               GOLDEN["user_pub"])
        sig = cg.b64url_encode(cg.ed25519_sign(cg.b64url_decode(GOLDEN["seed"]),
                                               msg.encode("utf-8")))
        r = api.verify_app_mqtt_signature(pw_json(sig, ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertTrue(r["ok"], r)
        self.assertEqual("legacy", r["mode"])

    def test_camel_case_aliases_accepted(self):
        ts = int(time.time())
        body = {"certPackage": {"userCert": {"subject": {"publicKey": GOLDEN["user_pub"]}}},
                "appTimestamp": ts, "appSignature": self._sign(ts)}
        r = api.verify_app_mqtt_signature(cg.b64url_encode(json.dumps(body).encode()),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertTrue(r["ok"], r)

    def test_no_pubkey_configured(self):
        api.CONFIG["dmrid"]["app_pubkey"] = ""
        ts = int(time.time())
        r = api.verify_app_mqtt_signature(pw_json(self._sign(ts), ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertIn("app_pubkey", r["reason"])

    def test_pubkey_list_supported(self):
        api.CONFIG["dmrid"]["app_pubkey"] = ["AAAA", GOLDEN["pub"]]
        ts = int(time.time())
        r = api.verify_app_mqtt_signature(pw_json(self._sign(ts), ts, GOLDEN["user_pub"]),
                                          GOLDEN["clientid"], GOLDEN["callsign"])
        self.assertTrue(r["ok"], "公钥列表里命中一个即应通过")

    def test_bad_password_encoding(self):
        r = api.verify_app_mqtt_signature("!!!not-base64!!!", GOLDEN["clientid"],
                                          GOLDEN["callsign"])
        self.assertFalse(r["ok"])
        self.assertEqual("none", r["mode"])


class PolicyIntegrationTests(unittest.TestCase):
    """BAS 的「只许本 APP」如何消费 app_verified"""

    def _client(self, **attrs):
        from bas_emqx import EmqxClient
        a = {"callsign": "BH6BHG", "uid": "1075"}
        a.update(attrs)
        return EmqxClient._normalize_client({
            "clientid": "FMO-BH6BHG-1075-B373", "username": "BH6BHG", "client_attrs": a})

    def test_app_verified_wins(self):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy()
        ok, _, why = p.client_is_app(self._client(app_verified="1", app_sig="bound"))
        self.assertTrue(ok)
        self.assertIn("APP 密钥签名已验证", why)

    def test_require_signature_rejects_unsigned(self):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy(policy={"app_require_signature": True})
        ok, _, why = p.client_is_app(self._client())     # 无 app_verified
        self.assertFalse(ok)
        self.assertIn("未通过 APP 密钥签名", why)

    def test_require_signature_accepts_signed(self):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy(policy={"app_require_signature": True})
        ok, _, _ = p.client_is_app(self._client(app_verified="1", app_sig="bound"))
        self.assertTrue(ok)

    def test_fallback_when_not_required(self):
        from bas_identity import IdentityPolicy
        p = IdentityPolicy()                              # 默认不强制
        ok, _, _ = p.client_is_app(self._client())         # 仅有证书身份
        self.assertTrue(ok, "APP 未改造时应回退到证书身份判定")


class ExemptionTests(unittest.TestCase):
    """内部服务/面板在强制模式下必须豁免，否则自家监控会被打死"""

    def setUp(self):
        self._saved = dict(api.SAS_RUNTIME_CONFIG)
        api.SAS_RUNTIME_CONFIG['require_client_signature'] = True

    def tearDown(self):
        api.SAS_RUNTIME_CONFIG.clear()
        api.SAS_RUNTIME_CONFIG.update(self._saved)

    def test_monitor_callsign_exempt(self):
        ok, why = api.app_signature_exempt("SERVER", "FMO-MONITOR-sub-x")
        self.assertTrue(ok)
        self.assertIn("内部服务呼号", why)

    def test_monitor_prefix_exempt(self):
        ok, _ = api.app_signature_exempt("BH6BHG", "FMO-MONITOR-sub-x")
        self.assertTrue(ok)

    def test_web_panel_prefix_exempt(self):
        ok, _ = api.app_signature_exempt("BH6BHG", "fmo-web-ptt-abc")
        self.assertTrue(ok)

    def test_normal_app_client_not_exempt(self):
        ok, why = api.app_signature_exempt("BH6BHG", "FMO-BH6BHG-1075-B373")
        self.assertFalse(ok)
        self.assertEqual("", why)

    def test_case_insensitive_callsign(self):
        ok, _ = api.app_signature_exempt("server", "whatever")
        self.assertTrue(ok)

    def test_custom_exempt_list_respected(self):
        api.SAS_RUNTIME_CONFIG['client_signature_exempt_callsigns'] = ['ADMIN']
        ok, _ = api.app_signature_exempt("ADMIN", "x")
        self.assertTrue(ok)
        ok2, _ = api.app_signature_exempt("SERVER", "x")
        self.assertFalse(ok2, "自定义列表应覆盖默认值")

    def test_firmware_certonly_callsign_exempt(self):
        """★ FMO 固件用户：没有 APP 私钥，强制模式下必须放行"""
        api.SAS_RUNTIME_CONFIG['client_signature_certonly_callsigns'] = ['BH6FWE']
        ok, why = api.app_signature_exempt('BH6FWE', 'FMO-BH6FWE-405-1733')
        self.assertTrue(ok)
        self.assertIn("固件", why)
        ok2, how2 = api.app_signature_exempt('BH9XXX', 'FMO-BH9XXX-9-AAAA')
        self.assertFalse(ok2, "未列入的呼号不应豁免")

    def test_firmware_list_case_insensitive(self):
        api.SAS_RUNTIME_CONFIG['client_signature_certonly_callsigns'] = ['bh6fwe']
        ok, _ = api.app_signature_exempt('BH6FWE', 'x')
        self.assertTrue(ok)
        ok2, _ = api.app_signature_exempt('bh6fwe', 'x')
        self.assertTrue(ok2)

    def test_certonly_key_in_defaults(self):
        self.assertIn('client_signature_certonly_callsigns', api.DEFAULT_SAS_RUNTIME_CONFIG)

    def test_defaults_present_in_config_template(self):
        for k in ('client_signature_exempt_callsigns', 'client_signature_exempt_prefixes'):
            self.assertIn(k, api.DEFAULT_SAS_RUNTIME_CONFIG)


if __name__ == "__main__":
    unittest.main(verbosity=2)
