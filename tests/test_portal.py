#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FUS 门户与页面命名测试
======================
背景：管理口（35929）从「一个后台四个标签」改为「门户 + 两个子系统」：
  /admin      → admin/portal.html   FUS 门户（SAS / FAS 两个入口）
  /admin/sas  → admin/index.html    SAS 统一认证服务
  /admin/fus  → admin/bas.html      FAS 统一审计服务（旧 /admin/bas 保留兼容）

覆盖：
  * 门户页存在，且两个入口指向正确地址
  * 三个页面各自身份正确（SAS / FAS 不串名，旧名 BAS 不再出现在用户可见文案里）
  * bas.js 把内联 onclick 用到的命名空间真的导出了（曾因 BAS→FUS 改名漏掉 window.FUS，
    导致「拉黑 / 踢下线 / 解封 / 放行」按钮点击即 ReferenceError）
  * 路由与安装脚本都知道 portal.html
"""

import os
import re
import unittest

from tests import ROOT

ADMIN = os.path.join(ROOT, "admin")


def _read(*parts):
    with open(os.path.join(ADMIN, *parts), "r", encoding="utf-8") as f:
        return f.read()


def _read_root(name):
    with open(os.path.join(ROOT, name), "r", encoding="utf-8") as f:
        return f.read()


class PortalPageTests(unittest.TestCase):
    def test_portal_exists_and_has_two_entries(self):
        html = _read("portal.html")
        self.assertIn("SAS 系统", html)
        self.assertIn("FAS 系统", html)
        self.assertIn('href="/admin/sas"', html)
        self.assertIn('href="/admin/fus"', html)

    def test_portal_carries_fus_brand_and_credit(self):
        html = _read("portal.html")
        self.assertIn("FUS", html)
        self.assertIn("FMO 统一安全服务端", html)
        self.assertIn("FMO Unified Security Server", html)
        self.assertIn("BG5ESN", html)

    def test_portal_is_self_contained(self):
        """门户页必须零外部依赖：管理口可能没有外网，绝不能引 CDN。"""
        html = _read("portal.html")
        self.assertNotIn("http://", html.replace("http://www.w3.org", ""))
        self.assertNotIn("https://", html)
        self.assertNotIn("<link", html)


class PageIdentityTests(unittest.TestCase):
    def test_sas_page_branded_sas(self):
        html = _read("index.html")
        self.assertIn("<title>SAS · FMO 统一认证服务</title>", html)
        self.assertIn("SAS 统一认证服务", html)
        self.assertIn("FMO Unified Authentication Server", html)

    def test_sas_page_links_back_to_portal_and_drops_bas_tab(self):
        html = _read("index.html")
        self.assertIn('href="/admin"', html)
        self.assertIn("返回门户", html)
        # 「审计（BAS）」这个旧外链标签必须已经去掉
        self.assertNotIn("审计（BAS）", html)
        self.assertNotIn("/admin/bas", html)

    def test_sas_page_has_footer_credit(self):
        html = _read("index.html")
        self.assertIn('class="foot"', html)
        self.assertIn("Original design by BG5ESN", html)

    def test_fas_page_branded_fas(self):
        html = _read("bas.html")
        self.assertIn("<title>FAS · FMO 统一审计服务</title>", html)
        self.assertIn("FAS", html)
        self.assertIn("FMO Unified Audit Server", html)
        self.assertIn("FMO 统一审计服务", html)
        # 不再自称 FUS（FUS 是总品牌，不是子系统名）
        self.assertNotIn("FUS — FMO Unified Security Server", html)
        self.assertNotIn('<div class="brand">FUS', html)

    def test_fas_page_returns_to_portal(self):
        html = _read("bas.html")
        self.assertIn("返回门户", html)
        self.assertNotIn("返回 SAS 管理", html)


class BasJsNamespaceTests(unittest.TestCase):
    """内联 onclick 里的 FUS.xxx 必须有对应的导出，否则按钮全是坏的。"""

    def test_inline_handlers_have_matching_export(self):
        js = _read("bas.js")
        used = set(re.findall(r"onclick=\\?\"([A-Za-z_$][\w$]*)\.", js))
        # onclick 在 JS 字符串里以 \" 转义，正则两种写法都兜住
        used |= set(re.findall(r"onclick=\\\\?\"([A-Za-z_$][\w$]*)\\\\?\.", js))
        self.assertTrue(used, "没解析到任何内联 onclick，正则需要更新")
        exported = set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=", js))
        missing = sorted(n for n in used if n not in exported)
        self.assertEqual([], missing,
                         "内联 onclick 用了未导出的命名空间: %s（导出的是 %s）"
                         % (missing, sorted(exported)))

    def test_bas_alias_kept_for_compat(self):
        js = _read("bas.js")
        self.assertIn("window.FUS", js)
        self.assertIn("window.BAS = window.FUS", js)


class RoutingAndPackagingTests(unittest.TestCase):
    def test_api_server_routes_portal_and_sas(self):
        src = _read_root("api_server.py")
        self.assertIn("_serve_portal_page", src)
        self.assertIn("'/admin/sas'", src)
        self.assertIn("portal.html", src)
        # 旧书签 /admin/index.html 必须 302 到 /admin/sas
        self.assertIn("'/admin/index.html'", src)
        self.assertIn("/admin/sas", src)

    def test_public_port_still_blocks_admin_pages(self):
        """门户与两个子系统都只在管理口；公网口白名单里绝不能出现。"""
        src = _read_root("api_server.py")
        block = src.split("PUBLIC_GET_PATHS", 1)[1].split(")", 1)[0]
        self.assertNotIn("/admin", block)

    def test_root_ca_downloadable_from_public_port(self):
        """根证书是公开信息，必须能在公网口拉走，别人才能接种信任。
        但 /api/ca/init、/api/ca/info 仍只在管理口（会泄露私钥状态/内部信息）。"""
        src = _read_root("api_server.py")
        block = src.split("PUBLIC_GET_PATHS", 1)[1].split(")", 1)[0]
        self.assertIn("'/api/ca/root.json'", block)
        for forbidden in ("'/api/ca/init'", "'/api/ca/renew'", "'/api/ca/info'"):
            self.assertNotIn(forbidden, block)

    def test_root_json_route_exists_and_never_leaks_private_key(self):
        src = _read_root("api_server.py")
        self.assertIn("_handle_sas_ca_root_json", src)
        self.assertIn("'/api/ca/root.json'", src)
        self.assertNotIn("ca_private", src.split("_handle_sas_ca_root_json")[1]
                         .split("def ", 1)[0],
                         "根证书下载端点绝不能碰私钥文件")


class RootCertPayloadTests(unittest.TestCase):
    """根证书下载响应必须是可 JSON 序列化的，且带完整自签证书。"""

    class _FakeCaMgr(object):
        def __init__(self):
            self.root_cert = {
                "sn": 1, "type": "rootCA",
                "issuer": {"name": "MYCA", "email": ""},
                "subject": {"name": "MYCA", "publicKey": "vht_DzLunLa2Sdj5uJ3IeJ7I6w"},
                "extensions": {"isCA": True, "pathLen": 1, "crl": "", "license": "",
                               "keyId": "1"},
                "iat": 1791090441, "exp": 2106450441,
                "signatureAlgorithm": "Ed25519",
                "signature": "hb0YePvSnM6rqXouko_MtrMiJ64Rv_bKgBJ6YoWPHwU",
            }
            self.root_fingerprint = "leWfFe5uVoojCkeKSafliV7X16cdn2Xf1ej0JBeIddw"

    def _payload(self):
        import api_server
        return api_server.build_ca_root_payload(
            self._FakeCaMgr(), {"subsystem_id": "sub-x", "domain": "d.example"})

    def test_payload_is_json_serializable(self):
        """回归：曾经传 bytes 指纹进去，导致 HTTP 500 bytes is not JSON serializable。"""
        import json
        p = self._payload()
        json.dumps(p)  # 不抛异常即通过
        self.assertTrue(p["ok"])

    def test_payload_carries_full_self_signed_cert(self):
        p = self._payload()
        self.assertEqual("rootCA", p["cert"]["type"])
        self.assertTrue(p["cert"]["signature"], "必须带 signature，否则对方无法验签接种")
        self.assertEqual("vht_DzLunLa2Sdj5uJ3IeJ7I6w",
                         p["cert"]["subject"]["publicKey"])

    def test_payload_contains_no_private_material(self):
        import json
        raw = json.dumps(self._payload())
        for bad in ("privateKey", "ca_private", "seed", "PRIVATE KEY"):
            self.assertNotIn(bad, raw, "响应里绝不能出现私钥相关字段")

    def test_uninitialized_ca_returns_none(self):
        import api_server

        class _Empty(object):
            root_cert = None
            root_fingerprint = ""

        self.assertIsNone(api_server.build_ca_root_payload(_Empty(), {}))

    def test_fingerprint_is_str_not_bytes(self):
        p = self._payload()
        self.assertIsInstance(p["fingerprint"], str)

    def test_install_scripts_know_portal(self):
        for name in ("install.sh", "build_release.sh"):
            src = _read_root(name)
            self.assertIn("admin/portal.html", src,
                          "%s 没有把 admin/portal.html 纳入校验/打包" % name)

    def test_bas_http_keeps_legacy_alias(self):
        src = _read_root("bas_http.py")
        self.assertIn("/admin/fus", src)
        self.assertIn("/admin/bas", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
