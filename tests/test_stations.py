#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO 站点目录测试
================
「FMO 房间」= 一个个 FMO 站（中继/服务器）。每个站广播一张二进制站点名片
FMO/SERVER_INFO。覆盖：

  * 二进制名片解析（用**真实报文**做的固定样本，含中文站名/简介）
  * 老代码把它当文本解析会把整包当站名（含 NUL 的乱码）——必须不再发生
  * 站点目录按呼号累积（老代码只留最后一条，导致永远只有 1 个站）
  * 三路数据源合并（总系统登记 / MQTT 实时 / 本机自身）
  * 总系统库不可用时不抛异常（降级）
"""

import os
import shutil
import struct
import tempfile
import unittest

from tests import ROOT  # noqa: F401
import fmo_stations as FS
from monitor import parse_server_info


def make_card(ver, station_no, counter, callsign, name, desc):
    """按真实报文结构造一张站点名片。"""
    b = bytes([ver]) + struct.pack("<I", station_no) + struct.pack("<I", counter)
    b += callsign.encode("utf-8")[:12].ljust(12, b"\x00")
    b += name.encode("utf-8") + b"\x00" + desc.encode("utf-8") + b"\x00"
    return b


# 真实抓包（本机 BH6BHG / 安铜集群），逐字节来自线上
REAL_BH6BHG = bytes.fromhex(
    "00020000001000000042483642484700000000000000000000e5ae89e9939ce99b86e7bea4"
    "28e9939ce999b5464d4fe7ab9929000000000000e6aca2e8bf8ee69da5e588b0e585abe7"
    "99bee9878ce79a96e6b19fe69cace4b8ade7bba7e4b88ee5ae89e5ba86e4b8ade7bba7e4"
    "ba92e8819400000000")


class ServerInfoParseTests(unittest.TestCase):
    def test_parses_real_local_capture(self):
        info = parse_server_info(REAL_BH6BHG)
        self.assertEqual("BH6BHG", info["callsign"])
        self.assertEqual("安铜集群(铜陵FMO站)", info["name"])
        self.assertEqual("欢迎来到八百里皖江本中继与安庆中继互联", info["desc"])
        self.assertEqual(2, info["station_no"])

    def test_parses_real_fmrs_station(self):
        """总系统库里另一台真实站（FMRS / BI7IOB）。"""
        card = make_card(1, 4, 9, "BI7IOB", "FMRS", "我们即将桥接接")
        info = parse_server_info(card)
        self.assertEqual("BI7IOB", info["callsign"])
        self.assertEqual("FMRS", info["name"])
        self.assertEqual("我们即将桥接接", info["desc"])
        self.assertEqual(4, info["station_no"])

    def test_parses_real_chongqing_station(self):
        card = make_card(1, 7, 81, "BG8LAK", "精品毛血旺（渝）",
                         "主料：鸭血、毛肚、黄喉、午餐肉、肥肠、鳝片；配")
        info = parse_server_info(card)
        self.assertEqual("BG8LAK", info["callsign"])
        self.assertEqual("精品毛血旺（渝）", info["name"])
        self.assertEqual(7, info["station_no"])

    def test_name_is_not_the_whole_binary_blob(self):
        """回归：老解析把整包当站名，站名里带 NUL 与 `BH6BHG` 等二进制头。"""
        info = parse_server_info(REAL_BH6BHG)
        self.assertNotIn("\x00", info["name"])
        self.assertNotIn("BH6BHG", info["name"])
        self.assertLess(len(info["name"]), 40)

    def test_too_short_or_empty(self):
        self.assertIsNone(parse_server_info(b""))
        self.assertIsNone(parse_server_info(b"\x00\x02\x00"))
        self.assertIsNone(parse_server_info(None))

    def test_name_only_no_desc(self):
        info = parse_server_info(make_card(0, 1, 0, "BH1AAA", "测试站", ""))
        self.assertEqual("测试站", info["name"])
        self.assertEqual("", info["desc"])


class StationLedgerTests(unittest.TestCase):
    """monitor 的站点累积（不再只留最后一条）。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-st-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _monitor(self):
        from monitor import VoiceMonitor
        m = VoiceMonitor.__new__(VoiceMonitor)
        import threading
        import time as _t
        m.base_dir = self.tmp
        m._lock = threading.Lock()
        m._stations = {}
        m.server_name = ""
        m.server_desc = ""
        m._server_info_raw = ""
        m._t = _t
        return m

    def test_accumulates_multiple_stations(self):
        m = self._monitor()
        m._note_station(parse_server_info(REAL_BH6BHG))
        m._note_station(parse_server_info(
            make_card(1, 4, 9, "BI7IOB", "FMRS", "即将桥接")))
        got = {s["callsign"]: s for s in m.stations()}
        self.assertEqual({"BH6BHG", "BI7IOB"}, set(got))
        self.assertEqual("安铜集群(铜陵FMO站)", got["BH6BHG"]["name"])
        self.assertEqual("FMRS", got["BI7IOB"]["name"])

    def test_same_station_updates_in_place(self):
        m = self._monitor()
        m._note_station(parse_server_info(REAL_BH6BHG))
        m._note_station(parse_server_info(REAL_BH6BHG))
        self.assertEqual(1, len(m.stations()))
        self.assertEqual(2, m.stations()[0]["hits"])

    def test_persisted_to_disk(self):
        m = self._monitor()
        m._note_station(parse_server_info(REAL_BH6BHG))
        path = os.path.join(self.tmp, "stations.json")
        self.assertTrue(os.path.exists(path), "站点目录要落盘，重启后仍在")

    def test_station_without_callsign_ignored(self):
        m = self._monitor()
        m._note_station({"name": "x", "desc": ""})
        self.assertEqual([], m.stations())


class MergeTests(unittest.TestCase):
    def test_master_plus_mqtt_merge(self):
        master = [{"subsystem_id": "s1", "callsign": "BH6BHG",
                   "name": "旧名字", "desc": "", "domain": "bh6bhg.cloud",
                   "api_url": "http://bh6bhg.cloud:35928",
                   "total_users": 42, "online_users": 1,
                   "last_report": 1000.0, "source": "master"}]
        mqtt = [{"callsign": "BH6BHG", "name": "安铜集群(铜陵FMO站)",
                 "desc": "欢迎", "station_no": 2, "last_seen": 999.0}]
        out = FS.merge_stations(master, mqtt, now=1000.0)
        self.assertEqual(1, len(out), "同呼号应合并成一条")
        self.assertEqual("安铜集群(铜陵FMO站)", out[0]["name"], "实时抄收的站名优先")
        self.assertEqual(42, out[0]["total_users"])
        self.assertTrue(out[0]["mqtt_live"])
        self.assertTrue(out[0]["online"])

    def test_self_marked_and_first(self):
        master = [{"subsystem_id": "s1", "callsign": "BH6BHG", "name": "A",
                   "domain": "a", "api_url": "", "total_users": 1,
                   "online_users": 0, "last_report": 0.0, "source": "master"},
                  {"subsystem_id": "s2", "callsign": "BG8LAK", "name": "B",
                   "domain": "b", "api_url": "", "total_users": 99,
                   "online_users": 0, "last_report": 0.0, "source": "master"}]
        out = FS.merge_stations(master, [], {"callsign": "BH6BHG",
                                             "domain": "a", "api_url": ""})
        self.assertTrue(out[0]["is_self"], "本机站点排最前")
        self.assertEqual("BH6BHG", out[0]["callsign"])

    def test_offline_when_stale(self):
        master = [{"subsystem_id": "s1", "callsign": "X1AAA", "name": "x",
                   "domain": "d", "api_url": "", "total_users": 0,
                   "online_users": 0, "last_report": 100.0, "source": "master"}]
        out = FS.merge_stations(master, [], now=100 + FS.OFFLINE_AFTER_SEC + 10)
        self.assertFalse(out[0]["online"])

    def test_entry_url_from_domain_when_no_api_url(self):
        st = {"domain": "fmo.fmrs.cn", "api_url": ""}
        self.assertEqual("http://fmo.fmrs.cn:35928", FS.entry_url(st))

    def test_entry_url_prefers_api_url(self):
        st = {"domain": "x", "api_url": "http://x:9999/"}
        self.assertEqual("http://x:9999", FS.entry_url(st))

    def test_empty_inputs(self):
        self.assertEqual([], FS.merge_stations([], [], None))


class MasterDbTests(unittest.TestCase):
    def test_bad_path_returns_empty_not_raise(self):
        self.assertEqual([], FS.read_master_subsystems(""))
        self.assertEqual([], FS.read_master_subsystems("/no/such/file.db"))
        self.assertEqual("", FS.find_master_db("/no/such/file.db"))

    def test_reads_real_master_db(self):
        """真实总系统库存在时能读出站点（不存在则跳过，不算失败）。"""
        db = FS.find_master_db()
        if not db:
            self.skipTest("本机没有总系统库")
        rows = FS.read_master_subsystems(db)
        self.assertTrue(rows, "总系统库应能读出子系统")
        with_card = [r for r in rows if r.get("callsign")]
        self.assertTrue(with_card, "至少应有一个站带站点名片")

    def test_parse_mqtt_name_tolerates_garbage(self):
        self.assertEqual({}, FS.parse_mqtt_name(None))
        self.assertEqual({}, FS.parse_mqtt_name(""))
        self.assertEqual({}, FS.parse_mqtt_name(b"\x00\x01"))

    def test_parse_mqtt_name_accepts_str_and_bytes(self):
        card = make_card(0, 2, 16, "BH6BHG", "安铜集群(铜陵FMO站)", "欢迎")
        as_bytes = FS.parse_mqtt_name(card)
        as_str = FS.parse_mqtt_name(card.decode("utf-8", "surrogateescape"))
        self.assertEqual("BH6BHG", as_bytes["callsign"])
        self.assertEqual(as_bytes["name"], as_str["name"])


class StationPageTests(unittest.TestCase):
    def test_page_and_assets_exist(self):
        for f in ("stations.html", "stations.js"):
            p = os.path.join(ROOT, "admin", f)
            self.assertTrue(os.path.exists(p), "缺少 %s" % f)

    def test_page_is_self_contained(self):
        html = open(os.path.join(ROOT, "admin", "stations.html"),
                    encoding="utf-8").read()
        self.assertNotIn("https://", html)
        self.assertIn("/admin/bas.css", html)
        self.assertIn("/admin/stations.js", html)

    def test_portal_links_to_stations(self):
        html = open(os.path.join(ROOT, "admin", "portal.html"),
                    encoding="utf-8").read()
        self.assertIn('href="/admin/stations"', html)
        self.assertIn("FMO 站点", html)

    def test_route_registered(self):
        src = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("'/admin/stations'", src)
        self.assertIn("/api/fus/stations", src)
        self.assertIn("_handle_fmo_stations", src)

    def test_api_not_exposed_on_public_port(self):
        """站点目录含全网拓扑与用户数，只在管理口。"""
        src = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        block = src.split("PUBLIC_GET_PATHS", 1)[1].split(")", 1)[0]
        self.assertNotIn("/api/fus/stations", block)
        self.assertNotIn("/admin/stations", block)

    def test_shipped_by_build_script(self):
        """新模块不进打包清单 → 出的包里缺文件，站点页会 503。"""
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("fmo_stations.py", src)
        self.assertIn("admin/stations.html", src)

    def test_static_asset_route_guards_traversal(self):
        """站点页要能取到 stations.js，但静态资源路由必须挡住目录穿越。"""
        src = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("_serve_admin_asset", src)
        handler = src.split("def _serve_admin_asset", 1)[1].split("    def ", 1)[0]
        for guard in ("'..' in name", "'/' in name", "startswith('.')"):
            self.assertIn(guard, handler,
                          "静态资源路由缺少防穿越检查: %s" % guard)


if __name__ == "__main__":
    unittest.main(verbosity=2)
