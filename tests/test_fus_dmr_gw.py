#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fus_dmr_gw.py（FMO 集群语音 ↔ 国服 DMR 网关）单元测试。

覆盖：IMA ADPCM 往返、FMO/RAW 帧组/解、呼号 12 字节（旧版只取 6 字节的坑）、
Opus 段识别与计数、坏帧拒绝、USRP 包格式、回环过滤、srcId 映射。
"""
import math
import os
import struct
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import fus_dmr_gw as G  # noqa: E402

BAD = bytes(8)          # 坏帧：过短（全 0x00）


class AdpcmTests(unittest.TestCase):
    def test_roundtrip_small_error(self):
        """IMA ADPCM 往返误差应远小于全幅（<1%）。"""
        pcm = [int(9000 * math.sin(i * 0.07)) for i in range(640)]
        payload, vp, idx = G.adpcm_encode(pcm, 0, 0)
        self.assertEqual(len(payload), 320)
        back = G.adpcm_decode(payload, 0, 0)
        self.assertEqual(len(back), 640)
        err = sum(abs(a - b) for a, b in zip(pcm, back)) / len(pcm)
        self.assertLess(err, 327.67, "ADPCM 往返误差过大: %.1f" % err)

    def test_block_shape(self):
        """一个 ADPCM 块 = 328B（8B 头 + 320B 数据）。"""
        pcm = [1000] * 640
        blk, vp, idx = G.adpcm_block(pcm, 1, 0, 0)
        self.assertEqual(len(blk), 328)
        seq, zero, v, i = struct.unpack_from("<BBhB", blk, 0)
        self.assertEqual(seq, 1)
        self.assertEqual(v, 0)
        self.assertEqual(i, 0)


class FmoFrameTests(unittest.TestCase):
    def _frame(self, call="BH6BHG", session=1234):
        inner = G.adpcm_block([1200] * 640, 1, 0, 0)[0]
        blk = G.make_block(1, 0x02, inner)
        return G.pack_frame(call, session, 1111, 2222, blk, 1, 0)

    def test_roundtrip(self):
        fr = self._frame()
        self.assertEqual(len(fr), 64 + 344)
        s, call, blocks, stats, opus_pkts = G.parse_fmo_frame(fr)
        self.assertEqual(s, 1234)
        self.assertEqual(call, "BH6BHG")
        self.assertEqual(len(blocks), 1)
        self.assertEqual(stats["adpcm"], 1)

    def test_callsign_takes_12_bytes(self):
        """
        ★ 呼号取 [10:22] 12 字节（真实 FMO 硬件）。
        旧版只取 [10:16] 6 字节，长呼号会被静默截断。
        """
        long_call = "ABCDEFGH"        # 8 字符 > 6
        head = bytearray(64)
        head[0] = 0x01
        struct.pack_into("<H", head, 6, 7)
        head[10:10 + len(long_call)] = long_call.encode("ascii")
        struct.pack_into("<H", head, 34, 0)
        got = G.parse_fmo_frame(bytes(head))
        self.assertIsNotNone(got)
        self.assertEqual(got[1], long_call, "呼号应取 12 字节，不应被截断成 6")

    def test_opus_counted_not_silent(self):
        """Opus 段（innerType 0x01）必须被识别并计数，不能静默丢弃。"""
        inner = bytes([0x01]) + struct.pack("<H", 8 + 40) + G.CONST5 + bytes(40)
        blk = G.make_block(2, 0x01, inner[8:])
        fr = G.pack_frame("BH6BHG", 99, 1, 2, blk, 1, 0)
        s, call, blocks, stats, opus_pkts = G.parse_fmo_frame(fr)
        self.assertEqual(stats["opus"], 1)
        self.assertEqual(stats["adpcm"], 0)
        self.assertEqual(len(blocks), 0)      # Opus 不产生 ADPCM 块
        self.assertEqual(len(opus_pkts), 1, "Opus 载荷必须被提取出来供解码")

    def test_bad_frames_rejected(self):
        self.assertIsNone(G.parse_fmo_frame(b""))
        self.assertIsNone(G.parse_fmo_frame(bytes([0x01]) * 10))
        bad = bytearray(self._frame())
        bad[0] = 0x02
        self.assertIsNone(G.parse_fmo_frame(bytes(bad)))


class UsrpTests(unittest.TestCase):
    def _gw(self, **kw):
        cfg = dict(G.DEFAULTS)
        cfg.update(kw)
        return G.DmrGateway(cfg)

    def test_voice_packet_layout(self):
        gw = self._gw()
        sent = []
        gw.usrp._send = lambda pkt: sent.append(pkt)
        gw.usrp.send_voice(True, bytes([0x11]) * 320)
        pkt = sent[0]
        self.assertEqual(pkt[0:4], b"USRP")
        self.assertEqual(len(pkt), 32 + 320)
        seq, _z, keyup, _z2, ptype, _z3, _z4 = struct.unpack(">iiiiiii", pkt[4:32])
        self.assertEqual(keyup, 1)
        self.assertEqual(ptype, 0)
        self.assertEqual(pkt[32:], bytes([0x11]) * 320)

    def test_command_packet_type_shift(self):
        gw = self._gw()
        sent = []
        gw.usrp._send = lambda pkt: sent.append(pkt)
        gw.usrp.send_command(b"REG:DVSWITCH", G.USRP_TYPE_TEXT)
        pkt = sent[0]
        ptype = struct.unpack(">i", pkt[20:24])[0]
        self.assertEqual(ptype, G.USRP_TYPE_TEXT << 24)
        self.assertEqual(pkt[32:], b"REG:DVSWITCH")


class LoopbackAndMappingTests(unittest.TestCase):
    def _gw(self, **kw):
        cfg = dict(G.DEFAULTS)
        cfg.update(kw)
        return G.DmrGateway(cfg)

    def _adpcm_frame(self, call, session):
        inner = G.adpcm_block([3000] * 640, 1, 0, 0)[0]
        blk = G.make_block(1, 0x02, inner)
        return G.pack_frame(call, session, 1, 2, blk, 1, 0)

    def test_short_payload_ignored(self):
        gw = self._gw()
        gw.usrp.registered.set()
        gw.on_mqtt_message("FMO/RAW", BAD)
        self.assertEqual(len(gw.tx_queue), 0)

    def test_own_frames_not_relayed(self):
        """网关自己发出去的帧不能又被转回 DMR（回环）。"""
        gw = self._gw(fmo_callsign="DMRGW")
        gw.usrp.registered.set()
        gw.on_mqtt_message("FMO/RAW", self._adpcm_frame("DMRGW", 5))
        self.assertEqual(len(gw.tx_queue), 0, "自己的帧被转回去了")

    def test_published_session_not_relayed(self):
        gw = self._gw()
        gw.usrp.registered.set()
        gw.published_sessions.add(4242)
        gw.on_mqtt_message("FMO/RAW", self._adpcm_frame("BH8GPV", 4242))
        self.assertEqual(len(gw.tx_queue), 0, "自己发出去的会话号又被转回去了")

    def test_real_frame_is_queued(self):
        gw = self._gw(dmr_gateway_id=8602262)
        gw.usrp.registered.set()
        gw.on_mqtt_message("FMO/RAW", self._adpcm_frame("BG4QBI", 77))
        self.assertEqual(len(gw.tx_queue), 4, "一帧 ADPCM 应切出 4 个 20ms 包")
        self.assertEqual(gw._tx_dmr_id, 8602262)

    def test_src_map_overrides(self):
        gw = self._gw(dmr_gateway_id=8602262, src_map={"BG4QBI": 8609999})
        gw.usrp.registered.set()
        gw.on_mqtt_message("FMO/RAW", self._adpcm_frame("BG4QBI", 78))
        self.assertEqual(gw._tx_dmr_id, 8609999, "src_map 应覆盖默认网关 ID")


class ConfigTests(unittest.TestCase):
    def test_defaults_present(self):
        for k in ("mqtt_host", "sub_topic", "dmr_tg", "dmr_ts",
                  "dmr_gateway_id", "usrp_rx_port", "client_id"):
            self.assertIn(k, G.DEFAULTS)
        self.assertEqual(G.DEFAULTS["sub_topic"], "FMO/RAW")
        self.assertEqual(G.DEFAULTS["dmr_tg"], 860562)
        self.assertEqual(G.DEFAULTS["dmr_ts"], 1)
        self.assertTrue(G.DEFAULTS["client_id"].startswith("FMO-"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
