#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tests/test_fus_ambe.py —— libfusambe.so 声码器（zig 交叉编译版）。

库不在位时自动跳过（不视为失败）：本地开发机没有 .so，
群晖部署后才跑得到。设 FUS_AMBE_LIB 指定路径。
"""
import math
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import fus_dmr_gw as G  # noqa: E402

LIB = os.environ.get("FUS_AMBE_LIB",
                     os.path.join(REPO, "lib", "libfusambe.so"))


@unittest.skipUnless(os.path.exists(LIB), "libfusambe.so 不在位（仅群晖部署后有）")
class AmbeCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = G.AmbeCodec(LIB)
        if not cls.codec.ok:
            raise unittest.SkipTest(
                "libfusambe.so 本平台加载失败（%s）—— 该库是 Linux x86_64，"
                "只在群晖上跑；Windows/macOS 开发机跳过" % cls.codec.err)

    def test_lib_loads(self):
        self.assertTrue(self.codec.ok, self.codec.err)

    def test_encode_returns_9_bytes(self):
        pcm = [int(9000 * math.sin(i * 0.05)) for i in range(160)]
        out = self.codec.encode(pcm)
        self.assertIsNotNone(out)
        self.assertEqual(len(out), 9)

    def test_encode_is_fast(self):
        """实时性：一帧 20ms，编码必须远快于它（实测约 2ms）。"""
        import time
        pcm = [int(6000 * math.sin(i * 0.07)) for i in range(160)]
        t0 = time.time()
        for _ in range(20):
            self.codec.encode(pcm)
        avg_ms = (time.time() - t0) / 20 * 1000
        self.assertLess(avg_ms, 15.0, "编码 %.1fms/帧，跟不上实时" % avg_ms)

    def test_decode_roundtrip_shape(self):
        """编出来再解回来：长度必须是 160，且不能全零（有声音）。"""
        pcm = [int(9000 * math.sin(i * 0.05)) for i in range(160)]
        ambe = self.codec.encode(pcm)
        self.assertIsNotNone(ambe)
        back = self.codec.decode(ambe)
        self.assertIsNotNone(back)
        self.assertEqual(len(back), 160)
        self.assertTrue(any(v != 0 for v in back), "解码全零 = 没声音")

    def test_silence_encodes(self):
        """静音帧也必须能编（DMR 通话里要补静音保流）。"""
        out = self.codec.encode([0] * 160)
        self.assertIsNotNone(out)
        self.assertEqual(len(out), 9)

    def test_bad_input_rejected(self):
        self.assertIsNone(self.codec.encode([0] * 100))   # 长度不对
        self.assertIsNone(self.codec.decode(b"\x00" * 8))  # 长度不对


if __name__ == "__main__":
    unittest.main(verbosity=2)
