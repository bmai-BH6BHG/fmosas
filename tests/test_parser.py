#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO/RAW 包头解析与 CRC32 测试
=============================
逐条移植上游 xUnit 用例（fmo-audit-service.Tests/CoreLogicTests.cs），
保证 Python 重写与 .NET 原实现在语义上一致。额外补充固件视角的边界向量。
"""

import struct
import unittest

from tests import ROOT  # noqa: F401  （触发 sys.path 设置）
from bas_fmo_parser import (
    crc32, parse, compare_versions, is_newer,
    HEAD_SIZE, MIN_VALID_LEN, MAX_LEN,
)


def build_packet(frame=None, uid=12345, len_override=None, callsign="BG5ESN",
                 version=2, flags=0xDEADBEEF, stream_begin=1700000000,
                 timestamp=1700000100, frame_num=7, smeter=9, srv_uid=999,
                 checksum=None):
    """构造合法 FMO/RAW 包：64B 包头（小端）+ 帧区，checkSum 默认 = CRC32(帧区)。"""
    if frame is None:
        frame = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    raw = bytearray(HEAD_SIZE + len(frame))
    struct.pack_into("<H", raw, 0, version)
    struct.pack_into("<I", raw, 2, flags)
    struct.pack_into("<I", raw, 6, uid)
    raw[10:22] = callsign.encode("ascii")[:12].ljust(12, b"\x00")
    struct.pack_into("<I", raw, 22, stream_begin)
    struct.pack_into("<I", raw, 26, timestamp)
    struct.pack_into("<I", raw, 30, len(raw) if len_override is None else len_override)
    struct.pack_into("<H", raw, 34, frame_num)
    struct.pack_into("<I", raw, 36, crc32(frame) if checksum is None else checksum)
    raw[40] = smeter
    struct.pack_into("<I", raw, 41, srv_uid)
    raw[HEAD_SIZE:] = frame
    return bytes(raw)


class Crc32Tests(unittest.TestCase):
    def test_standard_vector_123456789(self):
        """zlib 标准向量：CRC32("123456789") = 0xCBF43926"""
        self.assertEqual(0xCBF43926, crc32(b"123456789"))

    def test_empty_is_zero(self):
        self.assertEqual(0, crc32(b""))

    def test_matches_zlib(self):
        """与 zlib.crc32 全等（随机长度向量）"""
        import zlib
        for n in (1, 2, 3, 7, 8, 63, 64, 65, 1024):
            data = bytes((i * 37 + 11) & 0xFF for i in range(n))
            self.assertEqual(zlib.crc32(data) & 0xFFFFFFFF, crc32(data), "len=%d" % n)


class FmoRawParserTests(unittest.TestCase):
    def test_legal_packet_fields(self):
        """移植：Parse_合法包_字段正确"""
        r = parse(build_packet())
        self.assertTrue(r.ok, r.error)
        self.assertEqual(12345, r.uid)
        self.assertEqual("BG5ESN", r.callsign)
        self.assertEqual(72, r.len)
        self.assertEqual(7, r.frame_num)
        self.assertEqual(999, r.srv_uid)
        self.assertEqual(9, r.smeter)
        self.assertEqual(2, r.version)
        self.assertEqual(0xDEADBEEF, r.flags)
        self.assertEqual(1700000000, r.stream_begin_utc)
        self.assertEqual(1700000100, r.timestamp)
        self.assertTrue(r.crc_ok)

    def test_too_short_fails(self):
        """移植：Parse_包长不足72_失败"""
        self.assertFalse(parse(bytes(71)).ok)
        self.assertFalse(parse(b"").ok)
        self.assertFalse(parse(None).ok)

    def test_over_mtu_fails(self):
        """移植：Parse_超MTU_失败"""
        r = parse(bytes(1401))
        self.assertFalse(r.ok)
        self.assertIn("MTU", r.error)

    def test_len_mismatch_fails(self):
        """移植：Parse_len字段与包长不符_失败"""
        r = parse(build_packet(len_override=100))
        self.assertFalse(r.ok)
        self.assertIn("len", r.error)

    def test_callsign_zero_truncated(self):
        """移植：Parse_callsign按零截断_短呼号"""
        r = parse(build_packet(callsign="BG5AAA"))
        self.assertTrue(r.ok, r.error)
        self.assertEqual("BG5AAA", r.callsign)

    def test_crc_bad_only_flags(self):
        """移植：Parse_crc错误_仅标记CrcOkFalse_不判失败"""
        raw = bytearray(build_packet())
        raw[36] ^= 0xFF     # 破坏 checkSum
        r = parse(bytes(raw))
        self.assertTrue(r.ok)
        self.assertFalse(r.crc_ok)

    # ---- 固件视角补充边界 ----
    def test_exact_min_and_max_len(self):
        rmin = parse(build_packet(frame=bytes(8)))
        self.assertEqual(MIN_VALID_LEN, rmin.len)
        self.assertTrue(rmin.ok)
        rmax = parse(build_packet(frame=bytes(MAX_LEN - HEAD_SIZE)))
        self.assertEqual(MAX_LEN, rmax.len)
        self.assertTrue(rmax.ok)

    def test_full_12_byte_callsign(self):
        r = parse(build_packet(callsign="ABCDEF123456"))
        self.assertTrue(r.ok)
        self.assertEqual("ABCDEF123456", r.callsign)

    def test_callsign_padding_and_spaces(self):
        """12 字节全非零 + 尾部空格 → strip 掉（对齐 C# .Trim()）"""
        r = parse(build_packet(callsign="BG5ESN      "))
        self.assertTrue(r.ok)
        self.assertEqual("BG5ESN", r.callsign)

    def test_len_field_smaller_than_72(self):
        raw = build_packet(len_override=64)
        r = parse(raw)
        self.assertFalse(r.ok)

    def test_uid_zero_allowed(self):
        r = parse(build_packet(uid=0))
        self.assertTrue(r.ok)
        self.assertEqual(0, r.uid)

    def test_crc64_mismatch_but_ok(self):
        """checkSum 写错但包结构合法 → ok=True, crc_ok=False（审计据此展示）"""
        r = parse(build_packet(checksum=0x11223344))
        self.assertTrue(r.ok)
        self.assertFalse(r.crc_ok)


class VersionCompareTests(unittest.TestCase):
    """移植：UpdateServiceVersionTests.CompareVersions 的 5 组向量"""

    def test_vectors(self):
        cases = [
            ("2.0.14", "2.0.13", 1),
            ("2.0.13", "2.0.14", -1),
            ("2.0.13", "2.0.13", 0),
            ("v2.1.0", "2.0.99", 1),
            ("3.0.0", "2.99.99", 1),
        ]
        for a, b, expected in cases:
            self.assertEqual(expected, compare_versions(a, b), "%s vs %s" % (a, b))

    def test_is_newer(self):
        self.assertTrue(is_newer("2.0.23", "2.0.22"))
        self.assertFalse(is_newer("2.0.22", "2.0.22"))
        self.assertFalse(is_newer("2.0.21", "2.0.22"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
