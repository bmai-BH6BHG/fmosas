#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · FMO/RAW 包头解析器（从 FAS 的 FmoRawParser.cs 逐语义移植）
=================================================================
MQTT payload 前 64 字节为固定包头（**小端**）：

    offset  size  field
    0       2     version
    2       4     flags
    6       4     UID            （包头声明的身份 UID）
    10      12    callsign       （ASCII，定长 12，遇 \\0 截断再 strip）
    22      4     streamBeginUTC
    26      4     timestamp
    30      4     len            （应等于整包长度）
    34      2     frameNum
    36      4     checkSum       （= CRC32(raw[64:])）
    40      1     smeter
    41      4     srvUID
    45      19    reserved

合法性（对齐固件 isValidPacket）：
  * 包长 ≥ 72（64 包头 + 8 首帧头）
  * 包长 ≤ 1400（MTU）
  * head.len == 实际包长
  * len 字段 ≥ 72

CRC 语义（重要）：checkSum 只覆盖 offset 64 之后的帧区，设备端已核验过，
因此 **CRC 不匹配不判失败**，只把 crc_ok 置 False 供审计展示。

包头是明文声明、不加密不签名 —— 身份真相在连接认证侧（SAS 写入的 client_attrs）。
"""

import struct

HEAD_SIZE = 64
MIN_VALID_LEN = 72      # 64 包头 + 8 首帧头
MAX_LEN = 1400          # MTU

# 标准 CRC-32（zlib 语义，多项式 0xEDB88320，初值 0xFFFFFFFF，最终异或）——
# 与 ESP32 的 crc32_le 一致；用查表实现，保证与 C# 侧结果逐位相同。
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _k in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c & 0xFFFFFFFF)


def crc32(data: bytes) -> int:
    """标准 CRC-32（zlib 兼容）。crc32(b"123456789") == 0xCBF43926；crc32(b"") == 0。"""
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


class ParseResult(object):
    """解析结果。ok=False 时 error 给出原因。"""

    __slots__ = ("ok", "error", "uid", "callsign", "len", "frame_num", "check_sum",
                 "crc_ok", "smeter", "srv_uid", "stream_begin_utc", "timestamp",
                 "version", "flags")

    def __init__(self, ok=False, error=None):
        self.ok = ok
        self.error = error
        self.uid = 0
        self.callsign = ""
        self.len = 0
        self.frame_num = 0
        self.check_sum = 0
        self.crc_ok = False
        self.smeter = 0
        self.srv_uid = 0
        self.stream_begin_utc = 0
        self.timestamp = 0
        self.version = 0
        self.flags = 0

    def as_dict(self):
        return {
            "ok": self.ok,
            "error": self.error,
            "uid": self.uid,
            "callsign": self.callsign,
            "len": self.len,
            "frame_num": self.frame_num,
            "check_sum": self.check_sum,
            "crc_ok": self.crc_ok,
            "smeter": self.smeter,
            "srv_uid": self.srv_uid,
            "stream_begin_utc": self.stream_begin_utc,
            "timestamp": self.timestamp,
            "version": self.version,
            "flags": self.flags,
        }

    def __repr__(self):
        if not self.ok:
            return "<ParseResult ok=False error=%r>" % (self.error,)
        return "<ParseResult uid=%d callsign=%r len=%d frame=%d crcOk=%s>" % (
            self.uid, self.callsign, self.len, self.frame_num, self.crc_ok)


def parse(raw):
    """解析并校验一个 FMO/RAW 包；返回 ParseResult。"""
    if raw is None:
        return ParseResult(False, "payload 为空")
    n = len(raw)
    if n < MIN_VALID_LEN:
        return ParseResult(False, "包长不足 72 字节")
    if n > MAX_LEN:
        return ParseResult(False, "超过 MTU 1400")

    version, flags, uid = struct.unpack_from("<HII", raw, 0)
    cs_raw = bytes(raw[10:22])
    end = cs_raw.find(b"\x00")
    if end < 0:
        end = len(cs_raw)
    try:
        callsign = cs_raw[:end].decode("ascii", "replace").strip()
    except Exception:  # pragma: no cover - decode 已容错
        callsign = ""
    stream_begin, timestamp, length = struct.unpack_from("<III", raw, 22)
    (frame_num,) = struct.unpack_from("<H", raw, 34)
    (check_sum,) = struct.unpack_from("<I", raw, 36)
    smeter = raw[40]
    (srv_uid,) = struct.unpack_from("<I", raw, 41)

    # ---- 合法性校验（与固件 isValidPacket 一致）----
    if length != n:
        r = ParseResult(False, "len 字段(%d)与包长(%d)不符" % (length, n))
        return r
    if length < MIN_VALID_LEN:
        return ParseResult(False, "len 字段小于 72")

    crc_ok = crc32(bytes(raw[HEAD_SIZE:])) == check_sum

    r = ParseResult(True, None)
    r.uid = uid
    r.callsign = callsign
    r.len = length
    r.frame_num = frame_num
    r.check_sum = check_sum
    r.crc_ok = crc_ok
    r.smeter = smeter
    r.srv_uid = srv_uid
    r.stream_begin_utc = stream_begin
    r.timestamp = timestamp
    r.version = version
    r.flags = flags
    return r


# ==================== 版本号比较（UpdateService.CompareVersions 语义）====================

def _version_tuple(s):
    """把 'v2.1.0' / '2.0.13' 切成可比较的整数段；非数字段按 0 处理，长度对齐。"""
    s = str(s or "").strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    parts = []
    for seg in s.split("."):
        num = ""
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def compare_versions(a, b):
    """返回 -1 / 0 / 1。对齐上游 UpdateServiceVersionTests 的 5 组向量。"""
    ta, tb = _version_tuple(a), _version_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    if ta > tb:
        return 1
    if ta < tb:
        return -1
    return 0


def is_newer(candidate, current):
    """candidate 是否比 current 新。"""
    return compare_versions(candidate, current) > 0
