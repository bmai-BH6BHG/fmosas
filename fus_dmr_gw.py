#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO 集群语音 ↔ 国服 DMR 网关（fus_dmr_gw）
===========================================
把桥接集群里的语音送到国服 DMR 通话组（默认 TG860562「安铜集群」/ TS1），
也可以把国服侧语音带回集群 —— 双向。

链路：
    本机 EMQX(FMO/RAW) ←MQTT→ 本网关 ←USRP→ Analog_Bridge ←→ md380-emu(软 AMBE)
        ←→ MMDVM_Bridge ←Homebrew UDP 62031→ 国服主站 mastra.radiowo.com

设计要点（与旧版 fmo_dmr_gw.py 的差异，旧版连不上集群的原因逐条修掉）：
    ① 主题：旧写死 "APPNET/FMO/RAW"（收不到本集群任何语音）→ 本版默认 "FMO/RAW"
    ② MQTT：旧依赖 paho-mqtt（群晖没有）→ 本版复用同目录 monitor.py 的
       MqttMiniClient（纯标准库，久经半包/keepalive/重连考验）
    ③ 认证：旧用「呼号 + 空密码」（我们 EMQX 走证书认证，必被拒）
       → 本版复用 fmo_aprs 的 build_probe_credentials（呼号 SERVER + 证书 CBOR 证明），
         与本机桥接完全一致的凭证
    ④ 音频：旧只认 ADPCM(innerType 0x02)，遇到 Opus(0x01) 直接丢
       → 本版 ADPCM 全支持；Opus 记录并统计（DMR 侧只需要 8kHz PCM，
         由 md380-emu 编码，故 Opus 段默认跳过并明确计数，不静默）
    ⑤ 呼号：旧只取帧头 [10:16] 6 字节（真实硬件是 [10:22] 12 字节，长呼号被截断）
       → 本版取 12 字节，按 NUL 截断
    ⑥ 配置：TG/时隙/DMR ID/broker 全部走 config.json，不再写死在代码里
    ⑦ 增加：状态文件 + 看门狗 + 重启自愈（systemd 或独立循环）

运行方式（与分系统同机，依赖同目录模块）：
    cd /opt/fmo-subsystem
    python3 -u fus_dmr_gw.py [--config /opt/fmo-subsystem/fus_dmr_gw.json]

配置文件缺省值全部内置，最小可运行（只连本机 EMQX + 本机 DVSwitch）。
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
import zlib
from collections import deque

# ---------------------------------------------------------------- 复用现有模块
# 网关部署在 /opt/fmo-subsystem（与 monitor.py / fmo_aprs.py 同目录），
# 直接复用它们的 MQTT 客户端与证书凭证，避免重复实现、避免行为不一致。
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from monitor import MqttMiniClient          # MQTT 3.1.1 最小客户端
    _HAVE_MQTT = True
except Exception as _e:                          # pragma: no cover
    MqttMiniClient = None
    _HAVE_MQTT = False

try:
    from fmo_aprs import build_probe_credentials, load_probe_cert
    _HAVE_CRED = True
except Exception as _e:                          # pragma: no cover
    build_probe_credentials = load_probe_cert = None
    _HAVE_CRED = False

# ---------------------------------------------------------------- 默认配置
DEFAULTS = {
    # ---- MQTT（本机 EMQX；凭证与桥接一致，勿改）----
    "mqtt_host": "127.0.0.1",
    "mqtt_port": 1883,
    "sub_topic": "FMO/RAW",          # 集群语音主路径
    "pub_topic": "FMO/RAW",          # 国服语音回灌集群
    "client_id": "FMO-DMRGW-01",     # 必须 FMO- 前缀（EMQX ACL 只放行 FMO-*）

    # ---- DMR（国服 mastra；凭据需自行填）----
    "dmr_master_host": "mastra.radiowo.com",
    "dmr_master_port": 62031,
    "dmr_gateway_id": 0,             # 7 位国服 ID（登录主站用）
    "dmr_password": "",              # 国服 DMR 密码（登录主站用）
    "dmr_essid": 0,                  # ESSID 后缀：0=直接用 7 位 ID；1..99 = ID×100+后缀
    "dmr_tg": 860562,                # 通话组（860562 安铜集群 / 8601 国服公共）
    "dmr_ts": 1,                     # 时隙：860 区 TG 用 TS1
    "dmr_cc": 1,                     # 色码

    # ---- USRP（DVSwitch：Analog_Bridge 的 rx/tx 端口）----
    "usrp_host": "127.0.0.1",
    "usrp_rx_port": 51000,           # 发往 Analog_Bridge
    "usrp_tx_port": 51001,           # 本地绑定，收 Analog_Bridge

    # ---- 会话行为 ----
    "ptt_timeout_ms": 800,           # FMO 侧静默多久判定松键
    "fmo_callsign": "DMRGW",         # 本网关发帧用的呼号（取主叫呼号更佳）
    "src_map": {},                   # FMO 呼号 -> DMR ID 覆盖表（可选）
    "state_path": "",                # 状态文件路径（留空=不写）

    # ---- 配置来源（总系统）----
    "master_admin_url": "",          # 如 http://127.0.0.1:35931
    "master_admin_token": "",        # 总系统管理令牌（如有）
    "config_refresh_sec": 30,        # 从总系统刷新配置的间隔
}

SAMPLE_RATE = 8000
BLOCK_SAMPLES = 640          # 一个 ADPCM 块 = 640 样本 = 80ms
BLOCKS_PER_FRAME = 3         # 一帧 3 块 = 240ms
USRP_CHUNK = 320             # USRP 语音包 = 160 样本 s16le = 20ms
FRAME_HEADER = 64

# USRP 包类型
USRP_TYPE_VOICE = 0
USRP_TYPE_DTMF = 1
USRP_TYPE_TEXT = 2
USRP_TYPE_PING = 3
USRP_TYPE_TLV = 4
TLV_TAG_SET_INFO = 8
TLV_TAG_REMOTE_CMD = 5


def fetch_master_gateways(cfg):
    """从总系统拉 DMR 网关配置列表（失败返回 None，由调用方兜底）。"""
    base = str(cfg.get("master_admin_url") or "").rstrip("/")
    if not base:
        return None
    url = base + "/api/dmr/gateways"
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "FUS-DMR-GW"})
        if cfg.get("master_admin_token"):
            req.add_header("X-Admin-Token", str(cfg["master_admin_token"]))
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
        gws = d.get("gateways")
        return gws if isinstance(gws, list) else None
    except Exception as e:  # noqa: BLE001
        log("从总系统拉取 DMR 网关配置失败: %s" % e)
        return None


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# ================================================================ IMA ADPCM
INDEX_TABLE = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8]

STEP_TABLE = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
    50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230,
    253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
    1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024,
    3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623,
    27086, 29794, 32767,
]


def _clamp(v, lo, hi):
    return lo if v < lo else (hi if v > hi else v)


def adpcm_decode(payload, valprev, index):
    """320B nibble payload → 640 个 s16 样本（高 nibble 在前，与 ImaAdpcm.kt 一致）。"""
    index = _clamp(index, 0, 88)
    out = []
    for byte in payload:
        for nib in (byte >> 4, byte & 0x0F):
            step = STEP_TABLE[index]
            diff = step >> 3
            if nib & 4:
                diff += step
            if nib & 2:
                diff += step >> 1
            if nib & 1:
                diff += step >> 2
            valprev = valprev - diff if (nib & 8) else valprev + diff
            valprev = _clamp(valprev, -32768, 32767)
            index = _clamp(index + INDEX_TABLE[nib], 0, 88)
            out.append(valprev)
    return out


def adpcm_encode(pcm, valprev, index):
    """640 样本 → (320B payload, 新 valprev, 新 index)。"""
    index = _clamp(index, 0, 88)
    nibbles = []
    for s in pcm:
        step = STEP_TABLE[index]
        diff = s - valprev
        nibble = 0
        if diff < 0:
            nibble = 8
            diff = -diff
        vpdiff = step >> 3
        if diff >= step:
            nibble |= 4
            diff -= step
            vpdiff += step
        if diff >= step >> 1:
            nibble |= 2
            diff -= step >> 1
            vpdiff += step >> 1
        if diff >= step >> 2:
            nibble |= 1
            vpdiff += step >> 2
        valprev = _clamp(valprev - vpdiff if nibble & 8 else valprev + vpdiff,
                         -32768, 32767)
        index = _clamp(index + INDEX_TABLE[nibble], 0, 88)
        nibbles.append(nibble)
    out = bytes(((nibbles[i * 2] & 0x0F) << 4) | (nibbles[i * 2 + 1] & 0x0F)
                for i in range(len(nibbles) // 2))
    return out, valprev, index


def adpcm_block(pcm, seq, valprev, index):
    """328B 块：8B 头 [seq,0x00,vp(s16LE),idx,0x00,0x40,0xAA] + 320B payload。"""
    payload, vp2, idx2 = adpcm_encode(pcm, valprev, index)
    head = struct.pack("<BBhBBBB", seq & 0xFF, 0x00, valprev, index & 0xFF,
                       0x00, 0x40, 0xAA)
    return head + payload, vp2, idx2


# ================================================================ FMO/RAW 帧
CONST5 = bytes([0x3D, 0x14, 0x00, 0xE0, 0x3D])


def make_block(idx, inner_type, payload):
    inner = bytes([inner_type]) + struct.pack("<H", 3 + 5 + len(payload)) \
        + CONST5 + payload
    return bytes([idx & 0xFF, 0x00]) + struct.pack("<H", 8 + len(inner)) \
        + b"\x00" * 4 + inner


def pack_frame(callsign, session, ts1, ts2, blocks, nblocks, buf_depth):
    cs = callsign.upper().encode("ascii", "ignore")[:6].ljust(6, b"\x00")
    return (
        bytes([0x01, 0, 0, 0, 0, 0])
        + struct.pack("<H", session)
        + b"\x00\x00"
        + cs
        + b"\x00" * 6
        + struct.pack("<III", ts1, ts2, FRAME_HEADER + len(blocks))
        + struct.pack("<H", nblocks)
        + struct.pack("<I", zlib.crc32(blocks) & 0xFFFFFFFF)
        + bytes([buf_depth & 0xFF, 0xBF, 0x01, 0x00])
        + b"\x00" * 20
        + blocks
    )


def parse_fmo_frame(data):
    """
    解析 FMO/RAW 帧 → (session, 呼号, blocks, stats)。

    blocks: [(valprev, index, 320B nibble payload), ...]  仅 ADPCM
    stats : {'adpcm': n, 'opus': m, 'other': k} 统计各 innerType 数量
    帧头 64B；块从偏移 64 起。
    ★ 呼号取 [10:22] 12 字节（真实硬件），按 NUL 截断（旧版只取 6 字节会截断长呼号）。
    """
    stats = {"adpcm": 0, "opus": 0, "other": 0}
    opus_pkts = []
    if not data or len(data) < FRAME_HEADER or data[0] != 0x01:
        return None
    session = struct.unpack_from("<H", data, 6)[0]
    call_raw = data[10:22] if len(data) >= 22 else data[10:16]
    call = call_raw.split(b"\x00", 1)[0].decode("ascii", "ignore")
    nblocks = struct.unpack_from("<H", data, 34)[0]
    blocks = []
    off = FRAME_HEADER
    for _ in range(nblocks):
        if off + 8 > len(data):
            break
        blen = struct.unpack_from("<H", data, off + 2)[0]
        inner = off + 8
        if inner + 8 > len(data) or blen < 16:
            break
        itype = data[inner]
        innerlen = struct.unpack_from("<H", data, inner + 1)[0]
        payload = data[inner + 8: inner + 8 + (innerlen - 8)]
        if itype == 0x02:
            stats["adpcm"] += 1
            if len(payload) >= 328:
                vp = struct.unpack_from("<h", payload, 2)[0]
                idx = payload[4]
                blocks.append((vp, idx, payload[8:328]))
        elif itype == 0x01:
            stats["opus"] += 1
            # Opus 载荷 = 裸 Opus 包（inner 去掉 type/len/CONST5 后即包体）
            if payload:
                opus_pkts.append(payload)
        else:
            stats["other"] += 1
        off = inner + blen - 8
    return session, call, blocks, stats, opus_pkts


# ================================================================ AMBE 声码器
# libfusambe.so：用 zig cc 从 OpenDMR（mbelib-neo 解码 + OP25 MBEEncoder 编码）
# 为群晖交叉编译的 Linux x86_64 库，导出 opendmr_* C API：
#   opendmr_encoder_create/destroy/reset
#   opendmr_encode(enc, const int16_t pcm[160], uint8_t ambe[9])
#   opendmr_decoder_create/destroy/reset
#   opendmr_decode(dec, const uint8_t ambe[9], int16_t pcm[160], int *errs)
# ★ 必须用 RTLD_GLOBAL 加载：库内有 C++ 静态对象，RTLD_LOCAL 下 encode 会卡死
#   （实测：RTLD_LOCAL 第一次 encode 就 60s 不返回；RTLD_GLOBAL 后 2ms/帧）。
class AmbeCodec:
    """PCM(160 样本, 8kHz) ↔ AMBE(9 字节) 双向编解码。"""

    def __init__(self, lib_path):
        self.ok = False
        self.err = ""
        try:
            import ctypes
            self._ct = ctypes
            lib = ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)
            P16 = ctypes.POINTER(ctypes.c_int16)
            PU8 = ctypes.POINTER(ctypes.c_uint8)
            lib.opendmr_encoder_create.restype = ctypes.c_void_p
            lib.opendmr_encoder_create.argtypes = []
            lib.opendmr_encoder_destroy.argtypes = [ctypes.c_void_p]
            lib.opendmr_encoder_reset.argtypes = [ctypes.c_void_p]
            lib.opendmr_encode.restype = ctypes.c_bool
            lib.opendmr_encode.argtypes = [ctypes.c_void_p, P16, PU8]
            lib.opendmr_decoder_create.restype = ctypes.c_void_p
            lib.opendmr_decoder_create.argtypes = []
            lib.opendmr_decoder_destroy.argtypes = [ctypes.c_void_p]
            lib.opendmr_decoder_reset.argtypes = [ctypes.c_void_p]
            lib.opendmr_decode.restype = ctypes.c_bool
            lib.opendmr_decode.argtypes = [ctypes.c_void_p, PU8, P16,
                                           ctypes.POINTER(ctypes.c_int32)]
            self._lib = lib
            self._P16 = P16
            self._PU8 = PU8
            self._enc = lib.opendmr_encoder_create()
            self._dec = lib.opendmr_decoder_create()
            if not self._enc or not self._dec:
                self.err = "encoder/decoder 创建失败"
                return
            self.ok = True
            log("AMBE 声码器就绪: %s（encode 实测约 2ms/帧）" % lib_path)
        except Exception as e:  # noqa: BLE001
            self.err = str(e)
            log("AMBE 声码器不可用: %s" % e)

    def encode(self, pcm160):
        """160 个 int16 PCM → 9 字节 AMBE；失败返回 None。"""
        if not self.ok or len(pcm160) != 160:
            return None
        try:
            pcm = (self._ct.c_int16 * 160)(*pcm160)
            ambe = (self._ct.c_uint8 * 9)()
            if self._lib.opendmr_encode(self._enc, pcm, ambe):
                return bytes(ambe)
        except Exception:  # noqa: BLE001
            return None
        return None

    def decode(self, ambe9):
        """9 字节 AMBE → 160 个 int16 PCM；失败返回 None。"""
        if not self.ok or len(ambe9) != 9:
            return None
        try:
            ambe = (self._ct.c_uint8 * 9)(*ambe9)
            pcm = (self._ct.c_int16 * 160)()
            errs = self._ct.c_int32(0)
            if self._lib.opendmr_decode(self._dec, ambe, pcm, self._ct.byref(errs)):
                return list(pcm)
        except Exception:  # noqa: BLE001
            return None
        return None


# ================================================================ Opus 解码
# 现网集群（FMO/RAW）实际发的是 **Opus（SILK NB 8kHz）**，不是 ADPCM。
# 真实故障：早期版本只支持 ADPCM，结果整段语音被丢弃（"累计丢弃 N 块"），
# FMO→DMR 完全没声音。这里用 libopus.so 解码（群晖实测可用）。
class OpusCodec:
    """Opus 包 → PCM(8kHz s16)，每包 40ms = 320 样本。"""

    def __init__(self, lib_path):
        self.ok = False
        self.err = ""
        try:
            import ctypes
            self._ct = ctypes
            lib = ctypes.CDLL(lib_path, mode=ctypes.RTLD_GLOBAL)
            lib.opus_decoder_create.restype = ctypes.c_void_p
            lib.opus_decoder_create.argtypes = [ctypes.c_int, ctypes.c_int,
                                                ctypes.POINTER(ctypes.c_int)]
            lib.opus_decode.restype = ctypes.c_int
            lib.opus_decode.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(ctypes.c_ubyte),
                                        ctypes.c_int32,
                                        ctypes.POINTER(ctypes.c_int16),
                                        ctypes.c_int, ctypes.c_int]
            lib.opus_decoder_destroy.argtypes = [ctypes.c_void_p]
            self._lib = lib
            err = ctypes.c_int(0)
            self._dec = lib.opus_decoder_create(8000, 1, ctypes.byref(err))
            if not self._dec:
                self.err = "opus_decoder_create 失败 err=%d" % err.value
                return
            self.ok = True
            log("Opus 解码器就绪: %s（8kHz 单声道，40ms/包）" % lib_path)
        except Exception as e:  # noqa: BLE001
            self.err = str(e)
            log("Opus 解码器不可用（语音若为 Opus 将无法转发）: %s" % e)

    def decode(self, pkt):
        """一个 Opus 包 → 320 个 int16 样本（40ms）；失败返回 None。"""
        if not self.ok or not pkt:
            return None
        try:
            buf = (self._ct.c_ubyte * len(pkt))(*pkt)
            pcm = (self._ct.c_int16 * 320)()
            n = self._lib.opus_decode(self._dec, buf, len(pkt), pcm, 320, 0)
            if n > 0:
                return list(pcm[:n])
        except Exception:  # noqa: BLE001
            return None
        return None


# ================================================================ DMR 编解码
# 以下从 app1 的 DmrCodec.kt 逐算法移植（DMR 空口 LC / BPTC / Golay / RS）。
# 目的：自己直接产出 DMRD 语音帧与 LC 头，不依赖 md380-emu / DVSwitch。
RS_POLY = (64, 56, 14, 1)

RS_EXP = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1D, 0x3A, 0x74, 0xE8, 0xCD, 0x87, 0x13, 0x26,
    0x4C, 0x98, 0x2D, 0x5A, 0xB4, 0x75, 0xEA, 0xC9, 0x8F, 0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0,
    0x9D, 0x27, 0x4E, 0x9C, 0x25, 0x4A, 0x94, 0x35, 0x6A, 0xD4, 0xB5, 0x77, 0xEE, 0xC1, 0x9F, 0x23,
    0x46, 0x8C, 0x05, 0x0A, 0x14, 0x28, 0x50, 0xA0, 0x5D, 0xBA, 0x69, 0xD2, 0xB9, 0x6F, 0xDE, 0xA1,
    0x5F, 0xBE, 0x61, 0xC2, 0x99, 0x2F, 0x5E, 0xBC, 0x65, 0xCA, 0x89, 0x0F, 0x1E, 0x3C, 0x78, 0xF0,
    0xFD, 0xE7, 0xD3, 0xBB, 0x6B, 0xD6, 0xB1, 0x7F, 0xFE, 0xE1, 0xDF, 0xA3, 0x5B, 0xB6, 0x71, 0xE2,
    0xD9, 0xAF, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0D, 0x1A, 0x34, 0x68, 0xD0, 0xBD, 0x67, 0xCE,
    0x81, 0x1F, 0x3E, 0x7C, 0xF8, 0xED, 0xC7, 0x93, 0x3B, 0x76, 0xEC, 0xC5, 0x97, 0x33, 0x66, 0xCC,
    0x85, 0x17, 0x2E, 0x5C, 0xB8, 0x6D, 0xDA, 0xA9, 0x4F, 0x9E, 0x21, 0x42, 0x84, 0x15, 0x2A, 0x54,
    0xA8, 0x4D, 0x9A, 0x29, 0x52, 0xA4, 0x55, 0xAA, 0x49, 0x92, 0x39, 0x72, 0xE4, 0xD5, 0xB7, 0x73,
    0xE6, 0xD1, 0xBF, 0x63, 0xC6, 0x91, 0x3F, 0x7E, 0xFC, 0xE5, 0xD7, 0xB3, 0x7B, 0xF6, 0xF1, 0xFF,
    0xE3, 0xDB, 0xAB, 0x4B, 0x96, 0x31, 0x62, 0xC4, 0x95, 0x37, 0x6E, 0xDC, 0xA5, 0x57, 0xAE, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xC8, 0x8D, 0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0xDD, 0xA7, 0x53, 0xA6,
    0x51, 0xA2, 0x59, 0xB2, 0x79, 0xF2, 0xF9, 0xEF, 0xC3, 0x9B, 0x2B, 0x56, 0xAC, 0x45, 0x8A, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3D, 0x7A, 0xF4, 0xF5, 0xF7, 0xF3, 0xFB, 0xEB, 0xCB, 0x8B, 0x0B, 0x16,
    0x2C, 0x58, 0xB0, 0x7D, 0xFA, 0xE9, 0xCF, 0x83, 0x1B, 0x36, 0x6C, 0xD8, 0xAD, 0x47, 0x8E, 0x01,
)
RS_LOG = (
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1A, 0xC6, 0x03, 0xDF, 0x33, 0xEE, 0x1B, 0x68, 0xC7, 0x4B,
    0x04, 0x64, 0xE0, 0x0E, 0x34, 0x8D, 0xEF, 0x81, 0x1C, 0xC1, 0x69, 0xF8, 0xC8, 0x08, 0x4C, 0x71,
    0x05, 0x8A, 0x65, 0x2F, 0xE1, 0x24, 0x0F, 0x21, 0x35, 0x93, 0x8E, 0xDA, 0xF0, 0x12, 0x82, 0x45,
    0x1D, 0xB5, 0xC2, 0x7D, 0x6A, 0x27, 0xF9, 0xB9, 0xC9, 0x9A, 0x09, 0x78, 0x4D, 0xE4, 0x72, 0xA6,
    0x06, 0xBF, 0x8B, 0x62, 0x66, 0xDD, 0x30, 0xFD, 0xE2, 0x98, 0x25, 0xB3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xD0, 0x94, 0xCE, 0x8F, 0x96, 0xDB, 0xBD, 0xF1, 0xD2, 0x13, 0x5C, 0x83, 0x38, 0x46, 0x40,
    0x1E, 0x42, 0xB6, 0xA3, 0xC3, 0x48, 0x7E, 0x6E, 0x6B, 0x3A, 0x28, 0x54, 0xFA, 0x85, 0xBA, 0x3D,
    0xCA, 0x5E, 0x9B, 0x9F, 0x0A, 0x15, 0x79, 0x2B, 0x4E, 0xD4, 0xE5, 0xAC, 0x73, 0xF3, 0xA7, 0x57,
    0x07, 0x70, 0xC0, 0xF7, 0x8C, 0x80, 0x63, 0x0D, 0x67, 0x4A, 0xDE, 0xED, 0x31, 0xC5, 0xFE, 0x18,
    0xE3, 0xA5, 0x99, 0x77, 0x26, 0xB8, 0xB4, 0x7C, 0x11, 0x44, 0x92, 0xD9, 0x23, 0x20, 0x89, 0x2E,
    0x37, 0x3F, 0xD1, 0x5B, 0x95, 0xBC, 0xCF, 0xCD, 0x90, 0x87, 0x97, 0xB2, 0xDC, 0xFC, 0xBE, 0x61,
    0xF2, 0x56, 0xD3, 0xAB, 0x14, 0x2A, 0x5D, 0x9E, 0x84, 0x3C, 0x39, 0x53, 0x47, 0x6D, 0x41, 0xA2,
    0x1F, 0x2D, 0x43, 0xD8, 0xB7, 0x7B, 0xA4, 0x76, 0xC4, 0x17, 0x49, 0xEC, 0x7F, 0x0C, 0x6F, 0xF6,
    0x6C, 0xA1, 0x3B, 0x52, 0x29, 0x9D, 0x55, 0xAA, 0xFB, 0x60, 0x86, 0xB1, 0xBB, 0xCC, 0x3E, 0x5A,
    0xCB, 0x59, 0x5F, 0xB0, 0x9C, 0xA9, 0xA0, 0x51, 0x0B, 0xF5, 0x16, 0xEB, 0x7A, 0x75, 0x2C, 0xD7,
    0x4F, 0xAE, 0xD5, 0xE9, 0xE6, 0xE7, 0xAD, 0xE8, 0x74, 0xD6, 0xF4, 0xEA, 0xA8, 0x50, 0x58, 0xAF,
)
# Golay(20,8,7) 时隙类型编码表（DmrCodec.kt ENCODING_TABLE_2087）
GOLAY_2087 = (
    0x0000, 0xB08E, 0xE093, 0x501D, 0x70A9, 0xC027, 0x903A, 0x20B4, 0x60DC, 0xD052, 0x804F, 0x30C1,
    0x1075, 0xA0FB, 0xF0E6, 0x4068, 0x7036, 0xC0B8, 0x90A5, 0x202B, 0x009F, 0xB011, 0xE00C, 0x5082,
    0x10EA, 0xA064, 0xF079, 0x40F7, 0x6043, 0xD0CD, 0x80D0, 0x305E, 0xD06C, 0x60E2, 0x30FF, 0x8071,
    0xA0C5, 0x104B, 0x4056, 0xF0D8, 0xB0B0, 0x003E, 0x5023, 0xE0AD, 0xC019, 0x7097, 0x208A, 0x9004,
    0xA05A, 0x10D4, 0x40C9, 0xF047, 0xD0F3, 0x607D, 0x3060, 0x80EE, 0xC086, 0x7008, 0x2015, 0x909B,
    0xB02F, 0x00A1, 0x50BC, 0xE032, 0x90D9, 0x2057, 0x704A, 0xC0C4, 0xE070, 0x50FE, 0x00E3, 0xB06D,
    0xF005, 0x408B, 0x1096, 0xA018, 0x80AC, 0x3022, 0x603F, 0xD0B1, 0xE0EF, 0x5061, 0x007C, 0xB0F2,
    0x9046, 0x20C8, 0x70D5, 0xC05B, 0x8033, 0x30BD, 0x60A0, 0xD02E, 0xF09A, 0x4014, 0x1009, 0xA087,
    0x40B5, 0xF03B, 0xA026, 0x10A8, 0x301C, 0x8092, 0xD08F, 0x6001, 0x2069, 0x90E7, 0xC0FA, 0x7074,
    0x50C0, 0xE04E, 0xB053, 0x00DD, 0x3083, 0x800D, 0xD010, 0x609E, 0x402A, 0xF0A4, 0xA0B9, 0x1037,
    0x505F, 0xE0D1, 0xB0CC, 0x0042, 0x20F6, 0x9078, 0xC065, 0x70EB, 0xA03D, 0x10B3, 0x40AE, 0xF020,
    0xD094, 0x601A, 0x3007, 0x8089, 0xC0E1, 0x706F, 0x2072, 0x90FC, 0xB048, 0x00C6, 0x50DB, 0xE055,
    0xD00B, 0x6085, 0x3098, 0x8016, 0xA0A2, 0x102C, 0x4031, 0xF0BF, 0xB0D7, 0x0059, 0x5044, 0xE0CA,
    0xC07E, 0x70F0, 0x20ED, 0x9063, 0x7051, 0xC0DF, 0x90C2, 0x204C, 0x00F8, 0xB076, 0xE06B, 0x50E5,
    0x108D, 0xA003, 0xF01E, 0x4090, 0x6024, 0xD0AA, 0x80B7, 0x3039, 0x0067, 0xB0E9, 0xE0F4, 0x507A,
    0x70CE, 0xC040, 0x905D, 0x20D3, 0x60BB, 0xD035, 0x8028, 0x30A6, 0x1012, 0xA09C, 0xF081, 0x400F,
    0x30E4, 0x806A, 0xD077, 0x60F9, 0x404D, 0xF0C3, 0xA0DE, 0x1050, 0x5038, 0xE0B6, 0xB0AB, 0x0025,
    0x2091, 0x901F, 0xC002, 0x708C, 0x40D2, 0xF05C, 0xA041, 0x10CF, 0x307B, 0x80F5, 0xD0E8, 0x6066,
    0x200E, 0x9080, 0xC09D, 0x7013, 0x50A7, 0xE029, 0xB034, 0x00BA, 0xE088, 0x5006, 0x001B, 0xB095,
    0x9021, 0x20AF, 0x70B2, 0xC03C, 0x8054, 0x30DA, 0x60C7, 0xD049, 0xF0FD, 0x4073, 0x106E, 0xA0E0,
    0x90BE, 0x2030, 0x702D, 0xC0A3, 0xE017, 0x5099, 0x0084, 0xB00A, 0xF062, 0x40EC, 0x10F1, 0xA07F,
    0x80CB, 0x3045, 0x6058, 0xD0D6,
)
SYNC_MASK = (0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0)
MS_DATA_SYNC = (0x0D, 0x5D, 0x7F, 0x77, 0xFD, 0x75, 0x70)
MS_AUDIO_SYNC = (0x07, 0xF7, 0xD5, 0xDD, 0x57, 0xDF, 0xD0)
VOICE_LC_CRC_MASK = (0x96, 0x96, 0x96)
TERM_LC_CRC_MASK = (0x99, 0x99, 0x99)
FLCO_GROUP = 0
FLCO_USER_USER = 3
DT_VOICE_LC_HEADER = 0x01
DT_TERMINATOR_WITH_LC = 0x02


def _gmult(a, b):
    if a == 0 or b == 0:
        return 0
    return RS_EXP[(RS_LOG[a & 0xFF] + RS_LOG[b & 0xFF]) % 255]


def _crs129_encode(msg):
    """9 字节 → RS(12,9) 校验 parity[0..3]（msg[9..11] 由调用方异或掩码）。"""
    parity = [0, 0, 0, 0]
    for i in range(9):
        dbyte = msg[i] ^ parity[2]
        for j in (2, 1):
            parity[j] = parity[j - 1] ^ _gmult(RS_POLY[j], dbyte)
        parity[0] = _gmult(RS_POLY[0], dbyte)
    return parity


def _h15113_2(d, off):
    d[off + 11] = d[off + 0] ^ d[off + 1] ^ d[off + 2] ^ d[off + 3] ^ d[off + 5] ^ d[off + 7] ^ d[off + 8]
    d[off + 12] = d[off + 1] ^ d[off + 2] ^ d[off + 3] ^ d[off + 4] ^ d[off + 6] ^ d[off + 8] ^ d[off + 9]
    d[off + 13] = d[off + 2] ^ d[off + 3] ^ d[off + 4] ^ d[off + 5] ^ d[off + 7] ^ d[off + 9] ^ d[off + 10]
    d[off + 14] = d[off + 0] ^ d[off + 1] ^ d[off + 2] ^ d[off + 4] ^ d[off + 6] ^ d[off + 7] ^ d[off + 10]


def _h1393(d):
    d[9] = d[0] ^ d[1] ^ d[3] ^ d[5] ^ d[6]
    d[10] = d[0] ^ d[1] ^ d[2] ^ d[4] ^ d[6] ^ d[7]
    d[11] = d[0] ^ d[1] ^ d[2] ^ d[3] ^ d[5] ^ d[7] ^ d[8]
    d[12] = d[0] ^ d[2] ^ d[4] ^ d[5] ^ d[8]


def _bptc19696_encode(in_data):
    """12 字节 LC 块 → 33 字节 DMR 负载（BPTC(196,96)）。"""
    b = [0] * 96
    for i in range(12):
        byte = in_data[i] & 0xFF
        for k in range(8):
            b[i * 8 + k] = 1 if byte & (0x80 >> k) else 0

    di = [0] * 196
    pos = 0
    # BPTC 数据放置位置（cbptc19696.cpp encodeExtractData 的 9 段）
    _seg = [(4, 12), (16, 27), (31, 42), (46, 57), (61, 72),
            (76, 87), (91, 102), (106, 117), (121, 132)]
    for _lo, _hi in _seg:
        for a in range(_lo, _hi):
            di[a] = b[pos]
            pos += 1

    for r in range(9):
        _h15113_2(di, r * 15 + 1)
    for c in range(15):
        col = [0] * 13
        p = c + 1
        for k in range(13):
            col[k] = di[p]
            p += 15
        _h1393(col)
        p = c + 1
        for k in range(13):
            di[p] = col[k]
            p += 15

    raw = [0] * 196
    for x in range(196):
        raw[(x * 181) % 196] = di[x]

    out = [0] * 33

    def bits_to_byte(off):
        v = 0
        for k in range(8):
            if raw[off + k]:
                v |= (0x80 >> k)
        return v

    for i in range(12):
        out[i] = bits_to_byte(i * 8)
    byte = bits_to_byte(96)
    out[12] = (out[12] & 0x3F) | (byte & 0xC0)
    out[20] = (out[20] & 0xFC) | ((byte >> 4) & 0x03)
    for i, off in enumerate((100, 108, 116, 124, 132, 140, 148, 156, 164, 172, 180, 188)):
        out[21 + i] = bits_to_byte(off)
    return out


def _get_slot_data(data, data_type, cc):
    """Golay(20,8,7) 时隙类型写入负载 [12..20]。"""
    st0 = ((cc << 4) & 0xF0) | (data_type & 0x0F)
    cksum = GOLAY_2087[st0 & 0xFF]
    st1 = cksum & 0xFF
    st2 = (cksum >> 8) & 0xFF
    data[12] = (data[12] & 0xC0) | ((st0 >> 2) & 0x3F)
    data[13] = (data[13] & 0x0F) | ((st0 << 6) & 0xC0) | ((st1 >> 2) & 0x30)
    data[19] = (data[19] & 0xF0) | ((st1 >> 2) & 0x0F)
    data[20] = (data[20] & 0x03) | ((st1 << 6) & 0xC0) | ((st2 >> 2) & 0x3C)


def _lc_get_data(flco, dst_id, src_id):
    return [
        flco & 0xFF, 0, 0,
        (dst_id >> 16) & 0xFF, (dst_id >> 8) & 0xFF, dst_id & 0xFF,
        (src_id >> 16) & 0xFF, (src_id >> 8) & 0xFF, src_id & 0xFF,
    ]


def encode_full_lc_payload(flco, dst_id, src_id, data_type, cc=1):
    """LC 头/结束帧 → 33 字节 DMR 负载（含数据同步字 + 时隙类型 + BPTC）。"""
    data = [0] * 33
    for i in range(7):
        data[i + 13] = (data[i + 13] & (SYNC_MASK[i] ^ 0xFF)) | MS_DATA_SYNC[i]
    lc = _lc_get_data(flco, dst_id, src_id)
    lc_data = list(lc) + [0, 0, 0]
    parity = _crs129_encode(lc_data)
    mask = VOICE_LC_CRC_MASK if data_type == DT_VOICE_LC_HEADER else TERM_LC_CRC_MASK
    lc_data[9] = parity[2] ^ mask[0]
    lc_data[10] = parity[1] ^ mask[1]
    lc_data[11] = parity[0] ^ mask[2]
    _get_slot_data(data, data_type, cc)
    data = _bptc19696_encode(lc_data)
    return data


def encode_voice_sync_payload(ambe27):
    """语音同步帧负载：音频同步字 + AMBE（27B → 33B）。"""
    data = [0] * 33
    for i in range(7):
        data[i + 13] = (data[i + 13] & (SYNC_MASK[i] ^ 0xFF)) | MS_AUDIO_SYNC[i]
    place_ambe_27(data, ambe27)
    return data


def encode_voice_payload(ambe27):
    """普通语音帧负载：AMBE（27B → 33B）。"""
    data = [0] * 33
    place_ambe_27(data, ambe27)
    return data


def place_ambe_27(payload, ambe27):
    """27 字节 AMBE（3×9）→ 33 字节 DMR 负载（DmrCodec.placeAmbe 逐位一致）。"""
    for i in range(13):
        payload[i] = ambe27[i] & 0xFF
    payload[13] = (payload[13] & 0xF0) | (ambe27[13] & 0xF0)
    payload[19] = (payload[19] & 0xF0) | (ambe27[13] & 0x0F)
    for i in range(13):
        payload[20 + i] = ambe27[14 + i] & 0xFF


def build_dmrd_frame(seq, src_id, dst_id, gw_id, flags, stream_id,
                     payload33, with_tail=True):
    """DMRD 帧：55B（带 BER/RSSI）或 53B（860 区 HBLink3 系）。"""
    f = bytearray(55)
    f[0:4] = b"DMRD"
    f[4] = seq & 0xFF
    f[5] = (src_id >> 16) & 0xFF
    f[6] = (src_id >> 8) & 0xFF
    f[7] = src_id & 0xFF
    f[8] = (dst_id >> 16) & 0xFF
    f[9] = (dst_id >> 8) & 0xFF
    f[10] = dst_id & 0xFF
    f[11] = (gw_id >> 24) & 0xFF
    f[12] = (gw_id >> 16) & 0xFF
    f[13] = (gw_id >> 8) & 0xFF
    f[14] = gw_id & 0xFF
    f[15] = flags & 0xFF
    f[16] = stream_id & 0xFF
    f[17] = (stream_id >> 8) & 0xFF
    f[18] = (stream_id >> 16) & 0xFF
    f[19] = (stream_id >> 24) & 0xFF
    for i in range(33):
        f[20 + i] = payload33[i] & 0xFF
    f[53] = 0
    f[54] = 0
    return bytes(f) if with_tail else bytes(f[:53])


# ================================================================ Homebrew 对端
# MMDVM/Homebrew 协议（DMR 主站 side），字节序列与 APP DmrClient.kt 一致：
#   RPTL+gwId → RPTACK+salt → RPTK+gwId+SHA256(salt+password) → RPTACK
#   → RPTC+gwId+294B 配置 → RPTACK（此时才真正连通）
#   → 每 5s RPTPING+gwId / MSTPONG+gwId；RPTCL+gwId 断开
class HomebrewPeer:
    """国服 DMR 主站（mastra.radiowo.com:62031）连接。"""

    def __init__(self, cfg, on_voice=None, on_info=None):
        self.cfg = cfg
        self.host = cfg.get("dmr_master_host", "mastra.radiowo.com")
        self.port = int(cfg.get("dmr_master_port", 62031))
        self.gw_id = int(cfg.get("dmr_gateway_id") or 0)
        self.password = str(cfg.get("dmr_password") or "")
        self.callsign = str(cfg.get("fmo_callsign", "DMRGW"))[:8]
        self.cc = int(cfg.get("dmr_cc", 1))
        self.slot = int(cfg.get("dmr_ts", 1))
        self.on_voice = on_voice
        self.on_info = on_info
        self.sock = None
        self.connected = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._ping_at = 0.0

    # ---------------- 发送 ----------------
    def _send(self, data):
        if self.sock:
            try:
                self.sock.sendto(data, (self.host, self.port))
            except OSError:
                pass

    def _be32(self, v):
        return struct.pack(">I", v & 0xFFFFFFFF)

    def _login(self):
        self._send(b"RPTL" + self._be32(self.gw_id))

    def _key(self, salt):
        import hashlib
        md = hashlib.sha256()
        md.update(salt)
        md.update(self.password.encode("utf-8"))
        return b"RPTK" + self._be32(self.gw_id) + md.digest()

    def _config(self):
        """RPTC 294B 定宽 ASCII 配置（DmrClient.kt buildRptc）。"""
        import datetime
        s = "%-8.8s%09d%09d%02d%02d%8.8s%9.9s%03d%-20.20s%-19.19s%c%-124.124s%-40.40s%-40.40s" % (
            self.callsign, 432000000, 432000000, 1, self.cc,
            "", "", 0, "", "", '4', "",
            datetime.date.today().strftime("%Y%m%d"), "MMDVM")
        b = s.encode("ascii", "replace")
        return b[:294].ljust(294, b" ")

    def _ping(self):
        self._send(b"RPTPING" + self._be32(self.gw_id))
        self._ping_at = time.monotonic()

    def _logout(self):
        self._send(b"RPTCL" + self._be32(self.gw_id))

    def send_voice(self, payload33, dmrcnt, src_id, dst_id, flags, stream_id):
        f = build_dmrd_frame(dmrcnt, src_id, dst_id, self.gw_id, flags,
                             stream_id, payload33)
        self._send(f)

    # ---------------- 状态 ----------------
    @property
    def state(self):
        if not self.sock:
            return "idle"
        return "connected" if self.connected else "handshake"

    # ---------------- 后台循环 ----------------
    def run(self):
        backoff = 3.0
        hs = 0
        salt = b""
        while not self._stop.is_set():
            if self.sock is None:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.5)
                    s.bind(("0.0.0.0", 0))
                    self.sock = s
                    self.connected = False
                    hs = 0
                    log("DMR 连接 %s:%s（网关 ID %s）" % (self.host, self.port, self.gw_id))
                    self._login()
                except OSError as e:
                    log("DMR socket 失败: %s" % e)
                    self._stop.wait(backoff)
                    backoff = min(backoff * 2, 60.0)
                    continue
            # 读包
            try:
                data, _addr = self.sock.recvfrom(2048)
            except socket.timeout:
                data = None
            except OSError:
                data = b""
            if data == b"":
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
                self._stop.wait(2.0)
                continue
            if data:
                tag = data[:6]
                if tag == b"RPTACK":
                    hs += 1
                    if hs == 1:
                        salt = data[6:]
                        self._send(self._key(salt))
                    elif hs == 2:
                        self._send(b"RPTC" + self._be32(self.gw_id) + self._config())
                    elif hs == 3:
                        self.connected = True
                        backoff = 3.0
                        log("DMR 主站已连通（握手完成）：TG %s / TS%s"
                            % (self.cfg.get("dmr_tg"), self.slot))
                        self._ping()
                elif tag == b"MSTPONG":
                    self._ping_at = 0.0
                elif tag in (b"MSTNAK", b"RPTNAK"):
                    log("DMR 主站拒绝登录（%s）：网关 ID=%s 主机=%s:%s —— "
                        "请核对 ① 国服 ID 是否为 7 位 ② DMR 密码是否正确 "
                        "③ 该 ID 是否已在国服注册热点 ④ ESSID 后缀(%s)"
                        % (data[:6].decode("ascii", "replace"), self.gw_id,
                           self.host, self.port, self.cfg.get("dmr_essid", 0)))
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
                    self._stop.wait(10.0)
                    continue
                elif tag == b"MSTCL":
                    log("DMR 主站关闭了会话")
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
                    continue
                elif data[:4] == b"DMRD":
                    try:
                        self._on_dmrd(data)
                    except Exception as e:  # noqa: BLE001
                        log("DMRD 处理异常: %s" % e)
            # 心跳 / 超时重连
            now = time.monotonic()
            if self.connected:
                if self._ping_at and now - self._ping_at > 15:
                    log("DMR 心跳超时，重连")
                    try:
                        self.sock.close()
                    except OSError:
                        pass
                    self.sock = None
                    continue
                if now - self._ping_at >= 5:
                    self._ping()
            elif now - self._ping_at > 10:
                # 握手卡住：重来
                hs = 0
                self._login()

    def _on_dmrd(self, data):
        if len(data) < 53:
            return
        src = (data[5] << 16) | (data[6] << 8) | data[7]
        dst = (data[8] << 16) | (data[9] << 8) | data[10]
        flags = data[15]
        slot = 2 if (flags & 0x80) else 1
        payload = data[20:53]
        if self.on_voice:
            self.on_voice(payload, src, dst, slot, flags)

    def stop(self):
        self._stop.set()
        try:
            self._logout()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


# ================================================================ USRP
class UsrpLink:
    """Analog_Bridge 的 USRP 客户端（32B 大端头 + 载荷）。"""

    def __init__(self, host, rx_port, tx_port):
        self.host = host
        self.rx_port = int(rx_port)
        self.tx_port = int(tx_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.tx_port))
        self.sock.settimeout(0.5)
        self.seq = 0
        self.registered = threading.Event()
        self._lock = threading.Lock()

    def _send(self, packet):
        self.sock.sendto(packet, (self.host, self.rx_port))

    def send_voice(self, keyup, audio):
        """语音包：type=0，载荷 320B(160 样本 s16le)；keyup 映射 PTT。"""
        with self._lock:
            pkt = b"USRP" + struct.pack(">iiiiiii", self.seq & 0xFFFF, 0,
                                        1 if keyup else 0, 0,
                                        USRP_TYPE_VOICE, 0, 0) + audio
            self.seq = (self.seq + 1) & 0xFFFF
        self._send(pkt)

    def send_command(self, cmd, packet_type):
        """命令包：type 字段填 packetType<<24（大端打包后落在 int32 高字节）。"""
        with self._lock:
            pkt = b"USRP" + struct.pack(">iiiiiii", self.seq & 0xFFFF, 0, 0, 0,
                                        packet_type << 24, 0, 0) + cmd
            self.seq = (self.seq + 1) & 0xFFFF
        self._send(pkt)

    def send_remote_ascii(self, cmd):
        tlv = struct.pack("BB", TLV_TAG_REMOTE_CMD, len(cmd)) + cmd.encode("ascii")
        self.send_command(tlv, USRP_TYPE_TLV)

    def register(self):
        self.send_command(b"REG:DVSWITCH", USRP_TYPE_TEXT)

    def configure(self, cfg):
        """注册成功后下发工作参数（AMBE 模式 / DMR ID / TG / 时隙）。"""
        gw = int(cfg.get("dmr_gateway_id") or 0)
        if gw <= 0:
            log("未配置 dmr_gateway_id，跳过 USRP 参数下发（仅注册）")
            return
        for cmd in ("ambeMode=DMR", "ambeSize=72",
                    "gateway_dmr_id=%d" % gw,
                    "txTg=%d" % int(cfg.get("dmr_tg") or 0),
                    "txTs=%d" % int(cfg.get("dmr_ts") or 1),
                    "tgs=%d" % int(cfg.get("dmr_tg") or 0)):
            self.send_remote_ascii(cmd)
        log("已下发 DMR 参数：TG %s / TS%s" % (cfg.get("dmr_tg"), cfg.get("dmr_ts")))

    def recv_packet(self, timeout=0.5):
        """收一个 USRP 包 → (ptype, keyup, payload) 或 None。"""
        try:
            data, _addr = self.sock.recvfrom(2048)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(data) < 32 or data[0:4] != b"USRP":
            return None
        keyup = struct.unpack(">i", data[12:16])[0]
        ptype = data[20]
        return ptype, keyup, data[32:]


# ================================================================ 网关主体
class DmrGateway(threading.Thread):
    """FMO 集群语音 ↔ 国服 DMR 双向网关。"""

    def __init__(self, cfg):
        threading.Thread.__init__(self, daemon=True)
        self.cfg = cfg
        self._cfg_lock = threading.Lock()
        self.usrp = UsrpLink(cfg.get("usrp_host", "127.0.0.1"),
                             cfg.get("usrp_rx_port", 51000),
                             cfg.get("usrp_tx_port", 51001))
        self.client = None
        self._stop = threading.Event()

        # ---- FMO→DMR ----
        self.tx_queue = deque()       # 待发 320B PCM
        self.tx_active = False
        self.tx_last_frame = 0.0
        self.tx_session = None
        self.tx_lock = threading.Lock()
        self._tx_frames = 0           # 已转发的 FMO 帧数
        self._tx_dropped_opus = 0     # 因 Opus 未解码而丢弃的块数
        self._tx_dmr_id = 0           # 当前会话用的 DMR ID

        # ---- DMR→FMO ----
        self.rx_pcm = []
        self.rx_valprev = 0
        self.rx_index = 0
        self.rx_seq = 0
        self.rx_session = None
        self.rx_ts1 = 0
        self.rx_blocks_sent = 0
        self.rx_frame_count = 0
        self.rx_callsign = cfg.get("fmo_callsign", "DMRGW")
        self.published_sessions = set()
        self._rx_frames = 0           # 已回灌集群的 FMO 帧数

        # ---- 音频/链路 ----
        self.ambe = AmbeCodec(cfg.get("ambe_lib") or
                              os.path.join(_HERE, "lib", "libfusambe.so"))
        self.opus = OpusCodec(cfg.get("opus_lib") or
                              os.path.join(_HERE, "lib", "libopus.so"))
        self.peer = None
        self._ambe_buf = []       # 待组帧的 9B AMBE
        self._dmrcnt = 0
        self._stream_id = 0
        self._state_path = cfg.get("state_path") or ""
        self._last_state_write = 0.0

    # -------------------------------------------------- 工具
    def _dmr_id_for(self, callsign):
        """FMO 呼号 → DMR ID（srcId）。优先级：配置映射 > 网关 ID > 0。"""
        m = self.cfg.get("src_map") or {}
        cs = (callsign or "").upper()
        if cs in m:
            return int(m[cs] or 0)
        gw = int(self.cfg.get("dmr_gateway_id") or 0)
        return gw

    def _note_inbound(self, sid):
        pass

    def _write_state(self):
        """把运行状态写成 JSON（界面/排障用；留空则不写）。"""
        if not self._state_path:
            return
        now = time.time()
        if now - self._last_state_write < 5:
            return
        self._last_state_write = now
        try:
            st = {
                "ts": now,
                "dmr_connected": bool(self.peer and self.peer.connected),
                "ambe_ok": bool(self.ambe and self.ambe.ok),
                "opus_ok": bool(getattr(self, "opus", None) and self.opus.ok),
                "mqtt_connected": bool(self.client and self.client._sock),
                "tx_frames": self._tx_frames,
                "tx_dropped_opus": self._tx_dropped_opus,
                "rx_frames": self._rx_frames,
                "tx_active": self.tx_active,
                "rx_active": self.rx_session is not None,
                "tg": self.cfg.get("dmr_tg"),
                "ts": self.cfg.get("dmr_ts"),
                "gateway_id": self.cfg.get("dmr_gateway_id"),
            }
            tmp = self._state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._state_path)
        except Exception:
            pass

    # -------------------------------------------------- FMO → DMR
    def on_mqtt_message(self, topic, payload):
        parsed = parse_fmo_frame(payload)
        if parsed is None:
            return
        if len(parsed) == 5:
            session, call, blocks, stats, opus_pkts = parsed
        else:                                   # 兼容旧 4 元组
            session, call, blocks, stats = parsed
            opus_pkts = []
        # 回环过滤：自己发出去的帧不要又转回去
        if (call or "").upper() == (self.cfg.get("fmo_callsign") or "DMRGW").upper():
            return
        if session in self.published_sessions:
            return
        # ★ Opus 段：解码后照常转发（不再丢弃）
        if opus_pkts and getattr(self, "opus", None) is not None and self.opus.ok:
            with self.tx_lock:
                if not self.tx_active or self.tx_session != session:
                    self.tx_active = True
                    self.tx_session = session
                    self._tx_dmr_id = self._dmr_id_for(call)
                    self.on_new_tx()
                    log("FMO→DMR 会话开始（Opus）：%s session=%s → DMR ID %s"
                        % (call or "?", session, self._tx_dmr_id))
                self.tx_last_frame = time.monotonic()
                self._tx_frames += 1
                for pkt in opus_pkts:
                    pcm = self.opus.decode(pkt)       # 320 样本 = 40ms
                    if not pcm:
                        continue
                    for i in range(0, len(pcm), 160):  # 切成 20ms
                        chunk = pcm[i:i + 160]
                        if len(chunk) < 160:
                            chunk = chunk + [0] * (160 - len(chunk))
                        self.tx_queue.append(struct.pack("<160h", *chunk))
            return
        if not blocks:
            if stats.get("opus"):
                self._tx_dropped_opus += stats["opus"]
                log("FMO→DMR：Opus 段但解码器不可用（%s），丢弃 %d 包"
                    % (getattr(self.opus, "err", "未加载"), self._tx_dropped_opus))
            return
        with self.tx_lock:
            if not self.tx_active or self.tx_session != session:
                self.tx_active = True
                self.tx_session = session
                self._tx_dmr_id = self._dmr_id_for(call)
                self.on_new_tx()          # 换 streamId、清 AMBE 缓冲
                log("FMO→DMR 会话开始：%s session=%s → DMR ID %s"
                    % (call or "?", session, self._tx_dmr_id))
            self.tx_last_frame = time.monotonic()
            self._tx_frames += 1
            for valprev, index, nibbles in blocks:
                pcm = adpcm_decode(nibbles, valprev, index)   # 640 样本
                for i in range(0, len(pcm), 160):
                    chunk = pcm[i:i + 160]
                    if len(chunk) < 160:
                        chunk = chunk + [0] * (160 - len(chunk))
                    self.tx_queue.append(struct.pack("<160h", *chunk))

    def tx_tick(self):
        """
        20ms 绝对节拍：FMO→DMR 发送。
        队列里是 320B PCM(160 样本)；本函数每 tick 取一块编码为 9B AMBE，
        每 3 块(60ms) 组一个 DMRD 语音帧；dmrcnt=0 发 LC 头，之后每 6 帧
        插一个音频同步帧；PTT 结束补一个 TERMINATOR_WITH_LC。
        """
        next_tick = time.monotonic()
        timeout_ms = int(self.cfg.get("ptt_timeout_ms", 800))
        self._ambe_buf = []
        self._dmrcnt = 0
        self._stream_id = 0
        while not self._stop.is_set():
            next_tick += 0.02
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()
            peer = self.peer
            if peer is None or not peer.connected:
                continue
            with self.tx_lock:
                timed_out = self.tx_active and \
                    (time.monotonic() - self.tx_last_frame) * 1000 > timeout_ms
                chunk = self.tx_queue.popleft() if self.tx_queue else None
                active = self.tx_active
                if timed_out:
                    self.tx_active = False
                    log("FMO→DMR 会话结束（静默超时松键）")

            if not active:
                # 松键：补 EOT
                if self._ambe_buf or self._dmrcnt:
                    self._flush_eot()
                continue
            if chunk is None:
                chunk = b"\x00" * USRP_CHUNK     # PTT 期间补静音保流
            pcm = list(struct.unpack("<160h", chunk))
            ambe = self.ambe.encode(pcm)
            if ambe is None:
                continue
            self._ambe_buf.append(ambe)
            if len(self._ambe_buf) >= 3:
                self._emit_dmrd(bytes(b"".join(self._ambe_buf[:3])))
                self._ambe_buf = self._ambe_buf[3:]
            self._write_state()

    def _emit_dmrd(self, ambe27):
        """发一个 DMRD 语音帧（LC 头 / 同步帧 / 普通语音帧）。"""
        peer = self.peer
        if peer is None or not peer.connected:
            return
        n = self._dmrcnt
        src_id = self._tx_dmr_id or int(self.cfg.get("dmr_gateway_id") or 0)
        dst_id = int(self.cfg.get("dmr_tg") or 0)
        slot_bit = 0x80 if int(self.cfg.get("dmr_ts", 1)) == 2 else 0
        flco = FLCO_GROUP
        if n == 0:
            payload = encode_full_lc_payload(flco, dst_id, src_id,
                                             DT_VOICE_LC_HEADER, self.cfg.get("dmr_cc", 1))
            flags = 0x01 | slot_bit
            log("FMO→DMR 发起通话：DMR ID %s → TG %s TS%s"
                % (src_id, dst_id, self.cfg.get("dmr_ts", 1)))
        else:
            ndmr = (n - 1) % 6
            if ndmr == 0:
                payload = encode_voice_sync_payload(ambe27)
                flags = 0x10 | slot_bit
            else:
                payload = encode_voice_payload(ambe27)
                flags = (ndmr & 0x07) | slot_bit
        peer.send_voice(payload, n, src_id, dst_id, flags, self._stream_id)
        self._dmrcnt = (n + 1) & 0xFF
        self._tx_frames += 1

    def _flush_eot(self):
        """松键：补 TERMINATOR_WITH_LC（缺的 AMBE 用静音补齐）。"""
        peer = self.peer
        if peer is None or not peer.connected:
            self._ambe_buf = []
            self._dmrcnt = 0
            return
        while self._ambe_buf:
            take = self._ambe_buf[:3]
            take += [b"\x00" * 9] * (3 - len(take))
            self._emit_dmrd(bytes(b"".join(take)))
            self._ambe_buf = self._ambe_buf[3:]
        src_id = self._tx_dmr_id or int(self.cfg.get("dmr_gateway_id") or 0)
        dst_id = int(self.cfg.get("dmr_tg") or 0)
        slot_bit = 0x80 if int(self.cfg.get("dmr_ts", 1)) == 2 else 0
        payload = encode_full_lc_payload(FLCO_GROUP, dst_id, src_id,
                                         DT_TERMINATOR_WITH_LC,
                                         self.cfg.get("dmr_cc", 1))
        peer.send_voice(payload, self._dmrcnt, src_id, dst_id,
                        0x02 | slot_bit, self._stream_id)
        self._dmrcnt = 0
        self._ambe_buf = []

    def on_new_tx(self):
        """新 FMO 会话开始：换 streamId、清 AMBE 缓冲。"""
        import random
        self._stream_id = random.getrandbits(32)
        self._ambe_buf = []
        self._dmrcnt = 0

    # -------------------------------------------------- DMR → FMO
    def _emit_frame(self, frame_blocks):
        ts2 = (self.rx_ts1 + self.rx_blocks_sent * 80) & 0xFFFFFFFF
        buf_depth = 0 if self.rx_frame_count < 3 else 9
        blocks = b"".join(make_block(i + 1, 0x02, b)
                          for i, b in enumerate(frame_blocks))
        frame = pack_frame(self.rx_callsign, self.rx_session, self.rx_ts1,
                           ts2, blocks, len(frame_blocks), buf_depth)
        if self.client:
            try:
                self.client.publish(self.cfg.get("pub_topic", "FMO/RAW"),
                                    payload=frame, qos=0)
            except Exception as e:
                log("DMR→FMO 发布失败: %s" % e)
                return
        self.published_sessions.add(self.rx_session)
        if len(self.published_sessions) > 64:
            self.published_sessions.clear()
        self.rx_blocks_sent += len(frame_blocks)
        self.rx_frame_count += 1
        self._rx_frames += 1

    def begin_rx(self, call):
        self.rx_pcm = []
        self.rx_valprev = 0
        self.rx_index = 0
        self.rx_seq = 0
        self.rx_session = int(time.time_ns() // 1000) & 0xFFFF or 1
        self.rx_ts1 = int(time.time() * 1000) & 0xFFFFFFFF
        self.rx_blocks_sent = 0
        self.rx_frame_count = 0
        cs = (call or self.cfg.get("fmo_callsign", "DMRGW")).upper()
        cs = cs.encode("ascii", "ignore")[:6].decode("ascii")
        self.rx_callsign = cs or self.cfg.get("fmo_callsign", "DMRGW")
        log("DMR→FMO 会话开始：%s → %s" % (call or "?", self.cfg.get("pub_topic")))

    def end_rx(self):
        if self.rx_session is None:
            return
        if self.rx_pcm:
            self.rx_pcm += [0] * ((-len(self.rx_pcm)) % BLOCK_SAMPLES)
            tail = []
            for off in range(0, len(self.rx_pcm), BLOCK_SAMPLES):
                blk, self.rx_valprev, self.rx_index = adpcm_block(
                    self.rx_pcm[off:off + BLOCK_SAMPLES], self.rx_seq,
                    self.rx_valprev, self.rx_index)
                self.rx_seq = (self.rx_seq + 1) & 0xFF
                tail.append(blk)
            while tail:
                n = min(BLOCKS_PER_FRAME, len(tail))
                self._emit_frame(tail[:n])
                del tail[:n]
        log("DMR→FMO 会话结束：共 %d 帧" % self.rx_frame_count)
        self.rx_pcm = []
        self.rx_session = None
        self._write_state()

    def on_usrp_packet(self, ptype, keyup, payload):
        if ptype == USRP_TYPE_TEXT:
            if payload[0:4] == b"REG:":
                if payload[4:6] == b"OK":
                    if not self.usrp.registered.is_set():
                        self.usrp.registered.set()
                        log("已在 Analog_Bridge 注册成功（REG OK）")
                        self.usrp.configure(self.cfg)
                elif payload[4:9] == b"UNREG":
                    self.usrp.registered.clear()
                    log("Analog_Bridge 要求注销，将重新注册")
            elif payload and payload[0] == TLV_TAG_SET_INFO and len(payload) >= 15:
                rid = (payload[2] << 16) | (payload[3] << 8) | payload[4]
                tg = (payload[9] << 16) | (payload[10] << 8) | payload[11]
                slot = payload[12]
                private = bool(payload[13] & 0x80)
                call = ""
                if payload[14] != 0:
                    call = payload[14:payload.find(b"\x00", 14)].decode("ascii", "ignore")
                log("DMR 来波：%s → TG %s slot%s%s"
                    % (call or rid, tg, slot, "（私呼）" if private else ""))
                if self.rx_session is None:
                    self.begin_rx(call or str(rid))
            return
        if ptype != USRP_TYPE_VOICE:
            return
        if len(payload) != USRP_CHUNK:
            return
        if keyup and self.rx_session is None:
            self.begin_rx(self.cfg.get("fmo_callsign", "DMRGW"))
        if self.rx_session is None:
            return
        samples = struct.unpack("<160h", payload)
        self.rx_pcm.extend(samples)
        while len(self.rx_pcm) >= BLOCK_SAMPLES * BLOCKS_PER_FRAME:
            frame_pcm = self.rx_pcm[:BLOCK_SAMPLES * BLOCKS_PER_FRAME]
            del self.rx_pcm[:BLOCK_SAMPLES * BLOCKS_PER_FRAME]
            blocks = []
            for off in range(0, len(frame_pcm), BLOCK_SAMPLES):
                blk, self.rx_valprev, self.rx_index = adpcm_block(
                    frame_pcm[off:off + BLOCK_SAMPLES], self.rx_seq,
                    self.rx_valprev, self.rx_index)
                self.rx_seq = (self.rx_seq + 1) & 0xFF
                blocks.append(blk)
            self._emit_frame(blocks)
        if not keyup:
            self.end_rx()

    # -------------------------------------------------- USRP 收包循环
    def usrp_recv_loop(self):
        while not self._stop.is_set():
            pkt = self.usrp.recv_packet(timeout=0.5)
            if pkt is None:
                continue
            ptype, keyup, payload = pkt
            try:
                self.on_usrp_packet(ptype, keyup, payload)
            except Exception as e:
                log("USRP 包处理异常: %s" % e)

    # -------------------------------------------------- DMR → FMO
    def on_dmrd_voice(self, payload33, src, dst, slot, flags):
        """对端 DMRD 语音 → 解 AMBE → PCM → ADPCM → FMO/RAW 帧。"""
        # 只收本 TG（或目标为我们的私呼）
        want_tg = int(self.cfg.get("dmr_tg") or 0)
        if want_tg and dst not in (want_tg, self._tx_dmr_id):
            return
        if (flags & 0x01) and self.rx_session is None:
            self.begin_rx(str(src))
        if self.rx_session is None:
            return
        # 33B 负载 → 27B AMBE（placeAmbe 逆运算）
        ambe27 = bytearray(27)
        for i in range(13):
            ambe27[i] = payload33[i]
        ambe27[13] = (payload33[13] & 0xF0) | (payload33[19] & 0x0F)
        for i in range(13):
            ambe27[14 + i] = payload33[20 + i]
        for i in range(3):
            ambe9 = bytes(ambe27[i * 9:(i + 1) * 9])
            pcm = self.ambe.decode(ambe9)
            if pcm:
                self.rx_pcm.extend(pcm)
        if (flags & 0x02):                      # EOT
            self.end_rx()

    # -------------------------------------------------- 注册维护
    def registration_loop(self):
        while not self._stop.is_set():
            if not self.usrp.registered.is_set():
                try:
                    self.usrp.register()
                except OSError:
                    pass
                self._stop.wait(2.0)
            else:
                self._stop.wait(5.0)

    # -------------------------------------------------- MQTT
    def _build_credentials(self):
        """构造与桥接一致的 MQTT 凭证（呼号 SERVER + 证书 CBOR 证明）。"""
        if not _HAVE_CRED:
            return None, None
        try:
            mc = load_probe_cert(_HERE)
            if not mc:
                return None, None
            return build_probe_credentials(
                mc, self.cfg.get("mqtt_host", "127.0.0.1"),
                int(self.cfg.get("mqtt_port", 1883)), role="bridge")
        except Exception as e:
            log("构造 MQTT 凭证失败: %s" % e)
            return None, None

    def start_mqtt(self):
        if not _HAVE_MQTT:
            log("monitor.MqttMiniClient 不可用，无法启动 MQTT")
            return False
        user, pw = self._build_credentials()
        if not user:
            log("拿不到证书凭证（ca/monitor_cert.json 缺失？）—— 稍后自动重试")
        cid = self.cfg.get("client_id", "FMO-DMRGW-01")
        try:
            self.client = MqttMiniClient(
                self.cfg.get("mqtt_host", "127.0.0.1"),
                int(self.cfg.get("mqtt_port", 1883)),
                cid, username=user, password=pw,
                keepalive=60,
                # ★ 下行 PUBLISH 直接喂给桥接逻辑（签名 (topic, payload) ✓）
                on_message=self.on_mqtt_message,
                read_timeout=0.5, target="本机")
        except Exception as e:
            log("创建 MQTT 客户端失败: %s" % e)
            return False
        return True

    # -------------------------------------------------- 主循环
    def reconfigure(self, new_cfg):
        """hot-reload config (affects future connections only)."""
        with self._cfg_lock:
            self.cfg = dict(new_cfg)
        pr = new_cfg.get("peer")
        if pr is not None:
            try:
                pr.cfg = dict(new_cfg)
            except Exception:  # noqa: BLE001
                pass
        log("gateway %s config updated (TG%s/TS%s id=%s)"
            % (new_cfg.get("gw_id", ""), new_cfg.get("dmr_tg"),
               new_cfg.get("dmr_ts"), new_cfg.get("dmr_gateway_id")))

    def run(self):
        cfg = self.cfg
        log("FMO↔DMR 网关启动：MQTT %s:%s 主题 %s → USRP %s:%s → DMR TG%s/TS%s"
            % (cfg.get("mqtt_host"), cfg.get("mqtt_port"),
               cfg.get("sub_topic"), cfg.get("usrp_host"),
               cfg.get("usrp_rx_port"), cfg.get("dmr_tg"), cfg.get("dmr_ts")))

        threading.Thread(target=self.tx_tick, name="tx-tick",
                         daemon=True).start()

        # DMR 主站连接（Homebrew 握手 + DMRD 收发）
        if not self.ambe.ok:
            log("★ AMBE 声码器不可用（%s），FMO→DMR 发送与 DMR→FMO 解码都不可用"
                % self.ambe.err)
        if int(cfg.get("dmr_gateway_id") or 0) <= 0 or not str(cfg.get("dmr_password") or ""):
            log("★ 未配置 dmr_gateway_id / dmr_password，DMR 侧不连接"
                "（在 fus_dmr_gw.json 里填国服 ID 与 DMR 密码）")
        else:
            self.peer = HomebrewPeer(cfg, on_voice=self.on_dmrd_voice)
            threading.Thread(target=self.peer.run, name="dmr-peer",
                             daemon=True).start()

        # MQTT 连接 + 断线重连（带退避）
        backoff = 2.0
        while not self._stop.is_set():
            if not self.start_mqtt():
                self._stop.wait(5.0)
                continue
            try:
                self.client.connect()
                log("MQTT 已连接 %s:%s" % (cfg.get("mqtt_host"),
                                           cfg.get("mqtt_port")))
            except Exception as e:
                log("MQTT 连接失败（%.0fs 后重试）: %s" % (backoff, e))
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = 2.0
            try:
                codes = self.client.subscribe([cfg.get("sub_topic", "FMO/RAW")],
                                              wait=True)
                log("已订阅 %s（SUBACK=%s）" % (cfg.get("sub_topic"), codes))
            except Exception as e:
                log("订阅失败: %s" % e)
            # 在线期间：轮询 + 周期性写状态 + 断线检测
            while not self._stop.is_set():
                try:
                    self.client.poll_once()
                except Exception as e:
                    log("MQTT 读取异常（将重连）: %s" % e)
                    break
                self._write_state()
                self._stop.wait(0.01)
            try:
                self.client.disconnect()
            except Exception:
                pass
            log("MQTT 断开，2s 后重连")
            self._stop.wait(2.0)

    def stop(self):
        self._stop.set()


# ================================================================ 入口
def load_config(path):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            if isinstance(data, dict):
                cfg.update(data)
            log("已加载配置: %s" % path)
        except Exception as e:
            log("读取配置失败（用默认值）: %s" % e)
    else:
        log("配置文件不存在，使用默认值: %s" % (path or "(未指定)"))
    return cfg


def _gateway_cfg(base, gw):
    """把总系统下发的一条网关配置合并成本地配置字典。"""
    cfg = dict(base)
    cfg.update({
        "gw_id": gw.get("id") or "",
        "cluster_id": gw.get("cluster_id") or 0,
        "gw_name": gw.get("name") or "",
        # MQTT 桥接账号密码（总系统 UI 里配）
        "mqtt_user": gw.get("mqtt_user") or "SERVER",
        "mqtt_password": gw.get("mqtt_password") or "",
        # 国服
        "dmr_master_host": gw.get("dmr_master_host") or "mastra.radiowo.com",
        "dmr_master_port": int(gw.get("dmr_master_port") or 62031),
        "dmr_gateway_id": int(gw.get("dmr_gateway_id") or 0),
        "dmr_password": gw.get("dmr_password") or "",
        "dmr_tg": int(gw.get("dmr_tg") or 0),
        "dmr_ts": int(gw.get("dmr_ts") or 1),
        "dmr_cc": int(gw.get("dmr_cc") or 1),
        # FMO 侧
        "fmo_topic": gw.get("fmo_topic") or "FMO/RAW",
        "sub_topic": gw.get("fmo_topic") or "FMO/RAW",
        "pub_topic": gw.get("fmo_topic") or "FMO/RAW",
        "src_map": gw.get("src_map") or {},
    })
    cfg["client_id"] = "FMO-DMRGW-%s" % (gw.get("id") or "01")
    if base.get("state_path"):
        cfg["state_path"] = str(base["state_path"]).replace(
            ".json", "-%s.json" % (gw.get("id") or "01"))
    return cfg


def main():
    ap = argparse.ArgumentParser(description="FMO cluster voice to DMR gateway")
    ap.add_argument("--config", default="/opt/fmo-subsystem/fus_dmr_gw.json")
    ap.add_argument("--standalone", action="store_true",
                    help="only use local config file (single gateway)")
    args = ap.parse_args()
    base = load_config(args.config)

    # Mode A: managed by master (default) - config from master UI, multi-cluster
    if not args.standalone and base.get("master_admin_url"):
        log("master-managed mode: %s (refresh %ss)"
            % (base["master_admin_url"], base.get("config_refresh_sec", 30)))
        gws = {}
        try:
            while True:
                lst = fetch_master_gateways(base)
                if lst is None:
                    if not gws:
                        log("master unreachable and no gateway running, retry in %ss"
                            % base.get("config_refresh_sec", 30))
                    time.sleep(base.get("config_refresh_sec", 30))
                    continue
                want = {}
                for gw in lst:
                    if not gw.get("enabled"):
                        continue
                    gid = str(gw.get("id") or "")
                    if gid:
                        want[gid] = gw
                for gid in list(gws.keys()):
                    if gid not in want:
                        log("stop DMR gateway %s (disabled or removed)" % gid)
                        try:
                            gws[gid].stop()
                        except Exception:  # noqa: BLE001
                            pass
                        del gws[gid]
                for gid, gw in want.items():
                    cfg = _gateway_cfg(base, gw)
                    if gid not in gws:
                        log("start DMR gateway %s: cluster %s -> %s:%s TG%s/TS%s"
                            % (gid, cfg.get("cluster_id"), cfg.get("dmr_master_host"),
                               cfg.get("dmr_master_port"), cfg.get("dmr_tg"),
                               cfg.get("dmr_ts")))
                        inst = DmrGateway(cfg)
                        inst.daemon = True
                        gws[gid] = inst
                        inst.start()
                    else:
                        gws[gid].reconfigure(cfg)
                time.sleep(base.get("config_refresh_sec", 30))
        except KeyboardInterrupt:
            log("exiting")
            for g in gws.values():
                try:
                    g.stop()
                except Exception:  # noqa: BLE001
                    pass
        return

    # Mode B: single gateway (local config)
    gw = DmrGateway(base)
    try:
        gw.run()
    except KeyboardInterrupt:
        log("exiting")
        gw.stop()


if __name__ == "__main__":
    main()

