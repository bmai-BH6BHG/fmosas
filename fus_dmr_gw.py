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
        else:
            stats["other"] += 1
        off = inner + blen - 8
    return session, call, blocks, stats


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
class DmrGateway:
    """FMO 集群语音 ↔ 国服 DMR 双向网关。"""

    def __init__(self, cfg):
        self.cfg = cfg
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
                "usrp_registered": self.usrp.registered.is_set(),
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
        session, call, blocks, stats = parsed
        # 回环过滤：自己发出去的帧不要又转回去
        if (call or "").upper() == (self.cfg.get("fmo_callsign") or "DMRGW").upper():
            return
        if session in self.published_sessions:
            return
        if not blocks:
            # Opus 段等无 ADPCM：明确计数，不静默
            if stats.get("opus"):
                self._tx_dropped_opus += stats["opus"]
                log("FMO→DMR：收到 Opus 段（本网关只转 ADPCM），"
                    "累计丢弃 %d 块" % self._tx_dropped_opus)
            return
        with self.tx_lock:
            if not self.tx_active or self.tx_session != session:
                self.tx_active = True
                self.tx_session = session
                self._tx_dmr_id = self._dmr_id_for(call)
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
        """20ms 绝对节拍：维护 PTT 与 USRP 语音流。"""
        next_tick = time.monotonic()
        silence = b"\x00" * USRP_CHUNK
        timeout_ms = int(self.cfg.get("ptt_timeout_ms", 800))
        while not self._stop.is_set():
            next_tick += 0.02
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()
            if not self.usrp.registered.is_set():
                continue
            with self.tx_lock:
                timed_out = self.tx_active and \
                    (time.monotonic() - self.tx_last_frame) * 1000 > timeout_ms
                if timed_out:
                    self.tx_active = False
                    log("FMO→DMR 会话结束（静默超时松键）")
                chunk = self.tx_queue.popleft() if self.tx_queue else None
                active = self.tx_active
            if active:
                self.usrp.send_voice(True, chunk if chunk is not None else silence)
            elif chunk is not None:
                self.usrp.send_voice(True, chunk)
                self.usrp.send_voice(False, silence)
            self._write_state()

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
    def run(self):
        cfg = self.cfg
        log("FMO↔DMR 网关启动：MQTT %s:%s 主题 %s → USRP %s:%s → DMR TG%s/TS%s"
            % (cfg.get("mqtt_host"), cfg.get("mqtt_port"),
               cfg.get("sub_topic"), cfg.get("usrp_host"),
               cfg.get("usrp_rx_port"), cfg.get("dmr_tg"), cfg.get("dmr_ts")))

        threading.Thread(target=self.usrp_recv_loop, name="usrp-rx",
                         daemon=True).start()
        threading.Thread(target=self.registration_loop, name="usrp-reg",
                         daemon=True).start()
        threading.Thread(target=self.tx_tick, name="tx-tick",
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


def main():
    ap = argparse.ArgumentParser(description="FMO 集群语音 ↔ 国服 DMR 网关")
    ap.add_argument("--config", default="/opt/fmo-subsystem/fus_dmr_gw.json")
    args = ap.parse_args()
    cfg = load_config(args.config)
    gw = DmrGateway(cfg)
    try:
        gw.run()
    except KeyboardInterrupt:
        log("已退出")
        gw.stop()


if __name__ == "__main__":
    main()

