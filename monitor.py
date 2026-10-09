# -*- coding: utf-8 -*-
"""
FMO 语音/信标监控模块（分系统侧，零第三方依赖）。

职责：
  1. 以最小 MQTT 3.1.1 客户端（stdlib socket）连接本机 broker，订阅
     FMO/RAW（语音帧）、FMO/TELE（信标遥测）、FMO/SERVER_INFO（服务器信息）；
  2. 语音帧按 (呼号, 会话号) 聚合成"段"（一次连续发言），写本地 voice.db；
  3. 段完成后立即上报总系统（POST /api/voice/report），总系统无需连接
     各分系统 broker 即可瀑布图监控 + 播放全部语音；
  4. 为管理后台瀑布图提供数据（status / segments / audio / beacons）。

音频存储格式：
  codec='adpcm'：每块 323B = [valprev s16 LE][index u8][320B IMA ADPCM 数据]，
                 解码后每块 640 样本 s16le / 8kHz / 单声道（80ms）；
  codec='opus' ：每包 [u16 LE 长度][Opus 原始包]，经 ogg_wrap_opus() 封装为
                 Ogg/Opus 容器后前端 decodeAudioData 播放（Safari 不支持）。

监控身份：自动用本机 CA 签发一张专用监控证书（呼号 SERVER，uid=uid_end，
  不占用用户 UID 序列、不入 certificates 表），存 ca/monitor_cert.json，
  用与 APP 相同的 SAS 认证握手连接 broker。
"""

import json
import os
import socket
import sqlite3
import struct
import threading
import time
import urllib.request
import zlib

from cert_gen import (b64url_encode, b64url_decode, ed25519_sign,
                      cbor_tbs, cert_fingerprint, user_cert_tbs)

# -------------------- 常量 --------------------

TOPICS = ["FMO/RAW", "FMO/TELE", "FMO/SERVER_INFO"]

# 互联桥接：别的 FUS 系统转发过来的语音会在本机重播到 FMO/BRIDGE/<源节点>/<频道>。
# 监控也订阅它 —— 否则"互联进来的语音"在本机看不到、进不了 voice.db、界面上听不到。
# 注意只订阅 4 层的重播主题；桥接的**出站**主题是 6 层（/to/<对端>/），不会被这里收到，
# 所以监控不会把自己发出去的语音又抄回来。
BRIDGE_TOPICS = ["FMO/BRIDGE/+/RAW", "FMO/BRIDGE/+/TELE"]

FRAME_GAP_SEC = 3.0        # 同一 (呼号,会话) 帧间隔超过该值则切段
SEG_MAX_SEC = 300.0        # 单段最长时长（强制切段）
REPORT_RETRY_SEC = 60.0    # 未上报段重试间隔
CLEAN_INTERVAL_SEC = 3600  # 过期数据清理间隔
MONITOR_CERT_FILE = "monitor_cert.json"
MONITOR_CALLSIGN = "SERVER"
SERVER_INFO_FILE = "server_info.json"   # MQTT SERVER_INFO 抄收的服务器名持久化
STATIONS_FILE = "stations.json"         # FMO 站点目录（可进入的中继/服务器）
RECENT_DONE_SEC = 30.0       # 收尾段在内存中保留时长（供流式播放取尾部）

_CONST5 = b"\x3d\x14\x00\xe0\x3d"


def log(tag, msg):
    ts = time.strftime("%H:%M:%S")
    print("[%s] [%s] %s" % (ts, tag, msg))


# -------------------- Ogg/Opus 封装（裸 Opus 包 -> 浏览器可解码的 Ogg 容器） --------------------

_OGG_CRC_TABLE = None


def _ogg_crc_table():
    global _OGG_CRC_TABLE
    if _OGG_CRC_TABLE is None:
        t = []
        for i in range(256):
            r = i << 24
            for _ in range(8):
                r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (r & 0x80000000) else (r << 1) & 0xFFFFFFFF
            t.append(r)
        _OGG_CRC_TABLE = t
    return _OGG_CRC_TABLE


def _ogg_crc(data):
    t = _ogg_crc_table()
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ t[((crc >> 24) & 0xFF) ^ b]
    return crc


def _ogg_page(payload, granule, serial, seq, header_type):
    full, rem = divmod(len(payload), 255)
    segs = [255] * full + [rem]
    if len(payload) > 0 and rem == 0:
        segs.append(0)  # 整除时需以 0 lacing 表示包结束
    head = struct.pack('<4sBBQIIIB', b'OggS', 0, header_type, granule, serial, seq, 0, len(segs))
    page = head + bytes(bytearray(segs)) + payload
    crc = _ogg_crc(page)
    return page[:22] + struct.pack('<I', crc) + page[26:]


# Opus TOC 高 5 位 config -> 单帧时长（ms），见 RFC 6716
_OPUS_FRAME_MS = (10, 20, 40, 60, 10, 20, 40, 60, 10, 20, 40, 60, 10, 20, 10, 20,
                  2.5, 5, 10, 20, 2.5, 5, 10, 20, 2.5, 5, 10, 20, 2.5, 5, 10, 20)


def _opus_packet_samples(pkt):
    """估算一个 Opus 包包含的 48kHz 采样数（用于 Ogg granule 累计）。"""
    if not pkt:
        return 0
    toc = pkt[0]
    ms = _OPUS_FRAME_MS[(toc >> 3) & 31]
    code = toc & 3
    if code == 0:
        frames = 1
    elif code in (1, 2):
        frames = 2
    else:
        frames = (pkt[1] & 0x1F) if len(pkt) > 1 else 1
        if frames == 0:
            frames = 1
    return int(round(frames * ms * 48))


def ogg_wrap_opus(data, channels=1):
    """把存储的 [u16 LE 长度][Opus 原始包] 序列封装为 Ogg/Opus 容器。"""
    packets = []
    off, n = 0, len(data)
    while off + 2 <= n:
        plen = struct.unpack_from('<H', data, off)[0]
        off += 2
        if off + plen > n:
            break
        packets.append(bytes(data[off:off + plen]))
        off += plen
    if not packets:
        raise ValueError('no opus packets')
    serial = 0x464D4F31  # "FMO1"
    out = bytearray()
    # OpusHead 独占首页（BOS）：version=1, preskip=0, rate=48000, gain=0, mapping=0
    head = b'OpusHead' + struct.pack('<BBHIhB', 1, channels, 0, 48000, 0, 0)
    out += _ogg_page(head, 0, serial, 0, 2)
    # OpusTags 独占第二页
    vendor = b'FMO'
    tags = b'OpusTags' + struct.pack('<I', len(vendor)) + vendor + struct.pack('<I', 0)
    out += _ogg_page(tags, 0, serial, 1, 0)
    # 音频包每包一页，granule 累计 48kHz 采样数，末页置 EOS
    granule, seq = 0, 2
    last = len(packets) - 1
    for i, pkt in enumerate(packets):
        granule += _opus_packet_samples(pkt)
        out += _ogg_page(pkt, granule, serial, seq, 4 if i == last else 0)
        seq += 1
    return bytes(out)


# -------------------- FMO 帧解析（移植自 APP fmo_frame.rs） --------------------

def parse_fmo_frame(f):
    """解析一帧 FMO/RAW。失败返回 None，成功返回 dict。"""
    if not f or len(f) < 64 or f[0] != 1:
        return None
    total = struct.unpack_from("<I", f, 30)[0]
    if total != len(f):
        return None
    crc = struct.unpack_from("<I", f, 36)[0]
    if zlib.crc32(f[64:]) & 0xFFFFFFFF != crc:
        return None
    opus = []   # [bytes]
    adpcm = []  # [(valprev s16, index u8, payload 320B)]
    pos = 64
    n = len(f)
    while pos + 4 <= n:
        blen = f[pos + 2] | (f[pos + 3] << 8)
        if blen < 12 or pos + blen > n:
            return None
        inner = f[pos + 8:pos + blen]
        if not inner:
            return None
        ilen = inner[1] | (inner[2] << 8)
        body_end = min(3 + ilen, len(inner))
        body = inner[3:body_end]
        if len(body) < 5 or body[:5] != _CONST5:
            return None
        pkt = body[5:]
        if inner[0] == 0x01:
            if pkt:
                opus.append(bytes(pkt))
        elif inner[0] == 0x02:
            if len(pkt) == 328:
                vp = struct.unpack_from("<h", pkt, 2)[0]
                adpcm.append((vp, pkt[4], bytes(pkt[8:328])))
        pos += blen
    return {
        "session": struct.unpack_from("<H", f, 6)[0],
        "callsign": f[10:16].decode("ascii", "replace").rstrip("\x00").strip(),
        "ts1": struct.unpack_from("<I", f, 22)[0],
        "ts2": struct.unpack_from("<I", f, 26)[0],
        "block_count": struct.unpack_from("<H", f, 34)[0],
        "opus": opus,
        "adpcm": adpcm,
    }


def parse_tele(p):
    """解析 FMO/TELE 信标（33B）。失败返回 None。"""
    if not p or len(p) < 33 or p[0] != 0x02:
        return None
    callsign = p[9:21].split(b"\x00")[0].decode("utf-8", "replace").strip()
    return {
        "dev_id": struct.unpack_from("<I", p, 1)[0],
        "counter": struct.unpack_from("<I", p, 5)[0],
        "callsign": callsign,
        "tele_ts": struct.unpack_from("<I", p, 21)[0],
        "freq1": round(struct.unpack_from("<f", p, 25)[0], 4),
        "freq2": round(struct.unpack_from("<f", p, 29)[0], 4),
    }


# -------------------- FMO/SERVER_INFO（站点名片，二进制） --------------------
# 报文结构（对照真实报文逐个字节核对过，两个真实站点 + 本机站点）：
#   [0]     版本（0x00 / 0x01）
#   [1:5]   站点编号（uint32 LE；实测 2 / 4 / 7）
#   [5:9]   站内计数（uint32 LE；实测 16 / 9 / 23）
#   [9:21]  呼号，12 字节，NUL 补齐（与 FMO/RAW 头的 callsign[12] 一致）
#   [21:]   站名、简介：NUL 分隔的 UTF-8 串，依次为「站名」「欢迎语/简介」
#
# 真实样本：
#   BH6BHG → 站号2  安铜集群(铜陵FMO站) / 欢迎来到八百里皖江本中继与安庆中继互联
#   BI7IOB → 站号4  FMRS
#   BH8GYP → 站号7  重庆互联中继
#
# ⚠️ 老代码把它当 JSON/文本解析（_parse_server_name 直接 decode 整包），
#    于是站名变成「\x00\x02\x00\x00…BH6BHG…安铜集群…」一整坨乱码，
#    因为 NUL 能正常 decode、逃过了 \ufffd 检查。这里改为按二进制字段解析。

def parse_server_info(p):
    """解析 FMO/SERVER_INFO 站点名片。失败返回 None。"""
    if not p or len(p) < 21:
        return None
    try:
        callsign = p[9:21].split(b"\x00")[0].decode("utf-8", "replace").strip()
        runs = []
        for part in p[21:].split(b"\x00"):
            if not part:
                continue
            text = part.decode("utf-8", "replace").strip()
            if text and "\ufffd" not in text:
                runs.append(text)
        if not callsign and not runs:
            return None
        return {
            "ver": p[0],
            "station_no": struct.unpack_from("<I", p, 1)[0],
            "counter": struct.unpack_from("<I", p, 5)[0],
            "callsign": callsign,
            "name": runs[0] if runs else "",
            "desc": runs[1] if len(runs) > 1 else "",
        }
    except Exception:
        return None


# -------------------- 最小 MQTT 3.1.1 客户端（QoS0，stdlib） --------------------

def _mqtt_remaining_length(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            break
    return bytes(out)


def _mqtt_utf8(s):
    b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return struct.pack(">H", len(b)) + b


class MqttError(Exception):
    pass


class MqttMiniClient:
    """最小 MQTT 3.1.1 客户端：CONNECT/SUBSCRIBE(QoS0)/PINGREQ/DISCONNECT，
    循环读取下行 PUBLISH 并回调。仅供监控订阅使用。"""

    def __init__(self, host, port, client_id, username=None, password=None,
                 keepalive=60, on_message=None, read_timeout=5.0):
        self.host = host
        self.port = int(port)
        self.client_id = client_id
        self.username = username
        self.password = password
        self.keepalive = keepalive
        self.on_message = on_message
        # 读循环的 socket 超时。默认 5s 够监控用；互联桥接的**本机**连接要调小
        # （0.2s）—— 否则桥接靠"读完一个包再处理队列"，中继语音会被拖到 5 秒才播出去。
        self.read_timeout = float(read_timeout)
        self._sock = None
        self._buf = b""
        self._last_io = 0.0
        self._last_send = 0.0        # 上次**发包**时间（keepalive 必须按它算，见 poll_once）
        self._pkt_id = 0

    # ---- 底层 ----
    def _recv_exact(self, n):
        while len(self._buf) < n:
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout:
                return None  # 让上层处理 keepalive
            if not chunk:
                raise MqttError("连接被关闭")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _read_packet(self):
        """读取一个完整 MQTT 包。超时返回 None（用于 keepalive）。"""
        first = self._recv_exact(1)
        if first is None:
            return None
        # remaining length（变长）
        mult = 1
        rl = 0
        for _ in range(4):
            b = self._recv_exact(1)
            if b is None:
                return None
            rl += (b[0] & 0x7F) * mult
            if not (b[0] & 0x80):
                break
            mult *= 128
        else:
            raise MqttError("remaining length 非法")
        body = b""
        if rl:
            body = self._recv_exact(rl)
            if body is None:
                return None
        self._last_io = time.time()
        return first[0], body

    def _send(self, data):
        self._sock.sendall(data)
        self._last_io = time.time()
        self._last_send = time.time()

    # ---- 协议 ----
    def connect(self, timeout=10):
        self._sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self._sock.settimeout(self.read_timeout)  # 读循环短超时，便于 keepalive/及时处理队列
        self._buf = b""
        flags = 0x02  # clean session
        payload = _mqtt_utf8(self.client_id)
        if self.username is not None:
            flags |= 0x80
            payload += _mqtt_utf8(self.username)
            if self.password is not None:
                flags |= 0x40
                payload += _mqtt_utf8(self.password)
        vh = _mqtt_utf8("MQTT") + bytes([4, flags]) + struct.pack(">H", self.keepalive)
        pkt = bytes([0x10]) + _mqtt_remaining_length(len(vh) + len(payload)) + vh + payload
        self._send(pkt)
        resp = self._read_packet()
        if resp is None or resp[0] >> 4 != 2:
            raise MqttError("CONNACK 超时或非法")
        if len(resp[1]) < 2 or resp[1][1] != 0:
            rc = resp[1][1] if len(resp[1]) >= 2 else -1
            raise MqttError("连接被拒绝 rc=%d（认证失败或 broker 策略）" % rc)
        self._last_io = time.time()

    def subscribe(self, topics):
        self._pkt_id = (self._pkt_id + 1) & 0xFFFF or 1
        payload = b"".join(_mqtt_utf8(t) + b"\x00" for t in topics)
        vh = struct.pack(">H", self._pkt_id)
        pkt = bytes([0x82]) + _mqtt_remaining_length(len(vh) + len(payload)) + vh + payload
        self._send(pkt)
        # SUBACK 由 run_forever 循环自然读取（也可在此同步等待，从简）

    def publish(self, topic, payload, qos=0, retain=False):
        """
        发布一条消息（默认 QoS0）。

        桥接互联要用：把本机语音转发给对端、把对端语音在本机重播。
        QoS0 足够 —— 语音是实时流，丢一帧比等重传更合适；而且 QoS0 无需
        维护 PUBACK/重传队列，保持这个"最小客户端"不膨胀。
        ★ 注意：本对象的 socket 不是线程安全的，调用方必须保证
          同一时刻只有一个线程在读写（桥接里用队列把跨线程发布收敛到读循环线程）。
        """
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        payload = payload or b""
        flags = 0x30 | (0x01 if retain else 0x00) | ((qos & 0x03) << 1)
        vh = _mqtt_utf8(topic)
        if qos:
            self._pkt_id = (self._pkt_id + 1) & 0xFFFF or 1
            vh += struct.pack(">H", self._pkt_id)
        body = vh + payload
        self._send(bytes([flags]) + _mqtt_remaining_length(len(body)) + body)

    def ping(self):
        self._send(b"\xc0\x00")

    def disconnect(self):
        try:
            self._send(b"\xe0\x00")
        except Exception:
            pass
        try:
            self._sock.close()
        except Exception:
            pass

    def poll_once(self):
        """读取并分发一个包（无包时约 5s 超时返回 False）。异常抛出让上层重连。"""
        # ★ keepalive 必须按「上次**发包**时间」判断，不能按 _last_io（收发都刷新）。
        #   真实事故：本机订阅 FMO/RAW 流量不断 → _read_packet() 永远有包返回 →
        #   下面那个「空闲才 ping」的分支永远走不到 → 服务端视角是"客户端一直没发东西"，
        #   EMQX 按 1.5×keepalive（60s→90s）判定超时，每 ~2 分钟把监控踢掉一次。
        #   客户端收得多 ≠ 客户端活着。
        try:
            if time.time() - self._last_send > max(self.keepalive * 0.6, 10):
                self.ping()
        except Exception:  # noqa: BLE001
            pass
        try:
            pkt = self._read_packet()
        except socket.timeout:
            pkt = None
        if pkt is None:
            if time.time() - self._last_send > max(self.keepalive * 0.6, 10):
                self.ping()
            return False
        ptype = pkt[0] >> 4
        if ptype == 3:  # PUBLISH
            body = pkt[1]
            if len(body) < 2:
                return True
            tlen = struct.unpack_from(">H", body, 0)[0]
            topic = body[2:2 + tlen].decode("utf-8", "replace")
            pos = 2 + tlen
            qos = (pkt[0] >> 1) & 0x03
            pid = None
            if qos:
                pid = struct.unpack_from(">H", body, pos)[0]
                pos += 2
            payload = body[pos:]
            if qos == 1 and pid is not None:  # 回 PUBACK
                try:
                    self._send(bytes([0x40, 0x02]) + struct.pack(">H", pid))
                except Exception:
                    pass
            if self.on_message:
                try:
                    self.on_message(topic, payload)
                except Exception as e:
                    log("MONITOR", "消息处理异常: %s" % e)
        # PINGRESP/SUBACK 等其余包忽略
        return True


# -------------------- 语音段存储 --------------------

class _SharedConn(object):
    """常驻连接的包装：close() 是空操作（调用点写法都是 try/finally close）。"""

    __slots__ = ("_raw",)

    def __init__(self, raw):
        self._raw = raw

    def close(self):          # noqa: D401 - 故意空操作
        return None

    def __enter__(self):
        return self._raw

    def __exit__(self, *exc):
        return False

    def __getattr__(self, name):
        return getattr(self._raw, name)


class VoiceStore:
    """
    voice.db：语音段 + 信标。WAL + **常驻连接复用**，全部访问用锁串行化。

    ★ 真实事故（监控老是掉线 / 服务"莫名其妙断连"）：
      原实现是「每次操作新建连接」，而实测在 NAS 上
      「新建连接后的首次写入 + 关闭」要 **约 1 秒**
      （voice.db 800KB 时实测 758~1562ms；复用连接只要 0.1ms）。
      而监控**每收一个 FMO/TELE 信标就写一次**，于是读循环几乎全程被
      这个 1 秒写入堵住 → 服务端视角"客户端一直没发包" →
      MQTT 按 keepalive 超时把监控踢掉 → 表现为服务器反复断连。
      另外原实现没设 synchronous，默认 FULL 会让每次 commit 都 fsync。
    """

    def __init__(self, db_path, retention_days=3):
        self.db_path = db_path
        self.retention_days = retention_days
        self._lock = threading.RLock()
        self._shared = None
        self._init_db()

    def _raw_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        # ★ NORMAL：WAL 下已足够安全，且避免每次 commit 都 fsync（实测差 ~1000 倍）
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _conn(self):
        """复用常驻连接（见类注释：每操作新建连接要 ~1 秒）。失效时自动重建。"""
        c = self._shared
        if c is not None:
            try:
                c.execute("SELECT 1")
                return _SharedConn(c)
            except Exception:  # noqa: BLE001
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass
                self._shared = None
        c = self._raw_conn()
        self._shared = c
        return _SharedConn(c)

    def dispose(self):
        with self._lock:
            c, self._shared = self._shared, None
            if c is not None:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass

    def _init_db(self):
        with self._lock:
            conn = self._conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS voice_segments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    callsign TEXT NOT NULL,
                    session INTEGER NOT NULL,
                    start_ts REAL NOT NULL,
                    end_ts REAL NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    codec TEXT NOT NULL,
                    frames INTEGER NOT NULL,
                    audio BLOB NOT NULL,
                    reported INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_voice_seg
                    ON voice_segments(callsign, session, start_ts);
                CREATE INDEX IF NOT EXISTS ix_voice_start ON voice_segments(start_ts);
                CREATE TABLE IF NOT EXISTS beacons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    callsign TEXT NOT NULL,
                    freq1 REAL, freq2 REAL, tele_ts INTEGER,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_beacon_ts ON beacons(created_at);
            """)
            # 迁移：互联桥接要记录"这段语音来自哪个对端节点"（老的库补列，可空）
            try:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(voice_segments)")]
                if "origin" not in cols:
                    conn.execute("ALTER TABLE voice_segments ADD COLUMN origin TEXT")
            except Exception as e:  # noqa: BLE001
                log("MONITOR", "voice_segments 补 origin 列失败（不影响录音）: %s" % e)
            conn.commit()

    def add_segment(self, callsign, session, start_ts, end_ts, duration_ms,
                    codec, frames, audio, origin=""):
        """
        写入语音段（幂等：同 callsign/session/start_ts 忽略）。返回行 id 或 None。
        origin 非空表示这段语音是**互联桥接**从别的 FUS 节点转过来的。
        """
        with self._lock:
            conn = self._conn()
            cur = conn.execute("""
                INSERT OR IGNORE INTO voice_segments
                    (callsign, session, start_ts, end_ts, duration_ms, codec,
                     frames, audio, reported, created_at, origin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """, (callsign, session, start_ts, end_ts, duration_ms, codec,
                  frames, sqlite3.Binary(audio), time.time(),
                  str(origin or "")))
            conn.commit()
            return cur.lastrowid if cur.rowcount else None

    def mark_reported(self, seg_id):
        with self._lock:
            conn = self._conn()
            conn.execute("UPDATE voice_segments SET reported=1 WHERE id=?", (seg_id,))
            conn.commit()

    def unreported(self, limit=20):
        with self._lock:
            conn = self._conn()
            return [dict(r) for r in conn.execute("""
                SELECT id, callsign, session, start_ts, end_ts, duration_ms,
                       codec, frames, audio
                FROM voice_segments WHERE reported=0
                ORDER BY start_ts ASC LIMIT ?
            """, (limit,)).fetchall()]

    def segments_since(self, since=0.0, limit=200):
        with self._lock:
            conn = self._conn()
            return [dict(r) for r in conn.execute("""
                SELECT id, callsign, session, start_ts, end_ts, duration_ms,
                       codec, frames, origin
                FROM voice_segments WHERE start_ts > ?
                ORDER BY start_ts ASC LIMIT ?
            """, (since, limit)).fetchall()]

    def get_audio(self, seg_id):
        with self._lock:
            conn = self._conn()
            r = conn.execute(
                "SELECT codec, audio FROM voice_segments WHERE id=?",
                (seg_id,)).fetchone()
            return (r["codec"], r["audio"]) if r else (None, None)

    def add_beacon(self, callsign, freq1, freq2, tele_ts):
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT INTO beacons (callsign, freq1, freq2, tele_ts, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (callsign, freq1, freq2, tele_ts, time.time()))
            conn.commit()

    def beacons_since(self, since=0.0, limit=50):
        with self._lock:
            conn = self._conn()
            return [dict(r) for r in conn.execute("""
                SELECT id, callsign, freq1, freq2, tele_ts, created_at
                FROM beacons WHERE created_at > ?
                ORDER BY created_at DESC LIMIT ?
            """, (since, limit)).fetchall()]

    def cleanup(self):
        """清理过期语音段与信标。"""
        cutoff = time.time() - self.retention_days * 86400
        with self._lock:
            conn = self._conn()
            c1 = conn.execute("DELETE FROM voice_segments WHERE start_ts < ?", (cutoff,))
            c2 = conn.execute("DELETE FROM beacons WHERE created_at < ?", (cutoff,))
            conn.commit()
            return c1.rowcount, c2.rowcount

    def stats(self):
        with self._lock:
            conn = self._conn()
            seg = conn.execute(
                "SELECT COUNT(*) c, COALESCE(SUM(frames),0) f FROM voice_segments").fetchone()
            bc = conn.execute("SELECT COUNT(*) c FROM beacons").fetchone()
            return {"segments": seg["c"], "frames": seg["f"], "beacons": bc["c"]}


# -------------------- 监控主线程 --------------------

class VoiceMonitor(threading.Thread):
    """连接本机 MQTT broker，聚合语音段，入库并上报总系统。"""

    daemon = True

    def __init__(self, config, ca_mgr, base_dir):
        super().__init__(name="voice-monitor")
        self.config = config or {}
        self.ca_mgr = ca_mgr
        self.base_dir = base_dir
        mon = self.config.get("monitor") or {}
        self.enabled = bool(mon.get("enabled", True))
        self.mqtt_host = str(mon.get("mqtt_host", "127.0.0.1"))
        self.mqtt_port = int(mon.get("mqtt_port", 1883))
        self.report_voice = bool(mon.get("report_voice", True))
        retention = int(mon.get("retention_days", 3) or 3)
        self.master_url = str(self.config.get("master_url", "")).rstrip("/")
        self.subsystem_id = str(self.config.get("subsystem_id", ""))
        self.sync_token = str(self.config.get("sync_token")
                              or os.environ.get("FMO_SYNC_TOKEN", ""))
        self.store = VoiceStore(os.path.join(base_dir, "voice.db"), retention)
        self._stop_event = threading.Event()
        self._segments = {}          # (callsign, session) -> 进行中的段
        self._recent_done = {}       # (callsign, session) -> 刚收尾的段（流式取尾用）
        self._lock = threading.Lock()
        self._state = "disabled"     # disabled/connecting/connected/error
        self._state_detail = ""
        self._last_clean = 0.0
        self._last_retry = 0.0
        self.server_name, self.server_desc = self._load_server_info()
        self._stations = self._load_stations()   # 站点目录：呼号 -> 站点名片
        self._server_info_raw = ""   # 最近一次 SERVER_INFO 原始报文（诊断用）
        self._client = None          # 当前 MQTT 连接（界面热更新地址时断开它触发重连）

    def update_mqtt_config(self, host, port):
        """界面热更新 MQTT 地址：写入新地址并断开当前连接，
        主循环外层会立即用新地址重连，无需重启服务。"""
        self.mqtt_host = str(host).strip() or "127.0.0.1"
        self.mqtt_port = int(port)
        log("MONITOR", "MQTT 地址已更新为 %s:%d，即将重连" % (self.mqtt_host, self.mqtt_port))
        c = self._client
        if c is not None:
            try:
                c.disconnect()  # 内层 poll 随之抛异常 → 外层重连用新地址
            except Exception:
                pass

    # ---------- 服务器信息（MQTT SERVER_INFO 抄收） ----------
    def _server_info_path(self):
        return os.path.join(self.base_dir, SERVER_INFO_FILE)

    def _load_server_info(self):
        try:
            with open(self._server_info_path(), "r", encoding="utf-8") as f:
                d = json.load(f) or {}
            name = str(d.get("name") or "")[:64]
            desc = str(d.get("desc") or "")[:256]
            # 旧版本可能存入了乱码（含替换符），丢弃等重新抄收
            if "\ufffd" in name:
                name = ""
            if "\ufffd" in desc:
                desc = ""
            return name, desc
        except Exception:
            return "", ""

    @staticmethod
    def _decode_text(payload):
        """多编码尝试解码（UTF-8 → GB18030），应对 APP 非 UTF-8 发布的中文。"""
        for enc in ("utf-8", "gb18030"):
            try:
                return payload.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return payload.decode("utf-8", "replace")

    @staticmethod
    def _parse_server_name(payload):
        """宽容解析 SERVER_INFO：JSON 多字段名尝试，非 JSON 按文本。"""
        text = VoiceMonitor._decode_text(payload).strip()
        try:
            obj = json.loads(text)
        except Exception:
            obj = None
        name = ""
        if isinstance(obj, dict):
            dicts = [obj]
            for k in ("data", "info", "server"):
                if isinstance(obj.get(k), dict):
                    dicts.append(obj[k])
            for d in dicts:
                for k in ("name", "server_name", "serverName", "title",
                          "nickname", "site_name", "server"):
                    v = d.get(k)
                    if isinstance(v, str) and v.strip():
                        name = v.strip()[:64]
                        break
                if name:
                    break
        elif text:
            name = text[:64]
        # 解码结果仍含替换符说明是未知编码，视为失败（不显示乱码框）
        if name and "\ufffd" not in name:
            return name
        return ""

    @staticmethod
    def _parse_server_desc(payload):
        """宽容解析 SERVER_INFO 中的描述/欢迎语，失败返回 ''。"""
        text = VoiceMonitor._decode_text(payload).strip()
        try:
            obj = json.loads(text)
        except Exception:
            obj = None
        desc = ""
        if isinstance(obj, dict):
            dicts = [obj]
            for k in ("data", "info", "server"):
                if isinstance(obj.get(k), dict):
                    dicts.append(obj[k])
            for d in dicts:
                for k in ("description", "desc", "motd", "welcome", "comment",
                          "msg", "message", "text", "notice", "announcement",
                          "announce", "info"):
                    v = d.get(k)
                    if isinstance(v, str) and v.strip():
                        desc = v.strip()[:256]
                        break
                if desc:
                    break
        if desc and "\ufffd" not in desc:
            return desc
        return ""

    def _on_server_info(self, payload):
        self._server_info_raw = repr(payload[:200])
        # 优先按二进制站点名片解析（正确姿势）；失败再退回老的宽容文本解析
        info = parse_server_info(payload)
        if info:
            name, desc = info.get("name", ""), info.get("desc", "")
            self._note_station(info)
        else:
            name = self._parse_server_name(payload)
            desc = self._parse_server_desc(payload)
        if not name and not desc:
            # 低频主题，打原始报文方便诊断 APP 实际发布格式
            log("MONITOR", "SERVER_INFO 无法解析，原始报文(%dB): %r"
                % (len(payload), payload[:120]))
            return
        changed = False
        if name and name != self.server_name:
            self.server_name = name
            changed = True
        if desc != self.server_desc:
            self.server_desc = desc
            changed = True
        if not changed:
            return
        log("MONITOR", "抄收服务器信息: 名=%s 描述=%s"
            % (self.server_name, self.server_desc[:40]))
        try:
            with open(self._server_info_path(), "w", encoding="utf-8") as f:
                json.dump({"name": self.server_name, "desc": self.server_desc,
                           "ts": time.time()}, f, ensure_ascii=False)
        except Exception as e:
            log("MONITOR", "服务器信息持久化失败: %s" % e)

    # ---------- 站点目录（可进入的 FMO 中继/服务器） ----------
    def _stations_path(self):
        return os.path.join(self.base_dir, STATIONS_FILE)

    def _load_stations(self):
        try:
            with open(self._stations_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_stations(self):
        try:
            with open(self._stations_path(), "w", encoding="utf-8") as f:
                json.dump(self._stations, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log("MONITOR", "站点目录持久化失败: %s" % e)

    def _note_station(self, info):
        """把一张站点名片累积进目录。

        为什么要累积：SERVER_INFO 是**全网广播的站点名片**，老代码只留最后一条，
        于是「可进入的站点」永远只有 1 个。按呼号累积才能形成站点列表。
        """
        cs = str(info.get("callsign") or "").strip().upper()
        if not cs:
            return
        with self._lock:
            old = self._stations.get(cs) or {}
            self._stations[cs] = {
                "callsign": cs,
                "name": info.get("name") or old.get("name") or "",
                "desc": info.get("desc") or old.get("desc") or "",
                "station_no": info.get("station_no", old.get("station_no")),
                "counter": info.get("counter", old.get("counter")),
                "ver": info.get("ver", old.get("ver")),
                "first_seen": old.get("first_seen") or time.time(),
                "last_seen": time.time(),
                "hits": int(old.get("hits") or 0) + 1,
            }
            should_save = (old.get("name") != info.get("name")
                           or old.get("desc") != info.get("desc"))
        if should_save:
            log("MONITOR", "登记 FMO 站点: %s 「%s」站号=%s"
                % (cs, info.get("name", ""), info.get("station_no")))
            self._save_stations()

    def stations(self):
        """站点目录（最近出现的在前）"""
        with self._lock:
            return sorted((dict(v) for v in self._stations.values()),
                          key=lambda x: x.get("last_seen") or 0, reverse=True)

    # ---------- 状态 ----------
    def status(self):
        st = self.store.stats()
        return {
            "enabled": self.enabled,
            "state": self._state,
            "detail": self._state_detail,
            "mqtt": "%s:%d" % (self.mqtt_host, self.mqtt_port),
            "report_voice": self.report_voice,
            "master_url": bool(self.master_url),
            "server_name": self.server_name,
            "server_desc": self.server_desc,
            "server_info_raw": self._server_info_raw,
            "stats": st,
        }

    def _set_state(self, s, detail=""):
        self._state = s
        self._state_detail = detail

    def stop(self):
        self._stop_event.set()

    # ---------- 监控证书 ----------
    def _load_or_issue_monitor_cert(self):
        """加载/签发监控专用证书（呼号 SERVER，uid=uid_end，不入 certificates 表）。"""
        path = os.path.join(self.base_dir,
                            self.config.get("ca_dir", "ca"), MONITOR_CERT_FILE)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    mc = json.load(f)
                # 简单过期检查：user_cert tbs 中 exp（最后一个时间字段）
                tbs = mc["cert_user"].get("tbs") or []
                exp = None
                for v in reversed(tbs):
                    if isinstance(v, int) and v > 10 ** 9:
                        exp = v
                        break
                if exp is None or exp > time.time() + 86400:
                    return mc
                log("MONITOR", "监控证书已过期，重新签发")
            except Exception as e:
                log("MONITOR", "监控证书读取失败（%s），重新签发" % e)
        if self.ca_mgr is None or self.ca_mgr.int_cert is None:
            raise MqttError("CA 未初始化，无法签发监控证书")
        uid = int(getattr(self.ca_mgr, "uid_end", 200000) or 200000)
        certs = self.ca_mgr.issue_user_cert(MONITOR_CALLSIGN, uid)
        mc = {
            "callsign": MONITOR_CALLSIGN,
            "uid": uid,
            "fingerprint": certs["fingerprint"],
            "cert_root": certs["root_cert"],
            "cert_int": certs["int_cert"],
            "cert_user": certs["user_cert"],
            "cert_devicekey": certs["device_key"],
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(mc, f, ensure_ascii=False)
        except Exception as e:
            log("MONITOR", "监控证书保存失败: %s" % e)
        log("MONITOR", "已签发监控证书: callsign=%s uid=%d" % (MONITOR_CALLSIGN, uid))
        return mc

    def _build_credentials(self, mc):
        """构造统一老 FMO 格式的 MQTT 认证凭证（与官方/APP 一致）。

        username = 明文呼号；password = base64url(JSON)，内含
        certPackage{intermediateCert,userCert} + 目标服务器字段 +
        proof.signature（用监控证书私钥对 12 元素 CBOR TBS 签名，
        证明持有与 User Cert 配套的私钥）。
        服务器侧为宽松模式：目标字段不强制指向本机，只验签名有效。
        """
        cert_user = mc["cert_user"]
        user_tbs = user_cert_tbs(
            cert_user["issuerSn"],
            cert_user["subject"]["callsign"],
            cert_user["subject"]["uid"],
            b64url_decode(cert_user["subject"]["publicKey"]),
            cert_user["iat"],
            cert_user["exp"],
        )
        user_fp_bytes = cert_fingerprint(user_tbs)
        timestamp = int(time.time())
        target_host = str(self.mqtt_host)
        target_port = int(self.mqtt_port)
        server_fp_b64 = str(mc["fingerprint"])
        proof_tbs = [
            "FMO", 4, "serverAuthorizerReqHttp",
            0,                              # targetUID（宽松模式不校验指向）
            "",                             # targetCallsign
            0,                              # serverUid（与 targetUID 同值）
            "monitor",                      # role
            target_host,                    # targetUrl
            target_port,                    # targetPort
            b64url_decode(server_fp_b64),   # serverFingerprint(bytes)
            timestamp,
            user_fp_bytes,                  # userCertFingerprint(bytes)
        ]
        seed = b64url_decode(mc["cert_devicekey"]["seed"])
        signature = b64url_encode(ed25519_sign(seed, cbor_tbs(proof_tbs)))
        password = b64url_encode(json.dumps({
            "certPackage": {
                "intermediateCert": mc["cert_int"],
                "userCert": cert_user,
            },
            "targetCallsign": "",
            "targetUID": 0,
            "role": "monitor",
            "targetUrl": target_host,
            "targetPort": target_port,
            "serverFingerprint": server_fp_b64,
            "timestamp": timestamp,
            "proof": {"signature": signature},
        }, separators=(",", ":")).encode("utf-8"))
        username = str(mc["callsign"])
        return username, password

    # ---------- 语音段聚合 ----------
    def _on_message(self, topic, payload):
        now = time.time()
        # 互联桥接：monitor 也订阅了 FMO/BRIDGE/<源节点>/<频道>（4 层）。
        # 拆掉前缀后按同频道处理 —— 别人转来的语音照样入库、可听，
        # 只是记下 origin，界面上就能区分"本地收的"和"互联来的"。
        origin = ""
        if topic.startswith("FMO/BRIDGE/"):
            parts = topic.split("/")
            if len(parts) != 4:
                return          # 6 层的出站主题不会被订阅到；这里只做兜底
            origin = parts[2]
            topic = "FMO/%s" % parts[3]
        if topic == "FMO/RAW":
            frame = parse_fmo_frame(payload)
            if not frame or not frame["callsign"]:
                return
            frame["origin"] = origin
            self._on_voice_frame(frame, now)
        elif topic == "FMO/TELE":
            tele = parse_tele(payload)
            if tele and tele["callsign"]:
                try:
                    self.store.add_beacon(tele["callsign"], tele["freq1"],
                                          tele["freq2"], tele["tele_ts"])
                except Exception as e:
                    log("MONITOR", "信标入库失败: %s" % e)
        elif topic == "FMO/SERVER_INFO":
            try:
                self._on_server_info(payload)
            except Exception as e:
                log("MONITOR", "SERVER_INFO 解析失败: %s" % e)

    def _on_voice_frame(self, frame, now):
        key = (frame["callsign"], frame["session"])
        blocks_adpcm = frame["adpcm"]
        blocks_opus = frame["opus"]
        if not blocks_adpcm and not blocks_opus:
            return
        with self._lock:
            seg = self._segments.get(key)
            # 来源变化也收尾：同一呼号可能既有本机直收、又有互联转来的，
            # 不能让两路混成一段（key 仍是 (呼号,session)，不动它 —— 流式播放
            # 的按 (呼号,session) 查找依赖这个形状）。
            if seg and (now - seg["last_ts"] > FRAME_GAP_SEC
                        or seg["codec"] != ("adpcm" if blocks_adpcm else "opus")
                        or seg.get("origin", "") != frame.get("origin", "")):
                self._finalize_segment_locked(seg)
                seg = None
            if seg is None:
                seg = {
                    "callsign": frame["callsign"],
                    "session": frame["session"],
                    "codec": "adpcm" if blocks_adpcm else "opus",
                    "start_ts": now,
                    "last_ts": now,
                    "frames": 0,
                    "buf": bytearray(),
                    # 互联来源（空 = 本机直收）
                    "origin": frame.get("origin", ""),
                }
                self._segments[key] = seg
            for vp, idx, payload in blocks_adpcm:
                seg["buf"] += struct.pack("<hB", vp, idx) + payload
                seg["frames"] += 1
            for pkt in blocks_opus:
                seg["buf"] += struct.pack("<H", len(pkt)) + pkt
                seg["frames"] += 1
            seg["last_ts"] = now
            if now - seg["start_ts"] > SEG_MAX_SEC:
                self._finalize_segment_locked(seg)
                self._segments.pop(key, None)

    def _sweep_segments(self):
        """收尾超时无新帧的段。"""
        now = time.time()
        with self._lock:
            stale = [k for k, s in self._segments.items()
                     if now - s["last_ts"] > FRAME_GAP_SEC]
            for k in stale:
                seg = self._segments.pop(k)
                self._finalize_segment_locked(seg)
            # 清理过期的收尾缓存
            expired = [k for k, s in self._recent_done.items()
                       if now - s["done_ts"] > RECENT_DONE_SEC]
            for k in expired:
                self._recent_done.pop(k, None)

    def _finalize_segment_locked(self, seg):
        if seg["frames"] <= 0:
            return
        duration_ms = int(max(
            (seg["last_ts"] - seg["start_ts"]) * 1000,
            seg["frames"] * (80 if seg["codec"] == "adpcm" else 40)))
        audio = bytes(seg["buf"])
        # 收尾段保留在内存一段时间，供流式播放取尾部
        self._recent_done[(seg["callsign"], seg["session"])] = {
            "callsign": seg["callsign"], "session": seg["session"],
            "codec": seg["codec"], "start_ts": seg["start_ts"],
            "last_ts": seg["last_ts"], "frames": seg["frames"],
            "audio": audio, "done_ts": time.time(),
        }
        try:
            seg_id = self.store.add_segment(
                seg["callsign"], seg["session"], seg["start_ts"], seg["last_ts"],
                duration_ms, seg["codec"], seg["frames"], audio,
                origin=seg.get("origin", ""))
            if seg_id:
                _origin = seg.get("origin") or ""
                log("MONITOR", "语音段 #%d %s %.1fs %s x%d%s" % (
                    seg_id, seg["callsign"], duration_ms / 1000.0,
                    seg["codec"], seg["frames"],
                    ("（互联来自 %s）" % _origin) if _origin else ""))
                if self.report_voice:
                    self._report_segments([{
                        "id": seg_id, "callsign": seg["callsign"],
                        "session": seg["session"], "start_ts": seg["start_ts"],
                        "end_ts": seg["last_ts"], "duration_ms": duration_ms,
                        "codec": seg["codec"], "frames": seg["frames"],
                        "audio": audio,
                    }])
        except Exception as e:
            log("MONITOR", "语音段入库失败: %s" % e)

    # ---------- 流式播放（进行中段增量取数） ----------
    def get_active(self):
        """进行中 + 刚收尾的段元数据列表（不含音频体）。"""
        now = time.time()
        out = []
        with self._lock:
            for seg in self._segments.values():
                out.append({
                    "callsign": seg["callsign"], "session": seg["session"],
                    "codec": seg["codec"], "start_ts": seg["start_ts"],
                    "last_ts": seg["last_ts"], "frames": seg["frames"],
                    "bytes": len(seg["buf"]), "done": False,
                })
            for seg in self._recent_done.values():
                if now - seg["done_ts"] > RECENT_DONE_SEC:
                    continue
                out.append({
                    "callsign": seg["callsign"], "session": seg["session"],
                    "codec": seg["codec"], "start_ts": seg["start_ts"],
                    "last_ts": seg["last_ts"], "frames": seg["frames"],
                    "bytes": len(seg["audio"]), "done": True,
                })
        out.sort(key=lambda s: s["start_ts"])
        return out

    def get_active_audio(self, callsign, session, offset=0):
        """增量取音频字节。返回 (data, codec, done, total) 或 None。"""
        offset = max(int(offset or 0), 0)
        with self._lock:
            seg = self._segments.get((callsign, session))
            if seg is not None:
                buf = seg["buf"]
                total = len(buf)
                if offset > total:
                    offset = total
                return (bytes(buf[offset:]), seg["codec"], False, total)
            seg = self._recent_done.get((callsign, session))
            if seg is not None:
                buf = seg["audio"]
                total = len(buf)
                if offset > total:
                    offset = total
                return (buf[offset:], seg["codec"], True, total)
        return None

    # ---------- 上报总系统 ----------
    def _report_segments(self, segs):
        """上报语音段到总系统（失败保留 reported=0 待重试）。

        近期信标随报告携带上报（总系统按 tele_ts 去重，重复上报幂等）。"""
        if not self.master_url or not segs:
            return
        import base64
        items = []
        id_map = []
        for s in segs:
            items.append({
                "callsign": s["callsign"],
                "session": s["session"],
                "start_ts": s["start_ts"],
                "end_ts": s["end_ts"],
                "duration_ms": s["duration_ms"],
                "codec": s["codec"],
                "frames": s["frames"],
                "audio_b64": base64.b64encode(s["audio"]).decode("ascii"),
            })
            id_map.append(s["id"])
        beacons = [
            {"callsign": b["callsign"], "freq1": b["freq1"],
             "freq2": b["freq2"], "tele_ts": b["tele_ts"]}
            for b in self.store.beacons_since(time.time() - 300, limit=50)
        ]
        body = json.dumps({
            "subsystem_id": self.subsystem_id,
            "server_name": self.server_name,
            "segments": items,
            "beacons": beacons,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.master_url + "/api/voice/report", data=body,
            headers={"Content-Type": "application/json",
                     "X-Sync-Token": self.sync_token})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("ok"):
                for sid in id_map:
                    self.store.mark_reported(sid)
            else:
                log("MONITOR", "语音上报被拒绝: %s" % data.get("error", "?"))
        except Exception as e:
            log("MONITOR", "语音上报失败（稍后重试）: %s" % e)

    def _retry_unreported(self):
        rows = self.store.unreported(limit=10)
        if rows:
            self._report_segments(rows)

    # ---------- 主循环 ----------
    def run(self):
        if not self.enabled:
            self._set_state("disabled", "配置 monitor.enabled=false")
            return
        backoff = 2.0
        while not self._stop_event.is_set():
            client = None
            try:
                self._set_state("connecting", "%s:%d" % (self.mqtt_host, self.mqtt_port))
                mc = self._load_or_issue_monitor_cert()
                username, password = self._build_credentials(mc)
                client_id = "FMO-MONITOR-%s-%d" % (
                    self.subsystem_id or "SUB", int(time.time()) % 100000)
                client = MqttMiniClient(
                    self.mqtt_host, self.mqtt_port, client_id,
                    username=username, password=password,
                    keepalive=60, on_message=self._on_message)
                self._client = client
                client.connect()
                client.subscribe(TOPICS + BRIDGE_TOPICS)
                self._set_state("connected", "%s:%d" % (self.mqtt_host, self.mqtt_port))
                log("MONITOR", "已连接 MQTT %s:%d，订阅 %s" % (
                    self.mqtt_host, self.mqtt_port,
                    ", ".join(TOPICS + BRIDGE_TOPICS)))
                backoff = 2.0
                # 消息循环 + 定期维护
                last_sweep = 0.0
                while not self._stop_event.is_set():
                    client.poll_once()  # 读一个包并分发；超时自动 keepalive
                    now = time.time()
                    if now - last_sweep >= 1.0:
                        last_sweep = now
                        self._sweep_segments()
                    if now - self._last_retry >= REPORT_RETRY_SEC:
                        self._last_retry = now
                        try:
                            self._retry_unreported()
                        except Exception as e:
                            log("MONITOR", "重试上报异常: %s" % e)
                    if now - self._last_clean >= CLEAN_INTERVAL_SEC:
                        self._last_clean = now
                        try:
                            d1, d2 = self.store.cleanup()
                            if d1 or d2:
                                log("MONITOR", "清理过期数据: 语音 %d 段, 信标 %d 条" % (d1, d2))
                        except Exception as e:
                            log("MONITOR", "清理异常: %s" % e)
            except Exception as e:
                self._set_state("error", str(e))
                log("MONITOR", "连接断开/异常: %s（%.0fs 后重连）" % (e, backoff))
            finally:
                if client is not None:
                    try:
                        client.disconnect()
                    except Exception:
                        pass
                self._client = None
                self._sweep_segments()  # 收尾进行中段
            # 退避重连
            self._stop_event.wait(backoff)
            backoff = min(backoff * 2, 60.0)
        self._set_state("disabled", "已停止")
