# -*- coding: utf-8 -*-
"""
FMO 台站发现（APRS-IS）
=======================
FMO 台站**不在任何数据库里**，而是在 APRS-IS 上周期性广播自己的站点名片：

    BG8LAK-10>APFMO4,TCPIP*,qAC,T2HK:=2833.45NF10635.33Ei
        FMO-V4,STATION,CERT:...（后面还可能跟 SH:host / P端口 / U在线/总数 等）

所以要拿到「全部台站」只能**听 APRS**。而台站广播有周期（通常十几分钟一次），
短时间只能听到少数几个 —— 必须**常驻采集、长期累积**才能攒到几百个。

解析规则完全照搬现有监控大屏 monitor-deploy/index.html 的 FMO-V4 实现
（已在现场跑了很久，字段含义与 Java 端 AprsClient 一致）：

  行格式  CALLSIGN>DEST:body        '#' 开头是服务器注释，跳过
  body 含 "FMO"，标记优先 FMO-V4 → FMO-CLIENT → FMO-STATION
  comment = body 从标记处起；取第一个逗号后的部分按 ',' 切分
  tokens[0] = subtype（只有 STATION 且 host 非空才算有效台站）
  其余 token：
    SH:<host>        服务器地址          P<2-5位数字>   端口
    U<在线>/<总数>   人数                U<在线>        只有在线数
    FREQ: / HEIGHT: / RIG: / ANT: / F<数字>KM（覆盖半径）/ CERT:<b64url>
    SIG*/S<数字>     忽略                其余        → extra
  subtype==STATION 时 extra 依序解析：[国家(2大写字母)] [台站名(非域名)] [host(域名/IP)]

⚠️ 只读订阅：APRS-IS 用 `pass -1`（只收不发），不投递任何数据。
"""

import json
import os
import re
import socket
import threading
import time

APRS_HOST = "rotate.aprs2.net"       # 与现场监控大屏一致
APRS_PORT = 10152                    # 全馈口（无需 filter）
APRS_LOGIN = b"user FMO-MON pass -1 vers FMO-FUS 1.0\r\n"
APRS_STATIONS_FILE = "aprs_stations.json"

READ_TIMEOUT = 30.0                  # socket 读超时（APRS 平时也在心跳）
RECONNECT_MIN = 5.0
RECONNECT_MAX = 120.0
SAVE_INTERVAL = 30.0                 # 落盘节流

_HOST_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_PORT_RE = re.compile(r"^P\d{2,5}$")
_PEOPLE_RE = re.compile(r"^U\d+/\d+$")
_ONLINE_RE = re.compile(r"^U\d+$")
_COVER_RE = re.compile(r"^F\d+KM$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

MARKS = ("FMO-V4", "FMO-CLIENT", "FMO-STATION")


def is_host(s):
    return bool(_HOST_RE.match(s) or _IPV4_RE.match(s))


def parse_aprs_line(line):
    """
    解析一行 APRS 报文；不是有效 FMO STATION 台站则返回 None。
    与 monitor-deploy/index.html 的 parseAprsLine 逐条对应。
    """
    if not line or line[0] == "#":
        return None
    gt = line.find(">")
    if gt < 0:
        return None
    callsign = line[:gt].strip()
    if not callsign:
        return None
    after = line[gt + 1:]
    colon = after.find(":")
    if colon < 0:
        return None
    dest = after[:colon]
    for sep in (",", ":"):
        i = dest.find(sep)
        if i >= 0:
            dest = dest[:i]
    body = after[colon + 1:]
    if "FMO" not in body:
        return None                       # 全馈数据量大，先粗筛

    mark_idx, mark = -1, ""
    for m in MARKS:
        i = body.find(m)
        if i >= 0:
            mark_idx, mark = i, m
            break
    if mark_idx < 0:
        return None
    comment = body[mark_idx:]
    fc = comment.find(",")
    if fc < 0:
        return None
    tokens = comment[fc + 1:].split(",")
    if not tokens:
        return None
    subtype = tokens[0].strip()

    info = {
        "callsign": callsign, "dest": dest, "mark": mark, "subtype": subtype,
        "host": "", "port": None, "online": None, "total": None,
        "freq": "", "height": "", "rig": "", "ant": "", "cover_km": "",
        "extra": [], "country": "", "name": "", "cert": "",
    }

    for t in tokens[1:]:
        if not t:
            continue
        if t.startswith("SH:"):
            info["host"] = t[3:]
        elif _PORT_RE.match(t):
            info["port"] = int(t[1:])
        elif _PEOPLE_RE.match(t):
            a = t[1:].split("/")
            info["online"], info["total"] = int(a[0]), int(a[1])
        elif _ONLINE_RE.match(t):
            info["online"] = int(t[1:])
        elif t.startswith("FREQ:"):
            info["freq"] = t[5:]
        elif t.startswith("HEIGHT:"):
            info["height"] = t[7:]
        elif t.startswith("RIG:"):
            info["rig"] = t[4:]
        elif t.startswith("ANT:"):
            info["ant"] = t[4:]
        elif _COVER_RE.match(t):
            info["cover_km"] = t[1:-2]
        elif t.startswith("CERT:"):
            info["cert"] = t[5:]
        elif t.startswith("SIG") or re.match(r"^S\d+$", t):
            continue
        else:
            info["extra"].append(t)

    if subtype == "STATION":
        ex = info["extra"]
        ei = 0
        if ei < len(ex) and _COUNTRY_RE.match(ex[ei]):
            info["country"] = ex[ei]
            ei += 1
        if ei < len(ex) and not is_host(ex[ei]):
            info["name"] = ex[ei]
            ei += 1
        if ei < len(ex) and is_host(ex[ei]):
            info["host"] = ex[ei]
            ei += 1

    if info["name"] and _CTRL_RE.search(info["name"]):
        info["name"] = ""
    if info["name"] and len(info["name"]) > 20:
        info["name"] = info["name"][:20]

    if subtype != "STATION" or not info["host"]:
        return None
    return info


def station_entry_url(st):
    """台站的「进入」地址：优先 SH: 里的 host，端口默认 35928。"""
    host = str(st.get("host") or "").strip()
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    port = st.get("port") or 35928
    return "http://%s:%d" % (host, port)


def station_mqtt_addr(st):
    """
    台站的 MQTT 接入地址 host:port。

    ⚠️ APRS 名片里的 `P<端口>` 是 **MQTT 端口（通常 1883）**，不是 HTTP 端口。
    要「进入」某个台站，就是把 APP/固件连到这个 MQTT broker，所以
    「能不能进入」= 这个 MQTT 地址能不能连上。
    """
    host = str(st.get("host") or "").strip()
    if not host or host.startswith(("http://", "https://")):
        return ""
    port = st.get("port") or 1883
    return "%s:%d" % (host, port)


# ------------------------------------------------------------
#  「能不能进入」探测：真发一个 MQTT CONNECT，看 broker 回不回 CONNACK
# ------------------------------------------------------------
# 只做 TCP 连接判断会把「端口开着但不是 MQTT/已挂死」也算能进；
# 真发 CONNECT 拿到 CONNACK(0x20) 才算这个台站可以进（认证另说，这里只证明服务在）。

MQTT_PROBE_TIMEOUT = 6.0
PROBE_CLIENTID_PREFIX = "FMO-PROBE-"
PROBE_CERT_FILE = os.path.join("ca", "monitor_cert.json")


def _mqtt_connect_packet(clientid, username=None, password=None):
    """
    最小 MQTT 3.1.1 CONNECT。

    注意：**clientid 必须以 FMO- 开头** —— 现场 EMQX 的文件 ACL 只放行
    FMO-* 的 connect，用别的 clientid 即使证书完全有效也会被回 CONNACK 5（未授权），
    早期就是踩了这个坑才误判成"进不去"。
    """
    import struct as _s
    cid = clientid.encode("utf-8")[:23]
    flags = 0x02                                    # clean session
    payload = _s.pack(">H", len(b"MQTT")) + b"MQTT" + bytes([4, flags])
    payload += _s.pack(">H", 30)                    # keepalive
    payload += _s.pack(">H", len(cid)) + cid
    if username:
        ub = username.encode("utf-8")
        payload += _s.pack(">H", len(ub)) + ub
        flags |= 0x80
    if password:
        pb = password if isinstance(password, bytes) else password.encode("utf-8")
        payload += _s.pack(">H", len(pb)) + pb
        flags |= 0x40
    # flags 在 payload 里位置固定（第 8 字节），回填
    payload = (payload[:7] + bytes([flags]) + payload[8:])
    return bytes([0x10]) + _remlen(len(payload)) + payload


def _remlen(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            return bytes(out)


def load_probe_cert(base_dir):
    """读本机监控证书（由**本服务器 CA 签发**），用于真实登录探测。"""
    p = os.path.join(base_dir, PROBE_CERT_FILE)
    try:
        with open(p, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def build_probe_credentials(mc, host, port, role="probe"):
    """
    用本机证书 + 私钥签 proof，构造与 APP/固件同格式的 MQTT 登录凭证。
    这与 monitor 连 broker 用的是同一套（serverAuthorizerReqHttp 12 元素 CBOR TBS）。
    """
    from cert_gen import (b64url_decode, b64url_encode, cbor_tbs,
                          cert_fingerprint, ed25519_sign, user_cert_tbs)
    cert_user = mc["cert_user"]
    user_tbs = user_cert_tbs(
        cert_user["issuerSn"], cert_user["subject"]["callsign"],
        cert_user["subject"]["uid"],
        b64url_decode(cert_user["subject"]["publicKey"]),
        cert_user["iat"], cert_user["exp"])
    user_fp = cert_fingerprint(user_tbs)
    ts = int(time.time())
    proof_tbs = ["FMO", 4, "serverAuthorizerReqHttp", 0, "", 0, role,
                 host, port, b64url_decode(mc["fingerprint"]), ts, user_fp]
    seed = b64url_decode(mc["cert_devicekey"]["seed"])
    sig = b64url_encode(ed25519_sign(seed, cbor_tbs(proof_tbs)))
    pw = b64url_encode(json.dumps({
        "certPackage": {"intermediateCert": mc["cert_int"], "userCert": cert_user},
        "targetCallsign": "", "targetUID": 0, "role": role,
        "targetUrl": host, "targetPort": port,
        "serverFingerprint": mc["fingerprint"], "timestamp": ts,
        "proof": {"signature": sig},
    }, separators=(",", ":")).encode("utf-8"))
    return cert_user["subject"]["callsign"], pw


CONNACK_MEANING = {
    0: "接受", 1: "协议版本不支持", 2: "标识符被拒", 3: "服务不可用",
    4: "用户名或密码错误", 5: "未授权（对方不信任本机根 CA）",
}


def probe_station_login(st, base_dir, timeout=MQTT_PROBE_TIMEOUT, cert=None):
    """
    真发一次 MQTT 登录（带本机证书 + proof），判断「我的 APP 能不能进这个站」。

    返回 (ok, detail)；ok 仅当 CONNACK 返回码 == 0（接受）。
      code=5 → 对方不信任本机根 CA（需要对方把我的根证书放进它的信任目录）
      code=4 → 用户名/密码（证书）不被接受
      无响应 → 超时/拒绝连接/域名解析失败

    ⚠️ 不要用「匿名 CONNECT 收到 CONNACK 就算能进」——broker 对匿名连接会回
       4/5（拒绝），那样会把**所有**台站都判成能进，完全是假数据。
    """
    addr = station_mqtt_addr(st)
    if not addr:
        return False, {"ok": False, "addr": "", "ms": 0, "code": None,
                       "error": "无 MQTT 地址"}
    host, _, port_s = addr.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return False, {"ok": False, "addr": addr, "ms": 0, "code": None,
                       "error": "端口非法"}
    mc = cert if cert is not None else load_probe_cert(base_dir)
    if not mc:
        return False, {"ok": False, "addr": addr, "ms": 0, "code": None,
                       "error": "本机无可用证书，无法验证能否进入"}

    t0 = time.time()
    s = None
    try:
        username, pw = build_probe_credentials(mc, host, port)
        cid = PROBE_CLIENTID_PREFIX + "%04X" % (int(time.time() * 1000) & 0xFFFF)
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(_mqtt_connect_packet(cid, username, pw))
        data = s.recv(16)
        ms = int((time.time() - t0) * 1000)
        if len(data) >= 4 and data[0] == 0x20:
            code = data[3]
            ok = (code == 0)
            return ok, {"ok": ok, "addr": addr, "ms": ms, "code": code,
                        "error": "" if ok else CONNACK_MEANING.get(
                            code, "CONNACK %s" % code)}
        return False, {"ok": False, "addr": addr, "ms": ms, "code": None,
                       "error": "不是 MQTT 服务（无 CONNACK）"}
    except Exception as e:  # noqa: BLE001
        return False, {"ok": False, "addr": addr,
                       "ms": int((time.time() - t0) * 1000), "code": None,
                       "error": _short_err(e)}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _short_err(e):
    s = str(e) or e.__class__.__name__
    for k, v in (("timed out", "超时"), ("Connection refused", "拒绝连接"),
                 ("Name or service not known", "域名解析失败"),
                 ("No route to host", "无法路由"),
                 ("Network is unreachable", "网络不可达"),
                 ("Temporary failure in name resolution", "域名解析失败")):
        if k in s:
            return v
    return s[:60]


def probe_all(store, base_dir, timeout=MQTT_PROBE_TIMEOUT, workers=8,
              logger=None, only_enterable=True):
    """
    并发探测台账里所有台站「我的证书能不能进入」，结果写回台账。

    only_enterable=True 时只回能进的（即「进不去的不显示」）。
    """
    log = logger or (lambda m: None)
    stations = store.all()
    if not stations:
        return [], {"total": 0, "enterable": 0, "unreachable": 0, "elapsed_ms": 0}
    cert = load_probe_cert(base_dir)
    if not cert:
        log("[APRS] 没有可用证书，无法探测能否进入")
        return ([], {"total": len(stations), "enterable": 0,
                     "unreachable": len(stations), "elapsed_ms": 0,
                     "error": "本机无可用证书"}) if only_enterable else (
            stations, {"total": len(stations), "enterable": 0,
                       "unreachable": 0, "elapsed_ms": 0})
    t0 = time.time()

    def job(st):
        ok, detail = probe_station_login(st, base_dir, timeout=timeout, cert=cert)
        store.note_probe(st.get("callsign"), ok, detail)
        return ok

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max(1, int(workers))) as ex:
            list(ex.map(job, stations))
    except Exception:  # noqa: BLE001
        for st in stations:
            job(st)

    store.save(force=True)
    allst = store.all()
    good = [s for s in allst if s.get("reachable")]
    bad = [s for s in allst if s.get("reachable") is False]
    summary = {"total": len(stations), "enterable": len(good),
               "unreachable": len(bad),
               "elapsed_ms": int((time.time() - t0) * 1000)}
    log("[APRS] 可进入性探测(真实登录): 共 %d，能进 %d，进不去 %d，用时 %dms"
        % (summary["total"], summary["enterable"], summary["unreachable"],
           summary["elapsed_ms"]))
    return (good if only_enterable else allst), summary


class AprsStationStore(object):
    """APRS 台站台账：按呼号累积 + 落盘（重启不丢，长期才能攒到几百个）。"""

    def __init__(self, base_dir, path=None):
        self.base_dir = base_dir
        self.path = path or os.path.join(base_dir, APRS_STATIONS_FILE)
        self._lock = threading.RLock()
        self._stations = {}
        self._last_save = 0.0
        self._load()

    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._stations = data.get("stations") or {}
        except Exception:
            self._stations = {}

    def save(self, force=False):
        now = time.time()
        if not force and (now - self._last_save) < SAVE_INTERVAL:
            return
        self._last_save = now
        try:
            with self._lock:
                payload = {"saved_at": now, "count": len(self._stations),
                           "stations": self._stations}
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def note(self, info):
        """记一个台站（同呼号更新，记录首见/末见/次数）。"""
        cs = (info.get("callsign") or "").strip()
        if not cs:
            return False
        now = time.time()
        with self._lock:
            old = self._stations.get(cs) or {}
            self._stations[cs] = {
                "callsign": cs,
                "name": info.get("name") or old.get("name") or "",
                "host": info.get("host") or old.get("host") or "",
                "port": info.get("port") or old.get("port"),
                "online": info.get("online"),
                "total": info.get("total"),
                "freq": info.get("freq") or old.get("freq") or "",
                "height": info.get("height") or old.get("height") or "",
                "rig": info.get("rig") or old.get("rig") or "",
                "ant": info.get("ant") or old.get("ant") or "",
                "cover_km": info.get("cover_km") or old.get("cover_km") or "",
                "country": info.get("country") or old.get("country") or "",
                "mark": info.get("mark") or old.get("mark") or "",
                "has_cert": bool(info.get("cert")) or bool(old.get("has_cert")),
                "first_seen": old.get("first_seen") or now,
                "last_seen": now,
                "hits": int(old.get("hits") or 0) + 1,
            }
        return True

    def note_probe(self, callsign, ok, detail=None):
        """记录「能不能进入」的探测结果。"""
        cs = (callsign or "").strip()
        if not cs:
            return
        d = detail or {}
        with self._lock:
            cur = self._stations.get(cs)
            if not cur:
                return
            cur["reachable"] = bool(ok)
            cur["probe_ms"] = d.get("ms")
            cur["probe_code"] = d.get("code")
            cur["probe_error"] = d.get("error") or ""
            cur["probed_at"] = time.time()

    def get(self, callsign):
        """取单个台站（判断是否首次发现用）。"""
        with self._lock:
            v = self._stations.get((callsign or "").strip())
            return dict(v) if v else None

    def all(self):
        with self._lock:
            return sorted((dict(v) for v in self._stations.values()),
                          key=lambda x: x.get("last_seen") or 0, reverse=True)

    def count(self):
        with self._lock:
            return len(self._stations)

    def stats(self):
        with self._lock:
            now = time.time()
            recent = sum(1 for v in self._stations.values()
                         if (now - (v.get("last_seen") or 0)) < 1800)
            online = 0
            enterable = 0
            by_reason = {}
            for v in self._stations.values():
                try:
                    online += int(v.get("online") or 0)
                except Exception:
                    pass
                if v.get("reachable"):
                    enterable += 1
                elif v.get("reachable") is False:
                    r = v.get("probe_error") or "未知原因"
                    by_reason[r] = by_reason.get(r, 0) + 1
            return {"total": len(self._stations), "recent_30min": recent,
                    "online_users": online, "enterable": enterable,
                    "by_reason": by_reason}


class AprsCollector(threading.Thread):
    """
    常驻 APRS 采集线程：**不限时一直听**，边发现台站边探测能不能进。

    为什么要常驻：台站广播有周期，只听几十秒只有个位数；长期累积才有几百个。
    「扫码」是不限时的 —— 发现一个新的就立刻拿去探测（真实登录），
    所以台账和「能进入」列表会自己长起来，不需要人守着点。
    """

    def __init__(self, store, host=APRS_HOST, port=APRS_PORT, logger=None,
                 base_dir=None):
        super(AprsCollector, self).__init__(name="aprs-collector")
        self.daemon = True
        self.store = store
        self.host = host
        self.port = int(port)
        self.base_dir = base_dir or getattr(store, "base_dir", ".")
        self.log = logger or (lambda m: None)
        self._stop = threading.Event()
        self._state = "idle"
        self._lines = 0
        self._fmo_lines = 0
        self._started_at = 0.0
        self._last_data_at = 0.0
        self._discovered = 0          # 本次运行新发现的台站数
        self._probed = 0              # 已探测次数
        self._enterable = 0
        self._lock = threading.Lock()
        self._pool = None
        self._probe_cert = None
        self._last_sweep = 0.0

    def _ensure_pool(self):
        if self._pool is None:
            try:
                from concurrent.futures import ThreadPoolExecutor
                self._pool = ThreadPoolExecutor(max_workers=8,
                                                thread_name_prefix="aprs-probe")
            except Exception:  # noqa: BLE001
                self._pool = None
        return self._pool

    def ensure_running(self):
        """采集线程死了就拉起来（不限时扫描必须保证它一直活着）。"""
        try:
            if not self.is_alive() and not self._stop.is_set():
                self.log("[APRS] 采集线程未运行，重新启动")
                self.start()
                return True
        except Exception:  # noqa: BLE001
            pass
        return False

    # ---------- 状态 ----------
    def status(self):
        with self._lock:
            return {"state": self._state, "host": self.host, "port": self.port,
                    "lines": self._lines, "fmo_lines": self._fmo_lines,
                    "discovered": self._discovered, "probed": self._probed,
                    "enterable": self._enterable,
                    "uptime_sec": int(time.time() - self._started_at)
                    if self._started_at else 0,
                    "last_data_sec_ago": int(time.time() - self._last_data_at)
                    if self._last_data_at else None}

    def _set_state(self, s):
        with self._lock:
            self._state = s

    def stop(self):
        self._stop.set()
        if self._pool is not None:
            try:
                self._pool.shutdown(wait=False)
            except Exception:  # noqa: BLE001
                pass

    # ---------- 探测（发现即探） ----------
    def _probe_one(self, st):
        """探测单个台站（真实登录），结果写回台账。"""
        if self._probe_cert is None:
            self._probe_cert = load_probe_cert(self.base_dir)
        if not self._probe_cert:
            return
        try:
            ok, detail = probe_station_login(st, self.base_dir, cert=self._probe_cert)
            self.store.note_probe(st.get("callsign"), ok, detail)
            self.store.save()
            with self._lock:
                self._probed += 1
                if ok:
                    self._enterable += 1
            if ok:
                self.log("[APRS] 能进入: %s「%s」%s"
                         % (st.get("callsign"), st.get("name"),
                            detail.get("addr")))
        except Exception as e:  # noqa: BLE001
            self.log("[APRS] 探测失败 %s: %s" % (st.get("callsign"), e))

    def _submit_probe(self, st):
        pool = self._ensure_pool()
        if pool is None:
            self._probe_one(st)
        else:
            try:
                pool.submit(self._probe_one, st)
            except Exception:  # noqa: BLE001
                self._probe_one(st)

    def sweep(self, force=False, min_interval=60.0):
        """
        全量重探一遍台账里的台站（限流：默认最多每 60 秒一轮）。
        常驻运行时会自动周期性调用；也是页面「扫描全部台站」的即时动作。
        """
        now = time.time()
        if not force and (now - self._last_sweep) < min_interval:
            return 0
        self._last_sweep = now
        stations = self.store.all()
        for st in stations:
            self._submit_probe(st)
        return len(stations)

    # ---------- 主循环 ----------
    def run(self):
        backoff = RECONNECT_MIN
        while not self._stop.is_set():
            try:
                self._session()
                backoff = RECONNECT_MIN
            except Exception as e:  # noqa: BLE001
                self._set_state("error")
                self.log("[APRS] 采集中断: %s（%ds 后重连）" % (e, int(backoff)))
                self._stop.wait(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX)

    def _session(self):
        self._set_state("connecting")
        s = socket.create_connection((self.host, self.port), timeout=15)
        try:
            s.sendall(APRS_LOGIN)
            s.settimeout(READ_TIMEOUT)
            self._started_at = time.time()
            self._set_state("connected")
            self.log("[APRS] 已连接 %s:%d，**不限时持续扫描** FMO 台站"
                     "（当前台账 %d 个）" % (self.host, self.port, self.store.count()))
            # 连上先对已有台账做一轮全量重探
            self.sweep(force=True)
            buf = b""
            last_sweep = time.time()
            while not self._stop.is_set():
                # 周期性重探（久没验过的台站可能已经关了/开了）
                if time.time() - last_sweep > 120.0:
                    last_sweep = time.time()
                    self.sweep()
                try:
                    data = s.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    raise IOError("APRS-IS 连接被对端关闭")
                buf += data
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    self._handle(raw)
                if len(buf) > 1 << 20:
                    buf = b""      # 防御：异常超长行
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _handle(self, raw):
        line = raw.decode("utf-8", "replace").rstrip("\r")
        with self._lock:
            self._lines += 1
            self._last_data_at = time.time()
        if "FMO" not in line:
            return
        with self._lock:
            self._fmo_lines += 1
        info = parse_aprs_line(line)
        if not info:
            return
        cs = info.get("callsign")
        was_known = bool(self.store.get(cs)) if hasattr(self.store, "get") else False
        if self.store.note(info):
            self.store.save()
            if not was_known:
                with self._lock:
                    self._discovered += 1
                self.log("[APRS] 新台站: %s「%s」%s"
                         % (cs, info.get("name"), station_mqtt_addr(info)))
                # 发现即探：新台站立刻拿去真实登录
                self._submit_probe(info)


def scan_now(store, seconds=30.0, host=APRS_HOST, port=APRS_PORT, logger=None):
    """
    现场听一段 APRS-IS，把解析到的台站并入台账。

    返回 (found, lines_scanned, errors)：
      found  = 本次解析出的**有效台站**个数（去重后的呼号数）
      errors = 错误说明列表（连不上/被拒等；不影响已有台账）
    常驻采集线程在跑时，这个函数用于「手动扫描」即时补一批。
    """
    log = logger or (lambda m: None)
    found_calls = {}
    errors = []
    lines = 0
    s = None
    try:
        s = socket.create_connection((host, port), timeout=15)
        s.sendall(APRS_LOGIN)
        s.settimeout(5.0)
        buf = b""
        deadline = time.time() + max(1.0, float(seconds))
        while time.time() < deadline:
            try:
                data = s.recv(65536)
            except socket.timeout:
                continue
            if not data:
                errors.append("APRS-IS 连接被对端关闭")
                break
            buf += data
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                lines += 1
                info = parse_aprs_line(raw.decode("utf-8", "replace").rstrip("\r"))
                if info:
                    store.note(info)
                    found_calls[info["callsign"]] = True
        store.save(force=True)
    except Exception as e:  # noqa: BLE001
        errors.append(str(e)[:120])
        log("[APRS] 手动扫描失败: %s" % e)
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return len(found_calls), lines, errors


def build_aprs_station_payload(store, collector=None, config=None, now=None,
                               only_enterable=False):
    """
    组装台站列表响应（页面用）。

    only_enterable=True → 只回「能进入」的台站（进不去的不显示）。
    未探测过的台站（reachable 为 None）在 only_enterable 模式下会被排除，
    避免把没验过的站当成能进的显示出去。
    """
    now = now or time.time()
    out = []
    for st in store.all():
        entry = dict(st)
        entry["entry_url"] = station_entry_url(st)
        entry["mqtt_addr"] = station_mqtt_addr(st)
        last = st.get("last_seen") or 0
        entry["alive"] = (now - last) < 3600          # 1 小时内还听到过
        if only_enterable and not entry.get("reachable"):
            continue
        out.append(entry)
    payload = {
        "ok": True,
        "generated_at": now,
        "stations": out,
        "stats": store.stats(),
        "only_enterable": bool(only_enterable),
        # 给对方接种本机根证书要用的**公网地址**（内网 IP 别人访问不到）
        "root_url": _public_root_url(config),
    }
    if collector is not None:
        payload["collector"] = collector.status()
    return payload


def _public_root_url(config):
    """本机根证书的公开下载地址（优先公网域名 + 公网端口）。"""
    cfg = config or {}
    host = str(cfg.get("app_domain") or cfg.get("domain") or "").strip()
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        base = host.rstrip("/")
    else:
        base = "http://%s:%s" % (host, cfg.get("app_port") or 35928)
    return base + "/api/ca/root.json?raw=1"
