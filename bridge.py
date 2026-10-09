#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bridge.py —— FUS 系统之间的 MQTT 语音互联（无主 / 可自选 / 抗断）
==================================================================

需求（用户原话）：
  「添加桥接功能，安装了 FUS 的系统 MQTT 之间可语音互传，进行互联；
    然后自主选择加入或者是不加入；无主节点形式的桥接；
    即使有一方断了，也能正常和其他服务器桥接。」

## 拓扑：单跳全网状，没有中心
每个系统只做两件事，彼此完全对等：

  1. **收**：连到对端的 broker，订阅「发给我的」语音主题，收到后在本机重播。
  2. **发**：把本机 `FMO/RAW` / `FMO/TELE` 语音，按对端主题发布到**本机** broker。

   A ──连B的broker──▶ B          A、B、C 两两直连，没有主节点；
   A ──连C的broker──▶ C          任意一条链路断了，其它链路照常工作（各自独立线程）。

## 主题（关键设计，决定了可控性与"不会串台"）
本机把某频道语音发给**某个指定对端**时，发布在**本机 broker** 上：

    FMO/BRIDGE/<本机节点>/to/<对端节点>/RAW        （RAW/TELE 各一条）

对端连到本机 broker 时，只订阅"发给自己的"：

    FMO/BRIDGE/+/to/<对端节点>/RAW

于是「我的语音给谁」是**逐对端可控**的 —— 这就是"自主选择加入或者不加入"。

收到对端语音后，在本机重播成（供本机监控/APP 消费）：

    FMO/BRIDGE/<源节点>/RAW

### 为什么这样就不会有回环 / 不会被审计误判
* 桥接主题全在 `FMO/BRIDGE/` 下，而本机审计规则的过滤是 `FROM "FMO/RAW/#"`，
  **不匹配** `FMO/BRIDGE/...` → 桥接语音不会被当成"本机报文"灌进身份审计。
  （否则外站呼号 + 本机连接身份会被判成"伪造"，甚至误封 —— 这是必须避开的坑。）
* 本机只订阅 `FMO/RAW`、`FMO/TELE` 这两个**源生**主题，从不再订阅/转发
  `FMO/BRIDGE/...`，所以「收到的远端语音」永远不会被再次外发 → 结构上无环。
* 再叠一层 (源节点, 频道, payload 摘要) 去重，即使配置出现环路也不会重复播放。
* 收到 `源节点 == 自己` 直接丢弃（自己发出去又绕回来的包）。

## 认证
连对端 broker 用本机**监控证书**（本服务器 CA 签发）走标准 MQTT 认证
（username=呼号，password=证书包+proof），与监控/探测同一套。对端只需信任本机
根 CA 即可放行 —— 这正是本系统已有的信任机制，不引入新的密钥体系。
"""

import hashlib
import json
import os
import queue
import threading
import time

try:
    from monitor import MqttError, MqttMiniClient
except Exception:  # noqa: BLE001  允许在无 monitor 依赖的场景下单独导入
    MqttError = Exception

    class MqttMiniClient(object):      # pragma: no cover - 极简占位
        def __init__(self, *a, **kw):
            raise RuntimeError("monitor 模块不可用，无法建立 MQTT 连接")

BRIDGE_ROOT = "FMO/BRIDGE"
# 节点名片：每个节点在自己 broker 上保留(retain)一条自己的 node_id。
# 为什么必须有它：A 给对端起的本地别名（peer-xxxx，按 host 派生）对端自己不认得；
# 而"发给某对端"的主题必须用**对端认得的名字**（也就是对端自己的 node_id），
# 否则对端订阅 FMO/BRIDGE/+/to/<自己的id>/RAW 永远匹配不上 —— 语音根本发不过去。
# 有了名片，连上就能自动学到对方 node_id，不用人工填。
ANNOUNCE_TOPIC = "%s/ANNOUNCE" % BRIDGE_ROOT
ANNOUNCE_INTERVAL = 60.0              # 定期重播名片（配合 retain，新连上的对端也能立刻拿到）
DEFAULT_PORT = 1883
CHANNELS = ("RAW", "TELE")            # 可桥接的频道（对应 FMO/RAW、FMO/TELE）
LOCAL_BROKER = ("127.0.0.1", 1883)

RECONNECT_MIN = 5.0                   # 对端重连退避初值（秒）
RECONNECT_MAX = 120.0
DEDUPE_TTL = 20.0                     # 同一帧在这段时间内只播一次
DEDUPE_MAX = 4000
CLIENTID_PREFIX = "FMO-BRIDGE-"

DEFAULT_BRIDGE = {
    "enabled": False,                 # 总开关。默认关：要不要互联由部署者自己决定
    "node_id": "",                    # 默认取 subsystem_id
    "node_name": "",
    "channels": ["RAW", "TELE"],
    "peers": [],
}


# ---------------------------------------------------------------- 主题工具

def slot(value):
    """把一个标识清洗成安全的**主题层级**（不能含 / + # 和空白）。"""
    s = str(value or "").strip()
    for ch in ("/", "+", "#", " ", "\t", "\n"):
        s = s.replace(ch, "_")
    return s or "unknown"


def out_topic(node_id, peer_id, channel):
    """本机发给指定对端的主题（发布在**本机** broker 上）。"""
    return "%s/%s/to/%s/%s" % (BRIDGE_ROOT, slot(node_id), slot(peer_id),
                               slot(channel))


def in_filter(node_id, channel):
    """连对端 broker 时订阅的过滤器：任何节点发给「我」的某频道。"""
    return "%s/+/to/%s/%s" % (BRIDGE_ROOT, slot(node_id), slot(channel))


def local_relay_topic(origin_id, channel):
    """把对端语音在本机重播时用的主题（供本机监控/APP 消费）。"""
    return "%s/%s/%s" % (BRIDGE_ROOT, slot(origin_id), slot(channel))


def peer_target(peer):
    """
    「发给这个对端」时该用的地址 = **对端自己的 node_id**（不是本机给它起的别名）。

    对端还没广播名片时返回 ""，表示暂时无法寻址（等下一步握手完成即可）。
    允许人工在配置里写 node_id 覆盖（极少数对端无法自动握手的场合）。
    """
    p = peer or {}
    explicit = str(p.get("node_id") or "").strip()
    if explicit:
        return slot(explicit)
    learned = str(p.get("remote_id") or "").strip()
    return slot(learned) if learned else ""


def parse_in_topic(topic, node_id, channel):
    """
    从收到的主题里取出**源节点**；不是"发给我的/该频道"就返回 ""。

    期望形状：FMO/BRIDGE/<源>/to/<我>/<频道>
    """
    origin, ch = parse_in_topic_any(topic, node_id)
    if not origin:
        return ""
    return origin if ch == slot(channel) else ""


def parse_in_topic_any(topic, node_id):
    """
    解析桥接入站主题，返回 (源节点, 频道)。

    形状必须是 FMO/BRIDGE/<源>/to/<我>/<频道>（**正好 6 层**）。
    层次/位置不对就当作不是发给我的：
      * 本机重播给本地消费者用的 FMO/BRIDGE/<源>/<频道> 只有 4 层 → 不匹配，
        这正是"中继进来的语音不会再被转发出去"的关键（不会形成回环）。
    """
    parts = str(topic or "").split("/")
    if len(parts) != 6:
        return "", ""
    if parts[0] != "FMO" or parts[1] != "BRIDGE":
        return "", ""
    if parts[3] != "to":
        return "", ""
    if parts[4] != slot(node_id):
        return "", ""
    origin = parts[2] or ""
    if not origin or origin in ("+", "#"):
        return "", ""
    return origin, parts[5].upper()


def peer_id_from_host(host, port=None):
    """
    对端没有显式 id 时，用 host(+port) 派生一个稳定 id。

    ★ 必须带上端口：同一台机器上跑两个 FUS（不同端口）很常见，
      只用 host 会让两个对端算出同一个 id，进而在配置里被去重成一个 —— 真实踩过。
    """
    h = str(host or "").strip().lower()
    if port is not None:
        h = "%s:%s" % (h, port)
    return "peer-" + hashlib.sha1(h.encode("utf-8")).hexdigest()[:10]


def normalize_peer(raw):
    """把配置里的对端条目规范化（容错：缺字段、类型不对都不崩）。"""
    p = raw if isinstance(raw, dict) else {}
    host = str(p.get("host") or "").strip()
    try:
        port = int(p.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    if not (0 < port < 65536):
        port = DEFAULT_PORT
    return {
        "id": str(p.get("id") or "").strip() or peer_id_from_host(host, port),
        "name": str(p.get("name") or "").strip() or host,
        "host": host,
        "port": port,
        # enabled = 「加入」：我连它、听它的语音
        "enabled": bool(p.get("enabled", True)),
        # send    = 「把我的语音发给它」
        "send": bool(p.get("send", True)),
        "note": str(p.get("note") or ""),
        # node_id   = 人工指定的对端节点 id（一般留空，由名片自动学）
        "node_id": str(p.get("node_id") or "").strip(),
        # remote_id = 从对端名片自动学到的节点 id（运行时字段，会持久化便于重启后直接用）
        "remote_id": str(p.get("remote_id") or "").strip(),
    }


def load_bridge_config(config):
    """从 config.json 的 bridge 节读出配置（与默认值合并 + 规范化）。"""
    cfg = dict(DEFAULT_BRIDGE)
    saved = (config or {}).get("bridge")
    if isinstance(saved, dict):
        cfg.update(saved)
    chans = [str(c).strip().upper() for c in (cfg.get("channels") or [])]
    chans = [c for c in chans if c in CHANNELS] or ["RAW"]
    cfg["channels"] = chans
    peers = []
    seen = set()
    for p in (cfg.get("peers") or []):
        np = normalize_peer(p)
        if not np["host"] or np["id"] in seen:
            continue
        seen.add(np["id"])
        peers.append(np)
    cfg["peers"] = peers
    cfg["enabled"] = bool(cfg.get("enabled"))
    return cfg


# ---------------------------------------------------------------- 对端连接

class BridgeLink(threading.Thread):
    """
    一个对端的独立连接线程。

    ★ 「一方断了也能和其他服务器桥接」就是靠这个结构：每个对端一条线程、
      一条独立 TCP、独立退避重连，彼此不共享任何状态。
    """

    def __init__(self, svc, peer):
        super().__init__(name="bridge-%s" % peer.get("id"), daemon=True)
        self.svc = svc
        self.peer_id = peer.get("id")
        self.peer = dict(peer)
        self.stop_event = threading.Event()
        self.connected = False
        self.state = "connecting"
        self.last_error = ""
        self.rx_frames = 0
        self.last_rx = 0.0
        self.reconnects = 0
        self.connected_at = 0.0
        self._client = None
        self._alive = True

    # ---- 状态 ----
    def snapshot(self):
        return {
            "id": self.peer_id,
            "name": self.peer.get("name") or self.peer.get("host"),
            "host": self.peer.get("host"),
            "port": self.peer.get("port"),
            "enabled": bool(self.peer.get("enabled")),
            "send": bool(self.peer.get("send")),
            "note": self.peer.get("note") or "",
            "connected": bool(self.connected),
            "state": self.state,
            "rx_frames": self.rx_frames,
            "last_rx": self.last_rx,
            "last_error": self.last_error,
            "reconnects": self.reconnects,
            "uptime": (time.time() - self.connected_at) if self.connected else 0.0,
            "alive": self._alive,
            # 从对端名片学到的节点标识；有了它才能真正把语音发过去
            "remote_id": self.peer.get("remote_id") or "",
            "addressed": bool(peer_target(self.peer)),
        }

    def stop(self):
        self.stop_event.set()

    # ---- 连接生命周期 ----
    def run(self):
        backoff = RECONNECT_MIN
        while not self.stop_event.is_set():
            self.state = "connecting"
            client = None
            try:
                creds = self.svc.credentials(self.peer["host"], self.peer["port"])
                if not creds:
                    raise MqttError("本机监控证书不可用（ca/monitor_cert.json），无法向对端认证")
                username, password = creds
                client = MqttMiniClient(
                    self.peer["host"], self.peer["port"],
                    "%s%s" % (CLIENTID_PREFIX, self.svc.client_suffix()),
                    username=username, password=password, keepalive=60,
                    on_message=self._on_message)
                self._client = client
                client.connect()
                subs = [in_filter(self.svc.node_id, ch) for ch in self.svc.channels]
                subs.append(ANNOUNCE_TOPIC)          # 顺便取对端名片，学到它的 node_id
                client.subscribe(subs)
                self.connected = True
                self.state = "connected"
                self.connected_at = time.time()
                self.last_error = ""
                backoff = RECONNECT_MIN
                self.svc.log("[BRIDGE] 已连接对端 %s（%s:%d）" % (
                    self.peer.get("name"), self.peer["host"], self.peer["port"]))
                while not self.stop_event.is_set():
                    client.poll_once()
            except Exception as e:  # noqa: BLE001
                self.connected = False
                self.state = "error"
                self.last_error = str(e)
                self.svc.log("[BRIDGE] 对端 %s 断开: %s（%.0fs 后重连）" % (
                    self.peer.get("name") or self.peer.get("host"), e, backoff))
            finally:
                self.connected = False
                self.connected_at = 0.0
                self._client = None
                if client is not None:
                    try:
                        client.disconnect()
                    except Exception:  # noqa: BLE001
                        pass
            if self.stop_event.wait(backoff):
                break
            backoff = min(backoff * 2, RECONNECT_MAX)
            self.reconnects += 1
        self._alive = False
        self.state = "stopped"

    def _on_message(self, topic, payload):
        # 节点名片：用于学到对端真实 node_id（寻址必需），不算语音流量
        if topic == ANNOUNCE_TOPIC:
            self.svc.on_peer_announce(self.peer_id, payload)
            return
        self.rx_frames += 1
        self.last_rx = time.time()
        self.svc.on_remote_frame(self.peer, topic, payload)

    def update_peer(self, peer):
        """配置变更：更新用于展示的字段（连接本身由服务决定是否重启）。"""
        self.peer = dict(peer)


# ---------------------------------------------------------------- 桥接服务

class VoiceBridge(object):
    """
    语音互联服务。持有：
      * 一条**本机 broker** 连接（订阅源生语音 + 重播远端语音）
      * 每个「加入」的对端一条 BridgeLink
    """

    def __init__(self, base_dir, config, save_fn=None, logger=None,
                 broker=None):
        self.base_dir = base_dir
        self.config = config if isinstance(config, dict) else {}
        self.save_fn = save_fn
        self._log_fn = logger
        self._lock = threading.RLock()
        self._cfg = load_bridge_config(self.config)
        self.node_id = (str(self._cfg.get("node_id") or "").strip()
                        or str(self.config.get("subsystem_id") or "node"))
        self.node_name = (str(self._cfg.get("node_name") or "").strip()
                          or self.node_id)
        self.channels = list(self._cfg.get("channels") or ["RAW"])
        b = broker or LOCAL_BROKER
        mon = self.config.get("monitor") or {}
        if broker is None and mon.get("mqtt_host"):
            b = (str(mon.get("mqtt_host")), int(mon.get("mqtt_port") or DEFAULT_PORT))
        self.broker_host, self.broker_port = b[0], int(b[1])

        self._stop = threading.Event()
        self._links = {}                      # peer_id -> BridgeLink
        self._local_client = None
        self._local_ready = False
        self._local_state = "disabled"
        self._local_error = ""
        self._out_queue = queue.Queue(maxsize=2000)   # 跨线程发布队列
        self._dedupe = {}
        self._stats = {"published": 0, "rx_frames": 0, "deduped": 0}
        self._peer_tx = {}                    # peer_id -> 已发出的消息数
        self._unaddressed = {}                # 已提示过"还没拿到名片"的对端
        self._last_announce = 0.0
        self._cert_cache = None
        self._thread = None

    # ---------------- 日志 / 证书 ----------------
    def log(self, msg):
        if self._log_fn:
            try:
                self._log_fn(msg)
            except Exception:  # noqa: BLE001
                pass

    def client_suffix(self):
        """clientid 后缀：必须以 FMO- 开头（EMQX ACL 只放行 FMO-* 的 connect）。"""
        return slot(self.node_id)[:40]

    def credentials(self, host, port):
        """
        用本机监控证书构造 MQTT 认证凭证（与监控/探测同一套）。
        返回 (username, password)；证书不可用返回 None。
        """
        try:
            from fmo_aprs import build_probe_credentials, load_probe_cert
        except Exception as e:  # noqa: BLE001
            self.log("[BRIDGE] 无法加载凭据模块: %s" % e)
            return None
        mc = self._cert_cache
        if mc is None:
            mc = load_probe_cert(self.base_dir)
            self._cert_cache = mc
        if not mc:
            return None
        try:
            return build_probe_credentials(mc, host, int(port), role="bridge")
        except Exception as e:  # noqa: BLE001
            self.log("[BRIDGE] 构造凭据失败: %s" % e)
            return None

    # ---------------- 生命周期 ----------------
    def start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="voice-bridge",
                                            daemon=True)
            self._thread.start()
        self.log("[BRIDGE] 互联桥接已启动（节点 %s，broker %s:%d，频道 %s）" % (
            self.node_id, self.broker_host, self.broker_port, ",".join(self.channels)))

    def stop(self):
        self._stop.set()
        cli = None
        with self._lock:
            for link in list(self._links.values()):
                link.stop()
            self._links.clear()
            cli = self._local_client
            self._local_client = None
        if cli is not None:
            try:
                cli.disconnect()
            except Exception:  # noqa: BLE001
                pass

    def _run(self):
        """本机 broker 连接的主循环；同时负责按需启停各对端链路。"""
        backoff = RECONNECT_MIN
        while not self._stop.is_set():
            self._sync_links()
            if not self._cfg.get("enabled"):
                self._local_state = "disabled"
                self._local_error = ""
                self._local_ready = False
                self._stop.wait(2.0)
                continue
            client = None
            try:
                self._local_state = "connecting"
                creds = self.credentials(self.broker_host, self.broker_port)
                if not creds:
                    raise MqttError("本机监控证书不可用（ca/monitor_cert.json）")
                username, password = creds
                client = MqttMiniClient(
                    self.broker_host, self.broker_port,
                    "%s%s-LOCAL" % (CLIENTID_PREFIX, self.client_suffix()),
                    username=username, password=password, keepalive=60,
                    on_message=self._on_local_message,
                    # ★ 读超时调小：本机连接除了收源生语音，还负责把"对端转来的
                    #   语音"重播出去（跨线程经队列投递）。如果用默认 5s 读超时，
                    #   重播要等这次读超时才发生 → 互联语音最多晚 5 秒，实时语音不可接受。
                    read_timeout=0.2)
                self._local_client = client
                client.connect()
                # 只订阅**源生**主题：FMO/RAW、FMO/TELE。
                # 绝不订阅 FMO/BRIDGE/... —— 这是"收到的远端语音不会再外发"的保证。
                client.subscribe(["FMO/%s" % ch for ch in self.channels])
                self._local_ready = True
                self._local_state = "connected"
                self._local_error = ""
                backoff = RECONNECT_MIN
                # 立刻广播一次自己的名片（retain），让连过来的对端马上能学到我的 node_id
                self._publish_announce(client)
                self._last_announce = time.time()
                self.log("[BRIDGE] 已连接本机 broker %s:%d，订阅 %s" % (
                    self.broker_host, self.broker_port,
                    ", ".join("FMO/%s" % c for c in self.channels)))
                while not self._stop.is_set():
                    client.poll_once()
                    self._drain_out_queue(client)   # 跨线程的重播请求在这里落地
                    # 总开关被关掉时立刻退出内层循环，回到外层去把连接收掉并置为 disabled。
                    # （否则会一直挂着旧连接，界面上看起来"关了还连着"）
                    if not self._cfg.get("enabled"):
                        break
                    if time.time() - self._last_announce > ANNOUNCE_INTERVAL:
                        self._last_announce = time.time()
                        self._publish_announce(client)
            except Exception as e:  # noqa: BLE001
                self._local_ready = False
                self._local_state = "error"
                self._local_error = str(e)
                # 正常停止时不报错（关 socket 后读循环必然抛异常，那不是故障）
                if not self._stop.is_set():
                    self.log("[BRIDGE] 本机 broker 连接断开: %s（%.0fs 后重连）" % (e, backoff))
            finally:
                self._local_ready = False
                self._local_client = None
                if client is not None:
                    try:
                        client.disconnect()
                    except Exception:  # noqa: BLE001
                        pass
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, RECONNECT_MAX)

    def _drain_out_queue(self, client):
        """把其它线程投递的重播请求，在本线程（唯一写者）发出去。"""
        for _ in range(200):
            try:
                topic, payload = self._out_queue.get_nowait()
            except queue.Empty:
                return
            try:
                client.publish(topic, payload)
            except Exception as e:  # noqa: BLE001
                self.log("[BRIDGE] 本机重播失败: %s" % e)
                return

    # ---------------- 收：本机源生语音 → 各对端 ----------------
    def _on_local_message(self, topic, payload):
        parts = str(topic or "").split("/")
        if len(parts) != 2 or parts[0] != "FMO":
            return                       # 只认 FMO/RAW、FMO/TELE 这种源生主题
        channel = parts[1].upper()
        if channel not in self.channels:
            return
        self._forward(channel, payload)

    def _publish_announce(self, client):
        """广播本机名片（retain=保留，后连上的对端也能立刻拿到）。"""
        try:
            payload = json.dumps({
                "node_id": self.node_id,
                "node_name": self.node_name,
                "ver": 1,
                "ts": int(time.time()),
            }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            client.publish(ANNOUNCE_TOPIC, payload, retain=True)
        except Exception as e:  # noqa: BLE001
            self.log("[BRIDGE] 广播节点名片失败: %s" % e)

    def on_peer_announce(self, peer_id, payload):
        """
        收到对端名片 → 记下它的真实 node_id（寻址必需）。
        只在变化时落盘，避免每 60 秒写一次配置文件。
        """
        try:
            data = json.loads((payload or b"").decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            return
        rid = str(data.get("node_id") or "").strip()
        if not rid or rid == self.node_id:
            return
        rname = str(data.get("node_name") or "").strip()
        with self._lock:
            for p in self._cfg["peers"]:
                if p.get("id") != peer_id:
                    continue
                changed = (p.get("remote_id") != rid)
                p["remote_id"] = rid
                if rname and not p.get("name_manual"):
                    # 对端名片里的名字更好看，但只在用户没自己命名时采用
                    if p.get("name") in (p.get("host"), "") or changed:
                        p["name"] = rname
                break
            else:
                return
            link = self._links.get(peer_id)
            if link is not None:
                link.update_peer(p)
        if changed:
            self._persist()
            self.log("[BRIDGE] 学到对端 %s 的节点标识: %s" % (rname or peer_id, rid))

    def _forward(self, channel, payload):
        with self._lock:
            if not self._cfg.get("enabled"):
                return
            peers = [dict(p) for p in self._cfg["peers"] if p.get("send")]
            client = self._local_client
        if client is None or not peers:
            return
        payload = payload or b""
        for p in peers:
            target = peer_target(p)
            if not target:
                # 还没收到对端名片 → 无法寻址。等下一步握手完成即可，
                # 这里不刷屏（只提示一次），也绝不退化成"广播"（那会让"发给谁"失控）。
                pid = p.get("id")
                if pid not in self._unaddressed:
                    self._unaddressed[pid] = True
                    self.log("[BRIDGE] 对端 %s 尚未广播节点名片，暂不发送语音（等握手）"
                             % p.get("name"))
                continue
            try:
                # 逐对端主题 → "我的语音给谁"可精确控制
                client.publish(out_topic(self.node_id, target, channel), payload)
                with self._lock:
                    self._stats["published"] += 1
                    self._peer_tx[p["id"]] = self._peer_tx.get(p["id"], 0) + 1
            except Exception as e:  # noqa: BLE001
                self.log("[BRIDGE] 转发到 %s 失败: %s" % (p.get("name"), e))
                return

    # ---------------- 发：对端语音 → 本机重播 ----------------
    def on_remote_frame(self, peer, topic, payload):
        """
        收到对端（或经对端 broker 中转的第三方）语音。

        - 源节点是自己 → 丢弃（自己绕回来的）
        - 该对端没「加入」或已删除 → 丢弃（自主选择：不加入就不接收）
        - 重复帧 → 丢弃
        然后投递到队列，由本机连接线程重播给本机消费者。
        """
        pid = (peer or {}).get("id")
        with self._lock:
            cur = None
            for p in self._cfg["peers"]:
                if p["id"] == pid:
                    cur = p
                    break
            if cur is None or not cur.get("enabled"):
                return
        payload = payload or b""
        origin, channel = parse_in_topic_any(topic, self.node_id)
        if not origin:
            return
        if channel not in self.channels:
            return
        if origin == slot(self.node_id):
            return                                    # 自己的包绕回来了
        if self._is_duplicate(origin, channel, payload):
            return
        with self._lock:
            self._stats["rx_frames"] += 1
        try:
            self._out_queue.put_nowait((local_relay_topic(origin, channel), payload))
        except queue.Full:
            self.log("[BRIDGE] 重播队列已满，丢弃一帧（对端流量过载）")

    def _is_duplicate(self, origin, channel, payload):
        key = (origin, channel, hashlib.sha1(payload).hexdigest())
        now = time.time()
        with self._lock:
            d = self._dedupe
            if len(d) > DEDUPE_MAX:
                for k in [k for k, t in d.items() if now - t > DEDUPE_TTL]:
                    d.pop(k, None)
            ts = d.get(key)
            if ts is not None and now - ts < DEDUPE_TTL:
                self._stats["deduped"] += 1
                return True
            d[key] = now
        return False

    # ---------------- 对端链路管理 ----------------
    def _sync_links(self):
        """按当前配置启停对端线程（配置改了不用重启进程）。"""
        with self._lock:
            enabled = bool(self._cfg.get("enabled"))
            want = {}
            if enabled:
                for p in self._cfg["peers"]:
                    if p.get("enabled") and p.get("host"):
                        want[p["id"]] = p
            # 停掉不再需要的
            for pid in list(self._links.keys()):
                if pid not in want:
                    link = self._links.pop(pid)
                    link.stop()
                    self.log("[BRIDGE] 已停止对端链路 %s（不加入或已删除）"
                             % (link.peer.get("name") or pid))
            # 启动新增的
            for pid, p in want.items():
                link = self._links.get(pid)
                if link is None or not link.is_alive():
                    link = BridgeLink(self, p)
                    self._links[pid] = link
                    link.start()
                    self.log("[BRIDGE] 已建立对端链路 %s（%s:%d）"
                             % (p.get("name"), p.get("host"), p.get("port")))
                else:
                    link.update_peer(p)

    # ---------------- 配置读写 ----------------
    def _persist(self):
        """把当前配置写回 config.json（由 api_server 注入的 save_fn 落盘）。"""
        with self._lock:
            self.config["bridge"] = {
                "enabled": bool(self._cfg.get("enabled")),
                "node_id": self._cfg.get("node_id") or "",
                "node_name": self._cfg.get("node_name") or "",
                "channels": list(self._cfg.get("channels") or ["RAW"]),
                "peers": [dict(p) for p in self._cfg.get("peers") or []],
            }
            snapshot = json.loads(json.dumps(self.config["bridge"]))
        if self.save_fn:
            try:
                self.save_fn(self.config)
            except Exception as e:  # noqa: BLE001
                self.log("[BRIDGE] 配置保存失败: %s" % e)
                return False
        return True

    def set_config(self, enabled=None, node_name=None, channels=None,
                   node_id=None):
        with self._lock:
            if enabled is not None:
                was = bool(self._cfg.get("enabled"))
                self._cfg["enabled"] = bool(enabled)
                if was and not self._cfg["enabled"]:
                    # 关掉总开关：立刻反映到状态上（连接由本机循环在 0.2s 内收掉），
                    # 否则界面会显示"已关闭但仍连着"。
                    self._local_ready = False
                    self._local_state = "disabled"
                    self._local_error = ""
            if node_name is not None and str(node_name).strip():
                self._cfg["node_name"] = str(node_name).strip()
                self.node_name = self._cfg["node_name"]
            if node_id is not None and str(node_id).strip():
                self._cfg["node_id"] = str(node_id).strip()
                self.node_id = self._cfg["node_id"]
            if channels is not None:
                chans = [str(c).strip().upper() for c in channels]
                chans = [c for c in chans if c in CHANNELS] or ["RAW"]
                self._cfg["channels"] = chans
                self.channels = list(chans)
        self._persist()
        self._sync_links()
        return self.public_config()

    def upsert_peer(self, data):
        """新增或修改一个对端。data 里带 id 即为修改。"""
        np = normalize_peer(data)
        if not np["host"]:
            return None, "缺少对端主机（host）"
        with self._lock:
            peers = self._cfg["peers"]
            for i, p in enumerate(peers):
                if p["id"] == np["id"]:
                    peers[i] = np
                    break
            else:
                peers.append(np)
        self._persist()
        self._sync_links()
        return np, ""

    def set_peer_field(self, pid, field, value):
        if field not in ("enabled", "send"):
            return None, "不支持的字段: %s" % field
        with self._lock:
            for p in self._cfg["peers"]:
                if p["id"] == pid:
                    p[field] = bool(value)
                    hit = dict(p)
                    break
            else:
                return None, "对端不存在: %s" % pid
        self._persist()
        self._sync_links()
        return hit, ""

    def delete_peer(self, pid):
        with self._lock:
            before = len(self._cfg["peers"])
            self._cfg["peers"] = [p for p in self._cfg["peers"] if p["id"] != pid]
            removed = before - len(self._cfg["peers"])
        if removed:
            self._persist()
            self._sync_links()
        return removed > 0

    def public_config(self):
        with self._lock:
            return {
                "enabled": bool(self._cfg.get("enabled")),
                "node_id": self.node_id,
                "node_name": self.node_name,
                "channels": list(self.channels),
                "peers": [dict(p) for p in self._cfg["peers"]],
            }

    def peers(self):
        return self.public_config()["peers"]

    # ---------------- 状态 ----------------
    def status(self):
        with self._lock:
            cfg = self.public_config()
            links = dict(self._links)
            stats = dict(self._stats)
            peer_tx = dict(self._peer_tx)
            peers_cfg = list(cfg["peers"])
        out_peers = []
        for p in peers_cfg:
            link = links.get(p["id"])
            if link is not None and link.is_alive():
                snap = link.snapshot()
            else:
                snap = {
                    "id": p["id"], "name": p.get("name"), "host": p.get("host"),
                    "port": p.get("port"), "enabled": bool(p.get("enabled")),
                    "send": bool(p.get("send")), "note": p.get("note") or "",
                    "connected": False,
                    "state": ("disabled" if not (cfg["enabled"] and p.get("enabled"))
                              else "connecting"),
                    "rx_frames": 0, "last_rx": 0.0, "last_error": "",
                    "reconnects": 0, "uptime": 0.0, "alive": False,
                    "remote_id": p.get("remote_id") or "",
                    "addressed": bool(peer_target(p)),
                }
            snap["tx_frames"] = peer_tx.get(p["id"], 0)
            out_peers.append(snap)
        return {
            "ok": True,
            "enabled": cfg["enabled"],
            "node_id": cfg["node_id"],
            "node_name": cfg["node_name"],
            "broker": "%s:%d" % (self.broker_host, self.broker_port),
            "topics": list(cfg["channels"]),
            "local_state": self._local_state,
            "local_error": self._local_error,
            "local_connected": bool(self._local_ready),
            "local": {
                "published": stats.get("published", 0),
                "rx_frames": stats.get("rx_frames", 0),
                "deduped": stats.get("deduped", 0),
            },
            "peers": out_peers,
        }
