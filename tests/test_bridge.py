#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT 互联桥接测试
==================
用户要求：装了 FUS 的系统之间 MQTT 语音互传；可自主选择加入/不加入；
无主节点形式；**即使有一方断了，也能正常和其他服务器桥接**。

这里用**假 broker**（真 socket、真 MQTT 报文）做集成验证，重点证明：
  * 双向转发真的能在 socket 上跑通（本机语音发出去、对端语音在本机重播）
  * 一个对端不可达时，另一个对端照常连接、照常收发（无主 + 抗断）
  * 不加入（enabled=false）就不接收；不发送（send=false）就不外发
  * 去重、自己绕回来的包丢弃
  * 桥接主题是 4 层重播 / 6 层点对点，不会形成回环
"""

import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

from tests import ROOT

sys.path.insert(0, ROOT)

import bridge as B  # noqa: E402


# ---------------------------------------------------------------- MQTT 报文工具

def enc_remlen(n):
    out = bytearray()
    while True:
        d = n % 128
        n //= 128
        if n > 0:
            d |= 0x80
        out.append(d)
        if n == 0:
            return bytes(out)


def enc_str(s):
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack(">H", len(b)) + b


def publish_packet(topic, payload):
    body = enc_str(topic) + bytes(payload)
    return bytes([0x30]) + enc_remlen(len(body)) + body


def pop_packet(buf):
    """从缓冲区里取出一个完整 MQTT 包 → ((first_byte, body) | None, rest)"""
    if len(buf) < 2:
        return None, buf
    mult, rl, i = 1, 0, 1
    while True:
        if i >= len(buf):
            return None, buf
        b = buf[i]
        rl += (b & 0x7F) * mult
        i += 1
        if not (b & 0x80):
            break
        mult *= 128
    if len(buf) < i + rl:
        return None, buf
    return (buf[0], buf[i:i + rl]), buf[i + rl:]


def parse_publish(pkt):
    body = pkt[1]
    tlen = struct.unpack_from(">H", body, 0)[0]
    topic = body[2:2 + tlen].decode("utf-8", "replace")
    return topic, body[2 + tlen:]


class FakeBroker(threading.Thread):
    """
    够用的假 MQTT broker：CONNECT→CONNACK 0、SUBSCRIBE→SUBACK、PINGREQ→PINGRESP，
    记录收到的 PUBLISH，**支持保留(retain)消息 + 订阅时补发**（桥接靠名片握手寻址），
    并能主动向订阅者推消息。
    """

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = []          # [(topic, payload)]
        self.clients = []           # 已连接的客户端 socket
        self.subs = {}              # socket -> [订阅过滤器]
        self.retained = {}          # topic -> payload（retain 标志的包）
        self.connect_count = 0
        self._stop = False
        self._lock = threading.Lock()

    def run(self):
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(0.3)
            with self._lock:
                self.clients.append(conn)
                self.connect_count += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _topic_matches(filt, topic):
        f, t = filt.split("/"), topic.split("/")
        if len(f) != len(t):
            return False
        return all(a == "+" or a == b for a, b in zip(f, t))

    def _serve(self, conn):
        buf = b""
        while not self._stop:
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while True:
                pkt, buf = pop_packet(buf)
                if pkt is None:
                    break
                t = pkt[0] >> 4
                try:
                    if t == 1:                       # CONNECT
                        conn.sendall(b"\x20\x02\x00\x00")
                    elif t == 8:                     # SUBSCRIBE
                        pid = struct.unpack_from(">H", pkt[1], 0)[0]
                        conn.sendall(bytes([0x90, 0x03]) + struct.pack(">H", pid) + b"\x00")
                        body = pkt[1][2:]
                        while len(body) > 0:
                            tlen = struct.unpack_from(">H", body, 0)[0]
                            filt = body[2:2 + tlen].decode("utf-8", "replace")
                            body = body[2 + tlen + 1:]
                            with self._lock:
                                self.subs.setdefault(conn, []).append(filt)
                                items = list(self.retained.items())
                            # 补发保留消息（真 broker 的行为）
                            for rt, rp in items:
                                if self._topic_matches(filt, rt):
                                    try:
                                        conn.sendall(publish_packet(rt, rp))
                                    except OSError:
                                        return
                    elif t == 3:                     # PUBLISH
                        retain = bool(pkt[0] & 0x01)
                        topic, payload = parse_publish(pkt)
                        if retain:
                            with self._lock:
                                self.retained[topic] = payload
                        with self._lock:
                            self.received.append((topic, payload))
                        # ★ 关键：像真 broker 一样把消息路由给订阅者，
                        #   否则"对端订阅我的主题"永远收不到东西。
                        self._route(topic, payload)
                    elif t == 12:                    # PINGREQ
                        conn.sendall(b"\xd0\x00")
                    elif t == 14:                    # DISCONNECT
                        return
                except OSError:
                    return

    def _route(self, topic, payload):
        pkt = publish_packet(topic, payload)
        with self._lock:
            targets = [(c, list(f)) for c, f in self.subs.items()]
        for conn, filts in targets:
            if any(self._topic_matches(f, topic) for f in filts):
                try:
                    conn.sendall(pkt)
                except OSError:
                    pass

    def push(self, topic, payload):
        """模拟"对端把语音发过来了"：向所有已连接客户端推一条 PUBLISH。"""
        pkt = publish_packet(topic, payload)
        with self._lock:
            clients = list(self.clients)
        for c in clients:
            try:
                c.sendall(pkt)
            except OSError:
                pass
        return len(clients)

    def got(self, topic=None):
        with self._lock:
            items = list(self.received)
        if topic is None:
            return items
        return [p for t, p in items if t == topic]

    def topics(self):
        with self._lock:
            return [t for t, _ in self.received]

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def wait_for(pred, timeout=6.0, interval=0.05):
    """等条件成立（网络/线程有延迟，不能靠固定 sleep 断言）"""
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(interval)
    return False


class BridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fus-bridge-")
        self.brokers = []
        self.bridges = []
        self.config = {"subsystem_id": "sub-TEST", "monitor": {}}

    def tearDown(self):
        for br in self.bridges:
            try:
                br.stop()
            except Exception:  # noqa: BLE001
                pass
        for bk in self.brokers:
            try:
                bk.stop()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def new_broker(self):
        bk = FakeBroker()
        bk.start()
        self.brokers.append(bk)
        return bk

    def new_bridge(self, local_broker, peers=None, enabled=True, node_id="sub-ME"):
        cfg = dict(self.config)
        cfg["subsystem_id"] = node_id
        cfg["bridge"] = {"enabled": enabled, "node_id": node_id,
                         "node_name": "本机", "peers": peers or []}
        svc = B.VoiceBridge(self.tmp, cfg, save_fn=lambda c: True, logger=None,
                            broker=("127.0.0.1", local_broker.port))
        # 测试里不依赖真证书：直接给出假凭据
        svc.credentials = lambda host, port: ("CALL", "pw")
        self.bridges.append(svc)
        return svc


# ---------------------------------------------------------------- 纯函数：主题

class TopicTests(unittest.TestCase):
    def test_out_and_in_shapes(self):
        self.assertEqual("FMO/BRIDGE/sub-A/to/sub-B/RAW",
                         B.out_topic("sub-A", "sub-B", "RAW"))
        self.assertEqual("FMO/BRIDGE/+/to/sub-B/RAW", B.in_filter("sub-B", "RAW"))
        self.assertEqual("FMO/BRIDGE/sub-A/RAW", B.local_relay_topic("sub-A", "RAW"))

    def test_parse_inbound(self):
        self.assertEqual(("sub-A", "RAW"),
                         B.parse_in_topic_any("FMO/BRIDGE/sub-A/to/sub-B/RAW", "sub-B"))
        self.assertEqual(("sub-A", "TELE"),
                         B.parse_in_topic_any("FMO/BRIDGE/sub-A/to/sub-B/TELE", "sub-B"))

    def test_not_for_me(self):
        self.assertEqual(("", ""),
                         B.parse_in_topic_any("FMO/BRIDGE/sub-A/to/sub-C/RAW", "sub-B"))

    def test_local_relay_is_not_inbound(self):
        """
        ★ 防回环的关键：本机重播主题只有 4 层，绝不能匹配入站解析，
        否则"中继进来的语音"会被再次当成"发给我的语音"转发出去 → 无限回环。
        """
        self.assertEqual(("", ""),
                         B.parse_in_topic_any("FMO/BRIDGE/sub-A/RAW", "sub-B"))

    def test_source_topics_are_not_bridge(self):
        for t in ("FMO/RAW", "FMO/TELE", "FMO/SERVER_INFO"):
            self.assertEqual(("", ""), B.parse_in_topic_any(t, "sub-B"))

    def test_slot_sanitizes(self):
        self.assertEqual("a_b_c", B.slot("a/b+c"))
        self.assertEqual("x", B.slot(" x "))
        self.assertEqual("unknown", B.slot(""))

    def test_peer_id_from_host_stable(self):
        self.assertEqual(B.peer_id_from_host("1.2.3.4"),
                         B.peer_id_from_host("1.2.3.4"))
        self.assertNotEqual(B.peer_id_from_host("1.2.3.4"),
                            B.peer_id_from_host("1.2.3.5"))


# ---------------------------------------------------------------- 配置

class ConfigTests(unittest.TestCase):
    def test_defaults_are_opt_in(self):
        cfg = B.load_bridge_config({})
        self.assertFalse(cfg["enabled"], "互联必须默认关闭，由部署者自己决定")
        self.assertEqual(["RAW", "TELE"], cfg["channels"])
        self.assertEqual([], cfg["peers"])

    def test_normalize_peer_defaults(self):
        p = B.normalize_peer({"host": "1.2.3.4"})
        self.assertEqual(1883, p["port"])
        self.assertTrue(p["enabled"])
        self.assertTrue(p["send"])
        self.assertTrue(p["id"])

    def test_bad_port_falls_back(self):
        self.assertEqual(1883, B.normalize_peer({"host": "h", "port": "xx"})["port"])
        self.assertEqual(1883, B.normalize_peer({"host": "h", "port": 999999})["port"])

    def test_unknown_channel_filtered(self):
        cfg = B.load_bridge_config({"bridge": {"channels": ["raw", "BOGUS"]}})
        self.assertEqual(["RAW"], cfg["channels"])

    def test_empty_host_peer_dropped(self):
        cfg = B.load_bridge_config({"bridge": {"peers": [{"host": ""}, {"host": "a"}]}})
        self.assertEqual(1, len(cfg["peers"]))

    def test_duplicate_peers_deduped(self):
        cfg = B.load_bridge_config({"bridge": {"peers": [
            {"id": "p1", "host": "a"}, {"id": "p1", "host": "b"}]}})
        self.assertEqual(1, len(cfg["peers"]))


# ---------------------------------------------------------------- 对端管理

class PeerManagementTests(BridgeTestCase):
    def test_upsert_toggle_delete(self):
        svc = self.new_bridge(self.new_broker(), enabled=False)
        peer, err = svc.upsert_peer({"name": "站点甲", "host": "10.0.0.1"})
        self.assertEqual("", err)
        pid = peer["id"]
        self.assertEqual(1, len(svc.peers()))

        # 修改同一个（同 host → 同 id）
        peer2, _ = svc.upsert_peer({"name": "站点甲改", "host": "10.0.0.1"})
        self.assertEqual(pid, peer2["id"])
        self.assertEqual("站点甲改", svc.peers()[0]["name"])
        self.assertEqual(1, len(svc.peers()))

        hit, err = svc.set_peer_field(pid, "enabled", False)
        self.assertEqual("", err)
        self.assertFalse(hit["enabled"])
        self.assertFalse(svc.peers()[0]["enabled"])

        self.assertTrue(svc.delete_peer(pid))
        self.assertEqual([], svc.peers())
        self.assertFalse(svc.delete_peer(pid))

    def test_upsert_requires_host(self):
        svc = self.new_bridge(self.new_broker(), enabled=False)
        peer, err = svc.upsert_peer({"name": "没有主机"})
        self.assertIsNone(peer)
        self.assertTrue(err)

    def test_unsupported_field_rejected(self):
        svc = self.new_bridge(self.new_broker(), enabled=False)
        svc.upsert_peer({"host": "10.0.0.1"})
        pid = svc.peers()[0]["id"]
        _, err = svc.set_peer_field(pid, "evil", True)
        self.assertTrue(err)

    def test_config_persisted_via_save_fn(self):
        saved = {}

        def save(cfg):
            saved.update(cfg)
            return True

        bk = self.new_broker()
        cfg = dict(self.config)
        cfg["bridge"] = {"enabled": False, "peers": []}
        svc = B.VoiceBridge(self.tmp, cfg, save_fn=save, logger=None,
                            broker=("127.0.0.1", bk.port))
        svc.credentials = lambda h, p: ("C", "P")
        self.bridges.append(svc)
        svc.upsert_peer({"name": "甲", "host": "10.0.0.1"})
        self.assertIn("bridge", saved)
        self.assertEqual(1, len(saved["bridge"]["peers"]))
        self.assertEqual("10.0.0.1", saved["bridge"]["peers"][0]["host"])

    def test_save_fn_called_with_config_for_api_save_config(self):
        """
        api_server.save_config 的签名必须能接住桥接的调用约定 save_fn(cfg)。
        真实事故：save_config() 不收参数 → 每次改对端都报
        "takes 0 positional arguments but 1 was given"，**配置根本没落盘**。
        """
        import inspect
        import api_server
        sig = inspect.signature(api_server.save_config)
        self.assertGreaterEqual(len(sig.parameters), 1,
                                "save_config 必须能接受 cfg 参数")


# ---------------------------------------------------------------- 集成：真 socket

class BridgeIntegrationTests(BridgeTestCase):
    def test_local_voice_published_for_peers_to_pull(self):
        """
        本机语音按"逐对端主题"发布在**本机 broker** 上，由对端连过来拉取。
        （发布在本机 = 本机只发 N-1 条；对端订阅 FMO/BRIDGE/+/to/<自己>/RAW 取走）
        """
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "对端甲", "host": "127.0.0.1", "port": remote.port,
             "node_id": "sub-PEER",           # 人工指定对端节点标识（也可由名片自动学）
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["local_connected"]),
                        "本机 broker 应连上")
        want = B.out_topic("sub-ME", "sub-PEER", "RAW")

        local.push("FMO/RAW", b"\x01\x02voice")
        self.assertTrue(wait_for(lambda: local.got(want)),
                        "本机 broker 应出现逐对端出站主题=%s，实际=%s"
                        % (want, local.topics()))
        self.assertEqual(b"\x01\x02voice", local.got(want)[0])
        # 而且这个主题必须正好能被该对端的订阅过滤器取到
        self.assertTrue(self._topic_matches(B.in_filter("sub-PEER", "RAW"), want))

    @staticmethod
    def _topic_matches(filt, topic):
        f, t = filt.split("/"), topic.split("/")
        if len(f) != len(t):
            return False
        return all(a == "+" or a == b for a, b in zip(f, t))

    def test_remote_voice_relayed_locally(self):
        """对端发来的语音应当在本机 broker 上重播（供本机监控/APP 消费）。"""
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "对端甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))

        remote.push("FMO/BRIDGE/sub-PEER/to/sub-ME/RAW", b"remote-voice")
        want = B.local_relay_topic("sub-PEER", "RAW")
        self.assertTrue(wait_for(lambda: local.got(want)),
                        "本机应重播对端语音，主题=%s，实际=%s" % (want, local.topics()))
        self.assertEqual(b"remote-voice", local.got(want)[0])

    def test_one_peer_down_does_not_break_the_other(self):
        """
        ★ 核心要求：无主 + 一方断了不影响其他。
        两个对端：一个可达、一个不可达（连不上的端口）。
        可达那个必须照常连上、照常收发。
        """
        local = self.new_broker()
        good = self.new_broker()
        # 占一个端口然后立刻关掉 → 该端口必定连不上
        dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        svc = self.new_bridge(local, peers=[
            {"name": "好的对端", "host": "127.0.0.1", "port": good.port,
             "node_id": "sub-GOOD",           # 人工指定（也验证该覆盖路径）
             "enabled": True, "send": True},
            {"name": "坏的对端", "host": "127.0.0.1", "port": dead_port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["local_connected"]))

        def good_connected():
            for p in svc.status()["peers"]:
                if p["port"] == good.port:
                    return p["connected"]
            return False

        self.assertTrue(wait_for(good_connected, timeout=8),
                        "可达的对端必须连上（不受不可达对端影响）")

        # 坏对端确实处于错误态
        self.assertTrue(wait_for(lambda: any(
            p["port"] == dead_port and p["state"] in ("error", "connecting")
            for p in svc.status()["peers"])))

        # 好对端照常收到本机语音（发在本机 broker 上，由它拉取）
        local.push("FMO/RAW", b"still-works")
        want = B.out_topic("sub-ME", "sub-GOOD", "RAW")
        self.assertTrue(wait_for(lambda: local.got(want)),
                        "坏对端存在时，好对端那一路仍必须照常发出语音")

    def test_two_nodes_voice_roundtrip(self):
        """
        ★ 端到端：两个真实节点互连，A 站的语音必须能在 B 站听到（反向也要通）。
        这就是"安装了 FUS 的系统 MQTT 之间可语音互传"的最小可验证形态。
        """
        broker_a = self.new_broker()
        broker_b = self.new_broker()
        a = self.new_bridge(broker_a, node_id="sub-A", peers=[
            {"name": "B站", "host": "127.0.0.1", "port": broker_b.port,
             "enabled": True, "send": True}])
        b = self.new_bridge(broker_b, node_id="sub-B", peers=[
            {"name": "A站", "host": "127.0.0.1", "port": broker_a.port,
             "enabled": True, "send": True}])
        a.start()
        b.start()
        self.assertTrue(wait_for(lambda: a.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: b.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: a.status()["peers"][0]["connected"]))
        self.assertTrue(wait_for(lambda: b.status()["peers"][0]["connected"]))

        # A 站本地收到一个语音帧 → 应当出现在 B 站的 broker 上（B 重播给本机消费者）
        broker_a.push("FMO/RAW", b"voice-from-A")
        want_a = B.local_relay_topic("sub-A", "RAW")
        self.assertTrue(wait_for(lambda: broker_b.got(want_a), timeout=8),
                        "A 站语音应被 B 站重播到本机，主题=%s，B实际=%s"
                        % (want_a, broker_b.topics()))
        self.assertEqual(b"voice-from-A", broker_b.got(want_a)[-1])

        # 反向：B 站本地语音也要能被 A 站听到
        broker_b.push("FMO/RAW", b"voice-from-B")
        want_b = B.local_relay_topic("sub-B", "RAW")
        self.assertTrue(wait_for(lambda: broker_a.got(want_b), timeout=8),
                        "B 站语音应被 A 站重播到本机")

    def test_third_node_survives_a_peer_going_down(self):
        """
        ★ "即使有一方断了，也能正常和其他服务器桥接"：
        A 同时连 B 和 C；B 挂掉后，A 与 C 的互联必须照常。
        """
        broker_a = self.new_broker()
        broker_b = self.new_broker()
        broker_c = self.new_broker()
        a = self.new_bridge(broker_a, node_id="sub-A", peers=[
            {"name": "B站", "host": "127.0.0.1", "port": broker_b.port,
             "enabled": True, "send": True},
            {"name": "C站", "host": "127.0.0.1", "port": broker_c.port,
             "enabled": True, "send": True}])
        c = self.new_bridge(broker_c, node_id="sub-C", peers=[
            {"name": "A站", "host": "127.0.0.1", "port": broker_a.port,
             "enabled": True, "send": True}])
        a.start()
        c.start()
        self.assertTrue(wait_for(lambda: len([p for p in a.status()["peers"]
                                              if p["connected"]]) == 2, timeout=8),
                        "A 应同时连上 B 和 C")

        # B 挂了
        broker_b.stop()
        time.sleep(1.5)
        # A 与 C 的链路不受影响，语音照常互通
        broker_a.push("FMO/RAW", b"after-B-down")
        self.assertTrue(wait_for(lambda: broker_c.got(B.local_relay_topic("sub-A", "RAW")),
                                 timeout=8),
                        "B 挂掉后，A 与 C 必须仍能语音互通")
        # C 的链路仍是 connected
        st = c.status()
        self.assertTrue(st["peers"][0]["connected"], "C 到 A 的链路应保持连接")

    def test_disabled_peer_is_not_connected(self):
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "不加入", "host": "127.0.0.1", "port": remote.port,
             "enabled": False, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["local_connected"]))
        time.sleep(1.0)
        st = svc.status()
        self.assertFalse(st["peers"][0]["connected"], "未加入的对端不该建立连接")
        self.assertEqual("disabled", st["peers"][0]["state"])

    def test_send_false_does_not_publish(self):
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "只听不发", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": False}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))
        local.push("FMO/RAW", b"should-not-go-out")
        time.sleep(1.2)
        self.assertEqual([], remote.got(B.out_topic("sub-ME", svc.peers()[0]["id"], "RAW")),
                         "send=false 时不该把本机语音发给该对端")

    def test_disabled_global_stops_everything(self):
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, enabled=False, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        time.sleep(1.0)
        st = svc.status()
        self.assertFalse(st["enabled"])
        self.assertFalse(st["local_connected"], "总开关关闭时不该连本机 broker")
        self.assertFalse(st["peers"][0]["connected"])
        local.push("FMO/RAW", b"nope")
        time.sleep(0.8)
        self.assertEqual([], remote.got())

    def test_turning_off_disconnects_immediately(self):
        """
        运行中把总开关关掉，必须真的断开，而不是"关了还连着"。
        （真实踩过：状态一直停在 connected，界面上看着像没关掉。）
        """
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "node_id": "sub-PEER", "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))

        svc.set_config(enabled=False)
        self.assertFalse(svc.status()["local_connected"],
                         "关掉后 local_connected 必须立刻为 False")
        self.assertEqual("disabled", svc.status()["local_state"])
        self.assertTrue(wait_for(
            lambda: svc.status()["peers"][0]["state"] == "disabled", timeout=5),
            "对端链路也必须停掉")

    def test_dedupe_same_frame(self):
        """同一帧重复到达只重播一次。"""
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))
        topic = "FMO/BRIDGE/sub-PEER/to/sub-ME/RAW"
        remote.push(topic, b"dup-frame")
        want = B.local_relay_topic("sub-PEER", "RAW")
        self.assertTrue(wait_for(lambda: local.got(want)))
        remote.push(topic, b"dup-frame")
        remote.push(topic, b"dup-frame")
        time.sleep(1.0)
        self.assertEqual(1, len(local.got(want)), "重复帧必须被去重")
        self.assertGreaterEqual(svc.status()["local"]["deduped"], 2)

    def test_own_frame_coming_back_is_dropped(self):
        """自己发出去又绕回来的包必须丢弃（防回环）。"""
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))
        remote.push("FMO/BRIDGE/sub-ME/to/sub-ME/RAW", b"echo-of-myself")
        time.sleep(1.0)
        self.assertEqual([], local.got(B.local_relay_topic("sub-ME", "RAW")),
                         "自己的包不该在本机重播")

    def test_relayed_frame_is_not_resent_to_peers(self):
        """
        ★ 防回环：中继进来的语音只在本机重播（4 层主题），
        绝不能再按"发给对端"的 6 层主题发出去，否则 A→B→C→A 会无限放大。
        """
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))
        remote.push("FMO/BRIDGE/sub-OTHER/to/sub-ME/RAW", b"from-other")
        self.assertTrue(wait_for(lambda: local.got(B.local_relay_topic("sub-OTHER", "RAW"))))
        time.sleep(0.8)
        # 本机 broker 上不该出现任何"把 sub-OTHER 的语音发给对端"的 6 层主题
        for t in local.topics():
            if "sub-OTHER" in t:
                self.assertFalse(t.startswith("FMO/BRIDGE/sub-ME/to/"),
                                 "中继语音被再次外发会形成回环: %s" % t)
                self.assertEqual(4, len(t.split("/")),
                                 "中继语音只能是 4 层本机重播主题: %s" % t)

    def test_unknown_channel_payload_ignored(self):
        local = self.new_broker()
        remote = self.new_broker()
        svc = self.new_bridge(local, peers=[
            {"name": "甲", "host": "127.0.0.1", "port": remote.port,
             "enabled": True, "send": True}])
        svc.start()
        self.assertTrue(wait_for(lambda: svc.status()["peers"][0]["connected"]))
        remote.push("FMO/BRIDGE/sub-P/to/sub-ME/VIDEO", b"nope")
        time.sleep(0.8)
        self.assertEqual([], [t for t in local.topics() if "sub-P" in t],
                         "不在桥接频道白名单里的消息应忽略")

    def test_status_shape(self):
        """状态结构必须满足前端契约。"""
        local = self.new_broker()
        svc = self.new_bridge(local, peers=[{"name": "甲", "host": "10.9.9.9"}])
        st = svc.status()
        for k in ("ok", "enabled", "node_id", "node_name", "broker", "topics",
                  "local", "peers"):
            self.assertIn(k, st)
        for k in ("published", "rx_frames", "deduped"):
            self.assertIn(k, st["local"])
        p = st["peers"][0]
        for k in ("id", "name", "host", "port", "enabled", "send", "connected",
                  "state", "rx_frames", "tx_frames", "last_rx", "last_error",
                  "reconnects", "uptime"):
            self.assertIn(k, p)


class PackagingTests(unittest.TestCase):
    """互联功能必须能随发行包发布，别人装上才有这个入口。"""

    def test_in_build_release(self):
        src = open(os.path.join(ROOT, "build_release.sh"), encoding="utf-8").read()
        self.assertIn("bridge.py", src)

    def test_admin_page_and_route(self):
        for f in ("admin/bridge.html", "admin/bridge.js"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), "%s 缺失" % f)
        api = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("/admin/bridge", api)
        self.assertIn("_handle_bridge_routes", api)
        for route in ("/api/bridge/status", "/api/bridge/peers",
                      "/api/bridge/peers/toggle", "/api/bridge/peers/delete",
                      "/api/bridge/config", "/api/bridge/candidates"):
            self.assertIn(route, api, "缺少接口 %s" % route)

    def test_portal_links_to_bridge(self):
        portal = open(os.path.join(ROOT, "admin", "portal.html"), encoding="utf-8").read()
        self.assertIn("/admin/bridge", portal)

    def test_bridge_api_not_public(self):
        """桥接管理接口绝不能出现在公网白名单里（公网口必须 403）。"""
        api = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        for name in ("PUBLIC_GET_PATHS", "PUBLIC_POST_PATHS"):
            block = api.split(name, 1)[1].split(")", 1)[0]
            self.assertNotIn("bridge", block, "%s 里不该有 bridge" % name)

    def test_monitor_subscribes_bridge_topics(self):
        mon = open(os.path.join(ROOT, "monitor.py"), encoding="utf-8").read()
        self.assertIn("BRIDGE_TOPICS", mon)
        self.assertIn("FMO/BRIDGE/+/RAW", mon)

    def test_installers_mention_bridge_page(self):
        for name in ("install.sh", "install-bas.sh"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            self.assertIn("/admin/bridge", src, "%s 未提到互联入口" % name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
