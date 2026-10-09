#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT 互联桥接测试（集群模型）
==============================
用户要求：
  「这个服务器选择是否加入集群，确认加入集群的服务器之间实现语音互通，
    而不是我选择哪一个服务器互通。」

所以语义是**服务器级加入集群**：
  * 一个开关 = 加入 / 退出集群；
  * 加入的服务器之间**自动全互通**，不需要双方互相添加、也不用手工挑对端；
  * 成员发现靠"候选（APRS 里能进去的台站）+ 名片确认（对方也声明已加入集群）"；
  * 一方断了不影响其他成员的互联。

用**假 broker**（真 socket、真 MQTT 报文、含订阅路由与保留消息）做集成验证。
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
    return body[2:2 + tlen].decode("utf-8", "replace"), body[2 + tlen:]


class FakeBroker(threading.Thread):
    """
    够用的假 MQTT broker：CONNECT→CONNACK 0、SUBSCRIBE→SUBACK、PINGREQ→PINGRESP，
    记录 PUBLISH，**支持保留消息（订阅时补发）与真实的消息路由**，
    并能主动向订阅者推消息。
    """

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.received = []
        self.clients = []
        self.subs = {}
        self.retained = {}
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
                    if t == 1:
                        conn.sendall(b"\x20\x02\x00\x00")
                    elif t == 8:
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
                            for rt, rp in items:      # 补发保留消息
                                if self._topic_matches(filt, rt):
                                    try:
                                        conn.sendall(publish_packet(rt, rp))
                                    except OSError:
                                        return
                    elif t == 3:
                        retain = bool(pkt[0] & 0x01)
                        topic, payload = parse_publish(pkt)
                        if retain:
                            with self._lock:
                                self.retained[topic] = payload
                        with self._lock:
                            self.received.append((topic, payload))
                        self._route(topic, payload)
                    elif t == 12:
                        conn.sendall(b"\xd0\x00")
                    elif t == 14:
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
        """模拟某站本地有人说话（源生语音进入它的 broker）。"""
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


def wait_for(pred, timeout=8.0, interval=0.05):
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

    def new_bridge(self, local_broker, node_id="sub-ME", enabled=True,
                   candidates=None, peers=None, publish_local=True):
        cfg = {"subsystem_id": node_id, "monitor": {},
               "bridge": {"enabled": enabled, "node_id": node_id,
                          "node_name": node_id, "publish_local": publish_local,
                          "peers": peers or []}}
        # 名册来源模拟"从总服务器拉到的 FUS 分系统清单"：{host, port, name, subsystem_id}
        src = None
        if candidates is not None:
            src = lambda: [dict(c) for c in candidates]      # noqa: E731
        svc = B.VoiceBridge(self.tmp, cfg, save_fn=lambda c: True, logger=None,
                            broker=("127.0.0.1", local_broker.port),
                            candidate_source=src)
        svc.credentials = lambda host, port: ("CALL", "pw")
        self.bridges.append(svc)
        return svc

    @staticmethod
    def cand(broker, name, subsystem_id=""):
        return {"host": "127.0.0.1", "port": broker.port, "name": name,
                "subsystem_id": subsystem_id}


# ---------------------------------------------------------------- 主题

class TopicTests(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual("FMO/BRIDGE/sub-A/RAW", B.out_topic("sub-A", "RAW"))
        self.assertEqual("FMO/BRIDGE/+/RAW", B.in_filter("RAW"))
        self.assertEqual("FMO/BRIDGE/local/sub-A/RAW",
                         B.local_relay_topic("sub-A", "RAW"))

    def test_parse_member_voice(self):
        self.assertEqual(("sub-A", "RAW"), B.parse_in_topic("FMO/BRIDGE/sub-A/RAW"))
        self.assertEqual(("sub-A", "TELE"), B.parse_in_topic("FMO/BRIDGE/sub-A/TELE"))

    def test_local_relay_not_inbound(self):
        """
        ★ 防中转洪泛/回环的关键：本机重播主题是 5 层，
        对端订阅的过滤器是 4 层，匹配不到 → 中继语音不会被再传出去。
        """
        self.assertEqual(("", ""),
                         B.parse_in_topic("FMO/BRIDGE/local/sub-A/RAW"))
        self.assertFalse(BridgeTestCase.__dict__ and
                         FakeBroker._topic_matches(B.in_filter("RAW"),
                                                   B.local_relay_topic("sub-A", "RAW")))

    def test_non_bridge_topics_rejected(self):
        for t in ("FMO/RAW", "FMO/BRIDGE/ANNOUNCE",
                  "FMO/BRIDGE/sub-A/to/sub-B/RAW", ""):
            self.assertEqual(("", ""), B.parse_in_topic(t))

    def test_slot(self):
        self.assertEqual("a_b_c", B.slot("a/b+c"))
        self.assertEqual("unknown", B.slot(""))


# ---------------------------------------------------------------- 配置

class ConfigTests(unittest.TestCase):
    def test_defaults_are_opt_in(self):
        cfg = B.load_bridge_config({})
        self.assertFalse(cfg["enabled"], "默认不加入集群，由部署者自己决定")
        self.assertTrue(cfg["publish_local"], "加入集群后默认把自己的语音放出去")
        self.assertEqual(["RAW", "TELE"], cfg["channels"])

    def test_peer_normalize(self):
        p = B.normalize_peer({"host": "1.2.3.4"})
        self.assertEqual(1883, p["port"])
        self.assertTrue(p["enabled"])
        self.assertNotIn("send", p, "拉取模型下没有「逐个发送」开关")

    def test_peer_id_includes_port(self):
        """同一主机不同端口必须是两个成员（否则会被去重成一个）。"""
        self.assertNotEqual(B.peer_id_from_host("h", 1883),
                            B.peer_id_from_host("h", 2883))

    def test_bad_port(self):
        self.assertEqual(1883, B.normalize_peer({"host": "h", "port": "x"})["port"])


# ---------------------------------------------------------------- 集群集成

class ClusterTests(BridgeTestCase):
    def test_member_count_includes_self(self):
        """
        ★ 用户反馈：点了加入集群还显示 0，看不出自己进去没有。
        刚加入、还没有别的成员时，集群成员数应当是 **1**（本机自己）。
        """
        local = self.new_broker()
        a = self.new_bridge(local, node_id="sub-A", candidates=[])
        st = a.status()
        self.assertTrue(st["enabled"])
        self.assertEqual(1, st["member_count"], "加入集群后成员数应含自己=1")
        self.assertEqual(0, st["peer_member_count"])
        self.assertTrue(st["self_joined"])
        # 退出后应回到 0
        a.set_config(enabled=False)
        self.assertEqual(0, a.status()["member_count"])

    def test_registry_identity_mismatch_is_rejected(self):
        """
        ★ 相互验证：总服务器名册登记了这个地址对应哪个 subsystem_id，
        对方名片里的节点标识必须与之一致。不一致 → 不认作成员。
        （真实场景：同一台机器在名册里登记了两个域名，其中一个指向本机自己。）
        """
        local = self.new_broker()
        other = self.new_broker()
        b = self.new_bridge(other, node_id="sub-REAL", candidates=[])
        b.start()
        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(other, "冒名", "sub-OTHER")])
        a.start()
        self.assertTrue(wait_for(lambda: a.status()["local_connected"]))
        self.assertTrue(wait_for(
            lambda: any(p["state"] == "not_member" for p in a.status()["peers"]),
            timeout=20), "名册不符的不能算成员")
        st = a.status()
        self.assertEqual(0, st["peers"][0]["member"])
        self.assertEqual(1, st["member_count"], "只有本机自己")

    def test_registry_identity_match_is_accepted(self):
        """名册登记与名片一致 → 正常认作成员。"""
        local = self.new_broker()
        other = self.new_broker()
        b = self.new_bridge(other, node_id="sub-B", candidates=[])
        b.start()
        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(other, "B站", "sub-B")])
        a.start()
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1, timeout=15),
                        "应确认 1 个对端成员")

    def test_join_cluster_connects_automatically(self):
        """
        加入集群后，**不用手工添加对端**：自动发现的候选里，
        凡是名片声明已加入集群的，都会自动互联。
        """
        local = self.new_broker()
        other = self.new_broker()
        b = self.new_bridge(other, node_id="sub-B", candidates=[])
        b.start()
        time.sleep(0.5)

        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(other, "B站")])
        a.start()
        self.assertTrue(wait_for(lambda: a.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1),
                        "应自动把已加入集群的 B 站认成成员，实际=%s"
                        % json.dumps([{k: p[k] for k in ("name", "state", "member")}
                                      for p in a.status()["peers"]],
                                     ensure_ascii=False))

    def test_not_joined_server_is_not_a_member(self):
        """装了本系统但**没加入集群**的站，不该被当成成员。"""
        local = self.new_broker()
        other = self.new_broker()
        # B 桥接是关的（没加入集群）→ 不会广播集群名片
        b = self.new_bridge(other, node_id="sub-B", enabled=False)
        b.start()
        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(other, "B站")])
        a.start()
        self.assertTrue(wait_for(lambda: a.status()["local_connected"]))
        time.sleep(2.0)
        st = a.status()
        self.assertEqual(0, st["peer_member_count"], "未加入集群的站不该算成员")
        self.assertTrue(all(not p["member"] for p in st["peers"]))
        b.stop()

    def test_voice_flows_between_members_without_mutual_add(self):
        """
        ★ 核心：**只需各自加入集群**，语音就双向互通 —— 不需要双方互相添加，
        也不需要手工挑对端。
        """
        broker_a = self.new_broker()
        broker_b = self.new_broker()
        a = self.new_bridge(broker_a, node_id="sub-A",
                            candidates=[self.cand(broker_b, "B站")])
        b = self.new_bridge(broker_b, node_id="sub-B",
                            candidates=[self.cand(broker_a, "A站")])
        a.start()
        b.start()
        self.assertTrue(wait_for(lambda: a.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: b.status()["local_connected"]))
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1))
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))

        # A 站本地有人说话 → B 站应当能听到（重播到 B 的 broker）
        broker_a.push("FMO/RAW", b"voice-from-A")
        want_a = B.local_relay_topic("sub-A", "RAW")
        self.assertTrue(wait_for(lambda: broker_b.got(want_a), timeout=10),
                        "A 的声音应到 B，B实际=%s" % broker_b.topics())
        self.assertEqual(b"voice-from-A", broker_b.got(want_a)[-1])

        # 反向
        broker_b.push("FMO/RAW", b"voice-from-B")
        want_b = B.local_relay_topic("sub-B", "RAW")
        self.assertTrue(wait_for(lambda: broker_a.got(want_b), timeout=10),
                        "B 的声音应到 A")

    def test_three_members_full_mesh(self):
        """三个成员自动组成全网状，任意两方都能互通。"""
        ba, bb, bc = self.new_broker(), self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B"), self.cand(bc, "C")])
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A"), self.cand(bc, "C")])
        c = self.new_bridge(bc, node_id="sub-C",
                            candidates=[self.cand(ba, "A"), self.cand(bb, "B")])
        for x in (a, b, c):
            x.start()
        for x in (a, b, c):
            self.assertTrue(wait_for(lambda x=x: x.status()["peer_member_count"] == 2,
                                     timeout=15),
                            "每个成员应自动互联其余两个")
        ba.push("FMO/RAW", b"from-A")
        self.assertTrue(wait_for(lambda: bc.got(B.local_relay_topic("sub-A", "RAW")),
                                 timeout=10))
        self.assertTrue(wait_for(lambda: bb.got(B.local_relay_topic("sub-A", "RAW")),
                                 timeout=10))

    def test_one_member_down_does_not_break_others(self):
        """
        ★ "即使有一方断了，也能正常和其他服务器桥接"：
        A/B/C 都在集群里；B 的 broker 挂掉后，A 与 C 的互通必须照常。
        """
        ba, bb, bc = self.new_broker(), self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B"), self.cand(bc, "C")])
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A"), self.cand(bc, "C")])
        c = self.new_bridge(bc, node_id="sub-C",
                            candidates=[self.cand(ba, "A"), self.cand(bb, "B")])
        for x in (a, b, c):
            x.start()
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 2, timeout=15),
                        "A 应同时确认 B 和 C 两个成员")
        self.assertTrue(wait_for(lambda: c.status()["peer_member_count"] == 2, timeout=15))

        bb.stop()                       # B 挂了
        time.sleep(2.0)
        ba.push("FMO/RAW", b"after-B-down")
        self.assertTrue(wait_for(lambda: bc.got(B.local_relay_topic("sub-A", "RAW")),
                                 timeout=12),
                        "B 挂掉后 A 与 C 仍必须互通")
        self.assertGreaterEqual(c.status()["peer_member_count"], 1,
                                "C 至少还应保留与 A 的互联")

    def test_leaving_cluster_stops_everything(self):
        local = self.new_broker()
        other = self.new_broker()
        b = self.new_bridge(other, node_id="sub-B", candidates=[])
        b.start()
        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(other, "B")])
        a.start()
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1))

        a.set_config(enabled=False)
        self.assertFalse(a.status()["local_connected"], "退出集群后本机连接要断")
        self.assertEqual("disabled", a.status()["local_state"])
        self.assertEqual(0, a.status()["member_count"])
        self.assertTrue(wait_for(
            lambda: all(p["state"] == "disabled" for p in a.status()["peers"]),
            timeout=6))

    def test_publish_local_off_stops_sending_voice(self):
        """关掉「对外发送本机语音」后，别的成员听不到我。"""
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B")], publish_local=False)
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A")])
        a.start()
        b.start()
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1))
        ba.push("FMO/RAW", b"should-not-leave")
        time.sleep(1.5)
        self.assertEqual([], b.status()["peers"][0].get("rx_frames")
                         and bb.got(B.local_relay_topic("sub-A", "RAW")))
        self.assertEqual(0, b.status()["local"]["rx_frames"])

    def test_dedupe_same_frame(self):
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A", candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B", candidates=[self.cand(ba, "A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))
        ba.push("FMO/RAW", b"dup")
        want = B.local_relay_topic("sub-A", "RAW")
        self.assertTrue(wait_for(lambda: bb.got(want)))
        ba.push("FMO/RAW", b"dup")
        ba.push("FMO/RAW", b"dup")
        time.sleep(1.0)
        self.assertEqual(1, len(bb.got(want)), "重复帧必须去重")
        self.assertGreaterEqual(b.status()["local"]["deduped"], 2)

    def test_own_voice_does_not_loop_back(self):
        """自己的语音绕回来必须丢弃（防回环）。"""
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A", candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B", candidates=[self.cand(ba, "A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))
        bb.push("FMO/BRIDGE/sub-A/RAW", b"echo")
        time.sleep(1.0)
        self.assertEqual([], ba.got(B.local_relay_topic("sub-A", "RAW")),
                         "自己的声音不该被本机当成「互联进来的」再播一遍")

    def test_relayed_voice_is_not_forwarded_to_other_members(self):
        """中继语音只在本机重播，不再传给第三方（否则会中转洪泛/回环）。"""
        ba, bb, bc = self.new_broker(), self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A"), self.cand(bc, "C")])
        b.start(); a.start()
        time.sleep(3.0)
        ba.push("FMO/RAW", b"from-A")
        self.assertTrue(wait_for(lambda: bb.got(B.local_relay_topic("sub-A", "RAW")),
                                 timeout=10))
        time.sleep(1.0)
        # C 的 broker 上不该出现 A 的中继语音（本机重播主题是 5 层，B 不会转发）
        self.assertEqual([], [t for t in bc.topics() if "sub-A" in t],
                         "中继语音被再次转发会形成洪泛: %s" % bc.topics())

    def test_status_shape(self):
        local = self.new_broker()
        a = self.new_bridge(local, node_id="sub-A",
                            candidates=[self.cand(self.new_broker(), "X")])
        st = a.status()
        for k in ("ok", "enabled", "node_id", "node_name", "broker", "topics",
                  "local", "peers", "members", "member_count", "peer_member_count",
                  "self_joined", "publish_local"):
            self.assertIn(k, st)
        p = st["peers"][0]
        for k in ("id", "name", "host", "port", "member", "connected", "state",
                  "rx_frames", "tx_frames", "last_rx", "last_error",
                  "reconnects", "uptime", "manual"):
            self.assertIn(k, p)

    def test_manual_entry_visible_even_when_not_joined(self):
        """
        未加入集群时，手动补充的地址**仍要在列表里**（否则界面上凭空消失、
        连删都删不掉 —— 真实踩过）。
        """
        local = self.new_broker()
        a = self.new_bridge(local, node_id="sub-A", enabled=False,
                            peers=[{"name": "手动站点", "host": "10.1.2.3",
                                    "port": 1883}])
        st = a.status()
        self.assertFalse(st["enabled"])
        self.assertEqual(1, len(st["peers"]),
                         "未加入集群也要显示手动条目")
        self.assertTrue(st["peers"][0]["manual"])
        self.assertEqual("disabled", st["peers"][0]["state"])


# ---------------------------------------------------------------- 接口/打包

class ApiAndPackagingTests(unittest.TestCase):
    def test_admin_page_and_routes(self):
        for f in ("admin/bridge.html", "admin/bridge.js"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), "%s 缺失" % f)
        api = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("/admin/bridge", api)
        self.assertIn("_handle_bridge_routes", api)
        for route in ("/api/bridge/status", "/api/bridge/peers",
                      "/api/bridge/peers/toggle", "/api/bridge/peers/delete",
                      "/api/bridge/config", "/api/bridge/candidates"):
            self.assertIn(route, api, "缺少接口 %s" % route)

    def test_roster_source_pulls_from_master(self):
        """
        ★ 集群名册必须**从总服务器拉取**（装了我们 FUS 的分系统注册表），
        而不是拿 APRS 台站凑数 —— APRS 上绝大多数根本不是 FUS 服务器。
        总服务器的 /api/server/list 在公网口放行，分系统直接 GET 即可。
        """
        api = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        self.assertIn("_bridge_roster_source", api)
        block = api.split("def _bridge_roster_source", 1)[1].split("\ndef ", 1)[0]
        self.assertIn("/api/server/list", block, "应从总服务器 /api/server/list 拉名册")
        self.assertIn("master_url", block)
        self.assertIn("subsystem_id", block, "名册条目要带 subsystem_id（用于相互验证）")
        self.assertNotIn("aprs_store", block, "不该再拿 APRS 台站当集群候选")
        self.assertIn("_ROSTER_CACHE", api, "名册要缓存，别每轮都去打总服务器")

    def test_identity_verification_uses_roster(self):
        """相互验证：名片里的节点标识必须与名册登记的 subsystem_id 一致。"""
        src = open(os.path.join(ROOT, "bridge.py"), encoding="utf-8").read()
        self.assertIn("expect_id", src)
        self.assertIn("与总服务器名册不符", src)

    def test_bridge_api_not_public(self):
        api = open(os.path.join(ROOT, "api_server.py"), encoding="utf-8").read()
        for name in ("PUBLIC_GET_PATHS", "PUBLIC_POST_PATHS"):
            block = api.split(name, 1)[1].split(")", 1)[0]
            self.assertNotIn("bridge", block, "%s 里不该有 bridge" % name)

    def test_monitor_subscribes_relay_topics(self):
        mon = open(os.path.join(ROOT, "monitor.py"), encoding="utf-8").read()
        self.assertIn("FMO/BRIDGE/local/+/RAW", mon)

    def test_build_and_installers(self):
        self.assertIn("bridge.py",
                      open(os.path.join(ROOT, "build_release.sh"),
                           encoding="utf-8").read())
        for name in ("install.sh", "install-bas.sh"):
            self.assertIn("/admin/bridge",
                          open(os.path.join(ROOT, name), encoding="utf-8").read())
        self.assertIn("/admin/bridge",
                      open(os.path.join(ROOT, "admin", "portal.html"),
                           encoding="utf-8").read())

    def test_save_config_accepts_cfg_arg(self):
        """真实事故：save_config() 不收参数 → 桥接改配置全部没落盘。"""
        import inspect
        import api_server
        sig = inspect.signature(api_server.save_config)
        self.assertGreaterEqual(len(sig.parameters), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
