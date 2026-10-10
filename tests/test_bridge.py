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

import io
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
import monitor as Mb  # noqa: E402


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
        self.deny_sub = []          # 模拟对端 ACL：这些过滤器的订阅回 0x80
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
                        body = pkt[1][2:]
                        codes = bytearray()
                        granted = []
                        while len(body) > 0:
                            tlen = struct.unpack_from(">H", body, 0)[0]
                            filt = body[2:2 + tlen].decode("utf-8", "replace")
                            body = body[2 + tlen + 1:]
                            # 模拟对端 ACL 拒绝订阅：SUBACK 回 0x80
                            denied = any(self._topic_matches(p, filt)
                                         for p in self.deny_sub)
                            codes.append(0x80 if denied else 0x00)
                            if not denied:
                                granted.append(filt)
                        conn.sendall(bytes([0x90, len(codes) + 2])
                                     + struct.pack(">H", pid) + bytes(codes))
                        for filt in granted:
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
        # ★ 中继语音重播到**原生主题**：APP / FM 网关 / 监控 只订阅这个
        self.assertEqual("FMO/RAW", B.channel_topic("RAW"))
        self.assertEqual("FMO/TELE", B.channel_topic("TELE"))

    def test_parse_member_voice(self):
        self.assertEqual(("sub-A", "RAW"), B.parse_in_topic("FMO/BRIDGE/sub-A/RAW"))
        self.assertEqual(("sub-A", "TELE"), B.parse_in_topic("FMO/BRIDGE/sub-A/TELE"))

    def test_relay_topic_is_the_native_voice_topic(self):
        """
        ★ 真实故障回归：中继语音必须落在 APP / FM 网关**本来就在听**的主题上。

        早先把中继语音重播到 FMO/BRIDGE/local/<源>/RAW（只有监控订阅），
        结果就是"录音里有声音，APP 和 FM 一点声音都没有"。
        """
        for ch in ("RAW", "TELE"):
            t = B.channel_topic(ch)
            self.assertEqual("FMO/%s" % ch, t)
            self.assertEqual(2, len(t.split("/")),
                             "必须是原生两层主题，才和本机语音同一条路径")
        self.assertNotIn("BRIDGE", B.channel_topic("RAW"))

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
        want_a = B.channel_topic("RAW")
        self.assertTrue(wait_for(lambda: broker_b.got(want_a), timeout=10),
                        "A 的声音应到 B，B实际=%s" % broker_b.topics())
        self.assertEqual(b"voice-from-A", broker_b.got(want_a)[-1])

        # 反向
        broker_b.push("FMO/RAW", b"voice-from-B")
        want_b = B.channel_topic("RAW")
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
        self.assertTrue(wait_for(lambda: bc.got(B.channel_topic("RAW")),
                                 timeout=10))
        self.assertTrue(wait_for(lambda: bb.got(B.channel_topic("RAW")),
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
        self.assertTrue(wait_for(lambda: bc.got(B.channel_topic("RAW")),
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
                         and bb.got(B.channel_topic("RAW")))
        self.assertEqual(0, b.status()["local"]["rx_frames"])

    def test_dedupe_same_frame(self):
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A", candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B", candidates=[self.cand(ba, "A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))
        ba.push("FMO/RAW", b"dup")
        want = B.channel_topic("RAW")
        self.assertTrue(wait_for(lambda: bb.got(want)))
        ba.push("FMO/RAW", b"dup")
        ba.push("FMO/RAW", b"dup")
        time.sleep(1.0)
        self.assertEqual(1, len(bb.got(want)), "重复帧必须去重")
        self.assertGreaterEqual(b.status()["local"]["deduped"], 2)

    def test_relayed_voice_lands_on_native_topic(self):
        """
        ★★ 真实故障回归（用户报的"录音有、APP/FM 没声音"）：

        APP 和 FM 网关只订阅原生主题 `FMO/RAW`，所以中继语音**必须重播到那里**；
        早先放在 FMO/BRIDGE/local/<源>/RAW 上时，只有监控（录音）能看到，
        APP 和 FM 一点声音都没有。
        """
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A", candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B", candidates=[self.cand(ba, "A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))
        ba.push("FMO/RAW", b"voice-from-A")
        self.assertTrue(wait_for(lambda: bb.got("FMO/RAW") == [b"voice-from-A"],
                                 timeout=10),
                        "中继语音没有出现在 FMO/RAW 上 → APP/FM 收不到")
        # 也不能再落到那个"只有监控认识"的旧主题上
        self.assertEqual([], [t for t in bb.topics()
                              if t.startswith("FMO/BRIDGE/local/")],
                         "又往旧主题发了一份（会导致录音重复）")

    def test_injected_frame_is_not_re_forwarded(self):
        """
        ★★ 回环抑制：重播回本机 FMO/RAW 的帧，会被**我们自己**的订阅收回来。

        MQTT 3.1.1 没有 no-local 标志，不识别它就会：
          A 说话 → B 重播进 B 的 FMO/RAW → B 自己收到 → B 当成"本机语音"导出给 A
          → A 重播进 A 的 FMO/RAW → … 无限乒乓。
        """
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A", candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B", candidates=[self.cand(ba, "A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: b.status()["peer_member_count"] == 1))
        ba.push("FMO/RAW", b"one-shot")
        self.assertTrue(wait_for(lambda: bb.got("FMO/RAW") == [b"one-shot"],
                                 timeout=10))
        time.sleep(2.5)
        # B 不得把自己注入的帧再导出给对端
        self.assertEqual([], bb.got("FMO/BRIDGE/sub-B/RAW"),
                         "B 把注入的帧又转发出去 → 会无限乒乓")
        # A 的 broker 上也不该出现"自己的声音绕回来"再被注入一次
        self.assertEqual([], ba.got("FMO/RAW"),
                         "自己的声音绕回来又被注入到本机 FMO/RAW")

    def test_relayed_voice_is_not_forwarded_to_other_members(self):
        """中继语音只在本机重播，不再中转给第三方（否则会中转洪泛）。"""
        ba, bb, bc = self.new_broker(), self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B")])
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A"), self.cand(bc, "C")])
        b.start(); a.start()
        time.sleep(3.0)
        ba.push("FMO/RAW", b"from-A")
        self.assertTrue(wait_for(lambda: bb.got("FMO/RAW") == [b"from-A"],
                                 timeout=10))
        time.sleep(2.0)
        self.assertEqual([], bc.got("FMO/RAW"),
                         "A 的语音被 B 中转给了 C（洪泛）")
        self.assertEqual([], bc.got("FMO/BRIDGE/sub-B/RAW"),
                         "B 把自己注入的帧导出给了 C（洪泛）")

    def test_update_peer_keeps_learned_identity(self):
        """
        ★ _sync_links() 每 5 秒就用名册重建的目标刷新一次链路，而名册里没有
        remote_id/verified —— 不能用 dict(peer) 直接覆盖，否则刚验证到的对方身份
        会被抹掉，界面永远显示不出"对方是谁"（真实 bug：member=True 但 remote_id 空）。
        """
        b = self.new_bridge(self.new_broker(), node_id="sub-ME")
        b._cfg["enabled"] = True
        tgt = {"id": "127.0.0.1:1", "name": "X", "host": "127.0.0.1", "port": 1,
               "expect_id": "sub-X", "manual": False}
        link = B.BridgeLink(b, tgt)
        link.peer["remote_id"] = "sub-X"
        link.peer["verified"] = True
        # 名册刷新：新目标里没有学到的字段
        link.update_peer(dict(tgt))
        self.assertEqual("sub-X", link.peer.get("remote_id"),
                         "名册刷新把学到的 remote_id 抹掉了")
        self.assertTrue(link.peer.get("verified"), "verified 被抹掉了")
        self.assertEqual("sub-X", link.snapshot()["remote_id"])
        self.assertTrue(link.snapshot()["verified"])

    def test_announce_without_node_id_is_rejected(self):
        """
        ★ 相互验证的前提：名片必须带节点标识。

        否则任何人往 FMO/BRIDGE/ANNOUNCE 发一句 {"cluster": true} 就能被算成
        集群成员 —— 验证形同虚设。
        """
        bk = self.new_broker()
        b = self.new_bridge(bk, node_id="sub-ME",
                            candidates=[self.cand(bk, "X", "sub-X")])
        b._cfg["enabled"] = True
        link = B.BridgeLink(b, b._collect_targets()["127.0.0.1:%d" % bk.port])
        b._links[link.key] = link
        b.on_peer_announce(link.key,
                           json.dumps({"cluster": True}).encode())
        self.assertFalse(link.member, "没有 node_id 的名片不该被认成成员")
        self.assertIn("缺少节点标识", link.reject_reason)

    def test_verified_flag_reflects_roster_match(self):
        """verified 只在"名册登记的 subsystem_id 与名片一致"时为真。"""
        bk = self.new_broker()
        b = self.new_bridge(bk, node_id="sub-ME",
                            candidates=[self.cand(bk, "X", "sub-X")])
        b._cfg["enabled"] = True
        tgt = b._collect_targets()["127.0.0.1:%d" % bk.port]
        link = B.BridgeLink(b, tgt)
        b._links[link.key] = link
        # 名册说这个地址是 sub-X，名片也说是 sub-X → 成员 + 已核对
        b.on_peer_announce(link.key, json.dumps(
            {"cluster": True, "node_id": "sub-X", "node_name": "X"}).encode())
        self.assertTrue(link.member)
        self.assertTrue(link.peer.get("verified"), "应当标记为已核对")
        self.assertEqual("sub-X", link.peer.get("remote_id"))
        self.assertTrue(link.snapshot()["verified"])

    def test_subscribe_reports_suback_codes(self):
        """subscribe(wait=True) 必须返回 SUBACK 返回码 —— 否则订阅被拒时我们不知道。"""
        bk = self.new_broker()
        cli = Mb.MqttMiniClient("127.0.0.1", bk.port, "FMO-BRIDGE-t1",
                                read_timeout=1.0)
        cli.connect()
        codes = cli.subscribe(["FMO/BRIDGE/ANNOUNCE"], wait=True, timeout=5)
        self.assertEqual([0x00], codes, "允许订阅时应当返回 0x00")
        try:
            cli.close()
        except Exception:  # noqa: BLE001
            pass

    def test_denied_subscribe_is_reported_not_as_not_joined(self):
        """
        ★★ 对端 ACL 拒绝订阅时，报的必须是"订阅被拒"，**不能**报成"对方未加入集群"。

        以前 subscribe() 不看 SUBACK、链路只会等到超时，于是把"我们没订上"
        说成"对方没加入" —— 排查方向完全错（用户就是被这个误导的）。
        """
        bk = self.new_broker()
        bk.deny_sub = ["FMO/BRIDGE/ANNOUNCE"]        # 对端 ACL 拒绝名片主题
        b = self.new_bridge(bk, node_id="sub-ME",
                            candidates=[self.cand(bk, "X", "sub-X")])
        b._cfg["enabled"] = True
        tgt = b._collect_targets()["127.0.0.1:%d" % bk.port]
        link = B.BridgeLink(b, tgt)
        link.start()
        ok = wait_for(lambda: link.reject_reason != "", timeout=15)
        self.assertTrue(ok, "订阅被拒后应当马上给出原因")
        self.assertIn("ACL", link.reject_reason)
        self.assertIn("SUBACK", link.reject_reason)
        self.assertNotIn("未加入集群", link.reject_reason,
                         "不能把订阅被拒说成对方未加入集群")
        link.stop()

    def test_confirm_window_exceeds_announce_interval(self):
        """
        ★ 等名片的时限必须大于名片周期：对方名片若是**非保留**的（旧版本/别家实现），
        只有到下一次广播才收得到。以前 12 秒 < 60 秒周期 → 大多数情况误判成"未加入"。
        """
        self.assertGreater(B.MEMBER_CONFIRM_TIMEOUT, B.ANNOUNCE_INTERVAL,
                           "确认窗口必须大于名片周期")
        self.assertLessEqual(B.NON_MEMBER_RETRY, 300.0,
                             "非成员重试间隔不能太长（以前 900 秒让界面长时间显示未加入）")

    def test_thread_survives_main_loop_exception(self):
        """
        ★★ 真实故障回归（对端就是这个表现）：桥接线程绝不能因异常静默退出。

        以前外层循环没有兜底、`_sync_links()` 又在 try 之外 —— 抛一次异常整个线程
        就没了，但配置仍 enabled=true、界面照样显示"已加入集群"，
        实际不再发名片、不再互联 → "看着加入了，语音一直不通"，且没有任何报错。
        """
        bk = self.new_broker()
        b = self.new_bridge(bk, node_id="sub-ME")
        b._cfg["enabled"] = True
        calls = {"n": 0}
        real = b._main_loop

        def boom():
            calls["n"] += 1
            raise RuntimeError("模拟主循环崩溃")

        b._main_loop = boom
        b.start()
        self.assertTrue(wait_for(lambda: calls["n"] >= 2, timeout=10),
                        "主循环崩溃后应当被守护外壳重新拉起（而不是线程直接死掉）")
        self.assertTrue(b.thread_alive(), "桥接线程必须还活着")
        b._main_loop = real
        b.stop()
        self.assertTrue(wait_for(lambda: not b.thread_alive(), timeout=10))

    def test_status_exposes_thread_alive(self):
        """状态里要有 thread_alive，界面才能提示"已加入但其实没在工作"。"""
        bk = self.new_broker()
        b = self.new_bridge(bk, node_id="sub-ME")
        st = b.status()
        self.assertIn("thread_alive", st)
        self.assertFalse(st["thread_alive"])      # 还没 start
        b._cfg["enabled"] = True
        b.start()
        self.assertTrue(wait_for(lambda: b.status()["thread_alive"], timeout=10))
        b.stop()

    def test_cluster_defaults_to_main(self):
        """没选过集群 → 默认「主集群」= 原有的全局互联（升级后行为不变）。"""
        cfg = B.load_bridge_config({})
        self.assertEqual(B.DEFAULT_CLUSTER_NAME, cfg["cluster"])
        self.assertEqual("主集群", B.DEFAULT_CLUSTER_NAME)
        b = self.new_bridge(self.new_broker(), node_id="sub-ME")
        self.assertEqual(B.DEFAULT_CLUSTER_NAME, b.cluster)

    def test_set_config_cluster(self):
        """切换集群要能生效、能持久化、并清掉退避（立刻按新名册重建链路）。"""
        b = self.new_bridge(self.new_broker(), node_id="sub-ME")
        b._cfg["enabled"] = True
        b._backoff_until["x:1883"] = time.time() + 999
        cfg = b.set_config(cluster="华东集群")
        self.assertEqual("华东集群", b.cluster)
        self.assertEqual("华东集群", cfg["cluster"])
        self.assertEqual({}, b._backoff_until, "换集群后应清掉退避，立即重连")
        self.assertEqual("华东集群", b.public_config()["cluster"])

    def test_status_exposes_cluster(self):
        b = self.new_bridge(self.new_broker(), node_id="sub-ME")
        st = b.status()
        self.assertIn("cluster", st)
        self.assertIn("default_cluster", st)
        self.assertEqual(B.DEFAULT_CLUSTER_NAME, st["cluster"])
        self.assertEqual(B.DEFAULT_CLUSTER_NAME, st["default_cluster"])

    def test_config_persists_cluster(self):
        """
        ★ bridge.cluster 必须落盘：同步上报从配置里读它告诉总系统"我属于哪个集群"，
        漏了就会出现"界面上切换了、配置里却没有"→ 总系统永远收不到归属（真实踩过）。
        """
        b = self.new_bridge(self.new_broker(), node_id="sub-ME")
        saved = {}
        b.save_fn = lambda cfg: saved.update(cfg)
        b.set_config(cluster="华东集群")
        self.assertEqual("华东集群", (saved.get("bridge") or {}).get("cluster"),
                         "配置里必须保存 cluster")

    def test_member_ids_reports_confirmed_members(self):
        """
        ★ 本机要能报出"我确认到的集群成员"给总系统。

        为什么必须有：有些节点**有桥接功能、也确实在互通**，但版本较早
        （v1.8.10~v1.8.13），没有 `cluster_joined` 上报字段。若总系统只认自报的，
        就会显示 0 台已加入，而且名册会变空 —— **把正在工作的桥接全部断掉**
        （真实踩过）。这些成员本机都做过名片 + 名册身份比对，结论可靠。
        """
        ba, bb = self.new_broker(), self.new_broker()
        a = self.new_bridge(ba, node_id="sub-A",
                            candidates=[self.cand(bb, "B", "sub-B")])
        b = self.new_bridge(bb, node_id="sub-B",
                            candidates=[self.cand(ba, "A", "sub-A")])
        a.start(); b.start()
        self.assertTrue(wait_for(lambda: a.status()["peer_member_count"] == 1))
        a._cfg["enabled"] = False
        self.assertEqual([], a.member_ids(), "没加入集群就不该报成员")
        a._cfg["enabled"] = True
        self.assertEqual(["sub-B"], a.member_ids())
        b.stop()

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


class FUSClusterTests(unittest.TestCase):
    """分系统侧的"选集群"接线：名册必须按自己的集群去拉。"""

    @staticmethod
    def _read(rel):
        with io.open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_roster_request_carries_subsystem_id(self):
        """
        ★ 桥接拉名册时必须带上自己的 subsystem_id —— 总系统据此只返回**同集群**的
        成员，互联才会被限定在自己选的集群里（默认主集群）。
        """
        api = self._read("api_server.py")
        self.assertIn("?subsystem_id=", api)
        self.assertIn("_bridge_roster_source", api)
        # 集群列表来自总系统
        self.assertIn("def _fetch_master_clusters", api)
        self.assertIn("/api/clusters", api)

    def test_cluster_routes_exist_and_are_admin_only(self):
        api = self._read("api_server.py")
        self.assertIn("'/api/bridge/clusters'", api)
        self.assertIn("'/api/bridge/cluster'", api)
        # 公网口白名单里不能出现它们
        pub = api.split("PUBLIC_GET_PATHS", 1)
        self.assertGreater(len(pub), 1)
        self.assertNotIn("/api/bridge/clusters", pub[1].split("PUBLIC_POST_PATHS")[0])

    def test_cannot_join_nonexistent_cluster(self):
        """只允许加入总系统上已存在的集群（集群由总系统创建）。"""
        api = self._read("api_server.py")
        self.assertIn("总系统上没有名为", api)

    def test_report_carries_cluster(self):
        """同步上报要带 cluster + cluster_joined，总系统才能记下归属与"是否已加入"。"""
        se = self._read("sync_engine.py")
        self.assertIn("payload['cluster']", se)
        self.assertIn("payload['cluster_joined']", se)
        self.assertIn("'主集群'", se)
        # 加入/退出集群时必须立刻上报（否则总系统的成员数一直显示旧值）
        api = self._read("api_server.py")
        self.assertIn("_report_cluster_now(svc.cluster)", api)

    def test_report_carries_cluster_members(self):
        """上报载荷要带 cluster_members（总系统据此把他证成员算进集群）。"""
        se = self._read("sync_engine.py")
        self.assertIn("payload['cluster_members']", se)
        self.assertIn("member_source", se)
        api = self._read("api_server.py")
        self.assertIn("engine.member_source", api)

    def test_master_confirms_peers_and_keeps_selfreport_priority(self):
        """
        总系统侧：他证只在对方**从未自报**时采纳 —— 自己明确说没加入的，不能被别人算进来。
        """
        ms = self._read_master("master_server.py")
        self.assertIn("def confirm_cluster_members", ms)
        self.assertIn("cluster_reported", ms)
        # 自报优先：已自报的跳过
        self.assertIn("已自报 → 以它自己的为准", ms)

    @staticmethod
    def _read_master(rel):
        import io as _io
        p = os.path.join(os.path.dirname(ROOT), "fmo-master-deploy", rel)
        with _io.open(p, encoding="utf-8") as f:
            return f.read()

    def test_auth_reject_backoff(self):
        """
        ★ 认证被拒（rc=5）不是网络抖动：重试再密也不会成功，得等对方升级或补信任。
        必须把重试间隔拉长并给日志限流，否则日志被"连接被拒绝 rc=5"刷满，
        看起来像"一直连不上"（用户真实反馈过）。
        """
        self.assertTrue(B._is_auth_reject("连接被拒绝 rc=5（对端不认我方证书）"))
        self.assertTrue(B._is_auth_reject("Connection Refused: not authorised."))
        self.assertFalse(B._is_auth_reject("timed out"))
        self.assertFalse(B._is_auth_reject(""))
        self.assertGreaterEqual(B.AUTH_FAIL_RETRY, 600.0, "认证失败应显著拉长重试间隔")
        self.assertGreaterEqual(B.FAIL_LOG_INTERVAL, 120.0, "同类失败日志必须限流")
        br = self._read("bridge.py")
        self.assertIn("_log_fail", br, "失败日志要走限流函数")

    def test_cluster_list_falls_back_to_roster_channel(self):
        """
        ★ 集群列表必须能从**名册通道**兜底拿到。

        真实场景：有些现场的网络/反代/防火墙只放行了旧路径（/api/server/list 和几个
        POST），新加的 /api/clusters 被挡 → 分系统界面上就是"集群列表获取失败"。
        名册这条通道本来就是通的，总系统把集群列表塞进名册响应里，
        分系统据此兜底，用户不用去改现场网络策略。
        """
        api = self._read("api_server.py")
        self.assertIn("_ROSTER_CLUSTERS", api, "要有名册通道带回来的集群列表缓存")
        self.assertIn("payload.get('clusters')", api, "名册响应里要读集群列表")
        self.assertIn("cached = list(_ROSTER_CLUSTERS or [])", api, "直接读失败要回落到缓存")
        # 失败必须带上"每个地址各自的失败原因"，否则现场没法排查
        self.assertIn("'tried': tried", api)
        self.assertIn("def _fetch_master_clusters()", api)
        # 总系统侧：名册响应要带集群列表
        ms = self._read_master("master_server.py")
        self.assertIn('body["clusters"] =', ms)
        # 界面要把失败原因显示出来
        js = self._read("admin/bridge.js")
        self.assertIn("tried", js)
        self.assertIn("err.payload", js)

    def test_ui_has_cluster_selector(self):
        html = self._read("admin/bridge.html")
        js = self._read("admin/bridge.js")
        for token in ("br-cluster-sel", "br-cluster-apply", "br-cluster-cur"):
            self.assertIn(token, html, "界面缺少 %s" % token)
        self.assertIn("/api/bridge/clusters", js)
        self.assertIn("/api/bridge/cluster", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
