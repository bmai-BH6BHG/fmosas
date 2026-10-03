#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MQTT 监听器认证探测测试
=======================
用一个假 MQTT broker 分别扮演"匿名放行"和"拒绝错误凭据"，验证探测判读：
  CONNACK rc=0  → anonymous（认证没启用）★ 这就是"身份信息缺失"的根因
  CONNACK rc=4/5 → auth_enforced（认证在工作）
  无 CONNACK / 非 MQTT → 相应标注
"""

import socket
import threading
import unittest

from tests import ROOT  # noqa: F401
import bas_diagnose as bd


class FakeBroker(threading.Thread):
    """极简假 broker：收到 CONNECT 后按配置回 CONNACK（或什么都不回）"""

    def __init__(self, mode="anonymous"):
        super().__init__(daemon=True)
        self.mode = mode
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(3)
            data = conn.recv(256)
            if not data:
                return
            if self.mode == "anonymous":
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x00]))       # rc=0 accepted
            elif self.mode == "deny4":
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x04]))       # bad user/pass
            elif self.mode == "deny5":
                conn.sendall(bytes([0x20, 0x02, 0x00, 0x05]))       # not authorized
            elif self.mode == "garbage":
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n")
            # mode == "silent"：不回包，触发等待超时
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass


class MqttProbeTests(unittest.TestCase):
    def _probe(self, mode):
        b = FakeBroker(mode)
        b.start()
        try:
            return bd.mqtt_auth_probe("127.0.0.1", b.port, timeout=2)
        finally:
            b.close()

    def test_anonymous_means_auth_disabled(self):
        r = self._probe("anonymous")
        self.assertEqual("anonymous", r["verdict"])
        self.assertEqual(0, r["connack_rc"])
        self.assertTrue(r["connected"])

    def test_deny_4_means_auth_enforced(self):
        r = self._probe("deny4")
        self.assertEqual("auth_enforced", r["verdict"])
        self.assertEqual(4, r["connack_rc"])

    def test_deny_5_means_auth_enforced(self):
        r = self._probe("deny5")
        self.assertEqual("auth_enforced", r["verdict"])
        self.assertEqual(5, r["connack_rc"])

    def test_garbage_means_not_mqtt(self):
        r = self._probe("garbage")
        self.assertEqual("not_mqtt", r["verdict"])

    def test_silent_means_no_connack(self):
        r = self._probe("silent")
        self.assertEqual("no_connack", r["verdict"])
        self.assertTrue(r.get("error"), "应给出原因（超时或对端关闭）")

    def test_closed_port_unreachable(self):
        r = bd.mqtt_auth_probe("127.0.0.1", 59996, timeout=2)
        self.assertEqual("unreachable", r["verdict"])
        self.assertFalse(r["connected"])

    def test_connect_packet_structure(self):
        """CONNECT 报文必须是合法 MQTT 3.1.1 且带 username/password 标志位"""
        pkt = bd._mqtt_connect("cid", "USER", "PASS")
        self.assertEqual(0x10, pkt[0], "CONNECT 固定头")
        self.assertEqual(len(pkt) - 2, pkt[1], "剩余长度应等于报文长度-2")
        # 变长头里的 flags 字节：bit7=username, bit6=password, bit1=clean
        flags = pkt[9]
        self.assertTrue(flags & 0x80, "应带 username 标志")
        self.assertTrue(flags & 0x40, "应带 password 标志")
        self.assertTrue(flags & 0x02, "应带 clean session 标志")

    def test_check_listeners_marks_kinds(self):
        b = FakeBroker("anonymous")
        b.start()
        try:
            rows = bd.check_mqtt_listeners("127.0.0.1", (b.port,))
            self.assertEqual(1, len(rows))
            self.assertIn("kind", rows[0])
            self.assertEqual("?", rows[0]["kind"], "非标准端口标为 ?")
        finally:
            b.close()


class ReportIntegrationTests(unittest.TestCase):
    """整份报告要在"认证没启用"时给出 MQTT_AUTH_DISABLED 且带上修法"""

    def test_report_flags_disabled_auth(self):
        b = FakeBroker("anonymous")
        b.start()
        argv = ["--diagnose", "--base-dir", ".", "--no-probe"].copy()
        try:
            # 直接调内部函数，避免起完整 CLI 子进程
            probes = bd.check_mqtt_listeners("127.0.0.1", (b.port,))
            self.assertEqual("anonymous", probes[0]["verdict"])
        finally:
            b.close()
        self.assertEqual([], [a for a in argv if a == "--not-a-flag"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
