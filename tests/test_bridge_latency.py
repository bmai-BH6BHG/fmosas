#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
桥接延迟/指标回归测试。

真实事故：指标把"两次发言之间的静默（几十秒）"当成网络抖动与丢包，
于是状态里报出 jitter_ms=19608、packet_loss_rate 虚高、MOS 1.0，
UDAC 又拿它当桥接健康度给节点扣分。真实抖动其实只有几十毫秒。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge  # noqa: E402


class FakeSvc(object):
    """只接住链路回调，用于驱动指标。"""

    def __init__(self):
        self.frames = []

    def on_peer_announce(self, key, payload):
        pass

    def on_remote_frame(self, peer, topic, payload):
        self.frames.append((topic, payload))


def _link():
    svc = FakeSvc()
    peer = {"id": "p1", "host": "10.0.0.1", "port": 1883, "name": "peer"}
    return bridge.BridgeLink(svc, peer), svc


def _feed(link, count, gap_s, payload=b"x" * 64):
    """按指定间隔喂帧（直接改 audio_last_at，避免测试里真的 sleep）。"""
    for _ in range(count):
        link._on_message("FMO/BRIDGE/other/RAW", payload)
        link.audio_last_at -= gap_s          # 把"上一帧到达时刻"往前推


def test_silence_is_not_jitter():
    """★ 核心回归：发言之间的长静默不得被算成抖动。"""
    link, _ = _link()
    # 第 1 段：40ms 间隔的连续语音（真实帧间隔）
    _feed(link, 60, 0.040)
    jitter_after_voice = link.audio_jitter_ms
    assert jitter_after_voice < 30.0, "同一次发言内抖动应很小，实际 %.1f" % jitter_after_voice
    # 中间静默 25 秒（上一次发言结束 → 下一次开口）
    link._on_message("FMO/BRIDGE/other/RAW", b"y" * 64)
    link.audio_last_at -= 25.0
    link._on_message("FMO/BRIDGE/other/RAW", b"y" * 64)
    # 第 2 段：再来一串连续语音
    _feed(link, 60, 0.040)
    assert link.audio_jitter_ms < 50.0, (
        "静默不得进入抖动统计（旧实现会冲到上万毫秒），实际 %.1f"
        % link.audio_jitter_ms)
    assert link.audio_bursts >= 1, "应识别出至少一次新发言"
    snap = link.snapshot()
    assert snap["audio"]["jitter_ms"] < 50.0
    assert snap["audio"]["bursts"] >= 1
    # 丢包率也不能被静默污染（60 帧语音 + 几次静默 → 不应报成"严重丢包"）
    assert snap["health"]["packet_loss_rate"] < 0.1, (
        "静默不得被当成丢帧，实际 %.3f" % snap["health"]["packet_loss_rate"])


def test_real_jitter_is_measured_inside_burst():
    """同一发言内间隔忽大忽小，抖动要能量出来（不能一味压成 0）。"""
    link, _ = _link()
    gaps = [0.040, 0.040, 0.090, 0.040, 0.100, 0.040, 0.080]
    for g in gaps * 8:
        link._on_message("FMO/BRIDGE/other/RAW", b"z" * 64)
        link.audio_last_at -= g
    j = link.audio_jitter_ms
    assert 3.0 < j < 120.0, "真实抖动应被量出来（几十毫秒量级），实际 %.1f" % j


def test_mos_reflects_good_link():
    """指标修正后，一条正常链路不该再算成 MOS 1.0。"""
    link, _ = _link()
    _feed(link, 200, 0.040)
    snap = link.snapshot()
    mos = snap["audio"]["mos_estimate"]
    assert mos is not None and mos > 3.0, (
        "正常链路 MOS 不该只有 %.2f（旧实现因假抖动算成 1.0）" % (mos or 0))


def test_replay_delay_measured():
    """服务级：重播延迟要能测出来（帧到达 → 重播出去的耗时）。"""
    vb = bridge.VoiceBridge.__new__(bridge.VoiceBridge)   # 只测指标字段，不建连接
    import collections
    import threading
    vb._play = collections.deque()
    vb._play_lock = threading.Lock()
    vb._lock = threading.RLock()
    vb._stats = {"replayed": 0}
    vb._replay_delay_ms = 0.0
    vb._replay_delay_max_ms = 0.0
    vb.log = lambda *a, **k: None

    class FakeClient(object):
        def __init__(self):
            self.published = []

        def publish(self, topic, payload):
            self.published.append((topic, payload))

    c = FakeClient()
    # 正常：入队时带"到达时刻"，80ms 后释放 → 延迟约 80ms
    # （EWMA 需要若干次采样才收敛，所以多喂几帧）
    for _ in range(40):
        now = time.time()
        vb._play.append((now, now - 0.080, "FMO/RAW", b"a"))
        vb._drain_out_queue(c)
    assert c.published, "到期的帧必须重播出去"
    assert 60.0 < vb._replay_delay_ms < 200.0, (
        "重播延迟应约等于抖动缓冲，实际 %.1f" % vb._replay_delay_ms)
    # 迟到过多：直接丢弃，不播旧语音
    vb._play.append((time.time() - 1.0, time.time() - 10.0, "FMO/RAW", b"b"))
    n_before = len(c.published)
    vb._drain_out_queue(c)
    assert len(c.published) == n_before, "迟到超过阈值的帧应被丢弃（不放旧语音）"
    assert vb._stats.get("dropped_late") == 1


def test_constants_present():
    assert bridge.BURST_GAP_MS > 0
    assert bridge.LOCAL_READ_TIMEOUT <= 0.2, "本机读超时要小，否则重播被推迟"
    assert bridge.LATE_DROP_MS > 0
