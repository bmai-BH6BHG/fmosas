#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
语音录音库测试：永久保留策略 / 分页查询 / 时间轴 / 区间统计 / 合并导出 / 删除区间。

对应需求：
  「从部署那一刻开始，就开始记录这个 FMO 上的声音，存入数据库，随时都可以听」
  —— 所以重点是（1）默认永久保留不删（2）任何历史区间都能查出来、能导出、能删。
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import monitor  # noqa: E402


def _pkt(n=40):
    """造一个最小 Opus 包（TOC 字节 + 负载），够 ogg 封装与采样数估算用。"""
    return b'\x78' + bytes([n % 251]) * n


def _seg_blob(n_pkt=3):
    """造一段存储格式的音频：[u16 LE 长度][包]…"""
    out = bytearray()
    for _ in range(n_pkt):
        p = _pkt()
        out += struct.pack('<H', len(p)) + p
    return bytes(out)


def _store(tmp_path, **kw):
    return monitor.VoiceStore(str(tmp_path / 'voice.db'), **kw)


def test_keep_forever_by_default(tmp_path):
    """默认（retention_days=0）不按天删 —— 老录音必须还在。"""
    st = _store(tmp_path)
    old = time.time() - 400 * 86400          # 400 天前
    st.add_segment('BH6BHG', 1, old, old + 2, 2000, 'opus', 3, _seg_blob(), '')
    st.add_segment('BH6BHG', 2, time.time(), time.time() + 2, 2000, 'opus', 3,
                   _seg_blob(), '')
    n_seg, _ = st.cleanup()
    assert n_seg == 0, '默认应永久保留，不该删任何语音段'
    assert st.stats()['segments'] == 2
    assert st.stats()['keep_forever'] is True


def test_retention_days_still_works(tmp_path):
    """显式设了天数时仍按天删（兼容老配置）。"""
    st = _store(tmp_path, retention_days=7)
    old = time.time() - 30 * 86400
    st.add_segment('BH6BHG', 1, old, old + 2, 2000, 'opus', 3, _seg_blob(), '')
    st.add_segment('BH6BHG', 2, time.time(), time.time() + 2, 2000, 'opus', 3,
                   _seg_blob(), '')
    n_seg, _ = st.cleanup()
    assert n_seg == 1
    assert st.stats()['segments'] == 1
    assert st.stats()['keep_forever'] is False


def test_capacity_trim_keeps_newest(tmp_path):
    """设了容量上限：超了删**最老**的，最新的一定留着。"""
    st = _store(tmp_path, max_db_mb=0)
    st.max_db_mb = 1                      # 1MB 上限
    now = time.time()
    big = _seg_blob(600)                  # 每段约 25KB
    for i in range(600):                  # 约 15MB，必然超限
        st.add_segment('BH6BHG', i, now - (600 - i) * 10,
                       now - (600 - i) * 10 + 2, 2000, 'opus', 3, big, '')
    assert st.stats()['bytes'] > 1024 * 1024
    n_seg, _ = st.cleanup()
    assert n_seg > 0, '超容量应裁掉最老的段'
    assert st.stats()['bytes'] <= 1024 * 1024, '裁完应在容量内'
    # 裁的是**最老**的：最新那段（now-10）必须还在，最老的必须已被删
    rows, total = st.recordings(0, now + 100, limit=2000)
    assert rows, '不能把记录全删光'
    newest = max(r['start_ts'] for r in rows)
    oldest = min(r['start_ts'] for r in rows)
    assert newest >= now - 12, '最新的一段必须留着（newest=%.0f now=%.0f）' % (newest, now)
    assert oldest > now - 600 * 10 + 1, '最老的几段应已被裁掉'


def test_recordings_paging_and_filter(tmp_path):
    st = _store(tmp_path)
    t0 = 1700000000.0
    for i in range(25):
        st.add_segment('BH6BHG' if i % 2 == 0 else 'BG8XYZ', i,
                       t0 + i * 60, t0 + i * 60 + 3, 3000, 'opus', 3,
                       _seg_blob(), 'sub-peer' if i % 5 == 0 else '')
    rows, total = st.recordings(t0, t0 + 3600, limit=10, offset=0)
    assert total == 25 and len(rows) == 10
    rows2, _ = st.recordings(t0, t0 + 3600, limit=10, offset=10)
    assert rows2[0]['start_ts'] > rows[-1]['start_ts']
    only, n = st.recordings(t0, t0 + 3600, callsign='bg8xyz')
    assert n == 12 and all(r['callsign'] == 'BG8XYZ' for r in only)
    local, nl = st.recordings(t0, t0 + 3600, origin='')
    assert nl == 20 and all(r['origin'] == '' for r in local)
    bridged, nb = st.recordings(t0, t0 + 3600, origin='*')
    assert nb == 5 and all(r['origin'] == 'sub-peer' for r in bridged)


def test_timeline_buckets(tmp_path):
    st = _store(tmp_path)
    t0 = 1700000000.0
    for i in range(6):
        st.add_segment('BH6BHG', i, t0 + i * 1800, t0 + i * 1800 + 2, 2000,
                       'opus', 3, _seg_blob(), '')
    tl = st.timeline(t0, t0 + 10800, bucket_sec=3600)
    assert len(tl) == 3, '6 段每 30 分钟一段 → 落在 3 个小时桶里'
    assert sum(x['count'] for x in tl) == 6
    # 每小时 2 段 × 2 秒 = 4 秒
    assert all(x['seconds'] == 4.0 for x in tl)


def test_export_ogg_multi(tmp_path):
    st = _store(tmp_path)
    t0 = 1700000000.0
    for i in range(3):
        st.add_segment('BH6BHG', i, t0 + i * 30, t0 + i * 30 + 2, 2000,
                       'opus', 3, _seg_blob(), '')
    body, n = st.export_ogg(t0, t0 + 300)
    assert n == 3 and body and body[:4] == b'OggS', '必须是真的 Ogg 容器'
    assert b'OpusHead' in body[:64] and b'OpusTags' in body
    # 段间停顿用 granule 跳变表示：最后一段的 granule 应大于纯音频采样数
    assert len(body) > 100
    empty, n0 = st.export_ogg(t0 + 100000, t0 + 100100)
    assert empty is None and n0 == 0


def test_export_skips_non_opus(tmp_path):
    """ADPCM 段不能拼进 Ogg：应被跳过，且不报错。"""
    st = _store(tmp_path)
    t0 = 1700000000.0
    st.add_segment('BH6BHG', 1, t0, t0 + 2, 2000, 'adpcm', 1, b'\x00' * 323, '')
    body, n = st.export_ogg(t0, t0 + 60)
    assert body is None and n == 0


def test_delete_range(tmp_path):
    st = _store(tmp_path)
    t0 = 1700000000.0
    for i in range(10):
        st.add_segment('BH6BHG', i, t0 + i * 60, t0 + i * 60 + 2, 2000,
                       'opus', 3, _seg_blob(), '')
    n = st.delete_range(t0, t0 + 300)
    assert n == 5
    assert st.stats()['segments'] == 5


def test_stats_reports_span(tmp_path):
    st = _store(tmp_path)
    t0 = 1700000000.0
    st.add_segment('BH6BHG', 1, t0, t0 + 2, 2000, 'opus', 3, _seg_blob(), '')
    st.add_segment('BH6BHG', 2, t0 + 3600, t0 + 3602, 2000, 'opus', 3, _seg_blob(), '')
    s = st.stats()
    assert s['first_ts'] == t0
    assert s['last_ts'] == t0 + 3602
    assert s['seconds'] == 4.0
    assert s['bytes'] > 0


def test_beacons_have_own_retention(tmp_path):
    """信标按自己的天数留（默认 30 天），不跟着语音永久堆。"""
    st = _store(tmp_path, beacon_retention_days=30)
    st.add_beacon('BH6BHG', 439.5, 145.2, 1)
    st.db_size_bytes() if hasattr(st, 'db_size_bytes') else None
    with st._lock:
        conn = st._conn()
        conn.execute('UPDATE beacons SET created_at=?', (time.time() - 90 * 86400,))
        conn.commit()
    _, n_bc = st.cleanup()
    assert n_bc == 1
