# -*- coding: utf-8 -*-
"""
UDAC —— 统一动态授权与信任控制中心（FUS 第四组件）
Unified Dynamic Authorization & Trust Control Center

定位（严格遵循需求边界）：
  * SAS 解决"身份是否可信"，FAS 解决"认证与审计"，MQTT 互联桥接解决"消息如何互通"，
    **UDAC 解决"已认证实体现在能做什么、还能不能继续信"**。
  * 不实现证书签发/吊销（SAS）、不实现统一认证与原始审计（FAS）、
    不替代桥接（不碰路由/编解码）、不实现注册/台站扫描/全量抄收（总系统）。
  * 只通过内部接口**只读消费** SAS 证书状态、桥接健康度/音频质量，输出：
    信任评分 → 动态授权决策（PDP）→ 策略执行建议（PEP）→ 决策审计。

模块划分（与需求的插件清单一一对应，物理上合在一个文件，逻辑边界清晰）：
  BehaviorBaseline  → udac-behavior-baseine / udac-anomaly（行为基线 + 异常检测）
  TrustEngine       → udac-trust-score（0-100 多维加权信任分，含桥接健康/音质）
  PolicyEngine      → udac-policy / udac-pdp（策略版本化、灰度、回滚、仿真、fail-closed）
  PEP(enforce)      → udac-pep-bridge / udac-response（允许/拒绝/降权/限流/二次认证…）
  UDACCenter        → 组合 + udac-audit（决策审计、只追加事件日志）

存储：SQLite（udac.db，WAL），零第三方依赖。
信任分区间（需求规定）：
  80-100 正常(允许全部) / 60-79 观察(限流监控) / 40-59 警戒(二次认证/降权) / 0-39 危险(拒绝/断连/隔离)
"""

import os
import json
import time
import sqlite3
import threading
import hashlib
import math

__all__ = ['UDACCenter', 'TrustEngine', 'BehaviorBaseline', 'PolicyEngine', 'level_of']

# ---------------- 常量 ----------------

# 信任分默认权重（需求参考基线：Identity 30% / Behavior 25% / BridgeHealth 15%
# / AudioQuality 10%；其余维度补齐 100%，权重可通过 /api/udac/policy 调整）
DEFAULT_WEIGHTS = {
    'identity':       0.30,   # 身份信任（证书状态、认证结果、注册来源）
    'behavior':       0.25,   # 行为信任（基线偏离度、违规记录）
    'bridge_health':  0.15,   # 桥接健康度（RTT/丢包/抖动/重连）
    'audio_quality':  0.10,   # 音频流质量（MOS≥3.5、抖动<30ms）
    'context':        0.10,   # 环境（IP 变化、时段异常）
    'data':           0.10,   # 数据信任（证书链/传输加密由 SAS/FAS 保证，基线给高分）
}

# 信任分区间 → 状态
# ============================================================
# MQTT 桥接直通（不评分）
# ------------------------------------------------------------
# 桥接是 FUS **内部组件之间**的语音互通，不是待评估的终端实体：
#   * 身份本来就经过证书链 + 集群名片双重校验；
#   * 不参与信任评分，也不受策略门控/fail-closed 影响 —— 直接通过。
# 否则 PDP 一旦异常就会把桥接一起拒掉，表现成"桥接连接超时"。
# ============================================================
BRIDGE_CLIENTID_PREFIX = 'FMO-BRIDGE-'
BRIDGE_CALLSIGNS = ('SERVER',)          # 桥接/监控用的服务呼号
BRIDGE_PASS_REASON = 'MQTT 桥接 · 直接通过（不评分）'


# ------------------------------------------------------------
# 接入直通（不评分）：APP 接入 / 内部客户端 / MQTT 桥接
# ------------------------------------------------------------
# 这三类接入**已经过 SAS 身份校验**，不该再拿"证书记录/吊销/冷启动/时段"去扣分：
#   · APP 接入：SAS 身份 + APP 私钥签名（app_verified=1）。
#     注意同一个 APP 会**分两次接入**（先 user、再 super），两次都带 app_verified=1。
#   · 内部客户端：app_exempt=1（面板/服务账号，没有 APP 私钥，属信任豁免）。
#   · MQTT 桥接：clientid=FMO-BRIDGE-* 或服务呼号 SERVER（FUS 内部语音互通）。
# 用户反馈：给 APP 账号打 50 分判 step_up 是错的 —— 这里改成直接通过、只留审计。
# ------------------------------------------------------------
APP_VERIFIED_TRUE = ('1', 'true', 'yes', 'y', 'bound', 'ok', 'on')
APP_PASS_REASON = ('APP 接入 · 已通过 SAS 身份 + APP 签名校验'
                   '（user/super 两次接入均适用）· 直接通过（不评分）')
EXEMPT_PASS_REASON = '内部客户端 · SAS 已信任且豁免 APP 签名 · 直接通过（不评分）'
APP_CLIENT_PASS_REASON = ('APP 接入 · APP 客户端且 SAS 身份已通过（user/super 两次接入均适用）'
                         '· 直接通过（不评分）')


def is_app_verified_subject(app_verified=''):
    """APP 签名是否校验通过（/auth 写入 app_verified：1 = 通过）。"""
    try:
        return str(app_verified or '').strip().lower() in APP_VERIFIED_TRUE
    except Exception:  # noqa: BLE001
        return False


def is_app_client(callsign='', clientid=''):
    """
    是不是 **APP 的 MQTT 客户端**（同一个 APP 的两次接入 clientid 都长这样）。

    ★ 为什么需要它：APP 会**接入两次**（先 user、再 super），其中 super 那次
      **不带 app_signature**（app_verified=0(none)），只靠签名认不出来，就会被
      信任评分扣成 48 分、判 step_up —— 而用户明确要求"APP 的接入给他通过"。
      APP 的 clientid 形态是 FMO-<呼号>-<uid>-<随机>（内嵌自己的呼号）；
      调用点又在 SAS 认证放行之后，所以"形态 + SAS 已通过"两条合起来才成立。
    """
    try:
        cs = str(callsign or '').strip().upper()
        cid = str(clientid or '').strip().upper()
        if not cs or not cid:
            return False
        if cs in ('SERVER',):
            return False
        return cid.startswith('FMO-' + cs + '-')
    except Exception:  # noqa: BLE001
        return False


def _udac_bypass_reason(callsign='', clientid='', app_verified='',
                        app_exempt=''):
    """
    该接入是否**直接通过、不评分**；是则返回原因文案，否则返回 ''。

    顺序：APP 接入 → 内部客户端豁免 → MQTT 桥接。
    """
    try:
        if is_app_verified_subject(app_verified):
            return APP_PASS_REASON
        # APP 的第二次接入（super）不带签名，但 clientid 是 APP 形态、SAS 已通过
        if is_app_client(callsign, clientid):
            return APP_CLIENT_PASS_REASON
        if str(app_exempt or '').strip() in APP_VERIFIED_TRUE:
            return EXEMPT_PASS_REASON
        if is_bridge_subject(callsign, clientid):
            return BRIDGE_PASS_REASON
    except Exception:  # noqa: BLE001
        pass
    return ''


def is_bridge_subject(callsign='', clientid=''):
    """是不是 MQTT 桥接主体（clientid=FMO-BRIDGE-* 或服务呼号 SERVER）。"""
    try:
        if str(clientid or '').startswith(BRIDGE_CLIENTID_PREFIX):
            return True
        cs = str(callsign or '').strip().upper()
        return cs in BRIDGE_CALLSIGNS
    except Exception:  # noqa: BLE001
        return False


def level_of(score):
    """0-100 分 → 状态名（normal/watch/alert/danger）"""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return 'unknown'
    if s >= 80:
        return 'normal'
    if s >= 60:
        return 'watch'
    if s >= 40:
        return 'alert'
    return 'danger'

LEVEL_CN = {'normal': '正常', 'watch': '观察', 'alert': '警戒', 'danger': '危险',
            'unknown': '未知'}

# 信任分 → 默认 PEP 动作（需求：阈值与动作表）
LEVEL_ACTION = {
    'normal':  'allow',        # 允许全部授权操作
    'watch':   'rate_limit',   # 允许操作 + 限流监控
    'alert':   'step_up',      # 二次认证 / 降权
    'danger':  'deny',         # 拒绝 / 断连 / 隔离
}

# 动作严重度排序（取两者中更严的那个）
ACTION_SEVERITY = {'allow': 0, 'rate_limit': 1, 'degrade': 2, 'step_up': 3,
                   'disconnect': 4, 'quarantine': 5, 'deny': 6}

# 音质目标（非功能要求：MOS ≥ 3.5，抖动 < 30ms）
MOS_TARGET = 3.5
JITTER_TARGET_MS = 30.0

# 冷启动观察期（需求建议 7 天）：观察期内行为分保守
COLD_START_DAYS = 7
COLD_START_MIN_AUTHS = 5


def _clamp(v, lo=0.0, hi=100.0):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(hi, v))


def _stable_hash(s):
    """稳定哈希（灰度分流用；不用内置 hash() —— 它每次进程重启都变）"""
    return int(hashlib.sha1(str(s).encode('utf-8')).hexdigest()[:8], 16)


# ============================================================
# 行为基线与异常检测（UEBA 简化落地：规则 + 统计阈值）
# ============================================================

class BehaviorBaseline:
    """
    设备通信指纹：连接频率、重连频率（= 认证次数/小时，APP 频繁掉线重连
    会直接体现在这里）、IP 变化、活跃时段分布。
    数据源 = /auth 认证事件（note_auth 喂入），存 udac.db 的 auth_events 表。
    """

    # 异常阈值（简单硬规则；后续可做成策略条件）
    RECONNECT_PER_HOUR_MAX = 30     # 每小时重连次数（认证成功即一次"上线"）
    DISTINCT_IP_24H_MAX = 6         # 24h 内不同源 IP 数
    OFFHOURS_RATIO_MAX = 0.9        # 深夜(0-5点)占比（样本足够时才算）
    NEW_IP_BURST_1H = 4             # 1 小时内出现的新 IP 数

    def __init__(self, db, lock):
        self._db = db
        self._lock = lock

    def record_auth(self, callsign, clientid='', peerhost='', ok=True, ts=None):
        """记录一次认证事件（成功与失败都记：失败频率本身就是行为特征）"""
        if not callsign:
            return
        ts = float(ts or time.time())
        with self._lock:
            self._db.execute(
                "INSERT INTO auth_events (ts, callsign, clientid, peerhost, ok) "
                "VALUES (?, ?, ?, ?, ?)",
                (ts, str(callsign), str(clientid or ''), str(peerhost or ''),
                 1 if ok else 0))
            self._db.commit()

    def stats(self, callsign, window_h=24 * COLD_START_DAYS):
        """该呼号近 window_h 小时的行为摘要"""
        since = time.time() - window_h * 3600
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, clientid, peerhost, ok FROM auth_events "
                "WHERE callsign = ? AND ts > ? ORDER BY ts ASC",
                (str(callsign), since)).fetchall()
        rows = [dict(r) for r in rows]
        n = len(rows)
        hours = window_h if window_h > 0 else 1.0
        ips_24 = set()
        ips_1h = set()
        known_ips = set()
        new_ip_1h = 0
        offhours = 0
        ok_n = 0
        cutoff_24 = time.time() - 86400
        cutoff_1h = time.time() - 3600
        now = time.time()
        for r in rows:
            ip = (r.get('peerhost') or '').strip()
            if r.get('ok'):
                ok_n += 1
            if ip:
                if r['ts'] > cutoff_24:
                    ips_24.add(ip)
                if r['ts'] > cutoff_1h:
                    if ip not in known_ips:
                        new_ip_1h += 1
                    ips_1h.add(ip)
                known_ips.add(ip)
            # 本地时间 0-5 点算"非常规时段"（业余无线电使用高峰在白天）
            lt = time.localtime(r['ts'])
            if lt.tm_hour < 6:
                offhours += 1
        # 重连频率 = 每小时认证成功次数（EMQX 掉线重连会重新走 /auth）
        reconnect_per_hour = ok_n / hours
        return {
            'auth_count': n,
            'ok_count': ok_n,
            'fail_count': n - ok_n,
            'reconnect_per_hour': round(reconnect_per_hour, 2),
            'distinct_ips_24h': len(ips_24),
            'new_ip_1h': new_ip_1h,
            'offhours_ratio': round(offhours / n, 3) if n else 0.0,
            'first_seen': rows[0]['ts'] if rows else None,
            'window_days': round(window_h / 24, 1),
        }

    def anomalies(self, callsign):
        """异常清单（规则引擎）：返回原因列表，空列表 = 未见异常"""
        st = self.stats(callsign)
        out = []
        if st['auth_count'] == 0:
            return out
        if st['reconnect_per_hour'] > self.RECONNECT_PER_HOUR_MAX:
            out.append('重连频率异常 %.1f 次/时（阈值 %d）'
                       % (st['reconnect_per_hour'], self.RECONNECT_PER_HOUR_MAX))
        if st['distinct_ips_24h'] > self.DISTINCT_IP_24H_MAX:
            out.append('24h 源 IP 过多 %d 个（阈值 %d）'
                       % (st['distinct_ips_24h'], self.DISTINCT_IP_24H_MAX))
        if st['auth_count'] >= 20 and st['offhours_ratio'] > self.OFFHOURS_RATIO_MAX:
            out.append('非常规时段活跃占比 %.0f%%' % (st['offhours_ratio'] * 100))
        if st['new_ip_1h'] >= self.NEW_IP_BURST_1H:
            out.append('1 小时内新增源 IP %d 个' % st['new_ip_1h'])
        fail_ratio = st['fail_count'] / float(st['auth_count'])
        if st['auth_count'] >= 10 and fail_ratio > 0.5:
            out.append('认证失败率 %.0f%%（可能是爆破或密钥失效）'
                       % (fail_ratio * 100))
        return out

    def cold_start(self, callsign):
        """冷启动判定（需求：新设备观察期内以受限权限运行）"""
        st = self.stats(callsign)
        if st['auth_count'] < COLD_START_MIN_AUTHS:
            return True
        if st['first_seen'] and (time.time() - st['first_seen']) < COLD_START_DAYS * 86400:
            return True
        return False


# ============================================================
# 信任评分引擎（udac-trust-score）
# ============================================================

class TrustEngine:
    """
    TrustScore = IdentityTrust×W1 + BehaviorTrust×W2 + BridgeHealth×W5
               + AudioQuality×W6 + ContextTrust×W4 + DataTrust×W2'
    融合历史分（衰减与恢复）：当前分 0.7 + 历史分 0.3（历史随时间指数衰减，
    设备持续正常行为会逐步恢复信任分，而非永久锁死）。
    """

    HIST_DECAY_HALF_LIFE_H = 24.0    # 历史分半衰期（小时）
    HIST_BLEND = 0.25                # 历史分混入比例

    def __init__(self, db, lock, baseline,
                 weights=None, cert_lookup=None, bridge_source=None,
                 callsigns_source=None):
        self._db = db
        self._lock = lock
        self._baseline = baseline
        self.weights = dict(DEFAULT_WEIGHTS)
        if isinstance(weights, dict):
            for k, v in weights.items():
                if k in self.weights:
                    try:
                        self.weights[k] = _clamp(float(v), 0, 1)
                    except (TypeError, ValueError):
                        pass
        self._cert_lookup = cert_lookup          # callsign → cert dict | None
        self._bridge_source = bridge_source      # () → VoiceBridge.status() | None
        self._callsigns_source = callsigns_source  # () → [callsign, ...]

    # ---------------- 各维度分量 ----------------

    def _identity_component(self, callsign):
        """身份信任：证书有效性（只读消费 SAS）"""
        reasons = []
        cert = None
        if self._cert_lookup:
            try:
                cert = self._cert_lookup(callsign)
            except Exception:  # noqa: BLE001
                cert = None
        if cert is None:
            # 无证书不等于身份为零（分系统可能有纯密码用户），给及格偏下
            reasons.append('SAS 无该呼号证书记录')
            return 55.0, reasons
        if cert.get('revoked'):
            reasons.append('证书已被吊销')
            return 10.0, reasons
        score = 95.0
        issued = float(cert.get('issued_at') or 0)
        if issued:
            days = (time.time() - issued) / 86400.0
            if days > 365:
                score -= 10.0
                reasons.append('证书已使用超过 1 年（建议轮换）')
        reasons.append('持有效 SAS 证书')
        return score, reasons

    def _behavior_component(self, callsign):
        """行为信任：基线偏离 + 异常规则扣分 + 冷启动保守"""
        reasons = []
        anom = self._baseline.anomalies(callsign)
        score = 95.0 - 15.0 * len(anom)
        for a in anom:
            reasons.append('行为异常: ' + a)
        if self._baseline.cold_start(callsign):
            # 冷启动默认保守：压到"观察"水平而不是禁死
            score = min(score, 65.0)
            reasons.append('冷启动观察期内（%d 天）行为分保守'
                           % COLD_START_DAYS)
        if not reasons:
            reasons.append('行为符合基线，未见异常')
        return _clamp(score), reasons

    def _context_component(self, callsign, peerhost=''):
        """环境信任：IP 稳定性 + 时段"""
        reasons = []
        st = self._baseline.stats(callsign, window_h=24 * 14)
        score = 90.0
        if peerhost and st['distinct_ips_24h'] >= 3:
            score -= 15.0
            reasons.append('近 24h 出现 %d 个源 IP（当前 %s）'
                           % (st['distinct_ips_24h'], peerhost))
        lt = time.localtime()
        if lt.tm_hour < 6:
            score -= 5.0
            reasons.append('当前为非常规时段（0-6 点）')
        if not reasons:
            reasons.append('源 IP 与时段正常')
        return _clamp(score), reasons

    def _bridge_component(self):
        """桥接健康度：木桶最差值（需求2：UDAC 订阅桥接健康事件）"""
        src = self._bridge_source
        if not src:
            return None, ['桥接未启用，该维度不参与评分']
        try:
            st = src()
        except Exception:  # noqa: BLE001
            st = None
        if not st or not st.get('enabled'):
            return None, ['桥接未启用，该维度不参与评分']
        h = st.get('health') or {}
        reasons = []
        rtt = float(h.get('local_rtt_ms') or 0)
        loss = float(h.get('packet_loss_rate') or 0)
        jitter = float(h.get('jitter_ms') or 0)
        reconnects = int(h.get('reconnects_total') or 0)
        score = 100.0
        if rtt > 200:
            score -= 20
            reasons.append('桥接 RTT %.0fms 偏高' % rtt)
        elif rtt > 80:
            score -= 8
            reasons.append('桥接 RTT %.0fms' % rtt)
        if loss > 0.10:
            score -= 30
            reasons.append('桥接丢包率 %.1f%% 严重' % (loss * 100))
        elif loss > 0.03:
            score -= 12
            reasons.append('桥接丢包率 %.1f%%' % (loss * 100))
        if reconnects > 10:
            score -= 20
            reasons.append('链路重连 %d 次' % reconnects)
        elif reconnects > 3:
            score -= 8
            reasons.append('链路重连 %d 次' % reconnects)
        if not reasons:
            reasons.append('桥接健康（RTT %.0fms / 丢包 %.2f%% / 抖动 %.0fms）'
                           % (rtt, loss * 100, jitter))
        return _clamp(score), reasons

    def _audio_component(self):
        """音频流质量：MOS ≥ 3.5、抖动 < 30ms 为达标线"""
        src = self._bridge_source
        if not src:
            return None, ['无音频流，该维度不参与评分']
        try:
            st = src()
        except Exception:  # noqa: BLE001
            st = None
        if not st or not st.get('enabled'):
            return None, ['无音频流，该维度不参与评分']
        a = st.get('audio') or {}
        reasons = []
        mos = a.get('mos_estimate')
        jitter = float(a.get('jitter_ms') or 0)
        score = 100.0
        if mos is not None:
            m = float(mos)
            # MOS 4.5=满分、3.5=及格线（-30）、<2.5 接近零分
            s = _clamp((m - 2.0) / (4.5 - 2.0) * 100.0)
            score = min(score, s)
            if m < MOS_TARGET:
                reasons.append('MOS %.2f 低于目标 %.1f' % (m, MOS_TARGET))
            else:
                reasons.append('MOS %.2f 达标' % m)
        if jitter > JITTER_TARGET_MS:
            score -= min(30.0, (jitter - JITTER_TARGET_MS))
            reasons.append('音频抖动 %.0fms 超标（目标 <%dmS）'
                           % (jitter, int(JITTER_TARGET_MS)))
        if not reasons:
            reasons.append('音质达标（抖动 %.0fms）' % jitter)
        return _clamp(score), reasons

    @staticmethod
    def _data_component():
        """数据信任：证书链与传输加密由 SAS/FAS/EMQX(TLS) 保证，基线 90"""
        return 90.0, ['证书链与传输加密由 SAS/FAS 保证']

    def _historical_score(self, callsign):
        """历史信任贡献（EWMA + 时间衰减）：反映行为而非常量"""
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, score FROM decisions "
                "WHERE callsign = ? ORDER BY ts DESC LIMIT 20",
                (str(callsign),)).fetchall()
        if not rows:
            return None
        now = time.time()
        num = den = 0.0
        for r in rows:
            age_h = max(0.0, (now - float(r['ts'])) / 3600.0)
            w = math.pow(0.5, age_h / self.HIST_DECAY_HALF_LIFE_H)
            num += float(r['score']) * w
            den += w
        return (num / den) if den > 0 else None

    # ---------------- 汇总 ----------------

    def score_for(self, callsign, peerhost='', clientid='',
                  app_verified='', app_exempt=''):
        """
        计算某呼号的实时信任分。
        :return: {score, level, components:{dim:{score,weight,reasons}}, reasons}
        """
        # ★ 直通三类（APP 接入 / 内部客户端 / MQTT 桥接）：不评分、不做门控
        _bypass = _udac_bypass_reason(callsign, clientid,
                                      app_verified, app_exempt)
        if _bypass:
            return {
                'score': 100.0,
                'level': 'trusted',
                'level_cn': LEVEL_CN.get('trusted', '可信'),
                'components': {},
                'reasons': [_bypass],
                'exempt': True,
            }
        if is_bridge_subject(callsign, clientid):
            return {
                'score': 100.0,
                'level': 'trusted',
                'level_cn': LEVEL_CN.get('trusted', '可信'),
                'components': {},
                'reasons': [BRIDGE_PASS_REASON],
                'exempt': True,
            }

        comps = {}
        reasons = []

        def put(dim, val_reasons):
            s, rs = val_reasons
            if s is None:
                comps[dim] = None       # 不参与评分（如桥接未启用）
                return
            comps[dim] = {'score': round(s, 1),
                          'weight': self.weights.get(dim, 0.0),
                          'reasons': rs}
            reasons.extend(rs)

        put('identity', self._identity_component(callsign))
        put('behavior', self._behavior_component(callsign))
        put('context', self._context_component(callsign, peerhost))
        put('bridge_health', self._bridge_component())
        put('audio_quality', self._audio_component())
        put('data', self._data_component())

        wsum = sum(c['weight'] for c in comps.values() if c)
        if wsum <= 0:
            score = 50.0
        else:
            score = sum(c['score'] * c['weight']
                        for c in comps.values() if c) / wsum

        hist = self._historical_score(callsign)
        if hist is not None:
            score = score * (1 - self.HIST_BLEND) + hist * self.HIST_BLEND
            reasons.append('历史信任贡献 %.1f（半衰期 %gh）'
                           % (hist, self.HIST_DECAY_HALF_LIFE_H))

        score = round(_clamp(score), 1)
        return {
            'score': score,
            'level': level_of(score),
            'level_cn': LEVEL_CN[level_of(score)],
            'components': comps,
            'reasons': reasons,
        }


# ============================================================
# 策略引擎 PDP（udac-policy / udac-pdp）
# ============================================================

# 默认策略 v1：与信任分阈值表对齐（策略即代码，JSON 结构化，
# 不 eval 任意表达式 —— 条件字段化：trust_min / hour_from / hour_to / scope）
DEFAULT_POLICY_DEF = {
    'name': 'default-trust-gate',
    'description': '默认信任门控：按信任分区间给出 PEP 动作',
    'subject': {},                 # 空 = 匹配所有主体（callsign_prefix 等可加）
    'action': '*',                 # * = mqtt.connect / mqtt.publish / ...
    'scope': 'local',              # local / bridge
    'conditions': {},              # {'trust_min': 60} 等；空 = 不附加条件
    'effect': 'by_trust_score',    # 特殊值：按信任分阈值表给动作；也可直接 allow/deny/...
    'priority': 100,
}

VALID_EFFECTS = set(ACTION_SEVERITY) | {'by_trust_score'}


class PolicyEngine:
    """
    策略即代码：策略以 JSON 存库、版本化发布。
    * 发布新版本 → status='grayscale'（灰度%，按呼号稳定哈希分流）
    * promote(version) → 转正 active，旧 active 转 deprecated
    * rollback(version) → 把历史版本重新置为 active（之后版本全部 deprecated）
    * fail-closed：evaluate() 内部任何异常 → 返回 deny（新接入失败关闭，
      已建立会话的继续运行 —— PEP 只挂在新建连接路径上，天然满足分级表）
    """

    def __init__(self, db, lock, logger=print):
        self._db = db
        self._lock = lock
        self._log = logger
        self._ensure_default()

    def _ensure_default(self):
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) c FROM policies").fetchone()
            if row and row['c'] == 0:
                self._db.execute(
                    "INSERT INTO policies (version, status, gray_percent, "
                    "definition, created_at, created_by, note) "
                    "VALUES (1, 'active', 100, ?, ?, 'system', '初始默认策略')",
                    (json.dumps(DEFAULT_POLICY_DEF, ensure_ascii=False),
                     time.time()))
                self._db.commit()

    # ---------------- 版本管理 ----------------

    def publish(self, definition, gray_percent=0, created_by='admin', note=''):
        """
        发布新策略版本。gray_percent>0 = 先灰度（按呼号哈希命中新版本）。
        :return: (ok, version|error)
        """
        if not isinstance(definition, dict):
            return False, 'definition 必须是 JSON 对象'
        effect = str(definition.get('effect') or 'by_trust_score')
        if effect not in VALID_EFFECTS:
            return False, 'effect 非法: %s（可选 %s）' % (effect, sorted(VALID_EFFECTS))
        try:
            gray = _clamp(float(gray_percent or 0), 0, 100)
        except (TypeError, ValueError):
            gray = 0
        with self._lock:
            row = self._db.execute("SELECT MAX(version) v FROM policies").fetchone()
            ver = (row['v'] or 0) + 1
            self._db.execute(
                "INSERT INTO policies (version, status, gray_percent, "
                "definition, created_at, created_by, note) "
                "VALUES (?, 'grayscale', ?, ?, ?, ?, ?)",
                (ver, gray, json.dumps(definition, ensure_ascii=False),
                 time.time(), str(created_by), str(note or '')))
            self._db.commit()
        self._log('[UDAC] 策略 v%d 已发布（灰度 %.0f%%）' % (ver, gray))
        return True, ver

    def promote(self, version):
        """灰度转正：目标版本 active，其余 active/grayscale 全部 deprecated"""
        with self._lock:
            row = self._db.execute(
                "SELECT version FROM policies WHERE version = ?",
                (int(version),)).fetchone()
            if not row:
                return False, '版本不存在: %s' % version
            self._db.execute(
                "UPDATE policies SET status='deprecated' "
                "WHERE status IN ('active','grayscale')")
            self._db.execute(
                "UPDATE policies SET status='active', gray_percent=100 "
                "WHERE version = ?", (int(version),))
            self._db.commit()
        self._log('[UDAC] 策略 v%d 已转正（active）' % int(version))
        return True, int(version)

    def rollback(self, version):
        """回滚到历史版本（之后的所有版本置 deprecated）"""
        with self._lock:
            row = self._db.execute(
                "SELECT version FROM policies WHERE version = ?",
                (int(version),)).fetchone()
            if not row:
                return False, '版本不存在: %s' % version
            self._db.execute(
                "UPDATE policies SET status='deprecated' "
                "WHERE status IN ('active','grayscale') AND version > ?",
                (int(version),))
            self._db.execute(
                "UPDATE policies SET status='active', gray_percent=100 "
                "WHERE version = ?", (int(version),))
            self._db.commit()
        self._log('[UDAC] 策略已回滚到 v%d' % int(version))
        return True, int(version)

    def versions(self, limit=50):
        with self._lock:
            rows = self._db.execute(
                "SELECT version, status, gray_percent, created_at, created_by, note "
                "FROM policies ORDER BY version DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d['definition'] = self._def_of(d['version'])
            out.append(d)
        return out

    def _def_of(self, version):
        with self._lock:
            row = self._db.execute(
                "SELECT definition FROM policies WHERE version = ?",
                (int(version),)).fetchone()
        try:
            return json.loads(row['definition']) if row else None
        except (TypeError, ValueError):
            return None

    def current(self):
        """当前生效策略（active 的那个；没有 active 则取最新 grayscale 兜底）"""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM policies WHERE status='active' "
                "ORDER BY version DESC LIMIT 1").fetchone()
            if not row:
                row = self._db.execute(
                    "SELECT * FROM policies WHERE status='grayscale' "
                    "ORDER BY version DESC LIMIT 1").fetchone()
        if not row:
            return {'version': 0, 'status': 'none',
                    'definition': DEFAULT_POLICY_DEF}
        d = dict(row)
        try:
            d['definition'] = json.loads(d['definition'])
        except (TypeError, ValueError):
            d['definition'] = None
        return d

    # ---------------- 评估 ----------------

    def _match(self, definition, ctx):
        """主体/动作/条件匹配（字段化 ABAC；返回 (matched, reason)）"""
        subject = definition.get('subject') or {}
        prefix = str(subject.get('callsign_prefix') or '')
        if prefix and not str(ctx.get('callsign') or '').upper().startswith(prefix.upper()):
            return False, '呼号不匹配'
        cidp = str(subject.get('clientid_prefix') or '')
        if cidp and not str(ctx.get('clientid') or '').startswith(cidp):
            return False, 'clientid 不匹配'
        if subject.get('app_verified') is not None and \
                str(subject['app_verified']) != str(ctx.get('app_verified', '')):
            return False, 'app_verified 不匹配'

        action = str(definition.get('action') or '*')
        if action not in ('*', '*') and action != str(ctx.get('action') or ''):
            return False, 'action 不匹配'

        conds = definition.get('conditions') or {}
        score = float(ctx.get('trust_score') or 0)
        if 'trust_min' in conds and score < float(conds['trust_min']):
            return False, '信任分 %s < %s' % (score, conds['trust_min'])
        if 'hour_from' in conds and 'hour_to' in conds:
            h = time.localtime().tm_hour
            lo, hi = int(conds['hour_from']), int(conds['hour_to'])
            if lo <= hi:
                if not (lo <= h <= hi):
                    return False, '不在允许时段 %d-%d 点' % (lo, hi)
            elif not (h >= lo or h <= hi):
                return False, '不在允许时段 %d-%d 点' % (lo, hi)
        bh = ctx.get('bridge_health') or {}
        if 'jitter_max' in conds and bh.get('jitter_ms') is not None \
                and float(bh['jitter_ms']) > float(conds['jitter_max']):
            return False, '抖动 %.0fms > %.0fms' % (bh['jitter_ms'], conds['jitter_max'])
        aq = ctx.get('audio') or {}
        if 'mos_min' in conds and aq.get('mos_estimate') is not None \
                and float(aq['mos_estimate']) < float(conds['mos_min']):
            return False, 'MOS %.2f < %s' % (aq['mos_estimate'], conds['mos_min'])
        return True, '匹配'

    def evaluate(self, ctx, version=None):
        """
        策略评估（waterfall 链的最终短路点）。
        :param ctx: {callsign, clientid, action, app_verified, trust_score,
                     bridge_health{...}, audio{...}}
        :return: {'effect', 'matched_version', 'matched_policy', 'reason', 'gray_hit'}
                 effect ∈ allow/deny/degrade/rate_limit/step_up/disconnect/quarantine
                 或 'by_trust_score'（交给 PEP 按信任分阈值表决定）
        fail-closed：任何异常 → deny。
        """
        # ★ 直通三类：直接 allow，连异常兜底都不该把它拒掉
        try:
            _bp = _udac_bypass_reason(ctx.get('callsign'), ctx.get('clientid'),
                                      ctx.get('app_verified'),
                                      ctx.get('app_exempt'))
            if _bp:
                return {'effect': 'allow', 'matched_version': None,
                        'matched_policy': 'verified-bypass',
                        'reason': _bp, 'gray_hit': False,
                        'exempt': True}
            if is_bridge_subject(ctx.get('callsign'), ctx.get('clientid')):
                return {'effect': 'allow', 'matched_version': None,
                        'matched_policy': 'bridge-bypass',
                        'reason': BRIDGE_PASS_REASON, 'gray_hit': False,
                        'exempt': True}
        except Exception:  # noqa: BLE001
            pass
        try:
            callsign = str(ctx.get('callsign') or '')
            gray_hit = False
            rows = self.versions(200)
            # active 优先；灰度版本按呼号稳定哈希分流
            active = [v for v in rows if v['status'] == 'active']
            grays = [v for v in rows if v['status'] == 'grayscale']
            if version is not None:            # 仿真指定版本
                defs = [v for v in rows if v['version'] == int(version)]
            else:
                defs = list(active)
                if callsign and grays:
                    h = _stable_hash('udac-gray:' + callsign) % 100
                    for g in grays:
                        if h < float(g.get('gray_percent') or 0):
                            defs.insert(0, g)   # 灰度命中 → 优先用新版本
                            gray_hit = True
                            break
            for v in defs:
                d = v.get('definition') or {}
                ok, why = self._match(d, ctx)
                if ok:
                    eff = str(d.get('effect') or 'by_trust_score')
                    return {'effect': eff if eff in VALID_EFFECTS else 'by_trust_score',
                            'matched_version': v['version'],
                            'matched_policy': d.get('name') or '',
                            'reason': why, 'gray_hit': gray_hit}
            if not defs:
                return {'effect': 'by_trust_score', 'matched_version': None,
                        'matched_policy': 'default-trust-gate(内置)',
                        'reason': '无生效策略，走内置信任门控',
                        'gray_hit': False}
            return {'effect': 'by_trust_score', 'matched_version': None,
                    'matched_policy': None,
                    'reason': '策略均不匹配 → 内置信任门控', 'gray_hit': False}
        except Exception as e:  # noqa: BLE001
            self._log('[UDAC] PDP 异常 fail-closed: %s' % e)
            return {'effect': 'deny', 'matched_version': None,
                    'matched_policy': 'fail-closed',
                    'reason': 'PDP 异常，失败关闭: %s' % e, 'gray_hit': False}

    def simulate(self, ctx, version=None):
        """仿真：与 evaluate 相同路径，但不写审计（策略编辑器的"试运行"）"""
        return self.evaluate(ctx, version=version)


# ============================================================
# UDAC 中心（组合 + 审计 + 对外 API）
# ============================================================

class UDACCenter:
    """
    一个对象管全部：TrustEngine + BehaviorBaseline + PolicyEngine + PEP + 审计。
    api_server 持有单例：/auth 挂 PEP，/api/udac/* 暴露管理接口，
    sync 上报携带 ranking 摘要给总系统（全局台站信任排行）。
    """

    P99_WINDOW = 1000     # 决策延迟滑动窗口（内存内）

    def __init__(self, base_dir, logger=print,
                 cert_lookup=None, bridge_source=None, callsigns_source=None,
                 weights=None):
        self.base_dir = base_dir
        self._log = logger
        db_path = os.path.join(base_dir, 'udac.db')
        self.db_path = db_path
        self._lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False, timeout=15.0)
        # ★ 性能：必须开 WAL。认证路径每次连接都要写决策/事件；回滚日志模式下
        #   写入会**锁整库**、所有读被堵住 —— 实测 UDAC 状态接口 2 秒、排行直接
        #   60 秒超时、页面整片卡死；更严重的是 EMQX 调 /auth 时等不到响应
        #   → 桥接连接被判失败（CONNACK 超时，用户报的"桥接连不上"）。
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA busy_timeout=8000")
            self.db.execute("PRAGMA wal_autocheckpoint=400")
        except Exception:  # noqa: BLE001
            pass
        self.db.row_factory = sqlite3.Row
        self._init_tables()
        self.baseline = BehaviorBaseline(self.db, self._lock)
        self.trust = TrustEngine(self.db, self._lock, self.baseline,
                                 weights=weights,
                                 cert_lookup=cert_lookup,
                                 bridge_source=bridge_source,
                                 callsigns_source=callsigns_source)
        self.policy = PolicyEngine(self.db, self._lock, logger=logger)
        self._latencies = []          # P99 滑动窗口
        self._started_at = time.time()

    # ---------------- 表结构 ----------------

    def _init_tables(self):
        cur = self.db.cursor()
        cur.executescript("""
        -- 策略（版本化；status: active/grayscale/deprecated）
        CREATE TABLE IF NOT EXISTS policies (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            version       INTEGER NOT NULL UNIQUE,
            status        TEXT    NOT NULL DEFAULT 'grayscale',
            gray_percent  REAL    NOT NULL DEFAULT 0,
            definition    TEXT    NOT NULL DEFAULT '{}',
            created_at    REAL    NOT NULL,
            created_by    TEXT    NOT NULL DEFAULT 'admin',
            note          TEXT    NOT NULL DEFAULT ''
        );
        -- 决策审计（只追加；原始审计仍归 FAS，这里只记 UDAC 决策与风控特征）
        CREATE TABLE IF NOT EXISTS decisions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ts             REAL    NOT NULL,
            callsign       TEXT    NOT NULL DEFAULT '',
            clientid       TEXT    NOT NULL DEFAULT '',
            action         TEXT    NOT NULL DEFAULT 'mqtt.connect',
            effect         TEXT    NOT NULL DEFAULT 'allow',
            score          REAL    NOT NULL DEFAULT 0,
            level          TEXT    NOT NULL DEFAULT '',
            reasons        TEXT    NOT NULL DEFAULT '[]',
            policy_version INTEGER,
            latency_ms     REAL    NOT NULL DEFAULT 0,
            -- 1 = 桥接直通（不评分、不受策略门控影响）；界面据此区分
            exempt         INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_udac_dec_ts   ON decisions(ts);
        CREATE INDEX IF NOT EXISTS idx_udac_dec_call ON decisions(callsign);
        -- 行为基线数据源：/auth 认证事件（成功与失败都记）
        CREATE TABLE IF NOT EXISTS auth_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL    NOT NULL,
            callsign  TEXT    NOT NULL DEFAULT '',
            clientid  TEXT    NOT NULL DEFAULT '',
            peerhost  TEXT    NOT NULL DEFAULT '',
            ok        INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_udac_ae_call ON auth_events(callsign, ts);
        -- 只追加事件日志（udac.* 事件：SessionEvent 简化落地，可回放追溯）
        CREATE TABLE IF NOT EXISTS events (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      REAL    NOT NULL,
            type    TEXT    NOT NULL,
            payload TEXT    NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_udac_ev_ts ON events(ts);
        -- 信任分快照（ranking / 台站页用，避免每次全量现算）
        CREATE TABLE IF NOT EXISTS trust_snapshot (
            callsign    TEXT PRIMARY KEY,
            score       REAL    NOT NULL DEFAULT 0,
            level       TEXT    NOT NULL DEFAULT '',
            components  TEXT    NOT NULL DEFAULT '{}',
            updated_at  REAL    NOT NULL DEFAULT 0
        );
        """)
        # 老库补列：桥接直通标记（幂等，已存在就忽略）
        try:
            self.db.execute("ALTER TABLE decisions "
                            "ADD COLUMN exempt INTEGER NOT NULL DEFAULT 0")
        except Exception:  # noqa: BLE001
            pass
        self.db.commit()

    # ---------------- 事件日志 ----------------

    def record_event(self, etype, payload=None):
        """写入只追加事件日志（udac.decision.made / udac.cert.fullscan.triggered ...）"""
        with self._lock:
            self.db.execute(
                "INSERT INTO events (ts, type, payload) VALUES (?, ?, ?)",
                (time.time(), str(etype),
                 json.dumps(payload or {}, ensure_ascii=False)))
            self.db.commit()

    def events(self, limit=100):
        with self._lock:
            rows = self.db.execute(
                "SELECT ts, type, payload FROM events "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            try:
                p = json.loads(r['payload'])
            except (TypeError, ValueError):
                p = {}
            out.append({'ts': r['ts'], 'type': r['type'], 'payload': p})
        return out

    # ---------------- 认证喂入（udac-fas-connector 的只读消费） ----------------

    def note_auth(self, callsign, clientid='', peerhost='', ok=True):
        """认证结果喂入：行为基线 + udac.auth.result 事件"""
        try:
            self.baseline.record_auth(callsign, clientid, peerhost, ok)
            self.record_event('udac.auth.result', {
                'callsign': callsign, 'clientid': clientid,
                'peerhost': peerhost, 'ok': bool(ok)})
        except Exception as e:  # noqa: BLE001
            self._log('[UDAC] note_auth 失败（忽略）: %s' % e)

    # ---------------- PEP：enforce ----------------

    def enforce(self, action, callsign, clientid='', peerhost='',
                app_verified='', app_exempt=''):
        """
        策略执行点：在 /auth（新连接/新接入）路径上调用。
        流程 = 需求时序「消息路由路径上的授权决策」的连接版：
          信任评分 → PDP 决策（fail-closed）→ 与信任分阈值表取更严者 → 审计。
        :return: {action, effect, score, level, reasons, policy_version, decision_id}
        """
        t0 = time.time()
        score = 50.0
        level = 'unknown'
        reasons = []
        # ★ 直通三类（APP 接入 / 内部客户端 / MQTT 桥接）：不评分、不查策略、
        #   不受 fail-closed 影响，直接放行（用户明确要求）。
        _ex_reason = _udac_bypass_reason(callsign, clientid,
                                         app_verified, app_exempt)
        if _ex_reason:
            latency_ms = (time.time() - t0) * 1000.0
            did = self._audit_decision(callsign, clientid, action, 'allow',
                                       100.0, 'trusted', [_ex_reason],
                                       None, latency_ms, exempt=True)
            return {
                'decision_id': did,
                'action': 'allow',
                'score': 100.0,
                'level': 'trusted',
                'level_cn': LEVEL_CN.get('trusted', '可信'),
                'reasons': [_ex_reason],
                'policy_version': None,
                'latency_ms': round(latency_ms, 2),
                'exempt': True,
            }
        try:
            ts = self.trust.score_for(callsign, peerhost=peerhost,
                                      clientid=clientid,
                                      app_verified=app_verified,
                                      app_exempt=app_exempt)
            score, level = ts['score'], ts['level']
            reasons = list(ts['reasons'])
            ctx = {
                'callsign': callsign, 'clientid': clientid,
                'action': action, 'app_verified': app_verified,
                'app_exempt': app_exempt,
                'trust_score': score,
                'bridge_health': self._bridge_health_dict(),
                'audio': self._audio_dict(),
            }
            dec = self.policy.evaluate(ctx)
            effect = dec['effect']
            if effect == 'by_trust_score':
                effect = LEVEL_ACTION.get(level, 'deny')
                reasons.append('内置信任门控: %s(%s) → %s'
                               % (score, LEVEL_CN[level], effect))
            else:
                reasons.append('策略 v%s(%s) 命中 → %s'
                               % (dec.get('matched_version'),
                                  dec.get('matched_policy') or '-', effect))
            # 信任分阈值表与策略效果取**更严**者（叠加而不是覆盖）
            trust_action = LEVEL_ACTION.get(level, 'deny')
            if ACTION_SEVERITY.get(effect, 0) < ACTION_SEVERITY.get(trust_action, 0):
                effect = trust_action
                reasons.append('信任分门控更严 → %s' % effect)
            ver = dec.get('matched_version')
        except Exception as e:  # noqa: BLE001
            # fail-closed：评分/策略任何异常 → 拒绝新接入（已建立会话不受影响）
            self._log('[UDAC] enforce 异常 fail-closed: %s' % e)
            effect = 'deny'
            ver = None
            reasons = ['UDAC 内部异常，失败关闭: %s' % e]

        latency_ms = (time.time() - t0) * 1000.0
        did = self._audit_decision(callsign, clientid, action, effect,
                                   score, level, reasons, ver, latency_ms)
        return {
            'decision_id': did,
            'action': effect,
            'score': score,
            'level': level,
            'level_cn': LEVEL_CN.get(level, level),
            'reasons': reasons,
            'policy_version': ver,
            'latency_ms': round(latency_ms, 2),
        }

    def _bridge_health_dict(self):
        src = self.trust._bridge_source
        if not src:
            return {}
        try:
            st = src() or {}
            return st.get('health') or {}
        except Exception:  # noqa: BLE001
            return {}

    def _audio_dict(self):
        src = self.trust._bridge_source
        if not src:
            return {}
        try:
            st = src() or {}
            return st.get('audio') or {}
        except Exception:  # noqa: BLE001
            return {}

    # ---------------- 审计 ----------------

    def _audit_decision(self, callsign, clientid, action, effect,
                        score, level, reasons, policy_version, latency_ms,
                        exempt=False):
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO decisions (ts, callsign, clientid, action, effect, "
                "score, level, reasons, policy_version, latency_ms, exempt) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), str(callsign or ''), str(clientid or ''),
                 str(action), str(effect), float(score), str(level),
                 json.dumps(reasons, ensure_ascii=False),
                 policy_version, float(latency_ms), 1 if exempt else 0))
            self.db.commit()
            did = cur.lastrowid
        # P99 滑动窗口（内存，够用且不写放大）
        self._latencies.append(latency_ms)
        if len(self._latencies) > self.P99_WINDOW:
            del self._latencies[:len(self._latencies) - self.P99_WINDOW]
        self.record_event('udac.decision.made', {
            'decision_id': did, 'callsign': callsign, 'action': action,
            'effect': effect, 'score': score, 'level': level,
            'policy_version': policy_version,
            'latency_ms': round(latency_ms, 2),
            'exempt': bool(exempt),
            'exempt_reason': BRIDGE_PASS_REASON if exempt else ''})
        if effect not in ('allow',):
            self._log('[UDAC] 决策: %s(%s) → %s  分=%.1f  %s'
                      % (callsign or '-', action, effect, score,
                         '; '.join(reasons[:3])))
        return did

    def decisions(self, limit=100):
        with self._lock:
            rows = self.db.execute(
                "SELECT * FROM decisions ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d['reasons'] = json.loads(d['reasons'])
            except (TypeError, ValueError):
                d['reasons'] = []
            out.append(d)
        return out

    def _p99(self):
        data = sorted(self._latencies)
        if not data:
            return 0.0
        idx = min(len(data) - 1, int(math.ceil(0.99 * len(data))) - 1)
        return round(data[max(0, idx)], 2)

    # ---------------- 信任排行 / 快照 ----------------

    def _known_callsigns(self, limit=1000):
        """已知呼号 = SAS 证书呼号 + 近期认证过的呼号"""
        out = []
        src = self.trust._callsigns_source
        if src:
            try:
                out.extend([str(c) for c in (src() or []) if c])
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            rows = self.db.execute(
                "SELECT DISTINCT callsign FROM auth_events "
                "WHERE callsign != '' ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        out.extend([r['callsign'] for r in rows])
        seen, uniq = set(), []
        for c in out:
            c = c.strip().upper()
            if c and c not in seen:
                seen.add(c)
                uniq.append(c)
        return uniq[:limit]

    def recalc_ranking(self, limit=200):
        """
        重算信任分快照（管理页"重算"/ fullscan / 后台定时刷新调用）。

        ★ 性能：原来每个呼号单独 commit（_save_snapshot 内部 commit），几百次提交
          在回滚日志模式下会把库锁死几十秒 —— 实测 /api/udac/ranking 60 秒超时。
          现在**一个事务批量写完**；桥接/服务呼号直接跳过（它们本来就"直接通过、
          不评分"，进排行没有意义）。
        """
        out = []
        now = time.time()
        with self._lock:
            for cs in self._known_callsigns(limit):
                if is_bridge_subject(cs):
                    continue
                try:
                    ts = self.trust.score_for(cs)
                    self.db.execute(
                        "INSERT INTO trust_snapshot (callsign, score, level, components, updated_at) "
                        "VALUES (?, ?, ?, ?, ?) ON CONFLICT(callsign) DO UPDATE SET "
                        "score=excluded.score, level=excluded.level, "
                        "components=excluded.components, updated_at=excluded.updated_at",
                        (str(cs), float(ts['score']), str(ts['level']),
                         json.dumps(ts['components'], ensure_ascii=False), now))
                except Exception:  # noqa: BLE001
                    continue
                out.append({'callsign': cs, 'score': ts['score'],
                            'level': ts['level']})
            try:
                self.db.commit()
            except Exception:  # noqa: BLE001
                pass
        out.sort(key=lambda x: -x['score'])
        self.record_event('udac.trust.ranking_recalced', {'count': len(out)})
        return out

    def _save_snapshot(self, callsign, ts):
        with self._lock:
            self.db.execute(
                "INSERT INTO trust_snapshot (callsign, score, level, components, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT(callsign) DO UPDATE SET "
                "score=excluded.score, level=excluded.level, "
                "components=excluded.components, updated_at=excluded.updated_at",
                (str(callsign), float(ts['score']), str(ts['level']),
                 json.dumps(ts['components'], ensure_ascii=False), time.time()))
            self.db.commit()

    def ranking(self, limit=50, recalc=False):
        """
        台站信任排行（本机视角）。
        recalc=False（默认）= 直接读 trust_snapshot 快照，毫秒级返回；
        快照由后台定时刷新（api_server.start_udac_ranking_loop）。
        ★ 原来默认 True：页面每几秒请求一次就把几百个呼号全量重算，
          直接 60 秒超时、页面卡死（真实踩过）。
        :return: [{callsign, score, level, level_cn, updated_at}]
        """
        if recalc:
            self.recalc_ranking(limit=limit)
        with self._lock:
            rows = self.db.execute(
                "SELECT callsign, score, level, updated_at FROM trust_snapshot "
                "ORDER BY score DESC LIMIT ?", (limit,)).fetchall()
        return [{'callsign': r['callsign'], 'score': r['score'],
                 'level': r['level'], 'level_cn': LEVEL_CN.get(r['level'], r['level']),
                 'updated_at': r['updated_at']} for r in rows]

    def ranking_payload(self, n=20):
        """给 sync 上报用的精简排行（总系统汇总成全局排行）"""
        try:
            return [{'callsign': r['callsign'], 'score': r['score'],
                     'level': r['level']}
                    for r in self.ranking(limit=n, recalc=False)]
        except Exception:  # noqa: BLE001
            return []

    # ---------------- 状态 ----------------

    def status(self):
        with self._lock:
            n_dec = self.db.execute("SELECT COUNT(*) c FROM decisions").fetchone()['c']
            n_ev = self.db.execute("SELECT COUNT(*) c FROM events").fetchone()['c']
            dist_rows = self.db.execute(
                "SELECT level, COUNT(*) c FROM trust_snapshot GROUP BY level"
            ).fetchall()
            last_scan = self.db.execute(
                "SELECT ts, payload FROM events WHERE type='udac.cert.fullscan.triggered' "
                "ORDER BY id DESC LIMIT 1").fetchone()
        cur = self.policy.current()
        dist = {k: 0 for k in ('normal', 'watch', 'alert', 'danger')}
        for r in dist_rows:
            if r['level'] in dist:
                dist[r['level']] = r['c']
        st = {}
        try:
            st = (self.trust._bridge_source() or {}) if self.trust._bridge_source else {}
        except Exception:  # noqa: BLE001
            st = {}
        last_scan_out = None
        if last_scan:
            try:
                last_scan_out = {'ts': last_scan['ts'],
                                 'payload': json.loads(last_scan['payload'])}
            except (TypeError, ValueError):
                pass
        return {
            'ok': True,
            'started_at': self._started_at,
            'weights': self.trust.weights,
            'policy_version': cur.get('version'),
            'policy_status': cur.get('status'),
            'policy_definition': cur.get('definition'),
            'decisions_count': n_dec,
            'events_count': n_ev,
            'p99_ms': self._p99(),
            'trust_dist': dist,
            'bridge': {'enabled': bool(st.get('enabled')),
                       'health': st.get('health') or {},
                       'audio': st.get('audio') or {}},
            'last_fullscan': last_scan_out,
            'targets': {'mos_min': MOS_TARGET, 'jitter_max_ms': JITTER_TARGET_MS},
        }

    # ---------------- 全量扫描联动（总系统 → UDAC 通知） ----------------

    def handle_fullscan_triggered(self, payload):
        """
        需求时序「全量证书扫描流程」第 2 步：
        总系统触发全量扫描 → 通知 UDAC（udac.cert.fullscan.triggered）→
        UDAC 重算全局台站信任分并记 FullScan 事件（可追溯）。
        """
        scan = {
            'scan_id': str(payload.get('scan_id') or ''),
            'triggered_by': str(payload.get('triggered_by') or 'master'),
            'cert_count': int(payload.get('cert_count') or 0),
            'station_count': int(payload.get('station_count') or 0),
        }
        self.record_event('udac.cert.fullscan.triggered', scan)
        try:
            n = len(self.recalc_ranking(limit=500))
            scan['recalced'] = n
        except Exception as e:  # noqa: BLE001
            scan['recalc_error'] = str(e)
        self._log('[UDAC] 全量扫描联动: %s（%d 台站）→ 已重算 %s 条信任分'
                  % (scan['scan_id'] or '-', scan['station_count'],
                     scan.get('recalced', '?')))
        return scan
