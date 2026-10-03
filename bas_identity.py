#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · 身份控制策略引擎（替代 FAS 的硬判定，解决"合法呼号被误封"）
==================================================================

FAS 原判决（TopicEndpoints.cs:241-249）是二元的：

    verdict = (pktCallsign == connCallsign) && (pktUid == connUid) ? PASS : KICK
    KICK 且 identity_control 开启 → 立即 EMQX 拉黑（BanAsync）

两个缺陷导致 SAS 的合法用户被禁用：

  缺陷1（UID 过严）：包头 UID 只要不等于证书签发的 UID 就判 KICK。
    包头 UID 是设备固件里的"声明"，与 SAS 证书的 uid 可能因固件未更新、
    多设备同步、UID 重新分配等原因不一致 —— 呼号虽然正确，照样被封。

  缺陷2（单侧缺失即 KICK）：只有当连接身份的 callsign 与 uid **都**为空时才降级 WARN。
    若 EMQX 只下发了 uid（没有 callsign），csOk=False → 直接 KICK。
    典型场景：认证响应里的 client_attrs 没被 EMQX 落到连接上（属性下发失败）。

本引擎把判决拆成**可配置策略**：证据 → 场景 → 判决 → 动作，并提供：
  * 场景细分（呼号不符/UID 不符/单侧缺失/非法包/无法取证）
  * 三种运行模式（off / warn / ban），默认 **warn**（只记录不封人）
  * SAS 库交叉校验（呼号是否真实注册、UID 是否与签发记录一致）→ 可信度升级
  * 限流与白名单（防刷、防管理员误操作）
  * 每一条判决都给出可读 reason，便于事后审计与申诉

设计原则：**封人必须高置信度**。默认配置下，只有"呼号与连接身份不符"（明确伪造）
才会自动拉黑；UID 不符、单侧缺失一律降级为 warn 并留证。
"""

import time

# ---------------- 判决（verdict） ----------------
PASS = "PASS"        # 身份一致，放行
WARN = "WARN"        # 有疑点但证据不足（或策略要求只告警）
KICK = "KICK"        # 确认伪造，按策略决定是否封

# ---------------- 运行模式 ----------------
MODE_OFF = "off"     # 完全不审计（只做统计）
MODE_WARN = "warn"   # 审计并留证，绝不自动封人（默认，安全）
MODE_BAN = "ban"     # 审计 + 按策略自动封人

# ---------------- 场景（scene） ----------------
SCENE_PASS = "pass"                    # 身份一致
SCENE_FORGED = "forged"                # 包头呼号 ≠ 连接呼号（明确伪造）
SCENE_UID_MISMATCH = "uid_mismatch"    # 呼号一致但 UID 不一致（最常见误封源）
SCENE_ATTR_MISSING = "attr_missing"    # 连接侧身份缺失（属性下发失败/半截）
SCENE_BOTH_MISSING = "both_missing"    # 连接侧完全无身份（匿名）
SCENE_BAD_PACKET = "bad_packet"        # 非法包（长度/len/MTU）
SCENE_SAS_UNKNOWN = "sas_unknown"      # SAS 库里查不到该呼号（疑似伪造证书）
SCENE_SAS_UNAVAILABLE = "sas_unavailable"  # SAS 库不可用/还是空库（不得据以封人）
SCENE_SAS_UID_MISMATCH = "sas_uid_mismatch"  # SAS 记录的 uid 与包头 uid 不一致

DEFAULT_POLICY = {
    # 总开关：off / warn / ban。默认 warn —— 先观察，确认无误封再切 ban
    "mode": MODE_WARN,
    # 是否允许引擎调用 EMQX 拉黑（mode=ban 时仍需为 True 才真正封人）
    "auto_ban": False,
    # UID 不一致时的判决：warn（默认，安全）/ kick（严格，按 FAS 原行为）
    "uid_mismatch_verdict": WARN,
    # 连接侧只拿到 uid、没有 callsign 时的判决：warn（默认）/ kick
    "partial_attr_verdict": WARN,
    # 拉黑时长（小时）；None = 永久（FAS 默认永久）
    "ban_hours": None,
    # 拉黑白名单（永不自动封）：管理员/骨干台呼号
    "ban_whitelist": [],
    # 同一呼号在窗口内最多自动封几次（防刷）
    "ban_rate_limit_per_hour": 3,
    # SAS 交叉校验不可用（库读不到）时是否仍然自动封人；默认 False=宁可不封
    "ban_when_sas_unavailable": False,
    # 是否用 SAS 用户库做交叉校验
    "sas_cross_check": True,
    # 审计事件写库限流（每秒最多几条，防刷库）
    "audit_rate_limit_per_sec": 50,
}


def normalize_callsign(value):
    """呼号归一：去空白 + 大写（对齐 SAS 与 FAS 的处理）。空 → ''。"""
    if value is None:
        return ""
    return str(value).strip().upper()


def normalize_uid(value):
    """UID 归一：数字/字符串/null 统一成无前导零的数字字符串。空 → ''。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)
    s = str(value).strip()
    if s == "" or s.lower() in ("null", "undefined", "none"):
        return ""
    if s.isdigit():
        return str(int(s))
    return s


class Decision(object):
    """一次身份判决的结果。"""

    __slots__ = ("verdict", "scene", "reason", "action", "ban", "confidence")

    def __init__(self, verdict, scene, reason, action="none", ban=False, confidence=0.0):
        self.verdict = verdict
        self.scene = scene
        self.reason = reason
        self.action = action      # none / record / ban
        self.ban = ban            # 是否实际执行拉黑
        self.confidence = confidence

    def as_dict(self):
        return {
            "verdict": self.verdict,
            "scene": self.scene,
            "reason": self.reason,
            "action": self.action,
            "ban": self.ban,
            "confidence": round(self.confidence, 3),
        }

    def __repr__(self):
        return "<Decision %s/%s action=%s ban=%s>" % (
            self.verdict, self.scene, self.action, self.ban)


class IdentityPolicy(object):
    """策略引擎：加载配置、判决、限流、白名单、SAS 交叉校验。"""

    def __init__(self, policy=None, sas_lookup=None, ban_recorder=None, sas_has_any=None):
        """
        policy       : dict，字段见 DEFAULT_POLICY
        sas_lookup   : callable(callsign) -> None | dict(uid=int/str, revoked=bool)
                       （回 None 表示 SAS 库里没有该呼号；抛异常表示 SAS 不可用）
        ban_recorder : callable(callsign, reason, hours) -> bool，实际执行拉黑
        sas_has_any  : callable() -> bool，SAS 库是否已有任何注册用户/证书。
                       返回 False 时"sas 里查不到"不作为伪造证据——否则新装环境
                       （库还空着）会把所有合法连接都判成伪造，正是误封的来源之一。
        """
        cfg = dict(DEFAULT_POLICY)
        for k, v in (policy or {}).items():
            if k in cfg:
                cfg[k] = v
        self.cfg = cfg
        self.sas_lookup = sas_lookup
        self.ban_recorder = ban_recorder
        self.sas_has_any = sas_has_any
        self._ban_times = []          # 自动拉黑时间戳（限流用）
        self._audit_times = []        # 审计落库时间戳（限流用）
        self._attr_missing_streak = 0  # 连续"属性缺失"计数（用于链路诊断）

    # ---------------- 配置 ----------------
    def mode(self):
        m = str(self.cfg.get("mode", MODE_WARN)).lower()
        return m if m in (MODE_OFF, MODE_WARN, MODE_BAN) else MODE_WARN

    def set_mode(self, mode):
        m = str(mode).lower()
        if m not in (MODE_OFF, MODE_WARN, MODE_BAN):
            raise ValueError("mode 必须是 off/warn/ban 之一")
        self.cfg["mode"] = m
        return m

    # ---------------- 限流：审计落库 ----------------
    def allow_audit_write(self):
        limit = int(self.cfg.get("audit_rate_limit_per_sec", 50) or 0)
        if limit <= 0:
            return True
        now = time.time()
        self._audit_times = [t for t in self._audit_times if now - t < 1.0]
        if len(self._audit_times) >= limit:
            return False
        self._audit_times.append(now)
        return True

    # ---------------- 限流：自动拉黑 ----------------
    def _ban_rate_ok(self):
        limit = int(self.cfg.get("ban_rate_limit_per_hour", 3) or 0)
        if limit <= 0:
            return True
        now = time.time()
        self._ban_times = [t for t in self._ban_times if now - t < 3600]
        return len(self._ban_times) < limit

    def _mark_ban(self):
        self._ban_times.append(time.time())

    def in_whitelist(self, callsign):
        cs = normalize_callsign(callsign)
        wl = [normalize_callsign(x) for x in (self.cfg.get("ban_whitelist") or [])]
        return bool(cs) and cs in wl

    # ---------------- SAS 交叉校验 ----------------
    def sas_check(self, callsign, pkt_uid=None):
        """
        返回 (状态, 说明)：
          ('ok', ...)        SAS 里有该呼号（uid 一致或未比较）
          ('uid_diff', ...)  SAS 里的 uid 与包头声明不一致
          ('revoked', ...)   SAS 里该呼号证书已吊销
          ('unknown', ...)   SAS 库里没有该呼号
          ('unavailable', …) SAS 库读不到（不可作为封人依据）
          ('skipped', ...)   未启用交叉校验
        """
        if not self.cfg.get("sas_cross_check", True) or self.sas_lookup is None:
            return "skipped", "未启用 SAS 交叉校验"
        cs = normalize_callsign(callsign)
        if not cs:
            return "unknown", "呼号为空"
        # 安全阀：SAS 库还没有任何注册记录时，"查不到"不能作为伪造证据
        if self.sas_has_any is not None:
            try:
                if not self.sas_has_any():
                    return "unavailable", "SAS 库尚无任何注册用户/证书，不能据'查不到'判伪造"
            except Exception as e:  # noqa: BLE001
                return "unavailable", "SAS 库状态未知: %s" % e
        try:
            rec = self.sas_lookup(cs)
        except Exception as e:  # noqa: BLE001
            return "unavailable", "SAS 库不可用: %s" % e
        if not rec:
            return "unknown", "SAS 用户/证书库中没有呼号 %s" % cs
        if rec.get("revoked"):
            return "revoked", "SAS 中 %s 的证书已吊销" % cs
        rec_uid = normalize_uid(rec.get("uid"))
        want = normalize_uid(pkt_uid)
        if rec_uid and want and rec_uid != want:
            return "uid_diff", "SAS 记录 UID=%s，包头声明 UID=%s" % (rec_uid, want)
        return "ok", "SAS 记录匹配（UID=%s）" % (rec_uid or "-")

    # ---------------- 主判决 ----------------
    def decide(self, raw_payload, parsed, conn_callsign, conn_uid, client_id=None):
        """
        raw_payload : bytes|None（webhook 解出的原始载荷）
        parsed      : bas_fmo_parser.ParseResult | None（解析失败传 None/ok=False）
        conn_callsign/conn_uid : 连接身份（来自 client_attrs）
        返回 Decision
        """
        mode = self.mode()
        if mode == MODE_OFF:
            return Decision(PASS, SCENE_PASS, "身份控制已关闭（mode=off）")

        conn_cs = normalize_callsign(conn_callsign)
        conn_u = normalize_uid(conn_uid)

        # 1) 非法包：只记录，不处置（对齐 FAS：FAIL 降级）
        if raw_payload is None or len(raw_payload) == 0:
            return Decision(PASS, SCENE_PASS, "无载荷，跳过审计", action="none")
        if parsed is None or not getattr(parsed, "ok", False):
            err = getattr(parsed, "error", "解析失败") if parsed is not None else "解析失败"
            return Decision(WARN, SCENE_BAD_PACKET,
                            "非法包（%s），仅留证不处置" % err, action="record", confidence=0.0)

        pkt_cs = normalize_callsign(parsed.callsign)
        pkt_uid = normalize_uid(parsed.uid)

        # 2) 连接侧完全没有身份：无法比对，只记录（对齐 FAS 原行为，但明确提示链路问题）
        if not conn_cs and not conn_u:
            self._attr_missing_streak += 1
            hint = ""
            if self._attr_missing_streak >= 10:
                hint = "（连续 %d 次，疑似 EMQX 未把 SAS 的 client_attrs 下发到连接，请检查认证配置）" % self._attr_missing_streak
            return Decision(WARN, SCENE_BOTH_MISSING,
                            "连接无身份属性，无法比对，仅留证%s" % hint,
                            action="record", confidence=0.2)
        self._attr_missing_streak = 0

        # 3) 连接侧只有一半身份（FAS 原实现会在这里误判 KICK —— 缺陷2）
        #    只拿到 uid 没有 callsign 时无法做呼号比对，绝不据此封人
        if not conn_cs or not conn_u:
            v = str(self.cfg.get("partial_attr_verdict", WARN)).lower()
            verdict = KICK if v == "kick" else WARN
            return Decision(verdict, SCENE_ATTR_MISSING,
                            "连接身份不完整（callsign=%r uid=%r），无法完成比对" % (conn_cs or None, conn_u or None),
                            action="record", confidence=0.4)

        # 4) 呼号比对
        cs_ok = bool(pkt_cs) and pkt_cs == conn_cs

        # 5) UID 比对（缺陷1：不一致不再直接 KICK，按策略降级）
        uid_ok = bool(pkt_uid) and pkt_uid == conn_u
        uid_known = bool(pkt_uid) and bool(conn_u)

        if cs_ok and (uid_ok or not uid_known):
            scene = SCENE_PASS if uid_ok else SCENE_PASS
            note = "身份一致（呼号=%s UID=%s）" % (conn_cs, conn_u) if uid_ok else \
                   "呼号一致，UID 缺失无法比对（呼号=%s）" % conn_cs
            return Decision(PASS, scene, note, action="none", confidence=1.0 if uid_ok else 0.8)

        if cs_ok and uid_known and not uid_ok:
            # 呼号对得上、UID 对不上 —— 最常见的误封来源
            sc, sc_msg = self.sas_check(conn_cs, pkt_uid)
            v = str(self.cfg.get("uid_mismatch_verdict", WARN)).lower()
            verdict = KICK if v == "kick" else WARN
            reason = ("呼号一致但 UID 不一致：包头 %s / 连接 %s；%s" % (pkt_uid, conn_u, sc_msg))
            # SAS 交叉校验：包头 uid 与签发记录一致 → 极可能是设备端用了新的 uid → 只告警
            if sc == "uid_diff" or sc == "ok" or sc == "unknown" or sc == "unavailable":
                verdict = WARN if v != "kick" else KICK
            conf = 0.5 if sc in ("uid_diff", "unknown") else 0.3
            if sc == "revoked":
                verdict, conf = KICK, 0.9
            d = Decision(verdict, SCENE_UID_MISMATCH, reason, action="record", confidence=conf)
            return self._maybe_ban(d, conn_cs, conn_u, pkt_cs, pkt_uid, sc)

        # 6) 呼号不符 → 明确伪造
        sc, sc_msg = self.sas_check(conn_cs, pkt_uid)
        if sc == "unknown":
            reason = ("包头呼号 %s ≠ 连接呼号 %s；且 %s" % (pkt_cs, conn_cs, sc_msg))
            d = Decision(KICK, SCENE_SAS_UNKNOWN, reason, action="record", confidence=0.95)
        elif sc == "revoked":
            d = Decision(KICK, SCENE_SAS_UNKNOWN,
                         "连接呼号 %s 的证书已吊销（%s）" % (conn_cs, sc_msg),
                         action="record", confidence=0.95)
        elif sc == "unavailable":
            # SAS 库读不到/还是空库：呼号不符这件事本身仍可疑，但**不能算伪造证据**
            reason = ("包头呼号 %s ≠ 连接呼号 %s；%s" % (pkt_cs, conn_cs, sc_msg))
            d = Decision(WARN, SCENE_SAS_UNAVAILABLE, reason, action="record", confidence=0.5)
        else:
            reason = ("包头呼号 %s ≠ 连接呼号 %s（%s）" % (pkt_cs, conn_cs, sc_msg))
            d = Decision(KICK, SCENE_FORGED, reason, action="record", confidence=0.9)
        return self._maybe_ban(d, conn_cs, conn_u, pkt_cs, pkt_uid, sc)

    # ---------------- 动作：是否真的封 ----------------
    def _maybe_ban(self, decision, conn_cs, conn_u, pkt_cs, pkt_uid, sas_status):
        mode = self.mode()
        if decision.verdict != KICK:
            decision.action = "record"
            return decision

        # 以下任一条件不满足 → 只告警留证，不封人
        if mode != MODE_BAN:
            decision.action = "record"
            decision.reason += "；当前为 %s 模式，仅留证不封禁" % mode
            return decision
        if not self.cfg.get("auto_ban", False):
            decision.action = "record"
            decision.reason += "；auto_ban 未开启，仅留证"
            return decision
        if self.in_whitelist(conn_cs):
            decision.action = "record"
            decision.reason += "；%s 在白名单内，不封禁" % conn_cs
            return decision
        if not self._ban_rate_ok():
            decision.action = "record"
            decision.reason += "；触发自动封禁限流（每小时上限 %s），本次仅留证" % \
                               self.cfg.get("ban_rate_limit_per_hour")
            return decision
        if sas_status == "unavailable" and not self.cfg.get("ban_when_sas_unavailable", False):
            decision.action = "record"
            decision.reason += "；SAS 库不可用，无法确认身份，不封禁"
            return decision

        # 真正执行拉黑
        if self.ban_recorder is None:
            decision.action = "record"
            decision.reason += "；未提供 ban_recorder，未执行封禁"
            return decision
        try:
            hours = self.cfg.get("ban_hours")
            okk = self.ban_recorder(conn_cs, decision.reason, hours)
            if okk:
                decision.ban = True
                decision.action = "ban"
                self._mark_ban()
            else:
                decision.action = "record"
                decision.reason += "；EMQX 拉黑调用失败"
        except Exception as e:  # noqa: BLE001
            decision.action = "record"
            decision.reason += "；EMQX 拉黑异常: %s" % e
        return decision


# ---------------- 兼容：把决策写回 FAS 的 verdict 字符串 ----------------
def verdict_to_fas_verdict(decision_verdict):
    """PASS/WARN/KICK 与 FAS 一致，便于审计界面与历史数据兼容。"""
    return decision_verdict if decision_verdict in (PASS, WARN, KICK) else WARN
