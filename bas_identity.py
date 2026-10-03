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
    # 同一 uid 出现在多个在线连接时的判决：warn（默认，安全）/ kick（严格）
    # ⚠️ 多设备/多开用同一个 uid 是**正常现象**（实测：同一用户 3 个 clientid
    #    FMO-BH6BHG-1075-FB08/B373/8F43 被旧默认判成"重复登录"永久封禁）。
    #    所以只有"同一 uid 对应**不同呼号**"才算可疑，且默认只告警不封人。
    "dup_uid_verdict": WARN,
    # ---------------- 「只许本 APP 上来」策略（按现场要求新增）----------------
    # 判定"来自本 APP"的两个条件（都满足才算）：
    #   1) clientid 命中 app_clientid_prefixes（默认 FMO-，APP 的 clientid 形如
    #      FMO-BH6BHG-1075-B373）
    #   2) 带 SAS 认证下发的 client_attrs.callsign/uid（= 持有本系统签发的证书；
    #      clientid 可以伪造，证书不能）
    # 满足条件 → 即使同 uid 多连接（多设备/多开）也**一律放行**；
    # 不满足 → 按 app_only_verdict 处置（off/warn/ban）。
    "app_only_verdict": "ban",
    "app_clientid_prefixes": ["FMO-"],
    # 内部客户端前缀：监控/网页面板等，不受"只许本 APP"限制
    "app_exempt_prefixes": ["FMO-MONITOR", "fmo-web-", "fmo-web"],
    # 是否要求必须有 client_attrs（即通过 SAS 证书认证）才算本 APP
    "app_require_attrs": True,
    # 是否强制要求「APP 密钥签名」验证通过（client_attrs.app_verified == "1"）。
    # ⚠️ 建议**保持 False**：用 FMO 固件登录的用户没有 APP 私钥，永远签不出签名。
    #    现场要求：固件通道必须一直保留。一旦置 True，固件用户会被判为非本 APP。
    "app_require_signature": False,
    # 「仅证书客户端」是否视为合法（默认 True）：
    #   有 SAS 证书身份但**没有** APP 签名 → 判定为 FMO 固件/仅证书客户端，
    #   绝不因"没有 APP 签名"而封禁。置 False 才会把它们当非本 APP。
    "app_allow_certonly": True,
    # 连续 N 轮确认才处置（防抖：重连瞬间会有短暂的无属性状态）
    "app_confirm_rounds": 2,
    # 拉黑时长（小时）；None = 永久。默认 24 小时 —— 误封可自愈，不再出现 infinity
    "ban_hours": 24,
    # ---------------- 假证书 / 认证失败的反滥用（现场要求：假证书要封）----------------
    # 原则：**绝不按"客户端自称的呼号"封禁** —— 攻击者可以拿别人的呼号配假证书，
    #       按呼号封等于帮他栽赃（把无辜用户封掉）。因此封的是：
    #         ① 发起连接的 clientid（精确到那个客户端）
    #         ② 反复尝试的 peerhost（IP），到阈值才封，且短时
    #       呼号只用于**留证**，用于事后人工处理。
    "fake_cert_ban_clientid": True,     # 假证书 → 封该 clientid
    "fake_cert_callsign_ban": False,    # 是否按呼号封（默认关，防栽赃；慎开）
    "fake_cert_ip_ban_after": 10,       # 同一 IP 在窗口内失败多少次后封 IP
    "fake_cert_window_sec": 300,        # 统计窗口（秒）
    "fake_cert_ip_ban_hours": 1,        # 封 IP 时长（小时，短时可自愈）
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

    # ---------------- 「只许本 APP 上来」判定 ----------------
    def _prefix_hit(self, clientid, key):
        cid = str(clientid or "")
        for p in (self.cfg.get(key) or []):
            if p and cid.startswith(str(p)):
                return True
        return False

    def client_is_app(self, client):
        """
        判断一个在线连接是否"来自本 APP"。

        必须同时满足（app_require_attrs 为 True 时）：
          1) clientid 命中 app_clientid_prefixes（默认 FMO-）
          2) 带 SAS 认证下发的 client_attrs.callsign 与 uid
             —— clientid 谁都能伪造，**证书不能**，所以这一条是关键证据
        命中 app_exempt_prefixes 的内部客户端（监控/网页面板）直接视为放行。

        返回 (是否本APP, 是否豁免, 原因)
        """
        cid = str((client or {}).get("clientid") or "")
        attrs = (client or {}).get("client_attrs") or {}
        if not isinstance(attrs, dict):
            attrs = {}
        cs = normalize_callsign(attrs.get("callsign"))
        uid = normalize_uid(attrs.get("uid"))
        app_verified = str(attrs.get("app_verified") or "")
        app_sig = str(attrs.get("app_sig") or "")

        if self._prefix_hit(cid, "app_exempt_prefixes"):
            return False, True, "内部客户端（豁免）: %s" % cid

        # 最强证据：APP 私钥签名校验通过（client_attrs 由 SAS 验签后写入，
        # 客户端伪造不出来）。签名绑定了 clientid 与用户证书公钥。
        if app_verified == "1":
            return True, False, "本 APP（APP 密钥签名已验证: %s, clientid=%s）" % (
                app_sig or "ok", cid)

        # 要求强制签名时：没有有效签名就不算本 APP
        if self.cfg.get("app_require_signature"):
            return False, False, "未通过 APP 密钥签名（app_verified=%s, app_sig=%s）: %s" % (
                app_verified or "无", app_sig or "none", cid or "(空)")

        # 回退（兼容固件与尚未改造的 APP）：前缀 + SAS 证书身份
        # 注意：**没有 APP 签名不等于非法** —— FMO 固件用户就是这种情况，
        # 它的通道必须一直保留，绝不能因"签不出 APP 签名"而被判非本 APP / 被封。
        certonly = bool(cs and uid)
        if self.cfg.get("app_allow_certonly", True) and certonly:
            if not self._prefix_hit(cid, "app_clientid_prefixes"):
                # 仅证书但 clientid 不是 APP 形态：多为固件/其它客户端，仍放行并标注
                return True, False, "仅证书客户端（非 APP 形态 clientid=%s 身份=%s/%s）" % (
                    cid or "(空)", cs, uid)
            return True, False, "仅证书客户端（FMO 固件或未带 APP 签名；身份=%s/%s）" % (cs, uid)
        if self.cfg.get("app_require_signature"):
            return False, False, "未通过 APP 密钥签名（app_verified=%s, app_sig=%s）: %s" % (
                app_verified or "无", app_sig or "none", cid or "(空)")
        if not self._prefix_hit(cid, "app_clientid_prefixes"):
            return False, False, "clientid 不是 APP 形态: %s" % (cid or "(空)")
        if self.cfg.get("app_require_attrs", True) and not (cs and uid):
            return False, False, "没有 SAS 证书身份（client_attrs 为空）: %s" % cid
        return True, False, "本 APP（clientid=%s 证书身份=%s/%s）" % (cid, cs or "-", uid or "-")

    def app_only_verdict(self):
        v = str(self.cfg.get("app_only_verdict", "off")).lower()
        return v if v in ("off", "warn", "ban") else "warn"

    # ---------------- 主判决 ----------------
    def decide(self, raw_payload, parsed, conn_callsign, conn_uid, client_id=None,
               degraded=False):
        """
        raw_payload : bytes|None（webhook 解出的原始载荷）
        parsed      : bas_fmo_parser.ParseResult | None（解析失败传 None/ok=False）
        conn_callsign/conn_uid : 连接身份（优先来自 client_attrs；缺失时可能是降级来源）
        degraded    : True 表示连接身份不是来自 client_attrs（如 username/clientid 兜底）。
                      **降级身份只能用于核对与留证，绝不作为封人依据。**
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

        # 2) 连接侧完全没有身份：无法比对 → 只记录包内声明身份（便于事后取证/申诉）
        if not conn_cs and not conn_u:
            self._attr_missing_streak += 1
            hint = ""
            if self._attr_missing_streak >= 10:
                hint = ("（连续 %d 次，疑似 EMQX 未把 SAS 的 client_attrs 下发到连接，"
                        "请检查认证配置）" % self._attr_missing_streak)
            who = pkt_cs or "未知"
            return Decision(WARN, SCENE_BOTH_MISSING,
                            "连接无身份属性，无法比对；包内声明 %s(UID %s) 仅留证%s" % (
                                who, pkt_uid or "-", hint),
                            action="record", confidence=0.2)
        self._attr_missing_streak = 0

        # 3) 连接侧只有一半身份
        #    FAS 原实现会在这里直接 KICK（缺陷2）。更常见的情形是：
        #    EMQX 没下发 client_attrs，我们用 username/clientid 兜底 → 只有呼号没有 uid。
        #    此时**仍必须用呼号核对**，否则统计/排行榜里永远看不到这个人（现场现象）。
        if not conn_cs or not conn_u:
            if conn_cs and pkt_cs:
                if pkt_cs == conn_cs:
                    note = "呼号一致（%s），UID 缺失无法比对" % conn_cs
                    if degraded:
                        note += "；连接身份来自降级来源（EMQX 未下发 client_attrs）"
                    return Decision(PASS, SCENE_PASS, note, action="none",
                                    confidence=0.5 if degraded else 0.7)
                sc, sc_msg = self.sas_check(conn_cs, pkt_uid)
                v = str(self.cfg.get("partial_attr_verdict", WARN)).lower()
                verdict = KICK if (v == "kick" and not degraded) else WARN
                reason = ("连接身份不完整（callsign=%s uid 缺失），且包头呼号 %s 与之不符；%s"
                          % (conn_cs, pkt_cs, sc_msg))
                if degraded:
                    reason += "；连接身份来自降级来源（EMQX 未下发 client_attrs），仅留证不封禁"
                d = Decision(verdict, SCENE_ATTR_MISSING, reason,
                             action="record", confidence=0.4)
                return self._maybe_ban(d, conn_cs, conn_u, pkt_cs, pkt_uid, sc, degraded)
            v = str(self.cfg.get("partial_attr_verdict", WARN)).lower()
            verdict = KICK if (v == "kick" and not degraded) else WARN
            return Decision(verdict, SCENE_ATTR_MISSING,
                            "连接身份不完整（callsign=%r uid=%r），无法完成比对" % (
                                conn_cs or None, conn_u or None),
                            action="record", confidence=0.4)

        # 4) 呼号比对
        cs_ok = bool(pkt_cs) and pkt_cs == conn_cs

        # 5) UID 比对（缺陷1：不一致不再直接 KICK，按策略降级）
        uid_ok = bool(pkt_uid) and pkt_uid == conn_u
        uid_known = bool(pkt_uid) and bool(conn_u)

        if cs_ok and (uid_ok or not uid_known):
            note = "身份一致（呼号=%s UID=%s）" % (conn_cs, conn_u) if uid_ok else \
                   "呼号一致，UID 缺失无法比对（呼号=%s）" % conn_cs
            if degraded:
                note += "；注意：连接身份来自降级来源（EMQX 未下发 client_attrs）"
            return Decision(PASS, SCENE_PASS, note, action="none",
                            confidence=0.6 if degraded else (1.0 if uid_ok else 0.8))

        if cs_ok and uid_known and not uid_ok:
            # 呼号对得上、UID 对不上 —— 最常见的误封来源
            sc, sc_msg = self.sas_check(conn_cs, pkt_uid)
            v = str(self.cfg.get("uid_mismatch_verdict", WARN)).lower()
            verdict = KICK if v == "kick" else WARN
            reason = "呼号一致但 UID 不一致：包头 %s / 连接 %s；%s" % (pkt_uid, conn_u, sc_msg)
            conf = 0.5 if sc in ("uid_diff", "unknown") else 0.3
            if sc == "revoked":
                verdict, conf = KICK, 0.9
            if degraded:
                # 降级身份不可信，不允许判成 KICK
                verdict, conf = WARN, min(conf, 0.35)
                reason += "；连接身份来自降级来源，不作为封禁依据"
            d = Decision(verdict, SCENE_UID_MISMATCH, reason, action="record", confidence=conf)
            return self._maybe_ban(d, conn_cs, conn_u, pkt_cs, pkt_uid, sc, degraded)

        # 6) 呼号不符 → 明确伪造（降级身份时只告警）
        sc, sc_msg = self.sas_check(conn_cs, pkt_uid)
        if sc == "unknown":
            reason = "包头呼号 %s ≠ 连接呼号 %s；且 %s" % (pkt_cs, conn_cs, sc_msg)
            d = Decision(KICK, SCENE_SAS_UNKNOWN, reason, action="record", confidence=0.95)
        elif sc == "revoked":
            d = Decision(KICK, SCENE_SAS_UNKNOWN,
                         "连接呼号 %s 的证书已吊销（%s）" % (conn_cs, sc_msg),
                         action="record", confidence=0.95)
        elif sc == "unavailable":
            reason = "包头呼号 %s ≠ 连接呼号 %s；%s" % (pkt_cs, conn_cs, sc_msg)
            d = Decision(WARN, SCENE_SAS_UNAVAILABLE, reason, action="record", confidence=0.5)
        else:
            reason = "包头呼号 %s ≠ 连接呼号 %s（%s）" % (pkt_cs, conn_cs, sc_msg)
            d = Decision(KICK, SCENE_FORGED, reason, action="record", confidence=0.9)
        if degraded:
            d.verdict = WARN
            d.confidence = min(d.confidence, 0.4)
            d.reason += "；连接身份来自降级来源（EMQX 未下发 client_attrs），仅留证不封禁"
        return self._maybe_ban(d, conn_cs, conn_u, pkt_cs, pkt_uid, sc, degraded)

    # ---------------- 动作：是否真的封 ----------------
    def _maybe_ban(self, decision, conn_cs, conn_u, pkt_cs, pkt_uid, sas_status,
                   degraded=False):
        mode = self.mode()
        if decision.verdict != KICK:
            decision.action = "record"
            return decision

        # 降级身份（EMQX 未下发 client_attrs，身份来自 username/clientid 兜底）绝不可封人
        if degraded:
            decision.action = "record"
            decision.reason += "；连接身份为降级来源，禁止自动封禁"
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
