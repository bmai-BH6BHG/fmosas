#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · 审计服务（把 FAS 的 TopicIngestService + CollectorService + 判定链 融进分系统进程）

职责：
  1. webhook 接入（EMQX 规则引擎 → /api/ingest）
     - X-Ingest-Token 固定时间比较（对齐上游）
     - 解析 client_attrs（顶层对象，callsign/uid；uid 可能是 number，必须归一）
     - 逐包解析 64 字节包头 → bas_identity 判决 → 动作（留证 / 入待审 / 自动拉黑）
     - 10 秒桶聚合写入 topic_stats
  2. 轮询采集（EMQX REST）
     - 在线客户端全量（自动翻页）→ 每分钟统计 minute_stats（新 clientid 首轮只建基线）
     - 重复身份（同 uid 多连接）检测：连续 3 轮确认后才处置（避免重连风暴误封）
     - 健康快照（宿主机 + EMQX）→ health_snapshots，并按上游语义挂在采集成功路径内做清理
  3. 供给 Web 界面：在线列表、排行榜、主题统计、黑名单、审计事件、待审队列、健康

与上游的差异（都是修正，不是行为走样）：
  * 判决交给 bas_identity 策略引擎（可配置 warn/ban、UID 不符降级、白名单、限流）
  * 低置信度事件进 bas_quarantine 待审队列，而不是直接封人
  * 采集失败时仍按时间间隔做清理（上游失败即跳过清理）
  * topic_stats 写入使用 10 秒对齐键；失败不丢缓冲（上游先清缓冲后写库会永久丢数）
"""

import base64
import json
import re
import threading
import time

import bas_fmo_parser as parser_mod
from bas_identity import IdentityPolicy, PASS, WARN, KICK, DEFAULT_POLICY
from bas_emqx import EmqxClient, EmqxError, EmqxPoller, get_lan_ip
from bas_audit_db import AuditDB, now_text, ts10

COLLECT_INTERVAL = 60          # 采集周期（秒），对齐上游 1 分钟
HEALTH_INTERVAL = 60           # 健康快照周期
CLEAN_INTERVAL = 600           # 清理最小间隔（秒），上游 10 分钟
FAIL_RATE_LIMIT = 100          # FAIL 类事件每 60 秒最多落库条数（对齐上游）
DUP_UID_ROUNDS = 3             # 同 uid 多连接连续确认轮数（对齐上游）

# clientid 里带呼号的常见形态：FMO-BH8GDV-4-5817 / fmo_BH8GDV_xxx / BH8GDV-4-1234
_CALLSIGN_IN_CID = re.compile(r"(?:^|[^A-Z0-9])([A-Z]{1,2}\d[A-Z]{1,4})(?![A-Z0-9])")


def _callsign_from_clientid(clientid):
    """
    从 clientid 里提取呼号（兜底用）。实测 APP 的 clientid 形如 FMO-BH8GDV-4-5817，
    可作为 client_attrs 缺失时的降级身份来源；命中即返回大写呼号，否则空串。
    """
    if not clientid:
        return ""
    m = _CALLSIGN_IN_CID.search(str(clientid).upper())
    return m.group(1) if m else ""


class AuditService(object):
    """BAS 审计服务。线程安全的单例式对象，由 api_server 持有。"""

    def __init__(self, db, config=None, retention_days=30, auto_start=False):
        self.db = db
        self.config = config or {}
        self.retention_days = retention_days

        emqx_cfg = self._load_emqx_config()
        self.emqx = EmqxClient(emqx_cfg.get("url", ""), emqx_cfg.get("key", ""),
                               emqx_cfg.get("secret", ""))
        self.poller = EmqxPoller(self.emqx, interval=COLLECT_INTERVAL)

        # 预生成 ingest token：让设置页/EMQX 桥接在首次收数之前就能拿到
        try:
            if not self.db.get_setting("ingest_token"):
                self.db.get_ingest_token()
        except Exception:  # noqa: BLE001
            pass

        # 策略引擎：从 bas_policy 表加载，回调 SAS 交叉校验与拉黑执行
        self.sas_lookup = None          # 由 api_server 注入（查 SAS/用户库）
        self.sas_has_any = None         # 由 api_server 注入（SAS 库是否已有注册记录）
        self.policy = IdentityPolicy(policy=self._load_policy(),
                                     sas_lookup=self._sas_lookup,
                                     ban_recorder=self._ban_recorder,
                                     sas_has_any=self._sas_has_any)

        # 运行态
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads = []
        self._prev = {}                 # clientid -> 上轮计数器基线
        self._dup_uid_track = {}        # uid -> 连续轮数
        self._app_track = {}            # clientid -> 非本 APP 连续轮数
        self._fail_times = []           # FAIL 落库限流
        self._last_cleanup = 0.0
        self._last_collect = 0.0
        self._last_collect_error = None
        self._msg_rate = {"in": 0.0, "out": 0.0}
        self._prev_metrics = None
        self._prev_metrics_ts = 0.0
        self._stats = {"ingest_total": 0, "ingest_ok": 0, "audit_kick": 0, "audit_warn": 0,
                       "audit_fail": 0, "bans": 0, "quarantined": 0, "auth_rejected": 0}
        if auto_start:
            self.start()

    # ---------------- 配置 ----------------
    def _load_emqx_config(self):
        return {
            "url": self.db.get_setting("emqx_url", "") or "",
            "key": self.db.get_setting("emqx_api_key", "") or "",
            "secret": self.db.get_setting("emqx_api_secret", "") or "",
        }

    def reload_emqx(self):
        cfg = self._load_emqx_config()
        self.emqx = EmqxClient(cfg.get("url", ""), cfg.get("key", ""), cfg.get("secret", ""))
        self.poller = EmqxPoller(self.emqx, interval=COLLECT_INTERVAL)
        return cfg

    def _load_policy(self):
        """从 bas_policy 表加载策略，缺省用安全默认值（warn + 不自动封）。"""
        p = dict(DEFAULT_POLICY)
        stored = self.db.get_policy() or {}
        for k, v in stored.items():
            if k not in p or v == "":
                continue
            default = p[k]
            if isinstance(default, bool):
                p[k] = str(v).lower() in ("1", "true", "yes", "on")
            elif isinstance(default, int) and default is not None:
                try:
                    p[k] = int(v)
                except ValueError:
                    pass
            elif k == "ban_whitelist":
                p[k] = [x.strip().upper() for x in str(v).split(",") if x.strip()]
            elif k == "ban_hours":
                p[k] = None if str(v) in ("", "none", "0") else int(float(v))
            else:
                p[k] = v
        return p

    def reload_policy(self):
        self.policy.cfg.update(self._load_policy())
        return self.policy.cfg

    def set_policy(self, key, value):
        self.db.set_policy(key, value)
        return self.reload_policy()

    def policy_snapshot(self):
        p = dict(self.policy.cfg)
        p["mode"] = self.policy.mode()
        return p

    def identity_control_enabled(self):
        """对齐上游 settings.identity_control：!= "0" 即启用；再叠加 BAS 策略模式 off。"""
        raw = self.db.get_setting("identity_control", "1")
        enabled = str(raw) != "0"
        return enabled and self.policy.mode() != "off"

    # ---------------- SAS 交叉校验与拉黑执行 ----------------
    def _sas_lookup(self, callsign):
        if self.sas_lookup is None:
            raise RuntimeError("未注入 SAS 查询器")
        return self.sas_lookup(callsign)

    def _sas_has_any(self):
        """SAS 库是否已有注册记录（空库时不得据'查不到'判伪造）。"""
        if self.sas_has_any is None:
            return True     # 未注入时不阻断（保持上游语义）
        return bool(self.sas_has_any())

    def _ban_recorder(self, callsign, reason, hours):
        until = None
        if hours:
            until = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(time.time() + float(hours) * 3600))
        ok, err, kicked = self.emqx.ban_username(callsign, reason, until)
        if ok:
            self.db.add_blacklist_event("ban", callsign, reason, until or "infinity",
                                        "身份控制", "username")
            self._bump("bans")
        return bool(ok)

    def _bump(self, key, n=1):
        with self._lock:
            self._stats[key] = self._stats.get(key, 0) + n

    def stats(self):
        with self._lock:
            s = dict(self._stats)
        s["collect_last_ok"] = self._last_collect
        s["collect_last_error"] = self._last_collect_error
        s["policy"] = self.policy_snapshot()
        s["identity_control"] = self.identity_control_enabled()
        return s

    # ---------------- webhook 接入 ----------------
    def ingest(self, token, payload):
        """
        处理一次 EMQX webhook。返回 (http_code, body_dict)
        对齐上游：token 不对 → 401；非 JSON → 400；其它一律 200（避免 EMQX 重投）
        """
        expect = self.db.get_ingest_token()
        got = "" if token is None else str(token)
        import hmac
        if not expect or not hmac.compare_digest(got.encode("utf-8"), expect.encode("utf-8")):
            self._bump("auth_rejected")
            return 401, {"ok": False, "error": "invalid token"}
        if not isinstance(payload, dict):
            return 400, {"ok": False, "error": "bad content type"}
        try:
            self._handle_ingest(payload)
        except Exception as e:  # noqa: BLE001
            # 刻意返回 200：EMQX 会重投，重复计数比丢数据更糟
            return 200, {"ok": True, "warn": "ingest error: %s" % e}
        self._bump("ingest_ok")
        return 200, {"ok": True}

    def _handle_ingest(self, root):
        self._bump("ingest_total")
        topic = root.get("topic")
        clientid = root.get("clientid")
        username = root.get("username")
        if username == "undefined":       # EMQX 的 Erlang undefined atom
            username = None

        # client_attrs：顶层对象；callsign 非空时优先于 username
        attrs = root.get("client_attrs")
        callsign = None
        uid = None
        if isinstance(attrs, dict):
            cs = attrs.get("callsign")
            if isinstance(cs, str) and cs:
                callsign = cs
            if "uid" in attrs:
                v = attrs.get("uid")
                if isinstance(v, bool):
                    uid = "true" if v else "false"
                elif v is None:
                    uid = ""
                elif isinstance(v, (int, float)):
                    uid = str(v)
                else:
                    uid = str(v)
        if callsign:
            username = callsign

        raw = None
        nbytes = 0
        p = root.get("payload")
        if isinstance(p, str):
            try:
                raw = base64.b64decode(p)
                nbytes = len(raw)
            except Exception:  # noqa: BLE001
                nbytes = len(p)

        if not topic or not clientid:
            return

        # ---- 身份来源兜底（关键）----
        # client_attrs 是"可信身份"（SAS 认证写入）。但实测很多环境 EMQX 不下发它
        # （版本 <5.7、认证器 body 没配等）→ 此前会整条审计链失效。
        # 因此按可信度依次兜底，并记录来源，判决时据此降低置信度（不当作伪造证据）。
        attr_cs = callsign
        attr_uid = uid
        cs_src = "client_attrs" if callsign else ""
        uid_src = "client_attrs" if uid else ""
        if not callsign:
            if isinstance(username, str) and username and username.upper() != "UNDEFINED":
                cs_src = "username(降级)"
                callsign = username
            else:
                guess = _callsign_from_clientid(clientid)
                if guess:
                    callsign = guess
                    cs_src = "clientid(降级)"
        if not uid:
            uid_src = ""
        # 兜底身份不可信：明确标记，让策略层不据此判伪造/封人
        degraded = bool(callsign) and cs_src != "client_attrs"

        if self._stats.get("identity_sources") is None:
            self._stats["identity_sources"] = {}
        self._stats["identity_sources"][cs_src or "none"] = \
            self._stats["identity_sources"].get(cs_src or "none", 0) + 1
        if degraded:
            self._bump("degraded_identity")
        _ = (attr_cs, attr_uid, uid_src)

        # ① 主题统计（10 秒桶）
        if str(self.db.get_setting("topic_enabled", "0")) != "0":
            self.db.add_topic_stat(topic, clientid, username, callsign, uid, 1, nbytes)

        # ② 逐包身份审计
        if raw:
            self._audit_packet(raw, topic, callsign, uid, clientid, username,
                               degraded=degraded, cs_src=cs_src)

    def _audit_packet(self, raw, topic, conn_callsign, conn_uid, clientid, username,
                      degraded=False, cs_src=""):
        parsed = parser_mod.parse(raw)
        if not self.identity_control_enabled():
            return

        decision = self.policy.decide(raw, parsed, conn_callsign, conn_uid, clientid,
                                      degraded=degraded)
        # 兜底来源要写进原因，便于事后审计
        if cs_src and cs_src != "client_attrs":
            decision.reason = "%s；连接身份来源=%s（EMQX 未下发 client_attrs）" % (
                decision.reason, cs_src)

        # 判决计数
        if decision.verdict == KICK:
            self._bump("audit_kick")
        elif decision.verdict == WARN:
            self._bump("audit_warn")
        if decision.scene == "bad_packet":
            self._bump("audit_fail")

        # PASS 不落库（对齐上游）；FAIL 限流（60 秒 100 条）
        if decision.verdict == PASS:
            return
        if not self.policy.allow_audit_write():
            return

        pkt_cs = ""
        pkt_uid = ""
        if parsed is not None and getattr(parsed, "ok", False):
            pkt_cs = parsed.callsign
            pkt_uid = str(parsed.uid)

        self.db.write_audit_packet({
            "ts": now_text(True), "topic": topic, "clientid": clientid,
            "conn_callsign": conn_callsign, "conn_uid": conn_uid,
            "pkt_callsign": pkt_cs, "pkt_uid": pkt_uid,
            "verdict": decision.verdict, "scene": decision.scene,
            "reason": decision.reason, "confidence": decision.confidence,
            "len": getattr(parsed, "len", 0) if parsed else 0,
            "frame_num": getattr(parsed, "frame_num", 0) if parsed else 0,
            "crc_ok": bool(getattr(parsed, "crc_ok", False)) if parsed else False,
            "smeter": getattr(parsed, "smeter", 0) if parsed else 0,
            "srv_uid": str(getattr(parsed, "srv_uid", "")) if parsed else "",
            "pkt_ts": str(getattr(parsed, "timestamp", "")) if parsed else "",
            "stream_begin": str(getattr(parsed, "stream_begin_utc", "")) if parsed else "",
            "ban": decision.ban, "source": "packet",
        })

        # 可疑事件进待审队列（误封救援的关键）：
        #   * 判 KICK 但没真封 → 必须进待审
        #   * 判 WARN 的伪造/UID 不符/未知呼号 → 也进待审（否则降级身份下的可疑事件没人能看到）
        suspicious_scenes = ("forged", "uid_mismatch", "sas_unknown", "non_app_client",
                             "attr_missing", "dup_identity")
        if (not decision.ban) and (decision.verdict == KICK
                                   or decision.scene in suspicious_scenes):
            self.db.add_quarantine({
                "created_at": now_text(True),
                "conn_callsign": conn_callsign, "conn_uid": conn_uid,
                "pkt_callsign": pkt_cs, "pkt_uid": pkt_uid, "clientid": clientid,
                "scene": decision.scene, "reason": decision.reason,
                "confidence": decision.confidence, "status": "pending",
            })
            self._bump("quarantined")

    # ---------------- 采集（在线/统计/重复身份/健康） ----------------
    def collect_once(self):
        """
        一轮采集。返回 (ok, error)。
        新 clientid 首轮只建基线不落库（对齐上游：避免把连接以来的累计灌进第一分钟）。
        """
        try:
            clients = self.emqx.list_clients()
        except EmqxError as e:
            self._last_collect_error = str(e)
            return False, str(e)

        now = time.time()
        ts = now_text()
        bucket = ts10(ts)

        for c in clients:
            cid = c.get("clientid") or ""
            if not cid:
                continue
            prev = self._prev.get(cid)
            if prev is None:
                # 首次出现：只建基线
                self._prev[cid] = c
                continue
            delta = {}
            reconnect = 0
            for k in ("recv_msg", "send_msg", "recv_pkt", "send_pkt", "recv_oct", "send_oct"):
                d = int(c.get(k) or 0) - int(prev.get(k) or 0)
                if d < 0:
                    d = 0
                    if k == "send_pkt":
                        reconnect = 1        # 对齐上游：仅 send_pkt 负差分标记重连
                delta[k] = d
            self._prev[cid] = c
            self.db.upsert_minute_stat({
                "clientid": cid, "ts": bucket, "username": c.get("username"),
                "callsign": c.get("callsign"), "uid": c.get("uid"),
                "ip_address": c.get("ip_address"), "reconnect": reconnect,
                **delta
            })

        # 掉线的 clientid 清掉基线
        live = {c.get("clientid") for c in clients}
        for cid in list(self._prev.keys()):
            if cid not in live:
                self._prev.pop(cid, None)

        # 重复身份检测（同 uid 多连接）
        # 规则：**来自本 APP 的连接（有 SAS 证书身份）即使同 uid 多连接也放行**；
        #       同 uid 里有非本 APP 的连接 → 按下面「只许本 APP」规则处置。
        self._detect_duplicate_identity(clients)

        # 「只许本 APP 上来」：不是本 APP 的连接（无证书身份 / clientid 非 APP 形态）
        # 连续确认后按 app_only_verdict 处置（默认 ban）。
        self._enforce_app_only(clients)

        # 健康快照 + 清理（清理挂在采集成功路径内，但按时间间隔独立触发）
        self._write_health()
        if now - self._last_cleanup > CLEAN_INTERVAL:
            try:
                self.db.cleanup(self.retention_days)
            except Exception as e:  # noqa: BLE001
                self._last_collect_error = "cleanup: %s" % e
            self._last_cleanup = now

        self._last_collect = now
        self._last_collect_error = None
        return True, None

    def _enforce_app_only(self, clients):
        """
        只许本 APP 上来。

        本 APP 的判定见 IdentityPolicy.client_is_app：
          clientid 命中 FMO- 前缀 **且** 带 SAS 证书下发的 client_attrs(callsign/uid)。
        不是本 APP 的连接（含"伪造成 FMO- 形态但没有证书身份"的冒充者）：
          连续 app_confirm_rounds 轮确认后，按 app_only_verdict 处置（默认 ban）。
        内部客户端（FMO-MONITOR / fmo-web-*）豁免。
        """
        verdict_cfg = self.policy.app_only_verdict()
        if verdict_cfg == "off":
            self._app_track.clear()
            return
        rounds_need = max(1, int(self.policy.cfg.get("app_confirm_rounds", 2) or 2))
        seen = set()
        for c in clients:
            cid = str(c.get("clientid") or "")
            if not cid:
                continue
            is_app, exempt, why = self.policy.client_is_app(c)
            if is_app or exempt:
                self._app_track.pop(cid, None)
                continue
            seen.add(cid)
            n = self._app_track.get(cid, 0) + 1
            self._app_track[cid] = n
            if n < rounds_need:
                continue
            self._app_track[cid] = 0
            who = (c.get("username") or (c.get("client_attrs") or {}).get("callsign")
                   or cid)
            reason = "非本 APP 客户端（%s）；按策略处置" % why
            self.db.write_audit_packet({
                "ts": now_text(True), "topic": "", "clientid": cid,
                "conn_callsign": str(who), "conn_uid": str(
                    (c.get("client_attrs") or {}).get("uid") or ""),
                "verdict": KICK if verdict_cfg == "ban" else WARN,
                "scene": "non_app_client", "reason": reason,
                "confidence": 0.8, "source": "collector",
            })
            if verdict_cfg == "ban" and not self.policy.in_whitelist(who):
                try:
                    kicked = self.policy.ban_recorder(
                        who, reason, self.policy.cfg.get("ban_hours"))
                    if kicked:
                        self._bump("banned")
                except Exception as e:  # noqa: BLE001
                    self._last_collect_error = "app_only ban: %s" % e
            else:
                self.db.add_quarantine({
                    "created_at": now_text(True), "conn_callsign": str(who),
                    "scene": "non_app_client", "reason": reason,
                    "confidence": 0.8,
                })
                self._bump("quarantined")
        for cid in list(self._app_track.keys()):
            if cid not in seen:
                self._app_track.pop(cid, None)

    def _detect_duplicate_identity(self, clients):
        """
        同一 uid 出现在多个在线连接。

        ⚠️ 重要：**多设备/多开用同一个 uid 是正常的**。
        实测事故：同一用户 3 个 clientid（FMO-BH6BHG-1075-FB08/B373/8F43）同 uid=1075，
        被旧逻辑判成"UID 重复登录"→ 直接 until=infinity 永久封禁，导致用户登不上，
        而解锁界面读的是自己的黑名单表、看不到 EMQX 里这条封禁 → 无从解锁。

        因此现在的判定规则（可配置）：
          * 同一 uid + **同一个呼号** 的多个连接 → 视为正常多设备，只记一条 WARN，不封、不入待审
          * 同一 uid 对应**不同呼号** → 疑似凭证共享/伪造，按 dup_uid_verdict（默认 warn）处置
          * 只有显式把 dup_uid_verdict 配成 kick/ban 且 mode=ban+auto_ban 时才会真的封
        """
        by_uid = {}
        for c in clients:
            u = c.get("uid") or ""
            if not u:
                continue
            by_uid.setdefault(u, []).append(c)
        seen = set()
        for uid, rows in by_uid.items():
            if len(rows) < 2:
                continue
            seen.add(uid)
            names = sorted({(r.get("callsign") or r.get("username") or "") for r in rows} - {""})
            # 本 APP 判定：有 SAS 证书身份的连接才算"本 APP"
            app_flags = [self.policy.client_is_app(r)[0] for r in rows]
            all_app = all(app_flags)
            # 全部都是本 APP → 无论 uid 是否相同、连接有多少个，**一律放行**
            # （现场要求：APP 上来的即使 UID 一样也允许登录）
            if all_app:
                if len(rows) >= 3:
                    self.db.write_audit_packet({
                        "ts": now_text(True), "topic": "",
                        "clientid": ",".join(r.get("clientid", "") for r in rows),
                        "conn_callsign": ",".join(names), "conn_uid": uid,
                        "verdict": PASS, "scene": "dup_identity",
                        "reason": "本 APP 多设备在线（%d 个连接）—— 放行" % len(rows),
                        "confidence": 0.0, "source": "collector",
                    })
                self._dup_uid_track[uid] = 0
                continue
            # 同 uid 只对应一个呼号 → 多设备正常行为，不升级处置
            suspicious = len(names) > 1
            if not suspicious and len(rows) < 4:
                # 记录一次（便于统计多开），但明确标注为正常
                self._dup_uid_track[uid] = 0
                continue
            n = self._dup_uid_track.get(uid, 0) + 1
            self._dup_uid_track[uid] = n
            if n < DUP_UID_ROUNDS:
                continue
            cids = ",".join(r.get("clientid", "") for r in rows)
            if not suspicious:
                reason = ("同一呼号 %s 多设备在线（%d 个连接：%s）—— 正常多开，仅记录"
                          % (",".join(names), len(rows), cids))
                verdict, conf = WARN, 0.2
            else:
                reason = ("同一 uid=%s 对应多个呼号（%s），疑似凭证共享/伪造（连接 %s）"
                          % (uid, ",".join(names), cids))
                verdict, conf = WARN, 0.7
            self.db.write_audit_packet({
                "ts": now_text(True), "topic": "",
                "clientid": cids,
                "conn_callsign": ",".join(names), "conn_uid": uid,
                "verdict": verdict, "scene": "dup_identity", "reason": reason,
                "confidence": conf, "source": "collector",
            })
            # 只有"不同呼号共用 uid"且策略显式要求时才封；同呼号多开永不封
            want_ban = (suspicious
                        and str(self.policy.cfg.get("dup_uid_verdict", WARN)).lower() in ("ban", "kick")
                        and self.policy.mode() == "ban"
                        and self.policy.cfg.get("auto_ban"))
            if want_ban:
                for nm in names:
                    if self.policy.in_whitelist(nm):
                        continue
                    self._ban_recorder(nm, reason, self.policy.cfg.get("ban_hours"))
            elif suspicious:
                self.db.add_quarantine({
                    "created_at": now_text(True), "conn_callsign": ",".join(names),
                    "conn_uid": uid, "scene": "dup_identity", "reason": reason,
                    "confidence": conf,
                })
                self._bump("quarantined")
            self._dup_uid_track[uid] = 0
        for uid in list(self._dup_uid_track.keys()):
            if uid not in seen:
                self._dup_uid_track.pop(uid, None)

    def _write_health(self):
        health = self.emqx.node_health()
        metrics = health.get("metrics") or {}
        now = time.time()
        rate_in = rate_out = 0.0
        if self._prev_metrics is not None and now > self._prev_metrics_ts:
            dt = now - self._prev_metrics_ts
            rate_in = max(0.0, (int(metrics.get("messages.received") or 0)
                                - int(self._prev_metrics.get("messages.received") or 0)) / dt)
            rate_out = max(0.0, (int(metrics.get("messages.sent") or 0)
                                 - int(self._prev_metrics.get("messages.sent") or 0)) / dt)
        self._prev_metrics = dict(metrics)
        self._prev_metrics_ts = now
        self._msg_rate = {"in": round(rate_in, 2), "out": round(rate_out, 2)}

        host = read_host_health()
        self.db.add_health_snapshot({
            "ts": now_text(),
            **host,
            "emqx_nodes": health.get("nodes", 0),
            "emqx_alive": health.get("alive", 0),
            "emqx_conns": health.get("connections", 0),
            "emqx_cpu_pct": host.get("_emqx_load1"),     # 上游语义：EMQX 5.x 无 CPU%，用 load1
            "emqx_mem_used": _parse_mem(metrics.get("memory.used") or metrics.get("memory_used")),
            "emqx_mem_total": _parse_mem(metrics.get("memory.total") or metrics.get("memory_total")),
            "emqx_alarms": health.get("alarms", ""),
            "msg_rate_in": rate_in,
            "msg_rate_out": rate_out,
        })

    # ---------------- 后台线程 ----------------
    def start(self):
        if self._threads:
            return
        t = threading.Thread(target=self._loop, name="BAS-Collector", daemon=True)
        t.start()
        self._threads.append(t)

    def _loop(self):
        # 先探一次 EMQX，避免启动即报错刷屏
        time.sleep(2)
        while not self._stop.is_set():
            try:
                self.collect_once()
            except Exception as e:  # noqa: BLE001
                self._last_collect_error = str(e)
            self._stop.wait(COLLECT_INTERVAL)

    def stop(self):
        self._stop.set()

    # ---------------- 查询接口（供 Web 层） ----------------
    def online_clients(self):
        snap = self.poller.snapshot()
        clients = snap["clients"]
        if not clients:
            # 轮询器还没数据时直接查一次（页面首次打开也不空）
            try:
                clients = self.emqx.list_clients()
                self.poller._clients = clients            # noqa: SLF001
            except EmqxError:
                clients = []
        now = time.time()
        out = []
        for c in clients:
            connected_at = c.get("connected_at") or ""
            uptime = 0
            out.append({
                **c,
                "uptime_sec": uptime,
                "connected_at_text": connected_at,
            })
        _ = now
        return out

    def emqx_status(self):
        ok, why = self.emqx.ping()
        cfg = self._load_emqx_config()
        return {
            "configured": bool(cfg.get("url") and cfg.get("key")),
            "url": cfg.get("url", ""),
            "reachable": ok, "detail": why,
            "version": self.emqx.version() if ok else "",
            "supported": self.emqx.is_supported_version() if ok else False,
            "last_collect": self._last_collect,
            "last_error": self._last_collect_error,
            "online": self.poller.online_count(),
            "msg_rate": dict(self._msg_rate),
        }

    def configure_emqx(self, url, key, secret, enabled_topic=None, topic_name=None,
                       webhook_url=None):
        """
        保存 EMQX 配置并（可选）创建规则链路。webhook_url 默认用本机 IP + 管理口。
        """
        self.db.set_setting("emqx_url", url or "")
        if key is not None:
            self.db.set_setting("emqx_api_key", key)
        if secret is not None:
            self.db.set_setting("emqx_api_secret", secret)
        if topic_name:
            self.db.set_setting("topic_name", topic_name)
        if enabled_topic is not None:
            self.db.set_setting("topic_enabled", "1" if enabled_topic else "0")
        self.reload_emqx()

        ok, why = self.emqx.ping()
        result = {"reachable": ok, "detail": why, "steps": [], "ok": ok}
        if not ok:
            return result

        topic = topic_name or self.db.get_setting("topic_name", "FMO/RAW") or "FMO/RAW"
        url_webhook = webhook_url or "http://%s:%s/api/ingest" % (
            get_lan_ip(), int(self.config.get("admin_port") or 35929))
        self.db.set_setting("topic_webhook_url", url_webhook)
        token = self.db.get_ingest_token()
        setup = self.emqx.setup_topic_rule(url_webhook, token, topic)
        self.db.set_setting("topic_pending", ",".join(setup.get("pending") or []))
        self.db.set_setting("topic_failed", ",".join(setup.get("failed") or []))
        if setup.get("ok"):
            self.db.set_setting("wizard_done", "1")
            self.db.set_setting("topic_enabled", "1")
        result.update(setup)
        result["webhook_url"] = url_webhook
        return result

    def ban(self, who, reason="", hours=None, operator="admin"):
        until = None
        if hours:
            until = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(time.time() + float(hours) * 3600))
        ok, err, kicked = self.emqx.ban_username(who, reason, until)
        if ok:
            self.db.add_blacklist_event("ban", who, reason, until or "infinity",
                                        operator or "admin", "username")
            self._bump("bans")
        return ok, err, kicked

    def unban(self, who, operator="admin"):
        ok, err = self.emqx.unban(who)
        if ok:
            self.db.add_blacklist_event("unban", who, "手动解封", None, operator, "username")
        return ok, err

    def release_quarantine(self, qid, by="admin"):
        """一键放行：标记为误判并解封（若此前已被封）。"""
        rows = [r for r in self.db.list_quarantine(None, 500) if r["id"] == int(qid)]
        if not rows:
            return False, "待审记录不存在"
        row = rows[0]
        cs = (row.get("conn_callsign") or "").strip()
        if cs:
            self.unban(cs, by)
        self.db.resolve_quarantine(qid, "released", by)
        return True, None


# ---------------- 宿主机健康 ----------------
def read_host_health():
    """读取宿主机 CPU/内存/磁盘/网络（Linux 读 /proc；其它平台尽力而为）。"""
    out = {"host_cpu_pct": None, "host_mem_pct": None, "host_mem_used": None,
           "host_mem_total": None, "host_disk_pct": None, "host_disk_used": None,
           "host_disk_total": None, "host_net_rx": None, "host_net_tx": None,
           "_emqx_load1": None}
    try:
        with open("/proc/loadavg", "r") as f:
            out["_emqx_load1"] = float(f.read().split()[0])
    except Exception:  # noqa: BLE001
        pass
    try:
        with open("/proc/meminfo", "r") as f:
            info = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = int(parts[1].strip().split()[0]) * 1024
        total = info.get("MemTotal") or 0
        avail = info.get("MemAvailable") or info.get("MemFree") or 0
        used = max(0, total - avail)
        out["host_mem_total"] = total
        out["host_mem_used"] = used
        if total:
            out["host_mem_pct"] = round(used * 100.0 / total, 1)
    except Exception:  # noqa: BLE001
        pass
    try:
        st = __import__("os").statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used = max(0, total - free)
        out["host_disk_total"] = total
        out["host_disk_used"] = used
        if total:
            out["host_disk_pct"] = round(used * 100.0 / total, 1)
    except Exception:  # noqa: BLE001
        pass
    try:
        rx = tx = 0
        with open("/proc/net/dev", "r") as f:
            for line in f.readlines()[2:]:
                parts = line.split(":")
                if len(parts) != 2:
                    continue
                fields = parts[1].split()
                if len(fields) >= 9:
                    rx += int(fields[0])
                    tx += int(fields[8])
        out["host_net_rx"] = rx
        out["host_net_tx"] = tx
    except Exception:  # noqa: BLE001
        pass
    try:
        with open("/proc/stat", "r") as f:
            parts = f.readline().split()[1:]
            vals = [int(x) for x in parts]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
            total = sum(vals)
            if total:
                out["host_cpu_pct"] = round((total - idle) * 100.0 / total, 1)
    except Exception:  # noqa: BLE001
        pass
    return out


def _parse_mem(v):
    from bas_emqx import parse_byte_size
    return parse_byte_size(v)
