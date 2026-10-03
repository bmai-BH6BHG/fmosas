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

        # ① 主题统计（10 秒桶）
        if str(self.db.get_setting("topic_enabled", "0")) != "0":
            self.db.add_topic_stat(topic, clientid, username, callsign, uid, 1, nbytes)

        # ② 逐包身份审计
        if raw:
            self._audit_packet(raw, topic, callsign, uid, clientid, username)

    def _audit_packet(self, raw, topic, conn_callsign, conn_uid, clientid, username):
        parsed = parser_mod.parse(raw)
        if not self.identity_control_enabled():
            return

        decision = self.policy.decide(raw, parsed, conn_callsign, conn_uid, clientid)

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

        # 低置信度/未封禁的可疑事件进入待审队列（误封救援的关键）
        if decision.verdict == KICK and not decision.ban:
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

        # 重复身份检测（同 uid 多连接；连续 DUP_UID_ROUNDS 轮确认）
        self._detect_duplicate_identity(clients)

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

    def _detect_duplicate_identity(self, clients):
        """
        同一 uid 出现在多个在线连接 → 疑似凭证泄露。
        连续 DUP_UID_ROUNDS 轮确认后才处置（EMQX keepalive 期间新旧 clientid 会短暂并存）。
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
            n = self._dup_uid_track.get(uid, 0) + 1
            self._dup_uid_track[uid] = n
            if n < DUP_UID_ROUNDS:
                continue
            # 确认泄露：按策略处置
            names = sorted({(r.get("callsign") or r.get("username") or "") for r in rows} - {""})
            reason = "重复身份: uid=%s 同时有 %d 个连接（呼号 %s）" % (uid, len(rows), ",".join(names))
            self.db.write_audit_packet({
                "ts": now_text(True), "topic": "", "clientid": ",".join(
                    r.get("clientid", "") for r in rows),
                "conn_callsign": ",".join(names), "conn_uid": uid,
                "verdict": KICK, "scene": "dup_identity", "reason": reason,
                "confidence": 0.85, "source": "collector",
            })
            if self.policy.mode() == "ban" and self.policy.cfg.get("auto_ban"):
                for nm in names:
                    if self.policy.in_whitelist(nm):
                        continue
                    self._ban_recorder(nm, reason, self.policy.cfg.get("ban_hours"))
            else:
                self.db.add_quarantine({
                    "created_at": now_text(True), "conn_callsign": ",".join(names),
                    "conn_uid": uid, "scene": "dup_identity", "reason": reason,
                    "confidence": 0.85,
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
