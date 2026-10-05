#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · HTTP 接入层（把审计子系统并入分系统进程，单端口单登录）
==============================================================

路由分两类：
  公网口（35928，白名单）：
    POST /api/ingest        EMQX 规则引擎 webhook（X-Ingest-Token 校验，不占管理口）
  管理口（35929，内网）：
    /admin/bas                      审计界面（导航并入管理后台）
    /admin/bas.js /admin/bas.css    前端资源
    GET  /api/bas/status            总览（两端状态 + 计数）
    GET  /api/bas/online            在线客户端
    GET  /api/bas/leaderboard       排行榜（?since&until&limit&group）
    GET  /api/bas/leaderboard/<name> 呼号明细
    GET  /api/bas/topics            主题统计时间轴（?bucket=10s|1m|5m|1h）
    GET  /api/bas/topics/top        每桶 Top 呼号
    GET  /api/bas/audit             身份审计事件（?verdict&callsign&since&limit）
    GET  /api/bas/blacklist         当前生效黑名单
    GET  /api/bas/blacklist/history 黑名单流水
    POST /api/bas/blacklist/ban     手动拉黑 {who, reason, hours}
    POST /api/bas/blacklist/unban   解封 {who}
    GET  /api/bas/quarantine        待审队列（疑似误封）
    POST /api/bas/quarantine/release 一键放行 {id}
    GET  /api/bas/health            宿主机 + EMQX 健康快照
    GET  /api/bas/policy            当前身份控制策略
    POST /api/bas/policy            调整策略（mode/auto_ban/whitelist/...）
    GET  /api/bas/settings          审计设置（EMQX 地址等，密钥脱敏）
    POST /api/bas/settings          保存 EMQX 配置（可选：立即创建规则链路）
    POST /api/bas/setup-rule        一键创建/修复 EMQX 规则链路
    POST /api/bas/session           登录（换取审计前端用的会话令牌）
    POST /api/bas/clear             清空统计数据

设计取舍：
  * 审计库与分系统用户库**分开**（`{prefix}_audit.db`），各自 WAL，互不抢锁。
  * `/api/ingest` 同时在公网口与管理口放行：EMQX 与本机都能投递，不强制内网。
  * 管理口前端用一个**带过期时间的会话令牌**（HttpOnly Cookie 不可用时也可放 header），
    复用审计库的管理员口令（PBKDF2-SHA256，可复用上游 .NET 哈希）。
"""

import json
import os
import secrets
import threading
import time
import urllib.parse

import bas_audit_db as audit_db_mod
from bas_audit_db import AuditDB, now_text
from bas_audit import AuditService
from bas_emqx import get_lan_ip

SESSION_TTL = 24 * 3600
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SEC = 300

# ★ 后台账号登录开关。
#   已按要求**取消** BAS 认证审计后台的账号登录：管理口（35929）本身是内网/管理口，
#   直接放行即可。置为 True 可恢复原来的登录/会话校验（代码与前端界面都还在）。
BAS_ADMIN_LOGIN_REQUIRED = False

# 审计设置里允许前端写入的键（其余忽略）
WRITABLE_SETTINGS = {"emqx_url", "emqx_api_key", "emqx_api_secret", "topic_name",
                     "topic_enabled", "identity_control", "trust_proxy"}
# 策略里允许写入的键（防止前端写坏内核字段）
WRITABLE_POLICY = {"mode", "auto_ban", "uid_mismatch_verdict", "partial_attr_verdict",
                   "ban_hours", "ban_whitelist", "ban_rate_limit_per_hour",
                   "ban_when_sas_unavailable", "sas_cross_check", "audit_rate_limit_per_sec",
                   "audit_pass_log", "audit_pass_interval_sec"}


class BasAuth(object):
    """审计管理端登录：内存会话 + 失败锁定（对齐上游：username+IP 5 次锁 5 分钟）。"""

    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._sessions = {}          # token -> expire_ts
        self._fails = {}             # "user|ip" -> [count, first_ts]
        self._global_fails = []      # 全局兜底：1 分钟窗口 60 次

    def _now(self):
        return time.time()

    def _locked(self, key):
        rec = self._fails.get(key)
        if not rec:
            return 0
        count, first = rec
        if count >= LOGIN_MAX_FAILS:
            left = LOGIN_LOCK_SEC - (self._now() - first)
            if left > 0:
                return int(left)
            self._fails.pop(key, None)
        return 0

    def login(self, username, password, ip=""):
        key = "%s|%s" % (username, ip)
        with self._lock:
            left = self._locked(key)
            if left:
                return None, "登录失败次数过多，请 %d 秒后再试" % left
            now = self._now()
            self._global_fails = [t for t in self._global_fails if now - t < 60]
            if len(self._global_fails) >= 60:
                return None, "失败过于频繁，请稍后再试"
            if not self.db.has_admin():
                return None, "尚未设置管理员（请调用 POST /api/bas/setup-admin）"
            ok = self.db.verify_admin(username, password)
            if not ok:
                rec = self._fails.get(key) or [0, now]
                rec[0] += 1
                self._fails[key] = rec
                self._global_fails.append(now)
                return None, "用户名或密码错误"
            self._fails.pop(key, None)
            token = secrets.token_urlsafe(32)
            self._sessions[token] = now + SESSION_TTL
            return token, None

    def setup_admin(self, username, password):
        with self._lock:
            if self.db.has_admin():
                return False, "管理员已存在，请用登录接口或先清空审计库"
            if not username or len(str(password)) < 6:
                return False, "用户名不能为空，密码至少 6 位"
            self.db.set_admin(username, password)
            return True, None

    def check(self, token):
        if not token:
            return False
        now = self._now()
        with self._lock:
            exp = self._sessions.get(token)
            if not exp:
                return False
            if exp < now:
                self._sessions.pop(token, None)
                return False
            self._sessions[token] = now + SESSION_TTL      # 滑动续期
            return True

    def logout(self, token):
        with self._lock:
            self._sessions.pop(token, None)


def make_sas_lookup(sas_db_path, users_db_path, logger=None):
    """
    构造 SAS 交叉校验函数：callable(callsign) -> {uid, revoked} | None

    优先查 SAS 证书表（权威：证书里的 uid 就是签发值），
    退回分系统用户表（只要注册过就算合法）。
    抛异常 = SAS 不可用（策略层会据此拒绝封人）。
    """
    import sqlite3

    def lookup(callsign):
        cs = str(callsign or "").strip().upper()
        if not cs:
            return None
        # 1) SAS 证书表
        if sas_db_path and os.path.exists(sas_db_path):
            conn = None
            try:
                conn = sqlite3.connect("file:%s?mode=ro" % sas_db_path.replace("?", "%3f"),
                                       uri=True, timeout=3.0)
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT callsign, uid, revoked FROM certificates WHERE callsign=? "
                    "ORDER BY issued_at DESC LIMIT 1", (cs,)).fetchone()
                if row:
                    return {"uid": row["uid"], "revoked": bool(row["revoked"]),
                            "source": "sas_cert"}
            except Exception as e:  # noqa: BLE001
                if logger:
                    logger("[BAS] SAS 证书表查询失败: %s" % e)
                raise
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
        # 2) 分系统用户表（注册过即合法）
        if users_db_path and os.path.exists(users_db_path):
            conn = None
            try:
                conn = sqlite3.connect("file:%s?mode=ro" % users_db_path.replace("?", "%3f"),
                                       uri=True, timeout=3.0)
                row = conn.execute("SELECT callsign FROM users WHERE callsign=?", (cs,)).fetchone()
                if row:
                    return {"uid": None, "revoked": False, "source": "users"}
            except Exception as e:  # noqa: BLE001
                if logger:
                    logger("[BAS] 用户表查询失败: %s" % e)
                raise
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
        return None

    return lookup


def make_sas_has_any(sas_db_path, users_db_path, logger=None):
    """
    构造"SAS 库是否已有注册记录"探测函数（带 10 秒缓存）。

    用途：新装环境库里还没有用户时，不能让"查不到呼号"变成伪造证据 ——
    否则每个连接都会被判 KICK（这是上游误封的另一条路径）。
    """
    import sqlite3

    state = {"ts": 0.0, "val": False}

    def probe():
        now = time.time()
        if now - state["ts"] < 10 and state["ts"]:
            return state["val"]
        val = False
        for path, table in ((sas_db_path, "certificates"), (users_db_path, "users")):
            if not path or not os.path.exists(path):
                continue
            conn = None
            try:
                conn = sqlite3.connect("file:%s?mode=ro" % path.replace("?", "%3f"),
                                       uri=True, timeout=3.0)
                row = conn.execute("SELECT COUNT(*) FROM %s LIMIT 1" % table).fetchone()
                if row and int(row[0]) > 0:
                    val = True
                    break
            except Exception as e:  # noqa: BLE001
                if logger:
                    logger("[BAS] 探测 %s 失败: %s" % (table, e))
                continue
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001
                        pass
        state["val"] = val
        state["ts"] = now
        return val

    return probe


class BasHttp(object):
    """审计子系统的 HTTP 门面：路由分发 + JSON 响应。"""

    def __init__(self, service, db, base_dir, admin_port=None, logger=None):
        self.svc = service
        self.db = db
        self.base_dir = base_dir
        self.admin_port = admin_port
        self.log = logger or (lambda m: None)
        self.auth = BasAuth(db)
        self._js_cache = None
        self._css_cache = None

    # ---------------- 路由 ----------------
    def handle(self, handler, method, path, query, body):
        """
        由 ApiHandler 调用。返回 True 表示已处理（handler 已完成响应）。
        body: dict（已解析的 JSON）或 None
        """
        try:
            return self._dispatch(handler, method, path, query, body)
        except Exception as e:  # noqa: BLE001
            self.log("[BAS] 路由异常 %s %s: %s" % (method, path, e))
            handler.send_json({"ok": False, "error": "内部错误: %s" % e}, 500)
            return True

    def _dispatch(self, h, method, path, query, body):
        # ---- 公网白名单：webhook 接入 ----
        if path == "/api/ingest":
            token = h.headers.get("X-Ingest-Token") if hasattr(h, "headers") else None
            code, resp = self.svc.ingest(token, body)
            h.send_json(resp, code)
            return True

        # ---- 登录/初始化 ----
        # 已取消登录：不再需要账号密码。这些端点保留为兼容空实现。
        if path == "/api/bas/session" and method == "POST":
            if not BAS_ADMIN_LOGIN_REQUIRED:
                h.send_json({"ok": True, "token": "", "ttl": 0,
                             "login_disabled": True})
                return True
            body = body or {}
            ip = h.client_address[0] if getattr(h, "client_address", None) else ""
            token, err = self.auth.login(body.get("username", ""), body.get("password", ""), ip)
            if err:
                h.send_json({"ok": False, "error": err}, 401)
            else:
                h.send_json({"ok": True, "token": token, "ttl": SESSION_TTL})
            return True
        if path == "/api/bas/setup-admin" and method == "POST":
            if not BAS_ADMIN_LOGIN_REQUIRED:
                h.send_json({"ok": True, "login_disabled": True})
                return True
            body = body or {}
            ok, err = self.auth.setup_admin(body.get("username", ""), body.get("password", ""))
            h.send_json({"ok": ok, "error": err} if not ok else {"ok": True},
                        200 if ok else 400)
            return True
        if path == "/api/bas/bootstrap" and method == "GET":
            h.send_json({"ok": True, "need_setup": False if not BAS_ADMIN_LOGIN_REQUIRED
                         else (not self.db.has_admin()),
                         "login_disabled": not BAS_ADMIN_LOGIN_REQUIRED})
            return True

        # ---- 静态资源 ----
        # /admin/bas 与 /admin/fus 等价（系统更名为 FUS；旧地址保留兼容）
        if path in ("/admin/bas", "/admin/bas/", "/admin/bas/index.html",
                    "/admin/fus", "/admin/fus/", "/admin/fus/index.html"):
            self._serve_asset(h, "bas.html", "text/html; charset=utf-8")
            return True
        if path == "/admin/bas.js":
            self._serve_asset(h, "bas.js", "application/javascript; charset=utf-8")
            return True
        if path == "/admin/bas.css":
            self._serve_asset(h, "bas.css", "text/css; charset=utf-8")
            return True

        if not path.startswith("/api/bas/"):
            return False

        # ---- 会话校验 ----
        # ★ 已按要求**取消后台账号登录**：管理口（35929）本身就是内网/管理口，
        #   不再要求登录，直接放行。原会话逻辑保留（BAS_ADMIN_LOGIN_REQUIRED=False
        #   时可随时恢复），但默认不再拦截，避免"未登录或会话已过期"。
        token = h.headers.get("X-BAS-Token") if hasattr(h, "headers") else None
        if not token:
            cookie = h.headers.get("Cookie") if hasattr(h, "headers") else None
            if cookie:
                for part in str(cookie).split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "bas_token":
                        token = v
                        break
        if BAS_ADMIN_LOGIN_REQUIRED and not self.auth.check(token):
            h.send_json({"ok": False, "error": "未登录或会话已过期", "need_login": True}, 401)
            return True

        sub = path[len("/api/bas/"):]
        q = query or {}

        # ---- 总览 ----
        if sub == "status" and method == "GET":
            h.send_json({"ok": True, "status": self.svc.stats(),
                         "services": self._services(), "summary": self.db.stats_summary(),
                         "now": now_text()})
            return True

        # ---- 在线（实时：直查 EMQX + 按用户聚合 + 最近在线）----
        if sub == "online" and method == "GET":
            clients = self.svc.online_clients()
            mins = int((q.get("minutes") or ["30"])[0])
            h.send_json({"ok": True, "clients": clients,
                         "users": self.svc.online_users(clients),
                         "recent": self.svc.recent_clients(minutes=mins),
                         "recent_minutes": mins,
                         "fetched_at": now_text(), "source": "EMQX 实时列表"})
            return True

        # ---- 排行榜 ----
        if sub == "leaderboard" and method == "GET":
            h.send_json({"ok": True, "rows": self.db.leaderboard(
                since=q.get("since", [None])[0], until=q.get("until", [None])[0],
                limit=int((q.get("limit") or ["100"])[0]),
                group=(q.get("group") or ["callsign"])[0])})
            return True
        if sub.startswith("leaderboard/") and method == "GET":
            name = urllib.parse.unquote(sub[len("leaderboard/"):])
            h.send_json({"ok": True, "rows": self.db.leaderboard_detail(
                name, since=q.get("since", [None])[0], until=q.get("until", [None])[0])})
            return True

        # ---- 主题统计 ----
        if sub == "topics/top" and method == "GET":
            h.send_json({"ok": True, "buckets": self.db.top_by_bucket(
                topic=(q.get("topic") or [None])[0], since=q.get("since", [None])[0],
                until=q.get("until", [None])[0],
                top=int((q.get("top") or ["5"])[0]))})
            return True
        if sub == "topics" and method == "GET":
            h.send_json({"ok": True, "rows": self.db.topic_timeline(
                topic=(q.get("topic") or [None])[0], since=q.get("since", [None])[0],
                until=q.get("until", [None])[0],
                bucket=(q.get("bucket") or ["10s"])[0])})
            return True

        # ---- 管理操作：踢下线 / IP 封禁 / 白名单 / 策略 / 清理 ----
        if sub == "kick" and method == "POST":
            body = body or {}
            cid = str(body.get("clientid") or "").strip()
            ok, err = self.svc.kick_client(cid)
            h.send_json({"ok": ok, "error": err,
                         "detail": ("已踢下线 %s" % cid) if ok else err})
            return True
        if sub == "ban-ip" and method == "POST":
            body = body or {}
            ip = str(body.get("ip") or "").strip()
            hours = body.get("hours")
            ok, err = self.svc.ban_ip(ip, hours,
                                      str(body.get("reason") or "管理员手动封禁 IP"))
            h.send_json({"ok": ok, "error": err,
                         "detail": ("已封禁 IP %s" % ip) if ok else err})
            return True
        if sub == "unban-ip" and method == "POST":
            body = body or {}
            ip = str(body.get("ip") or "").strip()
            ok, err, detail = self.svc.unban(ip, "admin", "peerhost")
            h.send_json({"ok": ok, "error": err, "detail": detail})
            return True
        if sub == "whitelist" and method == "GET":
            h.send_json({"ok": True, "rows": self.svc.whitelist_list()})
            return True
        if sub == "whitelist/add" and method == "POST":
            body = body or {}
            ok, msg = self.svc.whitelist_add(body.get("callsign"))
            h.send_json({"ok": ok, "error": None if ok else msg, "detail": msg,
                         "rows": self.svc.whitelist_list()})
            return True
        if sub == "whitelist/remove" and method == "POST":
            body = body or {}
            ok, msg = self.svc.whitelist_remove(body.get("callsign"))
            h.send_json({"ok": ok, "error": msg if not ok else None,
                         "rows": self.svc.whitelist_list()})
            return True
        if sub == "policy" and method == "GET":
            h.send_json({"ok": True, "policy": self.svc.policy_snapshot()})
            return True
        if sub == "audit/prune" and method == "POST":
            body = body or {}
            days = body.get("days", 30)
            scene = str(body.get("scene") or "").strip() or None
            try:
                n = self.db.prune_audit_packets(days=days, scene=scene)
                h.send_json({"ok": True, "deleted": n,
                             "detail": "已清理 %d 条（保留最近 %s 天%s）"
                                       % (n, days, ("，场景 %s" % scene) if scene else "")})
            except Exception as e:  # noqa: BLE001
                h.send_json({"ok": False, "error": str(e)}, 500)
            return True
        if sub == "audit/stats" and method == "GET":
            h.send_json({"ok": True,
                         "total": self.db.count_audit_packets(),
                         "fake_cert": self.db.count_audit_packets("fake_cert"),
                         "now": now_text()})
            return True
        if sub == "seen/prune" and method == "POST":
            body = body or {}
            try:
                n = self.db.prune_client_seen(days=int(body.get("days") or 7))
                h.send_json({"ok": True, "deleted": n,
                             "detail": "已清理 %d 条连接登记" % n})
            except Exception as e:  # noqa: BLE001
                h.send_json({"ok": False, "error": str(e)}, 500)
            return True

        # ---- 身份审计事件 ----
        if sub == "audit" and method == "GET":
            rows = self.db.query_audit_packets(
                verdict=(q.get("verdict") or [None])[0],
                callsign=(q.get("callsign") or [None])[0],
                since=q.get("since", [None])[0], until=q.get("until", [None])[0],
                limit=int((q.get("limit") or ["200"])[0]),
                offset=int((q.get("offset") or ["0"])[0]))
            # ★ 认证类事件（auth_ok / fake_cert 等）发生在 MQTT CONNECT 那一刻，
            #   那时客户端还没发过任何 FMO 报文 → 天生没有包头身份。
            #   这里把"该 clientid 最近一次报文的包头身份"补上并标注来源，
            #   界面上就不会看着像"包头身份丢了"。
            try:
                need = [r.get("clientid") for r in rows
                        if not r.get("pkt_callsign") and r.get("clientid")]
                if need:
                    latest = self.db.latest_pkt_identity(need)
                    for r in rows:
                        if r.get("pkt_callsign"):
                            continue
                        hit = latest.get(str(r.get("clientid")))
                        if hit:
                            r["pkt_callsign_recent"] = hit["pkt_callsign"]
                            r["pkt_uid_recent"] = hit["pkt_uid"]
                            r["pkt_recent_at"] = hit["ts"]
            except Exception as e:  # noqa: BLE001
                print("[BAS] 补齐包头身份失败: %s" % e)
            h.send_json({"ok": True, "rows": rows})
            return True

        # ---- EMQX 实际封禁名单（关键：审计封的人在 EMQX 里，界面必须能看到并解开）----
        if sub == "banned" and method == "GET":
            rows, err = self._emqx_banned()
            h.send_json({"ok": err is None, "error": err, "rows": rows})
            return True
        if sub == "banned/unban" and method == "POST":
            body = body or {}
            who = str(body.get("who") or "").strip()
            as_type = str(body.get("as_type") or "").strip() or None
            ok, err, detail = self.svc.unban(who, "admin", as_type)
            h.send_json({"ok": ok, "error": err, "detail": detail})
            return True
        if sub == "banned/unban-all" and method == "POST":
            ok, err, detail = self.svc.unban_all("admin")
            h.send_json({"ok": ok, "error": err, "detail": detail})
            return True

        # ---- 审计库里记的黑名单（历史流水）+ 与 EMQX 实时状态核对 ----
        if sub == "blacklist" and method == "GET":
            rows = self.db.active_blacklist()
            # ★ 权威是 EMQX 的实际封禁名单：本表只是流水。
            #   在 EMQX 侧直接解封、或封禁自然到期时，本表不会自动产生 unban 行，
            #   于是界面会一直显示"拉黑中"（真实故障）。这里按 EMQX 实时名单核对：
            #     仍在 EMQX 里 → active（生效中）
            #     已不在 EMQX   → stale（已失效，可一键清理）
            live = None
            try:
                live = self.svc.emqx.list_banned(limit=5000) or []
            except Exception as e:  # noqa: BLE001
                live = None
                err_note = str(e)
            else:
                err_note = None
            if live is None:
                h.send_json({"ok": True, "active": rows, "stale": [],
                             "note": "读取 EMQX 封禁名单失败，以下为审计流水（可能已失效）: %s"
                                     % err_note})
                return True
            live_set = set()
            for b in live:
                live_set.add((str(b.get("as") or ""), str(b.get("who") or "")))
            active, stale = [], []
            for r in rows:
                key = (str(r.get("as_type") or "username"), str(r.get("who") or ""))
                (active if key in live_set else stale).append(r)
            h.send_json({"ok": True, "active": active, "stale": stale,
                         "live_count": len(live_set)})
            return True
        # 一键同步：把"EMQX 里已不存在"的流水写成 unban，让本表与线上状态一致
        if sub == "blacklist/sync" and method == "POST":
            rows = self.db.active_blacklist()
            try:
                live = self.svc.emqx.list_banned(limit=5000) or []
                live_set = set((str(b.get("as") or ""), str(b.get("who") or ""))
                               for b in live)
                n = 0
                for r in rows:
                    key = (str(r.get("as_type") or "username"), str(r.get("who") or ""))
                    if key not in live_set:
                        self.db.add_blacklist_event(
                            "unban", str(r.get("who") or ""),
                            "同步：EMQX 中已无此封禁（手动解封或已到期）",
                            None, "admin", str(r.get("as_type") or "username"))
                        n += 1
                self.svc.bump("blacklist_synced") if hasattr(self.svc, "bump") else None
                h.send_json({"ok": True, "cleaned": n,
                             "detail": "已把 %d 条失效记录标记为已解封" % n})
            except Exception as e:  # noqa: BLE001
                h.send_json({"ok": False, "error": str(e)}, 500)
            return True
        if sub == "blacklist/history" and method == "GET":
            h.send_json({"ok": True, "rows": self.db.blacklist_history(
                who=(q.get("who") or [None])[0],
                limit=int((q.get("limit") or ["200"])[0]))})
            return True
        if sub == "blacklist/ban" and method == "POST":
            body = body or {}
            who = str(body.get("who") or "").strip().upper()
            if not who:
                h.send_json({"ok": False, "error": "缺少呼号"}, 400)
                return True
            hours = body.get("hours")
            ok, err, kicked = self.svc.ban(who, body.get("reason") or "手动拉黑",
                                           hours, "admin")
            h.send_json({"ok": ok, "error": err, "kicked": kicked})
            return True
        if sub == "blacklist/unban" and method == "POST":
            body = body or {}
            who = str(body.get("who") or "").strip().upper()
            # 注意：**不传 as_type** → 会依次尝试 username/clientid/peerhost 三个维度
            # （真实事故：反滥用按 clientid 封，界面只按 username 解 → 解不掉）
            ok, err, detail = self.svc.unban(who, "admin")
            h.send_json({"ok": ok, "error": err, "detail": detail})
            return True

        # ---- 待审救援 ----
        if sub == "quarantine" and method == "GET":
            h.send_json({"ok": True, "rows": self.db.list_quarantine(
                (q.get("status") or ["pending"])[0])})
            return True
        if sub == "quarantine/release" and method == "POST":
            body = body or {}
            ok, err = self.svc.release_quarantine(body.get("id"), "admin")
            h.send_json({"ok": ok, "error": err})
            return True

        # ---- 健康 ----
        if sub == "health" and method == "GET":
            h.send_json({"ok": True, "emqx": self.svc.emqx_status(),
                         "series": self.db.health_series(
                             since=q.get("since", [None])[0], until=q.get("until", [None])[0])})
            return True

        # ---- 策略 ----
        if sub == "policy" and method == "GET":
            h.send_json({"ok": True, "policy": self.svc.policy_snapshot()})
            return True
        if sub == "policy" and method == "POST":
            body = body or {}
            applied = {}
            for k, v in (body.get("policy") or body).items():
                if k in WRITABLE_POLICY:
                    if k == "ban_whitelist" and isinstance(v, list):
                        v = ",".join(str(x).strip().upper() for x in v if str(x).strip())
                    if isinstance(v, bool):
                        v = "true" if v else "false"
                    self.svc.set_policy(k, v)
                    applied[k] = v
            h.send_json({"ok": True, "applied": applied,
                         "policy": self.svc.policy_snapshot()})
            return True

        # ---- EMQX 身份链路诊断（client_attrs 为什么没下发）----
        if sub == "diagnose" and method == "GET":
            h.send_json({"ok": True, "report": self._diagnose()})
            return True

        # ---- MQTT(EMQX) 认证接管 ----
        if sub == "emqx-auth" and method == "GET":
            h.send_json({"ok": True, "result": self._auth_switch(dry_run=True,
                                                                 force_all=bool(q.get("force_all")))})
            return True
        if sub == "emqx-auth" and method == "POST":
            body = body or {}
            h.send_json({"ok": True, "result": self._auth_switch(
                dry_run=bool(body.get("dry_run", False)),
                force_all=bool(body.get("force_all")),
                target_url=body.get("target_url"))})
            return True

        # ---- 设置 ----
        if sub == "settings" and method == "GET":
            s = self.db.all_settings()
            h.send_json({"ok": True, "settings": {k: v for k, v in s.items()
                                                 if k in WRITABLE_SETTINGS or k == "topic_enabled"},
                         "webhook_url": s.get("topic_webhook_url", ""),
                         "ingest_token_hint": (s.get("ingest_token", "")[:4] + "…"
                                               if s.get("ingest_token") else ""),
                         "policy": self.svc.policy_snapshot()})
            return True
        if sub == "settings" and method == "POST":
            body = body or {}
            kwargs = {}
            for k in WRITABLE_SETTINGS:
                if k in body:
                    kwargs[k] = body[k]
            if body.get("apply") or body.get("setup_rule"):
                res = self.svc.configure_emqx(
                    url=body.get("emqx_url", self.db.get_setting("emqx_url", "")),
                    key=body.get("emqx_api_key"),
                    secret=body.get("emqx_api_secret"),
                    enabled_topic=body.get("topic_enabled"),
                    topic_name=body.get("topic_name"),
                    webhook_url=body.get("webhook_url"))
                h.send_json({"ok": bool(res.get("ok")), "result": res})
                return True
            for k, v in kwargs.items():
                self.db.set_setting(k, "" if v is None else str(v))
            self.svc.reload_emqx()
            h.send_json({"ok": True, "saved": list(kwargs.keys())})
            return True

        # ---- 规则链路 ----
        if sub == "setup-rule" and method == "POST":
            body = body or {}
            res = self.svc.configure_emqx(
                url=self.db.get_setting("emqx_url", ""),
                key=None, secret=None,
                enabled_topic=True,
                topic_name=body.get("topic_name") or self.db.get_setting("topic_name", "FMO/RAW"),
                webhook_url=body.get("webhook_url"))
            h.send_json({"ok": bool(res.get("ok")), "result": res})
            return True
        if sub == "teardown-rule" and method == "POST":
            ok, errs = self.svc.emqx.teardown_topic_rule()
            self.db.set_setting("topic_enabled", "0")
            h.send_json({"ok": ok, "errors": errs})
            return True

        # ---- 清空统计 ----
        if sub == "clear" and method == "POST":
            body = body or {}
            self.db.clear_all(keep_blacklist=bool(body.get("keep_blacklist", True)))
            h.send_json({"ok": True})
            return True

        if sub == "session" and method == "DELETE":
            self.auth.logout(token)
            h.send_json({"ok": True})
            return True

        h.send_json({"ok": False, "error": "未知的 BAS 接口: %s" % sub}, 404)
        return True

    # ---------------- 辅助 ----------------
    def _emqx_banned(self):
        """
        读 EMQX 里**真实的**封禁名单（审计封的人就在这儿）。
        解锁界面以前只读审计库自己的黑名单表，导致"明明被封却看不到、解不了"。
        """
        try:
            cli = self.svc.emqx
            if cli is None or not getattr(cli, "url", ""):
                return [], "EMQX 未配置"
            payload = cli._json("GET", "/api/v5/banned")  # noqa: SLF001
            rows = payload.get("data") if isinstance(payload, dict) else payload
            out = []
            for b in (rows or []):
                if not isinstance(b, dict):
                    continue
                out.append({
                    "as": b.get("as"), "who": b.get("who"), "by": b.get("by"),
                    "reason": b.get("reason"), "until": b.get("until"),
                    "at": b.get("at"),
                    # 下面两个字段来自审计库，方便判断"这条封是谁、为什么"
                    "is_forever": str(b.get("until") or "").lower() == "infinity",
                })
            return out, None
        except Exception as e:  # noqa: BLE001
            return [], str(e)

    def _diagnose(self):
        """身份链路诊断：client_attrs 没下发的原因（版本/请求体/认证器/SAS 可达性）。"""
        import bas_diagnose as dg
        import glob
        port = int((self.svc.config or {}).get("port") or 35928)
        sas_url = "http://127.0.0.1:%d/auth" % port
        dbs = glob.glob(os.path.join(self.base_dir, "*_audit.db"))
        audit_db = dbs[0] if dbs else None
        try:
            r = dg.diagnose(
                emqx_url=self.db.get_setting("emqx_url", ""),
                key=self.db.get_setting("emqx_api_key", ""),
                secret=self.db.get_setting("emqx_api_secret", ""),
                sas_url=sas_url, base_dir=self.base_dir, audit_db=audit_db)
            return {"ok": r["ok"], "findings": r["findings"], "facts": r["facts"],
                    "sas_url": sas_url}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e), "findings": [], "facts": {}}

    def _auth_switch(self, dry_run=True, force_all=False, target_url=None):
        """
        识别 MQTT(EMQX) 并把客户端认证指向本服务端口。
        dry_run=True 只预览不动线上；真正执行前会把现有认证链备份进审计库。
        """
        import bas_emqx_auth as ea
        port = int((self.svc.config or {}).get("port") or 35928)
        detect = ea.detect_mqtt()
        out = {"detect": detect, "dry_run": dry_run}
        cfg = self.db.all_settings()          # 已脱敏
        url = self.db.get_setting("emqx_url", "")
        key = self.db.get_setting("emqx_api_key", "")
        sec = self.db.get_setting("emqx_api_secret", "")
        if not (url and key and sec):
            out["error"] = "尚未配置 EMQX（请先在上方保存 EMQX 连接信息）"
            return out
        from bas_emqx import EmqxClient
        cli = EmqxClient(url, key, sec)
        ok, why = cli.ping()
        out["emqx_url"] = url
        out["reachable"] = ok
        out["detail"] = why
        if not ok:
            out["error"] = "EMQX 不可达: %s" % why
            return out
        target = target_url or "http://%s:%d/auth" % (get_lan_ip(), port)
        out["target_url"] = target
        out["current"] = ea.inspect(cli)
        out["switch"] = ea.switch_auth(cli, target, force_all=force_all,
                                       dry_run=dry_run, db=self.db, log=self.log)
        _ = cfg
        return out

    def _services(self):
        """两端服务状态（分系统自身 + 审计）。"""
        out = {"subsystem": "running"}
        try:
            import subprocess
            for svc in ("fmo-subsystem", "fmo-bas", "fmo-fas"):
                r = subprocess.run(["systemctl", "is-active", svc], capture_output=True,
                                   text=True, timeout=2)
                st = (r.stdout or "").strip()
                if svc in ("fmo-subsystem", "fmo-bas") and st:
                    out["subsystem_service"] = "%s=%s" % (svc, st)
                if svc == "fmo-fas":
                    out["legacy_fas"] = st or "absent"
        except Exception:  # noqa: BLE001
            pass
        return out

    def _serve_asset(self, h, name, ctype):
        p = os.path.join(self.base_dir, "admin", name)
        try:
            with open(p, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            h.send_json({"ok": False, "error": "缺少前端文件 admin/%s" % name}, 404)
            return
        h.send_response(200)
        h.send_header("Content-Type", ctype)
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Cache-Control", "no-cache")
        h.end_headers()
        try:
            h.wfile.write(body)
        except Exception:  # noqa: BLE001
            pass


# ---------------- 初始化 ----------------
def init_bas(config, base_dir, users_db_path=None, sas_db_path=None, logger=None):
    """
    初始化 BAS 审计子系统。返回 (service, http) 或 (None, None)。
    失败不抛异常（保证分系统主服务仍能启动）。
    """
    log = logger or (lambda m: print(m))
    try:
        prefix = config.get("domain") or config.get("api_url") or "default"
        import re as _re
        safe = _re.sub(r"[^a-zA-Z0-9.\-]", "_", str(prefix)).strip("._") or "default"
        audit_path = os.path.join(base_dir, "%s_audit.db" % safe)
        db = AuditDB(audit_path)
        svc = AuditService(db, config=config)
        svc.sas_lookup = make_sas_lookup(sas_db_path, users_db_path, logger=log)
        svc.sas_has_any = make_sas_has_any(sas_db_path, users_db_path, logger=log)
        svc.policy.sas_lookup = svc.sas_lookup
        svc.policy.sas_has_any = svc.sas_has_any
        svc.start()
        http = BasHttp(svc, db, base_dir, admin_port=config.get("admin_port"), logger=log)
        log("[BAS] 审计子系统已启动: db=%s, 策略模式=%s" % (audit_path, svc.policy.mode()))
        return svc, http
    except Exception as e:  # noqa: BLE001
        log("[BAS] 审计子系统初始化失败: %s" % e)
        return None, None
