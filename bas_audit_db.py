#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · 审计数据库（对齐 FAS 的 7 张表，并修正其缺陷 + 增加误封救援）

上游 schema（bas/spec/db-schema.md，源码 Database.cs 核对）：
  minute_stats(clientid, ts, ...)      PK(clientid, ts)         呼号/客户端分钟统计
  topic_stats(topic, clientid, ts, ...) PK(topic, clientid, ts) 10 秒粒度主题统计
  health_snapshots(ts, ...)            PK(ts)                  宿主机 + EMQX 健康快照
  settings(key, value)                 PK(key)                 配置
  admin_user(id=1, ...)                CHECK(id=1)             管理员（PBKDF2-SHA256/10万/16B盐/32B）
  blacklist_audit(id AUTOINCREMENT)                            黑名单流水（含 operator/reason）
  audit_packets(id AUTOINCREMENT)                              身份审计事件

时间一律 TEXT 本地时间（字典序可比较）：统计用 '%Y-%m-%d %H:%M:%S'，
审计事件带毫秒 '%Y-%m-%d %H:%M:%S.%f' 截 3 位。**不要用 isoformat()**（带 T 会破坏比较）。

相对上游的修正：
  1. 每条连接都显式设置 PRAGMA（上游只在 Init 的单一连接上设置，其余靠连接池碰运气）
  2. 清理覆盖全部可增长表（上游 ClearAll 漏删 audit_packets）
  3. blacklist_audit / audit_packets 增加按行数上限的裁剪（上游无上限）
  4. 增加 bas_policy 表：身份控制策略持久化（模式/白名单/UID 判定），供管理界面调整
  5. 增加 bas_quarantine 表：**疑似误封待审队列**——低置信度事件不直接封人，先入队由管理员一键放行
"""

import datetime
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time

SCHEMA_VERSION = 1

TIME_FMT = "%Y-%m-%d %H:%M:%S"
TIME_FMT_MS = "%Y-%m-%d %H:%M:%S.%f"

RETENTION_DAYS = 30            # 统计与审计数据保留天数（对齐上游）
CLEAN_BATCH = 20000            # 每批删除行数（SQLite 不支持 DELETE ... LIMIT）
CLEAN_MAX_BATCHES = 200
AUDIT_MAX_ROWS = 500000        # audit_packets 行数上限（防无限增长）
BLACKLIST_AUDIT_MAX_ROWS = 200000


def now_text(with_ms=False):
    """本地时间文本（字典序可比较）。带毫秒时截断到 3 位。

    注意：time.strftime 不支持 %f，毫秒用 datetime 生成。
    """
    if with_ms:
        return datetime.datetime.now().strftime(TIME_FMT_MS)[:23]
    return time.strftime(TIME_FMT, time.localtime())


def ts10(ts_text=None):
    """把时间文本向下取整到 10 秒颗粒（对齐上游聚合键）。"""
    t = ts_text or now_text()
    # 'YYYY-mm-dd HH:MM:SS' → 秒位取整到 10
    try:
        sec = int(t[17:19])
        sec10 = (sec // 10) * 10
        return t[:17] + "%02d" % sec10
    except Exception:  # noqa: BLE001
        return t


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS minute_stats (
    clientid      TEXT NOT NULL,
    ts            TEXT NOT NULL,
    username      TEXT,
    callsign      TEXT,
    uid           TEXT,
    ip_address    TEXT,
    recv_msg      INTEGER DEFAULT 0,
    send_msg      INTEGER DEFAULT 0,
    recv_pkt      INTEGER DEFAULT 0,
    send_pkt      INTEGER DEFAULT 0,
    recv_oct      INTEGER DEFAULT 0,
    send_oct      INTEGER DEFAULT 0,
    reconnect     INTEGER DEFAULT 0,
    PRIMARY KEY (clientid, ts)
);
CREATE INDEX IF NOT EXISTS idx_minute_ts       ON minute_stats(ts);
CREATE INDEX IF NOT EXISTS idx_minute_username ON minute_stats(username);
CREATE INDEX IF NOT EXISTS idx_minute_callsign ON minute_stats(callsign);

CREATE TABLE IF NOT EXISTS topic_stats (
    topic      TEXT NOT NULL,
    clientid   TEXT NOT NULL,
    ts         TEXT NOT NULL,
    username   TEXT,
    callsign   TEXT,
    uid        TEXT,
    msgs       INTEGER DEFAULT 0,
    bytes      INTEGER DEFAULT 0,
    PRIMARY KEY (topic, clientid, ts)
);
CREATE INDEX IF NOT EXISTS idx_topic_ts       ON topic_stats(ts);
CREATE INDEX IF NOT EXISTS idx_topic_username ON topic_stats(username);
CREATE INDEX IF NOT EXISTS idx_topic_callsign ON topic_stats(callsign);

CREATE TABLE IF NOT EXISTS health_snapshots (
    ts             TEXT PRIMARY KEY,
    host_cpu_pct   REAL,
    host_mem_pct   REAL,
    host_mem_used  INTEGER,
    host_mem_total INTEGER,
    host_disk_pct  REAL,
    host_disk_used INTEGER,
    host_disk_total INTEGER,
    host_net_rx    INTEGER,
    host_net_tx    INTEGER,
    emqx_nodes     INTEGER,
    emqx_alive     INTEGER,
    emqx_conns     INTEGER,
    emqx_cpu_pct   REAL,        -- 注意：EMQX 5.x 无 CPU%，上游用 load1 顶替
    emqx_mem_used  INTEGER,
    emqx_mem_total INTEGER,
    emqx_alarms    TEXT,
    msg_rate_in    REAL,
    msg_rate_out   REAL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_user (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS blacklist_audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,          -- ban / unban
    as_type    TEXT NOT NULL DEFAULT 'username',
    who        TEXT NOT NULL,
    reason     TEXT,
    until      TEXT,                   -- NULL/'infinity' = 永久
    operator   TEXT,                   -- 手动操作者 或 '身份控制' / 'auto-uid-dup'
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bl_who  ON blacklist_audit(who);
CREATE INDEX IF NOT EXISTS idx_bl_time ON blacklist_audit(created_at);

CREATE TABLE IF NOT EXISTS audit_packets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    topic         TEXT,
    clientid      TEXT,
    ip            TEXT,                -- 来源 IP（认证事件取 peerhost；报文事件取 webhook/EMQX）
    conn_callsign TEXT,
    conn_uid      TEXT,
    pkt_callsign  TEXT,
    pkt_uid       TEXT,
    verdict       TEXT,                -- PASS/WARN/KICK/FAIL
    scene         TEXT,                -- BAS 新增：场景细分（forged/uid_mismatch/...）
    reason        TEXT,                -- BAS 新增：可读原因（便于申诉）
    confidence    REAL,                -- BAS 新增：置信度
    len           INTEGER,
    frame_num     INTEGER,
    crc_ok        INTEGER,
    smeter        INTEGER,
    srv_uid       TEXT,
    pkt_ts        TEXT,
    stream_begin  TEXT,
    ban           INTEGER DEFAULT 0,
    source        TEXT                 -- 'packet'=逐包审计 / 'collector'=采集判定
);
CREATE INDEX IF NOT EXISTS idx_ap_ts          ON audit_packets(ts);
CREATE INDEX IF NOT EXISTS idx_ap_verdict     ON audit_packets(verdict);
CREATE INDEX IF NOT EXISTS idx_ap_conn_call   ON audit_packets(conn_callsign);
CREATE INDEX IF NOT EXISTS idx_ap_pkt_call    ON audit_packets(pkt_callsign);
CREATE INDEX IF NOT EXISTS idx_ap_clientid    ON audit_packets(clientid);

CREATE TABLE IF NOT EXISTS bas_policy (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS bas_quarantine (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    conn_callsign TEXT,
    conn_uid      TEXT,
    pkt_callsign  TEXT,
    pkt_uid       TEXT,
    clientid      TEXT,
    scene         TEXT,
    reason        TEXT,
    confidence    REAL,
    status        TEXT DEFAULT 'pending',   -- pending / released / confirmed
    resolved_at   TEXT,
    resolved_by   TEXT
);
CREATE INDEX IF NOT EXISTS idx_quar_status ON bas_quarantine(status);
CREATE INDEX IF NOT EXISTS idx_quar_time   ON bas_quarantine(created_at);

-- 连接登记：每次认证通过记一笔。
-- 用途：有些客户端（尤其手机 APP）会**频繁短线重连**（实测：
-- 某用户每分钟换一个 clientid 重连一次、会话仅几十秒），
-- 只看"当前在线"会以为这个人从没上线；有了这张表就能显示
-- "最近 30 分钟上过线的用户 + 最后在线时间"。
CREATE TABLE IF NOT EXISTS client_seen (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    callsign      TEXT,
    uid           TEXT,
    clientid      TEXT,
    peerhost      TEXT
);
CREATE INDEX IF NOT EXISTS idx_seen_ts  ON client_seen(ts);
CREATE INDEX IF NOT EXISTS idx_seen_cs  ON client_seen(callsign, ts);
CREATE INDEX IF NOT EXISTS idx_seen_cid ON client_seen(clientid, ts);

-- 未信任根台账：客户端拿「我们不认识的根 CA」签发的证书来登录时被记一笔。
-- 为什么要这张表：根公钥曾经只写进 reason 的前 20 个字符，管理员既核对不了来源、
-- 也复制不出完整值去加白（出现"看得见问题、修不了"）。这里存**完整**公钥，
-- 配合「谁在用这个根、最近一次、自称呼号、IP、次数」，一眼能判断：
--   · 是自己某台老服务器 / 兄弟分系统 → 拿完整公钥去 roots/ 或 extraRootPubkeys 加白
--   · 是陌生人反复试            → 就是伪造证书的撞库，维持拒绝即可
-- ⚠️ 这张表只是**线索**，不是信任；加不加白永远由管理员决定。
CREATE TABLE IF NOT EXISTS untrusted_roots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    root_pubkey   TEXT NOT NULL,        -- 完整根公钥（base64url，可直接复制加白）
    ts            TEXT NOT NULL,        -- 最近一次出现时间
    first_ts      TEXT,                 -- 首次出现时间
    hits          INTEGER DEFAULT 1,    -- 累计出现次数
    last_callsign TEXT,                 -- 最近一次自称呼号（仅留证，不可信）
    last_clientid TEXT,
    last_ip       TEXT,
    distinct_cs   INTEGER DEFAULT 1     -- 自称呼号去重个数（撞库典型特征）
);
CREATE INDEX IF NOT EXISTS idx_uroot_ts  ON untrusted_roots(ts);
CREATE INDEX IF NOT EXISTS idx_uroot_key ON untrusted_roots(root_pubkey);
"""

DEFAULT_SETTINGS = {
    "emqx_url": "",
    "emqx_api_key": "",
    "emqx_api_secret": "",
    # 对齐上游：identity_control 判定是 != "0"；但 BAS 默认更安全的 warn 语义见 bas_policy
    "identity_control": "1",
    "trust_proxy": "0",
    "wizard_done": "0",
    "topic_enabled": "0",
    "topic_name": "FMO/RAW",
    "topic_webhook_url": "",
    "topic_pending": "",
    "topic_failed": "",
}


class AuditDB(object):
    """审计库。单写者模型：内部锁 + BEGIN IMMEDIATE，避免 `database is locked`。"""

    def __init__(self, path, retention_days=RETENTION_DAYS):
        self.path = path
        self.retention_days = retention_days
        self._lock = threading.RLock()
        d = os.path.dirname(os.path.abspath(path))
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d)
            except Exception:  # noqa: BLE001
                pass
        self._init()

    # ---------------- 连接 ----------------
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        # 每条连接都显式设置（修正上游只设一次的问题）
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=OFF;")
        return conn

    def _init(self):
        with self._lock:
            conn = self._conn()
            try:
                conn.executescript(SCHEMA_SQL)
                # 迁移：老库补列（CREATE TABLE IF NOT EXISTS 不会给已有表加列）
                try:
                    cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_packets)")]
                    if "ip" not in cols:
                        conn.execute("ALTER TABLE audit_packets ADD COLUMN ip TEXT")
                        print("[BAS] 已为 audit_packets 增加 ip 列")
                except Exception as e:  # noqa: BLE001
                    print("[BAS] 迁移 audit_packets.ip 失败: %s" % e)
                # 迁移协议：即使新建库也显式置版本
                cur = conn.execute("PRAGMA user_version;")
                ver = cur.fetchone()[0]
                if ver < SCHEMA_VERSION:
                    conn.execute("PRAGMA user_version=%d;" % SCHEMA_VERSION)
                # 默认 settings
                for k, v in DEFAULT_SETTINGS.items():
                    conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
            finally:
                conn.close()

    # ---------------- settings ----------------
    def get_setting(self, key, default=None):
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
                return row["value"] if row else default
            finally:
                conn.close()

    def set_setting(self, key, value):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                             "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                             (key, "" if value is None else str(value)))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def all_settings(self, hide_secret=True):
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute("SELECT key, value FROM settings").fetchall()
                out = {r["key"]: r["value"] for r in rows}
            finally:
                conn.close()
        if hide_secret and out.get("emqx_api_secret"):
            out["emqx_api_secret"] = "********"
        return out

    def get_ingest_token(self):
        """首次读取时生成 32 位大写 HEX 并持久化（对齐上游）。"""
        tok = self.get_setting("ingest_token")
        if not tok:
            tok = secrets.token_hex(16).upper()
            self.set_setting("ingest_token", tok)
        return tok

    # ---------------- bas_policy（BAS 新增：可调整的策略） ----------------
    def get_policy(self):
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute("SELECT key, value FROM bas_policy").fetchall()
                return {r["key"]: r["value"] for r in rows}
            finally:
                conn.close()

    def set_policy(self, key, value):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("INSERT INTO bas_policy(key, value, updated_at) VALUES(?, ?, ?) "
                             "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                             "updated_at=excluded.updated_at",
                             (key, "" if value is None else str(value), now_text()))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    # ---------------- 管理员与登录 ----------------
    @staticmethod
    def hash_password(password, iterations=100000, salt=None):
        """PBKDF2-HMAC-SHA256，格式 `iterations.salt_b64.hash_b64`（对齐上游，可直接复用 .NET 哈希）。"""
        import base64
        salt = salt or os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
        return "%d.%s.%s" % (iterations,
                             base64.b64encode(salt).decode("ascii"),
                             base64.b64encode(dk).decode("ascii"))

    @staticmethod
    def verify_password(password, stored):
        import base64
        try:
            iters_s, salt_b64, hash_b64 = str(stored).split(".")
            iterations = int(iters_s)
            salt = base64.b64decode(salt_b64)
            want = base64.b64decode(hash_b64)
        except Exception:  # noqa: BLE001
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations,
                                 dklen=len(want))
        return hmac.compare_digest(dk, want)

    def has_admin(self):
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT id FROM admin_user WHERE id=1").fetchone()
                return row is not None
            finally:
                conn.close()

    def get_admin(self):
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT * FROM admin_user WHERE id=1").fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def set_admin(self, username, password):
        h = self.hash_password(password)
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("INSERT INTO admin_user(id, username, password_hash, created_at, updated_at) "
                             "VALUES(1, ?, ?, ?, ?) "
                             "ON CONFLICT(id) DO UPDATE SET username=excluded.username, "
                             "password_hash=excluded.password_hash, updated_at=excluded.updated_at",
                             (username, h, now_text(), now_text()))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def verify_admin(self, username, password):
        a = self.get_admin()
        if not a:
            return False
        if str(a["username"]) != str(username):
            return False
        return self.verify_password(password, a["password_hash"])

    # ---------------- 统计写入 ----------------
    def upsert_minute_stat(self, row):
        """幂等覆盖（PK clientid+ts）：同分钟内重复写按最新值覆盖。"""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO minute_stats(clientid, ts, username, callsign, uid, ip_address, "
                    "recv_msg, send_msg, recv_pkt, send_pkt, recv_oct, send_oct, reconnect) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(clientid, ts) DO UPDATE SET username=excluded.username, "
                    "callsign=excluded.callsign, uid=excluded.uid, ip_address=excluded.ip_address, "
                    "recv_msg=excluded.recv_msg, send_msg=excluded.send_msg, recv_pkt=excluded.recv_pkt, "
                    "send_pkt=excluded.send_pkt, recv_oct=excluded.recv_oct, send_oct=excluded.send_oct, "
                    # reconnect 是"本桶内发生过重连"的粘性标记：同一 10 秒桶内多次采集
                    # 不能因为后一次 delta 正常就把标记抹掉（上游采集是覆盖写，会丢标记）
                    "reconnect=MAX(minute_stats.reconnect, excluded.reconnect)",
                    (row.get("clientid", ""), row.get("ts") or now_text(),
                     row.get("username"), row.get("callsign"), row.get("uid"),
                     row.get("ip_address"), int(row.get("recv_msg") or 0),
                     int(row.get("send_msg") or 0), int(row.get("recv_pkt") or 0),
                     int(row.get("send_pkt") or 0), int(row.get("recv_oct") or 0),
                     int(row.get("send_oct") or 0), int(row.get("reconnect") or 0)))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def add_topic_stat(self, topic, clientid, username, callsign, uid, msgs, nbytes, ts=None):
        """
        累加语义（ON CONFLICT DO UPDATE 累加）：重放会双计，调用方需保证不重放。
        ts 统一向下对齐到 10 秒桶（对齐上游聚合键 (topic, username, uid, clientid, ts10s)）。
        """
        ts = ts10(ts or now_text())
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO topic_stats(topic, clientid, ts, username, callsign, uid, msgs, bytes) "
                    "VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(topic, clientid, ts) DO UPDATE SET msgs=msgs+excluded.msgs, "
                    "bytes=bytes+excluded.bytes, username=excluded.username, "
                    "callsign=excluded.callsign, uid=excluded.uid",
                    (topic, clientid, ts, username, callsign, uid, int(msgs), int(nbytes)))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def add_health_snapshot(self, row):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT OR REPLACE INTO health_snapshots(ts, host_cpu_pct, host_mem_pct, "
                    "host_mem_used, host_mem_total, host_disk_pct, host_disk_used, host_disk_total, "
                    "host_net_rx, host_net_tx, emqx_nodes, emqx_alive, emqx_conns, emqx_cpu_pct, "
                    "emqx_mem_used, emqx_mem_total, emqx_alarms, msg_rate_in, msg_rate_out) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (row.get("ts") or now_text(), row.get("host_cpu_pct"), row.get("host_mem_pct"),
                     row.get("host_mem_used"), row.get("host_mem_total"), row.get("host_disk_pct"),
                     row.get("host_disk_used"), row.get("host_disk_total"), row.get("host_net_rx"),
                     row.get("host_net_tx"), row.get("emqx_nodes"), row.get("emqx_alive"),
                     row.get("emqx_conns"), row.get("emqx_cpu_pct"), row.get("emqx_mem_used"),
                     row.get("emqx_mem_total"), row.get("emqx_alarms"), row.get("msg_rate_in"),
                     row.get("msg_rate_out")))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    # ---------------- 审计事件 ----------------
    def write_audit_packet(self, row):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO audit_packets(ts, topic, clientid, ip, conn_callsign, conn_uid, "
                    "pkt_callsign, pkt_uid, verdict, scene, reason, confidence, len, frame_num, "
                    "crc_ok, smeter, srv_uid, pkt_ts, stream_begin, ban, source) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (row.get("ts") or now_text(True), row.get("topic"), row.get("clientid"),
                     row.get("ip"),
                     row.get("conn_callsign"), row.get("conn_uid"), row.get("pkt_callsign"),
                     row.get("pkt_uid"), row.get("verdict"), row.get("scene"), row.get("reason"),
                     row.get("confidence"), row.get("len"), row.get("frame_num"),
                     1 if row.get("crc_ok") else 0, row.get("smeter"), row.get("srv_uid"),
                     row.get("pkt_ts"), row.get("stream_begin"), 1 if row.get("ban") else 0,
                     row.get("source") or "packet"))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def query_audit_packets(self, verdict=None, callsign=None, since=None, until=None,
                            limit=200, offset=0):
        sql = "SELECT * FROM audit_packets WHERE 1=1"
        args = []
        if verdict:
            sql += " AND verdict=?"
            args.append(verdict)
        if callsign:
            sql += " AND (conn_callsign=? OR pkt_callsign=?)"
            args.extend([callsign, callsign])
        if since:
            sql += " AND ts>=?"
            args.append(since)
        if until:
            sql += " AND ts<=?"
            args.append(until)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args.extend([int(limit), int(offset)])
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, args).fetchall()]
            finally:
                conn.close()

    # ---------------- 黑名单流水 ----------------
    def add_blacklist_event(self, action, who, reason=None, until=None, operator=None,
                            as_type="username", ts=None):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("INSERT INTO blacklist_audit(action, as_type, who, reason, until, "
                             "operator, created_at) VALUES(?,?,?,?,?,?,?)",
                             (action, as_type, who, reason, until, operator,
                              ts or now_text()))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def active_blacklist(self, now=None):
        """
        当前生效名单：对每个 (who, as_type) 取最新一条流水，若最新是 ban 且未过期 → 生效。

        ⚠️ 两个必须注意的点：
          1) 必须按 **(who, as_type)** 分组。只按 who 分组时，同一个 who 在别的维度
             解封后仍会被旧的 ban 行遮住（真实故障：界面一直显示"拉黑中"）。
          2) 本表是**历史流水**，不是权威状态。权威是 EMQX 的实际封禁名单；
             在 EMQX 侧直接解封（或封禁到期）时这里不会自动出现 unban 行。
             调用方应拿 EMQX 的实时名单做核对/清理，见 bas_http 的 sync。
        """
        now = now or now_text()
        sql = """
        SELECT who, as_type, reason, until, operator, created_at FROM (
            SELECT who, as_type, reason, until, operator, created_at,
                   ROW_NUMBER() OVER (PARTITION BY who, as_type
                                      ORDER BY created_at DESC, id DESC) AS rn,
                   action
            FROM blacklist_audit
        ) WHERE rn=1 AND action='ban' AND (until IS NULL OR until='infinity' OR until > ?)
        ORDER BY created_at DESC
        """
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, (now,)).fetchall()]
            finally:
                conn.close()

    def blacklist_history(self, who=None, limit=200):
        sql = "SELECT * FROM blacklist_audit"
        args = []
        if who:
            sql += " WHERE who=?"
            args.append(who)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, args).fetchall()]
            finally:
                conn.close()

    def prune_audit_packets(self, days=30, scene=None):
        """
        清理旧的审计事件（默认保留 30 天）。
        scene 为空则清所有场景；给定 scene 只清该场景（例如只清历史的 fake_cert）。
        返回删除条数。
        """
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            conn = self._conn()
            try:
                if scene:
                    cur = conn.execute("DELETE FROM audit_packets WHERE ts < ? AND scene=?",
                                       (cutoff, str(scene)))
                else:
                    cur = conn.execute("DELETE FROM audit_packets WHERE ts < ?", (cutoff,))
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    def count_audit_packets(self, scene=None):
        with self._lock:
            conn = self._conn()
            try:
                if scene:
                    return conn.execute("SELECT COUNT(*) FROM audit_packets WHERE scene=?",
                                        (str(scene),)).fetchone()[0]
                return conn.execute("SELECT COUNT(*) FROM audit_packets").fetchone()[0]
            finally:
                conn.close()

    def latest_pkt_identity(self, clientids):
        """
        取这些 clientid **最近一次报文的包头身份** → {clientid: {...}}。

        为什么需要：认证事件（auth_ok）发生在 MQTT CONNECT 时，那时还没有任何 FMO 报文，
        所以它天生没有包头身份。界面上把两者关联起来，才不会看着像"数据丢了"。
        """
        ids = [str(x) for x in (clientids or []) if x]
        if not ids:
            return {}
        out = {}
        with self._lock:
            conn = self._conn()
            try:
                qs = ",".join("?" for _ in ids)
                sql = ("SELECT clientid, pkt_callsign, pkt_uid, ts FROM audit_packets "
                       "WHERE pkt_callsign IS NOT NULL AND pkt_callsign != '' "
                       "AND clientid IN (%s) ORDER BY id DESC" % qs)
                for r in conn.execute(sql, ids):
                    cid = str(r["clientid"])
                    if cid not in out:            # 倒序取，第一条即最近
                        out[cid] = {"pkt_callsign": r["pkt_callsign"],
                                    "pkt_uid": r["pkt_uid"], "ts": r["ts"]}
                return out
            finally:
                conn.close()

    # ---------------- 连接登记（最近在线） ----------------
    def add_client_seen(self, callsign, uid="", clientid="", peerhost="", ts=None):
        """
        记一笔"某客户端刚认证通过"。
        节流：同一 clientid 在 20 秒内只记一次（重连风暴时不刷爆库）。
        返回 True 表示本次写入。
        """
        ts = ts or now_text(True)
        with self._lock:
            conn = self._conn()
            try:
                if clientid:
                    row = conn.execute(
                        "SELECT ts FROM client_seen WHERE clientid=? ORDER BY id DESC LIMIT 1",
                        (str(clientid),)).fetchone()
                    if row and row[0]:
                        try:
                            from datetime import datetime
                            prev = datetime.fromisoformat(str(row[0])).timestamp()
                            cur = datetime.fromisoformat(str(ts)).timestamp()
                            if cur - prev < 20:
                                return False
                        except Exception:  # noqa: BLE001
                            pass
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO client_seen(ts, callsign, uid, clientid, peerhost) "
                    "VALUES(?,?,?,?,?)",
                    (str(ts), str(callsign or ""), str(uid or ""),
                     str(clientid or ""), str(peerhost or "")))
                conn.execute("COMMIT;")
                return True
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def recent_clients(self, minutes=30, limit=200):
        """
        最近 N 分钟内认证通过过的**用户**（按呼号聚合）→ "最近在线"视图。

        为什么需要：手机 APP 常见频繁短线重连（实测某用户每分钟换 clientid 重连、
        单次会话仅几十秒），只看"当前在线"会以为他从没上线。
        """
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(minutes=int(minutes))).strftime(
            "%Y-%m-%d %H:%M:%S")
        sql = """
        SELECT callsign,
               MAX(ts)       AS last_seen,
               COUNT(*)      AS hits,
               COUNT(DISTINCT clientid) AS conns,
               MAX(clientid) AS last_clientid,
               MAX(peerhost) AS last_ip,
               MAX(uid)      AS uid
        FROM client_seen
        WHERE ts >= ?
        GROUP BY callsign
        ORDER BY last_seen DESC
        LIMIT ?
        """
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, (cutoff, int(limit))).fetchall()]
            finally:
                conn.close()

    def prune_client_seen(self, days=7):
        """清理过期的连接登记（默认保留 7 天）"""
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute("DELETE FROM client_seen WHERE ts < ?", (cutoff,))
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    # ---------------- 未信任根台账 ----------------
    def note_untrusted_root(self, root_pubkey, callsign="", clientid="", peerhost="",
                            ts=None):
        """
        记一笔「未信任的根 CA」。同一根重复出现只累加计数与更新时间，
        并统计自称呼号去重个数（撞库的典型特征：换着呼号试）。
        返回该根当前的累计条数记录。
        """
        key = str(root_pubkey or "").strip()
        if not key:
            return None
        ts = ts or now_text(True)
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                row = conn.execute(
                    "SELECT id, first_ts, hits, distinct_cs FROM untrusted_roots "
                    "WHERE root_pubkey = ?", (key,)).fetchone()
                cs = str(callsign or "").strip().upper()
                if row is None:
                    conn.execute(
                        "INSERT INTO untrusted_roots(root_pubkey, ts, first_ts, hits, "
                        "last_callsign, last_clientid, last_ip, distinct_cs) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (key, ts, ts, 1, cs or None, clientid or None,
                         peerhost or None, 1 if cs else 0))
                    rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                else:
                    rid = row["id"]
                    n_cs = int(row["distinct_cs"] or 0)
                    if cs:
                        prev = conn.execute(
                            "SELECT last_callsign FROM untrusted_roots WHERE id=?",
                            (rid,)).fetchone()
                        prev_cs = (prev["last_callsign"] or "") if prev else ""
                        # 只有自称呼号变了才算新增（只记最后一个呼号，够用且省事）
                        if prev_cs != cs:
                            n_cs += 1
                    conn.execute(
                        "UPDATE untrusted_roots SET ts=?, hits=hits+1, "
                        "last_callsign=?, last_clientid=?, last_ip=?, distinct_cs=? "
                        "WHERE id=?",
                        (ts, cs or None, clientid or None, peerhost or None, n_cs, rid))
                conn.execute("COMMIT;")
                cur = conn.execute("SELECT * FROM untrusted_roots WHERE id=?", (rid,)).fetchone()
                return dict(cur) if cur else None
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def list_untrusted_roots(self, limit=50):
        """未信任根列表（最近出现的在前）"""
        with self._lock:
            conn = self._conn()
            try:
                sql = ("SELECT * FROM untrusted_roots ORDER BY ts DESC LIMIT ?")
                return [dict(r) for r in conn.execute(sql, (int(limit),)).fetchall()]
            finally:
                conn.close()

    def prune_untrusted_roots(self, days=90):
        """清理长期没再出现的根（默认 90 天）"""
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(days=int(days))).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            conn = self._conn()
            try:
                cur = conn.execute("DELETE FROM untrusted_roots WHERE ts < ?", (cutoff,))
                conn.commit()
                return cur.rowcount
            finally:
                conn.close()

    # ---------------- 待审队列（BAS 新增：误封救援） ----------------
    def add_quarantine(self, row):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO bas_quarantine(created_at, conn_callsign, conn_uid, pkt_callsign, "
                    "pkt_uid, clientid, scene, reason, confidence, status) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (row.get("created_at") or now_text(True), row.get("conn_callsign"),
                     row.get("conn_uid"), row.get("pkt_callsign"), row.get("pkt_uid"),
                     row.get("clientid"), row.get("scene"), row.get("reason"),
                     row.get("confidence"), row.get("status") or "pending"))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    def list_quarantine(self, status="pending", limit=200):
        with self._lock:
            conn = self._conn()
            try:
                if status:
                    rows = conn.execute("SELECT * FROM bas_quarantine WHERE status=? "
                                        "ORDER BY id DESC LIMIT ?", (status, int(limit))).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM bas_quarantine ORDER BY id DESC LIMIT ?",
                                        (int(limit),)).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def resolve_quarantine(self, qid, status, by="admin"):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("UPDATE bas_quarantine SET status=?, resolved_at=?, resolved_by=? "
                             "WHERE id=?", (status, now_text(True), by, int(qid)))
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()

    # ---------------- 查询：排行榜 / 主题统计 / 在线 ----------------
    def leaderboard(self, since=None, until=None, limit=100, group="callsign", min_bytes=0):
        """按呼号（或 clientid）聚合流量。上游语义：GROUP BY COALESCE(username, clientid)。"""
        since = since or _days_ago_text(self.retention_days)
        until = until or now_text()
        key = "COALESCE(NULLIF(callsign,''), NULLIF(username,''), clientid)" if group == "callsign" \
            else "clientid"
        sql = """
        SELECT %s AS name,
               SUM(send_msg+recv_msg) AS msgs,
               SUM(send_oct+recv_oct) AS bytes,
               SUM(send_pkt+recv_pkt) AS pkts,
               COUNT(DISTINCT clientid) AS clients,
               MAX(ts) AS last_seen
        FROM minute_stats WHERE ts>=? AND ts<=?
        GROUP BY name HAVING bytes>=? ORDER BY bytes DESC LIMIT ?
        """ % key
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, (since, until, int(min_bytes),
                                                            int(limit))).fetchall()]
            finally:
                conn.close()

    def leaderboard_detail(self, name, since=None, until=None, limit=200):
        since = since or _days_ago_text(self.retention_days)
        until = until or now_text()
        sql = """
        SELECT clientid, COALESCE(NULLIF(callsign,''), username) AS name, ip_address,
               SUM(send_msg+recv_msg) AS msgs, SUM(send_oct+recv_oct) AS bytes,
               SUM(reconnect) AS reconnects, MIN(ts) AS first_seen, MAX(ts) AS last_seen
        FROM minute_stats
        WHERE ts>=? AND ts<=? AND (callsign=? OR username=? OR clientid=?)
        GROUP BY clientid ORDER BY bytes DESC LIMIT ?
        """
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(
                    sql, (since, until, name, name, name, int(limit))).fetchall()]
            finally:
                conn.close()

    def topic_timeline(self, topic=None, since=None, until=None, bucket="10s", limit=20000):
        """
        主题时间轴：按粒度降采样（10s 原样 / 1m / 5m / 1h）。
        上游是查询时用 substr/printf 计算（BAS 沿用，避免物化表）。
        """
        since = since or _hours_ago_text(6)
        until = until or now_text()
        if bucket == "10s":
            expr = "ts"
        elif bucket == "1m":
            expr = "substr(ts,1,16) || ':00'"
        elif bucket == "5m":
            # 分钟向下取整到 5 的倍数（对齐上游"截断"语义）
            expr = ("substr(ts,1,14) || printf('%02d', (CAST(substr(ts,15,2) AS INTEGER)/5)*5) || ':00'")
        elif bucket == "1h":
            expr = "substr(ts,1,13) || ':00:00'"
        else:
            expr = "ts"
        sql = """
        SELECT %s AS bucket,
               COALESCE(NULLIF(callsign,''), NULLIF(username,''), clientid) AS name,
               SUM(msgs) AS msgs, SUM(bytes) AS bytes
        FROM topic_stats WHERE ts>=? AND ts<=?
        %s
        GROUP BY bucket, name ORDER BY bucket ASC, bytes DESC LIMIT ?
        """ % (expr, "AND topic=? " if topic else "")
        args = [since, until] + ([topic] if topic else []) + [int(limit)]
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(sql, args).fetchall()]
            finally:
                conn.close()

    def top_by_bucket(self, topic=None, since=None, until=None, top=5):
        rows = self.topic_timeline(topic, since, until, "10s", limit=100000)
        buckets = {}
        for r in rows:
            b = r["bucket"]
            buckets.setdefault(b, []).append({"name": r["name"], "msgs": r["msgs"],
                                              "bytes": r["bytes"]})
        out = []
        for b in sorted(buckets.keys()):
            top_rows = sorted(buckets[b], key=lambda x: -(x["bytes"] or 0))[:top]
            out.append({"bucket": b, "top": top_rows,
                        "total_bytes": sum((x["bytes"] or 0) for x in buckets[b])})
        return out

    def health_series(self, since=None, until=None, limit=2000):
        since = since or _hours_ago_text(6)
        until = until or now_text()
        with self._lock:
            conn = self._conn()
            try:
                return [dict(r) for r in conn.execute(
                    "SELECT * FROM health_snapshots WHERE ts>=? AND ts<=? ORDER BY ts ASC LIMIT ?",
                    (since, until, int(limit))).fetchall()]
            finally:
                conn.close()

    # ---------------- 清理 ----------------
    def cleanup(self, days=None, force=False):
        """按保留天数清理统计与审计表，并按行数上限裁剪流水表。返回各表删除行数。"""
        days = int(days or self.retention_days)
        cutoff = _days_ago_text(days)
        result = {}
        with self._lock:
            conn = self._conn()
            try:
                for table in ("minute_stats", "topic_stats", "health_snapshots", "audit_packets"):
                    deleted = self._delete_before(conn, table, cutoff)
                    result[table] = deleted
                # 行数上限裁剪（上游没有，防无限增长）
                result["audit_packets_trim"] = self._trim_table(
                    conn, "audit_packets", AUDIT_MAX_ROWS)
                result["blacklist_audit_trim"] = self._trim_table(
                    conn, "blacklist_audit", BLACKLIST_AUDIT_MAX_ROWS)
            finally:
                conn.close()
        return result

    @staticmethod
    def _delete_before(conn, table, cutoff):
        """SQLite 不支持 DELETE ... LIMIT，用 rowid 子查询分批删（对齐上游）。"""
        total = 0
        for _ in range(CLEAN_MAX_BATCHES):
            conn.execute("BEGIN IMMEDIATE;")
            cur = conn.execute(
                "DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE ts < ? LIMIT %d)"
                % (table, table, CLEAN_BATCH), (cutoff,))
            n = cur.rowcount or 0
            conn.execute("COMMIT;")
            total += n
            if n < CLEAN_BATCH:
                break
        return total

    @staticmethod
    def _trim_table(conn, table, max_rows):
        conn.execute("BEGIN IMMEDIATE;")
        row = conn.execute("SELECT COUNT(*) AS c FROM %s" % table).fetchone()
        count = int(row["c"] if row else 0)
        if count <= max_rows:
            conn.execute("COMMIT;")
            return 0
        excess = count - max_rows
        conn.execute("DELETE FROM %s WHERE rowid IN "
                     "(SELECT rowid FROM %s ORDER BY id ASC LIMIT %d)" % (table, table, excess))
        conn.execute("COMMIT;")
        return excess

    def stats_summary(self):
        with self._lock:
            conn = self._conn()
            try:
                out = {}
                for t in ("minute_stats", "topic_stats", "audit_packets",
                          "blacklist_audit", "health_snapshots", "bas_quarantine"):
                    row = conn.execute("SELECT COUNT(*) AS c FROM %s" % t).fetchone()
                    out[t] = int(row["c"] if row else 0)
                return out
            finally:
                conn.close()

    def clear_all(self, keep_blacklist=True):
        """清空统计数据（保留配置与管理员）。修正上游漏删 audit_packets 的缺陷。"""
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for t in ("minute_stats", "topic_stats", "health_snapshots", "audit_packets",
                          "bas_quarantine"):
                    conn.execute("DELETE FROM %s" % t)
                if not keep_blacklist:
                    conn.execute("DELETE FROM blacklist_audit")
                conn.execute("COMMIT;")
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:  # noqa: BLE001
                    pass
                raise
            finally:
                conn.close()


def _days_ago_text(days):
    return time.strftime(TIME_FMT, time.localtime(time.time() - days * 86400))


def _hours_ago_text(hours):
    return time.strftime(TIME_FMT, time.localtime(time.time() - hours * 3600))
