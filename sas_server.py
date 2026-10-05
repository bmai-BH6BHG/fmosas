#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO SAS 认证服务
================
Python 实现的 SAS（认证授权服务），替代 Rust 编译的 sas.exe。
支持分布式架构和交叉认证（信任链）。

功能接口：
  1. POST /auth              — MQTT 客户端认证（验证 Ed25519 证书链 → allow/deny）
  2. POST /api/cert/issue    — 证书签发（用本地 Int CA 签发 User Cert + Device Key）
  3. POST /api/trust/add     — 添加信任的远程 CA
     GET  /api/trust/list    — 列出所有信任的远程 CA
     DELETE /api/trust/{id}  — 删除信任的远程 CA
  4. GET  /api/ca/info       — 返回本地 Root CA + Int CA 信息
     POST /api/ca/init       — 初始化本地 CA
     POST /api/ca/renew      — 更新（轮换）CA 证书

架构：
  APP → MQTT CONNECT → broker (1883) → POST /auth → SAS (8080) → allow/deny

认证流程（POST /auth，与官方/APP 统一的老 FMO 格式）：
  - username = 明文呼号（如 "BH6BHG"）
  - password = base64url(JSON{certPackage{intermediateCert,userCert}, 目标字段..., proof{signature}})
  - 验证证书链：User Cert 由 Int CA 签发，Int CA 由其 issuer.publicKey（根）签发
  - 验证 proof 签名（12 元素 CBOR TBS，证明持有与 User Cert 配套的私钥）
  - 根 CA 信任判定（按根公钥，任一即可）：
      a. 本机 CA（分系统自己签发）
      b. 内置官方根 BG5ESN（ESN 体系，天然互认，不经 master、无需配置）
      c. roots 目录接种的第三方根（江苏等，手动放入/add-root.sh，重启生效）
      d. trust_chain 信任链表（master 同步下发的分系统互认，自动）
  - 返回 {result:"allow", acl:[...], client_attrs:{callsign,uid}, is_superuser:false}

数据库：SQLite3（certificates / trust_chain / ca_info 三表）
默认端口：8080（SAS 标准端口）
HTTP 服务：ThreadingHTTPServer 多线程

用法：
  python sas_server.py
  python sas_server.py --port 8080 --config config.json --ca-dir ./ca
"""

import argparse
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ============================================================
#  复用 cert_gen.py 的证书生成/验证逻辑
#  查找顺序：本目录 → 上级目录 → D:\fmo-server-deploy（开发环境兜底）
#  注意：本目录必须最优先（insert），兜底目录只能 append——
#  若兜底插到最前，旧版 cert_gen.py 会遮蔽本目录新版。
# ============================================================
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
for _p in (os.path.dirname(_HERE), r"D:\fmo-server-deploy"):
    if _p not in sys.path:
        sys.path.append(_p)

from cert_gen import (
    generate_keypair, ed25519_sign, ed25519_verify, pubkey_from_seed,
    b64url_encode, b64url_decode,
    cbor_tbs, cert_fingerprint, fingerprint_b64url,
    now_ts, years_to_seconds, ts_to_str,
    root_ca_tbs, intermediate_ca_tbs, user_cert_tbs,
    build_root_ca, build_intermediate_ca, build_user_cert, build_device_key,
    validate_root_ca_cert,
)


# ============================================================
#  内置信任的官方根 CA（根公钥 → 名称）
#  说明：分系统自身的 CA 完全独立运作，官方服务是否在线不影响本系统。
#  此处仅做"兼容互认"：ESN 官方体系（根为 BG5ESN）签发的证书
#  可直接登录本分系统，无需 master 背书、无需管理员手动配置。
#  江苏（根为 BD4RFG）及其他第三方 CA 不内置，需手动接种：
#  将其根证书 JSON 放入 roots 目录（或运行官方 add-root.sh），重启生效。
# ============================================================
OFFICIAL_ROOT_PUBKEYS = {
    "DCeeVS320f36ToVP2eOADVN-Q0LzpMYmiVkmNYzuysY": "BG5ESN",
}


# ============================================================
#  配置里追加信任的根公钥（trust.extraRootPubkeys）
#
#  用途：**本机 CA 被重新生成后，旧 CA 根签发的证书也要继续能用**。
#  真实事故：CA 文件在某次重启/重建时被重新生成（换了根），
#  所有此前签发的证书（含国服 8601 绑定流程签发的）立刻被判
#  "根 CA 不受信任" → 全体用户登录不了。
#  把旧根公钥列在 config.json 的 trust.extraRootPubkeys 里即可继续信任它，
#  新根照常给新绑定签发，两代证书并存。
# ============================================================
_CONFIG_EXTRA_ROOTS_CACHE = None


def get_config_extra_root_pubkeys() -> set:
    """
    读取 config.json → trust.extraRootPubkeys（字符串或数组）。
    注意：**直接读文件**，不走 load_config —— 后者只保留已知键，会把 trust 丢掉。
    结果缓存（改配置后需重启生效，与 roots 目录一致）。
    """
    global _CONFIG_EXTRA_ROOTS_CACHE
    if _CONFIG_EXTRA_ROOTS_CACHE is not None:
        return _CONFIG_EXTRA_ROOTS_CACHE
    out = set()
    try:
        p = os.path.join(_HERE, "config.json")
        with open(p, "r", encoding="utf-8-sig") as f:
            raw_cfg = json.load(f)
        raw = ((raw_cfg or {}).get("trust") or {}).get("extraRootPubkeys")
        if isinstance(raw, str):
            raw = [raw]
        for x in (raw or []):
            x = str(x).strip()
            if x:
                out.add(x)
    except Exception:  # noqa: BLE001
        pass
    _CONFIG_EXTRA_ROOTS_CACHE = out
    return out


# ============================================================
#  数据库命名前缀工具（基于域名/IP，避免多系统部署冲突）
# ============================================================

def _sanitize_db_name(name):
    """将域名/IP 转为安全的文件名部分（只保留字母数字、点、减号）"""
    safe = re.sub(r'[^a-zA-Z0-9.\-]', '_', str(name)).strip('._')
    return safe if safe else 'default'


def get_db_prefix(config=None, default='default'):
    """
    从配置中提取域名/IP，用于数据库命名前缀。
    优先级：config['domain'] > config['api_url']解析 > config['app_domain'] > 本机IP
    """
    config = config or {}
    # 1. 从 domain 字段获取
    domain = config.get('domain', '')
    if domain and domain not in ('register.example.com', 'localhost', '127.0.0.1', ''):
        return _sanitize_db_name(domain)
    # 2. 从 api_url 解析
    api_url = config.get('api_url', '')
    if api_url:
        try:
            parsed = urlparse(api_url)
            host = parsed.hostname
            if host and host not in ('localhost', '127.0.0.1', ''):
                return _sanitize_db_name(host)
        except Exception:
            pass
    # 3. 从 app_domain 获取
    app_domain = config.get('app_domain', '')
    if app_domain:
        return _sanitize_db_name(app_domain)
    # 4. 用本机 IP
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return _sanitize_db_name(ip)
    except Exception:
        return default


def _migrate_db(new_path, old_names):
    """
    数据库自动迁移：如果新数据库不存在但旧数据库存在，自动重命名。
    用于从旧命名（如 sas.db）平滑升级到新命名（如 {prefix}_sas.db），避免数据丢失。
    """
    if os.path.exists(new_path):
        return  # 新数据库已存在，无需迁移
    for old_name in old_names:
        old_path = os.path.join(os.path.dirname(new_path), old_name)
        if os.path.exists(old_path):
            try:
                os.rename(old_path, new_path)
                print("[DB] 自动迁移: %s -> %s" % (old_path, new_path))
                return
            except Exception as e:
                print("[DB] 迁移失败: %s -> %s, %s" % (old_path, new_path, e))
                return


# ============================================================
#  配置加载
# ============================================================

DEFAULT_CONFIG = {
    "port": 8080,
    "ca_dir": os.path.join(_HERE, "ca"),
    "db_path": os.path.join(_HERE, "%s_sas.db" % get_db_prefix()),
    "ca_name": "MYCA",
    "ca_email": "",
    "validity_years": 10,
    "uid_start": 1,
    "uid_end": 200000,
    "issuing_countries": ["CN"],
}


def load_config(config_path: str) -> dict:
    """
    加载配置文件，合并默认值。
    支持两种格式：
      1) 顶层含 "sas" 节点：{"sas": {"port": 8080, ...}, ...}
      2) 顶层直接是 SAS 配置：{"port": 8080, ...}
    """
    cfg = dict(DEFAULT_CONFIG)
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            sas_cfg = data.get("sas", data)
            for k in DEFAULT_CONFIG:
                if k in sas_cfg:
                    cfg[k] = sas_cfg[k]
        except Exception as e:
            print(f"[WARN] 读取配置失败 {config_path}: {e}，使用默认配置")
    return cfg


# ============================================================
#  数据库管理（SQLite3，线程安全）
# ============================================================

class Database:
    """
    SQLite3 数据库封装，线程安全（全局锁 + check_same_thread=False）。
    表结构：
      certificates  — 已签发的用户证书
      trust_chain   — 信任的远程 CA
      ca_info       — 本地 CA 元信息
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        # WAL 模式：允许 sync_engine 开第二个连接并发读取，避免读写互锁
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA busy_timeout=10000;")
        self._init_tables()

    def _init_tables(self):
        with self._lock:
            cur = self._conn.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id                   TEXT PRIMARY KEY,
                    callsign             TEXT NOT NULL,
                    uid                  INTEGER NOT NULL,
                    cert_user_json       TEXT NOT NULL,
                    cert_devicekey_json  TEXT NOT NULL,
                    fingerprint          TEXT NOT NULL,
                    issued_at            INTEGER NOT NULL,
                    revoked              INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_cert_callsign ON certificates(callsign);
                CREATE INDEX IF NOT EXISTS idx_cert_uid      ON certificates(uid);
                CREATE INDEX IF NOT EXISTS idx_cert_fp       ON certificates(fingerprint);

                CREATE TABLE IF NOT EXISTS trust_chain (
                    id                    TEXT PRIMARY KEY,
                    remote_ca_fingerprint TEXT NOT NULL,
                    remote_ca_json        TEXT NOT NULL,
                    ca_type               TEXT DEFAULT 'rootCA',
                    trusted_by            TEXT,
                    created_at            INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_trust_fp ON trust_chain(remote_ca_fingerprint);

                CREATE TABLE IF NOT EXISTS ca_info (
                    id            INTEGER PRIMARY KEY CHECK (id = 1),
                    root_cert_json TEXT NOT NULL,
                    int_cert_json  TEXT NOT NULL,
                    root_seed      TEXT NOT NULL,
                    int_seed       TEXT NOT NULL,
                    ca_name        TEXT,
                    root_fingerprint TEXT,
                    int_fingerprint  TEXT,
                    created_at     INTEGER NOT NULL,
                    updated_at     INTEGER NOT NULL
                );
            """)
            # ---- 同步字段迁移：增量同步与墓碑传播依赖 last_modified / deleted ----
            if not self._column_exists(cur, 'certificates', 'last_modified'):
                cur.execute("ALTER TABLE certificates ADD COLUMN last_modified INTEGER DEFAULT 0")
                cur.execute("UPDATE certificates SET last_modified = issued_at WHERE last_modified = 0")
            if not self._column_exists(cur, 'trust_chain', 'last_modified'):
                cur.execute("ALTER TABLE trust_chain ADD COLUMN last_modified INTEGER DEFAULT 0")
                cur.execute("UPDATE trust_chain SET last_modified = created_at WHERE last_modified = 0")
            if not self._column_exists(cur, 'trust_chain', 'deleted'):
                cur.execute("ALTER TABLE trust_chain ADD COLUMN deleted INTEGER DEFAULT 0")
            # 国服ID绑定证书：私钥由客户端从密码派生，服务器不持有 seed（devicekey_json 为空）
            if not self._column_exists(cur, 'certificates', 'derived'):
                cur.execute("ALTER TABLE certificates ADD COLUMN derived INTEGER DEFAULT 0")
            self._conn.commit()

    @staticmethod
    def _column_exists(cur, table: str, column: str) -> bool:
        cur.execute("PRAGMA table_info(%s)" % table)
        return any(row[1] == column for row in cur.fetchall())

    # ---------- certificates ----------

    def add_certificate(self, callsign: str, uid: int,
                        cert_user_json: str, cert_devicekey_json: str,
                        fingerprint: str, derived: bool = False) -> str:
        """
        记录已签发的用户证书，返回记录 id。
        derived=True 表示「国服ID绑定证书」：私钥由客户端从密码派生，
        cert_devicekey_json 为空，服务器不持有用户私钥 seed。
        """
        cid = uuid.uuid4().hex
        ts = now_ts()
        with self._lock:
            self._conn.execute(
                "INSERT INTO certificates "
                "(id, callsign, uid, cert_user_json, cert_devicekey_json, fingerprint, issued_at, revoked, last_modified, derived) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                (cid, callsign, uid, cert_user_json, cert_devicekey_json,
                 fingerprint, ts, ts, 1 if derived else 0),
            )
            self._conn.commit()
        return cid

    def get_certificate_by_fp(self, fingerprint: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return dict(row) if row else None

    def revoke_certificate(self, fingerprint: str) -> bool:
        with self._lock:
            # 刷新 last_modified，让吊销状态能通过增量同步传播到总系统/其他分系统
            cur = self._conn.execute(
                "UPDATE certificates SET revoked = 1, last_modified = ? WHERE fingerprint = ?",
                (now_ts(), fingerprint),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def list_certificates(self, limit: int = 100) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, callsign, uid, fingerprint, issued_at, revoked, derived "
                "FROM certificates ORDER BY issued_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def is_revoked(self, fingerprint: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT revoked FROM certificates WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        return bool(row and row["revoked"])

    def get_certificate_by_callsign(self, callsign: str) -> dict:
        """查询某呼号最新一张未吊销的证书（含完整 JSON），无则返回 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE callsign = ? AND revoked = 0 "
                "ORDER BY issued_at DESC LIMIT 1",
                (callsign,),
            ).fetchone()
        return dict(row) if row else None

    def get_latest_certificate_by_callsign(self, callsign: str) -> dict:
        """查询某呼号最近一张证书（含已吊销，用于国服ID绑定复用 UID 判断），无则 None。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE callsign = ? "
                "ORDER BY issued_at DESC LIMIT 1",
                (callsign,),
            ).fetchone()
        return dict(row) if row else None

    def get_max_uid(self) -> int:
        """返回已占用 UID 的最大值（含已吊销记录，UID 不复用），无记录返回 0。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(uid) AS m FROM certificates"
            ).fetchone()
        return int(row["m"] or 0)

    # ---------- trust_chain ----------

    def add_trust(self, remote_ca_fingerprint: str, remote_ca_json: str,
                  ca_type: str = "rootCA", trusted_by: str = "") -> str:
        """添加信任的远程 CA，返回 id。若指纹已存在则更新（含复活已删除记录）。"""
        tid = uuid.uuid4().hex
        ts = now_ts()
        with self._lock:
            existing = self._conn.execute(
                "SELECT id FROM trust_chain WHERE remote_ca_fingerprint = ?",
                (remote_ca_fingerprint,),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE trust_chain SET remote_ca_json = ?, ca_type = ?, "
                    "trusted_by = ?, created_at = ?, last_modified = ?, deleted = 0 WHERE id = ?",
                    (remote_ca_json, ca_type, trusted_by, ts, ts, existing["id"]),
                )
                tid = existing["id"]
            else:
                self._conn.execute(
                    "INSERT INTO trust_chain "
                    "(id, remote_ca_fingerprint, remote_ca_json, ca_type, trusted_by, created_at, last_modified, deleted) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                    (tid, remote_ca_fingerprint, remote_ca_json, ca_type,
                     trusted_by, ts, ts),
                )
            self._conn.commit()
        return tid

    def list_trust(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, remote_ca_fingerprint, ca_type, trusted_by, created_at "
                "FROM trust_chain WHERE deleted = 0 ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_trust_by_fp(self, fingerprint: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM trust_chain WHERE remote_ca_fingerprint = ? AND deleted = 0",
                (fingerprint,),
            ).fetchone()
        return dict(row) if row else None

    def delete_trust(self, tid: str) -> bool:
        with self._lock:
            # soft delete：保留墓碑，删除状态才能通过同步传播到总系统/其他分系统
            cur = self._conn.execute(
                "UPDATE trust_chain SET deleted = 1, last_modified = ? WHERE id = ?",
                (now_ts(), tid),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def is_trusted(self, fingerprint: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM trust_chain WHERE remote_ca_fingerprint = ? AND deleted = 0",
                (fingerprint,),
            ).fetchone()
        return row is not None

    def trusted_root_pubkeys(self) -> set:
        """返回信任链中所有远程 CA 的根公钥（base64url）集合。"""
        pubs = set()
        with self._lock:
            rows = self._conn.execute(
                "SELECT remote_ca_json FROM trust_chain WHERE deleted = 0"
            ).fetchall()
        for r in rows:
            try:
                ca = json.loads(r["remote_ca_json"])
                pub = ca.get("subject", {}).get("publicKey")
                if pub:
                    pubs.add(pub)
            except Exception:
                continue
        return pubs

    # ---------- ca_info ----------

    def save_ca_info(self, root_cert: dict, int_cert: dict,
                     root_seed: bytes, int_seed: bytes,
                     ca_name: str, root_fp: str, int_fp: str):
        """保存/更新本地 CA 信息到数据库。"""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ca_info "
                "(id, root_cert_json, int_cert_json, root_seed, int_seed, "
                " ca_name, root_fingerprint, int_fingerprint, created_at, updated_at) "
                "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (json.dumps(root_cert, ensure_ascii=False),
                 json.dumps(int_cert, ensure_ascii=False),
                 b64url_encode(root_seed), b64url_encode(int_seed),
                 ca_name, root_fp, int_fp, now_ts(), now_ts()),
            )
            self._conn.commit()

    def get_ca_info(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ca_info WHERE id = 1"
            ).fetchone()
        return dict(row) if row else None

    def close(self):
        with self._lock:
            self._conn.close()


# ============================================================
#  CA 管理器（Root CA + Intermediate CA）
# ============================================================

class CaManager:
    """
    管理本地 Root CA + Intermediate CA。
    CA 私钥和证书同时存文件（ca_dir）和数据库（ca_info 表）。
    """

    def __init__(self, ca_dir: str, db: Database,
                 ca_name: str = "MYCA", ca_email: str = "",
                 validity_years: int = 10,
                 uid_start: int = 1, uid_end: int = 200000,
                 issuing_countries: list = None):
        self.ca_dir = ca_dir
        self.db = db
        self.ca_name = ca_name
        self.ca_email = ca_email
        self.validity_years = validity_years
        self.uid_start = uid_start
        self.uid_end = uid_end
        self.issuing_countries = issuing_countries or ["CN"]

        self.root_cert = None
        self.int_cert = None
        self.root_seed = None
        self.int_seed = None
        self.root_fingerprint = None
        self.int_fingerprint = None

        os.makedirs(ca_dir, exist_ok=True)

    # ---------- 文件路径 ----------

    @property
    def root_path(self):
        return os.path.join(self.ca_dir, "cert_root.json")

    @property
    def int_path(self):
        return os.path.join(self.ca_dir, "cert_int.json")

    @property
    def ca_private_path(self):
        return os.path.join(self.ca_dir, "ca_private.json")

    # ---------- 指纹计算 ----------

    @staticmethod
    def compute_root_fingerprint(root_cert: dict) -> str:
        """计算 Root CA 证书指纹（base64url）。"""
        root_pub = b64url_decode(root_cert["subject"]["publicKey"])
        tbs = root_ca_tbs(
            sn=root_cert["sn"],
            issuer_name=root_cert["issuer"]["name"],
            issuer_email=root_cert["issuer"]["email"],
            subject_name=root_cert["subject"]["name"],
            pubkey=root_pub,
            is_ca=True,
            path_len=root_cert["extensions"]["pathLen"],
            crl=root_cert["extensions"]["crl"],
            license=root_cert["extensions"]["license"],
            key_id=root_cert["extensions"]["keyId"],
            iat=root_cert["iat"],
            exp=root_cert["exp"],
        )
        return fingerprint_b64url(tbs)

    @staticmethod
    def compute_int_fingerprint(int_cert: dict) -> str:
        """计算 Intermediate CA 证书指纹（base64url）。"""
        int_pub = b64url_decode(int_cert["subject"]["publicKey"])
        tbs = intermediate_ca_tbs(
            sn=int_cert["sn"],
            issuer_sn=int_cert["issuer"]["sn"],
            issuer_name=int_cert["issuer"]["name"],
            issuer_pubkey=b64url_decode(int_cert["issuer"]["publicKey"]),
            subject_name=int_cert["subject"]["name"],
            subject_email=int_cert["subject"]["email"],
            pubkey=int_pub,
            is_ca=True,
            path_len=int_cert["extensions"]["pathLen"],
            key_id=int_cert["extensions"]["keyId"],
            crl=int_cert["extensions"]["crl"],
            license=int_cert["extensions"]["license"],
            uid_start=int_cert["extensions"]["uidRange"]["start"],
            uid_end=int_cert["extensions"]["uidRange"]["end"],
            issuing_countries=int_cert["extensions"]["issuingCountries"],
            iat=int_cert["iat"],
            exp=int_cert["exp"],
        )
        return fingerprint_b64url(tbs)

    @staticmethod
    def compute_user_fingerprint(user_cert: dict) -> str:
        """计算 User Cert 证书指纹（base64url），即 serverFingerprint。"""
        user_pub = b64url_decode(user_cert["subject"]["publicKey"])
        tbs = user_cert_tbs(
            user_cert["issuerSn"],
            user_cert["subject"]["callsign"],
            user_cert["subject"]["uid"],
            user_pub,
            user_cert["iat"],
            user_cert["exp"],
        )
        return fingerprint_b64url(tbs)

    # ---------- 初始化 / 加载 ----------

    def init(self, force: bool = False) -> bool:
        """
        初始化本地 CA。如果已存在且 force=False 则加载现有 CA。
        返回 True 表示新生成，False 表示加载已有。

        ★ 安全阀（真实事故）：原先只要三个 CA 文件里有**任何一个**读不到，
          `_try_load()` 失败就**静默重新生成**整套 CA —— 换根之后，此前签发的
          所有证书（含国服 8601 绑定流程签发的）立刻被判「根 CA 不受信任」，
          全体用户登录不了。
          现在：只要 ca/ 下**已存在任何 CA 文件**而加载失败，就**拒绝生成**
          （抛错），必须显式 force=True 才重建；且重建前自动备份整个 ca/ 目录。
        """
        if not force and self._try_load():
            return False
        existing = [p for p in (self.ca_private_path, self.root_path, self.int_path)
                    if os.path.exists(p)]
        if existing and not force:
            raise RuntimeError(
                "检测到已有 CA 文件但加载失败（%s）；**拒绝重新生成**，"
                "以免作废全部已签发证书。请检查文件权限/完整性后重启；"
                "确要重建请显式 force=True（会先自动备份 ca/）"
                % "、".join(os.path.basename(p) for p in existing))
        if existing:
            self._backup_ca_dir()
        self._generate()
        return True

    def _backup_ca_dir(self) -> str:
        """重建 CA 前把整个 ca/ 目录备份走（返回备份路径）"""
        import shutil
        import time as _t
        stamp = _t.strftime("%Y%m%d-%H%M%S")
        ca_dir = os.path.dirname(self.root_path) or "."
        dst = os.path.join(ca_dir, "backup-%s" % stamp)
        try:
            os.makedirs(dst, exist_ok=True)
            for fn in os.listdir(ca_dir):
                src = os.path.join(ca_dir, fn)
                if os.path.isfile(src) and fn.endswith(".json"):
                    shutil.copy2(src, os.path.join(dst, fn))
            print("[CA] 重建前已备份旧 CA → %s" % dst)
        except Exception as e:  # noqa: BLE001
            print("[CA] 备份旧 CA 失败: %s" % e)
        return dst

    def _try_load(self) -> bool:
        """尝试从文件或数据库加载已有 CA。"""
        # 优先从文件加载（含私钥）
        if (os.path.exists(self.ca_private_path)
                and os.path.exists(self.root_path)
                and os.path.exists(self.int_path)):
            try:
                with open(self.ca_private_path, "r", encoding="utf-8") as f:
                    priv = json.load(f)
                with open(self.root_path, "r", encoding="utf-8") as f:
                    self.root_cert = json.load(f)
                with open(self.int_path, "r", encoding="utf-8") as f:
                    self.int_cert = json.load(f)
                self.root_seed = b64url_decode(priv["root_seed"])
                self.int_seed = b64url_decode(priv["int_seed"])
                self.root_fingerprint = self.compute_root_fingerprint(self.root_cert)
                self.int_fingerprint = self.compute_int_fingerprint(self.int_cert)
                print(f"[CA] 已加载现有 CA: {self.ca_name}")
                print(f"  Root CA 指纹: {self.root_fingerprint}")
                print(f"  Int  CA 指纹: {self.int_fingerprint}")
                return True
            except Exception as e:
                print(f"[WARN] 从文件加载 CA 失败: {e}，将重新生成")

        # 从数据库加载
        info = self.db.get_ca_info()
        if info:
            try:
                self.root_cert = json.loads(info["root_cert_json"])
                self.int_cert = json.loads(info["int_cert_json"])
                self.root_seed = b64url_decode(info["root_seed"])
                self.int_seed = b64url_decode(info["int_seed"])
                self.root_fingerprint = info["root_fingerprint"]
                self.int_fingerprint = info["int_fingerprint"]
                self.ca_name = info["ca_name"] or self.ca_name
                # 回写文件（确保文件存在）
                self._save_files()
                print(f"[CA] 从数据库加载 CA: {self.ca_name}")
                return True
            except Exception as e:
                print(f"[WARN] 从数据库加载 CA 失败: {e}，将重新生成")
        return False

    def _generate(self):
        """生成新的 Root CA + Intermediate CA。"""
        # Root CA
        root_seed, root_pub = generate_keypair()
        self.root_cert, _ = build_root_ca(
            seed=root_seed, pub=root_pub,
            ca_name=self.ca_name, ca_email=self.ca_email,
            sn=1, validity_years=self.validity_years,
        )
        # Intermediate CA
        int_seed, int_pub = generate_keypair()
        self.int_cert, _ = build_intermediate_ca(
            seed=int_seed, pub=int_pub,
            root_cert=self.root_cert, root_seed=root_seed,
            ca_name=self.ca_name, ca_email=self.ca_email,
            sn=1001, validity_years=self.validity_years,
            uid_start=self.uid_start, uid_end=self.uid_end,
            issuing_countries=self.issuing_countries,
        )
        self.root_seed = root_seed
        self.int_seed = int_seed
        self.root_fingerprint = self.compute_root_fingerprint(self.root_cert)
        self.int_fingerprint = self.compute_int_fingerprint(self.int_cert)

        # 保存到文件和数据库
        self._save_files()
        self.db.save_ca_info(
            self.root_cert, self.int_cert,
            self.root_seed, self.int_seed,
            self.ca_name, self.root_fingerprint, self.int_fingerprint,
        )
        print(f"[CA] 已生成新 CA: {self.ca_name}")
        print(f"  Root CA 公钥: {self.root_cert['subject']['publicKey']}")
        print(f"  Root CA 指纹: {self.root_fingerprint}")
        print(f"  Int  CA 公钥: {self.int_cert['subject']['publicKey']}")
        print(f"  Int  CA 指纹: {self.int_fingerprint}")
        print(f"  CA 私钥文件 : {self.ca_private_path}（请勿泄露！）")

    def _save_files(self):
        """把 CA 证书和私钥写入文件。"""
        with open(self.root_path, "w", encoding="utf-8") as f:
            json.dump(self.root_cert, f, ensure_ascii=False, indent=2)
            f.write("\n")
        with open(self.int_path, "w", encoding="utf-8") as f:
            json.dump(self.int_cert, f, ensure_ascii=False, indent=2)
            f.write("\n")
        priv = {
            "root_seed": b64url_encode(self.root_seed),
            "int_seed": b64url_encode(self.int_seed),
            "ca_name": self.ca_name,
        }
        with open(self.ca_private_path, "w", encoding="utf-8") as f:
            json.dump(priv, f, indent=2)
            f.write("\n")

    def renew(self):
        """轮换 CA（重新生成）。已签发的用户证书将失效。"""
        self._generate()

    # ---------- 证书签发 ----------

    def issue_user_cert(self, callsign: str, uid: int,
                        validity_years: int = None) -> dict:
        """
        用本地 Int CA 私钥签发 User Cert + Device Key。
        返回 {root_cert, int_cert, user_cert, device_key, fingerprint}
        """
        if validity_years is None:
            validity_years = self.validity_years
        if self.int_cert is None:
            raise RuntimeError("CA 未初始化，请先调用 init()")

        user_seed, user_pub = generate_keypair()
        user_cert, user_tbs = build_user_cert(
            seed=user_seed, pub=user_pub,
            int_cert=self.int_cert, int_seed=self.int_seed,
            callsign=callsign, uid=uid, validity_years=validity_years,
        )
        device_key = build_device_key(user_seed, user_pub)
        fp = fingerprint_b64url(user_tbs)

        return {
            "root_cert": self.root_cert,
            "int_cert": self.int_cert,
            "user_cert": user_cert,
            "device_key": device_key,
            "fingerprint": fp,
        }

    def issue_user_cert_for_pubkey(self, callsign: str, uid: int,
                                   pubkey, validity_years: int = None) -> dict:
        """
        用外部提供的公钥签发用户证书（国服ID绑定用）。
        私钥（seed）由客户端用「国服ID + 密码」派生，服务器不生成、不持有。
        :param pubkey: 32 字节 Ed25519 公钥（bytes）
        :return: {root_cert, int_cert, user_cert, fingerprint}（无 device_key）
        """
        if validity_years is None:
            validity_years = self.validity_years
        if self.int_cert is None:
            raise RuntimeError("CA 未初始化，请先调用 init()")
        pubkey = bytes(pubkey)
        if len(pubkey) != 32:
            raise ValueError("pubkey 必须为 32 字节 Ed25519 公钥")
        user_cert, user_tbs = build_user_cert(
            None, pubkey, self.int_cert, self.int_seed,
            callsign, uid, validity_years,
        )
        fp = fingerprint_b64url(user_tbs)
        return {
            "root_cert": self.root_cert,
            "int_cert": self.int_cert,
            "user_cert": user_cert,
            "fingerprint": fp,
        }

    # ---------- 信息查询 ----------

    def info(self) -> dict:
        """返回本地 CA 公开信息。"""
        if self.root_cert is None:
            return {"initialized": False}
        return {
            "initialized": True,
            "ca_name": self.ca_name,
            "root_ca": {
                "sn": self.root_cert["sn"],
                "name": self.root_cert["subject"]["name"],
                "publicKey": self.root_cert["subject"]["publicKey"],
                "fingerprint": self.root_fingerprint,
                "iat": self.root_cert["iat"],
                "exp": self.root_cert["exp"],
                "iat_str": ts_to_str(self.root_cert["iat"]),
                "exp_str": ts_to_str(self.root_cert["exp"]),
            },
            "int_ca": {
                "sn": self.int_cert["sn"],
                "name": self.int_cert["subject"]["name"],
                "publicKey": self.int_cert["subject"]["publicKey"],
                "fingerprint": self.int_fingerprint,
                "iat": self.int_cert["iat"],
                "exp": self.int_cert["exp"],
                "iat_str": ts_to_str(self.int_cert["iat"]),
                "exp_str": ts_to_str(self.int_cert["exp"]),
                "uid_range": self.int_cert["extensions"]["uidRange"],
                "issuing_countries": self.int_cert["extensions"]["issuingCountries"],
            },
        }


# ============================================================
#  证书链验证（静默版本，不打印 [OK]）
# ============================================================

def verify_cert_chain(root_cert: dict, int_cert: dict,
                      user_cert: dict) -> tuple:
    """
    验证 Ed25519 证书链签名。
    返回 (ok: bool, issues: list, pubs: dict)。
      pubs = {root_pub, int_pub, user_pub}
    """
    issues = []
    try:
        root_pub = b64url_decode(root_cert["subject"]["publicKey"])
        int_pub = b64url_decode(int_cert["subject"]["publicKey"])
        user_pub = b64url_decode(user_cert["subject"]["publicKey"])
    except Exception as e:
        return False, [f"公钥解码失败: {e}"], {}

    # 1. Root CA 自签名
    try:
        root_tbs = root_ca_tbs(
            sn=root_cert["sn"],
            issuer_name=root_cert["issuer"]["name"],
            issuer_email=root_cert["issuer"]["email"],
            subject_name=root_cert["subject"]["name"],
            pubkey=root_pub,
            is_ca=True,
            path_len=root_cert["extensions"]["pathLen"],
            crl=root_cert["extensions"]["crl"],
            license=root_cert["extensions"]["license"],
            key_id=root_cert["extensions"]["keyId"],
            iat=root_cert["iat"],
            exp=root_cert["exp"],
        )
        root_sig = b64url_decode(root_cert["signature"])
        if not ed25519_verify(root_pub, cbor_tbs(root_tbs), root_sig):
            issues.append("Root CA 自签名验证失败")
    except Exception as e:
        issues.append(f"Root CA 验证异常: {e}")

    # 2. Int CA 由 Root CA 签发
    try:
        int_tbs = intermediate_ca_tbs(
            sn=int_cert["sn"],
            issuer_sn=int_cert["issuer"]["sn"],
            issuer_name=int_cert["issuer"]["name"],
            issuer_pubkey=b64url_decode(int_cert["issuer"]["publicKey"]),
            subject_name=int_cert["subject"]["name"],
            subject_email=int_cert["subject"]["email"],
            pubkey=int_pub,
            is_ca=True,
            path_len=int_cert["extensions"]["pathLen"],
            key_id=int_cert["extensions"]["keyId"],
            crl=int_cert["extensions"]["crl"],
            license=int_cert["extensions"]["license"],
            uid_start=int_cert["extensions"]["uidRange"]["start"],
            uid_end=int_cert["extensions"]["uidRange"]["end"],
            issuing_countries=int_cert["extensions"]["issuingCountries"],
            iat=int_cert["iat"],
            exp=int_cert["exp"],
        )
        int_sig = b64url_decode(int_cert["signature"])
        if not ed25519_verify(root_pub, cbor_tbs(int_tbs), int_sig):
            issues.append("Int CA 签名验证失败（应由 Root CA 签发）")
    except Exception as e:
        issues.append(f"Int CA 验证异常: {e}")

    # 3. User Cert 由 Int CA 签发
    try:
        user_tbs = user_cert_tbs(
            user_cert["issuerSn"],
            user_cert["subject"]["callsign"],
            user_cert["subject"]["uid"],
            user_pub,
            user_cert["iat"],
            user_cert["exp"],
        )
        user_sig = b64url_decode(user_cert["signature"])
        if not ed25519_verify(int_pub, cbor_tbs(user_tbs), user_sig):
            issues.append("User Cert 签名验证失败（应由 Int CA 签发）")
    except Exception as e:
        issues.append(f"User Cert 验证异常: {e}")

    pubs = {"root_pub": root_pub, "int_pub": int_pub, "user_pub": user_pub}
    return (len(issues) == 0), issues, pubs


def check_cert_not_expired(cert: dict, label: str = "cert") -> tuple:
    """检查证书是否在有效期内。返回 (ok, msg)。"""
    now = now_ts()
    if now < cert.get("iat", 0):
        return False, f"{label} 尚未生效（iat={ts_to_str(cert['iat'])}）"
    if now > cert.get("exp", 0):
        return False, f"{label} 已过期（exp={ts_to_str(cert['exp'])}）"
    return True, ""


# ============================================================
#  ACL 规则生成
# ============================================================

def build_acl(callsign: str, uid: int, is_superuser: bool = False) -> list:
    """
    根据用户信息生成 MQTT ACL 规则。
    规则格式（与 mqtt_broker.js checkAcl 兼容）：
      {permission: "allow", action: "all"|"publish"|"subscribe", topic: "..."}
    """
    if is_superuser:
        # 超级用户：允许所有
        return [{"permission": "allow", "action": "all", "topic": "#"}]

    return [
        # 广播 topic：所有用户可订阅
        {"permission": "allow", "action": "subscribe", "topic": "fmo/broadcast/#"},
        # 在线状态：所有用户可订阅
        {"permission": "allow", "action": "subscribe", "topic": "fmo/+/presence"},
        # 自己的呼号 topic：可发布+订阅
        {"permission": "allow", "action": "all", "topic": f"fmo/{callsign}/#"},
        # 自己的 UID topic：可发布+订阅
        {"permission": "allow", "action": "all", "topic": f"fmo/uid/{uid}/#"},
        # 群组呼叫：可发布+订阅
        {"permission": "allow", "action": "all", "topic": f"fmo/group/{callsign}/#"},
    ]


# ============================================================
#  认证核心逻辑
# ============================================================

# ============================================================
#  第三方根 CA 接种（roots 目录，兼容官方 add-root.sh 机制）
#
#  服务器间互认的简化形式：
#    - 我们信任别人：把对方的根证书 JSON 放进 roots 目录
#      （或运行官方 add-root.sh --url <对方root.json>），重启即信任
#    - 别人信任我们：对方运行 add-root.sh --url <本机/api/ca/root.json>
#  每个 *.json 须为 type=rootCA 且自签名有效，否则跳过。
# ============================================================

_EXTRA_ROOTS = {}   # {根公钥(b64url): 根证书JSON}，启动时加载，重启生效
_EXTRA_ROOTS_LOADED = False


def get_extra_roots() -> dict:
    """获取第三方根 CA 表（懒加载）。
    sas_server.main() 启动时已加载，直接命中缓存；api_server 等独立进程
    import 本模块时（未走 main），首次认证请求触发加载，保证 /auth 路径
    下 roots 目录接种同样生效。"""
    global _EXTRA_ROOTS, _EXTRA_ROOTS_LOADED
    if _EXTRA_ROOTS_LOADED:
        return _EXTRA_ROOTS
    cfg = _CONFIG
    if cfg is None:
        try:
            cfg = load_config(os.path.join(_HERE, "config.json"))
        except Exception:
            return {}
    roots_dir = (cfg.get("trust") or {}).get("rootsDir") or "roots"
    if not os.path.isabs(roots_dir):
        roots_dir = os.path.join(_HERE, roots_dir)
    _EXTRA_ROOTS = load_extra_roots(roots_dir)
    _EXTRA_ROOTS_LOADED = True
    if _EXTRA_ROOTS:
        print("[ROOTS] 懒加载完成：已接种 %d 个第三方根" % len(_EXTRA_ROOTS))
    return _EXTRA_ROOTS


def load_extra_roots(roots_dir: str) -> dict:
    """扫描 roots 目录加载第三方根 CA（校验结构与自签名，与官方 add-root.sh
    放置的文件格式一致），返回 {根公钥(b64url): 根证书JSON}。"""
    roots = {}
    if not roots_dir or not os.path.isdir(roots_dir):
        return roots
    for fn in sorted(os.listdir(roots_dir)):
        if not fn.lower().endswith(".json"):
            continue
        try:
            with open(os.path.join(roots_dir, fn), "r", encoding="utf-8") as f:
                cert = json.load(f)
            pub_b64 = validate_root_ca_cert(cert)
            if pub_b64 is None:
                print("[ROOTS] 跳过 %s：rootCA 结构/自签名校验失败" % fn)
                continue
            roots[pub_b64] = cert
            print("[ROOTS] 已接种第三方根 CA: %s（%s）"
                  % (cert["subject"]["name"], fn))
        except Exception as e:
            print("[ROOTS] 跳过 %s：%s" % (fn, e))
    return roots


def authenticate(username: str, password: str,
                  ca_mgr: CaManager, db: Database) -> dict:
    """
    统一 FMO 认证核心逻辑（与官方/APP 格式一致，对应 FmoCert.buildMqttPassword）。

    入参：
      username — 明文呼号（如 "BH6BHG"）
      password — base64url(JSON)：
        {
          "certPackage": {"intermediateCert": {...}, "userCert": {...}},
          "targetCallsign": "...", "targetUID": 123, "role": "...",
          "targetUrl": "...", "targetPort": 1883,
          "serverFingerprint": "<b64url>", "timestamp": 1234567890,
          "proof": {"signature": "<b64url>"}
        }
    返回（与 EMQX auth HTTP 约定一致）：
      {result: "allow", acl: [...], client_attrs: {callsign, uid}, is_superuser: false}
      {result: "deny", reason: "..."}
    """
    # ---- 1. username 即明文呼号（不再做 base64 解码）----
    req_callsign = str(username or "").strip().upper()
    if not req_callsign:
        return {"result": "deny", "reason": "username 为空（应为明文呼号）"}

    # ---- 2. 解码 password ----
    try:
        pw_data = json.loads(b64url_decode(password).decode("utf-8"))
        pkg = pw_data["certPackage"]
        cert_int = pkg["intermediateCert"]
        cert_user = pkg["userCert"]
        proof_sig_b64 = (pw_data.get("proof") or {}).get("signature")
    except Exception as e:
        return {"result": "deny", "reason": f"password 解析失败: {e}"}

    # proof 是私钥持有证明：证书内容公开可查，不验签名等于没有防伪
    if not proof_sig_b64:
        return {"result": "deny", "reason": "缺少 proof 签名"}

    # ---- 3. 验证证书链签名（客户端无需提供根证书）----
    # User Cert 由 Int CA 签发；Int CA 由其 issuer.publicKey（根公钥）签发
    try:
        int_pub = b64url_decode(cert_int["subject"]["publicKey"])
        user_pub = b64url_decode(cert_user["subject"]["publicKey"])
        root_pub_b64 = str(cert_int["issuer"]["publicKey"])
        root_pub = b64url_decode(root_pub_b64)
    except Exception as e:
        return {"result": "deny", "reason": f"证书公钥解码失败: {e}"}

    try:
        int_tbs = intermediate_ca_tbs(
            sn=cert_int["sn"],
            issuer_sn=cert_int["issuer"]["sn"],
            issuer_name=cert_int["issuer"]["name"],
            issuer_pubkey=root_pub,
            subject_name=cert_int["subject"]["name"],
            subject_email=cert_int["subject"]["email"],
            pubkey=int_pub,
            is_ca=True,
            path_len=cert_int["extensions"]["pathLen"],
            key_id=cert_int["extensions"]["keyId"],
            crl=cert_int["extensions"]["crl"],
            license=cert_int["extensions"]["license"],
            uid_start=cert_int["extensions"]["uidRange"]["start"],
            uid_end=cert_int["extensions"]["uidRange"]["end"],
            issuing_countries=cert_int["extensions"]["issuingCountries"],
            iat=cert_int["iat"],
            exp=cert_int["exp"],
        )
        if not ed25519_verify(root_pub, cbor_tbs(int_tbs),
                              b64url_decode(cert_int["signature"])):
            return {"result": "deny",
                    "reason": "Int CA 签名验证失败（应由根 CA 签发）"}
    except Exception as e:
        return {"result": "deny", "reason": f"Int CA 验证异常: {e}"}

    try:
        user_tbs = user_cert_tbs(
            cert_user["issuerSn"],
            cert_user["subject"]["callsign"],
            cert_user["subject"]["uid"],
            user_pub,
            cert_user["iat"],
            cert_user["exp"],
        )
        if not ed25519_verify(int_pub, cbor_tbs(user_tbs),
                              b64url_decode(cert_user["signature"])):
            return {"result": "deny",
                    "reason": "User Cert 签名验证失败（应由 Int CA 签发）"}
    except Exception as e:
        return {"result": "deny", "reason": f"User Cert 验证异常: {e}"}

    # ---- 4. 验证证书有效期 ----
    for cert, label in [(cert_int, "Int CA"), (cert_user, "User Cert")]:
        ok_exp, msg = check_cert_not_expired(cert, label)
        if not ok_exp:
            return {"result": "deny", "reason": msg}

    # ---- 5. 呼号匹配（username 必须等于证书呼号）----
    cert_callsign = str(cert_user["subject"]["callsign"]).strip().upper()
    cert_uid = int(cert_user["subject"]["uid"])
    if cert_callsign != req_callsign:
        return {"result": "deny",
                "reason": f"呼号不匹配（username={req_callsign}，证书={cert_callsign}）"}

    # ---- 6. proof 验签（12 元素 CBOR TBS，证明持有私钥）----
    # 宽松模式：只验签名本身有效，不强制 TBS 中的目标服务器字段指向本机，
    # 因此任何一台服务器都能接受指向其他服务器的 proof（跨服互登不受限）。
    try:
        user_fp_bytes = cert_fingerprint(user_tbs)
        user_fp = fingerprint_b64url(user_tbs)
        target_uid = int(pw_data.get("targetUID") or 0)
        proof_tbs = [
            "FMO", 4, "serverAuthorizerReqHttp",
            target_uid,
            str(pw_data.get("targetCallsign") or "").upper(),
            target_uid,
            str(pw_data.get("role") or ""),
            str(pw_data.get("targetUrl") or ""),
            int(pw_data.get("targetPort") or 0),
            b64url_decode(str(pw_data.get("serverFingerprint") or "")),
            int(pw_data.get("timestamp") or 0),
            user_fp_bytes,
        ]
        if not ed25519_verify(user_pub, cbor_tbs(proof_tbs),
                              b64url_decode(proof_sig_b64)):
            return {"result": "deny", "reason": "proof 签名验证失败"}
    except Exception as e:
        return {"result": "deny", "reason": f"proof 验证异常: {e}"}

    # ---- 7. 检查证书吊销（本机签发的证书才在吊销表中，查不到视为未吊销）----
    if db.is_revoked(user_fp):
        return {"result": "deny", "reason": "证书已被吊销"}

    # ---- 8. 根 CA 信任判定（按根公钥比对，任一来源即可）----
    #   a. 本机 CA（分系统自己签发）
    #   b. 内置官方根（ESN 体系，天然互认，不经 master、无需配置）
    #   c. roots 目录接种（兼容官方 add-root.sh，江苏等第三方根）
    #   d. trust_chain 信任链表（master 同步下发的分系统互认）
    trusted = False
    if ca_mgr.root_cert is not None:
        local_root_pub = (ca_mgr.root_cert.get("subject") or {}).get("publicKey")
        trusted = (root_pub_b64 == local_root_pub)
    if not trusted and root_pub_b64 in OFFICIAL_ROOT_PUBKEYS:
        trusted = True
    # ★ 配置里追加信任的根（本机 CA 被重新生成时，旧根仍可用）
    if not trusted and root_pub_b64 in get_config_extra_root_pubkeys():
        trusted = True
    if not trusted and root_pub_b64 in get_extra_roots():
        trusted = True
    if not trusted and root_pub_b64 in db.trusted_root_pubkeys():
        trusted = True
    if not trusted:
        # 公钥**完整**返回，不要截断：
        #   截断后管理员在日志/审计库里只能看到 20 个字符，既没法核对来源，
        #   也没法把它加进 trust.extraRootPubkeys —— 会出现「看得见问题、修不了」。
        #   审计层 bas_audit.record_auth_rejection 会把完整值单独入台账便于核查。
        return {"result": "deny",
                "reason": f"根 CA 不受信任（公钥={root_pub_b64}）",
                "untrusted_root_pubkey": root_pub_b64}

    # ---- 9. 认证通过 ----
    is_superuser = False
    acl = build_acl(cert_callsign, cert_uid, is_superuser)
    return {
        "result": "allow",
        "acl": acl,
        "client_attrs": {"callsign": cert_callsign, "uid": str(cert_uid)},
        "is_superuser": is_superuser,
    }


# ============================================================
#  HTTP 请求处理器
# ============================================================

# 全局对象（在 main 中初始化）
_CA_MGR: CaManager = None
_DB: Database = None
_CONFIG: dict = None


class SasHandler(BaseHTTPRequestHandler):
    """SAS 认证服务 HTTP 处理器。"""

    # 超时设置，避免慢客户端占用线程
    timeout = 30

    def log_message(self, fmt, *args):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {self.address_string()} {args[0] if args else ''}")

    # ---------- 路由 ----------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send_json({"service": "FMO SAS", "version": "1.0",
                             "status": "running"})
        elif path == "/api/ca/info":
            self._handle_ca_info()
        elif path == "/api/ca/root.json":
            self._handle_ca_root_json()
        elif path == "/api/trust/list":
            self._handle_trust_list()
        elif path == "/api/cert/list":
            self._handle_cert_list()
        else:
            self._send_404()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/auth":
            self._handle_auth()
        elif path == "/api/cert/issue":
            self._handle_cert_issue()
        elif path == "/api/cert/revoke":
            self._handle_cert_revoke()
        elif path == "/api/trust/add":
            self._handle_trust_add()
        elif path == "/api/ca/init":
            self._handle_ca_init()
        elif path == "/api/ca/renew":
            self._handle_ca_renew()
        else:
            self._send_404()

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/trust/"):
            tid = path[len("/api/trust/"):]
            self._handle_trust_delete(tid)
        else:
            self._send_404()

    # ---------- POST /auth ----------

    def _handle_auth(self):
        body = self._read_json_body()
        if body is None:
            return

        username = body.get("username", "")
        password = body.get("password", "")

        if not username or not password:
            self._send_json({"result": "deny", "reason": "缺少 username 或 password"})
            return

        result = authenticate(username, password, _CA_MGR, _DB)

        if result["result"] == "allow":
            attrs = result.get("client_attrs", {})
            print(f"[AUTH] 通过: callsign={attrs.get('callsign')} "
                  f"uid={attrs.get('uid')}")
        else:
            # 诊断：拒绝时打印客户端原始 username（前 80 字符 repr），
            # 便于定位客户端凭证格式错误（如编码/字段不符）
            print(f"[AUTH] 拒绝: {result.get('reason', '未知原因')} | "
                  f"username(len={len(username)})={username[:80]!r}")

        self._send_json(result)

    # ---------- POST /api/cert/issue ----------

    def _handle_cert_issue(self):
        body = self._read_json_body()
        if body is None:
            return

        callsign = str(body.get("callsign", "")).strip().upper()
        uid = body.get("uid", 0)
        validity_years = body.get("validity_years", _CONFIG["validity_years"])

        # 校验呼号
        if not re.match(r"^[A-Z0-9]{4,10}$", callsign):
            self._send_json({"ok": False, "error": "呼号格式不正确，需 4-10 位大写字母和数字"})
            return
        # 校验 UID
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            self._send_json({"ok": False, "error": "UID 必须为整数"})
            return
        if uid < 1 or uid > 200000:
            self._send_json({"ok": False, "error": "UID 必须在 1-200000 之间"})
            return

        # 签发证书
        try:
            certs = _CA_MGR.issue_user_cert(callsign, uid, validity_years)
        except Exception as e:
            self._send_json({"ok": False, "error": f"证书签发失败: {e}"})
            return

        # 记录到数据库
        user_json = json.dumps(certs["user_cert"], ensure_ascii=False)
        dk_json = json.dumps(certs["device_key"])
        _DB.add_certificate(callsign, uid, user_json, dk_json, certs["fingerprint"])

        print(f"[ISSUE] 签发证书: callsign={callsign} uid={uid} "
              f"fp={certs['fingerprint'][:20]}...")

        self._send_json({
            "ok": True,
            "callsign": callsign,
            "uid": uid,
            "fingerprint": certs["fingerprint"],
            "cert_root": certs["root_cert"],
            "cert_int": certs["int_cert"],
            "cert_user": certs["user_cert"],
            "cert_devicekey": certs["device_key"],
        })

    # ---------- POST /api/cert/revoke ----------

    def _handle_cert_revoke(self):
        body = self._read_json_body()
        if body is None:
            return
        fingerprint = body.get("fingerprint", "")
        if not fingerprint:
            self._send_json({"ok": False, "error": "缺少 fingerprint"})
            return
        ok = _DB.revoke_certificate(fingerprint)
        self._send_json({"ok": ok,
                         "error": "" if ok else "未找到对应证书"})

    # ---------- GET /api/cert/list ----------

    def _handle_cert_list(self):
        certs = _DB.list_certificates(200)
        self._send_json({"ok": True, "certificates": certs, "count": len(certs)})

    # ---------- POST /api/trust/add ----------

    def _handle_trust_add(self):
        body = self._read_json_body()
        if body is None:
            return

        remote_ca = body.get("remote_ca")
        if not remote_ca:
            self._send_json({"ok": False, "error": "缺少 remote_ca 证书"})
            return
        trusted_by = body.get("trusted_by", "")
        ca_type = body.get("ca_type", "rootCA")

        # 计算远程 CA 指纹
        try:
            if ca_type == "rootCA":
                fp = CaManager.compute_root_fingerprint(remote_ca)
            else:
                fp = CaManager.compute_int_fingerprint(remote_ca)
        except Exception as e:
            self._send_json({"ok": False, "error": f"远程 CA 指纹计算失败: {e}"})
            return

        ca_json = json.dumps(remote_ca, ensure_ascii=False)
        tid = _DB.add_trust(fp, ca_json, ca_type, trusted_by)
        print(f"[TRUST] 添加信任 CA: fp={fp[:20]}... id={tid}")
        self._send_json({"ok": True, "id": tid, "fingerprint": fp})

    # ---------- GET /api/trust/list ----------

    def _handle_trust_list(self):
        trust_list = _DB.list_trust()
        self._send_json({"ok": True, "trust_chain": trust_list,
                         "count": len(trust_list)})

    # ---------- DELETE /api/trust/{id} ----------

    def _handle_trust_delete(self, tid: str):
        if not tid:
            self._send_json({"ok": False, "error": "缺少信任链 id"})
            return
        ok = _DB.delete_trust(tid)
        self._send_json({"ok": ok, "error": "" if ok else "未找到对应信任记录"})

    # ---------- GET /api/ca/root.json ----------

    def _handle_ca_root_json(self):
        """返回本机根 CA 证书完整 JSON。
        格式与 hamptt /api/ca/root.json 一致（type/sn/subject.publicKey/signature），
        供其他服务器用官方 add-root.sh --url 指向本地址完成接种。"""
        if _CA_MGR.root_cert is None:
            self._send_json({"ok": False, "error": "CA 未初始化"}, status=500)
            return
        self._send_json(_CA_MGR.root_cert)

    # ---------- GET /api/ca/info ----------

    def _handle_ca_info(self):
        info = _CA_MGR.info()
        # 附加信任链统计
        trust_list = _DB.list_trust()
        info["trusted_ca_count"] = len(trust_list)
        info["trusted_ca_fingerprints"] = [
            t["remote_ca_fingerprint"] for t in trust_list
        ]
        self._send_json({"ok": True, "ca": info})

    # ---------- POST /api/ca/init ----------

    def _handle_ca_init(self):
        body = self._read_json_body()
        if body is None:
            return
        force = bool(body.get("force", False))
        if _CA_MGR.root_cert is not None and not force:
            self._send_json({"ok": True, "message": "CA 已存在",
                             "ca": _CA_MGR.info()})
            return
        try:
            _CA_MGR.init(force=force)
        except Exception as e:
            self._send_json({"ok": False, "error": f"CA 初始化失败: {e}"})
            return
        self._send_json({"ok": True, "ca": _CA_MGR.info()})

    # ---------- POST /api/ca/renew ----------

    def _handle_ca_renew(self):
        try:
            _CA_MGR.renew()
        except Exception as e:
            self._send_json({"ok": False, "error": f"CA 轮换失败: {e}"})
            return
        print("[CA] CA 已轮换，已签发的用户证书将失效")
        self._send_json({"ok": True, "ca": _CA_MGR.info(),
                         "warning": "CA 已轮换，已签发的用户证书将失效"})

    # ---------- 工具方法 ----------

    def _read_json_body(self) -> dict:
        """读取并解析 JSON 请求体。失败时自动回复 400。"""
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length > 0 else b""
            if not raw:
                self._send_json({"ok": False, "error": "请求体为空"})
                return None
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as e:
            self._send_json({"ok": False, "error": f"JSON 解析失败: {e}"})
            return None
        except Exception as e:
            self._send_json({"ok": False, "error": f"读取请求体失败: {e}"})
            return None

    def _send_json(self, obj: dict, status: int = 200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def _send_404(self):
        self._send_json({"ok": False, "error": "Not Found"}, status=404)


# ============================================================
#  主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="FMO SAS 认证服务（Python 实现，替代 Rust sas.exe）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  python sas_server.py
  python sas_server.py --port 8080 --config config.json
  python sas_server.py --ca-dir ./ca --db-path ./sas.db
""",
    )
    parser.add_argument("--port", type=int, default=None,
                        help="服务端口（默认 8080，可被 config 覆盖）")
    parser.add_argument("--config", default=os.path.join(_HERE, "config.json"),
                        help="配置文件路径（默认同目录 config.json）")
    parser.add_argument("--ca-dir", default=None, help="CA 证书存储目录")
    parser.add_argument("--db-path", default=None, help="SQLite 数据库路径")
    parser.add_argument("--ca-name", default=None, help="CA 名称")
    parser.add_argument("--validity-years", type=int, default=None,
                        help="证书有效期（年）")
    args = parser.parse_args()

    # 加载配置
    config = load_config(args.config)
    # 命令行参数覆盖配置
    if args.port is not None:
        config["port"] = args.port
    if args.ca_dir is not None:
        config["ca_dir"] = args.ca_dir
    if args.db_path is not None:
        config["db_path"] = args.db_path
    if args.ca_name is not None:
        config["ca_name"] = args.ca_name
    if args.validity_years is not None:
        config["validity_years"] = args.validity_years

    # 转相对路径为绝对路径（基于配置文件所在目录）
    base_dir = os.path.dirname(os.path.abspath(args.config)) if args.config else _HERE
    for key in ("ca_dir", "db_path"):
        if config[key] and not os.path.isabs(config[key]):
            config[key] = os.path.join(base_dir, config[key])

    # 自动迁移旧 SAS 数据库（sas.db -> 新命名），保证升级后不丢数据
    _migrate_db(config["db_path"], ["sas.db"])
    print("[DB] SAS 数据库路径: %s" % config["db_path"])

    # 初始化全局对象
    global _CA_MGR, _DB, _CONFIG
    _CONFIG = config
    _DB = Database(config["db_path"])
    _CA_MGR = CaManager(
        ca_dir=config["ca_dir"],
        db=_DB,
        ca_name=config["ca_name"],
        ca_email=config.get("ca_email", ""),
        validity_years=config["validity_years"],
        uid_start=config.get("uid_start", 1),
        uid_end=config.get("uid_end", 200000),
        issuing_countries=config.get("issuing_countries", ["CN"]),
    )

    # 打印启动信息
    print("=" * 60)
    print("FMO SAS 认证服务")
    print("=" * 60)
    print(f"  端口        : {config['port']}")
    print(f"  配置文件    : {args.config}")
    print(f"  CA 目录     : {os.path.abspath(config['ca_dir'])}")
    print(f"  数据库      : {os.path.abspath(config['db_path'])}")
    print(f"  CA 名称     : {config['ca_name']}")
    print(f"  有效期      : {config['validity_years']} 年")
    print("-" * 60)

    # 初始化 CA
    _CA_MGR.init()
    print("-" * 60)

    # 加载 roots 目录接种的第三方根 CA（江苏等，兼容官方 add-root.sh 机制）
    roots_dir = (config.get("trust") or {}).get("rootsDir") or "roots"
    if not os.path.isabs(roots_dir):
        roots_dir = os.path.join(base_dir, roots_dir)
    global _EXTRA_ROOTS, _EXTRA_ROOTS_LOADED
    _EXTRA_ROOTS = load_extra_roots(roots_dir)
    _EXTRA_ROOTS_LOADED = True
    print(f"  Roots 目录  : {roots_dir}（已接种 {len(_EXTRA_ROOTS)} 个第三方根）")
    print("-" * 60)

    # 启动 HTTP 服务（多线程）
    server = ThreadingHTTPServer(("0.0.0.0", config["port"]), SasHandler)
    server.daemon_threads = True

    print(f"[OK] SAS 认证服务已启动: http://0.0.0.0:{config['port']}")
    print(f"  POST /auth              — MQTT 客户端认证")
    print(f"  POST /api/cert/issue    — 证书签发")
    print(f"  POST /api/cert/revoke   — 证书吊销")
    print(f"  GET  /api/cert/list     — 已签发证书列表")
    print(f"  POST /api/trust/add     — 添加信任 CA")
    print(f"  GET  /api/trust/list    — 信任链列表")
    print(f"  DELETE /api/trust/{{id}}  — 删除信任 CA")
    print(f"  GET  /api/ca/info       — CA 信息")
    print(f"  GET  /api/ca/root.json  — 根 CA 证书下载（供 add-root.sh 接种）")
    print(f"  POST /api/ca/init       — 初始化 CA")
    print(f"  POST /api/ca/renew      — 轮换 CA")
    print("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭 SAS 服务...")
    finally:
        server.server_close()
        _DB.close()
        print("服务已停止")


if __name__ == "__main__":
    main()