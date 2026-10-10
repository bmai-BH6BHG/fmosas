# -*- coding: utf-8 -*-
"""
FMO 分布式同步引擎 (sync_engine.py)
====================================
实现总分架构 + P2P 混合同步：

    1. 分系统 → 总系统上报（增强：用户 + 证书 + 信任链 + CA 信息）
       - 增量上报：基于 last_modified 时间戳，只发送变化数据
       - 全量上报：定期（默认 5 分钟）发送一次全量数据
    2. 总系统 → 分系统下发全量数据
       - 分系统定期从总系统拉取汇总后的总数据库
       - 冲突解决：总系统优先 / 时间戳优先
    3. 分系统 ↔ 分系统 P2P 直接同步
       - 只同步证书 + 信任链 + CA 信息（用户数据不 P2P 同步）
       - 双向交换增量数据
    4. 冲突解决策略
       - 时间戳优先：last_modified 新的覆盖旧的
       - 总系统优先：总系统下发数据覆盖本地
       - 证书不可覆盖：已签发证书不被 P2P 同步覆盖
       - soft delete：标记 deleted=1，不物理删除

约束：
    - Python 3 标准库 only（http.server + sqlite3 + json + threading + urllib）
    - 使用 threading.Thread 后台运行同步循环
    - 配置从 config.json 读取：master_url、peers、sync_interval
    - 不修改 api_server.py（由另一个任务负责整合）

集成方式（api_server.py 中，由其他任务负责）：

    from sync_engine import SyncEngine, SyncApiMixin

    # 1. 创建引擎（分系统模式）
    sync_engine = SyncEngine(CONFIG, DB_PATH, mode='subsystem')
    sync_engine.start()  # 启动后台线程

    # 2. Handler 集成路由（继承 Mixin 或手动调用）
    class ApiHandler(SyncApiMixin, http.server.BaseHTTPRequestHandler):
        sync_engine = sync_engine  # 类属性
        def send_json(self, data, code=200): ...
        def read_body(self): ...

    # 3. 在 do_GET / do_POST 中分发：
    def do_GET(self):
        if self.handle_sync_routes('GET', self.path): return
        ...  # 原有路由

API 接口：
    POST /api/sync/report  — 总系统端接收分系统上报
    GET  /api/sync/pull    — 总系统端返回全量数据
    POST /api/sync/peer    — 分系统端接收 P2P 同步数据
    GET  /api/sync/status  — 返回同步状态
"""

import json
import os
import sqlite3
import time
import threading
import urllib.request
import urllib.error
import uuid

# 根 CA 自签名校验（根证书接种语义，cert_gen 缺失时退化为不校验，
# 认证侧 sas_server 信任判定时仍有本机/内置根兜底，不会误放）
try:
    from cert_gen import validate_root_ca_cert
    _CERT_GEN_AVAILABLE = True
except Exception:
    _CERT_GEN_AVAILABLE = False


# ==================== 常量 ====================
DEFAULT_SYNC_INTERVAL = 30           # 增量上报间隔（秒）
DEFAULT_FULL_REPORT_INTERVAL = 300   # 全量上报间隔（秒，5 分钟）
DEFAULT_PULL_INTERVAL = 60           # 从总系统拉取间隔（秒）
DEFAULT_PEER_SYNC_INTERVAL = 60      # P2P 同步间隔（秒）
HTTP_TIMEOUT = 10                    # HTTP 请求超时（秒）

# 同步数据类型
DATA_TYPES = ('users', 'certificates', 'trust_chain', 'ca_info')

# 同步方向
DIR_REPORT = 'report'        # 分系统 → 总系统
DIR_PULL = 'pull'            # 总系统 → 分系统
DIR_PEER_OUT = 'peer_out'    # 分系统 → peer
DIR_PEER_IN = 'peer_in'      # peer → 分系统


# ==================== 工具函数 ====================
def now_ts():
    """当前 Unix 时间戳"""
    return time.time()


def log(tag, msg):
    """统一日志输出（带时间戳）"""
    print("[%s] [%s] %s" % (time.strftime("%H:%M:%S"), tag, msg))


def http_post(url, payload, timeout=HTTP_TIMEOUT):
    """
    发送 POST JSON 请求
    返回 (ok: bool, result: dict|str)
        ok=True  -> result = {'status': int, 'data': dict}
        ok=False -> result = error_str
    """
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('User-Agent', 'FMO-SyncEngine/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            resp_body = resp.read().decode('utf-8', errors='ignore')
            try:
                data = json.loads(resp_body)
            except Exception:
                data = {'raw': resp_body}
            return True, {'status': status, 'data': data}
    except urllib.error.HTTPError as e:
        return False, 'HTTPError %d' % e.code
    except urllib.error.URLError as e:
        return False, 'URLError: %s' % e.reason
    except Exception as e:
        return False, str(e)


def http_get(url, timeout=HTTP_TIMEOUT):
    """
    发送 GET 请求
    返回 (ok: bool, result: dict|str)
        ok=True  -> result = {'status': int, 'data': dict}
        ok=False -> result = error_str
    """
    req = urllib.request.Request(url, method='GET')
    req.add_header('User-Agent', 'FMO-SyncEngine/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode()
            resp_body = resp.read().decode('utf-8', errors='ignore')
            try:
                data = json.loads(resp_body)
            except Exception:
                data = {'raw': resp_body}
            return True, {'status': status, 'data': data}
    except urllib.error.HTTPError as e:
        return False, 'HTTPError %d' % e.code
    except urllib.error.URLError as e:
        return False, 'URLError: %s' % e.reason
    except Exception as e:
        return False, str(e)


def join_url(base, path):
    """拼接 URL，自动处理斜杠"""
    if not base:
        return path
    if base.endswith('/') and path.startswith('/'):
        return base + path[1:]
    if not base.endswith('/') and not path.startswith('/'):
        return base + '/' + path
    return base + path


# ==================== SyncEngine ====================
class SyncEngine:
    """
    分布式同步引擎

    模式：
        - 'subsystem'：分系统模式
            主动上报总系统 + 主动拉取总系统 + 主动 P2P 同步 + 接收 P2P 同步
        - 'master'：总系统模式
            接收分系统上报 + 返回全量数据

    配置字段（从 config.json 读取）：
        subsystem_id        : 分系统唯一 ID
        master_url          : 总系统 URL
        peers               : P2P peer 地址列表（其他分系统的 URL）
        sync_interval       : 增量上报间隔（秒，默认 30）
        full_report_interval: 全量上报间隔（秒，默认 300）
        pull_interval       : 拉取总系统间隔（秒，默认 60）
        peer_sync_interval  : P2P 同步间隔（秒，默认 60）
    """

    def __init__(self, config, db_path, mode='subsystem', base_dir=None):
        """
        :param config: dict 配置字典
        :param db_path: str SQLite 数据库路径
        :param mode: 'subsystem' 或 'master'
        :param base_dir: str 基础目录（默认同 db_path 所在目录）
        """
        self.config = config or {}
        # ★ 由外部注入：返回"本机确认到的集群成员节点 id"（互联桥接提供）。
        #   用于让那些**有桥接功能但版本较早、没有"已加入"上报字段**的节点
        #   也能被总系统认作集群成员 —— 否则总系统会一直显示 0 台，
        #   且名册会变空、把本来在互通的桥接全断掉（真实踩过）。
        self.member_source = None
        self.db_path = db_path
        self.mode = mode
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(db_path))
        # 占位常开连接：避免"每次操作新建连接"的 close 触发 WAL checkpoint（见 _ensure_keepalive）
        self._keepalive = {}

        # SAS 数据库路径（证书/信任链的真实数据源，由 sas_server.py 维护）
        # 推导规则：xxx_users.db -> xxx_sas.db；否则用显式传入或同目录 fmo_sas.db
        self.sas_db_path = self._derive_sas_db_path(db_path)

        # 同步配置
        self.subsystem_id = self._resolve_subsystem_id(self.config.get('subsystem_id', ''))
        self.master_url = str(self.config.get('master_url', '')).rstrip('/')
        self.peers = self.config.get('peers', []) or []
        if isinstance(self.peers, str):
            # 逗号分隔字符串
            self.peers = [p.strip() for p in self.peers.split(',') if p.strip()]
        # 兼容字典形式 {'url': ..., 'name': ...}，统一归一化为 URL 字符串
        _norm_peers = []
        for _p in self.peers:
            if isinstance(_p, dict):
                _u = str(_p.get('url', '')).strip()
                if _u:
                    _norm_peers.append(_u)
            elif _p:
                _norm_peers.append(str(_p).strip())
        self.peers = _norm_peers
        # 过滤与 master_url 重复的 peer：master 通道（上报/拉取）已覆盖，
        # P2P 再向 master 推送属于冗余且容易形成回环
        if self.master_url:
            self.peers = [p for p in self.peers if p.rstrip('/') != self.master_url]
        self.sync_interval = int(self.config.get('sync_interval', DEFAULT_SYNC_INTERVAL))
        self.full_report_interval = int(self.config.get('full_report_interval', DEFAULT_FULL_REPORT_INTERVAL))
        self.pull_interval = int(self.config.get('pull_interval', DEFAULT_PULL_INTERVAL))
        self.peer_sync_interval = int(self.config.get('peer_sync_interval', DEFAULT_PEER_SYNC_INTERVAL))

        # 同步令牌（可选）：总系统设置 FMO_SYNC_TOKEN 后，上报/拉取必须携带
        self.sync_token = str(
            self.config.get('sync_token') or os.environ.get('FMO_SYNC_TOKEN', '')
        )

        # 线程控制
        self._stop_event = threading.Event()
        self._threads = []
        self._db_lock = threading.RLock()  # SQLite 跨线程保护（可重入）

        # 上报状态（内存 + 可选持久化）
        self._last_report_time = 0.0        # 上次增量上报时间戳
        self._last_full_report_time = 0.0   # 上次全量上报时间戳
        self._last_pull_time = 0.0          # 上次从总系统拉取的时间戳

        # 初始化数据库表
        self.init_sync_tables()

    def _resolve_subsystem_id(self, configured_id):
        """
        解析分系统唯一 ID。
        如果 configured_id 是空、'sub-001'、'sub-unknown' 等默认值，
        则基于主机名 + MAC 地址自动生成唯一 ID（与 api_server.py 保持一致），
        并写回 config.json 持久化。
        这样多个分系统不会互相覆盖数据。
        """
        DEFAULT_IDS = {'', 'sub-001', 'sub-unknown', 'sub-default', 'sub-test-001'}
        if configured_id and configured_id not in DEFAULT_IDS:
            return configured_id

        # 自动生成：与 api_server.py 的 generate_subsystem_id() 保持一致
        # 用 uuid5 基于主机名+MAC 生成确定性 UUID，取前 8 位
        try:
            import socket as _socket
            hostname = _socket.gethostname() or 'host'
        except Exception:
            hostname = 'host'

        mac = ''
        try:
            import uuid as _uuid
            mac = _uuid.getnode().to_bytes(6, 'big').hex()
        except Exception:
            pass

        unique = uuid.uuid5(uuid.NAMESPACE_DNS, "%s|%s" % (hostname, mac)).hex[:8]
        generated = 'sub-' + unique

        log('SYNC', 'subsystem_id 自动生成: configured=%r -> generated=%s' % (configured_id, generated))

        # 写回 config.json 持久化
        try:
            config_path = os.path.join(self.base_dir, 'config.json')
            with open(config_path, 'r', encoding='utf-8-sig') as f:
                cfg = json.load(f)
            cfg['subsystem_id'] = generated
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(cfg, f, indent=4, ensure_ascii=False)
            log('SYNC', '已将 subsystem_id=%s 写回 config.json' % generated)
        except Exception as e:
            log('SYNC', '写回 config.json 失败（不影响运行）: %s' % e)

        return generated

    def _derive_sas_db_path(self, db_path):
        """
        推导 SAS 数据库路径。
        api_server.py 的数据库命名规则是 {prefix}_users.db / {prefix}_sas.db，
        因此把 '_users.db' 替换为 '_sas.db'；不匹配时回退到同目录 fmo_sas.db。
        也允许 config['sas_db_path'] 显式覆盖。
        """
        explicit = self.config.get('sas_db_path')
        if explicit:
            if not os.path.isabs(explicit):
                explicit = os.path.join(self.base_dir, explicit)
            return explicit
        if db_path.endswith('_users.db'):
            return db_path[:-len('_users.db')] + '_sas.db'
        return os.path.join(self.base_dir, 'fmo_sas.db')

    def _get_sas_db(self):
        """获取 SAS 数据库连接（只读使用，WAL 模式避免与 sas_server 互锁）"""
        self._ensure_keepalive(self.sas_db_path)
        conn = sqlite3.connect(self.sas_db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _ensure_keepalive(self, path):
        """
        为某个库保持**一条常开连接**（只占位，不做任何查询/写入）。

        ★ 真实事故（服务"莫名其妙断连 / 所有证书都进不来 / 界面卡"的根因）：
          SQLite 在**最后一个连接关闭时**会对 WAL 做一次 checkpoint。
          本模块（以及原先的审计库/语音库）都是"每次操作新建连接再 close"，
          于是**每一次写入的 close 都是最后一个连接** → 每次都全量 checkpoint
          → 实测在 NAS 上每次写入要 ~1 秒：
              无保活连接：中位 1058 ms/次
              加一条常开：中位 0.4 ms/次   （实测快约 2500 倍）
              断开保活后：中位 1091 ms/次（复现）
          只要这条"占位连接"一直开着，其它连接的 close 就不再是最后一个，
          checkpoint 不再每次触发 —— 且**不需要改任何调用点**。
        """
        if path in self._keepalive:
            return
        try:
            k = sqlite3.connect(path, timeout=10, check_same_thread=False)
            k.execute("PRAGMA journal_mode=WAL;")
            k.execute("PRAGMA busy_timeout=5000;")
            self._keepalive[path] = k
        except Exception:  # noqa: BLE001
            pass          # 库还不存在等情况：下次再试

    def close_keepalive(self):
        """关闭占位连接（进程退出用）"""
        for p, k in list(getattr(self, "_keepalive", {}).items()):
            try:
                k.close()
            except Exception:  # noqa: BLE001
                pass
            self._keepalive.pop(p, None)

    @staticmethod
    def _sas_table_columns(cur, table):
        """返回 sas.db 某表的列名集合（用于兼容旧库缺列的情况）"""
        try:
            cur.execute("PRAGMA table_info(%s)" % table)
            return {r[1] for r in cur.fetchall()}
        except Exception:
            return set()

    # -------------------- 数据库 --------------------
    def get_db(self):
        """获取数据库连接（WAL 模式，row_factory）"""
        self._ensure_keepalive(self.db_path)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    @staticmethod
    def _column_exists(cur, table, column):
        """检查表中某列是否存在"""
        cur.execute("PRAGMA table_info(%s)" % table)
        for row in cur.fetchall():
            if row[1] == column:
                return True
        return False

    def init_sync_tables(self):
        """
        创建同步相关的表，并为现有 users 表补充 last_modified / deleted / subsystem_id 列。
        所有建表使用 IF NOT EXISTS，可安全重复调用。
        """
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()

                # ---- 为现有 users 表补充同步字段 ----
                # users 表可能已存在（由 api_server.py 创建），需 ADD COLUMN
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        callsign TEXT UNIQUE,
                        phone TEXT,
                        password_hash TEXT,
                        cert_photo_path TEXT,
                        device_cert_path TEXT,
                        token TEXT,
                        last_heartbeat REAL DEFAULT 0,
                        created_at REAL
                    )
                """)
                if not self._column_exists(cur, 'users', 'last_modified'):
                    cur.execute("ALTER TABLE users ADD COLUMN last_modified REAL DEFAULT 0")
                if not self._column_exists(cur, 'users', 'deleted'):
                    cur.execute("ALTER TABLE users ADD COLUMN deleted INTEGER DEFAULT 0")
                if not self._column_exists(cur, 'users', 'subsystem_id'):
                    cur.execute("ALTER TABLE users ADD COLUMN subsystem_id TEXT")
                if not self._column_exists(cur, 'users', 'guoji_id'):
                    cur.execute("ALTER TABLE users ADD COLUMN guoji_id TEXT")
                if not self._column_exists(cur, 'users', 'dmr_id'):
                    cur.execute("ALTER TABLE users ADD COLUMN dmr_id TEXT")
                # 回填已有用户
                cur.execute(
                    "UPDATE users SET last_modified = created_at "
                    "WHERE last_modified IS NULL OR last_modified = 0"
                )
                cur.execute(
                    "UPDATE users SET subsystem_id = ? WHERE subsystem_id IS NULL",
                    (self.subsystem_id,)
                )

                # ---- 证书表 ----
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS certificates (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        cert_id         TEXT UNIQUE,
                        callsign        TEXT,
                        cert_type       TEXT,
                        cert_data       TEXT,
                        cert_photo_path TEXT,
                        device_cert_path TEXT,
                        issued_by       TEXT,
                        issued_at       REAL DEFAULT 0,
                        last_modified   REAL DEFAULT 0,
                        deleted         INTEGER DEFAULT 0,
                        subsystem_id    TEXT
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_callsign ON certificates(callsign)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_type ON certificates(cert_type)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_cert_modified ON certificates(last_modified)")

                # ---- 信任链表 ----
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS trust_chain (
                        id             INTEGER PRIMARY KEY AUTOINCREMENT,
                        trust_id       TEXT UNIQUE,
                        from_subsystem TEXT,
                        to_subsystem   TEXT,
                        trust_level    INTEGER DEFAULT 0,
                        trust_data     TEXT,
                        created_at     REAL DEFAULT 0,
                        last_modified  REAL DEFAULT 0,
                        deleted        INTEGER DEFAULT 0
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_trust_modified ON trust_chain(last_modified)")

                # ---- CA 信息表 ----
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS ca_info (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        ca_id         TEXT UNIQUE,
                        ca_type       TEXT,
                        ca_name       TEXT,
                        public_key    TEXT,
                        ca_cert_data  TEXT,
                        valid_from    REAL DEFAULT 0,
                        valid_to      REAL DEFAULT 0,
                        last_modified REAL DEFAULT 0,
                        deleted       INTEGER DEFAULT 0
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_ca_modified ON ca_info(last_modified)")

                # ---- 同步日志表 ----
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sync_log (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp  REAL,
                        direction  TEXT,
                        peer       TEXT,
                        data_type  TEXT,
                        count      INTEGER,
                        status     TEXT,
                        error      TEXT,
                        duration   REAL
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_synclog_ts ON sync_log(timestamp)")

                # ---- 同步状态表 ----
                # 注意：同一 peer 可能有 report/pull/peer_out 多个方向，
                # 唯一约束必须是 (peer, direction)，否则不同方向互相覆盖
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sync_status (
                        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                        peer                  TEXT,
                        direction             TEXT,
                        last_sync             REAL DEFAULT 0,
                        last_status           TEXT,
                        last_count            INTEGER DEFAULT 0,
                        consecutive_failures INTEGER DEFAULT 0,
                        UNIQUE(peer, direction)
                    )
                """)

                # 迁移：旧表是 peer TEXT UNIQUE（单列唯一），需要重建为 UNIQUE(peer, direction)
                cur.execute("PRAGMA index_list(sync_status)")
                need_rebuild = False
                for idx in cur.fetchall():
                    idx_name = idx[1]
                    cur.execute("PRAGMA index_info(%s)" % idx_name)
                    cols = [r[2] for r in cur.fetchall()]
                    if cols == ['peer']:
                        need_rebuild = True
                        break
                if need_rebuild:
                    log('SYNC', '迁移 sync_status 表: UNIQUE(peer) -> UNIQUE(peer, direction)')
                    cur.execute("ALTER TABLE sync_status RENAME TO sync_status_old")
                    cur.execute("""
                        CREATE TABLE sync_status (
                            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                            peer                  TEXT,
                            direction             TEXT,
                            last_sync             REAL DEFAULT 0,
                            last_status           TEXT,
                            last_count            INTEGER DEFAULT 0,
                            consecutive_failures INTEGER DEFAULT 0,
                            UNIQUE(peer, direction)
                        )
                    """)
                    cur.execute("""
                        INSERT OR IGNORE INTO sync_status
                        (peer, direction, last_sync, last_status, last_count, consecutive_failures)
                        SELECT peer, direction, last_sync, last_status, last_count, consecutive_failures
                        FROM sync_status_old
                    """)
                    cur.execute("DROP TABLE sync_status_old")

                conn.commit()
            finally:
                conn.close()

    # -------------------- 数据收集 --------------------
    def _collect(self, table, since=0, columns=None):
        """通用数据收集"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                if columns:
                    col_str = ", ".join(columns)
                else:
                    col_str = "*"
                if since > 0:
                    cur.execute(
                        "SELECT %s FROM %s WHERE last_modified > ? ORDER BY last_modified ASC" % (col_str, table),
                        (since,)
                    )
                else:
                    cur.execute(
                        "SELECT %s FROM %s ORDER BY last_modified ASC" % (col_str, table)
                    )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    # 用户表允许上报的列（token 是本机会话凭证，绝不上报；
    # password_hash 必须同步——否则远端系统只有档案没有密码，用户无法跨系统登录）
    USER_REPORT_COLUMNS = [
        'name', 'callsign', 'phone', 'password_hash', 'cert_photo_path', 'device_cert_path',
        'last_heartbeat', 'created_at', 'last_modified', 'deleted', 'subsystem_id',
        'guoji_id', 'dmr_id'
    ]

    def collect_users(self, since=0):
        """
        收集用户数据（since=0 全量，since>0 增量）。
        - 排除 token（本机会话凭证，各系统独立登录独立签发）
        - 携带 password_hash：一次注册、全系统可登录
        - 全量上报本机持有的全部账号（含远端合并副本、含 deleted 墓碑）：
          各分系统账号互通，master 按（上报方, 呼号）逐行存档，
          形成全局覆盖矩阵——哪个账号在哪台服务器缺失/异常一眼可见。
          防回环由 master 下发端保证（每个呼号只下发 last_modified 最大的行）。
        """
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                col_str = ", ".join(self.USER_REPORT_COLUMNS)
                where = "1=1"
                params = []
                if since > 0:
                    where += " AND last_modified > ?"
                    params.append(since)
                cur.execute(
                    "SELECT %s FROM users WHERE %s ORDER BY last_modified ASC" % (col_str, where),
                    params
                )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def collect_certificates(self, since=0):
        """
        收集证书数据。
        证书的真实数据源是 sas.db（sas_server.py 签发时写入），
        users.db 的 certificates 表只存放从总系统/P2P 合并来的远端副本，
        不参与上报（避免数据回环中转——总系统是唯一全局交换枢纽）。
        返回字段映射：cert_id=fingerprint（全局唯一），deleted=revoked。
        """
        if not os.path.exists(self.sas_db_path):
            return []
        conn = self._get_sas_db()
        try:
            cur = conn.cursor()
            cols = self._sas_table_columns(cur, 'certificates')
            if not cols:
                return []
            has_lm = 'last_modified' in cols
            lm_expr = 'last_modified' if has_lm else 'issued_at AS last_modified'
            sql = "SELECT id, callsign, uid, cert_user_json, cert_devicekey_json, fingerprint, issued_at, revoked, %s FROM certificates" % lm_expr
            if since > 0:
                sql += " WHERE %s > ?" % ('last_modified' if has_lm else 'issued_at')
                cur.execute(sql, (since,))
            else:
                cur.execute(sql)
            result = []
            for r in cur.fetchall():
                fp = r['fingerprint'] or r['id']
                cert_data = json.dumps({
                    'cert_user': json.loads(r['cert_user_json']) if r['cert_user_json'] else None,
                    'cert_devicekey': json.loads(r['cert_devicekey_json']) if r['cert_devicekey_json'] else None,
                }, ensure_ascii=False)
                result.append({
                    'cert_id': fp,
                    'callsign': r['callsign'] or '',
                    'cert_type': 'user',
                    'cert_data': cert_data,
                    'cert_photo_path': '',
                    'device_cert_path': '',
                    'issued_by': self.subsystem_id,
                    'issued_at': float(r['issued_at'] or 0),
                    'last_modified': float(r['last_modified'] or r['issued_at'] or 0),
                    'deleted': int(r['revoked'] or 0),
                    'subsystem_id': self.subsystem_id,
                    'uid': r['uid'],
                })
            return result
        except Exception as e:
            log('SYNC', '从 sas.db 收集证书失败: %s' % e)
            return []
        finally:
            conn.close()

    def collect_trust_chain(self, since=0):
        """
        收集信任链数据。
        真实数据源同样是 sas.db 的 trust_chain 表（本系统信任的远端 CA 列表）。
        trust_id 用 remote_ca_fingerprint 保证全局唯一。
        """
        if not os.path.exists(self.sas_db_path):
            return []
        conn = self._get_sas_db()
        try:
            cur = conn.cursor()
            cols = self._sas_table_columns(cur, 'trust_chain')
            if not cols:
                return []
            has_lm = 'last_modified' in cols
            has_del = 'deleted' in cols
            lm_expr = 'last_modified' if has_lm else 'created_at AS last_modified'
            del_expr = 'deleted' if has_del else '0 AS deleted'
            sql = "SELECT id, remote_ca_fingerprint, remote_ca_json, ca_type, trusted_by, created_at, %s, %s FROM trust_chain" % (lm_expr, del_expr)
            if since > 0:
                sql += " WHERE %s > ?" % ('last_modified' if has_lm else 'created_at')
                cur.execute(sql, (since,))
            else:
                cur.execute(sql)
            result = []
            for r in cur.fetchall():
                fp = r['remote_ca_fingerprint'] or r['id']
                result.append({
                    'trust_id': 'trust:%s' % fp,
                    'from_subsystem': r['trusted_by'] or self.subsystem_id,
                    'to_subsystem': self.subsystem_id,
                    'trust_level': 1,
                    'trust_data': r['remote_ca_json'] or '',
                    'ca_type': r['ca_type'] or '',
                    'created_at': float(r['created_at'] or 0),
                    'last_modified': float(r['last_modified'] or r['created_at'] or 0),
                    'deleted': int(r['deleted'] or 0),
                })
            return result
        except Exception as e:
            log('SYNC', '从 sas.db 收集信任链失败: %s' % e)
            return []
        finally:
            conn.close()

    def collect_ca_info(self, since=0):
        """
        收集 CA 信息数据。
        从 ca/ 目录的 JSON 文件读取（cert_root.json, cert_int.json），
        这是本地 CA 的真实数据源。
        ca_id 采用 {ca_type}:{publicKey} 形式，保证跨分系统全局唯一，
        避免多个分系统的 'root'/'intermediate' 记录互相覆盖。
        CA 证书内容不变（last_modified=签发时间 iat），增量同步天然幂等。
        """
        ca_dir = self.config.get('ca_dir', 'ca')
        if not os.path.isabs(ca_dir):
            ca_dir = os.path.join(self.base_dir, ca_dir)

        result = []
        now = now_ts()

        # 读取 Root CA
        root_path = os.path.join(ca_dir, 'cert_root.json')
        if os.path.exists(root_path):
            try:
                with open(root_path, 'r', encoding='utf-8-sig') as f:
                    root_cert = json.load(f)
                pub = root_cert.get('subject', {}).get('publicKey', '')
                result.append({
                    'ca_id': 'rootCA:%s' % pub,
                    'ca_type': 'rootCA',
                    'ca_name': root_cert.get('subject', {}).get('name', ''),
                    'public_key': pub,
                    'ca_cert_data': json.dumps(root_cert),
                    'valid_from': root_cert.get('iat', 0),
                    'valid_to': root_cert.get('exp', 0),
                    'last_modified': root_cert.get('iat', now),
                    'deleted': 0,
                })
            except Exception as e:
                log('SYNC', '读取 Root CA 失败: %s' % e)

        # 读取 Intermediate CA
        int_path = os.path.join(ca_dir, 'cert_int.json')
        if os.path.exists(int_path):
            try:
                with open(int_path, 'r', encoding='utf-8-sig') as f:
                    int_cert = json.load(f)
                pub = int_cert.get('subject', {}).get('publicKey', '')
                result.append({
                    'ca_id': 'intermediateCA:%s' % pub,
                    'ca_type': 'intermediateCA',
                    'ca_name': int_cert.get('subject', {}).get('name', ''),
                    'public_key': pub,
                    'ca_cert_data': json.dumps(int_cert),
                    'valid_from': int_cert.get('iat', 0),
                    'valid_to': int_cert.get('exp', 0),
                    'last_modified': int_cert.get('iat', now),
                    'deleted': 0,
                })
            except Exception as e:
                log('SYNC', '读取 Intermediate CA 失败: %s' % e)

        # 如果 since > 0（增量模式），只返回 last_modified > since 的记录
        if since > 0:
            result = [r for r in result if r.get('last_modified', 0) > since]

        return result

    def collect_all(self, since=0):
        """收集所有数据类型"""
        return {
            'users': self.collect_users(since),
            'certificates': self.collect_certificates(since),
            'trust_chain': self.collect_trust_chain(since),
            'ca_info': self.collect_ca_info(since),
        }

    # -------------------- 分系统 → 总系统上报 --------------------
    def build_report_payload(self, full=False):
        """
        构造上报数据包
        :param full: True=全量上报, False=增量上报
        """
        if full:
            since = 0
        else:
            since = self._last_report_time

        data = self.collect_all(since)

        # 上报地址优先采用后台"APP 登录地址配置"（app_domain/app_port/app_use_port），
        # 在界面保存后即生效，免手改 config.json 的 api_url；
        # 未配置 app_domain 时回退静态 api_url/domain。
        app_domain = str(self.config.get('app_domain', '') or '').strip()
        app_port = self.config.get('app_port')
        app_use_port = self.config.get('app_use_port', True)
        if app_domain:
            if app_use_port and app_port:
                api_url = 'http://%s:%s' % (app_domain, app_port)
            else:
                api_url = 'http://%s' % app_domain
            domain = app_domain
        else:
            api_url = self.config.get('api_url', '')
            domain = self.config.get('domain', '')

        payload = {
            'subsystem_id': self.subsystem_id,
            'name': self.config.get('name', ''),
            'domain': domain,
            'api_url': api_url,
            'full': full,
            'since': since,
            'timestamp': now_ts(),
            'data': data,
            'counts': {k: len(v) for k, v in data.items()}
        }
        # ★ 集群归属：本机在管理页选的"想加入哪个集群"，随上报带给总系统。
        #   总系统据此把我们归到那个集群，之后名册（/api/server/list）只返回
        #   同集群的成员 → 桥接自动只在同集群内互联。没选过就报「主集群」。
        bridge = (self.config.get('bridge') or {})
        cluster = str(bridge.get('cluster') or '').strip()
        payload['cluster'] = cluster or '主集群'
        # ★ 是否**已真正加入集群**（桥接开关已打开）：总系统的集群成员数只算已加入的
        #   —— 集群的意义是桥接互通，没加入桥接的台站不该显示成成员。
        payload['cluster_joined'] = bool(bridge.get('enabled'))
        # ★ 我确认到的集群成员：本机对每个成员都做过**名片 + 与总服务器名册的身份比对**。
        #   有些节点有桥接功能、也确实在互通，但版本较早、没有"已加入"上报字段；
        #   只等它们自己报的话，总系统会一直显示 0 台，而且名册会变空、
        #   把正在工作的桥接全部断掉。所以这里顺带把结论报给总系统。
        try:
            if self.member_source:
                members = list(self.member_source() or [])
                if members:
                    payload['cluster_members'] = members
        except Exception:  # noqa: BLE001
            pass
        if self.sync_token:
            payload['sync_token'] = self.sync_token
        return payload

    def report_to_master(self, full=False):
        """
        单次上报到总系统
        :param full: True=全量, False=增量
        :return: bool 是否成功
        """
        if not self.master_url:
            log('SYNC', 'master_url 未配置，跳过上报')
            return False

        url = join_url(self.master_url, '/api/sync/report')
        t0 = now_ts()
        payload = self.build_report_payload(full=full)

        ok, result = http_post(url, payload)
        duration = now_ts() - t0
        total_count = sum(payload['counts'].values())

        if ok:
            self._last_report_time = payload['timestamp']
            if full:
                self._last_full_report_time = payload['timestamp']
            self.log_sync(DIR_REPORT, self.master_url, 'all', total_count, 'ok', '', duration)
            self.update_sync_status(self.master_url, DIR_REPORT, 'ok', total_count)
            log('SYNC', '上报成功 full=%s count=%d (%.2fs)' % (full, total_count, duration))
            return True
        else:
            self.log_sync(DIR_REPORT, self.master_url, 'all', total_count, 'fail', str(result), duration)
            self.update_sync_status(self.master_url, DIR_REPORT, 'fail', total_count)
            log('SYNC', '上报失败: %s' % result)
            return False

    def report_loop(self, stop_event):
        """
        上报后台线程主循环
        - 每 sync_interval 秒增量上报
        - 每 full_report_interval 秒全量上报
        """
        log('SYNC', '上报线程启动，增量=%ds，全量=%ds' % (
            self.sync_interval, self.full_report_interval))

        while not stop_event.wait(self.sync_interval):
            try:
                # 判断是否该全量上报
                elapsed = now_ts() - self._last_full_report_time
                full = (self._last_full_report_time == 0) or (elapsed >= self.full_report_interval)
                self.report_to_master(full=full)
            except Exception as e:
                log('SYNC', '上报循环异常（已吞掉）: %s' % e)

        log('SYNC', '上报线程已停止')

    # -------------------- 总系统 → 分系统下发 --------------------
    def pull_from_master(self):
        """
        从总系统拉取全量数据并合并到本地。
        使用 POST /api/sync/pull（总系统公网端口只接受 POST）。
        :return: bool 是否成功
        """
        if not self.master_url:
            return False

        url = join_url(self.master_url, '/api/sync/pull')
        t0 = now_ts()

        # 构造 POST payload：总系统需要 subsystem_id 才能记录拉取状态
        payload = {
            'subsystem_id': self.subsystem_id,
            'last_sync_time': self._last_pull_time,
            'data_types': ['users', 'certificates', 'trust_chain', 'ca_info'],
        }
        if self.sync_token:
            payload['sync_token'] = self.sync_token
        ok, result = http_post(url, payload)
        duration = now_ts() - t0

        if not ok:
            self.log_sync(DIR_PULL, self.master_url, 'all', 0, 'fail', str(result), duration)
            self.update_sync_status(self.master_url, DIR_PULL, 'fail', 0)
            log('SYNC', '拉取失败: %s' % result)
            return False

        # http_post 返回 {'status': int, 'data': {HTTP响应体JSON}}
        # 总系统响应体: {"status": "ok", "data": {users, certificates, trust_chain, ca_info, counts, server_time}}
        resp_body = result.get('data', {}) or {}
        if not isinstance(resp_body, dict):
            resp_body = {}

        # 检查总系统返回的业务状态
        if resp_body.get('status') != 'ok':
            self.log_sync(DIR_PULL, self.master_url, 'all', 0, 'fail',
                          str(resp_body.get('error', 'unknown')), duration)
            self.update_sync_status(self.master_url, DIR_PULL, 'fail', 0)
            log('SYNC', '拉取失败（业务错误）: %s' % resp_body)
            return False

        # 实际数据在 resp_body['data'] 里
        payload_data = resp_body.get('data', {}) or {}
        merged = self.merge_all(payload_data, source='master')

        # 记数
        counts = payload_data.get('counts', {}) if isinstance(payload_data, dict) else {}
        server_time = payload_data.get('server_time', 0) if isinstance(payload_data, dict) else 0

        self._last_pull_time = server_time or now_ts()
        self.log_sync(DIR_PULL, self.master_url, 'all', merged, 'ok', '', duration)
        self.update_sync_status(self.master_url, DIR_PULL, 'ok', merged)
        log('SYNC', '拉取成功，合并 %d 条 counts=%s (%.2fs)' % (merged, counts, duration))
        return True

    def pull_loop(self, stop_event):
        """拉取后台线程主循环"""
        log('SYNC', '拉取线程启动，间隔=%ds' % self.pull_interval)
        while not stop_event.wait(self.pull_interval):
            try:
                self.pull_from_master()
            except Exception as e:
                log('SYNC', '拉取循环异常（已吞掉）: %s' % e)
        log('SYNC', '拉取线程已停止')

    # -------------------- 分系统 ↔ 分系统 P2P 同步 --------------------
    def build_peer_payload(self, since=0):
        """
        构造 P2P 同步数据包
        P2P 只同步证书 + 信任链 + CA 信息（用户数据不 P2P 同步）
        """
        payload = {
            'from_subsystem': self.subsystem_id,
            'since': since,
            'timestamp': now_ts(),
            'data': {
                'certificates': self.collect_certificates(since),
                'trust_chain': self.collect_trust_chain(since),
                'ca_info': self.collect_ca_info(since),
            }
        }
        if self.sync_token:
            payload['sync_token'] = self.sync_token
        return payload

    def sync_with_peer(self, peer_url):
        """
        与一个 peer 双向同步：
            1. 发送本地增量数据到 peer
            2. 接收 peer 返回的增量数据并合并
        :param peer_url: peer 的 URL
        :return: bool 是否成功
        """
        peer_url = str(peer_url).rstrip('/')
        if not peer_url:
            return False

        url = join_url(peer_url, '/api/sync/peer')
        t0 = now_ts()

        # 获取与该 peer 的最后同步时间（用于增量）
        since = self._get_peer_since(peer_url)
        payload = self.build_peer_payload(since)

        ok, result = http_post(url, payload)
        duration = now_ts() - t0
        sent_count = sum(len(v) for v in payload['data'].values())

        if not ok:
            self.log_sync(DIR_PEER_OUT, peer_url, 'peer', sent_count, 'fail', str(result), duration)
            self.update_sync_status(peer_url, DIR_PEER_OUT, 'fail', sent_count)
            log('SYNC', 'P2P 同步失败 peer=%s: %s' % (peer_url, result))
            return False

        # 合并 peer 返回的数据
        resp_data = result.get('data', {}) or {}
        peer_payload = resp_data.get('data', {}) if isinstance(resp_data, dict) else {}
        merged = self.merge_peer_data(peer_payload)

        # 更新与该 peer 的同步时间
        self._set_peer_since(peer_url, now_ts())
        total = sent_count + merged
        self.log_sync(DIR_PEER_OUT, peer_url, 'peer', total, 'ok', '', duration)
        self.update_sync_status(peer_url, DIR_PEER_OUT, 'ok', total)
        log('SYNC', 'P2P 同步成功 peer=%s sent=%d merged=%d (%.2fs)' % (
            peer_url, sent_count, merged, duration))
        return True

    def peer_loop(self, stop_event):
        """P2P 同步后台线程主循环"""
        log('SYNC', 'P2P 同步线程启动，间隔=%ds，peers=%d %s' % (
            self.peer_sync_interval, len(self.peers), self.peers))
        if not self.peers:
            log('SYNC', '无 peer 配置，P2P 线程空转')
        while not stop_event.wait(self.peer_sync_interval):
            for peer in list(self.peers):
                if stop_event.is_set():
                    break
                try:
                    self.sync_with_peer(peer)
                except Exception as e:
                    log('SYNC', 'P2P 同步异常 peer=%s: %s' % (peer, e))
        log('SYNC', 'P2P 同步线程已停止')

    def _get_peer_since(self, peer_url):
        """获取与某 peer 的最后同步时间"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT last_sync FROM sync_status WHERE peer=? AND direction=?",
                    (peer_url, DIR_PEER_OUT)
                )
                row = cur.fetchone()
                return float(row[0]) if row else 0.0
            finally:
                conn.close()

    def _set_peer_since(self, peer_url, ts):
        """更新与某 peer 的最后同步时间"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO sync_status (peer, direction, last_sync, last_status, last_count, consecutive_failures)
                    VALUES (?, ?, ?, 'ok', 0, 0)
                    ON CONFLICT(peer, direction) DO UPDATE SET last_sync=excluded.last_sync
                """, (peer_url, DIR_PEER_OUT, ts))
                conn.commit()
            finally:
                conn.close()

    # -------------------- 冲突解决 & 合并 --------------------
    def resolve_conflict(self, local, remote, strategy='timestamp'):
        """
        冲突解决核心逻辑
        :param local: 本地记录 dict 或 None
        :param remote: 远程记录 dict 或 None
        :param strategy: 'timestamp' / 'master'
        :return: 应保留的记录（local 或 remote），或 None
        """
        if local is None:
            return remote  # 本地不存在，采用远程
        if remote is None:
            return local  # 远程不存在，保留本地

        local_ts = float(local.get('last_modified', 0) or 0)
        remote_ts = float(remote.get('last_modified', 0) or 0)

        if strategy == 'master':
            # 总系统优先：远程覆盖本地（但仍检查时间戳避免回退）
            if remote_ts >= local_ts:
                return remote
            return local
        # 默认 timestamp 策略
        if remote_ts > local_ts:
            return remote
        return local

    def merge_users(self, remote_users, source='master'):
        """
        合并用户数据
        :param source: 'master'=总系统下发（优先覆盖）, 其他=时间戳比较
        """
        if not remote_users:
            return 0
        merged = 0
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                for u in remote_users:
                    if not isinstance(u, dict):
                        continue
                    callsign = u.get('callsign')
                    if not callsign:
                        continue
                    cur.execute("SELECT * FROM users WHERE callsign=?", (callsign,))
                    local = cur.fetchone()
                    remote_ts = float(u.get('last_modified', 0) or 0)

                    if local:
                        local_dict = dict(local)
                        local_ts = float(local_dict.get('last_modified', 0) or 0)

                        # 冲突解决
                        if source == 'master':
                            # 总系统优先：远程时间戳 >= 本地才覆盖
                            if remote_ts < local_ts:
                                continue
                            winner = u
                        else:
                            # 时间戳优先
                            if remote_ts <= local_ts:
                                continue
                            winner = u

                        deleted = int(winner.get('deleted', 0) or 0)
                        # last_heartbeat 是本机在线状态：本地原生用户（subsystem_id == 本机 ID）
                        # 的心跳不能被远端副本覆盖，否则会把本地在线用户"刷新"成远端旧时间
                        is_local_user = (local_dict.get('subsystem_id') == self.subsystem_id)
                        if is_local_user:
                            heartbeat = float(local_dict.get('last_heartbeat', 0) or 0)
                        else:
                            heartbeat = float(winner.get('last_heartbeat', 0) or 0)
                        cur.execute("""
                            UPDATE users SET name=?, phone=?, password_hash=?, last_heartbeat=?,
                                            last_modified=?, deleted=?, subsystem_id=?,
                                            guoji_id=?, dmr_id=?
                            WHERE callsign=?
                        """, (
                            winner.get('name', local_dict.get('name')),
                            winner.get('phone', local_dict.get('phone')),
                            # 远端没带密码字段（旧版对端）时保留本地密码，不覆盖
                            winner.get('password_hash') or local_dict.get('password_hash') or '',
                            heartbeat,
                            remote_ts,
                            deleted,
                            winner.get('subsystem_id', local_dict.get('subsystem_id')),
                            # 国服 ID：远端没带（旧版对端）时保留本地已有值
                            winner.get('guoji_id') or local_dict.get('guoji_id') or '',
                            winner.get('dmr_id') or local_dict.get('dmr_id') or '',
                            callsign
                        ))
                        merged += 1
                    else:
                        # 本地不存在，插入（携带远端 password_hash，实现一次注册全系统可登录）
                        cur.execute("""
                            INSERT INTO users (name, callsign, phone, password_hash, cert_photo_path,
                                              device_cert_path, token, last_heartbeat, created_at,
                                              last_modified, deleted, subsystem_id, guoji_id, dmr_id)
                            VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            u.get('name', ''),
                            callsign,
                            u.get('phone', ''),
                            u.get('password_hash') or '',
                            u.get('cert_photo_path', ''),
                            u.get('device_cert_path', ''),
                            float(u.get('last_heartbeat', 0) or 0),
                            float(u.get('created_at', 0) or remote_ts),
                            remote_ts,
                            int(u.get('deleted', 0) or 0),
                            u.get('subsystem_id', self.subsystem_id),
                            u.get('guoji_id') or '',
                            u.get('dmr_id') or '',
                        ))
                        merged += 1
                conn.commit()
            finally:
                conn.close()
        return merged

    def merge_certificates(self, remote_certs, source='master'):
        """
        合并证书吊销状态到 sas.db（认证生效库）。

        数据源为各系统 sas.db 的 certificates（cert_id = 用户证书指纹，
        deleted = 是否吊销）。MQTT 认证只依赖 sas.db 的 is_revoked()，
        因此这里只传播吊销状态，不把远端有效证书整体落地：
            - 本地已有该证书记录：远端较新（LWW）时更新 revoked/last_modified
            - 本地无记录且远端为吊销：插入吊销墓碑（无证书内容的占位行），
              保证跨系统吊销即时生效并继续传播
            - 本地无记录且远端为有效证书：不落地（有效证书由持有人在签发
              系统拉取；避免远端证书干扰本地自动签发的幂等查询）
        :return: 实际变更条数
        """
        if not remote_certs:
            return 0
        sas_path = getattr(self, 'sas_db_path', '')
        if not sas_path or not os.path.exists(sas_path):
            return 0
        merged = 0
        conn = self._get_sas_db()
        try:
            cur = conn.cursor()
            for c in remote_certs:
                if not isinstance(c, dict):
                    continue
                cert_id = c.get('cert_id')
                if not cert_id:
                    continue
                remote_ts = float(c.get('last_modified', 0) or 0)
                remote_deleted = int(c.get('deleted', 0) or 0)
                cur.execute("SELECT revoked, last_modified FROM certificates "
                            "WHERE fingerprint=?", (cert_id,))
                local = cur.fetchone()
                if local:
                    local_ts = float(local['last_modified'] or 0)
                    if remote_ts <= local_ts:
                        continue
                    cur.execute("""
                        UPDATE certificates SET revoked=?, last_modified=?
                        WHERE fingerprint=?
                    """, (remote_deleted, remote_ts, cert_id))
                    merged += 1
                elif remote_deleted:
                    # 吊销墓碑：本地从未见过该证书，但需让 is_revoked() 生效
                    cur.execute("""
                        INSERT INTO certificates (id, callsign, uid, cert_user_json,
                                                  cert_devicekey_json, fingerprint,
                                                  issued_at, revoked, last_modified)
                        VALUES (?, ?, 0, '', '', ?, ?, 1, ?)
                    """, (uuid.uuid4().hex, c.get('callsign', ''), cert_id,
                          float(c.get('issued_at', 0) or remote_ts), remote_ts))
                    merged += 1
                # 远端有效证书且本地无记录：不落地
            conn.commit()
        except Exception as e:
            conn.rollback()
            log('SYNC', '合并证书吊销状态失败: %s' % e)
        finally:
            conn.close()
        return merged

    @staticmethod
    def _sas_upsert_trust(cur, fp, ca_json, ca_type, trusted_by, remote_ts, deleted):
        """
        向 sas.db trust_chain 表 upsert 一条远程 CA 信任记录（LWW）。

        幂等关键：本地行未删除且本次也非删除 → 直接跳过。
        指纹是 CA 证书内容的哈希，同指纹必然同内容，无需刷新
        last_modified —— 避免 master 全量下发（merge_trust_issued 以当前
        时间作 ts）造成每次 pull 都刷新 last_modified、进而被 collect
        再次上报的心跳式流量。

        :return: 是否发生实际变更
        """
        cur.execute("SELECT deleted, last_modified FROM trust_chain "
                    "WHERE remote_ca_fingerprint=?", (fp,))
        local = cur.fetchone()
        if local:
            local_ts = float(local['last_modified'] or 0)
            if not local['deleted'] and not deleted:
                return False  # 同指纹同内容，幂等跳过
            if remote_ts <= local_ts:
                return False
            if deleted:
                cur.execute("""
                    UPDATE trust_chain SET deleted=1, last_modified=?
                    WHERE remote_ca_fingerprint=?
                """, (remote_ts, fp))
            else:
                # 复活：恢复内容并解除删除标记
                cur.execute("""
                    UPDATE trust_chain SET remote_ca_json=?, ca_type=?,
                                           trusted_by=?, deleted=0, last_modified=?
                    WHERE remote_ca_fingerprint=?
                """, (ca_json, ca_type, trusted_by, remote_ts, fp))
            return True
        # 无本地行：插入（含墓碑 —— 墓碑需落地才能继续传播删除状态）
        cur.execute("""
            INSERT INTO trust_chain (id, remote_ca_fingerprint, remote_ca_json,
                                     ca_type, trusted_by, created_at,
                                     last_modified, deleted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid.uuid4().hex, fp, ca_json, ca_type, trusted_by,
              remote_ts, remote_ts, 1 if deleted else 0))
        return True

    def merge_trust_chain(self, remote_chain, source='master'):
        """
        合并信任链数据到 sas.db trust_chain（认证生效库）。

        数据源为各系统 sas.db（trust_id = 'trust:<远程CA指纹>'，
        trust_data = 远程 CA 证书 JSON，from_subsystem = 添加者标识）。
        落点必须回到 sas.db，MQTT 认证的 is_trusted() 检查才能生效。
        """
        if not remote_chain:
            return 0
        sas_path = getattr(self, 'sas_db_path', '')
        if not sas_path or not os.path.exists(sas_path):
            return 0
        merged = 0
        conn = self._get_sas_db()
        try:
            cur = conn.cursor()
            for t in remote_chain:
                if not isinstance(t, dict):
                    continue
                trust_id = t.get('trust_id', '')
                fp = trust_id.split(':', 1)[1] if trust_id.startswith('trust:') else trust_id
                if not fp:
                    continue
                ca_json = t.get('trust_data', '') or ''
                deleted = int(t.get('deleted', 0) or 0)
                if not ca_json and not deleted:
                    continue  # 非删除条目必须携带 CA 内容
                if self._sas_upsert_trust(
                        cur, fp, ca_json,
                        ca_type=t.get('ca_type') or 'rootCA',
                        trusted_by=t.get('from_subsystem') or source,
                        remote_ts=float(t.get('last_modified', 0) or 0),
                        deleted=deleted):
                    merged += 1
            conn.commit()
        except Exception as e:
            conn.rollback()
            log('SYNC', '合并信任链失败: %s' % e)
        finally:
            conn.close()
        return merged

    def merge_trust_issued(self, entries):
        """
        合并 master 全量下发的信任背书（master_trust_issued）。

        master 为每个受信分系统 CA 签发 trustCert 表示总系统背书。
        分系统 pull 后把对应远程 CA 落入 sas.db trust_chain
        （trusted_by='master_sync'），MQTT 认证即可信任该分系统
        签发的用户证书 —— 无需管理员手动互相添加信任。

        全量替换语义：trusted_by='master_sync' 且不在本次下发集合中的
        本地行被软删（即 master 吊销背书的传播）。手动添加的信任
        （trusted_by 为其他值）不受 prune 影响 —— 手动优先。

        :return: 实际变更条数
        """
        if entries is None:
            return 0
        sas_path = getattr(self, 'sas_db_path', '')
        if not sas_path or not os.path.exists(sas_path):
            return 0
        merged = 0
        now = now_ts()
        conn = self._get_sas_db()
        try:
            cur = conn.cursor()
            keep_fps = set()
            for e in entries:
                if not isinstance(e, dict):
                    continue
                # 本机 CA 天然受信（is_local），无需落信任行
                if e.get('subsystem_id') == self.subsystem_id:
                    continue
                fp = e.get('remote_ca_fingerprint')
                ca_json = e.get('remote_ca_json', '') or ''
                if not fp or not ca_json:
                    continue
                # 根证书接种语义（江苏 add-root 模式的自动版）：
                # 校验根 CA 结构与自签名，无效根不接种、也不进 keep 集合
                # （若此前已落库会被下面的 prune 清掉）
                try:
                    _root_cert = json.loads(ca_json)
                except Exception:
                    continue
                if _CERT_GEN_AVAILABLE and not validate_root_ca_cert(_root_cert):
                    log('SYNC', '根 CA 自签名校验失败，跳过接种: fp=%s' % str(fp)[:20])
                    continue
                keep_fps.add(fp)
                if self._sas_upsert_trust(cur, fp, ca_json, 'rootCA',
                                          'master_sync', now, 0):
                    merged += 1
            # 全量替换：master 已吊销/移除的背书 → 本地软删
            cur.execute("SELECT remote_ca_fingerprint FROM trust_chain "
                        "WHERE trusted_by='master_sync' AND deleted=0")
            for row in cur.fetchall():
                fp = row['remote_ca_fingerprint']
                if fp not in keep_fps:
                    cur.execute("""
                        UPDATE trust_chain SET deleted=1, last_modified=?
                        WHERE remote_ca_fingerprint=? AND trusted_by='master_sync'
                    """, (now, fp))
                    merged += 1
            conn.commit()
        except Exception as e:
            conn.rollback()
            log('SYNC', '合并信任背书失败: %s' % e)
        finally:
            conn.close()
        return merged

    def merge_ca_info(self, remote_ca, source='master'):
        """合并 CA 信息数据"""
        if not remote_ca:
            return 0
        merged = 0
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                for c in remote_ca:
                    if not isinstance(c, dict):
                        continue
                    ca_id = c.get('ca_id')
                    if not ca_id:
                        continue
                    cur.execute("SELECT * FROM ca_info WHERE ca_id=?", (ca_id,))
                    local = cur.fetchone()
                    remote_ts = float(c.get('last_modified', 0) or 0)

                    if local:
                        local_dict = dict(local)
                        local_ts = float(local_dict.get('last_modified', 0) or 0)

                        if source == 'master':
                            if remote_ts < local_ts:
                                continue
                        else:
                            if remote_ts <= local_ts:
                                continue

                        cur.execute("""
                            UPDATE ca_info SET ca_type=?, ca_name=?, public_key=?, ca_cert_data=?,
                                             valid_from=?, valid_to=?, last_modified=?, deleted=?
                            WHERE ca_id=?
                        """, (
                            c.get('ca_type', local_dict.get('ca_type')),
                            c.get('ca_name', local_dict.get('ca_name')),
                            c.get('public_key', local_dict.get('public_key')),
                            c.get('ca_cert_data', local_dict.get('ca_cert_data')),
                            float(c.get('valid_from', 0) or 0),
                            float(c.get('valid_to', 0) or 0),
                            remote_ts,
                            int(c.get('deleted', 0) or 0),
                            ca_id
                        ))
                        merged += 1
                    else:
                        cur.execute("""
                            INSERT INTO ca_info (ca_id, ca_type, ca_name, public_key, ca_cert_data,
                                               valid_from, valid_to, last_modified, deleted)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            ca_id,
                            c.get('ca_type', ''),
                            c.get('ca_name', ''),
                            c.get('public_key', ''),
                            c.get('ca_cert_data', ''),
                            float(c.get('valid_from', 0) or 0),
                            float(c.get('valid_to', 0) or 0),
                            remote_ts,
                            int(c.get('deleted', 0) or 0)
                        ))
                        merged += 1
                conn.commit()
            finally:
                conn.close()
        return merged

    def merge_all(self, data, source='master'):
        """
        合并所有数据类型
        :param source: 'master' / 'peer' / 'subsystem_report'
        :return: 总合并条数
        """
        if not isinstance(data, dict):
            return 0
        total = 0
        total += self.merge_users(data.get('users', []), source=source)
        total += self.merge_certificates(data.get('certificates', []), source=source)
        total += self.merge_trust_chain(data.get('trust_chain', []), source=source)
        total += self.merge_ca_info(data.get('ca_info', []), source=source)
        # master 信任背书（全量下发、全量替换 prune）——仅 master pull 携带；
        # 以键是否存在区分"旧版 master 未实现该字段"（跳过）与
        # "master 下发了空集"（= 全部背书已吊销，需 prune 清空）
        if source == 'master' and 'trust_issued' in data:
            total += self.merge_trust_issued(data.get('trust_issued') or [])
        return total

    def merge_peer_data(self, data):
        """
        合并 P2P 数据（只合并证书 + 信任链 + CA，不合并用户）
        :return: 合并条数
        """
        if not isinstance(data, dict):
            return 0
        total = 0
        total += self.merge_certificates(data.get('certificates', []), source='peer')
        total += self.merge_trust_chain(data.get('trust_chain', []), source='peer')
        total += self.merge_ca_info(data.get('ca_info', []), source='peer')
        return total

    # -------------------- 同步状态管理 --------------------
    def log_sync(self, direction, peer, data_type, count, status, error='', duration=0.0):
        """记录同步日志"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO sync_log (timestamp, direction, peer, data_type, count, status, error, duration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (now_ts(), direction, peer, data_type, count, status, error, duration))
                conn.commit()
            except Exception as e:
                log('SYNC', '记录日志失败: %s' % e)
            finally:
                conn.close()

    def update_sync_status(self, peer, direction, status, count):
        """更新同步状态"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                if status == 'ok':
                    cur.execute("""
                        INSERT INTO sync_status (peer, direction, last_sync, last_status, last_count, consecutive_failures)
                        VALUES (?, ?, ?, 'ok', ?, 0)
                        ON CONFLICT(peer, direction) DO UPDATE SET
                            last_sync=excluded.last_sync,
                            last_status='ok', last_count=excluded.last_count, consecutive_failures=0
                    """, (peer, direction, now_ts(), count))
                else:
                    cur.execute("""
                        INSERT INTO sync_status (peer, direction, last_sync, last_status, last_count, consecutive_failures)
                        VALUES (?, ?, ?, 'fail', ?, 1)
                        ON CONFLICT(peer, direction) DO UPDATE SET
                            last_sync=excluded.last_sync,
                            last_status='fail', consecutive_failures=consecutive_failures+1
                    """, (peer, direction, now_ts(), count))
                conn.commit()
            except Exception as e:
                log('SYNC', '更新状态失败: %s' % e)
            finally:
                conn.close()

    def get_sync_status(self):
        """获取同步状态（含最近 50 条日志）"""
        with self._db_lock:
            conn = self.get_db()
            try:
                cur = conn.cursor()
                cur.execute("SELECT * FROM sync_status ORDER BY last_sync DESC")
                status = [dict(r) for r in cur.fetchall()]
                cur.execute("SELECT * FROM sync_log ORDER BY timestamp DESC LIMIT 50")
                recent = [dict(r) for r in cur.fetchall()]
                return {'status': status, 'recent_log': recent}
            finally:
                conn.close()

    # -------------------- API handler 方法 --------------------
    # 供 HTTP 服务器调用，handler 需提供：
    #   - handler.send_json(data, code=200)
    #   - handler.read_body() -> bytes

    @staticmethod
    def _read_json_body(handler):
        """从 handler 读取并解析 JSON body"""
        try:
            body = handler.read_body()
            if not body:
                return None
            return json.loads(body.decode('utf-8'))
        except Exception:
            return None

    def handle_api_sync_report(self, handler):
        """
        总系统端：接收分系统上报
        POST /api/sync/report
        """
        try:
            data = self._read_json_body(handler)
            if not data:
                handler.send_json({'ok': False, 'error': 'empty body or invalid json'}, 400)
                return
            sub_id = data.get('subsystem_id')
            if not sub_id:
                handler.send_json({'ok': False, 'error': 'missing subsystem_id'}, 400)
                return
            # 可选令牌校验：配置 sync_token 后推送方必须携带（防伪造数据注入）
            if self.sync_token and data.get('sync_token') != self.sync_token:
                handler.send_json({'ok': False, 'error': 'invalid sync_token'}, 403)
                return

            t0 = now_ts()
            payload_data = data.get('data', {}) or {}
            # 标记数据来源分系统
            for u in payload_data.get('users', []):
                if isinstance(u, dict):
                    u.setdefault('subsystem_id', sub_id)
            for c in payload_data.get('certificates', []):
                if isinstance(c, dict):
                    c.setdefault('subsystem_id', sub_id)

            merged = self.merge_all(payload_data, source='master')
            # 记录接收日志/状态（管理后台可见，master 主动推送可观测）
            self.log_sync(DIR_PEER_IN, sub_id, 'all', merged, 'ok',
                          duration=now_ts() - t0)
            self.update_sync_status(sub_id, DIR_PEER_IN, 'ok', merged)
            handler.send_json({
                'ok': True,
                'subsystem_id': sub_id,
                'full': data.get('full', False),
                'merged': merged,
                'timestamp': now_ts()
            })
        except Exception as e:
            log('SYNC', 'handle_report 异常: %s' % e)
            handler.send_json({'ok': False, 'error': str(e)}, 500)

    def handle_api_sync_pull(self, handler):
        """
        总系统端：返回全量数据
        GET /api/sync/pull
        """
        try:
            data = self.collect_all(since=0)
            handler.send_json({
                'ok': True,
                'timestamp': now_ts(),
                'data': data,
                'counts': {k: len(v) for k, v in data.items()}
            })
        except Exception as e:
            log('SYNC', 'handle_pull 异常: %s' % e)
            handler.send_json({'ok': False, 'error': str(e)}, 500)

    def handle_api_sync_peer(self, handler):
        """
        分系统端：接收 P2P 同步数据
        POST /api/sync/peer
        请求体：{from_subsystem, since, timestamp, data:{certificates, trust_chain, ca_info}}
        响应体：{ok, from_subsystem, merged, data:{certificates, trust_chain, ca_info}}
        """
        try:
            data = self._read_json_body(handler)
            if not data:
                handler.send_json({'ok': False, 'error': 'empty body or invalid json'}, 400)
                return

            from_sub = data.get('from_subsystem', 'unknown')
            # 可选令牌校验：配置 sync_token 后对端必须携带（防伪造数据注入）
            if self.sync_token and data.get('sync_token') != self.sync_token:
                handler.send_json({'ok': False, 'error': 'invalid sync_token'}, 403)
                return
            payload_data = data.get('data', {}) or {}

            # P2P 只合并证书 + 信任链 + CA（不合并用户）
            merged = self.merge_peer_data(payload_data)
            self.log_sync(DIR_PEER_IN, from_sub, 'peer', merged, 'ok')

            # 返回本地增量数据给 peer（基于请求中的 since）
            since = float(data.get('since', 0) or 0)
            resp_data = {
                'certificates': self.collect_certificates(since),
                'trust_chain': self.collect_trust_chain(since),
                'ca_info': self.collect_ca_info(since),
            }
            handler.send_json({
                'ok': True,
                'from_subsystem': self.subsystem_id,
                'merged': merged,
                'data': resp_data
            })
        except Exception as e:
            log('SYNC', 'handle_peer 异常: %s' % e)
            handler.send_json({'ok': False, 'error': str(e)}, 500)

    def handle_api_sync_status(self, handler):
        """
        返回同步状态
        GET /api/sync/status
        """
        try:
            status = self.get_sync_status()
            handler.send_json({
                'ok': True,
                'subsystem_id': self.subsystem_id,
                'mode': self.mode,
                'master_url': self.master_url,
                'peers': self.peers,
                'last_report_time': self._last_report_time,
                'last_full_report_time': self._last_full_report_time,
                **status
            })
        except Exception as e:
            log('SYNC', 'handle_status 异常: %s' % e)
            handler.send_json({'ok': False, 'error': str(e)}, 500)

    # -------------------- 启动 / 停止 --------------------
    def start(self):
        """启动后台同步线程（仅 subsystem 模式启动主动同步）"""
        if self.mode == 'subsystem':
            # 上报线程
            t1 = threading.Thread(
                target=self.report_loop, args=(self._stop_event,),
                name='SyncReportThread', daemon=True
            )
            self._threads.append(t1)
            t1.start()

            # 拉取线程
            t2 = threading.Thread(
                target=self.pull_loop, args=(self._stop_event,),
                name='SyncPullThread', daemon=True
            )
            self._threads.append(t2)
            t2.start()

            # P2P 线程（有 peer 才启动）
            if self.peers:
                t3 = threading.Thread(
                    target=self.peer_loop, args=(self._stop_event,),
                    name='SyncPeerThread', daemon=True
                )
                self._threads.append(t3)
                t3.start()

        log('SYNC', 'SyncEngine 已启动 mode=%s threads=%d' % (self.mode, len(self._threads)))

    def stop(self):
        """停止所有后台线程"""
        self._stop_event.set()
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=5)
        self._threads = []
        log('SYNC', 'SyncEngine 已停止')

    # -------------------- 便捷：标记本地数据变更 --------------------
    def touch_user(self, callsign):
        """标记用户数据已变更（更新 last_modified）"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE users SET last_modified=? WHERE callsign=?",
                    (now_ts(), callsign)
                )
                conn.commit()
            finally:
                conn.close()

    def touch_certificate(self, cert_id):
        """标记证书数据已变更"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE certificates SET last_modified=? WHERE cert_id=?",
                    (now_ts(), cert_id)
                )
                conn.commit()
            finally:
                conn.close()

    def touch_trust(self, trust_id):
        """标记信任链数据已变更"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE trust_chain SET last_modified=? WHERE trust_id=?",
                    (now_ts(), trust_id)
                )
                conn.commit()
            finally:
                conn.close()

    def touch_ca(self, ca_id):
        """标记 CA 信息已变更"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE ca_info SET last_modified=? WHERE ca_id=?",
                    (now_ts(), ca_id)
                )
                conn.commit()
            finally:
                conn.close()

    # -------------------- soft delete --------------------
    def soft_delete_user(self, callsign):
        """软删除用户（标记 deleted=1）"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE users SET deleted=1, last_modified=? WHERE callsign=?",
                    (now_ts(), callsign)
                )
                conn.commit()
            finally:
                conn.close()

    def soft_delete_certificate(self, cert_id):
        """软删除证书"""
        with self._db_lock:
            conn = self.get_db()
            try:
                conn.execute(
                    "UPDATE certificates SET deleted=1, last_modified=? WHERE cert_id=?",
                    (now_ts(), cert_id)
                )
                conn.commit()
            finally:
                conn.close()


# ==================== HTTP Handler Mixin ====================
class SyncApiMixin:
    """
    HTTP Handler Mixin，提供 /api/sync/* 路由分发

    使用方式：
        class ApiHandler(SyncApiMixin, http.server.BaseHTTPRequestHandler):
            sync_engine = sync_engine  # 设置类属性

            def send_json(self, data, code=200):
                ...

            def read_body(self):
                ...

            def do_GET(self):
                if self.handle_sync_routes('GET', self.path):
                    return
                # ... 原有路由

            def do_POST(self):
                if self.handle_sync_routes('POST', self.path):
                    return
                # ... 原有路由

    注意：sync_engine 必须作为类属性设置（而非实例属性），
    因为 BaseHTTPRequestHandler 每次请求会创建新实例。
    """

    # 类属性，由外部设置：SyncApiMixin.sync_engine = engine
    sync_engine = None

    def handle_sync_routes(self, method, path):
        """
        分发 /api/sync/* 路由
        :param method: 'GET' 或 'POST'
        :param path: 请求路径
        :return: True 如果路由被处理，False 如果不匹配
        """
        engine = self.__class__.sync_engine
        if engine is None:
            return False

        # 去除 query string
        if '?' in path:
            path = path.split('?', 1)[0]

        if method == 'GET' and path == '/api/sync/status':
            engine.handle_api_sync_status(self)
            return True

        if method == 'GET' and path == '/api/sync/pull':
            engine.handle_api_sync_pull(self)
            return True

        if method == 'POST' and path == '/api/sync/report':
            engine.handle_api_sync_report(self)
            return True

        if method == 'POST' and path == '/api/sync/peer':
            engine.handle_api_sync_peer(self)
            return True

        return False


# ==================== 独立运行入口（自测/调试） ====================
def _self_test():
    """
    独立运行自测：创建临时数据库，验证基本功能
    用法：python sync_engine.py
    """
    import tempfile
    import http.server
    import socketserver

    print("=" * 60)
    print("FMO 分布式同步引擎 - 自测模式")
    print("=" * 60)

    # 临时数据库
    tmp_dir = tempfile.mkdtemp(prefix='fmo_sync_test_')
    db_path = os.path.join(tmp_dir, 'test.db')
    print("临时数据库: %s" % db_path)

    config = {
        'subsystem_id': 'sub-test-001',
        'name': '测试分系统',
        'master_url': 'http://127.0.0.1:35999',
        'peers': [],
        'sync_interval': 5,
        'full_report_interval': 10,
        'pull_interval': 5,
        'peer_sync_interval': 5,
    }

    engine = SyncEngine(config, db_path, mode='subsystem')
    print("SyncEngine 创建成功: mode=%s, sub_id=%s" % (engine.mode, engine.subsystem_id))

    # 插入测试数据
    with engine.get_db() as conn:
        conn.execute("""
            INSERT INTO users (name, callsign, phone, password_hash, created_at, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('测试用户', 'BH1TEST', '13800000000', 'hash', now_ts(), now_ts()))
        conn.execute("""
            INSERT INTO certificates (cert_id, callsign, cert_type, cert_data, issued_at, last_modified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('cert-001', 'BH1TEST', 'user', 'cert-data', now_ts(), now_ts()))
        conn.commit()
    print("已插入测试数据")

    # 测试收集
    users = engine.collect_users()
    certs = engine.collect_certificates()
    print("收集用户: %d 条" % len(users))
    print("收集证书: %d 条" % len(certs))

    # 测试上报数据包构造
    payload = engine.build_report_payload(full=True)
    print("上报数据包: counts=%s" % payload['counts'])

    # 测试状态
    status = engine.get_sync_status()
    print("同步状态: %d 条记录" % len(status['status']))

    # 启动引擎（后台线程会尝试连接不存在的 master，会失败但不影响）
    engine.start()
    print("引擎已启动，运行 3 秒...")
    time.sleep(3)
    engine.stop()

    print("=" * 60)
    print("自测完成（后台线程的失败是正常的，因为 master_url 不存在）")
    print("=" * 60)


if __name__ == '__main__':
    _self_test()