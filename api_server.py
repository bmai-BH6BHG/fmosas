# -*- coding: utf-8 -*-
"""
FMO 注册系统 - 分系统后端 API 服务
前后端分离版本：仅提供 API（供 APP 公网调用）+ 后台线程上报总系统
管理后台 HTML 不在此服务暴露（admin/index.html 仅内网使用）

仅使用 Python 3 标准库实现（http.server + sqlite3 + json + hashlib + os + time
+ uuid + base64 + re + threading + urllib.request）
端口默认 35928
"""

import http.server
import socketserver
import socket
import sqlite3
import json
import hashlib
import os
import time
import uuid
import base64
import re
import sys
import argparse
import threading
import io
import zipfile
import urllib.request
import urllib.error
from urllib.parse import urlparse, parse_qs, unquote, quote

# ==================== 整合 SAS 认证服务 + 分布式同步引擎 ====================
# 导入 sas_server 和 sync_engine 模块的核心类/函数
# 注意：sas_server 顶部会自动把 _HERE 和 D:\fmo-server-deploy 加入 sys.path
# 以便找到 cert_gen 模块（Ed25519/CBOR 证书生成与验证）
try:
    from sas_server import (
        Database as SasDatabase,        # SAS 独立 SQLite（certificates/trust_chain/ca_info）
        CaManager,                     # Root CA + Int CA 管理器
        authenticate,                  # SAS 认证核心逻辑（POST /auth）
        load_config as sas_load_config,  # SAS 配置加载（避免与本文件 load_config 冲突）
        DEFAULT_CONFIG as SAS_DEFAULT_CONFIG,
    )
    _SAS_AVAILABLE = True
    print("[INIT] sas_server 模块加载成功")
except Exception as _e_sas:
    _SAS_AVAILABLE = False
    SasDatabase = None
    CaManager = None
    authenticate = None
    sas_load_config = None
    SAS_DEFAULT_CONFIG = {}
    print("[INIT] sas_server 模块加载失败（SAS 相关 API 将不可用）: %s" % _e_sas)

try:
    from sync_engine import SyncEngine, SyncApiMixin
    _SYNC_AVAILABLE = True
    print("[INIT] sync_engine 模块加载成功")
except Exception as _e_sync:
    _SYNC_AVAILABLE = False
    SyncEngine = None
    SyncApiMixin = object  # 占位基类，保证继承语法不报错
    print("[INIT] sync_engine 模块加载失败（同步相关 API 将不可用）: %s" % _e_sync)

try:
    from monitor import VoiceMonitor, ogg_wrap_opus
    _MONITOR_AVAILABLE = True
    print("[INIT] monitor 模块加载成功")
except Exception as _e_mon:
    _MONITOR_AVAILABLE = False
    VoiceMonitor = None
    print("[INIT] monitor 模块加载失败（语音监控 API 将不可用）: %s" % _e_mon)

try:
    from cert_gen import (
        b64url_decode, ed25519_verify, derive_keypair,
        BIND_KEY_PROOF_PREFIX, KDF_SALT_PREFIX, APP_AUTH_PREFIX,
    )
    _CERT_GEN_AVAILABLE = True
except Exception as _e_cg:
    b64url_decode = None
    ed25519_verify = None
    derive_keypair = None
    BIND_KEY_PROOF_PREFIX = "FMO-DMRID-bind:"
    KDF_SALT_PREFIX = "FMO-DMRID-v1"
    APP_AUTH_PREFIX = "FMO-APP-auth"
    _CERT_GEN_AVAILABLE = False
    print("[INIT] cert_gen 模块加载失败（国服ID绑定功能不可用）: %s" % _e_cg)

# ==================== BAS：内嵌 FAS 审计子系统（Python 重写，无 .NET 依赖）====================
# 把原 FAS（.NET）的审计能力并入本进程：EMQX 对接、逐包身份核对、黑名单、
# 排行榜、主题统计、在线列表、健康监控、待审救援。路由见 bas_http.py。
try:
    from bas_http import init_bas
    _BAS_AVAILABLE = True
    print("[INIT] bas_http 模块加载成功（审计子系统可用）")
except Exception as _e_bas:
    init_bas = None
    _BAS_AVAILABLE = False
    print("[INIT] bas_http 模块加载失败（审计子系统不可用）: %s" % _e_bas)

# ==================== FMO 站点目录（可以进入的中继/服务器）====================
try:
    import fmo_stations
    _STATIONS_AVAILABLE = True
except Exception as _e_st:
    fmo_stations = None
    _STATIONS_AVAILABLE = False
    print("[INIT] fmo_stations 模块加载失败（站点目录不可用）: %s" % _e_st)

# ==================== APRS 台站发现（FMO 台站只能从 APRS-IS 扫）====================
try:
    import fmo_aprs
    _APRS_AVAILABLE = True
except Exception as _e_aprs:
    fmo_aprs = None
    _APRS_AVAILABLE = False
    print("[INIT] fmo_aprs 模块加载失败（APRS 台站发现不可用）: %s" % _e_aprs)

# ==================== MQTT 互联桥接（FUS 之间语音互传，无主）====================
try:
    from bridge import VoiceBridge, load_bridge_config
    _BRIDGE_AVAILABLE = True
except Exception as _e_br:
    VoiceBridge = None
    load_bridge_config = None
    _BRIDGE_AVAILABLE = False
    print("[INIT] bridge 模块加载失败（MQTT 互联不可用）: %s" % _e_br)

_BRIDGE = None          # 桥接服务单例（main() 里创建）

# ==================== 全局配置 ====================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = None  # 稍后在 CONFIG 加载后基于域名/IP 动态设置
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
PORT = 35928
ONLINE_TIMEOUT = 15  # 在线判定：最后心跳在 15 秒内 = 在线
MAX_PHOTO_SIZE = 5 * 1024 * 1024  # 图片最大 5MB
ALLOWED_PHOTO_EXT = (".jpg", ".jpeg", ".png")  # 只接受 jpg/png
MAX_BODY_SIZE = 16 * 1024 * 1024  # 请求体上限（注册含两张 ≤5MB 图片 + multipart 开销）

# 呼号合法性正则（业余无线电呼号，如 BH1ACG）
CALLSIGN_PATTERN = re.compile(r'^[A-Z]{1,2}\d[A-Z]{1,4}$')


# ==================== 数据库命名前缀工具（基于域名/IP，避免多系统部署冲突） ====================
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
    用于从旧命名（如 users.db）平滑升级到新命名（如 {prefix}_users.db），避免数据丢失。
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


# ==================== 配置加载 ====================
def generate_subsystem_id():
    """
    基于主机名和 MAC 地址自动生成唯一的分系统 ID。
    同一台机器每次生成相同的 ID（确定性生成）。
    """
    hostname = socket.gethostname()
    # 尝试获取 MAC 地址作为额外唯一性来源
    mac = ""
    try:
        import uuid as _uuid
        mac = _uuid.getnode().to_bytes(6, 'big').hex()
    except Exception:
        pass
    # 用 uuid5 基于主机名+MAC 生成确定性 UUID，取前 8 位
    unique = uuid.uuid5(uuid.NAMESPACE_DNS, "%s|%s" % (hostname, mac)).hex[:8]
    return "sub-" + unique


def load_config():
    """
    读取 config.json 配置文件
    返回 dict；若文件不存在或解析失败则返回默认配置

    重要：subsystem_id 会自动生成唯一值，避免多个分系统用相同 ID 导致互相覆盖。
    """
    default_config = {
        "subsystem_id": "",
        "name": "FMO注册系统-默认",
        "domain": "register.example.com",
        "api_url": "https://register.example.com:35928",
        "port": 35928,
        "master_url": "http://127.0.0.1:35930",
        "report_interval": 30
    }
    try:
        if not os.path.exists(CONFIG_PATH):
            print("[CONFIG] config.json 不存在，使用默认配置")
            cfg = default_config
        else:
            with open(CONFIG_PATH, 'r', encoding='utf-8-sig') as f:
                cfg = json.load(f)
            # 合并默认配置（保证字段完整）
            for k, v in default_config.items():
                if k not in cfg:
                    cfg[k] = v

        # 自动生成唯一的 subsystem_id
        # 如果 subsystem_id 为空、或者是默认值 "sub-001"，则自动生成
        sub_id = cfg.get('subsystem_id', '')
        if not sub_id or sub_id == 'sub-001':
            cfg['subsystem_id'] = generate_subsystem_id()
            print("[CONFIG] 自动生成 subsystem_id: %s" % cfg['subsystem_id'])
            # 持久化到 config.json，下次启动不用再生成
            try:
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, indent=4, ensure_ascii=False)
            except Exception as e:
                print("[CONFIG] 保存 subsystem_id 失败: %s" % e)

        print("[CONFIG] 配置加载成功: subsystem_id=%s, name=%s" % (cfg.get('subsystem_id'), cfg.get('name')))
        return cfg
    except Exception as e:
        print("[CONFIG] 配置加载失败: %s，使用默认配置" % e)
        cfg = default_config
        cfg['subsystem_id'] = generate_subsystem_id()
        return cfg


# 全局配置实例
CONFIG = load_config()

# 根据配置动态生成数据库路径（基于域名/IP 前缀，避免多系统部署在同目录时数据库重名冲突）
DB_PATH = os.path.join(BASE_DIR, "%s_users.db" % get_db_prefix(CONFIG))
# 自动迁移旧数据库（users.db -> {prefix}_users.db），保证升级后不丢数据
_migrate_db(DB_PATH, ["users.db"])
print("[DB] 用户数据库路径: %s" % DB_PATH)


# ==================== SAS 服务全局对象 ====================
# 在 main() 中初始化，由 ApiHandler 通过类属性访问
# 不使用 sas_server.py 内部的全局变量 _CA_MGR/_DB/_CONFIG，避免状态混淆
_SAS_DB = None          # sas_server.Database 实例
_CA_MGR = None          # sas_server.CaManager 实例
_SAS_CONFIG = None      # SAS 配置 dict
_SYNC_ENGINE = None     # sync_engine.SyncEngine 实例
_AUTO_ISSUE_LOCK = threading.Lock()  # 自动签发全局锁（UID 分配串行化，防并发重号）


def init_sas_service():
    """
    初始化 SAS 认证服务：加载 SAS 配置、打开 SAS 数据库、初始化本地 CA。
    失败时不抛异常，仅打印日志（保证主服务能启动）。
    返回 (sas_db, ca_mgr, sas_config) 或 (None, None, None)
    """
    global _SAS_DB, _CA_MGR, _SAS_CONFIG
    if not _SAS_AVAILABLE:
        print("[SAS] sas_server 不可用，跳过 SAS 服务初始化")
        return None, None, None

    # 加载 SAS 配置（从同一个 config.json 读取 "sas" 节点或顶层字段）
    try:
        sas_config = sas_load_config(CONFIG_PATH)
    except Exception as e:
        print("[SAS] 配置加载失败: %s，使用默认配置" % e)
        sas_config = dict(SAS_DEFAULT_CONFIG)

    # 用 config.json 中的 sas_* / ca_dir / peers 等字段覆盖（统一配置入口）
    if 'ca_dir' in CONFIG:
        sas_config['ca_dir'] = CONFIG['ca_dir']
    # SAS 数据库路径：如果 config 中显式指定了非旧默认值则用配置值，否则用前缀动态生成
    sas_db_path_cfg = CONFIG.get('sas_db_path', '')
    if sas_db_path_cfg and sas_db_path_cfg != 'sas.db':
        sas_config['db_path'] = sas_db_path_cfg
    else:
        sas_config['db_path'] = os.path.join(BASE_DIR, "%s_sas.db" % get_db_prefix(CONFIG))
    if 'sas_ca_name' in CONFIG:
        sas_config['ca_name'] = CONFIG['sas_ca_name']
    if 'sas_validity_years' in CONFIG:
        sas_config['validity_years'] = CONFIG['sas_validity_years']

    # 转相对路径为绝对路径（基于 BASE_DIR）
    for key in ('ca_dir', 'db_path'):
        val = sas_config.get(key, '')
        if val and not os.path.isabs(val):
            sas_config[key] = os.path.join(BASE_DIR, val)

    # 自动迁移旧 SAS 数据库（sas.db -> {prefix}_sas.db）
    _migrate_db(sas_config['db_path'], ["sas.db"])

    # 打开 SAS 数据库
    try:
        sas_db = SasDatabase(sas_config['db_path'])
    except Exception as e:
        print("[SAS] 数据库初始化失败: %s" % e)
        return None, None, sas_config

    # 初始化 CA 管理器
    try:
        ca_mgr = CaManager(
            ca_dir=sas_config['ca_dir'],
            db=sas_db,
            ca_name=sas_config.get('ca_name', 'MYCA'),
            ca_email=sas_config.get('ca_email', ''),
            validity_years=sas_config.get('validity_years', 10),
            uid_start=sas_config.get('uid_start', 1),
            uid_end=sas_config.get('uid_end', 200000),
            issuing_countries=sas_config.get('issuing_countries', ['CN']),
        )
        ca_mgr.init()
    except Exception as e:
        print("[SAS] CA 管理器初始化失败: %s" % e)
        # 即使 CA 初始化失败，SAS 数据库仍可用（信任链 API 等仍可工作）
        ca_mgr = None

    _SAS_DB = sas_db
    _CA_MGR = ca_mgr
    _SAS_CONFIG = sas_config
    print("[SAS] SAS 服务初始化完成: ca_dir=%s, db=%s" % (
        sas_config.get('ca_dir'), sas_config.get('db_path')))
    return sas_db, ca_mgr, sas_config


def init_sync_service():
    """
    初始化分布式同步引擎并启动后台线程。
    失败时不抛异常，仅打印日志。
    返回 SyncEngine 实例或 None
    """
    global _SYNC_ENGINE
    if not _SYNC_AVAILABLE:
        print("[SYNC] sync_engine 不可用，跳过同步服务初始化")
        return None

    try:
        # 显式传入 SAS 数据库路径（证书/信任链的真实数据源），
        # 避免仅靠命名规则推导在自定义 sas_db_path 时失效
        sync_config = dict(CONFIG)
        if _SAS_CONFIG and _SAS_CONFIG.get('db_path'):
            sync_config['sas_db_path'] = _SAS_CONFIG['db_path']
        engine = SyncEngine(sync_config, DB_PATH, mode='subsystem', base_dir=BASE_DIR)
        engine.start()
        _SYNC_ENGINE = engine
        print("[SYNC] 同步引擎已启动: mode=subsystem, master_url=%s, peers=%s, sas_db=%s" % (
            CONFIG.get('master_url', ''), CONFIG.get('peers', []), engine.sas_db_path))
        return engine
    except Exception as e:
        print("[SYNC] 同步引擎初始化失败: %s" % e)
        return None


# SAS 配置默认值（用于 /api/sas/config GET/POST）
DEFAULT_SAS_RUNTIME_CONFIG = {
    'allowed_callsigns': [],        # 允许的呼号白名单（空表示不限制）
    'require_client_signature': False,  # 是否强制客户端签名
    # 强制 APP 签名时，这些内部服务/面板**豁免**（它们不是 APP，没有 APP 私钥）：
    #   SERVER          监控/语音服务用的呼号
    #   FMO-MONITOR*    监控子客户端
    #   fmo-web-*       网页 PTT 面板
    # 不豁免的话，一开强制就会把自家监控/网页打死。
    'client_signature_exempt_callsigns': ['SERVER'],
    'client_signature_exempt_prefixes': ['FMO-MONITOR', 'fmo-web-'],
    # 「仅证书客户端」：用 **FMO 固件**登录的用户。固件里没有 APP 私钥，
    # 永远签不出 app_signature —— 强制模式下必须放行，否则固件用户全部掉线。
    # 按呼号逐个加入（默认空）。
    'client_signature_certonly_callsigns': [],
    'auto_trust_local_ca': True,    # 自动信任本地 Root CA
    'uid_range': {'start': 1, 'end': 200000},
    'issuing_countries': ['CN'],
}

# SAS 运行时配置（可由 /api/sas/config 修改，持久化到 config.json 的 "sas_runtime" 节点）
SAS_RUNTIME_CONFIG = dict(DEFAULT_SAS_RUNTIME_CONFIG)


def load_sas_runtime_config():
    """从 config.json 加载 SAS 运行时配置"""
    global SAS_RUNTIME_CONFIG
    saved = CONFIG.get('sas_runtime', {})
    if isinstance(saved, dict):
        merged = dict(DEFAULT_SAS_RUNTIME_CONFIG)
        merged.update(saved)
        SAS_RUNTIME_CONFIG = merged


def save_sas_runtime_config():
    """把 SAS 运行时配置持久化到 config.json"""
    try:
        CONFIG['sas_runtime'] = SAS_RUNTIME_CONFIG
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(CONFIG, f, indent=4, ensure_ascii=False)
        print("[SAS] 运行时配置已保存")
    except Exception as e:
        print("[SAS] 运行时配置保存失败: %s" % e)


def save_config(cfg=None):
    """
    把当前 CONFIG 落盘到 config.json（原子替换）。

    先写临时文件再 os.replace：避免写一半被中断，把别人的配置文件截断成半截 JSON
    （那会导致下次启动直接起不来）。

    参数 cfg 只是为了兼容 save_fn(cfg) 这种调用约定 —— 调用方（如互联桥接）拿到的
    就是 CONFIG 本身并**原地修改**，所以这里直接存 CONFIG 即可。
    """
    try:
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(CONFIG, f, indent=4, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)
        return True
    except Exception as e:  # noqa: BLE001
        print("[CONFIG] 保存失败: %s" % e)
        return False


# 启动时加载 SAS 运行时配置
load_sas_runtime_config()


# ==================== 国服 ID（DMRID）绑定配置与客户端 ====================
# 目的：让「国服 ID（呼号）+ 密码」通过 KDF 派生一把 Ed25519 私钥，
#       再用本机 Int CA 把其公钥签进用户证书，实现：
#         - 用户无需保存/传输证书文件，凭国服账号密码即可完全接入（绑定→登录→MQTT）；
#         - MQTT 认证仍走证书链 + proof 私钥签名，密码不出现在 MQTT 报文。
# 与 DMRID 后端交互仅发生在「绑定」这一次（校验账号密码），之后不再调用。

DMRID_DEFAULT = {
    'enabled': False,                             # 是否启用国服ID绑定
    'base_url': 'https://dmriapi.radiowo.com',    # 国服后端 Base URL（不含 /api）
    'timeout': 10,                                # 国服请求超时（秒）
    # APP 签名公钥（base64url，Ed25519）。内置**官方 APP 公钥**，新装系统开箱即可
    # 校验官方 APP 的签名；不需要 APP 签名校验的部署可在 config.json 里显式设为 ""（fail-closed）。
    # 换密钥/补密钥用专门命令：sudo fus-set-appkey（见 set_appkey.py）。
    'app_pubkey': '4LL2krXOFvViFvbdP3pvTJK2pZXMIRNWQ6nz8jp5gr0',
    'app_timestamp_window': 300,                  # APP 签名时间戳允许窗口（秒）
    'verify_password': False,                     # False=仅查呼号存在(简化)；True=校验密码(强校验)
    'kdf_algorithm': 'pbkdf2',                    # pbkdf2 | scrypt（客户端派生用，须与 APP 一致）
    'kdf_pbkdf2_iterations': 600000,
    'kdf_scrypt_n': 32768,
    'kdf_scrypt_r': 8,
    'kdf_scrypt_p': 1,
    'dev_mode': False,                            # 自测模式：跳过真实国服查询（切勿生产开启）
}


def get_dmrid_config():
    """读取 config.json 的 dmrid 节（与默认值合并）。"""
    cfg = dict(DMRID_DEFAULT)
    saved = (CONFIG or {}).get('dmrid')
    if isinstance(saved, dict):
        cfg.update(saved)
    return cfg


def get_app_pubkeys(cfg=None):
    """返回 APP 签名公钥列表（base64url 字符串）。app_pubkey 支持单个字符串或列表。"""
    cfg = cfg if cfg is not None else get_dmrid_config()
    val = cfg.get('app_pubkey')
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    v = str(val or '').strip()
    return [v] if v else []


def app_signature_ok(body):
    """
    验证 APP 签名（Ed25519，防未授权绑定）。
    签名消息 = UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")
    - 未配置 app_pubkey：仅 dev_mode 放行（本地自测），生产一律拒绝（fail-closed）；
    - 校验时间戳新鲜度（±app_timestamp_window 秒）与 Ed25519 签名。
    """
    cfg = get_dmrid_config()
    pubkeys = get_app_pubkeys(cfg)
    if not pubkeys:
        return bool(cfg.get('dev_mode'))
    ts = body.get('app_timestamp')
    sig = body.get('app_signature')
    if ts in (None, '') or not sig:
        return False
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False
    window = int(cfg.get('app_timestamp_window', 300) or 300)
    if abs(time.time() - ts) > window:
        return False
    callsign = str(body.get('callsign', '')).strip().upper()
    pubkey_b64 = str(body.get('pubkey', '')).strip()
    msg = ("%s:%d:%s:%s" % (APP_AUTH_PREFIX, ts, callsign, pubkey_b64)).encode('utf-8')
    try:
        sig_bytes = b64url_decode(str(sig))
    except Exception:
        return False
    for pk_b64 in pubkeys:
        try:
            pk = b64url_decode(pk_b64)
            if len(pk) == 32 and ed25519_verify(pk, msg, sig_bytes):
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# APP 密钥绑定（MQTT 连接级）：确认连接确实来自「持有 APP 私钥的本 APP」
# ---------------------------------------------------------------------------
# 与 HTTP 侧 app_signature 的区别：HTTP 的签名信息是
#     FMO-APP-auth:{ts}:{callsign}:{pubkey}
# 只能证明"发请求的是真 APP"，可以被抓包后**重放到另一条 MQTT 连接**上。
# 因此 MQTT 侧用连接绑定式签名，把 clientid 与用户证书公钥一起签进去：
#     FMO-APP-mqtt:{ts}:{callsign}:{userPubkeyB64}:{clientid}
# 这样签名只对这一条连接有效；配合 300 秒时间窗，重放基本不可行。
# 校验通过 → client_attrs.app_verified="1"（EMQX 会写到连接上，审计据此判定"本 APP"）。
APP_MQTT_AUTH_PREFIX = "FMO-APP-mqtt"

# 内部服务/面板豁免：它们不是 APP，拿不到 APP 私钥，强制签名时必须放行
# （否则一开 require_client_signature，自家监控与网页 PTT 立刻掉线）
DEFAULT_SIGNATURE_EXEMPT_CALLSIGNS = ['SERVER']
DEFAULT_SIGNATURE_EXEMPT_PREFIXES = ['FMO-MONITOR', 'fmo-web-']
# 用 FMO 固件登录的用户：只有证书、没有 APP 私钥，强制模式下必须放行
DEFAULT_CERTONLY_CALLSIGNS = []


def app_signature_exempt(callsign, clientid):
    """
    判断该连接是否豁免 APP 签名要求。返回 (是否豁免, 原因)

    三类豁免：
      1) 内部服务呼号（SERVER）与内部客户端前缀（FMO-MONITOR / fmo-web-）
      2) 「仅证书客户端」= 用 FMO 固件登录的用户（固件没有 APP 私钥）
    """
    rt = SAS_RUNTIME_CONFIG or {}
    cs = str(callsign or '').strip().upper()
    cid = str(clientid or '')
    exempt_cs = rt.get('client_signature_exempt_callsigns')
    if exempt_cs is None:
        exempt_cs = DEFAULT_SIGNATURE_EXEMPT_CALLSIGNS
    exempt_pf = rt.get('client_signature_exempt_prefixes')
    if exempt_pf is None:
        exempt_pf = DEFAULT_SIGNATURE_EXEMPT_PREFIXES
    certonly = rt.get('client_signature_certonly_callsigns')
    if certonly is None:
        certonly = DEFAULT_CERTONLY_CALLSIGNS
    for x in (exempt_cs or []):
        if cs and cs == str(x).strip().upper():
            return True, "内部服务呼号 %s" % cs
    for p in (exempt_pf or []):
        if p and cid.startswith(str(p)):
            return True, "内部客户端前缀 %s" % p
    for x in (certonly or []):
        if cs and cs == str(x).strip().upper():
            return True, "仅证书客户端（FMO 固件用户）%s" % cs
    return False, ""


def _pw_data_of(password):
    """把 MQTT password（base64url(JSON)）解成 dict；失败返回 None。"""
    if not password or b64url_decode is None:
        return None
    try:
        raw = b64url_decode(str(password))
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return None


def _user_pubkey_of(pw_data):
    """从证书包里取用户证书公钥（b64url，32 字节 Ed25519）。"""
    try:
        cert = ((pw_data or {}).get('certPackage') or {}).get('userCert') or {}
        pk = ((cert.get('subject') or {}).get('publicKey')) or ''
        return str(pk)
    except Exception:
        return ''


def verify_app_mqtt_signature(password, clientid, callsign, log=None):
    """
    校验 MQTT 连接携带的 APP 签名。

    返回 {"ok":bool, "present":bool, "mode":str, "reason":str}
      mode = "bound"    连接绑定式签名校验通过（最强，推荐）
             "legacy"   只用了 HTTP 式签名（能证明是真 APP，但未绑定连接）
             "invalid"  带了签名但校验失败（可能被篡改/重放/时间窗过期）
             "none"     没有带签名
    """
    out = {"ok": False, "present": False, "mode": "none", "reason": "未提供 app_signature"}
    cfg = get_dmrid_config()
    pubkeys = get_app_pubkeys(cfg)
    if not pubkeys:
        out["reason"] = "服务端未配置 dmrid.app_pubkey（APP 签名校验未启用）"
        return out
    pw_data = _pw_data_of(password)
    if not pw_data:
        out["reason"] = "password 不是合法的 base64url(JSON)，无法读取 APP 签名"
        return out
    sig = pw_data.get('app_signature') or pw_data.get('appSignature')
    ts = pw_data.get('app_timestamp', pw_data.get('appTimestamp'))
    if not sig or ts in (None, ''):
        return out
    out["present"] = True
    out["reason"] = "签名存在但校验失败"
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        out["mode"] = "invalid"
        out["reason"] = "app_timestamp 不是整数"
        return out
    window = int(cfg.get('app_timestamp_window', 300) or 300)
    # 允许 5 秒的时钟偏移
    if abs(time.time() - ts) > (window + 5):
        out["mode"] = "invalid"
        out["reason"] = "app_timestamp 超出 %d 秒时间窗（服务端与 APP 时钟不同步？）" % window
        return out
    try:
        sig_bytes = b64url_decode(str(sig))
    except Exception:
        out["mode"] = "invalid"
        out["reason"] = "app_signature 不是合法 base64url"
        return out

    cs = str(callsign or '').strip().upper()
    pub_b64 = _user_pubkey_of(pw_data) or str(clientid or '')
    cid = str(clientid or '')
    candidates = [
        ("bound", "%s:%d:%s:%s:%s" % (APP_MQTT_AUTH_PREFIX, ts, cs, pub_b64, cid)),
        # 兼容：APP 尚未改造前，可直接复用 HTTP 式签名（弱一档，未绑定连接）
        ("legacy", "%s:%d:%s:%s" % (APP_AUTH_PREFIX, ts, cs, pub_b64)),
    ]
    for mode, msg in candidates:
        for pk_b64 in pubkeys:
            try:
                pk = b64url_decode(pk_b64)
                if len(pk) == 32 and ed25519_verify(pk, msg.encode('utf-8'), sig_bytes):
                    out.update({"ok": True, "mode": mode,
                                "reason": "APP 签名校验通过（%s）" % mode})
                    if log:
                        log("[AUTH] APP 签名通过: callsign=%s mode=%s clientid=%s"
                            % (cs, mode, cid))
                    return out
            except Exception:
                continue
    out["mode"] = "invalid"
    return out


def dmrid_login(login_id, password):
    """
    调用 DMRID 国服后端 POST /api/auth/login 校验账号密码。
    返回 (ok: bool, result: dict)：
        ok=True  -> result = {'user': {...}}（含 callsign / guojiId / dmrId / status）
        ok=False -> result = {'code': int, 'error': str}
    """
    cfg = get_dmrid_config()
    if not cfg.get('enabled'):
        return False, {'code': 503, 'error': '国服ID绑定未启用（config.dmrid.enabled=false）'}
    login_id = str(login_id or '').strip()
    if not login_id or not password:
        return False, {'code': 400, 'error': '呼号和密码不能为空'}

    # 自测模式：不真实调用国服后端，按呼号确定性合成 guojiId/dmrId（仅本地联调用）
    if cfg.get('dev_mode'):
        print("[DMRID] dev_mode 开启，跳过真实国服校验（仅限本地自测，严禁用于生产）")
        h = int(hashlib.md5(login_id.upper().encode('utf-8')).hexdigest(), 16)
        guoji = 4600000 + (h % 900000)
        dmr = 8600000 + (h % 900000)
        return True, {'user': {
            'callsign': login_id.upper(),
            'guojiId': guoji,
            'dmrId': dmr,
            'status': 'approved',
        }}

    base = str(cfg.get('base_url', '')).rstrip('/')
    timeout = int(cfg.get('timeout', 10))
    url = base + '/api/auth/login'
    body = json.dumps({'loginId': login_id, 'password': password}).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('User-Agent', 'FMO-Subsystem/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            payload = json.loads(resp.read().decode('utf-8', errors='ignore'))
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            payload = json.loads(e.read().decode('utf-8', errors='ignore'))
        except Exception:
            payload = {}
        msg = payload.get('message') or (
            '国服账号或密码错误' if code == 401 else '国服服务返回错误 %d' % code)
        return False, {'code': code, 'error': msg}
    except urllib.error.URLError as e:
        return False, {'code': 502, 'error': '无法连接国服后端: %s' % e.reason}
    except Exception as e:
        return False, {'code': 502, 'error': '调用国服后端异常: %s' % e}

    data = payload.get('data') or {}
    if code != 200 or payload.get('code') != 200 or not data:
        return False, {'code': code or 401,
                       'error': payload.get('message') or '国服登录失败'}
    user = data.get('user') or data
    status = str(user.get('status') or '')
    if status == 'blacklisted' or user.get('isDisabled'):
        return False, {'code': 403, 'error': '该账号已被限制使用，请联系管理员'}
    return True, {'user': user}


def dmrid_lookup(callsign):
    """
    简化校验：调用国服后端 GET /api/auth/callsign-lookup，仅确认「该呼号存在国服 ID」。
    返回 (ok: bool, result: dict)：
        ok=True  -> result = {'callsign': str, 'guojiId': int, 'dmrId': None}
        ok=False -> result = {'code': int, 'error': str}
    """
    cfg = get_dmrid_config()
    if not cfg.get('enabled'):
        return False, {'code': 503, 'error': '国服ID绑定未启用（config.dmrid.enabled=false）'}
    callsign = str(callsign or '').strip().upper()
    if not callsign:
        return False, {'code': 400, 'error': '呼号不能为空'}

    if cfg.get('dev_mode'):
        print("[DMRID] dev_mode 开启，按呼号合成 guojiId（仅限本地自测，严禁用于生产）")
        h = int(hashlib.md5(callsign.encode('utf-8')).hexdigest(), 16)
        return True, {'callsign': callsign,
                      'guojiId': 4600000 + (h % 900000), 'dmrId': None}

    base = str(cfg.get('base_url', '')).rstrip('/')
    timeout = int(cfg.get('timeout', 10))
    url = base + '/api/auth/callsign-lookup?callsign=' + quote(callsign)
    req = urllib.request.Request(url, method='GET')
    req.add_header('User-Agent', 'FMO-Subsystem/1.0')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            payload = json.loads(resp.read().decode('utf-8', errors='ignore'))
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            payload = json.loads(e.read().decode('utf-8', errors='ignore'))
        except Exception:
            payload = {}
        return False, {'code': code, 'error': payload.get('message') or '国服查询失败 %d' % code}
    except urllib.error.URLError as e:
        return False, {'code': 502, 'error': '无法连接国服后端: %s' % e.reason}
    except Exception as e:
        return False, {'code': 502, 'error': '调用国服后端异常: %s' % e}

    data = payload.get('data') or {}
    guoji_id = data.get('guojiId')
    if code != 200 or payload.get('code') != 200 or guoji_id is None:
        return False, {'code': 404, 'error': '该呼号未识别到国服 ID（国际 ID），无法绑定'}
    return True, {'callsign': str(data.get('callsign') or callsign).upper(),
                  'guojiId': guoji_id, 'dmrId': None}


# ==================== 数据库初始化 ====================
def init_db():
    """启动时自动建表、自动创建 uploads 目录"""
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # 用户表
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
    # 心跳日志表
    cur.execute("""
        CREATE TABLE IF NOT EXISTS heartbeat_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp REAL,
            device_info TEXT
        )
    """)
    # 同步字段兜底：即使 sync_engine 不可用，users 表也必须有这些列，
    # 否则 register/heartbeat 的 SQL 会报 no such column
    cur.execute("PRAGMA table_info(users)")
    existing_cols = {r[1] for r in cur.fetchall()}
    if 'last_modified' not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN last_modified REAL DEFAULT 0")
        cur.execute("UPDATE users SET last_modified = created_at WHERE last_modified = 0")
    if 'deleted' not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN deleted INTEGER DEFAULT 0")
    if 'subsystem_id' not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN subsystem_id TEXT")
        cur.execute("UPDATE users SET subsystem_id = ? WHERE subsystem_id IS NULL",
                    (CONFIG.get('subsystem_id', ''),))
    # 国服 ID 绑定字段（guojiId 国际 ID / dmrId DMR ID）
    if 'guoji_id' not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN guoji_id TEXT")
    if 'dmr_id' not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN dmr_id TEXT")
    conn.commit()
    conn.close()


# 占位常开连接：库路径 -> 连接（只占位，不做任何查询/写入）
_KEEPALIVE_CONNS = {}


def _ensure_keepalive(path):
    """
    为某个库保持一条**常开连接**（占位用，不读不写）。

    ★ 真实事故根因：SQLite 在**最后一个连接关闭时**会对 WAL 做一次 checkpoint。
      本模块（以及审计库、语音库、同步库）都是"每次操作新建连接再 close"，
      于是**每次写入的 close 都是最后一个连接** → 每次都全量 checkpoint →
      实测在 NAS 上每次写入约 1 秒：
          无保活：中位 1058 ms/次   有保活：中位 0.4 ms/次（快约 2500 倍）
      只要这条连接一直开着，其它连接的 close 就不再是最后一个，问题消失，
      而且**不需要改任何调用点**。
    """
    if path in _KEEPALIVE_CONNS:
        return
    try:
        k = sqlite3.connect(path, timeout=10, check_same_thread=False)
        k.execute("PRAGMA journal_mode=WAL;")
        k.execute("PRAGMA busy_timeout=10000;")
        _KEEPALIVE_CONNS[path] = k
    except Exception:  # noqa: BLE001
        pass          # 库还不存在等情况：下次再试


def get_db():
    """获取数据库连接（WAL 模式 + 超时，避免与 sync_engine 并发读写互锁）

    ★ 先确保有一条常开占位连接，否则每次写入的 close 都会触发全量 WAL checkpoint
      （实测每次约 1 秒，见 _ensure_keepalive）；另设 synchronous=NORMAL，
      避免每次 commit 都 fsync。
    """
    _ensure_keepalive(DB_PATH)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    return conn


# ==================== 工具函数 ====================
def sha256_hash(text):
    """SHA256 哈希"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def is_online(last_heartbeat):
    """判断是否在线"""
    if not last_heartbeat or last_heartbeat == 0:
        return False
    return (time.time() - last_heartbeat) < ONLINE_TIMEOUT


def format_time(ts):
    """格式化时间戳为可读字符串"""
    if not ts or ts == 0:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return "-"


def save_upload_file(file_data, original_filename):
    """
    保存上传文件到 uploads 目录
    文件名用 uuid + 原始扩展名
    返回保存后的文件名（仅文件名，不含路径）
    """
    # 取扩展名
    _, ext = os.path.splitext(original_filename)
    ext = ext.lower()
    if ext not in ALLOWED_PHOTO_EXT:
        return None
    # 生成 uuid 文件名
    new_filename = str(uuid.uuid4()).replace('-', '') + ext
    save_path = os.path.join(UPLOAD_DIR, new_filename)
    with open(save_path, 'wb') as f:
        f.write(file_data)
    return new_filename


# ==================== multipart/form-data 解析 ====================
def parse_multipart(body, boundary):
    """
    解析 multipart/form-data
    返回字典：{字段名: 值}，普通字段值为字符串，文件字段值为 dict(filename, data, content_type)
    """
    result = {}
    # boundary 分隔符
    delimiter = b'--' + boundary
    # 按 boundary 分割
    parts = body.split(delimiter)
    for part in parts:
        # 去除首尾空白
        part = part.strip(b'\r\n')
        if not part or part == b'--':
            continue
        # 分离头部和内容
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            continue
        header_bytes = part[:header_end]
        content_bytes = part[header_end + 4:]
        # 去除内容末尾的 \r\n
        if content_bytes.endswith(b'\r\n'):
            content_bytes = content_bytes[:-2]

        # 解析头部
        headers = {}
        for line in header_bytes.split(b'\r\n'):
            if b':' in line:
                key, val = line.split(b':', 1)
                headers[key.strip().lower()] = val.strip()

        # 解析 Content-Disposition
        cd = headers.get(b'content-disposition', b'').decode('utf-8', errors='ignore')
        if not cd:
            continue
        # 提取 name
        name_match = re.search(r'name="([^"]*)"', cd)
        if not name_match:
            continue
        field_name = name_match.group(1)
        # 提取 filename
        filename_match = re.search(r'filename="([^"]*)"', cd)

        if filename_match:
            # 文件字段
            filename = filename_match.group(1)
            content_type = headers.get(b'content-type', b'application/octet-stream').decode('utf-8', errors='ignore')
            result[field_name] = {
                'filename': filename,
                'data': content_bytes,
                'content_type': content_type
            }
        else:
            # 普通字段
            result[field_name] = content_bytes.decode('utf-8', errors='ignore')
    return result


def extract_boundary(content_type):
    """从 Content-Type 头提取 boundary"""
    match = re.search(r'boundary=([^;]+)', content_type)
    if match:
        boundary = match.group(1).strip()
        # 去除可能的双引号
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]
        return boundary.encode('utf-8')
    return None


# ==================== 上报总系统 ====================
# 旧上报通道（POST /api/subsystem/report + report_loop 线程）已移除：
# 统一由 sync_engine.SyncEngine 的上报线程负责（POST /api/sync/report），
# 支持增量/全量、用户+证书+信任链+CA 全类型同步，避免双通道互扰。


# ==================== 公网端口路径白名单 ====================
# 公网端口（API 端口）仅放行 APP 必需 + 系统间同步路径；
# 管理类接口（/admin、证书签发/吊销、CA/信任/监控/配置写等）一律 403，只在管理端口提供。
PUBLIC_GET_PATHS = frozenset({
    '/', '/index.html',
    '/api/health', '/api/users', '/api/stats', '/api/config',
    '/api/cert/mine', '/api/sync/status',
    # 根证书公开下载：别的 FMO 服务器要信任本机签发的证书（含国服绑定签发的），
    # 就得从这里取根证书放进它的 roots/。根证书是自签公开信息——它的公钥本来就
    # 出现在每张已签发证书的链里，私钥 ca_private.json 不在这里、也不外发。
    '/api/ca/root.json',
})
PUBLIC_GET_PREFIXES = ('/uploads/',)
PUBLIC_POST_PATHS = frozenset({
    '/api/register', '/api/login', '/api/heartbeat',
    '/auth',
    '/api/cert/bind',
    '/api/sync/peer', '/api/sync/report',
    # BAS：EMQX 规则引擎的 webhook 投递口（用 X-Ingest-Token 自校验，
    # 公网口必须放行，否则 EMQX 在别的机器上投递会被白名单 403）
    '/api/ingest',
})

def build_ca_root_payload(ca_mgr, config=None):
    """
    组装「根证书下载」响应体（纯函数，便于测试）。

    ⚠️ 只读 ca_mgr.root_cert（自签公开证书）。**绝不读 ca_private.json**——
    根证书是公开信息（公钥本来就在每张已签发证书的链里），私钥不外发。
    指纹取 ca_mgr.root_fingerprint（加载 CA 时算好的字符串）；
    注意 cert_fingerprint() 收的是 TBS 列表而不是证书，直接传证书会返回 bytes，
    会让 send_json 抛 "Object of type bytes is not JSON serializable"。
    """
    root = getattr(ca_mgr, 'root_cert', None) if ca_mgr else None
    if not root:
        return None
    cfg = config or {}
    return {
        'ok': True,
        'ca_name': (root.get('subject') or {}).get('name', ''),
        'fingerprint': str(getattr(ca_mgr, 'root_fingerprint', '') or ''),
        'subsystem_id': cfg.get('subsystem_id', ''),
        'domain': cfg.get('domain', ''),
        'cert': root,
        'usage': ('把 cert 字段存成 <名字>.json 放进对方安装目录的 roots/，'
                  '重启后本机签发的证书（含国服绑定签发的）即被对方信任'),
    }


# ==================== /auth 逐段计时（排障开关） ====================
# 真实事故：EMQX 认证 HTTP 超时（>5s）会把**所有**证书一起判 not_authorized，
# 对的证书也进不来。要定位 1.6~4.6 秒到底花在哪一段，需要在**线上进程**里计时。
# 启用方式：在安装目录建一个空文件 AUTH_TRACE（删掉即关闭），零配置、零依赖。
AUTH_TRACE_FLAG = os.path.join(BASE_DIR, "AUTH_TRACE")
AUTH_TRACE_LOG = os.path.join(BASE_DIR, "auth_trace.log")
_AUTH_TRACE_CACHE = [0.0, False]      # [检查时间, 是否开启]：加缓存，避免每次认证都 stat


def _auth_tracing_on():
    """是否开启 /auth 逐段计时（开关文件存在即开启）。5 秒缓存，热路径不做 syscall。"""
    now = time.time()
    c = _AUTH_TRACE_CACHE
    if now - c[0] < 5.0:
        return c[1]
    try:
        on = os.path.exists(AUTH_TRACE_FLAG)
    except Exception:  # noqa: BLE001
        on = False
    c[0], c[1] = now, on
    return on


def _auth_trace_write(marks, extra=""):
    """把各段耗时写进 auth_trace.log（不写 stdout，避免日志背压干扰测量）"""
    try:
        if len(marks) < 2:
            return
        total = marks[-1][1] - marks[0][1]
        parts = ["%s=%.1f" % (marks[i + 1][0],
                              (marks[i + 1][1] - marks[i][1]) * 1000)
                 for i in range(len(marks) - 1)]
        with open(AUTH_TRACE_LOG, "a", encoding="utf-8") as f:
            f.write("%s total=%.1fms %s %s\n"
                    % (time.strftime("%H:%M:%S"), total * 1000,
                       " ".join(parts), extra))
    except Exception:  # noqa: BLE001
        pass


# ==================== 请求处理器 ====================


class ApiHandler(SyncApiMixin, http.server.BaseHTTPRequestHandler):
    """
    分系统 API 请求处理器。
    继承 SyncApiMixin 以获得 /api/sync/* 路由分发能力。
    SAS 路由（/auth、/api/cert/*、/api/ca/*、/api/trust/*、/api/sas/config）
    在本类内手动分发，复用 sas_server 模块的 authenticate / CaManager / Database。
    """

    # 类属性：由 main() 设置，供所有请求实例共享
    # SyncApiMixin.sync_engine 也通过类属性访问
    sync_engine = None
    ca_mgr = None        # CaManager 实例
    sas_db = None        # sas_server.Database 实例
    sas_config = None    # SAS 配置 dict
    monitor = None       # monitor.VoiceMonitor 实例（语音/信标监控线程）
    bas_http = None      # bas_http.BasHttp 实例（内嵌 FAS 审计子系统）
    bas_service = None   # bas_audit.AuditService 实例
    public_only = False  # 公网端口处理器（PublicApiHandler）置 True，启用白名单拦截

    # 静默日志输出（避免刷屏），保留错误日志
    def log_message(self, format, *args):
        pass

    # ---------- 公网白名单拦截 ----------
    def _public_blocked(self, method, path):
        """公网端口白名单检查：非白名单路径回复 403 并返回 True。"""
        if not self.public_only:
            return False
        if method == 'GET':
            ok = path in PUBLIC_GET_PATHS or path.startswith(PUBLIC_GET_PREFIXES)
        elif method == 'POST':
            ok = path in PUBLIC_POST_PATHS
        else:
            ok = False
        if ok:
            return False
        self.send_json({'ok': False, 'error': '该接口仅内网管理端口提供'}, 403)
        return True

    # ---------- 通用响应方法 ----------
    def send_json(self, data, code=200):
        """发送 JSON 响应（含 CORS 头）"""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, filepath):
        """发送文件（用于图片访问，含 CORS 头）"""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            self.send_error(404, '文件不存在')
            return
        # 根据扩展名设置 Content-Type
        _, ext = os.path.splitext(filepath)
        ext = ext.lower()
        content_type = 'application/octet-stream'
        if ext in ('.jpg', '.jpeg'):
            content_type = 'image/jpeg'
        elif ext == '.png':
            content_type = 'image/png'
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'max-age=3600')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(500, '读取文件失败: ' + str(e))

    def read_body(self):
        """读取请求体（超过 MAX_BODY_SIZE 抛 ValueError，由调用方 try 兜底返回错误）"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            return b''
        if content_length <= 0:
            return b''
        if content_length > MAX_BODY_SIZE:
            raise ValueError('请求体超过大小限制（%d MB）' % (MAX_BODY_SIZE // 1024 // 1024))
        return self.rfile.read(content_length)

    # ---------- 路由：BAS 审计子系统（内嵌 FAS，Python 重写版）----------
    def handle_bas_routes(self, method, path, parsed):
        """
        把 BAS 路由交给 bas_http.BasHttp 处理。返回 True 表示已响应。
        覆盖：POST /api/ingest（公网 webhook）、/api/bas/*、/admin/bas*（审计界面）。
        """
        bas = getattr(self.__class__, 'bas_http', None)
        if bas is None:
            # 未启用审计子系统时，明确告知而不是静默 404
            if path.startswith('/api/bas/') or path == '/api/ingest':
                self.send_json({'ok': False,
                                'error': '审计子系统(BAS)未启用或初始化失败'}, 503)
                return True
            return False
        if not (path.startswith('/api/bas/') or path == '/api/ingest'
                or path.startswith('/admin/bas') or path.startswith('/admin/fus')):
            return False

        body = None
        if method in ('POST', 'PUT', 'DELETE'):
            raw = b''
            try:
                raw = self.read_body()
            except ValueError as e:
                self.send_json({'ok': False, 'error': str(e)}, 413)
                return True
            if raw:
                try:
                    body = json.loads(raw.decode('utf-8'))
                except Exception:
                    body = None
        query = parse_qs(parsed.query) if parsed and parsed.query else {}
        return bas.handle(self, method, path, query, body)

    # ---------- 路由：GET ----------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---- 公网端口白名单拦截 ----
        if self._public_blocked('GET', path):
            return

        # ---- BAS 审计路由分发（内嵌 FAS，Python 版）----
        if self.handle_bas_routes('GET', path, parsed):
            return

        # ---- 互联桥接路由（/api/bridge/*）----
        if self._handle_bridge_routes('GET', path, parsed):
            return

        # ---- SAS 路由分发（先检查新增路由，匹配则处理；不匹配则走原有逻辑）----
        if self._handle_sas_routes('GET', path):
            return

        # ---- 同步路由分发（/api/sync/*）----
        if self.handle_sync_routes('GET', self.path):
            return

        # 管理后台静态资源（admin/*.js / *.css）。BAS 的 bas.js/bas.css 由
        # bas_http 在前面处理；这里兜住其余页面（如 stations.js）。
        if path.startswith('/admin/') and path.endswith(('.js', '.css')):
            self._serve_admin_asset(path[len('/admin/'):])
            return
        # 管理后台页面（由后端提供，内网访问）
        #   /admin             → FUS 门户（SAS / FAS 两个子系统入口）
        #   /admin/sas         → SAS 统一认证服务后台（原 /admin 的内容）
        #   /admin/fus         → FAS 统一审计服务后台（由 bas_http 处理，见上方路由分发）
        #   /admin/index.html  → 旧书签兜底，302 到 /admin/sas
        if path == '/admin' or path == '/admin/' or path == '/admin/portal.html':
            self._serve_portal_page()
            return
        if path in ('/admin/sas', '/admin/sas/', '/admin/sas/index.html'):
            self._serve_admin_page()
            return
        if path in ('/admin/stations', '/admin/stations/',
                    '/admin/stations/index.html'):
            self._serve_admin_file('stations.html')
            return
        if path in ('/admin/bridge', '/admin/bridge/', '/admin/bridge/index.html'):
            self._serve_admin_file('bridge.html')
            return
        if path == '/admin/index.html':
            self.send_response(302)
            self.send_header('Location', '/admin/sas')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return

        # 根路径：返回 JSON 提示（不暴露管理后台）
        if path == '/' or path == '/index.html':
            if self.public_only:
                # 公网端口：精简响应，不列举任何端点
                self.send_json({'ok': True, 'service': 'FMO Subsystem API'})
                return
            self.send_json({
                'ok': True,
                'service': 'FMO Subsystem API',
                'message': 'This is the API service.',
                'admin': '/admin',
                'endpoints': [
                    'POST /api/register',
                    'POST /api/login',
                    'POST /api/heartbeat',
                    'GET  /api/users',
                    'GET  /api/stats',
                    'GET  /api/config',
                    'POST /api/config',
                    'GET  /uploads/<filename>',
                    'POST /auth (SAS 认证)',
                    'POST /api/cert/issue (证书签发)',
                    'GET  /api/cert/mine (APP 凭 token 拉取本人证书包)',
                    'POST /api/cert/revoke (吊销证书)',
                    'GET  /api/cert/list (证书列表)',
                    'GET  /api/ca/info (CA 信息)',
                    'POST /api/ca/init (CA 初始化)',
                    'POST /api/ca/renew (CA 轮换)',
                    'POST /api/trust/add (添加信任 CA)',
                    'GET  /api/trust/list (信任链列表)',
                    'DELETE /api/trust/{id} (删除信任 CA)',
                    'POST /api/sync/peer (P2P 同步)',
                    'GET  /api/sync/status (同步状态)',
                    'GET  /api/sas/config (SAS 配置)',
                    'POST /api/sas/config (更新 SAS 配置)'
                ]
            })
            return

        # 所有用户 JSON
        if path == '/api/users':
            self.handle_get_users()
            return

        # 统计数据
        if path == '/api/stats':
            self.handle_stats()
            return

        # 配置查询（管理界面用）
        if path == '/api/config':
            self.handle_get_config()
            return

        # 上传文件访问
        if path.startswith('/uploads/'):
            filename = path[len('/uploads/'):]
            # 防止路径穿越
            filename = os.path.basename(filename)
            if not filename:
                self.send_error(404, '文件不存在')
                return
            filepath = os.path.join(UPLOAD_DIR, filename)
            self.send_file(filepath)
            return

        # 健康检查端点（便于总系统/监控探活）
        if path == '/api/health':
            self.send_json({'ok': True, 'service': 'fmo-subsystem', 'time': time.time()})
            return

        # ---- 语音/信标监控路由（管理后台瀑布图用，内网）----
        if path == '/api/monitor/status':
            self._handle_monitor_status()
            return
        if path == '/api/monitor/segments':
            self._handle_monitor_segments(parsed.query)
            return
        if path == '/api/monitor/audio':
            self._handle_monitor_audio(parsed.query)
            return
        if path == '/api/monitor/live':
            self._handle_monitor_live()
            return
        if path == '/api/monitor/live_audio':
            self._handle_monitor_live_audio(parsed.query)
            return
        if path == '/api/monitor/beacons':
            self._handle_monitor_beacons(parsed.query)
            return

        # 未知路径
        self.send_json({'ok': False, 'error': '路径不存在'}, 404)

    # ---------- 路由：OPTIONS（CORS 预检） ----------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    # ---------- 路由：DELETE ----------
    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---- 公网端口白名单拦截（DELETE 全部为管理操作，公网口一律 403）----
        if self._public_blocked('DELETE', path):
            return

        # SAS 路由分发
        if self._handle_sas_routes('DELETE', path):
            return

        # ---- BAS 审计路由（会话语令登出等）----
        if self.handle_bas_routes('DELETE', path, parsed):
            return

        self.send_json({'ok': False, 'error': '路径不存在'}, 404)

    # ---------- 路由：POST ----------
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ---- 公网端口白名单拦截 ----
        if self._public_blocked('POST', path):
            return

        # ---- BAS 审计路由分发（/api/ingest 与 /api/bas/*）----
        if self.handle_bas_routes('POST', path, parsed):
            return

        # ---- 互联桥接路由（/api/bridge/*）----
        if self._handle_bridge_routes('POST', path, parsed):
            return

        # ---- SAS 路由分发 ----
        if self._handle_sas_routes('POST', path):
            return

        # ---- 同步路由分发（/api/sync/*）----
        if self.handle_sync_routes('POST', self.path):
            return

        if path == '/api/register':
            self.handle_register()
            return

        if path == '/api/login':
            self.handle_login()
            return

        if path == '/api/heartbeat':
            self.handle_heartbeat()
            return

        if path == '/api/config':
            self.handle_set_config()
            return

        self.send_json({'ok': False, 'error': '路径不存在'}, 404)

    # ---------- 管理后台页面 ----------
    def _serve_admin_file(self, filename):
        """提供 admin/ 目录下的 HTML 页面（内网访问）"""
        admin_html_path = os.path.join(BASE_DIR, 'admin', filename)
        try:
            with open(admin_html_path, 'r', encoding='utf-8') as f:
                html = f.read()
        except FileNotFoundError:
            self.send_error(404, 'admin/%s not found' % filename)
            return
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_portal_page(self):
        """FUS 门户页：SAS 系统 / FAS 系统 / FMO 站点 三个入口"""
        self._serve_admin_file('portal.html')

    def _serve_admin_asset(self, name):
        """
        提供 admin/ 目录下的 js/css 静态资源。

        安全：只接受**纯文件名**且扩展名为 .js/.css —— 含路径分隔符、`..`、
        隐藏文件一律拒绝，杜绝目录穿越（例如 /admin/../config.json）。
        """
        if (not name or '/' in name or '\\' in name or name.startswith('.')
                or '..' in name or not name.endswith(('.js', '.css'))):
            self.send_error(404, 'not found')
            return
        fp = os.path.join(BASE_DIR, 'admin', name)
        if not os.path.isfile(fp):
            self.send_error(404, 'not found')
            return
        ctype = ('application/javascript; charset=utf-8'
                 if name.endswith('.js') else 'text/css; charset=utf-8')
        try:
            with open(fp, 'rb') as f:
                body = f.read()
        except Exception as e:  # noqa: BLE001
            self.send_error(500, '读取失败: %s' % e)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(body)

    def _serve_admin_page(self):
        """SAS 统一认证服务后台（原「管理后台」主页面）"""
        self._serve_admin_file('index.html')

    # ---------- API：GET /api/config ----------
    def handle_get_config(self):
        """返回当前配置（管理界面用）"""
        mon = CONFIG.get('monitor') or {}
        self.send_json({
            'ok': True,
            'config': {
                'app_domain': CONFIG.get('app_domain', ''),
                'app_port': CONFIG.get('app_port', None),
                'app_use_port': CONFIG.get('app_use_port', True),
                'subsystem_id': CONFIG.get('subsystem_id', ''),
                'name': CONFIG.get('name', ''),
                'domain': CONFIG.get('domain', ''),
                'mqtt_host': mon.get('mqtt_host', '127.0.0.1'),
                'mqtt_port': mon.get('mqtt_port', 1883)
            }
        })

    # ---------- API：POST /api/config ----------
    def handle_set_config(self):
        """保存配置（管理界面用），保存 app_domain/app_port/app_use_port"""
        try:
            body = self.read_body()
            data = json.loads(body.decode('utf-8'))

            # 验证并更新 app_domain
            if 'app_domain' in data:
                domain = str(data['app_domain']).strip()
                CONFIG['app_domain'] = domain

            # 验证并更新 app_port（必须是有效端口号 1-65535，否则用实际服务端口）
            if 'app_port' in data:
                port_val = data['app_port']
                if port_val is None:
                    # 端口为空时，用实际服务端口作为默认值
                    CONFIG['app_port'] = int(CONFIG.get('port', 35928))
                else:
                    try:
                        port_int = int(port_val)
                        if 1 <= port_int <= 65535:
                            CONFIG['app_port'] = port_int
                        else:
                            self.send_json({'ok': False, 'error': '端口必须在 1-65535 范围内'})
                            return
                    except (ValueError, TypeError):
                        self.send_json({'ok': False, 'error': '端口必须是数字'})
                        return

            # 更新 app_use_port
            if 'app_use_port' in data:
                CONFIG['app_use_port'] = bool(data['app_use_port'])

            # 验证并更新 MQTT broker 地址（monitor 节，界面可自由配置，不写死）
            if 'mqtt_host' in data or 'mqtt_port' in data:
                mon = CONFIG.setdefault('monitor', {})
                if 'mqtt_host' in data:
                    mon['mqtt_host'] = str(data['mqtt_host']).strip() or '127.0.0.1'
                if 'mqtt_port' in data:
                    if data['mqtt_port'] is None:
                        mon['mqtt_port'] = 1883
                    else:
                        try:
                            mp = int(data['mqtt_port'])
                            if not (1 <= mp <= 65535):
                                raise ValueError
                            mon['mqtt_port'] = mp
                        except (ValueError, TypeError):
                            self.send_json({'ok': False, 'error': 'MQTT 端口必须是 1-65535 的数字'})
                            return

            # 持久化到 config.json
            try:
                with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(CONFIG, f, indent=4, ensure_ascii=False)
                print("[CONFIG] 配置已保存: app_domain=%s, app_port=%s, app_use_port=%s" % (
                    CONFIG.get('app_domain'), CONFIG.get('app_port'), CONFIG.get('app_use_port')))
            except Exception as e:
                print("[CONFIG] 保存失败: %s" % e)
                self.send_json({'ok': False, 'error': '保存文件失败: %s' % e})
                return

            # 热更新同步引擎配置：上报总系统的地址随"APP 登录地址"即时生效，无需重启
            # （init_sync_service 中是 dict(CONFIG) 浅拷贝，保存后必须同步刷新）
            if _SYNC_ENGINE is not None:
                _SYNC_ENGINE.config['app_domain'] = CONFIG.get('app_domain', '')
                _SYNC_ENGINE.config['app_port'] = CONFIG.get('app_port')
                _SYNC_ENGINE.config['app_use_port'] = CONFIG.get('app_use_port', True)

            # 热更新监控线程 MQTT 地址：断开当前连接并立即用新地址重连，无需重启
            mon_cfg = CONFIG.get('monitor') or {}
            mon_inst = getattr(self.__class__, 'monitor', None)
            if mon_inst is not None and hasattr(mon_inst, 'update_mqtt_config'):
                try:
                    mon_inst.update_mqtt_config(
                        mon_cfg.get('mqtt_host', '127.0.0.1'),
                        int(mon_cfg.get('mqtt_port', 1883)))
                except Exception as e:
                    print("[CONFIG] MQTT 地址热更新失败（重启后生效）: %s" % e)

            self.send_json({'ok': True, 'message': '配置已保存'})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    # ---------- API：GET /api/users ----------
    def handle_get_users(self):
        """返回所有用户 JSON（含在线状态、证书签发状态）"""
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE deleted = 0 ORDER BY id ASC")
            rows = cur.fetchall()
            # 证书签发状态（来自 SAS DB；SAS 不可用时静默降级，不影响用户列表）
            cert_map = {}
            try:
                sas_db = getattr(self.__class__, 'sas_db', None) or _SAS_DB
                if sas_db is not None:
                    for c in sas_db.list_certificates(1000):
                        if c.get('revoked'):
                            continue
                        cs = c.get('callsign')
                        # 同呼号保留最新一条（list 按 issued_at DESC 返回）
                        if cs and cs not in cert_map:
                            cert_map[cs] = c
            except Exception:
                pass
            users = []
            for r in rows:
                cert = cert_map.get(r['callsign'])
                users.append({
                    'id': r['id'],
                    'name': r['name'],
                    'callsign': r['callsign'],
                    'phone': r['phone'],
                    'cert_photo_path': r['cert_photo_path'],
                    'device_cert_path': r['device_cert_path'],
                    'last_heartbeat': r['last_heartbeat'],
                    'created_at': r['created_at'],
                    'subsystem_id': r['subsystem_id'] if 'subsystem_id' in r.keys() else None,
                    'guoji_id': r['guoji_id'] if 'guoji_id' in r.keys() else None,
                    'dmr_id': r['dmr_id'] if 'dmr_id' in r.keys() else None,
                    'online': is_online(r['last_heartbeat']),
                    'cert_uid': cert.get('uid') if cert else None,
                    'cert_fingerprint': cert.get('fingerprint') if cert else None,
                    'cert_derived': bool(cert.get('derived')) if cert else False,
                })
            conn.close()
            self.send_json({'ok': True, 'users': users})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    # ---------- API：GET /api/stats ----------
    def handle_stats(self):
        """统计数据 {total, online}"""
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE deleted = 0")
            total = cur.fetchone()['c']
            # 在线数：最后心跳在 15 秒内
            threshold = time.time() - ONLINE_TIMEOUT
            cur.execute("SELECT COUNT(*) AS c FROM users WHERE deleted = 0 AND last_heartbeat > ?", (threshold,))
            online = cur.fetchone()['c']
            conn.close()
            self.send_json({'ok': True, 'total': total, 'online': online})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    # ---------- API：POST /api/register ----------
    def handle_register(self):
        """
        注册接口
        接收 multipart/form-data：name, callsign, phone, password, cert_photo(文件), device_cert(文件)
        """
        try:
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_json({'ok': False, 'error': '需要 multipart/form-data 请求'})
                return

            boundary = extract_boundary(content_type)
            if not boundary:
                self.send_json({'ok': False, 'error': '缺少 boundary'})
                return

            body = self.read_body()
            form = parse_multipart(body, boundary)

            # 提取字段
            name = form.get('name', '').strip() if isinstance(form.get('name'), str) else ''
            callsign = form.get('callsign', '').strip().upper() if isinstance(form.get('callsign'), str) else ''
            phone = form.get('phone', '').strip() if isinstance(form.get('phone'), str) else ''
            password = form.get('password', '') if isinstance(form.get('password'), str) else ''

            # 参数校验
            if not name:
                self.send_json({'ok': False, 'error': '姓名不能为空'})
                return
            if not callsign:
                self.send_json({'ok': False, 'error': '呼号不能为空'})
                return
            if not CALLSIGN_PATTERN.match(callsign):
                self.send_json({'ok': False, 'error': '呼号格式不正确（如 BH1ACG）'})
                return
            if not phone:
                self.send_json({'ok': False, 'error': '手机号不能为空'})
                return
            if not password or len(password) < 6:
                self.send_json({'ok': False, 'error': '密码不能为空且至少 6 位'})
                return

            # 呼号唯一校验
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE callsign = ?", (callsign,))
            if cur.fetchone():
                conn.close()
                self.send_json({'ok': False, 'error': '该呼号已注册'})
                return

            # 处理证书图片
            cert_photo_path = None
            device_cert_path = None

            cert_photo = form.get('cert_photo')
            if cert_photo and isinstance(cert_photo, dict):
                if len(cert_photo['data']) > MAX_PHOTO_SIZE:
                    conn.close()
                    self.send_json({'ok': False, 'error': '操作证书图片超过 5MB 限制'})
                    return
                if cert_photo['filename']:
                    saved = save_upload_file(cert_photo['data'], cert_photo['filename'])
                    if saved:
                        cert_photo_path = saved
                    else:
                        conn.close()
                        self.send_json({'ok': False, 'error': '操作证书图片格式不支持（仅 jpg/png）'})
                        return

            device_cert = form.get('device_cert')
            if device_cert and isinstance(device_cert, dict):
                if len(device_cert['data']) > MAX_PHOTO_SIZE:
                    conn.close()
                    self.send_json({'ok': False, 'error': '设备证书图片超过 5MB 限制'})
                    return
                if device_cert['filename']:
                    saved = save_upload_file(device_cert['data'], device_cert['filename'])
                    if saved:
                        device_cert_path = saved
                    else:
                        conn.close()
                        self.send_json({'ok': False, 'error': '设备证书图片格式不支持（仅 jpg/png）'})
                        return

            # 密码哈希
            password_hash = sha256_hash(password)
            created_at = time.time()

            # 写入数据库（last_modified 供增量同步采集，subsystem_id 标记用户归属）
            cur.execute("""
                INSERT INTO users (name, callsign, phone, password_hash, cert_photo_path, device_cert_path, token, last_heartbeat, created_at, last_modified, deleted, subsystem_id)
                VALUES (?, ?, ?, ?, ?, ?, NULL, 0, ?, ?, 0, ?)
            """, (name, callsign, phone, password_hash, cert_photo_path, device_cert_path, created_at, created_at,
                  CONFIG.get('subsystem_id', '')))
            conn.commit()
            conn.close()

            # 注册即自动签发证书（失败不影响注册，APP 可稍后通过 /api/cert/mine 补取）
            cert_issued = False
            try:
                certs, err = self._auto_issue_cert(callsign)
                cert_issued = certs is not None
                if err:
                    print("[REGISTER] 自动签发证书失败(callsign=%s): %s" % (callsign, err))
            except Exception as e:
                print("[REGISTER] 自动签发证书异常(callsign=%s): %s" % (callsign, e))

            self.send_json({'ok': True, 'message': '注册成功', 'cert_issued': cert_issued})

        except Exception as e:
            self.send_json({'ok': False, 'error': '服务器错误: ' + str(e)}, 500)

    # ---------- API：POST /api/login ----------
    def handle_login(self):
        """
        登录接口
        接收 JSON：{callsign, password}
        返回 {ok, token, name, callsign}
        """
        try:
            body = self.read_body()
            try:
                data = json.loads(body.decode('utf-8'))
            except Exception:
                self.send_json({'ok': False, 'error': '请求体不是合法 JSON'})
                return

            callsign = str(data.get('callsign', '')).strip().upper()
            password = str(data.get('password', ''))

            if not callsign or not password:
                self.send_json({'ok': False, 'error': '呼号和密码不能为空'})
                return

            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE callsign = ? AND deleted = 0", (callsign,))
            row = cur.fetchone()
            if not row:
                conn.close()
                self.send_json({'ok': False, 'error': '呼号不存在'})
                return

            # 验证密码
            if row['password_hash'] != sha256_hash(password):
                conn.close()
                self.send_json({'ok': False, 'error': '密码错误'})
                return

            # 生成 token
            token = str(uuid.uuid4()).replace('-', '')
            cur.execute("UPDATE users SET token = ? WHERE id = ?", (token, row['id']))
            conn.commit()
            conn.close()

            self.send_json({
                'ok': True,
                'token': token,
                'name': row['name'],
                'callsign': row['callsign']
            })

        except Exception as e:
            self.send_json({'ok': False, 'error': '服务器错误: ' + str(e)}, 500)

    # ---------- API：POST /api/heartbeat ----------
    def handle_heartbeat(self):
        """
        心跳接口
        接收 JSON：{token, device_info}
        更新 last_heartbeat，记录心跳日志
        """
        try:
            body = self.read_body()
            try:
                data = json.loads(body.decode('utf-8'))
            except Exception:
                self.send_json({'ok': False, 'error': '请求体不是合法 JSON'})
                return

            token = str(data.get('token', ''))
            device_info = str(data.get('device_info', ''))

            if not token:
                self.send_json({'ok': False, 'error': 'token 不能为空'})
                return

            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE token = ?", (token,))
            row = cur.fetchone()
            if not row:
                conn.close()
                self.send_json({'ok': False, 'error': 'token 无效'})
                return

            user_id = row['id']
            now = time.time()
            # 更新最后心跳时间（同时刷新 last_modified，让在线状态随增量同步上报到总系统）
            cur.execute("UPDATE users SET last_heartbeat = ?, last_modified = ? WHERE id = ?",
                        (now, now, user_id))
            # 记录心跳日志
            cur.execute("INSERT INTO heartbeat_log (user_id, timestamp, device_info) VALUES (?, ?, ?)",
                        (user_id, now, device_info))
            conn.commit()
            conn.close()

            self.send_json({'ok': True, 'timestamp': now})

        except Exception as e:
            self.send_json({'ok': False, 'error': '服务器错误: ' + str(e)}, 500)

    # ============================================================
    #  SAS 路由分发与处理方法
    #  复用 sas_server.py 的 authenticate / CaManager / Database
    # ============================================================

    # ---------- 监控路由处理（语音段/信标，管理后台瀑布图用） ----------
    def _monitor_store_or_503(self):
        """返回 monitor.store；监控不可用/未启用时自动回复错误并返回 None。"""
        mon = self.__class__.monitor
        if mon is None:
            self.send_json({'ok': False, 'error': '监控模块未加载'}, 503)
            return None
        return mon

    def _handle_monitor_status(self):
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            self.send_json({'ok': True, 'monitor': mon.status()})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    def _handle_monitor_segments(self, query):
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            q = parse_qs(query or '')
            since = float(q.get('since', ['0'])[0] or 0)
            limit = min(int(q.get('limit', ['200'])[0] or 200), 1000)
            segs = mon.store.segments_since(since, limit)
            self.send_json({'ok': True, 'segments': segs, 'now': time.time()})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    def _handle_monitor_audio(self, query):
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            q = parse_qs(query or '')
            seg_id = int(q.get('id', ['0'])[0] or 0)
            codec, audio = mon.store.get_audio(seg_id)
            if audio is None:
                self.send_json({'ok': False, 'error': '语音段不存在'}, 404)
                return
            body, ctype = audio, 'application/octet-stream'
            if codec == 'opus':
                try:
                    body = ogg_wrap_opus(audio)
                    ctype = 'audio/ogg'
                except Exception:
                    body = audio  # 封装失败则回退原始数据
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('X-Codec', codec or '')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    def _handle_monitor_live(self):
        """进行中 + 刚收尾的语音段元数据（边发边放轮询用）。"""
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            self.send_json({'ok': True, 'segments': mon.get_active(),
                            'now': time.time()})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    def _handle_monitor_live_audio(self, query):
        """进行中段增量音频：?callsign=&session=&offset=，带 X-Codec/X-Done/X-Total 头。"""
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            q = parse_qs(query or '')
            callsign = (q.get('callsign', [''])[0] or '')[:16]
            session = int(q.get('session', ['0'])[0] or 0)
            offset = int(q.get('offset', ['0'])[0] or 0)
            want_ogg = (q.get('ogg', [''])[0] or '') == '1'
            res = mon.get_active_audio(callsign, session, offset)
            if res is None:
                self.send_json({'ok': False, 'error': '段不存在或已过期'}, 404)
                return
            data, codec, done, total = res
            ctype = 'application/octet-stream'
            # ogg=1：无 WebCodecs 的浏览器在段收尾后拉完整 Ogg 立即整段播放
            if want_ogg and codec == 'opus' and done:
                data = ogg_wrap_opus(data)
                ctype = 'audio/ogg'
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('X-Codec', codec or '')
            self.send_header('X-Done', '1' if done else '0')
            self.send_header('X-Total', str(total))
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    def _handle_monitor_beacons(self, query):
        mon = self._monitor_store_or_503()
        if mon is None:
            return
        try:
            q = parse_qs(query or '')
            since = float(q.get('since', ['0'])[0] or 0)
            limit = min(int(q.get('limit', ['50'])[0] or 50), 200)
            rows = mon.store.beacons_since(since, limit)
            self.send_json({'ok': True, 'beacons': rows, 'now': time.time()})
        except Exception as e:
            self.send_json({'ok': False, 'error': str(e)}, 500)

    # ---------- MQTT 互联桥接（/api/bridge/*） ----------
    def _handle_bridge_routes(self, method, path, parsed=None):
        """
        互联桥接管理接口。

        设计要点：桥接是**无主**的 —— 这里只操作本机自己的对端列表，不跟任何
        "中心"协商；每个对端独立连接、独立重连，所以某个对端挂了不影响其他。
        这些接口只在管理口暴露（公网口白名单里没有，公网访问会 403）。
        """
        if not path.startswith('/api/bridge/'):
            return False
        try:
            svc = _BRIDGE
            if svc is None:
                self.send_json({'ok': False,
                                'error': '桥接模块不可用（bridge.py 未加载）'}, 503)
                return True
            if method == 'GET' and path == '/api/bridge/status':
                self.send_json(svc.status())
                return True
            if method == 'GET' and path == '/api/bridge/peers':
                self.send_json({'ok': True, 'peers': svc.peers()})
                return True
            if method == 'GET' and path == '/api/bridge/candidates':
                self.send_json(self._bridge_candidates(svc))
                return True
            if method == 'POST' and path == '/api/bridge/peers':
                body = self._read_json_body()
                if body is None:
                    return True
                peer, err = svc.upsert_peer(body)
                if err:
                    self.send_json({'ok': False, 'error': err}, 400)
                else:
                    self.send_json({'ok': True, 'peer': peer})
                return True
            if method == 'POST' and path == '/api/bridge/peers/toggle':
                body = self._read_json_body()
                if body is None:
                    return True
                peer, err = svc.set_peer_field(str(body.get('id') or ''),
                                               str(body.get('field') or ''),
                                               bool(body.get('value')))
                if err:
                    self.send_json({'ok': False, 'error': err}, 400)
                else:
                    self.send_json({'ok': True, 'peer': peer})
                return True
            if method == 'POST' and path == '/api/bridge/peers/delete':
                body = self._read_json_body()
                if body is None:
                    return True
                pid = str(body.get('id') or '')
                ok = svc.delete_peer(pid) if pid else False
                self.send_json({'ok': bool(ok), 'deleted': bool(ok)})
                return True
            if method == 'POST' and path == '/api/bridge/config':
                body = self._read_json_body()
                if body is None:
                    return True
                cfg = svc.set_config(enabled=body.get('enabled'),
                                     node_name=body.get('node_name'),
                                     channels=body.get('channels'),
                                     node_id=body.get('node_id'))
                if cfg.get('enabled'):
                    svc.start()      # 之前可能处于禁用状态，这里把连接线程拉起来
                self.send_json({'ok': True, 'config': cfg})
                return True
            self.send_json({'ok': False, 'error': '未知的桥接接口: %s' % path}, 404)
            return True
        except Exception as e:  # noqa: BLE001
            try:
                self.send_json({'ok': False, 'error': '桥接处理异常: ' + str(e)}, 500)
            except Exception:  # noqa: BLE001
                pass
            return True

    def _bridge_candidates(self, svc):
        """
        推荐可互联的对端：从 APRS 扫到的 FMO 台站里挑（那些就是别的 FUS 系统）。
        纯便利功能，减少手工填 host；不做任何自动连接。
        """
        out = []
        store = getattr(self.__class__, 'aprs_store', None)
        if store is not None:
            have = {str(p.get('host') or '').strip().lower() for p in svc.peers()}
            for st in store.all():
                host = str(st.get('host') or '').strip()
                if not host:
                    continue
                try:
                    port = int(st.get('port') or 1883)
                except (TypeError, ValueError):
                    port = 1883
                addr = host
                if _APRS_AVAILABLE:
                    try:
                        addr = fmo_aprs.station_mqtt_addr(st)
                    except Exception:  # noqa: BLE001
                        addr = "%s:%d" % (host, port)
                out.append({
                    'callsign': st.get('callsign') or '',
                    'name': st.get('name') or '',
                    'host': host,
                    'port': port,
                    'mqtt_addr': addr,
                    'already': host.lower() in have,
                })
        out.sort(key=lambda x: (x['already'], x['callsign']))
        return {'ok': True, 'candidates': out}

    def _handle_sas_routes(self, method, path):
        """
        SAS 路由总分发。
        :param method: 'GET' / 'POST' / 'DELETE'
        :param path: 已解析的 URL path（不含 query string）
        :return: True 如果路由被处理，False 如果不匹配
        """
        # 去除 query string
        if '?' in path:
            path = path.split('?', 1)[0]

        try:
            if method == 'POST' and path == '/auth':
                self._handle_sas_auth()
                return True
            if method == 'GET' and path == '/api/fus/stations':
                self._handle_fmo_stations()
                return True
            if method == 'POST' and path == '/api/fus/stations/scan':
                self._handle_fmo_stations_scan()
                return True
            if method == 'POST' and path == '/api/cert/bind':
                self._handle_cert_bind()
                return True
            if method == 'POST' and path == '/api/cert/issue':
                self._handle_sas_cert_issue()
                return True
            if method == 'POST' and path == '/api/cert/auto-issue':
                self._handle_cert_auto_issue()
                return True
            if method == 'GET' and path == '/api/cert/mine':
                self._handle_cert_mine()
                return True
            if method == 'GET' and path == '/api/cert/bundle':
                self._handle_cert_bundle()
                return True
            if method == 'POST' and path == '/api/cert/revoke':
                self._handle_cert_revoke()
                return True
            if method == 'GET' and path == '/api/cert/list':
                self._handle_cert_list()
                return True
            if method == 'GET' and path == '/api/ca/info':
                self._handle_sas_ca_info()
                return True
            if method == 'GET' and path == '/api/ca/root.json':
                self._handle_sas_ca_root_json()
                return True
            if method == 'POST' and path == '/api/ca/init':
                self._handle_sas_ca_init()
                return True
            if method == 'POST' and path == '/api/ca/renew':
                self._handle_sas_ca_renew()
                return True
            if method == 'POST' and path == '/api/trust/add':
                self._handle_sas_trust_add()
                return True
            if method == 'GET' and path == '/api/trust/list':
                self._handle_sas_trust_list()
                return True
            if method == 'DELETE' and path.startswith('/api/trust/'):
                tid = path[len('/api/trust/'):]
                self._handle_sas_trust_delete(tid)
                return True
            if method == 'DELETE' and path.startswith('/api/user/'):
                cs = unquote(path[len('/api/user/'):]).strip().upper()
                self._handle_user_delete(cs)
                return True
            if method == 'GET' and path == '/api/sas/config':
                self._handle_sas_config_get()
                return True
            if method == 'POST' and path == '/api/sas/config':
                self._handle_sas_config_set()
                return True
        except Exception as e:
            # 兜底：任何 SAS 处理异常都返回 500，不让进程崩溃
            try:
                self.send_json({'ok': False, 'error': 'SAS 处理异常: ' + str(e)}, 500)
            except Exception:
                pass
            return True
        return False

    def _read_json_body(self):
        """读取并解析 JSON 请求体，失败返回 None 并自动回复 400"""
        try:
            body = self.read_body()
            if not body:
                self.send_json({'ok': False, 'error': '请求体为空'}, 400)
                return None
            return json.loads(body.decode('utf-8'))
        except json.JSONDecodeError as e:
            self.send_json({'ok': False, 'error': 'JSON 解析失败: ' + str(e)}, 400)
            return None
        except Exception as e:
            self.send_json({'ok': False, 'error': '读取请求体失败: ' + str(e)}, 400)
            return None

    def _require_sas(self):
        """
        检查 SAS 服务是否可用。
        返回 (sas_db, ca_mgr)；不可用时已自动回复错误，调用方应直接 return。
        """
        if not _SAS_AVAILABLE:
            self.send_json({'ok': False, 'error': 'SAS 服务未安装或加载失败'}, 503)
            return None, None
        sas_db = self.__class__.sas_db or _SAS_DB
        ca_mgr = self.__class__.ca_mgr or _CA_MGR
        if sas_db is None:
            self.send_json({'ok': False, 'error': 'SAS 数据库未初始化'}, 503)
            return None, None
        return sas_db, ca_mgr

    # ---------- POST /auth ----------
    def _handle_sas_auth(self):
        """MQTT broker 调用的认证端点，代理到 sas_server.authenticate"""
        _tr = _auth_tracing_on()
        _T = [("enter", time.time())]

        def _t(tag):
            if _tr:
                _T.append((tag, time.time()))

        sas_db, ca_mgr = self._require_sas()
        _t("require_sas")
        if sas_db is None:
            if _tr:
                _auth_trace_write(_T, "no_sas_db")
            return
        body = self._read_json_body()
        _t("read_body")
        if body is None:
            if _tr:
                _auth_trace_write(_T, "bad_body")
            return
        username = body.get('username', '')
        password = body.get('password', '')
        clientid = str(body.get('clientid') or '')
        peerhost = str(body.get('peerhost') or '')
        if not username or not password:
            # ⚠️ 重要：EMQX 的**授权源(authz)**也配置成打这个端点，但它的请求体
            # 只有 {"username": "..."}（没有 password）。那种请求不是认证请求：
            # 必须回 "ignore"，让 EMQX 继续用后面的授权源（文件 ACL）判定。
            # 若在这里回 "deny"，会把**所有已认证客户端**的 publish/subscribe 全部拒掉
            # —— 真实事故：修好认证后全站订阅被拒（监控收不到语音、APP 互相听不到）。
            self.send_json({'result': 'ignore',
                            'reason': '缺少 password：按授权探测处理，交由后续授权源'})
            _t("send_ignore")
            if _tr:
                _auth_trace_write(_T, "ignore(no-password)")
            return
        if ca_mgr is None:
            self.send_json({'result': 'deny', 'reason': 'CA 管理器未初始化'})
            _t("send_deny_noca")
            if _tr:
                _auth_trace_write(_T, "deny(no-ca)")
            return
        try:
            result = authenticate(username, password, ca_mgr, sas_db)
            _t("authenticate")

            # ---- APP 密钥绑定：确认连接来自「持有 APP 私钥的本 APP」----
            # 结果写进 client_attrs → EMQX 会挂到连接上 → 审计据此判定"本 APP"
            if result.get('result') == 'allow':
                app = verify_app_mqtt_signature(password, clientid, username, log=print)
                _t("app_signature")
                attrs = result.setdefault('client_attrs', {})
                attrs['app_verified'] = '1' if app['ok'] else '0'
                attrs['app_sig'] = app['mode']
                # require_client_signature=true 时，没有有效 APP 签名直接拒绝
                # （内部服务/面板豁免：它们没有 APP 私钥）
                if SAS_RUNTIME_CONFIG.get('require_client_signature') and not app['ok']:
                    exempt, why_ex = app_signature_exempt(username, clientid)
                    if exempt:
                        attrs['app_exempt'] = '1'
                        print("[AUTH] 内部客户端豁免 APP 签名: %s（%s）" % (username, why_ex))
                    else:
                        print("[AUTH] 拒绝: require_client_signature=true 且 %s（callsign=%s clientid=%s）"
                              % (app['reason'], username, clientid or '-'))
                        self.send_json({
                            'result': 'deny',
                            'reason': '需要有效 APP 签名（require_client_signature=true）: ' + app['reason'],
                        })
                        return

            if result.get('result') == 'allow':
                attrs = result.get('client_attrs', {})
                print("[AUTH] 通过: callsign=%s uid=%s app_verified=%s(%s) clientid=%s" % (
                    attrs.get('callsign'), attrs.get('uid'),
                    attrs.get('app_verified'), attrs.get('app_sig'), clientid or '-'))
                _t("print_ok")
                # 登记"最近在线"：手机 APP 常频繁短线重连，
                # 只靠"当前在线"会看不到刚断开的人（真实问题：某用户来回掉线，界面像没上线）
                try:
                    _svc = getattr(self.__class__, 'bas_service', None)
                    if _svc is not None and hasattr(_svc, 'note_client_seen'):
                        _svc.note_client_seen(attrs.get('callsign') or username,
                                              attrs.get('uid', ''), clientid, peerhost)
                    _t("note_client_seen")
                    # 认证通过也写一条身份审计（用户要求：审计里要看得到"通过"的事件）
                    if _svc is not None and hasattr(_svc, 'record_auth_ok'):
                        _svc.record_auth_ok(attrs.get('callsign') or username,
                                            attrs.get('uid', ''), clientid, peerhost,
                                            attrs.get('app_verified', ''))
                    _t("record_auth_ok")
                except Exception:  # noqa: BLE001
                    pass
            else:
                # 诊断：拒绝时打印客户端原始 username（前 80 字符 repr），
                # 便于定位客户端凭证格式错误（如编码/字段不符）
                print("[AUTH] 拒绝: %s | username(len=%d)=%r" % (
                    result.get('reason', '未知原因'),
                    len(username), username[:80]))
                # 假证书/验签失败 → 留证 + 反滥用（封 clientid / 反复尝试的 IP）。
                # 注意：**不按呼号封**（防栽赃），呼号只用于留证与人工核查。
                try:
                    svc = getattr(self.__class__, 'bas_service', None)
                    if svc is not None and hasattr(svc, 'record_auth_rejection'):
                        r = svc.record_auth_rejection(
                            username, clientid, peerhost, result.get('reason', ''),
                            root_pubkey=result.get('untrusted_root_pubkey', ''))
                        if r.get('banned_clientid') or r.get('banned_peerhost'):
                            print("[AUTH] 反滥用处置: clientid封=%s IP封=%s 假证书来源=%s"
                                  % (r.get('banned_clientid'), r.get('banned_peerhost'),
                                     peerhost or '-'))
                except Exception as _e_rec:  # noqa: BLE001
                    print("[AUTH] 拒绝事件记录失败（不影响认证）: %s" % _e_rec)
                _t("record_reject")
            self.send_json(result)
            _t("send_json")
            if _tr:
                _auth_trace_write(_T, "result=%s" % result.get('result'))
        except Exception as e:
            self.send_json({'result': 'deny', 'reason': '认证异常: ' + str(e)}, 500)
            _t("send_exc")
            if _tr:
                _auth_trace_write(_T, "exception")

    # ---------- POST /api/cert/bind（国服 ID 绑定） ----------
    def _handle_cert_bind(self):
        """
        国服 ID 绑定：向国服确认「该呼号存在国服 ID」，再用客户端从密码派生的
        公钥签发用户证书，返回证书包 + 登录 token。
        之后 MQTT 认证走证书（客户端用派生私钥做 proof 签名），不再调用国服。

        请求体（简化模式，默认）：
          {callsign, pubkey(32B base64url), key_proof(base64url),
           app_timestamp, app_signature}
        config.dmrid.verify_password=true 时额外要求 password 并校验密码。

        key_proof = Ed25519_sign(seed, UTF8("FMO-DMRID-bind:" + callsign))
        （证明调用方确实持有 pubkey 对应私钥；seed = derive_keypair(callsign, password)）
        app_signature = Ed25519_sign(app_seed, UTF8("FMO-APP-auth:{ts}:{callsign}:{pubkey_b64}"))
        （APP 鉴权：证明请求来自持有 APP 私钥的真实客户端；服务端用 config.dmrid.app_pubkey 验签）
        """
        if not _CERT_GEN_AVAILABLE:
            self.send_json({'ok': False, 'error': '证书模块未加载，无法绑定国服ID'}, 503)
            return
        body = self._read_json_body()
        if body is None:
            return
        # 0. APP 签名校验（Ed25519，防未授权绑定；先于一切其他校验）
        if not app_signature_ok(body):
            self.send_json({'ok': False, 'error': 'APP 签名无效或已过期'}, 403)
            return
        callsign = str(body.get('callsign', '')).strip().upper()
        password = str(body.get('password', ''))
        pubkey_b64 = str(body.get('pubkey', '')).strip()
        key_proof = str(body.get('key_proof', '')).strip()
        verify_password = bool(get_dmrid_config().get('verify_password'))

        if not callsign or not re.match(r'^[A-Z0-9]{4,10}$', callsign):
            self.send_json({'ok': False, 'error': '呼号格式不正确（需 4-10 位大写字母和数字）'}, 400)
            return
        if verify_password and not password:
            self.send_json({'ok': False, 'error': '密码不能为空'}, 400)
            return
        if not pubkey_b64 or not key_proof:
            self.send_json({'ok': False, 'error': '缺少 pubkey 或 key_proof（请用 derive_keypair 派生）'}, 400)
            return

        # 1. 公钥持有证明：证明调用方确实持有 pubkey 对应的私钥（seed 由密码派生）
        try:
            pubkey = b64url_decode(pubkey_b64)
            proof_sig = b64url_decode(key_proof)
        except Exception:
            self.send_json({'ok': False, 'error': 'pubkey/key_proof 不是合法 base64url'}, 400)
            return
        if len(pubkey) != 32:
            self.send_json({'ok': False, 'error': 'pubkey 必须为 32 字节 Ed25519 公钥'}, 400)
            return
        proof_msg = (BIND_KEY_PROOF_PREFIX + callsign).encode('utf-8')
        if not ed25519_verify(pubkey, proof_msg, proof_sig):
            self.send_json({'ok': False, 'error': 'key_proof 验证失败（公钥与私钥不匹配，或派生了错误的密钥）'}, 403)
            return

        # 2. 国服身份校验（仅绑定这一次；之后 MQTT 用证书，不再调国服）
        #    简化模式：仅查呼号存在（callsign-lookup）；强校验模式：校验密码（login）
        if verify_password:
            ok, res = dmrid_login(callsign, password)
            if not ok:
                self.send_json({'ok': False, 'error': res.get('error', '国服校验失败')}, res.get('code', 502))
                return
            user = res['user']
            auth_callsign = str(user.get('callsign', '')).strip().upper()
            if auth_callsign and auth_callsign != callsign:
                self.send_json({'ok': False, 'error': '呼号不匹配（国服返回 %s）' % auth_callsign}, 403)
                return
            status = str(user.get('status') or '')
            if status != 'approved':
                self.send_json({'ok': False, 'error': '账号状态为 %s，未通过审核，无法接入' % (status or 'unknown')}, 403)
                return
            guoji_id = user.get('guojiId')
            dmr_id = user.get('dmrId')
        else:
            ok, res = dmrid_lookup(callsign)
            if not ok:
                self.send_json({'ok': False, 'error': res.get('error', '国服查询失败')}, res.get('code', 502))
                return
            auth_callsign = str(res.get('callsign', '')).strip().upper()
            if auth_callsign and auth_callsign != callsign:
                self.send_json({'ok': False, 'error': '呼号不匹配（国服返回 %s）' % auth_callsign}, 403)
                return
            guoji_id = res.get('guojiId')
            dmr_id = res.get('dmrId')

        # 3. SAS 服务可用性
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if ca_mgr is None or ca_mgr.int_cert is None:
            self.send_json({'ok': False, 'error': 'CA 未初始化，请先 POST /api/ca/init'}, 503)
            return

        # 4. 找/建本地用户（呼号是 FMO 与国服共用的身份键），记录国服 ID，并签发登录 token
        token = str(uuid.uuid4()).replace('-', '')
        conn = get_db()
        try:
            row = conn.execute("SELECT id FROM users WHERE callsign = ?", (callsign,)).fetchone()
            now = time.time()
            if row is None:
                conn.execute("""
                    INSERT INTO users (name, callsign, phone, password_hash, token,
                                       last_heartbeat, created_at, last_modified, deleted,
                                       subsystem_id, guoji_id, dmr_id)
                    VALUES (?, ?, '', '', ?, 0, ?, ?, 0, ?, ?, ?)
                """, (callsign, callsign, token, now, now,
                      CONFIG.get('subsystem_id', ''), str(guoji_id or ''), str(dmr_id or '')))
            else:
                conn.execute("""
                    UPDATE users SET guoji_id = ?, dmr_id = ?, last_modified = ?, token = ?
                    WHERE callsign = ?
                """, (str(guoji_id or ''), str(dmr_id or ''), now, token, callsign))
            conn.commit()
        finally:
            conn.close()

        # 5. 签发/复用证书（幂等：同公钥复用；换公钥则吊销旧证重签；UID 保持稳定）
        try:
            with _AUTO_ISSUE_LOCK:
                existing = sas_db.get_latest_certificate_by_callsign(callsign)
                existing_revoked = bool(existing.get('revoked')) if existing else False
                if existing and not existing_revoked:
                    try:
                        existing_pub = json.loads(existing['cert_user_json'])['subject']['publicKey']
                        if existing_pub == pubkey_b64:
                            return self._send_bind_success(
                                callsign, existing['uid'], existing['fingerprint'],
                                json.loads(existing['cert_user_json']),
                                guoji_id, dmr_id, token, ca_mgr)
                    except Exception:
                        pass
                # 确定 uid：已有证书则沿用，否则 max+1（不复用已吊销的 uid）
                if existing:
                    uid = int(existing['uid'])
                    if not existing_revoked:
                        sas_db.revoke_certificate(existing['fingerprint'])
                else:
                    uid = max(sas_db.get_max_uid() + 1,
                              int(getattr(ca_mgr, 'uid_start', 1) or 1))
                    uid_end = int(getattr(ca_mgr, 'uid_end', 200000) or 200000)
                    if uid > uid_end:
                        self.send_json({'ok': False, 'error': 'UID 已分配完（范围 %d-%d）' % (1, uid_end)}, 503)
                        return
                certs = ca_mgr.issue_user_cert_for_pubkey(callsign, uid, pubkey)
                user_json = json.dumps(certs['user_cert'], ensure_ascii=False)
                sas_db.add_certificate(callsign, uid, user_json, '',
                                       certs['fingerprint'], derived=True)
                print("[BIND] 国服绑定签发证书: callsign=%s uid=%d fp=%s..." % (
                    callsign, uid, certs['fingerprint'][:20]))
                return self._send_bind_success(
                    callsign, uid, certs['fingerprint'], certs['user_cert'],
                    guoji_id, dmr_id, token, ca_mgr)
        except Exception as e:
            self.send_json({'ok': False, 'error': '证书签发失败: %s' % e}, 500)

    def _send_bind_success(self, callsign, uid, fingerprint, cert_user,
                           guoji_id, dmr_id, token, ca_mgr):
        """组装绑定成功响应（返回证书包 + token + 国服 ID；devicekey 为 null，私钥由客户端派生）。"""
        self.send_json({
            'ok': True,
            'message': '绑定成功，已用国服账号派生密钥签发证书',
            'token': token,
            'callsign': callsign,
            'uid': uid,
            'fingerprint': fingerprint,
            'guoji_id': guoji_id,
            'dmr_id': dmr_id,
            'derived': True,
            'cert_root': ca_mgr.root_cert,
            'cert_int': ca_mgr.int_cert,
            'cert_user': cert_user,
            'cert_devicekey': None,
        })

    # ---------- POST /api/cert/issue ----------
    def _handle_sas_cert_issue(self):
        """证书签发：用本地 Int CA 签发 User Cert + Device Key"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if ca_mgr is None:
            self.send_json({'ok': False, 'error': 'CA 管理器未初始化，请先 POST /api/ca/init'}, 503)
            return
        body = self._read_json_body()
        if body is None:
            return
        callsign = str(body.get('callsign', '')).strip().upper()
        uid = body.get('uid', 0)
        validity_years = body.get('validity_years', (_SAS_CONFIG or {}).get('validity_years', 10))
        # 校验呼号
        if not re.match(r'^[A-Z0-9]{4,10}$', callsign):
            self.send_json({'ok': False, 'error': '呼号格式不正确，需 4-10 位大写字母和数字'})
            return
        # 校验 UID
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            self.send_json({'ok': False, 'error': 'UID 必须为整数'})
            return
        if uid < 1 or uid > 200000:
            self.send_json({'ok': False, 'error': 'UID 必须在 1-200000 之间'})
            return
        # 呼号白名单检查
        allowed = SAS_RUNTIME_CONFIG.get('allowed_callsigns', [])
        if allowed and callsign not in allowed:
            self.send_json({'ok': False, 'error': '呼号 %s 不在白名单中' % callsign})
            return
        try:
            certs = ca_mgr.issue_user_cert(callsign, uid, validity_years)
        except Exception as e:
            self.send_json({'ok': False, 'error': '证书签发失败: ' + str(e)}, 500)
            return
        # 记录到 SAS 数据库
        try:
            user_json = json.dumps(certs['user_cert'], ensure_ascii=False)
            dk_json = json.dumps(certs['device_key'])
            sas_db.add_certificate(callsign, uid, user_json, dk_json, certs['fingerprint'])
        except Exception as e:
            print("[ISSUE] 记录证书到 SAS DB 失败（不影响签发结果）: %s" % e)
        print("[ISSUE] 签发证书: callsign=%s uid=%d fp=%s..." % (
            callsign, uid, certs['fingerprint'][:20]))
        self.send_json({
            'ok': True,
            'callsign': callsign,
            'uid': uid,
            'fingerprint': certs['fingerprint'],
            'cert_root': certs['root_cert'],
            'cert_int': certs['int_cert'],
            'cert_user': certs['user_cert'],
            'cert_devicekey': certs['device_key'],
        })

    # ---------- POST /api/cert/auto-issue ----------
    def _handle_cert_auto_issue(self):
        """一键签发（幂等）：按呼号自动分配 UID 并签发；已有有效证书直接返回现有记录"""
        body = self._read_json_body()
        if body is None:
            return
        callsign = str(body.get('callsign', '')).strip().upper()
        if not callsign:
            self.send_json({'ok': False, 'error': '缺少呼号'})
            return
        certs, err = self._auto_issue_cert(callsign)
        if err:
            self.send_json({'ok': False, 'error': err}, 500)
            return
        self.send_json({
            'ok': True,
            'callsign': certs['callsign'],
            'uid': certs['uid'],
            'fingerprint': certs['fingerprint'],
        })

    # ---------- 证书自动签发辅助 ----------
    def _auto_issue_cert(self, callsign):
        """
        为用户自动签发证书（幂等）：已有有效证书则直接返回现有证书包；
        否则按 UID = 已占用最大值+1（不低于 uid_start，不超过 uid_end）自动分配并签发。
        全程持全局锁串行化，防止并发注册分配到同一 UID。
        返回 (certs_dict, error_msg)：成功时 error_msg 为 None；
        certs_dict 含 callsign/uid/fingerprint/cert_root/cert_int/cert_user/cert_devicekey。
        """
        if not _SAS_AVAILABLE:
            return None, 'SAS 服务不可用'
        sas_db = self.__class__.sas_db or _SAS_DB
        ca_mgr = self.__class__.ca_mgr or _CA_MGR
        if sas_db is None or ca_mgr is None:
            return None, 'SAS 服务或 CA 未初始化（请先 POST /api/ca/init）'
        with _AUTO_ISSUE_LOCK:
            # 幂等：已有有效证书直接返回现有记录
            try:
                existing = sas_db.get_certificate_by_callsign(callsign)
            except Exception as e:
                return None, '查询已有证书失败: %s' % e
            if existing:
                try:
                    derived = bool(existing['derived']) if 'derived' in existing.keys() else False
                    dk = None
                    if not derived and existing.get('cert_devicekey_json'):
                        dk = json.loads(existing['cert_devicekey_json'])
                    return {
                        'callsign': callsign,
                        'uid': existing['uid'],
                        'fingerprint': existing['fingerprint'],
                        'cert_root': ca_mgr.root_cert,
                        'cert_int': ca_mgr.int_cert,
                        'cert_user': json.loads(existing['cert_user_json']),
                        'cert_devicekey': dk,
                        'derived': derived,
                    }, None
                except Exception as e:
                    return None, '解析已有证书失败: %s' % e
            # 白名单检查（与手动签发 /api/cert/issue 一致）
            allowed = SAS_RUNTIME_CONFIG.get('allowed_callsigns', [])
            if allowed and callsign not in allowed:
                return None, '呼号 %s 不在白名单中' % callsign
            # 自动分配 UID：不复用（已吊销的也占位），从 uid_start 起
            uid_start = int(getattr(ca_mgr, 'uid_start', 1) or 1)
            uid_end = int(getattr(ca_mgr, 'uid_end', 200000) or 200000)
            try:
                uid = max(sas_db.get_max_uid() + 1, uid_start)
            except Exception as e:
                return None, '分配 UID 失败: %s' % e
            if uid > uid_end:
                return None, 'UID 已分配完（范围 %d-%d）' % (uid_start, uid_end)
            validity_years = (_SAS_CONFIG or {}).get('validity_years', 10)
            try:
                certs = ca_mgr.issue_user_cert(callsign, uid, validity_years)
                user_json = json.dumps(certs['user_cert'], ensure_ascii=False)
                dk_json = json.dumps(certs['device_key'])
                sas_db.add_certificate(callsign, uid, user_json, dk_json, certs['fingerprint'])
            except Exception as e:
                return None, '证书签发失败: %s' % e
            print("[AUTO-ISSUE] 自动签发证书: callsign=%s uid=%d fp=%s..." % (
                callsign, uid, certs['fingerprint'][:20]))
            return {
                'callsign': callsign,
                'uid': uid,
                'fingerprint': certs['fingerprint'],
                'cert_root': certs['root_cert'],
                'cert_int': certs['int_cert'],
                'cert_user': certs['user_cert'],
                'cert_devicekey': certs['device_key'],
            }, None

    # ---------- GET /api/cert/mine ----------
    def _handle_cert_mine(self):
        """
        APP 凭登录 token 拉取本人呼号的完整证书包（root/int/user/devicekey 四个 JSON）。
        token 传递：?token=xxx 查询参数 或 Authorization: Bearer xxx 头。
        尚无有效证书且 CA 可用时按需自动签发（保证老注册用户也能拿到）。
        """
        token = ''
        auth = self.headers.get('Authorization', '') or ''
        if auth.startswith('Bearer '):
            token = auth[7:].strip()
        if not token:
            token = parse_qs(urlparse(self.path).query).get('token', [''])[0].strip()
        if not token:
            self.send_json({'ok': False, 'error': '缺少 token'}, 401)
            return
        # token -> callsign
        conn = get_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT callsign FROM users WHERE token = ? AND deleted = 0", (token,))
            row = cur.fetchone()
        finally:
            conn.close()
        if not row:
            self.send_json({'ok': False, 'error': 'token 无效或已过期'}, 401)
            return
        callsign = row['callsign']
        certs, err = self._auto_issue_cert(callsign)
        if certs is None:
            self.send_json({'ok': False, 'error': '证书不可用: %s' % (err or '未知原因')}, 503)
            return
        self.send_json({
            'ok': True,
            'callsign': certs['callsign'],
            'uid': certs['uid'],
            'fingerprint': certs['fingerprint'],
            'cert_root': certs['cert_root'],
            'cert_int': certs['cert_int'],
            'cert_user': certs['cert_user'],
            'cert_devicekey': certs['cert_devicekey'],
            'derived': bool(certs.get('derived')),
        })

    # ---------- GET /api/cert/bundle ----------
    def _handle_cert_bundle(self):
        """
        管理端：证书套 ZIP 一键下载（cert_root / cert_int / cert_user / cert_devicekey 四个 JSON）。
        参数：?callsign=XXX（最新未吊销证书）或 ?fingerprint=XXX（含已吊销存档）。
        仅管理端口提供（公网白名单不含此路径）。
        """
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if ca_mgr is None or ca_mgr.root_cert is None:
            self.send_json({'ok': False, 'error': 'CA 未初始化，请先 POST /api/ca/init'}, 503)
            return
        q = parse_qs(urlparse(self.path).query)
        callsign = q.get('callsign', [''])[0].strip().upper()
        fp = q.get('fingerprint', [''])[0].strip()
        cert = None
        try:
            if callsign:
                cert = sas_db.get_certificate_by_callsign(callsign)
            elif fp:
                cert = sas_db.get_certificate_by_fp(fp)
        except Exception as e:
            self.send_json({'ok': False, 'error': '查询证书失败: %s' % e}, 500)
            return
        if not cert:
            self.send_json({'ok': False, 'error': '未找到有效证书（呼号需存在未吊销证书）'}, 404)
            return
        try:
            cs = str(cert.get('callsign') or callsign or 'cert')
            files = {
                'cert_root.json': ca_mgr.root_cert,
                'cert_int.json': ca_mgr.int_cert,
                'cert_user.json': json.loads(cert['cert_user_json']),
            }
            # 国服ID绑定证书：私钥由客户端从密码派生，无 devicekey 文件可打包
            if cert.get('cert_devicekey_json'):
                files['cert_devicekey.json'] = json.loads(cert['cert_devicekey_json'])
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                for name, obj in files.items():
                    zf.writestr(name, json.dumps(obj, ensure_ascii=False, indent=2))
            payload = buf.getvalue()
        except Exception as e:
            self.send_json({'ok': False, 'error': '打包失败: %s' % e}, 500)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/zip')
        self.send_header('Content-Disposition',
                         'attachment; filename="%s_certs.zip"' % cs)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # ---------- POST /api/cert/revoke ----------
    def _handle_cert_revoke(self):
        """吊销证书：{fingerprint} 或 {callsign}（吊销该呼号最新有效证书）"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        body = self._read_json_body()
        if body is None:
            return
        fp = str(body.get('fingerprint', '')).strip()
        if not fp:
            callsign = str(body.get('callsign', '')).strip().upper()
            if callsign:
                try:
                    cert = sas_db.get_certificate_by_callsign(callsign)
                    fp = cert['fingerprint'] if cert else ''
                except Exception as e:
                    self.send_json({'ok': False, 'error': '查询证书失败: %s' % e}, 500)
                    return
        if not fp:
            self.send_json({'ok': False, 'error': '缺少 fingerprint 或 callsign（或该呼号无有效证书）'}, 400)
            return
        try:
            ok = sas_db.revoke_certificate(fp)
        except Exception as e:
            self.send_json({'ok': False, 'error': '吊销失败: %s' % e}, 500)
            return
        if ok:
            print("[REVOKE] 吊销证书: fp=%s..." % fp[:20])
            self.send_json({'ok': True, 'fingerprint': fp})
        else:
            self.send_json({'ok': False, 'error': '证书不存在'}, 404)

    # ---------- GET /api/cert/list ----------
    def _handle_cert_list(self):
        """列出本机已签发证书（不含证书 JSON 体），?limit=N 可选（默认 200，上限 1000）"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        limit = 200
        try:
            limit = max(1, min(1000, int(
                parse_qs(urlparse(self.path).query).get('limit', ['200'])[0])))
        except (TypeError, ValueError):
            pass
        try:
            certs = sas_db.list_certificates(limit)
            self.send_json({'ok': True, 'certificates': certs})
        except Exception as e:
            self.send_json({'ok': False, 'error': '查询失败: %s' % e}, 500)

    # ---------- GET /api/ca/info ----------
    def _handle_sas_ca_info(self):
        """返回本地 Root CA + Int CA 信息"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        info = ca_mgr.info() if ca_mgr else {'initialized': False}
        # 附加信任链统计
        try:
            trust_list = sas_db.list_trust()
            info['trusted_ca_count'] = len(trust_list)
            info['trusted_ca_fingerprints'] = [
                t['remote_ca_fingerprint'] for t in trust_list
            ]
        except Exception as e:
            info['trusted_ca_count'] = 0
            info['trusted_ca_error'] = str(e)
        self.send_json({'ok': True, 'ca': info})

    # ---------- GET /api/ca/root.json ----------
    def _handle_sas_ca_root_json(self):
        """
        下载本机 Root CA 完整证书（自签，含 signature）。

        用途：别的 FMO 服务器（多为**官方 SAS**）要信任本机签发的证书（含国服绑定
        流程签发的），就要把本机根证书放进它的信任目录。**根证书是公开信息**——
        公钥本来就存在于每张已签发证书的链里，私钥 ca_private.json 绝不外发。

        两种取法：
          · ?raw=1  直接返回**裸证书 JSON**（官方 SAS 的 RootsDir 要的就是它），
                    对方一条命令落盘即可：
              curl -fsS -o BH6BHG-CA.json "http://<本机>:35928/api/ca/root.json?raw=1"
              sudo cp BH6BHG-CA.json /root/.sas/roots/ && sudo systemctl restart fmo-sas
          · 不带参数  返回带元信息的包装（ca_name/fingerprint/usage），证书在 cert 字段
        """
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        payload = build_ca_root_payload(ca_mgr, CONFIG)
        if payload is None:
            self.send_json({'ok': False,
                            'error': '本机 CA 未初始化，无法下载根证书'}, 503)
            return
        # ?raw=1 → 裸证书 JSON（官方 SAS RootsDir 期望的文件格式）
        qs = parse_qs(urlparse(self.path).query)
        if str((qs.get('raw') or [''])[0]).lower() in ('1', 'true', 'yes'):
            self.send_json(payload['cert'])
        else:
            self.send_json(payload)
        print("[CA] 根证书已被下载：%s fp=%s（根证书是公开信息，私钥不外发）"
              % (payload['ca_name'], payload['fingerprint'][:24]))

    # ---------- GET /api/fus/stations ----------
    def _handle_fmo_stations(self):
        """
        FMO 台站目录（APRS 扫描 + 可进入性探测）。

        **FMO 台站不在任何数据库里**，是各站在 APRS-IS 上广播的站点名片
        （FMO-V4,STATION 报文）。常驻采集线程长期累积 → 才能攒到几百个。

        默认 only_enterable=1：只显示**探测过、且确实能进入**的台站
        （能进 = 该台站的 MQTT broker 对 CONNECT 回了 CONNACK）。进不去的不显示。
        带 ?all=1 可看全部（排障用）。
        """
        if not _APRS_AVAILABLE:
            self.send_json({'ok': False,
                            'error': 'fmo_aprs 模块不可用'}, 503)
            return
        store = getattr(self.__class__, 'aprs_store', None)
        coll = getattr(self.__class__, 'aprs_collector', None)
        if store is None:
            self.send_json({'ok': False,
                            'error': 'APRS 台站台账未初始化'}, 503)
            return
        qs = parse_qs(urlparse(self.path).query)
        only_enterable = str((qs.get('all') or [''])[0]).lower() not in (
            '1', 'true', 'yes')
        self.send_json(fmo_aprs.build_aprs_station_payload(
            store, coll, CONFIG, only_enterable=only_enterable))

    # ---------- POST /api/fus/stations/scan ----------
    def _handle_fmo_stations_scan(self):
        """
        启动/触发台站扫描。**不限时**：常驻采集器一直在听 APRS，
        发现新台站立刻用本机证书真实登录探测。这里只做两件事：
          1) 保证采集线程活着（死了拉起来）
          2) 立刻对现有台账做一轮全量重探
        然后**立即返回**当前结果（不阻塞等扫描），页面自己轮询看增长。
        """
        if not _APRS_AVAILABLE:
            self.send_json({'ok': False,
                            'error': 'fmo_aprs 模块不可用'}, 503)
            return
        store = getattr(self.__class__, 'aprs_store', None)
        coll = getattr(self.__class__, 'aprs_collector', None)
        if store is None:
            self.send_json({'ok': False,
                            'error': 'APRS 台站台账未初始化'}, 503)
            return
        restarted = False
        swept = 0
        if coll is not None:
            restarted = coll.ensure_running()
            try:
                # 不清空台账、不强制全量重探：只挑「没探过/很久没探」的补探一批
                swept = coll.sweep(force=True, min_interval=0)
            except Exception as e:  # noqa: BLE001
                print("[APRS] 补探提交失败: %s" % e)
        payload = fmo_aprs.build_aprs_station_payload(
            store, coll, CONFIG, only_enterable=True)
        payload['scan'] = {'continuous': True, 'restarted': restarted,
                           'swept': swept, 'total': store.count()}
        print("[APRS] 扫描已启动（不限时）: 台账 %d，本轮重探 %d，线程重启=%s"
              % (store.count(), swept, restarted))
        self.send_json(payload)

    # ---------- POST /api/ca/init ----------
    def _handle_sas_ca_init(self):
        """初始化本地 CA（force=true 强制重新生成）"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if ca_mgr is None:
            self.send_json({'ok': False, 'error': 'CA 管理器未初始化'}, 503)
            return
        body = self._read_json_body()
        if body is None:
            return
        force = bool(body.get('force', False))
        if ca_mgr.root_cert is not None and not force:
            self.send_json({'ok': True, 'message': 'CA 已存在', 'ca': ca_mgr.info()})
            return
        try:
            ca_mgr.init(force=force)
        except Exception as e:
            self.send_json({'ok': False, 'error': 'CA 初始化失败: ' + str(e)}, 500)
            return
        self.send_json({'ok': True, 'ca': ca_mgr.info()})

    # ---------- POST /api/ca/renew ----------
    def _handle_sas_ca_renew(self):
        """轮换 CA（重新生成，已签发证书将失效）"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if ca_mgr is None:
            self.send_json({'ok': False, 'error': 'CA 管理器未初始化'}, 503)
            return
        try:
            ca_mgr.renew()
        except Exception as e:
            self.send_json({'ok': False, 'error': 'CA 轮换失败: ' + str(e)}, 500)
            return
        print("[CA] CA 已轮换，已签发的用户证书将失效")
        self.send_json({'ok': True, 'ca': ca_mgr.info(),
                        'warning': 'CA 已轮换，已签发的用户证书将失效'})

    # ---------- POST /api/trust/add ----------
    def _handle_sas_trust_add(self):
        """添加信任的远程 CA"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        body = self._read_json_body()
        if body is None:
            return
        remote_ca = body.get('remote_ca')
        if not remote_ca:
            self.send_json({'ok': False, 'error': '缺少 remote_ca 证书'})
            return
        trusted_by = body.get('trusted_by', '')
        ca_type = body.get('ca_type', 'rootCA')
        # 计算远程 CA 指纹
        try:
            if ca_type == 'rootCA':
                fp = CaManager.compute_root_fingerprint(remote_ca)
            else:
                fp = CaManager.compute_int_fingerprint(remote_ca)
        except Exception as e:
            self.send_json({'ok': False, 'error': '远程 CA 指纹计算失败: ' + str(e)})
            return
        try:
            ca_json = json.dumps(remote_ca, ensure_ascii=False)
            tid = sas_db.add_trust(fp, ca_json, ca_type, trusted_by)
        except Exception as e:
            self.send_json({'ok': False, 'error': '写入信任链失败: ' + str(e)}, 500)
            return
        print("[TRUST] 添加信任 CA: fp=%s... id=%s" % (fp[:20], tid))
        self.send_json({'ok': True, 'id': tid, 'fingerprint': fp})

    # ---------- GET /api/trust/list ----------
    def _handle_sas_trust_list(self):
        """列出所有信任的远程 CA"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        try:
            trust_list = sas_db.list_trust()
        except Exception as e:
            self.send_json({'ok': False, 'error': '读取信任链失败: ' + str(e)}, 500)
            return
        self.send_json({'ok': True, 'trust_chain': trust_list, 'count': len(trust_list)})

    # ---------- DELETE /api/trust/{id} ----------
    def _handle_sas_trust_delete(self, tid):
        """删除信任的远程 CA"""
        sas_db, ca_mgr = self._require_sas()
        if sas_db is None:
            return
        if not tid:
            self.send_json({'ok': False, 'error': '缺少信任链 id'})
            return
        try:
            ok = sas_db.delete_trust(tid)
        except Exception as e:
            self.send_json({'ok': False, 'error': '删除信任链失败: ' + str(e)}, 500)
            return
        self.send_json({'ok': ok, 'error': '' if ok else '未找到对应信任记录'})

    # ---------- DELETE /api/user/{callsign} ----------
    def _handle_user_delete(self, callsign):
        """删除账户：吊销该呼号全部证书 + 软删除用户（删除/吊销状态经同步传播到全系统）"""
        if not callsign:
            self.send_json({'ok': False, 'error': '缺少呼号'})
            return
        # 1. 确认用户存在且未删除
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id, deleted FROM users WHERE callsign = ?", (callsign,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            self.send_json({'ok': False, 'error': '用户不存在: ' + callsign}, 404)
            return
        if row['deleted']:
            self.send_json({'ok': False, 'error': '用户已被删除: ' + callsign})
            return
        # 2. 吊销该呼号名下所有未吊销证书（revoked=1 + last_modified 刷新，随同步传播）
        revoked_count = 0
        sas_db = self.__class__.sas_db or _SAS_DB
        if sas_db is not None:
            try:
                for c in sas_db.list_certificates(10000):
                    if c.get('callsign') == callsign and not c.get('revoked'):
                        if sas_db.revoke_certificate(c['fingerprint']):
                            revoked_count += 1
            except Exception:
                pass  # 证书吊销失败不阻断账户删除
        # 3. 软删除用户（deleted=1 + last_modified 刷新，随同步传播到 master/其他分系统）
        eng = self.__class__.sync_engine
        if eng is not None:
            eng.soft_delete_user(callsign)
        else:
            conn = get_db()
            try:
                conn.execute(
                    "UPDATE users SET deleted=1, last_modified=? WHERE callsign=?",
                    (time.time(), callsign)
                )
                conn.commit()
            finally:
                conn.close()
        self.send_json({
            'ok': True,
            'callsign': callsign,
            'revoked_certs': revoked_count,
            'message': '账户已删除，%d 张证书已吊销，删除状态将同步到全系统' % revoked_count,
        })

    # ---------- GET /api/sas/config ----------
    def _handle_sas_config_get(self):
        """返回 SAS 运行时配置"""
        ca_mgr = self.__class__.ca_mgr or _CA_MGR
        ca_info = ca_mgr.info() if ca_mgr else None
        self.send_json({
            'ok': True,
            'config': dict(SAS_RUNTIME_CONFIG),
            'ca_info': ca_info,
        })

    # ---------- POST /api/sas/config ----------
    def _handle_sas_config_set(self):
        """更新 SAS 运行时配置（持久化到 config.json 的 sas_runtime 节点）"""
        body = self._read_json_body()
        if body is None:
            return
        # 只允许更新白名单等字段，不允许直接改 ca_dir 等敏感字段
        if 'allowed_callsigns' in body:
            val = body['allowed_callsigns']
            if isinstance(val, list):
                SAS_RUNTIME_CONFIG['allowed_callsigns'] = [
                    str(x).strip().upper() for x in val if str(x).strip()
                ]
            else:
                self.send_json({'ok': False, 'error': 'allowed_callsigns 必须是列表'})
                return
        if 'require_client_signature' in body:
            SAS_RUNTIME_CONFIG['require_client_signature'] = bool(body['require_client_signature'])
        # 仅证书客户端（FMO 固件用户）：强制 APP 签名时放行这些呼号
        if 'client_signature_certonly_callsigns' in body:
            val = body['client_signature_certonly_callsigns']
            if isinstance(val, list):
                SAS_RUNTIME_CONFIG['client_signature_certonly_callsigns'] = [
                    str(x).strip().upper() for x in val if str(x).strip()
                ]
            else:
                self.send_json({'ok': False, 'error': 'client_signature_certonly_callsigns 必须是列表'})
                return
        if 'client_signature_exempt_callsigns' in body:
            val = body['client_signature_exempt_callsigns']
            if isinstance(val, list):
                SAS_RUNTIME_CONFIG['client_signature_exempt_callsigns'] = [
                    str(x).strip().upper() for x in val if str(x).strip()
                ]
            else:
                self.send_json({'ok': False, 'error': 'client_signature_exempt_callsigns 必须是列表'})
                return
        if 'auto_trust_local_ca' in body:
            SAS_RUNTIME_CONFIG['auto_trust_local_ca'] = bool(body['auto_trust_local_ca'])
        if 'uid_range' in body:
            rng = body['uid_range']
            if isinstance(rng, dict) and 'start' in rng and 'end' in rng:
                try:
                    s = int(rng['start'])
                    e = int(rng['end'])
                    if 1 <= s <= e <= 200000:
                        SAS_RUNTIME_CONFIG['uid_range'] = {'start': s, 'end': e}
                    else:
                        self.send_json({'ok': False, 'error': 'uid_range 需满足 1<=start<=end<=200000'})
                        return
                except (ValueError, TypeError):
                    self.send_json({'ok': False, 'error': 'uid_range 必须是整数'})
                    return
            else:
                self.send_json({'ok': False, 'error': 'uid_range 必须含 start 和 end'})
                return
        if 'issuing_countries' in body:
            val = body['issuing_countries']
            if isinstance(val, list):
                SAS_RUNTIME_CONFIG['issuing_countries'] = [str(x) for x in val]
            else:
                self.send_json({'ok': False, 'error': 'issuing_countries 必须是列表'})
                return
        # 持久化
        save_sas_runtime_config()
        self.send_json({'ok': True, 'config': dict(SAS_RUNTIME_CONFIG)})


# ==================== 自定义服务器（允许重用端口） ====================
class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class PublicApiHandler(ApiHandler):
    """公网端口处理器：仅放行白名单路径（APP + 系统间同步），管理类一律 403。"""
    public_only = True


# ==================== 主入口 ====================
def main():
    parser = argparse.ArgumentParser(description='FMO 分系统后端 API 服务')
    parser.add_argument('--port', type=int, default=None, help='监听端口，默认读 config.json 或 35928')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='监听地址，默认 0.0.0.0')
    args = parser.parse_args()

    # 端口优先级：命令行 > config.json > 默认
    port = args.port if args.port is not None else int(CONFIG.get('port', PORT))

    # 初始化数据库和目录
    init_db()

    # ---- 初始化 SAS 认证服务 ----
    sas_db, ca_mgr, sas_config = init_sas_service()

    # ---- 初始化分布式同步引擎（后台线程）----
    sync_engine = init_sync_service()

    # ---- 初始化 BAS 审计子系统（内嵌 FAS：EMQX 审计/黑名单/统计，纯 Python）----
    bas_service, bas_http = None, None
    if _BAS_AVAILABLE:
        try:
            bas_cfg = dict(CONFIG)
            bas_cfg['admin_port'] = port + 1
            sas_db_path = (sas_config or {}).get('db_path')
            bas_service, bas_http = init_bas(
                bas_cfg, BASE_DIR,
                users_db_path=DB_PATH,
                sas_db_path=sas_db_path,
                logger=print)
        except Exception as e:
            print("[INIT] BAS 审计子系统初始化异常: %s" % e)
            bas_service, bas_http = None, None
    else:
        print("[INIT] BAS 审计子系统: 未启用（bas_http 模块不可用）")

    # ---- 初始化语音/信标监控线程（MQTT 抄收 + 上报总系统）----
    monitor = None
    if _MONITOR_AVAILABLE and _SAS_AVAILABLE:
        try:
            monitor = VoiceMonitor(CONFIG, ca_mgr, BASE_DIR)
            if monitor.enabled:
                monitor.start()
            else:
                print("[INIT] 语音监控: 配置已禁用（monitor.enabled=false）")
        except Exception as e:
            print("[INIT] 语音监控启动失败: %s" % e)
            monitor = None
    else:
        print("[INIT] 语音监控: 未启用（monitor 或 SAS 模块不可用）")

    # ---- 初始化 MQTT 互联桥接（无主：每个对端一条独立连接）----
    # 放在监控之后：桥接连 broker 要用的本机监控证书由监控线程签发。
    # 即使证书还没就绪也不会卡住 —— 桥接自身有退避重连。
    global _BRIDGE
    if _BRIDGE_AVAILABLE:
        try:
            _BRIDGE = VoiceBridge(BASE_DIR, CONFIG, save_fn=save_config,
                                  logger=print)
            if _BRIDGE.public_config().get('enabled'):
                _BRIDGE.start()
            else:
                _BRIDGE._local_state = 'disabled'
                print("[INIT] 互联桥接: 未启用（bridge.enabled=false，可在 /admin/bridge 打开）")
        except Exception as e:
            print("[INIT] 互联桥接启动失败: %s" % e)
            _BRIDGE = None
    else:
        print("[INIT] 互联桥接: 未启用（bridge 模块不可用）")

    # ---- 初始化 APRS 台站采集线程（FMO 台站不在库里，只能从 APRS-IS 累积）----
    # 台站广播有周期，短听只有个位数；常驻累积才能攒到几百个。
    aprs_store, aprs_collector = None, None
    if _APRS_AVAILABLE:
        try:
            aprs_store = fmo_aprs.AprsStationStore(BASE_DIR)
            aprs_collector = fmo_aprs.AprsCollector(aprs_store, logger=print,
                                                    base_dir=BASE_DIR)
            # 登记「自己」：探测时跳过，避免拿自己的证书反复连自家 broker
            # （真实事故：探自己把本机监控的 MQTT 连接挤掉 → 看起来像服务断联）
            _self_hosts = [str(CONFIG.get('app_domain') or ''),
                           str(CONFIG.get('domain') or ''),
                           'localhost', '127.0.0.1']
            try:
                _self_hosts.append(socket.gethostbyname(socket.gethostname()))
            except Exception:  # noqa: BLE001
                pass
            # master_url / api_url 里的域名也算自己（本机对外可能有好几个名字）
            for _key in ('master_url', 'api_url'):
                _u = str(CONFIG.get(_key) or '')
                if '://' in _u:
                    _u = _u.split('://', 1)[1]
                _self_hosts.append(_u.split('/')[0].split(':')[0])
            _self_cs = []
            try:
                if monitor is not None and getattr(monitor, 'stations', None):
                    for _st in monitor.stations():
                        if _st.get('callsign'):
                            _self_cs.append(_st['callsign'])
            except Exception:  # noqa: BLE001
                pass
            # 本机自己的站点名片呼号（BH6BHG）；APRS 上是带 SSID 的 BH6BHG-15，
            # fmo_aprs.base_callsign() 会归一化后再比对
            aprs_collector.set_self(hosts=_self_hosts, callsigns=_self_cs)
            aprs_collector.start()
            print("[INIT] APRS 台站采集: 已启动（%s:%d），台账现有 %d 个台站"
                  % (fmo_aprs.APRS_HOST, fmo_aprs.APRS_PORT, aprs_store.count()))
        except Exception as e:
            print("[INIT] APRS 台站采集启动失败: %s" % e)
            aprs_collector = None
    else:
        print("[INIT] APRS 台站采集: 未启用（fmo_aprs 模块不可用）")

    # ---- 把 SAS / Sync / Monitor / BAS 对象注入 ApiHandler 类属性 ----
    ApiHandler.sas_db = sas_db
    ApiHandler.ca_mgr = ca_mgr
    ApiHandler.sas_config = sas_config
    ApiHandler.sync_engine = sync_engine  # SyncApiMixin 通过 self.__class__.sync_engine 访问
    ApiHandler.monitor = monitor
    ApiHandler.aprs_store = aprs_store
    ApiHandler.aprs_collector = aprs_collector
    ApiHandler.bas_http = bas_http
    ApiHandler.bas_service = bas_service

    # 上报后台线程已由 sync_engine 接管（init_sync_service 内部启动），
    # 不再单独启动旧 report_loop，避免双通道重复上报。

    # 启动 HTTP 服务器（双端口：公网 API 口 + 内网管理口，管理口写死 = API 口 + 1）
    admin_port = port + 1
    server = ReusableTCPServer((args.host, port), PublicApiHandler)
    admin_server = ReusableTCPServer((args.host, admin_port), ApiHandler)
    t_admin = threading.Thread(
        target=admin_server.serve_forever, name='AdminPortThread', daemon=True)
    t_admin.start()

    # 计算 APP 登录地址
    app_domain = CONFIG.get('app_domain', '')
    app_port = CONFIG.get('app_port', port)
    app_use_port = CONFIG.get('app_use_port', True)
    if app_domain:
        if app_use_port and app_port:
            app_login_url = "%s:%d" % (app_domain, int(app_port))
        else:
            app_login_url = app_domain
    else:
        app_login_url = "（未配置，请在管理后台设置）"

    print("=" * 60)
    print("  FMO 分系统后端 API 服务已启动")
    print("=" * 60)
    print("  APP 登录地址: %s" % app_login_url)
    print("  公网 API 端口: %d（仅 APP/同步白名单，管理接口已隔离）" % port)
    print("  管理端口: %d（内网，勿映射公网）" % admin_port)
    print("  FUS 门户: http://内网IP:%d/admin" % admin_port)
    print("    ├─ SAS 系统（统一认证服务）: http://内网IP:%d/admin/sas" % admin_port)
    if bas_service is not None:
        print("    └─ FAS 系统（统一审计服务）: http://内网IP:%d/admin/fus"
              "  策略模式=%s" % (admin_port, bas_service.policy.mode()))
        print("            EMQX 收数口: POST /api/ingest（X-Ingest-Token 自校验）")
        print("            身份控制: %s" % ("启用" if bas_service.identity_control_enabled() else "关闭"))
    else:
        print("  BAS 审计: 未启用")
    print("  数据库:   %s" % DB_PATH)
    print("  上传目录: %s" % UPLOAD_DIR)
    print("  在线判定: 最后心跳 %d 秒内为在线" % ONLINE_TIMEOUT)
    if _SAS_AVAILABLE and ca_mgr is not None:
        print("  SAS 服务: 已整合（/auth, /api/cert/issue, /api/ca/*, /api/trust/*）")
    else:
        print("  SAS 服务: 未启用")
    if sync_engine is not None:
        print("  同步引擎: 已启动（/api/sync/peer, /api/sync/status）")
    else:
        print("  同步引擎: 未启用")
    if monitor is not None and monitor.enabled:
        print("  语音监控: 已启动（MQTT %s:%d → 瀑布图 /admin）" % (
            monitor.mqtt_host, monitor.mqtt_port))
    else:
        print("  语音监控: 未启用")
    print("=" * 60)
    print("按 Ctrl+C 停止服务")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n服务正在停止...")
    finally:
        # 关闭管理端口服务
        try:
            admin_server.shutdown()
            admin_server.server_close()
        except Exception:
            pass
        # 停止 BAS 审计采集线程
        if bas_service is not None:
            try:
                bas_service.stop()
            except Exception as e:
                print("[BAS] 停止审计线程异常: %s" % e)
        # 停止语音监控线程
        if monitor is not None:
            try:
                monitor.stop()
            except Exception as e:
                print("[MONITOR] 停止监控线程异常: %s" % e)
        # 停止同步引擎
        if sync_engine is not None:
            try:
                sync_engine.stop()
            except Exception as e:
                print("[SYNC] 停止同步引擎异常: %s" % e)
        # 关闭 SAS 数据库
        if sas_db is not None:
            try:
                sas_db.close()
            except Exception as e:
                print("[SAS] 关闭 SAS 数据库异常: %s" % e)
        server.server_close()
        print("服务已停止")


if __name__ == '__main__':
    main()