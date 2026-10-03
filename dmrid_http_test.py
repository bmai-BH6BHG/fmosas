#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
国服 ID 绑定 完整 HTTP 集成测试（APP 签名鉴权版）
================================================
在临时目录复制整套源码并启动真实 api_server（公网口 PublicApiHandler），
用 HTTP 走完整链路：

  1. 客户端 derive_keypair(呼号, 密码) 派生密钥
  2. POST /api/cert/bind（APP 私钥签名鉴权）-> 查呼号存在(dev_mode) + 签发派生公钥证书
  3. POST /auth           -> MQTT 认证应返回 allow
  4. 缺失/错误 APP 签名应 403
  5. 错误 key_proof 应 403

不改动仓库任何真实文件（config.json / users.db / ca/ 均在临时目录）。
用法： python dmrid_http_test.py
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

SRC = os.path.dirname(os.path.abspath(__file__))
FILES = ['api_server.py', 'sas_server.py', 'sync_engine.py', 'cert_gen.py', 'monitor.py']


def http_json(url, obj):
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.getcode(), json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode('utf-8'))
        except Exception:
            return e.code, {}


def main():
    tmp = tempfile.mkdtemp(prefix='fmo_full_test_')
    for f in FILES:
        shutil.copy(os.path.join(SRC, f), os.path.join(tmp, f))

    cfg = json.load(open(os.path.join(SRC, 'config.json'), encoding='utf-8-sig'))
    cfg['dmrid'] = {
        'enabled': True, 'dev_mode': True,
        'base_url': 'https://dmriapi.radiowo.com', 'timeout': 5,
        'app_pubkey': '', 'app_timestamp_window': 300,
        'verify_password': False,
        'kdf_algorithm': 'pbkdf2', 'kdf_pbkdf2_iterations': 600000,
    }
    cfg['subsystem_id'] = 'sub-fulltest'   # 避免自动重生成写回
    cfg['domain'] = ''                      # db 前缀走 default，隔离仓库
    cfg['api_url'] = ''
    cfg['master_url'] = ''
    cfg['peers'] = []
    cfg['monitor'] = {'enabled': False}     # 关闭监控，避免连 MQTT
    json.dump(cfg, open(os.path.join(tmp, 'config.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=4)

    os.chdir(tmp)
    sys.path.insert(0, tmp)

    import api_server
    from cert_gen import (
        derive_keypair, build_key_proof, build_mqtt_credentials, build_app_signature,
        b64url_encode, generate_keypair,
    )

    # APP 密钥对（服务端只存公钥）
    app_seed, app_pub = generate_keypair()
    app_pub_b64 = b64url_encode(app_pub)
    # 另一个"错误"密钥对（用于验证错误签名被拒）
    wrong_seed, _ = generate_keypair()

    # 回填 APP 公钥到运行时配置
    api_server.CONFIG['dmrid']['app_pubkey'] = app_pub_b64

    api_server.init_db()
    sas_db, ca_mgr, sas_config = api_server.init_sas_service()
    api_server.ApiHandler.sas_db = sas_db
    api_server.ApiHandler.ca_mgr = ca_mgr
    api_server.ApiHandler.sas_config = sas_config
    api_server.ApiHandler.sync_engine = None
    api_server.ApiHandler.monitor = None
    # 公网口处理器（APP 实际走的口），验证白名单放行 /api/cert/bind 与 /auth
    api_server.PublicApiHandler.sas_db = sas_db
    api_server.PublicApiHandler.ca_mgr = ca_mgr
    api_server.PublicApiHandler.sas_config = sas_config
    api_server.PublicApiHandler.sync_engine = None
    api_server.PublicApiHandler.monitor = None

    server = api_server.ReusableTCPServer(('127.0.0.1', 0), api_server.PublicApiHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    base = 'http://127.0.0.1:%d' % port
    print("临时目录: %s" % tmp)
    print("测试服务器: %s (公网口 PublicApiHandler)" % base)

    callsign = 'BG2XFM'
    password = 'test123456'
    seed, pub = derive_keypair(callsign, password)
    key_proof = build_key_proof(seed, callsign)
    pub_b64 = b64url_encode(pub)

    def bind_body(app_seed_use, ts=None):
        ts = int(ts if ts is not None else time.time())
        return {
            'callsign': callsign,
            'pubkey': pub_b64, 'key_proof': key_proof,
            'app_timestamp': ts,
            'app_signature': build_app_signature(app_seed_use, ts, callsign, pub_b64),
        }

    # 0. 缺失 APP 签名应 403
    code, r = http_json(base + '/api/cert/bind', {
        'callsign': callsign, 'pubkey': pub_b64, 'key_proof': key_proof,
    })
    assert code == 403 and not r.get('ok'), (code, r)
    print("[0] 缺失 APP 签名拒绝 OK: HTTP %d -> %s" % (code, r.get('error')))

    # 0b. 错误 APP 签名（另一把私钥）应 403
    code, r = http_json(base + '/api/cert/bind', bind_body(wrong_seed))
    assert code == 403 and not r.get('ok'), (code, r)
    print("[0b] 错误 APP 签名拒绝 OK: HTTP %d -> %s" % (code, r.get('error')))

    # 1. 绑定（正确签名）
    code, bind = http_json(base + '/api/cert/bind', bind_body(app_seed))
    assert code == 200 and bind.get('ok'), (code, bind)
    print("[1] /api/cert/bind OK  uid=%s  fp=%s  guoji=%s  derived=%s" % (
        bind.get('uid'), str(bind.get('fingerprint'))[:20],
        bind.get('guoji_id'), bind.get('derived')))
    assert bind.get('cert_devicekey') is None, "derived 证书不应下发 devicekey"

    # 2. 幂等：同公钥再次绑定应复用原证书（同 fingerprint）
    code, bind2 = http_json(base + '/api/cert/bind', bind_body(app_seed))
    assert code == 200 and bind2.get('ok') and bind2.get('fingerprint') == bind.get('fingerprint'), bind2
    print("[2] 幂等绑定 OK（同公钥复用同证书 fingerprint）")

    # 3. 用派生私钥构造 MQTT 凭证并认证
    username, pw = build_mqtt_credentials(
        bind['cert_int'], bind['cert_user'], seed,
        target_url='127.0.0.1', target_port=1883,
        role='user', target_callsign=callsign,
        server_fingerprint=bind['fingerprint'])
    code, auth = http_json(base + '/auth', {'username': username, 'password': pw})
    assert code == 200 and auth.get('result') == 'allow', (code, auth)
    print("[3] /auth OK  allow  client_attrs=%s" % auth.get('client_attrs'))

    # 4. 错误 key_proof 应 403
    bad_proof = build_key_proof(seed, 'OTHERCALL')
    ts = int(time.time())
    code, bad = http_json(base + '/api/cert/bind', {
        'callsign': callsign, 'pubkey': pub_b64, 'key_proof': bad_proof,
        'app_timestamp': ts,
        'app_signature': build_app_signature(app_seed, ts, callsign, pub_b64),
    })
    assert code == 403 and not bad.get('ok'), (code, bad)
    print("[4] 错误 key_proof 拒绝 OK: HTTP %d -> %s" % (code, bad.get('error')))

    # 5. 非法呼号格式应 400
    ts = int(time.time())
    code, bad = http_json(base + '/api/cert/bind', {
        'callsign': 'bad_sign', 'pubkey': pub_b64, 'key_proof': key_proof,
        'app_timestamp': ts,
        'app_signature': build_app_signature(app_seed, ts, 'bad_sign', pub_b64),
    })
    assert code == 400 and not bad.get('ok'), (code, bad)
    print("[5] 非法呼号格式拒绝 OK: HTTP %d -> %s" % (code, bad.get('error')))

    server.shutdown()
    server.server_close()
    print("=" * 62)
    print("PASS：真实 api_server HTTP 全链路（APP签名鉴权 -> 绑定 -> 幂等 -> MQTT 认证）通过")
    print("=" * 62)
    return 0


if __name__ == '__main__':
    sys.exit(main())
