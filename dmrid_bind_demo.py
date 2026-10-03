#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
国服 ID（DMRID）绑定 端到端自测脚本
====================================
验证核心链路：国服ID（呼号）+ 密码 → 确定性派生 Ed25519 私钥
            → 服务器对派生公钥签发证书 → 客户端构造 MQTT 凭证
            → 服务器 /auth 认证通过（allow）。

用法：
    python dmrid_bind_demo.py

说明：
    - 只用 cert_gen + sas_server 两个模块，在临时目录里跑，不改动仓库的
      config.json / users.db / ca/ 等任何真实文件。
    - 等价于 /api/cert/bind 的服务端签发步骤 + broker 回调 /auth 的认证步骤。
"""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cert_gen import (
    derive_keypair, build_key_proof, build_mqtt_credentials,
    b64url_decode, ed25519_verify, BIND_KEY_PROOF_PREFIX,
)
from sas_server import Database, CaManager, authenticate


def main():
    tmp = tempfile.mkdtemp(prefix='fmo_dmrid_test_')
    ca_dir = os.path.join(tmp, 'ca')
    db_path = os.path.join(tmp, 'sas.db')

    print("=" * 62)
    print("国服 ID 绑定 端到端自测")
    print("临时目录: %s" % tmp)
    print("=" * 62)

    # ---- 服务器侧：初始化 SAS 数据库 + 本地 CA ----
    db = Database(db_path)
    ca_mgr = CaManager(ca_dir=ca_dir, db=db, ca_name='MYCA', validity_years=10)
    ca_mgr.init()
    print("[服务器] 本地 CA 已初始化: %s" % ca_mgr.ca_name)

    # ---- 客户端：国服 ID + 密码 派生密钥（无需任何证书文件）----
    callsign = 'BG2XFM'
    password = 'myDmridPassword123'
    seed, pub = derive_keypair(callsign, password)
    print("[客户端] 派生 seed=%s... pub=%s..." % (seed.hex()[:16], pub.hex()[:16]))

    # 确定性：同账号同密码必得同密钥（换设备可重派生）
    seed2, pub2 = derive_keypair(callsign, password)
    assert seed == seed2 and pub == pub2, "派生不是确定性的！"
    print("[客户端] 确定性校验通过（同账号同密码 -> 同密钥，换设备可重建）")

    # 密钥持有证明（等价 /api/cert/bind 请求里的 key_proof 字段）
    key_proof = build_key_proof(seed, callsign)
    proof_msg = (BIND_KEY_PROOF_PREFIX + callsign).encode('utf-8')
    assert ed25519_verify(pub, proof_msg, b64url_decode(key_proof)), "key_proof 验签失败"
    print("[绑定] key_proof 验证通过（证明持有 pub 对应私钥，服务器无需接触 seed）")

    # ---- 服务器侧：对派生公钥签发证书（等效 /api/cert/bind 的签发步骤）----
    uid = 1001
    certs = ca_mgr.issue_user_cert_for_pubkey(callsign, uid, pub)
    db.add_certificate(callsign, uid, json.dumps(certs['user_cert'], ensure_ascii=False),
                       '', certs['fingerprint'], derived=True)
    print("[服务器] 已对派生公钥签发证书: fp=%s..." % certs['fingerprint'][:20])

    # ---- 客户端：用派生私钥构造 MQTT CONNECT 凭证 ----
    username, mqtt_password = build_mqtt_credentials(
        certs['int_cert'], certs['user_cert'], seed,
        target_url='127.0.0.1', target_port=1883,
        role='user', target_callsign=callsign,
        server_fingerprint=certs['fingerprint'])
    print("[客户端] MQTT username=%s password(len)=%d" % (username, len(mqtt_password)))

    # ---- 服务器侧：MQTT /auth 认证（等效 broker 回调）----
    result = authenticate(username, mqtt_password, ca_mgr, db)
    print("[服务器] /auth 结果: %s | %s" % (result.get('result'), result.get('reason', '')))
    if result.get('result') == 'allow':
        print("         client_attrs = %s" % result.get('client_attrs'))
        print("         acl 条数 = %d" % len(result.get('acl', [])))
    assert result.get('result') == 'allow', "MQTT 认证未通过！"

    print("=" * 62)
    print("PASS：国服 ID + 密码 -> 证书 -> MQTT 认证 全链路通过")
    print("=" * 62)
    return 0


if __name__ == '__main__':
    sys.exit(main())
