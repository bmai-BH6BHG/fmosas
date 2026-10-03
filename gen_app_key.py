#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 APP 签名密钥对（Ed25519）
===============================
用于 /api/cert/bind 的 APP 签名鉴权（方案 B）。

用法：
    python gen_app_key.py

输出：
    APP_SEED   —— 烧进 APP 代码（写死，绝不上传、绝不外泄）
    APP_PUBKEY —— 填入 config.json 的 dmrid.app_pubkey

签名规则（服务端验签用同一消息）：
    message = UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")
    signature = Ed25519_sign(app_seed, message)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cert_gen import generate_keypair, b64url_encode


def main():
    seed, pub = generate_keypair()
    print("=" * 62)
    print("APP 签名密钥对已生成（Ed25519）")
    print("=" * 62)
    print("")
    print("APP_SEED（烧进 APP 代码，写死，绝不上传/不外泄）:")
    print("  %s" % b64url_encode(seed))
    print("")
    print("APP_PUBKEY（填入 config.json 的 dmrid.app_pubkey）:")
    print("  %s" % b64url_encode(pub))
    print("")
    print("=" * 62)
    print("说明：")
    print("  - APP 每次调 /api/cert/bind 时，用 APP_SEED 对消息")
    print("    'FMO-APP-auth:{timestamp}:{callsign}:{pubkey}' 做 Ed25519 签名，")
    print("    随请求体 app_signature / app_timestamp 一起提交。")
    print("  - 服务端用 APP_PUBKEY 验签，通过才放行。")
    print("  - 换密钥：重新运行本脚本，新 PUBKEY 填 config，新 SEED 烧进 APP。")
    print("=" * 62)
    return 0


if __name__ == '__main__':
    sys.exit(main())
