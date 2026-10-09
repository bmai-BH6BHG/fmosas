#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 APP 签名密钥对（Ed25519）
===============================
⚠ 一般**不需要**用这个脚本。官方 APP 的密钥对是固定的，服务端只要写入它的公钥即可：

       sudo fus-set-appkey            # 写入官方 APP 公钥（推荐）

只有当你自己编译 APP、要用一套全新的密钥时，才需要本脚本生成新密钥对。

用法：
    python gen_app_key.py

输出：
    APP_SEED   —— 烧进 APP 代码（写死，绝不上传、绝不外泄）
    APP_PUBKEY —— 用 `sudo fus-set-appkey --pubkey <公钥>` 写入服务端

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
    print("APP_PUBKEY（用 `sudo fus-set-appkey --pubkey <公钥>` 写入服务端）:")
    print("  %s" % b64url_encode(pub))
    print("")
    print("=" * 62)
    print("说明：")
    print("  - 官方 APP 用固定密钥对：服务端只需 `sudo fus-set-appkey`（写官方公钥），")
    print("    不需要用本脚本生成新密钥。")
    print("  - 仅当你自己编译 APP 时才用上面的新密钥对。")
    print("  - APP 每次调 /api/cert/bind 时，用 APP_SEED 对消息")
    print("    'FMO-APP-auth:{timestamp}:{callsign}:{pubkey}' 做 Ed25519 签名，")
    print("    随请求体 app_signature / app_timestamp 一起提交。")
    print("  - 服务端用公钥验签，通过才放行。")
    print("=" * 62)
    return 0


if __name__ == '__main__':
    sys.exit(main())
