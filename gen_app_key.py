#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成 APP 签名密钥对（Ed25519）
===============================
★ 每套部署都必须**自己生成**密钥对：源码/发版包里**不再内置**任何 APP 密钥。
  历史上曾内置"官方密钥对"，而私钥 seed 又随公开仓库与发版包一起泄露 →
  任何人都能伪造 APP 签名。所以改为"谁部署谁生成"，且私钥只留在 APP 里。

用法：
    python gen_app_key.py

输出：
    APP_SEED   —— 烧进 APP 代码（写死；绝不上传、绝不入库、绝不贴进工单/文档）
    APP_PUBKEY —— 用 `sudo fus-set-appkey --pubkey <公钥>` 写入**每一台**分系统

换密钥（比如怀疑泄露）时的顺序：
    1) python gen_app_key.py            # 生成新的一对
    2) sudo fus-set-appkey --pubkey <新公钥>   # 先在服务端换成新公钥
    3) 把新 APP_SEED 烧进 APP 并发版     # 再更新 APP
    4) 旧公钥自然作废（也可 --append 过渡期同时信任新旧两把）

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
    print("  - 本密钥对是**你这套部署专属**的：源码/发版包里不再内置任何 APP 密钥。")
    print("  - APP_SEED 只能烧进 APP：不要写进 config.json、不要上传、不要入库、")
    print("    不要贴进工单或聊天记录。怀疑泄露就重新生成一对并更新服务端。")
    print("  - APP 每次调 /api/cert/bind 时，用 APP_SEED 对消息")
    print("    'FMO-APP-auth:{timestamp}:{callsign}:{pubkey}' 做 Ed25519 签名，")
    print("    随请求体 app_signature / app_timestamp 一起提交。")
    print("  - 服务端用公钥验签，通过才放行。")
    print("=" * 62)
    return 0


if __name__ == '__main__':
    sys.exit(main())
