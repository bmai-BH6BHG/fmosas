#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FMO 证书生成工具
================

生成完整的 FMO 证书体系（Ed25519 签名链）：
    Root CA（自签名）
      └─ Intermediate CA（由 Root CA 签发）
            └─ User Cert（由 Intermediate CA 签发）
                  └─ Device Key（用户私钥 seed + 公钥）

输出文件：
    cert_root.json        Root CA 证书
    cert_int.json         Intermediate CA 证书
    cert_user.json        用户证书
    cert_devicekey.json   设备密钥（私钥 seed + 公钥）
    server_fingerprint.txt 服务器指纹（User Cert 的 SHA256(CBOR(tbs))，base64url）

签名逻辑参考 Rust protocol.rs：
    tbs = ["FMO", 4, <certType>, ..., pubkey_bytes(32), iat, exp]
    signature = Ed25519.sign(private_seed, CBOR_encode(tbs))
    fingerprint = SHA256(CBOR_encode(tbs))

CBOR 编码规则（与 Rust cbor_head_write 完全一致）：
    UInt  major=0 | Text major=3 | Bytes major=2 | Array major=4
    head = (major << 5) | info
        value <  24        -> info = value
        value <= 0xFF      -> info = 24, +1 byte
        value <= 0xFFFF    -> info = 25, +2 bytes (big-endian)
        value <= 0xFFFFFFFF-> info = 26, +4 bytes (big-endian)
        else               -> info = 27, +8 bytes (big-endian)

用法:
    python cert_gen.py --callsign BH6BHG --uid 1075 --ca-name MYCA --output ./certs
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature


# ============================================================
#  base64url（无 padding，与 Rust URL_SAFE_NO_PAD 一致）
# ============================================================

def b64url_encode(data: bytes) -> str:
    """base64url 编码，去掉末尾 '=' padding。"""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """base64url 解码，兼容有无 padding。"""
    s = text.rstrip("=")
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


# ============================================================
#  CBOR 编码器（与 Rust cbor_tbs / cbor_head_write 逐字节一致）
# ============================================================

def _cbor_head(major: int, value: int) -> bytes:
    """编码 CBOR 头部（major type + 长度/值）。"""
    if value < 24:
        return bytes([(major << 5) | value])
    elif value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    elif value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    elif value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    else:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_encode(value) -> bytes:
    """
    将 Python 值编码为 CBOR 字节串。
    支持: int(无符号/负数), str(utf-8), bytes, list/tuple(array)。
    """
    if isinstance(value, bool):
        # CBOR major type 7: false=0xF4, true=0xF5（与 .NET CborWriter.WriteBoolean 一致）
        return bytes([0xF5]) if value else bytes([0xF4])
    elif isinstance(value, int):
        if value < 0:
            # 负整数: major=1, 编码 -1 - n
            return _cbor_head(1, -1 - value)
        return _cbor_head(0, value)
    elif isinstance(value, str):
        b = value.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    elif isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return _cbor_head(2, len(b)) + b
    elif isinstance(value, (list, tuple)):
        out = _cbor_head(4, len(value))
        for item in value:
            out += cbor_encode(item)
        return out
    else:
        raise TypeError(f"不支持的 CBOR 类型: {type(value).__name__}")


def cbor_tbs(array: list) -> bytes:
    """编码 TBS 数组（整体作为一个 CBOR array 编码）。"""
    return cbor_encode(list(array))


# ============================================================
#  Ed25519 密钥操作
# ============================================================

def generate_keypair() -> tuple:
    """
    生成 Ed25519 密钥对。
    返回 (seed: bytes(32), pubkey: bytes(32))。
    """
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk = sk.public_key()
    pub = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, pub


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """用 seed（32 字节）对 message 做 Ed25519 签名，返回 64 字节签名。"""
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.sign(message)


def ed25519_verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """用 pubkey（32 字节）验证签名。"""
    try:
        # cryptography 的 Ed25519PublicKey.verify 在失败时抛 InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        vk = Ed25519PublicKey.from_public_bytes(pubkey)
        vk.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def pubkey_from_seed(seed: bytes) -> bytes:
    """从 seed 推导公钥（用于校验 devicekey 与 user cert 是否配套）。"""
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


# ============================================================
#  国服 ID（DMRID）账号 → Ed25519 密钥派生（密码派生密钥 / brain-wallet）
# ============================================================
# 设计目标：让「国服 ID + 密码」通过 KDF 确定性地派生出一把 Ed25519 私钥，
# 再由 FMO 的 Int CA 把这把公钥签进用户证书。从而：
#   - 用户无需保存/传输 devicekey JSON，只要记得国服账号密码即可重派生私钥；
#   - MQTT 认证仍走「证书链 + proof 私钥签名」，密码不进入 MQTT 报文；
#   - 换设备 / 清数据后仍可凭国服账号密码重建身份。
#
# 跨平台一致性要求（APP 的 Rust / .NET / JS 实现必须与这里逐字节一致）：
#   identifier  = 呼号（大写，UTF-8）
#   password    = 国服密码明文（UTF-8）
#   salt        = UTF8(KDF_SALT_PREFIX + ":" + identifier)
#   seed(32B)   = KDF(password, salt)
#   pubkey      = Ed25519 公钥（由 seed 推导）
# 更换算法/参数必须同时升级 KDF_SALT_PREFIX 版本号，避免新旧密钥互相冲突。

KDF_SALT_PREFIX = "FMO-DMRID-v1"
BIND_KEY_PROOF_PREFIX = "FMO-DMRID-bind:"
APP_AUTH_PREFIX = "FMO-APP-auth"
# MQTT 连接绑定式 APP 签名的消息前缀（把 clientid + 用户证书公钥签进去，
# 使签名只对这一条连接有效；HTTP 的 APP_AUTH_PREFIX 签名未绑定连接）
APP_MQTT_AUTH_PREFIX = "FMO-APP-mqtt"


def derive_keypair(identifier, password, algorithm="pbkdf2",
                   pbkdf2_iterations=600000,
                   scrypt_n=32768, scrypt_r=8, scrypt_p=1,
                   salt_prefix=KDF_SALT_PREFIX) -> tuple:
    """
    由国服账号（identifier=呼号）与国服密码确定性派生 Ed25519 密钥对。
    返回 (seed: bytes(32), pub: bytes(32))。
    """
    identifier = str(identifier or "").strip().upper()
    if not identifier or not password:
        raise ValueError("identifier 和 password 不能为空")
    salt = (salt_prefix + ":" + identifier).encode("utf-8")
    pw = password.encode("utf-8")
    if algorithm == "scrypt":
        kdf = Scrypt(salt=salt, length=32, n=scrypt_n, r=scrypt_r, p=scrypt_p)
    else:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32,
            salt=salt, iterations=pbkdf2_iterations,
        )
    seed = kdf.derive(pw)
    return seed, pubkey_from_seed(seed)


def build_key_proof(seed: bytes, callsign: str) -> str:
    """
    生成「绑定」时证明持有私钥的签名（base64url）：
        signature = Ed25519_sign(seed, UTF8(BIND_KEY_PROOF_PREFIX + callsign))
    服务端用 pubkey 验签即可确认调用方确实拥有与公钥配套的私钥，
    而无需服务端接触私钥本身。
    """
    msg = (BIND_KEY_PROOF_PREFIX + str(callsign).strip().upper()).encode("utf-8")
    return b64url_encode(ed25519_sign(seed, msg))


def build_app_signature(app_seed, timestamp, callsign, pubkey_b64) -> str:
    """
    生成 APP 签名（base64url）：用于 /api/cert/bind 的 APP 鉴权。
        message = UTF8("FMO-APP-auth:{timestamp}:{callsign}:{pubkey_b64}")
        signature = Ed25519_sign(app_seed, message)
    app_seed：APP 的 Ed25519 私钥 seed（32B bytes 或 base64url 字符串），
              由 gen_app_key.py 生成后烧进 APP；服务端只存对应公钥。
    """
    seed = b64url_decode(app_seed) if isinstance(app_seed, str) else bytes(app_seed)
    if len(seed) != 32:
        raise ValueError("app_seed 必须为 32 字节")
    msg = ("%s:%d:%s:%s" % (APP_AUTH_PREFIX, int(timestamp),
                            str(callsign).strip().upper(),
                            str(pubkey_b64).strip())).encode("utf-8")
    return b64url_encode(ed25519_sign(seed, msg))


def build_app_signature_mqtt(app_seed, timestamp, callsign, user_pubkey_b64,
                             clientid) -> str:
    """
    生成 **MQTT 连接绑定式** APP 签名（base64url）。

    与 build_app_signature（HTTP /api/cert/bind 用）的区别：把 clientid 与
    用户证书公钥一起签进消息，签名只对**这一条连接**有效，防止把 HTTP 请求上
    抓到的签名重放到别的 MQTT 连接上。

        message = UTF8("FMO-APP-mqtt:{timestamp}:{callsign}:{userPubkeyB64}:{clientid}")
        signature = Ed25519_sign(app_seed, message)

    参数：
      app_seed        APP 的 Ed25519 私钥 seed（32B bytes 或 base64url 字符串）
      timestamp       unix 秒（服务端 ±app_timestamp_window，默认 300 秒）
      callsign        MQTT username（明文呼号，会转大写）
      user_pubkey_b64 用户证书里的公钥 subject.publicKey（base64url，32B）
      clientid        MQTT clientid（原样，不做大小写转换）
    """
    seed = b64url_decode(app_seed) if isinstance(app_seed, str) else bytes(app_seed)
    if len(seed) != 32:
        raise ValueError("app_seed 必须为 32 字节")
    msg = ("%s:%d:%s:%s:%s" % (APP_MQTT_AUTH_PREFIX, int(timestamp),
                               str(callsign).strip().upper(),
                               str(user_pubkey_b64).strip(),
                               str(clientid))).encode("utf-8")
    return b64url_encode(ed25519_sign(seed, msg))


def build_mqtt_credentials(cert_int: dict, cert_user: dict, device_seed,
                           target_url: str, target_port: int,
                           role: str = "user", target_callsign: str = "",
                           target_uid: int = 0, server_fingerprint: str = "") -> tuple:
    """
    构造 MQTT CONNECT 的 (username, password)（与官方 FmoCert.buildMqttPassword 一致）。
      username = 明文呼号
      password = base64url(JSON{certPackage{intermediateCert,userCert}, 目标字段, proof{signature}})
    device_seed 可为 bytes(32) 或 base64url 字符串（由 derive_keypair 得到）。
    server_fingerprint 缺省用用户证书指纹（即本机 /api/cert/mine 返回的 fingerprint）。
    """
    seed = b64url_decode(device_seed) if isinstance(device_seed, str) else bytes(device_seed)
    if len(seed) != 32:
        raise ValueError("device_seed 必须为 32 字节")
    user_tbs = user_cert_tbs(
        cert_user["issuerSn"],
        cert_user["subject"]["callsign"],
        cert_user["subject"]["uid"],
        b64url_decode(cert_user["subject"]["publicKey"]),
        cert_user["iat"],
        cert_user["exp"],
    )
    user_fp_bytes = cert_fingerprint(user_tbs)
    sfp_bytes = b64url_decode(server_fingerprint) if server_fingerprint else user_fp_bytes
    ts = int(time.time())
    proof_tbs = [
        "FMO", 4, "serverAuthorizerReqHttp",
        int(target_uid or 0),
        str(target_callsign or "").upper(),
        int(target_uid or 0),
        str(role or ""),
        str(target_url or ""),
        int(target_port or 0),
        sfp_bytes,
        ts,
        user_fp_bytes,
    ]
    signature = b64url_encode(ed25519_sign(seed, cbor_tbs(proof_tbs)))
    password = b64url_encode(json.dumps({
        "certPackage": {"intermediateCert": cert_int, "userCert": cert_user},
        "targetCallsign": str(target_callsign or "").upper(),
        "targetUID": int(target_uid or 0),
        "role": str(role or ""),
        "targetUrl": str(target_url or ""),
        "targetPort": int(target_port or 0),
        "serverFingerprint": b64url_encode(sfp_bytes),
        "timestamp": ts,
        "proof": {"signature": signature},
    }, separators=(",", ":")).encode("utf-8"))
    username = str(cert_user["subject"]["callsign"]).upper()
    return username, password


# ============================================================
#  证书指纹
# ============================================================

def cert_fingerprint(tbs: list) -> bytes:
    """
    证书指纹 = SHA256(CBOR_encode(tbs))，返回 32 字节。
    """
    return hashlib.sha256(cbor_tbs(tbs)).digest()


def fingerprint_b64url(tbs: list) -> str:
    """证书指纹的 base64url 表示（用于 server_fingerprint.txt）。"""
    return b64url_encode(cert_fingerprint(tbs))


# ============================================================
#  时间工具
# ============================================================

def now_ts() -> int:
    """当前 Unix 时间戳（秒）。"""
    return int(time.time())


def years_to_seconds(years: int) -> int:
    """年转秒（按 365 天/年）。"""
    return years * 365 * 86400


def ts_to_str(ts: int) -> str:
    """时间戳转可读字符串（UTC）。"""
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ============================================================
#  TBS 构造（与 Rust user_cert_tbs 同构）
# ============================================================

def root_ca_tbs(sn, issuer_name, issuer_email, subject_name, pubkey, is_ca, path_len, crl, license, key_id, iat, exp) -> list:
    """
    Root CA TBS（与 SAS RootCaCert.ToTbsCbor 一致，15 个元素）:
        ["FMO", 4, "rootCA", sn, issuerName, issuerEmail, subjectName, subjectPubKey,
         isCA, pathLen, crl, license, keyId, iat, exp]
    """
    return ["FMO", 4, "rootCA", sn, issuer_name, issuer_email, subject_name, pubkey,
            is_ca, path_len, crl, license, key_id, iat, exp]


def intermediate_ca_tbs(sn, issuer_sn, issuer_name, issuer_pubkey, subject_name, subject_email, pubkey, is_ca, path_len, key_id, crl, license, uid_start, uid_end, issuing_countries, iat, exp) -> list:
    """
    Intermediate CA TBS（与 SAS IntermediateCaCert.ToTbsCbor 一致，20 个元素）:
        ["FMO", 4, "intermediateCA", sn, issuerSn, issuerName, issuerPubKey,
         subjectName, subjectEmail, subjectPubKey, isCA, pathLen, keyId, crl, license,
         uidRangeStart, uidRangeEnd, issuingCountries[], iat, exp]

    issuing_countries 会按 ordinal 排序（与 SAS FromJson 中 OrderBy StringComparer.Ordinal 一致）。
    """
    sorted_countries = sorted(issuing_countries)
    return ["FMO", 4, "intermediateCA", sn, issuer_sn, issuer_name, issuer_pubkey,
            subject_name, subject_email, pubkey, is_ca, path_len, key_id, crl, license,
            uid_start, uid_end, sorted_countries, iat, exp]


def user_cert_tbs(issuer_sn: int, callsign: str, uid: int, pubkey: bytes, iat: int, exp: int) -> list:
    """
    User Cert TBS（与 Rust protocol::user_cert_tbs 完全一致）:
        ["FMO", 4, "userCert", issuerSn, callsign, uid, pubkey_bytes, iat, exp]
    """
    return ["FMO", 4, "userCert", issuer_sn, callsign, uid, pubkey, iat, exp]


# ============================================================
#  证书构建
# ============================================================

def build_root_ca(
    seed: bytes,
    pub: bytes,
    ca_name: str,
    ca_email: str = "",
    sn: int = 1,
    validity_years: int = 10,
) -> tuple:
    """
    构建 Root CA 证书（自签名）。
    返回 (cert_dict, tbs_list)。
    """
    iat = now_ts()
    exp = iat + years_to_seconds(validity_years)
    key_id = str(sn)
    tbs = root_ca_tbs(
        sn=sn,
        issuer_name=ca_name,
        issuer_email=ca_email,
        subject_name=ca_name,
        pubkey=pub,
        is_ca=True,
        path_len=1,
        crl="",
        license="",
        key_id=key_id,
        iat=iat,
        exp=exp,
    )
    signature = ed25519_sign(seed, cbor_tbs(tbs))

    cert = {
        "sn": sn,
        "type": "rootCA",
        "issuer": {"name": ca_name, "email": ca_email},
        "subject": {"name": ca_name, "publicKey": b64url_encode(pub)},
        "extensions": {
            "isCA": True,
            "pathLen": 1,
            "crl": "",
            "license": "",
            "keyId": str(sn),
        },
        "iat": iat,
        "exp": exp,
        "signatureAlgorithm": "Ed25519",
        "signature": b64url_encode(signature),
    }
    return cert, tbs


def build_intermediate_ca(
    seed: bytes,
    pub: bytes,
    root_cert: dict,
    root_seed: bytes,
    ca_name: str,
    ca_email: str = "",
    sn: int = 1001,
    validity_years: int = 10,
    uid_start: int = 1,
    uid_end: int = 200000,
    issuing_countries: list = None,
) -> tuple:
    """
    构建 Intermediate CA 证书（由 Root CA 签发）。
    返回 (cert_dict, tbs_list)。
    """
    if issuing_countries is None:
        issuing_countries = ["CN"]
    iat = now_ts()
    exp = iat + years_to_seconds(validity_years)
    # issuing_countries 按 ordinal 排序（与 SAS 一致）
    sorted_countries = sorted(issuing_countries)
    tbs = intermediate_ca_tbs(
        sn=sn,
        issuer_sn=root_cert["sn"],
        issuer_name=root_cert["subject"]["name"],
        issuer_pubkey=b64url_decode(root_cert["subject"]["publicKey"]),
        subject_name=ca_name,
        subject_email=ca_email,
        pubkey=pub,
        is_ca=True,
        path_len=0,
        key_id=str(sn),
        crl="",
        license="",
        uid_start=uid_start,
        uid_end=uid_end,
        issuing_countries=sorted_countries,
        iat=iat,
        exp=exp,
    )
    signature = ed25519_sign(root_seed, cbor_tbs(tbs))

    cert = {
        "sn": sn,
        "type": "intermediateCA",
        "issuer": {
            "sn": root_cert["sn"],
            "name": root_cert["subject"]["name"],
            "publicKey": root_cert["subject"]["publicKey"],
        },
        "subject": {
            "name": ca_name,
            "email": ca_email,
            "publicKey": b64url_encode(pub),
        },
        "extensions": {
            "isCA": True,
            "pathLen": 0,
            "keyId": str(sn),
            "crl": "",
            "license": "",
            "uidRange": {"start": uid_start, "end": uid_end},
            "issuingCountries": sorted_countries,
        },
        "iat": iat,
        "exp": exp,
        "signatureAlgorithm": "Ed25519",
        "signature": b64url_encode(signature),
    }
    return cert, tbs


def build_user_cert(
    seed: bytes,
    pub: bytes,
    int_cert: dict,
    int_seed: bytes,
    callsign: str,
    uid: int,
    validity_years: int = 10,
) -> tuple:
    """
    构建 User Cert（由 Intermediate CA 签发）。
    返回 (cert_dict, tbs_list)。
    """
    iat = now_ts()
    exp = iat + years_to_seconds(validity_years)
    tbs = user_cert_tbs(int_cert["sn"], callsign, uid, pub, iat, exp)
    signature = ed25519_sign(int_seed, cbor_tbs(tbs))

    cert = {
        "issuerSn": int_cert["sn"],
        "subject": {
            "callsign": callsign,
            "uid": uid,
            "publicKey": b64url_encode(pub),
        },
        "iat": iat,
        "exp": exp,
        "signatureAlgorithm": "Ed25519",
        "signature": b64url_encode(signature),
    }
    return cert, tbs


def build_device_key(seed: bytes, pub: bytes) -> dict:
    """
    构建设备密钥文件（私钥 seed + 公钥，base64url 编码）。
    """
    return {"seed": b64url_encode(seed), "pubKey": b64url_encode(pub)}


# ============================================================
#  签名链验证
# ============================================================

def validate_root_ca_cert(cert):
    """
    校验 rootCA 证书结构与自签名（Ed25519）。
    用于"根证书接种"场景：江苏 add-root 模式、roots 目录加载、
    master 根目录登记/分系统 merge 下发根。
    :param cert: rootCA 证书 dict
    :return: 通过返回根公钥(base64url str)，失败返回 None
    """
    try:
        if not isinstance(cert, dict):
            return None
        # 官方证书无 type 字段；显式标注了类型且不是 rootCA 的才拒绝
        if cert.get("type") is not None and cert.get("type") != "rootCA":
            return None
        pub_b64 = str(cert["subject"]["publicKey"])
        pub = b64url_decode(pub_b64)
        tbs = root_ca_tbs(
            sn=cert["sn"],
            issuer_name=cert["issuer"]["name"],
            issuer_email=cert["issuer"]["email"],
            subject_name=cert["subject"]["name"],
            pubkey=pub,
            is_ca=cert["extensions"]["isCA"],
            path_len=cert["extensions"]["pathLen"],
            crl=cert["extensions"]["crl"],
            license=cert["extensions"]["license"],
            key_id=cert["extensions"]["keyId"],
            iat=cert["iat"],
            exp=cert["exp"],
        )
        if not ed25519_verify(pub, cbor_tbs(tbs), b64url_decode(cert["signature"])):
            return None
        return pub_b64
    except Exception:
        return None


def verify_chain(root_cert, int_cert, user_cert, root_pub, int_pub, user_pub) -> list:
    """
    验证整条证书链签名。
    返回问题列表（空列表表示全部通过）。
    """
    issues = []

    # 1. Root CA 自签名验证
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
    else:
        print("  [OK] Root CA 自签名验证通过")

    # 2. Intermediate CA 由 Root CA 签发
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
        issues.append("Intermediate CA 签名验证失败（应由 Root CA 签发）")
    else:
        print("  [OK] Intermediate CA 签名验证通过（由 Root CA 签发）")

    # 3. User Cert 由 Intermediate CA 签发
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
        issues.append("User Cert 签名验证失败（应由 Intermediate CA 签发）")
    else:
        print("  [OK] User Cert 签名验证通过（由 Intermediate CA 签发）")

    return issues


# ============================================================
#  文件输出
# ============================================================

def write_json(path: str, obj: dict) -> None:
    """写 JSON 文件（UTF-8，2 空格缩进，保持 ASCII 安全外的中文可读）。"""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_text(path: str, text: str) -> None:
    """写文本文件。"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


# ============================================================
#  主流程
# ============================================================

def generate_all(
    callsign: str,
    uid: int,
    ca_name: str = "MYCA",
    ca_email: str = "",
    output_dir: str = ".",
    root_sn: int = 1,
    int_sn: int = 1001,
    validity_years: int = 10,
    uid_start: int = 1,
    uid_end: int = 200000,
    issuing_countries: list = None,
) -> dict:
    """
    生成完整证书体系并写入文件。
    返回各文件路径与摘要信息。
    """
    if issuing_countries is None:
        issuing_countries = ["CN"]

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 64)
    print("FMO 证书生成工具")
    print("=" * 64)
    print(f"  CA 名称     : {ca_name}")
    print(f"  用户呼号    : {callsign}")
    print(f"  用户 UID    : {uid}")
    print(f"  输出目录    : {output_dir}")
    print(f"  有效期      : {validity_years} 年")
    print("-" * 64)

    # ---- a. 生成 Root CA 密钥对 ----
    print("[1/7] 生成 Root CA 密钥对 (Ed25519) ...")
    root_seed, root_pub = generate_keypair()

    # ---- b. 创建 Root CA 证书（自签名）----
    print("[2/7] 创建 Root CA 证书（自签名）...")
    root_cert, root_tbs = build_root_ca(
        seed=root_seed,
        pub=root_pub,
        ca_name=ca_name,
        ca_email=ca_email,
        sn=root_sn,
        validity_years=validity_years,
    )

    # ---- c. 生成 Intermediate CA 密钥对 ----
    print("[3/7] 生成 Intermediate CA 密钥对 (Ed25519) ...")
    int_seed, int_pub = generate_keypair()

    # ---- d. 创建 Intermediate CA 证书（由 Root CA 签发）----
    print("[4/7] 创建 Intermediate CA 证书（由 Root CA 签发）...")
    int_cert, int_tbs = build_intermediate_ca(
        seed=int_seed,
        pub=int_pub,
        root_cert=root_cert,
        root_seed=root_seed,
        ca_name=ca_name,
        ca_email=ca_email,
        sn=int_sn,
        validity_years=validity_years,
        uid_start=uid_start,
        uid_end=uid_end,
        issuing_countries=issuing_countries,
    )

    # ---- e. 生成 User 密钥对 ----
    print("[5/7] 生成 User 密钥对 (Ed25519) ...")
    user_seed, user_pub = generate_keypair()

    # ---- f. 创建 User Cert（由 Intermediate CA 签发）----
    print("[6/7] 创建 User Cert（由 Intermediate CA 签发）...")
    user_cert, user_tbs = build_user_cert(
        seed=user_seed,
        pub=user_pub,
        int_cert=int_cert,
        int_seed=int_seed,
        callsign=callsign,
        uid=uid,
        validity_years=validity_years,
    )

    # ---- g. Device Key ----
    device_key = build_device_key(user_seed, user_pub)

    # ---- 服务器指纹（User Cert 指纹）----
    server_fp_bytes = cert_fingerprint(user_tbs)
    server_fp_b64url = b64url_encode(server_fp_bytes)
    server_fp_hex = server_fp_bytes.hex()

    # ---- 验证签名链 ----
    print("-" * 64)
    print("验证证书链签名 ...")
    issues = verify_chain(root_cert, int_cert, user_cert, root_pub, int_pub, user_pub)
    if issues:
        print("  [警告] 签名链存在问题:")
        for i in issues:
            print(f"    - {i}")
    else:
        print("  [OK] 证书链签名全部验证通过")

    # ---- 校验 devicekey 与 user cert 公钥配套 ----
    derived_pub = pubkey_from_seed(user_seed)
    if derived_pub == user_pub:
        print("  [OK] DeviceKey 私钥与 User Cert 公钥配套一致")
    else:
        print("  [警告] DeviceKey 私钥推导的公钥与 User Cert 公钥不匹配")

    # ---- 写入文件 ----
    print("-" * 64)
    print("写入文件 ...")
    p_root = os.path.join(output_dir, "cert_root.json")
    p_int = os.path.join(output_dir, "cert_int.json")
    p_user = os.path.join(output_dir, "cert_user.json")
    p_dev = os.path.join(output_dir, "cert_devicekey.json")
    p_fp = os.path.join(output_dir, "server_fingerprint.txt")

    write_json(p_root, root_cert)
    write_json(p_int, int_cert)
    write_json(p_user, user_cert)
    write_json(p_dev, device_key)

    # server_fingerprint.txt: 同时写 base64url 和 hex，便于对照
    fp_text = (
        f"# FMO 服务器指纹（User Cert fingerprint = SHA256(CBOR(tbs))）\n"
        f"# 用户: {callsign} (UID={uid})  CA: {ca_name}\n"
        f"# 生成时间: {ts_to_str(now_ts())}\n"
        f"base64url={server_fp_b64url}\n"
        f"hex={server_fp_hex}\n"
    )
    write_text(p_fp, fp_text)

    print(f"  -> {p_root}")
    print(f"  -> {p_int}")
    print(f"  -> {p_user}")
    print(f"  -> {p_dev}")
    print(f"  -> {p_fp}")

    # ---- 摘要 ----
    print("=" * 64)
    print("生成完成！摘要:")
    print(f"  Root CA  : sn={root_cert['sn']}  pub={root_cert['subject']['publicKey']}")
    print(f"             有效期 {ts_to_str(root_cert['iat'])} ~ {ts_to_str(root_cert['exp'])}")
    print(f"  Int  CA  : sn={int_cert['sn']}  pub={int_cert['subject']['publicKey']}")
    print(f"             有效期 {ts_to_str(int_cert['iat'])} ~ {ts_to_str(int_cert['exp'])}")
    print(f"  User Cert: callsign={user_cert['subject']['callsign']}  uid={user_cert['subject']['uid']}")
    print(f"             pub={user_cert['subject']['publicKey']}")
    print(f"             有效期 {ts_to_str(user_cert['iat'])} ~ {ts_to_str(user_cert['exp'])}")
    print(f"  DeviceKey: seed={device_key['seed'][:16]}...  pubKey={device_key['pubKey'][:16]}...")
    print(f"  服务器指纹(base64url): {server_fp_b64url}")
    print(f"  服务器指纹(hex)      : {server_fp_hex}")
    print("=" * 64)

    return {
        "files": {
            "root": p_root,
            "int": p_int,
            "user": p_user,
            "devicekey": p_dev,
            "fingerprint": p_fp,
        },
        "fingerprint_b64url": server_fp_b64url,
        "fingerprint_hex": server_fp_hex,
        "root_pubkey": root_cert["subject"]["publicKey"],
        "int_pubkey": int_cert["subject"]["publicKey"],
        "user_pubkey": user_cert["subject"]["publicKey"],
        "issues": issues,
    }


# ============================================================
#  命令行入口
# ============================================================

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="FMO 证书生成工具（Ed25519 证书链: Root CA -> Int CA -> User Cert -> Device Key）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  python cert_gen.py --callsign BH6BHG --uid 1075 --ca-name MYCA --output ./certs
  python cert_gen.py --callsign TEST --uid 1001 --output ./test_certs
""",
    )
    parser.add_argument("--callsign", required=True, help="用户呼号（如 BH6BHG）")
    parser.add_argument("--uid", required=True, type=int, help="用户 UID（如 1075）")
    parser.add_argument("--ca-name", default="MYCA", help="CA 名称（默认 MYCA）")
    parser.add_argument("--ca-email", default="", help="CA 邮箱（可选）")
    parser.add_argument("--output", default=".", help="输出目录（默认当前目录）")
    parser.add_argument("--root-sn", type=int, default=1, help="Root CA 序列号（默认 1）")
    parser.add_argument("--int-sn", type=int, default=1001, help="Intermediate CA 序列号（默认 1001）")
    parser.add_argument("--validity-years", type=int, default=10, help="证书有效期（年，默认 10）")
    parser.add_argument("--uid-start", type=int, default=1, help="Intermediate CA UID 范围起始（默认 1）")
    parser.add_argument("--uid-end", type=int, default=200000, help="Intermediate CA UID 范围结束（默认 200000）")
    parser.add_argument(
        "--countries",
        nargs="+",
        default=["CN"],
        help="Intermediate CA 可签发国家（默认 CN）",
    )

    args = parser.parse_args(argv)

    # 基本校验
    if not args.callsign or not args.callsign.strip():
        print("错误: 呼号不能为空", file=sys.stderr)
        return 2
    if args.uid <= 0:
        print("错误: UID 必须为正整数", file=sys.stderr)
        return 2
    if args.validity_years <= 0:
        print("错误: 有效期必须为正整数", file=sys.stderr)
        return 2

    try:
        result = generate_all(
            callsign=args.callsign.strip(),
            uid=args.uid,
            ca_name=args.ca_name,
            ca_email=args.ca_email,
            output_dir=args.output,
            root_sn=args.root_sn,
            int_sn=args.int_sn,
            validity_years=args.validity_years,
            uid_start=args.uid_start,
            uid_end=args.uid_end,
            issuing_countries=args.countries,
        )
    except Exception as e:
        print(f"错误: 生成证书失败: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    if result["issues"]:
        for issue in result["issues"]:
            print(f"警告: {issue}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())