#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fus-set-appkey —— 写入 APP 签名密钥（Ed25519 公钥）
====================================================
专门用来把 APP 的**验签公钥**写进服务端 config.json 的 `dmrid.app_pubkey`。
给"装了本系统、但没部署 APP 密钥对"的人用：跑一条命令即可，不需要知道内部结构。

服务端只需要**公钥**（用来验签）；私钥(seed)只存在于 APP 里，服务端不需要、
本命令默认也不会保存它。

用法
----
    # 1) 最常用：写入官方 APP 公钥（本命令内置，无需任何参数）
    sudo fus-set-appkey

    # 2) 看当前配置
    fus-set-appkey --show

    # 3) 校验当前配置是不是官方公钥
    fus-set-appkey --verify

    # 4) 写入你自己的公钥（自己编译 APP 的情况）
    sudo fus-set-appkey --pubkey <base64url 或 hex>

    # 5) 你只有 APP 的私钥 seed，没有公钥：由 seed 推导并写入
    sudo fus-set-appkey --seed <base64url>
    #    想连 seed 一起存进 config（一般不需要，且会明文落盘）：
    sudo fus-set-appkey --seed <base64url> --store-seed

    # 6) 保留已有公钥、再追加一个（支持一把公钥换 APP 时平滑过渡）
    sudo fus-set-appkey --pubkey <base64url> --append

    # 7) 只看会改什么，不落盘
    sudo fus-set-appkey --dry-run

其他选项
--------
    --config PATH   指定 config.json（默认自动定位）
    --json          以 JSON 输出结果（给脚本调用）
    --restart       写完后自动 systemctl restart fmo-subsystem
    -h, --help      帮助

退出码：0 成功 / 1 出错 / 2 用法错误
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time

# ---------------------------------------------------------------- 常量
# 官方 APP 验签公钥（Ed25519，base64url）。这是**公开**信息，写死在服务端没问题。
# 对应的私钥 seed 只存在于 APP 内部，不在这里、也不在任何发行包中。
#   原始公钥 hex: e0b2f692b5ce16f56216f6dd3f7a6f4c92b6a595cc21135643a9f3f23a7982bd
#   SPKI hex    : 302a300506032b6570032100e0b2f692b5ce16f56216f6dd3f7a6f4c92b6a595cc21135643a9f3f23a7982bd
OFFICIAL_APP_PUBKEY = "4LL2krXOFvViFvbdP3pvTJK2pZXMIRNWQ6nz8jp5gr0"
OFFICIAL_APP_PUBKEY_HEX = ("e0b2f692b5ce16f56216f6dd3f7a6f4c92b6a595cc21"
                           "135643a9f3f23a7982bd")

SERVICE = "fmo-subsystem"
CONFIG_CANDIDATES = [
    "/opt/fmo-subsystem/config.json",
    "/opt/fmo-subsystem/config.default.json",
]

# ---------------------------------------------------------------- 小工具


def b64url_decode(s):
    s = str(s).strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def looks_like_hex(s):
    s = str(s or "").strip()
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def norm_pubkey(val):
    """
    把用户给的公钥（base64url 或 64 位 hex）统一成 base64url。
    返回 (b64url, 错误信息)。公钥必须是 32 字节。
    """
    s = str(val or "").strip()
    if not s:
        return "", "公钥为空"
    if looks_like_hex(s):
        raw = bytes.fromhex(s)
    else:
        try:
            raw = b64url_decode(s)
        except Exception:  # noqa: BLE001
            return "", "公钥不是合法的 base64url / hex：%s" % s[:24]
    if len(raw) != 32:
        return "", "公钥长度必须是 32 字节（现在是 %d 字节）" % len(raw)
    return b64url_encode(raw), ""


def seed_to_pubkey(seed_b64):
    """由 APP 私钥 seed（base64url，32B）推导公钥。返回 (b64url, 错误信息)。"""
    try:
        seed = b64url_decode(seed_b64)
    except Exception:  # noqa: BLE001
        return "", "seed 不是合法的 base64url"
    if len(seed) != 32:
        return "", "seed 长度必须是 32 字节（现在是 %d 字节）" % len(seed)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
    except ImportError:
        return "", ("推导 seed 需要 python cryptography 库（未安装）。"
                    "可直接改用 --pubkey 指定公钥。")
    raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return b64url_encode(raw), ""


def find_config(explicit=None):
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("FMO_CONFIG")
    if env:
        return os.path.abspath(env)
    for p in CONFIG_CANDIDATES:
        if os.path.isfile(p):
            return p
    # 脚本所在目录（源码直跑 / 解包目录）
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("config.json", "config.default.json"):
        p = os.path.join(here, name)
        if os.path.isfile(p):
            return p
    return CONFIG_CANDIDATES[0]


def load_config(path):
    if not os.path.isfile(path):
        return {}, False
    with open(path, "rb") as f:
        raw = f.read()
    if not raw.strip():
        return {}, True
    # 兼容 BOM
    text = raw.decode("utf-8-sig")
    return json.loads(text), True


def atomic_write_json(path, data, orig_mode=None):
    """先备份、再原子替换，尽量保留原权限与换行风格。"""
    tmp = path + ".tmp-%d" % os.getpid()
    body = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    try:
        if orig_mode is not None:
            os.chmod(tmp, orig_mode & 0o777)
    except Exception:  # noqa: BLE001
        pass
    os.replace(tmp, path)


def service_active():
    try:
        r = subprocess.run(["systemctl", "is-active", SERVICE],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=8)
        return r.returncode == 0 and r.stdout.decode().strip() == "active"
    except Exception:  # noqa: BLE001
        return False


def restart_service():
    try:
        r = subprocess.run(["systemctl", "restart", SERVICE],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=90)
        return r.returncode == 0, r.stdout.decode("utf-8", "replace").strip()
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def emit(args, payload, text_lines):
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for line in text_lines:
            print(line)


# ---------------------------------------------------------------- 主流程


def cmd_show(args, path, cfg):
    dm = cfg.get("dmrid") or {}
    cur = dm.get("app_pubkey")
    keys = cur if isinstance(cur, list) else ([cur] if cur else [])
    lines = ["配置文件: %s" % path,
             "dmrid.app_pubkey: %s" % (json.dumps(cur, ensure_ascii=False)
                                       if cur is not None else "(未设置)")]
    if keys:
        for i, k in enumerate(keys):
            tag = "官方公钥 ✓" if str(k).strip() == OFFICIAL_APP_PUBKEY else "非官方"
            lines.append("  [%d] %s   %s" % (i, k, tag))
    else:
        lines.append("  ⚠ 未配置：生产环境下 APP 绑定会被拒绝（fail-closed）。")
        lines.append("    执行 `sudo fus-set-appkey` 写入官方公钥即可。")
    if dm.get("app_seed"):
        lines.append("dmrid.app_seed: (已保存，长度 %d)" % len(str(dm.get("app_seed"))))
    lines.append("dmrid.enabled: %s" % dm.get("enabled", False))
    emit(args, {"ok": True, "config": path, "app_pubkey": cur,
                "official": OFFICIAL_APP_PUBKEY,
                "is_official": bool(keys) and all(
                    str(k).strip() == OFFICIAL_APP_PUBKEY for k in keys),
                "app_seed_saved": bool(dm.get("app_seed"))}, lines)
    return 0


def cmd_verify(args, path, cfg):
    dm = cfg.get("dmrid") or {}
    cur = dm.get("app_pubkey")
    keys = cur if isinstance(cur, list) else ([cur] if cur else [])
    keys = [str(k).strip() for k in keys if str(k).strip()]
    has_official = OFFICIAL_APP_PUBKEY in keys
    problems = []
    if not keys:
        problems.append("未配置任何 APP 公钥 → 生产环境 APP 绑定会被拒绝")
    elif not has_official:
        problems.append("当前公钥里没有官方公钥：%s" % OFFICIAL_APP_PUBKEY)
    # 若传了 seed，顺便校验 seed 与配置的公钥是否是同一对
    seed_note = ""
    if args.seed:
        derived, err = seed_to_pubkey(args.seed)
        if err:
            problems.append("seed 校验失败：%s" % err)
        else:
            seed_note = "seed 推导出的公钥: %s" % derived
            if derived not in keys:
                problems.append("seed 推导出的公钥 %s 不在配置里（seed 与配置不配对）"
                                % derived)
            else:
                seed_note += "  → 与配置一致 ✓"
    lines = ["配置文件: %s" % path,
             "官方公钥: %s" % OFFICIAL_APP_PUBKEY,
             "当前公钥: %s" % (", ".join(keys) if keys else "(无)")]
    if seed_note:
        lines.append(seed_note)
    if problems:
        lines.append("")
        for p in problems:
            lines.append("✗ %s" % p)
        emit(args, {"ok": False, "config": path, "keys": keys,
                    "has_official": has_official, "problems": problems},
             lines)
        return 1
    lines.append("")
    lines.append("✓ 配置正确：服务端会用该公钥校验 APP 签名")
    emit(args, {"ok": True, "config": path, "keys": keys,
                "has_official": has_official, "problems": []}, lines)
    return 0


def normalize_argv(argv):
    """
    base64url 可能以 '-' 开头（例如官方 seed 就是 "-zbIIPI-..."），
    argparse 会把它当成选项名而报 "expected one argument"。
    这里把 `--seed -xxx` / `--pubkey -xxx` 预先合并成 `--seed=-xxx`。
    """
    out = []
    i = 0
    val_opts = ("--seed", "--pubkey", "--config")
    while i < len(argv):
        a = argv[i]
        if a in val_opts and i + 1 < len(argv):
            nxt = argv[i + 1]
            if nxt.startswith("-") and not nxt.startswith("--") and len(nxt) > 1:
                out.append("%s=%s" % (a, nxt))
                i += 2
                continue
        out.append(a)
        i += 1
    return out


def main(argv=None):
    argv = normalize_argv(list(sys.argv[1:] if argv is None else argv))
    ap = argparse.ArgumentParser(
        prog="fus-set-appkey",
        description="写入 APP 签名密钥（Ed25519 公钥）到服务端 config.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="不带任何参数时：写入官方 APP 公钥。")
    ap.add_argument("--pubkey", help="要写入的 APP 公钥（base64url 或 64 位 hex）")
    ap.add_argument("--seed", help="APP 私钥 seed（base64url，32B），由它推导公钥")
    ap.add_argument("--store-seed", action="store_true",
                    help="把 seed 也写进 config（一般不需要；会明文落盘）")
    ap.add_argument("--append", action="store_true",
                    help="保留已有公钥并追加（用于换 APP 时平滑过渡）")
    ap.add_argument("--show", action="store_true", help="显示当前配置")
    ap.add_argument("--verify", action="store_true", help="校验当前配置")
    ap.add_argument("--config", help="指定 config.json 路径")
    ap.add_argument("--dry-run", action="store_true", help="只显示改动，不写盘")
    ap.add_argument("--restart", action="store_true",
                    help="写完后自动重启 %s 服务" % SERVICE)
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args(argv)

    path = find_config(args.config)
    try:
        cfg, existed = load_config(path)
    except Exception as e:  # noqa: BLE001
        print("✗ 读取配置失败 %s: %s" % (path, e), file=sys.stderr)
        return 1

    # --show / --verify 只读
    if args.show:
        return cmd_show(args, path, cfg)
    if args.verify:
        return cmd_verify(args, path, cfg)

    # ---- 计算要写入的公钥 ----
    want = ""
    source = ""
    if args.pubkey:
        want, err = norm_pubkey(args.pubkey)
        if err:
            print("✗ %s" % err, file=sys.stderr)
            return 2
        source = "--pubkey"
    elif args.seed:
        want, err = seed_to_pubkey(args.seed)
        if err:
            print("✗ %s" % err, file=sys.stderr)
            return 2
        source = "--seed 推导"
    else:
        want = OFFICIAL_APP_PUBKEY
        source = "官方公钥（默认）"

    if not existed:
        # 配置不存在：给出一个最小可用结构，避免写出半截文件
        cfg = {}

    dm = cfg.get("dmrid")
    if not isinstance(dm, dict):
        dm = {}
    old = dm.get("app_pubkey")
    old_keys = old if isinstance(old, list) else ([old] if old else [])
    old_keys = [str(k).strip() for k in old_keys if str(k).strip()]

    if args.append and old_keys:
        if want in old_keys:
            new_keys = old_keys
            changed = False
        else:
            new_keys = old_keys + [want]
            changed = True
    else:
        new_keys = [want]
        changed = (old_keys != [want])

    dm["app_pubkey"] = new_keys[0] if len(new_keys) == 1 else new_keys
    if args.store_seed and args.seed:
        dm["app_seed"] = str(args.seed).strip()
    cfg["dmrid"] = dm

    payload = {
        "ok": True,
        "config": path,
        "source": source,
        "app_pubkey": dm["app_pubkey"],
        "previous": old if old is not None else None,
        "changed": changed,
        "is_official": want == OFFICIAL_APP_PUBKEY,
        "dry_run": bool(args.dry_run),
        "app_seed_saved": bool(dm.get("app_seed")),
    }

    lines = ["配置文件: %s" % path,
             "公钥来源: %s" % source,
             "公钥: %s%s" % (want, "   (官方公钥)" if want == OFFICIAL_APP_PUBKEY else ""),
             "之前: %s" % (json.dumps(old, ensure_ascii=False) if old else "(未设置)")]

    if args.dry_run:
        lines.append("")
        lines.append("--dry-run：未写入任何内容")
        emit(args, payload, lines)
        return 0

    # ---- 落盘（备份 + 原子替换 + 保留权限）----
    try:
        mode = os.stat(path).st_mode & 0o777 if existed else 0o600
    except Exception:  # noqa: BLE001
        mode = 0o600
    backup = ""
    if existed and changed:
        backup = "%s.bak-appkey-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        try:
            shutil.copy2(path, backup)
        except Exception as e:  # noqa: BLE001
            print("✗ 备份失败，已中止（不冒险覆盖）: %s" % e, file=sys.stderr)
            return 1
    try:
        if not os.path.isdir(os.path.dirname(path) or "."):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        atomic_write_json(path, cfg, mode)
    except PermissionError:
        print("✗ 没有写权限：%s\n  请用 sudo 运行（sudo fus-set-appkey）" % path,
              file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print("✗ 写入失败: %s" % e, file=sys.stderr)
        return 1

    payload["backup"] = backup
    lines.append("")
    if changed:
        lines.append("✓ 已写入%s" % ("（备份: %s）" % backup if backup else ""))
    else:
        lines.append("✓ 配置本来就是目标值，无需改动")

    # ---- 需要重启才生效 ----
    active = service_active()
    restarted = None
    if args.restart:
        if active:
            ok, out = restart_service()
            restarted = ok
            lines.append("✓ 已重启 %s" % SERVICE if ok
                         else "✗ 重启失败: %s" % out)
        else:
            lines.append("· %s 当前未运行，跳过重启" % SERVICE)
    elif active:
        lines.append("")
        lines.append("⚠ 配置已改，但服务还在用旧配置。立即生效请执行：")
        lines.append("     sudo systemctl restart %s" % SERVICE)
        lines.append("  （或下次运行本命令时加 --restart）")

    payload["service_was_active"] = active
    payload["restarted"] = restarted
    emit(args, payload, lines)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
