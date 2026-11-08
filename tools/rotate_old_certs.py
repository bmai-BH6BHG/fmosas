#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
旧 CA 证书审计 / 批量重签工具（强制换证 C 方案的配套工具）

用途：
  1. audit   列出本机所有证书按 CA 代际分组（新 CA / 旧 CA），指出谁需要换证
  2. reissue 给指定用户（或全部旧 CA 用户）用**新 CA**重新签发，并打印结果

背景：
  本机 CA 已从 sn=1/1001（撞官方号段）换成 sn=900000001/900001001。
  旧证书仍能登录（trust.extraRootPubkeys 白名单），但要让它们真正作废，
  需要：① 用户换新证 → ② 设置 trust.legacyRootGraceUntil 为过去时间。

用法：
  python3 tools/rotate_old_certs.py audit
  python3 tools/rotate_old_certs.py audit --json
  python3 tools/rotate_old_certs.py reissue --callsign BH6BHG
  python3 tools/rotate_old_certs.py reissue --all-old --yes

注意：
  - reissue 会**新增**一张证书记录，不删除旧记录（旧证书一旦被吊销会影响
    正在用的用户；由白名单/宽限期统一控制失效更安全）。
  - 执行前请确认已备份 sas.db。
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("FMO_SUBSYS", "/opt/fmo-subsystem")
sys.path.insert(0, BASE)
sys.path.insert(0, HERE)


def _load():
    import sas_server as S
    cfg = {}
    try:
        with open(os.path.join(BASE, "config.json"), "r", encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except Exception:  # noqa: BLE001
        pass
    sid = str(cfg.get("subsystem_id") or "").strip()
    db_name = ("%s_sas.db" % sid) if sid else "sas.db"
    db_path = os.path.join(BASE, db_name)
    if not os.path.exists(db_path):
        for fn in sorted(os.listdir(BASE)):
            if fn.endswith("_sas.db"):
                db_path = os.path.join(BASE, fn)
                break
    db = S.Database(db_path)
    mgr = S.CaManager(os.path.join(BASE, "ca"), db,
                      ca_name=str(cfg.get("sas_ca_name") or "MYCA"),
                      ca_email="", validity_years=10,
                      uid_start=1, uid_end=200000,
                      issuing_countries=["CN"])
    mgr.init(force=False)
    return S, mgr, db, cfg, db_path


def _cert_generation(cert_json, root_pub, int_sn):
    """判断一张证书属于新 CA 还是旧 CA。"""
    try:
        c = json.loads(cert_json) if isinstance(cert_json, str) else (cert_json or {})
    except Exception:  # noqa: BLE001
        return "unknown"
    if str(c.get("issuerSn")) == str(int_sn):
        return "new"
    return "old"


def cmd_audit(as_json=False):
    import sqlite3
    S, mgr, db, cfg, db_path = _load()
    int_sn = mgr.int_cert["sn"] if mgr.int_cert else "?"
    root_pub = (mgr.root_cert or {}).get("subject", {}).get("publicKey", "")

    rows = []
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        cur = conn.execute(
            "SELECT id, callsign, uid, cert_user_json, fingerprint, issued_at, revoked "
            "FROM certificates ORDER BY callsign, issued_at DESC")
        for r in cur:
            gen = _cert_generation(r[3], root_pub, int_sn)
            rows.append({
                "id": r[0], "callsign": r[1], "uid": r[2],
                "fingerprint": r[4], "issued_at": r[5],
                "issued": time.strftime("%Y-%m-%d %H:%M",
                                        time.localtime(r[5] or 0)),
                "revoked": bool(r[6]), "generation": gen,
            })
    finally:
        conn.close()

    # 每个呼号的最新证书代际 = 该用户当前实际在用的代际
    latest = {}
    for x in rows:
        cs = x["callsign"]
        if cs not in latest or (x["issued_at"] or 0) > (latest[cs]["issued_at"] or 0):
            latest[cs] = x

    by_gen = {"new": [], "old": [], "unknown": []}
    for x in rows:
        by_gen[x["generation"]].append(x)

    need_rotate = sorted(cs for cs, x in latest.items()
                         if x["generation"] != "new" and not x["revoked"])

    out = {
        "ca": {"root_sn": (mgr.root_cert or {}).get("sn"),
               "int_sn": int_sn,
               "root_pubkey": root_pub},
        "counts": {
            "certs_total": len(rows),
            "certs_new_ca": len(by_gen["new"]),
            "certs_old_ca": len(by_gen["old"]),
            "certs_unknown": len(by_gen["unknown"]),
            "users_total": len(latest),
            "users_need_rotate": len(need_rotate),
        },
        "need_rotate": need_rotate,
        "latest_by_user": {cs: {"callsign": cs, "uid": x["uid"],
                                "generation": x["generation"],
                                "issued": x["issued"],
                                "fingerprint": x["fingerprint"]}
                           for cs, x in sorted(latest.items())},
    }
    if as_json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return out

    c = out["counts"]
    print("=" * 66)
    print(" 旧 CA 证书审计")
    print("=" * 66)
    print("  当前 CA : root sn=%s  int sn=%s" % (out["ca"]["root_sn"], out["ca"]["int_sn"]))
    print("  证书总数: %d   （新 CA %d / 旧 CA %d / 未知 %d）"
          % (c["certs_total"], c["certs_new_ca"], c["certs_old_ca"], c["certs_unknown"]))
    print("  涉及用户: %d   （需要换证 %d）" % (c["users_total"], c["users_need_rotate"]))
    print("-" * 66)
    if need_rotate:
        print("  需要换证的用户（仍在用旧 CA 证书）：")
        for cs in need_rotate:
            x = out["latest_by_user"][cs]
            print("    %-10s uid=%-7s 签发于 %s" % (cs, x["uid"], x["issued"]))
        print()
        print("  换证：python3 %s reissue --all-old --yes" % os.path.basename(__file__))
    else:
        print("  ✓ 所有用户的当前证书都已由新 CA 签发")
    print("=" * 66)
    return out


def cmd_reissue(callsigns, do_all_old, yes):
    import sqlite3
    S, mgr, db, cfg, db_path = _load()
    int_sn = mgr.int_cert["sn"]

    if do_all_old:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        try:
            cur = conn.execute(
                "SELECT callsign, uid, cert_user_json, issued_at FROM certificates "
                "ORDER BY callsign, issued_at DESC")
            latest = {}
            for cs, uid, cj, at in cur:
                if cs not in latest or (at or 0) > (latest[cs][2] or 0):
                    latest[cs] = (cs, uid, at, cj)
        finally:
            conn.close()
        targets = [(cs, v[1]) for cs, v in latest.items()
                   if _cert_generation(v[3], None, int_sn) != "new"]
    else:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
        try:
            targets = []
            for cs in callsigns:
                row = conn.execute(
                    "SELECT callsign, uid FROM certificates WHERE callsign=? "
                    "ORDER BY issued_at DESC LIMIT 1", (cs,)).fetchone()
                if row:
                    targets.append((row[0], row[1]))
                else:
                    print("  [跳过] %s: 库里没有这个呼号的证书" % cs)
        finally:
            conn.close()

    if not targets:
        print("  没有需要换证的用户")
        return

    print("  将用新 CA（int sn=%s）重签 %d 个用户：" % (int_sn, len(targets)))
    for cs, uid in targets:
        print("    %-10s uid=%s" % (cs, uid))
    if not yes:
        ans = input("\n  确认执行？(yes/NO) ").strip().lower()
        if ans != "yes":
            print("  已取消")
            return

    ok = fail = 0
    for cs, uid in targets:
        try:
            certs = mgr.issue_user_cert(cs, int(uid))
            db.add_certificate(cs, int(uid),
                               json.dumps(certs["user_cert"], ensure_ascii=False),
                               json.dumps(certs["device_key"], ensure_ascii=False),
                               certs["fingerprint"])
            print("  ✓ %-10s 新指纹 %s" % (cs, certs["fingerprint"][:24]))
            ok += 1
        except Exception as e:  # noqa: BLE001
            print("  ✗ %-10s 失败: %s" % (cs, e))
            fail += 1
    print()
    print("  完成：成功 %d，失败 %d" % (ok, fail))
    print()
    print("  ⚠ 重签只是给用户一张新证书；要让旧证书彻底失效，还需：")
    print("     把 config.json 的 trust.legacyRootGraceUntil 设成一个过去的时间戳，")
    print("     然后重启 fmo-subsystem。")


def main():
    ap = argparse.ArgumentParser(description="旧 CA 证书审计 / 批量重签")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="审计证书代际")
    a.add_argument("--json", action="store_true", help="输出 JSON")

    r = sub.add_parser("reissue", help="用新 CA 重签")
    r.add_argument("--callsign", action="append", default=[],
                   help="指定呼号（可重复）")
    r.add_argument("--all-old", action="store_true", help="重签所有仍用旧证书的用户")
    r.add_argument("--yes", action="store_true", help="跳过确认")

    args = ap.parse_args()
    if args.cmd == "audit":
        cmd_audit(as_json=args.json)
    elif args.cmd == "reissue":
        if not args.all_old and not args.callsign:
            print("请指定 --callsign XXX 或 --all-old")
            sys.exit(2)
        cmd_reissue([x.strip().upper() for x in args.callsign],
                    args.all_old, args.yes)


if __name__ == "__main__":
    main()
