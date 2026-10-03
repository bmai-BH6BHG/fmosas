#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · EMQX 身份链路诊断（client_attrs 为什么没下发）
====================================================
症状：审计日志反复出现
  "连接无身份属性，无法比对，仅留证（连续 N 次，疑似 EMQX 未把 SAS 的 client_attrs 下发到连接）"

根因只有三类，本工具逐项判定并给出可执行的修法：

  A. EMQX 版本 < 5.7.0
     client_attrs 是 EMQX 5.7.0 才支持的响应字段（acl 需 5.8.0）。低于此版本，
     SAS 返回的 client_attrs 会被直接忽略 → 连接永远没有身份属性。

  B. EMQX 的 HTTP 认证**请求**没带 username/password
     SAS 需要 username（明文呼号）与 password（base64url 的证书包）才能验签并算出身份。
     若认证器 body 模板里少了这两个字段（或模板键名不是 username/password），
     SAS 会返回 deny 或空身份 → client_attrs 缺失。

  C. 连接走的是**别的认证器**（不是指向本服务的 HTTP 认证）
     例如还留着旧的 built_in_database / JWT / 指向老端口的 HTTP 认证，或认证器
     绑在别的监听器上。此时请求根本没到 SAS。

附带检查：
  D. SAS 的 /auth 是否可达、是否在公网口白名单里（EMQX 必须能 POST 到它）
  E. /auth 对空请求的响应形状（deny 时应带 reason，便于判断是"缺字段"还是"验签失败"）
  F. 审计库里最近的身份审计事件分布（验证症状确实来自 client_attrs 缺失）

用法：
  python3 bas_emqx_auth.py --diagnose                  # 用审计库里的 EMQX 配置自动诊断
  python3 bas_emqx_auth.py --diagnose --emqx-url http://127.0.0.1:18083 \
        --key KEY --secret SECRET --sas-url http://127.0.0.1:35928/auth
退出码：0 = 链路正常；1 = 发现问题（详见输出）
"""

import json
import os
import sys

import bas_emqx_auth as ea
from bas_emqx import EmqxClient, EmqxError


def _load_emqx_cfg_from_db(base_dir):
    """从审计库读 EMQX 配置（诊断默认走这条）。"""
    import glob
    import sqlite3
    dbs = glob.glob(os.path.join(base_dir, "*_audit.db"))
    if not dbs:
        return {}
    conn = None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % dbs[0].replace("?", "%3f"),
                               uri=True, timeout=3.0)
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        cfg = {k: v for k, v in rows}
        return {"url": cfg.get("emqx_url", ""), "key": cfg.get("emqx_api_key", ""),
                "secret": cfg.get("emqx_api_secret", ""), "topic": cfg.get("topic_name", "")}
    except Exception:  # noqa: BLE001
        return {}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _http_post_json(url, payload, timeout=8):
    """向 SAS /auth 发一次真实 POST，返回 (status, body_text)。"""
    import urllib.error
    import urllib.request
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, "连接失败: %s" % e


def _supports_client_attrs(version):
    """client_attrs 需要 EMQX >= 5.7.0；acl 需要 >= 5.8.0。"""
    try:
        parts = [int(x) for x in str(version).split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        major, minor, _patch = parts
    except Exception:  # noqa: BLE001
        return None, None
    return (major, minor) >= (5, 7), (major, minor) >= (5, 8)


def diagnose(emqx_url="", key="", secret="", sas_url="", base_dir=".",
             audit_db=None, log=print):
    """
    返回 {"ok":bool, "findings":[{level,code,title,detail,fix}], "facts":{...}}
    level: fatal(必须修) / warn(应修) / info
    """
    findings = []
    facts = {}

    def add(level, code, title, detail="", fix=""):
        findings.append({"level": level, "code": code, "title": title,
                         "detail": detail, "fix": fix})

    # ---------- 0) SAS /auth 基本可达性 ----------
    if sas_url:
        facts["sas_url"] = sas_url
        st, body = _http_post_json(sas_url, {})
        facts["sas_empty_probe"] = {"status": st, "body": body[:300]}
        if st == 0:
            add("fatal", "SAS_UNREACHABLE", "SAS /auth 连不上",
                "POST %s → %s" % (sas_url, body),
                "确认分系统在跑（systemctl status fmo-subsystem）且监听地址正确；"
                "EMQX 认证 URL 必须指向**公网 API 端口**（默认 35928），不是管理口 35929。")
        elif st == 403:
            add("fatal", "SAS_FORBIDDEN", "SAS /auth 被公网白名单拒绝（403）",
                body[:200],
                "EMQX 认证必须访问公网口 35928 的 /auth；若你填的是 35929 管理口会被白名单拦。")
        elif st in (200, 400, 401):
            add("info", "SAS_OK", "SAS /auth 可达", "HTTP %d（空请求返回 deny 属正常）" % st)
    else:
        add("warn", "SAS_URL_MISSING", "未提供 SAS 认证 URL，跳过可达性检查",
            "", "用 --sas-url http://127.0.0.1:35928/auth 指定")

    if not (emqx_url and key and secret):
        add("fatal", "EMQX_CFG_MISSING", "没有 EMQX API 凭据，无法检查认证器",
            "", "在审计界面 → 设置 填 EMQX 地址与 API 密钥；或命令行传 --emqx-url/--key/--secret")
        return {"ok": False, "findings": findings, "facts": facts}

    cli = EmqxClient(emqx_url, key, secret)
    ok, why = cli.ping()
    facts["emqx_url"] = emqx_url
    facts["emqx_reachable"] = ok
    if not ok:
        add("fatal", "EMQX_UNREACHABLE", "EMQX 不可达", why,
            "确认 EMQX 地址（含 http:// 与端口，默认 18083）与网络可达")
        return {"ok": False, "findings": findings, "facts": facts}

    # ---------- A) 版本 ----------
    ver = cli.version()
    facts["emqx_version"] = ver
    ca_ok, acl_ok = _supports_client_attrs(ver)
    if ca_ok is False:
        add("fatal", "EMQX_VER_TOO_OLD",
            "EMQX 版本 %s 低于 5.7.0，不支持 client_attrs" % (ver or "未知"),
            "client_attrs 是 EMQX 5.7.0 引入的认证响应字段；acl 需要 5.8.0。",
            "升级 EMQX 到 5.8+（推荐 5.8 或更新的 5.x）后重试；"
            "在升级前，FAS/BAS 的身份控制拿不到连接身份，只能做统计。")
    elif ca_ok:
        add("info", "EMQX_VER_OK", "EMQX 版本支持 client_attrs",
            "%s（acl 支持: %s）" % (ver, "是" if acl_ok else "否，需 5.8+"))

    # ---------- B) 认证器内容 ----------
    info = ea.inspect(cli)
    facts["authn_items"] = info["items"]
    http_items = [i for i in info["items"] if str(i.get("backend", "")).lower() == "http"]
    facts["http_authn_count"] = len(http_items)
    if not http_items:
        add("fatal", "NO_HTTP_AUTHN", "EMQX 上没有 HTTP 认证器",
            "当前认证链共 %d 项，没有一项是 HTTP 后端" % len(info["items"]),
            "在 EMQX Dashboard → 访问控制 → 认证 里创建：机制=Password-Based、"
            "后端=HTTP Server、URL=http://<本机IP>:35928/auth。"
            "注意要建在「认证」下，不是「授权」。")
    for it in http_items:
        url = str(it.get("url") or "")
        # 请求体是否带 username/password
        post_url = ea.normalize_base_url(emqx_url) if hasattr(ea, "normalize_base_url") else ""
        _ = post_url
        body = None
        try:
            raw = cli._json("GET", "/api/v5/authentication/%s" % it.get("id"), as_text=True)  # noqa: SLF001
            body = json.loads(raw[1]) if raw and raw[1] else None
        except Exception:  # noqa: BLE001
            body = None
        tmpl = (body or {}).get("body") or {}
        method = str((body or {}).get("method") or it.get("method") or "").lower()
        facts.setdefault("authn_detail", []).append(
            {"id": it.get("id"), "url": url, "method": method, "body_keys": sorted(tmpl.keys())})
        if not url.rstrip("/").endswith("/auth"):
            add("warn", "AUTHN_URL_ODD", "HTTP 认证 URL 看起来不是 SAS /auth",
                "认证器 %s 的 url=%s" % (it.get("id"), url),
                "SAS 的认证端点是 /auth（不是 /api/auth、/authn）。")
        if method not in ("post",):
            add("warn", "AUTHN_METHOD", "HTTP 认证方法不是 POST",
                "认证器 %s method=%s" % (it.get("id"), method or "未设置"),
                "SAS 用 POST + JSON body 接收 username/password。")
        if not tmpl:
            add("fatal", "AUTHN_BODY_EMPTY",
                "HTTP 认证器没有请求体模板（username/password 传不过去）",
                "认证器 %s 的 body 为空 → SAS 收到空凭据 → 不可能算出 client_attrs" % it.get("id"),
                "把 body 设为：{\"username\":\"${username}\",\"password\":\"${password}\"}，"
                "Content-Type: application/json。BAS 的「一键接管认证」会自动写成这样。")
        else:
            keys = set(tmpl.keys())
            if not ({"username", "password"} <= keys):
                add("fatal", "AUTHN_BODY_MISSING_FIELDS",
                    "HTTP 认证请求体缺少 username 或 password",
                    "认证器 %s 的 body 键=%s" % (it.get("id"), sorted(keys)),
                    "body 必须是 {\"username\":\"${username}\",\"password\":\"${password}\"}；"
                    "键名只能是 username/password（SAS 按这两个名字取值）。")
            else:
                add("info", "AUTHN_BODY_OK", "HTTP 认证请求体含 username/password",
                    "认证器 %s body 键=%s" % (it.get("id"), sorted(keys)))

    # ---------- C) 是否有"抢跑"的其它认证器 ----------
    others = [i for i in info["items"]
              if str(i.get("backend", "")).lower() != "http"
              and str(i.get("backend", "")).lower() not in ("", "http")]
    facts["other_authn"] = [{"id": i.get("id"), "backend": i.get("backend")} for i in others]
    if others:
        add("warn", "OTHER_AUTHN_PRESENT",
            "认证链里还有其它后端（可能先于 HTTP 认证命中）",
            "其它认证器: %s" % ", ".join("%s(%s)" % (i.get("id"), i.get("backend")) for i in others),
            "EMQX 按顺序尝试认证器；若前面的内置数据库/JWT 先放行，客户端就不会经过 SAS，"
            "自然没有 client_attrs。建议只保留指向 SAS 的 HTTP 认证，或把它排到第一位。")

    # ---------- D) 审计库取证 ----------
    if audit_db and os.path.exists(audit_db):
        try:
            import sqlite3
            conn = sqlite3.connect("file:%s?mode=ro" % audit_db.replace("?", "%3f"),
                                  uri=True, timeout=3.0)
            rows = conn.execute(
                "SELECT scene, COUNT(*) FROM audit_packets "
                "WHERE ts > datetime('now','-1 day','localtime') GROUP BY scene").fetchall()
            recent = conn.execute(
                "SELECT ts, scene, verdict, clientid, reason FROM audit_packets "
                "ORDER BY id DESC LIMIT 5").fetchall()
            conn.close()
            facts["audit_scenes_24h"] = {s: c for s, c in rows}
            facts["audit_recent"] = recent
            miss = sum(c for s, c in rows if s in ("both_missing", "attr_missing"))
            if miss:
                add("fatal", "ATTR_MISSING_CONFIRMED",
                    "审计库里确认有 %d 条「连接无身份」记录" % miss,
                    "近 24 小时场景分布: %s" % (facts["audit_scenes_24h"],),
                    "按上面 A/B/C 的结论修复后，重启 EMQX 连接（客户端重连）才会带上新属性。")
        except Exception as e:  # noqa: BLE001
            add("warn", "AUDIT_DB_READ_FAIL", "审计库读取失败", str(e))

    fails = [f for f in findings if f["level"] == "fatal"]
    return {"ok": not fails, "findings": findings, "facts": facts}


def print_report(r, log=print):
    icons = {"fatal": "✗ 必须修", "warn": "! 建议修", "info": "✓"}
    log("=" * 66)
    log("  BAS 身份链路诊断（client_attrs 下发）")
    log("=" * 66)
    for f in r["findings"]:
        log("")
        log("%s  [%s] %s" % (icons.get(f["level"], "?"), f["code"], f["title"]))
        if f.get("detail"):
            log("     现象: %s" % f["detail"])
        if f.get("fix"):
            log("     修法: %s" % f["fix"])
    log("")
    log("-" * 66)
    log("关键事实:")
    for k in ("emqx_url", "emqx_reachable", "emqx_version", "http_authn_count",
              "authn_detail", "other_authn", "sas_url", "sas_empty_probe",
              "audit_scenes_24h"):
        if k in r["facts"]:
            log("  %-20s %s" % (k, r["facts"][k]))
    log("-" * 66)
    log("结论: %s" % ("链路正常" if r["ok"] else "存在问题，请按上面【修法】处理"))
    return 0 if r["ok"] else 1


def main_diagnose(argv):
    import argparse
    ap = argparse.ArgumentParser(description="BAS 身份链路诊断")
    ap.add_argument("--diagnose", action="store_true")
    ap.add_argument("--emqx-url", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--secret", default="")
    ap.add_argument("--sas-url", default="")
    ap.add_argument("--base-dir", default=".")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    if not (args.emqx_url and args.key and args.secret):
        cfg = _load_emqx_cfg_from_db(args.base_dir)
    emqx_url = args.emqx_url or cfg.get("url", "")
    key = args.key or cfg.get("key", "")
    secret = args.secret or cfg.get("secret", "")
    sas_url = args.sas_url
    if not sas_url:
        # 默认用本机 + 分系统端口
        port = 35928
        cfgfile = os.path.join(args.base_dir, "config.json")
        if os.path.exists(cfgfile):
            try:
                with open(cfgfile, encoding="utf-8-sig") as f:
                    port = int(json.load(f).get("port", 35928))
            except Exception:  # noqa: BLE001
                pass
        sas_url = "http://127.0.0.1:%d/auth" % port
    audit_db = None
    import glob
    dbs = glob.glob(os.path.join(args.base_dir, "*_audit.db"))
    if dbs:
        audit_db = dbs[0]

    r = diagnose(emqx_url, key, secret, sas_url, args.base_dir, audit_db)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2, default=str))
    else:
        print_report(r)
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    if "--diagnose" in sys.argv:
        sys.exit(main_diagnose(sys.argv[1:]))
    sys.exit(ea.main())
