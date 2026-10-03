#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS · MQTT(EMQX) 识别与认证接管
================================
一键安装的这一步负责：**认出本机/指定的 MQTT(EMQX) 服务，把它的客户端认证
指向 BAS 部署的端口（默认 35928 的 /auth），并保留原有其它配置。**

为什么需要它
------------
SAS 是 EMQX 的 HTTP 认证后端：客户端 CONNECT → EMQX 发 HTTP 请求 → SAS 验签 →
返回 {result, client_attrs{callsign,uid}, acl}。认证 URL 若还指向旧地址（旧端口、
旧机器、旧 .NET 服务），新装的 BAS 就收不到认证请求，表现为"谁都连不上"或
"FAS 把所有人拉黑"。因此安装时必须把这条链路指过来。

安全策略（改认证配置是有风险的操作，一旦写坏会导致全部客户端连不上）
--------------------------------------------------------------------
1. 只改"认证(Authentication)"，绝不碰"授权(Authorization)"，也不动监听器/规则引擎。
2. 改动前先把现有认证链**完整导出并落盘备份**，失败可一键回滚（rollback）。
3. 默认 --dry-run：只打印将要做的改动；真正执行需要显式确认。
4. 只删除"看起来就是这个 SAS 认证"的项：type=http 且（URL 命中已知端口/路径，
   或--force-all 时是唯一的 http 认证项）。其它认证后端一律不碰。
5. 幂等：如果已经指向目标 URL，则什么都不做。

EMQX 接口（5.x）
----------------
列出：GET  /api/v5/authentication                       （全局认证链）
     GET  /api/v5/listeners                             （取监听器 id）
     GET  /api/v5/listeners/{id}/authentication         （监听器级认证链）
新建：POST /api/v5/authentication                        （body 带 listener_id 时绑到该监听器）
删除：DELETE /api/v5/authentication/{id}
备份写在审计库里，同时打印回滚命令。
"""

import json
import os
import socket
import time

import bas_emqx
from bas_emqx import EmqxClient, EmqxError, normalize_base_url

# 常见 EMQX 端口：MQTT 1883 / MQTTS 8883 / WS 8083 / Dashboard 18083
DEFAULT_MQTT_PORTS = (1883, 8883, 8083, 8084, 18083)
AUTHN_PATH_HINTS = ("/auth", "/api/auth", "/authn", "/mqtt/auth")
# 认为"这就是旧 SAS"的端口线索
SAS_PORT_HINTS = (35928, 8080, 18083)


def detect_mqtt(host="127.0.0.1", ports=None, timeout=0.6):
    """
    探测本机（或指定主机）是否有 EMQX 在跑。返回：
      {"found":bool, "host":..., "open_ports":[...], "mqtt":port|None,
       "dashboard":port|None, "note":...}
    """
    ports = list(ports or DEFAULT_MQTT_PORTS)
    open_ports = []
    for p in ports:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
        except Exception:  # noqa: BLE001
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
    mqtt = 1883 if 1883 in open_ports else (8883 if 8883 in open_ports else None)
    dashboard = 18083 if 18083 in open_ports else None
    note = ""
    if not open_ports:
        note = "未在本机发现 EMQX 常用端口（1883/8883/8083/18083）"
    elif not dashboard:
        note = "发现 MQTT 端口但没发现 Dashboard(18083)；若 Dashboard 在别的端口/机器，请手动填地址"
    return {"found": bool(open_ports), "host": host, "open_ports": open_ports,
            "mqtt": mqtt, "dashboard": dashboard, "note": note}


def guess_emqx_url(detect_result=None, extra_ports=(18083,)):
    """从探测结果猜出 EMQX Dashboard 地址（REST API 用）。"""
    d = detect_result or detect_mqtt()
    if d.get("dashboard"):
        return "http://%s:%d" % (d["host"], d["dashboard"])
    for p in extra_ports:
        if p in (d.get("open_ports") or []):
            return "http://%s:%d" % (d["host"], p)
    return ""


def _listeners(cli):
    try:
        payload = cli._json("GET", "/api/v5/listeners")  # noqa: SLF001
    except EmqxError:
        return []
    rows = payload.get("data") if isinstance(payload, dict) else payload
    out = []
    for r in (rows or []):
        if not isinstance(r, dict):
            continue
        # 监听器对象没有 node_status/current_connections；认证链只对 MQTT 类监听器有意义
        lid = r.get("id") or ""
        if lid and ("tcp" in lid or "ssl" in lid or "ws" in lid or "wss" in lid
                    or "quic" in lid):
            out.append({"id": lid, "type": r.get("type"), "running": r.get("running"),
                        "current_connections": r.get("current_connections")})
    return out


def list_authenticators(cli, include_listeners=True):
    """
    汇总当前认证链。返回 [{"scope":"global"|"tcp:default", "listener_id":..., "chain":[...]}]
    """
    out = []
    try:
        payload = cli._json("GET", "/api/v5/authentication")  # noqa: SLF001
        out.append({"scope": "global", "listener_id": None,
                    "chain": (payload.get("data") if isinstance(payload, dict) else payload) or []})
    except EmqxError as e:
        out.append({"scope": "global", "listener_id": None, "chain": [], "error": str(e)})
    if include_listeners:
        for lst in _listeners(cli):
            lid = lst["id"]
            try:
                payload = cli._json("GET", "/api/v5/listeners/%s/authentication" % lid)  # noqa: SLF001
                chain = (payload.get("data") if isinstance(payload, dict) else payload) or []
            except EmqxError:
                continue
            if chain:
                out.append({"scope": lid, "listener_id": lid, "chain": chain,
                            "running": lst.get("running")})
    return out


def _is_http_sas(authn, sas_url_hint="", force_all=False):
    """判断某个认证器是不是"本项目的 SAS HTTP 认证"。"""
    if not isinstance(authn, dict):
        return False
    backend = str(authn.get("backend") or authn.get("type") or "").lower()
    if backend != "http":
        return False
    url = str(authn.get("url") or "")
    if sas_url_hint and url.startswith(sas_url_hint):
        return True
    low = url.lower()
    if any(h in low for h in AUTHN_PATH_HINTS):
        return True
    for p in SAS_PORT_HINTS:
        if (":%d" % p) in url:
            return True
    return bool(force_all)


def inspect(cli, sas_url_hint=""):
    """只读检查：当前认证链里有多少项、哪些看起来是 SAS、目标 URL 是否已生效。"""
    chains = list_authenticators(cli)
    items = []
    for c in chains:
        for a in c.get("chain") or []:
            items.append({
                "scope": c["scope"],
                "listener_id": c.get("listener_id"),
                "id": a.get("id"),
                "backend": a.get("backend") or a.get("type"),
                "mechanism": a.get("mechanism"),
                "url": a.get("url"),
                "enable": a.get("enable"),
                "is_sas_like": _is_http_sas(a, sas_url_hint),
                "already_target": bool(sas_url_hint) and str(a.get("url") or "").startswith(sas_url_hint),
            })
    return {"chains": chains, "items": items,
            "http_count": sum(1 for i in items if str(i["backend"]).lower() == "http"),
            "sas_like_count": sum(1 for i in items if i["is_sas_like"]),
            "target_active": any(i["already_target"] for i in items)}


def preflight_target(url, timeout=6):
    """
    预检：目标认证 URL 必须真的能应答，否则绝不动线上配置。
    SAS 的 /auth 对空请求会返回 400/401 + {"result":"deny",...}，这就算"活着"。
    返回 {"ok":bool,"status":int,"detail":str,"body":str}
    """
    import urllib.error
    import urllib.request
    payload = json.dumps({"username": "BAS_PREFLIGHT", "password": "x"}).encode()
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return {"ok": True, "status": r.status, "detail": "可达（HTTP %d）" % r.status,
                    "body": body[:200]}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        # 400/401/403 也算服务在（它明确回应了），只有 5xx/0 才算不可用
        ok = e.code < 500
        return {"ok": ok, "status": e.code,
                "detail": "可达（HTTP %d）" % e.code if ok else "服务异常（HTTP %d）" % e.code,
                "body": body[:200]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "status": 0, "detail": "连不上: %s" % e, "body": ""}


def snapshot_authn(a, listener_id=None):
    """
    把现有认证器快照成"可重新 POST 的创建体"，用于建失败时回滚恢复。

    只保留 schema 白名单字段：EMQX 的 GET 会返回一堆只读/派生字段
    （id / status / metrics / enable_pipelining / ciphers / versions ...），
    原样回传会被 400 拒绝。
    """
    src = a or {}
    cfg = {
        "mechanism": src.get("mechanism") or "password_based",
        "backend": src.get("backend") or "http",
        "enable": bool(src.get("enable", True)),
    }
    for k in ("method", "url", "headers", "body", "pool_size",
              "connect_timeout", "request_timeout", "max_retries",
              "password_hash_algorithm", "user_id_type", "bootstrap_file",
              "bootstrap_type", "acl", "precondition"):
        if src.get(k) not in (None, "", {}, []):
            cfg[k] = src[k]
    # ssl 必须是**对象**且只带 enable（EMQX 5.8.9 实测：布尔值报
    # bad_value_for_struct；带 verify/ciphers 等会被 schema 拒绝）
    ssl_src = src.get("ssl")
    if isinstance(ssl_src, dict):
        cfg["ssl"] = {"enable": bool(ssl_src.get("enable", False))}
    else:
        cfg["ssl"] = {"enable": bool(ssl_src)}
    return cfg


def build_sas_authn(url, listener_id=None, name="fmo-sas-http", ssl_enable=False,
                    allow_anonymous=False):
    """
    构造 HTTP 认证器配置（密码认证 → HTTP 后端 → POST JSON）。

    字段依据**实测**的 EMQX 5.8.9 schema（这些坑都踩过，别再改回去）：
      * body 里必须有 mechanism；**不能**带 type / listener_id（会报
        unknown_fields: "listener_id,type"）
      * ssl 必须是对象且只带 enable —— 布尔值报 bad_value_for_struct，
        带 verify 等键也可能被拒
      * method 必须小写 post
      * body 必须含 username/password 两个键，否则 SAS 收到空凭据 → 全部 deny
      * 认证器 id 由 mechanism:backend 推导（→ password_based:http），
        同一作用域只能有一个，所以"改指向"必须删旧再建，且**建失败必须回滚**
      * 全局链对各监听器生效（tcp:default 等），不需要也不能传 listener_id
    """
    cfg = {
        "mechanism": "password_based",
        "backend": "http",
        "enable": True,
        "method": "post",
        "url": url,
        "headers": {"content-type": "application/json"},
        "body": {"username": "${username}", "password": "${password}"},
        "pool_size": 8,
        "connect_timeout": "5s",
        "request_timeout": "5s",
        "ssl": {"enable": bool(ssl_enable)},
    }
    if allow_anonymous:
        cfg["allow_anonymous"] = True
    _ = (listener_id, name)
    return cfg


def switch_auth(cli, target_url, sas_url_hint="", force_all=False, dry_run=True,
                also_listener_scopes=True, db=None, log=print):
    """
    把 EMQX 的客户端认证指向 target_url（BAS 的 /auth）。

    返回 {"ok":bool, "changed":[...], "skipped":[...], "errors":[...],
          "backup": {...}, "rollback_hint": str}
    """
    res = {"ok": False, "changed": [], "skipped": [], "errors": [],
           "backup": None, "rollback_hint": ""}
    try:
        before = inspect(cli, sas_url_hint)
    except EmqxError as e:
        res["errors"].append("读取认证链失败: %s" % e)
        return res

    if before["target_active"] and before["sas_like_count"] == 0:
        res["ok"] = True
        res["skipped"].append("认证已指向 %s，无需改动" % target_url)
        return res

    # 备份现有认证链
    res["backup"] = before["chains"]
    if db is not None:
        try:
            db.set_setting("emqx_authn_backup", json.dumps(before["chains"], ensure_ascii=False))
            db.set_setting("emqx_authn_backup_at", time.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:  # noqa: BLE001
            log("[认证接管] 备份写入审计库失败（继续，但请留意）: %s" % e)

    # 决定要操作的 scope：优先"已有认证链"的 scope；否则全局 + 默认监听器
    scopes = []
    for c in before["chains"]:
        if c.get("chain"):
            scopes.append(c)
    if not scopes:
        scopes = [{"scope": "global", "listener_id": None, "chain": []}]
        if also_listener_scopes:
            for lst in _listeners(cli):
                if lst.get("running"):
                    scopes.append({"scope": lst["id"], "listener_id": lst["id"], "chain": []})

    for c in scopes:
        scope = c["scope"]
        lid = c.get("listener_id")
        chain = c.get("chain") or []
        # 关键：先算出"这个 scope 已经指向目标了吗"，再决定删/建；
        # 否则删掉旧项后会拿旧链去判断，导致新认证不会被创建。
        already_at_target = False
        for a in chain:
            if _is_http_sas(a, sas_url_hint, False) and a.get("url") == target_url:
                already_at_target = True
        if already_at_target:
            res["skipped"].append("%s: 已存在指向目标的认证，跳过" % scope)
            continue

        # 这个 scope 里"像 SAS 的"那些项（要动的）与"不能动的"分开
        sas_items = [a for a in chain if _is_http_sas(a, sas_url_hint, force_all)]
        keep_items = [a for a in chain if a not in sas_items]

        # ---- 预检：目标 URL 必须真的能应答，否则什么都不做 ----
        if not dry_run:
            pre = preflight_target(target_url)
            res.setdefault("preflight", pre)
            if not pre["ok"]:
                res["errors"].append(
                    "%s: 目标认证服务预检未通过（%s），本次不做任何改动"
                    % (scope, pre["detail"]))
                continue

        if dry_run:
            for a in sas_items:
                res["changed"].append("[DRY] %s: 将替换认证 %s (url=%s) → %s" % (
                    scope, a.get("id"), a.get("url"), target_url))
            if not sas_items:
                res["changed"].append("[DRY] %s: 将新建 HTTP 认证 → %s" % (scope, target_url))
            for a in keep_items:
                res["skipped"].append("%s: 保留非 SAS 认证项 %s(%s)" % (
                    scope, a.get("id"), a.get("backend")))
            continue

        # ---- 真正的替换：先删后建，但**建失败立刻把旧配置恢复回去** ----
        # （旧实现删了不建/建失败就留在"无认证"状态，把服务搞挂过；这里必须能回滚）
        backup_cfgs = [snapshot_authn(a, lid) for a in sas_items]
        for a in sas_items:
            try:
                cli._json("DELETE", "/api/v5/authentication/%s" % a.get("id"))  # noqa: SLF001
                res["changed"].append("%s: 已删除旧认证 %s (url=%s)" % (
                    scope, a.get("id"), a.get("url")))
            except EmqxError as e:
                res["errors"].append("%s: 删除 %s 失败: %s" % (scope, a.get("id"), e))

        # 认证器 id 由 mechanism:backend 推导（password_based:http），
        # 同一作用域只能有一个，所以先删干净再建。
        cfg = build_sas_authn(target_url)
        created = False
        err_msg = None

        def _try_create(body):
            try:
                cli._json("POST", "/api/v5/authentication", body=body)  # noqa: SLF001
                return True, None
            except EmqxError as e:  # noqa: BLE001
                return False, str(e)

        created, err_msg = _try_create(cfg)
        # 409 already_exists：说明同 id 的项还在（可能是没被识别出的 SAS 项）→ 删掉重试一次
        if not created and err_msg and ("already_exists" in err_msg.lower()
                                        or "409" in err_msg):
            for aid in ("password_based:http",):
                try:
                    cli._json("DELETE", "/api/v5/authentication/%s" % aid)  # noqa: SLF001
                    res["changed"].append("%s: 删除同 id 冲突项 %s 后重试" % (scope, aid))
                except EmqxError:
                    pass
            created, err_msg = _try_create(cfg)

        if created:
            res["changed"].append("%s: 已新建 HTTP 认证 → %s" % (scope, target_url))
            # 建后立刻校验：URL 必须真的等于目标，否则按失败处理并回滚
            try:
                chk = inspect(cli, target_url)
                if not chk["target_active"]:
                    created = False
                    err_msg = "新建后校验失败：认证链里没有指向 %s 的项" % target_url
                    res["errors"].append("%s: %s" % (scope, err_msg))
            except EmqxError as e:
                res["errors"].append("%s: 建后校验异常: %s" % (scope, e))
        else:
            res["errors"].append("%s: 新建认证失败: %s" % (scope, err_msg))

        # 建失败 → 把刚才删掉的恢复回来，绝不留"无认证"状态
        if not created and backup_cfgs:
            log("[认证接管] 新建失败，正在回滚恢复原有认证（%d 项）..." % len(backup_cfgs))
            restored = 0
            for bcfg in backup_cfgs:
                try:
                    cli._json("POST", "/api/v5/authentication", body=bcfg)  # noqa: SLF001
                    restored += 1
                except EmqxError as e2:
                    res["errors"].append("回滚恢复失败: %s" % e2)
            res["rolled_back"] = restored
            if restored == len(backup_cfgs) and restored > 0:
                res["changed"].append("%s: 已回滚恢复原有认证配置（服务保持可用）" % scope)
            res["ok"] = False
        elif not created and not backup_cfgs:
            # 本来就没有可恢复的项 → 更要明确报警：此刻该 scope 无认证
            log("[认证接管] 新建失败且无可回滚项 —— 该作用域当前处于无认证状态，请立即处理！")
            res["errors"].append(
                "%s: 新建失败且无旧配置可回滚，该监听器可能处于无认证状态，请立即检查" % scope)

    # 复核
    try:
        after = inspect(cli, target_url)
        res["after"] = after["items"]
        res["ok"] = bool(after["target_active"]) and not res["errors"]
    except EmqxError as e:
        res["errors"].append("复核失败: %s" % e)
    res["rollback_hint"] = (
        "已备份原认证配置（emqx_authn_backup）；"
        "如需回滚可运行 restore_auth(备份)，或在 EMQX Dashboard → 访问控制 → 认证 里手工改回")
    return res


def restore_auth(cli, backup_json, dry_run=True, log=print):
    """按备份恢复认证链（尽力而为：删除现有 http 项后按备份重建）。"""
    res = {"ok": False, "changed": [], "errors": []}
    try:
        chains = json.loads(backup_json) if isinstance(backup_json, str) else backup_json
    except Exception as e:  # noqa: BLE001
        res["errors"].append("备份解析失败: %s" % e)
        return res
    for c in chains or []:
        scope = c.get("scope")
        lid = c.get("listener_id")
        for a in c.get("chain") or []:
            if dry_run:
                res["changed"].append("[DRY] %s: 恢复 %s" % (scope, a.get("id")))
                continue
            cfg = {k: v for k, v in a.items() if k not in ("id",)}
            cfg["type"] = cfg.get("type") or cfg.get("mechanism") or "password_based"
            if lid:
                cfg["listener_id"] = lid
            try:
                cli._json("POST", "/api/v5/authentication", body=cfg)  # noqa: SLF001
                res["changed"].append("%s: 已恢复 %s" % (scope, a.get("id")))
            except EmqxError as e:
                res["errors"].append("%s: 恢复 %s 失败: %s" % (scope, a.get("id"), e))
    res["ok"] = not res["errors"]
    return res


def main():
    import argparse
    ap = argparse.ArgumentParser(description="识别 MQTT(EMQX) 并把客户端认证指向 BAS")
    ap.add_argument("--emqx-url", default="", help="EMQX Dashboard 地址（含 http:// 与端口）")
    ap.add_argument("--key", default="", help="EMQX API Key")
    ap.add_argument("--secret", default="", help="EMQX API Secret")
    ap.add_argument("--target-port", type=int, default=35928, help="BAS 公网 API 端口（默认 35928）")
    ap.add_argument("--target-url", default="", help="直接指定认证 URL（默认按端口拼）")
    ap.add_argument("--apply", action="store_true", help="真正执行（默认只 dry-run 打印）")
    ap.add_argument("--force-all", action="store_true",
                    help="把所有 http 认证都当作 SAS 处理（默认只处理像 SAS 的）")
    ap.add_argument("--detect-only", action="store_true", help="只探测 MQTT，不做任何改动")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    d = detect_mqtt()
    if not args.json:
        print("MQTT 探测: %s" % (d["note"] or "发现 EMQX"))
        print("  开放端口: %s  MQTT=%s  Dashboard=%s" % (
            d["open_ports"] or "无", d["mqtt"] or "-", d["dashboard"] or "-"))
    if args.detect_only:
        if args.json:
            print(json.dumps(d, ensure_ascii=False))
        return 0

    url = normalize_base_url(args.emqx_url) or guess_emqx_url(d)
    if not url:
        print("[错误] 未找到 EMQX Dashboard 地址，请用 --emqx-url 指定")
        return 1
    if not (args.key and args.secret):
        print("[错误] 需要 --key 与 --secret（EMQX Dashboard → 系统设置 → API 密钥）")
        return 1
    cli = EmqxClient(url, args.key, args.secret)
    ok, why = cli.ping()
    print("EMQX %s 可达: %s（%s）" % (url, ok, why))
    if not ok:
        return 1
    target = args.target_url or "http://127.0.0.1:%d/auth" % args.target_port
    r = switch_auth(cli, target, sas_url_hint="", force_all=args.force_all,
                    dry_run=not args.apply)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("目标认证 URL: %s" % target)
        for x in r["changed"]:
            print("  改: %s" % x)
        for x in r["skipped"]:
            print("  跳过: %s" % x)
        for x in r["errors"]:
            print("  错误: %s" % x)
        print("结果: %s" % ("成功" if r["ok"] else "未完成" + ("（dry-run）" if not args.apply else "")))
    return 0 if (r["ok"] or not args.apply) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
