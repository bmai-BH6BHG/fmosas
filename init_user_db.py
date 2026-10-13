#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
初始化用户库：只保留**国服 ID 用户**，清掉旧流程（无国服 ID / derived=0）遗留。

背景（用户需求）：
  曾经没有 8601（国服 ID 绑定）流程时，用户凭呼号+密码注册即可拿证书；
  现在证书下发"只认国服 ID"，那些存量用户与旧证书属于遗留数据：
    * users 里没有 guoji_id 的账户 —— 不可用、会污染名册与统计；
    * certificates 里 derived=0 的旧证书 —— 旧流程签发，且多数已吊销。
  本工具把本地库裁剪到干净状态；用户想继续用就重新绑定国服 ID。

用法：
    python init_user_db.py --dry-run      # 只报告，不改动
    python init_user_db.py --apply        # 执行（自动备份到 <库>.bak-init-<时间>）
    python init_user_db.py --apply --keep-orphan-certs
                                          # 只清用户，不动旧证书

可选参数：
    --users-db /path   指定用户库（默认按配置推导）
    --sas-db /path     指定 SAS 库（默认按配置推导）
"""
import argparse
import io
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def _db_paths(users_db=None, sas_db=None):
    """推导用户库/SAS 库路径（与 api_server 同一套前缀规则）。"""
    if users_db and sas_db:
        return users_db, sas_db
    try:
        import api_server as A
        u = users_db or A.DB_PATH
        s = sas_db
        if not s:
            # SAS 库与用户库同前缀：xxx_users.db -> xxx_sas.db
            if u.endswith('_users.db'):
                s = u[:-len('_users.db')] + '_sas.db'
            else:
                s = os.path.join(os.path.dirname(u), 'fmo_sas.db')
        return u, s
    except Exception as e:  # noqa: BLE001
        print("★ 无法推导库路径（%s），请用 --users-db/--sas-db 指定" % e)
        sys.exit(2)


def _backup(path):
    if not os.path.exists(path):
        return ''
    dst = path + '.bak-init-' + time.strftime('%Y%m%d-%H%M%S')
    import shutil
    shutil.copy2(path, dst)
    return dst


def report(users_db, sas_db):
    out = {}
    if os.path.exists(users_db):
        c = sqlite3.connect('file:%s?mode=ro' % users_db, uri=True)
        try:
            out['users_total'] = c.execute('select count(*) from users').fetchone()[0]
            out['users_with_guoji'] = c.execute(
                "select count(*) from users where guoji_id is not null"
                " and guoji_id != ''").fetchone()[0]
            out['users_no_guoji'] = out['users_total'] - out['users_with_guoji']
        except Exception as e:  # noqa: BLE001
            out['users_err'] = str(e)
        finally:
            c.close()
    else:
        out['users_err'] = '文件不存在: %s' % users_db
    if os.path.exists(sas_db):
        c = sqlite3.connect('file:%s?mode=ro' % sas_db, uri=True)
        try:
            out['certs_total'] = c.execute('select count(*) from certificates').fetchone()[0]
            # 「真实遗留证书」= 旧流程签发且**带证书内容**的；
            # 空内容的是跨系统传播用的吊销墓碑，不算遗留、也不能删。
            out['certs_legacy_real'] = c.execute(
                "select count(*) from certificates"
                " where (derived is null or derived=0)"
                " and (length(coalesce(cert_user_json,'')) > 0"
                "      or length(coalesce(cert_devicekey_json,'')) > 0)"
            ).fetchone()[0]
            out['certs_revoke_tombstone'] = c.execute(
                "select count(*) from certificates"
                " where (derived is null or derived=0)"
                " and length(coalesce(cert_user_json,'')) = 0"
                " and length(coalesce(cert_devicekey_json,'')) = 0"
            ).fetchone()[0]
            out['certs_bound_valid'] = c.execute(
                'select count(*) from certificates where derived=1 and revoked=0'
            ).fetchone()[0]
        except Exception as e:  # noqa: BLE001
            out['certs_err'] = str(e)
        finally:
            c.close()
    else:
        out['certs_err'] = '文件不存在: %s' % sas_db
    return out


def apply_prune(users_db, sas_db, keep_orphan_certs=False):
    stat = {'users_backup': '', 'sas_backup': '',
            'users_deleted': 0, 'certs_deleted': 0}

    # ---- 用户库：只保留有国服 ID 的（无国服 ID 的标记 deleted=1 并清掉凭据）----
    if os.path.exists(users_db):
        stat['users_backup'] = _backup(users_db)
        c = sqlite3.connect(users_db)
        try:
            cur = c.cursor()
            # 先统计要处理的人数
            rows = cur.execute(
                "select callsign from users where (guoji_id is null or guoji_id='')"
            ).fetchall()
            stat['users_deleted'] = len(rows)
            if rows:
                # 标记删除（保留行以便追溯），并让它们不再被当成有效账户
                cur.execute(
                    "update users set deleted=1, token=NULL, password_hash=''"
                    " where (guoji_id is null or guoji_id='')")
                c.commit()
        finally:
            c.close()

    # ---- 证书库：清掉旧流程（derived=0）证书 ----
    if os.path.exists(sas_db) and not keep_orphan_certs:
        stat['sas_backup'] = _backup(sas_db)
        c = sqlite3.connect(sas_db)
        try:
            cur = c.cursor()
            cond = ("(derived is null or derived=0)"
                    " and (length(coalesce(cert_user_json,'')) > 0"
                    "      or length(coalesce(cert_devicekey_json,'')) > 0)")
            n = cur.execute('select count(*) from certificates where %s'
                            % cond).fetchone()[0]
            stat['certs_deleted'] = n
            if n:
                # 只删带真实内容的旧证书；空内容的吊销墓碑保留
                # （它们是跨系统传播吊销状态的载体，删了下轮 pull 还会回来）
                cur.execute('delete from certificates where %s' % cond)
                c.commit()
        finally:
            c.close()
    return stat


def main():
    ap = argparse.ArgumentParser(description='初始化用户库：只保留国服 ID 用户')
    ap.add_argument('--apply', action='store_true', help='真正执行（默认只报告）')
    ap.add_argument('--dry-run', action='store_true', help='只报告（默认行为）')
    ap.add_argument('--users-db', default='')
    ap.add_argument('--sas-db', default='')
    ap.add_argument('--keep-orphan-certs', action='store_true',
                    help='只清用户，不动旧证书')
    args = ap.parse_args()

    users_db, sas_db = _db_paths(args.users_db or None, args.sas_db or None)
    print("用户库: %s" % users_db)
    print("SAS 库: %s" % sas_db)
    print()
    print("=== 当前状态 ===")
    for k, v in report(users_db, sas_db).items():
        print("  %-20s %s" % (k, v))
    print()
    if not (args.apply and not args.dry_run):
        print("（只报告，未做改动。要执行请加 --apply）")
        return 0
    print("=== 执行初始化 ===")
    stat = apply_prune(users_db, sas_db, keep_orphan_certs=args.keep_orphan_certs)
    for k, v in stat.items():
        print("  %-20s %s" % (k, v))
    print()
    print("=== 处理后状态 ===")
    for k, v in report(users_db, sas_db).items():
        print("  %-20s %s" % (k, v))
    return 0


if __name__ == '__main__':
    sys.exit(main())
