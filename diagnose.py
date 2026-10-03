#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断脚本：检查分系统 CA 信息上报链路"""
import os, sys, json, glob

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
print('=== FMO 分系统 CA 上报诊断 ===')
print('工作目录:', BASE)
print()

# 1. 检查 ca/ 目录
print('[1] 检查 ca/ 目录:')
ca_dir = os.path.join(BASE, 'ca')
print('    路径:', ca_dir)
print('    存在:', os.path.isdir(ca_dir))
if os.path.isdir(ca_dir):
    files = os.listdir(ca_dir)
    print('    文件:', files)
    for fn in ['cert_root.json', 'cert_int.json']:
        fp = os.path.join(ca_dir, fn)
        if os.path.exists(fp):
            try:
                with open(fp, 'r', encoding='utf-8-sig') as f:
                    data = json.load(f)
                print('    %s: type=%s, name=%s' % (
                    fn, data.get('type'), data.get('subject', {}).get('name')))
            except Exception as e:
                print('    %s: 解析失败 %s' % (fn, e))
        else:
            print('    %s: 不存在!' % fn)
else:
    print('    *** ca/ 目录不存在！需要初始化 CA ***')
print()

# 2. 检查 config.json
print('[2] 检查 config.json:')
try:
    with open('config.json', 'r', encoding='utf-8-sig') as f:
        config = json.load(f)
    print('    master_url:', config.get('master_url'))
    print('    ca_dir:', config.get('ca_dir'))
    print('    subsystem_id:', config.get('subsystem_id'))
    print('    sync_interval:', config.get('sync_interval'))
except Exception as e:
    print('    解析失败:', e)
print()

# 3. 检查 sync_engine 能否导入
print('[3] 检查 sync_engine 导入:')
try:
    from sync_engine import SyncEngine, now_ts
    print('    导入成功')
except Exception as e:
    print('    导入失败:', e)
    sys.exit(1)
print()

# 4. 测试 collect_ca_info
print('[4] 测试 collect_ca_info:')
try:
    db_path = os.path.join(BASE, 'users.db')
    # 也检查域名命名的数据库
    db_files = glob.glob(os.path.join(BASE, '*_users.db'))
    if db_files:
        db_path = db_files[0]
    print('    数据库:', db_path)
    
    engine = SyncEngine(config, db_path, mode='subsystem', base_dir=BASE)
    ca_info = engine.collect_ca_info(since=0)
    print('    收集到 CA 信息数量:', len(ca_info))
    for ci in ca_info:
        print('      - ca_id=%s, ca_type=%s, ca_name=%s' % (
            ci.get('ca_id'), ci.get('ca_type'), ci.get('ca_name')))
except Exception as e:
    print('    失败:', e)
print()

# 5. 测试上报到总系统（默认跳过：会向总系统写入真实数据，加 --do-report 才执行）
print('[5] 测试上报到总系统:')
if '--do-report' in sys.argv:
    try:
        ok = engine.report_to_master(full=True)
        print('    上报结果:', ok)
    except Exception as e:
        print('    上报失败:', e)
else:
    print('    已跳过（避免向总系统写入真实数据；加 --do-report 参数才执行）')
print()

# 6. 检查 cert_gen
print('[6] 检查 cert_gen:')
try:
    sys.path.insert(0, BASE)
    from cert_gen import generate_keypair
    print('    cert_gen 导入成功')
except Exception as e:
    print('    cert_gen 导入失败:', e)
print()

print('=== 诊断完成 ===')