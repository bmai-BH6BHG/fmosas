#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
合并函数契约：merge_* 必须返回 int（条数）。

真实事故（2026-10-14）：merge_ca_info 漏了末尾的 `return merged` → 返回 None
  → merge_all 里 `total += None` 抛 TypeError
  → **整条 pull 静默挂掉**（日志只有一句"拉取循环异常（已吞掉）"）
  → trust_issued 永不落地 → 各台信任链收不到更新 → 桥接大面积 rc=5。

这类 bug 极隐蔽：同步线程在跑、上报正常，只有 pull 失败。所以必须有测试兜住。
"""
import ast
import io
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import sync_engine as S  # noqa: E402

MERGE_FUNCS = ('merge_users', 'merge_certificates', 'merge_trust_chain',
               'merge_ca_info', 'merge_trust_issued')
SRC = io.open(os.path.join(REPO, 'sync_engine.py'), encoding='utf-8').read()
TREE = ast.parse(SRC)


def _func_node(name):
    """在 SyncEngine 类里找到指定方法的 AST 节点。"""
    for node in ast.walk(TREE):
        if isinstance(node, ast.ClassDef) and node.name == 'SyncEngine':
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == name:
                    return item
    return None


class MergeContractTests(unittest.TestCase):
    """AST 级：每个 merge_* 的正常路径都必须显式 return。"""

    def test_every_merge_ends_with_return(self):
        for name in MERGE_FUNCS:
            node = _func_node(name)
            self.assertIsNotNone(node, '%s 未找到' % name)
            last = node.body[-1]
            # 允许末尾是 if/try（里面各有 return），否则必须是 return
            if isinstance(last, (ast.If, ast.Try)):
                has_ret = any(isinstance(x, ast.Return) for x in ast.walk(last))
            else:
                has_ret = isinstance(last, ast.Return)
            self.assertTrue(
                has_ret,
                '%s 的函数体末尾没有 return（会返回 None）→ merge_all 的 '
                '`total += ...` 会抛 TypeError，整条 pull 挂掉' % name)

    def test_merge_all_uses_plus_equals(self):
        body = ast.get_source_segment(SRC, _func_node('merge_all'))
        self.assertIn('total += self.merge_', body)

    def test_merge_all_extras_are_guarded(self):
        """merge_all 里新增的附加逻辑（密钥/运维指令）必须各自 try/except。"""
        body = ast.get_source_segment(SRC, _func_node('merge_all'))
        self.assertIn("data.get('bridge_auth')", body)
        self.assertIn("data.get('ops_command')", body)
        # 两者都必须在 try 里（不能把异常抛给 pull 循环）
        self.assertGreaterEqual(body.count('except Exception'), 2)


class MergeReturnTypeTests(unittest.TestCase):
    """运行时：真实引擎 + 临时库，空/非空输入都必须返回 int。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='merge_contract_')
        self.db = os.path.join(self.tmp, 'sub-TEST_users.db')
        self.eng = S.SyncEngine({'subsystem_id': 'sub-TEST'}, self.db,
                                mode='subsystem', base_dir=self.tmp)

    def tearDown(self):
        try:
            self.eng.stop()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_inputs_return_int(self):
        for name in MERGE_FUNCS:
            fn = getattr(self.eng, name, None)
            self.assertIsNotNone(fn, '%s 不存在' % name)
            out = fn([])
            self.assertIsInstance(out, int,
                                  '%s([]) 应返回 int，实际 %r' % (name, out))

    def test_nonempty_inputs_return_int(self):
        """★ 核心回归：非空输入也必须返回 int（漏 return 在这里必现）。"""
        out = self.eng.merge_ca_info([{
            'ca_id': 'rootCA:TESTKEY', 'ca_type': 'rootCA',
            'public_key': 'TESTKEY', 'last_modified': 1.0,
        }])
        self.assertIsInstance(out, int, 'merge_ca_info 非空也返回 %r' % out)

    def test_merge_all_returns_int_with_bridge_auth(self):
        """
        ★ 端到端回归：带 bridge_auth 的 pull 数据，
        merge_all 必须正常返回 int（而不是抛 TypeError）。
        """
        out = self.eng.merge_all({
            'users': [], 'certificates': [], 'trust_chain': [], 'ca_info': [],
            'trust_issued': [],
            'bridge_auth': {'secret': 'X' * 64},
        }, source='master')
        self.assertIsInstance(out, int, 'merge_all 返回 %r' % out)

    def test_merge_all_survives_broken_extra(self):
        """附加数据异常也不能让 merge_all 抛（各自 try/except 兜住）。"""
        out = self.eng.merge_all({
            'bridge_auth': 'not-a-dict',
            'ops_command': 'not-a-dict',
        }, source='master')
        self.assertIsInstance(out, int)


if __name__ == '__main__':
    unittest.main(verbosity=2)
