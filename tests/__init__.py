#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BAS 测试套件（零依赖，标准库 unittest；也可用 pytest 直接跑）
运行：python3 -m unittest discover -s tests -v
"""

import os
import sys

# 让测试能直接 import 仓库根目录的模块
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# 自检脚本的真实文件路径（部分测试要把它当独立脚本跑）
BAS_DIAGNOSE = os.path.join(ROOT, "bas_diagnose.py")
