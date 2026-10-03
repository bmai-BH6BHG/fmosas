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
