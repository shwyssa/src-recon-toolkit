# -*- coding: utf-8 -*-
"""
断点续跑：把各阶段结果落盘，重跑时自动跳过已完成阶段。

用法：python main.py --resume example.com
  - 如果 output/_state.json 里的目标列表和本次一致，就复用
  - 想强制重算，去掉 --resume 或删掉 _state.json
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def _path():
    # 每次调用时取 config.OUTPUT_DIR，保证 --out 变更后仍然正确
    return os.path.join(config.OUTPUT_DIR, "_state.json")


def read():
    try:
        p = _path()
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load(seeds):
    """seeds 是规范化后的域名列表；目标不一致则视为无状态。"""
    s = read()
    if not s:
        return {}
    if s.get("domains") != sorted(seeds):
        print("[续跑] 目标与上次不一致，忽略旧状态")
        return {}
    return s


def save(seeds, key, value):
    s = read()
    s["domains"] = sorted(seeds)
    s[key] = value
    try:
        os.makedirs(config.OUTPUT_DIR, exist_ok=True)
        with open(_path(), "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False)
    except Exception as e:
        print(f"[续跑] 保存状态失败：{e}")


def clear():
    try:
        p = _path()
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass
