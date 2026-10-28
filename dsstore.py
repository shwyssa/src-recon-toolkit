# -*- coding: utf-8 -*-
"""
dsstore.py —— .DS_Store 解析器
==================================================
macOS 的 .DS_Store 泄露时，里面记录着同目录下的文件名/子目录名。
本工具把二进制里的 UTF-16 字符串抽出来，还原成一份"目录清单"。

用法：
  python dsstore.py https://example.com/.DS_Store
  python dsstore.py ./local.DS_Store
"""

import os
import re
import sys

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Finder 自身元数据键，不是文件名
NOISE = ("ShowStatusBar", "ShowToolbar", "ShowTabView", "ContainerShowSidebar",
         "WindowBounds", "ShowSidebar", "bplist", "Bud1", "DS_Store",
         "fwswplb", "Iloc", "bwsp", "icvp", "modDate", "longID", "ph1S",
         "ptbL", "ptbN", "vSrn", "Iloc", "icvp")


def parse(data):
    """从 .DS_Store 字节里抽取文件名列表。"""
    names = set()
    # UTF-16BE: 00 xx
    for m in re.finditer(rb"\x00[\x20-\x7e](?:\x00[\x20-\x7e])*", data):
        try:
            names.add(m.group(0).decode("utf-16-be").strip())
        except Exception:
            pass
    # UTF-16LE: xx 00
    for m in re.finditer(rb"[\x20-\x7e]\x00(?:[\x20-\x7e]\x00)*", data):
        try:
            names.add(m.group(0).decode("utf-16-le").strip())
        except Exception:
            pass

    # 过滤噪声、太短的
    cand = [s for s in names
            if len(s) >= 2 and not any(n in s for n in NOISE)
            and re.match(r"^[A-Za-z0-9_.\- ]+$", s)]
    # 去掉"是别人子串"的碎片（如 INF 是 WEB-INF 的后缀）
    cand.sort(key=len, reverse=True)
    out = []
    for s in cand:
        if not any(s != o and s in o for o in out):
            out.append(s)
    return sorted(out)


def fetch(url):
    r = requests.get(url, timeout=config.TIMEOUT, verify=False,
                     headers={"User-Agent": config.USER_AGENT})
    return r.content


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    arg = sys.argv[1]

    if arg.startswith("http"):
        print(f"[ds] 下载 {arg}")
        data = fetch(arg)
    else:
        print(f"[ds] 读取 {arg}")
        with open(arg, "rb") as f:
            data = f.read()

    if data[:4] != b"\x00\x00\x00\x01" or b"Bud1" not in data[:8]:
        print("[!] 这不是标准 .DS_Store 文件（缺少 Bud1 魔数）")
        return

    names = parse(data)
    print(f"[ds] 文件 {len(data)} 字节，提取到 {len(names)} 个条目：")
    for n in names:
        print("   ", n)


if __name__ == "__main__":
    main()
