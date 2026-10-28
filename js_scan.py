# -*- coding: utf-8 -*-
"""
js_scan.py —— 从页面 JS 里挖接口 / 域名 / 密钥线索
==================================================
用途：SPA（Vue/React）的接口不会写在 HTML 里，而是在打包后的 JS bundle 中。
本工具会：
  1. 抓页面 HTML
  2. 取出所有 <script src> 和外链 JS
  3. 下载 JS，正则搜索 接口路径 / API 域名 / login、token 等关键词
  4. 去重输出

用法：
  python js_scan.py https://www.example.com/login
"""

import os
import re
import sys

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
INLINE_JS = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)
# 引号里的"路径/URL"字面量
PATH_LITERAL = re.compile(r"""["'`]((?:/|https?://)[A-Za-z0-9_\-./?=&%#:\[\]]{3,160})["'`]""")
# 关键词上下文
KEY_LINE = re.compile(r".{0,60}(?:login|logout|signin|auth|token|sso|passport|api/).{0,80}", re.I)

MAX_JS = 6 * 1024 * 1024      # 单个 JS 最大 6MB
MAX_FILES = 20

# 这些是第三方库，搜"token/login"只会命中它们自己的解析器代码，跳过关键词分析
LIB_HINTS = ("babel", "vue", "jquery", "react", "lodash", "moment", "echarts",
             "element", "antd", "axios", "core-js", "polyfill", "jsencrypt",
             "crypto", "webpack", "runtime")


def _get(url):
    return requests.get(url, timeout=15, verify=False,
                        headers={"User-Agent": config.USER_AGENT},
                        allow_redirects=True)


def _abs(base, src):
    if src.startswith("http"):
        return src
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("/"):
        root = "/".join(base.split("/")[:3])
        return root + src
    return base.rstrip("/") + "/" + src


_STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp")


def _analyze(js_text, source, skip_key=False):
    hits_path, hits_url, hits_key = set(), set(), set()
    for m in PATH_LITERAL.finditer(js_text):
        v = m.group(1)
        low = v.lower()
        if v.startswith("http"):
            hits_url.add(v.split("?")[0])
            continue
        # 收集所有"像接口"的路径（不再只收含关键词的），排除静态资源
        if (len(v) >= 4 and "/" in v
                and not any(low.endswith(e) for e in _STATIC_EXT)
                and not low.startswith(("/img", "/css", "/js/", "/fonts"))):
            hits_path.add(v)
    if not skip_key:
        for m in KEY_LINE.finditer(js_text):
            s = " ".join(m.group(0).split())
            if len(s) > 8:
                hits_key.add(s[:160])
    return hits_path, hits_url, hits_key


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    url = sys.argv[1]
    if not url.startswith("http"):
        url = "https://" + url

    print(f"[js] 抓取 {url}")
    try:
        r = _get(url)
    except Exception as e:
        print(f"[!] 页面抓取失败: {e}")
        return
    html = r.text
    print(f"    页面 {r.status_code}，{len(html)} 字节")

    js_urls = []
    for m in SCRIPT_SRC.finditer(html):
        js_urls.append(_abs(url, m.group(1)))
    # 去重、限制数量
    js_urls = list(dict.fromkeys(js_urls))[:MAX_FILES]
    print(f"    发现 {len(js_urls)} 个 JS 文件")

    all_path, all_url, all_key = set(), set(), set()

    # 先分析 HTML 里的内联 JS
    for m in INLINE_JS.finditer(html):
        p, u, k = _analyze(m.group(1), "inline")
        all_path |= p; all_url |= u; all_key |= k

    for i, js in enumerate(js_urls, 1):
        try:
            rj = _get(js)
            if rj.status_code != 200 or len(rj.content) > MAX_JS:
                continue
            p, u, k = _analyze(rj.text, js)
            all_path |= p; all_url |= u; all_key |= k
            print(f"    [{i}/{len(js_urls)}] {js.split('/')[-1][:50]} "
                  f"({len(rj.content)//1024}KB) +{len(p)} 路径")
        except Exception:
            continue

    print("\n" + "=" * 70)
    print("【可疑接口路径】")
    for v in sorted(all_path)[:60]:
        print("  ", v)
    if not all_path:
        print("  （无）")

    print("\n【JS 里出现的域名】")
    for v in sorted(all_url)[:40]:
        print("  ", v)
    if not all_url:
        print("  （无）")

    print("\n【含 login/token/auth 的代码片段】")
    for v in sorted(all_key)[:40]:
        print("  ", v)
    if not all_key:
        print("  （无）")


if __name__ == "__main__":
    main()
