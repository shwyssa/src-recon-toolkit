# -*- coding: utf-8 -*-
"""
sitemap.py —— 网站地图 / robots 路径提取器
==================================================
从目标的 sitemap.xml / sitemap_index.xml / sitemap.txt / robots.txt
里提取页面路径。

关键点：
  - 只保留目标域名（及其子域）下的 URL，自动过滤 sitemaps.org / w3.org
    这类"协议说明书"外链，不会再点进假线索。
  - 递归处理 sitemap 索引（sitemapindex）。
  - 自动在 https://www / https:// / http:// 之间探活，裸域没签证书也能跑。
  - 顺带解析 robots.txt 里的 Sitemap: 和 Disallow: 路径。

输出（在 output/ 下）：
  known_paths.txt   —— 去重后的路径（可直接喂给目录探测/指纹验证）
  known_urls.txt    —— 去重后的完整 URL（含查询参数，优先人工看）
  重点路径.txt       —— 含 admin/api/upload/login 等关键词的高价值路径

用法：
  python sitemap.py example.com        # 单个域名
  python sitemap.py                    # 读 domains.txt 批量
"""

import os
import re
import sys
import gzip
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Windows 控制台默认 GBK，强制 utf-8 输出，避免中文乱码
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 默认尝试的 sitemap 位置
DEFAULT_SITEMAPS = ["sitemap.xml", "sitemap_index.xml", "sitemap.txt"]
MAX_SITEMAP_FILES = 200      # 最多处理多少个 sitemap 文件
MAX_FILE_BYTES = 10 * 1024 * 1024

# 高价值路径关键词（用于挑出"重点路径"）
INTERESTING = re.compile(
    r"(admin|manager|manage|api|upload|download|login|passport|sso|oauth|"
    r"user|account|file|files|backup|bak|config|system|debug|test|console|"
    r"portal|demo|export|import|sync|data|db|database|sql|log|monitor|"
    r"actuator|swagger|druid|phpmyadmin|ueditor|kindeditor)", re.I)

# 视为噪声、不输出的路径
NOISE_PATHS = {"/", "", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
               "/sitemap.txt", "/favicon.ico"}


def _localname(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _fetch(url):
    try:
        r = requests.get(url, timeout=config.TIMEOUT, verify=False,
                         headers={"User-Agent": config.USER_AGENT},
                         allow_redirects=True)
        if r.status_code == 200:
            return r.content
    except Exception:
        pass
    return None


def _decode(content):
    if content[:2] == b"\x1f\x8b":          # 原始 gzip（.xml.gz）
        try:
            content = gzip.decompress(content)
        except Exception:
            return ""
    return content.decode("utf-8", "ignore")


def _same_domain(url, seed):
    host = (urlparse(url).hostname or "").lower()
    return host == seed or host.endswith("." + seed)


def _path_of(url):
    p = urlparse(url).path or "/"
    return p if p.startswith("/") else "/" + p


def _parse_xml(text):
    """返回 (kind, locs)。kind: 'sitemapindex' / 'urlset' / None"""
    try:
        root = ET.fromstring(text.lstrip("\ufeff"))
    except Exception:
        return None, []
    kind = _localname(root.tag)
    locs = []
    for el in root.iter():
        if _localname(el.tag) == "loc" and el.text and el.text.strip():
            locs.append(el.text.strip())
    return kind, locs


def _parse_robots(text):
    sitemaps, disallow = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("sitemap:"):
            v = line.split(":", 1)[1].strip()
            if v:
                sitemaps.append(v)
        elif low.startswith("disallow:"):
            v = line.split(":", 1)[1].strip()
            if v and v != "/":
                disallow.append(v)
    return sitemaps, disallow


def _extract_with_base(base, domain):
    """在指定 base 下抓取。返回 (paths, urls)。"""
    paths, urls = set(), set()
    queue = []

    # 1) robots.txt
    raw = _fetch(base + "/robots.txt")
    if raw:
        sms, dis = _parse_robots(_decode(raw))
        for p in dis:
            paths.add(p if p.startswith("/") else "/" + p)
        for s in sms:
            if _same_domain(s, domain):
                queue.append(s)

    # 2) 默认位置
    for name in DEFAULT_SITEMAPS:
        queue.append(f"{base}/{name}")

    # 3) BFS 处理 sitemap
    visited, processed = set(), 0
    while queue and processed < MAX_SITEMAP_FILES:
        u = queue.pop(0)
        if u in visited or not _same_domain(u, domain):
            continue
        visited.add(u)
        processed += 1
        raw = _fetch(u)
        if not raw or len(raw) > MAX_FILE_BYTES:
            continue
        text = _decode(raw)

        if u.endswith(".txt"):              # sitemap.txt：一行一个 URL
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http") and _same_domain(line, domain):
                    urls.add(line)
                    paths.add(_path_of(line))
            continue

        kind, locs = _parse_xml(text)
        if not kind:
            continue
        for loc in locs:
            if not _same_domain(loc, domain):
                continue                    # ← 过滤 sitemaps.org / w3.org 外链
            if kind == "sitemapindex":
                queue.append(loc)
            else:
                urls.add(loc)
                paths.add(_path_of(loc))

    return paths, urls


def extract_domain(domain):
    """依次尝试 www / 裸域 / http，返回 (paths, urls)。"""
    candidates = [
        f"https://www.{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"http://{domain}",
    ]
    for base in candidates:
        paths, urls = _extract_with_base(base, domain)
        if paths or urls:
            return paths, urls
    return set(), set()


def _load_domains(cli_domains):
    if cli_domains:
        doms = cli_domains
    else:
        if not os.path.exists(config.DOMAINS_FILE):
            return []
        with open(config.DOMAINS_FILE, "r", encoding="utf-8") as f:
            doms = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    out = []
    for d in doms:
        d = d.lower().replace("https://", "").replace("http://", "") \
             .split("/")[0].split(":")[0]
        if d.startswith("www."):
            d = d[4:]
        if d and d not in out:
            out.append(d)
    return out


def main():
    cli = [a for a in sys.argv[1:] if not a.startswith("-")]
    domains = _load_domains(cli)
    if not domains:
        print("[!] 没有域名。请在 domains.txt 填，或 python sitemap.py example.com")
        return

    all_paths, all_urls = set(), set()
    for d in domains:
        print(f"[sitemap] 提取 {d} ...")
        p, u = extract_domain(d)
        all_paths |= p
        all_urls |= u
        print(f"    路径 {len(p)}，URL {len(u)}")

    all_paths = {p for p in all_paths if p not in NOISE_PATHS}
    interesting = sorted(p for p in all_paths if INTERESTING.search(p))
    rest = sorted(p for p in all_paths if p not in set(interesting))
    ordered = interesting + rest

    if not os.path.exists(config.OUTPUT_DIR):
        os.makedirs(config.OUTPUT_DIR)

    p1 = os.path.join(config.OUTPUT_DIR, "known_paths.txt")
    p2 = os.path.join(config.OUTPUT_DIR, "known_urls.txt")
    p3 = os.path.join(config.OUTPUT_DIR, "重点路径.txt")

    with open(p1, "w", encoding="utf-8") as f:
        f.write("\n".join(ordered) + ("\n" if ordered else ""))
    with open(p2, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(all_urls)) + ("\n" if all_urls else ""))
    with open(p3, "w", encoding="utf-8") as f:
        f.write("\n".join(interesting) + ("\n" if interesting else ""))

    print("\n" + "=" * 60)
    print(f"完成：路径 {len(all_paths)} 条，其中重点 {len(interesting)} 条，URL {len(all_urls)} 条")
    print(f"  {p1}")
    print(f"  {p2}")
    print(f"  {p3}")
    print("=" * 60)


if __name__ == "__main__":
    main()
