# -*- coding: utf-8 -*-
"""
precheck.py —— 目标可达性预检
==================================================
跑全流程前，先花几秒确认目标「现在能不能测」。
避免对着一个已经把你拉黑、或者整站 500 的目标刷半天。

判断方式：依次尝试 https://www / https:// / http://www / http://，
看状态码 + 响应时间，给出结论：

  ✓ 可测         200/301/302
  ⚠ 可测(WAF)    401/403（能连，但被鉴权/WAF 挡）
  ⚠ 根路径404    能连，但根路径不是正常页（可能路径不对/被拦）
  ✗ 站点异常     5xx（整站 500/502，别测了）
  ✗ 不可达       全部连接失败/超时（IP 被封或主机下线）

用法：
  python main.py --check example.com
  python main.py --check                 # 读 domains.txt
  python modules/precheck.py example.com # 单独跑
"""

import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import decode_text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text[:200000], re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:50] if m else ""


def _probe(domain):
    urls = [
        f"https://www.{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"http://{domain}",
    ]
    last_err = "未知"
    for url in urls:
        t0 = time.time()
        try:
            r = requests.get(url, timeout=config.PRECHECK_TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT},
                             allow_redirects=True)
            ms = int((time.time() - t0) * 1000)
            return {"domain": domain, "url": url, "status": r.status_code,
                    "server": r.headers.get("Server", ""), "ms": ms,
                    "title": _title(decode_text(r))}
        except Exception as e:
            last_err = type(e).__name__
    return {"domain": domain, "url": "", "status": None,
            "server": "", "ms": 0, "title": f"({last_err})"}


def _verdict(row):
    s = row["status"]
    if s is None:
        return "✗ 不可达"
    if s in (200, 301, 302):
        return "✓ 可测"
    if s in (401, 403):
        return "⚠ 可测(WAF)"
    if s == 202:
        return "⚠ 疑似反爬(202)"
    if s == 404:
        return "⚠ 根路径404"
    if s >= 500:
        return "✗ 站点异常"
    return "⚠ 异常"


def _load(domains):
    if domains:
        src = domains
    else:
        if not os.path.exists(config.DOMAINS_FILE):
            return []
        with open(config.DOMAINS_FILE, "r", encoding="utf-8") as f:
            src = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    out = []
    for d in src:
        d = d.lower().replace("https://", "").replace("http://", "") \
             .split("/")[0].split(":")[0]
        if d.startswith("www."):
            d = d[4:]
        if d and d not in out:
            out.append(d)
    return out


def run(domains=None):
    doms = _load(domains)
    if not doms:
        print("[!] 没有域名：在 domains.txt 填写，或 python main.py --check example.com")
        return []

    print(f"预检 {len(doms)} 个目标（单次超时 {config.PRECHECK_TIMEOUT}s）...\n")
    rows = []
    with ThreadPoolExecutor(max_workers=min(10, len(doms))) as ex:
        futs = {ex.submit(_probe, d): d for d in doms}
        for f in as_completed(futs):
            rows.append(f.result())

    order = {d: i for i, d in enumerate(doms)}
    rows.sort(key=lambda r: order.get(r["domain"], 0))

    print(f"{'域名':<30}{'结论':<14}{'状态':<8}{'耗时':<8}信息")
    print("-" * 96)
    for r in rows:
        v = _verdict(r)
        info = r["url"] if r["status"] is not None else r["title"]
        if r["status"] == 202:
            info += "   [反爬/JS挑战，requests 拿不到真实内容]"
        print(f"{r['domain']:<30}{v:<14}{str(r['status']):<8}{str(r['ms']) + 'ms':<8}{info}")
    print("-" * 96)

    ok = sum(1 for r in rows if r["status"] in (200, 301, 302, 401, 403, 404))
    print(f"能连上的：{ok}/{len(rows)}")
    return rows


if __name__ == "__main__":
    run(sys.argv[1:] or None)
