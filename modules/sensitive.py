# -*- coding: utf-8 -*-
"""
敏感文件 / 路径 / 目录探测（带置信度分级）
==================================================
降误报，但不把"有信号"的东西一起扔掉：

  高置信 (high)
    - 文件路径返回 200/206 且内容像真的（.git/config、.env 等）
    - 目录路径返回 200/301/302
  低置信 (low)
    - 文件路径返回 301/302/401/403（可能是重定向到真文件、或被保护）
    - 目录路径返回 401/403（目录可能存在，但拒绝访问）
    - 低置信一律单独输出，供人工判断，不算"命中"

兜底页过滤（多基线）：
  先发 9 条不同形态的随机假路径，采站点兜底页指纹（软404 / SPA 首页 /
  WAF 403 / 500 错误页）。任何响应和基线一致 → 丢弃（软404/兜底页）。

统计：每次扫描都会打印「探测了多少、按状态码丢多少、按兜底页丢多少、保留多少」，
方便判断到底是"站点没东西"还是"过滤器太狠"。
"""

import os
import sys
import time
import random
import string
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import rate_limit, looks_like_waf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 这些路径即使 200 也基本没意义，不报
NOISE_PATHS = {"favicon.ico", "robots.txt", "sitemap.xml", "crossdomain.xml",
               ".gitignore"}

# 判断"这是不是一个文件路径"（决定用哪套状态码规则）
_FILE_KEYS = (".git", ".svn", ".env", "backup", ".sql", ".zip", ".rar",
              ".bak", ".tar", ".gz", ".7z", ".log", "config", "phpinfo",
              ".ds_store", "dump", "database")


def _load(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def _req(url, retries=2):
    """带全局限速 + 一次重试的 GET。

    并发高时 CDN/WAF 会突然 RST 连接，单个请求偶发异常不代表"路径不存在"，
    重试一次能显著减少误判为"异常"的数量。
    """
    last = None
    for attempt in range(retries):
        rate_limit(config.MAX_RPS)
        if config.REQUEST_DELAY:
            time.sleep(config.REQUEST_DELAY)
        try:
            return requests.get(
                url, timeout=config.TIMEOUT, verify=False,
                headers={"User-Agent": config.USER_AGENT}, allow_redirects=False,
            )
        except (requests.ConnectionError, requests.Timeout) as e:
            last = e
            if attempt < retries - 1:
                time.sleep(0.6 * (attempt + 1))
    raise last


def _sig(status, content_bytes, text):
    return (status, len(content_bytes),
            hashlib.md5(text.encode("utf-8", "ignore")).hexdigest())


def _baselines(url):
    """采样多种形态的假路径，收集站点兜底页指纹集合。"""
    r = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    probes = [
        f"/__probe_{r}",
        f"/__probe_{r}.sql",
        f"/__probe_{r}.zip",
        f"/__probe_{r}.bak",
        f"/__probe_{r}.php",
        f"/.__probe_{r}",
        f"/.git/__probe_{r}",
        f"/backup__probe_{r}.sql",
        f"/__probe_{r}/",
    ]
    sigs = set()
    for p in probes:
        try:
            resp = _req(url.rstrip("/") + p)
            sigs.add(_sig(resp.status_code, resp.content,
                          resp.text[: config.BODY_SCAN_LIMIT]))
        except Exception:
            pass
    return sigs


def _is_false_positive(sig, baselines):
    if not baselines or not sig:
        return False
    if sig in baselines:
        return True
    # 同状态码 + 长度几乎一致（应对带随机时间戳的兜底页）
    for b in baselines:
        if b[0] == sig[0] and abs(b[1] - sig[1]) <= 32:
            return True
    return False


def _is_file_path(path):
    p = path.lower()
    return any(k in p for k in _FILE_KEYS)


def _interesting_content(path, body):
    low = body[:4000].lower()
    p = path.lower()
    if p.endswith(".git/config"):
        return ("repositoryformatversion" in low or "[core]" in low or "[remote" in low)
    if ".env" in p:
        return ("=" in body and
                any(k in low for k in ("key", "secret", "password", "token",
                                       "database", "app_")))
    if p.endswith(".svn/entries"):
        return ("dir" in low or "file" in low)
    if p in ("phpinfo.php", "phpinfo"):
        return ("php version" in low or "phpinfo" in low)
    return True


def _probe(url, path, baselines):
    """返回 (结果dict|None, 丢弃原因|None)。"""
    if os.path.basename(path).lower() in NOISE_PATHS:
        return None, "noise"

    target = url.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = _req(target)
    except Exception:
        return None, "error"

    is_file = _is_file_path(path)
    st = r.status_code
    text = r.text[: config.BODY_SCAN_LIMIT]

    # 202 / WAF 挑战页基本等于"站点的反爬"，拿不到真实内容
    if st == 202:
        return None, "antibot"
    if looks_like_waf(text):
        return None, "antibot"

    # 状态码分级
    if is_file:
        if st in (200, 206):
            conf = "high"
        elif st in (301, 302, 401, 403):
            conf = "low"
        else:
            return None, "status"
    else:
        if st in (200, 301, 302):
            conf = "high"
        elif st in (401, 403):
            conf = "low"
        else:
            return None, "status"

    # 兜底页过滤（高低置信都要过）
    sig = _sig(st, r.content, text)
    if _is_false_positive(sig, baselines):
        return None, "baseline"

    # 高置信的文件还要过内容校验
    if conf == "high" and is_file and not _interesting_content(path, text):
        return None, "content"

    return {
        "url": target,
        "status": st,
        "length": len(r.content),
        "type": "敏感文件" if is_file else "目录",
        "conf": conf,
    }, None


def sensitive_scan(alive_assets):
    if not config.DO_SENSITIVE:
        print("[敏感] 已跳过（config.DO_SENSITIVE=False）")
        return []

    paths = _load(config.DICT_SENSITIVE)
    if config.DO_DIR_BRUTE:
        paths += _load(config.DICT_DIRS)
    paths = list(dict.fromkeys(paths))

    # 1) 多基线
    print(f"[敏感] 采样 {len(alive_assets)} 个资产的兜底页基线 ...")
    baselines = {}
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = {ex.submit(_baselines, a["url"]): a["url"] for a in alive_assets}
        for fut in as_completed(futs):
            baselines[futs[fut]] = fut.result()

    # 2) 探测
    print(f"[敏感] {len(alive_assets)} 资产 × {len(paths)} 路径 ...")
    findings = []
    drop = {"status": 0, "baseline": 0, "content": 0, "noise": 0,
            "error": 0, "antibot": 0}
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = []
        for a in alive_assets:
            bl = baselines.get(a["url"], set())
            for p in paths:
                futs.append(ex.submit(_probe, a["url"], p, bl))
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 2000 == 0:
                print(f"    已探测 {done}/{len(futs)}")
            res, reason = fut.result()
            if res:
                findings.append(res)
            elif reason in drop:
                drop[reason] += 1

    high = sum(1 for f in findings if f["conf"] == "high")
    low = sum(1 for f in findings if f["conf"] == "low")
    total = sum(drop.values()) + len(findings)
    print(f"[敏感] 共探测 {total} 次：高置信 {high}，低置信 {low}，"
          f"丢弃[状态码 {drop['status']} / 兜底页 {drop['baseline']} / "
          f"内容 {drop['content']} / 噪声 {drop['noise']} / "
          f"异常 {drop['error']} / 反爬202 {drop['antibot']}]")
    if drop["antibot"] and drop["antibot"] * 2 > total:
        print("[敏感] ⚠ 大量 202 响应 → 站点疑似反爬/JS挑战，"
              "requests 拿不到真实内容，建议改用浏览器（Playwright）")
    print(f"[敏感] 兜底页基线：{sum(len(v) for v in baselines.values())} 条指纹"
          f"（可判断站点是否对任意路径回同一页）")

    findings.sort(key=lambda x: (x["conf"] != "high", x["url"]))
    return findings
