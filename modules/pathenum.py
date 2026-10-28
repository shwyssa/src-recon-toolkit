# -*- coding: utf-8 -*-
"""
全量路径枚举
==================================================
和 sensitive.py 的区别：
  - sensitive 只报"敏感文件命中"（有选择地报）
  - pathenum 把**所有和兜底页不一样的响应**都列出来，交给人判断

仍然保留兜底页过滤：否则 SPA/WAF 站每条路径都返回同一个 200，列出来没意义。

输出给 report.py，写成 output/所有路径.txt
"""

import os
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.sensitive import _req, _baselines, _sig, _is_false_positive
from modules.util import decode_text, looks_like_waf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _title(text):
    m = TITLE_RE.search(text[: config.BODY_SCAN_LIMIT])
    return re.sub(r"\s+", " ", m.group(1)).strip()[:60] if m else ""


def _probe(url, path, baselines):
    target = url.rstrip("/") + "/" + path.lstrip("/")
    try:
        r = _req(target)
    except Exception:
        return None

    st = r.status_code
    text = r.text[: config.BODY_SCAN_LIMIT]

    # 反爬 / WAF 挑战页 / 明确 404 不列
    if st == 202:
        return None
    if st == 404:
        return None
    if looks_like_waf(text):
        return None
    # 跟兜底页一样的（软404/SPA首页/WAF页）不列
    if _is_false_positive(_sig(st, r.content, text), baselines):
        return None

    return {
        "url": target,
        "status": st,
        "length": len(r.content),
        "title": _title(decode_text(r)),
        "location": r.headers.get("Location", ""),
    }


def _rank_assets(assets):
    """按"值得看"排序：有指纹 > 200 > 有标题。"""
    def score(a):
        return (len(a.get("fingerprints") or []) * 10
                + (3 if a.get("status") == 200 else 0)
                + (2 if a.get("title") else 0))
    return sorted(assets, key=score, reverse=True)


def enumerate_paths(assets):
    # 没开启时返回 None（不是 []），report 里会显示"未开启"而不是"0 条"
    if not config.DO_PATH_ENUM:
        return None

    dict_path = config.DICT_PATHS_FAST if config.PATH_ENUM_FAST else config.DICT_PATHS
    if not os.path.exists(dict_path):
        print(f"[全量] 字典不存在: {dict_path}")
        return []
    with open(dict_path, "r", encoding="utf-8") as f:
        paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    paths = list(dict.fromkeys(paths))
    if not paths:
        return []

    total = len(assets)
    assets = _rank_assets(assets)[: config.PATH_ENUM_MAX_ASSETS]
    if not assets:
        return []

    print(f"[全量] {total} 个资产中，选最值得看的 {len(assets)} 个"
          f"（上限 {config.PATH_ENUM_MAX_ASSETS}，改 config.PATH_ENUM_MAX_ASSETS 可调）")
    print(f"[全量] 字典 {os.path.basename(dict_path)}：{len(paths)} 条，"
          f"按 {config.MAX_RPS} req/s 预计约 "
          f"{len(assets) * len(paths) / max(config.MAX_RPS, 1):.0f} 秒")

    print(f"[全量] 采样 {len(assets)} 个资产的兜底页基线 ...")
    baselines = {}
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = {ex.submit(_baselines, a["url"]): a["url"] for a in assets}
        for fut in as_completed(futs):
            baselines[futs[fut]] = fut.result()

    print(f"[全量] {len(assets)} 资产 × {len(paths)} 路径（按 {config.MAX_RPS} req/s）...")
    results = []
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = []
        for a in assets:
            bl = baselines.get(a["url"], set())
            for p in paths:
                futs.append(ex.submit(_probe, a["url"], p, bl))
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 500 == 0:
                print(f"    已探测 {done}/{len(futs)}")
            r = fut.result()
            if r:
                results.append(r)

    results.sort(key=lambda x: x["url"])
    print(f"[全量] 列出 {len(results)} 条和兜底页不同的响应")
    return results
