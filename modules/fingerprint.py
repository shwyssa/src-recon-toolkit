# -*- coding: utf-8 -*-
"""
指纹识别
  基于 dict/fingerprints.json 对存活资产做标题/正文/响应头/Cookie/端口 匹配。
  输出: 带 "fingerprints" 字段的资产列表。
"""

import sys
import os
import re
import json
import base64
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import decode_text, rate_limit, murmur3_32

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_fingerprints():
    if not os.path.exists(config.DICT_FINGERPRINT):
        print(f"[!] 指纹库不存在: {config.DICT_FINGERPRINT}")
        return []
    with open(config.DICT_FINGERPRINT, "r", encoding="utf-8") as f:
        return json.load(f)


_HIT_CACHE = {}


def _hit(keyword, text):
    if not keyword or not text:
        return False
    if keyword.isascii():
        # ASCII 关键字必须整词匹配，否则 "nacos" 会命中 base64 里的 "...aCosn..."
        # 中文关键字（如"用友"）没有词边界概念，仍用子串匹配。
        pat = _HIT_CACHE.get(keyword)
        if pat is None:
            pat = re.compile(
                r"(?<![A-Za-z0-9])" + re.escape(keyword) + r"(?![A-Za-z0-9])", re.I)
            _HIT_CACHE[keyword] = pat
        return pat.search(text) is not None
    return keyword.lower() in text.lower()


def match_fingerprints(fp_list, title, headers_text, cookie_names, body, ports):
    """返回命中的指纹名列表。"""
    hits = []
    for fp in fp_list:
        matched = False
        if any(_hit(k, title) for k in fp.get("title", [])):
            matched = True
        if any(_hit(k, body) for k in fp.get("body", [])):
            matched = True
        if any(_hit(k, headers_text) for k in fp.get("header", [])):
            matched = True
        if any(_hit(k, cookie_names) for k in fp.get("cookie", [])):
            matched = True
        # 注意：端口开放不再作为指纹命中依据。
        # 一个端口开着（如 8080）不代表上面就是 Tomcat/Jenkins，
        # 具体是什么服务交给 service_probe.py 去识别。
        if matched:
            hits.append(fp)
    return hits


_ICON_TAG = re.compile(r"<link[^>]*>", re.I)
_HREF_ATTR = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)


def _favicon_from_html(body, base):
    for tag in _ICON_TAG.findall(body):
        if "icon" not in tag.lower():
            continue
        m = _HREF_ATTR.search(tag)
        if m:
            return urljoin(base, m.group(1))
    return None


def _favicon_hash(url, body=""):
    """算 favicon 的 mmh3 哈希（等同 FOFA 的 icon_hash），用于反查同款系统。

    优先用页面 <link rel="icon"> 指向的地址，其次退回 /favicon.ico。
    """
    if not config.DO_FAVICON_HASH:
        return None
    candidates = []
    if body:
        link = _favicon_from_html(body, url)
        if link:
            candidates.append(link)
    candidates.append(url.rstrip("/") + "/favicon.ico")
    for u in candidates:
        try:
            rate_limit(config.MAX_RPS)
            r = requests.get(u, timeout=config.TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT},
                             allow_redirects=True)
            if r.status_code == 200 and r.content:
                return murmur3_32(base64.b64encode(r.content))
        except Exception:
            continue
    return None


def _fetch_and_match(asset, fp_list):
    """拉取页面，做指纹匹配。"""
    url = asset["url"]
    ports = asset.get("ports", [])
    body = ""
    rate_limit(config.MAX_RPS)
    try:
        r = requests.get(
            url, timeout=config.TIMEOUT, verify=False,
            headers={"User-Agent": config.USER_AGENT}, allow_redirects=True,
        )
        title = asset.get("title", "")
        body = decode_text(r)[: config.BODY_SCAN_LIMIT]
        # 拼响应头文本 + cookie 名
        headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        cookie_names = " ".join(r.cookies.keys())
        hits = match_fingerprints(fp_list, title, headers_text, cookie_names, body, ports)
        asset["fingerprints"] = hits
    except Exception:
        asset["fingerprints"] = []
    asset["icon_hash"] = _favicon_hash(url, body)
    return asset


def fingerprint(alive_assets):
    fp_list = load_fingerprints()
    if not fp_list:
        return alive_assets
    print(f"[指纹] 加载指纹库 {len(fp_list)} 条，开始识别 ...")
    results = []
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = [ex.submit(_fetch_and_match, a, fp_list) for a in alive_assets]
        done = 0
        for fut in as_completed(futs):
            done += 1
            if done % 100 == 0:
                print(f"    已识别 {done}/{len(alive_assets)}")
            results.append(fut.result())

    matched = [a for a in results if a.get("fingerprints")]
    print(f"[指纹] 命中指纹的资产 {len(matched)} 个")
    return results
