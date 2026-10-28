# -*- coding: utf-8 -*-
"""
存活探测 + 端口扫描
  输入: 子域名列表 [{"domain","ip","ips"}]
  输出: 存活资产 [{"domain","ip","scheme","url","status","title","server","ports", ...}]
"""

import sys
import os
import re
import socket
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules import cdn
from modules.util import decode_text, rate_limit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    return ""


def _probe_url(url, domain, ip):
    """对单个 URL 做 HTTP 探测。"""
    rate_limit(config.MAX_RPS)
    if config.REQUEST_DELAY:
        time.sleep(config.REQUEST_DELAY)
    try:
        r = requests.get(
            url, timeout=config.TIMEOUT, verify=False,
            headers={"User-Agent": config.USER_AGENT}, allow_redirects=True,
        )
        title = _get_title(decode_text(r)[: config.BODY_SCAN_LIMIT])
        return {
            "domain": domain, "ip": ip, "scheme": url.split(":")[0],
            "url": url, "status": r.status_code,
            "title": title, "server": r.headers.get("Server", ""),
        }
    except Exception:
        return None


def _port_open(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(config.PORT_TIMEOUT)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def _scan_ports(ip):
    if not config.DO_PORT_SCAN:
        return []
    open_ports = []
    for p in config.SCAN_PORTS:
        if _port_open(ip, p):
            open_ports.append(p)
    return open_ports


def alive_check(subdomains):
    """subdomains: [{"domain","ip","ips"}]"""
    # 生成探测目标：每个 (domain, ip) 组合，http/https 都试
    targets = []
    for s in subdomains:
        d, ip = s["domain"], s["ip"]
        for scheme in ("http", "https"):
            targets.append((f"{scheme}://{d}", d, ip))

    print(f"[存活] 开始探测 {len(targets)} 个 URL ...")
    alive = []
    with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
        futs = {ex.submit(_probe_url, u, d, ip): (u, d, ip) for (u, d, ip) in targets}
        done = 0
        for fut in as_completed(futs):
            r = fut.result()
            done += 1
            if done % 500 == 0:
                print(f"    已探测 {done}/{len(targets)}")
            if r:
                alive.append(r)

    # 按域名去重：同一域名 http/https 都活，优先保留 https
    best = {}
    for a in alive:
        k = (a["domain"], a["ip"])
        cur = best.get(k)
        if cur is None or (a["scheme"] == "https" and cur["scheme"] == "http"):
            best[k] = a
    alive = list(best.values())

    # 端口扫描（按 IP 去重）
    if config.DO_PORT_SCAN:
        print(f"[端口] 对 {len({a['ip'] for a in alive})} 个唯一 IP 做常见端口扫描 ...")
        ip_ports = {}
        with ThreadPoolExecutor(max_workers=config.THREADS_HTTP) as ex:
            futs = {ex.submit(_scan_ports, ip): ip for ip in {a["ip"] for a in alive}}
            for fut in as_completed(futs):
                ip = futs[fut]
                try:
                    ip_ports[ip] = fut.result()
                except Exception:
                    ip_ports[ip] = []
        for a in alive:
            a["ports"] = ip_ports.get(a["ip"], [])

    # CDN 判断（按域名去重，CNAME 指向已知 CDN 则标记）
    if getattr(config, "DO_CDN_CHECK", True):
        hosts = {urlparse(a["url"]).hostname for a in alive if a.get("url")}
        hosts.discard(None)
        cdn_map = {}
        if hosts:
            with ThreadPoolExecutor(max_workers=min(20, len(hosts))) as ex:
                futs = {ex.submit(cdn.cname_target, h): h for h in hosts}
                for fut in as_completed(futs):
                    cdn_map[futs[fut]] = fut.result()
        for a in alive:
            a["cdn"] = cdn_map.get(urlparse(a["url"]).hostname, "")
        n_cdn = sum(1 for a in alive if a.get("cdn"))
        if n_cdn:
            print(f"[CDN] 识别到 {n_cdn} 个资产套了 CDN（扫到的是边缘节点）")

    alive.sort(key=lambda x: (x["domain"], x["ip"]))
    print(f"[存活] 存活资产 {len(alive)} 个")
    return alive
