# -*- coding: utf-8 -*-
"""
子域名枚举
  1. 读入种子域名
  2. 字典爆破 + DNS 解析
  3. 证书透明日志（crt.sh）
  4. 去重、解析出 IP
输出: list[dict] -> {"domain", "ip"}
"""

import sys
import os
import re
import socket
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import rate_limit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 优先 dnspython，速度更快、超时更可靠；没有则退回 socket
try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


def _resolve(host):
    """解析 A 记录，返回 IP 列表（可能多个）。"""
    ips = []
    if HAVE_DNS:
        try:
            ans = dns.resolver.resolve(host, "A", lifetime=config.DNS_TIMEOUT)
            ips = [str(r) for r in ans]
        except Exception:
            pass
    else:
        try:
            # 注意：这里不要用 socket.setdefaulttimeout()——它是进程全局的，
            # 100 个线程同时改会互相覆盖，导致解析超时错乱（真实 bug）。
            # 没装 dnspython 时会慢一点，但结果是对的；建议 pip install dnspython。
            infos = socket.getaddrinfo(host, None)
            ips = list({i[4][0] for i in infos})
        except Exception:
            pass
    return ips


def _crt_sh(domain):
    """证书透明日志（crt.sh），返回该域名下出现过的子域集合。"""
    subs = set()
    if not config.DO_CERT_TRANSPARENCY:
        return subs
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print("    正在查证书透明日志（crt.sh 经常较慢，最多等 15 秒）...")
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            print(f"    crt.sh 返回 {r.status_code}，跳过")
            return subs
        for e in r.json():
            for name in str(e.get("name_value", "")).split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name and name.endswith("." + domain):
                    subs.add(name)
    except Exception as e:
        # crt.sh 偶发超时/503，忽略即可
        print(f"    crt.sh 失败（{type(e).__name__}），跳过")
    return subs


def _certspotter(domain):
    """Cert Spotter（SSLMate）证书透明源，crt.sh 的补充。"""
    subs = set()
    if not getattr(config, "DO_CERTSPOTTER", True):
        return subs
    try:
        rate_limit(config.MAX_RPS)
        r = requests.get(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true",
                    "expand": "dns_names"},
            timeout=15, headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            return subs
        for item in r.json():
            for name in item.get("dns_names") or []:
                n = str(name).strip().lstrip("*.").lower()
                if n and n.endswith("." + domain):
                    subs.add(n)
    except Exception:
        pass
    return subs


def _hackertarget(domain):
    """HackerTarget 免费子域接口（有限速，失败就跳过）。"""
    subs = set()
    if not getattr(config, "DO_HACKERTARGET", True):
        return subs
    try:
        rate_limit(config.MAX_RPS)
        r = requests.get("https://api.hackertarget.com/hostsearch/",
                         params={"q": domain}, timeout=15,
                         headers={"User-Agent": config.USER_AGENT})
        if r.status_code != 200:
            return subs
        body = r.text.strip()
        if not body or "error" in body[:40].lower() or "API count" in body:
            return subs
        for line in body.splitlines():
            host = line.split(",")[0].strip().lower()
            if host and host.endswith("." + domain):
                subs.add(host)
    except Exception:
        pass
    return subs


def _load_domains(domains=None):
    if domains:
        src = list(domains)
    else:
        path = config.DOMAINS_FILE
        if not os.path.exists(path):
            print(f"[!] 找不到输入文件 {path}，请在 domains.txt 里填种子域名（一行一个）")
            return []
        with open(path, "r", encoding="utf-8") as f:
            src = f.readlines()
    doms = []
    for line in src:
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = line.split("/")[0].split(":")[0]
        line = line.replace("http://", "").replace("https://", "").strip()
        if "." in line:
            doms.append(line)
    return doms


def _load_wordlist():
    if not os.path.exists(config.DICT_SUBDOMAIN):
        return []
    with open(config.DICT_SUBDOMAIN, "r", encoding="utf-8") as f:
        return [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]


_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)

# 首页外链里这些是 CDN/统计/社交/第三方 SaaS，不是目标业务站，过滤掉
_EXTERNAL_NOISE = ("w3.org", "google", "gstatic", "baidu", "qq.com", "weibo",
                   "sina", "bootstrapcdn", "jsdelivr", "cdnjs", "alicdn",
                   "aliyun", "gtimg", "byteimg", "bdstatic", "360.cn",
                   "doubleclick", "facebook", "twitter", "youtube", "bilibili",
                   "miit.gov.cn", "cnzz", "wanwang", "udesk", "tmall",
                   "taobao", "alipay", "umeng", "51.la", "tanx", "linkedin",
                   "jquery", "bootstrap", "fontawesome", "unpkg", "efty")


def _crawl(domain):
    """爬官网首页（+ 同站若干页面），返回 (同站子域集合, 外部业务域名集合)。

    这一步专治"字典猜不到"的情况：商城/子站如果是独立域名，
    官网首页一般会有链接，爬一遍就能发现。
    """
    subs, ext = set(), set()
    if not getattr(config, "DO_CRAWL", True):
        return subs, ext

    roots = [f"https://www.{domain}", f"https://{domain}", f"http://www.{domain}"]
    print("    正在爬首页（取子域/外链域名，较慢）...")
    pages = []
    for u in roots:
        try:
            rate_limit(config.MAX_RPS)
            r = requests.get(u, timeout=config.TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT},
                             allow_redirects=True)
            if r.status_code == 200 and r.text:
                pages.append((r.url, r.text))
                break
        except Exception:
            continue
    if not pages:
        print("    首页不可达，跳过爬取")
        return subs, ext

    links = []
    for base, html in pages:
        for m in _LINK_RE.finditer(html):
            links.append(urljoin(base, m.group(1)))

    # 再抓最多 5 个同站页面，继续收集链接
    same = [u for u in links
            if urlparse(u).hostname and urlparse(u).hostname.lower().endswith(domain)][:5]
    for u in same:
        try:
            rate_limit(config.MAX_RPS)
            r = requests.get(u, timeout=config.TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT})
            if r.status_code == 200:
                for m in _LINK_RE.finditer(r.text):
                    links.append(urljoin(u, m.group(1)))
        except Exception:
            continue

    for full in links:
        if not full.startswith("http"):
            continue
        h = (urlparse(full).hostname or "").strip().lower()
        if not h:
            continue
        if h == domain or h.endswith("." + domain):
            subs.add(h)
        elif "." in h and not any(n in h for n in _EXTERNAL_NOISE):
            ext.add(h)
    return subs, ext


def enumerate_subdomains(domains=None):
    domains = _load_domains(domains)
    if not domains:
        return []

    words = _load_wordlist()
    candidates = set(domains)  # 根域名本身也算资产
    all_results = {}
    all_external = set()

    for domain in domains:
        print(f"\n[子域名] 处理 {domain}")

        # 0) 首页爬链接：能发现字典里没有的子域，以及"商城在独立域名"的情况
        crawled, external = _crawl(domain)
        if crawled:
            candidates |= crawled
            print(f"    首页爬取到 {len(crawled)} 个子域")
        if external:
            all_external |= external
            print("    首页外链到这些域名（可能是商城/子站，需人工确认 scope）:")
            for h in sorted(external)[:10]:
                print(f"      - {h}")

        # 1) 证书透明（crt.sh + Cert Spotter）
        ct = _crt_sh(domain)
        ct |= _certspotter(domain)
        candidates |= ct
        if ct:
            print(f"    证书透明日志拿到 {len(ct)} 个子域")

        # 1.5) HackerTarget 补充
        ht = _hackertarget(domain)
        if ht - candidates:
            print(f"    HackerTarget 补充 {len(ht - candidates)} 个")
        candidates |= ht

        # 2) 字典爆破
        for w in words:
            candidates.add(f"{w}.{domain}")

    if all_external:
        if not os.path.exists(config.OUTPUT_DIR):
            os.makedirs(config.OUTPUT_DIR)
        p = os.path.join(config.OUTPUT_DIR, "crawled_domains.txt")
        with open(p, "w", encoding="utf-8") as f:
            for h in sorted(all_external):
                f.write(h + "\n")
        print(f"[子域名] 首页发现的疑似业务域名已存到 {p}（确认 scope 后可加进 domains.txt 再扫）")

    # 3) 并发解析
    print(f"[子域名] 共 {len(candidates)} 个候选，开始解析...")
    results = {}
    with ThreadPoolExecutor(max_workers=config.THREADS_DNS) as ex:
        futs = {ex.submit(_resolve, c): c for c in candidates}
        for fut in as_completed(futs):
            c = futs[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            if ips:
                results[c] = ips
    all_results = [{"domain": d, "ip": ips[0], "ips": ips} for d, ips in results.items()]
    all_results.sort(key=lambda x: x["domain"])
    print(f"[子域名] 解析成功 {len(all_results)} 个")
    return all_results
