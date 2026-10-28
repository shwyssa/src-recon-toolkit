# -*- coding: utf-8 -*-
"""
CDN 判断

依据 CNAME 指向：域名 CNAME 到已知 CDN 节点域名 → 判定为"套了 CDN"。
意义：套 CDN 的资产，扫到的是边缘节点，真实 IP 需要另找。

取 CNAME 有两条路：
  1. dnspython（如果装了，最快）
  2. DoH（阿里云 / doh.pub 的 JSON 接口，不需要额外依赖）

限制：只能识别 CNAME 型 CDN；用 A 记录直连的 CDN 识别不到。
"""

import sys
import os

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import rate_limit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

# 常见 CDN 的 CNAME 后缀
CDN_SUFFIXES = (
    # 阿里云
    "kunlun.com", "kunlungr.com", "alicdn.com", "cdngslb.com", "aliyuncs.com",
    "tbcache.com", "danuoyi",
    # 网宿 / 蓝汛
    "wsdvs.com", "wscdns.com", "ccgslb.com", "lxdns.com", "cdn30.com",
    "chinacache.net", "chinanetcenter.com", "fastcdn.com", "51cdn.com",
    "cdntip.com",
    # 腾讯云
    "myqcloud.com", "qcloudcdn.com", "tencentcdn.com", "tencent-cloud.com",
    # 百度云 / 字节 / 快手 / 京东 / 360
    "bcebos.com", "baidubce.com", "bdstatic.com", "jomodns.com",
    "volccdn.com", "pstatp.com", "bytecdn.cn", "ksyuncdn.com",
    "jdcdn.com", "360cdn.com", "qhcdn.com", "qhres.com",
    # 七牛 / 又拍 / 网易
    "qiniudn.com", "qbox.me", "qncdn.com", "upaiyun.com", "126.net",
    # 国际
    "cloudfront.net", "akamaiedge.net", "akamai.net", "edgekey.net",
    "edgecastcdn.net", "fastly.net", "cloudflare.com", "cloudflare.net",
    "cdn77.org", "stackpathdns.com", "jsdelivr.net", "bootcdn.net",
    "staticfile.org", "21vianet.com.cn",
)

DOH_ENDPOINTS = ("https://dns.alidns.com/resolve", "https://doh.pub/dns-query")


def _dnspython_cname(host):
    if not HAVE_DNS:
        return ""
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=config.DNS_TIMEOUT)
        for r in ans:
            return str(r.target).lower().rstrip(".")
    except Exception:
        pass
    return ""


def _doh_cname(host):
    for url in DOH_ENDPOINTS:
        try:
            rate_limit(config.MAX_RPS)
            r = requests.get(url, params={"name": host, "type": "CNAME"},
                             headers={"User-Agent": config.USER_AGENT,
                                      "Accept": "application/dns-json"},
                             timeout=config.DNS_TIMEOUT, verify=False)
            if r.status_code != 200:
                continue
            for a in (r.json().get("Answer") or []):
                if a.get("type") == 5:
                    return str(a.get("data", "")).lower().rstrip(".")
        except Exception:
            continue
    return ""


def cname_target(host):
    """返回命中的 CDN 节点域名；不是 CDN 返回空串。"""
    if not host:
        return ""
    target = _dnspython_cname(host) or _doh_cname(host)
    if target and any(s in target for s in CDN_SUFFIXES):
        return target
    return ""


def is_cdn(host):
    return bool(cname_target(host))
