# -*- coding: utf-8 -*-
"""
通用小工具
"""

import base64
import time
import threading

_rl_lock = threading.Lock()
_rl_next = [0.0]      # 下一个允许发请求的时间点


def rate_limit(rps):
    """全局限速：不管开多少线程，所有请求都排队，保证每秒不超过 rps 个。

    用法：在真正发 HTTP 请求前调用 rate_limit(config.MAX_RPS)。
    多线程下是安全的（只短暂持锁，睡眠在锁外）。
    """
    if not rps or rps <= 0:
        return
    interval = 1.0 / float(rps)
    with _rl_lock:
        now = time.time()
        if _rl_next[0] < now:
            _rl_next[0] = now
        wait = _rl_next[0] - now
        _rl_next[0] += interval
    if wait > 0:
        time.sleep(wait)


def decode_text(resp):
    """稳妥解码响应文本（中文站点常见 UTF-8 / GBK 混用）。

    requests 在响应头没有 charset 时会按 HTTP 规范默认 ISO-8859-1，
    导致中文标题变成乱码（如 ç½ç«...）。这里改成先试 UTF-8 再试 GB18030。
    """
    enc = (resp.encoding or "").lower()
    if enc in ("", "iso-8859-1", "latin-1"):
        for c in ("utf-8", "gb18030"):
            try:
                return resp.content.decode(c)
            except UnicodeDecodeError:
                continue
    try:
        return resp.text
    except Exception:
        return resp.content.decode("utf-8", "ignore")


# 常见 WAF / 反爬挑战页的正文特征（只用高置信特征，避免误杀正常登录页）
_WAF_MARKERS = (
    "aliyun_waf", "acw_sc__v2", "safedog", "yunsuo_session", "360wzws",
    "waf_aa", "waf_bb", "瑞数", "欢迎登录阿里云",
)


def looks_like_waf(text):
    """判断响应是不是 WAF/反爬挑战页（不是真实业务页）。"""
    if not text:
        return False
    low = text[:30000].lower()
    return any(m in low for m in _WAF_MARKERS)


def murmur3_32(data, seed=0):
    """MurmurHash3 x86_32（纯 Python 实现）。

    FOFA 的 icon_hash 算法就是：murmur3_32(base64(favicon 字节))，
    结果带符号（32 位有符号整数）。
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC

    for i in range(0, rounded_end, 4):
        k1 = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8) | \
             ((data[i + 2] & 0xFF) << 16) | ((data[i + 3] & 0xFF) << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 ^= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 ^= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1
