# -*- coding: utf-8 -*-
"""
手工测试清单生成器
==================================================
把"扫描结果"变成"你该去点什么"。

关键：登录/注册/后台入口**不靠首页链接**，而是主动探测常见路径
（很多站点的登录页压根不在首页挂链接，或者在 JS 里跳转）。

输出 output/手工测试清单.md：
  - 登录/注册/后台/接口 入口（主动探测 + 首页链接，双保险）
  - 带参数的 URL（越权候选，按 ID 类参数优先）
  - 表单、JS 接口、建议测试项
"""

import os
import re
import sys
from urllib.parse import urljoin, urlparse

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from modules.util import rate_limit, looks_like_waf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LINK_RE = re.compile(r"""(?:href|action)\s*=\s*["']([^"']+)["']""", re.I)
SCRIPT_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
JS_PATH_RE = re.compile(r"""["'`]((?:/|https?://)[A-Za-z0-9_\-./?=&%:]{3,160})["'`]""")
FORM_RE = re.compile(r"<form([^>]*)>", re.I)
ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.I)
METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp")

# 主动探测这些路径，判断是不是登录/注册/后台
ENTRY_PROBE = ["login", "login/", "sso/login", "passport/login", "cas/login",
               "user/login", "admin", "admin/login", "manage", "register",
               "signup", "reg", "enroll", "baoming", "apply"]

# 这些词出现在标题/正文里，说明是登录/注册页
ENTRY_SIGNALS = ("登录", "登陆", "login", "signin", "sign in", "password",
                 "密码", "注册", "register", "signup", "用户名")

ID_PARAMS = {"id", "uid", "userid", "user_id", "orderid", "order_id", "fileid",
             "file_id", "itemid", "docid", "pid", "cid", "sid", "tid", "no",
             "code", "key", "number", "account", "mobile", "phone", "email",
             "addressid", "address_id", "roleid", "role_id", "token"}

ENTRY_TOKENS = {
    "登录": {"login", "signin", "passport", "sso"},
    "注册": {"register", "signup", "reg", "enroll", "baoming", "apply"},
    "后台": {"admin", "manage", "manager", "console", "system", "backend",
             "houtai", "guanli"},
    "接口": {"api", "rest", "graphql", "openapi"},
    "上传/下载": {"upload", "download", "export", "import", "attachment"},
}


def _tokens(path):
    return {t for t in re.split(r"[/_\-\.]+", (path or "").lower()) if t}


def _is_static(path):
    return (path or "").lower().endswith(_STATIC_EXT)


def _registrable(host):
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _same_site(host, root):
    h = (host or "").lower()
    return h == root or h.endswith("." + root)


def _title(text):
    m = TITLE_RE.search((text or "")[: config.BODY_SCAN_LIMIT])
    return re.sub(r"\s+", " ", m.group(1)).strip()[:60] if m else ""


def _fetch(url):
    rate_limit(config.MAX_RPS)
    return requests.get(url, timeout=config.TIMEOUT, verify=False,
                        headers={"User-Agent": config.USER_AGENT},
                        allow_redirects=True)


def _idlike(url):
    q = (urlparse(url).query or "").lower()
    for pair in q.split("&"):
        if "=" not in pair:
            continue
        name = pair.split("=", 1)[0]
        if name in ID_PARAMS or name.endswith("id") or name.endswith("_id"):
            return True
    return False


def _probe_entries(base):
    """主动探测常见登录/注册/后台路径（不依赖首页是否有链接）。"""
    found = []
    for p in ENTRY_PROBE:
        u = base.rstrip("/") + "/" + p
        try:
            r = _fetch(u)
        except Exception:
            continue
        if r.status_code not in (200, 301, 302):
            continue
        text = r.text or ""
        if looks_like_waf(text):
            continue
        t = _title(text)
        low = (t + " " + text[:2000]).lower()
        if not any(k in low for k in ENTRY_SIGNALS):
            continue
        found.append((u, r.status_code, t))
    # 去重（/login 和 /login/ 算一条）
    seen, out = set(), []
    for u, st, t in found:
        key = u.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        out.append((u, st, t))
    return out


def _analyze_asset(asset):
    url = asset["url"]
    try:
        r = _fetch(url)
    except Exception:
        return None
    if r.status_code != 200 or not r.text:
        return None

    base = r.url
    root = _registrable(urlparse(base).hostname or "")
    html = r.text

    groups = {k: set() for k in ENTRY_TOKENS}

    links = set()
    for m in LINK_RE.finditer(html):
        links.add(urljoin(base, m.group(1)))

    forms = []
    for m in FORM_RE.finditer(html):
        attrs = m.group(1)
        a = ACTION_RE.search(attrs)
        me = METHOD_RE.search(attrs)
        forms.append((urljoin(base, a.group(1)) if a else base,
                      (me.group(1) if me else "GET").upper()))

    js_paths = set()
    for s in SCRIPT_RE.findall(html)[:6]:
        ju = urljoin(base, s)
        try:
            rj = _fetch(ju)
            if rj.status_code == 200 and len(rj.content) < 2 * 1024 * 1024:
                for mm in JS_PATH_RE.finditer(rj.text):
                    v = mm.group(1)
                    if v.startswith("http") or v.startswith("//") or len(v) < 4 or _is_static(v):
                        continue
                    js_paths.add(v)
        except Exception:
            continue

    # 同站再抓 3 页补链接
    same = [u for u in links
            if (urlparse(u).hostname or "").lower() == (urlparse(base).hostname or "").lower()][:3]
    for u in same:
        try:
            rr = _fetch(u)
            if rr.status_code == 200:
                for m in LINK_RE.finditer(rr.text):
                    links.add(urljoin(u, m.group(1)))
        except Exception:
            continue

    clean = set()
    for u in links:
        p = urlparse(u)
        if not p.hostname or not _same_site(p.hostname, root):
            continue
        if _is_static(p.path):
            continue
        clean.add(u)

    with_param = []
    for u in clean:
        p = urlparse(u)
        toks = _tokens(p.path)
        for g, ts in ENTRY_TOKENS.items():
            if toks & ts:
                groups[g].add(u)
        if p.query:
            with_param.append(u)

    # 主动探测登录/注册/后台
    entries = _probe_entries(base)
    for u, st, t in entries:
        toks = _tokens(urlparse(u).path)
        for g, ts in ENTRY_TOKENS.items():
            if toks & ts:
                groups[g].add(u)

    with_param.sort(key=lambda u: -1 if _idlike(u) else 1)

    score = (len(with_param) * 2 + len(forms) * 2 + len(js_paths)
             + len(groups["登录"]) * 3 + len(groups["注册"]) * 3
             + len(groups["后台"]) * 2)
    return {"url": base, "groups": groups, "with_param": with_param,
            "forms": forms, "js_paths": js_paths, "entries": entries,
            "score": score}


def build_checklists(assets):
    if not getattr(config, "DO_MANUAL", True):
        return None
    assets = assets[: config.MANUAL_MAX_ASSETS]
    if not assets:
        return None

    print(f"[清单] 分析 {len(assets)} 个资产，生成手工测试清单 ...")
    infos = []
    for a in assets:
        info = _analyze_asset(a)
        if info:
            infos.append(info)
    if not infos:
        print("[清单] 没有可用结果")
        return None

    infos.sort(key=lambda x: -x["score"])

    out = config.OUTPUT_DIR
    if not os.path.exists(out):
        os.makedirs(out)
    path = os.path.join(out, "手工测试清单.md")

    with open(path, "w", encoding="utf-8") as f:
        f.write("# 手工测试清单\n\n")
        f.write("> 工具只负责找门，推门得靠人。按评分从高到低排。\n\n")
        for i, info in enumerate(infos, 1):
            f.write(f"## {i}. {info['url']}（评分 {info['score']}）\n\n")

            if info["entries"]:
                f.write("**主动探测到的入口**\n")
                for u, st, t in info["entries"]:
                    f.write(f"- [{st}] {u}" + (f"  （{t}）" if t else "") + "\n")
                f.write("\n")

            for g in ("登录", "注册", "后台", "接口", "上传/下载"):
                extra = info["groups"][g] - {e[0] for e in info["entries"]}
                if extra:
                    f.write(f"**{g}入口（首页链接发现）**\n")
                    for u in sorted(extra)[:6]:
                        f.write(f"- {u}\n")
                    f.write("\n")

            if info["with_param"]:
                f.write("**带参数的 URL（越权候选，优先改 ID）**\n")
                for u in info["with_param"][:12]:
                    mark = " ⚠️ID类" if _idlike(u) else ""
                    f.write(f"- {u}{mark}\n")
                f.write("\n")

            if info["forms"]:
                f.write("**表单**\n")
                for a, m in info["forms"][:8]:
                    f.write(f"- {m} {a}\n")
                f.write("\n")

            if info["js_paths"]:
                f.write("**JS 里的接口**\n")
                for u in sorted(info["js_paths"])[:15]:
                    f.write(f"- {u}\n")
                f.write("\n")

            f.write("**建议测什么**\n")
            f.write("- [ ] 带 ⚠️ID类 的 URL，把 ID 改成相邻值，看是否返回别人的数据\n")
            f.write("- [ ] 去掉 Cookie 再请求一次，看是否仍返回数据\n")
            f.write("- [ ] 注册两个账号，用 A 的会话请求 B 的对象\n")
            f.write("- [ ] 数量/价格/优惠券改成负数或 0.01\n")
            f.write("\n---\n\n")

    print(f"[清单] 已生成：{path}")
    return path
