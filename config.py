# -*- coding: utf-8 -*-
"""
全局配置 —— 改这里就行，别动 modules/ 里的代码。
所有路径都相对于本脚本所在目录（信息收集/）。
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ============ 输入 ============
# 种子域名，一行一个（去企查查抓"ICP备案域名列表"，或直接填 SRC scope 域名）
DOMAINS_FILE = os.path.join(BASE_DIR, "domains.txt")

# ============ 字典路径 ============
DICT_SUBDOMAIN   = os.path.join(BASE_DIR, "dict", "subdomains.txt")
DICT_SENSITIVE   = os.path.join(BASE_DIR, "dict", "sensitive_paths.txt")
DICT_DIRS        = os.path.join(BASE_DIR, "dict", "dirs.txt")
DICT_PATHS       = os.path.join(BASE_DIR, "dict", "paths.txt")
DICT_PATHS_FAST  = os.path.join(BASE_DIR, "dict", "paths_fast.txt")
DICT_FINGERPRINT = os.path.join(BASE_DIR, "dict", "fingerprints.json")

# ============ 输出 ============
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# ============ 并发与超时 ============
THREADS_DNS   = 100   # 子域名爆破/DNS 解析线程
THREADS_HTTP  = 5     # HTTP 线程，建议 <= MAX_RPS（并发过高会被 CDN/WAF 重置连接）
TIMEOUT       = 8     # 单次 HTTP 请求超时（秒）
DNS_TIMEOUT   = 3     # 单次 DNS 解析超时（秒）
PORT_TIMEOUT  = 2     # 端口探测超时（秒）
PRECHECK_TIMEOUT = 8  # 预检单次请求超时（秒）

# 全局限速：每秒最多发多少个 HTTP 请求（不管开多少线程都受这个限制）
# 目标小/单 IP / 被 WAF 封过 → 调成 2~3；大厂集群可以到 10~20
MAX_RPS = 5

# 每次请求后额外停顿（秒）。MAX_RPS 已经限速了，这个一般留 0
REQUEST_DELAY = 0.0

# ============ 探测行为开关 ============
DO_CERT_TRANSPARENCY = True   # 证书透明日志（crt.sh），能翻出字典里没有的子域
DO_CERTSPOTTER       = True   # Cert Spotter 证书源（crt.sh 的补充）
DO_HACKERTARGET      = True   # HackerTarget 免费子域接口（有限速，失败自动跳过）
DO_CDN_CHECK         = True   # CNAME 判断是否套了 CDN
DO_CRAWL             = True   # 首页爬链接（能发现字典猜不到的子域/独立域名，但有额外请求）
DO_PORT_SCAN         = True   # 对存活 IP 做常见端口扫描
DO_FAVICON_HASH      = True   # 算 favicon mmh3 哈希（FOFA icon_hash 可反查同款系统）
DO_SENSITIVE         = True   # 敏感文件/路径探测
DO_PATH_ENUM         = False  # 全量路径枚举（列出所有和兜底页不同的响应；慢，默认关）
PATH_ENUM_FAST       = False  # 用精简字典（paths_fast.txt，约 72 条高价值路径）
PATH_ENUM_MAX_ASSETS = 10     # 全量枚举最多扫几个资产（按"有没有指纹/是否200"排序后取前 N）
DO_MANUAL            = True   # 生成《手工测试清单》（把扫描结果变成"该点哪里"）
MANUAL_MAX_ASSETS    = 10     # 清单最多分析几个资产
DO_DIR_BRUTE         = False  # 目录爆破（大字典、吵、慢，默认关；只在重点资产手动开）

# 端口扫描列表
SCAN_PORTS = [
    80, 443, 8000, 8001, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9090,
    7001, 7002, 9043,             # WebLogic / 应用服务器
    9200, 9300,                   # Elasticsearch
    6379,                         # Redis
    27017, 27018,                 # MongoDB
    3306, 5432,                   # MySQL / PostgreSQL
    2375, 2376,                   # Docker
    4848,                         # GlassFish
    888, 8180,                    # 常见管理口
]

# ============ 请求头 ============
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# 指纹匹配时，正文最多取前多少个字符（防止大页面拖慢内存）
BODY_SCAN_LIMIT = 200000

# 命中状态码：这些状态码视为"路径存在"
SENSITIVE_STATUS = {200, 301, 302, 403, 401, 405, 500, 503}
