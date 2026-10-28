# -*- coding: utf-8 -*-
"""
service_probe.py —— 高危端口服务指纹探测（只读、不登录、不爆破）
==================================================
对开放的数据库/中间件端口做一次"服务自报家门"的读取，用来判断
"端口开着，但到底是什么服务、什么版本"。

  MySQL(3306)        ：读服务器主动发来的握手包，拿版本号（完全被动）
  Redis(6379)        ：发 PING，判断是否未授权（PING 是只读命令）
  Elasticsearch(9200)：GET / 看是否未授权
  Docker(2375)       ：GET /version
  MongoDB(27017)     ：Mongo 要客户端先发起，无法被动读 banner，只报 TCP 开放

不做的事：不登录、不猜口令、不执行写操作。

用法：
  python service_probe.py example.com:3306
  python service_probe.py 1.2.3.4:6379 1.2.3.4:9200
  python service_probe.py --from-alive output/alive.txt
"""

import os
import sys
import socket

import requests
import urllib3

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

TIMEOUT = 5


def _connect(host, port):
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    return s


def probe_mysql(host, port):
    """读 MySQL 服务器握手包（服务器主动发，无需认证）。"""
    try:
        s = _connect(host, port)
        s.settimeout(TIMEOUT)
        data = s.recv(1024)
        s.close()
    except Exception as e:
        return f"连接失败: {type(e).__name__}"
    # 包结构: 3字节长度 + 1字节seq + 1字节协议版本(0x0a)；0xff 是 ERR 包
    if len(data) > 5 and data[4] == 0x0A:
        end = data.find(b"\x00", 5)
        ver = data[5:end].decode("utf-8", "ignore") if end > 5 else "?"
        return f"MySQL/MariaDB  {ver}"
    if len(data) > 6 and data[4] == 0xFF:
        code = data[5] | (data[6] << 8)
        msg = data[7:]
        if msg[:1] == b"#":          # 跳过 SQL state 标记
            msg = msg[6:]
        text = msg.decode("utf-8", "ignore").strip()
        if code == 1130:
            return ("MySQL  端口开放，但拒绝该来源 IP 连接"
                    "(1130 Host not allowed) —— 不可远程利用")
        if code in (1045, 1044):
            return f"MySQL  需要认证/权限不足({code}) —— 端口开放但需凭证"
        return f"MySQL  错误 {code}: {text[:60]}"
    if not data:
        return "TCP 开放，但无响应（可能被过滤/非 MySQL）"
    return f"非标准响应: {data[:40]!r}"


def probe_redis(host, port):
    """PING 是只读命令，未授权会直接返回 +PONG。"""
    try:
        s = _connect(host, port)
        s.settimeout(TIMEOUT)
        s.sendall(b"PING\r\n")
        data = s.recv(1024)
        s.close()
    except Exception as e:
        return f"连接失败: {type(e).__name__}"
    if b"+PONG" in data:
        return "Redis  【未授权 · PING 返回 +PONG】"
    if b"-NOAUTH" in data:
        return "Redis  需认证(-NOAUTH)"
    if b"-DENIED" in data:
        return "Redis  命令被拒绝(-DENIED)"
    return f"Redis 响应: {data[:40]!r}"


def _http_get(url):
    return requests.get(url, timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": config.USER_AGENT},
                        allow_redirects=False)


def probe_elasticsearch(host, port):
    try:
        r = _http_get(f"http://{host}:{port}/")
    except Exception as e:
        return f"连接失败: {type(e).__name__}"
    if r.status_code == 200 and "cluster_name" in r.text:
        return f"Elasticsearch  【未授权 · 返回 cluster 信息】"
    return f"HTTP {r.status_code}，非 ES 特征"


def probe_docker(host, port):
    try:
        r = _http_get(f"http://{host}:{port}/version")
    except Exception as e:
        return f"连接失败: {type(e).__name__}"
    if r.status_code == 200 and "ApiVersion" in r.text:
        return "Docker API  【未授权 · /version 可读】"
    return f"HTTP {r.status_code}"


def probe_generic(host, port):
    try:
        s = _connect(host, port)
        s.close()
        return "TCP 开放（服务类型未知）"
    except Exception as e:
        return f"连接失败: {type(e).__name__}"


HANDLERS = {
    3306: probe_mysql,
    6379: probe_redis,
    9200: probe_elasticsearch,
    9300: probe_elasticsearch,
    2375: probe_docker,
}


def probe(host, port):
    fn = HANDLERS.get(port, probe_generic)
    return fn(host, port)


def _parse_targets(args):
    targets = []
    for a in args:
        a = a.strip()
        if ":" in a:
            h, p = a.rsplit(":", 1)
            if p.isdigit():
                targets.append((h, int(p)))
    return targets


def _from_alive(path):
    """从 output/alive.txt 里解析出 host:port（只取高危端口）。"""
    risky = {2375, 3306, 5432, 6379, 7001, 9043, 9200, 9300, 27017}
    from urllib.parse import urlparse
    out = []
    if not os.path.exists(path):
        print(f"[!] 找不到 {path}")
        return out
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) < 5:
                continue
            host = urlparse(cols[0]).hostname
            ports = []
            for p in cols[4].split(","):
                if p.strip().isdigit():
                    ports.append(int(p))
            for p in ports:
                if p in risky:
                    out.append((host, p))
    return list(dict.fromkeys(out))


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    if args[0] == "--from-alive":
        path = args[1] if len(args) > 1 else os.path.join(config.OUTPUT_DIR, "alive.txt")
        targets = _from_alive(path)
    else:
        targets = _parse_targets(args)

    if not targets:
        print("[!] 没解析到 host:port")
        return

    print(f"共 {len(targets)} 个目标（只读探测）\n")
    for host, port in targets:
        print(f"[{host}:{port}] -> {probe(host, port)}")


if __name__ == "__main__":
    main()
