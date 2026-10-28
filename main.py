# -*- coding: utf-8 -*-
"""
SRC 信息收集 · 一键流水线
==================================================
流程：子域名枚举 → 存活/端口 → 指纹识别 → 敏感文件/目录 → 报告

用法：
    python main.py                        # 读 domains.txt 批量跑
    python main.py example.com            # 快速跑单个域名
    python main.py example.com example.cn # 跑多个

首次使用：
    pip install requests dnspython
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from modules import subdomain, alive, fingerprint, manual, sensitive, pathenum, report
from modules import state

# 让输出在管道/重定向下也实时可见（否则看起来像卡死）
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

# 这些端口一旦开放，值得自动做一次"只读服务识别"
RISKY_SERVICE_PORTS = {2375, 3306, 5432, 6379, 7001, 9043, 9200, 9300, 27017}


def _recover_domains():
    """上次运行如果被强杀，domains.txt 可能没还原：检测 .bak 并自动恢复。"""
    bak = config.DOMAINS_FILE + ".bak"
    if os.path.exists(bak):
        os.replace(bak, config.DOMAINS_FILE)
        print("[!] 发现上次异常退出残留的 domains.txt.bak，已自动恢复")


def _probe_services(assets):
    """对高危端口做只读服务识别（读 MySQL 握手 / Redis PING / ES 首页等）。"""
    targets = []
    for a in assets:
        hits = sorted(set(a.get("ports", [])) & RISKY_SERVICE_PORTS)
        if hits and a.get("ip"):
            targets.append((a, hits))
    if not targets:
        return
    try:
        from service_probe import probe as svc_probe
    except Exception as e:
        print(f"[服务] 跳过（导入 service_probe 失败：{e}）")
        return

    from concurrent.futures import ThreadPoolExecutor, as_completed
    total = sum(len(h) for _, h in targets)
    print(f"[服务] 对 {len(targets)} 个资产的 {total} 个高危端口做只读识别 ...")
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {}
        for a, ports in targets:
            for p in ports:
                futs[ex.submit(svc_probe, a["ip"], p)] = (a, p)
        for f in as_completed(futs):
            a, p = futs[f]
            try:
                a.setdefault("services", {})[p] = f.result()
            except Exception:
                pass


def main():
    argv = sys.argv[1:]

    # 先清理上次强杀留下的 .bak（兼容旧行为）
    _recover_domains()

    # 解析参数（--out / --rps 后面跟值，不能当成域名）
    cli_domains = []
    flags = set()
    out_dir = None
    rps = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--out" and i + 1 < len(argv):
            out_dir = argv[i + 1]
            i += 2
            continue
        if a == "--rps" and i + 1 < len(argv):
            rps = argv[i + 1]
            i += 2
            continue
        if a.startswith("-"):
            flags.add(a)
        else:
            cli_domains.append(a)
        i += 1

    # --out：输出目录（多开时每个进程用不同目录，避免互相覆盖）
    if out_dir:
        config.OUTPUT_DIR = os.path.abspath(out_dir)
        print(f"[输出] 目录 -> {config.OUTPUT_DIR}")

    # --rps：本进程的全局限速（多开时务必调低）
    if rps and rps.isdigit():
        config.MAX_RPS = int(rps)
        print(f"[限速] MAX_RPS -> {config.MAX_RPS} req/s（仅本进程）")

    # --paths：开启全量路径枚举（列出所有路径，而不只是敏感文件）
    # --fast ：配合 --paths，用精简字典（约 72 条高价值路径）
    # --quick：快速摸底。跳过爬首页/证书透明/敏感探测/手工清单，并把限速放宽
    if "--paths" in flags:
        config.DO_PATH_ENUM = True
    if "--fast" in flags:
        config.PATH_ENUM_FAST = True
    if "--quick" in flags:
        config.DO_CRAWL = False
        config.DO_CERT_TRANSPARENCY = False
        config.DO_CERTSPOTTER = False
        config.DO_HACKERTARGET = False
        config.DO_CDN_CHECK = False
        config.DO_SENSITIVE = False
        config.DO_MANUAL = False
        config.DO_PORT_SCAN = False
        if not rps:
            config.MAX_RPS = 10
        print("[模式] 快速摸底：跳过爬首页/证书源/敏感探测/手工清单")

    # 预检模式：只判断目标能不能测，不跑全流程
    if "--check" in flags:
        from modules import precheck
        precheck.run(cli_domains or None)
        return

    try:
        print("=" * 60)
        print("SRC 信息收集流水线")
        print("=" * 60)

        seeds = subdomain._load_domains(cli_domains or None)
        st = state.load(seeds) if "--resume" in flags else {}

        # 1) 子域名枚举（域名直接传参，不再改动 domains.txt）
        if st.get("subdomains"):
            subdomains = st["subdomains"]
            print(f"[续跑] 复用子域结果 {len(subdomains)} 个")
        else:
            subdomains = subdomain.enumerate_subdomains(seeds)
            if subdomains:
                state.save(seeds, "subdomains", subdomains)
        if not subdomains:
            print("[x] 没有解析到任何子域名，请检查域名和网络。")
            return

        # 2) 存活 + 端口
        if st.get("alive"):
            alive_assets = st["alive"]
            print(f"[续跑] 复用存活资产 {len(alive_assets)} 个")
        else:
            alive_assets = alive.alive_check(subdomains)
            if alive_assets:
                state.save(seeds, "alive", alive_assets)
        if not alive_assets:
            print("[x] 没有存活资产。")
            return

        # 2.5) 高危端口 → 只读服务识别
        _probe_services(alive_assets)

        # 3) 指纹识别
        if st.get("alive_fp"):
            alive_assets = st["alive_fp"]
            print(f"[续跑] 复用指纹结果")
        else:
            alive_assets = fingerprint.fingerprint(alive_assets)
            state.save(seeds, "alive_fp", alive_assets)

        # 3.5) 生成《手工测试清单》：把扫描结果变成"该点哪里"
        manual.build_checklists(alive_assets)

        # 4) 敏感文件/目录
        findings = sensitive.sensitive_scan(alive_assets)

        # 4.5) 全量路径枚举（--paths 开启）
        all_paths = pathenum.enumerate_paths(alive_assets)

        # 5) 报告
        rep = report.write_reports(subdomains, alive_assets, findings, all_paths)
        print("\n" + "=" * 60)
        print(f"完成！汇总报告：{rep}")
        print("=" * 60)
    except KeyboardInterrupt:
        print("\n[!] 已中断（Ctrl+C）。domains.txt 不会再被改动，直接重跑即可。")


if __name__ == "__main__":
    main()
