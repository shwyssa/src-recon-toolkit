# -*- coding: utf-8 -*-
"""
报告输出
  输出到 output/ 目录：
    - subdomains.txt    所有解析成功的子域名 + IP
    - alive.txt         存活资产
    - fingerprints.txt  命中指纹的资产
    - sensitive.txt     敏感文件/目录命中
    - 嫌疑清单.md        汇总：值得人工验证的重点目标
"""

import os
import time
import sys
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# 高危端口：对公网暴露时值得优先核查（数据库/缓存/未授权服务）
RISKY_PORTS = {2375, 3306, 5432, 6379, 7001, 9043, 9200, 9300, 27017}


def _ensure_out():
    if not os.path.exists(config.OUTPUT_DIR):
        os.makedirs(config.OUTPUT_DIR)
    return config.OUTPUT_DIR


def _fp_names(asset):
    return ", ".join(f["name"] for f in asset.get("fingerprints", []))


def write_reports(subdomains, alive_assets, sensitive_findings, all_paths=None):
    out = _ensure_out()
    ts = time.strftime("%Y%m%d_%H%M%S")

    # 1) 子域名
    with open(os.path.join(out, "subdomains.txt"), "w", encoding="utf-8") as f:
        f.write("# 域名\tIP\n")
        for s in subdomains:
            f.write(f"{s['domain']}\t{s['ip']}\n")

    # 2) 存活资产
    with open(os.path.join(out, "alive.txt"), "w", encoding="utf-8") as f:
        f.write("# URL\t状态\t标题\tServer\t开放端口\ticon_hash\tCDN\n")
        for a in alive_assets:
            ports = ",".join(map(str, a.get("ports", [])))
            ih = a.get("icon_hash")
            f.write(f"{a['url']}\t{a['status']}\t{a['title']}\t{a['server']}\t"
                    f"{ports}\t{'' if ih is None else ih}\t{a.get('cdn', '')}\n")

    # 3) 指纹命中
    matched = [a for a in alive_assets if a.get("fingerprints")]
    with open(os.path.join(out, "fingerprints.txt"), "w", encoding="utf-8") as f:
        f.write("# URL\t指纹\t风险\n")
        for a in matched:
            for fp in a["fingerprints"]:
                f.write(f"{a['url']}\t{fp['name']}\t{fp.get('risk','')}\n")

    # 4) 敏感文件/目录
    with open(os.path.join(out, "sensitive.txt"), "w", encoding="utf-8") as f:
        f.write("# URL\t状态码\t长度\t类型\t置信度\n")
        for s in sensitive_findings:
            f.write(f"{s['url']}\t{s['status']}\t{s['length']}\t{s['type']}\t{s.get('conf','')}\n")

    # 4.5) 全量路径（--paths 开启时才有）
    if all_paths is not None:
        with open(os.path.join(out, "所有路径.txt"), "w", encoding="utf-8") as f:
            f.write("# URL\t状态码\t长度\t标题\t跳转\n")
            for p in all_paths:
                f.write(f"{p['url']}\t{p['status']}\t{p['length']}\t"
                        f"{p['title']}\t{p['location']}\n")

    # 5) 汇总嫌疑清单
    report = os.path.join(out, "嫌疑清单.md")
    risky = [a for a in alive_assets
             if set(a.get("ports", [])) & RISKY_PORTS]
    with open(report, "w", encoding="utf-8") as f:
        f.write("# 信息收集结果汇总\n\n")
        f.write(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- 解析成功子域名：{len(subdomains)} 个\n")
        f.write(f"- 存活资产：{len(alive_assets)} 个\n")
        f.write(f"- 命中指纹资产：{len(matched)} 个\n")
        _h = sum(1 for s in sensitive_findings if s.get("conf") == "high")
        f.write(f"- 敏感路径命中：高置信 {_h} 条 / 低置信 {len(sensitive_findings) - _h} 条\n")
        _cdn_n = sum(1 for a in alive_assets if a.get("cdn"))
        f.write(f"- 暴露高危端口的资产：{len(risky)} 个\n")
        f.write(f"- 套 CDN 的资产：{_cdn_n} 个（扫到的是边缘节点，真实 IP 需另查）\n\n")

        f.write("## 一、暴露的高危端口（最容易出洞，优先看）\n\n")
        if risky:
            for a in risky:
                hit = sorted(set(a.get("ports", [])) & RISKY_PORTS)
                svc = a.get("services", {}) or {}
                detail = "；".join(f"{p}→{svc.get(p) or '未识别'}" for p in hit)
                f.write(f"- {a['url']} —— 端口 {', '.join(map(str, hit))}\n")
                f.write(f"  - 服务识别：{detail}\n")
        else:
            f.write("（无）\n")

        f.write("\n## 二、命中指纹的资产（优先验证）\n\n")
        if matched:
            for a in matched:
                f.write(f"### {a['url']}\n")
                f.write(f"- 状态：{a['status']} | 标题：{a['title']} | Server：{a['server']}\n")
                if a.get("icon_hash") is not None:
                    f.write(f"- icon_hash：`{a['icon_hash']}`"
                            f"（FOFA/微步搜 `icon_hash=\"{a['icon_hash']}\"` 可反查同款系统）\n")
                for fp in a["fingerprints"]:
                    f.write(f"- **{fp['name']}**（风险:{fp.get('risk','')}）— {fp.get('note','')}\n")
                f.write("\n")
        else:
            f.write("（无）\n\n")

        f.write("\n## 三、敏感文件/路径命中（高置信）\n\n")
        high = [s for s in sensitive_findings if s.get("conf") == "high"]
        low = [s for s in sensitive_findings if s.get("conf") != "high"]
        if high:
            for s in high:
                f.write(f"- [{s['status']}] {s['url']} ({s['type']})\n")
        else:
            f.write("（无）\n")

        f.write("\n## 四、低置信（需人工确认，不算命中）\n\n")
        if low:
            for s in low:
                f.write(f"- [{s['status']}] {s['url']} ({s['type']}，"
                        f"{'可能被保护/重定向' if s['status'] in (401,403) else '重定向'})\n")
        else:
            f.write("（无）\n\n")

        f.write("\n## 五、所有探测到的路径（全量）\n\n")
        if all_paths is None:
            f.write("（**未开启**。加 `--paths` 运行；`--paths --fast` 用精简字典）\n")
        elif not all_paths:
            f.write("（0 条。可能全被兜底页/WAF 过滤，或字典与站点不匹配）\n")
        else:
            f.write(f"共 {len(all_paths)} 条，完整见 `所有路径.txt`。\n\n")
            for p in all_paths[:50]:
                f.write(f"- [{p['status']}] {p['url']}  "
                        f"({p['length']}B{', ' + p['title'] if p['title'] else ''})\n")
            if len(all_paths) > 50:
                f.write(f"\n（仅显示前 50 条，完整见 `所有路径.txt`）\n")

        f.write("\n---\n> 提醒：仅对已获授权的 scope 内资产进行验证，别碰 scope 外目标。\n")

    # 6) 结构化结果，方便后续脚本/表格处理
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "subdomains": subdomains,
        "alive": alive_assets,
        "sensitive": sensitive_findings,
        "all_paths": all_paths,
    }
    with open(os.path.join(out, "result.json"), "w", encoding="utf-8") as fj:
        json.dump(data, fj, ensure_ascii=False, indent=2)

    return report
