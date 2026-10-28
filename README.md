# SRC 信息收集流水线

一条龙自动化：**种子域名 → 子域名枚举 → 存活/端口 → 指纹识别 → 敏感文件/目录 → 汇总报告**。

## 目录结构

```
信息收集/
├── config.py                # 全局配置（改这里）
├── domains.txt              # 输入：种子域名，一行一个
├── main.py                  # 主入口
├── sitemap.py               # 网站地图/robots 路径提取器（先跑它拿已知路径）
├── service_probe.py         # 高危端口服务指纹探测（只读，不登录不爆破）
├── dsstore.py               # .DS_Store 解析器（提取泄露的文件名清单）
├── js_scan.py               # 从页面 JS 里挖接口/域名
├── modules/
│   ├── subdomain.py         # 子域名枚举（字典 + crt.sh + Cert Spotter + HackerTarget + 首页爬取）
│   ├── alive.py             # 存活探测 + 端口扫描 + CDN 判断
│   ├── cdn.py               # CNAME 判断是否套 CDN（dnspython 或 DoH 回退）
│   ├── fingerprint.py       # 指纹识别 + favicon mmh3
│   ├── sensitive.py         # 敏感文件/目录探测（多基线降误报）
│   ├── pathenum.py          # 全量路径枚举（--paths）
│   ├── manual.py            # 手工测试清单生成
│   ├── precheck.py          # 目标可达性预检（--check）
│   ├── state.py             # 断点续跑（--resume）
│   ├── util.py              # 限速 / 解码 / WAF 识别 / murmur3
│   └── report.py            # 报告输出
├── dict/
│   ├── subdomains.txt       # 子域名字典（480 条）
│   ├── sensitive_paths.txt  # 敏感文件/路径字典（小、高价值）
│   ├── dirs.txt             # 目录字典
│   ├── paths.txt            # 全量路径字典（279 条）
│   ├── paths_fast.txt       # 精简路径字典（72 条）
│   └── fingerprints.json    # 指纹库（可自行扩充）
└── output/                  # 结果（自动生成）
```

## 环境

```bash
pip install requests dnspython
```

`dnspython` 可选但强烈建议装（子域名爆破速度/稳定性好很多）；不装也能跑（退回 socket）。

## 使用

**1. 填种子域名**（`domains.txt`，一行一个，只要根域名）：

```
example.com
example.cn
```

种子域名从哪来：
- 企查查 → 公司 → **"网站备案"** 里的 ICP 备案域名列表（比官网网址全，最接近 SRC scope）
- 或直接填公益SRC scope 清单里的域名

**2. 跑：**

```bash
python main.py                      # 读 domains.txt 批量跑
python main.py example.com          # 快速跑单个域名
python main.py --paths example.com  # 额外做「全量路径枚举」（列出所有路径）
python main.py --quick example.com  # 快速摸底：跳过爬首页/证书源/敏感/清单
python main.py --resume example.com # 断点续跑：复用上次的子域/存活/指纹结果
python main.py --out D:/out/a --rps 3 example.com   # 输出隔离 + 单进程限速
```

**3. 看结果**（在 `output/` 里）：

| 文件 | 内容 |
|---|---|
| `subdomains.txt` | 所有解析成功的子域名 + IP |
| `alive.txt` | 存活资产（URL/状态/标题/端口/icon_hash/CDN） |
| `fingerprints.txt` | 命中指纹的资产 |
| `sensitive.txt` | 敏感文件/目录命中 |
| `所有路径.txt` | **全量路径枚举结果**（`--paths` 才有）：URL/状态码/长度/标题/跳转 |
| `手工测试清单.md` | **把扫描结果变成"该点哪里"**：登录/注册/后台入口、ID类参数、表单、JS接口、测试建议 |
| `result.json` | 结构化结果（给后续脚本/表格用） |
| `嫌疑清单.md` | **汇总，从这里开始人工验证** |

## 先预检：这个目标现在能不能测？

跑全流程前，先花几秒确认目标状态，别对着已下线/被拉黑/整站 500 的目标刷半天。

```bash
python main.py --check example.com        # 预检单个目标
python main.py --check                    # 读 domains.txt 批量预检
python modules/precheck.py example.com    # 也能单独跑
```

输出示例：

```
域名                          结论          状态    耗时    信息
example.com                    ✓ 可测        200     320ms   https://www.example.com
wap.example.org            ✗ 站点异常    500     180ms   https://www.wap.example.org
47.91.106.235 的站            ✗ 不可达      -       -       (ConnectTimeout)
```

| 结论 | 含义 | 建议 |
|---|---|---|
| ✓ 可测 | 200/301/302 | 可以跑全流程 |
| ⚠ 可测(WAF) | 401/403 | 能连但被挡，降速 |
| ⚠ 根路径404 | 能连但根路径异常 | 可能路径不对，人工确认 |
| ✗ 站点异常 | 5xx | **别测**，等恢复或放弃 |
| ✗ 不可达 | 全部超时/连接失败 | **放弃**，可能 IP 被封或主机下线 |

## 网站地图路径提取（sitemap.py）

抓 `sitemap.xml` / `sitemap_index.xml` / `sitemap.txt` / `robots.txt`，把路径提取出来。
**自动过滤 `sitemaps.org`、`w3.org` 这类协议外链**（sitemap 顶部的 `xmlns` 指向那里，点进去只是说明书，不是目标资产）。

```bash
python sitemap.py example.com     # 单个域名
python sitemap.py                 # 读 domains.txt 批量
```

输出（在 `output/` 下）：

| 文件 | 内容 |
|---|---|
| `known_paths.txt` | 去重路径（重点路径排前面） |
| `known_urls.txt` | 完整 URL（含参数，优先人工看） |
| `重点路径.txt` | 含 admin/api/upload/login 等关键词的高价值路径 |

用法：`known_paths.txt` 可以追加进 `dict/dirs.txt`，或直接把里面看着像后台/接口的路径拿去人工验证。
另外它自带 https://www / 裸域 / http 的探活回退，裸域没签证书的站也能跑。

## 高危端口服务探测（service_probe.py）

`main.py` 只会告诉你"端口开着"，但**开着 ≠ 能打**。这个脚本做一次只读的"服务自报家门"：

```bash
python service_probe.py store.xxx.com:3306
python service_probe.py --from-alive            # 直接读 output/alive.txt 的高危端口
```

| 端口 | 探测方式 | 判断 |
|---|---|---|
| 3306 | 读 MySQL 握手包（被动） | 版本号 / 1130 拒绝本机 IP / 1045 需认证 |
| 6379 | 发 PING（只读） | `+PONG`=未授权；`-NOAUTH`=需认证 |
| 9200 | GET `/` | 返回 cluster 信息=未授权 |
| 2375 | GET `/version` | 可读=未授权 |
| 27017 | TCP 连通 | Mongo 需客户端先发起，只能报开放 |

**不登录、不猜口令、不写数据。** 典型输出：

```
[store.xxx.com:3306] -> MySQL  端口开放，但拒绝该来源 IP 连接(1130 Host not allowed) —— 不可远程利用
```

看到 `1130` 就说明这条线基本死了（服务在，但不让你连），不用再花时间。

## 手工测试清单（自动生成）

每次跑完 `main.py`，会额外生成 `output/手工测试清单.md`，把扫描结果翻译成"你该去点什么"：

- **登录 / 注册 / 后台 / 接口 / 上传下载** 入口（按路径词元精确匹配，不是子串）
- **带参数的 URL**，参数名是 `id / userId / orderId / categoryId…` 的会标 **⚠️ID类** ← 越权优先测
- **表单**（action + method）
- **JS 里挖到的接口**
- 每个资产一个**评分** + 建议测试项

按评分从高到低排序，**评分高的先看**。这是"工具 → 手工"的交接点：工具找门，推门靠人。

## 流程说明

1. **子域名枚举**：字典爆破（480 条）+ 三路证书源（crt.sh / Cert Spotter / HackerTarget）+ 首页链接爬取，能翻出字典里没有的子域，也能发现"商城在独立域名"的情况。
2. **存活 + 端口**：HTTP/HTTPS 探测 + 常见高危端口扫描，报告会把 **3306/6379/9200/2375/27017** 这类暴露的数据库/服务端口单独列在最前面，并**自动做只读服务识别**（读 MySQL 握手看版本/是否 1130 拒绝、Redis PING、ES 首页等）。同时做 **CDN 判断**（CNAME 指向已知 CDN 则标记，提示"扫到的是边缘节点，真实 IP 需另查"）；取 CNAME 走 dnspython，未安装时回退到阿里云 DoH，无需额外依赖。
3. **指纹识别**：按标题/正文/响应头/Cookie 匹配指纹库；ASCII 关键字按**整词**匹配（避免 `nacos` 命中 base64 段落造成误报）。同时算 **favicon mmh3 哈希**（等同 FOFA 的 `icon_hash`），可拿去 FOFA/微步反查同款系统。
4. **敏感探测**：`.git/config`、`.env`、备份文件、actuator、swagger 等。**带多基线过滤**——先发一批随机假路径采样站点兜底页，凡是和兜底页一样的响应（软404 / SPA 首页 / WAF 403 / 500 错误页）一律丢弃；敏感文件只认 200，WAF 的 403 不算命中。
4.5 **全量路径枚举**（加 `--paths`）：用 `dict/paths.txt`（279 条）枚举所有路径，把**所有和兜底页不同**的响应列到 `所有路径.txt`——登录、注册、后台、接口、文档全都会列出来，而不只是敏感文件。会自动过滤 WAF 挑战页（阿里云/安全狗/瑞数）和 SPA 兜底页。
5. **报告**：汇总出"嫌疑清单"供人工验证。
6. **断点续跑**（`--resume`）：子域 / 存活 / 指纹三个阶段的结果会落到 `output/_state.json`；重跑时若目标列表一致就自动复用，不用从头再扫一遍。想强制重算，去掉 `--resume` 或删掉该文件。

## 常用调整（都在 config.py）

- `MAX_RPS`：**全局限速**，每秒最多发多少个 HTTP 请求（默认 `5`）。不管开多少线程都受它限制。目标小/单 IP/被封过 → 调到 `2~3`；大厂集群可以到 `10~20`。
- `THREADS_DNS` / `THREADS_HTTP`：并发数（默认 100 / 10）。真正决定速率的是 `MAX_RPS`，线程数只是上限。
- `REQUEST_DELAY`：每次请求后额外停顿秒数（默认 0）。`MAX_RPS` 已限速，一般不用动。
- `DO_DIR_BRUTE`：默认 `False`（目录爆破大字典、吵、慢）。只对重点资产开，且把目标换成自己确认在 scope 内的。
- `SCAN_PORTS`：端口列表。
- `SENSITIVE_STATUS`：判定"路径存在"的状态码。

## 加自己的指纹

编辑 `dict/fingerprints.json`，每个条目：

```json
{
  "name": "某系统",
  "title": ["标题关键字"],
  "body": ["正文关键字"],
  "header": ["Server: xxx", "X-Powered-By: xxx"],
  "cookie": ["cookie名字"],
  "port": [8080],
  "note": "怎么打",
  "risk": "高"
}
```

字段是"或"关系，任意一项命中即算命中。

## 注意事项（重要）

- **只扫已获授权的 scope 内目标**，scope 外的资产别碰。
- **限速**：并发别开太高，别把目标站点打死，尤其 edu/gov。
- crt.sh 偶尔超时/503 是正常的，脚本会自动忽略。
- 如果敏感扫描时提示「大量 202 响应」，说明站点有**反爬/JS 挑战**（如瑞数），纯 requests 拿不到真实内容，应改用 Playwright 浏览器或换目标。
- 目录爆破默认关闭，需要时单独对重点资产手动跑，并降低线程。
