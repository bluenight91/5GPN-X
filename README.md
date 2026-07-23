# 5GPN-X

服务器端透明代理网关：mosdns DoT + SNI/QUIC 透明代理 + 可切换多协议出口。客户端只需把 DNS/DoT 指向服务器域名，无需安装任何代理客户端。

本仓库在 Xiuyixx/5GPN-X 基础上增强了管理与运维能力：网页控制台（含 mihomo 监控面板）、`--update` 一键更新（含快照回滚）、git 检出式 `/opt/5gpn`、`doctor` 健康检查、域名 DoH 上游与可配置 ECS、API 安全加固。

## 工作原理

面向 5G NPN / N6 互通、私网终端出海和轻量透明代理场景：

- `172.22.0.0/16` 私网客户端（可改，见 `--set-client-cidr`）把 DNS/DoT 指向网关。
- ChinaList 域名（所有来源）走国内 DNS 竞速（4 路并发 + TCP fallback + 海外兜底含 `22.22.22.22`），保持本地访问体验。
- 内网来源非 ChinaList 的 A 查询返回服务器 IP，流量进入 TCP/QUIC 代理。
- 其他来源：被墙域名不劫持，正常海外解析；其他域名也正常海外解析。
- wa-shim / sniproxy / quic-proxy 负责 WhatsApp Noise、SNI/Host 和 QUIC 转发，出站由当前出口控制。
- DNS 服务全局不返回 AAAA 记录，客户端只使用 IPv4。
- 国内 DNS 三层 fallback：UDP 竞速（4 路）→ 150ms 超时后 TCP 竞速 → 都不通时海外兜底（1.1.1.1、8.8.8.8、22.22.22.22）。国际 DNS primary/secondary fallback。

支持的出口：本机直出、WireGuard、SOCKS5/SOCKS5H、SS/SS2022、VMess、Trojan、VLESS、Hysteria2、TUIC、AnyTLS、HTTP/HTTPS。URI 类出口由锁定版 mihomo `1.19.28` 提供 TUN 出口和智能分流。

出口切换基于 `ip rule fwmark` + 独立路由表，只影响代理进程出站，不影响 SSH、DNS、证书续期。

## 主要功能

**网关核心**

- DNS + DoT：客户端通过 TCP/UDP 53（仅 `172.22.0.0/16`）或 DoT 853（所有来源）接入；来源 IP 按段区分解析策略；上游支持纯 IP 与 `https://`/`tls://`（**域名 DoH/DoT**，如自建 AdGuard Home）；ChinaList 查询携带 ECS（可配置）；全局不返回 AAAA。
- 智能分流：mihomo `smart` 出口按域名 / IP / GEOSITE / GEOIP / RULE-SET 分流，远程规则集自动更新。
- iOS WhatsApp Patch：wa-shim 监听 TCP 443，仅分流客户端网段内 `ED`/`WA` 开头的无 SNI Noise 连接，其余 fail-open 交给 sniproxy。
- WLOC 虚拟定位（可选）：拦截并改写 `gs-loc.apple.com` 的定位响应，让私网 iOS 设备的网络定位变为设定坐标（见 Telegram Bot 一节的 WLOC 虚拟定位）。
- 低内存模式：≤ 1 GB 内存自动降低缓存与内核参数，512 MB VPS 可运行。

**管理与控制台**

- 网页控制台（可选）：六页静态控制台——仪表盘、出口管理、分流规则、mihomo 监控、AI 助手、设置；深浅双主题跟随系统，移动端底部标签栏（可滑动、滚动自动隐藏），适配 iOS Safari。
- mihomo 监控面板：metacubexd 经 api-server 同源反代接入，secret 不出服务端；支持连接查看、延迟测试、断开连接、规则集刷新。
- Telegram Bot：状态、出口管理、分流规则、DNS/DoT 设置（含客户端网段）、日志、iOS 二维码、运维自检。
- AI 助手：绑定自己的 OpenAI 兼容接口，自然语言生成分流方案，人工确认后才生效。

**运维**

- `--update` 一键更新：git 自更新 + 重部署运行时（保留全部配置）；更新前自动快照，失败可回滚。
- `/opt/5gpn` 自动成为 git 检出，管理命令全部在该目录执行。
- `doctor` / `report`：结构化自检与脱敏诊断报告；`smoke` 为 `doctor --deep` 别名。
- 可配置客户端网段（CLI / Bot / WebUI）；健康定时器可经 Telegram 告警。
- 可选私网 SOCKS5（默认 TCP **38443**，用户名/密码 + 仅客户端 CIDR）：手机 Telegram 等可指向网关公网 IP；出站跟随当前出口。
- API 安全加固：全响应安全响应头（HSTS/XFO/nosniff/CSP）、每源 IP 限流（429）、PII 静默日志。

## 环境要求

主流 Linux 发行版（Ubuntu 20.04+ / Debian 11+ / RHEL 系 8+ / Fedora 39+），`amd64` 或 `arm64`，root 权限，公网 IPv4，以及一个 A 记录指向服务器的域名。内存最低 512 MB，推荐 1 GB+。

## 安装

一键安装（自动拉取仓库到 `/opt/5gpn`）：

```bash
curl -fsSL https://raw.githubusercontent.com/bluenight91/5GPN-X/main/install.sh -o /tmp/5gpnx-install.sh && sudo bash /tmp/5gpnx-install.sh
```

手动安装：

```bash
git clone https://github.com/bluenight91/5GPN-X.git
cd 5GPN-X
sudo ./install.sh
```

非交互安装（无 TTY 时必须设置 `DOMAIN`）：

```bash
export DOMAIN="dns.example.com"
export EMAIL="admin@example.com"
sudo ./install.sh
```

安装前请先把域名 A 记录指向服务器公网 IP；脚本在申请 Let's Encrypt 证书前会验证解析（最长等待 120 秒）。

## 升级

```bash
sudo 5gpn update
```

一条命令完成：更新前配置快照 → `git fetch` 强制更新 `origin/main` + `reset --hard` 自更新（有新代码则以新代码 re-exec）→ 重部署运行时——重渲染 sniproxy 配置（保留当前 DNS）、按需重编译 quic-proxy、刷新 mosdns/mihomo 二进制与生成器、从保存的 `.uri` 链接重建出口配置、刷新 api-server/metacubexd/tgbot（**令牌不变**）、重建 smart 配置并重启服务（先 `reset-failed` 清除启动频率限制）。防火墙、内核调优、DNS 设置、出口、分流规则、证书全部保持原样。更新失败时会尝试自动回滚到更新前快照；也可手动 `sudo 5gpn rollback`。

若 `git pull` 显示 `Already up to date` 但功能未出现，多半是当前分支未对齐 `origin/main`（例如只拉到了功能分支）。可手动：

```bash
cd /opt/5gpn
git fetch origin +refs/heads/main:refs/remotes/origin/main
git checkout -B main origin/main
git reset --hard origin/main
git log -1 --oneline
sudo 5gpn update
```

`sudo 5gpn status` 会显示当前部署的 commit 短哈希、提交说明与分支。

## 客户端配置

- Android：`设置 -> 网络和互联网 -> 私人 DNS`，填入安装时配置的域名。
- iOS / iPadOS：扫描安装时生成的二维码，或访问 `http://<你的域名>:8111/ios-dot.mobileconfig` 安装描述文件（仅蜂窝网络启用 DoT，Wi-Fi 自动停用）。重新生成：`sudo ./install.sh -ios`
- Windows / macOS / Linux：系统 DoT 设置或 Stubby / cloudflared 指向服务器域名 `853` 端口。

## 管理命令

安装后 `/opt/5gpn` 自动成为本仓库的 git 检出，同时提供全局命令 `5gpn`（`/usr/local/bin/5gpn`），在任意目录直接执行。首个子命令的 `--` 可省略（如 `5gpn update` 等同 `5gpn --update`）：

```bash
sudo 5gpn update             # 一键更新到最新版（保留全部配置；失败可回滚）
sudo 5gpn status             # 查看状态
sudo 5gpn doctor             # 结构化健康检查（--json / --deep）
sudo 5gpn report             # 脱敏诊断报告 → /tmp
sudo 5gpn snapshot           # 手动保存配置快照
sudo 5gpn rollback           # 回滚到最近快照
sudo 5gpn set-client-cidr 172.22.0.0/16   # 私网客户端源网段
sudo 5gpn detect-client-cidr # 从本机网卡猜测并应用
sudo 5gpn enable-client-socks   # 开启私网 SOCKS5（默认 :38443，打印一次密码）
sudo 5gpn client-socks-status   # 查看状态（密码隐藏）
sudo 5gpn disable-client-socks  # 关闭
sudo 5gpn update-rules       # 更新 GFWList/ChinaList 并重载 mosdns
sudo 5gpn renew-cert         # 续期证书
sudo 5gpn set-dot-domain dns.example.com
sudo 5gpn set-dns "1.1.1.1 8.8.8.8" "223.5.5.5 119.29.29.29"
sudo 5gpn set-ecs 112.96.54.0/24   # 设置国内链查询携带的 ECS（默认 139.226.48.0/24）
sudo 5gpn -ios               # 重新生成 iOS 描述文件和二维码
sudo 5gpn list-exits         # 列出出口
sudo 5gpn check-exits        # 检测出口连通性
sudo 5gpn list-direct-domains
sudo 5gpn add-direct-domain box2.example.com   # 私网客户端对该域名返回真实解析（SSH 等）
sudo 5gpn setup-tgbot        # 配置 Telegram Bot
sudo 5gpn setup-api          # 启用 HTTP 控制 API + 网页控制台（可选）
sudo 5gpn uninstall          # 卸载
```

出口与分流相关子命令见下两节；DNS 直连名单也可在网页控制台「设置」或 Telegram Bot「DoT 管理 → DNS 直连域名」中维护。其余子命令（`show-rules`、`show-policy`、`import-rules`、`proxy-domain`、`setup-whatsapp` 等）可用 `sudo 5gpn --help` 查看。排查步骤见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

## 出口管理

默认出口为 `local`（本机公网 IP 直出）。

```bash
# WireGuard：导入你自己准备好的 WireGuard client 配置
sudo 5gpn add-exit us us.conf

# URI 出口
sudo 5gpn add-exit jp 'socks5://user:pass@1.2.3.4:1080'
sudo 5gpn add-exit hk 'ss://2022-blake3-aes-128-gcm:PASSWORD@5.6.7.8:443'

# 原地修改已有出口（读取新配置，校验通过后替换，活动出口自动重新激活）
sudo 5gpn edit-exit jp < new-config.txt

# 切换 / 验证
sudo 5gpn set-exit hk
curl --interface pgw-hk -4 -s https://api.ipify.org; echo
```

密码含特殊字符时可用多行输入避免 URL 转义：

```bash
printf 'socks5://1.2.3.4:1080
user: myuser
pass: my@p:ss/word
remote-dns: on
' | sudo 5gpn add-exit jp
```

当前出口记录在 `/opt/5gpn/etc/current-exit`，开机自动恢复。

## 智能分流

`smart` 出口可把不同域名 / 规则集分配到不同出口。策略可以是已配置的出口名、`direct` 或 `block`。

```bash
cat > rules.conf <<'EOF'
DOMAIN-SUFFIX,google.com,us
DOMAIN-KEYWORD,netflix,jp
GEOSITE,telegram,us
GEOIP,cn,direct
RULE-SET,https://example.com/rules.mrs,jp
FINAL,us
EOF

sudo 5gpn set-rules rules.conf
sudo 5gpn set-exit smart
```

单独追加规则或规则集（不覆盖整份文件）：

```bash
sudo 5gpn add-rule 'DOMAIN-SUFFIX,openai.com,us'
sudo 5gpn add-ruleset 'https://example.com/openai.mrs' us
```

规则类型：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`GEOSITE`、`GEOIP`、`RULE-SET`、`FINAL`。

`RULE-SET` 支持 mihomo `.mrs`、Clash YAML 和纯文本列表（不支持旧 sing-box `.srs`）。类型按文件名自动推断，命名不明确时可在 URL 后加 `#domain` / `#ipcidr` / `#classical`。远程规则集由 mihomo 默认每 24 小时更新。

导入整份规则并按分类映射出口：

```bash
sudo 5gpn import-rules /path/to/rule.conf
sudo 5gpn set-policy Netflix hk
```

## 网页控制台与 mihomo 监控（可选）

```bash
sudo 5gpn setup-api   # 生成令牌并启用 HTTP 控制 API（默认端口 8444），同时安装 mihomo 监控面板
```

执行后会打印 **API 地址** 与 **令牌**。打开仓库里的 `webui/index.html`（纯静态单文件，可本地双击打开，或托管到任意静态托管 / Cloudflare Pages，见 `webui/README.md`），填入地址和令牌即可使用——与 Telegram Bot 调用同一后端，实时同步。

**控制台六页**：仪表盘（实时状态、流量/延迟曲线、mihomo 概览）、出口管理、分流规则、mihomo 监控、AI 助手、设置（更新规则集、备份/恢复、主题切换）。界面支持深浅双主题跟随系统（可手动锁定），移动端为底部标签栏布局，已适配 iOS Safari（可「添加到主屏幕」）。

**mihomo 监控**：`--setup-api` 会安装 metacubexd（固定版本 1.269.0），并在 smart 实例上启用仅回环的 Clash API（`127.0.0.1:9090`，不对公网开放，经 api-server 8444 反代访问）。控制台「监控」页上半为概览摘要，下半为完整 metacubexd 面板：**控制台与 API 同源时面板内嵌显示；控制台跨站托管（Cloudflare Pages、本地 file:// 等）时改为「新标签页打开」**——顶层导航下认证 cookie 属第一方，iOS Safari 可靠。首次打开完整面板时，在其设置里把后端地址填 `https://<你的域名>:8444/api/mihomo/proxy`，**secret 留空**。

**安全模型**：唯一公网入口是 8444（TLS + Bearer 令牌）。mihomo Clash API 仅回环，真实 Clash secret 由 api-server 在服务端注入，浏览器永不接触。mihomo 静态资源经一次性 `?token=` 完成首次鉴权后种下 `pgw_mihomo` 会话 cookie（`Path=/; HttpOnly; Secure; SameSite=Strict`），后续子资源与 `/api/mihomo/*` 调用（含写方法与 WS 白名单流）走该 cookie；其他 `/api/*` 仍仅认 Bearer。所有响应带安全响应头（HSTS / X-Frame-Options / nosniff / CSP），`/api/*` 另有每源 IP 令牌桶限流（超限 429），请求日志静默不落盘。令牌等同控制台全部权限：不要分享给他人，泄露后立即在 `/opt/5gpn/etc/api.env` 更换并 `systemctl restart 5gpn-api`。

令牌保存在 `/opt/5gpn/etc/api.env`（权限 600）。注意：默认 `FIREWALL_MODE=preserve` 不接管防火墙，需自行放行 TCP 8444；8443 已被回环 sniproxy 占用，故 API 默认用 8444。

## Telegram Bot

```bash
export TG_BOT_TOKEN="123456:ABC-your-bot-token"
export TG_ADMIN_IDS="11111111,22222222"
sudo 5gpn setup-tgbot
```

不知道自己的数字 ID 时，先启用 Bot 后发送 `/id`，把返回的 ID 写入 `/opt/5gpn/etc/tgbot.env` 并 `sudo systemctl restart 5gpn-tgbot`。

命令：`/start` 打开面板、`/status` 状态、`/exits` 出口、`/rules` 分流、`/wloc` 虚拟定位、`/cancel` 取消输入、`/id` 查 ID。

### WLOC 虚拟定位

在 Bot 的 `📡 WLOC 管理` 中选择预置地点，或输入 WGS84 经纬度（例如 `35.681236,139.767125`）。首次使用先通过菜单下载并安装 `5GPN-WLOC-CA.cer`，然后在 iOS `设置 -> 通用 -> 关于本机 -> 证书信任设置` 对该证书开启完全信任。

WLOC 仅在启用时将 `gs-loc.apple.com` 和 `gs-loc-cn.apple.com` 导向网关本地的受限拦截器；仅改写 `/clls/wloc` 及必要的 Apple 定位辅助响应。关闭后会清除这两个精确 DNS 映射并恢复原始网络定位。切换地点后 iOS 的 `locationd` 可能保有缓存，必要时重启设备。

添加出口：`🌐 出口 -> ➕ 添加出口`，直接粘贴节点链接（`ss:// vmess:// trojan:// vless:// hysteria2:// tuic:// anytls:// socks5:// http://`），备注会自动作为出口名。

## DNS 与 ECS

上游池分两组：**国际池**（`REMOTE_DNS`，海外/代理侧解析）与**国内池**（`LOCAL_DNS`，ChinaList 直连解析）。两组都支持：

- 纯 IP（`1.1.1.1`、`223.5.5.5:53`、IPv6 `[2001:4860:4860::8888]:53`）；
- `udp://` / `tcp://`（须 IP 字面量）；
- `https://` / `tls://`（**支持域名**，含伪装路径如 `https://host/api/xxxx`），域名由内置 bootstrap 解析器解析。

例如把上游指向自建 AdGuard Home 的 DoH：

```bash
# 国际池用 AGH DoH（不带 ECS）；国内池用 AGH DoH（携带 ECS）+ 传统 DNS 兜底
sudo 5gpn set-dns "https://agh-jp.example.com/api/xxxx https://adg.example.com/api/xxxx" \
                  "https://agh-jp.example.com/api/xxxx 180.76.76.76 119.29.29.29"
sudo 5gpn set-ecs 112.96.54.0/24
```

要点：

- **ECS 只随国内链查询发出**（`local_primary`/`local_secondary`），国际链查询不携带。用 `--set-ecs` 可随时修改，立即生效；安装期可用 `PGW_ECS` 预设（默认 `139.226.48.0/24`）。
- DoH 证书需为公网可信证书；建议在 AGH 侧按来源 IP 限流/白名单。
- sniproxy 的解析器只认纯 IP：上游为 DoH/DoT 时自动改用 `127.0.0.1`（本机 mosdns，走完整链路与缓存），不产生警告。

## 健康检查（每次安装/更新后）

```bash
sudo 5gpn doctor          # 结构化自检
sudo 5gpn doctor --deep   # 深度检查（等同 smoke）
sudo 5gpn smoke           # doctor --deep 别名
sudo 5gpn report          # 脱敏报告写入 /tmp
```

只读、约一分钟：服务状态、端口监听、DNS/DoT 应答（区分无应答与上游拒绝）、客户端网段、TUN 链路（`--deep` 含 `--interface pgw-smart` 出网探测）、fwmark 规则健康度、API 健康、证书有效期、WLOC 状态；配置了域名 DoH 上游时还会做一次 wire-format 直连探测。结尾附人工核对步骤。配置了 Telegram Bot 或 webhook 时，`5gpn-health.timer` 每 20 分钟复检并在失败/恢复时告警。

## 配置参考

### 仓库结构

```text
install.sh        # 安装/管理入口（唯一需要直接运行的脚本）
quick-install.sh  # 一键安装引导
lib/              # 组件源码与模板（tgbot、wa-shim、api-server、Go 代理、mihomo/mosdns 生成器等）
webui/            # 静态网页控制台（index.html 单文件）
scripts/          # 运维脚本（doctor / snapshot / report / health-notify）
docs/             # 排查手册等
tests/            # 策略与单元测试
CHANGELOG.md      # 变更记录
```

### 关键路径

| 路径 | 说明 |
| --- | --- |
| `/opt/5gpn` | 项目 git 检出 + 运行时主目录（`bin/5gpn-ctl`、`bin/api-server.py`、`bin/mihomo` 等） |
| `/opt/5gpn/etc/current-exit` | 当前出口 |
| `/opt/5gpn/etc/api.env` | 控制台 API 令牌与端口（权限 600） |
| `/opt/5gpn/etc/tgbot.env` | Bot Token 和管理员 ID（权限 600） |
| `/etc/5gpn/` | 出口与分流状态（`exits/`、`rules.conf`、`policy-map.conf`、`mihomo-api-secret`） |
| `/etc/mosdns/.client_cidr` | 私网客户端源网段（默认 `172.22.0.0/16`） |
| `/var/lib/5gpn/snapshots/` | 配置快照（`update` 前自动创建，可用 `rollback` 恢复） |
| `/etc/mosdns/config.yaml` | mosdns 实际配置 |
| `/etc/mosdns/.remote_dns` `.local_dns` `.ecs` | DNS 上游与 ECS（`--set-dns` / `--set-ecs` 维护） |
| `/etc/mosdns/gfwlist-extra-local.txt` | 本地补充 GFWList 域名（每行一个，`--update-rules` 时并入） |
| `/etc/mosdns/direct-domains.txt` | DNS 直连名单（私网客户端跳过劫持，返回真实 A 记录；SSH 主机名等） |
| `/etc/mosdns/wloc.txt` | WLOC 劫持域名（仅启用时写入，关闭即清空） |
| `/etc/sniproxy.conf` | sniproxy 配置（resolver 强制 `ipv4_only`） |

### 端口

| 端口 | 协议 | 范围 | 用途 |
| --- | --- | --- | --- |
| 53 | TCP/UDP | `172.22.0.0/16` | DNS |
| 80 | TCP | 私网（ACME 时临时公网） | HTTP 透明代理 / HTTP-01 |
| 443 | TCP | `172.22.0.0/16` | wa-shim（无 SNI / HTTPS fail-open 到 sniproxy 回环 8443） |
| 443 | UDP | `172.22.0.0/16` | QUIC 透明代理 |
| 853 | TCP | 公网 | DNS over TLS |
| 8111 | TCP | 公网 | iOS 描述文件下载 |
| 8444 | TCP | 公网 | HTTP 控制 API（可选，`--setup-api` 后） |
| 9090 | TCP | 仅 127.0.0.1 | mihomo Clash API（smart 实例回环；经 api-server 8444 反代访问） |

### 环境变量

```bash
DOMAIN="dns.example.com"        # DoT 域名（必需）
EMAIL="admin@example.com"       # ACME 邮箱
REMOTE_DNS="1.1.1.1,8.8.8.8,9.9.9.9"     # 海外 DNS 池
LOCAL_DNS="101.226.4.6,218.30.118.6,180.76.76.76,119.29.29.29"  # 国内 DNS 竞速池（4路 UDP 并发）
PGW_ECS="139.226.48.0/24"         # 国内链查询携带的 ECS（可用 --set-ecs 随时改）
CLIENT_CIDR="172.22.0.0/16"       # 私网客户端源网段（可用 --set-client-cidr / --detect-client-cidr）
LOWMEM=1                        # 强制低内存模式（≤1GB 自动启用）
MIHOMO_VERSION="1.19.28"        # 可覆盖锁定版，建议保持默认
METACUBEXD_VERSION="1.269.0"    # 可覆盖锁定版 metacubexd
TG_BOT_TOKEN="123456:ABC"
TG_ADMIN_IDS="11111111,22222222"
FIREWALL_MODE=preserve          # preserve(默认)/auto/managed，见下方说明
PGW_TUNING=essential            # essential(默认)/performance 内核调优档位
```

旧兼容变量 `DNS_UPSTREAMS`、`OVERSEAS_DNS`、`PRIVATE_OVERSEAS_DNS`、`SNIPROXY_DNS` 等同于 `REMOTE_DNS`。

### 防火墙与内核调优

安装脚本默认**不接管**主机防火墙（`FIREWALL_MODE=preserve`）：只维护项目自己的
出口打标规则（`pgw_exit` 表），并提示需要放行的端口，不会覆盖 `/etc/nftables.conf`、
不会 `flush ruleset`、不会修改 INPUT 默认策略。

- `FIREWALL_MODE=auto`：在现有防火墙（UFW / firewalld / nftables / iptables）里
  **增量**放行所需端口，不清空任何已有规则。
- `FIREWALL_MODE=managed`：由项目完整接管 INPUT 防火墙（旧版行为），每次运行安装器都必须显式指定，历史标记不会自动启用。应用前会
  自动识别并放行**所有检测到的 SSH 端口**（当前会话端口、`sshd -T` 配置、实际
  监听端口的并集，检测失败才回落 22），校验新规则并备份原有
  `/etc/nftables.conf` 到 `/etc/nftables.conf.pgw-backup`。
- 从旧版本升级或重装也默认保持 `preserve`；历史标记不会自动触发 `managed`，
  避免覆盖用户后来添加的规则。

内核参数同理分档：默认 `PGW_TUNING=essential` 只设置网关必需项（转发、
`rp_filter`、可用时启用 BBR）；`PGW_TUNING=performance` 使用旧版激进吞吐调优
（大连接表、短超时等）。旧版本升级时沿用 performance，不会悄悄改变内核行为。

## 常见问题

**为什么 SSH 到「主机名.域名」会进网关？** 私网客户端（`172.22.0.0/16`）对非 ChinaList 域名返回网关 IP；SSH 无 SNI，只能落到本机 `sshd`。把主机名加入 DNS 直连名单即可：`sudo 5gpn add-direct-domain box2.example.com`，或在 WebUI「设置」/ Bot「DoT 管理 → DNS 直连域名」中配置。公网 DoT 默认不劫持。

**为什么内网客户端不返回 IPv6？** 透明代理路径按 IPv4 设计；只有 `172.22.0.0/16` 来源的 AAAA 返回 NOERROR/NODATA。Wi-Fi、公网及其他来源正常返回 IPv6。

**为什么国内网站直连？** ChinaList 域名由 mosdns 转发到国内 DNS 竞速（携带 ECS，可用 `--set-ecs` 修改），获得更适合大陆访问的结果。UDP 150ms 无响应后自动切 TCP，都不通才走海外兜底（含 `22.22.22.22`），避免单一国内 DNS 故障卡住页面。

**如何更新规则集与程序本身？** 规则集：`sudo 5gpn update-rules`。程序：`sudo 5gpn update`（无需手动 git pull）。

**smart 模式分流全部失败怎么排查？** 先跑 `sudo 5gpn doctor --deep` 定位环节；再看 `journalctl -u 5gpn-mihomo@smart -n 30 --no-pager`（规则是否命中、拨号错误类型）、`ip route show table 100`（默认路由是否指向 pgw-smart）、以及 smart.yaml 的 `dns` 段是否就位。更完整步骤见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

**sniproxy 用什么 DNS？** 上游为纯 IP 时直接用该 IP；上游为 DoH/DoT 时用 `127.0.0.1`（本机 mosdns，走完整链路与缓存）。sniproxy 的解析器只用于解析被代理网站的上游主机名，与客户端 DNS 策略无关。

**如何查看日志？** 相关服务：`mosdns`、`sniproxy`、`wa-shim`、`quic-proxy`、`5gpn-tgbot`、`5gpn-mihomo@*`，用 `systemctl status` / `journalctl -u <服务> -f` 查看；也可在 Telegram Bot 的 📜 日志里按服务查看。

**如何测试 DoT？**

```bash
dig +tls @dns.example.com -p 853 youtube.com
curl -I --resolve youtube.com:443:127.0.0.1 https://youtube.com
```

**证书签发失败？** 确认域名 A 记录指向服务器公网 IP 且 TCP 80 可被公网访问。签发/续期时脚本会临时停止 sniproxy 并放行公网 80，完成后恢复 80/443 白名单。

**从旧 sing-box 版本升级？** 内核级迁移：旧 sing-box 服务和二进制会被移除，旧配置备份到 `/etc/5gpn/exits/singbox-backup/`。URI 出口需用原节点链接重新 `--add-exit`；`rules.conf` 和策略映射保留，出口补齐后重新 `--set-rules` / `--set-exit smart`。当前 WireGuard 出口不受影响。

**WhatsApp Patch 的风险控制？** wa-shim 仅对私网和 loopback 来源启用 ED/WA 分流；未知协议、TLS ClientHello、短包和超时都 fail-open 到 sniproxy；以 `pxout` 用户运行，跟随当前出口出站。

## 免责声明

本项目仅用于合法的网络互通、企业专网、测试和学习场景。使用者需自行确认部署和使用行为符合所在地法律法规、云服务商条款及目标网络服务条款。项目不保证在所有网络环境下可用，也不承诺规避封锁、审查或主动探测；因误用、配置错误、服务中断等造成的后果由使用者自行承担。
