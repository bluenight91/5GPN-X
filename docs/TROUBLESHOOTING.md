# 排查手册

按现象定位。多数步骤先跑：

```bash
sudo 5gpn doctor          # 结构化自检
sudo 5gpn doctor --deep   # 含 TUN 出网 / DoH 探测（等同 smoke）
sudo 5gpn report          # 脱敏报告 → /tmp/5gpn-report-*.txt
```

## 更新失败 / 想回到更新前

```bash
sudo 5gpn snapshot list
sudo 5gpn rollback                 # 最近一份
sudo 5gpn rollback <snapshot-id>   # 指定 ID
```

`update` 会在改动运行时前自动建 `pre-update` 快照；失败时脚本会尝试自动回滚。若自动回滚失败，用上面的命令手动恢复。

### 运行时快照 vs 轻量配置包

- **运行时快照（snapshot）**：服务器本机回滚点，包含 `/etc/5gpn`、mosdns 关键状态等，保存在 `/var/lib/5gpn/snapshots`。用于 `5gpn rollback` / WebUI「运行时快照」。
- **轻量配置包（WebUI 备份）**：浏览器下载的可导入配置包，默认排除 token/secret 和规则缓存，适合迁移或临时备份；它不是完整运行时快照。

## smart 分流全灭

1. `sudo 5gpn doctor --deep`：看 `5gpn-mihomo@smart`、`pgw-smart`、表 100、TUN 出网。
2. `journalctl -u 5gpn-mihomo@smart -n 50 --no-pager`
3. `ip route show table 100`、`ip rule show | grep fwmark`
4. 确认 `rules.conf` / 策略映射后：`sudo 5gpn set-rules` 或 `set-exit smart`

## 规则组 / policy-map / 出口

智能分流链路是三段：

1. `rules.conf` 里的最后一列可以是出口名，也可以是「规则组」名，例如 `ai`、`streaming`。
2. `/etc/5gpn/policy-map.conf` 把规则组映射到最终目标：某个 mihomo 出口、`direct` 或 `block`。
3. 生成 smart mihomo 配置时，规则先命中分类/规则组，再按 policy-map 落到对应 proxy group / exit。

排查顺序：

```bash
sudo 5gpn show-rules
sudo 5gpn show-policy
sudo 5gpn list-exits
sudo 5gpn set-policy ai tokyo     # 把 ai 规则组改走 tokyo 出口
```

如果某个分类没有 policy-map 项，脚本通常会按默认策略补齐；仍不符合预期时，显式 `set-policy` 后再 `set-exit smart` 重建。

## DNS / DoT 异常

| 现象 | 方向 |
| --- | --- |
| UDP/53 无应答 | mosdns 是否在跑；端口是否被占用 |
| status REFUSED | 上游 ACL/限流，或 `--set-dns` 上游不可达 |
| DoT TLS 失败 | 证书路径、域名、`openssl s_client -connect 127.0.0.1:853 -servername <域>` |
| 私网解析成网关但不应劫持 | `5gpn add-direct-domain …` 或核对客户端是否在配置的 CIDR 内 |

客户端网段（默认 `172.22.0.0/16`）支持英文逗号分隔多段：

```bash
sudo 5gpn detect-client-cidr          # 从本机网卡猜测
sudo 5gpn set-client-cidr 10.10.0.0/16
sudo 5gpn set-client-cidr 172.22.0.0/16,10.10.0.0/16
cat /etc/mosdns/.client_cidr
```

默认拒绝过宽网段（小于 `/16`）以避免误把大范围来源纳入劫持/放行。确认需要时设置 `FORCE_WIDE_CIDR=1` 后再运行命令。也可在 Bot「DoT 管理 → 客户端网段」或网页控制台「设置」中修改。改完后会刷新 mosdns；若是 `FIREWALL_MODE=managed`，也会尝试重写白名单。自管防火墙需自行放行新网段的 53/80/443。

## API / WebUI 访问

`5gpn setup-api` 默认把 API 绑定到 `127.0.0.1`，并由 API 服务同源提供 WebUI：

```bash
curl -k https://127.0.0.1:8444/api/health
```

如需公网访问，必须显式：

```bash
API_BIND=0.0.0.0 sudo 5gpn setup-api
```

同时用主机防火墙只向可信来源放行 API 端口。`API_ALLOW_ORIGIN` 默认留空（同源 WebUI 不需要 CORS）；只有明确要跨域托管控制台时才设置具体 Origin 或 `API_ALLOW_ORIGIN=*`。

## 私网 SOCKS5 连不上

可选功能，默认关闭。默认端口 **38443**（非 1080）。

```bash
sudo 5gpn client-socks-status
sudo 5gpn enable-client-socks          # 打印地址/用户/密码（只显示一次）
sudo 5gpn reset-client-socks-creds     # 忘记密码时轮换
```

核对：

1. 手机/客户端源 IP 必须在配置的客户端 CIDR 内（否则防火墙与进程 ACL 都会拒绝）。
2. Telegram 等填的是**网关公网 IP** + `38443`，不是 `172.22` 主机地址。
3. `FIREWALL_MODE=preserve` 时脚本会插入带 `5gpn-socks` 标签的临时规则；重启防火墙后可能丢失，需自行持久化。
4. `journalctl -u 5gpn-client-socks -n 50 --no-pager`

也可在 Bot「运维 → 私网 SOCKS5」或网页「设置」开关。

## SSH 到「主机名.域名」进了网关

私网客户端对非 ChinaList、非直连名单的域名会得到网关 IP；SSH 无 SNI，落到本机 `sshd`。

```bash
sudo 5gpn add-direct-domain box2.example.com
```

## 证书续期失败

确认域名 A 记录指向公网 IP，且公网能访问 TCP 80。签发/续期会临时停 sniproxy 并放行 80。见 `journalctl -u certbot` 与 `5gpn renew-cert`。

## Telegram 健康告警

`5gpn-health.timer` 每 20 分钟跑 `health-notify.sh`：配置了 `tgbot.env` 时发 Telegram；配置 `/opt/5gpn/etc/webhook.env` 且包含 `WEBHOOK_URL=...` 时，也会在状态变化时 POST JSON `{text, fail, ok}`。失败次数变化或恢复时推送。手动验证：

```bash
sudo systemctl list-timers 5gpn-health.timer
sudo bash /opt/5gpn/scripts/health-notify.sh
```

## 出口自愈（failover）不工作 / 行为异常

failover 默认关闭。开启后 `5gpn-failover.timer` 每 60s 探测当前出口的真实路径
（`curl --interface pgw-<出口>`）；连续 3 次失败才切换，切换有 10 分钟冷却、
每小时最多 3 次、手动 `set-exit` 后 5 分钟宽限。`local`/`smart` 不参与。

```bash
sudo 5gpn failover status            # 开关状态、候选顺序、内部状态 JSON
sudo 5gpn failover on|off            # 开关（Bot「运维 → 出口自愈」同效）
sudo 5gpn failover order hk,jp,us    # 固定候选顺序；不设置则按最近延迟排序
python3 /opt/5gpn/bin/failover.py tick   # 手动跑一跳，看 action 字段
systemctl list-timers 5gpn-failover.timer
```

手动探测当前出口：

```bash
curl --interface "pgw-$(cat /etc/5gpn/current-exit)" -m 8 -sf -o /dev/null -w '%{http_code}\n' \
  http://www.gstatic.com/generate_204
```

## 需要把现场发给维护者

在 Bot「运维 → 诊断报告」会收到脱敏 `.txt` 附件；或：

```bash
sudo 5gpn report
# 把打印出的 /tmp/5gpn-report-*.txt 发出去（默认已脱敏）
```
