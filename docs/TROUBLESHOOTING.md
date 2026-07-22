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

## smart 分流全灭

1. `sudo 5gpn doctor --deep`：看 `5gpn-mihomo@smart`、`pgw-smart`、表 100、TUN 出网。
2. `journalctl -u 5gpn-mihomo@smart -n 50 --no-pager`
3. `ip route show table 100`、`ip rule show | grep fwmark`
4. 确认 `rules.conf` / 策略映射后：`sudo 5gpn set-rules` 或 `set-exit smart`

## DNS / DoT 异常

| 现象 | 方向 |
| --- | --- |
| UDP/53 无应答 | mosdns 是否在跑；端口是否被占用 |
| status REFUSED | 上游 ACL/限流，或 `--set-dns` 上游不可达 |
| DoT TLS 失败 | 证书路径、域名、`openssl s_client -connect 127.0.0.1:853 -servername <域>` |
| 私网解析成网关但不应劫持 | `5gpn add-direct-domain …` 或核对客户端是否在配置的 CIDR 内 |

客户端网段（默认 `172.22.0.0/16`）：

```bash
sudo 5gpn detect-client-cidr          # 从本机网卡猜测
sudo 5gpn set-client-cidr 10.10.0.0/16
cat /etc/mosdns/.client_cidr
```

改完后会刷新 mosdns；若是 `FIREWALL_MODE=managed`，也会尝试重写白名单。自管防火墙需自行放行新网段的 53/80/443。

## SSH 到「主机名.域名」进了网关

私网客户端对非 ChinaList、非直连名单的域名会得到网关 IP；SSH 无 SNI，落到本机 `sshd`。

```bash
sudo 5gpn add-direct-domain box2.example.com
```

## 证书续期失败

确认域名 A 记录指向公网 IP，且公网能访问 TCP 80。签发/续期会临时停 sniproxy 并放行 80。见 `journalctl -u certbot` 与 `5gpn renew-cert`。

## Telegram 健康告警

`5gpn-health.timer` 每 10 分钟跑 `health-notify.sh`：仅在配置了 `tgbot.env` 时发信；失败次数变化或恢复时推送。手动验证：

```bash
sudo systemctl list-timers 5gpn-health.timer
sudo bash /opt/5gpn/scripts/health-notify.sh
```

## 需要把现场发给维护者

在 Bot「运维 → 诊断报告」会收到脱敏 `.txt` 附件；或：

```bash
sudo 5gpn report
# 把打印出的 /tmp/5gpn-report-*.txt 发出去（默认已脱敏）
```
