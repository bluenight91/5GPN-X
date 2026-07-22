# Changelog

## Unreleased

### Added

- **`5gpn doctor`**：结构化只读健康检查（`--json` / `--deep` / `--quiet`）；原 `5gpn smoke` 变为 `doctor --deep` 别名。
- **`5gpn report`**：生成脱敏诊断报告到 `/tmp`（可选 `--full`）。
- **`5gpn snapshot` / `5gpn rollback`**：配置快照与回滚（默认保留 5 份，目录 `/var/lib/5gpn/snapshots`）。
- **更新前自动快照**：`5gpn update` 在改动运行时前创建 `pre-update` 快照；失败时尝试自动回滚。
- **`5gpn set-client-cidr` / `detect-client-cidr`**：可配置私网客户端源网段（写入 `/etc/mosdns/.client_cidr`，默认仍为 `172.22.0.0/16`）；mosdns 与 managed 防火墙随之渲染。
- **`5gpn-health.timer`**：每 10 分钟跑 doctor；在配置了 Telegram Bot 时，失败/恢复会推送告警。
- Telegram Bot 运维菜单：自检、诊断报告、快照、回滚。
- 文档：`docs/TROUBLESHOOTING.md` 排查手册。

### Changed

- mosdns 模板中 `client_ip` 改为 `__CLIENT_CIDR__` 占位符，由 `update-rules` 按配置替换。
- managed 防火墙（nft/iptables）白名单改为读取 `.client_cidr`，不再写死 `172.22.0.0/16`。
