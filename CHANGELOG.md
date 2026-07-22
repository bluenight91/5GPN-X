# Changelog

## Unreleased

### Fixed

- **Bot「自检 doctor」失败但终端正常**：systemd 下 `LANG=C` 时 `doctor --json` 打印中文检查项触发 `UnicodeEncodeError`。改为显式 UTF-8 写出，并为 tgbot 设置 `LANG=C.UTF-8`。
- **`5gpn update` 在 setup_api 中断**：`API_PORT_DEFAULT` 被误删导致 `set -u` 报 *unbound variable*；已恢复默认 `8444`。

### Added

- **私网 SOCKS5（可选）**：仅客户端 CIDR 可连、用户名/密码鉴权；默认监听 **TCP 38443**（避开 1080/7890 等常见口）；进程以 `pxout` 运行，出站跟随当前出口。
  - CLI：`5gpn enable-client-socks` / `disable-client-socks` / `client-socks-status` / `reset-client-socks-creds`
  - WebUI「设置 → 私网 SOCKS5」、API `GET/POST /api/client-socks`、Bot「运维 → 私网 SOCKS5」
  - 防火墙按模式放行（managed 写入规则槽；preserve/auto 打 `5gpn-socks` 标签）；doctor / report / uninstall / `set-client-cidr` 已挂钩

### Changed

- Telegram「诊断报告」：只发脱敏 `.txt` 附件，聊天中不再刷全文。
- Telegram「自检 doctor」：改为摘要（失败/警告列表），完整现场用诊断报告。
- 健康告警文案改为引导使用 Bot「运维」菜单；告警中列出失败项。

### Added

- Bot「DoT 管理 → 客户端网段」：查看 / 设置 / 自动探测。
- WebUI「设置 → 客户端网段」与 API `GET/POST /api/client-cidr`。
- doctor：检测 git HEAD 与 `.deployed-rev` 不一致（半更新）、健康定时器未启用。

### Fixed

- **`5gpn update` 同文件 install 中断**：在 `/opt/5gpn` 原地更新时，`install` 把 `scripts/*.sh` 拷到自身会报 *are the same file* 并触发失败回滚，导致 tgbot 等后续步骤未跑完。现用 `install_repo_script` 跳过同源拷贝。

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
