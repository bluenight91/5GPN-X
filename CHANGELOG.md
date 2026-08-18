# Changelog

## Unreleased

### Fixed

- WebUI 7d/30d 日汇总流量图纵轴单位错误：日汇总点是一天的总字节量，此前套用速率公式（字节×8÷86400）把每日总量显示成"全天平均速率"（如 7.7GB/天 显示为 717 Kbps）。现在日汇总视图按每日总量（GB/天）绘制，并在图注中注明"流量=每日总量，延迟=日均值"，与速率口径的 24h 及更短窗口区分开。Policy 测试锁定。

## v1.2.2 (2026-08-18)

### Removed

- 移除 WLOC 虚拟定位功能：苹果在最新 iOS beta 中对 `gs-loc.apple.com` 启用证书固定，拦截改写定位响应已失效；升级时自动清理旧 WLOC 单元与运行时文件。

### Fixed

- `--update` 此前只刷新 mosdns 模板而不重渲染活配置 `/etc/mosdns/config.yaml`（只有每周规则更新才渲染）：模板与活配置漂移导致 WLOC 移除后旧配置仍引用已删除的 `wloc.txt`，mosdns 崩溃循环。`do_update` 现在刷新模板后立即重渲染并验证（validate-then-publish，失败仅告警）。Policy 测试锁定。
- `/api/traffic/daily` 与 `/api/latency/daily` 端点少传 `_load_json` 的 default 参数，请求即 TypeError（webui 7d/30d 图无数据）。新增真实 HTTP 端点级回归测试。

## v1.2.0 (2026-08-08)

### Added

- Daily config snapshot timer: `5gpn-snapshot.timer` takes a config snapshot every day (retention `SNAP_KEEP=7`), so a bad change can be rolled back with `5gpn rollback <name>` even when nobody noticed for days. Sandboxed per I10; locked by `tests/test_snapshot_timer_policy.sh`.
- API token self-service rotation: `5gpn --rotate-token` (also 运维 → 🔑 轮换令牌 in the TG bot, behind a confirm step) regenerates `API_TOKEN`, re-renders dependent units, and restarts the API without a full reinstall.
- API/webui source allowlist: `etc/api-allow.list` (CIDRs, hot-reloaded) makes the app layer answer HTTP 403 to non-listed sources on the control API; managed via `5gpn --api-allow list|add|del` and the TG bot (运维 → 🛡 API 白名单). Enforced at the HTTP layer because the installer never opens 8444 in any firewall template — that stays the operator's own firewall's job.
- Opt-in exit failover watchdog (invariant I11): `5gpn failover on|off|status|order` runs `lib/failover.py` against the active exit (probe via the exit's own `pgw-<name>` interface), switching to the next candidate after 3 consecutive failures with anti-flap guards (600s cooldown, ≤3 switches/hour, 300s grace after a manual switch, candidate order from `FAILOVER_ORDER` or measured latency). Telegram notifications reuse the bot credentials. Off by default.
- Long-range stats: the API now rolls the 24h traffic/latency rings into per-UTC-day buckets kept for 62 days (`history-traffic.json` / `history-latency.json`, idempotent fold, atomic writes) and serves them via `GET /api/traffic/daily?days=N` / `GET /api/latency/daily?days=N`. The webui time-range selector gains 7d/30d windows (daily ticks, UTC-day tooltips, in-progress today included).
- systemd unit hardening (invariant I10): sniproxy gets `ProtectSystem=strict` + `/var/run` write path (still no `NoNewPrivileges` — it binds 80/443 as root then setuid's to `pxout`); quic-proxy gets strict sandbox + capability bounding; mosdns is address-family restricted; `5gpn-mihomo@` is bounded to `CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER` (TUN + config I/O only); the iOS profile responder is sandboxed; the root orchestrators `5gpn-tgbot`/`5gpn-api` get `ProtectSystem=full` with an explicit identical `ReadWritePaths` whitelist (`/etc/5gpn`, `/etc/mosdns`, `/etc/sniproxy.conf`, `/etc/wireguard`, `/etc/nftables.conf`, `/etc/letsencrypt`, `/etc/systemd/system`, `/usr/local/bin`). Locked by `tests/test_systemd_hardening_policy.sh`. **Server-side acceptance after updating:** `systemd-analyze security <unit>` before/after, restart every unit, re-run `smoke-check`, and exercise add/delete/switch-exit from the TG bot — a missed whitelist path shows up as a read-only-fs error and gets a follow-up fix.
- Post-deploy readiness probe: `verify_installation` runs `doctor --deep --json` at the end of both fresh installs and `--update`, classifying failures by surface — core (services / listening ports / control API) fails the deploy with a pointer to `5gpn doctor --deep`, advisory (DNS answers, egress path, certs) only warns since domain propagation and cert issuance are legitimately transient. No automatic rollback on probe failure (fail-before-publish; the manual `5gpn rollback` path is printed instead). Locked by `tests/test_readiness_probe_policy.sh`.
- Normative architecture doc `docs/architecture.md`: system boundary, data flow, and runtime invariants I1–I9 (firewall managed-mode limits, loopback-only Clash API, pxout egress marking, secret permissions, sniproxy resolver rules, deterministic TUN naming, idempotent installs, validate-then-publish, public-repo hygiene), locked by the new `tests/test_architecture_invariants.sh` policy test. A short `AGENTS.md` points agents at the doc and the hard constraints.
- mihomo MASQUE exit type: `5gpn add-exit` accepts a custom `masque://` share URI or a pasted mihomo-style masque YAML proxy block (usque/wiki format); base64 keys are validated and normalized (URL-safe/PEM tolerated), `ip`/`ipv6` must be CIDR, `network` limited to `quic`/`h2`. The TG bot accepts both forms too (YAML paste takes its `name:` field as the exit name). UDP-transport exits (hysteria2/tuic/masque) are no longer TCP-probed by `check-exits`/`preflight_exit`, avoiding false UNREACHABLE/DOWN reports.

### Changed

- `install.sh` (5.5k lines) is split into sourced modules `lib/setup-core.sh` (deps/mosdns/sniproxy/certs/iOS), `lib/setup-exit.sh` (egress/mihomo/policy routing), `lib/setup-control.sh` (API/tgbot/webui/client proxies/failover), and `lib/setup-ops.sh` (schedules/snapshots/update/uninstall/lifecycle); `install.sh` keeps constants, the curl|bash bootstrap, logging helpers, usage, and command dispatch. Function bodies moved byte-for-byte (verified by a structural comparison script); curl|bash bootstrap re-execs into a full clone as before. ShellCheck in CI covers the new files; `tests/test_install_modules_policy.sh` locks the layout.

### Fixed

- Readiness probe raced service startup: right after `do_update` restarts mosdns, a low-memory host needs seconds to load rulesets and bind 53/853, so the probe reported false core failures (`DoT/DNS not listening`) on an otherwise healthy deploy. `verify_installation` now poll-waits (up to 60s) for the DoT/DNS listeners before running `doctor --deep`.
- I10 comment regression: the `5gpn-mihomo@` unit heredoc is unquoted, so a backticked `` `ip route/rule` `` in an explanatory comment was executed at unit-render time (`Object "route/rule" is unknown` noise on every install/update). Backticks removed; policy test now rejects backticks in any unquoted systemd unit heredoc.
- `--update` now re-renders the tgbot unit via `setup_tgbot` (reusing the existing `tgbot.env` credentials, non-interactive) instead of only swapping `tgbot.py` and restarting — previously the I10 sandbox directives never reached `5gpn-tgbot.service` on updated hosts. Policy test asserts every hardened unit is re-rendered during updates.
- Managed firewall mode: the generated `/etc/nftables.conf` no longer starts with a global `flush ruleset`; it now recreates only the project's own `inet filter` table (idempotent add-then-delete). A full flush also deleted chains owned by other netfilter users of the same kernel ruleset — notably docker's `DOCKER`/`DOCKER-FORWARD` chains via the iptables-nft shim — breaking `docker compose up` network creation (`No chain/target/match by that name`) until a docker restart.

## v1.1.0 (2026-07-28)

### Added

- HTTPS Clash remote API for third-party panels (Sphere / Neko Dash): token-authenticated remote read of mihomo state over HTTPS, enable/reset flow with API-parsed output contract.
- Optional private MTProto proxy on TCP 5753 (mtg + client-CIDR ACL): classic secrets Telegram can paste as 32-hex, FakeTLS wrap for bare keys, enable fails closed when mtg/front are inactive, fuller status coverage.
- Self-service version bumps: `5gpn update-webui [ver]` upgrades the vendored metacubexd dashboard and `5gpn update-mihomo [ver]` upgrades the mihomo TUN engine (restarting running exit instances). Explicit versions are pinned via `etc/metacubexd.pin` / `etc/mihomo.pin` so later `5gpn update` runs never silently downgrade; mihomo installs now record the installed version and `ensure_mihomo` resolves env > pin > repo default.
- Component version management in WebUI and TG bot: `GET /api/component/versions` reports current/pinned/latest (upstream latest from GitHub, 10-minute cache, failure-tolerant) and `POST /api/component/update` runs the pinned upgrade. The WebUI settings (运维 → 组件版本) and the bot ops menu (运维 → 🧩 组件版本) offer update checks, one-click upgrades (mihomo upgrade asks for confirmation since it restarts exits), and manual version pinning.

### Changed

- Hardening defaults: API now binds to `127.0.0.1` by default with empty CORS, mosdns cache/logging and China-DNS concurrency are reduced, and health checks run every 20 minutes.
- Runtime units now include restart throttles and memory caps; mihomo Go memory limits scale with RAM.
- Client CIDR handling supports comma-separated multi-CIDR lists across mosdns/firewall paths, with wide CIDRs gated by `FORCE_WIDE_CIDR=1`.
- WebUI stores API tokens in `sessionStorage`, distinguishes lightweight config packages from runtime snapshots, and exposes doctor/report/snapshot operations.

### Added

- Optional health-change webhook via `/opt/5gpn/etc/webhook.env` (`WEBHOOK_URL=...`) in addition to Telegram alerts.

### Fixed

- TG bot DNS upstream validation now matches `--set-dns`: DoH/DoT upstreams may use domain hostnames and custom paths (e.g. self-hosted AdGuard Home `https://domain/api/<id>`), while udp/tcp upstreams still require IP literals. Previously the bot rejected any non-IP hostname and any DoH path other than `/dns-query`, so camouflaged DoH endpoints could only be set from the CLI.
- `5gpn snapshot list` and `5gpn snapshot restore [id]` now dispatch to snapshot subcommands correctly.
- Private SOCKS5 enablement now aborts if firewall synchronization fails.

### Fixed

- **Bot doctor 在 #12 后仍误报**：`doctor --json` 改为经临时文件传 RESULTS（避免 argv/locale 丢检查项）；Bot 侧隔离 stderr、用干净 PATH 调用，并对 tgbot/api/smart/fwmark/pgw_exit 做主机侧复核纠错（Bot 进程存活即认定 tgbot 在跑）。

### Fixed

- **Bot doctor 仍误报服务/fwmark 全挂**：即便 #11 已合入，若未跑完 `5gpn update`，磁盘上旧的整份 `5gpn-ctl` 仍会 bootstrap。Bot 现启动时自动把 legacy ctl 修成薄包装，且 `op_doctor` 直接调用 `/opt/5gpn/scripts/doctor.sh`；doctor 内 `systemctl`/`ip`/`nft` 改用绝对路径。
- **Bot doctor 误报服务全挂**：`/opt/5gpn/bin/5gpn-ctl` 曾是整份 `install.sh` 拷贝，`SCRIPT_DIR` 变成 `/opt/5gpn/bin`，每次调用都会 bootstrap `git clone`，自检结果不可靠。改为与 `5gpn` 相同的薄包装，转调 `/opt/5gpn/install.sh`。
- **mihomo 面板看不到出口**：smart 配置缺少 `proxy-groups` 时，metacubexd「代理」页不易列出仅作为规则目标的出口；现会预加载全部出口，并增加仅供展示的 `EXITS` 选择组（规则仍直接指向出口名，不影响分流）。
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
- **`5gpn-health.timer`**：每 20 分钟跑 doctor；在配置了 Telegram Bot 或 webhook 时，失败/恢复会推送告警。
- Telegram Bot 运维菜单：自检、诊断报告、快照、回滚。
- 文档：`docs/TROUBLESHOOTING.md` 排查手册。

### Changed

- mosdns 模板中 `client_ip` 改为 `__CLIENT_CIDR__` 占位符，由 `update-rules` 按配置替换。
- managed 防火墙（nft/iptables）白名单改为读取 `.client_cidr`，不再写死 `172.22.0.0/16`。
