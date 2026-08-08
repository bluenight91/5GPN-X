# AGENTS.md

架构真相源是 [docs/architecture.md](docs/architecture.md)——改动架构前先读它，
改动后同步更新它。它定义的运行时不变量 I1–I11 由 `tests/` 下的 policy 测试锁定。

硬约束：

1. 本仓库是公开仓库：真实域名、密钥、token 永不进库，示例一律用 `example.com`。
2. `FIREWALL_MODE` 默认 `preserve`，只有显式 `managed` 才能写 `/etc/nftables.conf`，
   且禁止全局 `flush ruleset`（详见不变量 I1）。
3. 生成的 mihomo 配置必须先 `.tmp` + `mihomo -t` 校验再 `mv` 发布（不变量 I8）。
4. `install.sh` 只保留常量、bootstrap、日志函数、usage 与命令分发；函数本体按域
   拆到 `lib/setup-core.sh`（DNS/mosdns/sniproxy/证书/核心服务）、
   `lib/setup-exit.sh`（出口/mihomo/策略路由）、`lib/setup-control.sh`
   （客户端 SOCKS/MTProto/Clash-remote/tgbot/API）、`lib/setup-ops.sh`
   （CLI/更新/卸载/生命周期），由 install.sh 顶部按此顺序 source。

验证基线（提交前必跑）：

```bash
python3 -m unittest discover -s tests -p "test_*.py"
pipx run ruff check lib/ tests/
bash -n install.sh lib/host-setup.sh lib/setup-*.sh
for t in tests/test_*_policy.sh; do bash "$t"; done
```
