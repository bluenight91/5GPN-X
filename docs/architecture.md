# 5GPN-X 当前架构

本文档是当前系统的**规范性描述**（唯一架构真相源）。改动架构前必须先读本文；
改动架构后必须同步更新本文。设计草稿、历史代码、对话记录都不是当前行为的依据。

## 系统边界

5GPN-X 是一个多出口代理网关。客户端用系统原生 DoT（Android Private DNS /
iOS 描述文件）或明文 DNS 接入，DNS 答案决定"直连还是进网关"；进网关的 TCP/UDP
流量由本机透明代理接管，经策略路由进入当前出口的 mihomo TUN 实例出网。

运行时组件：

| 组件 | 职责 | 身份 |
| --- | --- | --- |
| `mosdns` | DNS 入口（DoT `:853` + UDP/TCP `:53`），按规则把命中域名改写为网关地址 | `mosdns` 用户 |
| `sniproxy` | TCP `80`/`443` SNI 透明代理（仅监听 `127.0.0.1:8443` 与 `0.0.0.0:80`） | root 启动，自降 `pxout` |
| `wa-shim` | 公网 TCP `443` 前置（WhatsApp no-SNI 分流），fail-open 到 sniproxy | `pxout` |
| `quic-proxy` | UDP `443` QUIC 透明代理 | `pxout` |
| `5gpn-mihomo@<exit>` | 每个出口一个 mihomo 实例 + 独立 TUN 设备 | root（需建 TUN） |
| `5gpn-tgbot` | Telegram 控制面 | root（编排服务） |
| `5gpn-api` | HTTP 控制 API + 静态 webui（默认仅回环 `:8444`） | root（编排服务） |
| `5gpn-ios-profile.socket` | iOS 描述文件 HTTP 分发（每连接一个实例） | root 短时 |
| 可选 | `5gpn-wloc`、`5gpn-mtproxy`、`5gpn-client-mtproto`、`5gpn-client-socks`、`5gpn-clash-remote` | 各自专用用户 |

## 数据流

```text
Android Private DNS / iOS 描述文件          明文 DNS
        | DoT :853                            | UDP :53
        v                                     v
                   mosdns（规则改写）
              命中代理名单 → 网关 IP；否则 → 真实 IP
                        |
              客户端连接网关 80/443(TCP)、443(UDP)
                        |
        wa-shim(:443) → sniproxy(:8443) / sniproxy(:80) / quic-proxy(UDP:443)
                        |
              以 pxout 用户发出 → fwmark 打标
                        |
              表 100 默认路由 → pgw-<当前出口> (TUN)
                        |
              5gpn-mihomo@<exit> → 运维者配置的节点出网
```

## 运行时不变量

以下不变量由 `tests/test_architecture_invariants.sh` 等 policy 测试锁定。
任何改动违反其中一条，都必须同时修改本文与对应测试——三者一致才算完成。

- **I1 防火墙**：`FIREWALL_MODE` 默认 `preserve`，不碰主机防火墙。仅显式
  `managed` 模式才写 `/etc/nftables.conf`，且 managed 模板**禁止全局
  `flush ruleset`**——只允许 `table inet filter` + `delete table inet filter`
  的本表 scoped 重建。全局 flush 会连坐删除同内核 ruleset 里其他使用者
  （如 docker 经 iptables-nft 的 `DOCKER`/`DOCKER-FORWARD` 链）。唯一例外是
  卸载流程的灾难恢复 fallback（`lib/host-setup.sh` 中的应急 rewrite）。
- **I2 Clash API**：mihomo `external-controller` 只绑定 `127.0.0.1:9090`，
  绝不暴露公网。
- **I3 出口打标**：进网关的流量由 `pxout`（`EXIT_USER`）用户发出，经
  fwmark + 表 100 策略路由进入当前出口 TUN；直连流量不打标。
- **I4 密钥权限**：`/etc/5gpn` 目录 `700`；`*.env`、出口 `.uri`、各类
  secret 文件 `600`。
- **I5 sniproxy 配置**：`resolver` 的 `nameserver` 必须是 IP 字面量且每条
  独立成行。域名会被跳过（`[WARN] Skipping invalid sniproxy DNS address`），
  拼接在同一行会让 sniproxy 解析失败、启动即退出（2026-07-19 事故教训）。
- **I6 TUN 命名**：设备名确定性派生 `pgw-` + `sha256(出口名)[:11]`。
  bash（`sha256sum | cut -c1-11`）与 python（`hexdigest()[:11]`）两处实现
  必须保持一致。
- **I7 幂等与配置所有权**：`install.sh` 重跑幂等；安装/升级不重建、不覆盖
  运维者的出口 YAML（`/etc/5gpn/exits/*.yaml`）与自定义规则。
- **I8 先校验再发布**：所有生成的 mihomo 配置先写 `.tmp`，`mihomo -t`
  校验通过后才 `mv` 正式发布；校验失败保留旧配置。
- **I9 公开仓库**：真实域名、密钥、token 永不进入仓库；文档与测试中的
  示例一律使用 `example.com`。
- **I10 单元沙盒**：非编排服务一律 `ProtectSystem=strict` + 能力边界 +
  `ProtectHome`/`PrivateTmp`；编排服务（`5gpn-tgbot`、`5gpn-api`）用
  `ProtectSystem=full` + 显式 `ReadWritePaths` 白名单，两者白名单必须一致。
  需要启动后自主降权的 sniproxy 和需要建 TUN 的 `5gpn-mihomo@` **禁止**
  `NoNewPrivileges`；`5gpn-mihomo@` 用 `CapabilityBoundingSet` 收敛到
  TUN 与配置读写所需的最小能力集，且不加 `ProtectSystem`
  （ExecStartPost 与 drop-in 面太宽）。

## 目录与文件所有权

| 路径 | 内容 | 写入者 |
| --- | --- | --- |
| `/opt/5gpn` | 程序本体（bin/scripts/lib/webui） | `install.sh` |
| `/etc/5gpn` (700) | 运行配置：`exits/`、`current-exit`、`*.env`、`pgw-exit.nft` | install.sh / tgbot / api-server |
| `/etc/5gpn/exits/*.yaml` (700 目录内) | 运维者出口配置 | 运维者经 CLI/tgbot/api；生成走 I8 |
| `/etc/mosdns` | mosdns 配置、证书、规则缓存 | install.sh / update-mosdns-rules.timer |
| `/etc/sniproxy.conf` | sniproxy 配置（脚本生成，I5） | install.sh / DNS 切换流程 |
| `/etc/systemd/system/` | 全部单元与 drop-in | install.sh（唯一写入者） |

## 与 moooyo/5gpn 的差异

moooyo/5gpn 是同源项目的另一种走向：纯 DNS steering，明确不碰 TUN、
fwmark、防火墙，出口只有一份运维者 mihomo 配置。本项目保留 UDP `:53`
明文入口、多出口 TUN 策略路由、可选 `managed` 防火墙模式与
wa-shim/quic-proxy 透明代理层。两项目机制可互相借鉴，架构边界不可混用。
