# 设计：控制台重构 + mihomo 面板安全接入

日期：2026-07-17 · 分支：feat/web-console · 状态：已批准

## 背景与目标

5GPN-X 已通过 `lib/api-server.py` + `webui/index.html` 获得 HTTP 控制 API 与静态控制台（移植自 5gpn）。本次迭代两件事：

1. **控制台重新设计**：结构重组 + 视觉刷新（双主题），并将 iOS Safari 移动体验作为一等公民。
2. **接入 mihomo 面板**：在"不允许非认证接入"的前提下，把 metacubexd 接入控制台，监控 smart 路由实例。

### 已确认的决策

| 决策点 | 结论 |
| --- | --- |
| 改版范围 | 结构重组 + 视觉刷新 |
| mihomo 能力 | 监控 + 实用控制集（延迟测试、断开连接、刷新规则集）；出口/策略切换仍归本控制台（走 5gpn-ctl） |
| 集成形态 | 混合：自制概览卡片 + 内嵌完整 metacubexd 面板 |
| 视觉风格 | 双主题：深色（运维风 A）/ 浅色（简洁风 B），默认跟随系统，可手动锁定 |
| 移动端 | iOS Safari 适配；<768px 使用底部标签栏导航 |
| 接入架构 | api-server 同源反代 + Clash secret 服务端注入（方案 1） |

## 整体架构

```
浏览器（webui/index.html 单文件，双主题 + 移动端底部标签栏）
  │  HTTPS + Bearer API_TOKEN（唯一认证入口，:8444）
  ▼
api-server.py
  ├─ /api/*                  现有控制端点 → 5gpn-ctl（不变）
  ├─ /api/mihomo/overview    新增：自制卡片聚合数据（连接数/规则命中/内存/版本）
  ├─ /api/mihomo/proxy/*     新增：反代 127.0.0.1:9090，服务端注入 Clash secret
  │                            （HTTP + WebSocket 中继，仅限白名单路径）
  └─ /mihomo/*               新增：metacubexd 静态文件（同样需认证）
mihomo router（smart 实例）：配置新增 external-controller 127.0.0.1:9090 + 随机 secret
```

安全模型：唯一公网入口是 8444（TLS + Bearer）。mihomo `external-controller` 只监听回环；Clash secret 仅存服务端（`/etc/5gpn/mihomo-api-secret`，0600），浏览器永不接触。`/mihomo/*` 与 `/api/mihomo/*` 全部走与 `/api/*` 相同的 Bearer 鉴权（`/api/health` 除外）。

## 组件设计

### 2.1 前端重写（`webui/index.html`）

保持**单文件、零依赖、零构建**的项目约束，整体重写：

- **双主题**：CSS 变量实现两套令牌（深色 = 运维风：深底、等宽数字、状态色；浅色 = 简洁风：白底卡片、细边框、柔阴影）。默认跟随系统 `prefers-color-scheme`，设置页可手动锁定（跟随系统 / 深色 / 浅色，localStorage 持久化）。`<meta name="theme-color">` 双主题各一，配合 `media` 属性。
- **布局**：≥768px 桌面侧边栏；<768px 底部标签栏（首页 / 出口 / 规则 / 监控 / 更多；AI 助手与设置收进"更多"）。
- **iOS Safari 适配清单**：
  - `viewport-fit=cover`，底部标签栏 `padding-bottom: env(safe-area-inset-bottom)`；
  - 输入框 `font-size ≥ 16px` 防聚焦自动缩放；
  - 高度用 `100dvh`（规避工具栏收缩抖动）；
  - 触摸目标 ≥44px；`-webkit-tap-highlight-color: transparent`；
  - `apple-mobile-web-app-capable` 等 meta，可"添加到主屏幕"。
- **页面（信息架构）**：
  1. **仪表盘**：状态卡片（CPU/内存/磁盘/运行时间）、实时速率与连接数、24h 流量与出口延迟曲线、**mihomo 概览卡**（连接数、Top 规则命中、内存、版本）；
  2. **出口管理**：列表、切换、增删改（含 `--edit-exit`）、连通性检查、延迟测试；
  3. **分流规则**：规则编辑、规则组管理（分类→出口映射）、域名路由测试器、一键定向；
  4. **mihomo 监控**：自制概览（连接/流量/日志摘要）+ "完整面板"入口（iframe 加载同源 `/mihomo/`）；
  5. **AI 助手**：沿用现有 `/api/ai/*`（自然语言 → 规则草案 → 人工确认）；
  6. **设置**：备份/恢复、更新规则集、API 令牌查看、主题切换。
- **metacubexd 接入**：iframe 指向同源 `/mihomo/index.html`；其后端配置为同源 `/api/mihomo/proxy`，secret 留空（服务端注入）。metacubexd 支持以带路径的 URL 作为后端 base URL；实现时先行验证，若版本不支持，则在静态托管时为其注入默认后端配置（同源反代地址），保证开箱即用。面板内仅使用监控与实用控制（测速/断开连接/刷新规则集），不做出口切换。

### 2.2 api-server 扩展（`lib/api-server.py`，约 +350 行）

- **静态服务** `GET /mihomo/*`：映射到安装目录 `${BASE_DIR}/webui/mihomo/`，路径规范化 + 白名单防穿越，基础 MIME 映射；需 Bearer 认证。
- **反代** `/api/mihomo/proxy/*` → `http://127.0.0.1:9090/*`：
  - 注入 `Authorization: Bearer <CLASH_SECRET>`（从 `MIHOMO_API_SECRET_FILE` 默认 `/etc/5gpn/mihomo-api-secret` 读取，可用环境变量覆盖）；
  - 剥除 hop-by-hop 头；响应原样回传；
  - **WebSocket 中继**：`Upgrade: websocket` 且路径在白名单（`traffic`、`logs`、`connections`、`memory`）时，向 mihomo 发起对应 upgrade 请求，完成 101 后进入裸 socket 双向转发（不解析帧，透传）；非白名单路径拒绝。
- **聚合端点** `GET /api/mihomo/overview`：调用 Clash API `/connections`、`/memory`、`/version`，聚合返回连接数、上下行总量、规则命中 Top N、内存、版本，供自制卡片。
- 以上全部沿用现有 `_auth()` Bearer 校验。

### 2.3 mihomo router 配置（`lib/mihomo-router-config.py`）

- smart 路由实例配置追加：
  ```yaml
  external-controller: 127.0.0.1:9090
  secret: <从 /etc/5gpn/mihomo-api-secret 读取>
  ```
- per-exit 实例**不开启** external-controller（攻击面最小化）。
- `regen_smart` 重建配置后生效（mihomo 重启）。

### 2.4 install.sh 变更

- `setup_api()` 扩展：
  1. 生成 Clash secret：`/etc/5gpn/mihomo-api-secret`（`openssl rand -hex 32`，0600，已存在则复用）；
  2. 安装 metacubexd：与 mihomo/mosdns 二进制一致的模式——**固定版本号 + 安装时从 GitHub release 下载 + 校验**，解压到 `${BASE_DIR}/webui/mihomo/`；
  3. 触发 `regen_smart` + 重启 smart 路由实例，使 external-controller 生效；
  4. 输出面板使用提示（mihomo 监控页位置）。
- 卸载：`do_uninstall` 已覆盖 5gpn-api；补充清理 `${BASE_DIR}/webui/mihomo/`（随 `rm -rf $BASE_DIR` 自然清理）与 `/etc/5gpn/mihomo-api-secret`（随 `rm -rf /etc/5gpn` 自然清理）——无需额外代码，仅验证。

### 2.5 端口与暴露面

| 端口 | 变更 |
| --- | --- |
| 8444 | 不变，仍是唯一公网入口（API + 静态面板 + 反代） |
| 9090 | 新增但**仅 127.0.0.1**（mihomo external-controller），防火墙无需任何放行 |

## 错误处理

- mihomo 未运行 / 9090 不可达：`/api/mihomo/*` 返回 502 + 中文错误说明，自制卡片降级显示"mihomo 离线"；
- Clash secret 文件缺失：api-server 启动可运行，仅 mihomo 相关端点返回 503；
- WS 中继异常（对端断开/超时）：双向拷贝任一端关闭即清理两端 socket，无泄漏；
- metacubexd 下载失败：`--setup-api` 给出警告但不中断（控制台其余功能可用）。

## 测试策略

- **新增 `tests/test_api_mihomo_policy.sh`**：断言反代/WS 白名单/secret 注入/静态服务/9090 仅回环/external-controller 配置生成等关键代码片段存在；
- **新增 `tests/test_api_mihomo.py`**（unittest）：反代路径映射、secret 注入头、非白名单 WS 路径拒绝、路径穿越防护；
- 保留全部现有测试（20 个 shell + Python 单测）不回归。

## 交付边界（不做）

- per-exit mihomo 实例开启 external-controller；
- 面板内出口/策略切换（已决定归本控制台）；
- PWA manifest / 离线缓存；
- AI 助手功能变更（仅随整体重写迁移样式）。

## 工作量预估

- `webui/index.html` 重写：约 1200 行（单文件）；
- `lib/api-server.py`：+约 350 行；
- `lib/mihomo-router-config.py`：+约 15 行；
- `install.sh`：+约 80 行；
- 测试：2 个新文件。
