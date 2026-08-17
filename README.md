# Odyssey Adult Log

一个轻量化的 Discord 审核日志（Audit Log）归档与检索 Bot。长期落库保存服务器的审核日志，支持按执行者、被操作者、操作类型、时间范围检索，并自动自愈补全数据缺口。

## 功能

- **实时归档**：通过 Gateway 事件 `GUILD_AUDIT_LOG_ENTRY_CREATE` 实时接收审核日志，先落盘到 SQLite staging 中转表，再由后台 worker 转入正式表，进程崩溃不丢已落盘数据。
- **自动自愈**：定期通过 REST 增量拉取，用持久化 checkpoint 加重叠窗口补齐 Gateway 阶段可能丢失的条目，无需手动全量回填。
- **45 天历史回填**：支持从 Discord 当前保留期（45 天）内完整回填历史审核日志。
- **检索命令**（Slash Command）：
  - `/audit by-actor`：查询某用户执行的操作
  - `/audit by-target`：查询以某用户为目标的操作
  - `/audit stats`：查看归档与同步状态
- **权限管理**：
  - `/audit role-add`、`/audit role-remove`、`/audit role-list`、`/audit role-clear`：管理可查询的身份组
  - `/audit backfill`：手动触发历史回填
- **存储**：单文件 SQLite（WAL 模式），无需外部数据库，轻量部署。

## 技术栈

- Python 3.10+
- [discord.py](https://github.com/Rapptz/discord.py) 2.x
- 标准库 `sqlite3`、`asyncio`

## 快速开始

### 1. 创建 Discord Application

前往 [Discord Developer Portal](https://discord.com/developers/applications) 新建一个 Application，创建 Bot，并：

1. 开启 `GUILD_MODERATION` intent（用于接收审核日志事件）。
2. 复制 Bot Token。
3. 邀请 Bot 加入目标服务器，授权时需要 `View Audit Log` 权限。

### 2. 安装依赖

```bash
pip install "discord.py==2.7.1"
```

### 3. 配置环境变量

```bash
export DISCORD_TOKEN="你的 Bot Token"
export TARGET_GUILD_IDS="目标服务器ID"        # 可选，多个用逗号分隔；留空则监控所有服务器
export AUDIT_DB="./data/audit_logs.db"          # 可选，SQLite 文件路径
export AUDIT_SYNC_INTERVAL_MINUTES=10           # 可选，自愈间隔（分钟），默认 10
export AUDIT_REPLAY_OVERLAP_SECONDS=300         # 可选，自愈重叠窗口（秒），默认 300
export AUDIT_COMMAND_SYNC_MODE=none             # 可选：none / guild / global
export AUDIT_COMMAND_GUILD_IDS="目标服务器ID"   # guild 同步模式时使用
```

### 4. 首次部署同步命令

首次部署建议用 guild 作用域同步 Slash Command：

```bash
export AUDIT_COMMAND_SYNC_MODE=guild
export AUDIT_COMMAND_GUILD_IDS="目标服务器ID"
python discord_audit_archiver.py
```

日志确认同步成功后，可改为 `AUDIT_COMMAND_SYNC_MODE=none` 并重启，避免每次启动都同步。

### 5. 运行

```bash
python discord_audit_archiver.py
```

建议使用 systemd 或容器托管，实现开机自启与崩溃自动拉起。

## 权限模型

| 命令 | 允许使用者 |
|---|---|
| `role-add` / `role-remove` / `role-list` / `role-clear` / `backfill` | 服务器拥有者 + Administrator |
| `by-actor` / `by-target` / `stats` | 服务器拥有者 + 已授权身份组 |

可选：设置 `AUDIT_ALLOW_VIEW_LOG_PERMISSION=true` 可额外放行持有 `View Audit Log` 权限的成员使用查询命令。

## 数据说明

- 审核日志条目在 Discord 端仅保留 **45 天**，本 Bot 的本地归档是长期留底的唯一来源，请妥善备份数据库。
- `MESSAGE_DELETE` 的审核条目**不包含消息正文**，仅记录被删消息的作者、频道和数量。
- 部分聚合操作（如 `MEMBER_MOVE`、`MEMBER_PRUNE`、`MESSAGE_BULK_DELETE`）Discord 不提供具体被操作成员名单，无法按人检索。

## License

[MIT](./LICENSE)

