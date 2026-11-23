# 加密备份服务（支持主密钥在线轮换 + 断点续传准备）

基于 Flask + SQLite + `cryptography` 的小型备份页：上传小文件加密备份、下载还原原件，
并支持主密钥（KEK）的发起轮换、进度查看和旧密钥移除。备份页可为单份备份执行
"准备续传"：之后就绪备份的下载链接支持 HTTP Range 断点续传，且只读取所需密文块。

## 1. 密码学模型：信封加密

```
明文文件 ──AES-256-GCM(DEK)──► 密文正文 blob（备份卷，只存密文）
每份备份独立 DEK（32 字节随机）
DEK ──AES-256-GCM(KEK)──► wrapped_dek（SQLite，密钥卷）
主密钥 KEK（32 字节随机，0600 权限文件，密钥卷）
```

- **每份备份一个独立数据密钥 DEK**，互不相同；相同明文产出的密文也不同。
- **主密钥与备份分卷保存**：
  - `keystore` 卷：主密钥文件 `*.kek` + SQLite 元数据库（含被包装的 DEK）
  - `backup-volumes` 卷：只有密文正文 `*.blob`，拿走此卷无法解密
- GCM nonce 为 12 字节随机数并前置；包装 DEK 时以 `backup_id + kek_id` 作为 AAD 绑定，
  防止包装记录被挪动复用；正文 blob 以 `backup_id` 作为 AAD。
- 下载还原后会校验 SHA-256，密文被篡改时 GCM 认证直接失败。

## 2. 轮换语义（重点）

| 需求 | 实现方式 |
| --- | --- |
| 轮换不重写正文密文 | 轮换只把 DEK 用新 KEK **重新包装**（新增一行 `wrapped_keys`），blob 文件字节不变 |
| 上传/恢复无需等轮换结束 | 上传走当前 active KEK；下载会尝试该备份所有可用 KEK 的包装，任一可用即可还原 |
| 轮换启动后的新备份只用新 KEK 恢复 | 轮换启动即把新 KEK 置为 active、旧 KEK 置 retired，新上传只写新 KEK 包装，且不计入轮换总数 |
| 进程中断后能继续 | 轮换进度全部持久化在 `rotation_jobs` / `wrapped_keys`；新进程启动后后台 worker 自动续跑同一任务，重包装按 `(backup_id, kek_id)` 唯一索引幂等 |
| 全部备份可用新 KEK 恢复后才允许移除旧 KEK | `remove_key` 强校验：active 不可删、有 running 轮换不可删、存在"仅依赖该 KEK"的备份不可删；通过后先删元数据再粉碎密钥文件 |

### 轮换的状态机

1. `POST /rotations`：生成新 KEK 文件并置 active，旧 KEK 置 retired，创建 `running` 任务，
   任务总量 = 启动那一刻挂在旧 KEK 下的备份数。
2. 后台 `RotationWorker` 每 `ROTATION_INTERVAL` 秒取一批（`ROTATION_BATCH` 个）尚未获得
   新 KEK 包装的备份：用旧 KEK 解开 DEK → 用新 KEK 重新包装 → 写新包装 → 更新进度。
3. 当所有旧 KEK 下的备份都有了新 KEK 包装，任务置 `completed`（旧包装保留，直到显式移除旧 KEK）。
4. 控制台对已退役且可安全移除的 KEK 显示"移除并粉碎"按钮；移除时覆写+删除密钥文件。

## 3. 断点续传准备（HTTP Range resume）

未准备的备份走**原规则**：每次下载（含 Range 请求）都读取并校验整份密文，由
`send_file` 在已校验明文上切片返回。为单份备份点击"准备续传"后，后台 worker 会：

1. 解开 DEK，解密整份原始 blob 并校验 SHA-256（**原件校验不通过则准备失败**）；
2. 把明文按 64 KiB 逐块用**同一 DEK** 重新加密（AES-256-GCM，AAD 绑定
   `backup_id + 块序号 + 全文件 SHA-256`），写入 `*.prep.tmp`；
3. fsync 后原子改名 `<backup_id>.prep`，再落库置为 `ready` —— **写全之前不显示就绪**。

就绪后的语义：

| 需求 | 实现方式 |
| --- | --- |
| 只读所需密文 | 每块独立认证，连续 64 KiB 请求最多触及 2 个块记录（≤ 128 KiB + 56 B），远低于 512 KiB 预算 |
| 先认证后返回 | 请求范围涉及的全部块通过 GCM 认证后才返回 206；任一块失败返回 500，**不发送任何明文** |
| 坏段隔离 | 某块密文损坏只影响覆盖该块的 Range 请求；其余块照常 206，整份下载（走原 blob）也不受影响 |
| 额外磁盘有界 | 每块仅多 28 B（12 B nonce + 16 B tag），单份准备 ≤ 原密文 + 64 KiB；重试前先清旧文件 |
| 重启语义 | `ready` 行与 `.prep` 文件都在卷上，重启后直接续传；`preparing` 行由 worker 自动重试，启动时清理孤儿临时文件 |
| 失败可重试 | 准备失败只影响该功能本身：原链接仍按原规则整份下载，页面可重试 |
| 与轮换正交 | 块用 DEK 加密而非 KEK，轮换只重包装 DEK；正常移除旧主密钥后就绪备份仍可续传 |
| 暂停不阻塞 | "暂停准备"只让准备 worker 空转；上传、整份下载、主密钥轮换照常完成（准备的重计算不持有写锁） |

原始 blob 永远保留、永不改写：整份下载的校验逻辑与之前完全一致；两个卷上都只有密文
（`.prep` 与 `.blob` 同在密文卷），密钥卷仍只有 KEK 文件与 SQLite 元数据。

## 4. 快速开始（Docker Compose）

```bash
docker compose up --build
# 打开 http://localhost:8000
```

两个命名卷分别承载密钥/元数据与密文正文，见 `docker-compose.yml`：

```yaml
volumes:
  keystore:          # /data/keystore：*.kek 主密钥 + backup.db
  backup-volumes:    # /data/volumes：*.blob 密文正文
```

健康检查：`GET /healthz`。

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `KEYSTORE_DIR` | `/data/keystore` | 主密钥文件与 SQLite 目录 |
| `VOLUME_DIR` | `/data/volumes` | 密文 blob 目录 |
| `DB_PATH` | `$KEYSTORE_DIR/backup.db` | SQLite 路径 |
| `ROTATION_INTERVAL` | `1` | 后台轮换轮询秒数 |
| `ROTATION_BATCH` | `10` | 每个 tick 重包装的备份数 |
| `PREP_INTERVAL` | `1` | 后台续传准备轮询秒数 |
| `MAX_UPLOAD_MB` | `16` | 单文件上传上限（MB） |

## 5. 本地开发

```bash
python3 -m venv --without-pip .venv        # 若系统没有 ensurepip
.venv/bin/python get-pip.py                # 自行引导 pip 后
.venv/bin/pip install -r requirements.txt
KEYSTORE_DIR=./data/keystore VOLUME_DIR=./data/volumes \
  .venv/bin/python -m backup_app.wsgi
```

## 6. 测试

```bash
.venv/bin/python -I tests/test_service.py   # 32 个服务层测试
.venv/bin/python -I tests/test_web.py       # 14 个 HTTP 集成测试（含真实后台 worker）
```

覆盖：加解密往返、DEK 独立性、密文篡改拒绝、轮换不改 blob、中途上传只挂新 KEK、
模拟进程崩溃后续跑、幂等 tick、移除保护、密钥粉碎、两代轮换后旧密钥全删仍可恢复、
密钥卷与备份卷材料互斥；续传准备的跨块边界 Range 往返、64 KiB 请求读放大 ≤ 512 KiB、
磁盘占用 ≤ 原密文 + 64 KiB、准备中断/失败后的重试与回退、坏块隔离（206/500）、
就绪状态跨重启持久、移除旧 KEK 后仍可续传、暂停期间核心操作可用、两卷均无明文。

## 7. 目录结构

```
backup_app/
  config.py      # 环境变量配置
  crypto.py      # AES-256-GCM、DEK 包装/解包、AAD 绑定（含续传块 AAD）
  db.py          # SQLite 连接与表结构（含 resume_preps / settings）
  keystore.py    # 主密钥文件生成/加载/粉碎（0600、原子写）
  service.py     # 上传/下载/轮换/移除/续传准备的全部业务规则
  worker.py      # 后台轮换线程 + 续传准备线程（无自身状态，全部从 SQLite 恢复）
  web.py         # Flask 路由与控制台（含 206 Range 响应）
  wsgi.py        # 入口
  templates/     # 单页控制台
tests/           # 单元 + HTTP 集成测试
Dockerfile
docker-compose.yml
```

## 8. 运维注意事项

- **备份密钥卷**：丢失 `keystore` 卷即永久无法解密；备份卷泄露不构成明文泄露。
- 移除旧 KEK 前请确认数据库已另行备份；移除操作会覆写并删除密钥文件，不可撤销。
- 升级镜像/重启容器不影响轮换：任务在数据库里，重启自动续跑。
- 本服务未内置鉴权，生产环境应放在网关/内网鉴权之后，或自行增加登录中间件。
