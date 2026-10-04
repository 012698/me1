# LENG_MING 社交网站后端 — Aiven PostgreSQL 版

## 技术栈

- **运行时**: Node.js 22+
- **Web框架**: Express 4
- **数据库**: Aiven PostgreSQL（云端托管）
- **WebSocket**: ws
- **认证**: JWT + bcryptjs
- **其他**: cors

## 目录结构

```
backend_pg/
├── server.js          # 主服务文件（~800行，所有API + WebSocket）
├── package.json       # 依赖声明
├── .env.example       # 环境变量模板
├── deploy.sh          # 一键部署脚本
└── public/            # 前端静态文件（需手动放入）
```

## 快速开始

### 1. 获取 Aiven PostgreSQL 连接串

1. 登录 [Aiven Console](https://console.aiven.io/)
2. 创建 PostgreSQL 服务（免费层即可）
3. 进入服务详情页 → **Connection Information**
4. 复制 **Service URI**（格式如 `postgres://user:pass@host:port/defaultdb?sslmode=require`）

### 2. 配置环境变量

```bash
cd backend_pg
cp .env.example .env
```

编辑 `.env`，**至少填写** `DATABASE_URL`：

```env
DATABASE_URL=postgres://avnuser:secret@pg-host.aivencloud.com:12345/defaultdb?sslmode=require
PG_SSL=true
PORT=3000
JWT_SECRET=your-random-secret-key-here
ADMIN_PASSWORD=your-admin-password
```

### 3. 安装依赖并启动

```bash
npm install
npm start
```

或使用部署脚本（会自动检查环境和配置）：

```bash
chmod +x deploy.sh
bash deploy.sh
```

### 4. 验证

- 健康检查：`curl http://localhost:3000/api/health`
- 首次启动自动建表，无需手动执行 SQL

## 与 SQLite 版的区别

| 项目 | SQLite 版 | PostgreSQL 版 |
|------|-----------|---------------|
| 数据库 | 本地文件 `data/app.db` | Aiven 云端 PostgreSQL |
| 连接方式 | 零配置 | 需配置 `DATABASE_URL` |
| 并发支持 | 单进程读写锁 | 真正的并发读写 |
| 部署复杂度 | 极低 | 需要云端数据库 |
| 适用场景 | 开发/小流量 | 生产环境/高并发 |
| 占位符语法 | `?` | `$1, $2, $3...` |

## 生产部署

### Render / Railway

1. 推送代码到 GitHub
2. 在平台新建 Web Service，指向 `backend_pg/` 目录
3. 在环境变量中配置 `DATABASE_URL`、`JWT_SECRET`、`ADMIN_PASSWORD`
4. Build Command: `npm install`
5. Start Command: `npm start`

### VPS (systemd)

```bash
# 创建服务文件
sudo tee /etc/systemd/system/lengming-api.service << 'EOF'
[Unit]
Description=LENG_MING API (PostgreSQL)
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/lengming/backend_pg
EnvironmentFile=/opt/lengming/backend_pg/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now lengming-api
```

### Docker

```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

```bash
docker build -t lengming-api .
docker run -d --env-file .env -p 3000:3000 lengming-api
```

## 数据库迁移（从 SQLite 迁移数据）

如果需要将 SQLite 版的数据迁移到 PostgreSQL：

1. 导出 SQLite 数据为 JSON：
   ```bash
   sqlite3 data/app.db ".mode json" ".output users.json" "SELECT * FROM users;"
   ```

2. 编写迁移脚本，逐条 INSERT 到 PostgreSQL（注意 `?` 改为 `$1, $2...`）

3. 或使用 `pgloader` 工具直接迁移

## 常见问题

**Q: 连接 Aiven 超时？**
确保 `PG_SSL=true` 且 `DATABASE_URL` 包含 `?sslmode=require`

**Q: 端口被占用？**
修改 `.env` 中的 `PORT` 值

**Q: 建表失败？**
检查数据库用户是否有 CREATE TABLE 权限（Aiven 默认有）

**Q: WebSocket 不工作？**
确保反向代理（nginx）配置了 WebSocket 升级：
```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

## API 文档

所有接口与 SQLite 版完全一致，参见前端项目的 `API_BASE` 配置。

**主要接口：**
- `POST /api/register` — 注册
- `POST /api/login` — 登录
- `GET /api/me` — 当前用户
- `GET /api/friends` — 好友列表
- `POST /api/messages` — 发送消息
- `GET /api/messages/:friendId` — 聊天记录
- `GET /api/categories/approved` — 游戏分类
- `POST /api/admin/login` — 管理员登录
- 更多接口见 server.js 路由定义

## 注意事项

1. **不要**将 `.env` 提交到 Git
2. **必须**在生产环境更换 `JWT_SECRET` 为随机长字符串
3. Aiven 免费层有连接数限制（通常 5-10 个并发连接），高流量需升级
4. `pg.Pool` 默认保持连接池，生产环境建议设置 `max` 参数（当前默认 10）
