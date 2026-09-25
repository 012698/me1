# LENG_MING 后端部署教程（SQLite 零配置版）

> 零数据库依赖，启动即用，适合个人/小团队轻量部署。

---

## 一、购买服务器

推荐以下轻量应用服务器，**免备案**，便宜好用：

| 平台 | 推荐配置 | 参考价格 | 备注 |
|------|---------|---------|------|
| **腾讯云** | 轻量应用服务器 2核2G | ¥50-70/年 | 选**香港/新加坡**地域，免备案 |
| **阿里云** | 轻量应用服务器 2核2G | ¥60-80/年 | 选**香港**地域，免备案 |

> 💡 **重要**：选「香港」或「新加坡」地域可以免去域名备案流程，开通后直接可用。

系统选 **Ubuntu 22.04 LTS** 或 **Debian 12**。

---

## 二、上传文件到服务器

### 方法 A：scp 命令（推荐）

在你本地电脑终端执行：

```bash
scp -r backend_sqlite/* root@你的服务器IP:/opt/lengming/
```

### 方法 B：SFTP 工具

使用 [WinSCP](https://winscp.net/)（Windows）或 [FileZilla](https://filezilla-project.org/)（全平台），连接服务器后把 `backend_sqlite/` 目录整个拖到 `/opt/lengming/`。

### 方法 C：Git 拉取

如果代码在 GitHub/Gitee：

```bash
ssh root@你的服务器IP
cd /opt
git clone 你的仓库地址 lengming
cd lengming
```

---

## 三、一键部署

SSH 登录服务器后执行：

```bash
ssh root@你的服务器IP

cd /opt/lengming
chmod +x deploy.sh
bash deploy.sh
```

脚本会自动完成：
- ✅ 检测并安装 Node.js 20+
- ✅ npm install 安装依赖
- ✅ 自动建库建表
- ✅ PM2 启动服务 + 开机自启
- ✅ 生成随机 JWT_SECRET

部署完成后输出服务地址，如 `http://123.45.67.89:3000`

---

## 四、开放防火墙端口

```bash
# Ubuntu / Debian
sudo ufw allow 3000/tcp
sudo ufw reload

# CentOS / AlmaLinux
sudo firewall-cmd --permanent --add-port=3000/tcp
sudo firewall-cmd --reload
```

> ⚠️ 云服务器还需要在**控制台安全组**中放行 3000 端口入站！

### 腾讯云安全组设置：
控制台 → 轻量应用服务器 → 防火墙 → 添加规则 → 端口 3000，TCP，允许

### 阿里云安全组设置：
控制台 → ECS → 安全组 → 入方向 → 手动添加 → 端口 3000，TCP，授权对象 0.0.0.0/0

---

## 五、前端配置

把前端打包好的 `index.html` 放到服务器的 `public/` 目录：

```bash
# 假设你本地打包出了 dist/
scp -r dist/* root@你的服务器IP:/opt/lengming/public/
```

**前端只需改一行**：把 API 地址改成你的服务器地址：

```javascript
// 在前端代码中找到 API_BASE_URL 或类似配置
const API_BASE_URL = 'http://你的服务器IP:3000';
// 例如：const API_BASE_URL = 'http://123.45.67.89:3000';
```

---

## 六、常用运维命令

```bash
# 查看服务状态
pm2 status

# 查看实时日志
pm2 logs lengming-api

# 重启服务
pm2 restart lengming-api

# 停止服务
pm2 stop lengming-api

# 修改管理员密码
# 编辑 .env 文件中的 ADMIN_PASSWORD，然后重启
vi /opt/lengming/.env
pm2 restart lengming-api
```

---

## 七、目录结构说明

```
/opt/lengming/
├── server.js          # 后端主程序
├── package.json       # 依赖配置
├── .env               # 环境变量（自动生成，含密钥）
├── deploy.sh          # 一键部署脚本
├── data/
│   └── app.db         # SQLite 数据库文件（启动自动创建）
└── public/
    └── index.html     # 你的前端文件放这里
```

---

## 八、可选：绑定域名 + HTTPS

如果有域名，推荐用 Nginx 反向代理 + Let's Encrypt 免费证书：

```bash
# 安装 Nginx 和 certbot
sudo apt install nginx certbot python3-certbot-nginx -y

# Nginx 配置
sudo tee /etc/nginx/sites-available/lengming << 'EOF'
server {
    listen 80;
    server_name your-domain.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/lengming /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 申请 HTTPS 证书
sudo certbot --nginx -d your-domain.com
```

---

## 常见问题

**Q: better-sqlite3 编译失败？**
A: 确保安装了 `build-essential` 和 `python3`：`sudo apt install build-essential python3`。如果仍然失败，程序会自动回退使用 Node.js 内置的 `node:sqlite` 模块（需 Node 22+）。

**Q: 服务器重启后服务没启动？**
A: 执行 `pm2 startup` 重新设置开机自启，然后 `pm2 save`。

**Q: 数据库怎么备份？**
A: 直接复制 `data/app.db` 文件即可，例如：`cp data/app.db data/app.db.backup`

**Q: 默认管理员密码是什么？**
A: `YOUR_ADMIN_PASSWORD_HERE`，可在 `.env` 文件中修改 `ADMIN_PASSWORD` 后重启。
