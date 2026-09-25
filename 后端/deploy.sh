#!/bin/bash
# ============================================================
# LENG_MING 社交网站 — SQLite 版一键部署脚本
# 适用：全新 Linux 服务器（Ubuntu 20.04+ / Debian 11+ / CentOS 8+）
# 用法：curl -fsSL <你的地址>/deploy.sh | bash
#    或：bash deploy.sh
# ============================================================
set -e

echo "========================================="
echo "  LENG_MING 后端部署脚本 (SQLite 零配置)"
echo "========================================="

# ---------- 1. 检测/安装 Node.js 22+（需要内置 node:sqlite 模块） ----------
echo ""
echo "[1/5] 检测 Node.js..."
if command -v node &> /dev/null; then
  NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
  if [ "$NODE_VER" -ge 22 ]; then
    echo "✅ Node.js $(node -v) 已安装，版本满足要求"
  else
    echo "⚠️  Node.js $(node -v) 版本过低，需要 22+（内置 node:sqlite）"
    NEED_INSTALL=1
  fi
else
  echo "❌ 未检测到 Node.js，开始安装..."
  NEED_INSTALL=1
fi

if [ "$NEED_INSTALL" = "1" ]; then
  echo "正在安装 Node.js 22.x ..."
  # 使用 NodeSource 官方安装脚本
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - 2>/dev/null || \
    (curl -fsSL https://rpm.nodesource.com/setup_22.x | bash -)
  apt-get install -y nodejs 2>/dev/null || yum install -y nodejs 2>/dev/null || dnf install -y nodejs 2>/dev/null
  echo "✅ Node.js $(node -v) 安装完成"
fi

# ---------- 2. 安装 npm 依赖 ----------
echo ""
echo "[2/5] 安装 npm 依赖..."
cd "$(dirname "$0")"

# better-sqlite3 是可选的（编译失败则自动回退到 Node 22 内置的 node:sqlite）
if ! command -v make &> /dev/null; then
  echo "安装编译工具（可选，用于 better-sqlite3）..."
  apt-get install -y build-essential python3 2>/dev/null || \
    yum install -y gcc-c++ make python3 2>/dev/null || \
    dnf install -y gcc-c++ make python3 2>/dev/null
fi

# 尝试安装，忽略 better-sqlite3 编译失败
npm install --production --ignore-scripts 2>/dev/null
# 尝试编译 better-sqlite3（如果安装了的话）
cd node_modules/better-sqlite3 && npx --yes node-gyp rebuild 2>/dev/null || echo "ℹ️  better-sqlite3 编译跳过，将使用 node:sqlite 内置模块"
cd ../..
echo "✅ npm 依赖安装完成"

# ---------- 3. 创建必要目录 ----------
echo ""
echo "[3/5] 创建数据目录..."
mkdir -p data public
echo "✅ data/ 和 public/ 目录就绪"

# ---------- 4. 创建 .env 文件（如果不存在） ----------
if [ ! -f .env ]; then
  JWT_SECRET=$(openssl rand -hex 32)
  cat > .env << EOF
PORT=3000
JWT_SECRET=${JWT_SECRET}
ADMIN_PASSWORD=YOUR_ADMIN_PASSWORD_HERE
EOF
  echo "✅ 已自动生成 .env 文件（JWT_SECRET 已随机生成）"
else
  echo "ℹ️  .env 文件已存在，跳过创建"
fi

# ---------- 5. 使用 PM2 启动 ----------
echo ""
echo "[4/5] 配置 PM2 进程管理..."

if ! command -v pm2 &> /dev/null; then
  npm install -g pm2
  echo "✅ PM2 安装完成"
fi

# 停止旧进程（如有）
pm2 delete lengming-api 2>/dev/null || true

# 启动服务
cd "$(dirname "$0")"
pm2 start server.js --name lengming-api
pm2 save

# 设置开机自启
echo ""
echo "[5/5] 设置开机自启..."
pm2 startup 2>/dev/null || echo "⚠️  开机自启设置失败，可手动执行: pm2 startup"

echo ""
echo "========================================="
echo "  ✅ 部署完成！"
echo "========================================="
echo ""
echo "📌 服务地址: http://$(hostname -I | awk '{print $1}'):3000"
echo "📁 数据库文件: $(pwd)/data/app.db"
echo "🔑 默认管理员密码: YOUR_ADMIN_PASSWORD_HERE（请务必修改）"
echo ""
echo "⚡ 下一步："
echo "  1. 把前端 index.html 放到: $(pwd)/public/"
echo "  2. 开放防火墙 3000 端口:"
echo "     sudo ufw allow 3000/tcp     (Ubuntu/Debian)"
echo "     sudo firewall-cmd --permanent --add-port=3000/tcp && sudo firewall-cmd --reload  (CentOS)"
echo "  3. 查看日志: pm2 logs lengming-api"
echo "  4. 重启服务: pm2 restart lengming-api"
echo "========================================="
