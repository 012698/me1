#!/bin/bash
# ============================================================
# LENG_MING 后端部署脚本（Aiven PostgreSQL 版）
# 适用于：VPS / Render / Railway / 任何 Node.js 22+ 环境
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================="
echo "  LENG_MING 后端部署 (PG版)"
echo "=============================="

# 检查 Node.js 版本
if ! command -v node &> /dev/null; then
  echo "❌ 未找到 Node.js，请先安装 Node.js 22+"
  exit 1
fi

NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VER" -lt 22 ]; then
  echo "⚠️  Node.js 版本 v$NODE_VER < 22，建议使用 nvm 升级"
  echo "   nvm install 22 && nvm use 22"
fi
echo "✅ Node.js $(node -v)"

# 检查环境变量
if [ ! -f .env ]; then
  echo "⚠️  未找到 .env 文件，从 .env.example 复制..."
  cp .env.example .env
  echo ""
  echo "=========================================="
  echo "  ⚠️  请先编辑 .env 文件！"
  echo "  必须填写 DATABASE_URL（Aiven 连接串）"
  echo "=========================================="
  echo ""
  echo "必填项："
  echo "  DATABASE_URL=postgres://user:pass@host:port/db?sslmode=require"
  echo ""
  echo "可选项（有默认值）："
  echo "  PORT=3000"
  echo "  JWT_SECRET=（随机字符串）"
  echo "  ADMIN_PASSWORD=（管理员密码）"
  echo ""
  echo "编辑完成后重新运行: bash deploy.sh"
  exit 1
fi

# 加载 .env
source .env

# 验证 DATABASE_URL 已设置
if [ -z "$DATABASE_URL" ] || echo "$DATABASE_URL" | grep -q "YOUR_USER"; then
  echo "❌ DATABASE_URL 未配置或仍是占位符，请编辑 .env"
  exit 1
fi

echo "✅ DATABASE_URL 已配置"

# 安装依赖
echo "📦 安装依赖..."
npm install --production

# 创建 public 目录（如果不存在，前端文件需提前放置）
mkdir -p public

# 检查前端文件
if [ ! -f public/index.html ]; then
  echo "⚠️  public/index.html 不存在，请将前端构建产物放入 public/ 目录"
fi

echo ""
echo "🚀 启动服务..."
echo "   按 Ctrl+C 停止"
echo ""

# 启动（前台运行，适合 systemd/pm2/docker 托管）
exec node server.js
