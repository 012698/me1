#!/bin/bash
set -e
echo "🚀 开始部署 LENG_MING 社交网站后端..."
cd /opt/lengming
chmod +x deploy.sh
bash deploy.sh
echo ""
echo "✅ 后端部署完成！"
echo "⚡ 接下来："
echo "  1. 开放防火墙 3000 端口"
echo "  2. 修改前端 index.html 中的 API_BASE 和 WS_BASE"
echo "  3. 重新部署前端到扣子 Pages"
echo "📌 当前服务地址: http://$(hostname -I | awk '{print $1}'):3000"
