#!/bin/bash

echo "========================================"
echo "  Niuniu Java 安全审计工具"
echo "========================================"
echo ""

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未检测到Python3，请先安装Python 3.8+"
    exit 1
fi

# 检查依赖是否安装
echo "[检查] 检查依赖包..."
if ! python3 -c "import fastapi" &> /dev/null; then
    echo "[安装] 正在安装依赖包..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[错误] 依赖安装失败，请检查网络连接"
        exit 1
    fi
fi

echo "[启动] 正在启动服务..."
echo "[提示] 服务启动后请访问: http://localhost:7777/static/index.html"
echo "[提示] 按 Ctrl+C 停止服务"
echo ""

python3 app.py

