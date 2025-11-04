@echo off
chcp 65001 >nul
echo ========================================
echo   Niuniu Java 安全审计工具
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

REM 检查依赖是否安装
echo [检查] 检查依赖包...
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo [安装] 正在安装依赖包...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请检查网络连接
        pause
        exit /b 1
    )
)

echo [启动] 正在启动服务...
echo [提示] 服务启动后请访问: http://localhost:7777/static/index.html
echo [提示] 按 Ctrl+C 停止服务
echo.

python app.py

pause

