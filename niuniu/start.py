#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Niuniu Java 安全审计工具 - 快速启动脚本
"""
import sys
import os
import subprocess

def check_dependencies():
    """检查依赖是否安装"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'javalang',
        'requests'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    return missing

def install_dependencies():
    """安装依赖"""
    print("[安装] 正在安装依赖包...")
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("[成功] 依赖安装完成")
        return True
    except subprocess.CalledProcessError:
        print("[错误] 依赖安装失败，请检查网络连接")
        return False

def main():
    """主函数"""
    print("=" * 50)
    print("  Niuniu Java 安全审计工具")
    print("=" * 50)
    print()
    
    # 检查Python版本
    if sys.version_info < (3, 8):
        print("[错误] 需要Python 3.8或更高版本")
        print(f"当前版本: {sys.version}")
        sys.exit(1)
    
    # 检查依赖
    missing = check_dependencies()
    if missing:
        print(f"[警告] 缺少依赖包: {', '.join(missing)}")
        response = input("[询问] 是否自动安装? (y/n): ").strip().lower()
        if response == 'y':
            if not install_dependencies():
                sys.exit(1)
        else:
            print("[提示] 请手动运行: pip install -r requirements.txt")
            sys.exit(1)
    
    # 切换到脚本所在目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # 启动服务
    print()
    print("[启动] 正在启动服务...")
    print("[提示] 服务启动后请访问: http://localhost:7777/static/index.html")
    print("[提示] 按 Ctrl+C 停止服务")
    print()
    
    try:
        import uvicorn
        from app import app
        uvicorn.run(app, host='0.0.0.0', port=7777, log_level='info')
    except KeyboardInterrupt:
        print("\n[停止] 服务已停止")
    except Exception as e:
        print(f"\n[错误] 启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

