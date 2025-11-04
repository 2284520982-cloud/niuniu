# ⚡ 快速开始

## 3秒启动

### Windows
```
双击 start.bat
```

### Linux/Mac
```bash
chmod +x start.sh && ./start.sh
```

### 通用
```bash
python start.py
```

## 访问地址

**前端页面**：http://localhost:7777/static/index.html

## 使用流程

1. ✅ 启动服务（双击start.bat）
2. ✅ 打开浏览器访问前端
3. ✅ 填写项目路径
4. ✅ 点击"开始扫描"

## 系统要求

- Python 3.8+
- 依赖包会自动安装

## 默认配置

- 端口：7777
- 规则：自动加载所有规则文件
- 深度：15层
- 富化：开启

## 故障排除

**端口被占用**：修改 `app.py` 最后一行端口号

**依赖安装失败**：使用国内镜像
```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

**无法访问**：检查服务是否启动，访问 `http://localhost:7777/api/ping` 测试

