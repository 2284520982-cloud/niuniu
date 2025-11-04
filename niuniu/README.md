# Niuniu Java 安全审计工具

## 项目简介

Niuniu 是一个专业的 Java 代码安全审计工具，支持函数级回溯、规则驱动检测和 AI 风险总结。

## 核心特性

- ✅ **函数级回溯**：深度追踪污点传播路径
- ✅ **规则驱动**：灵活的规则配置系统
- ✅ **双引擎架构**：完整引擎 + 轻量引擎
- ✅ **模板扫描**：支持 JSP、JSPX、FreeMarker、Velocity 等
- ✅ **增强规则库**：覆盖主流框架和漏洞类型
- ✅ **现代化前端**：模块化、响应式 UI
- ✅ **AI 风险总结**：可选的 AI 辅助分析

## 项目结构

```
niuniu/
├── core/                    # 核心模块
│   ├── constants.py        # 常量配置
│   ├── exceptions.py       # 自定义异常
│   ├── validators.py       # 输入验证
│   ├── cache.py           # 缓存管理
│   ├── logger.py          # 日志配置
│   ├── helpers.py         # 辅助函数
│   ├── utils.py           # 工具函数
│   └── middleware.py      # 中间件
├── utils/                   # 工具模块
│   ├── performance.py     # 性能监控
│   └── security.py        # 安全工具
├── Rules/                   # 规则目录
│   ├── rules.json         # 基础规则
│   ├── enhanced_rules.json # 增强模板规则
│   ├── enhanced_sources.json
│   ├── enhanced_sanitizers.json
│   └── enhanced_sinks.json
├── static/                  # 前端资源
│   ├── index.html
│   ├── style.css
│   └── js/                 # 模块化前端代码
│       ├── main.js
│       ├── api.js
│       ├── config.js
│       ├── utils.js
│       └── components/
├── analyzer.py              # 分析器主类
├── app.py                   # FastAPI 应用
├── docs/                    # 文档目录
└── requirements.txt         # Python 依赖
```

## 快速开始（开箱即用）

### 方式一：一键启动（推荐）

**Windows系统**：
```bash
双击运行 start.bat
```

**Linux/Mac系统**：
```bash
chmod +x start.sh
./start.sh
```

**或使用Python启动脚本**：
```bash
python start.py
```

### 方式二：手动启动

1. **安装依赖**（首次运行）
```bash
pip install -r requirements.txt
```

2. **启动服务**
```bash
python app.py
```

3. **访问前端**

浏览器打开：`http://localhost:7777/static/index.html`

**提示**：如果端口7777被占用，可以修改`app.py`最后一行更改端口

## 主要功能

### 1. 代码扫描

- 支持完整引擎和轻量引擎
- 可配置回溯深度和超时时间
- 实时进度显示
- 部分结果保存

### 2. 模板扫描

- 独立模板扫描功能
- 支持多种模板格式
- 上下文分析和智能评分

### 3. 结果管理

- 多维度分类展示（严重性/类型/置信度）
- 全局搜索功能
- 批量操作支持
- 报告导出

### 4. 规则管理

- 丰富的规则库
- 可扩展的规则系统
- 规则版本管理

## 配置说明

### 扫描参数

- **回溯深度**：默认 15（推荐 15+）
- **最大链条数**：默认 50
- **单链路超时**：默认 600 秒（推荐 600+）
- **模板扫描**：默认开启
- **Lite 富化**：默认开启（推荐）

### 规则配置

规则文件位于 `Rules/` 目录：
- `rules.json` - 基础规则
- `enhanced_*.json` - 增强规则

## API 文档

### 主要接口

- `POST /api/analyze` - 代码分析
- `POST /api/template-scan` - 模板扫描
- `GET /api/partial` - 获取部分结果
- `POST /api/report` - 生成报告
- `GET /api/ping` - 健康检查

详细 API 文档请参考代码注释。

## 开发指南

### 代码结构

- **core/** - 核心模块，提供基础功能
- **utils/** - 工具模块，提供通用工具
- **analyzer.py** - 分析器实现
- **app.py** - API 接口

### 添加新规则

1. 编辑 `Rules/rules.json` 或创建增强规则文件
2. 规则格式参考现有规则
3. 重启服务生效

### 扩展功能

1. 在 `core/` 中添加新模块
2. 在 `analyzer.py` 中集成
3. 在 `app.py` 中添加 API

## 常见问题

### Q: 扫描速度慢？

A: 
- 启用 Lite 引擎
- 调整并发数（`core/constants.py`）
- 减少回溯深度

### Q: 内存占用高？

A:
- 减小文件大小限制
- 启用缓存清理
- 限制并发数

### Q: 误报多？

A:
- 启用严格字符串匹配
- 调整置信度阈值
- 完善规则排除模式

## 许可证

本项目仅供学习和研究使用。

## 更新日志

### v2.0.0 (最新)
- ✅ 核心模块重构
- ✅ 前端模块化
- ✅ 增强规则库
- ✅ 改进异常处理
- ✅ 性能优化

详见 `docs/代码重构总结.md`

