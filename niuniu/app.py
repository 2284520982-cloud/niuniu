from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import List, Dict, Optional, Any, Union
import os
import requests
import threading
import logging
import json

from analyzer import Analyzer
from utils.security import resource_limiter, sanitize_html
from utils.performance import performance_monitor, cache_manager

# 导入核心模块
try:
    from core.exceptions import (
        AnalyzerError, ValidationError, RulesLoadError, FileProcessingError
    )
    from core.constants import DEFAULT_DEPTH, DEFAULT_MAX_SECONDS, DEFAULT_RULES_PATH
    from core.validators import validate_project_path as core_validate_project_path, validate_rules_path
    # 使用核心模块的验证函数，优先级更高
    validate_project_path = core_validate_project_path
except ImportError:
    # 向后兼容
    class AnalyzerError(Exception):
        pass
    class ValidationError(AnalyzerError):
        pass
    class RulesLoadError(AnalyzerError):
        pass
    class FileProcessingError(AnalyzerError):
        pass
    DEFAULT_DEPTH = 15
    DEFAULT_MAX_SECONDS = 600
    DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), 'Rules', 'rules.json')
    
    # 简化验证函数
    def validate_project_path(path: str) -> str:
        if not os.path.isdir(path):
            raise ValidationError(f"项目路径不存在或不是目录: {path}")
        return os.path.abspath(path)
    
    def validate_rules_path(path: str) -> str:
        if not os.path.isfile(path):
            raise ValidationError(f"规则文件不存在: {path}")
        return os.path.abspath(path)

# 配置日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('niuniu.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
# 尝试导入“原始引擎”与报告模块；若不可用，回退为仅 lite 引擎可用
try:
    from JavaSinkTracer import JavaSinkTracer
    from AutoVulReport import generate_markdown_report
    HAS_ORIGINAL = True
except Exception:
    JavaSinkTracer = None
    generate_markdown_report = None
    HAS_ORIGINAL = False

app = FastAPI()
STOP_EVENT = threading.Event()
PAUSE_EVENT = threading.Event()  # 暂停事件，set表示暂停，clear表示继续


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(__file__)
static_dir = os.path.join(BASE_DIR, 'static')
app.mount('/static', StaticFiles(directory=static_dir), name='static')

# 额外内置模板规则（根据你提供的清单增强），与 Rules.json 的 template_rules 等价结构
EXTRA_TEMPLATE_RULES: List[Dict[str, Any]] = [
    {
        'name': 'JSP_TRUST_PROXY_HEADER',
        'vul_type': 'SECURITY_MISCONFIG',
        'desc': '不可信的代理/来源头直接用于逻辑判断或IP识别',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx','html'],
        'patterns': [
            r'request\\.getHeader\\s*\\(\\s*\\"(X-Forwarded-For|Client-IP|HTTP_CLIENT_IP|HTTP_X_FORWARDED_FOR|Referer)\\"\\s*\\)',
            r'HTTP_CLIENT_IP|HTTP_X_FORWARDED_FOR|Referer'
        ]
    },
    {
        'name': 'JSP_HEADER_REDIRECT',
        'vul_type': 'REDIRECT',
        'desc': '未校验的URL重定向（Location/Refresh）',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx','html'],
        'patterns': [
            r'response\\.setHeader\\s*\\(\\s*\\"Location\\"\\s*,',
            r'http-equiv=\\"refresh\\"',
            r'sendRedirect\\s*\\(',
            r'location\\.href'
        ]
    },
    {
        'name': 'JSP_MULTIPART_TRANSFER_TO',
        'vul_type': 'FILE_WRITE',
        'desc': '文件上传直接 transferTo/写入，存在路径/扩展名绕过风险',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'MultipartFile\\.transferTo\\s*\\(',
            r'Part\\.write\\s*\\('
        ]
    },
    {
        'name': 'JSP_RESPONSE_HEADER_INJECTION',
        'vul_type': 'XSS',
        'desc': '响应头值来源于未信任输入，可能造成Header注入',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'response\\.(addHeader|setHeader)\\s*\\(',
            r'pageContext\\.getOut'
        ]
    }
]

# 规则扩展：补充 JSP/EL、Freemarker、Velocity、Thymeleaf 常见高危与弱净化场景（模板启发式扫描增强）
EXTRA_TEMPLATE_RULES.extend([
    {
        'name': 'JSP_EL_RAW_PARAM_OUTPUT',
        'vul_type': 'XSS',
        'desc': 'EL 直接输出 param 变量，缺少编码',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx','html'],
        'patterns': [
            r'\$\{\s*param\.',
            r'\$\{\s*requestScope\.',
            r'\$\{\s*sessionScope\.',
            r'\$\{\s*header\.'
        ]
    },
    {
        'name': 'JSP_SCRIPTLET_PRINT_PARAM',
        'vul_type': 'XSS',
        'desc': '脚本片段中直接 out.print/println 未编码输出',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'out\\.(print|println)\\s*\(',
            r'request\\.getParameter\\s*\('
        ]
    },
    {
        'name': 'JSP_INCLUDE_FORWARD_DYNAMIC',
        'vul_type': 'FILE_INCLUDE',
        'desc': 'jsp:include/forward 目标由变量/请求决定，可能导致任意文件包含/跳转',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'<jsp:include\s+page\s*=\s*\"\s*\$\{',
            r'<jsp:forward\s+page\s*=\s*\"\s*\$\{'
        ]
    },
    {
        'name': 'JSP_SET_COOKIE_INJECTION',
        'vul_type': 'HEADER_INJECTION',
        'desc': 'Set-Cookie 头由未校验输入拼接，存在注入风险',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'response\\.(addHeader|setHeader)\\s*\(\s*\"Set-Cookie\"'
        ]
    },
    {
        'name': 'JS_META_REDIRECT',
        'vul_type': 'REDIRECT',
        'desc': '基于前端的跳转逻辑（document/window.location）',
        'severity': 'Low',
        'file_exts': ['jsp','jspx','html'],
        'patterns': [
            r'document\\.location', r'window\\.location', r'location\\.(assign|replace)'
        ]
    },
    {
        'name': 'THYMELEAF_UTEXT',
        'vul_type': 'XSS',
        'desc': 'th:utext 使用未转义输出',
        'severity': 'High',
        'file_exts': ['html','jsp','jspx'],
        'patterns': ['th:utext']
    },
    {
        'name': 'THYMELEAF_UNSANITIZED_ATTR',
        'vul_type': 'XSS',
        'desc': 'thymeleaf 事件/链接属性可能未做净化',
        'severity': 'Medium',
        'file_exts': ['html','jsp','jspx'],
        'patterns': [
            r'th:[a-zA-Z]+\s*=\s*\"\$\{',
            r'on[a-z]+\s*=\s*\"\$\{'
        ]
    },
    {
        'name': 'FREEMARKER_RAW_OUTPUT',
        'vul_type': 'XSS',
        'desc': 'Freemarker 直接 ${...} 输出未带 ?html/?xhtml/?js 编码',
        'severity': 'High',
        'file_exts': ['ftl'],
        'patterns': [
            r'\$\{[^}]+\}(?!\?html|\?xhtml|\?js)'
        ]
    },
    {
        'name': 'FREEMARKER_INCLUDE_DYNAMIC',
        'vul_type': 'FILE_INCLUDE',
        'desc': '<#include>/<#import> 参数可控',
        'severity': 'High',
        'file_exts': ['ftl'],
        'patterns': [
            r'<#include\s+\$\{', r'<#import\s+\$\{'
        ]
    },
    {
        'name': 'FREEMARKER_EVAL',
        'vul_type': 'SSTI',
        'desc': '使用 ?eval 动态求值，存在模板注入风险',
        'severity': 'High',
        'file_exts': ['ftl'],
        'patterns': [r'\?eval']
    },
    {
        'name': 'VELOCITY_RAW_OUTPUT',
        'vul_type': 'XSS',
        'desc': 'Velocity 直接输出变量（$param / $!param）',
        'severity': 'Medium',
        'file_exts': ['vm'],
        'patterns': [
            r'\$!?\{?params?\.[a-zA-Z_][a-zA-Z0-9_]*\}?',
            r'\$!?\{?request\.[a-zA-Z_][a-zA-Z0-9_]*\}?'
        ]
    },
    {
        'name': 'VELOCITY_PARSE_DYNAMIC',
        'vul_type': 'FILE_INCLUDE',
        'desc': '#parse/#include 参数可控',
        'severity': 'High',
        'file_exts': ['vm'],
        'patterns': [r'#parse\s*\(\s*\$', r'#include\s*\(\s*\$']
    },
    {
        'name': 'JSP_DOWNLOAD_FILENAME_HEADER',
        'vul_type': 'HEADER_INJECTION',
        'desc': 'Content-Disposition 下载文件名由未校验输入拼接',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx','html'],
        'patterns': [
            r'Content-Disposition', r'attachment;\s*filename\s*='
        ]
    },
    {
        'name': 'JSP_RESPONSE_WRITER_PRINT',
        'vul_type': 'XSS',
        'desc': 'response.getWriter().print/println 直接输出',
        'severity': 'Medium',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'response\\.getWriter\\s*\(\)\\.(print|println)'
        ]
    }
])

# 高危规则扩展（RCE/危险文件写/动态执行/SpEL）
# 标记高危规则强制直匹配（跳过提示词预筛选）所覆盖的类型
_FORCE_VUL_TYPES = {'RCE','SQLI','PATH_TRAVERSAL','FILE_INCLUDE','FILE_WRITE','SSTI'}

EXTRA_TEMPLATE_RULES.extend([
    {
        'name': 'JSP_RCE_RUNTIME_EXEC',
        'vul_type': 'RCE',
        'desc': 'JSP 脚本中直接调用 Runtime.exec() 执行系统命令',
        'severity': 'Critical',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'Runtime\\.getRuntime\\s*\(\)\\.exec\\s*\(']
    },
    {
        'name': 'JSP_RCE_PROCESS_BUILDER',
        'vul_type': 'RCE',
        'desc': 'JSP 脚本中使用 ProcessBuilder 执行系统命令',
        'severity': 'Critical',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'new\\s+ProcessBuilder\\s*\(']
    },
    {
        'name': 'JSP_DANGEROUS_FILE_WRITE',
        'vul_type': 'FILE_WRITE',
        'desc': 'JSP 脚本中使用 FileOutputStream/Files.write 直接写文件',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'new\\s+FileOutputStream\\s*\(', r'Files\\.write\\s*\(']
    },
    {
        'name': 'THYMELEAF_SPEL_RUNTIME_EXEC',
        'vul_type': 'SSTI',
        'desc': 'Thymeleaf SpEL 表达式调用 Runtime.exec()',
        'severity': 'Critical',
        'file_exts': ['html','jsp','jspx'],
        'patterns': [r'T\\(\\s*java\\.lang\\.Runtime\\s*\\)\\.getRuntime\\s*\(\)\\.exec\\s*\(']
    },
    {
        'name': 'THYMELEAF_SPEL_CLASS_FORNAME',
        'vul_type': 'SSTI',
        'desc': 'Thymeleaf SpEL 使用 Class.forName/反射，潜在危险动态加载',
        'severity': 'High',
        'file_exts': ['html','jsp','jspx'],
        'patterns': [r'T\\(\\s*java\\.lang\\.Class\\s*\\)\\.forName\\s*\(']
    },
    {
        'name': 'FREEMARKER_EVALUATE_DYNAMIC',
        'vul_type': 'SSTI',
        'desc': 'Freemarker 使用 #assign + ?eval 或直接 ?eval 动态执行',
        'severity': 'Critical',
        'file_exts': ['ftl'],
        'patterns': [r'\?eval', r'<#assign[^>]*=']
    },
    {
        'name': 'VELOCITY_EVALUATE',
        'vul_type': 'SSTI',
        'desc': 'Velocity 使用 #evaluate 动态执行模板片段',
        'severity': 'Critical',
        'file_exts': ['vm'],
        'patterns': [r'#evaluate\\s*\(']
    },
    {
        'name': 'VELOCITY_RUNTIME_EXEC',
        'vul_type': 'RCE',
        'desc': 'Velocity 模板中出现对 Runtime.exec 的调用痕迹',
        'severity': 'Critical',
        'file_exts': ['vm'],
        'patterns': [r'Runtime\\.getRuntime\\s*\(\)\\.exec\\s*\(']
    }
])

# 路径遍历/任意文件读写 高危规则扩展
EXTRA_TEMPLATE_RULES.extend([
    {
        'name': 'JSP_PATH_TRAVERSAL_READ',
        'vul_type': 'PATH_TRAVERSAL',
        'desc': '基于请求参数拼接的文件读取（FileInputStream/Files.readAllBytes/Paths.get）',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'(FileInputStream|Files\\.(readAllBytes|newInputStream)|Paths\\.get)\\s*\([^\)]*request\\.getParameter'
        ]
    },
    {
        'name': 'JSP_PATH_TRAVERSAL_WRITE',
        'vul_type': 'PATH_TRAVERSAL',
        'desc': '基于请求参数拼接的文件写入（FileOutputStream/Files.write）',
        'severity': 'Critical',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'(FileOutputStream|Files\\.write)\\s*\([^\)]*request\\.getParameter'
        ]
    },
    {
        'name': 'JSP_INCLUDE_PATH_TRAVERSAL',
        'vul_type': 'FILE_INCLUDE',
        'desc': 'jsp:include 目标包含 ../ 可疑路径',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'<jsp:include\\s+page\\s*=\\s*\"[^\"]*\\.\\./',
            r'<jsp:include\\s+page\\s*=\\s*\"\\s*\$\\{[^\}]*\\.\\./'
        ]
    },
    {
        'name': 'FREEMARKER_INCLUDE_PATH_TRAVERSAL',
        'vul_type': 'FILE_INCLUDE',
        'desc': 'Freemarker <#include> 目标包含 ../ 可疑路径',
        'severity': 'High',
        'file_exts': ['ftl'],
        'patterns': [r'<#include\\s+\$\\{[^\}]*\\.\\./']
    },
    {
        'name': 'VELOCITY_PARSE_PATH_TRAVERSAL',
        'vul_type': 'FILE_INCLUDE',
        'desc': 'Velocity #parse 参数包含 ../ 可疑路径',
        'severity': 'High',
        'file_exts': ['vm'],
        'patterns': [r'#parse\\s*\(\\s*\$[^\)]*\\.\\./']
    },
    {
        'name': 'JSP_REALPATH_TRAVERSAL',
        'vul_type': 'PATH_TRAVERSAL',
        'desc': 'getRealPath 结果与请求参数拼接使用，可能可控路径',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'ServletContext\\.getRealPath[^;\n]*\\+[^;\n]*request\\.getParameter'
        ]
    }
])

# 目录穿越/RCE/SQL注入 高危补充规则（模板与脚本场景）
EXTRA_TEMPLATE_RULES.extend([
    # 进一步的路径遍历变体（Windows/绝对路径）
    {
        'name': 'JSP_PATH_TRAVERSAL_WINDOWS',
        'vul_type': 'PATH_TRAVERSAL',
        'desc': 'JSP 中可能的 \\..\\ 或盘符绝对路径参与拼接',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'\\.\\.\\\\', r'[A-Za-z]:\\\\']
    },
    {
        'name': 'JSP_PATH_TRAVERSAL_UNIX_ABS',
        'vul_type': 'PATH_TRAVERSAL',
        'desc': 'JSP 中可见 /etc/ 等绝对路径常量与变量拼接',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'/etc/']
    },
    # RCE：脚本引擎/反射
    {
        'name': 'JSP_SCRIPT_ENGINE_EVAL',
        'vul_type': 'RCE',
        'desc': 'JSP 使用 ScriptEngineManager/engine.eval 执行动态脚本',
        'severity': 'Critical',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'new\\s+ScriptEngineManager', r'engine\\.eval\\s*\(']
    },
    {
        'name': 'JSP_REFLECTION_FORNAME',
        'vul_type': 'RCE',
        'desc': 'JSP 中使用 Class.forName/反射，潜在危险动态加载',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [r'Class\\.forName\\s*\(']
    },
    # SQL 注入：JSP 脚本内 SQL 拼接
    {
        'name': 'JSP_SQLI_EXEC_CONCAT',
        'vul_type': 'SQLI',
        'desc': 'JSP 脚本中 execute/prepareStatement 参数包含字符串拼接或可控输入',
        'severity': 'High',
        'file_exts': ['jsp','jspx'],
        'patterns': [
            r'(Statement|PreparedStatement|JdbcTemplate)\\.(execute(Query|Update)?|query|update|prepareStatement)\\s*\([^)]*(\\+|request\\.getParameter|\\$\\{param\\.)'
        ]
    },
    # SQL 注入：MyBatis XML 使用 ${} 原样替换
    {
        'name': 'MYBATIS_XML_DOLLAR_VARIABLE',
        'vul_type': 'SQLI',
        'desc': 'MyBatis 映射 XML 使用 ${var}（原样替换），存在注入风险（应使用 #{var}）',
        'severity': 'High',
        'file_exts': ['xml'],
        'patterns': [r'<(select|update|delete|insert)[^>]*>[\\s\\S]*?\\$\\{[^}]+\\}']
    },
    # SQL 注入：模板直接拼接 SQL 语句（Freemarker/Velocity）
    {
        'name': 'FREEMARKER_SQL_CONCAT',
        'vul_type': 'SQLI',
        'desc': 'Freemarker 模板出现 SQL 关键词并拼接 ${...} 变量',
        'severity': 'High',
        'file_exts': ['ftl'],
        'patterns': [r'(?i)(select|update|delete|insert)[^\n]*\\$\\{']
    },
    {
        'name': 'VELOCITY_SQL_CONCAT',
        'vul_type': 'SQLI',
        'desc': 'Velocity 模板出现 SQL 关键词并拼接 $var/$!var 变量',
        'severity': 'High',
        'file_exts': ['vm'],
        'patterns': [r'(?i)(select|update|delete|insert)[^\n]*\\$!?\\{?']
    }
])

# 根据高危类型批量追加 force_regex 标记（直通正则匹配，跳过提示词预筛选）
try:
    _FORCE_VUL_TYPES
except NameError:
    _FORCE_VUL_TYPES = {'RCE','SQLI','PATH_TRAVERSAL','FILE_INCLUDE','FILE_WRITE','SSTI'}
for _r in EXTRA_TEMPLATE_RULES:
    vt = (_r.get('vul_type') or '').upper()
    if vt in _FORCE_VUL_TYPES:
        _r['force_regex'] = True

# 解析 CSV 规则 -> template_rules 项列表（与现有规则结构一致）
def _parse_external_rules_csv(csv_path: str) -> List[Dict[str, Any]]:
    import csv
    csv_path = os.path.abspath(csv_path)
    if not os.path.exists(csv_path):
        raise Exception('CSV 文件不存在')
    rules = []
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # 兼容列名：name/vul_type/desc/severity/file_exts/patterns
            name = (row.get('name') or row.get('vul_type') or row.get('desc') or 'EXT_RULE').strip()
            desc = (row.get('desc') or '').strip()
            severity = (row.get('severity') or 'Medium').strip()
            file_exts_raw = (row.get('file_exts') or 'jsp,ftl,vm,html').strip()
            patterns_raw = (row.get('patterns') or row.get('pattern') or '').strip()
            file_exts = [e.strip().lstrip('.') for e in file_exts_raw.split(',') if e.strip()]
            # patterns 支持 | 或 ; 分隔
            seps = '|' if '|' in patterns_raw and ';' not in patterns_raw else ';'
            patterns = [p.strip() for p in patterns_raw.split(seps) if p.strip()]
            if not patterns:
                continue
            rules.append({
                'name': name,
                'vul_type': row.get('vul_type') or name,
                'desc': desc,
                'severity': severity,
                'file_exts': file_exts,
                'patterns': patterns
            })
    return rules

class AnalyzeRequest(BaseModel):
    project_path: str
    rules_path: str = os.path.join(BASE_DIR, 'Rules', 'rules.json')  # 默认规则路径
    sink_types: Optional[List[str]] = None
    depth: Optional[int] = 15  # 默认深度提升到15，确保深度回溯
    engine: str = 'original'  # 'original' 使用原引擎，'lite' 使用轻量版
    max_seconds: Optional[int] = 600  # 单个链路回溯最长时间（秒），提升到10分钟确保完整回溯
    template_scan: str = 'on'  # 'on'|'off' 是否启用模板文件正则扫描
    lite_enrich: str = 'on'  # 默认开启富化模式，确保准确性
    apply_must_substrings: Optional[bool] = False  # 启用 must_substrings/exclude_substrings 过滤降低误报
class ChainRequest(BaseModel):
    project_path: str
    rules_path: str = os.path.join(BASE_DIR, 'Rules', 'rules.json')
    call_chain: List[str] = []
    chain: Optional[List[str]] = None  # 兼容前端传入的chain字段

class SinkTypesRequest(BaseModel):
    rules_path: str = os.path.join(BASE_DIR, 'Rules', 'rules.json')

class AISummaryRequest(BaseModel):
    api_key: str
    text: str
    model: str = 'gpt-4o-mini'
    api_base: str = 'https://api.openai.com/v1'

@app.api_route('/api/analyze', methods=['POST', 'HEAD'])
@performance_monitor.timeit('analyze')
def analyze(request: Request, req: Optional[AnalyzeRequest] = None):
    # HEAD请求直接返回200
    if request.method == 'HEAD':
        return Response(status_code=200)
    
    # POST请求需要body
    if req is None:
        raise HTTPException(status_code=400, detail='请求体不能为空')
    """
    分析接口，包含输入验证和异常处理
    
    Args:
        req: 分析请求
        
    Returns:
        分析结果
    """
    try:
        # 输入验证 - 使用核心验证模块
        try:
            project_path = validate_project_path(req.project_path)
            rules_path = validate_rules_path(req.rules_path)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # 每次扫描前清除取消和暂停标志
        try:
            STOP_EVENT.clear()
            PAUSE_EVENT.clear()
        except Exception as e:
            logger.warning(f"清除停止/暂停标志失败: {e}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'请求参数验证失败: {str(e)}')

    # 选择引擎：original 完全保留原项目功能；lite 使用轻量版
    if req.engine == 'original':
        if not HAS_ORIGINAL:
            raise HTTPException(status_code=400, detail='原始引擎不可用：请将 JavaSinkTracer.py、JavaCodeExtract.py、AutoVulReport.py 复制到当前 niuniu 目录')
        try:
            # 将部分结果持续写入本地文件，供前端轮询显示进度（original 引擎）
            partial_path = os.path.join(BASE_DIR, 'reports')
            os.makedirs(partial_path, exist_ok=True)
            partial_file = os.path.join(partial_path, 'last_partial.json')
            def on_partial(items):
                import json as pyjson, time as _t
                snap = {
                    'success': True,
                    'total': len(items),
                    'vulnerabilities': items[-200:],
                    'current_file': getattr(engine, 'current_file', ''),
                    'parsed': getattr(engine, 'stats', {}).get('parsed_files', 0),
                    'total_files': getattr(engine, 'stats', {}).get('total_files', 0),
                    'rate_per_min': getattr(engine, 'stats', {}).get('rate_per_min', 0.0),
                    'ts': int(_t.time())
                }
                with open(partial_file, 'w', encoding='utf-8') as f:
                    pyjson.dump(snap, f, ensure_ascii=False, indent=2)
            engine = JavaSinkTracer(project_path, rules_path, on_partial=on_partial)
            # 融合内置增强规则 + 外部CSV规则 -> template_rules
            base = engine.rules.get('template_rules', []) or []
            engine.rules['template_rules'] = base + EXTRA_TEMPLATE_RULES
            engine.build_ast()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'原始引擎初始化失败：{e}')
        # 可选覆盖回溯深度与超时（为避免卡死，支持轻量返回）
        if req.max_seconds is not None:
            engine.rules['max_seconds'] = int(req.max_seconds)
        if req.depth is not None:
            engine.rules['depth'] = int(req.depth)
        # 可选过滤 sink 类型
        original_sink_rules = engine.rules.get('sink_rules', [])
        if req.sink_types:
            engine.rules['sink_rules'] = [r for r in original_sink_rules if r.get('sink_name') in req.sink_types]
        # 若设置了 max_seconds，则优先使用轻量扫描，避免长时间代码提取阻塞
        try:
            if engine.rules.get('max_seconds'):
                vulns = engine.find_taint_paths_lightweight()
            else:
                vulns = engine.find_taint_paths()  # 原始完整流程（含代码提取）
        except Exception as e:
            # 扫描中断时，返回已扫描的数据
            vulns = engine.partial_results.copy() if hasattr(engine, 'partial_results') else []
            # 保存最终结果（即使出错）
            if engine.on_partial:
                try:
                    engine.on_partial(engine.partial_results)
                except Exception:
                    pass
            import traceback
            print(f"[警告] 原始引擎扫描过程中出现异常，已保存部分结果: {e}")
            print(traceback.format_exc())
        finally:
            # 确保最终结果已保存
            if engine.on_partial:
                try:
                    engine.on_partial(engine.partial_results)
                except Exception:
                    pass
        # 模板扫描（在 original 引擎下也执行一次模板文本扫描并合并）
        try:
            if (not req.template_scan) or req.template_scan.lower() != 'off':
                tmpl_an = Analyzer(project_path, rules_path)
                # 加载增强的Java/JSP规则
                enhanced_rules_path = os.path.join(BASE_DIR, 'enhanced_rules.json')
                enhanced_rules = []
                if os.path.exists(enhanced_rules_path):
                    try:
                        with open(enhanced_rules_path, 'r', encoding='utf-8') as f:
                            enhanced_data = json.load(f)
                            enhanced_rules = enhanced_data.get('enhanced_template_rules', [])
                    except Exception as e:
                        logger.warning(f"加载增强规则失败: {e}")
                base_tmpl = tmpl_an.rules.get('template_rules', []) or []
                tmpl_an.rules['template_rules'] = base_tmpl + EXTRA_TEMPLATE_RULES + enhanced_rules
                tmpl_hits = tmpl_an._scan_template_files()
                if tmpl_hits:
                    vulns.extend(tmpl_hits)
        except Exception as e:
            import traceback
            print(f"[警告] 模板扫描过程中出现异常: {e}")
            print(traceback.format_exc())
        # 还原规则
        if req.sink_types:
            engine.rules['sink_rules'] = original_sink_rules
        return {
            'success': True,
            'total_vulnerabilities': len(vulns),
            'vulnerabilities': vulns,
            'engine': 'original',
            'stats': getattr(tmpl_an, 'template_scan_stats', {}) if 'tmpl_an' in locals() else {}
        }
    else:
        try:
            # 将部分结果持续写入本地文件，供前端轮询显示进度
            partial_path = os.path.join(BASE_DIR, 'reports')
            os.makedirs(partial_path, exist_ok=True)
            partial_file = os.path.join(partial_path, 'last_partial.json')
            def on_partial(items):
                import json as pyjson, time as _t
                snap = {
                    'success': True,
                    'total': len(items),
                    'vulnerabilities': items[-200:],  # 限制大小
                    'current_file': getattr(analyzer, 'current_file', ''),
                    'parsed': getattr(analyzer, '_parsed_files', 0),
                    'total_files': getattr(analyzer, '_total_files', 0),
                    'rate_per_min': getattr(analyzer, '_rate_per_min', 0.0),
                    'ts': int(_t.time())
                }
                with open(partial_file, 'w', encoding='utf-8') as f:
                    pyjson.dump(snap, f, ensure_ascii=False, indent=2)
            # 组合停止和暂停检查：停止优先于暂停
            def should_stop_or_pause():
                if STOP_EVENT.is_set():
                    return True
                # 如果暂停，等待恢复
                while PAUSE_EVENT.is_set() and not STOP_EVENT.is_set():
                    import time
                    time.sleep(0.1)  # 每100ms检查一次
                return STOP_EVENT.is_set()
            analyzer = Analyzer(project_path, rules_path, on_partial=on_partial, should_stop=should_stop_or_pause)
            # 融合内置增强规则 + 外部CSV规则 -> template_rules
            base = analyzer.rules.get('template_rules', []) or []
            analyzer.rules['template_rules'] = base + EXTRA_TEMPLATE_RULES
            analyzer.build_ast()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'轻量引擎初始化失败：{e}')
        # 设置回溯超时（避免卡死）
        if req.max_seconds is not None:
            analyzer.rules['max_seconds'] = int(req.max_seconds)
        if req.depth is not None:
            analyzer.rules['depth'] = int(req.depth)
        # lite 快速/富化 开关：
        # lite_enrich='on' → __lite_fast__=False → 富化模式（打分/消毒/溯源）
        # lite_enrich='off' → __lite_fast__=True → 快速模式（仅返回链路）
        lite_enrich_value = str(req.lite_enrich).lower() if req.lite_enrich else 'off'
        analyzer.rules['__lite_fast__'] = (lite_enrich_value != 'on')
        logger.info(f"Lite模式配置: lite_enrich={lite_enrich_value}, __lite_fast__={analyzer.rules['__lite_fast__']}")
        analyzer.rules['__apply_must_substrings__'] = bool(req.apply_must_substrings)
        if req.template_scan and req.template_scan.lower() == 'off':
            analyzer.rules['__disable_template_scan__'] = True
        # 加载增强的Java/JSP模板规则
        enhanced_rules_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_rules.json')
        enhanced_rules = []
        if os.path.exists(enhanced_rules_path):
            try:
                with open(enhanced_rules_path, 'r', encoding='utf-8') as f:
                    enhanced_data = json.load(f)
                    enhanced_rules = enhanced_data.get('enhanced_template_rules', [])
            except Exception as e:
                logger.warning(f"加载增强模板规则失败: {e}")
        base_tmpl = analyzer.rules.get('template_rules', []) or []
        analyzer.rules['template_rules'] = base_tmpl + EXTRA_TEMPLATE_RULES + enhanced_rules
        
        # 加载增强的Source规则
        enhanced_sources_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_sources.json')
        if os.path.exists(enhanced_sources_path):
            try:
                with open(enhanced_sources_path, 'r', encoding='utf-8') as f:
                    enhanced_sources_data = json.load(f)
                    enhanced_sources = enhanced_sources_data.get('enhanced_source_rules', [])
                    base_sources = analyzer.rules.get('source_rules', []) or []
                    analyzer.rules['source_rules'] = base_sources + enhanced_sources
                    logger.info(f"已加载 {len(enhanced_sources)} 条增强Source规则")
            except Exception as e:
                logger.warning(f"加载增强Source规则失败: {e}")
        
        # 加载增强的Sanitizer规则
        enhanced_sanitizers_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_sanitizers.json')
        if os.path.exists(enhanced_sanitizers_path):
            try:
                with open(enhanced_sanitizers_path, 'r', encoding='utf-8') as f:
                    enhanced_sanitizers_data = json.load(f)
                    enhanced_sanitizers = enhanced_sanitizers_data.get('enhanced_sanitizer_rules', [])
                    base_sanitizers = analyzer.rules.get('sanitizer_rules', []) or []
                    analyzer.rules['sanitizer_rules'] = base_sanitizers + enhanced_sanitizers
                    logger.info(f"已加载 {len(enhanced_sanitizers)} 条增强Sanitizer规则")
            except Exception as e:
                logger.warning(f"加载增强Sanitizer规则失败: {e}")
        
        # 加载增强的Sink规则
        enhanced_sinks_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_sinks.json')
        if os.path.exists(enhanced_sinks_path):
            try:
                with open(enhanced_sinks_path, 'r', encoding='utf-8') as f:
                    enhanced_sinks_data = json.load(f)
                    enhanced_sinks = enhanced_sinks_data.get('enhanced_sink_rules', [])
                    base_sinks = analyzer.rules.get('sink_rules', []) or []
                    analyzer.rules['sink_rules'] = base_sinks + enhanced_sinks
                    logger.info(f"已加载 {len(enhanced_sinks)} 条增强Sink规则")
            except Exception as e:
                logger.warning(f"加载增强Sink规则失败: {e}")
        
        # 加载综合规则（comprehensive_rules.json）作为额外的模板规则
        comprehensive_rules_path = os.path.join(BASE_DIR, 'Rules', 'comprehensive_rules.json')
        if os.path.exists(comprehensive_rules_path):
            try:
                with open(comprehensive_rules_path, 'r', encoding='utf-8') as f:
                    comprehensive_data = json.load(f)
                    comprehensive_rules = comprehensive_data.get('comprehensive_rules', [])
                    if comprehensive_rules:
                        base_tmpl = analyzer.rules.get('template_rules', []) or []
                        analyzer.rules['template_rules'] = base_tmpl + comprehensive_rules
                        logger.info(f"已加载 {len(comprehensive_rules)} 条综合规则")
            except Exception as e:
                logger.warning(f"加载综合规则失败: {e}")
        if req.sink_types:
            original = analyzer.rules.get('sink_rules', [])
            analyzer.rules['sink_rules'] = [r for r in original if r.get('sink_name') in req.sink_types]
        try:
            vulns = analyzer.find_vulnerabilities()
        except Exception as e:
            # 扫描中断时，返回已扫描的数据
            vulns = analyzer.partial_results.copy() if hasattr(analyzer, 'partial_results') else []
            # 保存最终结果（即使出错）
            if analyzer.on_partial:
                try:
                    analyzer.on_partial(analyzer.partial_results)
                except Exception:
                    pass
            # 仍然抛出异常，但前端可以通过last_partial.json获取部分结果
            import traceback
            print(f"[警告] 扫描过程中出现异常，已保存部分结果: {e}")
            print(traceback.format_exc())
        finally:
            # 确保最终结果已保存
            if analyzer.on_partial:
                try:
                    analyzer.on_partial(analyzer.partial_results)
                except Exception:
                    pass
        if req.sink_types:
            analyzer.rules['sink_rules'] = original
        return {
            'success': True,
            'total_vulnerabilities': len(vulns),
            'vulnerabilities': vulns,
            'engine': 'lite',
            'stats': getattr(analyzer, 'template_scan_stats', {}) if hasattr(analyzer, 'template_scan_stats') else {}
        }

@app.api_route('/api/sink-types', methods=['POST', 'HEAD'])
def sink_types(request: Request, req: Optional[SinkTypesRequest] = None):
    # HEAD请求直接返回200
    if request.method == 'HEAD':
        return Response(status_code=200)
    
    # POST请求需要body
    if req is None:
        raise HTTPException(status_code=400, detail='请求体不能为空')
    try:
        rules_path = os.path.abspath(req.rules_path)
        import json
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        sink_names = {r.get('sink_name') for r in rules.get('sink_rules', []) if r.get('sink_name')}
        tmpl_names = set()
        for r in rules.get('template_rules', []) or []:
            name = r.get('name') or r.get('vul_type')
            if name:
                tmpl_names.add(name)
        names = sorted(list(sink_names | tmpl_names))
        return {'success': True, 'sink_types': names}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/chain')
def chain_details(req: ChainRequest):
    project_path = os.path.abspath(req.project_path)
    rules_path = os.path.abspath(req.rules_path)
    analyzer = Analyzer(project_path, rules_path)
    analyzer.build_ast()

    # 兼容chain和call_chain两种字段名
    call_chain = req.call_chain if req.call_chain else (req.chain or [])
    
    details = []
    for func_sig in call_chain:
        cls, mtd = func_sig.split(':', 1)
        file_path, code = analyzer.extract_method_definition(cls, mtd)
        details.append({
            'function': func_sig,
            'file_path': file_path or '未找到',
            'code': code or '未找到源码',
            'line': analyzer.last_extracted_line if hasattr(analyzer, 'last_extracted_line') else None
        })
    return {'success': True, 'chain': details}

class TemplateSnippetRequest(BaseModel):
    project_path: str
    file_path: str  # 绝对或相对 project_path 的路径
    group_lines: Optional[List[int]] = None  # 命中行集合（可选）
    start: Optional[int] = None  # 起始行（可选）
    end: Optional[int] = None    # 结束行（可选）
    context: Optional[int] = 2   # 额外上下文行数（默认2）

@app.post('/api/template-snippet')
def template_snippet(req: TemplateSnippetRequest):
    try:
        base = os.path.abspath(req.project_path)
        fp = req.file_path
        if not os.path.isabs(fp):
            fp = os.path.join(base, fp)
        fp = os.path.abspath(fp)
        if not os.path.exists(fp):
            raise HTTPException(status_code=404, detail='文件不存在')
        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        if req.group_lines and len(req.group_lines) > 0:
            s = max(1, min(req.group_lines))
            e = min(len(lines), max(req.group_lines))
        else:
            s = int(req.start) if req.start else 1
            e = int(req.end) if req.end else min(len(lines), s + 50)
        ctx = int(req.context or 0)
        s = max(1, s - ctx)
        e = min(len(lines), e + ctx)
        code = ''.join(lines[s-1:e])
        return {
            'success': True,
            'file_path': fp,
            'start': s,
            'end': e,
            'line_count': e - s + 1,
            'code': code
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class TemplateScanRequest(BaseModel):
    project_path: str
    rules_path: str = os.path.join(BASE_DIR, 'Rules', 'rules.json')
    lite_enrich: Optional[str] = None  # 'on'|'off'
    ignore_skip_dirs: Optional[bool] = False  # 忽略内置跳过目录（/target/ 等）
    include_exts: Optional[List[str]] = None  # 仅扫描这些扩展名（如 ["jsp","html"])
    apply_must_substrings: Optional[bool] = False  # 启用 must_substrings/exclude_substrings 过滤降低误报
@app.post('/api/template-scan')
def template_scan(req: TemplateScanRequest):
    """
    模板扫描接口
    
    Args:
        req: 模板扫描请求
        
    Returns:
        扫描结果
    """
    try:
        import traceback
        # 使用核心验证模块
        try:
            project_path = validate_project_path(req.project_path)
            rules_path = validate_rules_path(req.rules_path)
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))
        try:
            STOP_EVENT.clear()
            PAUSE_EVENT.clear()
        except Exception:
            pass
        # 组合停止和暂停检查
        def should_stop_or_pause():
            if STOP_EVENT.is_set():
                return True
            while PAUSE_EVENT.is_set() and not STOP_EVENT.is_set():
                import time
                time.sleep(0.1)
            return STOP_EVENT.is_set()
        analyzer = Analyzer(project_path, rules_path, should_stop=should_stop_or_pause)
        # 融合内置增强规则，仅做模板扫描，不构建AST
        base = analyzer.rules.get('template_rules', []) or []
        # 加载增强的Java/JSP模板规则
        enhanced_rules_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_rules.json')
        enhanced_rules = []
        if os.path.exists(enhanced_rules_path):
            try:
                with open(enhanced_rules_path, 'r', encoding='utf-8') as f:
                    enhanced_data = json.load(f)
                    enhanced_rules = enhanced_data.get('enhanced_template_rules', [])
            except Exception as e:
                logger.warning(f"加载增强模板规则失败: {e}")
        analyzer.rules['template_rules'] = base + EXTRA_TEMPLATE_RULES + enhanced_rules
        
        # 加载综合规则（comprehensive_rules.json）
        comprehensive_rules_path = os.path.join(BASE_DIR, 'Rules', 'comprehensive_rules.json')
        if os.path.exists(comprehensive_rules_path):
            try:
                with open(comprehensive_rules_path, 'r', encoding='utf-8') as f:
                    comprehensive_data = json.load(f)
                    comprehensive_rules = comprehensive_data.get('comprehensive_rules', [])
                    if comprehensive_rules:
                        analyzer.rules['template_rules'] = analyzer.rules.get('template_rules', []) + comprehensive_rules
                        logger.info(f"模板扫描已加载 {len(comprehensive_rules)} 条综合规则")
            except Exception as e:
                logger.warning(f"加载综合规则失败: {e}")
        
        # 加载增强的Source/Sanitizer/Sink规则（模板扫描也需要这些规则用于上下文分析）
        enhanced_sources_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_sources.json')
        if os.path.exists(enhanced_sources_path):
            try:
                with open(enhanced_sources_path, 'r', encoding='utf-8') as f:
                    enhanced_sources_data = json.load(f)
                    enhanced_sources = enhanced_sources_data.get('enhanced_source_rules', [])
                    base_sources = analyzer.rules.get('source_rules', []) or []
                    analyzer.rules['source_rules'] = base_sources + enhanced_sources
            except Exception as e:
                logger.warning(f"加载增强Source规则失败: {e}")
        
        enhanced_sanitizers_path = os.path.join(BASE_DIR, 'Rules', 'enhanced_sanitizers.json')
        if os.path.exists(enhanced_sanitizers_path):
            try:
                with open(enhanced_sanitizers_path, 'r', encoding='utf-8') as f:
                    enhanced_sanitizers_data = json.load(f)
                    enhanced_sanitizers = enhanced_sanitizers_data.get('enhanced_sanitizer_rules', [])
                    base_sanitizers = analyzer.rules.get('sanitizer_rules', []) or []
                    analyzer.rules['sanitizer_rules'] = base_sanitizers + enhanced_sanitizers
            except Exception as e:
                logger.warning(f"加载增强Sanitizer规则失败: {e}")
        analyzer.rules['__lite_fast__'] = (str(req.lite_enrich).lower() != 'on')
        analyzer.rules['__ignore_skip_dirs__'] = bool(req.ignore_skip_dirs)
        if req.include_exts:
            analyzer.rules['__include_exts__'] = [e.lower().lstrip('.') for e in req.include_exts]
        analyzer.rules['__apply_must_substrings__'] = bool(req.apply_must_substrings)
        # 直接执行模板扫描
        vulns = analyzer._scan_template_files()
        stats = getattr(analyzer, 'template_scan_stats', {})
        # 附加起始路径与存在性
        stats['start_path'] = project_path
        stats['base_exists'] = os.path.exists(project_path)
        return { 'success': True, 'total_vulnerabilities': len(vulns), 'vulnerabilities': vulns, 'engine': 'template-only', 'stats': stats }
    except HTTPException:
        raise
    except Exception as e:
        # 返回更可诊断的错误
        tb = traceback.format_exc(limit=2)
        raise HTTPException(status_code=500, detail=f'{e.__class__.__name__}: {e}; Trace: {tb}')

@app.post('/api/cancel')
def cancel_scan():
    """停止扫描（取消）"""
    try:
        STOP_EVENT.set()
        PAUSE_EVENT.clear()  # 停止时清除暂停状态
        return {'success': True, 'message': '停止扫描信号已发送'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/pause')
def pause_scan():
    """暂停扫描"""
    try:
        if STOP_EVENT.is_set():
            return {'success': False, 'message': '扫描已停止，无法暂停'}
        PAUSE_EVENT.set()
        return {'success': True, 'message': '暂停信号已发送', 'paused': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/resume')
def resume_scan():
    """继续扫描"""
    try:
        if STOP_EVENT.is_set():
            return {'success': False, 'message': '扫描已停止，无法继续'}
        PAUSE_EVENT.clear()
        return {'success': True, 'message': '继续扫描信号已发送', 'paused': False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.api_route('/api/scan-status', methods=['GET', 'HEAD'])
def get_scan_status(request: Request):
    """获取扫描状态"""
    # HEAD请求直接返回200
    if request.method == 'HEAD':
        return Response(status_code=200)
    
    try:
        return {
            'success': True,
            'stopped': STOP_EVENT.is_set(),
            'paused': PAUSE_EVENT.is_set(),
            'running': not STOP_EVENT.is_set() and not PAUSE_EVENT.is_set()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/ai-summary')
def ai_summary(req: AISummaryRequest):
    try:
        # 简单校验，避免第三方返回难以理解的错误
        if not req.model:
            raise HTTPException(status_code=400, detail='缺少模型参数：请填写 Model（例如 x1）')
        headers = {
            'Authorization': f'Bearer {req.api_key}',
            'Content-Type': 'application/json'
        }
        payload = {
            'model': req.model,
            'messages': [
                {'role': 'system', 'content': '你是安全审计助手。严格遵守：只进行审计与风险识别，不提供任何修复建议。面对初学者（小白）要逐条解释：具体不安全写法、触发的规则点、为什么有风险（含可能攻击面）。'},
                {'role': 'user', 'content': req.text}
            ]
        }
        url = req.api_base.rstrip('/') + '/chat/completions'
        # 简易缓存：按 model+base+text 生成 key
        import hashlib, json as pyjson
        cache_dir = os.path.join(BASE_DIR, 'reports')
        os.makedirs(cache_dir, exist_ok=True)
        cache_file = os.path.join(cache_dir, 'ai_cache.json')
        cache = {}
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache = pyjson.load(f)
        except Exception:
            cache = {}
        key = hashlib.sha256((req.model + '|' + req.api_base + '|' + req.text).encode('utf-8')).hexdigest()
        if key in cache:
            return {'success': True, 'summary': cache[key]}
        # 请求 + 重试一次
        for attempt in range(2):
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                # 兼容星火X1与OpenAI格式：优先 content，附加 reasoning_content
                try:
                    msg = (data.get('choices') or [{}])[0].get('message') or {}
                except Exception:
                    msg = {}
                content = (msg.get('content') or '').strip()
                reasoning = (msg.get('reasoning_content') or '').strip()
                summary = (reasoning + ('\n\n' if reasoning and content else '') + content) or (data.get('message') or '') or resp.text
                cache[key] = summary
                try:
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        pyjson.dump(cache, f, ensure_ascii=False, indent=2)
                except Exception:
                    pass
                meta = {
                    'usage': data.get('usage'),
                    'provider_code': data.get('code'),
                    'provider_message': data.get('message'),
                    'sid': data.get('sid')
                }
                return {'success': True, 'summary': summary, 'meta': meta}
            last_err = resp.text
        raise HTTPException(status_code=500, detail=last_err)
    except HTTPException:
        # 直接抛出显式错误给前端
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ReportRequest(BaseModel):
    project_path: str
    rules_path: str = os.path.join(BASE_DIR, 'Rules', 'rules.json')
    output_dir: Optional[str] = None  # 默认写入 niuniu/reports
    vulnerabilities: Optional[List[Dict[str, Any]]] = None  # 若前端传入当前视图下的漏洞列表，则直接用它生成报告
    title: Optional[str] = None  # 可选自定义报告标题
    filters: Optional[Dict[str, Any]] = None  # 前端展示层的筛选条件（用于报告标注）


@app.post('/api/report')
def generate_report(req: ReportRequest):
    project_path = os.path.abspath(req.project_path)
    rules_path = os.path.abspath(req.rules_path)
    output_dir = os.path.abspath(req.output_dir) if req.output_dir else os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(output_dir, exist_ok=True)

    # 若前端已提供漏洞集合（已按当前筛选过滤），则直接使用；否则回退到原始扫描生成
    if req.vulnerabilities is not None:
        vulns = req.vulnerabilities
    else:
        tracer = JavaSinkTracer(project_path, rules_path)
        tracer.build_ast()
        vulns = tracer.find_taint_paths()

    # 将结果写入一个中间 JSON（兼容原报告生成流程）
    json_path = os.path.join(output_dir, 'vulns.json')
    import json as pyjson
    with open(json_path, 'w', encoding='utf-8') as f:
        pyjson.dump([{
            'vul_type': v.get('vul_type'),
            'sink_desc': v.get('sink_desc'),
            'severity': v.get('severity'),
            'sink': v.get('sink'),
            'call_chains': v.get('call_chains'),
            'file_path': v.get('file_path'),
            'group_lines': v.get('group_lines'),
            'group_size': v.get('group_size'),
        } for v in vulns], f, ensure_ascii=False, indent=2)
    # 写入可选 meta（用于在报告中标注筛选条件）
    try:
        meta = {
            'title': req.title,
            'filters': req.filters or {},
        }
        with open(os.path.join(output_dir, 'vulns_meta.json'), 'w', encoding='utf-8') as mf:
            pyjson.dump(meta, mf, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # 生成 Markdown + HTML 报告（Windows 目录名需清洗）
    project_name = os.path.basename(project_path.rstrip('/\\'))
    def _sanitize_name(name: str) -> str:
        bad = set('<>:"/\\|?*')
        return ''.join(ch if ch not in bad else '_' for ch in name)[:80].rstrip(' .') or 'report'
    safe_title = _sanitize_name(req.title or project_name)
    generate_markdown_report(safe_title, project_path, json_path, output_dir)

    return {'success': True, 'output_dir': output_dir, 'count': len(vulns), 'title': safe_title}

@app.get('/api/engines')
def get_engines():
    engines = ['lite']
    if HAS_ORIGINAL:
        engines.insert(0, 'original')
    return {'engines': engines}

@app.get('/api/ping')
@app.head('/api/ping')
def ping():
    return {'ok': True}

@app.api_route('/api/partial', methods=['GET', 'HEAD'])
def get_partial(request: Request):
    # HEAD请求直接返回200
    if request.method == 'HEAD':
        return Response(status_code=200)
    
    try:
        partial_file = os.path.join(BASE_DIR, 'reports', 'last_partial.json')
        if os.path.exists(partial_file):
            import json as pyjson
            with open(partial_file, 'r', encoding='utf-8') as f:
                return pyjson.load(f)
        return {'success': True, 'total': 0, 'vulnerabilities': []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/')
def index():
    return {'message': 'Niuniu Analyzer is running. Visit /static/index.html'}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=7777)
