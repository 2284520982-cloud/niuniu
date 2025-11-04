"""
项目常量配置
"""
import os

# 文件大小限制
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
MAX_FILE_LINES = 200000  # 20万行
MAX_FILE_BYTES = 50 * 1024 * 1024  # 模板扫描最大文件大小

# 扫描限制
MAX_FINDINGS = 999999  # 单文件最大发现数
MAX_REGEX_EVALS_PER_FILE = 500  # 单文件最大正则评估次数
PER_FILE_RULE_CAP = 1  # 单文件单规则最大命中数

# 上下文窗口
CONTEXT_WINDOW = 15  # 上下文分析窗口大小

# 缓存配置
CACHE_TTL = 300  # 缓存过期时间（秒）
CACHE_MAX_SIZE = 1000  # 最大缓存条目数

# 并发配置
MAX_WORKERS = min(4, os.cpu_count() or 1)  # 最大并发工作线程数
DEFAULT_THREAD_POOL_SIZE = 4

# 默认扫描参数
DEFAULT_DEPTH = 15  # 默认回溯深度
DEFAULT_MAX_SECONDS = 600  # 默认单链路超时（秒）
DEFAULT_MAX_CHAINS = 50  # 默认最大显示链条数

# 文件扩展名
JAVA_EXTENSIONS = {'.java'}
TEMPLATE_EXTENSIONS = {'.jsp', '.jspx', '.ftl', '.vm', '.html'}
CLASS_EXTENSIONS = {'.class'}
SCANNABLE_EXTENSIONS = JAVA_EXTENSIONS | TEMPLATE_EXTENSIONS | CLASS_EXTENSIONS

# 跳过目录模式
SKIP_DIR_PATTERNS = [
    '/resources/template/',
    '/src/test/resources/',
    '/target/',
    '/build/',
    '/.git/',
    '/.idea/',
    '/node_modules/',
    '/.mvn/',
    '/out/',
    '/dist/',
    '/.svn/',
    '/.hg/',
]

# 跳过文件扩展名（仅用于AST构建）
SKIP_AST_EXTENSIONS = {'.ftl', '.vm'}  # 纯模板文件在模板扫描中处理

# 严重性级别
SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low']
SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

# 漏洞类型
VULNERABILITY_TYPES = {
    'RCE', 'SQLI', 'XSS', 'SSRF', 'XXE', 'PATH_TRAVERSAL',
    'FILE_WRITE', 'FILE_DELETE', 'ZIP_SLIP', 'TEMPLATE_INJECTION',
    'REDIRECT', 'LDAP_INJECTION', 'EL_INJECTION', 'REFLECTION',
    'LOG_INJECTION', 'CRYPTO_WEAKNESS', 'HARDCODED_SECRET',
    'JWT_WEAK', 'OAUTH2_VULNERABLE', 'NOSQL_INJECTION',
    'REDIS_COMMAND_INJECTION', 'GRAPHQL_INJECTION'
}

# 日志配置
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'WARNING'
LOG_FILE = 'niuniu.log'

# API配置
API_BASE_PATH = '/api'
DEFAULT_BACKEND_URL = 'http://localhost:7777'

# 资源限制
MAX_MEMORY_USAGE_MB = 2048  # 最大内存使用（MB）
MAX_CPU_PERCENT = 80  # 最大CPU使用率

# 正则表达式超时（秒）
REGEX_TIMEOUT = 5

# 默认规则路径
DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Rules', 'rules.json')

