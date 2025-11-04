"""
自定义异常类
"""


class AnalyzerError(Exception):
    """分析器基础异常"""
    pass


class RulesLoadError(AnalyzerError):
    """规则加载错误"""
    pass


class ASTParseError(AnalyzerError):
    """AST解析错误"""
    pass


class FileProcessingError(AnalyzerError):
    """文件处理错误"""
    pass


class ValidationError(AnalyzerError):
    """验证错误"""
    pass


class ResourceLimitError(AnalyzerError):
    """资源限制错误"""
    pass


class SecurityError(AnalyzerError):
    """安全错误"""
    pass


class ConfigurationError(AnalyzerError):
    """配置错误"""
    pass

