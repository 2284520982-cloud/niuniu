"""
核心工具函数
"""
import re
from typing import List, Dict, Any, Optional


def compile_regex_patterns(patterns: List[str]) -> List[re.Pattern]:
    """
    编译正则表达式模式列表
    
    Args:
        patterns: 正则表达式字符串列表
        
    Returns:
        编译后的Pattern对象列表
    """
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE | re.MULTILINE))
        except re.error as e:
            # 无效的正则表达式，记录警告但继续
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"正则表达式编译失败: {pattern[:50]}..., 错误: {e}")
    return compiled


def safe_split(s: str, delimiter: str, maxsplit: int = -1) -> List[str]:
    """
    安全分割字符串
    
    Args:
        s: 要分割的字符串
        delimiter: 分隔符
        maxsplit: 最大分割次数
        
    Returns:
        分割后的列表
    """
    try:
        return s.split(delimiter, maxsplit) if maxsplit >= 0 else s.split(delimiter)
    except Exception:
        return [s]


def truncate_string(s: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    截断字符串
    
    Args:
        s: 原始字符串
        max_length: 最大长度
        suffix: 后缀
        
    Returns:
        截断后的字符串
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    合并多个字典
    
    Args:
        *dicts: 要合并的字典
        
    Returns:
        合并后的字典
    """
    result = {}
    for d in dicts:
        if isinstance(d, dict):
            result.update(d)
    return result


def get_nested_value(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    获取嵌套字典的值
    
    Args:
        data: 字典数据
        path: 路径，用点分隔，如 "a.b.c"
        default: 默认值
        
    Returns:
        值或默认值
    """
    try:
        keys = path.split('.')
        value = data
        for key in keys:
            value = value[key]
        return value
    except (KeyError, TypeError, AttributeError):
        return default


def set_nested_value(data: Dict[str, Any], path: str, value: Any) -> None:
    """
    设置嵌套字典的值
    
    Args:
        data: 字典数据
        path: 路径，用点分隔
        value: 要设置的值
    """
    try:
        keys = path.split('.')
        target = data
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = value
    except (TypeError, AttributeError):
        pass

