"""
安全工具模块
提供XSS防护、输入验证、路径安全等功能
"""
import os
import re
from typing import Optional, List, Tuple
from pathlib import Path


def sanitize_html(text: str) -> str:
    """
    HTML转义，防止XSS
    
    Args:
        text: 需要转义的文本
        
    Returns:
        转义后的文本
    """
    if not isinstance(text, str):
        text = str(text)
    
    html_escape_map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
    }
    
    for char, escaped in html_escape_map.items():
        text = text.replace(char, escaped)
    
    return text


def sanitize_for_regex(text: str) -> str:
    """
    清理用于正则表达式的文本，防止ReDoS
    
    Args:
        text: 需要清理的文本
        
    Returns:
        清理后的文本
    """
    # 移除可能导致ReDoS的特殊字符
    return re.escape(text)


def validate_project_path(path: str, base_dir: Optional[str] = None) -> bool:
    """
    验证项目路径是否安全（防止路径遍历）
    
    Args:
        path: 项目路径
        base_dir: 基础目录（可选）
        
    Returns:
        是否安全
    """
    try:
        abs_path = os.path.abspath(path)
        
        # 检查路径是否存在
        if not os.path.exists(abs_path):
            return False
        
        # 如果是目录，检查是否真的是目录
        if not os.path.isdir(abs_path):
            return False
        
        # 如果有基础目录，检查路径是否在基础目录内
        if base_dir:
            base_abs = os.path.abspath(base_dir)
            try:
                common_path = os.path.commonpath([abs_path, base_abs])
                if common_path != base_abs:
                    return False
            except ValueError:
                # 路径不在同一驱动器上
                return False
        
        # 检查路径中是否包含危险字符
        if '..' in path or path.startswith('/') or ':' in path:
            # Windows路径可能包含:，需要更细致的检查
            if os.name == 'nt':
                # Windows允许C:这样的路径
                if not re.match(r'^[A-Za-z]:', path):
                    return False
            else:
                return False
        
        return True
    except Exception:
        return False


def sanitize_filename(filename: str) -> str:
    """
    清理文件名，移除危险字符
    
    Args:
        filename: 原始文件名
        
    Returns:
        清理后的文件名
    """
    # 移除路径分隔符和危险字符
    dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
    safe_name = filename
    for char in dangerous_chars:
        safe_name = safe_name.replace(char, '_')
    
    # 限制长度
    safe_name = safe_name[:255]
    
    return safe_name


def validate_file_size(file_path: str, max_size: int = 10 * 1024 * 1024) -> bool:
    """
    验证文件大小是否在限制内
    
    Args:
        file_path: 文件路径
        max_size: 最大大小（字节）
        
    Returns:
        是否在限制内
    """
    try:
        size = os.path.getsize(file_path)
        return size <= max_size
    except OSError:
        return False


def validate_file_lines(file_path: str, max_lines: int = 50000) -> bool:
    """
    验证文件行数是否在限制内
    
    Args:
        file_path: 文件路径
        max_lines: 最大行数
        
    Returns:
        是否在限制内
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)
            return line_count <= max_lines
    except Exception:
        return False


def limit_regex_complexity(pattern: str, max_length: int = 1000) -> bool:
    """
    检查正则表达式复杂度（防止ReDoS）
    
    Args:
        pattern: 正则表达式
        max_length: 最大长度
        
    Returns:
        是否安全
    """
    if len(pattern) > max_length:
        return False
    
    # 检查是否有嵌套量词（ReDoS风险）
    nested_quantifier_pattern = r'\([^)]*\+[^)]*\+[^)]*\)'
    if re.search(nested_quantifier_pattern, pattern):
        return False
    
    return True


class ResourceLimiter:
    """资源限制器"""
    
    def __init__(self, 
                 max_file_size: int = 100 * 1024 * 1024,  # 提升到100MB
                 max_file_lines: int = 500000,  # 提升到50万行
                 max_regex_length: int = 5000):  # 提升到5000字符
        """
        Args:
            max_file_size: 最大文件大小（字节）- 为了准确性大幅提升
            max_file_lines: 最大文件行数 - 为了准确性大幅提升
            max_regex_length: 最大正则表达式长度 - 为了准确性提升
        """
        self.max_file_size = max_file_size
        self.max_file_lines = max_file_lines
        self.max_regex_length = max_regex_length
    
    def check_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """
        检查文件是否符合资源限制
        
        Returns:
            (是否通过, 错误信息)
        """
        if not validate_file_size(file_path, self.max_file_size):
            return False, f"文件大小超过限制: {self.max_file_size / 1024 / 1024}MB"
        
        if not validate_file_lines(file_path, self.max_file_lines):
            return False, f"文件行数超过限制: {self.max_file_lines}"
        
        return True, None
    
    def check_regex(self, pattern: str) -> Tuple[bool, Optional[str]]:
        """
        检查正则表达式是否符合资源限制
        
        Returns:
            (是否通过, 错误信息)
        """
        if not limit_regex_complexity(pattern, self.max_regex_length):
            return False, f"正则表达式长度超过限制: {self.max_regex_length}"
        
        return True, None


# 全局资源限制器实例
resource_limiter = ResourceLimiter()

