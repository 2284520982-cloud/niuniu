"""
输入验证和资源检查
"""
import os
import logging
from pathlib import Path
from typing import Optional
from .constants import MAX_FILE_SIZE, MAX_FILE_LINES, SKIP_DIR_PATTERNS
from .exceptions import ValidationError, SecurityError, ResourceLimitError

logger = logging.getLogger(__name__)


def validate_project_path(project_path: str) -> str:
    """
    验证项目路径
    
    Args:
        project_path: 项目路径
        
    Returns:
        绝对路径
        
    Raises:
        ValidationError: 路径无效
        SecurityError: 路径不安全
    """
    if not project_path:
        raise ValidationError("项目路径不能为空")
    
    try:
        abs_path = os.path.abspath(project_path)
        
        if not os.path.exists(abs_path):
            raise ValidationError(f"项目路径不存在: {project_path}")
        
        if not os.path.isdir(abs_path):
            raise ValidationError(f"项目路径不是目录: {project_path}")
        
        # 安全检查：防止路径遍历
        # 确保路径在允许的范围内
        if not os.path.isabs(abs_path):
            raise SecurityError(f"项目路径必须是绝对路径: {project_path}")
        
        # 检查是否在系统关键目录
        critical_dirs = ['/etc', '/usr', '/bin', '/sbin', '/windows', 'C:\\Windows']
        for critical in critical_dirs:
            if abs_path.startswith(critical):
                raise SecurityError(f"项目路径不能在系统关键目录: {project_path}")
        
        return abs_path
    except (OSError, ValueError) as e:
        raise ValidationError(f"项目路径验证失败: {e}")


def validate_rules_path(rules_path: str) -> str:
    """
    验证规则文件路径
    
    Args:
        rules_path: 规则文件路径
        
    Returns:
        绝对路径
        
    Raises:
        ValidationError: 路径无效
    """
    if not rules_path:
        raise ValidationError("规则文件路径不能为空")
    
    try:
        abs_path = os.path.abspath(rules_path)
        
        if not os.path.exists(abs_path):
            raise ValidationError(f"规则文件不存在: {rules_path}")
        
        if not os.path.isfile(abs_path):
            raise ValidationError(f"规则路径不是文件: {rules_path}")
        
        # 检查文件扩展名
        if not abs_path.endswith('.json'):
            raise ValidationError(f"规则文件必须是JSON格式: {rules_path}")
        
        return abs_path
    except (OSError, ValueError) as e:
        raise ValidationError(f"规则文件路径验证失败: {e}")


def validate_file_size(file_path: str, max_size: Optional[int] = None) -> bool:
    """
    验证文件大小
    
    Args:
        file_path: 文件路径
        max_size: 最大大小（字节），None使用默认值
        
    Returns:
        True if valid
        
    Raises:
        ResourceLimitError: 文件过大
    """
    max_size = max_size or MAX_FILE_SIZE
    
    try:
        size = os.path.getsize(file_path)
        if size > max_size:
            raise ResourceLimitError(
                f"文件过大: {file_path} ({size / 1024 / 1024:.2f}MB > {max_size / 1024 / 1024:.2f}MB)"
            )
        return True
    except OSError as e:
        logger.warning(f"无法获取文件大小: {file_path}, {e}")
        return False


def validate_file_lines(file_path: str, max_lines: Optional[int] = None) -> bool:
    """
    验证文件行数
    
    Args:
        file_path: 文件路径
        max_lines: 最大行数，None使用默认值
        
    Returns:
        True if valid
        
    Raises:
        ResourceLimitError: 文件行数过多
    """
    max_lines = max_lines or MAX_FILE_LINES
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = sum(1 for _ in f)
            if line_count > max_lines:
                raise ResourceLimitError(
                    f"文件行数过多: {file_path} ({line_count} lines > {max_lines} lines)"
                )
        return True
    except (OSError, IOError) as e:
        logger.warning(f"无法读取文件行数: {file_path}, {e}")
        return False


def should_skip_file(file_path: str, project_path: str) -> bool:
    """
    判断文件是否应该跳过
    
    Args:
        file_path: 文件路径
        project_path: 项目根路径
        
    Returns:
        True if should skip
    """
    try:
        # 安全检查：防止路径遍历
        rel_path = os.path.relpath(file_path, project_path)
        try:
            common_path = os.path.commonpath([project_path, os.path.abspath(file_path)])
            if common_path != os.path.abspath(project_path):
                logger.warning(f"检测到可疑路径: {file_path}")
                return True
        except ValueError:
            # 路径不在同一驱动器上
            logger.warning(f"路径跨驱动器: {file_path}")
            return True
        
        # 检查跳过目录模式
        normalized_path = rel_path.replace(os.sep, '/')
        if any(pattern in normalized_path for pattern in SKIP_DIR_PATTERNS):
            return True
        
        # 文件大小检查
        if not validate_file_size(file_path):
            return True
        
        return False
    except Exception as e:
        logger.warning(f"文件跳过检查异常: {file_path}, {e}")
        return True


def sanitize_path(path: str, base_path: str) -> str:
    """
    清理和规范化路径，防止路径遍历
    
    Args:
        path: 要清理的路径
        base_path: 基础路径
        
    Returns:
        清理后的绝对路径
        
    Raises:
        SecurityError: 路径不安全
    """
    try:
        # 移除路径遍历字符
        if '..' in path or path.startswith('/'):
            raise SecurityError(f"不安全的路径: {path}")
        
        # 构建完整路径
        full_path = os.path.join(base_path, path)
        abs_path = os.path.abspath(full_path)
        
        # 确保路径在基础路径内
        if not abs_path.startswith(os.path.abspath(base_path)):
            raise SecurityError(f"路径超出基础目录: {path}")
        
        return abs_path
    except (OSError, ValueError) as e:
        raise SecurityError(f"路径清理失败: {e}")

