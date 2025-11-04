"""
辅助函数模块
"""
import os
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from .constants import SEVERITY_ORDER


def normalize_signature(sig: str) -> str:
    """
    规范化方法签名
    
    Args:
        sig: 方法签名，格式为 "ClassName:methodName"
        
    Returns:
        规范化后的签名
    """
    try:
        if ':' not in sig:
            return sig
        cls, mtd = sig.split(':', 1)
        # 简化类名（取最后一部分）
        cls_short = cls.split('.')[-1]
        return f"{cls_short}:{mtd}"
    except Exception:
        return sig


def parse_method_signature(sig: str) -> Tuple[str, str]:
    """
    解析方法签名
    
    Args:
        sig: 方法签名，格式为 "ClassName:methodName"
        
    Returns:
        (类名, 方法名) 元组
    """
    try:
        if ':' in sig:
            cls, mtd = sig.split(':', 1)
            return cls.strip(), mtd.strip()
        return sig, ''
    except Exception:
        return sig, ''


def match_rule_signature(sig: str, rule_sig: str) -> bool:
    """
    匹配规则签名
    
    Args:
        sig: 目标签名
        rule_sig: 规则签名（可能包含多个方法，用|分隔）
        
    Returns:
        True if matches
    """
    try:
        sig_cls, sig_mtd = parse_method_signature(sig)
        rule_cls, rule_mtds = parse_method_signature(rule_sig)
        
        # 类名匹配（简化名）
        sig_cls_short = sig_cls.split('.')[-1]
        rule_cls_short = rule_cls.split('.')[-1]
        
        if sig_cls_short != rule_cls_short:
            return False
        
        # 方法名匹配（支持多个方法，用|分隔）
        if '|' in rule_mtds:
            methods = [m.strip() for m in rule_mtds.split('|')]
            return sig_mtd in methods
        else:
            return sig_mtd == rule_mtds
        
    except Exception:
        return False


def sort_by_severity(items: List[Dict[str, Any]], severity_key: str = 'severity') -> List[Dict[str, Any]]:
    """
    按严重性排序
    
    Args:
        items: 项目列表
        severity_key: 严重性字段名
        
    Returns:
        排序后的列表
    """
    def get_severity_order(item: Dict[str, Any]) -> int:
        severity = item.get(severity_key, 'Low')
        return SEVERITY_ORDER.get(severity, 999)
    
    return sorted(items, key=get_severity_order)


def deduplicate_vulnerabilities(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    去重漏洞列表
    
    Args:
        vulns: 漏洞列表
        
    Returns:
        去重后的列表
    """
    seen = set()
    result = []
    
    for vuln in vulns:
        # 生成唯一标识
        key_parts = [
            vuln.get('sink', ''),
            vuln.get('file_path', ''),
            str(vuln.get('line_no', '')),
            vuln.get('vul_type', '')
        ]
        key = '|'.join(key_parts)
        
        if key not in seen:
            seen.add(key)
            result.append(vuln)
    
    return result


def extract_file_extension(file_path: str) -> str:
    """
    提取文件扩展名（不含点）
    
    Args:
        file_path: 文件路径
        
    Returns:
        扩展名（小写，不含点）
    """
    try:
        _, ext = os.path.splitext(file_path)
        return ext.lstrip('.').lower()
    except Exception:
        return ''


def format_confidence(confidence: float) -> str:
    """
    格式化置信度
    
    Args:
        confidence: 置信度值（0.0-1.0）
        
    Returns:
        格式化后的字符串（百分比）
    """
    return f"{int(confidence * 100)}%"


def escape_regex_pattern(pattern: str) -> str:
    """
    转义正则表达式特殊字符
    
    Args:
        pattern: 原始模式
        
    Returns:
        转义后的模式
    """
    return re.escape(pattern)


def combine_patterns(patterns: List[str], operator: str = '|') -> str:
    """
    组合多个正则模式
    
    Args:
        patterns: 模式列表
        operator: 组合操作符（| 或 &）
        
    Returns:
        组合后的模式
    """
    if operator == '|':
        return '|'.join(f'({p})' for p in patterns)
    elif operator == '&':
        return '(?=.*' + ')(?=.*'.join(patterns) + ')'
    else:
        return '|'.join(patterns)

