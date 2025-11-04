"""
污点追踪增强模块
提供更精确的数据流分析
"""
import re
from typing import Dict, List, Set, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class TaintTracker:
    """
    污点追踪器
    跟踪变量从源点到sink点的传播路径
    """
    
    def __init__(self):
        self.tainted_vars: Dict[str, Set[str]] = {}  # method -> set of tainted variables
        self.var_sources: Dict[str, str] = {}  # var -> source type
    
    def mark_tainted(self, method: str, var_name: str, source_type: str = 'UNKNOWN'):
        """
        标记变量为污点
        
        Args:
            method: 方法签名
            var_name: 变量名
            source_type: 源类型
        """
        if method not in self.tainted_vars:
            self.tainted_vars[method] = set()
        self.tainted_vars[method].add(var_name)
        self.var_sources[f"{method}:{var_name}"] = source_type
    
    def is_tainted(self, method: str, var_name: str) -> bool:
        """
        检查变量是否为污点
        
        Args:
            method: 方法签名
            var_name: 变量名
            
        Returns:
            True if tainted
        """
        return method in self.tainted_vars and var_name in self.tainted_vars[method]
    
    def propagate_taint(self, source_method: str, target_method: str, 
                       source_var: str, target_var: str):
        """
        传播污点：从源方法/变量到目标方法/变量
        
        Args:
            source_method: 源方法签名
            target_method: 目标方法签名
            source_var: 源变量名
            target_var: 目标变量名
        """
        if self.is_tainted(source_method, source_var):
            source_type = self.var_sources.get(f"{source_method}:{source_var}", 'UNKNOWN')
            self.mark_tainted(target_method, target_var, source_type)
    
    def trace_parameter_pass(self, caller_method: str, callee_method: str,
                            param_mapping: Dict[int, str]):
        """
        追踪参数传递
        
        Args:
            caller_method: 调用者方法
            callee_method: 被调用方法
            param_mapping: 参数映射 {param_index: var_name}
        """
        # 检查调用者的污点变量是否传递给被调用者
        caller_tainted = self.tainted_vars.get(caller_method, set())
        for param_idx, var_name in param_mapping.items():
            if var_name in caller_tainted:
                # 标记被调用者的参数为污点
                callee_param_name = f"param{param_idx}"
                source_type = self.var_sources.get(f"{caller_method}:{var_name}", 'UNKNOWN')
                self.mark_tainted(callee_method, callee_param_name, source_type)


def extract_variable_assignments(code: str) -> List[Tuple[str, str]]:
    """
    提取变量赋值语句
    
    Args:
        code: 代码字符串
        
    Returns:
        (变量名, 赋值表达式) 元组列表
    """
    assignments = []
    
    # 匹配常见的赋值模式
    patterns = [
        r'(\w+)\s*=\s*([^;]+);',  # var = expr;
        r'(\w+)\s*\+=\s*([^;]+);',  # var += expr;
        r'(\w+)\s*-=\s*([^;]+);',  # var -= expr;
        r'(\w+)\s*\?=\s*([^;]+);',  # var ?= expr;
    ]
    
    for pattern in patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            var_name = match.group(1)
            expr = match.group(2).strip()
            assignments.append((var_name, expr))
    
    return assignments


def extract_method_calls(code: str) -> List[Tuple[str, List[str]]]:
    """
    提取方法调用
    
    Args:
        code: 代码字符串
        
    Returns:
        (方法名, 参数列表) 元组列表
    """
    calls = []
    
    # 匹配方法调用模式
    pattern = r'(\w+(?:\.\w+)*)\s*\(\s*([^)]*)\s*\)'
    matches = re.finditer(pattern, code)
    
    for match in matches:
        method_name = match.group(1)
        params_str = match.group(2)
        
        # 简单分割参数（不考虑嵌套括号）
        params = [p.strip() for p in params_str.split(',') if p.strip()]
        calls.append((method_name, params))
    
    return calls


def identify_source_variables(code: str) -> List[str]:
    """
    识别源变量（用户输入）
    
    Args:
        code: 代码字符串
        
    Returns:
        源变量名列表
    """
    source_vars = []
    source_patterns = [
        r'(\w+)\s*=\s*request\.getParameter',
        r'(\w+)\s*=\s*request\.get',
        r'(\w+)\s*=\s*request\.getInputStream',
        r'(\w+)\s*=\s*request\.getReader',
        r'(\w+)\s*=\s*request\.getAttribute',
        r'(\w+)\s*=\s*session\.getAttribute',
        r'(\w+)\s*=\s*response\.getHeader',
        r'@RequestParam\s+(\w+)',
        r'@PathVariable\s+(\w+)',
        r'@RequestBody\s+(\w+)',
    ]
    
    for pattern in source_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            var_name = match.group(1)
            if var_name not in source_vars:
                source_vars.append(var_name)
    
    return source_vars


def identify_sink_variables(code: str, sink_patterns: List[str]) -> List[Tuple[str, str]]:
    """
    识别Sink变量（危险操作）
    
    Args:
        code: 代码字符串
        sink_patterns: Sink模式列表
        
    Returns:
        (变量名, sink类型) 元组列表
    """
    sinks = []
    
    for pattern in sink_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            var_name = match.group(1) if match.lastindex else 'unknown'
            sink_type = pattern.split(':')[0] if ':' in pattern else 'UNKNOWN'
            sinks.append((var_name, sink_type))
    
    return sinks

