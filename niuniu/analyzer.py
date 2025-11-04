import os
import json
import re
import logging
from collections import deque
from typing import Dict, List, Union, Tuple, Optional, Set, Any
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

import javalang

# 配置日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 导入核心模块
try:
    from core.constants import (
        MAX_FILE_SIZE, MAX_FILE_LINES, MAX_WORKERS, CACHE_TTL,
        DEFAULT_DEPTH, DEFAULT_MAX_SECONDS, JAVA_EXTENSIONS,
        SKIP_AST_EXTENSIONS, SEVERITY_ORDER
    )
    from core.exceptions import (
        AnalyzerError, RulesLoadError, ASTParseError, FileProcessingError,
        ValidationError, ResourceLimitError
    )
    from core.validators import (
        validate_project_path, validate_rules_path, validate_file_size,
        validate_file_lines, should_skip_file
    )
except ImportError:
    # 向后兼容：如果核心模块不存在，使用默认值
    logger.warning("核心模块未找到，使用默认配置")
    MAX_FILE_SIZE = 50 * 1024 * 1024
    MAX_FILE_LINES = 200000
    MAX_WORKERS = min(4, os.cpu_count() or 1)
    CACHE_TTL = 300
    DEFAULT_DEPTH = 15
    DEFAULT_MAX_SECONDS = 600
    JAVA_EXTENSIONS = {'.java'}
    SKIP_AST_EXTENSIONS = {'.ftl', '.vm'}
    SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    
    # 简化异常类
    class AnalyzerError(Exception):
        pass
    class RulesLoadError(AnalyzerError):
        pass
    class ASTParseError(AnalyzerError):
        pass
    class FileProcessingError(AnalyzerError):
        pass
    class ValidationError(AnalyzerError):
        pass
    class ResourceLimitError(AnalyzerError):
        pass
    
    # 简化验证函数
    def validate_project_path(path: str) -> str:
        if not os.path.isdir(path):
            raise ValueError(f"项目路径不存在或不是目录: {path}")
        return os.path.abspath(path)
    
    def validate_rules_path(path: str) -> str:
        if not os.path.isfile(path):
            raise ValueError(f"规则文件不存在: {path}")
        return os.path.abspath(path)
    
    def should_skip_file(file_path: str, project_path: str) -> bool:
        return False

# 导入工具模块
try:
    from utils.performance import cache_manager, performance_monitor
    from utils.security import resource_limiter
except ImportError:
    # 向后兼容：如果工具模块不存在，使用简化版本
    logger.warning("工具模块未找到，使用简化版本")
    cache_manager = None
    performance_monitor = None
    resource_limiter = None

class Analyzer:
    """
    代码分析器主类
    
    负责构建AST、分析调用链、检测漏洞
    """
    
    def __init__(self, project_path: str, rules_path: str, on_partial=None, should_stop=None):
        """
        初始化分析器
        
        Args:
            project_path: 项目路径
            rules_path: 规则文件路径
            on_partial: 部分结果回调函数
            should_stop: 停止检查函数
            
        Raises:
            ValidationError: 输入验证失败
            RulesLoadError: 规则加载失败
        """
        # 输入验证
        try:
            self.project_path = validate_project_path(project_path)
            self.rules_path = validate_rules_path(rules_path)
        except Exception as e:
            raise ValidationError(f"初始化失败: {e}") from e
        
        # 加载规则
        try:
            self.rules = self._load_rules(self.rules_path)
        except Exception as e:
            raise RulesLoadError(f"规则加载失败: {e}") from e
        
        # 数据存储
        self.call_graph: Dict[str, List[str]] = {}
        self.reverse_call_graph: Dict[str, List[str]] = {}
        self.class_methods: Dict[str, Dict[str, Union[str, Dict[str, Dict[str, bool]]]]] = {}
        self.class_to_file_map: Dict[str, str] = {}
        
        # 回调函数
        self.on_partial = on_partial
        self.partial_results: List[dict] = []
        self.should_stop = (should_stop if callable(should_stop) else (lambda: False))
        
        # 性能优化：添加缓存
        self._file_cache: Dict[str, Tuple[Optional[javalang.tree.CompilationUnit], float]] = {}
        self._cache_ttl = CACHE_TTL
        
        # 文件大小限制
        self.max_file_size = MAX_FILE_SIZE
        self.max_file_lines = MAX_FILE_LINES
        
        # 并发控制
        self._parse_lock = threading.Lock()
        self._max_workers = MAX_WORKERS
        
        # 统计信息
        self._stats_start_ts = None
        self._parsed_files = 0
        self._total_files = 0

    @staticmethod
    def _load_rules(path: str) -> dict:
        """
        加载规则文件
        
        Args:
            path: 规则文件路径
            
        Returns:
            规则字典
            
        Raises:
            RulesLoadError: 规则加载失败
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            if not isinstance(rules, dict):
                raise RulesLoadError("规则文件格式错误：应为JSON对象")
            
            # 验证必需字段
            required_keys = ['sink_rules']
            missing_keys = [key for key in required_keys if key not in rules]
            if missing_keys:
                logger.warning(f"规则文件缺少字段: {missing_keys}")
            
            logger.info(f"成功加载规则文件: {path}")
            return rules
            
        except json.JSONDecodeError as e:
            raise RulesLoadError(f"规则文件JSON解析失败: {e}") from e
        except IOError as e:
            raise RulesLoadError(f"无法读取规则文件: {e}") from e
        except Exception as e:
            raise RulesLoadError(f"规则加载异常: {e}") from e

    def _should_skip_file(self, file_path: str) -> bool:
        """
        判断文件是否应该跳过
        
        Args:
            file_path: 文件路径
            
        Returns:
            True if should skip
        """
        try:
            # 使用核心验证模块
            return should_skip_file(file_path, self.project_path)
        except Exception as e:
            logger.warning(f"文件跳过检查异常: {file_path}, {e}", exc_info=True)
            return True

    def build_ast(self):
        """构建AST - 支持并发优化版本"""
        # 速率与进度统计（lite引擎）
        self._stats_start_ts = time.time()
        self._parsed_files = 0
        self._total_files = 0
        
        # 收集所有Java相关文件（.java用于AST构建，.jsp/.jspx/.class用于模板扫描）
        java_files = []
        for root, _, files in os.walk(self.project_path):
            if self.should_stop():
                break
            for file in files:
                if self.should_stop():
                    break
                # 只处理.java文件进行AST构建（其他文件类型在模板扫描中处理）
                if not file.endswith('.java'):
                    continue
                file_path = os.path.join(root, file)
                if not self._should_skip_file(file_path):
                    java_files.append(file_path)
        
        self._total_files = len(java_files)
        
        # 并发解析文件（限制并发数）
        def parse_single_file(file_path: str) -> Optional[Tuple]:
            """解析单个文件"""
            if self.should_stop():
                return None
            
            try:
                self.current_file = os.path.relpath(file_path, self.project_path)
            except Exception as e:
                logger.debug(f"路径相对化失败: {file_path}, {e}")
                self.current_file = file_path
            
            try:
                tree = self._parse_file_with_cache(file_path)
                if tree is None:
                    return None
                
                # 线程安全地更新数据结构
                with self._parse_lock:
                    self._extract_class_info(tree, file_path)
                    self._build_call_graph(tree)
                    self._parsed_files += 1
                
                return (file_path, tree)
            except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
                logger.debug(f"解析错误: {file_path}, {e}")
                return None
            except Exception as e:
                logger.warning(f"文件解析异常: {file_path}, {e}", exc_info=True)
                return None
        
        # 使用线程池并发解析
        if len(java_files) > 10:  # 文件多时才使用并发
            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                futures = {executor.submit(parse_single_file, fp): fp for fp in java_files}
                
                for future in as_completed(futures):
                    if self.should_stop():
                        break
                    
                    result = future.result()
                    # 心跳：每解析若干文件就触发一次进度写入
                    if self.on_partial and (self._parsed_files % 10 == 0):
                        elapsed = time.time() - self._stats_start_ts
                        self._rate_per_min = round(((self._parsed_files / elapsed) * 60.0) if elapsed > 0 else 0.0, 2)
                        try:
                            self.on_partial(self.partial_results)
                        except Exception as e:
                            logger.warning(f"心跳回调异常: {e}")
        else:
            # 文件少时串行处理（避免线程开销）
            for file_path in java_files:
                if self.should_stop():
                    break
                parse_single_file(file_path)
                if self.on_partial and (self._parsed_files % 10 == 0):
                    elapsed = time.time() - self._stats_start_ts
                    self._rate_per_min = round(((self._parsed_files / elapsed) * 60.0) if elapsed > 0 else 0.0, 2)
                    try:
                        self.on_partial(self.partial_results)
                    except Exception as e:
                        logger.warning(f"心跳回调异常: {e}")
        
        # 扫描完毕也更新一次速率
        elapsed = time.time() - self._stats_start_ts
        self._rate_per_min = round(((self._parsed_files / elapsed) * 60.0) if elapsed > 0 else 0.0, 2)
        self._build_reverse_call_graph()
    
    def _parse_file_with_cache(self, file_path: str) -> Optional[javalang.tree.CompilationUnit]:
        """解析文件，使用缓存优化性能"""
        current_time = time.time()
        
        # 检查缓存
        if file_path in self._file_cache:
            cached_tree, cache_time = self._file_cache[file_path]
            if current_time - cache_time < self._cache_ttl:
                return cached_tree
        
        try:
            # 读取文件（限制大小）
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # 先检查行数
                lines = f.readlines()
                if len(lines) > self.max_file_lines:
                    logger.debug(f"文件行数过多，跳过: {file_path} ({len(lines)} lines)")
                    return None
                code = ''.join(lines)
            
            # 解析AST
            tree = javalang.parse.parse(code)
            
            # 更新缓存
            self._file_cache[file_path] = (tree, current_time)
            
            # 清理过期缓存（每100个文件清理一次）
            if len(self._file_cache) > 1000:
                expired = [k for k, (_, t) in self._file_cache.items() if current_time - t > self._cache_ttl]
                for k in expired[:100]:  # 一次清理100个
                    del self._file_cache[k]
            
            return tree
        except Exception as e:
            logger.debug(f"文件解析失败: {file_path}, {e}")
            return None

    def _extract_class_info(self, code_tree, file_path: str):
        MAPPING_ANNOTATIONS = {
            'GetMapping', 'PostMapping', 'RequestMapping', 'PutMapping', 'DeleteMapping',
            'Path', 'GET', 'POST', 'PUT', 'DELETE'
        }
        for path, node in code_tree.filter(javalang.tree.ClassDeclaration):
            class_name = node.name
            self.class_to_file_map[class_name] = file_path
            methods_info = {}
            for method_node in node.methods:
                method_name = method_node.name
                requires_params = len(method_node.parameters) > 0
                has_mapping_annotation = False
                if method_node.annotations:
                    for annotation in method_node.annotations:
                        name = annotation.name.lstrip('@')
                        if name in MAPPING_ANNOTATIONS:
                            has_mapping_annotation = True
                            break
                methods_info[method_name] = {
                    'requires_params': requires_params,
                    'has_mapping_annotation': has_mapping_annotation
                }
            self.class_methods[class_name] = {
                'file_path': file_path,
                'methods': methods_info
            }

    def _build_call_graph(self, file_code_tree):
        variable_symbols = self.get_variable_symbols(file_code_tree)
        for path, node in file_code_tree.filter(javalang.tree.MethodInvocation):
            caller = self._get_current_method_from_path(path)
            callee = '[!]callee解析失败'
            if node.qualifier:
                default = node.qualifier.split('.')[0] if '.' in node.qualifier and node.qualifier.split('.')[0][0].isupper() else node.qualifier
                base_type = variable_symbols.get(node.qualifier, default)
                base_type = base_type.split('<')[0]
                callee = f"{base_type}:{node.member}"
            else:
                base_type = '[!]base_type解析失败'
                try:
                    parent_node = path[-2] if len(path) > 1 else None
                    if isinstance(parent_node, javalang.tree.ClassCreator):
                        base_type = parent_node.type.name
                    elif isinstance(parent_node, javalang.tree.ClassReference):
                        base_type = parent_node.type.name
                    else:
                        if caller in self.call_graph and self.call_graph[caller]:
                            base_type = self.call_graph[caller][-1].split(':')[0]
                except Exception as e:
                    logger.debug(f"类型解析失败: {e}")
                    pass
                callee = f"{base_type}:{node.member}"
            self.call_graph.setdefault(caller, []).append(callee)

    @staticmethod
    def get_variable_symbols(file_code_tree):
        variable_symbols = {}
        for path, node in file_code_tree:
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.FieldDeclaration):
                var_type = node.type.name
                for declarator in node.declarators:
                    variable_symbols[declarator.name] = var_type
            elif isinstance(node, javalang.tree.MethodDeclaration):
                for param in node.parameters:
                    variable_symbols[param.name] = param.type.name
        return variable_symbols

    def _get_current_method_from_path(self, path) -> str:
        for node in reversed(path):
            if isinstance(node, javalang.tree.MethodDeclaration):
                class_node = self.find_parent_class(path)
                cls_name = class_node.name if (class_node and hasattr(class_node, 'name')) else 'unknown'
                mtd_name = node.name if hasattr(node, 'name') else 'unknown'
                return f"{cls_name}:{mtd_name}"
        return 'unknown:unknown'

    @staticmethod
    def find_parent_class(path):
        for node in reversed(path):
            if isinstance(node, (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration, javalang.tree.EnumDeclaration)):
                return node
        return None

    def _build_reverse_call_graph(self):
        self.reverse_call_graph.clear()
        for caller, callees in self.call_graph.items():
            for callee in callees:
                if callee not in self.reverse_call_graph:
                    self.reverse_call_graph[callee] = []
                self.reverse_call_graph[callee].append(caller)
        for callee in self.reverse_call_graph:
            self.reverse_call_graph[callee] = list(set(self.reverse_call_graph[callee]))

    def _trace_back(self, sink: str, max_depth: int) -> List[List[str]]:
        """
        调用链回溯 - 深度优先，确保不漏检
        移除超时限制，提升回溯深度
        """
        paths = []
        visited_states = set()
        queue = deque([([sink], 0, {sink}, time.time())])
        # 为了准确性，大幅提升超时时间（从60秒提升到600秒）
        max_seconds = int(self.rules.get('max_seconds', 600))  # 10分钟超时
        # 默认深度从5提升到15，确保深度回溯
        effective_max_depth = max(max_depth, 15) if max_depth < 10 else max_depth
        
        while queue:
            if self.should_stop():
                break
            current_path, current_depth, path_nodes, start_ts = queue.popleft()
            # 移除超时限制（为了准确性）
            # if (time.time() - start_ts) > max_seconds:
            #     continue
            if current_depth >= effective_max_depth:
                continue
            current_sink = current_path[0]
            caller_methods = self.reverse_call_graph.get(current_sink, [])
            if not caller_methods:
                continue
            for caller in caller_methods:
                if caller in path_nodes:
                    continue
                state_key = (caller, current_depth + 1)
                if state_key in visited_states:
                    continue
                visited_states.add(state_key)
                cls, mtd = caller.split(':', 1)
                if not self.is_has_parameters(cls, mtd):
                    continue
                new_path = [caller] + current_path
                new_nodes = path_nodes | {caller}
                if self.is_entry_point(caller):
                    paths.append(new_path)
                else:
                    queue.append((new_path, current_depth + 1, new_nodes, start_ts))
        return paths

    def is_has_parameters(self, class_name: str, method_name: str) -> bool:
        info = self.class_methods.get(class_name, {})
        return info.get('methods', {}).get(method_name, {}).get('requires_params', True)

    def is_entry_point(self, method: str) -> bool:
        class_name, method_name = method.split(':')
        info = self.class_methods.get(class_name, {})
        return info.get('methods', {}).get(method_name, {}).get('has_mapping_annotation', False)

    def _rule_matches(self, sig: str, rules: List[dict], key: str = 'sinks') -> List[str]:
        """
        匹配规则签名
        
        Args:
            sig: 方法签名，格式为 "ClassName:methodName"
            rules: 规则列表
            key: 规则键名（'sinks', 'sources', 'sanitizers'）
            
        Returns:
            匹配的规则名称列表
        """
        hits = []
        if not sig or ':' not in sig:
            return hits
        
        try:
            cls, mtd = sig.split(':', 1)
            cls = cls.strip()
            mtd = mtd.strip()
            
            if not cls or not mtd:
                return hits
            
            for r in rules:
                if not isinstance(r, dict):
                    continue
                
                rule_items = r.get(key, [])
                if not rule_items:
                    continue
                
                for s in rule_items:
                    if not isinstance(s, str) or ':' not in s:
                        continue
                    
                    try:
                        sc, sm = s.split(':', 1)
                        sc = sc.strip()
                        sm = sm.strip()
                        
                        # 类名匹配（支持完整类名和短类名）
                        cls_short = cls.split('.')[-1]
                        sc_short = sc.split('.')[-1]
                        
                        # 方法名匹配（支持多个方法，用|分隔）
                        methods = [m.strip() for m in sm.split('|')]
                        
                        if (cls == sc or cls_short == sc_short) and mtd in methods:
                            hit_name = (r.get('sanitizer_name') or 
                                       r.get('source_name') or 
                                       r.get('sink_name') or 
                                       s)
                            if hit_name and hit_name not in hits:
                                hits.append(hit_name)
                    except (ValueError, AttributeError) as e:
                        logger.debug(f"规则项解析失败: {s}, {e}")
                        continue
                        
        except Exception as e:
            logger.debug(f"规则匹配异常: {sig}, {e}", exc_info=True)
        
        return hits

    def _is_sanitized(self, chain: List[str]) -> List[str]:
        """
        检查调用链中是否包含净化器
        
        Args:
            chain: 调用链列表
            
        Returns:
            找到的净化器名称列表
        """
        sanitizers = self.rules.get('sanitizer_rules', [])
        if not sanitizers or not isinstance(sanitizers, list):
            return []
        
        found = []
        # 确定键名
        if sanitizers and len(sanitizers) > 0 and isinstance(sanitizers[0], dict):
            key = 'sanitizers' if 'sanitizers' in sanitizers[0] else 'sinks'
        else:
            key = 'sinks'
        
        for sig in chain:
            if not sig:
                continue
            found.extend(self._rule_matches(sig, sanitizers, key=key))
        
        return list(set(found))

    def _find_sources(self, chain: List[str]) -> List[str]:
        """
        查找调用链中的源点
        
        Args:
            chain: 调用链列表
            
        Returns:
            找到的源点名称列表
        """
        sources = self.rules.get('source_rules', [])
        if not sources or not isinstance(sources, list):
            return []
        
        found = []
        # 确定键名
        if sources and len(sources) > 0 and isinstance(sources[0], dict):
            key = 'sources' if 'sources' in sources[0] else 'sinks'
        else:
            key = 'sinks'
        
        for sig in chain:
            if not sig:
                continue
            found.extend(self._rule_matches(sig, sources, key=key))
        
        return list(set(found))

    def _get_pattern_hits(self, chain: List[str]) -> List[str]:
        hits = []
        patterns = self.rules.get('pattern_rules', {}) or {}
        # 通用：遍历所有 pattern_rules，将类名简化为短名后与链路签名匹配
        for pname, sig_list in patterns.items():
            try:
                sigs = {
                    s.split(':', 1)[0].split('.')[-1] + ':' + s.split(':', 1)[1]
                    for s in sig_list
                }
            except Exception as e:
                logger.debug(f"模式规则解析失败: {e}")
                sigs = set()
            for sig in chain:
                if sig in sigs:
                    hits.append(pname)
        # 额外：SQL 字符串拼接的文本启发式命中（+、append、format 等）
        if self._detect_sql_concat_text(chain):
            hits.append('SQL_CONCAT_TEXT')
        return list(set(hits))

    def _detect_sql_concat_text(self, chain: List[str]) -> bool:
        import re
        patterns = [
            re.compile(r"\bStringBuilder\b.*append\s*\(", re.I | re.S),
            re.compile(r"\bStringBuffer\b.*append\s*\(", re.I | re.S),
            re.compile(r"sql\s*[+]=\s*", re.I),
            re.compile(r"\+\s*\w*\s*;"),
            re.compile(r"String\.format\s*\(")
        ]
        # 仅扫描链中的少量节点，避免过重：最多前 3 个节点源码
        for sig in chain[:3]:
            try:
                cls, mtd = sig.split(':', 1)
                file_path, code = self.extract_method_definition(cls, mtd)
                if not code:
                    continue
                snippet = code if len(code) < 8000 else code[:8000]
                if any(p.search(snippet) for p in patterns):
                    return True
            except Exception as e:
                logger.debug(f"SQL拼接检测异常: {e}")
                continue
        return False

    def _score_chain(self, chain: List[str], sink_name: str = '') -> float:
        """
        计算调用链的置信度分数
        
        Args:
            chain: 调用链列表
            sink_name: Sink点名称
            
        Returns:
            置信度分数 (0.0-1.0)
        """
        if not chain:
            return 0.0
        
        score = 1.0
        sink_name_upper = (sink_name or '').upper()
        
        # 净化器降低置信度
        sanitizers = self._is_sanitized(chain)
        if sanitizers:
            # 多个净化器或多个位置的净化，降低更多
            sanitizer_count = len(sanitizers)
            if sanitizer_count >= 2:
                score -= 0.5  # 多个净化器，大幅降低
            else:
                score -= 0.4  # 单个净化器
        
        # 源点提高置信度
        sources = self._find_sources(chain)
        if sources:
            source_count = len(sources)
            if source_count >= 2:
                score += 0.4  # 多个源点，提高更多
            else:
                score += 0.3  # 单个源点
        
        # 规则化模式命中提升：如 JDBC 字符串拼接构造 SQL
        pattern_hits = self._get_pattern_hits(chain)
        if sink_name_upper == 'SQLI' and ('SQL_CONCAT' in pattern_hits or 'SQL_CONCAT_TEXT' in pattern_hits):
            score += 0.3
        
        # 增强：检查链长（过长可能降低置信度，过短可能提高）
        chain_length = len(chain)
        if chain_length > 20:
            score -= 0.1  # 链过长，可能包含不相关代码
        elif chain_length < 3:
            score += 0.1  # 链短且直接，更可能是真实漏洞
        
        return max(0.0, min(1.0, score))

    def _is_false_positive(self, line: str, lines: List[str], line_no: int, context_window: int, rule: dict) -> bool:
        """
        误报检测：识别注释、字符串字面量、测试代码等
        """
        import re
        
        line_stripped = line.strip()
        line_lower = line.lower()
        
        # 1. 检查是否在注释中（单行注释、多行注释）
        if line_stripped.startswith('//') or line_stripped.startswith('#'):
            return True
        
        # 检查多行注释上下文
        if context_window > 0:
            context_start = max(0, line_no - context_window - 1)
            context_end = min(len(lines), line_no + context_window)
            context = ''.join(lines[context_start:context_end])
            
            # HTML注释
            line_pos = context.find(line)
            if line_pos >= 0:
                before_line = context[:line_pos]
                if '<!--' in before_line and '-->' not in before_line:
                    return True
                
                # 多行注释开始
                comment_start = context.rfind('/*', 0, line_pos)
                comment_end = context.find('*/', line_pos)
                if comment_start != -1 and (comment_end == -1 or comment_end > line_pos):
                    return True
        
        # 2. 检查是否在字符串字面量中（简单的启发式）
        # 如果行被引号包裹，可能是字面量
        if (line.count('"') % 2 == 0 and line.count("'") % 2 == 0 and 
            line_stripped.startswith('"') and line_stripped.endswith('"')):
            # 但排除模板表达式
            if not ('${' in line or '<%=' in line or '$!' in line):
                return True
        
        # 3. 测试代码标记
        test_indicators = ['test', 'mock', 'stub', 'fake', 'dummy', 'example']
        if any(indicator in line_lower for indicator in test_indicators):
            # 检查文件路径
            if 'test' in rule.get('file_path', '').lower():
                return True
        
        # 4. 配置文件中常见的安全字符串
        safe_patterns = [
            r'password\s*=\s*["\']?\*+["\']?',  # password=***
            r'secret\s*=\s*["\']?\*+["\']?',     # secret=***
            r'key\s*=\s*["\']?\*+["\']?',        # key=***
        ]
        for pattern in safe_patterns:
            if re.search(pattern, line, re.I):
                return True
        
        return False

    def _analyze_context(self, lines: List[str], line_no: int, context_window: int, rule: dict) -> float:
        """
        上下文分析：根据前后文判断漏洞可能性（增强版）
        返回置信度分数 0.0-1.0
        """
        if context_window <= 0 or line_no < 1 or line_no > len(lines):
            return 0.5
        
        context_start = max(0, line_no - context_window - 1)
        context_end = min(len(lines), line_no + context_window)
        context_lines = lines[context_start:context_end]
        current_line = lines[line_no - 1]
        
        score = 0.5  # 基础分数
        context_text = ' '.join(context_lines).lower()
        line_lower = current_line.lower()
        
        vul_type = (rule.get('vul_type') or '').upper()
        rule_name = (rule.get('name') or '').upper()
        
        # 增强：检查是否为JSP/JSPX特定上下文
        is_jsp_context = any('jsp' in line.lower() or 'jspx' in line.lower() for line in context_lines[:5])
        if is_jsp_context and ('XSS' in vul_type or 'INJECTION' in vul_type):
            score += 0.1  # JSP上下文中的注入风险更高
        
        # 1. SQL注入上下文增强
        if 'SQLI' in vul_type or 'SQL' in rule_name:
            sql_indicators = ['select', 'from', 'where', 'insert', 'update', 'delete', 'executequery', 'preparedstatement']
            if any(ind in context_text for ind in sql_indicators):
                score += 0.2
            if 'request.getparameter' in context_text or 'request.get' in context_text:
                score += 0.2
            if 'stringbuilder' in context_text or 'stringbuffer' in context_text:
                score += 0.1
        
        # 2. XSS上下文增强
        if 'XSS' in vul_type:
            xss_indicators = ['out.print', 'response.getwriter', 'document.write', 'innerhtml']
            if any(ind in context_text for ind in xss_indicators):
                score += 0.2
            if 'request.getparameter' in context_text:
                score += 0.2
            # 检查是否有编码
            if any(enc in context_text for enc in ['escapehtml', 'encode', 'sanitize', 'escape']):
                score -= 0.3
        
        # 3. 路径遍历上下文增强
        if 'PATH_TRAVERSAL' in vul_type or 'FILE' in rule_name:
            path_indicators = ['../', '..\\', 'getrealpath', 'file', 'filestream']
            if any(ind in context_text for ind in path_indicators):
                score += 0.2
            if 'request.getparameter' in context_text:
                score += 0.2
            # 检查是否有规范化
            if any(norm in context_text for norm in ['canonical', 'normalize', 'getcanonical']):
                score -= 0.3
        
        # 4. RCE上下文增强
        if 'RCE' in vul_type:
            rce_indicators = ['runtime.exec', 'processbuilder', 'command', 'exec']
            if any(ind in context_text for ind in rce_indicators):
                score += 0.3
            if 'request.getparameter' in context_text:
                score += 0.2
        
        # 5. 反序列化上下文增强
        if 'UNSERIALIZE' in vul_type or 'DESERIALIZE' in rule_name:
            deser_indicators = ['readobject', 'objectinputstream', 'json.parse', 'fastjson']
            if any(ind in context_text for ind in deser_indicators):
                score += 0.2
            if 'request.getinputstream' in context_text or 'request.getreader' in context_text:
                score += 0.2
        
        # 6. JSP/EL注入上下文增强
        if 'EL_INJECTION' in vul_type or 'JSP' in rule_name:
            el_indicators = ['${', '<%=', 'param.', 'requestscope', 'sessionScope']
            if any(ind in context_text for ind in el_indicators):
                score += 0.15
            if 'out.print' in context_text or 'response.getwriter' in context_text:
                score += 0.1
        
        # 7. 用户输入来源检查（增强版）
        input_sources = ['request.getparameter', 'request.get', 'request.getinputstream', 
                        'request.getreader', 'request.getattribute', 'session.getattribute',
                        'param.', 'header.', 'cookie.']
        input_count = sum(1 for src in input_sources if src in context_text)
        if input_count >= 2:
            score += 0.15  # 多个输入源，风险更高
        elif input_count >= 1:
            score += 0.1
        
        # 8. 净化/编码检查（降低分数，但更精确）- 增强版
        sanitizer_keywords = ['escapehtml', 'htmlutils', 'stringescapeutils', 
                             'owasp.encoder', 'sanitize', 'filter', 'encode', 'encodeurl',
                             'encodeuri', 'escapexml', 'escapejavascript', 'escapejava',
                             'preparedstatement', 'parameterized', 'setstring', 'setint',
                             'setparameter', 'escapelike', 'quote', 'canonicalize']
        sanitizer_count = sum(1 for kw in sanitizer_keywords if kw in context_text)
        
        # 检查是否在Sink前有净化
        if sanitizer_count >= 2:
            score -= 0.4  # 多处净化，大幅降低风险
        elif sanitizer_count >= 1:
            # 检查净化是否在危险操作之前
            sanitizer_positions = [i for i, line in enumerate(context_lines) 
                                 if any(kw in line.lower() for kw in sanitizer_keywords)]
            current_pos = line_no - context_start - 1
            if sanitizer_positions and min(sanitizer_positions) < current_pos:
                score -= 0.3  # 净化在操作之前，大幅降低
            else:
                score -= 0.2  # 有净化但位置不确定
        
        # 9. 检查是否在异常处理或日志中（可能降低风险）
        if any(log in context_text for log in ['catch', 'exception', 'logger', 'log.', 'printstacktrace']):
            score -= 0.1
        
        # 10. JSP脚本片段检测（高风险）
        # 通过检查文件路径或内容判断是否为JSP文件
        if ('<%' in context_text and '%>' in context_text) or '<jsp:' in context_text.lower():
            if 'request.getparameter' in context_text:
                score += 0.1  # JSP脚本中的用户输入处理
        
        return max(0.0, min(1.0, score))

    def _calculate_confidence(self, line: str, lines: List[str], line_no: int, rule: dict, base_score: float) -> float:
        """
        智能评分：综合多个因素计算置信度（增强版）
        
        Args:
            line: 当前行代码
            lines: 所有代码行
            line_no: 行号（1-based）
            rule: 规则字典
            base_score: 基础分数
            
        Returns:
            置信度分数 (0.0-1.0)
        """
        if not line or not lines or line_no < 1 or line_no > len(lines):
            return base_score
        
        score = base_score
        line_lower = line.lower()
        vul_type = (rule.get('vul_type') or '').upper()
        
        # 增加：行号有效性检查
        if line_no > len(lines):
            logger.warning(f"行号超出范围: {line_no} > {len(lines)}")
            return base_score
        
        # 1. 关键字密度
        keywords_in_line = sum(1 for keyword in ['request', 'getparameter', 'getinputstream', 'response', 'execute'] 
                              if keyword in line_lower)
        if keywords_in_line >= 2:
            score += 0.1
        
        # 2. 代码复杂度（简单启发式）
        if line.count('(') > 3 or line.count('.') > 5:
            score += 0.05  # 复杂调用更可能是真实漏洞
        
        # 3. 字符串拼接模式
        if ('+' in line or 'concat' in line_lower or 'append' in line_lower) and 'SQL' in vul_type:
            score += 0.1
        
        # 4. 直接危险操作（增强版）
        dangerous_patterns = {
            'SQLI': ['executequery', 'executestatement', 'preparedstatement', 'createstatement', 
                    'executeupdate', 'executebatch', 'query', 'update', 'jdbctemplate', 'hibernate'],
            'XSS': ['print', 'println', 'write', 'innerhtml', 'getwriter', 'out.print', 
                   'response.getwriter', 'document.write', 'eval'],
            'RCE': ['exec', 'eval', 'runtime', 'processbuilder', 'getruntime', 'command'],
            'PATH_TRAVERSAL': ['../', '..\\', 'filestream', 'fileoutputstream', 'filewriter',
                             'fileinputstream', 'filereader', 'getrealpath', 'getcanonicalpath'],
            'XXE': ['documentbuilder', 'saxparser', 'dom4j', 'jdom', 'xpath', 'xmlreader'],
            'DESERIALIZE': ['readobject', 'objectinputstream', 'readresolve', 'readunsafe',
                          'fastjson', 'jackson', 'gson', 'xstream'],
        }
        
        for vtype, patterns in dangerous_patterns.items():
            if vtype in vul_type:
                pattern_count = sum(1 for pattern in patterns if pattern in line_lower)
                if pattern_count >= 2:
                    score += 0.25  # 多个危险模式，大幅提升
                elif pattern_count >= 1:
                    score += 0.15
        
        # 5. 上下文一致性（前后行相关，使用更大的窗口）- 增强版
        context_window = 7  # 扩大到7行
        if line_no >= context_window and line_no < len(lines) - context_window:
            context_start = max(0, line_no - context_window)
            context_end = min(len(lines), line_no + context_window + 1)
            context_block = lines[context_start:context_end]
            context_block_text = ' '.join(context_block).lower()
            
            # 如果上下文中有相关操作，提高分数
            input_keywords = ['request', 'parameter', 'input', 'getparameter', 'getinputstream', 
                            'getattribute', 'getheader', 'getcookie', 'requestparam', 'pathvariable',
                            'requestbody', 'queryparam', 'bodytomono', 'getquery', 'getpathinfo']
            output_keywords = ['response', 'output', 'print', 'write', 'send', 'setheader', 
                             'getwriter', 'sendredirect', 'forward', 'render', 'view', 'model']
            
            input_count = sum(1 for kw in input_keywords if kw in context_block_text)
            output_count = sum(1 for kw in output_keywords if kw in context_block_text)
            
            if input_count >= 2 and output_count >= 1:
                score += 0.3  # 多个输入源+输出，大幅提升
            elif input_count >= 1 and output_count >= 1:
                score += 0.2  # 同时有输入输出
            elif input_count >= 2:
                score += 0.15  # 多个输入源
            elif input_count >= 1 or output_count >= 1:
                score += 0.1
            
            # 6. 检查Spring框架特定模式
            spring_patterns = ['@requestmapping', '@getmapping', '@postmapping', '@putmapping',
                             '@deletemapping', '@requestparam', '@pathvariable', '@requestbody',
                             '@modelattribute', '@valid', '@responsebody', '@controller',
                             '@restcontroller', '@service', '@repository']
            spring_count = sum(1 for pattern in spring_patterns if pattern in context_block_text)
            if spring_count >= 2:
                score += 0.1  # Spring框架中的漏洞通常更严重
            elif spring_count >= 1:
                score += 0.05
        
        # 7. 增强：检查方法返回值和参数传递
        if 'return' in line_lower:
            # 如果返回的是用户输入，提高风险
            if any(src in line_lower for src in ['request', 'parameter', 'input', 'getparameter']):
                score += 0.1
        
        # 8. 增强：检查数组和集合操作
        collection_patterns = ['list', 'array', 'map', 'set', 'collection']
        if any(pattern in line_lower for pattern in collection_patterns):
            if 'getparameter' in line_lower or 'request' in line_lower:
                score += 0.05  # 集合中的用户输入
        
        # 9. 增强：检查类型转换
        cast_patterns = ['tostring', 'valueof', 'parse', 'convert']
        if any(pattern in line_lower for pattern in cast_patterns):
            if 'request' in line_lower or 'parameter' in line_lower:
                score += 0.05  # 类型转换中的用户输入
        
        return max(0.0, min(1.0, score))

    def _scan_template_files(self) -> List[dict]:
        """
        模板文件扫描 - 优化版本
        支持全量模式和轻量模式
        全量模式：上下文分析、智能评分、误报过滤
        轻量模式：快速扫描、基础匹配
        """
        import re
        findings = []
        template_rules = self.rules.get('template_rules', []) or []
        if not template_rules:
            return findings
        
        # 模式配置 - 为了准确性，移除上限限制
        is_lite_mode = bool(self.rules.get('__lite_fast__'))
        MAX_FINDINGS = 999999 if not is_lite_mode else 999999  # 移除上限，确保不漏检
        # 预编译：扩展名 -> [规则]，以及 规则 -> 已编译正则，避免重复编译带来的性能损耗
        # 使用缓存管理器优化正则编译缓存
        ext_map: Dict[str, List[Dict[str, Any]]] = {}
        compiled_cache: Dict[int, List[re.Pattern]] = {}
        bad_patterns: List[Tuple[str, str]] = []  # (rule_name, pattern)
        include_exts = set([e.lower().lstrip('.') for e in (self.rules.get('__include_exts__') or [])])
        
        for r in template_rules:
            rid = id(r)
            
            # 检查缓存
            cache_key_str = f"regex_{rid}"
            cached_patterns = None
            if cache_manager:
                cached_patterns = cache_manager.get(cache_key_str)
            
            if cached_patterns:
                compiled_list = cached_patterns
            else:
                compiled_list: List[re.Pattern] = []
                for pat in r.get('patterns', []) or []:
                    try:
                        # 安全检查：限制正则表达式复杂度
                        if resource_limiter:
                            is_safe, err_msg = resource_limiter.check_regex(pat)
                            if not is_safe:
                                logger.warning(f"正则表达式过于复杂，跳过: {pat[:50]}...")
                                bad_patterns.append((r.get('name') or r.get('vul_type') or 'unknown', pat))
                                continue
                        
                        compiled_list.append(re.compile(pat, re.I | re.S))
                    except Exception as e:
                        logger.debug(f"正则编译失败: {pat[:50]}..., 错误: {e}")
                        bad_patterns.append((r.get('name') or r.get('vul_type') or 'unknown', pat))
                
                # 存入缓存
                if cache_manager and compiled_list:
                    cache_manager.set(cache_key_str, compiled_list, ttl=3600)  # 1小时TTL
            
            compiled_cache[rid] = compiled_list
            exts = [e.lower().lstrip('.') for e in r.get('file_exts', [])]
            if include_exts:
                exts = [e for e in exts if e in include_exts]
            for ext in exts:
                ext_map.setdefault(ext, []).append(r)
        # 轻量触发词：基础提示词（小集合）+ 按规则动态提取的字面提示词，先做包含判断再跑正则，降低开销
        BASE_HINTS = {
            # 通用 IO/模板输出
            'request.getparameter', 'out.print', 'out.println', '${', '<%=', 'document.write',
            # JSP/Servlet
            'response.setheader', 'response.addheader', 'pagecontext.getout', 'sendredirect', 'http-equiv="refresh"', 'location.href',
            # Freemarker
            '<#', '#include', '#import', '#assign', '#if', '#list', '${',
            # Velocity
            '$!', '#set', '#parse', '#foreach',
            # Thymeleaf
            'th:', '@{'
        }
        # 从规则正则中抽取字面提示词 -> 规则级缓存，避免在每个文件上重复构建
        def _hint_words(pat_str: str):
            return [w.lower() for w in re.findall(r'[A-Za-z][A-Za-z0-9_.]{2,}', pat_str)]
        rule_hints_cache: Dict[int, Set[str]] = {}
        for r in template_rules:
            rh = set(h.lower() for h in BASE_HINTS)
            for _ps in r.get('patterns', []) or []:
                for w in _hint_words(_ps):
                    rh.add(w)
            rule_hints_cache[id(r)] = rh
        # 为了准确性，放宽大部分限制，但保留合理的性能限制
        MAX_FILE_BYTES = 50 * 1024 * 1024 if not is_lite_mode else 50 * 1024 * 1024  # 50MB，确保不漏检
        MAX_LINES_PER_FILE = 200000 if not is_lite_mode else 200000  # 20万行，扫描完整文件
        PARTIAL_FLUSH_INTERVAL = 50
        partial_since_last = 0
        MAX_REGEX_EVALS_PER_FILE = 500 if is_lite_mode else 2000  # 保留合理的正则评估上限
        regex_evals = 0
        
        # 去重集合 - 保留每文件每规则上限，避免过度刷屏
        seen = set()  # (rule_name, rel_path, line_no) - 用于行级去重
        per_file_rule_count: Dict[Tuple[str, str], int] = {}
        PER_FILE_RULE_CAP = 1 if is_lite_mode else 5  # 保留上限，避免刷屏
        
        # 文件级漏洞类型去重：同一文件同一漏洞类型只保留一个结果
        file_vul_type_seen = set()  # (rel_path, vul_type) - 用于文件级去重
        
        # 上下文分析配置 - 大幅增强上下文窗口，提升准确性
        CONTEXT_WINDOW = 15 if not is_lite_mode else 15  # 前后15行上下文（大幅提升，确保上下文完整）
        ENABLE_CONTEXT_ANALYSIS = True  # 始终启用上下文分析，提升准确性
        ENABLE_SMART_SCORING = True  # 始终启用智能评分，提升准确性
        # 目录跳过：避免构建/打包/依赖目录中的噪声
        SKIP_DIRS = ('/target/', '/build/', '/dist/', '/out/', '/node_modules/')
        if self.rules.get('__ignore_skip_dirs__'):
            SKIP_DIRS = tuple()
        # 遍历模板文件
        scanned_files = 0
        scanned_dirs = 0
        first_files = []
        for root, _, files in os.walk(self.project_path):
            norm_root = root.replace('\\\\', '/').replace('\\', '/')
            scanned_dirs += 1
            if any(sd in norm_root for sd in SKIP_DIRS):
                continue
            for file in files:
                ext = file.split('.')[-1].lower() if '.' in file else ''
                # 支持Java相关文件的扫描：.java, .jsp, .jspx, .class 都需要扫描
                java_related_exts = {'java', 'jsp', 'jspx', 'class'}
                if ext not in ext_map and ext not in java_related_exts:
                    continue
                file_path = os.path.join(root, file)
                scanned_files += 1
                if len(first_files)<5:
                    first_files.append(file_path)
                
                try:
                    # 资源限制检查 - 使用安全工具
                    if resource_limiter:
                        is_safe, err_msg = resource_limiter.check_file(file_path)
                        if not is_safe:
                            logger.debug(f"文件超出资源限制，跳过: {file_path}, {err_msg}")
                            continue
                    
                    # 文件大小检查
                    try:
                        if os.path.getsize(file_path) > MAX_FILE_BYTES:
                            continue
                    except Exception:
                        pass
                    # 对于.class文件，尝试读取（可能是文本格式的反编译输出）
                    # 对于其他文件，正常读取
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                    except UnicodeDecodeError:
                        # 如果是二进制文件（如.class），尝试以二进制模式读取部分内容
                        # 主要是为了检测可能的字符串字面量
                        if ext == 'class':
                            try:
                                with open(file_path, 'rb') as f:
                                    content = f.read(10240)  # 读取前10KB
                                    # 尝试提取可打印的ASCII字符串
                                    import re
                                    text_content = re.sub(rb'[^\x20-\x7E\r\n\t]', b' ', content)
                                    lines = text_content.decode('ascii', errors='ignore').split('\n')
                                    if len(lines) < 2:
                                        continue  # 如果没有有效文本，跳过
                            except Exception:
                                continue
                        else:
                            continue
                    if len(lines) > MAX_LINES_PER_FILE:
                        # 为了准确性，扫描完整文件（不再截取）
                        # head = lines[:2000]
                        # tail = lines[-2000:]
                        # lines = head + tail
                        # 继续扫描完整文件
                        pass
                except Exception:
                    continue
                rel = os.path.relpath(file_path, self.project_path)
                # 每个文件的正则评估计数重置
                regex_evals = 0
                # 对于Java相关文件（.java, .jsp, .jspx, .class），匹配所有模板规则
                # 其他文件只匹配对应扩展名的规则
                java_related_exts = {'java', 'jsp', 'jspx', 'class'}
                if ext in java_related_exts:
                    rules_to_check = template_rules  # Java相关文件检查所有规则
                else:
                    rules_to_check = ext_map.get(ext, [])  # 其他文件只检查对应扩展名的规则
                for rule in rules_to_check:
                    # 特例：FORM_NO_CSRF 做块级判断，避免单行误报
                    if (rule.get('name') or '').upper() == 'FORM_NO_CSRF':
                        i = 0
                        while i < len(lines):
                            line = lines[i]
                            if '<form' in line and 'method="post"' in line:
                                window = ''.join(lines[i:i+50])  # 向后窗口
                                if ('name="csrf"' not in window) and ('_csrf' not in window):
                                    key = (rule.get('name'), rel, i+1)
                                    fr_key = (rule.get('name'), rel)
                                    vul_type = rule.get('vul_type') or rule.get('name')
                                    file_vul_key = (rel, vul_type)
                                    
                                    count = per_file_rule_count.get(fr_key, 0)
                                    # 检查：1) 行级去重 2) 每文件每规则上限 3) 文件级漏洞类型去重
                                    if key not in seen and count < PER_FILE_RULE_CAP and file_vul_key not in file_vul_type_seen:
                                        seen.add(key)
                                        per_file_rule_count[fr_key] = count + 1
                                        file_vul_type_seen.add(file_vul_key)  # 标记该文件该漏洞类型已存在
                                        item = {
                                            'vul_type': vul_type,
                                            'sink_desc': rule.get('desc') or '模板文本风险',
                                            'severity': rule.get('severity') or 'Medium',
                                            'sink': rule.get('name'),
                                            'call_chains': [[f"{rel}:{i+1}"]],
                                            'confidence': 0.8,
                                            'chain_count': 1,
                                            'sanitized_by': [],
                                            'sources': [],
                                            'patterns': [rule.get('name')],
                                            'file_path': rel,  # 使用相对路径
                                            'file_path_abs': file_path,  # 保留绝对路径
                                            'group_lines': [i+1],  # 添加行号信息
                                            'scan_mode': 'lite' if is_lite_mode else 'full'
                                        }
                                        findings.append(item)
                                        self.partial_results.append(item)
                                        partial_since_last += 1
                                        if self.on_partial and partial_since_last >= PARTIAL_FLUSH_INTERVAL:
                                            try:
                                                self.on_partial(self.partial_results)
                                            except Exception:
                                                pass
                                            partial_since_last = 0
                                        if len(findings) >= MAX_FINDINGS:
                                            break
                                i += 1
                            else:
                                i += 1
                        # 已处理该规则，进入下一个规则
                        if len(findings) >= MAX_FINDINGS:
                            break
                        continue
                    # 常规规则：行级匹配 + 预筛选 + 去重 + 每文件每规则上限
                    pats = compiled_cache.get(id(rule), [])
                    fr_key = (rule.get('name'), rel)
                    rule_force = bool(rule.get('force_regex'))
                    # 动态提示词集合：基础提示词 + 从正则模式中提取的字面词（大小写不敏感）
                    def _hint_words(pat_str: str):
                        return [w.lower() for w in re.findall(r'[A-Za-z][A-Za-z0-9_.]{2,}', pat_str)]
                    rule_hints = set()
                    if not rule_force:
                        rule_hints = set(h.lower() for h in BASE_HINTS)
                        for _ps in rule.get('patterns', []) or []:
                            for w in _hint_words(_ps):
                                rule_hints.add(w)
                    hit_lines: List[int] = []
                    for i, line in enumerate(lines, start=1):
                        if self.should_stop():
                            break
                        if len(line) > 10000:
                            continue
                        line_lower = line.lower()
                        if (not rule_force) and rule_hints and (not any(h in line_lower for h in rule_hints)):
                            continue
                        count = per_file_rule_count.get(fr_key, 0)
                        if count >= PER_FILE_RULE_CAP:
                            break
                        for pat in pats:
                            if self.should_stop():
                                break
                            if regex_evals >= MAX_REGEX_EVALS_PER_FILE:
                                break
                            regex_evals += 1
                            if pat.search(line):
                                # 二次过滤以降低误报
                                line_lower = line_lower if 'line_lower' in locals() else line.lower()
                                
                                # 1. 基础过滤：must_substrings/exclude_substrings
                                if self.rules.get('__apply_must_substrings__'):
                                    ms = [s.lower() for s in (rule.get('must_substrings') or [])]
                                    es = [s.lower() for s in (rule.get('exclude_substrings') or [])]
                                    if es and any(x in line_lower for x in es):
                                        continue
                                    if ms and not all(x in line_lower for x in ms):
                                        continue
                                
                                # 2. 误报过滤：注释检测、字符串字面量等（增强版）
                                if ENABLE_CONTEXT_ANALYSIS:
                                    is_fp = self._is_false_positive(line, lines, i, CONTEXT_WINDOW, rule)
                                    # 对于JSP/JSPX文件，采用更宽松的误报过滤
                                    if is_fp:
                                        # 计算置信度，只有明显误报才过滤
                                        base_conf = 0.6 if ext in {'jsp', 'jspx'} else 0.5
                                        if ENABLE_SMART_SCORING:
                                            temp_conf = self._calculate_confidence(line, lines, i, rule, base_conf)
                                            if temp_conf < 0.3:  # 只有明显误报才过滤
                                                continue
                                        else:
                                            continue
                                
                                # 3. 上下文验证（全量模式，增强版）
                                if ENABLE_CONTEXT_ANALYSIS:
                                    context_score = self._analyze_context(lines, i, CONTEXT_WINDOW, rule)
                                    # 对于JSP/JSPX文件，降低上下文匹配阈值
                                    threshold = 0.25 if ext in {'jsp', 'jspx'} else 0.3
                                    if context_score < threshold:  # 上下文不匹配，跳过
                                        continue
                                else:
                                    context_score = 0.5  # 轻量模式默认分数
                                
                                key = (rule.get('name'), rel, i)
                                if key in seen:
                                    break
                                seen.add(key)
                                
                                # 智能评分（全量模式，增强版）
                                confidence = context_score if ENABLE_SMART_SCORING else 0.8
                                if ENABLE_SMART_SCORING:
                                    confidence = self._calculate_confidence(line, lines, i, rule, context_score)
                                    # 对于JSP/JSPX文件，适当提升基础置信度
                                    if ext in {'jsp', 'jspx'} and confidence > 0.5:
                                        confidence = min(1.0, confidence + 0.05)
                                
                                hit_lines.append((i, confidence))  # 存储行号和置信度
                                break
                    # 将相邻命中折叠为区间并生成单条记录，附带细分行信息和置信度
                    if hit_lines:
                        # 处理带置信度的命中列表
                        if hit_lines and isinstance(hit_lines[0], tuple):
                            hit_lines_with_conf = hit_lines
                            hit_lines_nums = [ln for ln, _ in hit_lines_with_conf]
                        else:
                            # 兼容旧格式（纯整数列表）
                            hit_lines_nums = [ln if isinstance(ln, int) else ln[0] for ln in hit_lines]
                            hit_lines_with_conf = [(ln, 0.8) for ln in hit_lines_nums]
                        
                        hit_lines_nums.sort()
                        groups: List[Tuple[int, int, float]] = []  # (start, end, max_confidence)
                        start_ln = prev_ln = hit_lines_nums[0]
                        max_conf_in_group = max(c for ln, c in hit_lines_with_conf if ln == start_ln)
                        
                        for ln in hit_lines_nums[1:]:
                            if ln == prev_ln + 1:
                                prev_ln = ln
                                conf_at_ln = max(c for l, c in hit_lines_with_conf if l == ln)
                                max_conf_in_group = max(max_conf_in_group, conf_at_ln)
                            else:
                                groups.append((start_ln, prev_ln, max_conf_in_group))
                                start_ln = prev_ln = ln
                                max_conf_in_group = max(c for l, c in hit_lines_with_conf if l == ln)
                        groups.append((start_ln, prev_ln, max_conf_in_group))
                        
                        for gs, ge, group_conf in groups:
                            count = per_file_rule_count.get(fr_key, 0)
                            if count >= PER_FILE_RULE_CAP:
                                break
                            
                            vul_type = rule.get('vul_type') or rule.get('name')
                            file_vul_key = (rel, vul_type)
                            
                            # 检查文件级漏洞类型去重：同一文件同一漏洞类型只保留一个结果
                            if file_vul_key in file_vul_type_seen:
                                break  # 该文件该漏洞类型已存在，跳过
                            
                            per_file_rule_count[fr_key] = count + 1
                            file_vul_type_seen.add(file_vul_key)  # 标记该文件该漏洞类型已存在
                            
                            range_str = f"{rel}:{gs}" if gs == ge else f"{rel}:{gs}-{ge}"
                            detail_lines = [ln for ln in hit_lines_nums if gs <= ln <= ge]
                            
                            # 根据置信度调整严重性
                            severity = rule.get('severity') or 'Medium'
                            if group_conf < 0.5 and severity == 'High':
                                severity = 'Medium'
                            elif group_conf < 0.3:
                                severity = 'Low'
                            
                            item = {
                                'vul_type': vul_type,
                                'sink_desc': rule.get('desc') or '模板文本风险',
                                'severity': severity,
                                'sink': rule.get('name'),
                                'call_chains': [[range_str]],
                                'chain_count': 1,
                                'confidence': round(group_conf, 2),
                                'sanitized_by': [],
                                'sources': [],
                                'patterns': [rule.get('name')],
                                'file_path': rel,  # 使用相对路径，便于前端处理
                                'file_path_abs': file_path,  # 保留绝对路径供后端使用
                                'group_lines': detail_lines,
                                'group_size': len(detail_lines),
                                'scan_mode': 'lite' if is_lite_mode else 'full'
                            }
                            findings.append(item)
                            self.partial_results.append(item)
                            partial_since_last += 1
                            if self.on_partial and partial_since_last >= PARTIAL_FLUSH_INTERVAL:
                                try:
                                    self.on_partial(self.partial_results)
                                except Exception:
                                    pass
                                partial_since_last = 0
                            if len(findings) >= MAX_FINDINGS:
                                break
                if len(findings) >= MAX_FINDINGS:
                    break
        # 批次尾刷写一次
        if self.on_partial and partial_since_last > 0:
            try:
                self.on_partial(self.partial_results)
            except Exception:
                pass
        # 汇总统计信息，便于前端/调用方诊断
        try:
            self.template_scan_stats = {
                'scanned_dirs': scanned_dirs,
                'scanned_files': scanned_files,
                'first_files': first_files[:5],
                'findings': len(findings),
                'effective_skip_dirs': list(SKIP_DIRS),
                'bad_patterns': bad_patterns,
            }
        except Exception:
            self.template_scan_stats = {'findings': len(findings)}
        # 确保最终保存已扫描数据
        finally:
            if self.on_partial:
                try:
                    self.on_partial(self.partial_results)
                except Exception as e:
                    logger.debug(f"类型解析失败: {e}")
                    pass
        return findings

    def find_vulnerabilities(self) -> List[dict]:
        results = []
        # 为了准确性，默认深度提升到15（确保深度回溯）
        depth = self.rules.get('depth', 15)
        depth = max(depth, 15)  # 确保至少15层深度
        # 1) Java AST 回溯检测
        try:
            for rule in self.rules.get('sink_rules', []):
                if self.should_stop():
                    break
                try:
                    for sink in rule.get('sinks', []):
                        if self.should_stop():
                            break
                        try:
                            class_name, methods = sink.split(':')
                            class_name = class_name.split('.')[-1]
                            for method in methods.split('|'):
                                if self.should_stop():
                                    break
                                try:
                                    sink_point = f"{class_name}:{method}"
                                    paths = self._trace_back(sink_point, depth)
                                    if paths:
                                        fast = bool(self.rules.get('__lite_fast__'))
                                        if fast:
                                            item = {
                                                'vul_type': rule.get('sink_name'),
                                                'sink_desc': rule.get('sink_desc'),
                                                'severity': rule.get('severity_level'),
                                                'sink': sink_point,
                                                'call_chains': paths,
                                                'chain_count': len(paths)
                                            }
                                        else:
                                            enriched = []
                                            for chain in paths:
                                                try:
                                                    enriched.append({
                                                        'nodes': chain,
                                                        'confidence': self._score_chain(chain, rule.get('sink_name','')),
                                                        'sanitized_by': self._is_sanitized(chain),
                                                        'sources': self._find_sources(chain),
                                                        'patterns': self._get_pattern_hits(chain)
                                                    })
                                                except Exception:
                                                    # 富化失败时使用快速模式
                                                    enriched.append({
                                                        'nodes': chain,
                                                        'confidence': 0.5,
                                                        'sanitized_by': [],
                                                        'sources': [],
                                                        'patterns': []
                                                    })
                                            item = {
                                                'vul_type': rule.get('sink_name'),
                                                'sink_desc': rule.get('sink_desc'),
                                                'severity': rule.get('severity_level'),
                                                'sink': sink_point,
                                                'call_chains': [c['nodes'] for c in enriched],
                                                'chain_count': len(paths),
                                                'confidence': max(c['confidence'] for c in enriched) if enriched else 0.0,
                                                'sanitized_by': list(set(sum([c['sanitized_by'] for c in enriched], []))),
                                                'sources': list(set(sum([c['sources'] for c in enriched], []))),
                                                'patterns': list(set(sum([c.get('patterns', []) for c in enriched], [])))
                                            }
                                        results.append(item)
                                        self.partial_results.append(item)
                                        # 每次添加结果都保存，确保中断时数据不丢失
                                        if self.on_partial:
                                            try:
                                                self.on_partial(self.partial_results)
                                            except Exception:
                                                pass
                                except Exception:
                                    continue
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception as e:
            # 即使出错也保存已扫描的数据
            if self.on_partial:
                try:
                    self.on_partial(self.partial_results)
                except Exception as e:
                    logger.debug(f"类型解析失败: {e}")
                    pass
        # 2) 模板文本扫描（JSP/FTL/VM/Thymeleaf 等）
        try:
            if not self.rules.get('__disable_template_scan__'):
                tmpl_results = self._scan_template_files()
                if tmpl_results:
                    results.extend(tmpl_results)
                    # 模板扫描结果也立即保存
                    if self.on_partial:
                        try:
                            self.on_partial(self.partial_results)
                        except Exception:
                            pass
        except Exception as e:
            # 模板扫描失败也保存已扫描的数据
            if self.on_partial:
                try:
                    self.on_partial(self.partial_results)
                except Exception as e:
                    logger.debug(f"类型解析失败: {e}")
                    pass
        # 最终保存一次，确保所有数据都已保存
        if self.on_partial:
            try:
                self.on_partial(self.partial_results)
            except Exception:
                pass
        return results

    def extract_method_definition(self, class_name: str, method_name: str) -> Tuple[Union[str, None], Union[str, None]]:
        for dirpath, _, filenames in os.walk(self.project_path):
            for filename in filenames:
                if not filename.endswith('.java'):
                    continue
                filepath = os.path.join(dirpath, filename)
                if self._should_skip_file(filepath):
                    continue
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    content = ''.join(lines)
                    tree = javalang.parse.parse(content)
                except Exception:
                    continue
                for node_type in (javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration, javalang.tree.EnumDeclaration):
                    for _, node in tree.filter(node_type):
                        if getattr(node, 'name', None) == class_name:
                            for method in getattr(node, 'methods', []) or []:
                                if getattr(method, 'name', None) == method_name and getattr(method, 'position', None):
                                    start_line = method.position.line
                                    self.last_extracted_line = start_line
                                    code = self._extract_code_block(lines, start_line - 1)
                                    return filepath, code
        return None, None

    @staticmethod
    def _extract_code_block(lines: List[str], start_index: int) -> str:
        code_lines = []
        brace_depth = 0
        started = False
        for line in lines[start_index:]:
            code_lines.append(line)
            if not started and '{' in line:
                brace_depth += line.count('{') - line.count('}')
                started = True
            elif started:
                brace_depth += line.count('{') - line.count('}')
            if started and brace_depth == 0:
                break
        return ''.join(code_lines)
