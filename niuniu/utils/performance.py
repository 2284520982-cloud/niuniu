"""
性能优化工具模块
提供防抖、节流、缓存等工具函数
"""
import time
import functools
from typing import Callable, Any, Optional, Dict, Tuple, List
from functools import lru_cache
import hashlib
import json


def debounce(wait: float = 0.3):
    """
    防抖装饰器 - 用于搜索输入等场景
    
    Args:
        wait: 等待时间（秒）
    """
    def decorator(func: Callable) -> Callable:
        last_call_time = [0]
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            if current_time - last_call_time[0] >= wait:
                last_call_time[0] = current_time
                return func(*args, **kwargs)
        return wrapper
    return decorator


def throttle(wait: float = 0.3):
    """
    节流装饰器 - 用于滚动事件等场景
    
    Args:
        wait: 等待时间（秒）
    """
    def decorator(func: Callable) -> Callable:
        last_exec_time = [0]
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            if current_time - last_exec_time[0] >= wait:
                last_exec_time[0] = current_time
                return func(*args, **kwargs)
        return wrapper
    return decorator


class CacheManager:
    """内存缓存管理器"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        """
        Args:
            max_size: 最大缓存条目数
            ttl: 缓存过期时间（秒）
        """
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.max_size = max_size
        self.ttl = ttl
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存"""
        if key not in self.cache:
            return None
        
        value, expire_time = self.cache[key]
        if time.time() > expire_time:
            del self.cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """设置缓存"""
        if len(self.cache) >= self.max_size:
            # LRU淘汰：删除最旧的条目
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
        
        expire_time = time.time() + (ttl or self.ttl)
        self.cache[key] = (value, expire_time)
    
    def clear(self):
        """清空缓存"""
        self.cache.clear()
    
    def delete(self, key: str):
        """删除指定缓存"""
        self.cache.pop(key, None)


def cache_key(*args, **kwargs) -> str:
    """生成缓存键"""
    key_data = json.dumps({
        'args': args,
        'kwargs': sorted(kwargs.items())
    }, sort_keys=True, default=str)
    return hashlib.md5(key_data.encode()).hexdigest()


class PerformanceMonitor:
    """性能监控工具"""
    
    def __init__(self):
        self.metrics: Dict[str, List[float]] = {}
    
    def timeit(self, name: str):
        """性能计时装饰器"""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                start = time.time()
                try:
                    result = func(*args, **kwargs)
                    elapsed = time.time() - start
                    if name not in self.metrics:
                        self.metrics[name] = []
                    self.metrics[name].append(elapsed)
                    return result
                except Exception as e:
                    elapsed = time.time() - start
                    if name not in self.metrics:
                        self.metrics[name] = []
                    self.metrics[name].append(elapsed)
                    raise e
            return wrapper
        return decorator
    
    def get_stats(self, name: str) -> Dict[str, float]:
        """获取统计信息"""
        if name not in self.metrics or not self.metrics[name]:
            return {}
        
        times = self.metrics[name]
        return {
            'count': len(times),
            'total': sum(times),
            'avg': sum(times) / len(times),
            'min': min(times),
            'max': max(times),
        }
    
    def reset(self, name: Optional[str] = None):
        """重置统计"""
        if name:
            self.metrics.pop(name, None)
        else:
            self.metrics.clear()


# 全局缓存实例
cache_manager = CacheManager(max_size=2000, ttl=600)  # 10分钟TTL
performance_monitor = PerformanceMonitor()

