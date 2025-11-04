"""
缓存管理模块
"""
import time
import logging
from typing import Dict, Tuple, Optional, Any
from collections import OrderedDict
from .constants import CACHE_TTL, CACHE_MAX_SIZE

logger = logging.getLogger(__name__)


class LRUCache:
    """
    LRU缓存实现
    """
    
    def __init__(self, max_size: int = CACHE_MAX_SIZE, ttl: int = CACHE_TTL):
        """
        初始化LRU缓存
        
        Args:
            max_size: 最大缓存条目数
            ttl: 缓存过期时间（秒）
        """
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            缓存值，如果不存在或已过期返回None
        """
        if key not in self._cache:
            self._misses += 1
            return None
        
        value, timestamp = self._cache[key]
        
        # 检查是否过期
        if time.time() - timestamp > self.ttl:
            del self._cache[key]
            self._misses += 1
            return None
        
        # 移动到末尾（LRU）
        self._cache.move_to_end(key)
        self._hits += 1
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        设置缓存值
        
        Args:
            key: 缓存键
            value: 缓存值
        """
        # 如果已存在，更新值
        if key in self._cache:
            self._cache.move_to_end(key)
        
        # 添加新条目
        self._cache[key] = (value, time.time())
        
        # 如果超过最大大小，删除最旧的条目
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)
    
    def clear(self) -> None:
        """清空缓存"""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    def stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            统计信息字典
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        
        return {
            'size': len(self._cache),
            'max_size': self.max_size,
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': f'{hit_rate:.2f}%',
            'ttl': self.ttl
        }
    
    def invalidate(self, key: str) -> None:
        """
        使缓存项失效
        
        Args:
            key: 缓存键
        """
        if key in self._cache:
            del self._cache[key]


# 全局缓存实例
_global_cache: Optional[LRUCache] = None


def get_cache() -> LRUCache:
    """
    获取全局缓存实例
    
    Returns:
        LRU缓存实例
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = LRUCache()
    return _global_cache


def clear_cache() -> None:
    """清空全局缓存"""
    global _global_cache
    if _global_cache is not None:
        _global_cache.clear()

