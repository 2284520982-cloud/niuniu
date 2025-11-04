// 工具函数模块
import { CONFIG } from './config.js';

/**
 * Toast通知系统
 */
export class Toast {
  constructor() {
    this.container = this._createContainer();
  }

  _createContainer() {
    const container = document.getElementById('toast') || document.createElement('div');
    container.id = 'toast';
    container.className = 'toast hidden';
    if (!document.getElementById('toast')) {
      document.body.appendChild(container);
    }
    return container;
  }

  show(message, type = 'info', duration = CONFIG.TOAST_DURATION) {
    this.container.textContent = message;
    this.container.className = `toast toast-${type}`;
    this.container.classList.remove('hidden');
    
    setTimeout(() => {
      this.container.classList.add('hidden');
    }, duration);
  }

  success(message, duration) { this.show(message, 'success', duration); }
  error(message, duration) { this.show(message, 'error', duration); }
  warning(message, duration) { this.show(message, 'warning', duration); }
  info(message, duration) { this.show(message, 'info', duration); }
}

/**
 * 加载状态管理
 */
export class LoadingManager {
  constructor() {
    this.overlay = document.getElementById('loadingOverlay');
    if (!this.overlay) {
      this.overlay = this._createOverlay();
    }
  }

  _createOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'loadingOverlay';
    overlay.className = 'loading-overlay hidden';
    overlay.innerHTML = `
      <div class="loading-content">
        <div class="spinner-large"></div>
        <div class="loading-text">处理中...</div>
        <div class="loading-progress-bar"></div>
      </div>
    `;
    document.body.appendChild(overlay);
    return overlay;
  }

  show(text = '处理中...', progress = null) {
    const textEl = this.overlay.querySelector('.loading-text');
    const progressEl = this.overlay.querySelector('.loading-progress-bar');
    if (textEl) textEl.textContent = text;
    if (progressEl && progress !== null) {
      progressEl.style.width = `${progress}%`;
    }
    this.overlay.classList.remove('hidden');
  }

  hide() {
    this.overlay.classList.add('hidden');
  }
}

/**
 * 本地存储管理
 */
export class Storage {
  static get(key) {
    try {
      const value = localStorage.getItem(CONFIG.CACHE_PREFIX + key);
      return value ? JSON.parse(value) : null;
    } catch {
      return null;
    }
  }

  static set(key, value) {
    try {
      localStorage.setItem(CONFIG.CACHE_PREFIX + key, JSON.stringify(value));
    } catch (e) {
      console.warn('存储失败:', e);
    }
  }

  static remove(key) {
    try {
      localStorage.removeItem(CONFIG.CACHE_PREFIX + key);
    } catch {}
  }

  static clear() {
    try {
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith(CONFIG.CACHE_PREFIX)) {
          localStorage.removeItem(key);
        }
      });
    } catch {}
  }
}

/**
 * 复制到剪贴板
 */
export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    // 降级方案
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      document.body.removeChild(textarea);
      return true;
    } catch {
      document.body.removeChild(textarea);
      return false;
    }
  }
}

/**
 * HTML转义
 */
export function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * 防抖函数
 */
export function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * 节流函数
 */
export function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * 获取API基础URL
 */
export function getApiBase() {
  const urlInput = document.getElementById('backendUrl');
  if (urlInput && urlInput.value.trim()) {
    return urlInput.value.trim().replace(/\/$/, '');
  }
  return CONFIG.API_BASE;
}

/**
 * 格式化文件大小
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * 格式化时间
 */
export function formatTime(seconds) {
  if (seconds < 60) return `${seconds}秒`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (minutes < 60) return `${minutes}分${secs}秒`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return `${hours}小时${mins}分${secs}秒`;
}

/**
 * 深拷贝
 */
export function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

