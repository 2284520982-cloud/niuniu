// API请求模块
import { getApiBase } from './utils.js';
import { Toast } from './utils.js';
import { LoadingManager } from './utils.js';

const toast = new Toast();
const loading = new LoadingManager();

/**
 * 通用API请求封装
 */
async function request(url, options = {}) {
  console.log(`[API] 请求: ${options.method || 'GET'} ${url}`);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 300000); // 5分钟超时

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });
    
    console.log(`[API] 响应状态: ${response.status} ${response.statusText}`);

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      let errorData;
      try {
        errorData = JSON.parse(errorText);
      } catch {
        errorData = { detail: errorText };
      }
      throw new Error(errorData.detail || errorData.message || `HTTP ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      const jsonData = await response.json();
      console.log('[API] JSON响应:', jsonData);
      return jsonData;
    }
    const textData = await response.text();
    console.log('[API] 文本响应:', textData);
    return textData;
  } catch (error) {
    clearTimeout(timeoutId);
    console.error('[API] 请求错误:', error);
    if (error.name === 'AbortError') {
      throw new Error('请求超时，请检查网络连接');
    }
    throw error;
  }
}

/**
 * API客户端
 */
export class ApiClient {
  static async ping() {
    return request(`${getApiBase()}/api/ping`);
  }

  static async analyze(payload) {
    return request(`${getApiBase()}/api/analyze`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async templateScan(payload) {
    return request(`${getApiBase()}/api/template-scan`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async getPartial() {
    return request(`${getApiBase()}/api/partial`);
  }

  static async getChainCode(payload) {
    return request(`${getApiBase()}/api/chain`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async getTemplateSnippet(payload) {
    return request(`${getApiBase()}/api/template-snippet`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async getSinkTypes(payload) {
    return request(`${getApiBase()}/api/sink-types`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async cancel() {
    return request(`${getApiBase()}/api/cancel`, {
      method: 'POST'
    });
  }

  static async pause() {
    return request(`${getApiBase()}/api/pause`, {
      method: 'POST'
    });
  }

  static async resume() {
    return request(`${getApiBase()}/api/resume`, {
      method: 'POST'
    });
  }

  static async getScanStatus() {
    return request(`${getApiBase()}/api/scan-status`, {
      method: 'GET'
    });
  }

  static async generateReport(payload) {
    return request(`${getApiBase()}/api/report`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  static async aiSummarize(payload) {
    return request(`${getApiBase()}/api/ai-summarize`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }
}

/**
 * 检查后端可用性
 */
export async function checkBackend() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const res = await fetch(`${getApiBase()}/api/ping`, {
      method: 'GET',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    if (!res.ok) throw new Error('后端未就绪');
    const data = await res.json();
    return data && data.ok;
  } catch (e) {
    if (e.name === 'AbortError' || e.message?.includes('aborted')) {
      toast.error('后端连接超时，请检查服务是否启动', 5000);
    } else {
      toast.error('后端未启动或端口被拦截，请先启动服务后再试', 5000);
    }
    return false;
  }
}

