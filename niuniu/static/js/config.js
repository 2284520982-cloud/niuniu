// 配置文件
export const CONFIG = {
  API_BASE: window.location.origin,
  DEFAULT_BACKEND_URL: 'http://localhost:7777',
  DEFAULT_RULES_PATH: 'Rules/rules.json',
  DEFAULT_DEPTH: 15,
  DEFAULT_MAX_CHAINS: 50,
  DEFAULT_MAX_SECONDS: 600,
  POLL_INTERVAL: 2000,
  TOAST_DURATION: 3000,
  SEARCH_SHORTCUT: 'Ctrl+K',
  CACHE_PREFIX: 'niuniu_',
  SEVERITY_COLORS: {
    Critical: '#ff4444',
    High: '#ff6666',
    Medium: '#ffaa00',
    Low: '#44aa44'
  },
  SEVERITY_ORDER: ['Critical', 'High', 'Medium', 'Low']
};
