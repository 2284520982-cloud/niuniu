// 主应用入口
import { ViewManager } from './components/ViewManager.js';
import { VulnerabilityRenderer } from './components/VulnerabilityRenderer.js';
import { ApiClient, checkBackend } from './api.js';
import { Toast } from './utils.js';
import { Storage } from './utils.js';
import { escapeHtml } from './utils.js';
import { CONFIG } from './config.js';

// 全局实例
let viewManager;
let vulnerabilityRenderer;
let selectedVulns = new Set();
const toast = new Toast();

// 扫描进度相关
let scanProgressInterval = null;
let isScanning = false;

/**
 * 初始化应用
 */
async function init() {
  try {
    console.log('=== Initializing application ===');
    
    // 检查后端
    console.log('Checking backend...');
    const backendOk = await checkBackend();
    if (!backendOk) {
      console.warn('Backend not ready');
      toast.warning('后端服务未就绪，部分功能可能无法使用', 5000);
    } else {
      console.log('Backend OK');
    }

    // 初始化视图管理器
    console.log('Initializing ViewManager...');
    viewManager = new ViewManager();
    console.log('ViewManager initialized');

    // 初始化漏洞渲染器
    console.log('Initializing VulnerabilityRenderer...');
    const resultContainer = document.getElementById('result');
    if (resultContainer) {
      vulnerabilityRenderer = new VulnerabilityRenderer(resultContainer);
      console.log('VulnerabilityRenderer initialized, container:', resultContainer);
      console.log('Container parent:', resultContainer.parentElement);
      console.log('Container visible:', resultContainer.offsetParent !== null);
    } else {
      console.error('✗ result container not found!');
      toast.error('无法找到结果容器，漏洞可能无法显示');
    }

    // 加载配置
    console.log('Loading configs...');
    loadConfigs();

    // 绑定事件
    console.log('Binding events...');
    bindEvents();
    console.log('Events bound');

    // 加载Sink类型
    console.log('Loading sink types...');
    await loadSinkTypes();
    console.log('Sink types loaded');
    
    // 恢复选中的chips
    restoreSelectedChips();
    
    // 初始化状态面板
    updateMetrics();

    console.log('=== Initialization complete ===');
    toast.success('应用初始化完成');
  } catch (e) {
    console.error('初始化失败:', e);
    console.error('Stack:', e.stack);
    toast.error('应用初始化失败: ' + e.message);
    throw e;
  }
}

/**
 * 加载配置
 */
function loadConfigs() {
  const fields = ['projectPath', 'rulesPath', 'backendUrl', 'engine', 'apiBase', 'model', 'apiKey', 'depth', 'maxChains', 'maxSeconds'];
  fields.forEach(id => {
    const value = Storage.get(id);
    const el = document.getElementById(id);
    if (el && value !== null) {
      el.value = value;
    }
  });
}

/**
 * 保存配置
 */
function saveConfig(id) {
  const el = document.getElementById(id);
  if (el) {
    Storage.set(id, el.value);
  }
}

/**
 * 绑定事件
 */
function bindEvents() {
  console.log('Binding events...');
  
  // 扫描按钮（多个位置）
  const btnScan = document.getElementById('btnScan');
  const qaStart = document.getElementById('qaStart');
  
  if (btnScan) {
    btnScan.addEventListener('click', (e) => {
      console.log('btnScan clicked');
      e.preventDefault();
      handleScan();
    });
    console.log('btnScan bound');
  } else {
    console.warn('btnScan not found');
  }
  
  if (qaStart) {
    qaStart.addEventListener('click', (e) => {
      console.log('qaStart clicked');
      e.preventDefault();
      handleScan();
    });
    console.log('qaStart bound');
  } else {
    console.warn('qaStart not found');
  }
  
  // 清空结果
  document.getElementById('btnClear')?.addEventListener('click', () => {
    if (vulnerabilityRenderer) {
      vulnerabilityRenderer.container.innerHTML = '';
    }
    selectedVulns.clear();
    toast.info('结果已清空');
  });

  // 导出报告
  document.getElementById('btnExport')?.addEventListener('click', handleExport);
  
  // 控制面板快速操作按钮
  document.getElementById('qaToggleTmpl')?.addEventListener('click', () => {
    const el = document.getElementById('templateScan');
    if (el) {
      el.value = el.value === 'on' ? 'off' : 'on';
      saveConfig('templateScan');
      updateMetrics(); // 更新指标
      toast.info(`模板扫描已${el.value === 'on' ? '开启' : '关闭'}`);
    }
  });
  
  document.getElementById('qaToggleLite')?.addEventListener('click', () => {
    const el = document.getElementById('liteEnrich');
    if (el) {
      el.value = el.value === 'on' ? 'off' : 'on';
      saveConfig('liteEnrich');
      updateMetrics(); // 更新指标
      toast.info(`Lite富化已${el.value === 'on' ? '开启' : '关闭'}`);
    }
  });
  
  document.getElementById('qaSwitchLite')?.addEventListener('click', () => {
    const el = document.getElementById('engine');
    if (el) {
      el.value = 'lite';
      saveConfig('engine');
      updateMetrics(); // 更新指标
      toast.info('已切换到轻量引擎');
    }
  });
  
  document.getElementById('qaSwitchOrig')?.addEventListener('click', () => {
    const el = document.getElementById('engine');
    if (el) {
      el.value = 'original';
      saveConfig('engine');
      updateMetrics(); // 更新指标
      toast.info('已切换到完整引擎');
    }
  });
  
  // 刷新指标
  document.getElementById('btnRefreshMetrics')?.addEventListener('click', () => {
    updateMetrics();
    toast.success('指标已刷新');
  });
  
  // Sink类型全选/清空
  document.getElementById('btnSinkAll')?.addEventListener('click', () => {
    document.querySelectorAll('#sinkTypeChips .chip').forEach(chip => {
      chip.classList.add('active');
    });
    saveSelectedChips();
    toast.info('已全选所有漏洞类型');
  });
  
  document.getElementById('btnSinkNone')?.addEventListener('click', () => {
    document.querySelectorAll('#sinkTypeChips .chip').forEach(chip => {
      chip.classList.remove('active');
    });
    saveSelectedChips();
    toast.info('已清空选择');
  });
  
  // 搜索按钮
  document.getElementById('btnSearch')?.addEventListener('click', showGlobalSearch);
  document.getElementById('searchClose')?.addEventListener('click', hideGlobalSearch);
  
  // 批量操作
  document.getElementById('btnBatchOps')?.addEventListener('click', () => {
    toast.info('批量操作：点击漏洞卡片进行选择');
  });
  
  // 切换视图
  document.getElementById('btnToggleView')?.addEventListener('click', () => {
    const tabs = document.querySelectorAll('#viewModeTabs .view-tab');
    if (tabs.length === 0) return;
    
    const current = Array.from(tabs).findIndex(t => t.classList.contains('active'));
    const next = (current + 1) % tabs.length;
    
    tabs.forEach(t => t.classList.remove('active'));
    tabs[next].classList.add('active');
    
    const viewMode = tabs[next].dataset.view;
    if (window.lastVulns) {
      renderVulns(window.lastVulns, viewMode);
    }
  });

  // 配置变更保存
  ['projectPath', 'rulesPath', 'backendUrl', 'engine', 'depth', 'maxChains', 'maxSeconds', 'templateScan', 'liteEnrich'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', () => saveConfig(id));
      el.addEventListener('input', () => saveConfig(id));
    }
  });
  
  // 复选框配置保存
  const applyMustSub = document.getElementById('applyMustSub');
  if (applyMustSub) {
    applyMustSub.addEventListener('change', () => {
      Storage.set('applyMustSub', applyMustSub.checked);
    });
    const saved = Storage.get('applyMustSub');
    if (saved !== null) {
      applyMustSub.checked = saved;
    }
  }

  // 源码查看面板按钮
  document.getElementById('btnCopyCode')?.addEventListener('click', () => {
    const codeEl = document.getElementById('sourceCode');
    if (codeEl && codeEl.textContent.trim()) {
      navigator.clipboard.writeText(codeEl.textContent).then(() => {
        toast.success('代码已复制到剪贴板');
      }).catch(() => {
        toast.error('复制失败，请手动选择复制');
      });
    } else {
      toast.warning('没有可复制的代码');
    }
  });

  document.getElementById('btnClearCode')?.addEventListener('click', () => {
    const codeEl = document.getElementById('sourceCode');
    if (codeEl) {
      codeEl.textContent = '';
      toast.info('源码已清空');
    }
  });

  document.getElementById('btnFormatCode')?.addEventListener('click', () => {
    const codeEl = document.getElementById('sourceCode');
    if (codeEl && codeEl.textContent.trim()) {
      // 简单的格式化：移除多余空行
      const formatted = codeEl.textContent
        .split('\n')
        .filter((line, idx, arr) => {
          // 保留分隔符行和代码行，移除连续空行
          if (line.trim() === '' && arr[idx + 1]?.trim() === '') {
            return false;
          }
          return true;
        })
        .join('\n');
      codeEl.textContent = formatted;
      toast.success('代码已格式化');
    } else {
      toast.warning('没有可格式化的代码');
    }
  });

  // 全局搜索快捷键
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      showGlobalSearch();
    }
    if (e.key === 'Escape') {
      hideGlobalSearch();
    }
  });

  // 漏洞选择事件
  document.addEventListener('vuln-toggle', (e) => {
    const { index, selected } = e.detail;
    if (selected) {
      selectedVulns.add(index);
    } else {
      selectedVulns.delete(index);
    }
    updateBatchOpsBar();
  });

  // 视图切换
  document.querySelectorAll('#viewModeTabs .view-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#viewModeTabs .view-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const viewMode = tab.dataset.view;
      if (window.lastVulns) {
        renderVulns(window.lastVulns, viewMode);
      }
    });
  });

  // 筛选器
  document.getElementById('mainSeverity')?.addEventListener('change', applyFilters);
  document.getElementById('mainTypeFilter')?.addEventListener('input', debounce(applyFilters, 300));
  document.getElementById('confidenceFilter')?.addEventListener('input', (e) => {
    document.getElementById('confValue').textContent = e.target.value + '%';
    applyFilters();
  });
  
  // AI总结按钮
  document.getElementById('btnAIAll')?.addEventListener('click', async () => {
    const apiKey = document.getElementById('apiKey')?.value.trim();
    if (!apiKey) {
      toast.warning('请先填写API Key');
      return;
    }
    
    if (!window.lastVulns || window.lastVulns.length === 0) {
      toast.warning('没有可总结的漏洞，请先进行扫描');
      return;
    }
    
    toast.info('AI总结功能开发中...');
  });
  
  // 设置按钮
  document.getElementById('btnSettings')?.addEventListener('click', () => {
    if (viewManager) {
      viewManager.show('audit');
    }
  });
  
  // 刷新进度按钮
  document.getElementById('btnRefreshProgress')?.addEventListener('click', () => {
    refreshScanProgress();
  });
  
  // 暂停扫描按钮
  document.getElementById('btnPauseScan')?.addEventListener('click', async () => {
    try {
      const result = await ApiClient.pause();
      if (result.success) {
        toast.info('扫描已暂停');
        document.getElementById('btnPauseScan').style.display = 'none';
        document.getElementById('btnResumeScan').style.display = '';
      } else {
        toast.warning(result.message || '暂停失败');
      }
    } catch (e) {
      toast.error(`暂停扫描失败: ${e.message}`);
    }
  });

  // 继续扫描按钮
  document.getElementById('btnResumeScan')?.addEventListener('click', async () => {
    try {
      const result = await ApiClient.resume();
      if (result.success) {
        toast.info('扫描已继续');
        document.getElementById('btnResumeScan').style.display = 'none';
        document.getElementById('btnPauseScan').style.display = '';
      } else {
        toast.warning(result.message || '继续失败');
      }
    } catch (e) {
      toast.error(`继续扫描失败: ${e.message}`);
    }
  });

  // 停止扫描按钮
  document.getElementById('btnStopScan')?.addEventListener('click', async () => {
    try {
      await ApiClient.cancel();
      stopProgressPolling();
      isScanning = false;
      toast.info('已发送停止扫描请求');
      document.getElementById('btnStopScan').style.display = 'none';
      document.getElementById('btnPauseScan').style.display = 'none';
      document.getElementById('btnResumeScan').style.display = 'none';
    } catch (e) {
      toast.error(`停止扫描失败: ${e.message}`);
    }
  });
}

/**
 * 加载Sink类型
 */
async function loadSinkTypes() {
  try {
    const rulesPath = document.getElementById('rulesPath')?.value.trim() || CONFIG.DEFAULT_RULES_PATH;
    const data = await ApiClient.getSinkTypes({ rules_path: rulesPath });
    const chipsContainer = document.getElementById('sinkTypeChips');
    if (!chipsContainer || !data.sink_types) return;

    chipsContainer.innerHTML = '';
    data.sink_types.forEach(type => {
      const chip = document.createElement('div');
      chip.className = 'chip';
      chip.dataset.value = type;
      chip.textContent = type;
      chip.addEventListener('click', () => {
        chip.classList.toggle('active');
        saveSelectedChips();
      });
      chipsContainer.appendChild(chip);
    });

    // 恢复已选择的chips
    const selected = Storage.get('sink_types') || [];
    selected.forEach(type => {
      const chip = chipsContainer.querySelector(`[data-value="${type}"]`);
      if (chip) chip.classList.add('active');
    });
  } catch (e) {
    console.error('加载Sink类型失败:', e);
  }
}

/**
 * 保存选中的Sink类型
 */
function saveSelectedChips() {
  const selected = Array.from(document.querySelectorAll('#sinkTypeChips .chip.active'))
    .map(chip => chip.dataset.value);
  Storage.set('sink_types', selected);
}

/**
 * 恢复选中的Sink类型
 */
function restoreSelectedChips() {
  const selected = Storage.get('sink_types') || [];
  selected.forEach(type => {
    const chip = document.querySelector(`#sinkTypeChips .chip[data-value="${type}"]`);
    if (chip) chip.classList.add('active');
  });
}

/**
 * 获取选中的Sink类型
 */
function getSelectedSinkTypes() {
  return Array.from(document.querySelectorAll('#sinkTypeChips .chip.active'))
    .map(chip => chip.dataset.value);
}

/**
 * 处理扫描
 */
async function handleScan() {
  console.log('=== handleScan called ===');
  
  // 清空上次扫描结果，确保显示新扫描状态
  console.log('清空上次扫描结果...');
  window.lastVulns = [];
  selectedVulns.clear();
  
  // 清空漏洞渲染容器
  if (vulnerabilityRenderer && vulnerabilityRenderer.container) {
    vulnerabilityRenderer.container.innerHTML = '<div class="empty-state">扫描中...</div>';
  }
  
  // 重置指标显示
  const metricVulns = document.getElementById('metric_vulns');
  if (metricVulns) {
    metricVulns.textContent = '0';
  }
  
  const projectPath = document.getElementById('projectPath')?.value.trim();
  const rulesPath = document.getElementById('rulesPath')?.value.trim();
  
  console.log('Project path:', projectPath);
  console.log('Rules path:', rulesPath);
  
  if (!projectPath || !rulesPath) {
    console.warn('Missing project path or rules path');
    toast.error('请填写项目路径和规则路径');
    return;
  }
  
  console.log('✓ 路径验证通过，准备发送扫描请求');

  const btn = document.getElementById('btnScan') || document.getElementById('qaStart');
  if (!btn) {
    console.error('No scan button found!');
    toast.error('未找到扫描按钮');
    return;
  }

  const btnText = btn.querySelector('.btn-text');
  const btnLoading = btn.querySelector('.btn-loading');
  
  btn.disabled = true;
  if (btnText) btnText.style.display = 'none';
  if (btnLoading) btnLoading.style.display = '';

  try {
    const payload = {
      project_path: projectPath,
      rules_path: rulesPath,
      sink_types: getSelectedSinkTypes().length ? getSelectedSinkTypes() : null,
      depth: parseInt(document.getElementById('depth')?.value || CONFIG.DEFAULT_DEPTH),
      engine: document.getElementById('engine')?.value || 'lite',
      max_seconds: parseInt(document.getElementById('maxSeconds')?.value || CONFIG.DEFAULT_MAX_SECONDS),
      template_scan: document.getElementById('templateScan')?.value || 'on',
      lite_enrich: document.getElementById('liteEnrich')?.value || 'on',
      apply_must_substrings: document.getElementById('applyMustSub')?.checked || false
    };

    console.log('准备发送扫描请求，payload:', JSON.stringify(payload, null, 2));
    toast.info('开始扫描...');
    
    // 启动进度轮询
    isScanning = true;
    startProgressPolling();
    
    // 显示扫描进度页面
    if (viewManager) {
      viewManager.show('reports');
    }
    
    console.log('调用 ApiClient.analyze...');
    const data = await ApiClient.analyze(payload);
    console.log('✓ 扫描请求返回，数据:', data);
    console.log('✓ 数据类型检查:', {
      hasSuccess: 'success' in data,
      success: data.success,
      hasVulnerabilities: 'vulnerabilities' in data,
      vulnerabilitiesType: Array.isArray(data.vulnerabilities) ? 'array' : typeof data.vulnerabilities,
      vulnerabilitiesLength: Array.isArray(data.vulnerabilities) ? data.vulnerabilities.length : 'N/A',
      hasTotalVulnerabilities: 'total_vulnerabilities' in data,
      totalVulnerabilities: data.total_vulnerabilities,
      keys: Object.keys(data)
    });
    
    // 停止进度轮询
    stopProgressPolling();
    isScanning = false;
    
    // 处理响应数据（兼容不同的响应格式）
    let vulns = null;
    if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      vulns = data.vulnerabilities;
    } else if (data.success && data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      vulns = data.vulnerabilities;
    } else if (data.total_vulnerabilities > 0 && Array.isArray(data.vulnerabilities)) {
      vulns = data.vulnerabilities;
    }
    
    // 标准化漏洞数据格式（将 call_chains 转换为 chain）
    if (vulns && vulns.length > 0) {
      vulns = vulns.map((v, idx) => {
        const normalized = { ...v };
        
        // 将 call_chains (二维数组) 转换为 chain (一维数组)
        // 如果有多个调用链，取第一个最长的链，或者合并所有链
        if (v.call_chains && Array.isArray(v.call_chains) && v.call_chains.length > 0) {
          // 取第一个链，或者选择最长的链
          const chains = v.call_chains.filter(c => Array.isArray(c) && c.length > 0);
          if (chains.length > 0) {
            // 选择最长的链
            const longestChain = chains.reduce((a, b) => a.length > b.length ? a : b);
            normalized.chain = longestChain;
          } else {
            normalized.chain = [];
          }
          // 保留原始 call_chains 以供后续使用
          normalized.call_chains = v.call_chains;
        } else if (!v.chain && v.call_chain) {
          // 兼容 call_chain 字段
          normalized.chain = Array.isArray(v.call_chain) ? v.call_chain : [];
        } else if (!v.chain) {
          normalized.chain = [];
        }
        
        // 确保必要字段存在
        if (!normalized.severity) normalized.severity = 'Medium';
        if (!normalized.vul_type) normalized.vul_type = normalized.sink || 'UNKNOWN';
        if (normalized.confidence === undefined) normalized.confidence = 0.5;
        
        return normalized;
      });
    }
    
    console.log('✓ 提取并标准化后的漏洞数据:', {
      vulnsLength: vulns ? vulns.length : 0,
      firstVuln: vulns && vulns.length > 0 ? {
        vul_type: vulns[0].vul_type,
        severity: vulns[0].severity,
        sink: vulns[0].sink,
        hasChain: !!vulns[0].chain,
        chainLength: vulns[0].chain ? vulns[0].chain.length : 0,
        hasCallChains: !!vulns[0].call_chains,
        callChainsCount: vulns[0].call_chains ? vulns[0].call_chains.length : 0
      } : null
    });
    
    // 更新状态面板指标
    if (data.stats) {
      updateMetricsFromData(data.stats, data.total_vulnerabilities || (vulns ? vulns.length : 0));
    } else {
      // 如果没有stats，至少更新漏洞总数
      updateMetricsFromData({}, vulns ? vulns.length : 0);
    }
    
    if (vulns && vulns.length > 0) {
      console.log(`✓ 准备渲染 ${vulns.length} 个漏洞`);
      window.lastVulns = vulns;
      
      // 确保漏洞管理页面可见
      if (viewManager) {
        viewManager.show('vulns');
      }
      
      // 等待DOM更新后再渲染
      setTimeout(() => {
        try {
          renderVulns(vulns);
          console.log('✓ 漏洞渲染完成');
          toast.success(`扫描完成，发现 ${vulns.length} 个漏洞`);
        } catch (e) {
          console.error('✗ 渲染漏洞时出错:', e);
          toast.error(`渲染漏洞失败: ${e.message}`);
        }
      }, 100);
    } else {
      console.warn('✗ 未发现漏洞或数据格式异常');
      // 明确清空结果，显示"未发现漏洞"
      window.lastVulns = [];
      if (vulnerabilityRenderer && vulnerabilityRenderer.container) {
        vulnerabilityRenderer.container.innerHTML = '<div class="empty-state">未发现漏洞</div>';
      }
      toast.warning('扫描完成，但未发现漏洞');
    }
  } catch (e) {
    // 停止进度轮询
    stopProgressPolling();
    isScanning = false;
    
    // 扫描失败时清空结果（如果没有成功获取新结果）
    if (!window.lastVulns || window.lastVulns.length === 0) {
      if (vulnerabilityRenderer && vulnerabilityRenderer.container) {
        vulnerabilityRenderer.container.innerHTML = '<div class="empty-state" style="color:#ff6666">扫描失败，请重试</div>';
      }
    }
    
    toast.error(`扫描失败: ${e.message}`);
    console.error('扫描错误:', e);
  } finally {
    const btn = document.getElementById('btnScan') || document.getElementById('qaStart');
    if (btn) {
      btn.disabled = false;
      const btnText = btn.querySelector('.btn-text');
      const btnLoading = btn.querySelector('.btn-loading');
      if (btnText) btnText.style.display = '';
      if (btnLoading) btnLoading.style.display = 'none';
    }
  }
}

/**
 * 渲染漏洞
 */
function renderVulns(vulns, viewMode = 'severity') {
  console.log('renderVulns called:', {
    vulnsLength: vulns ? vulns.length : 0,
    viewMode: viewMode,
    hasRenderer: !!vulnerabilityRenderer
  });
  
  if (!vulnerabilityRenderer) {
    console.error('✗ vulnerabilityRenderer 未初始化');
    return;
  }
  
  if (!vulns || !Array.isArray(vulns) || vulns.length === 0) {
    console.warn('✗ 漏洞数据为空或格式错误');
    vulnerabilityRenderer.container.innerHTML = '<div class="empty-state">未发现漏洞</div>';
    return;
  }

  try {
    // 构建搜索索引
    vulnerabilityRenderer.buildSearchIndex(vulns);
    console.log('✓ 搜索索引构建完成');

    // 应用筛选
    const filtered = applyFiltersToVulns(vulns);
    console.log(`✓ 筛选后漏洞数: ${filtered.length} / ${vulns.length}`);

    // 获取当前视图模式
    const activeTab = document.querySelector('#viewModeTabs .view-tab.active');
    const currentViewMode = activeTab ? (activeTab.dataset.view || viewMode) : viewMode;

    // 按视图模式渲染
    switch (currentViewMode) {
      case 'severity':
        vulnerabilityRenderer.renderBySeverity(filtered);
        break;
      case 'type':
        vulnerabilityRenderer.renderByType(filtered);
        break;
      case 'confidence':
        vulnerabilityRenderer.renderByConfidence(filtered);
        break;
      default:
        vulnerabilityRenderer.renderAll(filtered);
    }
    console.log(`✓ 漏洞渲染完成 (${currentViewMode} 模式)`);

    // 更新统计
    updateSummary(vulns);
  } catch (e) {
    console.error('✗ 渲染漏洞时出错:', e);
    console.error('错误堆栈:', e.stack);
    vulnerabilityRenderer.container.innerHTML = `<div class="empty-state" style="color:#ff6666">渲染错误: ${e.message}</div>`;
  }
}

/**
 * 应用筛选
 */
function applyFiltersToVulns(vulns) {
  const severity = (document.getElementById('mainSeverity')?.value || '').toLowerCase();
  const typeFilter = (document.getElementById('mainTypeFilter')?.value || '').trim().toUpperCase();
  const confidenceThreshold = Number(document.getElementById('confidenceFilter')?.value || 0) / 100;

  let filtered = vulns.slice();

  if (severity) {
    filtered = filtered.filter(v => (v.severity || '').toLowerCase() === severity);
  }

  if (typeFilter) {
    filtered = filtered.filter(v => (v.vul_type || '').toUpperCase().includes(typeFilter));
  }

  if (confidenceThreshold > 0) {
    filtered = filtered.filter(v => (v.confidence || 0) >= confidenceThreshold);
  }

  return filtered;
}

/**
 * 应用筛选（事件处理）
 */
function applyFilters() {
  if (window.lastVulns) {
    const activeTab = document.querySelector('#viewModeTabs .view-tab.active');
    const viewMode = activeTab ? activeTab.dataset.view : 'severity';
    renderVulns(window.lastVulns, viewMode);
  }
}

/**
 * 更新状态面板指标
 */
function updateMetrics() {
  // 从表单获取当前配置
  const templateScan = document.getElementById('templateScan')?.value || 'on';
  const engine = document.getElementById('engine')?.value || 'lite';
  
  // 更新模板扫描状态
  const metricTmpl = document.getElementById('metric_tmpl');
  if (metricTmpl) {
    metricTmpl.textContent = templateScan === 'off' ? 'OFF' : 'ON';
  }
  
  // 更新引擎状态
  const metricEngine = document.getElementById('metric_engine');
  if (metricEngine) {
    metricEngine.textContent = engine;
  }
  
  // 如果有扫描结果，更新其他指标
  if (window.lastVulns) {
    const metricVulns = document.getElementById('metric_vulns');
    if (metricVulns) {
      metricVulns.textContent = window.lastVulns.length;
    }
  }
}

/**
 * 从扫描结果数据更新指标
 */
function updateMetricsFromData(stats, vulnCount) {
  // 更新文件速率
  const metricRate = document.getElementById('metric_rate');
  if (metricRate && stats.rate_per_min !== undefined) {
    metricRate.textContent = `${Math.round(stats.rate_per_min || 0)} / 分钟`;
  }
  
  // 更新已解析文件数
  const metricParsed = document.getElementById('metric_parsed');
  if (metricParsed && stats.parsed !== undefined) {
    metricParsed.textContent = stats.parsed || 0;
  }
  
  // 更新总文件数
  const metricTotal = document.getElementById('metric_total');
  if (metricTotal && stats.total_files !== undefined) {
    metricTotal.textContent = stats.total_files || 0;
  }
  
  // 更新漏洞总数
  const metricVulns = document.getElementById('metric_vulns');
  if (metricVulns) {
    metricVulns.textContent = vulnCount || 0;
  }
  
  // 更新模板扫描状态
  const templateScan = document.getElementById('templateScan')?.value || 'on';
  const metricTmpl = document.getElementById('metric_tmpl');
  if (metricTmpl) {
    metricTmpl.textContent = templateScan === 'off' ? 'OFF' : 'ON';
  }
  
  // 更新引擎状态
  const engine = document.getElementById('engine')?.value || 'lite';
  const metricEngine = document.getElementById('metric_engine');
  if (metricEngine) {
    metricEngine.textContent = engine;
  }
}

/**
 * 更新统计信息
 */
function updateSummary(vulns) {
  const summary = {
    total: vulns.length,
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0
  };

  vulns.forEach(v => {
    const sev = v.severity || 'Low';
    if (summary.hasOwnProperty(sev)) {
      summary[sev]++;
    }
  });

  const summaryEl = document.getElementById('summary');
  if (summaryEl) {
    summaryEl.innerHTML = `
      总计: <strong>${summary.total}</strong> | 
UNI: <strong style="color:${CONFIG.SEVERITY_COLORS.Critical}">${summary.Critical}</strong> | 
高危: <strong style="color:${CONFIG.SEVERITY_COLORS.High}">${summary.High}</strong> | 
中危: <strong style="color:${CONFIG.SEVERITY_COLORS.Medium}">${summary.Medium}</strong> | 
低危: <strong style="color:${CONFIG.SEVERITY_COLORS.Low}">${summary.Low}</strong>
    `;
  }
}

/**
 * 更新批量操作栏
 */
function updateBatchOpsBar() {
  const count = selectedVulns.size;
  let bar = document.getElementById('batchOpsBar');
  
  if (count === 0 && bar) {
    bar.remove();
    return;
  }

  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'batchOpsBar';
    bar.className = 'batch-ops-bar';
    document.getElementById('view_vulns')?.insertBefore(bar, document.getElementById('result'));
  }

  bar.innerHTML = `
    <div class="batch-info">
      <span class="selected-count">已选择 ${count} 项</span>
    </div>
    <div class="batch-actions">
      <button class="ghost" onclick="window.batchExportSelected()">导出选中</button>
      <button class="ghost" onclick="selectedVulns.clear(); updateBatchOpsBar();">取消选择</button>
    </div>
  `;
}

/**
 * 全局搜索
 */
function showGlobalSearch() {
  const searchEl = document.getElementById('globalSearch');
  if (searchEl) {
    searchEl.classList.remove('hidden');
    document.getElementById('searchInput')?.focus();
  }
}

function hideGlobalSearch() {
  const searchEl = document.getElementById('globalSearch');
  if (searchEl) {
    searchEl.classList.add('hidden');
  }
}

/**
 * 导出报告
 */
async function handleExport() {
  const projectPath = document.getElementById('projectPath')?.value.trim();
  const rulesPath = document.getElementById('rulesPath')?.value.trim();
  
  if (!projectPath || !rulesPath) {
    toast.error('请填写项目路径和规则路径');
    return;
  }

  try {
    toast.info('正在生成报告...');
    const payload = {
      project_path: projectPath,
      rules_path: rulesPath,
      vulnerabilities: window.lastVulns || []
    };

    const data = await ApiClient.generateReport(payload);
    toast.success(`报告已生成：${data.output_dir}（${data.count || 0} 条）`, 5000);
  } catch (e) {
    toast.error(`导出失败: ${e.message}`);
  }
}

/**
 * 启动进度轮询
 */
function startProgressPolling() {
  // 清除之前的轮询
  stopProgressPolling();
  
  // 显示扫描控制按钮
  const btnStop = document.getElementById('btnStopScan');
  const btnPause = document.getElementById('btnPauseScan');
  const btnResume = document.getElementById('btnResumeScan');
  
  if (btnStop) {
    btnStop.style.display = '';
  }
  if (btnPause) {
    btnPause.style.display = '';
  }
  if (btnResume) {
    btnResume.style.display = 'none';  // 初始不显示继续按钮
  }
  
  // 立即获取一次进度
  refreshScanProgress();
  
  // 每2秒轮询一次进度和状态
  scanProgressInterval = setInterval(async () => {
    if (isScanning) {
      refreshScanProgress();
      
      // 检查扫描状态（暂停/继续）
      try {
        const status = await ApiClient.getScanStatus();
        if (status.success) {
          if (status.paused && btnPause && btnResume) {
            btnPause.style.display = 'none';
            btnResume.style.display = '';
          } else if (!status.paused && btnPause && btnResume) {
            btnPause.style.display = '';
            btnResume.style.display = 'none';
          }
          if (status.stopped) {
            stopProgressPolling();
            isScanning = false;
          }
        }
      } catch (e) {
        // 忽略状态检查错误
        console.debug('状态检查失败:', e);
      }
    } else {
      stopProgressPolling();
    }
  }, CONFIG.POLL_INTERVAL);
}

/**
 * 停止进度轮询
 */
function stopProgressPolling() {
  if (scanProgressInterval) {
    clearInterval(scanProgressInterval);
    scanProgressInterval = null;
  }
  
  // 隐藏所有扫描控制按钮
  const btnStop = document.getElementById('btnStopScan');
  const btnPause = document.getElementById('btnPauseScan');
  const btnResume = document.getElementById('btnResumeScan');
  
  if (btnStop) {
    btnStop.style.display = 'none';
  }
  if (btnPause) {
    btnPause.style.display = 'none';
  }
  if (btnResume) {
    btnResume.style.display = 'none';
  }
}

/**
 * 刷新扫描进度
 */
async function refreshScanProgress() {
  try {
    console.log('[进度] 正在获取扫描进度...');
    const data = await ApiClient.getPartial();
    
    if (!data) {
      console.log('[进度] 无进度数据');
      return;
    }
    
    // 更新进度信息
    const progressInfo = document.getElementById('progressInfo');
    const progressDiv = document.getElementById('progress');
    
    // 提取统计数据
    const stats = data.stats || {};
    const currentFile = data.current_file || stats.current_file || '正在初始化...';
    const parsed = data.parsed || stats.parsed || stats.parsed_files || 0;
    const totalFiles = data.total_files || stats.total_files || 0;
    const rate = data.rate_per_min || stats.rate_per_min || 0;
    const total = data.total || data.total_vulnerabilities || (data.vulnerabilities?.length || 0);
    
    let progressPercent = 0;
    if (totalFiles > 0) {
      progressPercent = Math.round((parsed / totalFiles) * 100);
    } else if (isScanning) {
      // 如果还在扫描但没有总文件数，显示"进行中"
      progressPercent = -1;
    }
    
    // 更新进度信息面板
    if (progressInfo) {
      progressInfo.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:12px">
          <div><strong>当前文件:</strong> <span style="color:#4CAF50">${escapeHtml(currentFile)}</span></div>
          <div><strong>文件进度:</strong> ${parsed} / ${totalFiles || '?'} ${totalFiles > 0 ? `(${progressPercent}%)` : ''}</div>
          <div><strong>处理速率:</strong> ${Math.round(rate)} 文件/分钟</div>
          <div><strong>已发现漏洞:</strong> <span style="color:#ff6666">${total}</span></div>
        </div>
      `;
    }
    
    // 更新进度条
    if (progressDiv) {
      if (progressPercent >= 0) {
        progressDiv.innerHTML = `
          <div style="background:#1a2332;border-radius:8px;padding:12px;margin-top:12px">
            <div style="display:flex;justify-content:space-between;margin-bottom:8px">
              <span>扫描进度</span>
              <span>${progressPercent}%</span>
            </div>
            <div style="background:#0f2034;border-radius:4px;height:24px;overflow:hidden;position:relative">
              <div style="background:linear-gradient(90deg,#4CAF50,#8BC34A);height:100%;width:${progressPercent}%;transition:width 0.3s;display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;font-weight:bold">
                ${progressPercent > 10 ? progressPercent + '%' : ''}
              </div>
            </div>
          </div>
        `;
      } else {
        // 无进度时显示"进行中"
        progressDiv.innerHTML = `
          <div style="background:#1a2332;border-radius:8px;padding:12px;margin-top:12px">
            <div style="display:flex;justify-content:space-between;margin-bottom:8px">
              <span>扫描进度</span>
              <span>进行中...</span>
            </div>
            <div style="background:#0f2034;border-radius:4px;height:24px;overflow:hidden;position:relative">
              <div style="background:linear-gradient(90deg,#4CAF50,#8BC34A);height:100%;width:100%;animation:pulse 2s infinite;opacity:0.6"></div>
            </div>
          </div>
        `;
      }
    }
    
    // 更新控制面板指标（实时刷新）
    updateMetricsFromData({
      parsed: parsed,
      total_files: totalFiles,
      rate_per_min: rate
    }, total);
    
    // 如果有部分结果，显示在漏洞管理页面
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      window.lastVulns = data.vulnerabilities;
      // 只在漏洞管理页面可见时更新
      const vulnsView = document.getElementById('view_vulns');
      if (vulnsView && vulnsView.style.display !== 'none') {
        renderVulns(data.vulnerabilities);
      }
    }
    
    console.log(`[进度] 已更新: ${parsed}/${totalFiles} (${progressPercent}%), 漏洞: ${total}`);
    
  } catch (e) {
    console.error('[进度] 刷新失败:', e);
    // 显示错误提示（仅当在报告管理页面时）
    const reportsView = document.getElementById('view_reports');
    if (reportsView && reportsView.style.display !== 'none') {
      const progressInfo = document.getElementById('progressInfo');
      if (progressInfo && !progressInfo.textContent.includes('错误')) {
        progressInfo.innerHTML = `<div style="color:#ff6666">无法获取进度: ${e.message}</div>`;
      }
    }
  }
}

/**
 * 防抖函数
 */
function debounce(func, wait) {
  let timeout;
  return function(...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}

// 全局函数（供HTML调用）
window.viewCode = async function(chainJson) {
  try {
    const chain = JSON.parse(chainJson);
    // 需要提供项目路径和规则路径
    const projectPath = document.getElementById('projectPath')?.value.trim();
    const rulesPath = document.getElementById('rulesPath')?.value.trim();
    
    if (!projectPath || !rulesPath) {
      toast.error('请先填写项目路径和规则路径');
      return;
    }
    
    const data = await ApiClient.getChainCode({
      project_path: projectPath,
      rules_path: rulesPath,
      call_chain: chain
    });
    
    const codeEl = document.getElementById('sourceCode');
    if (codeEl && data.chain) {
      // 组合所有链路的代码
      const codeParts = data.chain.map(item => {
        return `// ${item.function}\n// ${item.file_path}:${item.line || ''}\n${item.code || '未找到源码'}\n`;
      });
      codeEl.textContent = codeParts.join('\n---\n\n');
    } else if (codeEl) {
      codeEl.textContent = '未找到源码';
    }
    viewManager.show('rules');
  } catch (e) {
    toast.error(`获取源码失败: ${e.message}`);
  }
};

window.copySink = function(sink) {
  navigator.clipboard.writeText(sink).then(() => {
    toast.success('已复制到剪贴板');
  });
};

window.copyPath = function(path) {
  navigator.clipboard.writeText(path).then(() => {
    toast.success('已复制到剪贴板');
  });
};

// 模板扫描查看源码（全局函数）
window.viewTemplateCode = async function(templateJson) {
  try {
    const templateData = JSON.parse(templateJson);
    const projectPath = document.getElementById('projectPath')?.value.trim();
    
    if (!projectPath) {
      toast.error('请先填写项目路径');
      return;
    }
    
    if (!templateData.file_path) {
      toast.error('文件路径不存在');
      return;
    }
    
    // 构建payload：优先使用group_lines，如果没有则使用start/end
    const payload = {
      project_path: projectPath,
      file_path: templateData.file_path,  // 相对路径
      context: 5  // 显示前后5行上下文
    };
    
    if (templateData.group_lines && templateData.group_lines.length > 0) {
      payload.group_lines = templateData.group_lines;
    } else if (templateData.start && templateData.end) {
      payload.start = templateData.start;
      payload.end = templateData.end;
    } else if (templateData.start) {
      payload.start = templateData.start;
      payload.end = templateData.start + 10;  // 默认显示10行
    }
    
    console.log('获取模板源码，payload:', payload);
    const data = await ApiClient.getTemplateSnippet(payload);
    console.log('模板源码返回:', data);
    
    const codeEl = document.getElementById('sourceCode');
    if (codeEl && data.code) {
      // 显示文件路径和行号范围
      const title = `${data.file_path || templateData.file_path || ''}:${data.start || ''}-${data.end || ''}`;
      codeEl.textContent = `${title}\n${'-'.repeat(Math.max(10, title.length))}\n${data.code || '未找到源码'}`;
      toast.success('源码已加载');
    } else if (codeEl) {
      codeEl.textContent = '未找到源码';
      toast.warning('未找到源码');
    }
    
    // 切换到源码查看面板
    if (viewManager) {
      viewManager.show('rules');
    }
  } catch (e) {
    toast.error(`获取模板源码失败: ${e.message}`);
    console.error('获取模板源码错误:', e);
  }
};

window.batchExportSelected = function() {
  if (selectedVulns.size === 0) {
    toast.warning('请先选择要导出的漏洞');
    return;
  }
  toast.info('批量导出功能开发中...');
};

// 页面加载完成后初始化
console.log('main.js loaded, readyState:', document.readyState);
console.log('DOM elements check:', {
  btnScan: !!document.getElementById('btnScan'),
  qaStart: !!document.getElementById('qaStart'),
  viewManager: 'pending'
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    console.log('DOMContentLoaded fired');
    init().catch(e => {
      console.error('Init error:', e);
      alert('初始化失败: ' + e.message);
    });
  });
} else {
  console.log('DOM already ready, calling init');
  init().catch(e => {
    console.error('Init error:', e);
    alert('初始化失败: ' + e.message);
  });
}

