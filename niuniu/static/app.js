// fetch 兼容处理（老版 Edge/IE 不支持 fetch）
(function(){
  if(!window.fetch){
    window.fetch = function(url, opts){
      opts = opts || {}; const method = (opts.method||'GET').toUpperCase();
      const headers = opts.headers || {}; const body = opts.body || null;
      return new Promise(function(resolve, reject){
        try{
          const xhr = new XMLHttpRequest();
          xhr.open(method, url, true);
          Object.keys(headers).forEach(k=>xhr.setRequestHeader(k, headers[k]));
          xhr.onreadystatechange = function(){
            if(xhr.readyState === 4){
              const res = {
                ok: (xhr.status>=200 && xhr.status<300),
                status: xhr.status,
                text: function(){ return Promise.resolve(xhr.responseText); },
                json: function(){ try{ return Promise.resolve(JSON.parse(xhr.responseText)); } catch(e){ return Promise.reject(e); } }
              };
              resolve(res);
            }
          };
          xhr.onerror = function(){ reject(new Error('Network error')); };
          xhr.send(body);
        }catch(e){ reject(e); }
      });
    };
  }
})();

const resultEl = document.getElementById('result');
const summaryEl = document.getElementById('summary');
const chipsEl = document.getElementById('sinkTypeChips');
const toastEl = document.getElementById('toast');
const modalEl = document.getElementById('modal');
const modalTitleEl = document.getElementById('modalTitle');
const modalBodyEl = document.getElementById('modalBody');
const modalCloseEl = document.getElementById('modalClose');

modalCloseEl.onclick = () => modalEl.classList.add('hidden');

// 改进的Toast通知系统
function toast(msg, type = 'info', duration = 3000){
  if(!toastEl) return;
  toastEl.textContent = msg;
  toastEl.className = `toast toast-${type}`;
  toastEl.classList.remove('hidden');
  setTimeout(()=>toastEl.classList.add('hidden'), duration);
}

// 显示加载状态
function showLoading(text = '处理中...', progress = null){
  const overlay = document.getElementById('loadingOverlay');
  const textEl = overlay?.querySelector('.loading-text');
  const progressEl = overlay?.querySelector('.loading-progress-bar');
  if(overlay){
    if(textEl) textEl.textContent = text;
    if(progressEl && progress !== null){
      progressEl.style.width = `${progress}%`;
    }
    overlay.classList.remove('hidden');
  }
}

function hideLoading(){
  const overlay = document.getElementById('loadingOverlay');
  if(overlay) overlay.classList.add('hidden');
}

// 设置按钮加载状态
function setButtonLoading(btnId, loading){
  const btn = document.getElementById(btnId);
  if(!btn) return;
  if(loading){
    btn.classList.add('loading');
    btn.disabled = true;
  }else{
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

function getBase(){
  const v = (document.getElementById('backendUrl') && document.getElementById('backendUrl').value.trim()) || '';
  if(v) return v.replace(/\/$/, '');
  // 默认同源
  return window.location.origin;
}

// 复制到剪贴板工具函数
async function copyToClipboard(text){
  try{
    await navigator.clipboard.writeText(text);
    toast('已复制到剪贴板', 'success', 2000);
  }catch(e){
    // 降级方案
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try{
      document.execCommand('copy');
      toast('已复制到剪贴板', 'success', 2000);
    }catch(err){
      toast('复制失败，请手动复制', 'error');
    }
    document.body.removeChild(textarea);
  }
}

async function loadSinkTypes(){
  const rulesPath = document.getElementById('rulesPath').value;
  chipsEl.innerHTML = '<div class="spinner"></div>';
  setButtonLoading('btnSinkAll', true);
  try{
    const res = await fetch(getBase() + '/api/sink-types', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ rules_path: rulesPath }) });
    if(!res.ok) throw new Error('加载失败');
    const data = await res.json();
    const names = data.sink_types || [];
    chipsEl.innerHTML='';
    names.forEach(n=>{
      const chip = document.createElement('button');
      chip.className = 'chip'; chip.textContent = n; chip.dataset.value = n;
      chip.onclick = ()=> chip.classList.toggle('active');
      chipsEl.appendChild(chip);
    });
    toast(`已加载 ${names.length} 个规则类型`, 'success', 2000);
  }catch(e){ 
    chipsEl.innerHTML=''; 
    toast('加载规则失败，请检查路径或后端是否启动', 'error', 5000); 
  }finally{
    setButtonLoading('btnSinkAll', false);
  }
}

function getSelectedSinkTypes(){
  return Array.from(chipsEl.querySelectorAll('.chip.active')).map(c=>c.dataset.value);
}

// 全选/清空漏洞类型
document.getElementById('btnSinkAll')?.addEventListener('click', ()=>{
  chipsEl.querySelectorAll('.chip').forEach(c=> c.classList.add('active'));
});
document.getElementById('btnSinkNone')?.addEventListener('click', ()=>{
  chipsEl.querySelectorAll('.chip').forEach(c=> c.classList.remove('active'));
});

function renderSummary(vulns){
  const total = vulns.length;
  const byType = {};
  const bySeverity = {Critical:0, High:0, Medium:0, Low:0};
  const byConfidence = {high:0, medium:0, low:0}; // >0.7, 0.4-0.7, <0.4
  
  vulns.forEach(v=>{ 
    byType[v.vul_type] = (byType[v.vul_type]||0)+1;
    const sev = v.severity || 'Low';
    if(bySeverity.hasOwnProperty(sev)) bySeverity[sev]++;
    const conf = v.confidence || 0;
    if(conf > 0.7) byConfidence.high++;
    else if(conf > 0.4) byConfidence.medium++;
    else byConfidence.low++;
  });
  
  const parts = Object.entries(byType).map(([k,v])=>`${k}:${v}`).join(' · ');
  summaryEl.innerHTML = `
    <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
      <strong>共 ${total} 个漏洞</strong>
      <span>严重性: C:${bySeverity.Critical} H:${bySeverity.High} M:${bySeverity.Medium} L:${bySeverity.Low}</span>
      <span>置信度: 高:${byConfidence.high} 中:${byConfidence.medium} 低:${byConfidence.low}</span>
      <span style="color:var(--muted)">${parts}</span>
    </div>
  `;
  
  // 渲染统计卡片
  renderStatsCards(vulns, bySeverity, byConfidence, byType);
}

function renderStatsCards(vulns, bySeverity, byConfidence, byType){
  const statsEl = document.getElementById('statsCards');
  if(!statsEl) return;
  
  const total = vulns.length;
  const highConfCount = vulns.filter(v=>(v.confidence||0)>0.7).length;
  const topType = Object.entries(byType).sort((a,b)=>b[1]-a[1])[0];
  
  statsEl.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">总漏洞数</div>
      <div class="stat-value">${total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">高危漏洞</div>
      <div class="stat-value" style="color:var(--danger)">${bySeverity.Critical + bySeverity.High}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">高置信度</div>
      <div class="stat-value" style="color:var(--ok)">${highConfCount}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">最多类型</div>
      <div class="stat-value" style="font-size:16px">${topType ? topType[0] : 'N/A'}</div>
      <div class="stat-label">${topType ? topType[1] + '个' : ''}</div>
    </div>
  `;
  statsEl.style.display = 'grid';
}

function normalizeChain(chain){
  if(Array.isArray(chain)) return chain;
  if(chain && Array.isArray(chain.nodes)) return chain.nodes;
  if(typeof chain === 'string') return [chain];
  if(chain && typeof chain === 'object'){
    if(Array.isArray(chain.call_chain)) return chain.call_chain;
  }
  return [];
}

function dedupeForDisplay(vulns){
  const seen = new Set();
  const out = [];
  vulns.forEach(v=>{
    // 优先按 文件+类型 去重（模板扫描项有 file_path）；否则按 类型+sink 去重（近似）
    const key = v.file_path ? `${v.vul_type}|${v.file_path}` : `${v.vul_type}|${v.sink}`;
    if(!seen.has(key)) { seen.add(key); out.push(v); }
  });
  return out;
}

// HTML转义函数 - XSS防护
function escapeHtml(text){
  if(typeof text !== 'string') text = String(text);
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderCard(v, idx){
  // 使用文档片段优化DOM操作性能
  const fragment = document.createDocumentFragment();
  const card = document.createElement('div');
  const sev = (v.severity||'Low').toLowerCase();
  card.className = `card ${sev}`;
  card.dataset.vulnIndex = idx;
  
  // 添加点击选择功能 - 使用事件委托优化
  card.onclick = (e) => {
    if(e.target.classList.contains('card-checkbox') || e.target.closest('.card-actions')) return;
    toggleVulnSelection(idx);
  };
  
  // XSS防护：转义所有用户输入
  const sani = (v.sanitized_by&&v.sanitized_by.length) ? `已清洗：${escapeHtml(v.sanitized_by.join(', '))}` : '未清洗';
  const srcs = (v.sources&&v.sources.length) ? `来源：${escapeHtml(v.sources.join(', '))}` : '';
  const filePathEscaped = v.file_path ? escapeHtml(v.file_path).replace(/'/g, "\\'") : '';
  const fileInfo = v.file_path ? `<div class="desc" style="cursor:pointer" onclick="copyToClipboard('${filePathEscaped}')" title="点击复制">📁 文件：${escapeHtml(v.file_path)}</div>` : '';
  const confidence = (v.confidence||0).toFixed(2);
  const confPercent = Math.round(confidence * 100);
  const confColor = confidence > 0.7 ? 'var(--ok)' : confidence > 0.4 ? 'var(--warn)' : 'var(--danger)';
  
  // 扫描模式标签
  const scanModeTag = v.scan_mode ? `<span class="tag" style="background:#234">${v.scan_mode === 'full' ? '全量扫描' : '轻量扫描'}</span>` : '';
  
  // 转义所有用户内容
  const vulTypeEscaped = escapeHtml(v.vul_type || '');
  const sinkEscaped = escapeHtml(v.sink || '');
  const sinkDescEscaped = escapeHtml(v.sink_desc || '');
  
  card.innerHTML = `
    <div class="card-head">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <strong style="font-size:16px">${v.vul_type}</strong>
        <span class="sev ${v.severity}">${v.severity}</span>
        <span class="sev" style="background:${confColor}">可信度 ${confidence}</span>
        ${scanModeTag}
      </div>
      <div style="margin:8px 0">
        <div class="confidence-bar">
          <div class="confidence-fill" style="width:${confPercent}%"></div>
        </div>
      </div>
      <div class="sink" style="color:var(--accent);margin:8px 0">Sink: ${sinkEscaped}</div>
      <div class="desc" style="margin:4px 0">${sinkDescEscaped}</div>
      ${fileInfo}
      <div class="tag-group">
        ${sani !== '未清洗' ? `<span class="tag" style="background:var(--ok);color:#fff">${sani}</span>` : ''}
        ${srcs ? `<span class="tag">${srcs}</span>` : ''}
        ${v.patterns && v.patterns.length ? `<span class="tag">模式: ${v.patterns.join(', ')}</span>` : ''}
      </div>
    </div>
    <div class="card-body">
      <div style="margin-bottom:8px">调用链数量：<strong>${v.chain_count || (v.call_chains ? v.call_chains.length : 0)}</strong></div>
      <div class="card-actions">
        <button class="card-action-btn ghost" onclick="event.stopPropagation(); copyToClipboard('${sinkEscaped.replace(/'/g, "\\'")}')" title="复制Sink">📋 Sink</button>
        ${fileInfo ? `<button class="card-action-btn ghost" onclick="event.stopPropagation(); copyToClipboard('${filePathEscaped}')" title="复制文件路径">📁 路径</button>` : ''}
        <button class="card-action-btn ghost" onclick="event.stopPropagation(); toggleVulnSelection(${idx})" title="选中/取消选中">${selectedVulns.has(idx) ? '✓ 已选' : '☐ 选择'}</button>
      </div>
      <details open>
        <summary style="cursor:pointer;user-select:none">查看调用链</summary>
        <div id="chains_${idx}" style="margin-top:8px"></div>
      </details>
    </div>`;
  // 使用文档片段批量添加调用链，减少DOM操作
  const chainsEl = document.createElement('div');
  chainsEl.id = `chains_${idx}`;
  chainsEl.style.marginTop = '8px';
  
  const maxChains = Number(document.getElementById('maxChains')?.value || 10);
  const chainsFragment = document.createDocumentFragment();
  
  (v.call_chains||[]).slice(0, maxChains).forEach((chain)=>{
    const row = document.createElement('div');
    row.className = 'chain-row';
    const seq = normalizeChain(chain);
    const text = (seq.length ? seq : [String(chain)]).join(' → ');
    const span = document.createElement('span'); 
    span.textContent = text; // textContent自动转义HTML
    const btnCode = document.createElement('button'); 
    btnCode.className = 'card-action-btn ghost';
    btnCode.textContent='查看源码'; 
    btnCode.onclick=()=>fetchChainCode(seq);
    
    const btnCopy = document.createElement('button'); 
    btnCopy.className='card-action-btn ghost'; 
    btnCopy.textContent='📋 复制'; 
    btnCopy.title = '复制调用链';
    btnCopy.onclick=(e)=>{e.stopPropagation(); copyToClipboard(text);};
    
    const btnAI = document.createElement('button'); 
    btnAI.className='card-action-btn ghost';
    btnAI.textContent='🤖 AI'; 
    btnAI.title = 'AI风险总结';
    btnAI.onclick=(e)=>{e.stopPropagation(); aiSummarize(seq);};
    
    // 添加悬停提示
    span.style.cursor = 'pointer';
    span.title = '点击复制调用链';
    span.onclick = (e) => { e.stopPropagation(); copyToClipboard(text); };
    
    row.appendChild(span); 
    row.appendChild(btnCopy); 
    row.appendChild(btnCode); 
    row.appendChild(btnAI);
    chainsFragment.appendChild(row);
  });
  
  chainsEl.appendChild(chainsFragment);
  
  // 将卡片添加到结果区域
  const detailsSummary = card.querySelector('details summary');
  const detailsContent = card.querySelector('details');
  if(detailsContent){
    detailsContent.appendChild(chainsEl);
  }
  
  resultEl.appendChild(card);
}

function renderGrouped(vulns){
  const groups = {};
  vulns.forEach(v=>{ (groups[v.vul_type] ||= []).push(v); });
  Object.keys(groups).sort().forEach(type=>{
    const h = document.createElement('h3'); h.textContent = type; h.className='group-head';
    resultEl.appendChild(h);
    groups[type].sort((a,b)=> (b.confidence||0) - (a.confidence||0)).forEach((v, idx)=> renderCard(v, `${type}_${idx}`));
  });
}

function splitTemplateVulns(vulns){
  const templExts = new Set(['jsp','jspx','ftl','vm','html']);
  const tmpl = [], others = [];
  vulns.forEach(v=>{
    const fp = (v.file_path||'').toLowerCase();
    const ext = fp.includes('.') ? fp.split('.').pop() : '';
    if(v.file_path && templExts.has(ext)) tmpl.push(v); else others.push(v);
  });
  return { tmpl, others };
}

function renderTemplateSummary(vulns){
  const total = vulns.length;
  const byType = {};
  const bySeverity = {Critical:0, High:0, Medium:0, Low:0};
  const byConfidence = {high:0, medium:0, low:0};
  
  vulns.forEach(v=>{ 
    byType[v.vul_type] = (byType[v.vul_type]||0)+1;
    const sev = v.severity || 'Low';
    if(bySeverity.hasOwnProperty(sev)) bySeverity[sev]++;
    const conf = v.confidence || 0;
    if(conf > 0.7) byConfidence.high++;
    else if(conf > 0.4) byConfidence.medium++;
    else byConfidence.low++;
  });
  
  const parts = Object.entries(byType).map(([k,v])=>`${k}:${v}`).join(' · ');
  const summaryEl = document.getElementById('tmplSummary');
  if(summaryEl){
    summaryEl.innerHTML = `
      <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center">
        <strong>共 ${total} 条模板风险</strong>
        <span>严重性: C:${bySeverity.Critical} H:${bySeverity.High} M:${bySeverity.Medium} L:${bySeverity.Low}</span>
        <span>置信度: 高:${byConfidence.high} 中:${byConfidence.medium} 低:${byConfidence.low}</span>
        <span style="color:var(--muted)">${parts}</span>
      </div>
    `;
  }
}

function renderTemplateCard(v, idx){
  const wrap = document.getElementById('tmplResult');
  const card = document.createElement('div');
  const sev = (v.severity||'Low').toLowerCase();
  card.className = `card ${sev}`;
  
  const rel = v.file_path || '';
  const group = (v.group_lines && v.group_lines.length) ? `命中行：${v.group_lines.join(', ')}` : '';
  const confidence = (v.confidence||0).toFixed(2);
  const confPercent = Math.round(confidence * 100);
  const confColor = confidence > 0.7 ? 'var(--ok)' : confidence > 0.4 ? 'var(--warn)' : 'var(--danger)';
  const scanModeTag = v.scan_mode ? `<span class="tag" style="background:#234">${v.scan_mode === 'full' ? '全量扫描' : '轻量扫描'}</span>` : '';
  
  card.innerHTML = `
    <div class="card-head">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <strong style="font-size:16px">${v.vul_type}</strong>
        <span class="sev ${v.severity}">${v.severity}</span>
        <span class="sev" style="background:${confColor}">可信度 ${confidence}</span>
        ${scanModeTag}
      </div>
      <div style="margin:8px 0">
        <div class="confidence-bar">
          <div class="confidence-fill" style="width:${confPercent}%"></div>
        </div>
      </div>
      <div class="desc" style="margin:4px 0">${v.sink_desc||''}</div>
      <div class="desc" style="color:var(--accent)">文件：${rel}</div>
      <div class="desc">${group}</div>
      ${v.sink ? `<div class="tag-group"><span class="tag">规则: ${v.sink}</span></div>` : ''}
    </div>
    <div class="card-body">
      <button class="primary" id="tmplBtn_${idx}">查看源码</button>
    </div>`;
  wrap.appendChild(card);
  document.getElementById(`tmplBtn_${idx}`).onclick = ()=> fetchTemplateSnippet(v);
}

async function fetchTemplateSnippet(v){
  try{
    const projectPath = document.getElementById('projectPath').value;
    // 若没有 group_lines，尝试从 call_chains 的第一段 "rel:line" 兜底行号
    let groupLines = v.group_lines||null;
    if((!groupLines || !groupLines.length) && Array.isArray(v.call_chains) && v.call_chains.length){
      const first = v.call_chains[0][0]||''; // 形如 "path:123" 或 "path:10-20"
      const m = String(first).match(/:(\d+)(?:-(\d+))?$/);
      if(m){
        const s = parseInt(m[1],10); const e = m[2] ? parseInt(m[2],10) : s;
        groupLines = Array.from({length: Math.min(e-s+1, 20)}, (_,i)=> s+i);
      }
    }
    const payload = { project_path: projectPath, file_path: v.file_path, group_lines: groupLines, context: 2 };
    const res = await fetch(getBase() + '/api/template-snippet', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    const data = await res.json();
    const pre = document.getElementById('sourceCode');
    // 带路径标题
    const title = `${data.file_path || ''}:${data.start||''}-${data.end||''}`;
    pre.textContent = `${title}\n${'-'.repeat(Math.max(10, title.length))}\n${data.code||''}`;
    // 切换到“规则管理/源码查看”页签
    document.querySelector('#featureList button[data-target="rules"]').click();
    document.getElementById('view_rules').scrollIntoView({behavior:'smooth'});
  }catch(e){ 
    toast('获取模板源码失败：' + (e.message||e), 'error'); 
  }
}

function renderVulns(data){
  resultEl.innerHTML='';
  const raw = data.vulnerabilities||[];
  let vulns = dedupeForDisplay(raw);
  
  // 构建搜索索引
  buildSearchIndex(raw);
  
  // 清除选中状态
  selectedVulns.clear();
  updateBatchOpsBar();
  
  const { tmpl, others } = splitTemplateVulns(vulns);

  // 渲染普通（非模板）到"漏洞管理"（支持筛选，但仅在展示层应用）
  function applyMainFilters(list){
    const sevF = (document.getElementById('mainSeverity')?.value||'').toLowerCase();
    const typeKey = (document.getElementById('mainTypeFilter')?.value||'').trim().toUpperCase();
    const confThreshold = Number(document.getElementById('confidenceFilter')?.value||0) / 100;
    let out = list.slice();
    if(sevF) out = out.filter(v=> (v.severity||'').toLowerCase()===sevF);
    if(typeKey) out = out.filter(v=> (v.vul_type||'').toUpperCase().includes(typeKey));
    if(confThreshold > 0) out = out.filter(v=> (v.confidence||0) >= confThreshold);
    return out;
  }
  
  // 按视图模式渲染
  let currentViewMode = 'severity';
  function renderByViewMode(list){
    resultEl.innerHTML='';
    if(list.length === 0){
      resultEl.innerHTML = '<div class="empty-state"><div>暂无漏洞</div></div>';
      return;
    }
    
    switch(currentViewMode){
      case 'severity':
        renderBySeverity(list);
        break;
      case 'type':
        renderByType(list);
        break;
      case 'confidence':
        renderByConfidence(list);
        break;
      default:
        renderAll(list);
    }
  }
  
  function renderBySeverity(list){
    const groups = {Critical:[], High:[], Medium:[], Low:[]};
    list.forEach(v=>{
      const sev = v.severity || 'Low';
      if(groups[sev]) groups[sev].push(v);
      else groups.Low.push(v);
    });
    
    ['Critical', 'High', 'Medium', 'Low'].forEach(sev=>{
      if(groups[sev].length === 0) return;
      const section = createCategorySection(sev, groups[sev].length, sev);
      const body = section.querySelector('.category-body');
      groups[sev].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> body.appendChild(renderCardReturn(v, `${sev}_${idx}`)));
      resultEl.appendChild(section);
    });
  }
  
  function renderByType(list){
    const groups = {};
    list.forEach(v=>{ (groups[v.vul_type] ||= []).push(v); });
    Object.keys(groups).sort().forEach(type=>{
      const section = createCategorySection(type, groups[type].length, 'type');
      const body = section.querySelector('.category-body');
      groups[type].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> body.appendChild(renderCardReturn(v, `${type}_${idx}`)));
      resultEl.appendChild(section);
    });
  }
  
  function renderByConfidence(list){
    const groups = {high:[], medium:[], low:[]};
    list.forEach(v=>{
      const conf = v.confidence || 0;
      if(conf > 0.7) groups.high.push(v);
      else if(conf > 0.4) groups.medium.push(v);
      else groups.low.push(v);
    });
    
    ['high', 'medium', 'low'].forEach(level=>{
      if(groups[level].length === 0) return;
      const labels = {high:'高置信度 (>0.7)', medium:'中置信度 (0.4-0.7)', low:'低置信度 (<0.4)'};
      const section = createCategorySection(labels[level], groups[level].length, level);
      const body = section.querySelector('.category-body');
      groups[level].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> body.appendChild(renderCardReturn(v, `${level}_${idx}`)));
      resultEl.appendChild(section);
    });
  }
  
  function renderAll(list){
    list.sort((a,b)=> (b.confidence||0) - (a.confidence||0))
      .forEach((v, idx)=> renderCard(v, `all_${idx}`));
  }
  
  function createCategorySection(title, count, id){
    const section = document.createElement('div');
    section.className = 'category-section';
    section.innerHTML = `
      <div class="category-header" data-id="${id}">
        <h3>${title} <span class="badge">${count}</span></h3>
        <span class="toggle">▼</span>
      </div>
      <div class="category-body expanded">
      </div>
    `;
    const header = section.querySelector('.category-header');
    const body = section.querySelector('.category-body');
    const toggle = section.querySelector('.toggle');
    header.onclick = ()=>{
      const expanded = body.classList.toggle('expanded');
      toggle.textContent = expanded ? '▼' : '▶';
    };
    return section;
  }
  
  function renderCardReturn(v, idx){ 
    const wrap = document.createElement('div');
    // 创建临时容器用于渲染卡片
    const tempContainer = document.createElement('div');
    tempContainer.style.display = 'none';
    document.body.appendChild(tempContainer);
    
    // 保存原始resultEl
    const originalResultEl = resultEl;
    resultEl = tempContainer;
    renderCard(v, idx);
    resultEl = originalResultEl;
    
    // 移动卡片到wrap
    const card = tempContainer.firstChild;
    if(card) wrap.appendChild(card);
    document.body.removeChild(tempContainer);
    
    return wrap;
  }
  
  let viewOthers = applyMainFilters(others);
  renderSummary(viewOthers);
  renderByViewMode(viewOthers);
  
  // 绑定筛选控件的变更事件 - 使用防抖优化
  try{
    let refreshTimer = null;
    const refreshView = ()=>{
      // 清除之前的定时器
      if(refreshTimer){
        clearTimeout(refreshTimer);
      }
      // 防抖：100ms后执行
      refreshTimer = setTimeout(() => {
        const vo = applyMainFilters(others);
        renderSummary(vo);
        renderByViewMode(vo);
        refreshTimer = null;
      }, 100);
    };
    
    document.getElementById('mainSeverity')?.addEventListener('change', refreshView);
    
    // 输入框使用防抖
    let inputTimer = null;
    document.getElementById('mainTypeFilter')?.addEventListener('input', (e) => {
      if(inputTimer) clearTimeout(inputTimer);
      inputTimer = setTimeout(() => {
        refreshView();
        inputTimer = null;
      }, 300);
    });
    
    document.getElementById('confidenceFilter')?.addEventListener('input', (e)=>{
      document.getElementById('confValue').textContent = e.target.value + '%';
      refreshView();
    });
    
    // 视图切换
    document.querySelectorAll('.view-tab').forEach(tab=>{
      tab.addEventListener('click', ()=>{
        document.querySelectorAll('.view-tab').forEach(t=>t.classList.remove('active'));
        tab.classList.add('active');
        currentViewMode = tab.dataset.view;
        refreshView();
      });
    });
  }catch{}

  // 渲染模板风险到"模板扫描"独立页面
  const wrap = document.getElementById('tmplResult');
  if(wrap){ wrap.innerHTML=''; }
  renderTemplateSummary(tmpl);
  
  // 模板扫描视图模式（在主扫描中，使用全局变量）
  if(typeof window.currentTmplViewMode === 'undefined'){
    window.currentTmplViewMode = 'severity';
  }
  
  function renderTmplByViewMode(list, targetWrap){
    const container = targetWrap || wrap;
    if(!container) return;
    container.innerHTML='';
    if(list.length === 0){
      container.innerHTML = '<div class="empty-state"><div>暂无模板风险</div></div>';
      return;
    }
    
    const viewMode = window.currentTmplViewMode || 'severity';
    switch(viewMode){
      case 'severity':
        renderTmplBySeverity(list, container);
        break;
      case 'type':
        renderTmplByType(list, container);
        break;
      case 'confidence':
        renderTmplByConfidence(list, container);
        break;
      default:
        renderTmplAll(list, container);
    }
  }
  
  function renderTmplBySeverity(list, container){
    const groups = {Critical:[], High:[], Medium:[], Low:[]};
    list.forEach(v=>{
      const sev = v.severity || 'Low';
      if(groups[sev]) groups[sev].push(v);
      else groups.Low.push(v);
    });
    ['Critical', 'High', 'Medium', 'Low'].forEach(sev=>{
      if(groups[sev].length === 0) return;
      const section = createCategorySection(sev, groups[sev].length, `tmpl_${sev}`);
      const body = section.querySelector('.category-body');
      groups[sev].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> {
          const cardWrap = document.createElement('div');
          const tempEl = document.createElement('div');
          tempEl.style.display = 'none';
          document.body.appendChild(tempEl);
          const originalWrap = wrap;
          wrap = tempEl;
          renderTemplateCard(v, `${sev}_${idx}`);
          wrap = originalWrap;
          const card = tempEl.firstChild;
          if(card) cardWrap.appendChild(card);
          document.body.removeChild(tempEl);
          body.appendChild(cardWrap);
        });
      container.appendChild(section);
    });
  }
  
  function renderTmplByType(list, container){
    const groups = {};
    list.forEach(v=>{ (groups[v.vul_type] ||= []).push(v); });
    Object.keys(groups).sort().forEach(type=>{
      const section = createCategorySection(type, groups[type].length, `tmpl_type_${type}`);
      const body = section.querySelector('.category-body');
      groups[type].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> {
          const cardWrap = document.createElement('div');
          const tempEl = document.createElement('div');
          tempEl.style.display = 'none';
          document.body.appendChild(tempEl);
          const originalWrap = wrap;
          wrap = tempEl;
          renderTemplateCard(v, `${type}_${idx}`);
          wrap = originalWrap;
          const card = tempEl.firstChild;
          if(card) cardWrap.appendChild(card);
          document.body.removeChild(tempEl);
          body.appendChild(cardWrap);
        });
      container.appendChild(section);
    });
  }
  
  function renderTmplByConfidence(list, container){
    const groups = {high:[], medium:[], low:[]};
    list.forEach(v=>{
      const conf = v.confidence || 0;
      if(conf > 0.7) groups.high.push(v);
      else if(conf > 0.4) groups.medium.push(v);
      else groups.low.push(v);
    });
    ['high', 'medium', 'low'].forEach(level=>{
      if(groups[level].length === 0) return;
      const labels = {high:'高置信度 (>0.7)', medium:'中置信度 (0.4-0.7)', low:'低置信度 (<0.4)'};
      const section = createCategorySection(labels[level], groups[level].length, `tmpl_conf_${level}`);
      const body = section.querySelector('.category-body');
      groups[level].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
        .forEach((v, idx)=> {
          const cardWrap = document.createElement('div');
          const tempEl = document.createElement('div');
          tempEl.style.display = 'none';
          document.body.appendChild(tempEl);
          const originalWrap = wrap;
          wrap = tempEl;
          renderTemplateCard(v, `${level}_${idx}`);
          wrap = originalWrap;
          const card = tempEl.firstChild;
          if(card) cardWrap.appendChild(card);
          document.body.removeChild(tempEl);
          body.appendChild(cardWrap);
        });
      container.appendChild(section);
    });
  }
  
  function renderTmplAll(list, container){
    list.sort((a,b)=> (b.confidence||0) - (a.confidence||0))
      .forEach((v, idx)=> renderTemplateCard(v, `all_${idx}`));
  }
  
  // 展示层筛选（模板页签）
  function applyTmplFilters(list){
    const sev = (document.getElementById('tmplSeverity')?.value || '').toLowerCase();
    const typeKey = (document.getElementById('tmplTypeFilter')?.value || '').trim().toUpperCase();
    const confThreshold = Number(document.getElementById('tmplConfidenceFilter')?.value||0) / 100;
    let out = list.slice();
    if(sev) out = out.filter(v=> (v.severity||'').toLowerCase()===sev);
    if(typeKey) out = out.filter(v=> (v.vul_type||'').toUpperCase().includes(typeKey));
    if(confThreshold > 0) out = out.filter(v=> (v.confidence||0) >= confThreshold);
    return out;
  }
  
  let vt = applyTmplFilters(tmpl);
  renderTmplByViewMode(vt);
  
  // 统计信息（如果主扫描也带 stats）
  try{
    const sum = document.getElementById('tmplSummary');
    const s = (data && data.stats) ? data.stats : null;
    if(s && sum){ 
      // 统计信息已在renderTemplateSummary中显示
    }
    // 渲染模板统计卡片
    renderTmplStatsCards(tmpl);
  }catch{}
  
  // 绑定筛选控件的变更事件
  try{
    const refreshTmplView = ()=>{
      const filtered = applyTmplFilters(tmpl);
      renderTmplByViewMode(filtered);
    };
    document.getElementById('tmplSeverity')?.addEventListener('change', refreshTmplView);
    document.getElementById('tmplTypeFilter')?.addEventListener('input', refreshTmplView);
    document.getElementById('tmplConfidenceFilter')?.addEventListener('input', (e)=>{
      document.getElementById('tmplConfValue').textContent = e.target.value + '%';
      refreshTmplView();
    });
    
    // 模板视图切换
    document.querySelectorAll('#tmplViewModeTabs .view-tab').forEach(tab=>{
      tab.addEventListener('click', ()=>{
        document.querySelectorAll('#tmplViewModeTabs .view-tab').forEach(t=>t.classList.remove('active'));
        tab.classList.add('active');
        window.currentTmplViewMode = tab.dataset.view;
        refreshTmplView();
      });
    });
  }catch{}
}

function renderTmplStatsCards(vulns){
  const statsEl = document.getElementById('tmplStatsCards');
  if(!statsEl || !vulns.length) return;
  
  const total = vulns.length;
  const bySeverity = {Critical:0, High:0, Medium:0, Low:0};
  const highConfCount = vulns.filter(v=>(v.confidence||0)>0.7).length;
  const byType = {};
  vulns.forEach(v=>{
    byType[v.vul_type] = (byType[v.vul_type]||0)+1;
    const sev = v.severity || 'Low';
    if(bySeverity.hasOwnProperty(sev)) bySeverity[sev]++;
  });
  const topType = Object.entries(byType).sort((a,b)=>b[1]-a[1])[0];
  
  statsEl.innerHTML = `
    <div class="stat-card">
      <div class="stat-label">总模板风险</div>
      <div class="stat-value">${total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">高危风险</div>
      <div class="stat-value" style="color:var(--danger)">${bySeverity.Critical + bySeverity.High}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">高置信度</div>
      <div class="stat-value" style="color:var(--ok)">${highConfCount}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">最多类型</div>
      <div class="stat-value" style="font-size:16px">${topType ? topType[0] : 'N/A'}</div>
      <div class="stat-label">${topType ? topType[1] + '个' : ''}</div>
    </div>
  `;
  statsEl.style.display = 'grid';
}

async function fetchChainCode(chain){
  const projectPath = document.getElementById('projectPath').value;
  const rulesPath = document.getElementById('rulesPath').value;
  try{
    const res = await fetch(getBase() + '/api/chain', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ project_path: projectPath, rules_path: rulesPath, call_chain: chain }) });
    const data = await res.json();
    const pre = document.getElementById('sourceCode');
    if(Array.isArray(data.chain)){
      const blocks = data.chain.map((c,idx)=>{
        const file = c.file_path || c.file || '';
        const line = (typeof c.line==='number' && c.line>0) ? `:${c.line}` : '';
        const title = `[${idx+1}] ${c.function || ''} — ${file}${line}`.trim();
        const code = (c.code||'').trim();
        return `${title}\n${'-'.repeat(Math.max(10, title.length))}\n${code}`;
      });
      pre.textContent = blocks.join('\n\n');
    }else{
      pre.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    }
    // 切换到"规则管理/源码查看"页签
    document.querySelector('#featureList button[data-target="rules"]')?.click();
    document.getElementById('view_rules')?.scrollIntoView({behavior:'smooth'});
  }catch(e){ 
    toast('获取源码失败：' + (e.message||e), 'error'); 
  }
}

async function aiSummarize(chain){
  const apiKey = document.getElementById('apiKey').value;
  const apiBase = document.getElementById('apiBase').value;
  const model = document.getElementById('model').value;
  if(!apiKey){ toast('请先填写 API Key'); return; }
  // 先取源码片段作为上下文
  let snippet = '';
  try{
    const projectPath = document.getElementById('projectPath').value;
    const rulesPath = document.getElementById('rulesPath').value;
    const res = await fetch(getBase() + '/api/chain', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ project_path: projectPath, rules_path: rulesPath, call_chain: chain }) });
    const data = await res.json();
    if(data && data.chain){
      // 拼接多段代码为一个上下文文本（限制长度）
      const parts = data.chain.map((c)=>`[${c.function}]\n${(c.code||'').slice(0,2000)}`).join('\n\n');
      snippet = parts.slice(0,6000);
    }
  }catch{}
  const text = `只进行审计，不给出修复建议。请针对我是小白的背景，逐条指出不安全写法与具体风险点，并解释原因。\n\n调用链/位置：\n${chain.join(' → ')}\n\n命中源码片段（供分析）：\n${snippet}`;
  try{
    // 先打开弹窗提示请求中，避免用户觉得“没反应”
    modalTitleEl.textContent = 'AI 风险总结（请求中）';
    modalBodyEl.textContent = '正在请求AI服务，请稍候...';
    modalEl.classList.remove('hidden');

    const res = await fetch(getBase() + '/api/ai-summary', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ api_key: apiKey, api_base: apiBase, model, text }) });
    const rawText = await res.text();
    let data = {};
    try { data = JSON.parse(rawText); } catch { data = { detail: rawText }; }
    modalTitleEl.textContent = 'AI 风险总结';
    const content = (data && data.summary) ? data.summary : (data && data.detail ? data.detail : JSON.stringify(data||{}, null, 2));
    const meta = (data && data.meta) ? `\n\n—— 元信息：${JSON.stringify(data.meta)}` : '';
    modalBodyEl.textContent = content + meta;
    // 添加复制按钮
    if(!modalBodyEl.querySelector('.btn-copy-ai')){
      const copyBtn = document.createElement('button');
      copyBtn.className = 'ghost';
      copyBtn.textContent = '复制内容';
      copyBtn.style.marginTop = '8px';
      copyBtn.onclick = () => copyToClipboard(content + meta);
      modalBodyEl.parentElement.insertBefore(copyBtn, modalBodyEl.nextSibling);
    }
  }catch(e){
    console.error('AI 总结错误:', e);
    modalTitleEl.textContent = 'AI 风险总结（错误）';
    modalBodyEl.textContent = e.message||String(e);
    toast(`AI 总结失败：${e.message||e}`, 'error', 5000);
  }
}

let progressTimer = null;
async function pollPartial(){
  try{
    const res = await fetch(getBase() + '/api/partial');
    const data = await res.json();
    const infoEl = document.getElementById('progressInfo');
    const listEl = document.getElementById('progress');
    const cur = data.current_file ? ` · 正在解析：${data.current_file}` : '';
    const rate = (typeof data.rate_per_min==='number') ? ` · 速率：${data.rate_per_min} 文件/分钟` : '';
    const parsed = (typeof data.parsed==='number' && typeof data.total_files==='number') ? ` · 进度：${data.parsed}/${data.total_files}` : '';
    infoEl.textContent = `已找到 ${data.total||0} 条疑似链路（实时预览）${cur}${rate}${parsed}`;
    // 更新仪表盘指标
    try{
      document.getElementById('metric_rate').textContent = `${data.rate_per_min||0} / 分钟`;
      document.getElementById('metric_parsed').textContent = data.parsed||0;
      document.getElementById('metric_total').textContent = data.total_files||0;
      document.getElementById('metric_vulns').textContent = data.total||0;
      document.getElementById('metric_tmpl').textContent = (document.getElementById('templateScan')?.value==='off') ? 'OFF' : 'ON';
      document.getElementById('metric_engine').textContent = document.getElementById('engine')?.value || 'lite';
    }catch{}
    listEl.innerHTML = '';
    (data.vulnerabilities||[]).slice(0, 20).forEach(v=>{
      const div = document.createElement('div');
      div.className='item';
      const count = (typeof v.chain_count==='number') ? v.chain_count : ((v.call_chains && Array.isArray(v.call_chains)) ? v.call_chains.length : 0);
      div.textContent = `${v.vul_type} · ${v.sink} · 链路 ${count}`;
      listEl.appendChild(div);
    });
  }catch{}
}

async function scan(){
  const projectPath = document.getElementById('projectPath').value.trim();
  const rulesPath = document.getElementById('rulesPath').value.trim();
  const sinkTypes = getSelectedSinkTypes();
  const depth = Number(document.getElementById('depth').value)||5;
  const maxSeconds = Number(document.getElementById('maxSeconds').value)||60;
  
  // 输入验证
  if(!projectPath || !rulesPath){ 
    toast('请填写项目路径与规则路径', 'warning'); 
    return; 
  }
  
  // 检查后端连接
  const backendOk = await checkBackend();
  if(!backendOk) return;
  
  // 设置加载状态
  setButtonLoading('btnScan', true);
  setButtonLoading('qaStart', true);
  const stopBtn = document.getElementById('btnStopScan');
  if(stopBtn){ stopBtn.style.display = ''; }
  
  summaryEl.innerHTML = '<span class="status-indicator info"></span>正在扫描 <span class="spinner"></span>';
  showLoading('初始化扫描引擎...', 10);
  
  try{
    const engine = document.getElementById('engine').value;
    if(progressTimer) clearInterval(progressTimer);
    progressTimer = setInterval(pollPartial, 2000);
    const templateScan = document.getElementById('templateScan')?.value || 'on';
    const liteEnrich = document.getElementById('liteEnrich')?.value || 'off';
    const applyMust = !!document.getElementById('applyMustSub')?.checked;
    // 确保lite_enrich参数正确传递：'on'=富化模式, 'off'=快速模式
    const payload = {
      project_path: projectPath,
      rules_path: rulesPath,
      sink_types: sinkTypes.length ? sinkTypes : null,
      depth,
      engine,
      max_seconds: maxSeconds,
      template_scan: templateScan,
      lite_enrich: liteEnrich, // 'on'=富化(打分/消毒/溯源), 'off'=快速(仅链路)
      apply_must_substrings: applyMust
    };
    console.log('扫描请求参数:', payload); // 调试日志
    
    showLoading('发送扫描请求...', 20);
    const res = await fetch(getBase() + '/api/analyze', { 
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body: JSON.stringify(payload) 
    });
    
    showLoading('处理响应...', 40);
    const text = await res.text();
    let data = {};
    try{ data = JSON.parse(text); }catch{ }
    
    if(!res.ok){
      hideLoading(); 
      // 即使请求失败，也尝试从last_partial.json获取已扫描的数据
      try{
        const partialRes = await fetch(getBase() + '/api/partial');
        const partialData = await partialRes.json();
        if(partialData && partialData.vulnerabilities && partialData.vulnerabilities.length > 0){
          toast(`扫描中断，已显示 ${partialData.total||0} 条已扫描结果`);
          renderVulns({ vulnerabilities: partialData.vulnerabilities, total_vulnerabilities: partialData.total||0 });
          try{ window.__lastScanData = { vulnerabilities: partialData.vulnerabilities, total_vulnerabilities: partialData.total||0 }; }catch{}
          return;
        }
      }catch{}
      const errorMsg = data.detail || text || '请求失败';
      toast(`扫描失败: ${errorMsg}`, 'error', 5000);
      throw new Error(errorMsg); 
    }
    
    showLoading('渲染结果...', 80);
    renderVulns(data);
    try{ window.__lastScanData = data; }catch{}
    
    hideLoading();
    toast(`扫描完成！发现 ${data.total_vulnerabilities || 0} 个漏洞`, 'success');
  }catch(e){
    hideLoading(); 
    // 扫描失败时，尝试从last_partial.json获取已扫描的数据
    try{
      const partialRes = await fetch(getBase() + '/api/partial');
      const partialData = await partialRes.json();
      if(partialData && partialData.vulnerabilities && partialData.vulnerabilities.length > 0){
        toast(`扫描中断，已显示 ${partialData.total||0} 条已扫描结果`, 'warning');
        renderVulns({ vulnerabilities: partialData.vulnerabilities, total_vulnerabilities: partialData.total||0 });
        try{ window.__lastScanData = { vulnerabilities: partialData.vulnerabilities, total_vulnerabilities: partialData.total||0 }; }catch{}
      }else{
        toast(`扫描失败：${e.message||e}`, 'error', 5000);
      }
    }catch{
      toast(`扫描失败：${e.message||e}`, 'error', 5000);
    }
  }
  finally{ 
    if(progressTimer) { clearInterval(progressTimer); progressTimer=null; } 
    setButtonLoading('btnScan', false);
    setButtonLoading('qaStart', false);
    const stopBtn = document.getElementById('btnStopScan');
    if(stopBtn){ stopBtn.style.display = 'none'; }
    hideLoading();
  }
}

// 全局搜索功能 - 性能优化版本
let searchIndex = [];
let searchIndexMap = new Map(); // 使用Map提升查找性能

function buildSearchIndex(vulns){
  if(!vulns || !Array.isArray(vulns)) return;
  
  // 清空旧索引
  searchIndex = [];
  searchIndexMap.clear();
  
  // 批量构建索引，使用Map优化查找
  vulns.forEach((v, idx) => {
    const chains = (v.call_chains || []).flat().join(' ');
    const item = {
      index: idx,
      vul_type: String(v.vul_type || ''),
      sink: String(v.sink || ''),
      sink_desc: String(v.sink_desc || ''),
      file_path: String(v.file_path || ''),
      severity: String(v.severity || ''),
      call_chains: chains,
      text: [
        v.vul_type, v.sink, v.sink_desc, v.file_path, v.severity, chains
      ].filter(Boolean).join(' ').toLowerCase()
    };
    searchIndex.push(item);
    // 建立反向索引用于快速查找
    const key = `${item.vul_type}_${item.severity}`.toLowerCase();
    if(!searchIndexMap.has(key)){
      searchIndexMap.set(key, []);
    }
    searchIndexMap.get(key).push(item);
  });
}

function performSearch(query){
  if(!query.trim()) return [];
  const q = query.toLowerCase().trim();
  
  // 优化：如果查询很短，使用精确匹配优化
  if(q.length <= 3){
    // 尝试精确匹配类型或严重性
    const exactMatch = searchIndexMap.get(q);
    if(exactMatch && exactMatch.length > 0){
      return exactMatch;
    }
  }
  
  // 模糊匹配
  const results = [];
  const qWords = q.split(/\s+/).filter(w => w.length > 0);
  
  // 使用Set去重，提升性能
  const seen = new Set();
  
  for(const item of searchIndex){
    // 多关键词匹配：所有关键词都必须出现
    const itemText = item.text;
    if(qWords.every(word => itemText.includes(word))){
      if(!seen.has(item.index)){
        seen.add(item.index);
        results.push(item);
      }
    }
  }
  
  return results;
}

function showSearchModal(){
  const searchEl = document.getElementById('globalSearch');
  const inputEl = document.getElementById('searchInput');
  if(searchEl && inputEl){
    searchEl.classList.remove('hidden');
    inputEl.focus();
    inputEl.select();
  }
}

function hideSearchModal(){
  const searchEl = document.getElementById('globalSearch');
  const inputEl = document.getElementById('searchInput');
  if(searchEl){
    searchEl.classList.add('hidden');
    if(inputEl) inputEl.value = '';
  }
}

function renderSearchResults(query){
  const resultsEl = document.getElementById('searchResults');
  if(!resultsEl) return;
  
  if(!query.trim()){
    resultsEl.innerHTML = '<div class="tip" style="padding:16px;text-align:center;color:var(--muted)">输入关键词搜索漏洞...</div>';
    return;
  }
  
  const results = performSearch(query);
  if(results.length === 0){
    resultsEl.innerHTML = '<div class="tip" style="padding:16px;text-align:center;color:var(--muted)">未找到匹配结果</div>';
    return;
  }
  
  resultsEl.innerHTML = results.slice(0, 20).map(item => {
    const v = window.__lastScanData?.vulnerabilities?.[item.index];
    if(!v) return '';
    const highlighted = (text) => {
      if(!text) return '';
      const q = query.toLowerCase();
      const textLower = text.toLowerCase();
      const idx = textLower.indexOf(q);
      if(idx === -1) return text;
      return text.slice(0, idx) + 
        `<span class="highlight">${text.slice(idx, idx + q.length)}</span>` + 
        text.slice(idx + q.length);
    };
    return `
      <div class="search-result-item" onclick="scrollToVuln(${item.index}); hideSearchModal();">
        <div style="display:flex;justify-content:space-between;align-items:start">
          <div style="flex:1">
            <strong>${highlighted(item.vul_type)}</strong>
            <span class="sev ${item.severity}" style="margin-left:8px">${item.severity}</span>
          </div>
        </div>
        <div style="color:var(--muted);font-size:12px;margin-top:4px">
          ${item.file_path ? `📁 ${highlighted(item.file_path)}` : ''}
          ${item.sink ? ` · Sink: ${highlighted(item.sink)}` : ''}
        </div>
      </div>
    `;
  }).join('');
}

function scrollToVuln(index){
  // 滚动到对应的漏洞卡片
  const cards = document.querySelectorAll('#result .card');
  if(cards[index]){
    cards[index].scrollIntoView({behavior:'smooth', block:'center'});
    cards[index].style.animation = 'flash 1s';
    setTimeout(() => cards[index].style.animation = '', 1000);
    // 临时高亮
    cards[index].style.boxShadow = '0 0 0 3px rgba(43,130,217,0.5)';
    setTimeout(() => cards[index].style.boxShadow = '', 2000);
  }
}

// 批量操作功能
let selectedVulns = new Set();
function toggleVulnSelection(index){
  if(selectedVulns.has(index)){
    selectedVulns.delete(index);
  }else{
    selectedVulns.add(index);
  }
  updateBatchOpsBar();
  updateCardSelection();
}

function updateBatchOpsBar(){
  const bar = document.querySelector('.batch-ops-bar');
  const countEl = bar?.querySelector('.selected-count');
  if(bar && countEl){
    const count = selectedVulns.size;
    if(count > 0){
      bar.classList.add('active');
      countEl.textContent = `已选择 ${count} 项`;
    }else{
      bar.classList.remove('active');
    }
  }
}

function updateCardSelection(){
  document.querySelectorAll('#result .card').forEach((card) => {
    const idx = parseInt(card.dataset.vulnIndex);
    if(isNaN(idx)) return;
    
    if(selectedVulns.has(idx)){
      card.classList.add('selected');
      // 更新选择按钮文本
      const selectBtn = card.querySelector('.card-actions button[onclick*="toggleVulnSelection"]');
      if(selectBtn) selectBtn.textContent = '✓ 已选';
      if(!card.querySelector('.card-checkbox')){
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'card-checkbox';
        checkbox.checked = true;
        checkbox.onclick = (e) => { e.stopPropagation(); toggleVulnSelection(idx); };
        card.style.position = 'relative';
        card.appendChild(checkbox);
      }
    }else{
      card.classList.remove('selected');
      const checkbox = card.querySelector('.card-checkbox');
      if(checkbox) checkbox.remove();
      // 更新选择按钮文本
      const selectBtn = card.querySelector('.card-actions button[onclick*="toggleVulnSelection"]');
      if(selectBtn) selectBtn.textContent = '☐ 选择';
    }
  });
}

async function batchExportSelected(){
  if(selectedVulns.size === 0){
    toast('请先选择要导出的漏洞', 'warning');
    return;
  }
  const projectPath = document.getElementById('projectPath').value.trim();
  const rulesPath = document.getElementById('rulesPath').value.trim();
  if(!projectPath || !rulesPath){
    toast('请先填写项目路径和规则路径', 'warning');
    return;
  }
  
  const vulns = Array.from(selectedVulns).map(idx => {
    // 查找实际的漏洞数据
    const cards = document.querySelectorAll('#result .card');
    const card = cards[idx];
    if(!card) return null;
    const vulnIdx = parseInt(card.dataset.vulnIndex);
    return window.__lastScanData?.vulnerabilities?.[vulnIdx];
  }).filter(Boolean);
  
  if(vulns.length === 0){
    toast('未找到有效的漏洞数据', 'warning');
    return;
  }
  
  showLoading(`导出 ${vulns.length} 个选中漏洞...`, 20);
  try{
    const res = await fetch(getBase() + '/api/report', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        project_path: projectPath,
        rules_path: rulesPath,
        vulnerabilities: vulns,
        title: `批量导出_${vulns.length}个漏洞_${new Date().toISOString().slice(0,10)}`
      })
    });
    const text = await res.text();
    let data = {};
    try{ data = JSON.parse(text); }catch{ data = { detail: text }; }
    if(!res.ok) throw new Error(data.detail || text || '导出失败');
    hideLoading();
    toast(`批量导出成功：${data.output_dir}（${vulns.length} 项）`, 'success', 5000);
    selectedVulns.clear();
    updateBatchOpsBar();
    updateCardSelection();
  }catch(e){
    hideLoading();
    toast(`批量导出失败：${e.message||e}`, 'error', 5000);
  }
}

async function loadEngines(){
  const sel = document.getElementById('engine');
  try{
    const res = await fetch(getBase() + '/api/engines');
    const data = await res.json();
    sel.innerHTML='';
    const list = (data && data.engines && data.engines.length) ? data.engines : ['lite'];
    list.forEach(e=>{
      const opt = document.createElement('option');
      opt.value = e; opt.textContent = e==='original' ? '原始完整引擎（含代码提取）' : '轻量引擎（仅链路）';
      sel.appendChild(opt);
    });
  }catch(e){
    sel.innerHTML='';
    ['lite'].forEach(e=>{
      const opt = document.createElement('option');
      opt.value = e; opt.textContent = '轻量引擎（仅链路）';
      sel.appendChild(opt);
    });
    try{ document.getElementById('toast').textContent='后端引擎列表获取失败，使用默认轻量引擎'; document.getElementById('toast').classList.remove('hidden'); setTimeout(()=>document.getElementById('toast').classList.add('hidden'), 2500);}catch{}
  }
}

// 初始化事件监听器
document.getElementById('btnScan').onclick = scan;
document.getElementById('btnClear').onclick = ()=>{ 
  if(confirm('确定要清空所有扫描结果吗？')){
    resultEl.innerHTML=''; 
    summaryEl.textContent=''; 
    selectedVulns.clear();
    updateBatchOpsBar();
    if(window.__lastScanData) window.__lastScanData = null;
    searchIndex = [];
    toast('结果已清空', 'info');
  }
};

// 源码复制和格式化
document.getElementById('btnCopyCode')?.addEventListener('click', () => {
  const codeEl = document.getElementById('sourceCode');
  if(codeEl && codeEl.textContent.trim()){
    copyToClipboard(codeEl.textContent);
  }else{
    toast('没有可复制的代码', 'warning');
  }
});

document.getElementById('btnClearCode')?.addEventListener('click', () => {
  const codeEl = document.getElementById('sourceCode');
  if(codeEl) codeEl.textContent = '';
  toast('源码已清空', 'info');
});

document.getElementById('btnFormatCode')?.addEventListener('click', () => {
  const codeEl = document.getElementById('sourceCode');
  if(!codeEl || !codeEl.textContent.trim()){
    toast('没有可格式化的代码', 'warning');
    return;
  }
  // 简单的格式化：基本缩进和换行
  let code = codeEl.textContent;
  // 基本的格式化逻辑
  code = code.replace(/\}\s*\{/g, '}\n{');
  code = code.replace(/\{\s*/g, '{\n');
  code = code.replace(/\}\s*/g, '}\n');
  codeEl.textContent = code;
  toast('代码已格式化', 'success', 2000);
});

// 搜索功能
document.getElementById('btnSearch')?.addEventListener('click', showSearchModal);
document.getElementById('searchClose')?.addEventListener('click', hideSearchModal);
// 防抖优化：搜索输入防抖处理
let searchDebounceTimer = null;
document.getElementById('searchInput')?.addEventListener('input', (e) => {
  const query = e.target.value;
  
  // 清除之前的定时器
  if(searchDebounceTimer){
    clearTimeout(searchDebounceTimer);
  }
  
  // 如果查询为空，立即显示
  if(!query.trim()){
    renderSearchResults('');
    return;
  }
  
  // 防抖：300ms后执行搜索
  searchDebounceTimer = setTimeout(() => {
    renderSearchResults(query);
    searchDebounceTimer = null;
  }, 300);
});
document.getElementById('searchInput')?.addEventListener('keydown', (e) => {
  if(e.key === 'Escape') hideSearchModal();
  if(e.key === 'Enter'){
    const firstResult = document.querySelector('.search-result-item');
    if(firstResult) firstResult.click();
  }
});

// 快捷键支持
document.addEventListener('keydown', (e) => {
  // Ctrl+K 或 Cmd+K 打开搜索
  if((e.ctrlKey || e.metaKey) && e.key === 'k'){
    e.preventDefault();
    showSearchModal();
  }
  // Esc 关闭搜索/模态框
  if(e.key === 'Escape'){
    hideSearchModal();
    if(!modalEl.classList.contains('hidden')){
      modalEl.classList.add('hidden');
    }
  }
});

// 批量操作
document.getElementById('btnBatchOps')?.addEventListener('click', () => {
  const bar = document.querySelector('.batch-ops-bar');
  if(!bar) return;
  if(bar.classList.contains('active')){
    selectedVulns.clear();
    updateBatchOpsBar();
    updateCardSelection();
  }else{
    bar.classList.add('active');
  }
});

// 在漏洞卡片区域添加批量操作栏
const vulnsPanel = document.getElementById('view_vulns');
if(vulnsPanel && !vulnsPanel.querySelector('.batch-ops-bar')){
  const batchBar = document.createElement('div');
  batchBar.className = 'batch-ops-bar';
  batchBar.innerHTML = `
    <div>
      <span class="selected-count">已选择 0 项</span>
    </div>
    <div class="batch-actions">
      <button class="ghost" onclick="batchExportSelected()">导出选中</button>
      <button class="ghost" onclick="selectedVulns.clear(); updateBatchOpsBar(); updateCardSelection();">取消选择</button>
    </div>
  `;
  vulnsPanel.insertBefore(batchBar, vulnsPanel.querySelector('#result'));
}

document.getElementById('btnExport').onclick = async ()=>{
  const projectPath = document.getElementById('projectPath').value.trim();
  const rulesPath = document.getElementById('rulesPath').value.trim();
  if(!projectPath || !rulesPath){ 
    toast('请填写项目路径与规则路径', 'warning'); 
    return; 
  }
  
  showLoading('准备导出报告...', 10);
  try{
    // 若有上次扫描结果，则按当前筛选导出；否则回退后端重扫导出
    let payload = { project_path: projectPath, rules_path: rulesPath };
    if(window.__lastScanData && Array.isArray(window.__lastScanData.vulnerabilities)){
      // 复用与渲染一致的筛选逻辑
      const raw = window.__lastScanData.vulnerabilities;
      const { tmpl, others } = splitTemplateVulns(raw);
      // 主结果筛选
      const sevMain = (document.getElementById('mainSeverity')?.value||'').toLowerCase();
      const typeMain = (document.getElementById('mainTypeFilter')?.value||'').trim().toUpperCase();
      let viewOthers = others.slice();
      if(sevMain) viewOthers = viewOthers.filter(v=> (v.severity||'').toLowerCase()===sevMain);
      if(typeMain) viewOthers = viewOthers.filter(v=> (v.vul_type||'').toUpperCase().includes(typeMain));
      // 模板结果筛选
      const sevT = (document.getElementById('tmplSeverity')?.value||'').toLowerCase();
      const typeT = (document.getElementById('tmplTypeFilter')?.value||'').trim().toUpperCase();
      let viewTmpl = tmpl.slice();
      if(sevT) viewTmpl = viewTmpl.filter(v=> (v.severity||'').toLowerCase()===sevT);
      if(typeT) viewTmpl = viewTmpl.filter(v=> (v.vul_type||'').toUpperCase().includes(typeT));
      const merged = [...viewOthers, ...viewTmpl];
      payload.vulnerabilities = merged;
      const titleParts = [];
      if(sevMain||typeMain) titleParts.push(`Main:${sevMain||'all'}/${typeMain||'all'}`);
      if(sevT||typeT) titleParts.push(`Tpl:${sevT||'all'}/${typeT||'all'}`);
      if(titleParts.length) payload.title = `筛选导出(${titleParts.join(' | ')})`;
      payload.filters = {
        main: { severity: sevMain||'all', type: typeMain||'all' },
        template: { severity: sevT||'all', type: typeT||'all' }
      };
    }
    const res = await fetch('/api/report', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    const text = await res.text();
    let data = {};
    try{ data = JSON.parse(text); }catch{ data = { detail: text }; }
    if(!res.ok) throw new Error(data.detail || text || '导出失败');
    hideLoading();
    toast(`报告已生成：${data.output_dir}（条目：${data.count||0}）`, 'success', 5000);
  }catch(e){ 
    hideLoading();
    toast(`导出失败：${e.message||e}`, 'error', 5000); 
  }
};

// 左侧功能导航切换
// 左侧导航：点击切换视图（仪表盘/审计/AI/规则/漏洞/报告）
(function(){
  const map = {
    dashboard: 'view_dashboard',
    audit: 'view_audit',
    ai: 'view_ai',
    rules: 'view_rules',
    vulns: 'view_vulns',
    templates: 'view_templates',
    reports: 'view_reports'
  };
  const tabs = document.querySelectorAll('#featureList button');
  function activate(target){
    tabs.forEach(b=>b.classList.remove('active'));
    const btn = Array.from(tabs).find(b=>b.dataset.target===target);
    if(btn) btn.classList.add('active');
    const ids = Object.values(map);
    ids.forEach(id=>{
      const el = document.getElementById(id);
      if(el) el.style.display = (id===map[target]) ? '' : 'none';
    });
    document.getElementById(map[target])?.scrollIntoView({behavior:'smooth'});
  }
  tabs.forEach(b=>{
    b.addEventListener('click', ()=> activate(b.dataset.target));
  });
  // 仪表盘快捷操作
  document.getElementById('qaStart')?.addEventListener('click', ()=> document.getElementById('btnScan').click());
  document.getElementById('qaToggleTmpl')?.addEventListener('click', ()=>{
    const sel = document.getElementById('templateScan');
    sel.value = (sel.value==='on') ? 'off' : 'on';
    document.getElementById('metric_tmpl').textContent = (sel.value==='off') ? 'OFF' : 'ON';
  });
  document.getElementById('qaToggleLite')?.addEventListener('click', ()=>{
    const sel = document.getElementById('liteEnrich');
    sel.value = (sel.value==='on') ? 'off' : 'on';
  });
  document.getElementById('qaSwitchLite')?.addEventListener('click', ()=>{
    const sel = document.getElementById('engine'); sel.value='lite';
    document.getElementById('metric_engine').textContent = 'lite';
  });
  document.getElementById('qaSwitchOrig')?.addEventListener('click', ()=>{
    const sel = document.getElementById('engine'); sel.value='original';
    document.getElementById('metric_engine').textContent = 'original';
  });
  // 刷新指标按钮
  document.getElementById('btnRefreshMetrics')?.addEventListener('click', ()=>{
    pollPartial();
    toast('指标已刷新');
  });
  
  // 默认展示仪表盘
  activate('dashboard');

  // 模板独立扫描按钮
      // 模板扫描视图模式（全局）
  if(typeof window.currentTmplViewMode === 'undefined'){
    window.currentTmplViewMode = 'severity';
  }
  let lastTmplVulns = [];
  
  document.getElementById('btnTmplScan')?.addEventListener('click', async ()=>{
    const projectPath = document.getElementById('projectPath').value.trim();
    const rulesPath = document.getElementById('rulesPath').value.trim();
    if(!projectPath || !rulesPath){ toast('请填写项目路径与规则路径'); return; }
    const btn = document.getElementById('btnTmplScan');
    const stopBtn = document.getElementById('btnStopScan');
    btn.disabled = true; btn.textContent = '扫描中...';
    if(stopBtn){ stopBtn.style.display = ''; }
    try{
      const liteEnrich = document.getElementById('liteEnrich')?.value || 'off';
      const ignoreSkip = !!document.getElementById('ignoreSkipDirs')?.checked;
      const applyMust = !!document.getElementById('applyMustSubTmpl')?.checked;
      const res = await fetch(getBase() + '/api/template-scan', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ project_path: projectPath, rules_path: rulesPath, lite_enrich: liteEnrich, ignore_skip_dirs: ignoreSkip, include_exts: ['jsp','jspx','html','java'], apply_must_substrings: applyMust }) });
      const data = await res.json();
      const wrap = document.getElementById('tmplResult');
      if(wrap) wrap.innerHTML = '';
      
      // 保存原始数据
      lastTmplVulns = data.vulnerabilities || [];
      
      // 统计信息回显
      const st = data.stats||{};
      renderTemplateSummary(lastTmplVulns);
      renderTmplStatsCards(lastTmplVulns);
      
      if(st.first_files && st.first_files.length){
        const p = document.createElement('div'); p.className='tip';
        p.textContent = '部分扫描文件示例：' + st.first_files.join(' | ');
        wrap.appendChild(p);
      }
      if(st.bad_patterns && st.bad_patterns.length){
        const p2 = document.createElement('div'); p2.className='tip';
        p2.textContent = '无效规则（已跳过）：' + st.bad_patterns.map(x=>`[${x[0]}]${x[1]}`).join(' | ');
        wrap.appendChild(p2);
      }
      
      // 应用筛选并渲染
      function applyTmplFilters(list){
        const sev = (document.getElementById('tmplSeverity')?.value || '').toLowerCase();
        const typeKey = (document.getElementById('tmplTypeFilter')?.value || '').trim().toUpperCase();
        const confThreshold = Number(document.getElementById('tmplConfidenceFilter')?.value||0) / 100;
        let out = list.slice();
        if(sev) out = out.filter(v=> (v.severity||'').toLowerCase()===sev);
        if(typeKey) out = out.filter(v=> (v.vul_type||'').toUpperCase().includes(typeKey));
        if(confThreshold > 0) out = out.filter(v=> (v.confidence||0) >= confThreshold);
        return out;
      }
      
      function renderTmplByViewMode(list){
        if(!wrap) return;
        const tips = wrap.querySelectorAll('.tip');
        wrap.innerHTML = '';
        tips.forEach(tip => wrap.appendChild(tip));
        
        if(list.length === 0){
          wrap.appendChild(document.createElement('div')).innerHTML = '<div class="empty-state"><div>暂无模板风险</div></div>';
          return;
        }
        
        const viewMode = window.currentTmplViewMode || 'severity';
        switch(viewMode){
          case 'severity':
            renderTmplBySeverity(list, container);
            break;
          case 'type':
            renderTmplByType(list, container);
            break;
          case 'confidence':
            renderTmplByConfidence(list, container);
            break;
          default:
            renderTmplAll(list, container);
        }
      }
      
      function renderTmplBySeverity(list, container){
        const targetWrap = container || wrap;
        const groups = {Critical:[], High:[], Medium:[], Low:[]};
        list.forEach(v=>{
          const sev = v.severity || 'Low';
          if(groups[sev]) groups[sev].push(v);
          else groups.Low.push(v);
        });
        ['Critical', 'High', 'Medium', 'Low'].forEach(sev=>{
          if(groups[sev].length === 0) return;
          const section = createCategorySection(sev, groups[sev].length, `tmpl_${sev}`);
          const body = section.querySelector('.category-body');
          groups[sev].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
            .forEach((v, idx)=> {
              const cardWrap = document.createElement('div');
              const tempEl = document.createElement('div');
              tempEl.style.display = 'none';
              document.body.appendChild(tempEl);
              const originalWrap = wrap;
              wrap = tempEl;
              renderTemplateCard(v, `${sev}_${idx}`);
              wrap = originalWrap;
              const card = tempEl.firstChild;
              if(card) cardWrap.appendChild(card);
              document.body.removeChild(tempEl);
              body.appendChild(cardWrap);
            });
          targetWrap.appendChild(section);
        });
      }
      
      function renderTmplByType(list, container){
        const targetWrap = container || wrap;
        const groups = {};
        list.forEach(v=>{ (groups[v.vul_type] ||= []).push(v); });
        Object.keys(groups).sort().forEach(type=>{
          const section = createCategorySection(type, groups[type].length, `tmpl_type_${type}`);
          const body = section.querySelector('.category-body');
          groups[type].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
            .forEach((v, idx)=> {
              const cardWrap = document.createElement('div');
              const tempEl = document.createElement('div');
              tempEl.style.display = 'none';
              document.body.appendChild(tempEl);
              const originalWrap = wrap;
              wrap = tempEl;
              renderTemplateCard(v, `${type}_${idx}`);
              wrap = originalWrap;
              const card = tempEl.firstChild;
              if(card) cardWrap.appendChild(card);
              document.body.removeChild(tempEl);
              body.appendChild(cardWrap);
            });
          targetWrap.appendChild(section);
        });
      }
      
      function renderTmplByConfidence(list, container){
        const targetWrap = container || wrap;
        const groups = {high:[], medium:[], low:[]};
        list.forEach(v=>{
          const conf = v.confidence || 0;
          if(conf > 0.7) groups.high.push(v);
          else if(conf > 0.4) groups.medium.push(v);
          else groups.low.push(v);
        });
        ['high', 'medium', 'low'].forEach(level=>{
          if(groups[level].length === 0) return;
          const labels = {high:'高置信度 (>0.7)', medium:'中置信度 (0.4-0.7)', low:'低置信度 (<0.4)'};
          const section = createCategorySection(labels[level], groups[level].length, `tmpl_conf_${level}`);
          const body = section.querySelector('.category-body');
          groups[level].sort((a,b)=> (b.confidence||0) - (a.confidence||0))
            .forEach((v, idx)=> {
              const cardWrap = document.createElement('div');
              const tempEl = document.createElement('div');
              tempEl.style.display = 'none';
              document.body.appendChild(tempEl);
              const originalWrap = wrap;
              wrap = tempEl;
              renderTemplateCard(v, `${level}_${idx}`);
              wrap = originalWrap;
              const card = tempEl.firstChild;
              if(card) cardWrap.appendChild(card);
              document.body.removeChild(tempEl);
              body.appendChild(cardWrap);
            });
          targetWrap.appendChild(section);
        });
      }
      
      function renderTmplAll(list, container){
        const targetWrap = container || wrap;
        list.sort((a,b)=> (b.confidence||0) - (a.confidence||0))
          .forEach((v, idx)=> renderTemplateCard(v, `all_${idx}`));
      }
      
      // 初始渲染
      const filtered = applyTmplFilters(lastTmplVulns);
      renderTmplByViewMode(filtered, wrap);
      
      // 绑定筛选事件
      const refreshTmplView = ()=>{
        const filtered = applyTmplFilters(lastTmplVulns);
        renderTmplByViewMode(filtered, wrap);
      };
      
      // 移除旧的事件监听器（避免重复绑定）
      ['tmplSeverity', 'tmplTypeFilter', 'tmplConfidenceFilter'].forEach(id=>{
        const el = document.getElementById(id);
        if(el){
          const newEl = el.cloneNode(true);
          el.parentNode.replaceChild(newEl, el);
        }
      });
      
      document.getElementById('tmplSeverity')?.addEventListener('change', refreshTmplView);
      document.getElementById('tmplTypeFilter')?.addEventListener('input', refreshTmplView);
      document.getElementById('tmplConfidenceFilter')?.addEventListener('input', (e)=>{
        document.getElementById('tmplConfValue').textContent = e.target.value + '%';
        refreshTmplView();
      });
      
      // 模板视图切换
      document.querySelectorAll('#tmplViewModeTabs .view-tab').forEach(tab=>{
        tab.addEventListener('click', ()=>{
          document.querySelectorAll('#tmplViewModeTabs .view-tab').forEach(t=>t.classList.remove('active'));
          tab.classList.add('active');
          window.currentTmplViewMode = tab.dataset.view;
          refreshTmplView();
        });
      });
      
    }catch(e){ toast('模板扫描失败: ' + (e.message||e)); }
    finally{ 
      btn.disabled=false; btn.textContent='开始模板扫描（仅模板）';
      const stopBtn = document.getElementById('btnStopScan');
      if(stopBtn){ stopBtn.style.display = 'none'; }
    }
  });
})();


// 批量生成 AI 总结（按钮在左侧设置区）
document.getElementById('btnAIAll')?.addEventListener('click', async ()=>{
  const apiKey = document.getElementById('apiKey').value;
  const apiBase = document.getElementById('apiBase').value;
  const model = document.getElementById('model').value;
  const prog = document.getElementById('aiAllProgress');
  if(!apiKey){ toast('请先填写 API Key'); return; }
  const cards = Array.from(document.querySelectorAll('#result .card'));
  let ok=0, fail=0;
  for(let i=0;i<cards.length;i++){
    try{
      const chainRows = cards[i].querySelectorAll('.chain-row span');
      if(!chainRows.length) continue;
      const chainText = chainRows[0].textContent || '';
      const chain = chainText.split(' → ').map(s=>s.trim()).filter(Boolean);
      await aiSummarize(chain);
      ok++;
    }catch(e){ fail++; }
    prog.textContent = `已生成：${ok}，失败：${fail}`;
    await new Promise(r=>setTimeout(r, 500));
  }
  toast('批量 AI 总结完成');
});


// 后端可用性检测，避免“没交互”的误判
async function checkBackend(){
  try{
    // 创建超时控制器
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    
    const res = await fetch(getBase() + '/api/ping', { 
      method: 'GET',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    if(!res.ok) throw new Error('后端未就绪');
    const data = await res.json();
    if(!data || !data.ok){ throw new Error('后端未就绪'); }
    return true;
  }catch(e){
    if(e.name === 'AbortError' || e.message?.includes('aborted')){
      toast('后端连接超时，请检查服务是否启动', 'error', 5000);
    }else{
      toast('后端未启动或端口被拦截，请先启动服务后再试', 'error', 5000);
    }
    return false;
  }
}

// 简易本地存储（不需要每次重填）
function savePref(id){ try{ localStorage.setItem('niuniu_'+id, document.getElementById(id).value); }catch{} }
function loadPref(id){ try{ const v = localStorage.getItem('niuniu_'+id); if(v!==null){ document.getElementById(id).value = v; } }catch{} }
['projectPath','rulesPath','backendUrl','engine','apiBase','model','apiKey','depth','maxChains','maxSeconds','displayMode'].forEach(loadPref);
['projectPath','rulesPath','backendUrl','engine','apiBase','model','apiKey','depth','maxChains','maxSeconds','displayMode'].forEach(id=>{
  const el = document.getElementById(id); if(el){ el.onchange = ()=>savePref(id); el.oninput = ()=>savePref(id); }
});
// 记住已选 sink 类型
function saveSelectedChips(){ try{ const sel = getSelectedSinkTypes(); localStorage.setItem('niuniu_sink_types', JSON.stringify(sel)); }catch{} }
function restoreSelectedChips(){ try{ const raw = localStorage.getItem('niuniu_sink_types'); if(!raw) return; const sel = JSON.parse(raw)||[]; Array.from(chipsEl.querySelectorAll('.chip')).forEach(ch=>{ if(sel.includes(ch.dataset.value)) ch.classList.add('active'); }); }catch{} }

// 复制代码按钮
document.getElementById('btnCopyCode')?.addEventListener('click', ()=>{
  const code = document.getElementById('sourceCode')?.textContent || '';
  if(!code.trim()){ toast('没有可复制的代码'); return; }
  navigator.clipboard.writeText(code).then(()=>{
    toast('代码已复制到剪贴板');
  }).catch(()=>{
    toast('复制失败，请手动选择复制');
  });
});

// 清空代码按钮
document.getElementById('btnClearCode')?.addEventListener('click', ()=>{
  const codeEl = document.getElementById('sourceCode');
  if(codeEl){ codeEl.textContent = ''; toast('已清空'); }
});

// 刷新进度按钮
document.getElementById('btnRefreshProgress')?.addEventListener('click', ()=>{
  pollPartial();
  toast('已刷新进度');
});

// 停止扫描按钮（当前扫描不支持中断，但可以显示提示）
document.getElementById('btnStopScan')?.addEventListener('click', async ()=>{
  try{
    const res = await fetch(getBase() + '/api/cancel', { method:'POST' });
    const data = await res.json();
    toast(data && data.message ? data.message : '已发送取消指令');
  }catch(e){ toast('取消失败'); }
});

// 页面初始化：先检查后端
checkBackend().then((ok)=>{
  loadSinkTypes().then(()=>restoreSelectedChips());
  loadEngines();
});
chipsEl.addEventListener('click', saveSelectedChips);
