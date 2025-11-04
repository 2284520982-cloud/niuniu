// 视图管理组件
export class ViewManager {
  constructor() {
    console.log('ViewManager constructor called');
    this.views = new Map();
    this.currentView = null;
    try {
      this.init();
    } catch (e) {
      console.error('ViewManager init error:', e);
      throw e;
    }
  }

  init() {
    console.log('ViewManager.init() called');
    // 初始化视图映射
    const viewMap = {
      dashboard: 'view_dashboard',
      audit: 'view_audit',
      ai: 'view_ai',
      rules: 'view_rules',
      vulns: 'view_vulns',
      templates: 'view_templates',
      reports: 'view_reports'
    };

    // 注册所有视图
    Object.entries(viewMap).forEach(([key, id]) => {
      const element = document.getElementById(id);
      if (element) {
        this.views.set(key, { id, element });
        console.log(`View registered: ${key} -> ${id}`);
      } else {
        console.warn(`View element not found: ${id}`);
      }
    });

    // 绑定导航按钮
    const featureList = document.querySelectorAll('#featureList button');
    console.log(`Found ${featureList.length} navigation buttons`);
    featureList.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.dataset.target;
        console.log('Navigation button clicked:', target);
        if (target) {
          this.show(target);
        }
      });
    });

    // 默认显示仪表盘
    this.show('dashboard');
    console.log('ViewManager initialization complete');
  }

  show(viewKey) {
    // 隐藏所有视图
    this.views.forEach(({ element }) => {
      element.style.display = 'none';
    });

    // 更新导航按钮状态
    document.querySelectorAll('#featureList button').forEach(btn => {
      btn.classList.remove('active');
      if (btn.dataset.target === viewKey) {
        btn.classList.add('active');
      }
    });

    // 显示目标视图
    const view = this.views.get(viewKey);
    if (view) {
      view.element.style.display = '';
      this.currentView = viewKey;
      // 平滑滚动到视图
      view.element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  getCurrentView() {
    return this.currentView;
  }
}

