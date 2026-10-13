const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness() {
  const elements = new Map();

  function makeElement(id, tagName = 'div') {
    const el = {
      id,
      tagName: tagName.toUpperCase(),
      classList: {
        _classes: new Set(),
        add(...cls) { cls.forEach(c => this._classes.add(c)); },
        remove(...cls) { cls.forEach(c => this._classes.delete(c)); },
        contains(c) { return this._classes.has(c); },
        toggle(c, force) {
          if (force === undefined) {
            if (this._classes.has(c)) this._classes.delete(c); else this._classes.add(c);
          } else if (force) {
            this._classes.add(c);
          } else {
            this._classes.delete(c);
          }
        }
      },
      textContent: '',
      value: '',
      innerHTML: '',
      children: [],
      appendChild(child) {
        this.children.push(child);
      },
      setAttribute(k, v) { this[k] = v; },
      getAttribute(k) { return this[k]; },
      style: {}
    };
    elements.set(id, el);
    return el;
  }

  // Register DOM elements
  makeElement('activeBrandName', 'span');
  makeElement('brandDropdown', 'div');
  makeElement('newBrandNameInput', 'input');
  makeElement('newBrandAliasesInput', 'input');
  makeElement('newBrandIndustryInput', 'input');
  makeElement('addBrandFormError', 'div');
  makeElement('addBrandModal', 'div');
  makeElement('brandProfileTitle', 'h2');
  makeElement('brandProfileIndustry', 'span');
  makeElement('brandProfileOrgId', 'code');
  makeElement('brandProfileAliasesList', 'div');
  makeElement('brandProfileDomainsList', 'div');
  makeElement('brandProfileHandlesList', 'div');
  makeElement('brandProfileAppsList', 'div');

  const storage = new Map();
  const localStorageMock = {
    getItem(k) { return storage.get(k) || null; },
    setItem(k, v) { storage.set(k, String(v)); },
    removeItem(k) { storage.delete(k); }
  };

  const windowMock = {
    URL: { createObjectURL: () => '', revokeObjectURL: () => {} }
  };

  const documentMock = {
    getElementById(id) {
      if (elements.has(id)) return elements.get(id);
      return makeElement(id);
    },
    createElement(tag) {
      return makeElement('gen_' + Math.random().toString(36).substring(7), tag);
    },
    addEventListener() {},
    cookie: 'brandsentinel_csrf=test-csrf-token'
  };

  const ctx = {
    window: windowMock,
    document: documentMock,
    localStorage: localStorageMock,
    URLSearchParams: global.URLSearchParams,
    console,
    fetch: async () => ({ ok: true, json: async () => ({}) }),
    triggerToast: () => {},
    updateSampleBanner: () => {},
    renderCategoryCounts: () => {},
    renderFindingsTable: () => {},
    renderDataSourcesPanel: () => {},
    renderApiConnectionsView: () => {},
    selectFinding: () => {},
    setTimeout: () => {}
  };

  vm.createContext(ctx);

  const rawCode = fs.readFileSync(path.join(__dirname, 'static', 'js', 'app.js'), 'utf-8');
  // Convert top-level `let appData` to `var appData` so it is accessible on context
  const appJsCode = rawCode.replace('let appData =', 'var appData =');
  vm.runInContext(appJsCode, ctx);

  return { ctx, elements, localStorageMock };
}

test('frontend renders top brand dropdown with all available brands including MG Indian Super League', () => {
  const { ctx, elements } = harness();

  ctx.appData.available_brands = [
    { id: 'brand-northstar-tech', name: 'Northstar Technologies', active_threats: 8 },
    { id: 'brand-northstar-athletics', name: 'Northstar Athletics', active_threats: 3 },
    { id: 'brand-northstar-fintech', name: 'Northstar FinTech', active_threats: 5 },
    { id: 'brand-mg-isl', name: 'MG Indian Super League', active_threats: 0 }
  ];
  ctx.appData.current_brand = { id: 'brand-mg-isl', name: 'MG Indian Super League' };

  vm.runInContext('renderBrandSelector()', ctx);

  const activeName = elements.get('activeBrandName');
  assert.equal(activeName.textContent, 'MG Indian Super League');

  const dropdown = elements.get('brandDropdown');
  assert.match(dropdown.innerHTML, /Select Monitored Brand/);
  assert.match(dropdown.innerHTML, /Northstar Technologies/);
  assert.match(dropdown.innerHTML, /Northstar Athletics/);
  assert.match(dropdown.innerHTML, /Northstar FinTech/);
  assert.match(dropdown.innerHTML, /MG Indian Super League/);
  assert.match(dropdown.innerHTML, /8 threats/);
  assert.match(dropdown.innerHTML, /selectBrand\('brand-mg-isl'/);
});

test('frontend selectBrand switches brand and saves to localStorage for refresh persistence', async () => {
  const { ctx, elements, localStorageMock } = harness();

  ctx.fetch = async (url) => {
    if (url.includes('/api/brands/brand-mg-isl')) {
      return {
        ok: true,
        json: async () => ({
          id: 'brand-mg-isl',
          name: 'MG Indian Super League',
          aliases: ['Indian Super League', 'ISL'],
          industry: 'Sports & Entertainment',
          official_assets: []
        })
      };
    }
    return { ok: true, json: async () => ({}) };
  };

  await vm.runInContext("selectBrand('brand-mg-isl', 'MG Indian Super League')", ctx);

  assert.equal(ctx.appData.current_brand.id, 'brand-mg-isl');
  assert.equal(localStorageMock.getItem('brandsentinel_selected_brand'), 'brand-mg-isl');
  assert.equal(elements.get('activeBrandName').textContent, 'MG Indian Super League');
});

test('frontend fetchAppData requests persisted brand from localStorage on refresh', async () => {
  const { ctx, localStorageMock } = harness();
  localStorageMock.setItem('brandsentinel_selected_brand', 'brand-mg-isl');

  const requestedUrls = [];
  ctx.fetch = async (url) => {
    requestedUrls.push(url);
    return {
      ok: true,
      json: async () => ({
        system_info: {},
        current_brand: { id: 'brand-mg-isl', name: 'MG Indian Super League' },
        available_brands: [
          { id: 'brand-northstar-tech', name: 'Northstar Technologies' },
          { id: 'brand-mg-isl', name: 'MG Indian Super League' }
        ],
        counts: {}
      })
    };
  };

  await vm.runInContext('fetchAppData()', ctx);

  assert.ok(requestedUrls.includes('/api/data?brand_id=brand-mg-isl'));
  assert.equal(ctx.appData.current_brand.name, 'MG Indian Super League');
});

test('frontend handleCreateBrand submits new brand and selects it', async () => {
  const { ctx, elements } = harness();

  elements.get('newBrandNameInput').value = 'MG Indian Super League';
  elements.get('newBrandAliasesInput').value = 'Indian Super League, ISL';
  elements.get('newBrandIndustryInput').value = 'Sports & Entertainment';

  let postedBody = null;
  ctx.fetch = async (url, opts) => {
    if (url === '/api/brands' && opts?.method === 'POST') {
      postedBody = JSON.parse(opts.body);
      return {
        ok: true,
        json: async () => ({
          message: 'Brand created successfully',
          brand: {
            id: 'brand-mg-isl',
            name: 'MG Indian Super League',
            aliases: ['Indian Super League', 'ISL'],
            industry: 'Sports & Entertainment'
          }
        })
      };
    }
    if (url.includes('/api/brands/brand-mg-isl')) {
      return {
        ok: true,
        json: async () => ({
          id: 'brand-mg-isl',
          name: 'MG Indian Super League',
          aliases: ['Indian Super League', 'ISL'],
          official_assets: []
        })
      };
    }
    return { ok: true, json: async () => ({}) };
  };

  await vm.runInContext(`handleCreateBrand({ preventDefault: () => {} })`, ctx);

  assert.equal(postedBody.name, 'MG Indian Super League');
  assert.deepEqual(postedBody.aliases, ['Indian Super League', 'ISL']);
  assert.equal(ctx.appData.current_brand.name, 'MG Indian Super League');
});
