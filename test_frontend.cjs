const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function harness() {
  const elements = new Map();
  const element = () => ({ textContent: '', innerHTML: '', className: '', children: [],
    classList: { add() {}, remove() {} }, appendChild(child) { this.children.push(child); } });
  const ctx = vm.createContext({ console, document: {
    cookie: 'brandsentinel_csrf=test-csrf', addEventListener() {},
    getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
    createElement: element
  }});
  vm.runInContext(fs.readFileSync('static/js/app.js', 'utf8'), ctx);
  vm.runInContext(`renderCategoryCounts = () => {}; renderFindingsTable = () => {};
    selectFinding = () => {}; triggerToast = (title, message) => { globalThis.toast = {title, message}; };
    appData.findings = [{id:'finding-1', target_name:'Test', status:'Flagged'}];
    selectedFindingId = 'finding-1';`, ctx);
  return { ctx, elements };
}

test('rejected reviews preserve the displayed status and send CSRF', async () => {
  const {ctx} = harness();
  ctx.fetch = async (url, options) => {
    assert.equal(options.headers['X-CSRF-Token'], 'test-csrf');
    return {ok:false, json:async () => ({error:'Permission denied'})};
  };
  await vm.runInContext('handleWhitelistFinding()', ctx);
  assert.equal(vm.runInContext('appData.findings[0].status', ctx), 'Flagged');
  assert.equal(ctx.toast.title, 'Review not saved');
});

test('successful reviews update only after the response', async () => {
  const {ctx} = harness();
  ctx.fetch = async () => {
    assert.equal(vm.runInContext('appData.findings[0].status', ctx), 'Flagged');
    return {ok:true, json:async () => ({status:'whitelisted'})};
  };
  await vm.runInContext('handleWhitelistFinding()', ctx);
  assert.equal(vm.runInContext('appData.findings[0].status', ctx), 'Whitelisted');
});

test('failed scans show readable provider errors and skipped coverage', () => {
  const {ctx, elements} = harness();
  vm.runInContext(`renderMultiScanSummary({status:'failed', sources_queried:['youtube','instagram'],
    failed_sources:[{provider:'youtube', message:'Quota exhausted'}],
    skipped_sources:[{provider:'instagram', reason:'Coming later'}]})`, ctx);
  assert.equal(elements.get('multiScanStatusPill').textContent, 'Scan Failed');
  assert.match(elements.get('multiScanFailureText').textContent, /youtube: Quota exhausted/);
  assert.doesNotMatch(elements.get('multiScanFailureText').textContent, /\[object Object\]/);
  assert.match(elements.get('multiScanCoveragePills').children[1].innerHTML, /Source skipped/);
});

test('zero risk and missing evidence never become fabricated high confidence', () => {
  const {ctx, elements} = harness();
  vm.runInContext(`renderEvidenceCard({target_name:'Test', risk_level:'Low', risk_score:0, match_score:0})`, ctx);
  assert.equal(elements.get('evidenceMatchScore').textContent, '0% Match');
  assert.equal(elements.get('evidenceRiskPill').textContent, 'Low Risk (0/100)');
  assert.equal(elements.get('evidenceVectorStats').textContent, 'Visual comparison not performed');
});

test('brand selection switches the actual scan context and findings', async () => {
  const {ctx} = harness();
  vm.runInContext('renderBrandProfile = async () => {}; toggleBrandDropdown = () => {};', ctx);
  ctx.fetch = async url => ({ok:true, json:async () => url.startsWith('/api/brands/')
    ? {id:'brand-two', name:'Second Brand'} : {findings:[]}});
  await vm.runInContext("selectBrand('brand-two', 'Second Brand')", ctx);
  assert.equal(vm.runInContext('appData.current_brand.id', ctx), 'brand-two');
  assert.equal(vm.runInContext('appData.findings.length', ctx), 0);
  assert.equal(vm.runInContext('selectedFindingId', ctx), null);
});
