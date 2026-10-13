// BrandSentinel Prototype Application State & Controller

let appData = {
  system_info: {},
  current_brand: {},
  available_brands: [],
  sources: [],
  findings: [],
  counts: { all: 0, social: 0, apps: 0, new: 0, in_review: 0, confirmed: 0, dismissed: 0, whitelisted: 0, flagged: 0 },
  pagination: { page: 1, per_page: 10, total: 0, total_pages: 1 },
  has_live_scans: false,
  is_sample_dataset: true
};

let currentCategory = 'all';
let currentSearch = '';
let currentRisk = 'all';
let currentStatus = 'all';
let currentSort = 'risk_desc';
let currentPage = 1;
let currentPerPage = 10;
let selectedFindingId = null;
let selectedRowIds = new Set();
let pendingReviewVerdict = 'in_review';

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Platform Icons SVG Map
const PLATFORM_ICONS = {
  youtube: `<svg class="w-4 h-4 text-rose-600" fill="currentColor" viewBox="0 0 24 24"><path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z"/></svg>`,
  telegram: `<svg class="w-4 h-4 text-sky-500" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.562 8.161c-.18.895-1.02 5.093-1.442 7.352-.178.955-.532 1.275-.873 1.306-.74.068-1.302-.489-2.02-.959-1.124-.736-1.758-1.194-2.85-1.913-1.261-.831-.444-1.288.275-2.036.188-.196 3.456-3.168 3.519-3.438.008-.034.015-.162-.061-.23-.076-.068-.188-.045-.27-.026-.115.026-1.944 1.235-5.489 3.627-.519.356-.989.531-1.41.522-.464-.01-1.356-.262-2.02-.477-.813-.264-1.46-.404-1.403-.853.03-.234.352-.474.965-.722 3.782-1.646 6.304-2.73 7.565-3.252 3.599-1.492 4.346-1.751 4.834-1.76.107-.002.348.025.504.152.132.107.168.252.185.353.018.107.037.332.02.483z"/></svg>`,
  facebook: `<svg class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 24 24"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`,
  instagram: `<svg class="w-4 h-4 text-pink-600" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/></svg>`,
  linkedin: `<svg class="w-4 h-4 text-sky-700" fill="currentColor" viewBox="0 0 24 24"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>`,
  twitter: `<svg class="w-4 h-4 text-sky-500" fill="currentColor" viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>`,
  playstore: `<svg class="w-4 h-4 text-emerald-600" fill="currentColor" viewBox="0 0 24 24"><path d="M3.609 1.814L13.792 12 3.61 22.186a2.008 2.008 0 0 1-.61-1.44V3.254c0-.555.228-1.07.61-1.44zM15.206 13.414l2.457 2.457-11.69 6.75 9.233-9.207zm2.457-2.828l-2.457 2.457-9.233-9.207 11.69 6.75zm1.574 1.828l3.155 1.821c1.042.602 1.042 1.583 0 2.185l-3.155 1.822-2.174-2.174 2.174-1.654z"/></svg>`,
  appstore: `<svg class="w-4 h-4 text-blue-600" fill="currentColor" viewBox="0 0 24 24"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.63 1.35-.58.67-.99 1.74-.88 2.76 1.01.08 2.04-.54 2.59-1.26z"/></svg>`,
  tiktok: `<svg class="w-4 h-4 text-slate-800" fill="currentColor" viewBox="0 0 24 24"><path d="M12.525.02c1.31-.02 2.61-.01 3.91-.02.08 1.53.63 3.09 1.75 4.17 1.12 1.11 2.7 1.62 4.24 1.79v4.03c-1.44-.05-2.89-.35-4.2-.97-.57-.26-1.1-.59-1.62-.97-.01 2.92.01 5.84-.02 8.75-.08 1.4-.54 2.79-1.35 3.94-1.31 1.92-3.58 3.17-5.91 3.21-1.43.08-2.86-.31-4.08-1.03-2.02-1.19-3.44-3.37-3.65-5.71-.02-.5-.03-1-.01-1.49.18-1.9 1.12-3.72 2.58-4.96 1.66-1.44 3.98-2.13 6.15-1.72.02 1.48-.04 2.96-.04 4.44-.99-.32-2.15-.23-3.02.37-.63.41-1.11 1.04-1.36 1.75-.21.51-.24 1.07-.14 1.61.24 1.16 1.18 2.09 2.35 2.27 1.25.21 2.58-.28 3.32-1.3.36-.5.54-1.1.56-1.71.02-3.64.01-7.29.01-10.93z"/></svg>`,
  discord: `<svg class="w-4 h-4 text-indigo-500" fill="currentColor" viewBox="0 0 24 24"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.929 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.894.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>`,
  globe: `<svg class="w-4 h-4 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>`
};

function getPlatformIcon(key) {
  const k = (key || '').toLowerCase().replace(/[-_]/g, '');
  if (k.includes('youtube')) return PLATFORM_ICONS.youtube;
  if (k.includes('telegram')) return PLATFORM_ICONS.telegram;
  if (k.includes('facebook') || k.includes('meta')) return PLATFORM_ICONS.facebook;
  if (k.includes('apple') || k.includes('appstore')) return PLATFORM_ICONS.appstore;
  if (k.includes('play') || k.includes('googleplay')) return PLATFORM_ICONS.playstore;
  if (k.includes('instagram')) return PLATFORM_ICONS.instagram;
  if (k.includes('linkedin')) return PLATFORM_ICONS.linkedin;
  if (k.includes('discord')) return PLATFORM_ICONS.discord;
  if (k.includes('tiktok')) return PLATFORM_ICONS.tiktok;
  if (k.includes('twitter') || k === 'x') return PLATFORM_ICONS.twitter;
  return PLATFORM_ICONS.globe;
}

function getStatusBadgeHtml(status) {
  const s = (status || 'not_configured').toLowerCase().replace(/\s+/g, '_');
  switch (s) {
    case 'connected':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>Connected</span>`;
    case 'limited_access':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-600"></span>Limited access</span>`;
    case 'expired':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-rose-600"></span>Expired</span>`;
    case 'rate_limited':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 text-purple-800 border border-purple-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-purple-600"></span>Rate limited</span>`;
    case 'unavailable':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-700 border border-slate-300 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>Unavailable</span>`;
    case 'coming_later':
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>Coming later</span>`;
    case 'not_configured':
    default:
      return `<span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600 border border-slate-200 inline-flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-slate-400"></span>Not configured</span>`;
  }
}

function formatCapabilityBadge(cap) {
  const capLabels = {
    searchCandidates: 'Search Candidates',
    lookupAsset: 'Lookup Asset',
    readAuthorizedChannel: 'Read Bot Channels',
    readManagedPages: 'Managed Pages Only',
    importRecords: 'Developer Import',
    searchPublicStore: 'Public Store Search',
    exportTelemetry: 'Export Telemetry'
  };
  const label = capLabels[cap] || cap;
  return `<span class="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-mono">${label}</span>`;
}

// Initialize Application on Page Load
document.addEventListener('DOMContentLoaded', async () => {
  setupDateDisplay();
  await fetchAppData();
  renderAllViews();
  const hash = window.location.hash.replace('#', '');
  if (['brand-profile', 'scan-review', 'api-connections', 'reports'].includes(hash)) {
    switchNav(hash);
  }
});

// Format today's date in header
function setupDateDisplay() {
  const d = new Date();
  const options = { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' };
  const dateElem = document.getElementById('currentDateDisplay');
  if (dateElem) {
    dateElem.textContent = d.toLocaleDateString('en-US', options);
  }
}

// Fetch Full Dataset from Flask API
async function fetchAppData() {
  try {
    let savedBrandId = '';
    try {
      savedBrandId = localStorage.getItem('brandsentinel_selected_brand') || '';
    } catch (e) {}

    const url = savedBrandId ? `/api/data?brand_id=${encodeURIComponent(savedBrandId)}` : '/api/data';
    const res = await fetch(url);
    if (res.ok) {
      const data = await res.json();
      appData = {
        ...appData,
        ...data,
        counts: data.counts || appData.counts,
        has_live_scans: !!data.has_live_scans,
        is_sample_dataset: !!data.is_sample_dataset
      };
      if (appData.current_brand && appData.current_brand.id) {
        try {
          localStorage.setItem('brandsentinel_selected_brand', appData.current_brand.id);
        } catch (e) {}
      }
    }
  } catch (err) {
    console.error('Failed to fetch API data, using fallback state:', err);
  }
  await fetchFindings();
}

// Fetch Paginated, Filtered, and Sorted Findings from API
async function fetchFindings() {
  const tbody = document.getElementById('findingsTableBody');
  if (tbody && tbody.children.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-400">Loading candidate findings...</td></tr>`;
  }

  try {
    const params = new URLSearchParams();
    if (appData.current_brand?.id) params.set('brand_id', appData.current_brand.id);
    if (currentCategory && currentCategory !== 'all') params.set('category', currentCategory);
    if (currentStatus && currentStatus !== 'all') params.set('status', currentStatus);
    if (currentRisk && currentRisk !== 'all') params.set('risk_level', currentRisk);
    if (currentSearch) params.set('search', currentSearch);
    if (currentSort) params.set('sort', currentSort);
    params.set('page', currentPage);
    params.set('per_page', currentPerPage);

    const res = await fetch(`/api/findings?${params.toString()}`);
    if (res.ok) {
      const data = await res.json();
      appData.findings = data.findings || [];
      appData.counts = data.counts || appData.counts;
      appData.pagination = {
        page: data.page || currentPage,
        per_page: data.per_page || currentPerPage,
        total: data.total ?? appData.findings.length,
        total_pages: data.total_pages || 1
      };
      if (typeof data.has_live_scans !== 'undefined') appData.has_live_scans = !!data.has_live_scans;
      if (typeof data.is_sample_dataset !== 'undefined') appData.is_sample_dataset = !!data.is_sample_dataset;
    }
  } catch (err) {
    console.error('Error fetching findings:', err);
  }

  updateSampleBanner();
  renderCategoryCounts();
  renderFindingsTable();

  // If no finding is selected or current selection is not in list, select first
  if (appData.findings && appData.findings.length > 0) {
    if (!selectedFindingId || !appData.findings.some(f => f.id === selectedFindingId)) {
      selectFinding(appData.findings[0].id);
    }
  }
}

// Toggle Prominent Sample Dataset Banner
function updateSampleBanner() {
  const banner = document.getElementById('sampleResultsBanner');
  if (banner) {
    if (appData.is_sample_dataset || !appData.has_live_scans) {
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
  }
}

// Render All Initial Components
function renderAllViews() {
  renderBrandSelector();
  renderCategoryCounts();
  renderFindingsTable();
  renderDataSourcesPanel();
  renderBrandProfile();
  renderApiConnectionsView();
  
  if (appData.findings && appData.findings.length > 0) {
    selectFinding(appData.findings[0].id);
  }
}

// Render Brand Information in Top Bar
function renderBrandSelector() {
  const brandName = document.getElementById('activeBrandName');
  if (brandName && appData.current_brand) {
    brandName.textContent = appData.current_brand.name || 'Northstar Technologies';
  }

  const dropdown = document.getElementById('brandDropdown');
  if (dropdown && Array.isArray(appData.available_brands) && appData.available_brands.length > 0) {
    let html = `
      <div class="px-3 py-1.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
        Select Monitored Brand
      </div>
    `;
    const curId = appData.current_brand?.id;
    appData.available_brands.forEach(b => {
      const isSelected = b.id === curId;
      const dotColor = isSelected ? 'bg-blue-600' : 'bg-slate-300';
      const threatText = (b.active_threats !== undefined && b.active_threats !== null) ? `${b.active_threats} threats` : '';
      html += `
        <button onclick="selectBrand('${escapeHtml(b.id)}', '${escapeHtml(b.name)}')" class="w-full text-left px-3.5 py-2 hover:bg-blue-50 flex items-center justify-between text-slate-800 font-medium ${isSelected ? 'bg-blue-50/60' : ''}">
          <span class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${dotColor}"></span>
            ${escapeHtml(b.name)}
          </span>
          <span class="text-[11px] text-slate-400 font-normal">${threatText}</span>
        </button>
      `;
    });
    dropdown.innerHTML = html;
  }

  const webSelect = document.getElementById('websiteBrandSelect');
  if (webSelect && Array.isArray(appData.available_brands)) {
    const curId = appData.current_brand?.id;
    webSelect.innerHTML = appData.available_brands.map(b => `
      <option value="${escapeHtml(b.id)}" ${b.id === curId ? 'selected' : ''}>
        ${escapeHtml(b.name)}
      </option>
    `).join('');
  }
}

// Calculate and Render Tab Badge Counts
function renderCategoryCounts() {
  const c = appData.counts || {};
  const bAll = document.getElementById('count-badge-all');
  const bSoc = document.getElementById('count-badge-social');
  const bApp = document.getElementById('count-badge-apps');

  if (bAll) bAll.textContent = c.all ?? (appData.findings || []).length;
  if (bSoc) bSoc.textContent = c.social ?? 0;
  if (bApp) bApp.textContent = c.apps ?? 0;

  const sidebarCount = document.getElementById('sidebarFlaggedCount');
  if (sidebarCount) {
    const unreviewed = (c.new || 0) + (c.in_review || 0) + (c.flagged || 0);
    sidebarCount.textContent = unreviewed || c.all || 0;
  }
}

// Format Review Status Badge HTML
function getFindingStatusBadgeHtml(status) {
  const s = (status || 'new').toLowerCase().replace(/[\s-]+/g, '_');
  if (s === 'confirmed' || s.includes('takedown')) {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-50 text-rose-700 border border-rose-200">Confirmed</span>`;
  } else if (s === 'in_review' || s === 'under_review') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-50 text-amber-800 border border-amber-200">In review</span>`;
  } else if (s === 'whitelisted') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">Whitelisted</span>`;
  } else if (s === 'dismissed') {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-300">Dismissed</span>`;
  } else {
    return `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">New</span>`;
  }
}

// Filter and Render Results Table
function renderFindingsTable() {
  const tbody = document.getElementById('findingsTableBody');
  if (!tbody) return;

  tbody.innerHTML = '';
  const list = appData.findings || [];
  const pag = appData.pagination || { page: 1, total_pages: 1, total: list.length };

  // Update Status Count Text
  const countText = document.getElementById('tableRecordCountText');
  if (countText) {
    countText.textContent = `Showing ${list.length} of ${pag.total} findings (${currentCategory.toUpperCase()})`;
  }

  // Update Pagination Controls
  const pageIndicator = document.getElementById('pageIndicatorText');
  if (pageIndicator) {
    pageIndicator.textContent = `Page ${pag.page} of ${Math.max(pag.total_pages, 1)}`;
  }
  const btnPrev = document.getElementById('btnPrevPage');
  const btnNext = document.getElementById('btnNextPage');
  if (btnPrev) btnPrev.disabled = pag.page <= 1;
  if (btnNext) btnNext.disabled = pag.page >= pag.total_pages;

  // Update Bulk Actions Bar
  updateBulkActionsBar();

  if (list.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center py-8 text-slate-400">
          <div class="flex flex-col items-center justify-center gap-2">
            <svg class="w-8 h-8 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            <span class="font-medium text-slate-600">No impersonation findings match the active filters</span>
            <span class="text-[11px] text-slate-400">Try adjusting the search query, review status, or risk filters.</span>
            <button type="button" onclick="resetTableFilters()" class="mt-1 px-3 py-1 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors">
              Reset Filters
            </button>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  list.forEach(item => {
    const isSelected = item.id === selectedFindingId;
    const isChecked = selectedRowIds.has(item.id);
    const tr = document.createElement('tr');
    tr.id = `row-${item.id}`;
    tr.className = `table-row-hover smooth-trans cursor-pointer border-b border-slate-100 ${isSelected ? 'table-row-selected' : ''}`;
    tr.onclick = (e) => {
      if (e.target.tagName.toLowerCase() === 'input' || e.target.tagName.toLowerCase() === 'button' || e.target.closest('button')) return;
      selectFinding(item.id);
    };

    // Platform Icon
    const iconSvg = PLATFORM_ICONS[item.platform_icon] || PLATFORM_ICONS['globe'];

    // Severity Badge
    let riskBadge = '';
    const risk = (item.risk_level || '').toLowerCase();
    if (risk === 'critical') {
      riskBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
        <span class="w-1.5 h-1.5 rounded-full bg-rose-600"></span>Critical
      </span>`;
    } else if (risk === 'high') {
      riskBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-200">
        <span class="w-1.5 h-1.5 rounded-full bg-amber-600"></span>High
      </span>`;
    } else {
      riskBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 text-slate-700 border border-slate-200">
        <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>Medium
      </span>`;
    }

    // Status Badge
    const statusBadge = getFindingStatusBadgeHtml(item.status);
    const matchScoreStr = item.match_score_display || (typeof item.match_score === 'number' ? `${Math.round(item.match_score * 100)}%` : (item.match_score ? item.match_score.split(' ')[0] : '85%'));

    tr.innerHTML = `
      <td class="py-3 px-3 text-center">
        <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleRowCheck('${item.id}', this)" class="rounded border-slate-300 text-blue-600 focus:ring-blue-500 cursor-pointer">
      </td>
      <td class="py-3 px-3">
        <div class="flex items-center gap-2">
          <div class="w-6 h-6 rounded-md bg-slate-100 flex items-center justify-center shrink-0 border border-slate-200">
            ${iconSvg}
          </div>
          <div class="min-w-0">
            <span class="font-bold text-slate-900 block truncate max-w-[180px]">${escapeHtml(item.target_name)}</span>
            <span class="text-[10px] text-slate-600">${escapeHtml(item.detected_at || '')}</span>
          </div>
        </div>
      </td>
      <td class="py-3 px-3">
        <span class="text-slate-700 font-medium">${escapeHtml(item.platform || '')}</span>
      </td>
      <td class="py-3 px-3">
        ${riskBadge}
      </td>
      <td class="py-3 px-3">
        <span class="text-slate-800 text-[11px] truncate block max-w-[160px]">${escapeHtml(item.detection_type || '')}</span>
      </td>
      <td class="py-3 px-3">
        <div class="flex items-center gap-1.5">
          <div class="w-12 bg-slate-200 rounded-full h-1.5 overflow-hidden">
            <div class="bg-blue-600 h-full" style="width: ${Math.min(item.risk_score || 85, 100)}%"></div>
          </div>
          <span class="font-mono text-[10px] text-slate-600">${matchScoreStr}</span>
        </div>
      </td>
      <td class="py-3 px-3">
        ${statusBadge}
      </td>
      <td class="py-3 px-3 text-right">
        <button type="button" onclick="selectFinding('${item.id}')" class="px-2.5 py-1 rounded bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-700 font-medium text-[11px] transition-colors">
          Inspect
        </button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

// Select a specific row and update the Evidence Card
async function selectFinding(id) {
  selectedFindingId = id;

  // Highlight selected row in table
  document.querySelectorAll('#findingsTableBody tr').forEach(row => {
    row.classList.remove('table-row-selected');
  });
  const rowElem = document.getElementById(`row-${id}`);
  if (rowElem) {
    rowElem.classList.add('table-row-selected');
  }

  let finding = (appData.findings || []).find(f => f.id === id);
  if (!finding) return;

  // Fetch complete details and review history from API
  try {
    const res = await fetch(`/api/findings/${id}`);
    if (res.ok) {
      const detailed = await res.json();
      finding = { ...finding, ...detailed };
      const idx = appData.findings.findIndex(f => f.id === id);
      if (idx !== -1) appData.findings[idx] = finding;
    }
  } catch (err) {
    console.warn('Using cached finding data:', err);
  }

  renderEvidenceCard(finding);
}

// Normalize Verdict Key
function normalizeVerdictKey(status) {
  const s = (status || 'new').toLowerCase().replace(/[\s-]+/g, '_');
  if (s === 'confirmed' || s.includes('takedown')) return 'confirmed';
  if (s === 'in_review' || s === 'under_review') return 'in_review';
  if (s === 'whitelisted') return 'whitelisted';
  if (s === 'dismissed') return 'dismissed';
  return 'new';
}

function formatVerdictLabel(verdict) {
  const v = (verdict || 'new').toLowerCase().replace(/[\s-]+/g, '_');
  if (v === 'in_review') return 'In review';
  if (v === 'confirmed') return 'Confirmed';
  if (v === 'dismissed') return 'Dismissed';
  if (v === 'whitelisted') return 'Whitelisted';
  if (v === 'new') return 'New';
  return verdict;
}

// Populate the Evidence Card with Forensic Details & Review Controls
function renderEvidenceCard(f) {
  const targetName = document.getElementById('evidenceTargetName');
  const targetHandle = document.getElementById('evidenceTargetHandle');
  const targetAudience = document.getElementById('evidenceTargetAudience');
  const targetAge = document.getElementById('evidenceTargetAge');
  const matchScore = document.getElementById('evidenceMatchScore');
  const platformBadge = document.getElementById('evidencePlatformBadge');
  const riskPill = document.getElementById('evidenceRiskPill');
  const statusBadge = document.getElementById('evidenceStatusBadge');
  const officialHandle = document.getElementById('evidenceOfficialHandle');
  const officialAudience = document.getElementById('evidenceOfficialAudience');
  const vectorStats = document.getElementById('evidenceVectorStats');
  const hostTelemetry = document.getElementById('evidenceHostTelemetry');
  const violationsList = document.getElementById('evidenceViolationsList');
  const sourceLink = document.getElementById('evidenceSourceLink');
  const sourceLinkText = document.getElementById('evidenceSourceLinkText');
  const assessmentExplanation = document.getElementById('evidenceAssessmentExplanation');
  const corroboratingList = document.getElementById('evidenceCorroboratingSignalsList');
  const missingEvidenceNotice = document.getElementById('evidenceMissingEvidenceNotice');

  if (targetName) targetName.textContent = f.target_name || f.candidate?.display_name || 'Suspect Asset';
  if (targetHandle) targetHandle.textContent = f.evidence?.target_handle || f.candidate?.package_or_handle || f.target_name;
  if (targetAudience) targetAudience.textContent = f.evidence?.audience || (f.candidate?.publisher_id ? `Publisher: ${f.candidate.publisher_id}` : 'Audience metrics unavailable');
  if (targetAge) targetAge.textContent = f.evidence?.account_age || (f.detected_at ? `Observed: ${f.detected_at}` : 'Recent candidate discovery');
  if (matchScore) matchScore.textContent = f.match_score_display || (typeof f.match_score === 'number' ? `${Math.round(f.match_score * 100)}% Match` : f.match_score || 'Not assessed');
  if (platformBadge) platformBadge.textContent = `${f.platform || 'Platform'} Telemetry Integration`;
  
  if (officialHandle) officialHandle.textContent = f.evidence?.official_counterpart || '@northstar_tech';
  if (officialAudience) officialAudience.textContent = f.evidence?.official_audience || '248K verified enterprise followers';

  // Source URL External Link
  const rawUrl = f.candidate?.source_url || f.evidence?.source_url || f.source_url;
  if (rawUrl && (rawUrl.startsWith('http://') || rawUrl.startsWith('https://'))) {
    if (sourceLink) {
      sourceLink.href = rawUrl;
      sourceLink.classList.remove('opacity-40', 'pointer-events-none');
    }
    if (sourceLinkText) sourceLinkText.textContent = `Inspect External Source (${f.platform || 'Listing'})`;
  } else {
    if (sourceLink) {
      sourceLink.href = '#';
      sourceLink.classList.add('opacity-40', 'pointer-events-none');
    }
    if (sourceLinkText) sourceLinkText.textContent = 'No external source URL recorded';
  }

  // Risk Pill
  if (riskPill) {
    riskPill.textContent = `${f.risk_level || 'Medium'} Risk (${f.risk_score ?? 'N/A'}/100)`;
    const r = (f.risk_level || '').toLowerCase();
    if (r === 'critical') {
      riskPill.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-100 text-rose-800';
    } else if (r === 'high') {
      riskPill.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-100 text-amber-800';
    } else {
      riskPill.className = 'px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700';
    }
  }

  // Status Badge
  if (statusBadge) {
    statusBadge.innerHTML = getFindingStatusBadgeHtml(f.status);
  }

  // Assessment Rationale & Corroborating Signals
  if (assessmentExplanation) {
    assessmentExplanation.textContent = f.assessment_rationale || f.rationale || 'Detailed assessment rationale established impersonation risk based on multi-signal evidence evaluation.';
  }

  if (corroboratingList) {
    corroboratingList.innerHTML = '';
    const signals = f.corroborating_signals || f.evidence?.corroborating_signals || [];
    if (signals.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'Exact registered name and target string match evaluated against official brand registry.';
      corroboratingList.appendChild(li);
    } else {
      signals.forEach(sig => {
        const li = document.createElement('li');
        li.textContent = sig;
        corroboratingList.appendChild(li);
      });
    }
  }

  // Missing Evidence Notice
  if (missingEvidenceNotice) {
    const missing = f.missing_evidence_indicators || f.evidence?.missing_evidence_indicators;
    if (missing && missing.length > 0) {
      missingEvidenceNotice.textContent = `Missing-evidence notice: ${missing.join('. ')}`;
    } else {
      missingEvidenceNotice.textContent = 'Missing-evidence notice: Automated logo image comparison was not performed; visual likeness is unverified without image analysis.';
    }
  }

  // Technical Forensic Details
  if (vectorStats) {
    const vc = f.evidence?.visual_comparison;
    if (vc) {
      vectorStats.textContent = `${vc.logo_similarity || 'Visual pending'} • ${vc.color_palette || 'Palette unverified'}`;
    } else {
      vectorStats.textContent = 'String Levenshtein • Unicode normalized';
    }
  }

  if (hostTelemetry) {
    hostTelemetry.textContent = f.evidence?.host_telemetry || (f.candidate?.publisher_id ? `Publisher: ${f.candidate.publisher_id}` : 'Platform connector feed');
  }

  // Violations List
  if (violationsList) {
    violationsList.innerHTML = '';
    const violations = f.evidence?.violations || f.violations || ['Candidate identifier closely matches official trademark'];
    violations.forEach(v => {
      const li = document.createElement('li');
      li.textContent = v;
      violationsList.appendChild(li);
    });
  }

  // Set Verdict Selection to Match Current Status
  setReviewVerdictChoice(normalizeVerdictKey(f.status));

  // Render Persistent Review Audit History
  renderReviewHistory(f.reviews || []);
}

// Set Review Verdict Choice Button State
function setReviewVerdictChoice(verdict) {
  pendingReviewVerdict = verdict;
  const buttons = document.querySelectorAll('.verdict-btn');
  buttons.forEach(btn => {
    btn.classList.remove('ring-2', 'ring-blue-500', 'ring-amber-500', 'ring-rose-500', 'ring-emerald-500', 'ring-slate-500');
  });

  const activeBtn = document.getElementById(`btnVerdict-${verdict}`);
  if (activeBtn) {
    if (verdict === 'confirmed') activeBtn.classList.add('ring-2', 'ring-rose-500');
    else if (verdict === 'in_review') activeBtn.classList.add('ring-2', 'ring-amber-500');
    else if (verdict === 'whitelisted') activeBtn.classList.add('ring-2', 'ring-emerald-500');
    else if (verdict === 'dismissed') activeBtn.classList.add('ring-2', 'ring-slate-500');
    else activeBtn.classList.add('ring-2', 'ring-blue-500');
  }
}

// Submit Current Review with Analyst Notes
async function submitCurrentReview() {
  if (!selectedFindingId) {
    triggerToast('Select Finding', 'Please select a finding from the table first.');
    return;
  }

  const notesElem = document.getElementById('evidenceAnalystNotes');
  const notes = notesElem ? notesElem.value.trim() : '';

  try {
    const res = await fetch(`/api/findings/${selectedFindingId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        status: pendingReviewVerdict,
        notes: notes || undefined
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Failed to save review decision.');
    }

    if (notesElem) notesElem.value = '';

    triggerToast('Review Saved', `Finding marked as ${formatVerdictLabel(pendingReviewVerdict)}.`);
    
    await selectFinding(selectedFindingId);
    await fetchFindings();
  } catch (err) {
    console.error('Error saving review:', err);
    triggerToast('Review Error', err.message || 'Could not save review decision.');
  }
}

// Render Review History Timeline
function renderReviewHistory(reviews) {
  const container = document.getElementById('evidenceReviewHistoryList');
  if (!container) return;

  container.innerHTML = '';
  if (!reviews || reviews.length === 0) {
    container.innerHTML = `<div class="text-[11px] text-slate-400 italic">No formal review entries recorded yet.</div>`;
    return;
  }

  reviews.forEach(r => {
    const item = document.createElement('div');
    item.className = 'p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs flex flex-col gap-1';
    
    let badgeClass = 'bg-slate-100 text-slate-700 border border-slate-300';
    const v = (r.verdict || '').toLowerCase();
    if (v === 'confirmed' || v.includes('takedown')) badgeClass = 'bg-rose-50 text-rose-700 border border-rose-200';
    else if (v === 'in_review') badgeClass = 'bg-amber-50 text-amber-800 border border-amber-200';
    else if (v === 'whitelisted') badgeClass = 'bg-emerald-50 text-emerald-800 border border-emerald-200';
    else if (v === 'dismissed') badgeClass = 'bg-slate-100 text-slate-700 border border-slate-300';
    else if (v === 'new') badgeClass = 'bg-blue-50 text-blue-700 border border-blue-200';

    item.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="font-bold text-slate-800">${escapeHtml(r.reviewer_name || 'Analyst')} <span class="text-[10px] text-slate-500 font-normal">(${escapeHtml(r.reviewer_role || 'analyst')})</span></span>
        <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${badgeClass}">${formatVerdictLabel(r.verdict)}</span>
      </div>
      <div class="text-slate-600 text-[11px]">${escapeHtml(r.notes || 'Status updated.')}</div>
      <div class="text-[10px] text-slate-400">${escapeHtml(r.created_at || 'Just now')}</div>
    `;
    container.appendChild(item);
  });
}

// Render Data Sources List in Right-Side Panel
function renderDataSourcesPanel() {
  const container = document.getElementById('dataSourcesList');
  if (!container) return;

  container.innerHTML = '';
  const sources = appData.sources || [];

  sources.forEach(src => {
    const iconSvg = PLATFORM_ICONS[src.icon] || PLATFORM_ICONS['globe'];
    const card = document.createElement('div');
    card.className = `p-3 rounded-lg border ${src.connected ? 'border-slate-200 bg-white' : 'border-slate-200 bg-slate-50/60'} flex items-center justify-between gap-3 text-xs transition-all`;

    let statusBadge = '';
    if (src.connected) {
      statusBadge = `<span class="px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 font-semibold text-[10px] border border-emerald-200 flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>Connected
      </span>`;
    } else if (src.test_status === 'error' || src.status === 'Error') {
      statusBadge = `<span class="px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 font-semibold text-[10px] border border-rose-200 flex items-center gap-1" title="${src.status_message || 'Connection Error'}">
        <span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>Error
      </span>`;
    } else if (src.test_status === 'ready_to_connect' || src.status === 'Ready to Connect') {
      statusBadge = `<span class="px-2 py-0.5 rounded-full bg-amber-50 text-amber-700 font-semibold text-[10px] border border-amber-200 flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full bg-amber-500"></span>Ready
      </span>`;
    } else {
      statusBadge = `<span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 font-semibold text-[10px] border border-slate-200 flex items-center gap-1">
        <span class="w-1.5 h-1.5 rounded-full bg-slate-400"></span>Unconfigured
      </span>`;
    }

    card.innerHTML = `
      <div class="flex items-center gap-2.5 min-w-0">
        <div class="w-8 h-8 rounded-lg ${src.connected ? 'bg-blue-50 border border-blue-100 text-blue-600' : 'bg-slate-100 border border-slate-200 text-slate-400'} flex items-center justify-center shrink-0">
          ${iconSvg}
        </div>
        <div class="min-w-0">
          <div class="font-bold text-slate-900 truncate">${src.name}</div>
          <div class="text-[10px] text-slate-500 truncate">${src.rate_limit || src.status_message || ''}</div>
        </div>
      </div>

      <div class="flex items-center gap-2 shrink-0">
        ${statusBadge}
        <button onclick="openDataSourceModal('${src.id}')" class="px-2.5 py-1 rounded bg-slate-100 hover:bg-blue-50 hover:text-blue-600 text-slate-700 font-semibold text-[10px] border border-slate-200 transition-colors">
          ${src.connected ? 'Manage' : (src.is_configured ? 'Test' : 'Connect')}
        </button>
      </div>
    `;

    container.appendChild(card);
  });

  const activeCount = sources.filter(s => s.connected).length;
  const badge = document.getElementById('sidebarActiveSourcesCount');
  if (badge) {
    badge.textContent = `${activeCount} / ${sources.length}`;
  }
}

// Toggle Source Connection State via API
async function toggleSourceConnection(sourceId) {
  try {
    const res = await fetch('/api/sources', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({ id: sourceId, action: 'toggle' })
    });
    if (res.ok) {
      const data = await res.json();
      await fetchAppData();
      renderDataSourcesPanel();
      renderApiConnectionsView();
      triggerToast('Connector Updated', `${data.message}`);
    }
  } catch (e) {
    console.error('Error updating source connection:', e);
  }
}

// Toggle All Scan Sources Checkboxes
function toggleAllScanSources() {
  const checkboxes = document.querySelectorAll('input[name="multiSourceOption"]');
  const allChecked = Array.from(checkboxes).every(cb => cb.checked);
  checkboxes.forEach(cb => { cb.checked = !allChecked; });
}

// Render Multi-Source Scan Summary Card
function renderMultiScanSummary(result) {
  const card = document.getElementById('multiScanSummaryCard');
  if (!card) return;

  card.classList.remove('hidden');

  // Status pill
  const pill = document.getElementById('multiScanStatusPill');
  if (pill) {
    if (result.status === 'completed') {
      pill.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-emerald-100 text-emerald-800';
      pill.textContent = 'Scan Complete';
    } else {
      pill.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-amber-100 text-amber-800';
      pill.textContent = result.status === 'failed' ? 'Scan Failed' : 'Partial Success';
    }
  }

  // Query display
  const qDisplay = document.getElementById('multiScanQueryDisplay');
  if (qDisplay) qDisplay.textContent = `Query: "${result.query || ''}"`;

  // Timestamp
  const tDisplay = document.getElementById('multiScanTimestampDisplay');
  if (tDisplay) tDisplay.textContent = new Date().toLocaleTimeString();

  // Metrics numbers
  const sumSources = document.getElementById('sumSourcesQueried');
  const sumCandidates = document.getElementById('sumCandidatesExamined');
  const sumOfficial = document.getElementById('sumOfficialExcluded');
  const sumFlagged = document.getElementById('sumImpersonatorsFlagged');
  const sumInconclusive = document.getElementById('sumInconclusiveCount');

  if (sumSources) sumSources.textContent = (result.sources_queried || []).length;
  if (sumCandidates) sumCandidates.textContent = result.total_candidates || 0;
  if (sumOfficial) sumOfficial.textContent = result.official_excluded_count || 0;
  if (sumFlagged) sumFlagged.textContent = result.impersonators_flagged || 0;
  if (sumInconclusive) sumInconclusive.textContent = result.inconclusive_count || 0;

  // Telemetry Coverage Breakdown Pills
  const pillsContainer = document.getElementById('multiScanCoveragePills');
  if (pillsContainer) {
    pillsContainer.innerHTML = '';
    const breakdown = result.per_source_breakdown || {};
    const sources = (result.sources_queried || Object.keys(breakdown)).filter(Boolean);

    sources.forEach(src => {
      const stats = breakdown[src] || { candidates: 0, infringements: 0, official_matches: 0 };
      const failed = (result.failed_sources || []).some(item => (typeof item === 'string' ? item : item.provider) === src);
      const skipped = (result.skipped_sources || []).some(item => (typeof item === 'string' ? item : item.provider) === src);
      const chip = document.createElement('div');
      chip.className = `inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium ${failed ? 'bg-rose-50 border-rose-200 text-rose-800' : 'bg-slate-50 border-slate-200 text-slate-800'}`;
      chip.innerHTML = `
        <span class="w-2 h-2 rounded-full ${failed ? 'bg-rose-500' : skipped ? 'bg-amber-500' : 'bg-emerald-500'}"></span>
        <span class="font-bold capitalize">${src.replace(/_/g, ' ')}:</span>
        <span class="text-slate-600">${failed ? 'Provider failed' : skipped ? 'Source skipped / unavailable' : `${stats.candidates || 0} evaluated • ${stats.infringements || 0} flagged`}</span>
      `;
      pillsContainer.appendChild(chip);
    });
  }

  // Partial Failure Banner
  const failureBanner = document.getElementById('multiScanPartialFailureBanner');
  const failureText = document.getElementById('multiScanFailureText');
  const failed = [...(result.failed_sources || []), ...(result.skipped_sources || [])].map(item => typeof item === 'string' ? item : `${item.name || item.provider}: ${item.message || item.reason || 'Unavailable'}`);
  if (failureBanner && failureText) {
    if (failed.length > 0) {
      failureBanner.classList.remove('hidden');
      failureText.textContent = `Upstream issues encountered with: ${failed.join(', ')}. Unavailable sources do not establish that no threats exist. Results from successful sources are preserved.`;
    } else {
      failureBanner.classList.add('hidden');
    }
  }
}

// Handle Form Submission for Multi-Source Platform Scan
async function handleTriggerScan(e) {
  if (e) e.preventDefault();
  const input = document.getElementById('scanQueryInput');
  const query = input ? input.value.trim() : '';

  if (!query) {
    triggerToast('Input Required', 'Please enter a brand handle, app package, or domain to scan.');
    return;
  }

  // Determine selected sources from checkboxes
  const checkboxes = document.querySelectorAll('input[name="multiSourceOption"]:checked');
  let selectedSources = Array.from(checkboxes).map(cb => cb.value);

  // If no checkboxes checked, check dropdown or default to all
  if (selectedSources.length === 0) {
    const select = document.getElementById('scanSourceSelect');
    const val = select ? select.value : 'All Sources';
    if (val && val !== 'All Sources') {
      selectedSources = [val];
    } else {
      selectedSources = ['youtube', 'telegram', 'facebook', 'apple_app_store', 'google_play'];
    }
  }

  // Show scan progress modal animation
  const modal = document.getElementById('scanProgressModal');
  const pBar = document.getElementById('scanProgressBar');
  const pText = document.getElementById('scanProgressText');

  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }

  if (pBar) pBar.style.width = '25%';
  if (pText) pText.textContent = `Federating queries across ${selectedSources.length} target connector(s)...`;

  const scanBtn = document.getElementById('scanBtn');
  if (scanBtn) scanBtn.disabled = true;

  try {
    if (pBar) pBar.style.width = '60%';
    if (pText) pText.textContent = `Evaluating exact source-scoped identity matches against official registry...`;

    const res = await fetch('/api/scan/multi', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        query: query,
        sources: selectedSources,
        brand_id: appData.current_brand?.id || 'brand-northstar-tech'
      })
    });

    const result = await res.json();

    if (pBar) pBar.style.width = '100%';
    if (pText) pText.textContent = `Multi-source scan complete. Aggregating telemetry findings...`;

   setTimeout(async () => {
      if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
      }
      if (scanBtn) scanBtn.disabled = false;

      if (!res.ok) {
        triggerToast('Scan Error', result.error || 'Failed to complete multi-source scan.');
        return;
      }

      // Render Multi-Source Scan Summary Card
      renderMultiScanSummary(result);

      if (result.status === 'completed' || result.status === 'partial_success') {
        appData.has_live_scans = true;
        appData.is_sample_dataset = false;
        updateSampleBanner();
      }

      await fetchFindings();

      if (result.status === 'failed') {
        triggerToast('Scan Failed', 'No selected source completed successfully. Check the source errors and API connections.');
        return;
      }

      const statusMsg = result.status === 'partial_success' 
        ? `Partial scan completed with warnings. Preserved valid candidates.` 
        : `Federated scan complete. Evaluated ${result.total_candidates || 0} candidates across ${selectedSources.length} sources.`;
      triggerToast('Multi-Source Scan Complete', statusMsg);

    }, 400);

  } catch (err) {
    console.error('Scan API error:', err);
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
    if (scanBtn) scanBtn.disabled = false;
    triggerToast('Network Error', 'Failed to communicate with multi-source scan coordinator.');
  }
}

// Switch Category Tab (All, Social, Apps)
function switchCategoryTab(cat) {
  currentCategory = cat;
  currentPage = 1;

  ['all', 'social', 'apps'].forEach(c => {
    const btn = document.getElementById(`tab-${c}`);
    if (btn) {
      if (c === cat) {
        btn.className = 'px-3.5 py-1.5 text-xs font-bold rounded-md bg-white text-blue-700 shadow-xs transition-all flex items-center gap-1.5';
        btn.setAttribute('aria-selected', 'true');
      } else {
        btn.className = 'px-3.5 py-1.5 text-xs font-semibold rounded-md text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-all flex items-center gap-1.5';
        btn.setAttribute('aria-selected', 'false');
      }
    }
  });

  fetchFindings();
}

// Filter results table by search text
function handleTableSearch() {
  const input = document.getElementById('tableSearchInput');
  currentSearch = input ? input.value.trim() : '';
  currentPage = 1;
  fetchFindings();
}

// Filter results table by review status
function handleStatusFilter() {
  const select = document.getElementById('statusFilterSelect');
  currentStatus = select ? select.value : 'all';
  currentPage = 1;
  fetchFindings();
}

// Filter results table by risk severity
function handleRiskFilter() {
  const select = document.getElementById('riskFilterSelect');
  currentRisk = select ? select.value : 'all';
  currentPage = 1;
  fetchFindings();
}

// Sort results table
function handleSortBy() {
  const select = document.getElementById('sortBySelect');
  currentSort = select ? select.value : 'risk_desc';
  currentPage = 1;
  fetchFindings();
}

// Change items per page
function handlePerPageChange(val) {
  currentPerPage = parseInt(val, 10) || 10;
  currentPage = 1;
  fetchFindings();
}

// Pagination navigation
function goToPrevPage() {
  if (currentPage > 1) {
    currentPage--;
    fetchFindings();
  }
}

function goToNextPage() {
  const totalPages = appData.pagination?.total_pages || 1;
  if (currentPage < totalPages) {
    currentPage++;
    fetchFindings();
  }
}

// Reset all table filters
function resetTableFilters() {
  currentSearch = '';
  currentStatus = 'all';
  currentRisk = 'all';
  currentSort = 'risk_desc';
  currentPage = 1;

  const sInput = document.getElementById('tableSearchInput');
  if (sInput) sInput.value = '';
  const stSelect = document.getElementById('statusFilterSelect');
  if (stSelect) stSelect.value = 'all';
  const rSelect = document.getElementById('riskFilterSelect');
  if (rSelect) rSelect.value = 'all';
  const soSelect = document.getElementById('sortBySelect');
  if (soSelect) soSelect.value = 'risk_desc';

  fetchFindings();
}

// Toggle Checkbox for Row
function toggleRowCheck(id, checkbox) {
  if (checkbox.checked) {
    selectedRowIds.add(id);
  } else {
    selectedRowIds.delete(id);
  }
  updateBulkActionsBar();
}

// Toggle Select All Checkbox
function toggleSelectAll(masterCheckbox) {
  const list = appData.findings || [];
  if (masterCheckbox.checked) {
    list.forEach(item => selectedRowIds.add(item.id));
  } else {
    selectedRowIds.clear();
  }
  renderFindingsTable();
}

// Clear Row Selection
function clearRowSelection() {
  selectedRowIds.clear();
  const master = document.getElementById('selectAllCheckbox');
  if (master) master.checked = false;
  renderFindingsTable();
}

// Update Bulk Actions Bar Visibility
function updateBulkActionsBar() {
  const bar = document.getElementById('bulkActionsBar');
  const countSpan = document.getElementById('bulkSelectedCountText');
  if (!bar) return;

  if (selectedRowIds.size > 0) {
    bar.classList.remove('hidden');
    if (countSpan) countSpan.textContent = `${selectedRowIds.size} selected`;
  } else {
    bar.classList.add('hidden');
  }
}

// Bulk Status Update API Handler
async function handleBulkStatusUpdate(status) {
  const ids = Array.from(selectedRowIds);
  if (ids.length === 0) {
    triggerToast('No Selection', 'Please select one or more findings to update.');
    return;
  }

  try {
    const res = await fetch('/api/findings/bulk', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        detection_ids: ids,
        status: status,
        notes: `Bulk status update to ${formatVerdictLabel(status)}`
      })
    });

    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Bulk update failed.');
    }

    selectedRowIds.clear();
    const master = document.getElementById('selectAllCheckbox');
    if (master) master.checked = false;

    triggerToast('Bulk Update Complete', `Updated ${data.updated_count || ids.length} findings to ${formatVerdictLabel(status)}.`);
    await fetchFindings();
    if (selectedFindingId) await selectFinding(selectedFindingId);
  } catch (err) {
    console.error('Bulk update error:', err);
    triggerToast('Bulk Update Failed', err.message || 'Could not update findings.');
  }
}

// Quick Actions: Simulate Takedown and Whitelist
async function handleSimulateTakedown() {
  if (!selectedFindingId) return;
  pendingReviewVerdict = 'confirmed';
  const notesElem = document.getElementById('evidenceAnalystNotes');
  if (notesElem && !notesElem.value) notesElem.value = 'Simulated takedown request initiated';
  return submitCurrentReview();
}

async function handleWhitelistFinding() {
  if (!selectedFindingId) return;
  pendingReviewVerdict = 'whitelisted';
  const notesElem = document.getElementById('evidenceAnalystNotes');
  if (notesElem && !notesElem.value) notesElem.value = 'Official asset verified and whitelisted';
  return submitCurrentReview();
}

// Switch Primary Navigation Views
function switchNav(viewId, event) {
  if (event) event.preventDefault();

  const views = ['scan-review', 'brand-profile', 'api-connections', 'data-sources', 'reports'];

  views.forEach(v => {
    const viewElem = document.getElementById(`view-${v}`);
    const navElem = document.getElementById(`nav-${v}`);

    if (v === viewId) {
      if (viewElem) viewElem.classList.remove('hidden');
      if (navElem) {
        navElem.className = 'nav-item group flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-semibold text-white bg-blue-600 shadow-sm shadow-blue-700/50 transition-colors';
      }
    } else {
      if (viewElem) viewElem.classList.add('hidden');
      if (navElem) {
        navElem.className = 'nav-item group flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-navy-800 transition-colors';
      }
    }
  });

  if (viewId === 'data-sources') {
    loadDataSourcesView();
  }

  // Close mobile sidebar if open
  closeMobileSidebar();
}

// Render Brand Profile View
async function renderBrandProfile() {
  const currentBrand = appData.current_brand || {};
  const brandId = currentBrand.id || 'brand-northstar-tech';

  // Fetch complete brand record with official assets from API
  try {
    const res = await fetch(`/api/brands/${brandId}`);
    if (res.ok) {
      const detailedBrand = await res.json();
      appData.current_brand = detailedBrand;
    }
  } catch (err) {
    console.warn('Using cached brand details:', err);
  }

  const brand = appData.current_brand || {};

  // Header and Metadata
  const titleElem = document.getElementById('brandProfileTitle');
  const indElem = document.getElementById('brandProfileIndustry');
  const orgElem = document.getElementById('brandProfileOrgId');
  if (titleElem) titleElem.textContent = brand.name || 'Northstar Technologies';
  if (indElem) indElem.textContent = brand.industry || 'Enterprise Cloud & Cybersecurity';
  if (orgElem) orgElem.textContent = brand.organization_id || 'org-northstar-fictional';

  // Aliases List
  const aliasesContainer = document.getElementById('brandProfileAliasesList');
  if (aliasesContainer) {
    aliasesContainer.innerHTML = '';
    const aliases = brand.aliases || [];
    if (aliases.length === 0) {
      aliasesContainer.innerHTML = `<span class="text-xs text-slate-400 italic">No aliases registered. Click 'Edit Brand Details' to add aliases.</span>`;
    } else {
      aliases.forEach(a => {
        const span = document.createElement('span');
        span.className = 'px-2.5 py-1 rounded-lg bg-blue-50 text-blue-800 border border-blue-200 text-xs font-medium';
        span.textContent = a;
        aliasesContainer.appendChild(span);
      });
    }
  }

  // Official Assets Categorization
  const assets = brand.official_assets || [];
  const domains = assets.filter(a => a.asset_type === 'domain' || a.source_platform === 'domain');
  const socials = assets.filter(a => a.asset_type === 'social_account');
  const apps = assets.filter(a => a.asset_type === 'mobile_app');

  // Render Domains
  const domainsContainer = document.getElementById('brandProfileDomainsList');
  if (domainsContainer) {
    domainsContainer.innerHTML = '';
    if (domains.length === 0) {
      domainsContainer.innerHTML = `<div class="p-3 text-slate-400 text-xs italic">No official domains configured.</div>`;
    } else {
      domains.forEach(d => {
        const item = document.createElement('div');
        item.className = 'p-3 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-between';
        item.innerHTML = `
          <div>
            <div class="font-bold text-slate-900">${d.exact_identifier}</div>
            <div class="text-[10px] text-slate-500">${d.display_name || 'Primary FQDN'} • Exact Host Match</div>
          </div>
          <div class="flex items-center gap-2">
            <span class="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 text-[10px] font-bold">Verified</span>
            <button onclick="deleteOfficialAsset('${d.id}')" class="text-slate-400 hover:text-rose-600 p-1 rounded" title="Remove Asset">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </div>
        `;
        domainsContainer.appendChild(item);
      });
    }
  }

  // Render Social Accounts
  const handlesContainer = document.getElementById('brandProfileHandlesList');
  if (handlesContainer) {
    handlesContainer.innerHTML = '';
    if (socials.length === 0) {
      handlesContainer.innerHTML = `<div class="p-3 text-slate-400 text-xs italic">No official social channels configured.</div>`;
    } else {
      socials.forEach(s => {
        const item = document.createElement('div');
        item.className = 'p-3 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-between';
        item.innerHTML = `
          <div class="min-w-0">
            <div class="font-bold text-slate-900 flex items-center gap-1.5">
              <span>${s.exact_identifier}</span>
              <span class="text-[10px] text-slate-500 font-normal">(${s.source_platform})</span>
            </div>
            <div class="text-[10px] text-indigo-700 font-mono mt-0.5 truncate">
              Stable ID: ${s.stable_id}
            </div>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 text-[10px] font-bold">Verified</span>
            <button onclick="deleteOfficialAsset('${s.id}')" class="text-slate-400 hover:text-rose-600 p-1 rounded" title="Remove Asset">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </div>
        `;
        handlesContainer.appendChild(item);
      });
    }
  }

  // Render Mobile Apps
  const appsContainer = document.getElementById('brandProfileAppsList');
  if (appsContainer) {
    appsContainer.innerHTML = '';
    if (apps.length === 0) {
      appsContainer.innerHTML = `<div class="p-3 text-slate-400 text-xs italic">No official applications configured.</div>`;
    } else {
      apps.forEach(a => {
        const item = document.createElement('div');
        item.className = 'p-3 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-between';
        item.innerHTML = `
          <div class="min-w-0">
            <div class="font-bold text-slate-900">${a.display_name || a.exact_identifier}</div>
            <div class="text-[10px] text-slate-500">${a.source_platform} • ID: <code class="text-slate-700">${a.exact_identifier}</code></div>
            ${a.authorized_publisher_id ? `<div class="text-[10px] text-emerald-700 font-mono">Publisher: ${a.authorized_publisher_id}</div>` : ''}
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-800 text-[10px] font-bold">Production</span>
            <button onclick="deleteOfficialAsset('${a.id}')" class="text-slate-400 hover:text-rose-600 p-1 rounded" title="Remove Asset">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </div>
        `;
        appsContainer.appendChild(item);
      });
    }
  }
}

// Brand Setup & Editing Modal Handlers
function openEditBrandModal() {
  const brand = appData.current_brand || {};
  const nameInput = document.getElementById('editBrandNameInput');
  const aliasesInput = document.getElementById('editBrandAliasesInput');
  const indInput = document.getElementById('editBrandIndustryInput');
  const logoInput = document.getElementById('editBrandLogoUrlInput');
  const errBox = document.getElementById('brandFormError');

  if (nameInput) nameInput.value = brand.name || '';
  if (aliasesInput) aliasesInput.value = (brand.aliases || []).join(', ');
  if (indInput) indInput.value = brand.industry || '';
  if (logoInput) logoInput.value = brand.logo_url || '';
  if (errBox) errBox.classList.add('hidden');

  const modal = document.getElementById('editBrandModal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function closeEditBrandModal() {
  const modal = document.getElementById('editBrandModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

async function handleSaveBrandEdits(e) {
  e.preventDefault();
  const brand = appData.current_brand || {};
  const brandId = brand.id || 'brand-northstar-tech';

  const name = document.getElementById('editBrandNameInput').value.trim();
  const rawAliases = document.getElementById('editBrandAliasesInput').value;
  const industry = document.getElementById('editBrandIndustryInput').value.trim();
  const logo_url = document.getElementById('editBrandLogoUrlInput').value.trim();
  const errBox = document.getElementById('brandFormError');

  const aliases = rawAliases.split(',').map(a => a.trim()).filter(a => a.length > 0);

  try {
    const res = await fetch(`/api/brands/${brandId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
      body: JSON.stringify({ name, aliases, industry, logo_url })
    });

    const data = await res.json();
    if (!res.ok) {
      if (errBox) {
        errBox.textContent = data.error || 'Validation failed on server.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    closeEditBrandModal();
    triggerToast('Brand Profile Updated', `Saved brand name '${name}' and ${aliases.length} aliases.`);
    await renderBrandProfile();
    renderBrandSelector();
  } catch (err) {
    console.error('Failed to save brand edits:', err);
    if (errBox) {
      errBox.textContent = 'Server communication error.';
      errBox.classList.remove('hidden');
    }
  }
}

// Add Brand Modal Handlers
function openAddBrandModal() {
  const nameInput = document.getElementById('newBrandNameInput');
  const aliasesInput = document.getElementById('newBrandAliasesInput');
  const indInput = document.getElementById('newBrandIndustryInput');
  const errBox = document.getElementById('addBrandFormError');

  if (nameInput) nameInput.value = '';
  if (aliasesInput) aliasesInput.value = '';
  if (indInput) indInput.value = '';
  if (errBox) {
    errBox.textContent = '';
    errBox.classList.add('hidden');
  }

  const modal = document.getElementById('addBrandModal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function closeAddBrandModal() {
  const modal = document.getElementById('addBrandModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

async function handleCreateBrand(e) {
  e.preventDefault();
  const nameInput = document.getElementById('newBrandNameInput');
  const aliasesInput = document.getElementById('newBrandAliasesInput');
  const indInput = document.getElementById('newBrandIndustryInput');
  const errBox = document.getElementById('addBrandFormError');

  const name = nameInput ? nameInput.value.trim() : '';
  const rawAliases = aliasesInput ? aliasesInput.value : '';
  const industry = indInput ? indInput.value.trim() : 'General Enterprise';

  if (!name) {
    if (errBox) {
      errBox.textContent = 'Brand name is required.';
      errBox.classList.remove('hidden');
    }
    return;
  }

  const aliases = rawAliases.split(',').map(a => a.trim()).filter(a => a.length > 0);

  try {
    const res = await fetch('/api/brands', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        name,
        aliases,
        industry: industry || 'General Enterprise',
        is_sample: false
      })
    });

    const data = await res.json();
    if (!res.ok) {
      if (errBox) {
        errBox.textContent = data.error || 'Failed to create brand.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    const brand = data.brand;
    if (Array.isArray(appData.available_brands)) {
      const exists = appData.available_brands.some(b => b.id === brand.id);
      if (!exists) {
        appData.available_brands.push({
          id: brand.id,
          name: brand.name,
          aliases: brand.aliases || [],
          industry: brand.industry,
          active_threats: 0
        });
      }
    }

    closeAddBrandModal();
    await selectBrand(brand.id, brand.name);
    triggerToast(
      data.already_exists ? 'Brand Selected' : 'Brand Created',
      data.message || `Brand '${brand.name}' is now active.`
    );
  } catch (err) {
    console.error('Error creating brand:', err);
    if (errBox) {
      errBox.textContent = 'Server communication error.';
      errBox.classList.remove('hidden');
    }
  }
}

// Add Official Asset Modal Handlers
function openAddAssetModal(type = 'domain') {
  const select = document.getElementById('assetTypeSelect');
  if (select) select.value = type;
  toggleAssetTypeFields();

  const errBox = document.getElementById('assetFormError');
  if (errBox) errBox.classList.add('hidden');

  const modal = document.getElementById('addAssetModal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function closeAddAssetModal() {
  const modal = document.getElementById('addAssetModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

function toggleAssetTypeFields() {
  const type = document.getElementById('assetTypeSelect').value;
  const domSec = document.getElementById('domainFieldsSection');
  const socSec = document.getElementById('socialFieldsSection');
  const appSec = document.getElementById('appFieldsSection');

  if (domSec) domSec.classList.toggle('hidden', type !== 'domain');
  if (socSec) socSec.classList.toggle('hidden', type !== 'social_account');
  if (appSec) appSec.classList.toggle('hidden', type !== 'mobile_app');
}

async function handleSaveOfficialAsset(e) {
  e.preventDefault();
  const brand = appData.current_brand || {};
  const brandId = brand.id || 'brand-northstar-tech';
  const type = document.getElementById('assetTypeSelect').value;
  const errBox = document.getElementById('assetFormError');

  let payload = { asset_type: type };

  if (type === 'domain') {
    payload.domain = document.getElementById('domainInput').value.trim();
    payload.display_name = document.getElementById('domainDisplayName').value.trim() || payload.domain;
  } else if (type === 'social_account') {
    payload.source_platform = document.getElementById('socialPlatformSelect').value;
    payload.handle = document.getElementById('socialHandleInput').value.trim();
    payload.stable_account_id = document.getElementById('socialStableIdInput').value.trim();
  } else if (type === 'mobile_app') {
    payload.source_platform = document.getElementById('appStoreSelect').value;
    payload.package_or_app_id = document.getElementById('appPackageInput').value.trim();
    payload.stable_app_id = payload.package_or_app_id;
    payload.authorized_publisher_id = document.getElementById('appPublisherIdInput').value.trim();
    payload.authorized_publisher_name = document.getElementById('appPublisherNameInput').value.trim();
  }

  try {
    const res = await fetch(`/api/brands/${brandId}/assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok) {
      if (errBox) {
        errBox.textContent = data.error || 'Server validation failed.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    closeAddAssetModal();
    triggerToast('Official Asset Registered', data.message);
    renderBrandProfile();
  } catch (err) {
    console.error('Error saving asset:', err);
    if (errBox) {
      errBox.textContent = 'Server communication error.';
      errBox.classList.remove('hidden');
    }
  }
}

async function deleteOfficialAsset(assetId) {
  const brand = appData.current_brand || {};
  const brandId = brand.id || 'brand-northstar-tech';

  try {
    const res = await fetch(`/api/brands/${brandId}/assets/${assetId}`, {
      method: 'DELETE',
      headers: { 'X-CSRF-Token': getCsrfToken() }
    });
    if (res.ok) {
      triggerToast('Official Asset Removed', 'Asset successfully deleted from official registry.');
      renderBrandProfile();
    }
  } catch (err) {
    console.error('Error deleting asset:', err);
  }
}

// State cache for Platform Connector Catalog and Active Instances
let cachedCatalog = null;
let cachedConnections = [];

// Fetch Platform Catalog and Active Connections
async function loadConnectorsCatalog() {
  try {
    const [catalogRes, connRes] = await Promise.all([
      fetch('/api/connectors/catalog'),
      fetch('/api/connectors')
    ]);

    if (catalogRes.ok) {
      cachedCatalog = await catalogRes.json();
    }
    if (connRes.ok) {
      const data = await connRes.json();
      cachedConnections = data.connections || [];
    }
  } catch (err) {
    console.error('Failed to load connector catalog:', err);
  }
}

// Render API Connections View (Platform Catalog & Multi-Source Hub)
async function renderApiConnectionsView() {
  await loadConnectorsCatalog();
  if (!cachedCatalog) return;

  const implementedGrid = document.getElementById('implementedCatalogGrid');
  const comingLaterGrid = document.getElementById('comingLaterCatalogGrid');
  const countBadge = document.getElementById('activeAdapterCountBadge');

  if (countBadge && cachedCatalog.implemented) {
    countBadge.textContent = `${cachedCatalog.implemented.length} Available`;
  }

  // 1. Render Implemented Platforms
  if (implementedGrid) {
    implementedGrid.innerHTML = '';
    (cachedCatalog.implemented || []).forEach(connector => {
      // Find active connection instances for this provider
      const instances = (cachedConnections || []).filter(c => c.provider_id === connector.id);
      const isConfigured = instances.length > 0 || connector.is_configured;
      const primaryInstance = instances[0];

      // Determine status
      const status = primaryInstance ? primaryInstance.status : connector.status;
      const statusBadge = getStatusBadgeHtml(status);

      const card = document.createElement('div');
      card.className = 'bg-white rounded-xl border border-slate-200 card-shadow flex flex-col justify-between overflow-hidden transition-all hover:border-slate-300';
      
      const iconSvg = getPlatformIcon(connector.id);
      const capsBadges = (connector.supported_capabilities || []).map(formatCapabilityBadge).join('');

      card.innerHTML = `
        <div class="p-5 space-y-3.5">
          <!-- Card Header -->
          <div class="flex items-start justify-between gap-3">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shrink-0">
                ${iconSvg}
              </div>
              <div>
                <h3 class="font-bold text-slate-900 text-sm">${connector.name}</h3>
                <span class="text-[11px] text-slate-500 font-medium">${connector.auth_method}</span>
              </div>
            </div>
            <div>
              ${statusBadge}
            </div>
          </div>

          <!-- Capabilities -->
          <div class="space-y-1.5">
            <div class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Supported Capabilities</div>
            <div class="flex flex-wrap gap-1">
              ${capsBadges}
            </div>
          </div>

          <!-- Setup Requirements & Honest Limitations -->
          <div class="p-2.5 rounded-lg bg-slate-50 border border-slate-100 text-[11px] text-slate-600 space-y-1">
            <div class="font-semibold text-slate-800 text-[10px] uppercase tracking-wide">Access Boundaries & Scope</div>
            <p class="leading-relaxed line-clamp-2" title="${connector.limitations}">${connector.limitations}</p>
          </div>

          <!-- Connection Instances (Multi-connection support) -->
          ${instances.length > 0 ? `
            <div class="pt-2 border-t border-slate-100 space-y-1.5">
              <div class="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Active Instances (${instances.length}):</div>
              <div class="space-y-1 max-h-24 overflow-y-auto">
                ${instances.map(inst => `
                  <div class="flex items-center justify-between p-1.5 rounded bg-slate-50 border border-slate-200/60 text-xs">
                    <div class="min-w-0 pr-2">
                      <div class="font-semibold text-slate-800 truncate">${inst.name}</div>
                      <div class="text-[10px] text-slate-400">${inst.auth_method || 'Verified'}</div>
                    </div>
                    <div class="flex items-center gap-1 shrink-0">
                      <button onclick="testExistingConnection('${inst.id}')" class="px-2 py-0.5 rounded text-[10px] bg-white border border-slate-200 hover:bg-slate-100 text-slate-700 font-medium" title="Test Connection">
                        Test
                      </button>
                      <button onclick="openDynamicConnectionModal('${connector.id}', '${inst.id}')" class="px-2 py-0.5 rounded text-[10px] bg-white border border-slate-200 hover:bg-slate-100 text-blue-600 font-medium" title="Edit Connection">
                        Edit
                      </button>
                      <button onclick="deleteExistingConnection('${inst.id}')" class="p-0.5 text-slate-400 hover:text-rose-600 rounded" title="Delete Connection">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                      </button>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>
          ` : ''}

          <!-- Metadata: Last Tested & Scanned -->
          <div class="pt-2 border-t border-slate-100 grid grid-cols-2 gap-2 text-[10px] text-slate-500">
            <div>
              <span class="block text-slate-400">Last Verified:</span>
              <span class="font-medium text-slate-700">${primaryInstance && primaryInstance.last_tested_at ? new Date(primaryInstance.last_tested_at).toLocaleDateString() : (connector.last_tested_at ? new Date(connector.last_tested_at).toLocaleDateString() : 'Never')}</span>
            </div>
            <div>
              <span class="block text-slate-400">Last Scanned:</span>
              <span class="font-medium text-slate-700">${primaryInstance && primaryInstance.last_scan_at ? new Date(primaryInstance.last_scan_at).toLocaleDateString() : (connector.last_scan_at ? new Date(connector.last_scan_at).toLocaleDateString() : 'Never')}</span>
            </div>
          </div>
        </div>

        <!-- Card Footer Actions -->
        <div class="px-5 py-3 bg-slate-50/70 border-t border-slate-100 flex items-center justify-between gap-2">
          <div class="text-[11px] text-slate-500">
            ${isConfigured ? '<span class="text-emerald-700 font-medium">Ready for Scans</span>' : '<span class="text-slate-400">Not active</span>'}
          </div>
          <div class="flex items-center gap-2">
            <button onclick="openDynamicConnectionModal('${connector.id}')" class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors">
              ${instances.length > 0 ? '+ Add Instance' : 'Configure'}
            </button>
          </div>
        </div>
      `;

      implementedGrid.appendChild(card);
    });
  }

  // 2. Render Coming Later Platforms
  if (comingLaterGrid) {
    comingLaterGrid.innerHTML = '';
    (cachedCatalog.coming_later || []).forEach(item => {
      const card = document.createElement('div');
      card.className = 'bg-slate-50/70 rounded-xl border border-slate-200/80 p-5 flex flex-col justify-between space-y-3 opacity-80';

      const iconSvg = getPlatformIcon(item.id);
      const capsBadges = (item.supported_capabilities || []).map(formatCapabilityBadge).join('');

      card.innerHTML = `
        <div class="space-y-3">
          <div class="flex items-start justify-between gap-3">
            <div class="flex items-center gap-3">
              <div class="w-10 h-10 rounded-xl bg-slate-200/60 border border-slate-300/60 flex items-center justify-center text-slate-500 shrink-0">
                ${iconSvg}
              </div>
              <div>
                <h3 class="font-bold text-slate-800 text-sm">${item.name}</h3>
                <span class="text-[11px] text-slate-500 font-medium">${item.auth_method}</span>
              </div>
            </div>
            <div>
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-slate-200 text-slate-700 border border-slate-300 inline-flex items-center gap-1">
                <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>Coming later
              </span>
            </div>
          </div>

          <div class="space-y-1">
            <div class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Planned Capabilities</div>
            <div class="flex flex-wrap gap-1">
              ${capsBadges}
            </div>
          </div>

          <div class="p-2.5 rounded-lg bg-white border border-slate-200/60 text-[11px] text-slate-500 space-y-1">
            <div class="font-semibold text-slate-700 text-[10px] uppercase tracking-wide">Developer Review Status</div>
            <p class="leading-relaxed">${item.limitations || 'Pending partner verification and commercial developer access agreements. Live scanning is not available.'}</p>
          </div>
        </div>

        <div class="pt-3 border-t border-slate-200/60 flex items-center justify-between text-[11px]">
          <span class="text-slate-400 italic">Phase 7+ Roadmap</span>
          <button disabled class="px-3 py-1.5 rounded-lg bg-slate-200 text-slate-400 font-semibold text-xs cursor-not-allowed">
            Unavailable
          </button>
        </div>
      `;

      comingLaterGrid.appendChild(card);
    });
  }
}

// Open Dynamic Modal to Create Connection
function openCreateConnectionModal() {
  if (!cachedCatalog || !cachedCatalog.implemented || cachedCatalog.implemented.length === 0) return;
  const first = cachedCatalog.implemented[0];
  openDynamicConnectionModal(first.id);
  const platSec = document.getElementById('dynamicPlatformSelectSection');
  if (platSec) platSec.classList.remove('hidden');
}

// Platform selected in create modal
function handleDynamicPlatformSelected(providerId) {
  openDynamicConnectionModal(providerId);
  const platSec = document.getElementById('dynamicPlatformSelectSection');
  if (platSec) {
    platSec.classList.remove('hidden');
    const sel = document.getElementById('dynamicPlatformSelect');
    if (sel) sel.value = providerId;
  }
}

// Open Dynamic Connection Modal for a specific provider and optional connection instance
function openDynamicConnectionModal(providerId, connectionId) {
  if (!cachedCatalog) return;

  const connector = (cachedCatalog.implemented || []).find(c => c.id === providerId) || cachedCatalog.implemented[0];
  if (!connector) return;

  const instance = connectionId ? (cachedConnections || []).find(c => c.id === connectionId) : null;

  // Set hidden inputs
  document.getElementById('dynamicModalProviderId').value = connector.id;
  document.getElementById('dynamicModalConnectionId').value = connectionId || '';

  // Icon & Titles
  const iconContainer = document.getElementById('dynamicModalIcon');
  if (iconContainer) iconContainer.innerHTML = getPlatformIcon(connector.id);

  const titleElem = document.getElementById('dynamicModalTitle');
  if (titleElem) titleElem.textContent = instance ? `Edit Connection: ${instance.name}` : `Configure ${connector.name}`;

  const statusBadge = document.getElementById('dynamicModalStatusBadge');
  if (statusBadge) {
    statusBadge.outerHTML = `<span id="dynamicModalStatusBadge">${getStatusBadgeHtml(instance ? instance.status : connector.status)}</span>`;
  }

  // Hide platform selector when provider is known
  const platSec = document.getElementById('dynamicPlatformSelectSection');
  if (platSec) platSec.classList.add('hidden');

  // Capabilities & limitations
  const capsList = document.getElementById('dynamicModalCapabilitiesList');
  if (capsList) capsList.innerHTML = (connector.supported_capabilities || []).map(formatCapabilityBadge).join('');

  const limitsText = document.getElementById('dynamicModalLimitationsText');
  if (limitsText) limitsText.textContent = connector.limitations || '';

  // Accessible Assets Box
  const assetsBox = document.getElementById('dynamicModalAccessibleAssetsBox');
  const assetsContent = document.getElementById('dynamicModalAccessibleAssetsContent');
  if (assetsBox && assetsContent) {
    const granted = instance ? instance.granted_permissions : connector.granted_permissions;
    if (granted && Object.keys(granted).length > 0) {
      assetsBox.classList.remove('hidden');
      if (connector.id === 'telegram') {
        const chats = granted.accessible_chats || [];
        assetsContent.innerHTML = chats.length > 0 
          ? `<div><strong>Authorized Telegram Chats:</strong> ${chats.map(c => `<code class="bg-emerald-100 text-emerald-800 px-1 py-0.5 rounded font-mono text-[11px]">${c}</code>`).join(' ')}</div>`
          : `<div>Bot token verified with <code>@${granted.bot_username || 'bot'}</code>. Specify channel IDs below to permit monitoring.</div>`;
      } else if (connector.id === 'facebook') {
        const pages = (granted.managed_pages || []).map(p => p.name || p.id).join(', ');
        const perms = (granted.scopes || granted.granted_scopes || []).join(', ');
        assetsContent.innerHTML = `
          <div><strong>Accessible Pages:</strong> ${pages || 'None configured'}</div>
          <div><strong>Granted Permissions:</strong> <code>${perms || 'pages_read_engagement'}</code></div>
        `;
      } else {
        assetsContent.innerHTML = `<pre class="text-[10px] bg-emerald-100/60 p-2 rounded">${JSON.stringify(granted, null, 2)}</pre>`;
      }
    } else {
      assetsBox.classList.add('hidden');
    }
  }

  // Name & brand scope
  const nameInput = document.getElementById('dynamicConnectionName');
  if (nameInput) {
    nameInput.value = instance ? instance.name : `${connector.name} Connection`;
  }

  const brandSelect = document.getElementById('dynamicBrandScope');
  if (brandSelect) {
    brandSelect.innerHTML = '<option value="all">All Organization Brands</option>';
    const brands = appData.available_brands || [appData.current_brand];
    brands.forEach(b => {
      if (b && b.id) {
        const opt = document.createElement('option');
        opt.value = b.id;
        opt.textContent = b.name;
        if (instance && (instance.enabled_brand_ids || []).includes(b.id)) {
          opt.selected = true;
        }
        brandSelect.appendChild(opt);
      }
    });
  }

  // Dynamic Fields Container
  const fieldsContainer = document.getElementById('dynamicSchemaFieldsContainer');
  if (fieldsContainer) {
    fieldsContainer.innerHTML = '';
    const schema = connector.config_schema || {};

    (schema.fields || []).forEach(spec => {
  const key = spec.key;
      const fieldDiv = document.createElement('div');
      fieldDiv.className = 'space-y-1';

      const label = document.createElement('label');
      label.className = 'block font-semibold text-slate-800 text-xs';
      label.setAttribute('for', `field_${key}`);
      label.textContent = `${spec.label || key}${spec.required ? ' *' : ''}`;
      fieldDiv.appendChild(label);

      if (spec.type === 'password' || spec.type === 'secret') {
        const inputWrap = document.createElement('div');
        inputWrap.className = 'relative';

        const input = document.createElement('input');
        input.type = 'password';
        input.id = `field_${key}`;
        input.name = key;
        input.placeholder = instance ? '•••••••••••••••• (Leave blank to keep existing encrypted secret)' : (spec.placeholder || 'Enter secret key or token...');
        input.className = 'w-full pr-10 p-2.5 bg-slate-50 border border-slate-300 rounded-lg text-slate-900 font-mono text-xs focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500';
        if (!instance && spec.required) input.required = true;

        const eyeBtn = document.createElement('button');
        eyeBtn.type = 'button';
        eyeBtn.className = 'absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-700 disabled:opacity-30';
        eyeBtn.title = 'Toggle visibility for newly typed input';
        eyeBtn.disabled = true;
        eyeBtn.innerHTML = `
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>
        `;

        input.addEventListener('input', () => {
          eyeBtn.disabled = !input.value || input.value.trim().length === 0;
          if (eyeBtn.disabled) input.type = 'password';
        });

        eyeBtn.addEventListener('click', () => {
          if (!input.value) return;
          input.type = input.type === 'password' ? 'text' : 'password';
        });

        inputWrap.appendChild(input);
        inputWrap.appendChild(eyeBtn);
        fieldDiv.appendChild(inputWrap);

      } else if (spec.type === 'array') {
        const textarea = document.createElement('textarea');
        textarea.id = `field_${key}`;
        textarea.name = key;
        textarea.rows = 2;
        textarea.placeholder = spec.placeholder || 'Enter comma-separated values...';
        textarea.className = 'w-full p-2.5 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-mono text-xs focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500';
        
        if (instance && instance.config && instance.config[key]) {
          const val = instance.config[key];
          textarea.value = Array.isArray(val) ? val.join(', ') : val;
        }
        fieldDiv.appendChild(textarea);

      } else if (spec.type === 'select' && spec.options) {
        const select = document.createElement('select');
        select.id = `field_${key}`;
        select.name = key;
        select.className = 'w-full p-2.5 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 font-medium focus:outline-none focus:ring-2 focus:ring-blue-500';
        spec.options.forEach(opt => {
          const optEl = document.createElement('option');
          optEl.value = opt.value || opt;
          optEl.textContent = opt.label || opt;
          if (instance && instance.config && instance.config[key] === (opt.value || opt)) {
            optEl.selected = true;
          }
          select.appendChild(optEl);
        });
        fieldDiv.appendChild(select);

      } else {
        const input = document.createElement('input');
        input.type = 'text';
        input.id = `field_${key}`;
        input.name = key;
        input.placeholder = spec.placeholder || '';
        input.className = 'w-full p-2.5 bg-slate-50 border border-slate-300 rounded-lg text-slate-800 text-xs focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500';
        if (instance && instance.config && instance.config[key]) {
          input.value = instance.config[key];
        }
        fieldDiv.appendChild(input);
      }

      if (spec.description) {
        const help = document.createElement('p');
        help.className = 'text-[11px] text-slate-500 leading-normal';
        help.textContent = spec.description;
        fieldDiv.appendChild(help);
      }

      fieldsContainer.appendChild(fieldDiv);
    });
  }

  // Error box reset
  const errBox = document.getElementById('dynamicModalErrorBox');
  if (errBox) {
    errBox.classList.add('hidden');
    errBox.textContent = '';
  }

  // Disconnect button
  const discBtn = document.getElementById('dynamicModalDisconnectBtn');
  if (discBtn) {
    if (instance) discBtn.classList.remove('hidden');
    else discBtn.classList.add('hidden');
  }

  // Open modal
  const modal = document.getElementById('connectionConfigModal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

// Close Dynamic Connection Modal
function closeConnectionConfigModal() {
  const modal = document.getElementById('connectionConfigModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

// Save Connection Instance (Create or Update)
async function handleSaveDynamicConnection(e) {
  if (e) e.preventDefault();
  const providerId = document.getElementById('dynamicModalProviderId').value;
  const connectionId = document.getElementById('dynamicModalConnectionId').value;
  const name = document.getElementById('dynamicConnectionName').value.trim();
  const brandScope = document.getElementById('dynamicBrandScope').value;
  const errBox = document.getElementById('dynamicModalErrorBox');

  const connector = (cachedCatalog?.implemented || []).find(c => c.id === providerId);
  if (!connector) return;

  const credentials = {};
  const config = {};

  // Extract fields from schema
  (connector.config_schema?.fields || []).forEach(spec => {
  const key = spec.key;
    const el = document.getElementById(`field_${key}`);
    if (!el) return;
    const val = el.value.trim();

    if (spec.type === 'password' || spec.type === 'secret') {
      if (val) {
        credentials[key] = val;
      }
    } else if (spec.type === 'array') {
      const items = val.split(',').map(s => s.trim()).filter(Boolean);
      config[key] = items;
    } else {
      config[key] = val;
    }
  });

  const payload = {
    provider_id: providerId,
    name: name,
    config: config,
    credentials: credentials,
    brand_ids: brandScope === 'all' ? [] : [brandScope]
  };

  const saveBtn = document.getElementById('dynamicModalSaveBtn');
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving & Verifying...';
  }

  try {
    const url = connectionId ? `/api/connectors/${connectionId}` : '/api/connectors';
    const method = connectionId ? 'PUT' : 'POST';

    const res = await fetch(url, {
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();

    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save & Verify';
    }

    if (!res.ok) {
      if (errBox) {
        errBox.textContent = data.error || 'Validation or connection verification failed.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    // Clear secret fields
    Object.entries(connector.config_schema || {}).forEach(([key, spec]) => {
      if (spec.type === 'password' || spec.type === 'secret') {
        const el = document.getElementById(`field_${key}`);
        if (el) el.value = '';
      }
    });

    closeConnectionConfigModal();
    triggerToast('Connection Configured', data.message || `Successfully verified ${name}.`);
    await renderApiConnectionsView();
    await fetchAppData();
    renderDataSourcesPanel();

  } catch (err) {
    console.error('Save connection error:', err);
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save & Verify';
    }
    if (errBox) {
      errBox.textContent = 'Network communication failure.';
      errBox.classList.remove('hidden');
    }
  }
}

// Test Dynamic Connection
async function handleTestDynamicConnection() {
  const connectionId = document.getElementById('dynamicModalConnectionId').value;
  if (!connectionId) {
    // If unsaved, trigger form save to test and verify
    handleSaveDynamicConnection();
    return;
  }
  await testExistingConnection(connectionId);
}

// Test existing connection instance via API
async function testExistingConnection(connectionId) {
  try {
    const res = await fetch(`/api/connectors/${connectionId}/test`, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken()
      }
    });
    const data = await res.json();
    if (res.ok) {
      const isOk = data.result?.status === 'connected';
      triggerToast(
        isOk ? 'Connection Operational' : 'Connection Test Result',
        data.result?.message || `Status: ${data.result?.detailed_status || data.result?.status}`
      );
      await renderApiConnectionsView();
    } else {
      triggerToast('Test Failed', data.error || 'Connection test encountered an error.');
    }
  } catch (err) {
    console.error('Test error:', err);
    triggerToast('Network Error', 'Failed to communicate with connection test endpoint.');
  }
}

// Disconnect from dynamic modal
async function handleDisconnectDynamicConnection() {
  const connectionId = document.getElementById('dynamicModalConnectionId').value;
  if (!connectionId) return;
  if (!confirm('Are you sure you want to disconnect and delete this provider connection?')) return;
  await deleteExistingConnection(connectionId);
  closeConnectionConfigModal();
}

// Delete connection instance via API
async function deleteExistingConnection(connectionId) {
  if (!connectionId) return;
  try {
    const res = await fetch(`/api/connectors/${connectionId}`, {
      method: 'DELETE',
      headers: {
        'X-CSRF-Token': getCsrfToken()
      }
    });
    const data = await res.json();
    if (res.ok) {
      triggerToast('Connection Removed', data.message || 'Connector successfully removed.');
      await renderApiConnectionsView();
      await fetchAppData();
      renderDataSourcesPanel();
    } else {
      triggerToast('Error', data.error || 'Failed to remove connection.');
    }
  } catch (err) {
    console.error('Delete error:', err);
  }
}

// Toggle Export Menu Dropdown
function toggleExportMenu() {
  const menu = document.getElementById('exportMenu');
  if (menu) menu.classList.toggle('hidden');
}

// Close Export Menu when clicking outside
document.addEventListener('click', (e) => {
  const container = document.getElementById('exportDropdownContainer');
  const menu = document.getElementById('exportMenu');
  if (container && menu && !container.contains(e.target)) {
    menu.classList.add('hidden');
  }
});

// Export Data via Authenticated, Permission-Checked API Endpoint
async function exportData(type = 'telemetry', format = 'csv') {
  const menu = document.getElementById('exportMenu');
  if (menu) menu.classList.add('hidden');

  try {
    const brandId = appData.current_brand?.id || '';
    const url = `/api/reports/export?type=${encodeURIComponent(type)}&format=${encodeURIComponent(format)}&brand_id=${encodeURIComponent(brandId)}`;
    const res = await fetch(url);

    if (res.status === 403) {
      const data = await res.json().catch(() => ({}));
      triggerToast('Permission Denied', data.error || `Your current role does not have permission to export ${type} data.`);
      return;
    }

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      triggerToast('Export Failed', data.error || `Failed to export ${type} report.`);
      return;
    }

    const blob = await res.blob();
    const disposition = res.headers.get('content-disposition');
    let filename = `brandsentinel_${type}_export.${format}`;
    if (disposition && disposition.indexOf('filename=') !== -1) {
      const match = disposition.match(/filename="?([^";]+)"?/);
      if (match && match[1]) filename = match[1];
    }

    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(downloadUrl);

    triggerToast('Report Exported', `Downloaded ${type} report (${format.toUpperCase()}).`);
  } catch (err) {
    console.error('Export error:', err);
    triggerToast('Network Error', 'Failed to communicate with report export service.');
  }
}

function exportSampleDataset() {
  return exportData('telemetry', 'json');
}

// Dropdown Toggles
function toggleBrandDropdown() {
  const drop = document.getElementById('brandDropdown');
  if (drop) drop.classList.toggle('hidden');
}

async function selectBrand(brandId, brandName) {
  try {
    const brandResponse = await fetch(`/api/brands/${encodeURIComponent(brandId)}`);
    if (!brandResponse.ok) throw new Error('Unable to load this brand.');
    const brand = await brandResponse.json();
    appData.current_brand = brand;
    try {
      localStorage.setItem('brandsentinel_selected_brand', brand.id);
    } catch (e) {}
    selectedFindingId = null;
    selectedRowIds.clear();
    currentPage = 1;
    renderBrandSelector();
    await fetchFindings();
    await renderBrandProfile();
    toggleBrandDropdown();
    triggerToast('Monitored Brand Switched', `Switched active brand context to ${brand.name}.`);
  } catch (err) {
    triggerToast('Brand switch failed', err.message);
  }
}

function toggleUserDropdown() {
  const drop = document.getElementById('userDropdown');
  if (drop) drop.classList.toggle('hidden');
}

// Get current CSRF token from document cookies
function getCsrfToken() {
  const match = document.cookie.match(new RegExp('(^| )brandsentinel_csrf=([^;]+)'));
  return match ? match[2] : '';
}

// Active selected source in modal
let activeModalSourceId = null;

function openDataSourceModal(sourceId) {
  const sources = appData.sources || [];
  // Default to first source if none specified
  const source = (sourceId ? sources.find(s => s.id === sourceId) : null) || sources[0];
  if (!source) return;

  activeModalSourceId = source.id;
  const hiddenId = document.getElementById('modalActiveSourceId');
  if (hiddenId) hiddenId.value = source.id;

  const iconContainer = document.getElementById('modalSourceIconContainer');
  if (iconContainer) {
    iconContainer.innerHTML = PLATFORM_ICONS[source.icon] || PLATFORM_ICONS['globe'];
  }

  const titleElem = document.getElementById('modalSourceTitle');
  if (titleElem) titleElem.textContent = source.name;

  const subElem = document.getElementById('modalSourceSubtitle');
  if (subElem) subElem.textContent = `Platform: ${source.platform} • Telemetry Stream`;

  const badgeElem = document.getElementById('modalSourceStatusBadge');
  if (badgeElem) {
    if (source.connected) {
      badgeElem.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-200';
      badgeElem.textContent = 'Connected (Verified)';
    } else if (source.test_status === 'error') {
      badgeElem.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-100 text-rose-800 border border-rose-200';
      badgeElem.textContent = `Error: ${source.error_type || 'Failed'}`;
    } else if (source.test_status === 'ready_to_connect') {
      badgeElem.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-100 text-amber-800 border border-amber-200';
      badgeElem.textContent = 'Ready to Connect';
    } else {
      badgeElem.className = 'px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-slate-100 text-slate-700 border border-slate-200';
      badgeElem.textContent = 'Unconfigured';
    }
  }

  const keySrcElem = document.getElementById('modalSourceKeySource');
  if (keySrcElem) {
    if (source.key_source === 'org_supplied') {
      keySrcElem.textContent = 'Organization Vault (Encrypted)';
    } else if (source.key_source === 'deployment_configured') {
      keySrcElem.textContent = 'Deployment Server Secret';
    } else if (source.key_source === 'developer_import') {
      keySrcElem.textContent = 'Verified Developer Import';
    } else {
      keySrcElem.textContent = 'None';
    }
  }

  const testedElem = document.getElementById('modalSourceLastTested');
  if (testedElem) {
    testedElem.textContent = source.last_tested_at ? new Date(source.last_tested_at).toLocaleString() : 'Never';
  }

  const msgBanner = document.getElementById('modalSourceMessageBanner');
  if (msgBanner) {
    msgBanner.textContent = source.status_message || (source.connected ? 'Operational and streaming telemetry.' : 'Awaiting configuration and verification test.');
  }

  // Label & placeholder
  const labelElem = document.getElementById('modalSecretKeyLabel');
  const inputElem = document.getElementById('modalSecretKeyInput');
  const deleteBtn = document.getElementById('modalDeleteSecretBtn');
  const gpSection = document.getElementById('googlePlayImportSection');

  if (source.platform === 'youtube') {
    if (labelElem) labelElem.textContent = 'YouTube Data API v3 Key (Google Cloud)';
    if (inputElem) inputElem.placeholder = 'AIzaSy... (Enter Google Cloud API Key)';
  } else if (source.platform === 'google_play') {
    if (labelElem) labelElem.textContent = 'Google Play Service Account JSON or API Key';
    if (inputElem) inputElem.placeholder = '{"type": "service_account", ...}';
  } else if (source.platform === 'apple_app_store') {
    if (labelElem) labelElem.textContent = 'Apple App Store Connect Key (Optional)';
    if (inputElem) inputElem.placeholder = 'Public iTunes Search API is active by default';
  } else {
    if (labelElem) labelElem.textContent = `${source.name} Credentials`;
    if (inputElem) inputElem.placeholder = 'Enter API token / secret...';
  }

  // Reset input and visibility
  if (inputElem) {
    inputElem.value = '';
    inputElem.type = 'password';
  }
  updateEyeIcon(false);

  // Show/hide Delete button
  if (deleteBtn) {
    if (source.is_configured && source.key_source === 'org_supplied') {
      deleteBtn.classList.remove('hidden');
    } else {
      deleteBtn.classList.add('hidden');
    }
  }

  // Show/hide Google Play Import section
  if (gpSection) {
    if (source.platform === 'google_play') {
      gpSection.classList.remove('hidden');
    } else {
      gpSection.classList.add('hidden');
    }
  }

  const modal = document.getElementById('dataSourceModal');
  if (modal) {
    modal.classList.remove('hidden');
    modal.classList.add('flex');
  }
}

function closeDataSourceModal() {
  const modal = document.getElementById('dataSourceModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.classList.remove('flex');
  }
}

// "Allow visibility toggling only for newly typed, unsaved input"
function toggleUnsavedSecretVisibility() {
  const input = document.getElementById('modalSecretKeyInput');
  if (!input) return;
  // If input is empty, no visibility toggle allowed
  if (!input.value || input.value.trim().length === 0) {
    return;
  }
  const isPass = input.type === 'password';
  input.type = isPass ? 'text' : 'password';
  updateEyeIcon(!isPass);
}

function handleCredentialInputChanged() {
  const input = document.getElementById('modalSecretKeyInput');
  const btn = document.getElementById('modalToggleVisibilityBtn');
  if (!input || !btn) return;
  if (!input.value || input.value.trim().length === 0) {
    input.type = 'password';
    updateEyeIcon(false);
    btn.disabled = true;
  } else {
    btn.disabled = false;
  }
}

function updateEyeIcon(isOpen) {
  const eyeOpen = document.getElementById('eyeIconOpen');
  const eyeClosed = document.getElementById('eyeIconClosed');
  if (eyeOpen && eyeClosed) {
    if (isOpen) {
      eyeOpen.classList.remove('hidden');
      eyeClosed.classList.add('hidden');
    } else {
      eyeOpen.classList.add('hidden');
      eyeClosed.classList.remove('hidden');
    }
  }
}

async function handleSaveSourceCredentials(e) {
  if (e) e.preventDefault();
  const sourceId = activeModalSourceId || document.getElementById('modalActiveSourceId')?.value;
  const input = document.getElementById('modalSecretKeyInput');
  const val = input ? input.value.trim() : '';

  if (!val) {
    triggerToast('Input Required', 'Please enter a credential value or API key.');
    return;
  }

  const saveBtn = document.getElementById('modalSaveCredentialsBtn');
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Encrypting & Testing...';
  }

  try {
    let payload = { api_key: val };
    if (val.startsWith('{') && val.endsWith('}')) {
      try {
        payload = { service_account: JSON.parse(val) };
      } catch (err) {}
    }

    const res = await fetch(`/api/sources/${sourceId}/credentials`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save & Verify';
    }

    if (!res.ok) {
      triggerToast('Credential Error', data.error || 'Failed to save credentials.');
      return;
    }

    // "Clear the input after saving"
    if (input) {
      input.value = '';
      input.type = 'password';
      updateEyeIcon(false);
    }

    // Refresh application state
    await fetchAppData();
    renderDataSourcesPanel();
    openDataSourceModal(sourceId);

    const isConn = data.source?.connected;
    if (isConn) {
      triggerToast('Connector Verified', `${data.message} Status: Connected.`);
    } else {
      triggerToast('Credential Saved', `Key encrypted. Verification status: ${data.source?.status_message || data.source?.status}`);
    }

  } catch (err) {
    console.error('Error saving credentials:', err);
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save & Verify';
    }
    triggerToast('Network Error', 'Failed to communicate with authentication endpoint.');
  }
}

async function handleDeleteSourceCredentials() {
  const sourceId = activeModalSourceId || document.getElementById('modalActiveSourceId')?.value;
  if (!confirm('Are you sure you want to delete stored credentials for this connector?')) return;

  try {
    const res = await fetch(`/api/sources/${sourceId}/credentials`, {
      method: 'DELETE',
      headers: {
        'X-CSRF-Token': getCsrfToken()
      }
    });
    const data = await res.json();
    if (res.ok) {
      await fetchAppData();
      renderDataSourcesPanel();
      openDataSourceModal(sourceId);
      triggerToast('Credentials Deleted', data.message || 'Credentials successfully removed from vault.');
    } else {
      triggerToast('Error', data.error || 'Failed to delete credentials.');
    }
  } catch (err) {
    console.error('Error deleting credentials:', err);
  }
}

async function handleTestLiveConnection() {
  const sourceId = activeModalSourceId || document.getElementById('modalActiveSourceId')?.value;
  const testBtn = document.getElementById('modalTestConnectionBtn');
  if (testBtn) {
    testBtn.disabled = true;
    testBtn.textContent = 'Testing...';
  }

  try {
    const res = await fetch(`/api/sources/${sourceId}/test`, {
      method: 'POST',
      headers: {
        'X-CSRF-Token': getCsrfToken()
      }
    });
    const data = await res.json();
    if (testBtn) {
      testBtn.disabled = false;
      testBtn.textContent = 'Test Connection';
    }

    if (res.ok) {
      await fetchAppData();
      renderDataSourcesPanel();
      openDataSourceModal(sourceId);
      const isConn = data.source?.connected;
      triggerToast(
        isConn ? 'Connection Succeeded' : 'Test Result',
        data.source?.status_message || (isConn ? 'Connected successfully.' : 'Test failed.')
      );
    } else {
      triggerToast('Test Error', data.error || 'Failed to execute test.');
    }
  } catch (err) {
    if (testBtn) {
      testBtn.disabled = false;
      testBtn.textContent = 'Test Connection';
    }
    triggerToast('Network Error', 'Connection test failed.');
  }
}

async function handleImportGooglePlayPackages() {
  const area = document.getElementById('googlePlayImportJson');
  const raw = area ? area.value.trim() : '';
  if (!raw) {
    triggerToast('Input Required', 'Please enter a valid JSON array of packages.');
    return;
  }

  let packages = [];
  try {
    packages = JSON.parse(raw);
    if (!Array.isArray(packages)) throw new Error('Must be array');
  } catch (e) {
    triggerToast('JSON Error', 'Invalid JSON syntax. Must be an array of package objects.');
    return;
  }

  try {
    const res = await fetch('/api/sources/google-play/import', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({ packages })
    });
    const data = await res.json();
    if (res.ok) {
      if (area) area.value = '';
      await fetchAppData();
      renderDataSourcesPanel();
      openDataSourceModal(activeModalSourceId);
      triggerToast('Import Successful', data.message);
    } else {
      triggerToast('Import Failed', data.error || 'Validation error on server.');
    }
  } catch (err) {
    console.error('Import error:', err);
    triggerToast('Error', 'Server communication failure.');
  }
}

// Mobile Sidebar Controls
function toggleMobileSidebar() {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('mobileBackdrop');
  if (sidebar && backdrop) {
    const isOpen = sidebar.classList.contains('open');
    if (isOpen) {
      sidebar.classList.remove('open');
      backdrop.classList.add('hidden');
    } else {
      sidebar.classList.add('open');
      backdrop.classList.remove('hidden');
    }
  }
}

function closeMobileSidebar() {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('mobileBackdrop');
  if (sidebar && backdrop) {
    sidebar.classList.remove('open');
    backdrop.classList.add('hidden');
  }
}

// Toast Feedback Notifications
function triggerToast(title, message) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'bg-slate-900 text-white p-3.5 rounded-xl shadow-xl border border-slate-700/80 text-xs flex items-start gap-2.5 pointer-events-auto transform transition-all duration-200 animate-in fade-in slide-in-from-top-2';
  toast.innerHTML = `
    <div class="w-5 h-5 rounded-full bg-blue-500 text-white flex items-center justify-center shrink-0 mt-0.5">
      <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>
    </div>
    <div class="min-w-0 flex-1">
      <div class="font-bold text-white leading-tight">${title}</div>
      <div class="text-slate-300 text-[11px] mt-0.5 leading-normal">${message}</div>
    </div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-y-[-4px]');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ==============================================================================
// EXACT YOUTUBE CHANNEL VERIFICATION CONTROLLER
// ==============================================================================

async function handleVerifyYouTubeChannel(event) {
  if (event) event.preventDefault();

  const inputElem = document.getElementById('ytVerifyInput');
  const btnElem = document.getElementById('ytVerifyBtn');
  const btnTextElem = document.getElementById('ytVerifyBtnText');
  const errorBanner = document.getElementById('ytVerifyErrorBanner');
  const resultCard = document.getElementById('ytVerifyResultCard');

  const rawValue = inputElem ? inputElem.value.trim() : '';

  if (!rawValue) {
    renderYouTubeVerificationError({
      title: 'Input Required',
      message: 'Please enter a YouTube channel URL, @handle, or UC... channel ID.',
      code: 'EMPTY_INPUT'
    });
    return;
  }

  // Clear previous state
  if (errorBanner) errorBanner.classList.add('hidden');
  if (resultCard) resultCard.classList.add('hidden');

  // Set loading state on button
  if (btnElem) btnElem.disabled = true;
  if (btnTextElem) btnTextElem.textContent = 'Verifying...';

  try {
    const brandId = (typeof appData !== 'undefined' && appData.current_brand && appData.current_brand.id) 
      ? appData.current_brand.id 
      : 'brand-northstar-tech';

    const response = await fetch('/api/verify/youtube', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        identifier: rawValue,
        brand_id: brandId
      })
    });

    const data = await response.json();

    if (!response.ok) {
      renderYouTubeVerificationError({
        title: getYouTubeErrorTitle(data.code),
        message: data.error || 'Failed to verify YouTube channel.',
        code: data.code
      });
      return;
    }

    if (data.verification) {
      renderYouTubeVerificationResult(data.verification);
    }
  } catch (err) {
    renderYouTubeVerificationError({
      title: 'Connection Error',
      message: 'Network error or service unavailable while contacting the server.',
      code: 'NETWORK_ERROR'
    });
  } finally {
    if (btnElem) btnElem.disabled = false;
    if (btnTextElem) btnTextElem.textContent = 'Verify Channel';
  }
}

function getYouTubeErrorTitle(code) {
  switch (code) {
    case 'UNSUPPORTED_VIDEO_LINK':
      return 'Unsupported Video Link';
    case 'CHANNEL_NOT_FOUND':
      return 'Channel Not Found';
    case 'MISSING_CREDENTIALS':
      return 'Missing API Credentials';
    case 'QUOTA_EXCEEDED':
      return 'YouTube API Quota Exceeded';
    case 'API_NOT_ENABLED':
      return 'YouTube API Not Enabled';
    case 'INVALID_CREDENTIALS':
      return 'Invalid API Credentials';
    case 'PROVIDER_OUTAGE':
    case 'OUTAGE':
      return 'YouTube Provider Outage';
    case 'TIMEOUT':
      return 'Request Timed Out';
    default:
      return 'Verification Error';
  }
}

function renderYouTubeVerificationError(err) {
  const errorBanner = document.getElementById('ytVerifyErrorBanner');
  const errorTitle = document.getElementById('ytVerifyErrorTitle');
  const errorMsg = document.getElementById('ytVerifyErrorMessage');
  const resultCard = document.getElementById('ytVerifyResultCard');

  if (resultCard) resultCard.classList.add('hidden');

  if (errorBanner && errorTitle && errorMsg) {
    errorTitle.innerHTML = `
      <svg class="w-4 h-4 text-rose-600 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
      <span>${escapeHtml(err.title || 'Verification Error')}</span>
    `;
    errorMsg.textContent = err.message || 'An error occurred during channel verification.';
    errorBanner.classList.remove('hidden');
  }
}

function renderYouTubeVerificationResult(verification) {
  const errorBanner = document.getElementById('ytVerifyErrorBanner');
  const resultCard = document.getElementById('ytVerifyResultCard');

  if (errorBanner) errorBanner.classList.add('hidden');
  if (!resultCard) return;

  const verdict = verification.verdict || 'Inconclusive';
  const channelName = verification.channel_name || 'Unknown Channel';
  const channelUrl = verification.channel_url || '';
  const stableId = verification.stable_channel_id || '';
  const reasons = verification.reasons || [];
  const evidence = verification.evidence || {};
  const meta = verification.channel_metadata || {};

  // Determine styling based on verdict
  let badgeStyle = '';
  let borderStyle = '';
  let verdictIcon = '';
  let headlineText = '';

  if (verdict === 'Official') {
    badgeStyle = 'bg-emerald-100 text-emerald-800 border-emerald-300';
    borderStyle = 'border-emerald-200 bg-emerald-50/40';
    headlineText = 'Official — Channel ID matches the brand’s registered official account.';
    verdictIcon = `<svg class="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg>`;
  } else if (verdict === 'Suspected impersonation') {
    badgeStyle = 'bg-rose-100 text-rose-800 border-rose-300';
    borderStyle = 'border-rose-200 bg-rose-50/40';
    headlineText = 'Suspected Impersonation';
    verdictIcon = `<svg class="w-4 h-4 text-rose-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
  } else if (verdict === 'Unrelated') {
    badgeStyle = 'bg-slate-100 text-slate-800 border-slate-300';
    borderStyle = 'border-slate-200 bg-slate-50/60';
    headlineText = 'Unrelated Channel';
    verdictIcon = `<svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  } else {
    // Inconclusive
    badgeStyle = 'bg-amber-100 text-amber-800 border-amber-300';
    borderStyle = 'border-amber-200 bg-amber-50/40';
    headlineText = 'Inconclusive Evidence';
    verdictIcon = `<svg class="w-4 h-4 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  }

  const thumbHtml = meta.thumbnail_url 
    ? `<img src="${escapeHtml(meta.thumbnail_url)}" alt="Thumbnail" class="w-10 h-10 rounded-full border border-slate-200 object-cover shrink-0">`
    : `<div class="w-10 h-10 rounded-full bg-rose-100 text-rose-600 flex items-center justify-center font-bold text-sm shrink-0">${escapeHtml(channelName.charAt(0) || 'Y')}</div>`;

  const reasonsListHtml = reasons.map(r => `
    <li class="flex items-start gap-2 text-xs text-slate-700 leading-normal">
      <span class="w-1.5 h-1.5 rounded-full bg-slate-400 mt-1.5 shrink-0"></span>
      <span>${escapeHtml(r)}</span>
    </li>
  `).join('');

  const registeredIds = Array.isArray(evidence.registered_official_channel_ids) && evidence.registered_official_channel_ids.length > 0
    ? evidence.registered_official_channel_ids.map(id => `<code class="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px] text-slate-800">${escapeHtml(id)}</code>`).join(' ')
    : '<span class="text-slate-400 italic">None registered for brand</span>';

  let evidenceDetailsHtml = `
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] pt-1">
      <div>
        <span class="text-slate-500 font-semibold block">Resolved Channel ID:</span>
        <code class="font-mono text-slate-800">${escapeHtml(stableId || 'N/A')}</code>
      </div>
      <div>
        <span class="text-slate-500 font-semibold block">Brand Registered Official ID(s):</span>
        <div class="flex flex-wrap gap-1 mt-0.5">${registeredIds}</div>
      </div>
    </div>
  `;

  if (evidence.missing_official_identity) {
    evidenceDetailsHtml += `
      <div class="text-[11px] pt-2 border-t border-slate-200/60 mt-2">
        <span class="text-amber-700 font-semibold block">Missing official identity: Brand has no registered official YouTube channel on record.</span>
      </div>
    `;
  }

  if (evidence.impersonation_indicators && evidence.impersonation_indicators.length > 0) {
    evidenceDetailsHtml += `
      <div class="text-[11px] pt-2 border-t border-slate-200/60 mt-2">
        <span class="text-rose-700 font-semibold block mb-1">Detected Impersonation Indicators:</span>
        <ul class="space-y-1">
          ${evidence.impersonation_indicators.map(ind => `<li class="text-rose-800">• ${escapeHtml(ind)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  if (evidence.detected_disclosures && evidence.detected_disclosures.length > 0) {
    evidenceDetailsHtml += `
      <div class="text-[11px] pt-2 border-t border-slate-200/60 mt-2">
        <span class="text-amber-700 font-semibold block mb-1">Detected Community / Review Markers:</span>
        <div class="flex flex-wrap gap-1">
          ${evidence.detected_disclosures.map(d => `<span class="px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 font-medium text-[10px]">${escapeHtml(d)}</span>`).join('')}
        </div>
      </div>
    `;
  }

  const officialNoteHtml = verdict === 'Official' ? `
    <div class="p-2.5 rounded-lg bg-emerald-100/60 border border-emerald-200 text-[11px] text-emerald-900 flex items-start gap-1.5">
      <svg class="w-3.5 h-3.5 text-emerald-700 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
      <span><strong>Identity Scope:</strong> “Official” confirms a registered identity match, not that every video or message is safe.</span>
    </div>
  ` : '';

  resultCard.className = `rounded-xl border p-4 sm:p-5 card-shadow space-y-4 animate-in fade-in duration-150 ${borderStyle}`;
  resultCard.innerHTML = `
    <!-- Result Header & Verdict -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-200/70 pb-3.5">
      <div class="flex items-center gap-3">
        ${thumbHtml}
        <div>
          <h4 class="font-bold text-slate-900 text-base flex items-center gap-2">
            <span>${escapeHtml(channelName)}</span>
          </h4>
          <div class="flex flex-wrap items-center gap-2 text-xs text-slate-500 mt-0.5">
            ${channelUrl ? `<a href="${escapeHtml(channelUrl)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline flex items-center gap-1 font-mono text-[11px]">${escapeHtml(channelUrl)} <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg></a>` : ''}
          </div>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${badgeStyle}">
          ${verdictIcon}
          <span>${escapeHtml(verdict)}</span>
        </span>
      </div>
    </div>

    <!-- Stable ID and Main Verdict Headline -->
    <div class="space-y-1">
      <div class="flex items-center gap-2">
        <span class="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Stable Channel ID:</span>
        <code class="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-900 font-mono text-xs font-bold">${escapeHtml(stableId || 'N/A')}</code>
      </div>
      <div class="font-bold text-sm text-slate-900 pt-1">
        ${escapeHtml(headlineText)}
      </div>
    </div>

    <!-- Reasons Section -->
    <div class="space-y-1.5">
      <span class="text-[11px] font-bold uppercase tracking-wider text-slate-600 block">Assessment Reasons:</span>
      <ul class="space-y-1 pl-1">
        ${reasonsListHtml}
      </ul>
    </div>

    <!-- Evidence Breakdown -->
    <div class="p-3 rounded-lg bg-white/80 border border-slate-200/80 space-y-2">
      <span class="text-[11px] font-bold uppercase tracking-wider text-slate-600 block">Available Evidence:</span>
      ${evidenceDetailsHtml}
    </div>

    ${officialNoteHtml}
  `;

  resultCard.classList.remove('hidden');
}

// =============================================================================
// WEBSITE PHISHING MODEL & DATA SOURCE INTEGRATION
// =============================================================================

let activeDatasetId = null;
let currentPreviewPage = 1;
let currentPreviewTotal = 0;
let trainingPollInterval = null;

// Toggle collapsible YouTube verification card
function toggleYoutubeVerificationCard() {
  const card = document.getElementById('youtubeVerificationCard');
  const chevron = document.getElementById('ytCardChevron');
  if (!card) return;
  const isHidden = card.classList.contains('hidden');
  if (isHidden) {
    card.classList.remove('hidden');
    if (chevron) chevron.textContent = '▼';
  } else {
    card.classList.add('hidden');
    if (chevron) chevron.textContent = '▶';
  }
}

// Handle Website URL scan
async function handleWebsiteScan(e) {
  if (e) e.preventDefault();

  const urlInput = document.getElementById('websiteScanInput');
  const brandSelect = document.getElementById('websiteBrandSelect');
  const btn = document.getElementById('websiteScanBtn');
  const btnText = document.getElementById('websiteScanBtnText');
  const errBanner = document.getElementById('websiteScanErrorBanner');
  const errTitle = document.getElementById('websiteScanErrorTitle');
  const errMessage = document.getElementById('websiteScanErrorMessage');

  if (errBanner) errBanner.classList.add('hidden');
  const platformNotice = document.getElementById('websitePlatformNotice');
  if (platformNotice) platformNotice.classList.add('hidden');

  const rawUrl = urlInput ? urlInput.value.trim() : '';
  const brandId = brandSelect ? brandSelect.value : null;

  if (!rawUrl) {
    if (errBanner) {
      if (errTitle) errTitle.textContent = 'Invalid Input';
      if (errMessage) errMessage.textContent = 'Please enter a website URL.';
      errBanner.classList.remove('hidden');
    }
    return;
  }

  if (btn) btn.disabled = true;
  if (btnText) btnText.textContent = 'Checking...';

  try {
    const res = await fetch('/api/scan/url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        url: rawUrl,
        brand_id: brandId
      })
    });

    const data = await res.json();

    if (!res.ok) {
      if (errBanner) {
        if (errTitle) errTitle.textContent = data.code || 'Scan Failed';
        if (errMessage) errMessage.textContent = data.error || 'Failed to scan website URL.';
        errBanner.classList.remove('hidden');
      }
      return;
    }

    // Render results
    renderWebsiteScanResult(data);

  } catch (err) {
    if (errBanner) {
      if (errTitle) errTitle.textContent = 'Network Error';
      if (errMessage) errMessage.textContent = 'Failed to connect to scanner service. Please verify your connection.';
      errBanner.classList.remove('hidden');
    }
  } finally {
    if (btn) btn.disabled = false;
    if (btnText) btnText.textContent = 'Check URL';
  }
}

// Render Website Scan Result matching reference visual design
function renderWebsiteScanResult(data) {
  const headerTitle = document.getElementById('websiteResultHeaderTitle');
  const versionTag = document.getElementById('websiteModelVersionTag');
  const idBadge = document.getElementById('websiteIdentityBadge');
  const idDesc = document.getElementById('websiteIdentityDesc');
  const phishBadge = document.getElementById('websitePhishingBadge');
  const phishDesc = document.getElementById('websitePhishingDesc');
  const platformNotice = document.getElementById('websitePlatformNotice');
  const platformText = document.getElementById('websitePlatformNoticeText');

  if (headerTitle) headerTitle.textContent = 'Result';
  if (versionTag) {
    versionTag.textContent = data.model_version ? `Model: ${data.model_version}` : 'Model: not trained';
  }

  // Official Identity formatting
  const idStatus = data.identity?.status || 'Unable to verify';
  if (idBadge) {
    idBadge.textContent = `Identity: ${idStatus}`;
    if (idStatus === 'Official') {
      idBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800';
    } else if (idStatus === 'Not verified as official') {
      idBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-slate-200 text-slate-700';
    } else {
      idBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800';
    }
  }
  if (idDesc) {
    idDesc.textContent = data.identity?.description || "No match in the selected brand's official registry.";
  }

  // Phishing Assessment formatting
  const phishStatus = data.phishing?.status || 'Unable to assess';
  if (phishBadge) {
    phishBadge.textContent = `Phishing assessment: ${phishStatus}`;
    if (phishStatus === 'Likely phishing') {
      phishBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-amber-100 text-amber-800';
    } else if (phishStatus === 'Likely legitimate') {
      phishBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800';
    } else {
      phishBadge.className = 'inline-block px-2.5 py-0.5 rounded text-xs font-semibold bg-slate-200 text-slate-700';
    }
  }
  if (phishDesc) {
    phishDesc.textContent = data.phishing?.description || 'Model prediction based on URL features.';
  }

  // Platform limitation note
  if (platformNotice && platformText) {
    if (data.limitation_note) {
      platformText.textContent = data.limitation_note;
      platformNotice.classList.remove('hidden');
    } else {
      platformNotice.classList.add('hidden');
    }
  }
}

// Load and populate the Data Sources View
async function loadDataSourcesView() {
  // Update YouTube connection card status based on appData
  const ytStatusText = document.getElementById('dataSourcesYtStatusText');
  const ytBadge = document.getElementById('dataSourcesYtBadge');
  const ytDesc = document.getElementById('dataSourcesYtDescText');
  
  const ytSource = (appData.sources || []).find(s => s.platform === 'youtube' || s.id === 'youtube');
  const isYtConnected = ytSource && (ytSource.connection_status === 'connected' || ytSource.is_configured);

  if (ytStatusText && ytBadge) {
    if (isYtConnected) {
      ytStatusText.textContent = 'Existing API connection';
      ytBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200';
      if (ytDesc) ytDesc.textContent = 'Continue using your saved API key.';
    } else {
      ytStatusText.textContent = 'Unconfigured';
      ytBadge.className = 'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-200';
      if (ytDesc) ytDesc.textContent = 'API key required for YouTube identity resolution.';
    }
  }

  // Fetch active model status
  try {
    const res = await fetch('/api/models/phishing/status');
    if (res.ok) {
      const modelInfo = await res.json();
      updateModelStatusUI(modelInfo);
    }
  } catch (err) {
    console.warn('Error fetching model status:', err);
  }

  // Fetch dataset info if available
  try {
    const listRes = await fetch('/api/datasets/import', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        file_path: 'C:\\hackathon\\data\\datasets\\PhiUSIIL_Phishing_URL_Dataset.csv'
      })
    });
    if (listRes.ok) {
      const data = await listRes.json();
      if (data.dataset) {
        activeDatasetId = data.dataset.dataset_id;
        const totalRowsElem = document.getElementById('statSourceRows');
        const repeatedUrlsElem = document.getElementById('statRepeatedUrls');
        if (totalRowsElem) totalRowsElem.textContent = (data.dataset.total_rows || 235795).toLocaleString();
        if (repeatedUrlsElem) repeatedUrlsElem.textContent = (data.dataset.duplicate_rows || 425).toLocaleString();
        await loadDatasetPreview(activeDatasetId, 1);
      }
    }
  } catch (e) {
    console.warn('Error syncing dataset:', e);
  }
}

function updateModelStatusUI(info) {
  const badge = document.getElementById('statModelStatusBadge');
  const verText = document.getElementById('activeModelVersionText');
  const metricsContainer = document.getElementById('modelMetricsSummaryContainer');

  if (badge) {
    badge.textContent = info.status || 'Not trained';
    if (info.status === 'Ready') {
      badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800';
    } else if (info.status === 'Training') {
      badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-blue-100 text-blue-800 animate-pulse';
    } else {
      badge.className = 'inline-flex items-center px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800';
    }
  }

  if (verText) {
    verText.textContent = info.model_version ? `Active Model: ${info.model_version} (${info.model_type || 'HistGradientBoosting'})` : 'No active model loaded';
  }

  if (metricsContainer && info.metrics && info.status === 'Ready') {
    const testM = info.metrics.test_metrics || info.metrics;
    const acc = document.getElementById('metricAccuracy');
    const rec = document.getElementById('metricRecall');
    const f1 = document.getElementById('metricMacroF1');
    const fpr = document.getElementById('metricFpr');

    if (acc) acc.textContent = testM.accuracy ? `${(testM.accuracy * 100).toFixed(1)}%` : '--';
    if (rec) rec.textContent = testM.phishing_recall ? `${(testM.phishing_recall * 100).toFixed(1)}%` : '--';
    if (f1) f1.textContent = testM.macro_f1 ? `${(testM.macro_f1 * 100).toFixed(1)}%` : '--';
    if (fpr) fpr.textContent = testM.false_positive_rate !== undefined ? `${(testM.false_positive_rate * 100).toFixed(2)}%` : '--';

    metricsContainer.classList.remove('hidden');
  }
}

function handleDatasetFileChosen(e) {
  const file = e.target?.files?.[0];
  const nameDisplay = document.getElementById('selectedDatasetFileName');
  if (file && nameDisplay) {
    nameDisplay.textContent = file.name;
  }
}

// Handle Validate & Import
async function handleImportDataset() {
  const btn = document.getElementById('validateImportBtn');
  const spinner = document.getElementById('validateImportSpinner');
  const btnText = document.getElementById('validateImportText');
  const fileInput = document.getElementById('datasetFileInput');

  if (btn) btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  if (btnText) btnText.textContent = 'Importing...';

  try {
    let res;
    if (fileInput && fileInput.files && fileInput.files.length > 0) {
      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      res = await fetch('/api/datasets/import', {
        method: 'POST',
        headers: {
          'X-CSRF-Token': getCsrfToken()
        },
        body: formData
      });
    } else {
      res = await fetch('/api/datasets/import', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken()
        },
        body: JSON.stringify({
          file_path: 'C:\\hackathon\\data\\datasets\\PhiUSIIL_Phishing_URL_Dataset.csv'
        })
      });
    }

    const data = await res.json();

    if (!res.ok) {
      triggerToast('Import Failed', data.error || 'Failed to import dataset.', 'error');
      return;
    }

    triggerToast('Dataset Imported', `Successfully processed ${data.dataset?.total_rows?.toLocaleString() || 235795} rows.`);
    activeDatasetId = data.dataset?.dataset_id;

    // Update numbers
    const totalRowsElem = document.getElementById('statSourceRows');
    const repeatedUrlsElem = document.getElementById('statRepeatedUrls');
    if (totalRowsElem) totalRowsElem.textContent = (data.dataset?.total_rows || 235795).toLocaleString();
    if (repeatedUrlsElem) repeatedUrlsElem.textContent = (data.dataset?.duplicate_rows || 425).toLocaleString();

    // Load preview page 1
    if (activeDatasetId) {
      await loadDatasetPreview(activeDatasetId, 1);
    }

    // Refresh model status
    const statusRes = await fetch('/api/models/phishing/status');
    if (statusRes.ok) {
      const info = await statusRes.json();
      updateModelStatusUI(info);
    }

  } catch (err) {
    triggerToast('Import Error', 'Failed to connect to dataset import service.', 'error');
  } finally {
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.textContent = 'Validate & Import';
  }
}

// Handle Train Model
async function handleStartTraining() {
  const btn = document.getElementById('trainModelBtn');
  const spinner = document.getElementById('trainModelSpinner');
  const btnText = document.getElementById('trainModelText');
  const progressContainer = document.getElementById('trainingProgressContainer');

  if (btn) btn.disabled = true;
  if (spinner) spinner.classList.remove('hidden');
  if (btnText) btnText.textContent = 'Queuing...';
  if (progressContainer) progressContainer.classList.remove('hidden');

  try {
    const res = await fetch('/api/models/phishing/train', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken()
      },
      body: JSON.stringify({
        dataset_id: activeDatasetId
      })
    });

    const data = await res.json();
    if (!res.ok) {
      triggerToast('Training Error', data.error || 'Failed to initiate model training.', 'error');
      if (btn) btn.disabled = false;
      if (spinner) spinner.classList.add('hidden');
      if (btnText) btnText.textContent = 'Train Model';
      return;
    }

    triggerToast('Training Started', 'Model training job queued. Training in background.');
    pollTrainingJob(data.job_id);

  } catch (err) {
    triggerToast('Training Failed', 'Failed to communicate with training service.', 'error');
    if (btn) btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (btnText) btnText.textContent = 'Train Model';
  }
}

// Poll Training Job Status
function pollTrainingJob(jobId) {
  if (trainingPollInterval) clearInterval(trainingPollInterval);

  const stageText = document.getElementById('trainingStageText');
  const percentText = document.getElementById('trainingPercentText');
  const progressBar = document.getElementById('trainingProgressBar');
  const btn = document.getElementById('trainModelBtn');
  const spinner = document.getElementById('trainModelSpinner');
  const btnText = document.getElementById('trainModelText');

  trainingPollInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/models/phishing/jobs/${jobId}`);
      if (!res.ok) return;

      const job = await res.json();

      if (stageText) {
        const stageDescriptions = {
          'queued': 'Training job queued in worker...',
          'loading_dataset': 'Loading clean dataset rows from disk...',
          'validating': 'Validating dataset integrity...',
          'extracting_features': 'Extracting 30 lexical URL features...',
          'splitting_domains': 'Partitioning domain-grouped train/val/test splits...',
          'training_baseline': 'Training Logistic Regression baseline...',
          'training_gradient_boosting': 'Fitting HistGradientBoostingClassifier...',
          'evaluating': 'Evaluating models and selecting best pipeline...',
          'saving_model': 'Serializing model bundle and saving metadata...',
          'ready': 'Model training complete and activated!'
        };
        stageText.textContent = stageDescriptions[job.stage] || `Stage: ${job.stage}`;
      }

      if (percentText) percentText.textContent = `${job.progress_percent}%`;
      if (progressBar) progressBar.style.width = `${job.progress_percent}%`;

      if (job.status === 'completed') {
        clearInterval(trainingPollInterval);
        trainingPollInterval = null;

        triggerToast('Model Ready', `Trained & activated model ${job.model_version}!`);
        if (btn) btn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = 'Train Model';

        // Reload status
        const statusRes = await fetch('/api/models/phishing/status');
        if (statusRes.ok) {
          const info = await statusRes.json();
          updateModelStatusUI(info);
        }
      } else if (job.status === 'failed') {
        clearInterval(trainingPollInterval);
        trainingPollInterval = null;

        triggerToast('Training Failed', job.error_message || 'Training failed.', 'error');
        if (btn) btn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = 'Retry Training';
      }
    } catch (e) {
      console.warn('Poll error:', e);
    }
  }, 1200);
}

// Load Paginated Dataset Preview
async function loadDatasetPreview(datasetId, page = 1) {
  if (!datasetId) return;
  activeDatasetId = datasetId;
  currentPreviewPage = page;

  const tbody = document.getElementById('datasetPreviewTableBody');
  const countSpan = document.getElementById('previewRecordCount');
  const pageInfo = document.getElementById('previewPageInfo');
  const paginationContainer = document.getElementById('previewPaginationContainer');
  const prevBtn = document.getElementById('previewPrevBtn');
  const nextBtn = document.getElementById('previewNextBtn');

  try {
    const res = await fetch(`/api/datasets/${datasetId}/preview?page=${page}&page_size=15`);
    if (!res.ok) return;

    const data = await res.json();
    currentPreviewTotal = data.total_records || 0;

    if (countSpan) countSpan.textContent = `${(data.total_records || 0).toLocaleString()} rows`;
    if (pageInfo) {
      const maxPages = Math.ceil(data.preview_total / data.page_size);
      pageInfo.textContent = `Showing page ${data.page} of ${maxPages} (${data.preview_total.toLocaleString()} preview rows)`;
    }

    if (paginationContainer) paginationContainer.classList.remove('hidden');
    if (prevBtn) prevBtn.disabled = data.page <= 1;
    if (nextBtn) {
      const maxPages = Math.ceil(data.preview_total / data.page_size);
      nextBtn.disabled = data.page >= maxPages;
    }

    if (tbody && Array.isArray(data.rows) && data.rows.length > 0) {
      tbody.innerHTML = data.rows.map(r => {
        const isLegit = r.label === 1;
        const badgeClass = isLegit ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800';
        const labelText = isLegit ? 'Legitimate (1)' : 'Phishing (0)';
        return `
          <tr class="hover:bg-slate-50/70 transition-colors">
            <td class="px-4 py-2.5 font-mono text-[11px] text-slate-800 max-w-xs truncate" title="${escapeHtml(r.url)}">
              ${escapeHtml(r.url)}
            </td>
            <td class="px-4 py-2.5 font-mono text-[11px] text-slate-600 truncate">
              ${escapeHtml(r.domain)}
            </td>
            <td class="px-4 py-2.5">
              <span class="inline-block px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">
                ${labelText}
              </span>
            </td>
          </tr>
        `;
      }).join('');
    }
  } catch (err) {
    console.warn('Error loading preview:', err);
  }
}

function handlePreviewPageChange(delta) {
  const targetPage = currentPreviewPage + delta;
  if (targetPage >= 1 && activeDatasetId) {
    loadDatasetPreview(activeDatasetId, targetPage);
  }
}

