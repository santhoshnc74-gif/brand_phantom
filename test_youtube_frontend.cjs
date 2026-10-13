const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function harness() {
  const elements = new Map();
  const element = () => ({
    textContent: '',
    innerHTML: '',
    className: '',
    value: '',
    disabled: false,
    children: [],
    classList: {
      add(...cls) { cls.forEach(c => this._classes.add(c)); },
      remove(...cls) { cls.forEach(c => this._classes.delete(c)); },
      contains(c) { return this._classes.has(c); },
      _classes: new Set()
    },
    appendChild(child) { this.children.push(child); }
  });

  const ctx = vm.createContext({
    console,
    document: {
      cookie: 'brandsentinel_csrf=test-csrf-token-123',
      addEventListener() {},
      getElementById(id) {
        if (!elements.has(id)) {
          const el = element();
          elements.set(id, el);
        }
        return elements.get(id);
      },
      createElement: element
    },
    appData: {
      current_brand: { id: 'brand-northstar-tech', name: 'Northstar Technologies' }
    }
  });

  vm.runInContext(fs.readFileSync('static/js/app.js', 'utf8'), ctx);
  return { ctx, elements };
}

test('frontend verifies official channel ID match and displays required headline', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = 'https://www.youtube.com/@northstar_official';

  ctx.fetch = async (url, options) => {
    assert.equal(url, '/api/verify/youtube');
    assert.equal(options.method, 'POST');
    assert.equal(options.headers['X-CSRF-Token'], 'test-csrf-token-123');
    const body = JSON.parse(options.body);
    assert.equal(body.identifier, 'https://www.youtube.com/@northstar_official');
    assert.equal(body.brand_id, 'brand-northstar-tech');

    return {
      ok: true,
      json: async () => ({
        success: true,
        verification: {
          verdict: 'Official',
          channel_name: 'Northstar Technologies Official',
          channel_url: 'https://www.youtube.com/@northstar_official',
          stable_channel_id: 'UC_NORTHSTAR_OFFICIAL',
          summary: 'Official — Channel ID matches the brand’s registered official account.',
          reasons: [
            'Official — Channel ID matches the brand’s registered official account.',
            "Resolved channel ID 'UC_NORTHSTAR_OFFICIAL' matches registered official YouTube identity for 'Northstar Technologies'."
          ],
          evidence: {
            resolved_channel_id: 'UC_NORTHSTAR_OFFICIAL',
            registered_official_channel_ids: ['UC_NORTHSTAR_OFFICIAL'],
            brand_name: 'Northstar Technologies'
          },
          channel_metadata: {
            channel_id: 'UC_NORTHSTAR_OFFICIAL',
            thumbnail_url: 'https://example.com/thumb.jpg'
          }
        }
      })
    };
  };

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const resultCard = elements.get('ytVerifyResultCard');
  assert.equal(resultCard.classList.contains('hidden'), false);
  assert.match(resultCard.innerHTML, /Official — Channel ID matches the brand’s registered official account\./);
  assert.match(resultCard.innerHTML, /UC_NORTHSTAR_OFFICIAL/);
  assert.match(resultCard.innerHTML, /confirms a registered identity match, not that every video or message is safe/);
});

test('frontend displays suspected impersonation verdict with reasons and evidence', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = '@northstar_support_rewards';

  ctx.fetch = async () => ({
    ok: true,
    json: async () => ({
      success: true,
      verification: {
        verdict: 'Suspected impersonation',
        channel_name: 'Northstar Support Desk',
        channel_url: 'https://www.youtube.com/@northstar_support_rewards',
        stable_channel_id: 'UC_FAKE_SUPPORT_999',
        summary: 'Suspected impersonation — Different channel ID with meaningful evidence of impersonating Northstar Technologies.',
        reasons: [
          "Channel ID 'UC_FAKE_SUPPORT_999' does not match registered official account.",
          "Meaningful evidence of impersonating Northstar Technologies detected.",
          "Channel uses authority/official modifier: 'support'"
        ],
        evidence: {
          resolved_channel_id: 'UC_FAKE_SUPPORT_999',
          registered_official_channel_ids: ['UC_NORTHSTAR_OFFICIAL'],
          brand_name: 'Northstar Technologies',
          impersonation_indicators: ["Channel uses authority/official modifier: 'support'"],
          absence_of_disclosure: true
        }
      }
    })
  });

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const resultCard = elements.get('ytVerifyResultCard');
  assert.equal(resultCard.classList.contains('hidden'), false);
  assert.match(resultCard.innerHTML, /Suspected Impersonation/);
  assert.match(resultCard.innerHTML, /UC_FAKE_SUPPORT_999/);
  assert.match(resultCard.innerHTML, /Channel uses authority\/official modifier/);
  assert.match(resultCard.innerHTML, /support/);
});

test('frontend displays unrelated channel verdict without labeling as impersonator', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = 'https://www.youtube.com/@gardening_pro';

  ctx.fetch = async () => ({
    ok: true,
    json: async () => ({
      success: true,
      verification: {
        verdict: 'Unrelated',
        channel_name: 'Gardening Pro',
        channel_url: 'https://www.youtube.com/@gardening_pro',
        stable_channel_id: 'UC_GARDEN_123',
        summary: 'Unrelated — Available evidence indicates no meaningful relationship to Northstar Technologies.',
        reasons: [
          'Available evidence indicates no meaningful relationship to Northstar Technologies.',
          "Channel title ('Gardening Pro'), handle ('@gardening_pro'), and description do not reference the brand."
        ],
        evidence: {
          resolved_channel_id: 'UC_GARDEN_123',
          registered_official_channel_ids: ['UC_NORTHSTAR_OFFICIAL'],
          brand_name: 'Northstar Technologies',
          relationship_found: false
        }
      }
    })
  });

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const resultCard = elements.get('ytVerifyResultCard');
  assert.equal(resultCard.classList.contains('hidden'), false);
  assert.match(resultCard.innerHTML, /Unrelated Channel/);
  assert.doesNotMatch(resultCard.innerHTML, /Suspected Impersonation/);
  assert.doesNotMatch(resultCard.innerHTML, /Fake/);
});

test('frontend displays inconclusive verdict when brand official identity is missing', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = '@random_channel';

  ctx.fetch = async () => ({
    ok: true,
    json: async () => ({
      success: true,
      verification: {
        verdict: 'Inconclusive',
        channel_name: 'Random Channel',
        channel_url: 'https://www.youtube.com/@random_channel',
        stable_channel_id: 'UC_RANDOM_456',
        summary: 'Inconclusive — Missing official identity for Northstar Technologies.',
        reasons: [
          "The selected brand 'Northstar Technologies' does not have a registered official YouTube channel ID.",
          'Official status cannot be established without a registered baseline channel ID.'
        ],
        evidence: {
          resolved_channel_id: 'UC_RANDOM_456',
          registered_official_channel_ids: [],
          missing_official_identity: true
        }
      }
    })
  });

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const resultCard = elements.get('ytVerifyResultCard');
  assert.equal(resultCard.classList.contains('hidden'), false);
  assert.match(resultCard.innerHTML, /Inconclusive Evidence/);
  assert.match(resultCard.innerHTML, /Missing official identity/);
});

test('frontend renders clear error banner for unsupported video links without converting to scan result', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';

  ctx.fetch = async () => ({
    ok: false,
    json: async () => ({
      code: 'UNSUPPORTED_VIDEO_LINK',
      error: 'Unsupported video link: Direct video URLs cannot be verified. Please provide a YouTube channel URL, @handle, or UC... channel ID.'
    })
  });

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const errorBanner = elements.get('ytVerifyErrorBanner');
  const errorTitle = elements.get('ytVerifyErrorTitle');
  const errorMsg = elements.get('ytVerifyErrorMessage');
  const resultCard = elements.get('ytVerifyResultCard');

  assert.equal(errorBanner.classList.contains('hidden'), false);
  assert.equal(resultCard.classList.contains('hidden'), true);
  assert.match(errorTitle.innerHTML, /Unsupported Video Link/);
  assert.match(errorMsg.textContent, /Direct video URLs cannot be verified/);
});

test('frontend renders clear error banner for quota exhaustion', async () => {
  const { ctx, elements } = harness();
  ctx.document.getElementById('ytVerifyInput').value = '@northstar_official';

  ctx.fetch = async () => ({
    ok: false,
    json: async () => ({
      code: 'QUOTA_EXCEEDED',
      error: 'YouTube API quota limit exceeded. Daily quota units have been exhausted.'
    })
  });

  await vm.runInContext('handleVerifyYouTubeChannel()', ctx);

  const errorBanner = elements.get('ytVerifyErrorBanner');
  const errorTitle = elements.get('ytVerifyErrorTitle');
  const errorMsg = elements.get('ytVerifyErrorMessage');
  const resultCard = elements.get('ytVerifyResultCard');

  assert.equal(errorBanner.classList.contains('hidden'), false);
  assert.equal(resultCard.classList.contains('hidden'), true);
  assert.match(errorTitle.innerHTML, /YouTube API Quota Exceeded/);
  assert.match(errorMsg.textContent, /quota limit exceeded/);
});
