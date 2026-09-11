import { expect, test, type Page, type Route } from '@playwright/test';

const now = '2026-09-10T11:00:00Z';

function flow(id: string, host = `${id}.example`) {
  return {
    id,
    owner: 'proxy',
    network: 'tcp',
    protocol: 'tls',
    source: '127.0.0.1:10000',
    destination: `${host}:443`,
    host,
    process: 'luminet',
    process_path: '/usr/bin/luminet',
    rule: 'direct',
    rule_payload: '',
    chain: [],
    labels: {},
    started_at: now,
    last_activity_at: now,
    upload_bytes: 1,
    download_bytes: 2,
    network_epoch: 1,
    state: 'active',
    closeable: true,
    destination_provider: null,
  };
}

function flowList(flows: ReturnType<typeof flow>[], matched = flows.length) {
  return {
    flows,
    coverage: [{
      owner: 'proxy', visible: true, closeable: true, byte_counters: true,
      process_attribution: true, destination_metadata: true, notes: [],
    }],
    stats: {
      active: flows.length, closing: 0, capacity: 4096,
      upload_bytes: flows.length, download_bytes: flows.length * 2,
    },
    matched,
    returned: flows.length,
    network_revision: 1,
    coverage_complete: false,
    coverage_model: 'participating-runtime-owners',
  };
}

const networkState = {
  running: true,
  current: {
    revision: 1,
    captured_at: now,
    fingerprint: 'test',
    interfaces: [],
    default_ipv4_interface: 'eth0',
    default_ipv4_local_ip: '192.0.2.2',
    default_ipv6_interface: '',
    default_ipv6_local_ip: '',
  },
  history: [],
  last_error: '',
};

const networkIntelligence = {
  generated_at: now,
  coverage_complete: false,
  coverage_model: 'participating-runtime-owners',
  network_revision: 1,
  network_captured_at: now,
  default_ipv4_interface: 'eth0',
  default_ipv4_local_ip: '192.0.2.2',
  default_ipv6_interface: '',
  default_ipv6_local_ip: '',
  active_interfaces: 1,
  retained_handoffs: 0,
  latest_handoff_kinds: [],
  active_flows: 0,
  closing_flows: 0,
  pre_handoff_flows: 0,
  unknown_epoch_flows: 0,
  unattributed_flows: 0,
  upload_bytes: 0,
  download_bytes: 0,
  distinct_protocols: 1,
  distinct_providers: 0,
  provider_corpus_ready: false,
  provider_corpus_id: '',
  provider_corpus_stale: false,
  owners: [],
  providers: [],
};

async function mockConnectionCompanions(page: Page) {
  await page.route('**/api/system/network-state*', (route) => route.fulfill({ json: networkState }));
  await page.route('**/api/system/network-intelligence*', (route) => route.fulfill({ json: networkIntelligence }));
}

async function delayedFulfill(route: Route, ms: number, json: unknown) {
  await new Promise((resolve) => setTimeout(resolve, ms));
  if (route.request().isNavigationRequest()) return;
  await route.fulfill({ json }).catch(() => undefined);
}

test('Connections suppresses an older response after filters change', async ({ page }) => {
  await mockConnectionCompanions(page);
  await page.route('**/api/system/flows*', async (route) => {
    const requestURL = new URL(route.request().url());
    const query = requestURL.searchParams.get('q') ?? '';
    if (query === '') {
      await delayedFulfill(route, 700, flowList([flow('stale', 'stale.example')]));
      return;
    }
    await route.fulfill({ json: flowList([flow('fresh', 'fresh.example')]) });
  });

  await page.goto('/#/connections');
  const search = page.getByRole('textbox', { name: 'Search connections' });
  await search.fill('fresh');

  await expect(page.getByText('fresh.example:443')).toBeVisible();
  await page.waitForTimeout(900);
  await expect(page.getByText('stale.example:443')).toHaveCount(0);
});

test('Connections bounds initial DOM rows and expands only on request', async ({ page }) => {
  await mockConnectionCompanions(page);
  const flows = Array.from({ length: 250 }, (_, index) => flow(`flow-${index}`));
  await page.route('**/api/system/flows*', (route) => route.fulfill({ json: flowList(flows, 250) }));

  await page.goto('/#/connections');
  const table = page.locator('section[aria-labelledby="flow-table-title"] tbody');
  await expect(table.locator('tr')).toHaveCount(100);
  await expect(page.getByText('Rendering 100 of 250 fetched flows.')).toBeVisible();

  await page.getByRole('button', { name: 'Show 100 more' }).click();
  await expect(table.locator('tr')).toHaveCount(200);
});

test('Connections confirms owner teardown and removes a successfully closed flow', async ({ page }) => {
  await mockConnectionCompanions(page);
  let closed = false;
  let deleteSeen = false;
  const corsHeaders = {
    'access-control-allow-origin': 'http://127.0.0.1:4173',
    'access-control-allow-methods': 'GET, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type, x-api-key',
  };
  await page.route(/\/api\/system\/flows(?:\/.*|\?.*)?$/, async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: corsHeaders });
      return;
    }
    if (request.method() === 'DELETE' && pathname.endsWith('/close-me')) {
      deleteSeen = true;
      closed = true;
      await route.fulfill({ status: 200, headers: corsHeaders, json: { status: 'closed' } });
      return;
    }
    await route.fulfill({ headers: corsHeaders, json: flowList(closed ? [] : [flow('close-me', 'close-me.example')]) });
  });
  page.on('dialog', (dialog) => void dialog.accept());

  await page.goto('/#/connections');
  const row = page.getByRole('row').filter({ hasText: 'close-me.example:443' });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Close' }).click();

  await expect.poll(() => deleteSeen).toBe(true);
  await expect(page.getByText('close-me.example:443')).toHaveCount(0);
});

test('Connections exposes a degraded daemon failure and recovers on explicit retry', async ({ page }) => {
  await mockConnectionCompanions(page);
  let degraded = true;
  await page.route('**/api/system/flows*', (route) => {
    if (degraded) return route.fulfill({ status: 503, json: { error: 'daemon warming up' } });
    return route.fulfill({ json: flowList([flow('recovered', 'recovered.example')]) });
  });

  await page.goto('/#/connections');
  await expect(page.getByRole('alert')).toContainText('status 503: daemon warming up');

  degraded = false;
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(page.getByText('recovered.example:443')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('Settings keeps local controls accessible and excludes remote deployment fields', async ({ page }) => {
  await page.route('**/api/system/evasion-tunnel', (route) => route.fulfill({
    json: {
      running: false,
      split_bytes: 2,
      delay_ms: 10,
      mutate_host: false,
      fake_packet_inject: false,
      ws_use_utls: false,
      ws_fingerprint: 'firefox',
    },
  }));

  await page.goto('/#/settings');
  await expect(page.getByRole('slider', { name: 'ClientHello Split Offset' })).toBeVisible();
  await expect(page.getByRole('slider', { name: 'Inter-packet Desync Delay' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Auth Email' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Upload Script' })).toHaveCount(0);
});

test('Deployment owns accessible remote Worker mutation and announces verification limits', async ({ page }) => {
  await page.route('**/api/system/cloudflare-deploy', (route) => route.fulfill({
    json: {
      status: 'success',
      verified: false,
      message: 'Cloudflare accepted the Worker script upload; runtime protocol behavior was not verified',
    },
  }));

  await page.goto('/#/deployment');
  await expect(page.getByRole('textbox', { name: 'Auth Email' })).toBeVisible();
  await expect(page.getByLabel('API Token')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Account ID' })).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Worker JavaScript source' })).toBeVisible();

  await page.getByRole('textbox', { name: 'Auth Email' }).fill('operator@example.com');
  await page.getByLabel('API Token').fill('test-token');
  await page.getByRole('textbox', { name: 'Account ID' }).fill('account');
  await page.getByRole('button', { name: 'Upload Script' }).click();

  const status = page.getByRole('status');
  await expect(status).toContainText('Cloudflare accepted the Worker script upload');
  await expect(status).toContainText('does not verify VLESS');
});
