import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

const app = read('../src/App.tsx');
const layout = read('../src/AppLayout.tsx');
const navigation = read('../src/navigation.ts');
const palette = read('../src/CommandPalette.tsx');
const fuzzy = read('../src/lib/fuzzy.ts');
const health = read('../src/pages/Health.tsx');
const operations = read('../src/pages/Operations.tsx');
const logs = read('../src/pages/Logs.tsx');
const settings = read('../src/pages/Settings.tsx');
const appearance = read('../src/lib/appearance.ts');
const appearanceHook = read('../src/hooks/useAppearance.ts');
const main = read('../src/main.tsx');
const css = read('../src/index.css');
const peerRoutes = read('../../../apps/daemon/internal/adapters/api/routes_system.go');
const peerHandler = read('../../../apps/daemon/internal/adapters/api/handlers_peer_discovery.go');
const endpointHandler = read('../../../apps/daemon/internal/adapters/api/handlers_seventh_planners.go');
const endpointPlanner = read('../../../apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go');
const peerPlanner = read('../../../apps/daemon/internal/analysis/peerdiscovery/planner.go');
const bep42 = read('../../../apps/daemon/internal/analysis/peerdiscovery/bep42.go');
const updateStage = read('../../../apps/daemon/internal/foundation/updateadmission/stage.go');
const updateSyncUnix = read('../../../apps/daemon/internal/foundation/updateadmission/sync_stage_dir_unix.go');
const updateSyncWindows = read('../../../apps/daemon/internal/foundation/updateadmission/sync_stage_dir_windows.go');
const updateReplaceUnix = read('../../../apps/daemon/internal/foundation/updateadmission/replace_stage_file_unix.go');
const updateReplaceWindows = read('../../../apps/daemon/internal/foundation/updateadmission/replace_stage_file_windows.go');
const subscriptionRoutes = read('../../../apps/daemon/internal/adapters/api/routes_misc.go');
const subscriptionHandlers = read('../../../apps/daemon/internal/adapters/api/handlers_subscription.go');
const deepLinkParser = read('../../../apps/daemon/internal/integrations/sub/deeplink.go');
const profiles = read('../src/pages/Profiles.tsx');

const checks = [
  ['Health route is first-class', app.includes('path="health"') && app.includes('<Health') && navigation.includes("path: '/health'")],
  ['shared navigation is the UI source', layout.includes('navigationItems.map') && palette.includes('for (const item of navigationItems)')],
  ['command palette global shortcut', layout.includes("event.key.toLowerCase() === 'k'") && layout.includes('event.metaKey || event.ctrlKey')],
  ['command palette has dialog semantics', palette.includes('role="dialog"') && palette.includes('aria-modal="true"') && palette.includes('aria-labelledby="command-palette-title"')],
  ['command palette restores focus', palette.includes('previousFocusRef') && palette.includes('previousFocusRef.current?.focus()')],
  ['command palette traps tab focus', palette.includes("event.key === 'Tab'") && palette.includes('querySelectorAll<HTMLElement>') && palette.includes('last.focus()') && palette.includes('first.focus()')],
  ['command palette bounds and validates recents', palette.includes('const MAX_RECENTS = 5') && palette.includes('allowed.has(value)') && palette.includes('.slice(0, MAX_RECENTS)')],
  ['command palette local cache is non-authoritative', palette.includes('preference cache, never product authority')],
  ['fuzzy matcher is deterministic subsequence scoring', fuzzy.includes('deterministic subsequence matcher') && fuzzy.includes('run * 12') && fuzzy.includes('boundary') && fuzzy.includes('startsWith(lowerQuery)')],
  ['health reads three independent evidence sources', health.includes("'/api/doctor'") && health.includes("'/api/capabilities'") && health.includes("'/api/system/network-state?history=16'")],
  ['health accepts structured unhealthy doctor response', health.includes('response.status !== 200 && response.status !== 503')],
  ['health never converts no evidence into healthy', health.includes("return 'unavailable'") && health.includes('This is not reported as healthy')],
  ['health source failures remain visible', health.includes('sourceErrors') && health.includes('Health source unavailable') && health.includes('role="alert"')],
  ['health timeline is bounded', health.includes('.slice(0, 32)')],
  ['diagnostic bundle is explicitly redacted', health.includes("schema: 'luminet.redacted-diagnostics.v1'") && health.includes('intentionally excludes')],
  ['diagnostic bundle states excluded sensitive classes', health.includes('configuration bodies') && health.includes('API keys') && health.includes('raw logs') && health.includes('hardware addresses') && health.includes('credential-bearing URLs')],
  ['diagnostic bundle exports local evidence', health.includes('new Blob') && health.includes('luminet-diagnostics-')],
  ['diagnostic export omits free-form readiness messages', !health.includes('message: check.message') && health.includes('latency_ns: check.latencyNs')],
  ['diagnostic export collapses raw source failures to source names', health.includes("source_errors: snapshot.sourceErrors.map((item) => item.split(':', 1)[0])")],
  ['diagnostic export records network error presence without raw text', health.includes('last_error_present: Boolean(network.lastError)') && !health.includes('last_error: network.lastError')],
  ['endpoint planner accepts network-quality evidence', endpointPlanner.includes('JitterMs') && endpointPlanner.includes('PacketLossPct')],
  ['endpoint planner has bounded deterministic diversity', endpointPlanner.includes('stableScopeHash') && endpointPlanner.includes('endpointDiversityBand') && endpointPlanner.includes('fnv.New64a')],
  ['endpoint planner keeps last-known-good quality bounded', endpointPlanner.includes('PreviousSuccessful') && endpointPlanner.includes('bestScore-previousScore > endpointDiversityBand')],
  ['endpoint planner reports selection provenance', endpointPlanner.includes('SelectionBasis') && endpointPlanner.includes('ReusedPreviousSuccess') && endpointPlanner.includes('DiversityApplied')],
  ['endpoint API exposes new evidence only through planner', endpointHandler.includes('PreviousSuccessful') && endpointHandler.includes('Scope') && endpointHandler.includes('BuildEndpointPoolPlanWithOptions')],
  ['operations exposes endpoint evidence and preferred result', operations.includes('jitter') && operations.includes('loss') && operations.includes('Last-known-good hint') && operations.includes('Preferred')],
  ['peer discovery route is explicit', peerRoutes.includes('sys.POST("/peer-discovery-plan"')],
  ['peer discovery planner is bounded', peerPlanner.includes('MaxCandidates') && peerPlanner.includes('MaxResults') && peerPlanner.includes('candidate count must be between')],
  ['peer discovery is public-address only', peerPlanner.includes('netpolicy.IsPublicAddress') && peerPlanner.includes('non-public-address')],
  ['peer discovery has bounded local CIDR deny policy without DNSBL I/O', peerPlanner.includes('MaxBlockedCIDRs = 128') && peerPlanner.includes('blocked-address') && peerPlanner.includes('local CIDR deny policy only; no DNSBL lookups')],
  ['peer discovery treats shared public addresses as evidence rather than false identity failure', peerPlanner.includes('SharedAddressObserved') && peerPlanner.includes('SharedAddressCount') && peerPlanner.includes('Multiple valid peers behind one public address can be legitimate')],
  ['peer discovery rejects duplicate and self identities', peerPlanner.includes('"self"') && peerPlanner.includes('duplicate-node-id') && peerPlanner.includes('duplicate-endpoint')],
  ['peer discovery uses exact XOR ordering', peerPlanner.includes('xorDistance') && peerPlanner.includes('accepted[i].Distance < accepted[j].Distance')],
  ['peer trust cannot override identity/admission', peerPlanner.includes('TrustObserved') && peerPlanner.includes('TrustScore') && peerPlanner.includes('no DNSBL lookups, sockets, peer dialing, persistence, route mutation, or trust-based identity bypass')],
  ['BEP42 uses CRC32C and IPv4-bound mask', bep42.includes('crc32.Castagnoli') && bep42.includes('0x030f3fff')],
  ['peer handler only reads runtime trust evidence', peerHandler.includes('SnapshotScores()') && peerHandler.includes('peerdiscovery.BuildPlan')],
  ['operations labels peer plane read-only', operations.includes('Peer discovery admission') && operations.includes('Read-only') && operations.includes('never dials')],
  ['operations exposes local peer deny policy and shared-address evidence', operations.includes('Local blocked IPv4 CIDRs') && operations.includes('blocked_cidrs') && operations.includes('shared address ×')],
  ['logs pause tail follow on operator scroll', logs.includes('shouldStickToBottom') && logs.includes('<= 24') && logs.includes('setFollowTail(atBottom)')],
  ['logs offer explicit tail resume', logs.includes('Resume live tail') && logs.includes('resumeTail')],
  ['appearance has bounded preference vocabulary', appearance.includes("value === 'system' || value === 'dark' || value === 'light'")],
  ['appearance follows OS without remote authority', appearance.includes("'(prefers-color-scheme: dark)'") && settings.includes('never changes daemon configuration')],
  ['appearance tolerates local-storage failure', appearance.includes('try {') && appearance.includes('preference cache, never product authority')],
  ['appearance supports cross-tab sync', appearance.includes("window.addEventListener('storage', syncFromStorage)")],
  ['appearance initializes before React paint', main.includes('initializeAppearance();') && main.indexOf('initializeAppearance();') < main.indexOf('ReactDOM.createRoot')],
  ['appearance hook uses external-store semantics', appearanceHook.includes('useSyncExternalStore') && appearanceHook.includes('subscribeAppearance')],
  ['settings exposes accessible appearance radiogroup', settings.includes('role="radiogroup"') && settings.includes('role="radio"') && settings.includes('aria-checked={appearance === value}')],
  ['light palette overrides semantic tokens', css.includes(':root[data-theme="light"]') && css.includes('--color-bg-primary: #f7f9fc') && css.includes('--color-text-primary: #0f172a')],
  ['staged artifact publication fsyncs its directory on Unix', updateStage.includes('syncStageDirectory(filepath.Dir(target))') && updateSyncUnix.includes('dir.Sync()')],
  ['Unix staged publication uses atomic rename-overwrite', updateReplaceUnix.includes('return os.Rename(source, target)') && !updateReplaceUnix.includes('os.Remove(target)')],
  ['Windows staged publication has explicit portable replacement fallback', updateReplaceWindows.includes('os.Remove(target)') && updateReplaceWindows.includes('os.Rename(source, target)')],
  ['Windows staging sync limitation is explicit', updateSyncWindows.includes('func syncStageDirectory') && updateSyncWindows.includes('return nil')],
  ['old generic Rust mutation-retry owner is absent from product surfaces', !layout.includes('mutation_retry') && !operations.includes('mutation_retry')],
  ['deep-link admission route is inspect-only', subscriptionRoutes.includes('POST("/deeplink/inspect"') && subscriptionHandlers.includes('InspectSubscriptionDeepLink') && subscriptionHandlers.includes('requires_confirmation')],
  ['deep-link parser only accepts luminet import and canonical HTTPS source validation', deepLinkParser.includes('luminet://import') && deepLinkParser.includes('ValidateProfileSourceURL(source)') && deepLinkParser.includes('subscription URL must not embed credentials')],
  ['deep-link parser is bounded and rejects unsupported parameters', deepLinkParser.includes('maxDeepLinkLength') && deepLinkParser.includes('= 4096') && deepLinkParser.includes('unsupported deep-link parameter') && deepLinkParser.includes('must appear exactly once')],
  ['deep-link product flow is explicit inspect then prefill', profiles.includes('Inspect & prefill') && profiles.includes('never fetches, saves, refreshes, or activates') && profiles.includes('Review the proposed profile below, then create it explicitly')],
];

const failed = checks.filter(([, ok]) => !ok);
for (const [name, ok] of checks) {
  if (!ok) console.error(`FAIL: ${name}`);
}
if (failed.length) process.exit(1);
assert.ok(checks.length >= 40, 'post-refactor convergence suite should remain broad');
console.log(`Post-refactor-222 convergence characterization: ${checks.length} checks passed`);
