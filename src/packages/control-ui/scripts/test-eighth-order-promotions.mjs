import { readFileSync } from 'node:fs';

const connections = readFileSync(new URL('../src/pages/Connections.tsx', import.meta.url), 'utf8');
const flowApi = readFileSync(new URL('../src/api/flows.ts', import.meta.url), 'utf8');
const profiles = readFileSync(new URL('../src/pages/Profiles.tsx', import.meta.url), 'utf8');
const operations = readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');
const recoveryApi = readFileSync(new URL('../src/api/recovery.ts', import.meta.url), 'utf8');
const conversionApi = readFileSync(new URL('../src/api/conversion.ts', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const layout = readFileSync(new URL('../src/AppLayout.tsx', import.meta.url), 'utf8');
const navigation = readFileSync(new URL('../src/navigation.ts', import.meta.url), 'utf8');
const routes = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/routes_system.go', import.meta.url), 'utf8');
const miscRoutes = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/routes_misc.go', import.meta.url), 'utf8');
const handlers = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_system_flows.go', import.meta.url), 'utf8');
const netHandler = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_system_network_state.go', import.meta.url), 'utf8');
const networkIntelligenceHandler = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_system_network_intelligence.go', import.meta.url), 'utf8');
const recovery = readFileSync(new URL('../../../apps/daemon/internal/workflows/jobs/recovery.go', import.meta.url), 'utf8');
const historyHandlers = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_history.go', import.meta.url), 'utf8');
const flowRegistry = readFileSync(new URL('../../../apps/daemon/internal/foundation/flowregistry/registry.go', import.meta.url), 'utf8');
const conversionHandler = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_subscription_convert.go', import.meta.url), 'utf8');
const roundTrip = readFileSync(new URL('../../../apps/daemon/internal/integrations/sub/roundtrip.go', import.meta.url), 'utf8');
const capabilitiesPage = readFileSync(new URL('../src/pages/Capabilities.tsx', import.meta.url), 'utf8');
const capabilitiesApi = readFileSync(new URL('../src/api/capabilities.ts', import.meta.url), 'utf8');
const capabilitiesHandler = readFileSync(new URL('../../../apps/daemon/internal/adapters/api/handlers_capabilities.go', import.meta.url), 'utf8');

const checks = [
  ['Connections route', app.includes('path="connections"') && app.includes('<Connections')],
  ['Connections navigation', navigation.includes('Connections') && layout.includes('Network')],
  ['owner-declared coverage truth', connections.includes('Runtime coverage truth') && connections.includes('coverageComplete') && connections.includes('coverageModel')],
  ['partial visibility warning', connections.includes('Missing coverage is shown explicitly') && connections.includes('host has no other connections')],
  ['explicit selected-flow close', connections.includes('Close selected') && connections.includes('confirm: true') && connections.includes('window.confirm')],
  ['no UI close-all affordance', !connections.includes('Close all') && !connections.includes('closeAll')],
  ['flow network epoch presentation', connections.includes('networkEpoch') && connections.includes('pre-handoff')],
  ['passive network handoff history', connections.includes('Passive network state') && connections.includes('networkState?.history') && connections.includes('Recent handoffs')],
  ['flow list API route', routes.includes('sys.GET("/flows"')],
  ['single flow delegated close route', routes.includes('sys.DELETE("/flows/:id"')],
  ['bounded explicit bulk close route', routes.includes('sys.POST("/flows/close"') && handlers.includes('MaxBulkCloseFlows') && handlers.includes('explicit confirmation is required')],
  ['coverage never claims host completeness', handlers.includes('CoverageComplete: false') && handlers.includes('participating-runtime-owners-only')],
  ['passive network-state endpoint', routes.includes('sys.GET("/network-state"') && netHandler.includes('GetNetworkMonitor')],
  ['derived network-intelligence endpoint', routes.includes('sys.GET("/network-intelligence"') && networkIntelligenceHandler.includes('netintel.Build') && networkIntelligenceHandler.includes('DefaultService.Lookup')],
  ['path intelligence is passive/local-only', connections.includes('Path intelligence') && connections.includes('No DNS, GeoIP fetch, scan, route mutation, or runtime mutation')],
  ['safe integer transport parsing', flowApi.includes('Number.isSafeInteger')],
  ['local provider attribution', flowApi.includes('destination_provider') && connections.includes('destinationProvider.displayName') && connections.includes('destinationProvider.prefix')],
  ['provider corpus freshness truth', flowApi.includes('corpus_stale') && connections.includes('stale corpus') && handlers.includes('CorpusStale: status.Stale')],
  ['bulk close is all-or-nothing above bound', flowRegistry.includes('bulk close exceeds') && flowRegistry.includes('return nil, fmt.Errorf') && handlers.includes('resultMap, err := flowregistry.Default().CloseIDs')],
  ['profile conversion API route', miscRoutes.includes('subs.POST("/convert"') && miscRoutes.includes('CapProfileConversion')],
  ['compatibility lab local-only copy', profiles.includes('Compatibility lab') && profiles.includes('never fetches URLs') && profiles.includes('never mutates managed profiles')],
  ['compatibility strict toggle', profiles.includes('Strict compatibility') && profiles.includes('strict: conversionStrict')],
  ['five conversion targets', ['uri-list', 'base64', 'luminet-json', 'clash-meta', 'sing-box'].every((target) => conversionApi.includes(target))],
  ['bounded compatibility issue rendering', profiles.includes('.issues.slice(0, 100)')],
  ['local shaping pipeline', profiles.includes('Local shaping pipeline') && profiles.includes('transform:') && profiles.includes('deduplicate: conversionDeduplicate') && profiles.includes('sort_by: conversionSortBy')],
  ['transformation result parsing', conversionApi.includes('transformation?: TransformReport') && conversionApi.includes('transformation input_nodes')],
  ['detour-safe shaping copy', profiles.includes('Detour chains fail closed if a filter or limit would orphan a hop')],
  ['strict conversion requires local re-ingest proof', conversionHandler.includes('ValidateRoundTrip') && conversionHandler.includes('strict conversion failed local round-trip validation') && roundTrip.includes('no network or process side effects')],
  ['round-trip result is typed and bounded in UI', conversionApi.includes('roundTrip?: RoundTripReport') && conversionApi.includes('round-trip exact_nodes') && profiles.includes('Local re-ingest proof') && profiles.includes('.issues.slice(0, 100)')],
  ['round-trip graph drift is explicit', roundTrip.includes('detour_change') && roundTrip.includes('semantic_change') && profiles.includes('drift detected')],
  ['restart recovery routes', miscRoutes.includes('rg.GET("/jobs/:id/recovery"') && miscRoutes.includes('rg.POST("/jobs/:id/requeue"')],
  ['restart recovery is explicit new execution', recovery.includes('operator-confirmed-new-job') && recovery.includes('RecoveredFrom') && historyHandlers.includes('confirm=true is required')],
  ['restart recovery has no boot replay contract', recovery.includes('GetRecoveryInfo') && recovery.includes('RequeueInterrupted') && !recovery.includes('init()')],
  ['operator recovery widget', operations.includes('Interrupted job recovery') && operations.includes('Inspect recovery') && operations.includes('Confirm & create new execution')],
  ['operator recovery requires explicit confirm', operations.includes('window.confirm') && operations.includes('JSON.stringify({ confirm: true })') && recoveryApi.includes('requeueAvailable')],
  ['operator recovery shows active descendant truth', operations.includes('activeDescendant') && recoveryApi.includes('active_descendant')],
  ['capability center route', app.includes('path="capabilities"') && app.includes('<Capabilities') && layout.includes("'/capabilities'")],
  ['capability center separates evidence dimensions', capabilitiesPage.includes('Capability & coverage center') && capabilitiesPage.includes('Runtime flow coverage') && capabilitiesPage.includes('Passive network observation') && capabilitiesPage.includes('Provider corpus')],
  ['capability report parser is typed and bounded', capabilitiesApi.includes('parseCapabilityReport') && capabilitiesApi.includes('Number.isSafeInteger') && capabilitiesApi.includes('coverageComplete')],
  ['capability API reports partial flow truth', capabilitiesHandler.includes('coverage_complete') && capabilitiesHandler.includes('participating-runtime-owners-only') && capabilitiesHandler.includes('flowregistry.Default().Coverage()')],
  ['capability API reports passive network and corpus freshness independently', capabilitiesHandler.includes('GetNetworkMonitor().Status(0)') && capabilitiesHandler.includes('DefaultService.Status') && capabilitiesHandler.includes('missing evidence is never promoted to availability')],
];

const failed = checks.filter(([, ok]) => !ok);
if (failed.length) {
  for (const [name] of failed) console.error(`FAIL: ${name}`);
  process.exit(1);
}
console.log(`Eighth-order feature-promotion characterization: ${checks.length} checks passed`);
