# LumiNet Current-System Manual

Status: **current consolidation reference**  
Reviewed: **2026-08-10**

This document describes the repository as it exists now. It is the bridge
between the implementation and the historical/product documents. A claim is
not supported merely because it appears in an older plan, generated report,
or porting compendium.

## Authority order

1. Runtime code, tests, build manifests, and generated schemas.
2. `governance/conductor/` ABI, preservation, and provenance ledgers.
   Repository tooling resolves these canonical authorities from repository root; command-line paths are explicit overrides, not duplicated defaults.
3. This manual, current architecture documents, and accepted ADRs.
4. Product/design/strategy and operational documents, when consistent with the above.
5. Porting reports, excluded-project notes, simulations, and session state are
   historical evidence only.

When two documents disagree, preserve the more capable behavior only after it
has an owner, a compatibility test, and truthful capability reporting.

## Runtime topology

- `src/apps/daemon/` owns orchestration, API and WebSocket surfaces, persistence,
  scheduling, policy, subscription aggregation, scanners, and platform
  control.
- `src/apps/daemon/internal/runtime/runtimecore/` is the single long-lived runtime-engine owner for Tor and Psiphon. Callers use its `Start`/`Stop`/`Status`/`Close` interface and do not own engine maps or process objects; the concrete Tor/Psiphon subprocess adapters and lifecycle tests live under the same owner. The separate proxy `CoreManager` remains a temporary Xray/sing-box runner for proxy tests; it is not runtime state authority. Embedded Tailscale is not a supported runtime and its compatibility route reports that explicitly.
- WebSocket telemetry has one live transport owner at `internal/adapters/api.Hub`. RX/TX are rates derived from the monotonic `internal/foundation/trafficstats` byte counters, one JSON envelope is sent per frame, and unavailable tunnel latency is represented as `null` rather than a fabricated zero. Diagnostic jobs use their job/REST status paths; the unused standalone telemetry server is preserved under `labs/daemon/system-alternates/`.
- `labs/daemon/` is a governed, non-authoritative capability corpus. Lab code is preserved and catalogued but is not imported by the live daemon; promotion requires extraction into a canonical owner with explicit verification.
- `src/packages/lumicore/` owns selected native and performance-sensitive execution behind the
  versioned ABI described by `governance/conductor/abi/`.
- `src/packages/lumicore-sdk/` ships the embeddable C header and the pure-Python `luminet`
  bindings for the lumicore ABI. The Python SDK degrades to documented pure-Python fallbacks
  when the native library is absent; its unit tests run under `make test-lumicore-sdk`.
- `src/apps/daemon/internal/adapters/mobilebind/` is the canonical generated mobile binding adapter
  exported by the release workflow. It translates gobind-compatible JSON and lifecycle calls
  into the same runtime and safety-policy owners used by other transports; it does not own
  independent runtime state or capability truth. Historical portable client facades under
  `client/` had no live product or release consumer and are retired; Android consumes the generated
  `mobilebind` AAR directly, while platform socket protection is owned by daemon `platform/mobilehost`.
  Supported UI code and the production embed bundle are owned by `src/packages/control-ui/`.
- `src/apps/desktop/` contains the single Wails host package. Authored React source and the production embed bundle are owned by `src/packages/control-ui/` and consumed by both daemon and desktop.
- `labs/desktop/platform-alternates/` preserves hash-accounted desktop/platform sidecars that have no product import/build edge.
- `src/apps/android/` is the canonical Android application source root with one Activity, one mobile-local per-app policy owner, one passive physical-underlay observer, and one `VpnService`. Package selection is validated before `VpnService.Builder` mutation and uses exactly one allow/disallow mode per tunnel. The underlay observer watches only `INTERNET + NOT_VPN` networks and never calls `requestNetwork`; socket protection remains the routing-safety authority. The service transfers its TUN descriptor to the generated `mobilebind` AAR, whose real data plane is `CoreController -> mobilehost.StartTun2SocksWithDNS`. Release publishes both the AAR and the linked APK.
- `deploy/` contains the canonical bundled Cloudflare worker and serverless
  adapters. deployable templates live under `deploy/templates/`; shared relay policy and adapters live under `deploy/relays/`.

Go owns control-plane behavior; Rust owns selected host data-plane behavior. Host CGO builds consume one checked private declaration surface at `src/apps/daemon/internal/native/bridge/lumicore_abi.h`, while Cargo owns static-library/native-link requirements. The supported Android host selects the pure-Go bridge path rather than host Rust CGO. Target-specific iOS source remains guarded code, not a shipped host or release artifact. FFI boundaries must version layouts, define ownership, prevent panic unwinding across C boundaries, and return structured failures.
The shared host-FFI Tokio runtime is fallible and process-owned rather than panic-initialized. The retained streaming ABI has no production Go caller and its current scan body is a stub, so it is not a supported scan capability; Cargo-backed CI is required before that ABI can be retired or implemented. Its ownership contract remains guarded: streaming startup fails with a zero handle when the runtime is unavailable, cancellation is a signal rather than deallocation, Rust retains stream ownership until a single terminal callback, and only that terminal callback lets the dormant Go bridge close the channel and free its callback context. Stream-event numeric constants are checked across Rust and the private C header.

## Capability truth

Every public status, health, and capability response distinguishes:

- `available`: the advertised path is implemented and verified for the target.
- `degraded`: the path works with an explicit limitation or fallback.
- `unavailable`: the dependency, platform, or transport is absent.

Stubs, configuration-only generators, log-only shells, missing native
libraries, and unverified simulations must not report `available` or `ready`.

Operational controls must cross the production runtime owner that consumes their state. The 20 advanced system compatibility registrations carry explicit capability truth; disconnected controls fail closed rather than creating handler-owned state. `GET /api/routes` is the served-route authority and reports workflow/capability/availability metadata from the live Gin inventory.

## Cross-cutting safety contracts

- System DNS, proxy, firewall, certificate, and TUN mutations use snapshot,
  apply, verify, rollback, and crash-recovery steps. Configuration-only HTTP intents use one optimistic-concurrency owner: server-owned side-effect-free intents may replay against a fresh authoritative snapshot on revision conflict with a default budget of 3 and hard cap of 8, while explicit client revision preconditions are single-attempt. Runtime/network side effects happen only after durable commit.
- Remote subscription ingestion is owned by `internal/integrations/sub`: refresh work is daemon-cancellable, remote fetch is bounded and SSRF-safe, and format normalization has one owner. Conditional ETags are source-scoped, stripped across cross-origin redirects, and accepted only after payload validation; invalid 2xx bodies cannot advance freshness or replace last-known-good state, while a valid 304 renews source health without replacing content. Canonical per-node parsing flows through `internal/networking/proxyconfig`; retired Telegram/alternate parser corpus is not product capability.
- Credentials, tokens, authorization references, raw subscription URLs, and
  internal endpoints are redacted before logs, metrics, previews, events,
  exports, and public errors.
- Native secret stores are required for production TPM migration. Migration is
  copy-on-write, verified after reopen, atomically activated, rollback-readable,
  and cutoff-controlled.
- Go values containing synchronization primitives are never copied. Snapshot
  data under locks and clone only data fields.
- Provider, subscription, routing, scanner, probe, runtime-core, certificate,
  and traffic-policy owners publish one canonical state; compatibility layers
  delegate and do not maintain parallel business state.

## Relay and worker modes

Worker runtimes retain their mechanisms while sharing policy and terminology:

- `fixed-http`: deployment-owned target, path/query preservation, sanitized
  headers, request ID, integer hop count, bounded body, stable errors.
- `envelope-http`: versioned buffered envelope for compatibility clients;
  arbitrary targets require explicit SSRF and redirect policy before use.
- `doh`: RFC 8484 GET/POST with one-shot body materialization, explicit
  provider/failover policy, CORS, and resolver-safe headers.
- `websocket-tcp`: versioned handshake, destination policy, backpressure, and
  deterministic close mapping; VLESS remains a compatibility adapter.

The shared fixed-target policy is implemented in
`deploy/relays/fixed_http_contract.mjs`. Vercel provides the streaming
reference adapter; Cloudflare provides edge/request adapters; Apps Script
retains buffered ordered failover. Runtime-specific strengths are not erased.

## Verification baseline

Changed domains require normal-path, failure-path, and integration-edge tests.
The release evidence set includes:

- `make verify-release` as the canonical tag/publication admission interface; CI and release consume the same compiler/test/truth/security/preservation seam.
- Go tests, vet, and race tests for changed packages.
- Rust format, check, Clippy, and tests for changed crates.
- Frontend install, lint, build, and audit checks.
- ABI layout, allocation/free, version mismatch, and package-load smoke tests.
- SSRF, redirect, redaction, authentication, rollback, missing-dependency,
  and unavailable-capability tests.
- Artifact target, ABI version, checksum, manifest, SBOM/license, and package
  smoke evidence.

Documentation checklists are not test evidence. A `ready` review requires
dated evidence links, existing referenced artifacts, and no unexplained open
rounds.

Repository verification also enforces request-context ownership, subscription ownership, served-route truth, operational capability truth, runtime-core locality, and evidence-backed retirement. Active internal source with no product consumer is removed only after dynamic/native/platform stop conditions are dispositioned; historical migrations and governed lab provenance are not treated as runtime code.

Architecture reviews optimize for module depth rather than package count: large modules remain when their caller-visible interface is small and coherent, while one-caller modules remain when they hide state, protocol, process-lifetime, platform, curated-data, or external-adapter complexity. Shallow pass-through and zero-consumer implementations are retired instead of preserved for hypothetical reuse.

## Documentation lifecycle

- Current implementation and contract documents remain in their functional
  locations and must be refreshed when code changes.
- The post-convergence ownership decisions are recorded in `docs/adr/`. Older execution plans are historical inputs, not current runtime authority.
- `governance/conductor/` ledgers and schemas are machine-facing authorities.
- `docs/excluded/`, porting compendia, Tor investigations, and old design
  references are archive/provenance material, not implementation truth.
- Generated graphs, session state, unlinked snapshots, and dangling live-edit
  configuration are disposable and must not be used to approve a release.

## Naming and compatibility

Use canonical names for new code: `provider`, `subscription`, `relay`,
`fixed-http`, `envelope-http`, `websocket-tcp`, `capability`, `status`, and
`snapshot`. Keep legacy wire keys, CLI flags, and exported compatibility
functions only where consumers require them; implement them as thin adapters
and mark their ownership in tests. Do not rename a public symbol or wire field
without a migration fixture and a release-cycle deprecation plan.
## Eighth-order resilience convergence (2026-08-13)

The current runtime has three additional resilience contracts established by the eighth-order peer-convergence pass:

1. **Automatic remote mutation retry is authority-aware and coordinated across calls.** Mutations use `internal/foundation/remoteaction`; replay remains limited to declared `idempotent` or `reconcile-before-retry` actions, while `single-attempt` actions are never replayed. Provider `429`/`Retry-After` state is remembered in a bounded in-memory coordinator keyed by canonical action ID, so concurrent or periodic callers share cooldown without storing URLs/secrets or blocking unrelated actions. Aggregate counters are exposed as `remote_mutation_retry` in `GET /api/system/status`.
2. **DNS cache memory and refresh behavior have one bounded primitive.** DoH HTTP caching, weighted DoH proxy caching, and failover resolver caching use a bounded TTL/LRU owner. DoH HTTP errors are never cached as successful answers; same-key misses are coalesced; stale answers are eligible only inside the configured stale window and only after refresh failure; maintenance is context-cancellable; resolver provider/client configuration is snapshot-safe and empty provider state fails closed.
3. **Child-process readiness is not equivalent to health.** `ProcessSupervisor` escalates short ready-then-crash loops. Consecutive backoff debt is reset only after a meaningful stable-ready interval, while the independent rolling failure history remains intact and is pruned against its time window during recording/evaluation.

The pass does **not** add a second generic scheduler, second host-network mutator, or donor-specific DNS proxy daemon. Existing service-owned profile refresh, host-network snapshot/apply/verify/rollback, process supervision, and DNS owners remain authoritative.

## Post-refactor-160 convergence (2026-08-14)

The 19-peer post-refactor convergence adds target-native value without introducing a second proxy runtime, scanner authority, DNS owner, subscription owner, or commerce/account control plane. The exact donor surfaces and dispositions are governed under `governance/convergence/post-refactor-160-*`.

1. **Configuration mutation retry is bounded intent replay, not stale-snapshot retry.** `foundation/config.Manager.Mutate` reloads a fresh authoritative snapshot after CAS conflict only for side-effect-free server-owned intents. Default attempts are 3, the hard cap is 8, and any explicit `If-Match`/revision precondition forces one attempt. `adapters/api.commitConfigMutation` is the one HTTP adapter and exposes attempt telemetry.
2. **Android per-app routing is real mobile authority.** `PerAppVpnPolicy` owns `ALL`/`INCLUDE`/`EXCLUDE` mode selection, validates the complete bounded package set before builder mutation, rejects an empty include set and self-inclusion, and fails tunnel startup closed on platform package errors. `UnderlyingNetworkTracker` passively tracks only non-VPN physical candidates for `setUnderlyingNetworks`; it never becomes a routing authority.
3. **Remote endpoint admission is shared.** `foundation/netpolicy` owns public/special-use/documentation address classification used by subscription egress and active diagnostics. Mixed public/private DNS answers fail closed rather than becoming DNS-rebinding or LAN-scan paths.
4. **Tor bridge diagnostics are fronting-aware and bounded.** The bridge planner distinguishes literal bridge endpoints from front/broker endpoints, recognizes documentation placeholders, caps lines/workers/time, pins admitted numeric dial targets, and reports refused/unparsed/fronted/reachable states without modifying Tor runtime state.
5. **Throughput diagnostics use the actual iperf3 protocol.** The previous raw zero-byte socket surrogate is replaced by bounded `iperf3 -J` execution with TCP retransmit/CPU and UDP jitter/loss parsing, reverse/bidirectional support, output/time/parallel/bitrate caps, public-only target admission, numeric DNS pinning after validation, and per-operation authorization attestation. Missing `iperf3` is reported as unavailable rather than fabricated success.
6. **NAT diagnostics report only RFC 5389 evidence.** The STUN probe uses one UDP socket, cryptographic transaction IDs, bounded retries, source/origin checks, public-only user/server destinations, and same-socket mapped-address comparison. It reports only `endpoint-independent`, `endpoint-dependent-or-port-dependent`, or `unknown`; it does not infer cone/filter labels without the required evidence.
7. **Subscription refresh is validate-before-swap with last-known-good semantics.** Conditional ETag refresh was fused into the existing profile mirror/backoff owner rather than added as a second rule-set manager. Invalid responses preserve accepted content, validators, and freshness truth.

The same pass explicitly rejects broad exploit/scanner corpora, donor commerce/reseller planes, parallel Xray/V2Ray/sing-box runtime authority, and donor-specific DNS/observatory managers where LumiNet already has a stronger canonical owner. Those rejections are evidence-backed dispositions, not unexamined exclusions.

## Post-refactor-180 convergence (2026-08-14)

The 20-peer successor wave keeps the post-refactor-160 ownership model intact while hardening path diagnostics, remote-source HTTP recovery, prefix attribution, WARP stability scoring, and packet correctness. Exact evidence and dispositions live under `governance/convergence/post-refactor-180-*`.

1. **Traceroute is now a truthful path diagnostic.** The previous loop changed a TTL variable without applying it to the socket. `analysis/diagnostics/trace_route.go` now invokes the bounded platform `traceroute`/`tracert` backend without a shell, rejects URL/option-shaped targets, caps hops/probes/wait/output, and parses per-hop addresses, timeouts, loss, latency, temporal jitter, load balancing, and destination reachability. Missing platform tooling is reported as unsupported instead of synthesized from TCP-connect timings.
2. **Subscription follow-ups are bounded again.** The custom Go redirect hook now restores an explicit 10-follow-up budget, detects redirect loops, re-admits every redirect target, and strips origin-scoped ETags on cross-origin hops. `429`/`503` `Retry-After` is accepted only as a bounded lower bound on the existing source backoff, with a 24-hour cap; it cannot create an unbounded server-controlled sleep.
3. **Provider attribution uses an immutable longest-prefix index.** Corpus activation still validates, sorts, and atomically publishes one snapshot, but IPv4/IPv6 lookup now searches exact masked prefix buckets by prefix length rather than linearly scanning every provider prefix. Stable corpus order and priority ties preserve the previous semantics, with a differential test against the former linear reference.
4. **WARP endpoint ranking distinguishes temporal instability.** Repeated real handshake RTTs now produce mean absolute adjacent-sample jitter. Ranking remains success first and loss first; when loss matches, lower jitter precedes median RTT. The donor's arbitrary aggregate scoring and worker model were not copied.
5. **IP packet parsing obeys declared lengths.** LumiCore rejects IPv4 total lengths smaller than the header or larger than available bytes, rejects truncated IPv6 declared payloads, and exposes only the declared payload rather than trailing storage bytes. Go-side IPv4 validity mirrors the declared-length checks.
6. **IPv4 reassembly is bounded and conflict-aware.** NAT defragmentation now places bytes by fragment offset, tracks exact coverage, requires the offset-zero header, caps concurrent flows and age, evicts the oldest flow at capacity, accepts identical duplicate overlap, and rejects conflicting overlap or inconsistent final lengths by dropping the flow. Arrival order can no longer choose the reconstructed bytes.

The same pass deliberately does **not** create a universal connections page from incomplete runtime-local session maps, a daemon-wide Tailscale-derived route monitor, arbitrary restart-resume for jobs that have not declared idempotent checkpoint semantics, a second raw SNI packet-injection authority, a legacy OpenSSH protocol fork, a reseller/Xray server control plane, or a local OIDC identity provider. Those peers remain reference, supersession, guardrail, or rejection evidence until a target-native authority model exists.


## Post-refactor-220 cross-40 convergence (2026-08-14)

This successor pass re-audits the two uploaded peer waves as one **40-project universe**: LumiNet plus 39 donor archives whose 18,517 file/symlink surfaces remain fully accountable in the immutable post-refactor-160 and post-refactor-180 matrices. It promotes previously held higher-order value only after target-native ownership prerequisites exist.

1. **Cross-runtime flows have one canonical observation contract.** `foundation/flowregistry` requires every runtime owner to declare visibility, close, byte-counter, process, and destination coverage before a flow can be registered. Close is delegated to the real runtime owner, callbacks execute outside the registry lock, oversized bulk close is rejected before any side effect, and missing owners remain visible as negative coverage rather than disappearing. Evasion SOCKS and stateful relay transports publish real flows; Tor/Psiphon/SSTP/IKEv2 currently declare per-flow visibility unavailable rather than implying completeness.
2. **Daemon network state is passive, revisioned evidence.** `platform/system.NetworkMonitor` captures bounded interface/address/link/MTU/flag/default-egress snapshots and advances a monotonic epoch only when the meaningful fingerprint changes. It never requests a network or mutates routes. Flow records carry their creation epoch, allowing the operator plane to identify pre-handoff or unknown-epoch flows without rewriting history.
3. **Network intelligence is a derived read model, not another scanner.** `analysis/netintel` composes registered flows, runtime coverage, network epochs, and the already-activated immutable provider-prefix corpus into provider/protocol distributions, owner path state, handoff context, and corpus-freshness truth. It performs no DNS lookup, GeoIP fetch, active scan, process execution, route change, or runtime mutation.
4. **The Compatibility Lab is a loss-aware local transformation plane.** Canonical `ProxyConfig` nodes can be shaped with bounded RE2-compatible include/exclude/rename rules, protocol allowlisting, semantic de-duplication, sorting, and limits, then exported as URI lists, Base64 subscriptions, LumiNet JSON, Clash Meta YAML, or sing-box JSON. Detour chains are rebound to retained top-level nodes and cycles, ambiguity, dangling references, or orphaning transforms fail closed. Conversion never fetches URLs or mutates managed profiles.
5. **Strict conversion proves local re-ingest.** Generated output is parsed back through LumiNet and compared to the canonical source for semantic fields, cardinality, and top-level detour graph. A strict export is rejected on parser error or drift even when first-pass exporter compatibility bookkeeping reported no loss. That oracle exposed and fixed a VLESS URI bug where explicit `security=tls`/`reality` could be serialized as `security=none` when the legacy boolean field disagreed.
6. **Interrupted-job recovery is typed, redacted, and operator-confirmed.** Persisted proxy-test history no longer stores full credential-bearing proxy URIs; it stores a transport-safe preview and scrubs legacy rows on read. Only explicitly reconstructible credential-free observational jobs can be requeued. Recovery creates a new durable job with `recovered_from` lineage, requires `confirm=true`, serializes duplicate-descendant creation, and never auto-replays work at daemon boot. Consequential provisioning/deployment and secret-bearing proxy jobs remain non-reconstructible.
7. **Previously shipped automatic configuration mutation retry remains unchanged.** `foundation/config.Manager.Mutate` still reloads fresh authority only after revision conflict for side-effect-free server-owned intents, uses a default three-attempt budget with hard cap eight, and forces one attempt for explicit revision/`If-Match` preconditions. HTTP adapters still commit configuration before any runtime side effect.

The pass intentionally does not turn connection observation into arbitrary process killing, add a second firewall/route mutator, embed public scraped proxy corpora, revive raw SNI packet-injection services or legacy SSH protocol forks, add a second GTK application stack, or turn LumiNet into a general-purpose reseller/Xray server administration system or OIDC identity provider. Those are explicit product/authority boundaries, not unreviewed omissions.

8. **Capability truth is now a cross-plane operator surface.** `/api/capabilities` schema v4 keeps registry availability, native-core linkage, flow-owner participation, passive network-monitor health/revision, and provider-corpus freshness as separate evidence dimensions. The Capability & Coverage Center renders those states read-only, so partial runtime coverage or stale/absent evidence cannot hide behind a generic available badge.
