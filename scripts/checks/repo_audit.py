#!/usr/bin/env python3
"""Fail-fast repository structure audit for LumiNet's source distribution."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []
warnings: list[str] = []


def error(message: str) -> None:
    errors.append(message)


def warn(message: str) -> None:
    warnings.append(message)


def text(path: str) -> str:
    candidate = ROOT / path
    if not candidate.is_file():
        error(f"missing required file: {path}")
        return ""
    return candidate.read_text(encoding="utf-8", errors="replace")


# Source-distribution purity -------------------------------------------------
for forbidden_dir in ("node_modules", "target", ".gradle", "__pycache__"):
    for path in ROOT.rglob(forbidden_dir):
        if path.is_dir():
            error(f"generated/dependency directory in source tree: {path.relative_to(ROOT).as_posix()}")

for path in ROOT.rglob(".git"):
    if path.is_dir() and path != ROOT / ".git":
        error(f"nested VCS metadata in source tree: {path.relative_to(ROOT).as_posix()}")

skip_parts = {".git", "node_modules", "target", ".gradle", "build", "release"}
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    relative = path.relative_to(ROOT)
    if any(part in skip_parts for part in relative.parts):
        continue
    if path.suffix.lower() in {".exe", ".dll", ".so", ".dylib", ".syso", ".class", ".jar", ".aar"}:
        error(f"compiled artifact in source tree: {relative.as_posix()}")

# Project boundaries ---------------------------------------------------------
required = [
    "src/packages/lumicore/Cargo.toml",
    "src/apps/daemon/go.mod",
    "src/apps/desktop/go.mod",
    "src/packages/control-ui/package.json",
    "src/packages/control-ui/go.mod",
    "src/apps/android/settings.gradle.kts",
    "src/apps/android/app/build.gradle.kts",
    "src/apps/android/app/src/main/AndroidManifest.xml",
    "docs/current-system.md",
    "docs/architecture/repository-layout.md",
    "docs/audit/inventory/summary.json",
    "docs/plans/2026-08-07-repository-recovery-plan.md",
    ".graphifyignore",
    "scripts/graphify.sh",
    "scripts/checks/check_graphify_output.py",
    "scripts/checks/check_native_verification_coverage.py",
    "scripts/checks/check_tooling_surface.py",
    "scripts/README.md",
    "rust-toolchain.toml",
]
for relative in required:
    if not (ROOT / relative).is_file():
        error(f"missing required project boundary: {relative}")

# Live-source navigation truth ----------------------------------------------
# Historical porting provenance belongs in governance evidence. Live source
# must not carry obsolete pre-src target-path comments that mislead navigation.
legacy_target_prefixes = (
    "# Target path: server/",
    "// Target path: server/",
    "// Target: server/",
    "// LumiNet target: server/",
    "; Target path: server/",
    "//! Target path: core/",
    "// core/src/",
)
for source in (ROOT / "src").rglob("*"):
    if not source.is_file():
        continue
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        continue
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if any(stripped.startswith(prefix) for prefix in legacy_target_prefixes):
            error(
                f"live source retains obsolete pre-src target-path comment: "
                f"{source.relative_to(ROOT).as_posix()}:{lineno}"
            )

# Remote-response resource bounds ------------------------------------------
# Donor convergence established one repository-wide invariant: remote
# control-plane bodies must be bounded by their owning protocol/package.
# Streaming speed/decoy bodies are allowed when lifetime/throughput is
# explicitly bounded; direct JSON decoders/read-all calls over response bodies
# are not.
for source in (ROOT / "src/apps/daemon").rglob("*.go"):
    if source.name.endswith("_test.go"):
        continue
    body = source.read_text(encoding="utf-8", errors="replace")
    for forbidden in (
        "json.NewDecoder(resp.Body)",
        "json.NewDecoder(mResp.Body)",
        "json.NewDecoder(response.Body)",
        "ioutil.ReadAll(resp.Body)",
        "io.ReadAll(resp.Body)",
        "ioutil.ReadAll(response.Body)",
        "io.ReadAll(response.Body)",
    ):
        if forbidden in body:
            error(
                f"unbounded remote response body in {source.relative_to(ROOT).as_posix()}: {forbidden}; "
                "use an owner-specific bound"
            )

# ECH verification default --------------------------------------------------
# Peer convergence exposed a dangerous default: ECH/domain-fronting TLS must
# verify certificates unless an operator explicitly opts into insecure mode.
ech_source = text("src/apps/daemon/internal/runtime/proxy/ech.go")
if not re.search(r"(?m)^\s*ECHInsecureSkipVerify\s*=\s*false\s*$", ech_source):
    error("ECH certificate verification must be enabled by default")
if re.search(r"(?m)^\s*ECHInsecureSkipVerify\s*=\s*true\s*$", ech_source):
    error("ECH insecure verification must not be the repository default")

# Repository layout depth ---------------------------------------------------
# Keep taxonomy shallow outside directories whose depth is imposed by a real
# interface (language/package namespaces, vendored module paths, immutable
# evidence locators, or build-system source sets). These paths are known
# category wrappers that add no independent ownership seam.
for redundant in (
    "deploy/packaging",
    "deploy/relays/contracts",
    "deploy/relays/serverless",
    "deploy/templates/enterprise",
    "docs/assets/screenshots",
    "docs/keystone",
    "docs/superpowers",
    "governance/conductor/code_styleguides",
    "governance/design-system/luminet",
    "governance/reference/routes",
    "governance/review-stage",
    "labs/daemon/advanced-runtime-retired",
    "labs/daemon/dormant-surface-alternates",
    "labs/daemon/host-network-alternates",
    "labs/daemon/mobile-api-alternates",
    "labs/daemon/modules/internal",
    "labs/daemon/modules/proxy",
    "labs/daemon/proxy-facades",
    "labs/daemon/proxy-parser-facade",
    "labs/daemon/routing-preserved",
    "labs/daemon/runtime-core-alternates",
    "labs/daemon/scanner-dormant",
    "labs/daemon/telemetry-alternates",
    "labs/desktop/legacy-client-ui/components",
    "labs/desktop/legacy-client-ui/styles",
    "labs/desktop/platform-alternates/internal",
    "labs/lumicore/mobile-alternates/ffi",
    "labs/lumicore/mobile-alternates/src",
    "labs/lumicore/mobile-alternates/transport",
    "labs/mobile/android",
    "labs/mobile/runtime-alternates/app",
    "src/apps/mobile",
    "src/packages/control-ui/src/components/layout",
    "src/packages/control-ui/src/components",
    "src/apps/daemon/internal/runtime/proxy/state",
    "third_party/gaio/gaio-master",
):
    if (ROOT / redundant).exists():
        error(f"redundant repository layout wrapper remains: {redundant}")

# Generic wrapper-depth invariant -------------------------------------------
# A directory that owns no files and only categorizes one child adds navigation
# depth without defining an interface. Preserve only paths whose nesting is an
# external/package/immutable-locator contract; new exceptions require rationale.
wrapper_roots = ("src", "deploy", "docs", "governance", "labs", "scripts", "tests", "third_party")
wrapper_exceptions = {
    "governance/conductor/provenance-ledger/raw",  # immutable raw/snapshots locator
    "third_party/gaio/.github",                    # upstream GitHub workflow convention
}
wrapper_ignored_parts = {".git", "vendor", "node_modules", "target", "dist", "build", "__pycache__"}
for root_name in wrapper_roots:
    root_dir = ROOT / root_name
    if not root_dir.is_dir():
        continue
    for directory in root_dir.rglob("*"):
        if not directory.is_dir():
            continue
        relative = directory.relative_to(ROOT).as_posix()
        if relative in wrapper_exceptions or any(part in wrapper_ignored_parts for part in directory.relative_to(ROOT).parts):
            continue
        child_dirs = [child for child in directory.iterdir() if child.is_dir() and child.name not in wrapper_ignored_parts]
        owned_files = [child for child in directory.iterdir() if child.is_file()]
        if len(child_dirs) == 1 and not owned_files:
            error(f"redundant one-child repository wrapper remains: {relative} -> {child_dirs[0].name}")

# Generated/output ignore paths must follow current repository ownership.
gitignore = text(".gitignore")
for stale in ("/core/target/", "desktop/frontend/dist/", "server/internal/webui/dist/"):
    if stale in gitignore:
        error(f".gitignore retains retired path: {stale}")
if "**/target/" not in gitignore:
    error(".gitignore must ignore Cargo target directories at their current module locations")

graphifyignore = text(".graphifyignore")
for required in ("third_party/", "labs/", "governance/", "docs/", "scripts/vendor/"):
    if required not in graphifyignore:
        error(f".graphifyignore missing current non-product exclusion: {required}")
for stale in ("server/third_party/", "server/internal/proxy/scratch_tuic/", "conductor/", "review-stage/", "mobile/android/incubator/"):
    if stale in graphifyignore:
        error(f".graphifyignore retains retired path: {stale}")

# Toolchain consistency ------------------------------------------------------
if text(".go-version").strip() != "1.26.5":
    error(".go-version must select Go 1.26.5")

go_work = text("go.work")
if not re.search(r"(?m)^go 1\.26\.0$", go_work):
    error("go.work must declare language version 1.26.0")
if not re.search(r"(?m)^toolchain go1\.26\.5$", go_work):
    error("go.work must select toolchain go1.26.5")

for mod in sorted(ROOT.rglob("go.mod")):
    if any(part in {"vendor", "third_party"} for part in mod.relative_to(ROOT).parts):
        continue
    body = mod.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"(?m)^go\s+(\S+)", body)
    if not match or match.group(1) != "1.26.0":
        error(f"{mod.relative_to(ROOT).as_posix()} must declare go 1.26.0")

if text(".nvmrc").strip() != "22.16.0":
    error(".nvmrc must select Node 22.16.0")

try:
    control_ui_package = json.loads(text("src/packages/control-ui/package.json"))
except json.JSONDecodeError as exc:
    error(f"invalid control-ui package.json: {exc}")
else:
    if control_ui_package.get("packageManager") != "npm@10.9.2":
        error("control-ui packageManager must match Node 22.16.0 bundled npm 10.9.2")
    if (control_ui_package.get("scripts") or {}).get("audit") != "npm audit":
        error("control-ui package must own a full npm dependency-audit script")

rust_toolchain = text("rust-toolchain.toml")
if not re.search(r'(?m)^channel = "1\.97\.1"$', rust_toolchain):
    error("rust-toolchain.toml must pin Rust 1.97.1")
if re.search(r'(?m)^channel = "stable"$', rust_toolchain):
    error("rust-toolchain.toml must not use the moving stable channel")

ci_workflow = text(".github/workflows/ci.yml")
for workflow_name, workflow in (("CI", ci_workflow), ("release", text(".github/workflows/release.yml"))):
    if "node-version: '22'" in workflow:
        error(f"{workflow_name} workflow must pin Node 22.16.0 instead of the moving 22.x line")
    if "setup-node@" in workflow and "node-version: '22.16.0'" not in workflow:
        error(f"{workflow_name} workflow setup-node must consume the .nvmrc Node 22.16.0 authority")
    for floating, explicit in (("ubuntu-latest", "ubuntu-24.04"), ("windows-latest", "windows-2025"), ("macos-latest", "macos-15")):
        if f"runs-on: {floating}" in workflow:
            error(f"{workflow_name} workflow uses moving runner label {floating}; use {explicit}")
    rust_lines = workflow.splitlines()
    rust_setup_indices = [i for i, line in enumerate(rust_lines) if "uses: dtolnay/rust-toolchain@" in line]
    for index, line_index in enumerate(rust_setup_indices, start=1):
        block = "\n".join(rust_lines[line_index : line_index + 8])
        if "toolchain: 1.97.1" not in block:
            error(f"{workflow_name} Rust setup #{index} must explicitly select toolchain 1.97.1")
if "make verify-release" not in ci_workflow:
    error("CI must consume the canonical make verify-release admission interface")

release_workflow = text(".github/workflows/release.yml")
if not re.search(r"(?m)^  verify-release:\s*$", release_workflow):
    error("release workflow must define a verify-release admission job")
if "make verify-release" not in release_workflow:
    error("release workflow must consume the canonical make verify-release admission interface")
if not re.search(r"(?ms)^  verify-release:\n.*?name:\s+luminet-control-ui.*?src/packages/control-ui/dist", release_workflow):
    error("release verification job must publish the verified control-ui bundle")
if re.search(r"(?m)^  build-control-ui:\s*$", release_workflow):
    error("release workflow must not maintain a second unverified control-ui build job")

# Release admission owns dependency security and preservation truth. Callers
# provide installed pinned tools plus the history base; they must not maintain
# parallel verification jobs with drift-prone implementations.
makefile_for_admission = text("Makefile")
for admission_dependency in ("audit-dependencies", "validate-preservation"):
    if not re.search(rf"(?m)^verify-release:.*\b{re.escape(admission_dependency)}\b", makefile_for_admission):
        error(f"verify-release must include {admission_dependency}")
if not re.search(r"(?m)^audit-dependencies:", makefile_for_admission):
    error("Makefile must own the dependency-security audit interface")
if "govulncheck ./..." not in makefile_for_admission or "cargo audit" not in makefile_for_admission:
    error("dependency-security audit must cover Go govulncheck and locked Cargo audit")
if not re.search(r"(?m)^validate-preservation:", makefile_for_admission):
    error("Makefile must own the preservation-ledger validation interface")
if "PRESERVATION_BASE_SHA" not in makefile_for_admission or "validate-preservation-ledger" not in makefile_for_admission:
    error("preservation admission must consume a deterministic base SHA through the canonical validator")
for workflow_name, workflow in (("CI", ci_workflow), ("release", release_workflow)):
    if "govulncheck@v1.6.0" not in workflow or "cargo-audit --version 0.22.2 --locked" not in workflow:
        error(f"{workflow_name} workflow must install the pinned dependency-audit tools before release admission")
    if "PRESERVATION_BASE_SHA" not in workflow:
        error(f"{workflow_name} workflow must provide the preservation base SHA to release admission")
if re.search(r"(?m)^  preservation-ledger:\s*$", ci_workflow):
    error("CI must not maintain a preservation-ledger job outside canonical release admission")
if re.search(r"(?m)^  security:\s*$", ci_workflow):
    error("CI must not maintain a dependency-security job outside canonical release admission")

# Current agent/navigation context -------------------------------------------
if (ROOT / "goal.md").exists():
    error("root goal.md returned; completed execution goals belong under docs/plans, not current repository authority")
if not (ROOT / "docs/plans/2026-07-29-lossless-consolidation-goal.md").is_file():
    error("historical July 2026 consolidation goal is missing from docs/plans")

gemini = text("GEMINI.md")
if "src/packages/client-go/" in gemini:
    error("GEMINI.md references the retired client-go source root")
if "route classification" in gemini or "public-error" in gemini:
    error("GEMINI.md describes retired shared-contract surfaces")

design = text("DESIGN.md")
if "`core/`" in design or "`server/`" in design:
    error("DESIGN.md references pre-src live source roots")

product = text("PRODUCT.md")
if "Product intent and target scope, not proof of current runtime capability" not in product:
    error("PRODUCT.md must distinguish product intent from current runtime capability truth")
product_strategy = text("docs/product-strategy.md")
if "Product direction and future productization strategy" not in product_strategy:
    error("product strategy must be labeled as direction rather than current capability authority")
current_system = text("docs/current-system.md")
if "current consolidation roadmap" in current_system:
    error("current-system authority order still treats the completed consolidation roadmap as current authority")
if "current architecture documents, and accepted ADRs" not in current_system:
    error("current-system authority order must name current architecture and ADRs")

porting_readme = text("docs/porting/README.md")
if "`conductor/`" in porting_readme and "`governance/conductor/`" not in porting_readme:
    error("docs/porting/README.md points current truth at the retired conductor root")

# Preservation-ledger worktree truth ------------------------------------------
preservation_ledger_path = ROOT / "governance/conductor/preservation-ledger/families.v1.json"
if not preservation_ledger_path.is_file():
    error("missing preservation ledger")
else:
    try:
        preservation_ledger = json.loads(preservation_ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid preservation ledger: {exc}")
    else:
        for family in preservation_ledger.get("families", []):
            for peer in family.get("peers", []):
                if peer.get("state") != "live":
                    continue
                peer_path = peer.get("path", "")
                if not peer_path or not (ROOT / peer_path).exists():
                    error(
                        f"preservation ledger marks absent path live: "
                        f"{peer.get('peer_id', '<unknown>')} -> {peer_path or '<empty>'}"
                    )

# Current CLI documentation must not become a second command-definition owner.
quickstart = text("docs/guides/quickstart.md")
cli_reference = text("docs/guides/cli-reference.md")
if "luminet <command> --help" not in cli_reference:
    error("CLI reference must name live Cobra help as the flag-level authority")
retired_cli_forms = {
    r"build-all\.ps1\s+-SkipTests": "retired PowerShell -SkipTests flag",
    r"luminet\s+serve\s+--gui": "retired native-Walk --gui invocation",
    r"luminet\s+scan\s+resolver-dns": "nonexistent resolver-dns scan subcommand",
    r"luminet\s+scan\s+ports[^\n]*--banner": "nonexistent scan ports --banner flag",
    r"luminet\s+scan\s+sni[^\n]*--dns-resolver": "nonexistent scan sni --dns-resolver flag",
    r"luminet\s+diagnose[^\n]*--export": "retired diagnose --export flag",
    r"luminet\s+proxy\s+subscribe\s+(?:add|fetch)\b": "nonexistent proxy subscribe add/fetch subcommand",
    r"luminet\s+system\s+dns\s+(?:set|restore)\b": "retired system dns set/restore command",
    r"luminet\s+system\s+leak-protection\b": "nonexistent system leak-protection command",
    r"luminet\s+system\s+evasion-tunnel[^\n]*--split-offset": "retired evasion --split-offset flag",
    r"luminet\s+system\s+evasion-tunnel[^\n]*--split-delay": "retired evasion --split-delay flag",
}
for pattern, label in retired_cli_forms.items():
    for doc_name, body in (("quickstart", quickstart), ("cli-reference", cli_reference)):
        if re.search(pattern, body):
            error(f"{doc_name} teaches {label}")

# Release authority -----------------------------------------------------------
if (ROOT / ".goreleaser.yaml").exists() or (ROOT / ".goreleaser.yml").exists():
    error("repository-root GoReleaser authority returned; GitHub Actions is the supported release authority")
legacy_goreleaser = ROOT / "governance/reference/release/.goreleaser.yaml"
if not legacy_goreleaser.is_file():
    error("retired GoReleaser reference evidence is missing")

# Build graph ----------------------------------------------------------------
makefile = text("Makefile")
if len(re.findall(r"(?m)^build-go:", makefile)) != 1:
    error("Makefile must define build-go exactly once")
if "FRONTEND_DIR := $(ROOT_DIR)/src/packages/control-ui" not in makefile:
    error("Makefile does not point to src/packages/control-ui through FRONTEND_DIR")
for target in ("verify-repo", "inventory", "graph", "doctor"):
    if not re.search(rf"(?m)^{re.escape(target)}:", makefile):
        error(f"Makefile is missing {target} target")

main_go = text("src/apps/desktop/main.go")
controlui_embed = text("src/packages/control-ui/embed.go")
if "github.com/maybeknott/luminet/controlui" not in main_go or "controlui.Dist()" not in main_go:
    error("desktop host must consume the shared controlui.Dist() embed seam")
if "//go:embed all:dist" not in controlui_embed or "func Dist() fs.FS" not in controlui_embed:
    error("src/packages/control-ui must own the single production embed seam")
if (ROOT / "src/apps/desktop/frontend").exists() or (ROOT / "src/apps/daemon/internal/webui").exists():
    error("legacy live UI authority returned outside src/packages/control-ui")

# Frontend contracts and quality gates --------------------------------------
frontend_src = ROOT / "src/packages/control-ui/src"
app_tsx = text("src/packages/control-ui/src/App.tsx")
if "HashRouter" not in app_tsx or "BrowserRouter" in app_tsx:
    error("embedded desktop frontend must use HashRouter")

vite_config = text("src/packages/control-ui/vite.config.ts")
if not re.search(r"base:\s*['\"]\./['\"]", vite_config):
    error("Vite base must be './' for embedded desktop assets")

index_css = text("src/packages/control-ui/src/index.css")
if re.search(r"https?://", index_css):
    error("frontend CSS must not depend on remote assets or fonts")
if "prefers-reduced-motion" not in index_css:
    error("frontend must provide a reduced-motion path")

for dead in (
    "src/packages/control-ui/src/App.css",
    "src/packages/control-ui/src/components/VpnStatusWidget.tsx",
    "src/packages/control-ui/src/components/LogGrid.tsx",
    "src/packages/control-ui/src/components/NodeGlobe.tsx",
):
    if (ROOT / dead).exists():
        error(f"stale frontend artifact remains: {dead}")

if frontend_src.is_dir():
    # Only type-position `any` is an explicit-any violation; the bare word in
    # comments, prose, or string literals is not a type.
    explicit_any = re.compile(
        r"(?:\bas any\b|\b:\s*any\b|\b<\s*any\s*(?=[>,]|$)|\bany\s*\[\s*\]|"
        r"\bArray\s*<\s*any\s*>|\b(?:Record|Promise|Partial|Pick|Omit|Readonly|ReturnType|Awaited)\s*<[^>]*\bany\b)"
    )
    for source in sorted(frontend_src.rglob("*")):
        if source.suffix not in {".ts", ".tsx"}:
            continue
        for line_no, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if explicit_any.search(line) and "// audit-allow-any" not in line:
                error(f"explicit any in frontend: {source.relative_to(ROOT).as_posix()}:{line_no}")

contracts = text("src/packages/control-ui/src/api/contracts.ts")
for symbol in ("Decoder", "parseSystemStatus", "parseTelemetryEvent", "parseEvasionSettings"):
    if symbol not in contracts:
        error(f"frontend contract seam is missing {symbol}")

transport = text("src/packages/control-ui/src/api/ControlTransport.ts")
if not re.search(r"json<T>\([^)]*decode:\s*Decoder<T>", transport, re.DOTALL):
    error("ControlTransport JSON path must require a decoder")

store = text("src/packages/control-ui/src/store/systemStore.ts")
if "TelemetryConnectionState" not in store or "authenticating" not in store:
    error("telemetry connection state machine is incomplete")

# Go diagnostic contract -----------------------------------------------------
plan = text("src/apps/daemon/internal/workflows/jobs/diagnostic_plan.go")
if "buildDiagnosticPlan" not in plan or "MetricSniMatrix" not in plan:
    error("diagnostic jobs do not honor requested diagnostic types")
if not (ROOT / "src/apps/daemon/internal/workflows/jobs/diagnostic_plan_test.go").is_file():
    error("diagnostic plan lacks regression tests")
handler = text("src/apps/daemon/internal/adapters/api/handlers_diagnostics.go")
if "Options map[string]string" not in handler:
    error("diagnostic API does not preserve request options")

# Deep-module ownership guards ----------------------------------------------
# Canonical owners must remain live while retired proxy compatibility facades
# stay preserved as historical evidence under labs. The dedicated
# check_proxy_facade_ownership.py guard enforces the active facade ban.
ownership_requirements = {
    "src/apps/daemon/internal/integrations/relayclient/serverless_dialer.go": "serverless relay client owner",
    "src/apps/daemon/internal/integrations/relayclient/gsa_relay.go": "GSA relay client owner",
    "src/apps/daemon/internal/protocols/tarpit/tarpit.go": "tarpit owner",
    "src/apps/daemon/internal/protocols/asyncreactor/reactor.go": "async reactor owner",
    "src/apps/daemon/internal/runtime/proxy/circular_cache.go": "proxy-internal circular cache implementation",
    "src/apps/daemon/internal/integrations/captchaclient/solver.go": "active remote CAPTCHA client owner",
    "src/apps/daemon/internal/foundation/trafficstats/accounting.go": "traffic accounting owner",
    "labs/daemon/modules/relayserver/relay_server.go": "preserved relay-server peer",
    "labs/daemon/modules/captcha/plugin.go": "preserved build-tagged CAPTCHA experiment",
    "labs/daemon/modules/domainfront/domainfront.go": "preserved independent domain-fronting peer",
}
for relative, label in ownership_requirements.items():
    if not (ROOT / relative).is_file():
        error(f"missing {label}: {relative}")

for retired in (
    "src/apps/daemon/internal/runtime/proxy/apps_script_front.go",
    "src/apps/daemon/internal/runtime/proxy/sidecar_server.go",
    "src/apps/daemon/internal/runtime/proxy/path_bonding.go",
):
    if (ROOT / retired).exists():
        error(f"retired zero-consumer/false runtime returned: {retired}")

for false_runtime in (
    "src/apps/daemon/internal/runtime/proxy/dispatcher.go",
    "src/apps/daemon/internal/runtime/proxy/multi_wireguard.go",
    "src/apps/daemon/internal/runtime/proxy/dns_tunnel.go",
):
    if (ROOT / false_runtime).exists():
        error(f"retired mock/simulation runtime returned: {false_runtime}")

hysteria = text("src/apps/daemon/internal/runtime/proxy/hysteria_binding.go")
if "Hysteria2_Start" not in hysteria or "return -1" not in hysteria:
    error("Hysteria native compatibility export must remain present and fail closed without an embedded runtime")
if "net.Dial(" in hysteria or "Mock native Client execution loop" in hysteria:
    error("Hysteria compatibility boundary regained direct/mock success semantics")

for forbidden in (
    "src/apps/daemon/internal/runtime/proxy/types/async_reactor.go",
    "src/apps/daemon/internal/runtime/proxy/types/circular_cache.go",
    "src/apps/daemon/internal/runtime/proxy/types/captcha_solver.go",
    "src/apps/daemon/internal/runtime/proxy/types/traffic_accounting.go",
    "src/apps/daemon/internal/runtime/proxy/types/coalescer.go",
):
    if (ROOT / forbidden).exists():
        error(f"extracted implementation reintroduced under proxy/types: {forbidden}")

# The CAPTCHA solver remains a canonical active owner. The Apps Script coalescer
# had no product consumer after subscription-ingestion convergence and is retired;
# former proxy facades remain historical only.
for relative in (
    "src/apps/daemon/internal/runtime/proxy/relay_coalescer.go",
    "src/apps/daemon/internal/runtime/proxy/captcha_solver.go",
):
    if (ROOT / relative).exists():
        error(f"retired proxy compatibility facade returned to active source: {relative}")

# Wave 19: proxy URI/config parsing has one canonical owner. Historical
# duplicate protocol sources are retired from the working tree after their
# baseline hashes and canonical ownership are recorded by convergence evidence.
if (ROOT / "src/apps/daemon/internal/runtime/proxy/types").exists():
    error("legacy proxy/types owner remains after proxyconfig consolidation")
for relative in (
    "src/apps/daemon/internal/networking/proxyconfig/types.go",
    "src/apps/daemon/internal/networking/proxyconfig/parser_vless.go",
    "src/apps/daemon/internal/networking/proxyconfig/parser_nipo.go",
    "src/apps/daemon/internal/networking/proxyconfig/parser_tuic.go",
    "src/apps/daemon/internal/integrations/sub/ingest.go",
):
    if not (ROOT / relative).exists():
        error(f"missing Wave 19 canonical/peer parser surface: {relative}")
for relative in (
    "src/apps/daemon/internal/linkparser",
    "src/apps/daemon/internal/integrations/subparser",
    "src/apps/daemon/internal/runtime/proxy/subscription.go",
    "src/apps/daemon/internal/runtime/proxy/proxy_subscription_parser.go",
):
    if (ROOT / relative).exists():
        error(f"retired Wave 19 subscription parser surface returned: {relative}")
if (ROOT / "src/apps/daemon/internal/runtime/proxy/parser.go").exists():
    error("retired proxy parser compatibility facade reappeared active")
parser_internal = text("src/apps/daemon/internal/runtime/proxy/proxyconfig_internal.go")
for token in ("internal/networking/proxyconfig", "extractRealityParams"):
    if token not in parser_internal:
        error(f"private proxyconfig implementation glue lost {token}")
preserved_parser_facade = text("labs/daemon/proxy-alternates/parser.go")
for token in ("internal/proxyconfig", "ExtractRealityParams"):
    if token not in preserved_parser_facade:
        error(f"preserved Wave 11 proxy parser facade lost {token}")
direct_parser_facade = text("src/apps/daemon/internal/runtime/proxy/parser_direct_compat.go")
for token in ("ParseNipoDirect", "ParseTUICDirect"):
    if token not in direct_parser_facade:
        error(f"direct protocol compatibility path lost {token}")

# Wave 19 duplicate-root parser retirement ----------------------------------
# Parser consolidation remains one-owner, but the canonical parser is allowed
# to evolve after consolidation. Immutable original hashes stay in the topology
# baseline; verify_repository_topology.py requires reviewed transformations for
# later behavior changes. Do not freeze live parsers to their pre-convergence
# bytes here.
for parser_name in ("anytls", "dnstt", "hy2", "juicity", "kcp", "naive", "nipo", "ss", "trojan", "tuic", "vless", "vmess", "wg"):
    legacy_path = ROOT / f"server/internal/proxy/parser_{parser_name}.go"
    canonical_path = ROOT / f"src/apps/daemon/internal/networking/proxyconfig/parser_{parser_name}.go"
    if legacy_path.exists():
        error(f"retired duplicate parser reintroduced: {legacy_path.relative_to(ROOT).as_posix()}")
    if not canonical_path.is_file():
        error(f"canonical parser missing for retired duplicate: {parser_name}")

# Wave 20 dormant-proxy preservation ----------------------------------------
wave20_manifest_path = ROOT / "governance/topology/wave20-experiments.json"
if not wave20_manifest_path.is_file():
    error("missing Wave 20 experiment preservation manifest")
else:
    try:
        wave20 = json.loads(wave20_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid Wave 20 experiment preservation manifest: {exc}")
        wave20 = {}
    moved = wave20.get("moved", []) if isinstance(wave20, dict) else []
    if len(moved) != 281:
        error(f"Wave 20 manifest must account for 281 moved Go files, found {len(moved)}")
    for row in moved:
        source = ROOT / row.get("source", "")
        target = ROOT / row.get("target", "")
        if source.exists():
            error(f"Wave 20 dormant implementation reintroduced under live proxy: {row.get('source')}")
        if not target.is_file():
            error(f"Wave 20 preserved experiment missing: {row.get('target')}")
            continue
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != row.get("sha256"):
            error(f"Wave 20 preserved experiment hash drift: {row.get('target')}")
    relocations_path = ROOT / "governance/topology/relocations.json"
    try:
        topology_relocations = json.loads(relocations_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid topology relocation ledger while checking Wave 20 retained sources: {exc}")
        topology_relocations = {}
    exact_relocations = topology_relocations.get("exact_relocations", {}) if isinstance(topology_relocations, dict) else {}
    retired_relocations = topology_relocations.get("retired", {}) if isinstance(topology_relocations, dict) else {}
    for row in wave20.get("retained", []) if isinstance(wave20, dict) else []:
        name = row.get("file", "")
        baseline = f"server/internal/proxy/{name}"
        final_relative = exact_relocations.get(baseline)
        live = ROOT / f"src/apps/daemon/internal/runtime/proxy/{name}"
        preserved_facade = ROOT / f"labs/daemon/proxy-alternates/{name}"
        if live.is_file():
            continue
        if final_relative:
            if not (ROOT / final_relative).is_file():
                error(f"Wave 20 retained source final owner missing: {baseline} -> {final_relative}")
        elif baseline in retired_relocations:
            continue
        elif not preserved_facade.is_file():
            error(f"Wave 20 retained source lacks final owner, retirement, or preserved facade: {name}")

# Wave 21 connected dormant-proxy preservation ------------------------------
wave21_manifest_path = ROOT / "governance/topology/wave21-experiments.json"
if not wave21_manifest_path.is_file():
    error("missing Wave 21 connected experiment preservation manifest")
else:
    try:
        wave21 = json.loads(wave21_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid Wave 21 connected experiment preservation manifest: {exc}")
        wave21 = {}
    moved = wave21.get("moved", []) if isinstance(wave21, dict) else []
    if len(moved) != 48:
        error(f"Wave 21 manifest must account for 48 moved Go files, found {len(moved)}")
    for row in moved:
        source = ROOT / row.get("source", "")
        target = ROOT / row.get("target", "")
        if source.exists():
            error(f"Wave 21 connected dormant implementation reintroduced under live proxy: {row.get('source')}")
        if not target.is_file():
            error(f"Wave 21 preserved connected experiment missing: {row.get('target')}")
            continue
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != row.get("sha256"):
            error(f"Wave 21 preserved connected experiment hash drift: {row.get('target')}")
    for group in wave21.get("retained_components", []) if isinstance(wave21, dict) else []:
        for name in group.get("files", []):
            relative = f"src/apps/daemon/internal/runtime/proxy/{name}"
            if not (ROOT / relative).is_file():
                error(f"Wave 21 retained dependency/native component missing: {relative}")

# Wave 22 general preset catalog ownership ----------------------------------
wave22_manifest_path = ROOT / "governance/topology/wave22-presets.json"
if not wave22_manifest_path.is_file():
    error("missing Wave 22 preset ownership manifest")
else:
    try:
        wave22 = json.loads(wave22_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid Wave 22 preset ownership manifest: {exc}")
        wave22 = {}
    owner = ROOT / wave22.get("owner", "")
    facade_path = ROOT / wave22.get("historical_facade", "")
    if not owner.is_file():
        error("Wave 22 canonical preset owner missing")
    else:
        normalized = owner.read_bytes().replace(b"package presets\n", b"package proxy\n", 1)
        normalized_hash = hashlib.sha256(normalized).hexdigest()
        normalized_size = len(normalized)
        if normalized_hash != wave22.get("source_sha256") or normalized_size != wave22.get("source_size"):
            # Descendant waves may add presets without rewriting Wave 22 history.
            # When post-refactor-224 exists, validate the Wave 22 source against
            # the exact frozen pre-224 successor baseline plus a normalization receipt.
            successor = ROOT / "governance/convergence/post-refactor-224-baseline-files.csv"
            anchor_path = ROOT / "governance/convergence/post-refactor-224-wave22-preset-baseline.json"
            historical_ok = False
            if successor.is_file() and anchor_path.is_file():
                try:
                    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
                    with successor.open(encoding="utf-8", newline="") as f:
                        row = next((r for r in csv.DictReader(f) if r.get("path") == wave22.get("owner")), None)
                    historical_ok = bool(
                        row
                        and row.get("sha256") == anchor.get("pre_224_sha256")
                        and anchor.get("wave22_normalized_sha256") == wave22.get("source_sha256")
                        and anchor.get("wave22_normalized_size") == wave22.get("source_size")
                    )
                except (OSError, json.JSONDecodeError, StopIteration):
                    historical_ok = False
            if not historical_ok:
                if normalized_hash != wave22.get("source_sha256"):
                    error("Wave 22 canonical preset source no longer normalizes to recorded baseline hash")
                if normalized_size != wave22.get("source_size"):
                    error("Wave 22 canonical preset normalized source size drift")
    if facade_path.exists():
        error("Wave 22 retired proxy preset facade returned to active source")
    if not (ROOT / "labs/daemon/proxy-alternates/presets.go").is_file():
        error("Wave 22 historical proxy preset facade is not preserved under labs")
    handler_presets = text("src/apps/daemon/internal/adapters/api/handlers_presets.go")
    if "internal/integrations/presets" not in handler_presets or "proxy.GetCDNPresets" in handler_presets:
        error("Wave 22 live preset API does not depend directly on canonical preset owner")
    if not (ROOT / "labs/daemon/modules/isppresets/isppresets.go").is_file():
        error("Wave 22 preserved independent embedded ISP preset peer missing")

# Wave 23 active API support ownership --------------------------------------
wave23_manifest_path = ROOT / "governance/topology/wave23-api-support.json"
if not wave23_manifest_path.is_file():
    error("missing Wave 23 API support ownership manifest")
else:
    try:
        wave23 = json.loads(wave23_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid Wave 23 API support ownership manifest: {exc}")
        wave23 = {}
    for row in wave23.get("sources", []) if isinstance(wave23, dict) else []:
        owner = ROOT / row.get("owner", "")
        if not owner.is_file():
            error(f"Wave 23 canonical support owner missing: {row.get('owner')}")
            continue
        if row.get("owner_validation", "baseline-byte-equivalent") == "baseline-byte-equivalent":
            pkg = row.get("package", "")
            normalized = owner.read_bytes().replace(f"package {pkg}\n".encode(), b"package proxy\n", 1)
            if hashlib.sha256(normalized).hexdigest() != row.get("sha256") or len(normalized) != row.get("size"):
                error(f"Wave 23 byte-equivalent owner no longer normalizes to recorded baseline: {row.get('owner')}")
        elif row.get("owner_validation") != "reviewed-transform":
            error(f"Wave 23 owner validation mode is unknown: {row.get('owner_validation')}")
    retired_support_facades = (
        "ip_security_analyzer.go",
        "smart_dns.go",
        "clean_ip_prober.go",
        "vpn_service_bridge.go",
        "warp_noise.go",
    )
    for name in retired_support_facades:
        live = ROOT / "src/apps/daemon/internal/runtime/proxy" / name
        preserved = ROOT / "labs/daemon/proxy-alternates" / name
        if live.exists():
            error(f"Wave 23 retired proxy compatibility facade returned: {live.relative_to(ROOT).as_posix()}")
        if not preserved.is_file():
            error(f"Wave 23 historical proxy facade is not preserved: {preserved.relative_to(ROOT).as_posix()}")
    handler = text("src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go")
    for token in ("internal/analysis/diagnostics", "internal/networking/dns", "internal/runtime/warp"):
        if token not in handler:
            error(f"Wave 23 live API handler missing canonical dependency {token}")
    if "internal/vpnstate" in handler:
        error("Wave 23 retired VPN state helper returned to the live API handler")
    for token in ("proxy.NewIPSecurityAnalyzer", "proxy.NewSmartDNSRouter", "proxy.NewCloudflareCleanIPProber", "proxy.NewVPNServiceBridge", "proxy.NewWarpNoiseInjector"):
        if token in handler:
            error(f"Wave 23 live API handler still routes through compatibility facade: {token}")
    for relative in wave23.get("preserved_peer_roots", []) if isinstance(wave23, dict) else []:
        if not (ROOT / relative).exists():
            error(f"Wave 23 independent peer root missing: {relative}")

# Wave 24 active diagnostic ownership ---------------------------------------
wave24_manifest_path = ROOT / "governance/topology/wave24-diagnostics.json"
if not wave24_manifest_path.is_file():
    error("missing Wave 24 diagnostic ownership manifest")
else:
    try:
        wave24 = json.loads(wave24_manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f"invalid Wave 24 diagnostic ownership manifest: {exc}")
        wave24 = {}
    for row in wave24.get("sources", []) if isinstance(wave24, dict) else []:
        owner = ROOT / row.get("owner", "")
        if not owner.is_file():
            error(f"Wave 24 canonical diagnostic owner missing: {row.get('owner')}")
            continue
        if row.get("owner_validation", "baseline-byte-equivalent") == "baseline-byte-equivalent":
            pkg = row.get("package", "")
            normalized = owner.read_bytes().replace(f"package {pkg}\n".encode(), b"package proxy\n", 1)
            if hashlib.sha256(normalized).hexdigest() != row.get("sha256") or len(normalized) != row.get("size"):
                # A later convergence wave may intentionally harden an old canonical
                # owner. Preserve Wave-24 history by proving the exact pre-225 owner
                # still normalized to the recorded Wave-24 bytes, then require the
                # post-225 delta to account the descendant transform explicitly.
                successor = ROOT / "governance/convergence/post-refactor-225-baseline-files.csv"
                delta_path = ROOT / "governance/convergence/post-refactor-225-target-delta.csv"
                anchor_path = ROOT / "governance/convergence/post-refactor-225-wave24-tlsfragment-baseline.json"
                historical_ok = False
                if successor.is_file() and delta_path.is_file() and anchor_path.is_file():
                    try:
                        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
                        with successor.open(encoding="utf-8", newline="") as f:
                            baseline_row = next((r for r in csv.DictReader(f) if r.get("path") == row.get("owner")), None)
                        with delta_path.open(encoding="utf-8", newline="") as f:
                            delta_row = next((r for r in csv.DictReader(f) if r.get("path") == row.get("owner")), None)
                        historical_ok = bool(
                            anchor.get("owner") == row.get("owner")
                            and anchor.get("wave24_normalized_sha256") == row.get("sha256")
                            and anchor.get("wave24_normalized_size") == row.get("size")
                            and baseline_row
                            and baseline_row.get("sha256") == anchor.get("pre_225_sha256")
                            and delta_row
                            and delta_row.get("change_type") == "modified"
                            and delta_row.get("baseline_sha256") == anchor.get("pre_225_sha256")
                        )
                    except (OSError, json.JSONDecodeError, StopIteration):
                        historical_ok = False
                if not historical_ok:
                    error(f"Wave 24 byte-equivalent owner no longer normalizes to recorded baseline: {row.get('owner')}")
        elif row.get("owner_validation") != "reviewed-transform":
            error(f"Wave 24 owner validation mode is unknown: {row.get('owner_validation')}")
    for name in ("utls_fragment.go", "censorship_doctor.go"):
        live = ROOT / "src/apps/daemon/internal/runtime/proxy" / name
        preserved = ROOT / "labs/daemon/proxy-alternates" / name
        if live.exists():
            error(f"Wave 24 retired diagnostic facade returned: {live.relative_to(ROOT).as_posix()}")
        if not preserved.is_file():
            error(f"Wave 24 historical diagnostic facade is not preserved: {preserved.relative_to(ROOT).as_posix()}")
    adaptive = text("src/apps/daemon/internal/runtime/proxy/adaptive_dialer.go")
    if "internal/protocols/tlsfragment" not in adaptive or "tlsfragment.WrapUTLSFragmentConn" not in adaptive:
        error("Wave 24 AdaptiveDialer does not depend directly on canonical TLS fragmentation owner")
    matrix = text("src/apps/daemon/internal/analysis/diagnostics/sni_matrix.go")
    if "internal/protocols/tlsfragment" not in matrix or "proxy.WrapUTLSFragmentConn" in matrix:
        error("Wave 24 SNI matrix does not depend directly on canonical TLS fragmentation owner")
    doctor_handler = text("src/apps/daemon/internal/adapters/api/handlers_diagnostic_doctor.go")
    if "internal/analysis/diagnostics" not in doctor_handler or "proxy.NewCensorshipDoctor" in doctor_handler:
        error("Wave 24 doctor API does not depend directly on canonical censorship doctor owner")
    expected_native_boundaries = {
        "src/apps/daemon/internal/runtime/proxy/package_exclusions.go",
        "src/apps/daemon/internal/runtime/proxy/package_exclusions_jni.go",
        "src/apps/daemon/internal/runtime/proxy/hysteria_binding.go",
    }
    if wave24.get("convergence_status") != "reviewed":
        error("Wave 24 convergence review is not closed")
    retained_native = set(wave24.get("convergence_retained_native_boundaries", [])) if isinstance(wave24, dict) else set()
    if retained_native != expected_native_boundaries:
        error(f"Wave 24 retained native boundary set drift: {sorted(retained_native)}")
    for relative in sorted(expected_native_boundaries):
        if not (ROOT / relative).is_file():
            error(f"reviewed native/export boundary missing: {relative}")
    if wave24.get("retained_for_later_review"):
        error("Wave 24 still contains unresolved retained_for_later_review entries")

# Historical-value convergence ownership ------------------------------------
provider_radix_path = ROOT / "src/apps/daemon/internal/analysis/provider/radix.go"
provider_corpus_owner = text("src/apps/daemon/internal/analysis/provider/corpus.go")
provider_observation_path = ROOT / "src/apps/daemon/internal/analysis/provider/observation.go"
scanner_index_path = ROOT / "src/apps/daemon/internal/analysis/scanner/network_index.go"
geosite_owner = text("labs/daemon/routing-alternates/domain_dynamic_matcher.go")
provider_handler = text("src/apps/daemon/internal/adapters/api/handlers_provider_corpus.go")
warp_geosite_handler = text("src/apps/daemon/internal/adapters/api/handlers_warp_geosite.go")

if provider_radix_path.exists():
    error("retired provider mutable radix index returned after exact zero-consumer proof")
if provider_observation_path.exists():
    error("retired zero-consumer provider Observation compatibility payload returned")
for token in ("func (s *Service) Lookup", "func (s *Service) Status"):
    if token not in provider_corpus_owner:
        error(f"canonical provider corpus interface lost {token}")
if scanner_index_path.exists():
    error("retired scanner provider compatibility alias surface returned: src/apps/daemon/internal/analysis/scanner/network_index.go")
if "internal/analysis/provider" not in provider_handler:
    error("provider corpus handler no longer depends directly on canonical provider owner")
if (ROOT / "src/apps/daemon/internal/runtime/proxy/provider_corpus.go").exists():
    error("provider proxy compatibility facade returned to active source")
if not (ROOT / "labs/daemon/proxy-alternates/provider_corpus.go").is_file():
    error("historical provider proxy facade is not preserved under labs")
if "type DynamicMatcher struct" not in geosite_owner:
    error("historical-value convergence preserved dynamic domain override corpus missing")
if "internal/networking/routing" not in warp_geosite_handler:
    error("GeoSite handler no longer depends directly on canonical domain-routing owner")
if (ROOT / "src/apps/daemon/internal/runtime/proxy/geosite_routing_matcher.go").exists():
    error("GeoSite proxy compatibility facade returned to active source")
if not (ROOT / "labs/daemon/proxy-alternates/geosite_routing_matcher.go").is_file():
    error("historical GeoSite proxy facade is not preserved under labs")
if "globalGeoSiteMatcher" in warp_geosite_handler:
    error("unused GeoSiteMatcher singleton returned to live API state")

# Convergence planning retirement --------------------------------------------
if (ROOT / "governance/tasks").exists():
    error("retired legacy governance/tasks root returned; current planning authority belongs under docs/plans")

# Convergence retirement of duplicate source archives ------------------------
if (ROOT / "governance/topology/source-archive").exists():
    error("duplicate topology source-archive returned after convergence retirement")
retirement_register = ROOT / "governance/convergence/retirement-register.csv"
archive_retirements = []
if not retirement_register.is_file():
    error("historical-value convergence retirement register is missing")
else:
    try:
        with retirement_register.open(newline="", encoding="utf-8") as handle:
            archive_retirements = [row for row in csv.DictReader(handle) if row.get("object_class") == "refactor-source-archive"]
    except (OSError, csv.Error) as exc:
        error(f"invalid convergence retirement register: {exc}")
if len(archive_retirements) != 47:
    error(f"convergence retirement register must account for 47 removed refactor source archives, found {len(archive_retirements)}")

# Governed daemon labs -------------------------------------------------------
labs_root = ROOT / "labs/daemon"
if (ROOT / "src/apps/daemon/experiments").exists():
    error("legacy daemon experiments root returned; valuable dormant capabilities belong under governed labs")
if not (labs_root / "README.md").is_file():
    error("daemon labs contract README is missing")
labs_catalog_path = labs_root / "CAPABILITIES.csv"
lab_rows = []
if not labs_catalog_path.is_file():
    error("daemon labs capability catalog is missing")
else:
    try:
        with labs_catalog_path.open(newline="", encoding="utf-8") as handle:
            lab_rows = list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        error(f"invalid daemon labs capability catalog: {exc}")
if len(lab_rows) != 329:
    error(f"daemon labs catalog must account for 329 preserved Go files, found {len(lab_rows)}")
catalog_paths = set()
for row in lab_rows:
    relative = row.get("lab_path", "")
    if not relative.startswith("labs/daemon/proxy/"):
        error(f"daemon labs catalog path escaped labs/proxy: {relative}")
        continue
    if relative in catalog_paths:
        error(f"duplicate daemon labs catalog path: {relative}")
        continue
    catalog_paths.add(relative)
    path = ROOT / relative
    if not path.is_file():
        error(f"catalogued daemon lab source missing: {relative}")
        continue
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != row.get("sha256"):
        error(f"daemon lab source hash drift: {relative}")
    try:
        expected_size = int(row.get("size_bytes", "-1"))
    except ValueError:
        expected_size = -1
    if len(data) != expected_size:
        error(f"daemon lab source size drift: {relative}")
actual_lab_go = {path.relative_to(ROOT).as_posix() for path in (labs_root / "proxy").glob("*.go")}
if actual_lab_go != catalog_paths:
    missing = sorted(actual_lab_go - catalog_paths)
    stale = sorted(catalog_paths - actual_lab_go)
    error(f"daemon labs catalog/file mismatch: unlisted={missing[:5]} stale={stale[:5]}")
for path in (ROOT / "src/apps/daemon/internal").rglob("*.go"):
    body = path.read_text(encoding="utf-8", errors="replace")
    if "labs/daemon" in body or "/labs/" in body:
        error(f"live daemon internal package imports or references labs: {path.relative_to(ROOT).as_posix()}")
for manifest_path in (ROOT / "governance/topology/wave20-experiments.json", ROOT / "governance/topology/wave21-experiments.json"):
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        continue
    for row in manifest.get("moved", []):
        if not str(row.get("target", "")).startswith("labs/daemon/proxy/"):
            error(f"preserved dormant capability is not promoted to labs: {row.get('target')}")

# Governed Android labs ------------------------------------------------------
android_labs = ROOT / "labs/mobile/fragments"
if (ROOT / "src/apps/android/incubator").exists():
    error("legacy Android incubator root returned; retained fragments belong under governed labs")
android_lab_catalog = android_labs / "CAPABILITIES.csv"
android_lab_rows = []
if not (android_labs / "README.md").is_file() or not android_lab_catalog.is_file():
    error("Android labs contract/catalog is incomplete")
else:
    try:
        with android_lab_catalog.open(newline="", encoding="utf-8") as handle:
            android_lab_rows = list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        error(f"invalid Android labs catalog: {exc}")
if len(android_lab_rows) != 11:
    error(f"Android labs catalog must account for 11 preserved code fragments, found {len(android_lab_rows)}")
for row in android_lab_rows:
    relative = row.get("lab_path", "")
    path = ROOT / relative
    if not path.is_file():
        error(f"Android lab fragment missing: {relative}")
        continue
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != row.get("sha256") or len(data) != int(row.get("size_bytes", "-1")):
        error(f"Android lab fragment drift: {relative}")
for build_file in (ROOT / "src/apps/android").rglob("*.gradle.kts"):
    body = build_file.read_text(encoding="utf-8", errors="replace")
    if "labs/" in body or "labs/mobile/fragments" in body:
        error(f"Android build unexpectedly references labs: {build_file.relative_to(ROOT).as_posix()}")

# Governed desktop labs ------------------------------------------------------
desktop_labs = ROOT / "labs/desktop"
legacy_desktop_archive = ROOT / "docs/porting/archive/legacy-client-ui"
if legacy_desktop_archive.exists():
    error("legacy desktop UI archive returned; valuable prototype assets belong under governed Desktop Labs")
desktop_lab_catalog = desktop_labs / "CAPABILITIES.csv"
desktop_lab_rows = []
if not (desktop_labs / "README.md").is_file() or not desktop_lab_catalog.is_file():
    error("Desktop Labs contract/catalog is incomplete")
else:
    try:
        with desktop_lab_catalog.open(newline="", encoding="utf-8") as handle:
            desktop_lab_rows = list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        error(f"invalid Desktop Labs catalog: {exc}")
if len(desktop_lab_rows) != 4:
    error(f"Desktop Labs catalog must account for 4 preserved UI/design assets, found {len(desktop_lab_rows)}")
for row in desktop_lab_rows:
    relative = row.get("lab_path", "")
    path = ROOT / relative
    if not path.is_file():
        error(f"Desktop Lab asset missing: {relative}")
        continue
    data = path.read_bytes()
    try:
        expected_size = int(row.get("size_bytes", "-1"))
    except ValueError:
        expected_size = -1
    if hashlib.sha256(data).hexdigest() != row.get("sha256") or len(data) != expected_size:
        error(f"Desktop Lab asset drift: {relative}")
frontend_root = ROOT / "src/packages/control-ui"
for path in frontend_root.rglob("*") if frontend_root.is_dir() else []:
    if not path.is_file() or path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".css", ".json"}:
        continue
    body = path.read_text(encoding="utf-8", errors="replace")
    if "labs/desktop" in body or "/labs/" in body or "../labs" in body:
        error(f"supported control UI imports or references labs: {path.relative_to(ROOT).as_posix()}")

# Android boundary -----------------------------------------------------------
android_main = ROOT / "src/apps/android/app/src/main"
android_sources = sorted(
    path for path in android_main.rglob("*")
    if path.suffix.lower() in {".kt", ".java"}
) if android_main.is_dir() else []
expected_android_sources = {
    "src/apps/android/app/src/main/java/com/luminet/android/LumiNetActivity.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/LumiNetTileService.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/PerAppVpnPolicy.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/VpnRuntimeState.kt",
}
actual_android_sources = {path.relative_to(ROOT).as_posix() for path in android_sources}
if actual_android_sources != expected_android_sources:
    error(
        "canonical Android source set must contain exactly Activity, tile controller, per-app policy, "
        "physical-underlay observer, VpnEngineService, and runtime-state model; "
        f"found {sorted(actual_android_sources)}"
    )

per_app_source = text("src/apps/android/app/src/main/java/com/luminet/android/PerAppVpnPolicy.kt")
if "PerAppVpnMode.INCLUDE" not in per_app_source or "PerAppVpnMode.EXCLUDE" not in per_app_source:
    error("Android per-app policy must keep include/exclude modes explicit")
if "MAX_PACKAGES = 256" not in per_app_source:
    error("Android per-app policy must keep the package-set resource bound")
underlay_source = text("src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt")
if "NET_CAPABILITY_NOT_VPN" not in underlay_source or "registerNetworkCallback" not in underlay_source:
    error("Android underlay tracker must observe only passive non-VPN candidates")
if "connectivity.requestNetwork(" in underlay_source:
    error("Android underlay tracker must not request or hold a physical network")
if "setUnderlyingNetworks" not in underlay_source or "unregisterNetworkCallback" not in underlay_source:
    error("Android underlay tracker must apply metadata and own callback cleanup")

manifest = text("src/apps/android/app/src/main/AndroidManifest.xml")
if "LumiNetActivity" not in manifest or "VpnEngineService" not in manifest:
    error("Android manifest must declare LumiNetActivity and canonical VpnEngineService")
service_count = len(re.findall(r"<service\b", manifest))
if service_count != 2:
    error(f"Android manifest must declare exactly two services (VPN authority + Quick Settings controller), found {service_count}")
if manifest.count("android.permission.BIND_VPN_SERVICE") != 1:
    error("Android manifest must retain exactly one BIND_VPN_SERVICE authority")
if "LumiNetTileService" not in manifest or "android.permission.BIND_QUICK_SETTINGS_TILE" not in manifest:
    error("Android manifest must declare the permission-bound LumiNet Quick Settings tile controller")
for legacy_component in ("OutlineVpnService", "WhiteDnsVpnService", "OrbotVpnService"):
    if legacy_component in manifest:
        error(f"legacy Android VPN authority remains declared: {legacy_component}")

banned_android = ("GlobalScope", "Dispatchers.Unconfined", "runBlocking", "System.loadLibrary", "external fun")
for source in android_sources:
    body = source.read_text(encoding="utf-8", errors="replace")
    for token in banned_android:
        if token in body:
            error(f"unsafe/legacy Android primitive {token} in {source.relative_to(ROOT).as_posix()}")

android_gradle = text("src/apps/android/app/build.gradle.kts")
if "libs/luminet.aar" not in android_gradle or "verifyLuminetAar" not in android_gradle:
    error("Android app does not fail closed around the generated mobilebind AAR")

if not (ROOT / "src/apps/android/gradlew").is_file():
    warn("Android Gradle wrapper is not present for local wrapper-based builds; CI/release explicitly provision Gradle 9.5.0")

# CI and release reproducibility --------------------------------------------
action_ref = re.compile(r"uses:\s+([^\s#]+)\s*(?:#\s*(.*))?")
full_sha = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
for workflow in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
    body = workflow.read_text(encoding="utf-8", errors="replace")
    if "GO_VERSION: '1.26.5'" not in body:
        error(f"{workflow.relative_to(ROOT).as_posix()} does not select Go 1.26.5")
    for line_no, line in enumerate(body.splitlines(), 1):
        match = action_ref.search(line)
        if not match:
            continue
        reference, comment = match.groups()
        if not full_sha.match(reference):
            error(f"floating action ref: {workflow.relative_to(ROOT).as_posix()}:{line_no}: {reference}")
        if not comment:
            error(f"pinned action lacks readable version comment: {workflow.relative_to(ROOT).as_posix()}:{line_no}")
    if "@latest" in body:
        warn(f"{workflow.relative_to(ROOT).as_posix()} contains an @latest tool install")
    if "raw.githubusercontent.com" in body and "/main/" in body:
        warn(f"{workflow.relative_to(ROOT).as_posix()} downloads a script from a floating main branch")

# Historical material and graph tooling -------------------------------------
for legacy in (
    "LumiNet_Master_Porting_Compendium.md",
    "LumiNet_Porting_Investigation_Report.md",
    "PORTING_CATALOG.md",
    "Tor_Porting_Investigation_Report.md",
    "porting_progress.json",
):
    if (ROOT / legacy).exists():
        error(f"historical porting file remains at repository root: {legacy}")

if not (ROOT / "docs/porting/archive").is_dir():
    error("historical porting material has no explicit archive boundary")

# Report ---------------------------------------------------------------------
print(f"errors={len(errors)} warnings={len(warnings)}")
for item in errors:
    print(f"ERROR: {item}")
for item in warnings:
    print(f"WARN: {item}")
sys.exit(1 if errors else 0)
