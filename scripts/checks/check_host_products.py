#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def job_body(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if not match:
        errors.append(f"workflow missing job: {name}")
        return ""
    return match.group("body")


makefile = read("Makefile")
package_json = read("src/packages/control-ui/package.json")
if '"packageManager": "npm@10.9.2"' not in package_json:
    errors.append("control UI packageManager must match the pinned Node 22.16.0 npm 10.9.2 toolchain")
if '"audit": "npm audit"' not in package_json:
    errors.append("control UI package must own the full dependency-audit command")
if not re.search(r"(?m)^release:\s+verify-release(?:\s|$)", makefile):
    errors.append("local make release must depend on canonical release admission")
if not re.search(
    r'cd "\$\(DESKTOP_DIR\)" && go build -trimpath -o "\$\(BUILD_DIR\)/luminet-desktop\$\(EXE_EXT\)" \.',
    makefile,
):
    errors.append("Makefile desktop build must compile the Wails host without daemon-only build-info linker flags")
if not re.search(r"(?m)^build-go:\s+build-rust\s+build-web(?:\s|$)", makefile):
    errors.append("Makefile build-go must depend on build-web so daemon never embeds the bootstrap in a canonical Make build")

shell = read("scripts/build-all.sh")
for needle, label in {
    'WEB_DIR="$ROOT_DIR/src/packages/control-ui"': "shared UI path",
    'DESKTOP_DIR="$ROOT_DIR/src/apps/desktop"': "desktop path",
    'npm ci': "canonical UI install",
    'npm run build': "canonical UI build",
    'luminet-desktop': "desktop artifact build",
    '-ldflags "$LDFLAGS"': "shared build identity",
}.items():
    if needle not in shell:
        errors.append(f"build-all.sh missing {label}")

dev_shell = read("scripts/dev.sh")
dev_powershell = read("scripts/dev.ps1")
if "pnpm" in dev_shell or "npm run dev" not in dev_shell:
    errors.append("dev.sh must use the control UI's canonical npm package-manager interface")
if "pnpm" in dev_powershell or 'Assert-Command "npm"' not in dev_powershell or 'FilePath "npm.cmd"' not in dev_powershell:
    errors.append("dev.ps1 must use the control UI's canonical npm package-manager interface")


for legacy_resource in (
    "src/apps/daemon/luminet_windows.rc",
    "src/apps/daemon/luminet.exe.manifest",
):
    if (ROOT / legacy_resource).exists():
        errors.append(f"retired native-Walk Windows daemon resource remains live: {legacy_resource}")

powershell = read("scripts/build-all.ps1")
if "windres" in powershell or "rsrc_windows_amd64.syso" in powershell:
    errors.append("build-all.ps1 must not generate a legacy daemon UI resource inside live source")
for needle, label in {
    'src/packages/control-ui': "shared UI path",
    'src/apps/desktop': "desktop path",
    'npm ci': "canonical UI install",
    'npm run build': "canonical UI build",
    'luminet-desktop.exe': "desktop artifact build",
}.items():
    if needle not in powershell:
        errors.append(f"build-all.ps1 missing {label}")



bootstrap = read("src/packages/control-ui/dist/index.html")
bootstrap_marker = 'data-luminet-bootstrap="unbuilt"'
legacy_bundle = ROOT / "src/packages/control-ui/dist/assets"
legacy_markers = ("localhost:9090", "ws://localhost:9090", "/api/v1/telemetry/stream")
if bootstrap_marker in bootstrap:
    for legacy in legacy_markers:
        if legacy in bootstrap:
            errors.append(f"tracked control-ui bootstrap retains legacy backend marker: {legacy}")
else:
    js_assets = sorted(legacy_bundle.rglob("*.js")) if legacy_bundle.exists() else []
    if not js_assets:
        errors.append("control-ui dist is neither the fail-closed bootstrap nor a generated JS bundle")
    built_js = "\n".join(asset.read_text(encoding="utf-8", errors="replace") for asset in js_assets)
    for legacy in legacy_markers:
        if legacy in built_js:
            errors.append(f"generated control-ui bundle retains legacy backend marker: {legacy}")
    if "Desktop session discovery failed; refusing direct HTTP fallback." not in built_js:
        errors.append("generated control-ui bundle lacks current Wails fail-closed session behavior")
    if "/api/session/ws" not in built_js:
        errors.append("generated control-ui bundle lacks current WebSocket session transport")
    if "ExecuteDiagnosticRun" in built_js:
        errors.append("generated control-ui bundle retains retired Wails diagnostic shortcut")

transport = read("src/packages/control-ui/src/api/ControlTransport.ts")
if "Desktop session discovery failed; refusing direct HTTP fallback." not in transport:
    errors.append("Wails session discovery failure must fail closed instead of falling back to direct HTTP")
if "Wails session unavailable; using direct HTTP configuration." in transport:
    errors.append("ControlTransport retains unsafe Wails-to-direct-HTTP fallback")


desktop_main = read("src/apps/desktop/main.go")
bridge_methods = re.findall(r"(?m)^func \(b \*AppBridge\) ([A-Z][A-Za-z0-9_]*)\(", desktop_main)
if bridge_methods != ["GetSessionConfig"]:
    errors.append(f"desktop AppBridge must expose only GetSessionConfig, found: {bridge_methods}")
for retired_method in ("GetBuildInfo", "ExecuteDiagnosticRun"):
    if retired_method in transport or retired_method in desktop_main:
        errors.append(f"retired desktop Wails method remains reachable: {retired_method}")

router = read("src/apps/daemon/internal/adapters/api/router.go")
if "subFS.Open(" in router:
    errors.append("daemon web host still references removed subFS variable")
if "webFS.Open(filePath)" not in router:
    errors.append("daemon web host must probe assets through shared WebDist filesystem")

ci = read(".github/workflows/ci.yml")
ci_main = job_body(ci, "ci")
ci_macos_secrets = job_body(ci, "macos-secrets")
if "./internal/foundation/secrets" not in ci_macos_secrets:
    errors.append("macOS Keychain CI must test the live internal/foundation/secrets package")
if "./internal/secrets" in ci_macos_secrets:
    errors.append("macOS Keychain CI retains the retired pre-band secrets package path")
if "make build-all" not in ci_main:
    errors.append("CI full host build must run make build-all so desktop is compiled")
if "make verify-release" not in ci_main:
    errors.append("CI must consume the canonical release-admission interface")
for required in ("govulncheck@v1.6.0", "cargo-audit --version 0.22.2 --locked", "PRESERVATION_BASE_SHA"):
    if required not in ci_main:
        errors.append(f"CI release-admission job missing prerequisite: {required}")
if not re.search(r'(?ms)^test-web:.*?\n\s*cd .*?npm ci && npm run audit && npm test && npm run lint && npm run build', makefile):
    errors.append("Makefile test-web must call the control UI full dependency-audit interface before executing test/lint/build tooling")
if 'npm audit --omit=dev' in makefile or 'npm run audit:prod' in makefile:
    errors.append("release admission must not omit frontend dev/build dependencies from npm audit")
if not re.search(r'(?m)^validate-abi:.*$', makefile) or './cmd/validate-abi-manifest -repo-root ..' not in makefile:
    errors.append("Makefile must validate the repository ABI authority before release admission")
for admission_dependency in ("test-tooling", "validate-abi", "validate-preservation", "verify-repo", "audit-dependencies", "lint-rust", "test-rust", "vet-go", "test-go", "test-desktop", "test-web"):
    if not re.search(rf'(?m)^verify-release:.*\b{re.escape(admission_dependency)}\b', makefile):
        errors.append(f"verify-release missing admission dependency: {admission_dependency}")

release = read(".github/workflows/release.yml")
release_verify = job_body(release, "verify-release")
if "make verify-release" not in release_verify:
    errors.append("release verify-release job must consume the canonical Make admission interface")
for required in ("govulncheck@v1.6.0", "cargo-audit --version 0.22.2 --locked", "PRESERVATION_BASE_SHA"):
    if required not in release_verify:
        errors.append(f"release verify-release job missing admission prerequisite: {required}")
if "src/packages/control-ui/dist" not in release_verify or "name: luminet-control-ui" not in release_verify:
    errors.append("release verify-release job must publish the verified control-ui bundle")
if re.search(r"(?m)^  build-control-ui:\s*$", release):
    errors.append("release must not rebuild the control UI outside the verified release-admission job")
release_android = job_body(release, "build-android")
if "needs: verify-release" not in release_android:
    errors.append("release Android build must depend on verified release admission")

release_windows = job_body(release, "build-windows")
if "go vet ./..." not in release_windows or "go test ./... -count=1" not in release_windows:
    errors.append("Windows release build must vet and test Windows/CGO code before packaging")
release_macos_arm64 = job_body(release, "build-macos-arm64")
if "./internal/foundation/secrets" not in release_macos_arm64:
    errors.append("macOS arm64 release build must exercise the live native Keychain provider before packaging")

expected_macos_runners = {
    "build-macos-amd64": "runs-on: macos-15-intel",
    "build-macos-arm64": "runs-on: macos-15",
}
for name, artifact in {
    "build-linux": "luminet-desktop",
    "build-windows": "luminet-desktop.exe",
    "build-macos-amd64": "luminet-desktop",
    "build-macos-arm64": "luminet-desktop",
}.items():
    body = job_body(release, name)
    if not body:
        continue
    if "needs: verify-release" not in body:
        errors.append(f"release job {name} must depend on verified release admission")
    if "src/apps/desktop" not in body or "go build" not in body:
        errors.append(f"release job {name} does not build the desktop host")
    if artifact not in body:
        errors.append(f"release job {name} does not package {artifact}")
    exe = ".exe" if name == "build-windows" else ""
    for expected_output, label in {
        f"-o ../../../build/luminet{exe}": "daemon repository-root output",
        f"-o ../../../build/watchdog{exe}": "watchdog repository-root output",
        f"-o ../../../build/luminet-desktop{exe}": "desktop repository-root output",
    }.items():
        if expected_output not in body:
            errors.append(f"release job {name} has stale src-relative {label}: expected {expected_output}")
    if "mkdir -p build" not in body:
        errors.append(f"release job {name} does not create the clean-checkout build directory")
    if name in expected_macos_runners and expected_macos_runners[name] not in body:
        errors.append(
            f"release job {name} does not pin the architecture-explicit macOS runner "
            f"{expected_macos_runners[name].split(': ', 1)[1]}"
        )


# Control-UI source imports must resolve after structural refactors.
ui_src = ROOT / "src/packages/control-ui/src"
relative_import = re.compile(r"(?:from\s+|import\s*)['\"](\.[^'\"]+)['\"]")
for source in sorted([*ui_src.rglob("*.ts"), *ui_src.rglob("*.tsx")]):
    text = source.read_text(encoding="utf-8")
    for match in relative_import.finditer(text):
        spec = match.group(1)
        base = (source.parent / spec).resolve()
        candidates = [
            base,
            Path(str(base) + ".ts"),
            Path(str(base) + ".tsx"),
            base / "index.ts",
            base / "index.tsx",
        ]
        # TypeScript's node16/bundler resolution maps ".js"-suffixed relative
        # specifiers onto sibling ".ts"/".tsx" modules (the emitted-layout
        # convention). Resolve that mapping before declaring the import dead.
        if spec.endswith(".js"):
            stem = Path(str(base)[:-3])
            candidates += [
                Path(str(stem) + ".ts"),
                Path(str(stem) + ".tsx"),
                stem / "index.ts",
                stem / "index.tsx",
            ]
        if not any(candidate.is_file() for candidate in candidates):
            errors.append(
                f"unresolved control-ui relative import: {source.relative_to(ROOT)} -> {spec}"
            )

settings = read("src/packages/control-ui/src/pages/Settings.tsx")
if "{warpParams.privateKey}" in settings:
    errors.append("Settings must not render the WARP private key unconditionally")
for required in ("warpPrivateKeyVisible", "'Reveal'", "'Hide'"):
    if required not in settings:
        errors.append(f"Settings missing deliberate WARP secret visibility control: {required}")

print(f"host_products errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
sys.exit(1 if errors else 0)
