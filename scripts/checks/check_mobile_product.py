#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import ipaddress
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []


def read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing required file: {rel}")
        return ""
    return p.read_text(encoding="utf-8")


def check_catalog(rel: str, expected_count: int) -> int:
    p = ROOT / rel
    if not p.is_file():
        errors.append(f"missing preservation catalog: {rel}")
        return 0
    rows = list(csv.DictReader(p.open(encoding="utf-8", newline="")))
    if len(rows) != expected_count:
        errors.append(f"{rel}: expected {expected_count} rows, found {len(rows)}")
    for row in rows:
        target = ROOT / row["lab_path"]
        if not target.is_file():
            errors.append(f"{rel}: missing preserved target {row['lab_path']}")
            continue
        data = target.read_bytes()
        if len(data) != int(row["bytes"]):
            errors.append(f"{rel}: size mismatch for {row['lab_path']}")
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            errors.append(f"{rel}: sha256 mismatch for {row['lab_path']}")
    return len(rows)

# Android compiled source boundary.
java_root = ROOT / "src/apps/android/app/src/main/java"
kotlin = sorted(p.relative_to(ROOT).as_posix() for p in java_root.rglob("*.kt"))
expected_kotlin = [
    "src/apps/android/app/src/main/java/com/luminet/android/LumiNetActivity.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/LumiNetTileService.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/PerAppVpnPolicy.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt",
    "src/apps/android/app/src/main/java/com/luminet/android/VpnRuntimeState.kt",
]
if kotlin != expected_kotlin:
    errors.append(
        "Android live Kotlin source must be exactly the Activity, Quick Settings observer/controller, VPN service, runtime-state contract, per-app policy owner, "
        f"and passive underlying-network tracker; found {kotlin}"
    )

activity = read("src/apps/android/app/src/main/java/com/luminet/android/LumiNetActivity.kt")
for needle, label in {
    "registerForActivityResult(ActivityResultContracts.StartActivityForResult())": "VPN permission activity-result launcher",
    "VpnService.prepare(this)": "VPN permission preparation",
    "ContextCompat.startForegroundService": "foreground VPN service start",
    "setAction(VpnEngineService.ACTION_STOP)": "VPN service stop action",
    "VpnEngineService.runtimeState.collectAsStateWithLifecycle()": "lifecycle-aware service-owned connection state",
}.items():
    if needle not in activity:
        errors.append(f"LumiNetActivity missing {label}")
if "isConnected = !isConnected" in activity:
    errors.append("LumiNetActivity still uses a UI-only connection toggle")
for forbidden in ["Latency: 24 ms", "Evasion: uTLS Active"]:
    if forbidden in activity:
        errors.append(f"LumiNetActivity advertises fabricated runtime telemetry: {forbidden}")
if "VpnRuntimeStage.STARTING" not in activity or "VpnRuntimeStage.STOPPING" not in activity or "VpnRuntimeStage.ERROR" not in activity:
    errors.append("LumiNetActivity must render transitional/error service-owned runtime stages")

manifest = read("src/apps/android/app/src/main/AndroidManifest.xml")
services = re.findall(r"<service\b", manifest)
if len(services) != 2:
    errors.append(f"Android manifest must declare VPN authority plus Quick Settings controller, found {len(services)}")
if manifest.count("android.permission.BIND_VPN_SERVICE") != 1:
    errors.append("Android manifest must retain exactly one BIND_VPN_SERVICE authority")
if 'android:name="com.luminet.android.VpnEngineService"' not in manifest:
    errors.append("Android manifest must declare canonical VpnEngineService")

service = read("src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt")
required_service = {
    "import com.luminet.mobilebind.VPNEngine": "generated VPNEngine import",
    "import com.luminet.mobilebind.Mobilebind": "generated mobilebind package bridge import",
    "import com.luminet.mobilebind.SocketProtector": "generated socket protector import",
    "Mobilebind.registerSocketProtector": "socket protector registration",
    "this@VpnEngineService.protect(fd.toInt())": "VpnService.protect delegation",
    "Mobilebind.registerSocketProtector(null)": "socket protector teardown",
    ".setBlocking(true)": "blocking TUN mode",
    "PerAppVpnPolicyStore.load(this).applyTo(builder, packageName)": "mobile-local per-app policy enforcement",
    "UnderlyingNetworkTracker(this).also { it.start() }": "passive physical-underlay observation",
    "detachFd()": "TUN ownership transfer",
    "candidate.start(tunFd, \"\")": "direct generated AAR start",
}
for needle, label in required_service.items():
    if needle not in service:
        errors.append(f"VpnEngineService missing {label}")
# Socket protection is a lifecycle contract, not merely a generated symbol.
start_fn = re.search(r"(?ms)private fun startVpnTunnel\(\): Boolean \{(?P<body>.*?)(?=^    private fun )", service)
if not start_fn:
    errors.append("VpnEngineService missing startVpnTunnel lifecycle")
else:
    body = start_fn.group("body")
    reg = body.find("registerSocketProtector()")
    start = body.find('candidate.start(tunFd, "")')
    if reg < 0 or start < 0 or reg > start:
        errors.append("socket protector registration must occur before VPNEngine.start in startVpnTunnel")
    catch = body.find("catch (ex: Exception)")
    if catch < 0 or "unregisterSocketProtector()" not in body[catch:]:
        errors.append("startVpnTunnel failure cleanup must unregister the socket protector")
stop_fn = re.search(r"(?ms)private fun stopVpn\([^)]*\) \{(?P<body>.*?)(?=^    private fun )", service)
if not stop_fn or "unregisterSocketProtector()" not in stop_fn.group("body"):
    errors.append("stopVpn must unregister the socket protector")

# Per-app VPN authority must remain Android-local, bounded, mode-exclusive, and fail closed.
per_app_policy = read("src/apps/android/app/src/main/java/com/luminet/android/PerAppVpnPolicy.kt")
for needle, label in {
    "MAX_PACKAGES = 256": "bounded package policy",
    "PerAppVpnMode.ALL": "all-app mode",
    "PerAppVpnMode.INCLUDE": "allow-list mode",
    "PerAppVpnMode.EXCLUDE": "deny-list mode",
    "builder::addAllowedApplication": "allow-list enforcement",
    "builder.addDisallowedApplication": "deny-list/self-exclusion enforcement",
    "selfPackage !in normalized.packages": "self-inclusion rejection",
}.items():
    if needle not in per_app_policy:
        errors.append(f"PerAppVpnPolicy missing {label}")
if "addAllowedApplication" in service or "addDisallowedApplication" in service:
    errors.append("VpnEngineService must delegate package selection to the canonical PerAppVpnPolicy owner")

# Physical underlay observation is advisory metadata, never a second routing authority.
underlay = read("src/apps/android/app/src/main/java/com/luminet/android/UnderlyingNetworkTracker.kt")
for needle, label in {
    "NetworkCapabilities.NET_CAPABILITY_INTERNET": "internet-capable network filter",
    "NetworkCapabilities.NET_CAPABILITY_NOT_VPN": "non-VPN network filter",
    "connectivity.registerNetworkCallback": "passive network callback",
    "vpnService.setUnderlyingNetworks": "VPN underlying-network update",
    "connectivity.unregisterNetworkCallback": "network callback teardown",
}.items():
    if needle not in underlay:
        errors.append(f"UnderlyingNetworkTracker missing {label}")
if re.search(r"\bconnectivity\.requestNetwork\s*\(", underlay):
    errors.append("UnderlyingNetworkTracker must remain passive and must not request/hold a network")
if "stopUnderlyingNetworkTracker()" not in service:
    errors.append("VpnEngineService must tear down the underlying-network tracker")
if "ACCESS_NETWORK_STATE" not in manifest:
    errors.append("Android manifest must declare ACCESS_NETWORK_STATE for passive underlay observation")

for forbidden in ["external fun", "System.loadLibrary", "android.system.Os", "dup2", "STABLE_TUN_FD"]:
    if forbidden in service:
        errors.append(f"VpnEngineService retains forbidden legacy native path: {forbidden}")
if "getInstance()" in service or "private var instance: VpnEngineService?" in service:
    errors.append("VpnEngineService retains unused process-global service instance access")

# Android's advertised resolver must be an actual routed DNS endpoint. The
# synthetic TUN subnet is owned by the userspace NAT; advertising an address
# inside that subnet without a local DNS listener blackholes resolver traffic.
dns_match = re.search(r'private const val VPN_DNS = "([^"]+)"', service)
address_match = re.search(r'private const val VPN_ADDRESS = "([^"]+)"', service)
prefix_match = re.search(r'private const val VPN_ADDRESS_PREFIX = (\d+)', service)
if not dns_match or not address_match or not prefix_match:
    errors.append("VpnEngineService must declare VPN_DNS, VPN_ADDRESS, and VPN_ADDRESS_PREFIX")
else:
    try:
        dns_ip = ipaddress.ip_address(dns_match.group(1))
        tun_network = ipaddress.ip_network(
            f"{address_match.group(1)}/{prefix_match.group(1)}", strict=False
        )
        if dns_ip in tun_network:
            errors.append(
                f"Android VPN DNS {dns_ip} is inside synthetic TUN network {tun_network}; "
                "use a routable resolver or add an explicit local DNS owner"
            )
    except ValueError as exc:
        errors.append(f"invalid Android VPN network/DNS constant: {exc}")

# Generated AAR dependency is mandatory and fail-closed.
gradle = read("src/apps/android/app/build.gradle.kts")
for needle in [
    'layout.projectDirectory.file("libs/luminet.aar")',
    "implementation(files(luminetAar))",
    'tasks.named("preBuild")',
    "dependsOn(verifyLuminetAar)",
]:
    if needle not in gradle:
        errors.append(f"Android Gradle missing linked AAR invariant: {needle}")

bind_script = read("scripts/mobile_bind.sh")
if "-javapkg=com.luminet -target=android" not in bind_script:
    errors.append("mobile_bind.sh must pin generated Java package prefix to com.luminet")
for needle, label in {
    'ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"': "repository-root resolution",
    'OUT_DIR="$ROOT_DIR/build/mobile"': "repository-root mobile output directory",
    'APP_LIB_DIR="$ROOT_DIR/src/apps/android/app/libs"': "canonical Android app AAR directory",
    'cd "$ROOT_DIR/src/apps/daemon"': "canonical daemon module entry",
    '-o "$OUT_DIR/luminet.aar"': "repository-root AAR output path",
    'cp "$OUT_DIR/luminet.aar" "$APP_LIB_DIR/luminet.aar"': "generated AAR-to-app linkage",
}.items():
    if needle not in bind_script:
        errors.append(f"mobile_bind.sh missing {label}")

# Android is the only current shipped mobile host. Keep iOS source-level
# compatibility/future work from becoming an accidental product delivery path
# without a real host, CI lane, release artifact, and architecture decision.
for forbidden in ["-target=ios", ".xcframework", "LumiNet.xcframework"]:
    if forbidden in bind_script:
        errors.append(f"mobile_bind.sh advertises unsupported current iOS delivery: {forbidden}")

current_system = read("docs/current-system.md")
if "Android/iOS select the pure-Go bridge path" in current_system:
    errors.append("current-system docs still present iOS as a current mobile host")

mobile_arch = read("docs/architecture/multi-platform-client.md")
mobile_arch_lower = mobile_arch.lower()
if "historical zygisk, swift network extension" not in mobile_arch_lower or "not shipped product surfaces" not in mobile_arch_lower:
    errors.append("supported-host architecture must keep historical iOS/Swift surfaces explicitly unshipped")
if "no current ios host, ci product lane, or release artifact" not in mobile_arch_lower:
    errors.append("supported-host architecture must state the current iOS delivery boundary")

# CI and release must prove the actual linked Android product, not just source
# structure or the standalone AAR. The same generated AAR must be copied into
# app/libs before Gradle assembles the APK so the app's fail-closed dependency
# check exercises the artifact that ships.
ci_workflow = read(".github/workflows/ci.yml")
ci_android = re.search(r"(?ms)^  android:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", ci_workflow)
if not ci_android:
    errors.append("CI must contain a dedicated Android product job")
else:
    body = ci_android.group("body")
    for needle, label in {
        "mkdir -p build src/apps/android/app/libs": "clean-checkout Android build directories",
        "gomobile bind": "gomobile AAR build",
        "-o ../../../build/luminet.aar": "repository-root AAR output path",
        "-javapkg=com.luminet": "deterministic generated Java package",
        "cp build/luminet.aar src/apps/android/app/libs/luminet.aar": "AAR-to-app linkage",
        "gradle --no-daemon :app:assembleDebug": "linked APK build",
    }.items():
        if needle not in body:
            errors.append(f"CI Android job missing {label}")

release_workflow = read(".github/workflows/release.yml")
release_android = re.search(r"(?ms)^  build-android:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", release_workflow)
if not release_android:
    errors.append("release workflow must contain build-android job")
else:
    body = release_android.group("body")
    for needle, label in {
        "mkdir -p build src/apps/android/app/libs": "clean-checkout Android build directories",
        "gomobile bind": "gomobile AAR build",
        "-o ../../../build/luminet.aar": "repository-root AAR output path",
        "-javapkg=com.luminet": "deterministic generated Java package",
        "cp build/luminet.aar src/apps/android/app/libs/luminet.aar": "AAR-to-app linkage",
        "gradle --no-daemon :app:assembleRelease": "linked release APK build",
        "find app/build/outputs/apk/release": "release APK output discovery",
        "luminet-android-unsigned.apk": "explicit unsigned release artifact naming",
        'cp "${apks[0]}" ../../../../build/luminet-android-unsigned.apk': "repository-root APK output path",
        "build/luminet.aar": "AAR artifact upload",
        "build/luminet-android-unsigned.apk": "truthfully named unsigned APK artifact upload",
    }.items():
        if needle not in body:
            errors.append(f"release Android job missing {label}")
    for forbidden in ["Setup Rust", "Install cbindgen", "Build Rust core", "Generate header"]:
        if forbidden in body:
            errors.append(f"release Android job retains obsolete host-Rust step: {forbidden}")

release_job = re.search(r"(?ms)^  release:\n(?P<body>.*)\Z", release_workflow)
if not release_job:
    errors.append("release workflow must contain final release job")
else:
    body = release_job.group("body")
    for needle, label in {
        "artifacts/luminet.aar": "AAR publication",
        "artifacts/luminet-android-unsigned.apk": "unsigned APK publication",
        "sbom-android-aar.spdx.json": "AAR SBOM",
        "sbom-android-apk.spdx.json": "APK SBOM",
        "subject-path: artifacts/luminet.aar": "AAR provenance attestation",
        "subject-path: artifacts/luminet-android-unsigned.apk": "unsigned APK provenance attestation",
    }.items():
        if needle not in body:
            errors.append(f"final release job missing {label}")

# Gobind surface and ownership semantics.
binding = read("src/apps/daemon/internal/adapters/mobilebind/mobilebind.go")
if not re.search(r"func\s+\(e\s+\*VPNEngine\)\s+Start\(tunFd\s+int32,\s*config\s+string\)\s+error", binding):
    errors.append("VPNEngine.Start must be Start(tunFd int32, config string) error")
core = read("src/apps/daemon/internal/runtime/mobilecore/controller.go")
start_match = re.search(r"func \(c \*CoreController\) StartLoop\(configContent string, tunFd int32\) error \{(?P<body>.*?)\n\}", core, re.S)
if not start_match:
    errors.append("CoreController.StartLoop signature missing")
else:
    body = start_match.group("body")
    if "tunFd >= 0" not in body:
        errors.append("CoreController must treat fd 0 as valid transferred TUN")
    newfile = body.find("os.NewFile")
    running = body.find("if c.isRunning")
    if newfile < 0 or running < 0 or newfile > running:
        errors.append("CoreController must take TUN ownership before lifecycle rejection")
    if "mobilehost.StartTun2SocksWithDNS" not in body:
        errors.append("CoreController must use real mobilehost.StartTun2SocksWithDNS adapter")
    if "system.StartTun2Socks" in body:
        errors.append("CoreController must not route mobile TUN ownership through the broad system module")
    if "startTunDeviceRouting" in body:
        errors.append("legacy packet-drain TUN path remains live")

for rel in [
    "src/apps/daemon/internal/runtime/proxy/mobile_bind_platform.go",
    "src/apps/daemon/internal/platform/system/gomobile_api.go",
]:
    if (ROOT / rel).exists():
        errors.append(f"deprecated fake mobile API remains live: {rel}")

# Host Rust C ABI must not enter gomobile target builds.
cgo_files = ["ffi.go", "version.go", "streaming.go", "ffi_types.go", "core.go"]
for name in cgo_files:
    first = read(f"src/apps/daemon/internal/native/bridge/{name}").splitlines()[:1]
    if first != ["//go:build cgo && !android && !ios"]:
        errors.append(f"bridge/{name} is not host-only")
if read("src/apps/daemon/internal/native/bridge/core_degraded.go").splitlines()[:1] != ["//go:build !cgo || android || ios"]:
    errors.append("bridge/core_degraded.go must be selected for Android/iOS")
if (ROOT / "src/apps/daemon/internal/native/bridge/core_mock.go").exists():
    errors.append("retired bridge/core_mock.go must not return; degraded truth is owned by core_degraded.go")

rust_ffi_mod = read("src/packages/lumicore/src/ffi/mod.rs")
rust_transport_mod = read("src/packages/lumicore/src/transport/mod.rs")
cargo = read("src/packages/lumicore/Cargo.toml")
if "android_jni" in rust_ffi_mod:
    errors.append("obsolete Rust Android JNI remains in live module graph")
# Match the placeholder module by exact identifier, not substring: the live
# userspace NAT router is legitimately named tun2socks_router and must not
# trip a check intended for a stub module literally named tun2socks.
if re.search(r"\bpub mod tun2socks\b|\bpub use tun2socks\b", rust_transport_mod):
    errors.append("placeholder Rust tun2socks remains in live module graph")
if re.search(r"^jni\s*=", cargo, re.M):
    errors.append("unused JNI crate remains an active Cargo dependency")

android_alts = check_catalog("labs/mobile/runtime-alternates/ALTERNATES.csv", 8)
rust_alts = check_catalog("labs/lumicore/mobile-alternates/ALTERNATES.csv", 2)
go_alts = check_catalog("labs/daemon/mobile-api-alternates.csv", 4)

print(
    f"android_sources={len(kotlin)} android_services={len(services)} "
    f"android_runtime_alternates={android_alts} rust_mobile_alternates={rust_alts} "
    f"go_mobile_alternates={go_alts} errors={len(errors)}"
)
for err in errors:
    print(f"ERROR: {err}")
sys.exit(1 if errors else 0)
