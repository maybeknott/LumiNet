#!/usr/bin/env python3
"""Enforce LumiNet's src/ containment and daemon dependency-band direction."""
from __future__ import annotations
import re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
DAEMON = SRC / "apps" / "daemon"
INTERNAL = DAEMON / "internal"
MODULE = "github.com/maybeknott/luminet/internal/"

BANDS = {
    "foundation": 0,
    "native": 0,
    "protocols": 1,
    "platform": 1,
    "networking": 2,
    "analysis": 3,
    "integrations": 3,
    "runtime": 4,
    "workflows": 5,
    "adapters": 6,
}
EXPECTED_ROOTS = {
    "src/apps/daemon", "src/apps/desktop", "src/apps/android",
    "src/packages/contracts",
    "src/packages/control-ui", "src/packages/lumicore",
    "src/packages/lumicore-sdk",
}
EXPECTED_APP_DIRS = {"daemon", "desktop", "android"}
EXPECTED_PACKAGE_DIRS = {"contracts", "control-ui", "lumicore", "lumicore-sdk"}
IMPORT_RE = re.compile(r'"github\.com/maybeknott/luminet/internal/([^"/]+)(?:/([^"/]+))?')
errors: list[str] = []

for rel in EXPECTED_ROOTS:
    if not (ROOT / rel).is_dir():
        errors.append(f"missing canonical source root: {rel}")

for parent, expected in ((SRC / "apps", EXPECTED_APP_DIRS), (SRC / "packages", EXPECTED_PACKAGE_DIRS)):
    if not parent.is_dir():
        continue
    actual = {entry.name for entry in parent.iterdir() if entry.is_dir()}
    for name in sorted(actual - expected):
        errors.append(f"unexpected canonical source root: {(parent / name).relative_to(ROOT)}")
    for name in sorted(expected - actual):
        errors.append(f"missing canonical source root: {(parent / name).relative_to(ROOT)}")
for obsolete in (ROOT / "apps", ROOT / "packages"):
    if obsolete.exists():
        errors.append(f"legacy top-level source root returned: {obsolete.relative_to(ROOT)}")
if not (ROOT / "third_party" / "gaio").is_dir():
    errors.append("third-party gaio reference is not separated under third_party/gaio")
if (DAEMON / "third_party").exists():
    errors.append("third-party source leaked back under daemon product source")

# Local Go module replacements are part of the source-layout contract. A source move
# is incomplete if a relative replacement still points at the old physical tree.
for mod_file in SRC.rglob("go.mod"):
    for lineno, line in enumerate(mod_file.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = re.match(r"\s*replace\s+\S+\s+=>\s+([^\s]+)", line)
        if not match:
            continue
        target = match.group(1)
        if not target.startswith(("./", "../")):
            continue
        resolved = (mod_file.parent / target).resolve()
        if not resolved.exists():
            errors.append(
                f"{mod_file.relative_to(ROOT)}:{lineno}: local replace target does not exist: {target}"
            )

actual_bands = {p.name for p in INTERNAL.iterdir() if p.is_dir()} if INTERNAL.is_dir() else set()
unknown = sorted(actual_bands - set(BANDS))
missing = sorted(set(BANDS) - actual_bands)
for band in unknown:
    errors.append(f"unknown daemon internal band: {band}")
for band in missing:
    errors.append(f"missing daemon internal band: {band}")

# Each band is a namespace only; source code belongs to a concrete child module.
for band in BANDS:
    d = INTERNAL / band
    if d.is_dir():
        direct_go = sorted(p.name for p in d.glob("*.go"))
        if direct_go:
            errors.append(f"{d.relative_to(ROOT)}: source bypasses module folders: {', '.join(direct_go)}")

edges: set[tuple[str, str]] = set()
for path in DAEMON.rglob("*.go"):
    if path.name.endswith("_test.go"):
        # Tests must obey the same import direction; keep them in the scan.
        pass
    try:
        rel = path.parent.relative_to(INTERNAL)
    except ValueError:
        continue
    if len(rel.parts) < 2:
        continue
    source_band = rel.parts[0]
    if source_band not in BANDS:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in IMPORT_RE.finditer(text):
        target_band = match.group(1)
        target_module = match.group(2)
        if target_band not in BANDS:
            errors.append(
                f"{path.relative_to(ROOT)}: flat/unknown internal import {match.group(0)[1:]}"
            )
            continue
        if not target_module:
            errors.append(
                f"{path.relative_to(ROOT)}: imports band namespace instead of concrete module: {target_band}"
            )
            continue
        edges.add((source_band, target_band))
        if source_band != target_band and BANDS[target_band] >= BANDS[source_band]:
            errors.append(
                f"{path.relative_to(ROOT)}: reverse dependency {source_band} -> {target_band}; "
                f"target rank {BANDS[target_band]} must be lower than source rank {BANDS[source_band]}"
            )

print(
    f"source-structure roots={len(EXPECTED_ROOTS)} bands={len(actual_bands)} "
    f"cross_band_edges={len([e for e in edges if e[0] != e[1]])} errors={len(errors)}"
)
for error in errors:
    print("ERROR:", error)
sys.exit(1 if errors else 0)
