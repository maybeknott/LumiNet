#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "src/packages/control-ui"
SRC = UI / "src"
API = SRC / "api"
SHADOW = ROOT / "labs/control-ui/api-shadow"
MANIFEST = ROOT / "governance/control-ui-api-authority.json"
ENTRYPOINT = SRC / "main.tsx"
IMPORT_RE = re.compile(
    r"(?:import|export)\s+(?:[^'\"]*?\s+from\s+)?['\"]([^'\"]+)['\"]|"
    r"import\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".css")


def resolve(source: Path, spec: str) -> Path | None:
    if not spec.startswith('.'):
        return None
    raw = (source.parent / spec).resolve()
    candidates: list[Path] = []
    if raw.suffix:
        candidates.append(raw)
        if raw.suffix in {".js", ".jsx"}:
            candidates.extend([raw.with_suffix(".ts"), raw.with_suffix(".tsx")])
    else:
        candidates.extend(Path(str(raw) + ext) for ext in EXTS)
        candidates.extend(raw / ("index" + ext) for ext in EXTS)
    for candidate in candidates:
        try:
            candidate.relative_to(SRC.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


reachable: set[Path] = set()
stack = [ENTRYPOINT.resolve()]
while stack:
    source = stack.pop()
    if source in reachable:
        continue
    reachable.add(source)
    if source.suffix == ".css":
        continue
    text = source.read_text(encoding="utf-8")
    for match in IMPORT_RE.finditer(text):
        spec = match.group(1) or match.group(2)
        target = resolve(source, spec)
        if target is not None and target not in reachable:
            stack.append(target)

api_files = sorted(
    p.resolve() for p in API.rglob("*")
    if p.is_file() and p.suffix in {".ts", ".tsx"}
)

# Preservation policy keeps pre-existing source paths present. When a retired
# API module is mirrored byte-for-byte under labs/control-ui/api-shadow, the
# live-path copy is a compatibility/preservation mirror rather than a second
# product authority. Only exact mirrors receive this treatment: any divergence
# immediately returns the live path to canonical reachability accounting.
compatibility_mirrors: list[Path] = []
canonical_api_files: list[Path] = []
for api_file in api_files:
    relative = api_file.relative_to(API.resolve())
    shadow_file = SHADOW / relative
    if shadow_file.is_file() and api_file.read_bytes() == shadow_file.read_bytes():
        compatibility_mirrors.append(api_file)
    else:
        canonical_api_files.append(api_file)

unreachable = [p for p in canonical_api_files if p not in reachable]
errors: list[str] = []
if unreachable:
    errors.append(
        "canonical src/api contains modules unreachable from src/main.tsx: "
        + ", ".join(str(p.relative_to(UI)) for p in unreachable[:20])
        + (" ..." if len(unreachable) > 20 else "")
    )

for source in (SRC.rglob("*.ts"), SRC.rglob("*.tsx")):
    for path in source:
        text = path.read_text(encoding="utf-8")
        if "labs/control-ui/api-shadow" in text:
            errors.append(f"live source imports the non-authoritative shadow corpus: {path.relative_to(ROOT)}")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
if manifest.get("api_unreachable") != 0:
    errors.append("authority manifest must record api_unreachable=0 after relocation")
if manifest.get("api_total") != len(canonical_api_files):
    errors.append(
        f"authority manifest api_total={manifest.get('api_total')} but canonical src/api has {len(canonical_api_files)} modules"
    )
if manifest.get("api_reachable") != len(canonical_api_files):
    errors.append("authority manifest must classify every canonical API module as reachable")
if not SHADOW.is_dir():
    errors.append("explicit labs/control-ui/api-shadow boundary is missing")

print(
    "control-ui-api-authority "
    f"canonical={len(canonical_api_files)} "
    f"compatibility_mirrors={len(compatibility_mirrors)} "
    f"unreachable={len(unreachable)} errors={len(errors)}"
)
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
