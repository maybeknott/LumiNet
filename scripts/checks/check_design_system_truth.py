#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
master = (ROOT / "governance/design-system/MASTER.md").read_text(encoding="utf-8")
css = (ROOT / "src/packages/control-ui/src/index.css").read_text(encoding="utf-8")
errors: list[str] = []

required_master = {
    "--bg-void": "#020617",
    "--bg-surface": "#0f172a",
    "--bg-element": "#1e293b",
    "--neon-blue": "#3b82f6",
    "--neon-cyan": "#06b6d4",
    "--neon-purple": "#8b5cf6",
    "--neon-emerald": "#10b981",
    "--neon-warning": "#f59e0b",
    "--neon-error": "#ef4444",
}
css_mapping = {
    "--color-bg-primary": "#020617",
    "--color-bg-secondary": "#0f172a",
    "--color-bg-tertiary": "#1e293b",
    "--color-accent": "#3b82f6",
    "--color-cyan": "#06b6d4",
    "--color-purple": "#8b5cf6",
    "--color-success": "#10b981",
    "--color-warning": "#f59e0b",
    "--color-error": "#ef4444",
}

if "authoritative visual token and component specification" not in master:
    errors.append("MASTER.md no longer declares visual authority")
for token, value in required_master.items():
    if token not in master or value not in master:
        errors.append(f"MASTER.md missing authoritative token {token}={value}")
for token, value in css_mapping.items():
    pattern = rf"{re.escape(token)}\s*:\s*{re.escape(value)}\s*;"
    if not re.search(pattern, css, re.I):
        errors.append(f"index.css drifted from authority: {token} must be {value}")

for font in ("Outfit", "JetBrains Mono"):
    if font not in master or font not in css:
        errors.append(f"font authority drift: {font}")

if "@media (prefers-reduced-motion: reduce)" not in css:
    errors.append("reduced-motion override missing")
if ".btn:focus-visible" not in css or "3px var(--color-accent-glow)" not in css:
    errors.append("keyboard focus treatment missing from canonical controls")
if "rounded-lg" not in css or "rounded-md" not in css:
    errors.append("canonical component rounding primitives missing")

# Prevent the most visible pre-remediation raw palette from returning to the
# retired Cockpit or live page code. CSS variables are the production authority.
for page in (ROOT / "src/packages/control-ui/src/pages").glob("*.tsx"):
    text = page.read_text(encoding="utf-8")
    for raw in ("bg-slate-950", "text-sky-400", "shadow-sky-500", "text-emerald-400"):
        if raw in text:
            errors.append(f"{page.relative_to(ROOT)} reintroduced raw cockpit palette {raw}")

print(f"design-system-truth errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
