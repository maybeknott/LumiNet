#!/usr/bin/env python3
"""Guard the controller-monolith remediation in the canonical Control UI."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "src/packages/control-ui/src"
errors: list[str] = []


def read(relative: str) -> str:
    path = UI / relative
    if not path.is_file():
        errors.append(f"missing required feature-owner file: {relative}")
        return ""
    return path.read_text(encoding="utf-8")


def count(source: str, pattern: str) -> int:
    return len(re.findall(pattern, source))


operations = read("pages/Operations.tsx")
connections = read("pages/Connections.tsx")
diagnostics = read("features/operations/DiagnosticsOperations.tsx")
recovery = read("features/operations/RecoveryOperations.tsx")
deployment = read("features/operations/DeploymentOperations.tsx")
connections_feed = read("features/connections/useConnectionsFeed.ts")
flow_mutations = read("features/connections/useFlowMutations.ts")

# Page shells compose behavioral owners; they do not own request lifecycles.
for page_name, source, byte_limit in (
    ("Operations", operations, 12_000),
    ("Connections", connections, 20_000),
):
    size = len(source.encode("utf-8"))
    if size > byte_limit:
        errors.append(f"{page_name} page shell is {size} bytes; expected <= {byte_limit} after ownership split")
    if "controlTransport" in source:
        errors.append(f"{page_name} page shell must not call controlTransport directly")
    if count(source, r"\buseState\s*\(") > 0:
        errors.append(f"{page_name} page shell must not own mutable request/workflow state")
    if count(source, r"\buseEffect\s*\(") > 0:
        errors.append(f"{page_name} page shell must not own request lifecycle effects")

for required_import in (
    "DiagnosticsOperations",
    "RecoveryOperations",
    "DeploymentOperations",
):
    if required_import not in operations:
        errors.append(f"Operations page does not compose {required_import}")

for required_import in (
    "useConnectionsFeed",
    "useFlowMutations",
    "FlowTable",
):
    if required_import not in connections:
        errors.append(f"Connections page does not compose {required_import}")

# Feature owners carry bounded state rather than recreating a 100+ state page.
for owner_name, source, state_limit in (
    ("DiagnosticsOperations", diagnostics, 20),
    ("RecoveryOperations", recovery, 10),
    ("DeploymentOperations", deployment, 40),
):
    states = count(source, r"\buseState(?:<[^;\n]+>)?\s*\(")
    if states > state_limit:
        errors.append(f"{owner_name} owns {states} useState calls; expected <= {state_limit}")

# Polling ownership must remain cancellation-aware and single-flight.
if "AbortController" not in diagnostics or "setTimeout" not in diagnostics or "setInterval" in diagnostics:
    errors.append("DiagnosticsOperations polling must use cancellation-aware serialized scheduling")
if "AbortController" not in connections_feed or "setInterval" in connections_feed:
    errors.append("Connections feed must remain cancellation-aware and avoid overlapping interval polling")
if "controlTransport" not in flow_mutations:
    errors.append("flow mutation ownership unexpectedly left useFlowMutations")

print(
    "control-ui-feature-ownership "
    f"operations_bytes={len(operations.encode('utf-8'))} "
    f"connections_bytes={len(connections.encode('utf-8'))} "
    f"errors={len(errors)}"
)
for message in errors:
    print(f"ERROR: {message}")
raise SystemExit(1 if errors else 0)
