#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance/convergence"
EXPECTED = {
    "donors": 8,
    "directories": 341,
    "surfaces": 2979,
    "modules": 109,
    "symbols": 7351,
    "high_signal": 2094,
    "semantic_rechecks": 110,
    "ledger": 10,
    "repairs": 4,
    "baseline": 2393,
    "supersession": 11,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VALID_STATUS = {"verified", "statically-validated", "reviewed", "inferred", "unverified", "pending"}
VALID_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only",
}
IMPLEMENTED = {"adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized", "inspired-native", "guardrail-derived", "superseded"}
DELTA_REL = "governance/convergence/fourth-order-target-delta.csv"
SUCCESSOR_BASELINE = G / "fifth-order-baseline-files.csv"


def read_csv(name: str) -> list[dict[str, str]]:
    p = G / name
    if not p.is_file():
        raise AssertionError(f"missing {name}")
    with p.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def digest_path(p: Path) -> tuple[str, str, str]:
    if p.is_symlink():
        target = os.readlink(p)
        return "symlink", hashlib.sha256(target.encode()).hexdigest(), target
    return "file", hashlib.sha256(p.read_bytes()).hexdigest(), "n/a"


def scan_current() -> dict[str, tuple[str, str, str]]:
    # Once fifth-order exists, validate the delivered fourth-order state against
    # its frozen successor baseline so richer later features cannot rewrite the
    # fourth-order receipt.
    if SUCCESSOR_BASELINE.is_file():
        out: dict[str, tuple[str, str, str]] = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                out[rel] = (row["file_type"].strip(), row["sha256"].strip(), row["link_target"])
        return out
    out: dict[str, tuple[str, str, str]] = {}
    for p in sorted(ROOT.rglob("*")):
        if not (p.is_file() or p.is_symlink()):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/"):
            continue
        out[rel] = digest_path(p)
    return out


def anchor_exists(node: str) -> bool:
    node = node.strip()
    if not node or node == "n/a":
        return True
    if "#" not in node:
        return False
    path_text, anchor = node.split("#", 1)
    path = ROOT / path_text
    if not path.is_file():
        return False
    raw = path.read_text(encoding="utf-8", errors="replace")
    candidates = {anchor, anchor.split(".")[-1], anchor.replace("-", " "), anchor.replace("-", "_")}
    return any(c and re.search(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"(?![A-Za-z0-9_])", raw, re.I) for c in candidates)


def main() -> int:
    errors: list[str] = []
    try:
        peer_donors = read_csv("peer-donors.csv")
        peer_dirs = read_csv("peer-directories.csv")
        peer_surfaces = read_csv("peer-surfaces.csv")
        peer_modules = read_csv("peer-modules.csv")
        peer_symbols = read_csv("peer-symbols.csv")
        peer_ledger = read_csv("peer-adoption-ledger.csv")
        donor_review = read_csv("fourth-order-donor-review.csv")
        dir_review = read_csv("fourth-order-directory-review.csv")
        surface_review = read_csv("fourth-order-surface-review.csv")
        module_review = read_csv("fourth-order-module-review.csv")
        symbol_review = read_csv("fourth-order-symbol-review.csv")
        sem_review = read_csv("fourth-order-semantic-reversal.csv")
        ledger = read_csv("fourth-order-adoption-ledger.csv")
        repairs = read_csv("fourth-order-target-repairs.csv")
        baseline_rows = read_csv("fourth-order-baseline-files.csv")
        supersession = read_csv("fourth-order-supersession-map.csv")
        delta_rows = read_csv("fourth-order-target-delta.csv")
    except AssertionError as exc:
        print(f"fourth-order convergence: FAIL: {exc}", file=sys.stderr)
        return 1

    counts = {
        "donors": len(donor_review), "directories": len(dir_review), "surfaces": len(surface_review),
        "modules": len(module_review), "symbols": len(symbol_review),
        "high_signal": sum(r.get("high_signal") == "yes" for r in symbol_review),
        "semantic_rechecks": len(sem_review), "ledger": len(ledger), "repairs": len(repairs),
        "baseline": len(baseline_rows), "supersession": len(supersession),
    }
    for key, want in EXPECTED.items():
        if counts.get(key) != want:
            errors.append(f"{key} count {counts.get(key)} != {want}")

    # Donor identities/counts are inherited only from the prior byte-verified snapshot.
    pd = {r["donor"]: r for r in peer_donors}
    dr = {r["donor"]: r for r in donor_review}
    if len(pd) != EXPECTED["donors"] or set(pd) != set(dr):
        errors.append("donor review set disagrees with immutable peer donor set")
    donor_identity_fields = ["archive_path", "archive_sha256", "archive_members", "directories", "surfaces", "symbols", "modules", "safe_symlinks", "surface_hash"]
    for donor, src in pd.items():
        row = dr[donor]
        for field in donor_identity_fields:
            if row.get(field) != src.get(field):
                errors.append(f"{donor}: fourth-order donor identity drift in {field}")
        if row.get("raw_archive_available_this_pass") != "no":
            errors.append(f"{donor}: pass must not falsely claim original ZIP bytes were rehashed")
        if row.get("review_status") != "reviewed":
            errors.append(f"{donor}: donor not reviewed")

    # Exact historical keys for review matrices.
    pdir = {(r["donor"], r["path"]): r for r in peer_dirs}
    psurf = {(r["donor"], r["path"]): r for r in peer_surfaces}
    pmod = {(r["donor"], r["module_id"]): r for r in peer_modules}
    psym = {(r["donor"], r["path"], r["kind"], r["symbol"], r["line"]): r for r in peer_symbols}
    if len(pdir) != len(peer_dirs) or len(psurf) != len(peer_surfaces) or len(pmod) != len(peer_modules) or len(psym) != len(peer_symbols):
        errors.append("duplicate historical evidence key")

    dkeys = {(r["donor"], r["path"]): r for r in dir_review}
    if set(dkeys) != set(pdir):
        errors.append(f"directory review coverage mismatch missing={len(set(pdir)-set(dkeys))} extra={len(set(dkeys)-set(pdir))}")
    for key, r in dkeys.items():
        src = pdir[key]
        for field in ["depth", "direct_file_count", "direct_child_dir_count", "recursive_file_count", "recursive_bytes"]:
            if r.get(field) != src.get(field):
                errors.append(f"directory {key}: historical field drift {field}")
        try:
            prefix = "" if r["path"] == "." else r["path"].rstrip("/") + "/"
            expected_surface_count = sum(
                sr["donor"] == r["donor"] and (r["path"] == "." or sr["path"] == r["path"] or sr["path"].startswith(prefix))
                for sr in peer_surfaces
            )
            if int(r["reviewed_surface_count"]) != expected_surface_count:
                errors.append(f"directory {key}: reviewed surface count mismatch {r['reviewed_surface_count']} != {expected_surface_count}")
        except ValueError:
            errors.append(f"directory {key}: invalid reviewed surface count")
        if r.get("current_resolution") != "fully-accounted-fourth-order" or r.get("review_status") != "reviewed" or not r.get("review_rationale", "").strip():
            errors.append(f"directory {key}: incomplete fourth-order review")

    skeys = {(r["donor"], r["path"]): r for r in surface_review}
    if set(skeys) != set(psurf):
        errors.append(f"surface review coverage mismatch missing={len(set(psurf)-set(skeys))} extra={len(set(skeys)-set(psurf))}")
    for key, r in skeys.items():
        src = psurf[key]
        for field in ["sha256", "size_bytes", "file_type", "language", "classification", "module_id"]:
            if r.get(field) != src.get(field):
                errors.append(f"surface {key}: historical field drift {field}")
        if not HEX64.fullmatch(r.get("sha256", "")):
            errors.append(f"surface {key}: invalid historical hash")
        if r.get("review_status") != "reviewed" or not r.get("current_resolution", "").strip() or not r.get("review_rationale", "").strip():
            errors.append(f"surface {key}: incomplete review")

    mkeys = {(r["donor"], r["module_id"]): r for r in module_review}
    if set(mkeys) != set(pmod):
        errors.append(f"module review coverage mismatch missing={len(set(pmod)-set(mkeys))} extra={len(set(mkeys)-set(pmod))}")
    for key, r in mkeys.items():
        src = pmod[key]
        for field in ["module_role", "file_count", "bytes", "semantic_record_ids"]:
            if r.get(field) != src.get(field):
                errors.append(f"module {key}: historical field drift {field}")
        if r.get("review_status") != "reviewed" or not r.get("current_module_disposition", "").strip() or not r.get("review_rationale", "").strip():
            errors.append(f"module {key}: incomplete review")

    symkeys = {(r["donor"], r["path"], r["kind"], r["symbol"], r["line"]): r for r in symbol_review}
    if set(symkeys) != set(psym):
        errors.append(f"symbol review coverage mismatch missing={len(set(psym)-set(symkeys))} extra={len(set(symkeys)-set(psym))}")
    for key, r in symkeys.items():
        src = psym[key]
        for field in ["language", "visibility", "module_id", "high_signal", "high_signal_keywords"]:
            if r.get(field) != src.get(field):
                errors.append(f"symbol {key}: historical field drift {field}")
        if r.get("current_resolution") != "resolved-fourth-order" or r.get("review_status") != "reviewed" or not r.get("review_rationale", "").strip():
            errors.append(f"symbol {key}: incomplete review")
        if r.get("high_signal") == "yes" and r.get("review_depth") != "semantic":
            errors.append(f"high-signal symbol not semantically reviewed: {key}")

    peer_sem = {r["record_id"]: r for r in peer_ledger if r["record_id"].startswith("SEM")}
    semrows = {r["source_record_id"]: r for r in sem_review}
    if set(semrows) != set(peer_sem):
        errors.append(f"semantic recheck coverage mismatch missing={sorted(set(peer_sem)-set(semrows))[:10]} extra={sorted(set(semrows)-set(peer_sem))[:10]}")
    for rid, r in semrows.items():
        src = peer_sem[rid]
        for field in ["donor", "domain", "value_unit", "donor_path", "donor_sha256", "donor_symbol"]:
            if r.get(field) != src.get(field):
                errors.append(f"{rid}: historical semantic field drift {field}")
        if r.get("prior_disposition") != src.get("disposition"):
            errors.append(f"{rid}: prior disposition drift")
        if r.get("current_disposition") not in VALID_DISPOSITIONS or r.get("validation_status") not in VALID_STATUS:
            errors.append(f"{rid}: invalid current disposition/status")
        if not r.get("review_result", "").strip() or not r.get("review_rationale", "").strip():
            errors.append(f"{rid}: incomplete recheck")
        for node in [x for x in r.get("target_evidence", "").split(";") if x and x != "n/a"]:
            if not anchor_exists(node):
                errors.append(f"{rid}: target evidence missing {node}")

    # Successor/new adoption ledger.
    records = {r["record_id"]: r for r in ledger}
    if len(records) != len(ledger):
        errors.append("duplicate fourth-order adoption record")
    validation = (G / "fourth-order-validation.md").read_text(encoding="utf-8") if (G / "fourth-order-validation.md").is_file() else ""
    for rid, r in records.items():
        if r.get("disposition") not in VALID_DISPOSITIONS or r.get("validation_status") not in VALID_STATUS:
            errors.append(f"{rid}: invalid disposition/status")
        src = psurf.get((r["donor"], r["donor_path"]))
        if src is None or src.get("sha256") != r.get("donor_sha256"):
            errors.append(f"{rid}: donor path/hash not pinned to historical surface")
        for source_id in [x for x in r.get("source_peer_record_ids", "").split(";") if x and x != "n/a"]:
            if source_id not in peer_sem:
                errors.append(f"{rid}: unknown source peer semantic {source_id}")
        for dep in [x for x in r.get("dependency_record_ids", "").split(";") if x and x != "n/a"]:
            if dep not in records:
                errors.append(f"{rid}: unknown fourth-order dependency {dep}")
        if f"### {rid.lower()}" not in validation:
            errors.append(f"{rid}: missing fourth-order validation heading")
        if r.get("disposition") in IMPLEMENTED:
            if r.get("target_nodes") == "n/a" or r.get("test_node") == "n/a":
                errors.append(f"{rid}: live/superseding record missing target/test evidence")
            for node in r.get("target_nodes", "").split(";"):
                if not anchor_exists(node):
                    errors.append(f"{rid}: target node missing {node}")
            if not anchor_exists(r.get("test_node", "")):
                errors.append(f"{rid}: test node missing {r.get('test_node')}")
            if r.get("invariant") == "n/a" or r.get("negative_invariant") == "n/a":
                errors.append(f"{rid}: missing invariants")

    # Repair/accountability records.
    repair_ids = set()
    for r in repairs:
        rid = r.get("repair_id", "").strip()
        if not rid or rid in repair_ids:
            errors.append(f"duplicate/empty repair {rid!r}")
        repair_ids.add(rid)
        if r.get("status") not in VALID_STATUS or not (ROOT / r.get("path", "")).is_file() or not anchor_exists(r.get("evidence", "")):
            errors.append(f"{rid}: incomplete repair evidence")

    # Supersession map: every comparison has a concrete current evidence anchor.
    gids = set()
    for r in supersession:
        gid = r.get("group_id", "").strip()
        if not gid or gid in gids:
            errors.append(f"duplicate/empty supersession group {gid!r}")
        gids.add(gid)
        if not all(r.get(k, "").strip() for k in ["peer_units", "winning_target_owner", "decision", "why_it_wins", "negative_boundary"]):
            errors.append(f"{gid}: incomplete supersession rationale")
        if not anchor_exists(r.get("evidence", "")):
            errors.append(f"{gid}: evidence anchor missing {r.get('evidence')}")

    # Immutable baseline rows are unique and well formed.
    baseline: dict[str, tuple[str, str, str]] = {}
    for r in baseline_rows:
        path = r.get("path", "").strip()
        if not path or path in baseline:
            errors.append(f"duplicate/empty fourth baseline path {path!r}")
            continue
        if r.get("file_type") not in {"file", "symlink"} or not HEX64.fullmatch(r.get("sha256", "")):
            errors.append(f"fourth baseline {path}: invalid row")
        baseline[path] = (r["file_type"], r["sha256"], r["link_target"])

    # Exact current delta from frozen third-wave baseline, excluding the self-referential delta itself.
    current = scan_current()
    expected: dict[str, tuple[str, str, str]] = {}
    for path in sorted(set(baseline) | set(current)):
        before, after = baseline.get(path), current.get(path)
        if before == after:
            continue
        if before is None:
            expected[path] = ("added", "n/a", after[1])
        elif after is None:
            expected[path] = ("deleted", before[1], "n/a")
        else:
            expected[path] = ("modified", before[1], after[1])
    delta = {}
    for r in delta_rows:
        path = r.get("path", "").strip()
        if not path or path in delta:
            errors.append(f"duplicate/empty fourth delta path {path!r}")
            continue
        delta[path] = r
        exp = expected.get(path)
        if exp is None:
            errors.append(f"fourth delta {path}: not changed from frozen third-wave baseline")
            continue
        got = (r.get("change_type"), r.get("third_wave_sha256"), r.get("current_sha256"))
        if got != exp:
            errors.append(f"fourth delta {path}: change/hash mismatch got={got} expected={exp}")
        for rid in [x for x in r.get("fourth_order_record_ids", "").split(";") if x and x != "n/a"]:
            if rid not in records and rid not in repair_ids:
                errors.append(f"fourth delta {path}: unknown accountability id {rid}")
        if not r.get("accountability_class", "").strip() or not r.get("reason", "").strip() or not r.get("verification_node", "").strip():
            errors.append(f"fourth delta {path}: incomplete accountability")
        if r.get("verification_node") != "n/a" and not anchor_exists(r.get("verification_node", "")):
            errors.append(f"fourth delta {path}: verification anchor missing {r.get('verification_node')}")
    missing = sorted(set(expected) - set(delta))
    extra = sorted(set(delta) - set(expected))
    if missing:
        errors.append(f"fourth target delta missing {len(missing)} paths: {missing[:20]}")
    if extra:
        errors.append(f"fourth target delta has {len(extra)} extra paths: {extra[:20]}")

    # Static authority invariants for new higher-level planes.
    update_core = (ROOT / "src/apps/daemon/internal/foundation/updateadmission/updateadmission.go").read_text(encoding="utf-8")
    update_api = (ROOT / "src/apps/daemon/internal/adapters/api/handlers_update_admission.go").read_text(encoding="utf-8")
    if "ApplyAuthorized: false" not in update_core or "ed25519.Verify" not in update_core:
        errors.append("update admission no longer proves signature + non-authoritative plan")
    if "buildinfo.Version" not in update_api or "current_version" in update_api:
        errors.append("update admission API is not bound exclusively to daemon build identity")
    if "http.MaxBytesReader" not in update_api or "DisallowUnknownFields" not in update_api:
        errors.append("update admission outer request is not bounded/strict")
    if re.search(r"http\.Get|client\.Do|os\.Rename|os\.WriteFile|exec\.Command", update_core):
        errors.append("update admission acquired download/install/execution authority")

    host = (ROOT / "src/apps/daemon/internal/platform/system/host_network.go").read_text(encoding="utf-8")
    plan_block = host[host.find("func (m *hostNetworkManager) Plan"):host.find("func (m *hostNetworkManager) currentStateForPlan")]
    if "ApplyAuthorized:  false" not in plan_block or any(token in plan_block for token in ["writeHostRecord", ".setDNS(", ".setProxy(", ".setNCSI(", ".startTun(", ".stopTun("]):
        errors.append("host-network preview gained mutation/apply authority")

    budget = (ROOT / "src/apps/daemon/internal/foundation/resourcebudget/resourcebudget.go").read_text(encoding="utf-8")
    agg = (ROOT / "src/apps/daemon/internal/integrations/sub/aggregate.go").read_text(encoding="utf-8")
    sni = (ROOT / "src/apps/daemon/internal/analysis/diagnostics/sni_spoof_scan.go").read_text(encoding="utf-8")
    if "func (b Budget) CapWorkers" not in budget or "resourcebudget.Detect().CapWorkers" not in agg or "resourcebudget.Detect().CapWorkers" not in sni:
        errors.append("host capacity envelope not wired as target ceilings")

    profile = (ROOT / "src/apps/daemon/internal/integrations/sub/profile_service.go").read_text(encoding="utf-8")
    egress = (ROOT / "src/apps/daemon/internal/integrations/sub/egress.go").read_text(encoding="utf-8")
    subapi = (ROOT / "src/apps/daemon/internal/adapters/api/handlers_subscription_profiles.go").read_text(encoding="utf-8")
    # The mirror ceiling may be declared in a const block; require the
    # identifier with its value rather than one specific formatting.
    if re.search(r"\bmaxProfileMirrors\s*=\s*3\b", profile) is None or "LastSourceURL" not in profile or "SourceHealthByURL" not in profile:
        errors.append("bounded source mirror/last-good state missing")
    if "func ValidateProfileSourceURL" not in egress or "validateSubscriptionSources" not in subapi:
        errors.append("subscription source static admission boundary missing")

    quarantine = (ROOT / "src/apps/daemon/internal/foundation/config/quarantine.go").read_text(encoding="utf-8")
    config = (ROOT / "src/apps/daemon/internal/foundation/config/config.go").read_text(encoding="utf-8")
    if "maxCorruptConfigQuarantines = 1024" not in quarantine or "quarantineCorruptConfig" not in config:
        errors.append("config corruption quarantine is missing/unbounded")

    bounded_line = (ROOT / "src/apps/daemon/internal/foundation/boundedio/line.go").read_text(encoding="utf-8")
    if "func ReadLine" not in bounded_line or "ErrLineTooLong" not in bounded_line:
        errors.append("bounded line allocation primitive missing")
    for go_path in (ROOT / "src/apps/daemon/internal").rglob("*.go"):
        if go_path.as_posix().endswith("foundation/boundedio/line.go"):
            continue
        text = go_path.read_text(encoding="utf-8", errors="replace")
        if "ReadString('\\n')" in text:
            errors.append(f"unbounded line reader remains: {go_path.relative_to(ROOT)}")

    actions = read_csv("remote-http-actions.csv")
    if len(actions) != 29:
        errors.append(f"remote action registry count {len(actions)} != 29")
    valid_safety = {"idempotent", "reconcile-before-retry", "single-attempt", "not-applicable", "protocol-owned"}
    for r in actions:
        if r.get("safety_class") not in valid_safety:
            errors.append(f"remote action {r.get('action_id')}: invalid/unclassified safety class {r.get('safety_class')}")

    if errors:
        print(f"fourth-order convergence: errors={len(errors)}", file=sys.stderr)
        for e in errors[:160]:
            print("ERROR:", e, file=sys.stderr)
        if len(errors) > 160:
            print(f"ERROR: ... {len(errors)-160} more", file=sys.stderr)
        return 1
    print(
        "fourth-order convergence:",
        f"donors={counts['donors']} dirs={counts['directories']} surfaces={counts['surfaces']} modules={counts['modules']} symbols={counts['symbols']} high_signal={counts['high_signal']} semantic_rechecks={counts['semantic_rechecks']} records={counts['ledger']} repairs={counts['repairs']} baseline={counts['baseline']} changes={len(delta_rows)} supersession={counts['supersession']} errors=0",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
