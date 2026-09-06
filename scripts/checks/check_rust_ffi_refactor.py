#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FFI = ROOT / "src/packages/lumicore/src/ffi"
BASELINE = ROOT / "governance/audit/rust-ffi-abi-before.json"


def normalize_ws(value: str | None) -> str:
    return " ".join((value or "").split())


def normalize_ret(value: str | None) -> str:
    value = normalize_ws(value)
    return value or "()"


def current_abi() -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    pattern = re.compile(
        r'#\[no_mangle\]\s*(?:///[^\n]*\n|\s)*pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+'
        r'(\w+)\s*\((.*?)\)\s*(?:->\s*([^\{]+))?\s*\{',
        re.S,
    )
    for path in sorted(FFI.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            records.append(
                (match.group(1), normalize_ws(match.group(2)), normalize_ret(match.group(3)))
            )
    return sorted(records)


def baseline_abi() -> list[tuple[str, str, str]]:
    rows = json.loads(BASELINE.read_text(encoding="utf-8"))
    return sorted(
        (row["name"], normalize_ws(row.get("args")), normalize_ret(row.get("ret")))
        for row in rows
    )


def unsafe_exports_missing_safety(text: str) -> list[str]:
    lines = text.splitlines()
    missing: list[str] = []
    for index, line in enumerate(lines):
        match = re.search(r'pub unsafe extern "C" fn\s+(\w+)', line)
        if not match:
            continue
        preamble = "\n".join(lines[max(0, index - 14) : index])
        if "# Safety" not in preamble:
            missing.append(match.group(1))
    return missing


def main() -> int:
    errors: list[str] = []
    before = baseline_abi()
    after = current_abi()
    if before != after:
        errors.append("legacy/native C ABI changed relative to frozen refactor baseline")
        old_only = [row for row in before if row not in after]
        new_only = [row for row in after if row not in before]
        if old_only:
            errors.append(f"ABI removed/changed: {old_only[:8]}")
        if new_only:
            errors.append(f"ABI added/changed: {new_only[:8]}")

    all_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(FFI.rglob("*.rs"))
    )
    exports = (FFI / "exports.rs").read_text(encoding="utf-8")
    async_exports = (FFI / "async_exports.rs").read_text(encoding="utf-8")
    bridge = (FFI / "json_bridge.rs").read_text(encoding="utf-8")

    if "c_str_to_str" in all_text:
        errors.append("arbitrary-borrow legacy c_str_to_str helper remains")
    if re.search(r"fn\s+\w+<'a>\([^)]*\*const[^)]*\)[^{]*->\s*&'a", all_text):
        errors.append("raw pointer helper still fabricates caller-selected lifetime")
    if "clippy::missing_safety_doc" in exports:
        errors.append("exports.rs still suppresses missing safety documentation")
    missing = unsafe_exports_missing_safety(exports)
    if missing:
        errors.append(f"unsafe legacy exports missing # Safety docs: {missing}")

    required_bridge = [
        "CStr::from_ptr(ptr)",
        "to_owned()",
        "NullPointer",
        "InvalidUtf8",
        "InvalidJson",
        "catch_unwind(AssertUnwindSafe(operation))",
    ]
    for token in required_bridge:
        if token not in bridge:
            errors.append(f"legacy JSON bridge missing invariant token: {token}")

    if exports.count("parse_json_input(input_json)") != 21:
        errors.append("typed legacy JSON exports do not all use centralized input admission")
    if exports.count("catch_json_ffi") < 22:
        errors.append("legacy pointer-returning exports do not share the panic envelope")
    if "std::panic::catch_unwind" in exports:
        errors.append("exports.rs contains bypass panic envelopes")
    if "read_c_string_owned(endpoint)" not in async_exports or "parse_json_input(input_json)" not in async_exports:
        errors.append("async legacy entry point does not copy/validate raw inputs before dispatch")

    unsafe_legacy_exports = len(re.findall(r'pub unsafe extern "C" fn', exports))
    print(
        f"rust-ffi-refactor abi_exports={len(after)} "
        f"unsafe_legacy_exports={unsafe_legacy_exports} "
        f"errors={len(errors)}"
    )
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
