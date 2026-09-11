#!/usr/bin/env python3
"""Resolve LumiCore's Cargo-owned static-link contract for host CGO builds."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

MARKER = "native-static-libs:"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(value: str) -> str:
    """Remove terminal control sequences from Cargo diagnostics before parsing.

    `cargo rustc --print native-static-libs` writes its note to stderr and may
    decorate it even when stdout is captured. Control bytes must never become
    part of CGO_LDFLAGS: cgo treats the decorated token as a different library
    name (for example `-lkernel32<ESC>[0m`).
    """
    return ANSI_ESCAPE_RE.sub("", value)


def parse_native_static_libs(output: str) -> list[str]:
    matches: list[list[str]] = []
    for raw_line in output.splitlines():
        line = strip_ansi(raw_line)
        if MARKER not in line:
            continue
        payload = line.split(MARKER, 1)[1].strip()
        if payload:
            matches.append(shlex.split(payload))
    if not matches:
        raise ValueError("Cargo output did not contain native-static-libs")
    return matches[-1]


def select_static_library(
    target_directory: Path, profile: str, target: str | None = None
) -> Path:
    profile_dir = Path(target_directory)
    if target:
        profile_dir /= target
    profile_dir /= profile
    candidates = [profile_dir / "liblumicore.a", profile_dir / "lumicore.lib"]
    existing = [candidate.resolve() for candidate in candidates if candidate.is_file()]
    if len(existing) != 1:
        rendered = ", ".join(str(path) for path in candidates)
        raise FileNotFoundError(
            f"expected exactly one lumicore static library after Cargo build; checked: {rendered}"
        )
    return existing[0]


def cargo_target_directory(cargo: str, manifest: Path) -> Path:
    result = subprocess.run(
        [
            cargo,
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(result.stdout)
    return Path(metadata["target_directory"])


def resolve_link_flags(
    cargo: str, manifest: Path, profile: str, target: str | None = None
) -> str:
    if profile not in {"debug", "release"}:
        raise ValueError(f"unsupported profile: {profile}")
    command = [
        cargo,
        "rustc",
        "--locked",
        "--manifest-path",
        str(manifest),
        "--lib",
    ]
    if profile == "release":
        command.append("--release")
    if target:
        command.extend(["--target", target])
    command.extend(["--", "--print", "native-static-libs"])
    result = subprocess.run(command, capture_output=True, text=True)
    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    if result.returncode != 0:
        if combined:
            print(combined, file=sys.stderr)
        raise subprocess.CalledProcessError(result.returncode, command)
    native_flags = parse_native_static_libs(combined)
    target_directory = cargo_target_directory(cargo, manifest)
    archive = select_static_library(target_directory, profile, target)
    if any(char.isspace() for char in str(archive)):
        raise ValueError(
            "LumiCore static-library path contains whitespace; CGO_LDFLAGS cannot represent it safely"
        )
    # Go's cgo flag validator (go1.26+) rejects bare absolute library paths in
    # CGO_LDFLAGS; the linker-equivalent -L/-l: form carries the same contract.
    link_dir = archive.parent.as_posix()
    return " ".join(
        [f"-L{link_dir}", f"-l:{archive.name}", *translate_native_flags(native_flags, target_directory)]
    )


def _find_import_library(name: str, target_directory: Path) -> Path | None:
    """Locate a crate-shipped import/archive library for a native -l token.

    Sources searched: the cargo target directory and local registry checkouts
    of windows_x86_64_{gnu,gnullvm,msvc} and winapi-x86_64-pc-windows-gnu
    crates. GNU crates ship lib<name>.a archives, MSVC crates ship <name>.lib
    import libraries; MinGW ld accepts both.
    """
    shapes = [name, f"lib{name}.a", f"{name}.lib"]
    candidates = []
    for shape in shapes:
        candidates.extend(
            [
                target_directory / shape,
                *target_directory.glob(f"deps/{shape}"),
                *target_directory.glob(f"build/*/out/{shape}"),
                *target_directory.glob(f"x86_64-pc-windows-gnu/debug/{shape}"),
                *target_directory.glob(f"x86_64-pc-windows-gnu/debug/deps/{shape}"),
            ]
        )
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    registry = cargo_home / "registry"
    if registry.is_dir():
        crate_patterns = (
            f"src/*/windows_x86_64_gnu-*/lib/lib{name}.a",
            f"src/*/windows_x86_64_gnullvm-*/lib/lib{name}.a",
            f"src/*/windows_x86_64_msvc-*/lib/{name}.lib",
            f"src/*/winapi-x86_64-pc-windows-gnu-*/lib/lib{name}.a",
        )
        for crate_pattern in crate_patterns:
            candidates.extend(registry.glob(crate_pattern))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def translate_native_flags(flags: list[str], target_directory: Path) -> list[str]:
    """Convert Cargo's native-static-libs into tokens GNU ld can resolve."""
    out: list[str] = []
    seen_dirs: set[str] = set()
    # Shims that only exist in the Windows SDK / MSVC; mingw-w64 provides the
    # equivalent CRT compatibility symbols through msvcrt itself.
    msvc_only = {"legacy_stdio_definitions"}
    for flag in flags:
        if flag.startswith("/defaultlib:") or flag.startswith("-defaultlib:"):
            continue  # MSVC runtime directive; mingw links msvcrt by default
        name = flag[2:] if flag.startswith("-l") else flag.removesuffix(".lib")
        if not name or flag == name and not flag.endswith(".lib") and not flag.startswith("-l"):
            out.append(flag)
            continue
        if name in msvc_only:
            print(f"lumicore link: skipping MSVC-only import library {flag}", file=sys.stderr)
            continue
        archive = _find_import_library(name, target_directory)
        if archive is not None:
            lib_dir = archive.parent.as_posix()
            if lib_dir not in seen_dirs:
                out.append(f"-L{lib_dir}")
                seen_dirs.add(lib_dir)
            out.append(f"-l:{archive.name}")
            continue
        # Nothing locatable on this machine; hand ld a plain -l so its own
        # search paths (mingw system archives) still get a chance.
        out.append(f"-l{name}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "src/packages/lumicore/Cargo.toml",
    )
    parser.add_argument("--profile", choices=("debug", "release"), default="release")
    parser.add_argument("--target")
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    try:
        print(resolve_link_flags(args.cargo, args.manifest.resolve(), args.profile, args.target))
    except (ValueError, FileNotFoundError, subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
        print(f"lumicore link resolution failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
