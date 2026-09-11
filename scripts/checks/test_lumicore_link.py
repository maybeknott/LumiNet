#!/usr/bin/env python3
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import lumicore_link


class NativeStaticLibParserTests(unittest.TestCase):
    def test_parses_last_native_static_libs_note(self) -> None:
        output = """
   Compiling lumicore v0.1.0
note: native-static-libs: -ldl -lpthread
note: native-static-libs: -lutil -lrt -lpthread -lm -ldl -lc
    Finished release [optimized] target(s)
"""
        self.assertEqual(
            lumicore_link.parse_native_static_libs(output),
            ["-lutil", "-lrt", "-lpthread", "-lm", "-ldl", "-lc"],
        )

    def test_strips_ansi_from_native_static_libs_note(self) -> None:
        output = (
            "\x1b[1m\x1b[32mnote\x1b[0m: native-static-libs: "
            "-lws2_32 -lkernel32\x1b[0m\n"
        )
        self.assertEqual(
            lumicore_link.parse_native_static_libs(output),
            ["-lws2_32", "-lkernel32"],
        )

    def test_rejects_missing_native_static_libs_note(self) -> None:
        with self.assertRaisesRegex(ValueError, "native-static-libs"):
            lumicore_link.parse_native_static_libs("Finished release")


class StaticLibrarySelectionTests(unittest.TestCase):
    def test_selects_host_release_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "release" / "liblumicore.a"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b"archive")
            self.assertEqual(
                lumicore_link.select_static_library(root, "release"), archive.resolve()
            )

    def test_selects_cross_target_windows_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "x86_64-pc-windows-gnu" / "debug" / "liblumicore.a"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b"archive")
            self.assertEqual(
                lumicore_link.select_static_library(
                    root, "debug", "x86_64-pc-windows-gnu"
                ),
                archive.resolve(),
            )

    def test_rejects_missing_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(FileNotFoundError, "lumicore static library"):
                lumicore_link.select_static_library(Path(temp), "release")


if __name__ == "__main__":
    unittest.main()
