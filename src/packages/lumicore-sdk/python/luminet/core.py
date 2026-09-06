"""
LumiNet Core SDK Python Bindings

Provides direct access to lumicore DPI evasion, scanning, and transport layers via ctypes.
"""

import ctypes
import json
import os
import platform
import socket
import time
from typing import Any, Dict, List, Optional


class LumicoreError(Exception):
    """Raised when an operation in the native lumicore runtime fails."""
    pass


class LumiCore:
    """High-level client wrapping the native lumicore runtime."""

    def __init__(self, lib_path: Optional[str] = None):
        self._lib = self._load_library(lib_path)
        self._setup_function_signatures()

    def _load_library(self, lib_path: Optional[str]) -> Optional[ctypes.CDLL]:
        if lib_path and os.path.exists(lib_path):
            return ctypes.CDLL(lib_path)

        # Search default locations
        system = platform.system()
        lib_name = "lumicore.dll" if system == "Windows" else ("liblumicore.dylib" if system == "Darwin" else "liblumicore.so")

        candidate_dirs = [
            os.path.dirname(os.path.abspath(__file__)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "lumicore", "target", "release")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "lumicore", "target", "debug")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "target", "release")),
        ]

        for directory in candidate_dirs:
            p = os.path.join(directory, lib_name)
            if os.path.exists(p):
                try:
                    return ctypes.CDLL(p)
                except Exception:
                    pass

        return None

    def _setup_function_signatures(self):
        if not self._lib:
            return

        # free_string(char* ptr)
        if hasattr(self._lib, "free_string"):
            self._lib.free_string.argtypes = [ctypes.c_char_p]
            self._lib.free_string.restype = None

        # scan_ports_ffi(char* json) -> char*
        if hasattr(self._lib, "scan_ports_ffi"):
            self._lib.scan_ports_ffi.argtypes = [ctypes.c_char_p]
            self._lib.scan_ports_ffi.restype = ctypes.c_char_p

        # detect_sni_ffi(char* json) -> char*
        if hasattr(self._lib, "detect_sni_ffi"):
            self._lib.detect_sni_ffi.argtypes = [ctypes.c_char_p]
            self._lib.detect_sni_ffi.restype = ctypes.c_char_p

        # probe_tls_ffi(char* json) -> char*
        if hasattr(self._lib, "probe_tls_ffi"):
            self._lib.probe_tls_ffi.argtypes = [ctypes.c_char_p]
            self._lib.probe_tls_ffi.restype = ctypes.c_char_p

        # lumicore_version(uint16_t min_major) -> uint64_t
        if hasattr(self._lib, "lumicore_version"):
            self._lib.lumicore_version.argtypes = [ctypes.c_uint16]
            self._lib.lumicore_version.restype = ctypes.c_uint64

    @property
    def is_available(self) -> bool:
        """Returns True if the native library is loaded and operational."""
        return self._lib is not None

    def version(self) -> int:
        """Returns the runtime ABI version."""
        if not self._lib:
            return 3  # Fallback ABI version
        return int(self._lib.lumicore_version(0))

    def scan_ports(self, target: str, ports: List[int], timeout_ms: int = 3000) -> List[Dict[str, Any]]:
        """Scans specified TCP ports on target."""
        if not self._lib:
            return self._fallback_scan_ports(target, ports, timeout_ms)

        payload = json.dumps({"target": target, "ports": ports, "config": {"timeout": timeout_ms}})
        res_ptr = self._lib.scan_ports_ffi(payload.encode("utf-8"))
        if not res_ptr:
            raise LumicoreError("Native scan_ports_ffi returned null pointer")

        res_str = ctypes.string_at(res_ptr).decode("utf-8")
        self._lib.free_string(res_ptr)
        return json.loads(res_str)

    def detect_sni(self, domain: str, timeout_ms: int = 3000) -> Dict[str, Any]:
        """Probes for SNI-based middlebox blocking against domain."""
        if not self._lib:
            return {"domain": domain, "blocked": False, "simulated": True}

        payload = json.dumps({"domain": domain, "timeout_ms": timeout_ms})
        res_ptr = self._lib.detect_sni_ffi(payload.encode("utf-8"))
        if not res_ptr:
            raise LumicoreError("Native detect_sni_ffi returned null pointer")

        res_str = ctypes.string_at(res_ptr).decode("utf-8")
        self._lib.free_string(res_ptr)
        return json.loads(res_str)

    def _fallback_scan_ports(self, target: str, ports: List[int], timeout_ms: int) -> List[Dict[str, Any]]:
        """Pure-Python fallback when native core is not compiled."""
        results = []
        timeout_sec = timeout_ms / 1000.0
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_sec)
            start = time.time()
            try:
                s.connect((target, p))
                latency = (time.time() - start) * 1000.0
                results.append({"port": p, "open": True, "latency_ms": latency})
            except Exception as e:
                results.append({"port": p, "open": False, "error": str(e)})
            finally:
                s.close()
        return results


class EvasionSocket:
    """TCP socket implementing user-space TCP desync and SNI fragmentation."""

    def __init__(self, desync_offset: int = 2, desync_delay_ms: int = 30):
        self.desync_offset = desync_offset
        self.desync_delay_ms = desync_delay_ms
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, address: tuple):
        self._sock.connect(address)

    def send_evasive(self, data: bytes) -> int:
        """Sends data by splitting at desync_offset and delaying second chunk."""
        if len(data) <= self.desync_offset:
            return self._send_all(data)

        chunk1 = data[:self.desync_offset]
        chunk2 = data[self.desync_offset:]

        sent1 = self._send_all(chunk1)
        if self.desync_delay_ms > 0:
            time.sleep(self.desync_delay_ms / 1000.0)
        sent2 = self._send_all(chunk2)
        return sent1 + sent2

    def _send_all(self, data: bytes) -> int:
        """Sends data until it is fully written; returns total bytes sent.

        socket.send() may accept fewer bytes than requested, which would
        silently truncate a chunk. Loop until the buffer drains so evasive
        writes are byte-complete.
        """
        total = 0
        view = memoryview(data)
        while total < len(data):
            sent = self._sock.send(view[total:])
            if sent <= 0:
                break
            total += sent
        return total

    def recv(self, bufsize: int) -> bytes:
        return self._sock.recv(bufsize)

    def close(self):
        self._sock.close()
