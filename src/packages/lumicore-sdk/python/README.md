# LumiNet Core Python SDK

Python bindings for the LumiNet native evasion and diagnostic engine
(`lumicore`). The SDK exposes a `LumiCore` client for port scanning, SNI
blocking detection, and TLS probing, plus an `EvasionSocket` transport with
user-space TCP desync support.

## Loading the native library

`LumiCore` loads `lumicore.dll` (Windows), `liblumicore.dylib` (macOS), or
`liblumicore.so` (Linux) from an explicit path, the package directory, or the
monorepo `src/packages/lumicore/target/{release,debug}` build output. When the
native library is unavailable, the SDK degrades to documented pure-Python
fallbacks (`scan_ports` uses plain sockets, `detect_sni` reports a simulated
result) so integrations keep working without a compiled core.

## Usage

```python
from luminet import LumiCore

core = LumiCore()                 # or LumiCore("/path/to/liblumicore.so")
if core.is_available:
    print(core.version())
print(core.scan_ports("127.0.0.1", [80, 443], timeout_ms=500))
```

## Tests

```bash
cd src/packages/lumicore-sdk/python
PYTHONPATH=. python3 -m unittest discover -s tests
```
