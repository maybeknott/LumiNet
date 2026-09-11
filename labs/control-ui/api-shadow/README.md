# Control UI API shadow corpus

This directory preserves 211 TypeScript API modules that were present under the canonical Control UI `src/api` tree but are not reachable from the production entrypoint (`src/main.tsx`).

They are retained only as non-authoritative reference material. Production code must not import from `labs/`, and these files must not be counted as live product capability or API surface.
