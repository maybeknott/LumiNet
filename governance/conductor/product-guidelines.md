# Product Guidelines: LumiNet

## Creative North Star: "Sovereign Glass Command Cockpit"
LumiNet's visual identity represents high technical precision and resilience, optimized for power users operating under dark ambient conditions.

## Visual Design & Color System
- **Backgrounds:** Space Void Navy (`#0a0e1a`), Slate Grey Card Overlays (`#0f1425`).
- **Interactive Accents:** Electric Blue (`#3b82f6`).
- **Status Indicators:** Terminal Green (`#10b981`) for healthy/connected states, Neon Cyan (`#06b6d4`) and Neon Purple (`#8b5cf6`) for telemetry & CPU metrics.
- **Typography:**
  - **Layout & Headers:** Outfit font family for clean readability.
  - **Console & Diagnostics:** JetBrains Mono for logs, IP addresses, hostnames, and command line inputs.
- **Contrast:** Minimum 4.5:1 contrast ratio against backgrounds.
- **Animations:** Subtle 150ms-200ms ease transitions; respects `prefers-reduced-motion`.

## User Experience Principles
- **Honest Diagnostic Feedback:** Present exact, un-truncated empirical network metrics rather than masked generic error screens.
- **Local-First Data:** Store operational logs, telemetry, scan history, and configuration state locally. LumiNet does not claim application-layer encryption-at-rest for the operational SQLite databases; supported credentials and secrets belong in the platform secret store, while database files rely on private local filesystem permissions.
- **Keyboard-First Traversability:** Fully accessible visual focus outlines for keyboard navigation.
