*   **Color Scheme:** Space Void Navy base (`#0a0e1a`), slate grey card overlays (`#0f1425`), and electric blue interactive elements (`#3b82f6`). High-status events are accented in Terminal Green (`#10b981`), while CPU and diagnostic telemetry are highlighted in Neon Cyan (`#06b6d4`) and Neon Purple (`#8b5cf6`).
*   **Typography:** The Outfit font family is used for layout titles and displays to ensure crisp readability. The JetBrains Mono font family is used for all console logs, hostnames, IP addresses, port maps, and command-line inputs.
*   **Contrast and Performance:** All visual indicators, logs, and text elements maintain a minimum contrast ratio of **4.5:1** against backgrounds. Interactive transitions utilize brief, non-shifting transforms (150ms-200ms ease) to keep the app highly responsive. Emojis are replaced by scalable vector SVGs.

---

## 6. Accessibility & Compliance

*   **Keyboard Navigation:** Visual focus outlines are mapped for all interactive elements to support keyboard-only traversal.
*   **Reduced Motion:** Respects the `prefers-reduced-motion` browser flag, turning off sliding status bars and glowing scans upon request.
*   **Local Data Privacy:** Operational telemetry, scan history, and configuration state are stored locally in SQLite. LumiNet does **not** claim application-layer encryption-at-rest for those SQLite databases; instead, their files and parent data directories are created with private filesystem permissions where the platform exposes POSIX modes. Credentials and other supported secrets are kept in the platform secret store rather than being represented as ordinary operational database fields.