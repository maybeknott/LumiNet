# Agent Skills & Behaviors

Adopted from locally-installed Cursor, Gemini/Antigravity, OpenAI Codex, and the GoogleChrome `modern-web-guidance` skill pack. These rules apply to all interactions in this workspace.

## Locally-Installed Skill Locations (for reference)
- **Cursor** rules/history: `C:\Users\ACER\AppData\Roaming\Cursor\User\`
- **Antigravity** config: `C:\Users\ACER\AppData\Roaming\Antigravity\User\`
- **Agy** binary: `C:\Users\ACER\AppData\Local\agy\bin\agy.exe`
- **Codex** package: `C:\Users\ACER\AppData\Local\Packages\OpenAI.Codex_*`
- **Modern Web Guidance skill** (GoogleChrome): `C:\Users\ACER\AppData\Local\Temp\skills-tWsnqC\` — `modern-web-guidance` v0.0.169 + `chrome-extensions` skill pack
- **Project AGENTS.md files**: `ConfigStream` (Python async pipeline rules), `Early-History` (HTML-first architecture, scholarly content rules)

---

## From Cursor — Agentic Workflow & Diff Discipline

- **Plan before acting.** For any multi-file or unfamiliar change, read the relevant code first, outline the approach, then implement. Never jump straight to edits on complex tasks.
- **Surgical diffs.** Present changes as focused, reviewable hunks. Avoid rewriting large blocks when a small targeted edit achieves the goal.
- **Repo-wide awareness.** Before adding a new pattern, search the codebase to see if one already exists. Match existing conventions — naming, error handling, module structure — rather than introducing new ones.
- **Verify after every change.** After editing, run the build or relevant tests. If verification fails, fix before presenting the result.
- **Modes of operation:**
  - *Ask/Plan mode* — explore and reason before touching files.
  - *Agent/Implement mode* — execute end-to-end with full tool use.
  - *Manual/Surgical mode* — targeted single-file edits when precision matters more than speed.
- **Team rules awareness.** Respect `.cursor/rules`, `.kiro/steering`, `AGENTS.md`, or any workspace-level instruction files as authoritative constraints.

---

## From Gemini / Antigravity — Artifacts, Trust, and Parallel Thinking

- **Generate verifiable artifacts.** For non-trivial tasks, produce a concrete deliverable before diving into code: a task list, an implementation plan, or a short design note. This makes intent auditable and reversible.
- **Thought continuity.** On multi-step tasks, carry forward the reasoning chain explicitly. State what was done, what comes next, and why — especially after context resets or compaction.
- **Agent-first framing.** Treat complex features as delegatable pipelines: break them into discrete subtasks (plan → implement → test → document), execute each with full context, and hand off clean artifacts between stages.
- **Multimodal awareness.** When images, screenshots, diagrams, or documents are attached, analyze them fully and incorporate their content into the response before writing any code.
- **Parallel sub-task identification.** When a task has independent parts (e.g., backend + frontend, multiple modules), identify them explicitly and handle them in parallel where possible rather than sequentially.
- **Browser/environment grounding.** When a task involves UI, APIs, or external services, ground the implementation in real observable behavior — check docs, fetch specs, or note what cannot be verified without running the code.

---

## From OpenAI Codex — Long-Horizon Coding & Safety Boundaries

- **AGENTS.md as contract.** If an `AGENTS.md` file exists in the repo, treat it as the authoritative guide for how to work in that repository — build commands, test commands, style rules, and off-limits areas.
- **Context compaction discipline.** On long sessions, periodically re-anchor by re-reading key files or recent outputs rather than relying on memory. State what was re-confirmed.
- **Reviewer mindset.** Frame the relationship as: Kiro drafts, the developer reviews. Produce clean diffs that are easy to accept or reject. Never make the developer hunt for what changed.
- **Explicit risk tiers.** Before executing any action, classify it:
  - *Low risk* (read, lint, single-file edit) → proceed immediately.
  - *Medium risk* (install deps, config changes, multi-file refactor) → proceed but narrate.
  - *High risk* (prod changes, data deletion, auth modifications, force push) → explain impact and wait for explicit confirmation.
- **Sandboxed reasoning.** Treat each task as if it runs in an isolated environment. Do not assume state from a previous session unless it has been re-confirmed in the current context.
- **Telemetry-friendly output.** Structure responses so they are auditable: clear before/after for edits, explicit command invocations, and stated assumptions. Avoid opaque "magic" changes.
- **Large refactors and migrations.** For repo-wide changes (rename, migration, dependency upgrade), produce a step-by-step plan first, execute in stages, and verify each stage before proceeding to the next.

---

## Cross-Agent Principles (Synthesized)

- **Minimal footprint.** Solve exactly what was asked. Do not add features, abstractions, or defensive code beyond the task scope unless the user asks.
- **Honest uncertainty.** If something cannot be verified without running the code or checking an external system, say so explicitly rather than presenting assumptions as facts.
- **Persistent autonomy.** Work through obstacles rather than stopping. If one approach fails twice, diagnose the root cause and try a fundamentally different track. Dropping a requirement is a last resort.
- **Security by default.** Use parameterized queries, validate inputs, handle errors explicitly, and use pinned dependency versions. Flag anything that looks like a security concern.
- **Attribution and sourcing.** When using information from web searches or external docs, cite the source inline.

---

## From GoogleChrome Modern Web Guidance Skill (v0.0.169) — Web Platform Best Practices

> Source: `C:\Users\ACER\AppData\Local\Temp\skills-tWsnqC\skills\modern-web-guidance\`
> Installed via `agy plugin install` / `npx modern-web-guidance@latest install`

**MANDATORY trigger:** Execute these rules at the START of any HTML/CSS/client-side JS task. Do NOT skip — web APIs evolve rapidly and training data contains obsolete patterns.

### When to apply
Trigger immediately for:
- UI/Layout: Modals, dialogs, popovers, backdrop-filters, anchor positioning, container queries, `:has()`, `:user-valid`
- Scroll/Motion: View Transitions, Scroll-driven animations, parallax/reveals
- Performance: CWV (LCP, INP), `content-visibility`, Fetch Priority, image optimization
- System/APIs: Local filesystem, WebUSB, WebSockets, WebAssembly
- Frameworks: Adapting layout/styles in React, Vue, Angular
- General Frontend: Forms, autofill, advanced inputs, custom scrollbars, modern component states

Do NOT trigger for: Backend SQL/ORMs, CI/CD pipelines, Docker, local scripts (Python/Go), ESLint, Git.

### Core Web Rules (adopted)

**Accessibility**
- All content in landmarks (`<header>`, `<nav>`, `<main>`, `<aside>`, `<footer>`). Sequential non-skipping heading hierarchy.
- Prefer native HTML over ARIA. `<button>` over `<div role="button">`. `<label for>` over `aria-label` when visible label exists.
- Use `.visually-hidden` (clip-path: inset(50%)) not `display:none` for screen-reader-only text.
- `:focus-visible` for focus rings — never `outline: none` without a replacement.
- `aria-invalid` must be synced via JS when using `:user-invalid` CSS — they don't auto-sync.
- Use native `<dialog>.showModal()` for modals — no custom focus traps needed. Browser sets outside content as `inert`.
- `prefers-reduced-motion`: wrap all animations. `prefers-contrast: more`: reinforce low-contrast borders.

**Forms**
- `autocomplete` on every `<input>`, `<select>`, `<textarea>`. Use `current-password` for sign-in, `new-password` for sign-up.
- `type="email"` + `inputmode="email"` + `autocomplete="email"` — they control different things and reinforce each other.
- Never `type="number"` for credit cards or ZIP codes (strips leading zeros, adds spinners).
- `:user-invalid` not `:invalid` — only shows error after user interaction, not on page load.
- Place hints/rules ABOVE inputs so mobile keyboards don't obscure them.
- `field-sizing: content` for auto-sizing inputs — pair with `min-inline-size` and `max-inline-size`.

**CSS Architecture**
- `color-scheme: light dark` on `:root` + `<meta name="color-scheme" content="light dark">` in `<head>`.
- `light-dark()` for color tokens. Re-specify inherited `<color>` properties on elements with `color-scheme` overrides.
- `interpolate-size: allow-keywords` on `:root` to animate to `auto`/`max-content`. Use `calc-size()` only when math on intrinsic size is needed.
- `@starting-style` + `transition-behavior: allow-discrete` for entry/exit animations on `display` changes.
- Include `overlay` in transition list for top-layer elements (`<dialog>`, `[popover]`).
- `content-visibility: auto` + `contain-intrinsic-size` for off-screen heavy sections. Never apply above the fold.
- `@layer` for cascade management. `:where()` to zero-out specificity for defaults.
- Logical properties (`margin-inline-start`, `padding-block`) over physical ones.
- `text-wrap: balance` for headings, `text-wrap: pretty` for body text.

**Performance**
- `fetchpriority="high"` on LCP image. Never `loading="lazy"` on LCP image.
- `fetchpriority="low"` on hidden above-fold images (carousel slides, mega menus).
- `scheduler.yield()` with 50ms deadline budget for long tasks. Fallback: `setTimeout(resolve, 0)`.
- `scheduler.postTask()` for priority queuing: `user-blocking` > `user-visible` > `background`.
- `fetchLater()` for analytics/telemetry beacons — reliable even on page close. Polyfill with `visibilitychange` + `fetch({keepalive:true})`.
- Speculation Rules API (`<script type="speculationrules">`) for prefetch/prerender of next pages. Progressive enhancement — ignored by unsupported browsers.
- `scrollend` event instead of debounced `scroll` for deferred work after scroll stops.

**View Transitions**
- `@view-transition { navigation: auto }` on both pages for cross-document transitions.
- `document.startViewTransition({ update, types: ['forward'] })` for SPA directional transitions.
- `html:active-view-transition-type(forward)::view-transition-old(root)` for directional CSS.
- `blocking="render"` on critical `<script>` + `<link rel="expect" href="#id" blocking="render">` to prevent animating to incomplete page.
- Always wrap in `@media (prefers-reduced-motion: no-preference)`.

**Passkeys / WebAuthn**
- Use vetted server-side libraries (SimpleWebAuthn for JS, py_webauthn for Python).
- Call native browser APIs directly on client — no `startAuthentication()` wrappers.
- `PublicKeyCredential.parseRequestOptionsFromJSON()` + `.toJSON()` for serialization. Polyfill: `webauthn-polyfills`.
- `mediation: "conditional"` for form autofill suggestions. Abort before explicit button flow.
- `signalUnknownCredential()` when server returns 404 for a credential ID.
- AAGUID for UX hints only (provider name/icon) — never for security decisions.

**Invoker Commands (Declarative UI)**
- `commandfor="id" command="toggle-popover"` on `<button>` — no JS event listeners needed.
- Custom commands must start with `--` (e.g., `command="--my-action"`).
- Listen for `command` event directly on target element (does not bubble).
- Polyfill: `invokers-polyfill` from keithamus/invokers-polyfill.

**Temporal API**
- `Temporal.PlainDate` / `Temporal.PlainTime` for location-agnostic data (birthdates, alarms).
- `Temporal.ZonedDateTime` for global events with DST handling. `disambiguation: 'reject'` to detect conflicts.
- `Temporal.Instant` for nanosecond-precision distributed tracing.
- Polyfill: `@js-temporal/polyfill` — must manually assign `globalThis.Temporal`.

**Fallback discipline**
- Always provide a CSS fallback before `calc-size()`, `image-set()`, `field-sizing`, etc.
- Use `@supports` to gate progressive enhancements. Use `@supports not` for fallback-only blocks.
- Feature-detect JS APIs before use: `if ('scheduler' in window && 'yield' in window.scheduler)`.
- Baseline Widely Available = safe without fallback. Baseline Newly Available = check user's target. Limited = always fallback.

---

## From Chrome Extensions Skill (v0.0.169) — Manifest V3 Rules

> Source: `C:\Users\ACER\AppData\Local\Temp\skills-tWsnqC\skills\chrome-extensions\`

Apply when building or modifying Chrome extensions.

- **Always Manifest V3.** `background.service_worker` not `background.scripts`. `chrome.action` not `chrome.browserAction`. `host_permissions` separate from `permissions`.
- **Icons must exist.** Every icon path in manifest must be a real file at the correct pixel dimensions, or omit icons entirely.
- **Side panel needs an explicit open trigger.** `chrome.action.onClicked` or `chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true })` — NOT `openPanelOnActionIconClick` (causes silent TypeError).
- **No `eval()` in extension pages.** Use sandboxed iframe + `postMessage`, blob URL, or `srcdoc`. Cannot access `iframe.contentDocument` cross-origin.
- **`tab.url` requires `"tabs"` permission.** Without it, returns `undefined` silently.
- **Always `async/await`.** No `.then()` chains. `return true` in `onMessage` listeners with async `sendResponse`.
- **Service workers are ephemeral.** Never store state in global variables — use `chrome.storage`. Use `chrome.alarms` not `setTimeout`/`setInterval`.
- **`activeTab` does NOT work from side panel button clicks.** Use `"tabs"` + `host_permissions` instead.
- **`chrome.windows` has no `.query()`.** Use `getAll`, `getLastFocused`, or `getCurrent`.
- **Offscreen documents:** only `chrome.runtime` messaging available — no `chrome.downloads`, `chrome.action`, etc.
- **State locking for capture APIs.** Use `chrome.storage.session` state machine (`idle → starting → recording → stopping → idle`) to prevent double-start errors.
- **DevTools panel paths** are relative to extension root, not the devtools page file.
- **`"action": {}` required** in manifest if using any `chrome.action.*` APIs.

---

## From ConfigStream AGENTS.md — Python Async Pipeline Rules

> Source: `C:\Users\ACER\Documents\GitHub\ConfigStream\AGENTS.md`

Apply when working on Python async/pipeline code in this workspace.

- **Python 3.10+, strict typing.** All function signatures need type hints. Check with `mypy`.
- **Never blocking I/O in async functions.** No `requests`, no `time.sleep`. Use `asyncio` for I/O, `ProcessPoolExecutor`/`ThreadPoolExecutor` for CPU-bound work.
- **Log sanitization is mandatory.** Wrap URLs/errors with sanitizer before logging. No raw tokens or passwords in logs.
- **Unbounded queues = OOM.** Always use `maxsize` on `asyncio.Queue`.
- **Never exit pipeline early on zero results.** Always generate outputs so downstream consumers don't break.
- **Singleton pattern:** use `threading.Lock` in `__new__` for thread-safe singletons.
- **Pre-submit checklist:** run `pytest`, sanitize new log statements, verify async compatibility, update docs.

---

## From Early-History AGENTS.md — Content & Architecture Rules

> Source: `C:\Users\ACER\Documents\GitHub\Early-History\AGENTS.md`

Apply when working on content-heavy or documentation projects.

- **HTML-first.** No `.md` files for content. All content in `.html` with YAML frontmatter.
- **No orphaned assets.** Every image must have a metadata entry. Prefer Public Domain / CC0 sources.
- **Plan first.** Articulate approach before touching files. Verify output after every build.
- **Clean up temp scripts.** If you generate a helper script, delete it after verifying its output.
- **Depth over breadth.** Content must explain concepts from ground up to scholarly level. Avoid "AI-marketing" fluff.
- **Evidence pyramid.** Material evidence > External sources > Tradition/secondary sources.
