# 🌐 Design System Reference Manual: LumiNet

This document outlines the visual identity, typography system, component specifications, and style constraints of the **LumiNet** platform.

---

## 1. Creative North Star: "Sovereign Glass Command Cockpit"

LumiNet utilizes a technical, high-precision visual design that balances functional density with immersive aesthetic polish. The environment is dark-first, reflecting the typical physical context of researchers and power users auditing hostile networks in low-light environments. Information density is kept high, avoiding excessive whitespace that slows down log auditing, but remains structured using crisp glassmorphic panels and thin high-contrast borders.

Visual anchors are driven by neon-accented telemetry indicators and responsive status updates, ensuring that every design detail serves an active information-carrying purpose.

---

## 2. Design Tokens & Styling Variables

Copy this stylesheet setup into your global CSS styles to configure custom system tokens:

```css
:root {
  /* Font Families */
  --font-display: 'Outfit', sans-serif;
  --font-body: 'Outfit', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;

  /* Space Void Navy (Default Theme) Colors */
  --bg-primary: #0a0e1a;
  --bg-secondary: #0f1425;
  --bg-tertiary: #151b2e;
  --border-color: rgba(255, 255, 255, 0.08);
  --border-hover: rgba(255, 255, 255, 0.15);
  
  /* Text Accents */
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  
  /* Neon Status Colors */
  --color-accent: #3b82f6;       /* Electric Blue */
  --color-accent-glow: rgba(59, 130, 246, 0.15);
  --color-cyan: #06b6d4;         /* Neon Cyan (CPU operations) */
  --color-purple: #8b5cf6;       /* Neon Purple (Memory / Diag) */
  --color-success: #10b981;      /* Terminal Green (Passed audits) */
  --color-warning: #f59e0b;      /* Warning Amber (Degraded status) */
  --color-error: #ef4444;        /* Critical Red (Failed status) */
  
  /* Radius Sizes */
  --rounded-sm: 0.375rem;        /* 6px */
  --rounded-md: 0.5rem;          /* 8px */
  --rounded-lg: 0.75rem;         /* 12px */
  --rounded-xl: 1rem;            /* 16px */

  /* Spacing Spans */
  --space-xs: 0.25rem;           /* 4px */
  --space-sm: 0.5rem;            /* 8px */
  --space-md: 1rem;              /* 16px */
  --space-lg: 1.5rem;            /* 24px */
  --space-xl: 2rem;              /* 32px */
  --space-2xl: 3rem;             /* 48px */

  /* System Transitions */
  --transition-fast: 100ms ease;
  --transition-base: 200ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 300ms ease;
}
```

---

## 3. Font System & Type Hierarchy

Typography must prioritize scannability. Monospace families are strictly enforced on all log data, telemetry cards, hostnames, and IP maps.

| Level | Size | Weight | Line Height | Usage |
|:---|:---|:---|:---|:---|
| **Display / H1** | `2.25rem` (36px) | 600 (SemiBold) | 1.2 | Main workspace headers |
| **Headline / H2** | `1.5rem` (24px) | 600 (SemiBold) | 1.3 | Major telemetry group headers |
| **Title / H3** | `1.125rem` (18px) | 500 (Medium) | 1.4 | Card labels, configuration groups |
| **Body** | `0.875rem` (14px) | 400 (Regular) | 1.6 | Narrative descriptions and documentation |
| **Label / Mono** | `0.8125rem` (13px) | 400 (Regular) | 1.4 | IP addresses, ports, logs, and values |

---

## 4. Visual Themes Mapping

The platform supports six visual configurations:

1.  **Space Void Navy (Default):** deep dark blue base (`#0a0e1a`), steel blue cards (`#0f1425`), electric blue actions (`#3b82f6`).
2.  **Matrix Cyberpunk:** deep forest black base (`#020502`), slate green containers (`#0a0f0a`), glowing neon green actions (`#00ff66`), fonts forced to JetBrains Mono.
3.  **Nord Frost:** arctic base (`#2e3440`), secondary slate grey (`#3b4252`), frosted blue actions (`#88c0d0`).
4.  **Dracula (Vampire Purple):** deep midnight violet background (`#282a36`), secondary dark violet (`#44475a`), neon pink/cyan status accents (`#ff79c6`).
5.  **Sunset Sahara:** warm dark clay background (`#1a1515`), dark copper containers (`#261d1d`), fiery warning amber actions (`#f97316`).
6.  **Light Slate Override:** light slate background (`#f8fafc`), clean white panels (`#ffffff`), dark blue text (`#0f172a`), border opacity shifted to 15% dark opacity (`rgba(0,0,0,0.1)`).

---

## 5. UI Component Specifications

### 5.1 Interactive Buttons
Buttons feature hover transitions and focus outlines. Emojis are forbidden; use SVG icons.

```css
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-display);
  font-size: 0.875rem;
  font-weight: 600;
  padding: 0.625rem 1.25rem;
  border-radius: var(--rounded-md);
  border: 1px solid transparent;
  cursor: pointer;
  transition: all var(--transition-base);
  gap: var(--space-sm);
  outline: none;
}

.btn-primary {
  background: linear-gradient(135deg, var(--color-accent), #4f46e5);
  color: #ffffff;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(59, 130, 246, 0.35);
  opacity: 0.95;
}

.btn-secondary {
  background: rgba(255, 255, 255, 0.03);
  color: var(--text-primary);
  border-color: var(--border-color);
}

.btn-secondary:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: var(--border-hover);
  transform: translateY(-1px);
}
```

### 5.2 Glassmorphic Cards & Containers
Depth is created using borders with 6% to 12% white opacity and backdrop filters rather than heavy drop shadows:

```css
.card {
  background: rgba(15, 20, 37, 0.65);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border-color);
  border-radius: var(--rounded-lg);
  padding: var(--space-lg);
  transition: border-color var(--transition-base), transform var(--transition-base);
}

.card:hover {
  border-color: var(--border-hover);
  transform: translateY(-2px);
}
```

### 5.3 Forms & Inputs
```css
.input-text {
  background: rgba(10, 14, 26, 0.8);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
  border-radius: var(--rounded-md);
  padding: 0.625rem 0.875rem;
  font-family: var(--font-mono);
  font-size: var(--mono);
  transition: all var(--transition-base);
  width: 100%;
}

.input-text:focus {
  border-color: var(--color-accent);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
  outline: none;
}
```

---

## 6. Pre-Delivery & Accessibility Checklist

Before releasing or merging any frontend code changes, verify:

- [ ] **No Emojis as Icons:** All indicators and actions use SVGs (Lucide or Heroicons).
- [ ] **Accessibility (a11y):** Keyboard navigation outlines must be visible on Tab traverse.
- [ ] **Theme Variables:** Colors utilize CSS property tokens instead of fixed HEX values.
- [ ] **Monospace Enforcement:** Monospace fonts are applied to all IP addresses, port lists, and logs.
- [ ] **Contrast Verification:** Text-to-background contrast maintains a minimum **4.5:1** ratio.
