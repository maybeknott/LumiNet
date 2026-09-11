import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(packageRoot, '..', '..', '..');

const master = readFileSync(path.join(repoRoot, 'governance', 'design-system', 'MASTER.md'), 'utf8');
const css = readFileSync(path.join(packageRoot, 'src', 'index.css'), 'utf8');

const mappings = new Map([
  ['--bg-void', '--color-bg-primary'],
  ['--bg-surface', '--color-bg-secondary'],
  ['--bg-element', '--color-bg-tertiary'],
  ['--neon-blue', '--color-accent'],
  ['--neon-cyan', '--color-cyan'],
  ['--neon-purple', '--color-purple'],
  ['--neon-emerald', '--color-success'],
  ['--neon-warning', '--color-warning'],
  ['--neon-error', '--color-error'],
]);

function masterHex(token) {
  const row = master.split(/\r?\n/).find((line) => line.includes(`\`${token}\``));
  assert.ok(row, `MASTER.md must define ${token}`);
  const match = row.match(/#[0-9a-fA-F]{6}/);
  assert.ok(match, `MASTER.md must give ${token} an explicit hex value`);
  return match[0].toLowerCase();
}

function cssValue(token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = css.match(new RegExp(`${escaped}\\s*:\\s*(#[0-9a-fA-F]{6})\\s*;`));
  assert.ok(match, `index.css must define ${token} with an explicit hex value`);
  return match[1].toLowerCase();
}

for (const [masterToken, cssToken] of mappings) {
  assert.equal(
    cssValue(cssToken),
    masterHex(masterToken),
    `${cssToken} must remain an alias of authoritative ${masterToken}`,
  );
}

assert.match(css, /--font-display:\s*"Outfit"/i, 'display typography must follow MASTER.md');
assert.match(css, /--font-body:\s*"Outfit"/i, 'body typography must follow MASTER.md');
assert.match(css, /--font-mono:[^;]*(?:"JetBrains Mono"|"Fira Code")/i, 'mono typography must follow MASTER.md');
assert.match(master, /authoritative visual token and component specification/i, 'MASTER.md must remain explicitly authoritative');

console.log(`design-token governance: ${mappings.size} color aliases and typography authority verified`);
