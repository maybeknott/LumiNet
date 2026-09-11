import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);
const outDir = mkdtempSync(join(tmpdir(), 'luminet-v2rayn-import-'));

try {
  const compile = spawnSync(
    process.execPath,
    [join(rootPath, 'node_modules', 'typescript', 'bin', 'tsc'),
      'src/utils/v2raynImport.ts',
      'src/utils/stampFeed.ts',
      'src/utils/profileKey.ts',
      '--outDir', outDir,
      '--target', 'ES2023',
      '--module', 'ES2022',
      '--strict',
      '--skipLibCheck',
      '--ignoreConfig'],
    { cwd: rootPath },
  );
  assert.equal(compile.status, 0, `tsc failed: ${compile.stderr?.toString()}`);

  const mod = await import(pathToFileURL(join(outDir, 'v2raynImport.js')).href);

  // Array export with the classic configType numbering.
  const exportJson = JSON.stringify([
    { configType: 1, remarks: 'vmess-a', address: 'a.example.com', port: 443, id: 'uuid' },
    { configType: 5, remarks: 'vless-b', address: 'b.example.com', port: 8443, flow: 'xtls-rprx-vision' },
    { configType: 2, remarks: 'custom-should-skip', address: 'x', port: 1 },
    { remarks: 'no-type' },
    { configType: 6, address: 'c.example.com', port: 0 },
    'not-an-object',
  ]);
  const { items, skipped } = mod.parseV2rayNExport(exportJson);
  assert.equal(items.length, 2);
  assert.equal(items[0].protocol, 'vmess');
  assert.equal(items[0].name, 'vmess-a');
  assert.ok(typeof items[0].profileKey === 'string' && items[0].profileKey.length === 64);
  assert.equal(items[1].protocol, 'vless');
  assert.ok(typeof items[1].profileKey === 'string' && items[1].profileKey.length === 64);
  assert.ok(skipped.length >= 3, `expected >=3 skips, got ${skipped.length}`);

  // Full-config export with profileItems wrapper.
  const wrapped = JSON.stringify({
    profileItems: [{ configType: 7, remarks: 'hy2', address: 'd.example.com', port: 443 }],
  });
  const w = mod.parseV2rayNExport(wrapped);
  assert.equal(w.items.length, 1);
  assert.equal(w.items[0].protocol, 'hysteria2');

  // Single object export.
  const single = mod.parseV2rayNExport(JSON.stringify({ configType: 8, remarks: 't', address: 'e.example.com', port: 443 }));
  assert.equal(single.items.length, 1);
  assert.equal(single.items[0].protocol, 'tuic');

  // Invalid JSON is reported, not thrown.
  const bad = mod.parseV2rayNExport('not json');
  assert.equal(bad.items.length, 0);
  assert.equal(bad.skipped[0].reason, 'input is not valid JSON');

  // Hint: empty for non-JSON text and plain share links.
  assert.equal(mod.v2raynImportHint('vmess://x'), '');
  assert.equal(mod.v2raynImportHint(''), '');

  // Hint: recognises v2rayN JSON.
  const hint = mod.v2raynImportHint(exportJson);
  assert.ok(hint.includes('2 v2rayN profile(s) recognised'), hint);
  assert.ok(hint.includes('skipped'), hint);

  console.log('test-v2rayn-import: all assertions passed');
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
