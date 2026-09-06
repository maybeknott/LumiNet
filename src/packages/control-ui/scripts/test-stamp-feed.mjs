import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const rootPath = fileURLToPath(root);
const outDir = mkdtempSync(join(tmpdir(), 'luminet-stamp-feed-'));

try {
  const compile = spawnSync(
    process.execPath,
    [join(rootPath, 'node_modules', 'typescript', 'bin', 'tsc'),
      'src/utils/stampFeed.ts',
      '--outDir', outDir,
      '--target', 'ES2023',
      '--module', 'ES2022',
      '--strict',
      '--skipLibCheck',
      '--ignoreConfig'],
    { cwd: rootPath },
  );
  assert.equal(compile.status, 0, `tsc failed: ${compile.stderr?.toString()}`);

  const mod = await import(pathToFileURL(join(outDir, 'stampFeed.js')).href);

  // splitStampFeed: separates sdns:// lines from share links
  const text = [
    '# feed',
    'sdns://AgcAAAAAAAAABzguOC44LjgQgPCrtQ-g',
    'vmess://eyJ2IjoiMiJ9',
    'sdns://AgcAAAAAAAAACC5kbnMuZ29vZ2xl',
    '',
  ].join('\n');
  const { stamps, other } = mod.splitStampFeed(text);
  assert.equal(stamps.length, 2);
  assert.deepEqual(other, ['# feed', 'vmess://eyJ2IjoiMiJ9']);

  // CRLF + case-insensitive prefix
  const crlf = mod.splitStampFeed('SDNS://AAAA\r\nplain');
  assert.deepEqual(crlf.stamps, ['SDNS://AAAA']);

  // blank input
  assert.deepEqual(mod.splitStampFeed(''), { stamps: [], other: [] });

  // hint: empty without stamps
  assert.equal(mod.stampFeedHint('vmess://x'), '');

  // hint: singular/plural wording
  assert.ok(mod.stampFeedHint('sdns://a').includes('1 dnscrypt DNS stamp'));
  assert.ok(mod.stampFeedHint('sdns://a\nsdns://b').includes('2 dnscrypt DNS stamps'));

  console.log('test-stamp-feed: all assertions passed');
} finally {
  rmSync(outDir, { recursive: true, force: true });
}
