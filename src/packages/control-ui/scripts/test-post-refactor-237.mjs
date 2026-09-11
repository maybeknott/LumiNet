import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const cockpitPath = path.resolve('src/pages/NetworkCockpit.tsx');
const appPath = path.resolve('src/App.tsx');
const navPath = path.resolve('src/navigation.ts');

const cockpitSrc = fs.readFileSync(cockpitPath, 'utf8');
const appSrc = fs.readFileSync(appPath, 'utf8');
const navSrc = fs.readFileSync(navPath, 'utf8');

assert.ok(cockpitSrc.includes('export const NetworkCockpit'), 'retired deep-link component must remain explicit');
assert.ok(cockpitSrc.includes('Unavailable'), 'cockpit must classify its evidence state');
assert.ok(cockpitSrc.includes('does not currently have an authoritative daemon contract'), 'cockpit must explain missing authority');
assert.ok(!cockpitSrc.includes('GLOBAL_NODES'), 'authored sample nodes must not appear as production telemetry');
assert.ok(!cockpitSrc.includes('CABLE_HOPS'), 'authored sample cable topology must not appear as production telemetry');
assert.ok(!cockpitSrc.includes('MIDDLEBOX INTERFERENCE DETECTED'), 'fabricated interference assertions must be absent');
assert.ok(!cockpitSrc.includes('Real-time WebGL visualization'), 'unbacked real-time/WebGL claim must be absent');

assert.ok(appSrc.includes('path="cockpit"'), 'legacy cockpit deep link should be handled explicitly');
assert.ok(appSrc.includes('<Navigate to="/connections" replace />'), 'legacy cockpit deep link must redirect to measured evidence');
assert.ok(!navSrc.includes("path: '/cockpit'"), 'unverified cockpit must not be a primary navigation destination');

console.log('test-post-refactor-237 (cockpit evidence truth): all assertions passed');
