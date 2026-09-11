import assert from 'node:assert/strict';
import { computeSubscriptionDiff } from '../src/api/subscription_pipeline.ts';
import { parsePropfindXml } from '../src/api/webdav_backup.ts';
import { verifyCertPins, normalizePin, createPinningConfig } from '../src/api/cert_pinning.ts';
import { parseAdblockHosts } from '../src/api/adblock_hosts_parser.ts';
import { AutoProxyRulesetMatcher } from '../src/api/composite_rule_compiler.ts';
import {
  VlessCommand,
  VlessAddressType,
  serializeVlessRequestHeader,
  deserializeVlessRequestHeader,
  serializeVlessResponseHeader,
  deserializeVlessResponseHeader,
} from '../src/api/vless_codec.ts';
import { computeProfileKey, matchProfile, MatchDecision } from '../src/utils/profileKey.ts';
import {
  encryptPayload,
  decryptPayload,
  encryptIpList,
  decryptIpList,
} from '../src/api/encrypted_envelope.ts';
import {
  resolveMitmAction,
  MitmActionKind,
  matchesSan,
  GOOGLE_PROFILE,
} from '../src/api/domain_fronting.ts';
import { Ipv4Math, Ipv4Prefix, HostWalker } from '../src/utils/ipv4Subnet.ts';

console.log('Running test-donor-refactors...');

// 1. Subscription Diffing
const oldNodes = [
  { protocol: 'vless', endpoint: 'node1.com:443', tag: 'Fast US' },
  { protocol: 'vmess', endpoint: 'node2.com:443', tag: 'Old HK' },
];
const newNodes = [
  { protocol: 'vless', endpoint: 'node1.com:443', tag: 'Fast US Updated' },
  { protocol: 'trojan', endpoint: 'node3.com:443', tag: 'New SG' },
];
const diff = computeSubscriptionDiff(oldNodes, newNodes);
assert.equal(diff.added.length, 1, 'expected 1 added node');
assert.equal(diff.added[0].tag, 'New SG');
assert.equal(diff.removed.length, 1, 'expected 1 removed node');
assert.equal(diff.removed[0].tag, 'Old HK');
assert.equal(diff.modified.length, 1, 'expected 1 modified node');
assert.equal(diff.modified[0].old.tag, 'Fast US');
assert.equal(diff.modified[0].new.tag, 'Fast US Updated');
assert.equal(diff.hasChanges, true);
console.log('PASS SubscriptionDiff: ' + diff.summary);

// 2. WebDAV XML Propfind Parsing
const xmlSample =
  '<D:multistatus xmlns:D="DAV:"><D:response><D:href>/remote.php/dav/files/user/LumiNet/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response><D:response><D:href>/remote.php/dav/files/user/LumiNet/backup_2026.zip</D:href><D:propstat><D:prop><D:getcontentlength>12345</D:getcontentlength><D:getlastmodified>Sun, 06 Sep 2026 12:00:00 GMT</D:getlastmodified></D:prop></D:propstat></D:response></D:multistatus>';
const backups = parsePropfindXml(xmlSample, '/remote.php/dav/files/user/LumiNet/');
assert.equal(backups.length, 1, 'should parse 1 backup entry excluding base collection');
assert.equal(backups[0].name, 'backup_2026.zip');
assert.equal(backups[0].size, 12345);
console.log('PASS WebDAV Propfind XML parsing');

// 3. Certificate Pinning Flow
const samplePin = 'a'.repeat(64);
assert.equal(normalizePin('A'.repeat(64)), samplePin);
const config = createPinningConfig('prof1', samplePin, ['b'.repeat(64)]);
const okRes = verifyCertPins([samplePin], config);
assert.equal(okRes.status, 'ok');
const mismatchRes = verifyCertPins(['c'.repeat(64)], config);
assert.equal(mismatchRes.status, 'mismatch');
console.log('PASS CertPinningFlow verification');

// 4. Adblock Hosts Parser
const hostsText =
  '# Sample hosts\n127.0.0.1 localhost\n0.0.0.0 tracker.example.com\n0.0.0.0 ads.doubleclick.net # inline comment\n::1 broadcasthost\ninvalid_line_ignored\n0.0.0.0 *.wildcard.com\n';
const blocked = parseAdblockHosts(hostsText);
assert.ok(blocked.includes('tracker.example.com'));
assert.ok(blocked.includes('ads.doubleclick.net'));
assert.ok(!blocked.includes('localhost'));
assert.ok(!blocked.includes('broadcasthost'));
console.log('PASS AdblockHostsParser (' + blocked.length + ' domains)');

// 5. AutoProxy Ruleset Matcher
const ap = new AutoProxyRulesetMatcher();
ap.parseLine('! comment');
ap.parseLine('||google.com');
ap.parseLine('@@||google.com/search');
assert.equal(ap.match('https://google.com/search?q=test'), 'DIRECT');
assert.equal(ap.match('https://google.com/maps'), 'PROXY');
assert.equal(ap.match('https://internal.lan'), undefined);
console.log('PASS AutoProxyRulesetMatcher');

// 6. VLESS Stream Codec
const uuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
const serialized = serializeVlessRequestHeader({
  version: 0,
  uuid,
  command: VlessCommand.TCP,
  port: 8443,
  address: { type: VlessAddressType.Domain, value: 'example.com' },
});
const deserialized = deserializeVlessRequestHeader(serialized);
assert.equal(deserialized.header.version, 0);
assert.equal(deserialized.header.uuid, uuid);
assert.equal(deserialized.header.command, VlessCommand.TCP);
assert.equal(deserialized.header.port, 8443);
assert.equal(deserialized.header.address.type, VlessAddressType.Domain);
assert.equal(deserialized.header.address.value, 'example.com');

const respSerialized = serializeVlessResponseHeader({
  version: 0,
  addons: new Uint8Array([0xaa, 0xbb]),
});
const respDeserialized = deserializeVlessResponseHeader(respSerialized);
assert.equal(respDeserialized.header.version, 0);
assert.equal(respDeserialized.header.addons?.length, 2);
console.log('PASS VlessStreamCodec request and response roundtrip');

// 7. ProfileKey Deduplication & Deterministic Identity
const pk1 = computeProfileKey({
  protocol: 'vless',
  host: 'us1.edge.net',
  port: 443,
  uuid: 'abc-123',
  alias: 'Label 1',
});
const pk2 = computeProfileKey({
  protocol: 'vless',
  host: 'us1.edge.net',
  port: 443,
  uuid: 'abc-123',
  alias: 'Different Cosmetic Label',
});
const pkDifferent = computeProfileKey({
  protocol: 'vless',
  host: 'us2.edge.net',
  port: 443,
  uuid: 'abc-123',
});
assert.equal(pk1.hash, pk2.hash, 'cosmetic alias changes must not change ProfileKey hash');
assert.equal(matchProfile(pk1, pk2), MatchDecision.Match);
assert.notEqual(pk1.hash, pkDifferent.hash);
assert.equal(matchProfile(pk1, pkDifferent), MatchDecision.Mismatch);
console.log('PASS ProfileKey: deterministic content identity (' + pk1.shortHash + ')');

// 8. EncryptedPayloadEnvelope WebCrypto roundtrip
const passphrase = 'SuperSecretMasterKey2026!';
const plaintext = new TextEncoder().encode('Hello LumiNet Secure Envelope');
const envelope = await encryptPayload(plaintext, passphrase);
assert.equal(envelope.version, 1);
assert.equal(envelope.algorithm, 'AES-GCM');
assert.equal(envelope.encoding, 'base64url');
const decrypted = await decryptPayload(envelope, passphrase);
assert.equal(new TextDecoder().decode(decrypted), 'Hello LumiNet Secure Envelope');

const ipList = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];
const encryptedIpBlob = await encryptIpList(ipList, passphrase);
const decryptedIps = await decryptIpList(encryptedIpBlob, passphrase);
assert.deepEqual(decryptedIps, ipList);
console.log('PASS EncryptedPayloadEnvelope AES-GCM roundtrip');

// 9. MitmFrontingManager / Domain Fronting
assert.ok(matchesSan('video.google.com', '*.google.com'));
assert.ok(matchesSan('google.com', '*.google.com'));
assert.ok(!matchesSan('evilgoogle.com', '*.google.com'));

const frontAction = resolveMitmAction('www.youtube.com', 443);
assert.equal(frontAction.kind, MitmActionKind.RepackFronted);
assert.equal(frontAction.frontedSni, GOOGLE_PROFILE.frontedSni);

const directAction = resolveMitmAction('unfronted.private.org', 8080);
assert.equal(directAction.kind, MitmActionKind.Direct);
assert.equal(directAction.port, 8080);
console.log('PASS MitmFrontingManager domain fronting resolution');

// 10. Ipv4Prefix, Ipv4Math, and HostWalker
const prefix = Ipv4Math.parsePrefix('192.168.1.0/24');
assert.ok(prefix instanceof Ipv4Prefix);
assert.equal(prefix.normalizedString(), '192.168.1.0/24');
assert.equal(prefix.addressCount(), 256);
assert.equal(prefix.usableHostCount(), 254);
const bounds = prefix.hostBounds();
assert.equal(Ipv4Math.formatAddress(bounds.start), '192.168.1.1');
assert.equal(Ipv4Math.formatAddress(bounds.end), '192.168.1.254');

const walker = new HostWalker();
const visited = [];
walker.walk(['10.0.0.0/30'], 10, (ip) => {
  visited.push(ip);
});
assert.deepEqual(visited, ['10.0.0.1', '10.0.0.2']);
console.log('PASS Ipv4Subnet & HostWalker target scanning');

console.log('All donor refactor tests passed successfully.');
