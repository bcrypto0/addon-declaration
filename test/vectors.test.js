// Runs the fixed conformance vectors in vectors/ (SPEC.md section 15).

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { verifyDeclarationText, parseTime, isHttpsUrl } from '../lib/declaration.js';
import { parsePublicKeyText } from '../lib/keys.js';
import { toolsHashFromPages } from '../lib/tools.js';

const dir = new URL('../vectors/', import.meta.url);
// Files are read outside any assert.throws callback, so a missing file fails
// the test instead of counting as the expected rejection.
const read = (name) => fs.readFileSync(new URL(name, dir));
const manifest = JSON.parse(read('manifest.json'));

test('vector set covers both algorithms, every offline state and both key methods', () => {
  const states = new Set(manifest.declarations.map((c) => c.expect.state));
  for (const s of ['valid', 'malformed', 'invalid_signature', 'key_not_found', 'expired', 'not_yet_valid', 'name_domain_mismatch', 'tools_hash_mismatch', 'chain_mismatch']) assert.ok(states.has(s), s);
  for (const alg of ['ed25519', 'ecdsap384']) {
    for (const id of ['valid', 'valid-http', 'valid-adk-record', 'key-not-found-http-adk-record', 'valid-bom', 'valid-16384-bytes', 'malformed-too-large', 'malformed-invalid-utf8', 'malformed-duplicate-member', 'chain-mismatch-forged-previous', 'valid-chain-key-change', 'valid-chain-key-change-both-keys', 'chain-mismatch-key-change-forged-previous']) {
      assert.ok(manifest.declarations.some((c) => c.id === `${alg}/${id}`), `${alg}/${id}`);
    }
  }
  const rules = new Set(manifest.fields.map((c) => c.rule));
  for (const r of ['https-url', 'contact', 'domain', 'version', 'time', 'amount', 'network', 'asset', 'name', 'tool', 'signature']) assert.ok(rules.has(r), r);
  for (const c of manifest.tools) if (c.expect.error) assert.ok(typeof c.expect.reason === 'string', `${c.id} names its reason`);
  // Invisible characters outside Cf are among the rejected field values.
  for (const rule of ['version', 'tool']) {
    for (const cp of [0xfe0f, 0xe0100, 0x3164]) {
      assert.ok(manifest.fields.some((c) => c.rule === rule && c.expect === 'reject' && [...c.value].some((ch) => ch.codePointAt(0) === cp)), `${rule} U+${cp.toString(16)}`);
    }
  }
});

for (const c of manifest.declarations) {
  test(`declaration vector ${c.id}`, async () => {
    const bytes = read(c.declaration);
    const toolsText = c.tools ? read(c.tools) : undefined;
    const previousText = c.previous ? read(c.previous) : undefined;
    const r = await verifyDeclarationText(bytes, { keySource: { kind: 'offline', keys: parsePublicKeyText(c.pubkey) }, now: parseTime(c.now), toolsText, previousText });
    assert.equal(r.state, c.expect.state, r.reasons.join('; '));
    assert.equal(r.exitCode, c.expect.exitCode);
    if (c.expect.declarationHash) assert.equal(r.details.declarationHash, c.expect.declarationHash);
    if (c.expect.keyChangeNote) assert.match((r.details.notes || []).join(' '), /key changed/);
    else if (c.previous && r.state === 'valid') assert.equal(r.details.notes, undefined);
    if (c.expect.chain) {
      assert.equal(r.details.chain.keyChanged, c.expect.chain.keyChanged);
      assert.equal(r.details.chain.previousSignature, c.expect.chain.previousSignature);
      // A link across a key change is not listed under the same words as continuity.
      assert.equal(r.details.checked.includes('chain link to previous declaration'), !c.expect.chain.keyChanged);
    }
    if (c.expect.bytes) assert.equal(bytes.length, c.expect.bytes);
  });
}

test('size vectors sit on the 16384 byte limit, one on each side', () => {
  for (const alg of ['ed25519', 'ecdsap384']) {
    assert.equal(read(`${alg}-valid-16384-bytes.json`).length, 16384);
    assert.equal(read(`${alg}-malformed-too-large.json`).length, 16385);
  }
});

function setPointer(obj, pointer, value) {
  const parts = pointer.split('/').slice(1);
  let o = obj;
  for (const p of parts.slice(0, -1)) o = o[p];
  o[parts[parts.length - 1]] = value;
}

const base = JSON.parse(read('ed25519-valid.json'));
const baseKey = manifest.declarations.find((c) => c.id === 'ed25519/valid').pubkey;
for (const c of manifest.fields) {
  test(`field vector ${c.id} ${c.expect} ${JSON.stringify(c.value).slice(0, 60)}`, async () => {
    const d = structuredClone(base);
    setPointer(d, c.pointer, c.value);
    const r = await verifyDeclarationText(JSON.stringify(d), { keySource: { kind: 'offline', keys: parsePublicKeyText(baseKey) }, now: parseTime('2026-11-18T12:00:00Z') });
    if (c.expect === 'reject') assert.equal(r.state, 'malformed', `expected malformed, got ${r.state}`);
    else assert.notEqual(r.state, 'malformed', r.reasons.join('; '));
    if (c.rule === 'https-url') assert.equal(isHttpsUrl(c.value), c.expect === 'accept');
  });
}

for (const c of manifest.tools) {
  test(`tools vector ${c.id}`, () => {
    const pages = (c.inputs || [c.input]).map(read);
    if (c.expect.error) {
      assert.throws(() => toolsHashFromPages(pages), (e) => {
        assert.ok(e.name === 'ToolsError' || e.name === 'JsonError', e.name);
        assert.equal(e.reason, c.expect.reason, e.message);
        return true;
      });
    } else assert.equal(toolsHashFromPages(pages), c.expect.toolsHash);
  });
}

test('tools vectors: equal values written differently hash the same', () => {
  const byId = Object.fromEntries(manifest.tools.map((c) => [c.id, c]));
  assert.equal(byId['number-forms'].expect.toolsHash, byId['number-forms-same'].expect.toolsHash);
  assert.equal(byId['bom'].expect.toolsHash, byId['jsonrpc-wrapper'].expect.toolsHash);
  assert.equal(byId['paged'].expect.toolsHash, byId['jsonrpc-wrapper'].expect.toolsHash);
  // Members next to the tools array are not hashed, however deep they nest.
  const plain = 'sha256:' + crypto.createHash('sha256').update('[{"name":"n"}]', 'utf8').digest('hex');
  assert.equal(byId['deep-sibling-meta'].expect.toolsHash, plain);
  assert.equal(byId['deep-sibling-cursor'].expect.toolsHash, plain);
  assert.equal(byId['jsonrpc-depth-65'].expect.reason, 'depth');
  // UTF-16 order puts U+1F600 (D83D DE00) before U+FB33; a code point sort would not.
  const text = read(byId['sort-astral-before-high-bmp'].input).toString('utf8');
  assert.ok(text.indexOf(String.fromCharCode(0xfb33)) < text.indexOf(String.fromCodePoint(0x1f600)), 'input lists the BMP name first');
  const canonical = JSON.stringify([{ name: String.fromCodePoint(0x1f600) }, { name: String.fromCharCode(0xfb33) }]);
  assert.equal(byId['sort-astral-before-high-bmp'].expect.toolsHash, 'sha256:' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex'));
});
