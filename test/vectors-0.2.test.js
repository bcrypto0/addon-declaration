// Runs the fixed conformance vectors of format addon-declaration/0.2 in
// vectors/v0.2/ (SPEC.md section 17), and checks that the 0.1 vectors in
// vectors/ are still the files generate.js wrote.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { verifyDeclarationText, parseTime } from '../lib/declaration.js';
import { parsePublicKeyText } from '../lib/keys.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';

const dir = new URL('../vectors/v0.2/', import.meta.url);
const read = (name) => fs.readFileSync(new URL(name, dir));
const manifest = JSON.parse(read('manifest.json'));

test('0.2 vector set covers the cases of SPEC.md section 17 for both algorithms', () => {
  assert.equal(manifest.spec, 'addon-declaration/0.2');
  const want = [
    'valid', 'valid-no-contact', 'valid-null-extras', 'valid-0.1-previous',
    'valid-chain-from-0.1', 'valid-chain-from-0.1-format-0.2-only', 'valid-chain-from-0.1-key-change', 'valid-chain-from-0.1-key-change-both-keys',
    'chain-mismatch-from-forged-0.1', 'chain-mismatch-0.1-follows-0.2',
    'tools-extras-mismatch', 'tools-contract-mismatch', 'tools-null-extras-mismatch', 'tools-extras-declared-none-received', 'tools-no-extras-digest', 'tools-incomplete-list',
    'tools-extras-tsd-text', 'tools-contract-tsd-number', 'tools-tsd-tool', 'tools-unreadable', 'valid-repeated-tool-name', 'valid-repeated-member',
    'malformed-tools-hash-member', 'malformed-both-members', 'malformed-hex-digest', 'malformed-missing-extras', 'malformed-0.1-with-tool-set-digest',
    'malformed-relabelled-0.1', 'invalid-signature-relabelled-0.1', 'malformed-relabelled-0.2', 'invalid-signature-relabelled-0.2',
    'invalid-signature-0.2-body-0.1-prefix', 'invalid-signature-0.1-body-0.2-prefix',
    'format-0.1-not-accepted', 'format-0.2-not-accepted',
  ];
  for (const alg of ['ed25519', 'ecdsap384']) for (const id of want) assert.ok(manifest.declarations.some((c) => c.id === `${alg}/${id}`), `${alg}/${id}`);
  const rules = new Set(manifest.fields.map((c) => c.rule));
  for (const r of ['digest', 'extras', 'tool-set-digest', 'toolsHash', 'spec', 'contact']) assert.ok(rules.has(r), r);
  // The two kinds of tool difference are kept apart in the expectations.
  const byId = Object.fromEntries(manifest.declarations.map((c) => [c.id, c]));
  assert.deepEqual(byId['ed25519/tools-extras-mismatch'].expect.toolSetDigest.differs, ['extras']);
  assert.deepEqual(byId['ed25519/tools-contract-mismatch'].expect.toolSetDigest.differs, ['contract']);
  assert.equal(byId['ed25519/tools-extras-mismatch'].expect.exitCode, 8);
  assert.equal(byId['ed25519/tools-contract-mismatch'].expect.exitCode, 8);
  // A digest that could not be computed is not listed as a difference.
  assert.deepEqual(byId['ed25519/tools-extras-tsd-text'].expect.toolSetDigest.differs, []);
  assert.deepEqual(byId['ed25519/tools-extras-tsd-text'].expect.toolSetDigest.noDigest, ['extras']);
  assert.deepEqual(byId['ed25519/tools-incomplete-list'].expect.toolSetDigest.differs, []);
  // The repeated tool name case: two lists that differ in which tool carries
  // the annotation share both digests, and the result reports the name.
  assert.deepEqual(byId['ed25519/valid-repeated-tool-name'].expect.toolSetDigest.repeatedNames, [{ name: 'f', count: 2 }]);
  const sigOf = (n) => toolSetDigestsFromPages([read(n)]);
  const [a, b] = [sigOf('tools-repeated-name.json'), sigOf('tools-repeated-name-moved.json')];
  assert.equal(a.contract.digest, b.contract.digest);
  assert.equal(a.extras.digest, b.extras.digest);
  assert.notEqual(read('tools-repeated-name.json').toString(), read('tools-repeated-name-moved.json').toString());
  // A null extras digest is written as JSON null.
  assert.equal(JSON.parse(read('ed25519-valid-null-extras.json')).toolSetDigest.extras, null);
});

for (const c of manifest.declarations) {
  test(`0.2 declaration vector ${c.id}`, async () => {
    const bytes = read(c.declaration);
    const r = await verifyDeclarationText(bytes, {
      keySource: { kind: 'offline', keys: parsePublicKeyText(c.pubkey) },
      now: parseTime(c.now),
      toolsText: c.tools ? [read(c.tools)] : undefined,
      previousText: c.previous ? read(c.previous) : undefined,
      formats: c.formats,
    });
    const e = c.expect;
    assert.equal(r.state, e.state, r.reasons.join('; '));
    assert.equal(r.exitCode, e.exitCode);
    if (e.declarationHash) assert.equal(r.details.declarationHash, e.declarationHash);
    if (e.format) assert.equal(r.details.format, e.format);
    if (e.toolSetDigest) {
      const t = r.details.toolSetDigest;
      const x = e.toolSetDigest;
      assert.equal(t.contract.result, x.contract);
      assert.equal(t.extras.result, x.extras);
      assert.deepEqual(t.differs, x.differs);
      for (const k of ['noDigest', 'repeatedMembers', 'repeatedNames']) if (Object.hasOwn(x, k)) assert.deepEqual(t[k], x[k], k);
      assert.equal(t.comparable, t.noDigest.length === 0);
      if (Object.hasOwn(x, 'contractCode')) assert.equal(t.contract.code, x.contractCode);
      if (Object.hasOwn(x, 'extrasCode')) assert.equal(t.extras.code, x.extrasCode);
      // The text names the digest that differs, or says the list could not be compared.
      const why = r.reasons.join(' ');
      if (x.differs.includes('contract')) assert.match(why, /the contract digest differs/);
      else if (x.differs.includes('extras')) assert.match(why, /^only the extras digest differs/);
      else if (e.state !== 'valid') assert.match(why, /could not be compared[\s\S]*not evidence that the tools changed/);
      if (x.repeatedNames && x.repeatedNames.length) assert.match((t.notes || []).join(' '), /tool name "[^"]+" appears \d+ times/);
      if (x.repeatedMembers) assert.match((t.notes || []).join(' '), /repeated member name/);
    }
    if (e.chain) {
      for (const [k, v] of Object.entries(e.chain)) assert.equal(r.details.chain[k], v, `chain.${k}`);
      assert.equal(r.details.checked.includes('chain link to previous declaration'), !e.chain.keyChanged);
    }
    const notes = (r.details.notes || []).join(' ');
    assert.equal(/key changed/.test(notes), Boolean(e.keyChangeNote));
    assert.equal(/format changed/.test(notes), Boolean(e.formatChangeNote));
  });
}

function setPointer(obj, pointer, value, remove) {
  const parts = pointer.split('/').slice(1);
  let o = obj;
  for (const p of parts.slice(0, -1)) o = o[p];
  if (remove) delete o[parts[parts.length - 1]];
  else o[parts[parts.length - 1]] = value;
}

const base = JSON.parse(read('ed25519-valid.json'));
const baseKey = manifest.declarations.find((c) => c.id === 'ed25519/valid').pubkey;
for (const c of manifest.fields) {
  test(`0.2 field vector ${c.id} ${c.expect} ${c.remove ? 'remove ' + c.pointer : JSON.stringify(c.value).slice(0, 60)}`, async () => {
    const d = structuredClone(base);
    setPointer(d, c.pointer, c.value, c.remove);
    const r = await verifyDeclarationText(JSON.stringify(d), { keySource: { kind: 'offline', keys: parsePublicKeyText(baseKey) }, now: parseTime('2026-11-18T12:00:00Z') });
    if (c.expect === 'reject') assert.equal(r.state, 'malformed', `expected malformed, got ${r.state}`);
    else assert.notEqual(r.state, 'malformed', r.reasons.join('; '));
  });
}

// The 0.1 vectors are fixed files (SPEC.md section 15). This pins all of them,
// with generate.js and manifest.json, as they were before format 0.2 was added
// (19 November 2026); regenerating them on purpose means updating this value.
const V01_PIN = '04e56401efe09f7ed9c7db96b637e83f993f02db8533db4c6b795fb055df6b59';
test('the 0.1 vector files are unchanged', () => {
  const top = new URL('../vectors/', import.meta.url);
  const names = fs.readdirSync(top).filter((n) => n.endsWith('.json') || n === 'generate.js').sort();
  assert.ok(names.length >= 70, `found ${names.length}`);
  const h = crypto.createHash('sha256');
  for (const n of names) h.update(n + '\0' + crypto.createHash('sha256').update(fs.readFileSync(new URL(n, top))).digest('hex') + '\n');
  assert.equal(h.digest('hex'), V01_PIN);
});
