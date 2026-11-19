// A 0.1 declaration that is live and that a registry listing names by its
// hash (copied unchanged into testlib/live-0.1/ on 19 November 2026, with its
// tool list and the published key record). It has to keep verifying exactly
// as on the day it was signed, with the same hashes, in every later version
// of this verifier.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { verifyDeclarationText, declarationHash, parseDeclarationText, signDeclaration, SPEC_ID_01, SPEC_ID_02 } from '../lib/declaration.js';
import { parsePublicKeyText } from '../lib/keys.js';
import { toolsHashFromPages } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';
import { makeKey } from '../testlib/helpers.js';

const dir = new URL('../testlib/live-0.1/', import.meta.url);
const read = (n) => fs.readFileSync(new URL(n, dir));
const DECL = read('declaration.json');
const TOOLS = read('tools.json');
const KEY = parsePublicKeyText(read('mcp-registry-auth.txt').toString('utf8'));

test('the live 0.1 declaration: same bytes, same hashes, still valid', async () => {
  assert.equal(crypto.createHash('sha256').update(DECL).digest('hex'), 'ea74a41ccd263107376bc1008bbb5da055c39b8dd5345be456927f5ad28701c0');
  assert.equal(declarationHash(parseDeclarationText(DECL)), 'sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6');
  assert.equal(toolsHashFromPages([TOOLS]), 'sha256:317fad35d11e84f3d5a5c36f308eac5f4ba9329eb803916c707c8bdd4770d833');
  const r = await verifyDeclarationText(DECL, { keySource: { kind: 'offline', keys: KEY }, now: Date.parse('2026-11-19T12:00:00Z'), toolsText: [TOOLS] });
  assert.equal(r.state, 'valid', r.reasons.join('; '));
  assert.equal(r.details.format, SPEC_ID_01);
  assert.deepEqual(r.details.checked, ['name: namespace covered by an http key at rtlpdf.com', 'signature', 'time window', 'tools hash']);
  assert.equal(r.details.declarationHash, 'sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6');
  // Valid until its own expiry, and not after.
  assert.equal((await verifyDeclarationText(DECL, { keySource: { kind: 'offline', keys: KEY }, now: Date.parse('2027-05-18T00:08:45Z') })).state, 'valid');
  assert.equal((await verifyDeclarationText(DECL, { keySource: { kind: 'offline', keys: KEY }, now: Date.parse('2027-05-18T00:08:46Z') })).state, 'expired');
  // A check that accepts 0.2 only refuses it, and says why.
  const only02 = await verifyDeclarationText(DECL, { keySource: { kind: 'offline', keys: KEY }, now: Date.parse('2026-11-19T12:00:00Z'), formats: [SPEC_ID_02] });
  assert.equal(only02.state, 'malformed');
  assert.match(only02.reasons[0], /not accepted by this check/);
});

test('the live 0.1 declaration can be the previous of a 0.2 declaration (here signed by a throwaway key)', async () => {
  const k = makeKey('ed25519');
  const prev = parseDeclarationText(DECL);
  const d = toolSetDigestsFromPages([TOOLS]);
  const up = signDeclaration(
    {
      spec: SPEC_ID_02,
      name: prev.name,
      version: prev.version,
      toolSetDigest: { spec: 'mcp-tool-set-digest/1', contract: d.contract.digest, extras: d.extras.digest },
      remotes: prev.remotes,
      issuedAt: '2026-11-19T12:00:00Z',
      previous: declarationHash(prev),
      key: { method: 'http', domain: 'rtlpdf.com' },
    },
    k.loaded,
  );
  const r = await verifyDeclarationText(JSON.stringify(up), { keySource: { kind: 'offline', keys: [k.loaded.public] }, now: Date.parse('2026-11-19T12:00:00Z'), toolsText: [TOOLS], previousText: DECL });
  assert.equal(r.state, 'valid', r.reasons.join('; '));
  assert.equal(r.details.chain.previous, 'sha256:9170020c77a92f039806c11f714d1aa6eb50780bdb90c27e52016958045baca6');
  assert.equal(r.details.chain.previousFormat, SPEC_ID_01);
  // A throwaway key is not the live key: the link is reported as a key change, earlier signature not checked.
  assert.equal(r.details.chain.keyChanged, true);
  assert.equal(r.details.chain.previousSignature, 'not_checked');
  // With the live key given too, the 0.1 signature is checked under the 0.1 prefix.
  const both = await verifyDeclarationText(JSON.stringify(up), { keySource: { kind: 'offline', keys: [k.loaded.public, ...KEY] }, now: Date.parse('2026-11-19T12:00:00Z'), previousText: DECL });
  assert.equal(both.details.chain.previousSignature, 'checked');
});
