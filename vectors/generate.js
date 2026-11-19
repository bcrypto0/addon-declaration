#!/usr/bin/env node
// Writes the fixed conformance vectors in this folder (SPEC.md section 15).
// Run once; the files are then kept as they are. Keys are generated in memory
// and only their public halves are written. Running it again makes new keys
// and new signatures, so only rerun it to change the vector set on purpose.
//
//   node vectors/generate.js
//
// Expected results for the field vectors are written by hand below, not
// computed by this implementation, so test/vectors.test.js checks the code
// against them.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadPrivateKey, proofRecord, signBytes } from '../lib/keys.js';
import { SPEC_ID, ordered, signingInput, declarationHash, signDeclaration, STATES } from '../lib/declaration.js';
import { toolsHash, toolsHashFromPages } from '../lib/tools.js';
import { jsonOut } from '../lib/cli.js';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const NOW = '2026-11-18T12:00:00Z';

function newKey(alg) {
  const pair = alg === 'ed25519' ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  return loadPrivateKey(pair.privateKey.export({ format: 'pem', type: 'pkcs8' }));
}

function signRaw(u, loaded) {
  const d = ordered({ ...u, key: { ...u.key, alg: loaded.alg, id: loaded.public.id } });
  return ordered({ ...d, signature: signBytes(loaded.alg, loaded.privateKey, signingInput(d)).toString('base64') });
}

const TOOLS = [
  { name: 'get_forecast', description: 'Forecast.', inputSchema: { type: 'object', properties: { days: { type: 'integer', minimum: 1, maximum: 7 } } } },
  { name: 'get_alerts', description: 'Alerts.', inputSchema: { type: 'object' } },
];

function base(over = {}) {
  return {
    spec: SPEC_ID,
    name: 'com.example/weather',
    version: '1.4.0',
    toolsHash: toolsHash(TOOLS),
    remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }],
    payment: [{ network: 'eip155:84532', asset: '0x1111111111111111111111111111111111111111', payTo: '0x2222222222222222222222222222222222222222', amount: '10000' }],
    contact: 'mailto:security@example.com',
    issuedAt: '2026-11-18T10:00:00Z',
    expiresAt: '2027-05-17T10:00:00Z',
    key: { method: 'dns', domain: 'example.com' },
    ...over,
  };
}

const files = {};
const text = (v) => (typeof v === 'string' || Buffer.isBuffer(v) ? v : JSON.stringify(v, null, 2) + '\n');
const put = (name, value) => {
  files[name] = text(value);
  return name;
};

const cases = [];
put('tools.json', { tools: TOOLS });
put('tools-other.json', { tools: [TOOLS[0]] });

for (const alg of ['ed25519', 'ecdsap384']) {
  const k = newKey(alg);
  const other = newKey(alg);
  const pub = proofRecord(k.public);
  const p = (s) => `${alg}-${s}.json`;
  const add = (id, decl, expect, extra = {}) => {
    const file = put(p(id), decl);
    const hash = typeof decl === 'object' && !Buffer.isBuffer(decl) && expect !== 'malformed' ? { declarationHash: declarationHash(decl) } : {};
    cases.push({
      id: `${alg}/${id}`,
      declaration: file,
      pubkey: extra.pubkey || pub,
      now: NOW,
      ...(extra.tools ? { tools: extra.tools } : {}),
      ...(extra.previous ? { previous: extra.previous } : {}),
      expect: { state: expect, exitCode: STATES[expect], ...hash, ...(extra.expect || {}) },
    });
  };

  const first = signDeclaration(base({ version: '1.3.0', issuedAt: '2026-10-01T00:00:00Z', expiresAt: '2027-03-30T00:00:00Z' }), k);
  put(p('previous'), first);
  const good = signDeclaration(base({ previous: declarationHash(first) }), k);
  const goodText = text(good);
  add('valid', good, 'valid', { tools: 'tools.json', previous: p('previous'), expect: { chain: { keyChanged: false, previousSignature: 'checked' } } });
  add('valid-subnamespace', signDeclaration(base({ name: 'com.example.sub/weather' }), k), 'valid');
  add('valid-http', signDeclaration(base({ key: { method: 'http', domain: 'example.com' } }), k), 'valid');
  add('valid-adk-record', good, 'valid', { pubkey: proofRecord(k.public, 'addon') });
  add('key-not-found-http-adk-record', signDeclaration(base({ key: { method: 'http', domain: 'example.com' } }), k), 'key_not_found', { pubkey: proofRecord(k.public, 'addon') });
  add('valid-bom', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(goodText)]), 'valid');
  add('malformed-extra-member', { ...good, note: 'x' }, 'malformed');
  // The size limit is 16384 bytes inclusive: padded with legal whitespace to
  // exactly 16384 bytes the file is valid, one byte more and it is malformed.
  const padTo = (size) => {
    const body = goodText.replace(/\n$/, '');
    return body + ' '.repeat(size - Buffer.byteLength(body) - 1) + '\n';
  };
  add('valid-16384-bytes', padTo(16384), 'valid', { expect: { bytes: 16384 } });
  add('malformed-too-large', padTo(16385), 'malformed', { expect: { bytes: 16385 } });
  {
    const b = Buffer.from(goodText);
    b[b.indexOf('security@')] = 0xff;
    add('malformed-invalid-utf8', b, 'malformed');
  }
  add('malformed-duplicate-member', goodText.replace('"version": "1.4.0",', '"version": "1.4.0",\n  "version": "1.4.1",'), 'malformed');
  add('invalid-signature', { ...good, payment: [{ ...good.payment[0], payTo: '0x2222222222222222222222222222222222222223' }] }, 'invalid_signature');
  add('key-not-found', good, 'key_not_found', { pubkey: proofRecord(other.public) });
  add('expired', signDeclaration(base({ issuedAt: '2026-01-01T00:00:00Z', expiresAt: '2026-06-01T00:00:00Z' }), k), 'expired');
  add('not-yet-valid', signDeclaration(base({ issuedAt: '2026-11-18T12:05:01Z', expiresAt: '2027-05-17T10:00:00Z' }), k), 'not_yet_valid');
  add('name-domain-mismatch', signRaw(base({ name: 'foo.com.example/weather' }), k), 'name_domain_mismatch');
  add('name-domain-mismatch-http-subnamespace', signRaw(base({ name: 'com.example.sub/weather', key: { method: 'http', domain: 'example.com' } }), k), 'name_domain_mismatch');
  add('tools-hash-mismatch', good, 'tools_hash_mismatch', { tools: 'tools-other.json' });
  add('chain-mismatch', signDeclaration(base({ previous: 'sha256:' + '0'.repeat(64) }), k), 'chain_mismatch', { previous: p('previous') });
  // Same key on both links: that key did not sign the earlier file.
  const forged = { ...first, signature: Buffer.alloc(alg === 'ed25519' ? 64 : 96, 7).toString('base64') };
  put(p('previous-forged'), forged);
  add('chain-mismatch-forged-previous', signDeclaration(base({ previous: declarationHash(forged) }), k), 'chain_mismatch', { previous: p('previous-forged') });
  // A different key links to the earlier declaration: the link holds, and the
  // result must say that the key changed (SPEC.md section 10), in prose and in
  // the structured chain object.
  const takeover = signDeclaration(base({ previous: declarationHash(first) }), other);
  add('valid-chain-key-change', takeover, 'valid', { pubkey: proofRecord(other.public), previous: p('previous'), expect: { keyChangeNote: true, chain: { keyChanged: true, previousSignature: 'not_checked' } } });
  // The same link with the earlier key among the keys given: its signature is checked.
  const bothKeys = `${proofRecord(other.public)}\n${pub}`;
  add('valid-chain-key-change-both-keys', takeover, 'valid', { pubkey: bothKeys, previous: p('previous'), expect: { keyChangeNote: true, chain: { keyChanged: true, previousSignature: 'checked' } } });
  // A new key links to an earlier file that names the old key, which did not sign it.
  add('chain-mismatch-key-change-forged-previous', signDeclaration(base({ previous: declarationHash(forged) }), other), 'chain_mismatch', { pubkey: bothKeys, previous: p('previous-forged') });
}

// Field vectors: one member of ed25519-valid.json replaced. "accept" means the
// file still passes step 1 of SPEC.md section 11 (the later state does not
// matter: the signature no longer matches); "reject" means malformed.
const fields = [];
const field = (rule, pointer, values, expect) => {
  for (const value of values) fields.push({ id: `${rule}/${fields.length}`, rule, pointer, value, expect });
};
const a63 = 'a'.repeat(63);
const a64 = 'a'.repeat(64);
const astral = String.fromCodePoint(0x1f600);
field('https-url', '/remotes/0/url', ['https://mcp.example.com/mcp', 'https://mcp.example.com/', 'https://a.com/%7e', 'https://a.com/?x=%27', 'https://localhost/mcp', 'https://[::1]/mcp', 'https://1.2.3.4/', 'https://a.com:8443/mcp', 'https://xn--bcher-kva.example/'], 'accept');
field('https-url', '/remotes/0/url', [
  "https://a.com/?x='", 'https://a.com/a/%2e%2e/b', 'https://a.com/a/../b', 'https://a.com', 'https://A.com/', 'https://a.com:443/', 'https://user@a.com/', 'https://u:p@a.com/',
  'https://evil.com\\@good.com/', 'https:evil.com/', 'https:/evil.com/', 'http://a.com/', 'https://{tenant}.a.com/', 'https://a.com/a b', 'https://a.com/%zz', 'https://bücher.example/', 'https:///path',
], 'reject');
field('contact', '/contact', ['mailto:security@example.com', 'mailto:a.b+c_d-e@x-y.example.org', `mailto:x@${a63}.com`, 'https://example.com/security'], 'accept');
field('contact', '/contact', [`mailto:x@${a64}.com`, 'mailto:a@b', 'mailto:a@-b.com', 'mailto:a@b-.com', 'mailto:@b.com', 'mailto:a b@c.com', 'mailto:a@b.com?subject=x', 'mailto:"a"@b.com', 'MAILTO:a@b.com', 'https://a.com'], 'reject');
field('domain', '/key/domain', ['example.com', 'a-b.example.com', `${a63}.com`, 'xn--bcher-kva.example'], 'accept');
field('domain', '/key/domain', ['Example.com', `${a64}.com`, '1.2.3.4', 'example.123', 'localhost', 'github.io', 'foo.github.io', '-a.com', 'a-.com', 'a..com', 'example.com.', '_dmarc.example.com'], 'reject');
field('version', '/version', ['1.0.0', '1.0.0+build:7', 'latest', astral.repeat(255), 'é'], 'accept');
field('version', '/version', ['', astral.repeat(256), '1.0.0\u0085', '1.0.0\u202e', '1.0.0\u200b', '1.0.0\ufeff', '1.0.0\u00ad', '1.0.0\u{e0041}', '1.0.0\u2028', '1.0.0\u0007', '1.0.0\ud800'], 'reject');
// Invisible characters outside Cf: variation selectors (which can carry hidden
// bytes), Hangul fillers and other default ignorable code points, private use,
// a noncharacter, and a code point unassigned in every Unicode version so far.
field('version', '/version', ['1.0.0\ufe0f', '1.0.0\u{e0100}', '1.0.0\u3164', '1.0.0\u115f', '1.0.0\uffa0', '1.0.0\u034f', '1.0.0\u180b', '1.0.0\ufff0', '1.0.0\u{e0fff}', '1.0.0\ue000', '1.0.0\uffff', '1.0.0\u0378'], 'reject');
field('time', '/issuedAt', ['2026-11-18T10:00:00Z', '2024-02-29T00:00:00Z'], 'accept');
field('time', '/issuedAt', ['2016-12-31T23:59:60Z', '2026-02-30T00:00:00Z', '2025-02-29T00:00:00Z', '2026-11-18T24:00:00Z', '2026-11-18T10:00:00.000Z', '2026-11-18T10:00:00+00:00', '2026-11-18t10:00:00z', '2026-11-18 10:00:00Z'], 'reject');
field('amount', '/payment/0/amount', ['0', '1', '9'.repeat(78)], 'accept');
field('amount', '/payment/0/amount', ['01', '1.0', '1e3', '9'.repeat(79), '-1', '', ' 1'], 'reject');
field('network', '/payment/0/network', ['eip155:8453', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'], 'accept');
field('network', '/payment/0/network', ['EIP155:8453', 'eip155', 'eip155:', 'ab:1'], 'reject');
field('name', '/name', ['com.example/weather', 'com.example/...', 'com.example/a.b_c-d'], 'accept');
field('name', '/name', ['com.example/..', 'com.example/.', '../weather', 'com.example', 'com.example/a/b', 'com.example/a b'], 'reject');
field('asset', '/payment/0/asset', ['0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'USDC', 'usd'], 'accept');
field('asset', '/payment/0/asset', ['USD', 'EUR', '0x 1', ''], 'reject');
field('tool', '/payment/0/tool', ['get_forecast', 'get.forecast'], 'accept');
field('tool', '/payment/0/tool', ['', 'get\u200b', 'get\u001b[2K', 'x'.repeat(129), 'get\u3164weather', 'get_forecast\ufe0f', 'get_forecast\u{e0100}'], 'reject');

// Signature text forms, built from the ed25519 vector's own signature.
const sigCases = (() => {
  const sig = JSON.parse(files['ed25519-valid.json']).signature; // 88 characters ending in "=="
  const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const last = ALPH.indexOf(sig[85]);
  const looseBits = sig.slice(0, 85) + ALPH[last ^ 1] + '==';
  return [
    { value: looseBits, why: 'nonzero padding bits' },
    { value: sig.slice(0, 86), why: 'padding removed' },
    { value: sig.slice(0, 44) + '\n' + sig.slice(44), why: 'line break' },
    { value: sig.replace(/\+/g, '-').replace(/\//g, '_'), why: 'base64url alphabet', skipIfSame: true },
  ];
})();
for (const c of sigCases) {
  if (c.skipIfSame && c.value === JSON.parse(files['ed25519-valid.json']).signature) continue;
  fields.push({ id: `signature/${fields.length}`, rule: 'signature', pointer: '/signature', value: c.value, expect: 'reject', note: c.why });
}

// Tools hash vectors: the cases where JSON and JCS implementations differ.
// "inputs" is one file per tools/list page, in order. A rejection names the
// rule that refuses it ("reason"); a verifier in another language can map its
// own errors to these codes.
const toolCases = [];
const tool = (id, pages, reason) => {
  const list = Array.isArray(pages) ? pages : [pages];
  const names = list.map((t, n) => put(list.length === 1 ? `tools-${id}.json` : `tools-${id}-page${n + 1}.json`, t));
  let expect;
  try {
    expect = { toolsHash: toolsHashFromPages(list) };
    if (reason) throw new Error(`tools vector ${id} was expected to be refused (${reason})`);
  } catch (e) {
    if (!e.reason) throw e;
    if (e.reason !== reason) throw new Error(`tools vector ${id}: refused for ${e.reason}, expected ${reason}`);
    expect = { error: true, reason };
  }
  toolCases.push({ id, ...(names.length === 1 ? { input: names[0] } : { inputs: names }), expect });
};
const bmpHigh = String.fromCharCode(0xfb33);
tool('sort-astral-before-high-bmp', JSON.stringify([{ name: bmpHigh }, { name: astral }]));
tool('number-forms', '[{"name":"n","inputSchema":{"a":1E2,"b":-0,"c":0.000001,"d":1e21,"e":1.5e-7}}]');
tool('number-forms-same', '[{"name":"n","inputSchema":{"a":100,"b":0,"c":1e-6,"d":10e20,"e":0.00000015}}]');
tool('integer-beyond-2-53', '[{"name":"n","inputSchema":{"maximum":9007199254740993}}]', 'range');
tool('uint64-max', '[{"name":"n","inputSchema":{"maximum":18446744073709551615}}]', 'range');
tool('uint64-max-as-double', '[{"name":"n","inputSchema":{"maximum":1.8446744073709552e19}}]');
tool('underflow', '[{"name":"n","inputSchema":{"minimum":1e-400}}]', 'underflow');
tool('jsonrpc-wrapper', JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: TOOLS, nextCursor: 'x' } }));
tool('ambiguous-wrapper', JSON.stringify({ jsonrpc: '2.0', id: 1, tools: [], result: { tools: TOOLS } }), 'ambiguous');
tool('duplicate-name', '[{"name":"a"},{"name":"a"}]', 'duplicate-name');
tool('duplicate-member', '[{"name":"a","x":1,"x":2}]', 'duplicate-member');
tool('invalid-utf8', Buffer.from([0x5b, 0x7b, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d, 0x5d]), 'encoding');
tool('bom', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(TOOLS))]));
tool('depth-64', '[{"name":"n","s":' + '['.repeat(62) + ']'.repeat(62) + '}]');
tool('depth-65', '[{"name":"n","s":' + '['.repeat(63) + ']'.repeat(63) + '}]', 'depth');
// The nesting limit is counted from each page's tools array (SPEC.md section 4):
// 64 levels of tools inside a JSON-RPC wrapper are accepted and 65 refused, and
// members next to the tools array are not limited by the 64 level rule.
const nest = (levels) => '['.repeat(levels) + ']'.repeat(levels);
tool('jsonrpc-depth-64', '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"n","s":' + nest(62) + '}]}}');
tool('jsonrpc-depth-65', '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"n","s":' + nest(63) + '}]}}', 'depth');
tool('deep-sibling-meta', '{"tools":[{"name":"n"}],"_meta":{"x":' + nest(65) + '}}');
tool('deep-sibling-cursor', '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"n"}],"nextCursor":' + nest(65) + '}}');
tool('paged', [JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [TOOLS[0]], nextCursor: 'c' } }), JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: [TOOLS[1]] } })]);
tool('paged-duplicate-across-pages', [JSON.stringify([TOOLS[0]]), JSON.stringify([TOOLS[0]])], 'duplicate-name');
tool('empty', '[]');

for (const name of fs.readdirSync(DIR)) if (name.endsWith('.json') && !Object.hasOwn(files, name)) fs.rmSync(path.join(DIR, name));
for (const [name, value] of Object.entries(files)) fs.writeFileSync(path.join(DIR, name), value);
// jsonOut writes the unusual characters in the field values as \u escapes.
fs.writeFileSync(path.join(DIR, 'manifest.json'), jsonOut({ spec: SPEC_ID, generated: new Date().toISOString().slice(0, 10), declarations: cases, fields, tools: toolCases }) + '\n');
console.log(`wrote ${cases.length} declaration vectors, ${fields.length} field vectors and ${toolCases.length} tools vectors`);
