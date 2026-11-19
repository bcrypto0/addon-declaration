// End to end tests of the CLI. Every verify call passes --pubkey, so nothing
// here uses the network.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeKey, TOOLS, signRaw } from '../testlib/helpers.js';
import { toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';

const BIN = fileURLToPath(new URL('../bin/addon-declare.js', import.meta.url));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-test-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const seen = []; // every byte of output, checked for key material at the end

function run(args, env = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd: tmp, env: { ...process.env, ...env }, encoding: 'utf8' });
  seen.push(r.stdout, r.stderr);
  return r;
}
const f = (name) => path.join(tmp, name);
function write(name, value) {
  fs.writeFileSync(f(name), typeof value === 'string' ? value : JSON.stringify(value, null, 2));
  return f(name);
}

const keys = { ed25519: makeKey('ed25519'), ecdsap384: makeKey('ecdsap384') };
write('tools.json', { jsonrpc: '2.0', id: 1, result: TOOLS });
write('server.json', {
  name: 'com.example/weather',
  version: '1.4.0',
  remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp', headers: [{ name: 'X-Ignored' }] }],
});
write('payment.json', { network: 'eip155:8453', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0x1111111111111111111111111111111111111111', amount: '10000' });

test('hash-tools prints the tools hash', () => {
  const r = run(['hash-tools', f('tools.json')]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), toolsHash(TOOLS));
});

// Format 0.2 is what init writes by default; 0.1 is still written on request.
for (const [alg0, k] of Object.entries(keys)) for (const fmt of ['0.1', '0.2']) {
  // The 0.2 run keeps the file names the later tests read.
  const alg = fmt === '0.2' ? alg0 : `${alg0}-0.1`;
  test(`${alg0}: format ${fmt}: init, sign (env and file), verify offline with exit codes`, () => {
    const pubFile = write(`${alg}.pub.txt`, k.record + '\n');
    const keyFile = write(`${alg}.key.pem`, k.pem);

    const init = run(['init', '--server-json', f('server.json'), '--tools', f('tools.json'), '--contact', 'mailto:security@example.com',
      '--payment', f('payment.json'), '--issued-at', '2026-11-18T10:00:00Z', '--expires-in-days', '180', '--out', f(`${alg}.unsigned.json`), ...(fmt === '0.1' ? ['--format', '0.1'] : [])]);
    assert.equal(init.status, 0, init.stderr);
    assert.match(init.stderr, fmt === '0.2' ? /^format: addon-declaration\/0[.]2 \(the default/m : /^format: addon-declaration\/0[.]1$/m);
    const unsigned = JSON.parse(fs.readFileSync(f(`${alg}.unsigned.json`), 'utf8'));
    assert.equal(unsigned.spec, `addon-declaration/${fmt}`);
    if (fmt === '0.1') assert.equal(unsigned.toolsHash, toolsHash(TOOLS));
    else {
      const d = toolSetDigestsFromPages([fs.readFileSync(f('tools.json'))]);
      assert.deepEqual(unsigned.toolSetDigest, { spec: 'mcp-tool-set-digest/1', contract: d.contract.digest, extras: d.extras.digest });
      assert.equal(unsigned.toolsHash, undefined);
    }
    assert.deepEqual(unsigned.remotes, [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }]);
    assert.deepEqual(unsigned.key, { method: 'dns', domain: 'example.com' });
    assert.equal(unsigned.expiresAt, '2027-05-17T10:00:00Z');

    const viaEnv = run(['sign', f(`${alg}.unsigned.json`), '--key-env', 'TEST_DECL_KEY', '--out', f(`${alg}.signed.json`)], { TEST_DECL_KEY: k.hex });
    assert.equal(viaEnv.status, 0, viaEnv.stderr);
    assert.match(viaEnv.stderr, new RegExp(k.record.replace(/[+/=]/g, (c) => '\\' + c)));
    seen.push(fs.readFileSync(f(`${alg}.signed.json`), 'utf8'));

    const viaFile = run(['sign', f(`${alg}.unsigned.json`), '--key-file', keyFile]);
    assert.equal(viaFile.status, 0, viaFile.stderr);
    const fromFile = JSON.parse(viaFile.stdout);
    assert.equal(fromFile.key.id, k.loaded.public.id);

    const ok = run(['verify', f(`${alg}.signed.json`), '--pubkey', pubFile, '--tools', f('tools.json'), '--now', '2026-11-18T12:00:00Z']);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /^valid: com\.example\/weather 1\.4\.0/);
    assert.match(ok.stdout, new RegExp(`^  format: addon-declaration/${fmt.replace('.', '[.]')}$`, 'm'));
    assert.match(ok.stdout, fmt === '0.2' ? /checked: tool set digest \(mcp-tool-set-digest\/1\): contract and extras/ : /checked: tools hash/);
    assert.match(ok.stdout, /publication at the domain was not checked/);

    const inline = run(['verify', f(`${alg}.signed.json`), '--pubkey', k.record, '--now', '2026-11-18T12:00:00Z', '--json']);
    assert.equal(inline.status, 0);
    assert.equal(JSON.parse(inline.stdout).state, 'valid');

    const expired = run(['verify', f(`${alg}.signed.json`), '--pubkey', pubFile, '--now', '2028-01-01T00:00:00Z']);
    assert.equal(expired.status, 5);

    const early = run(['verify', f(`${alg}.signed.json`), '--pubkey', pubFile, '--now', '2026-01-01T00:00:00Z']);
    assert.equal(early.status, 6);

    const wrongKey = run(['verify', f(`${alg}.signed.json`), '--pubkey', makeKey(alg).record, '--now', '2026-11-18T12:00:00Z']);
    assert.equal(wrongKey.status, 4);

    const tampered = JSON.parse(fs.readFileSync(f(`${alg}.signed.json`), 'utf8'));
    tampered.payment[0].payTo = '0x2222222222222222222222222222222222222222';
    write(`${alg}.tampered.json`, tampered);
    const bad = run(['verify', f(`${alg}.tampered.json`), '--pubkey', pubFile, '--now', '2026-11-18T12:00:00Z']);
    assert.equal(bad.status, 3);
    assert.match(bad.stdout, /^invalid_signature/);

    const otherTools = write('tools-changed.json', { tools: [{ name: 'x', inputSchema: { type: 'object' } }] });
    const tm = run(['verify', f(`${alg}.signed.json`), '--pubkey', pubFile, '--tools', otherTools, '--now', '2026-11-18T12:00:00Z']);
    assert.equal(tm.status, 8);

    const mismatch = JSON.parse(fs.readFileSync(f(`${alg}.unsigned.json`), 'utf8'));
    mismatch.key.domain = 'example.org';
    write(`${alg}.mismatch.unsigned.json`, mismatch);
    // sign refuses a key domain that cannot prove the name...
    const refused = run(['sign', f(`${alg}.mismatch.unsigned.json`), '--key-file', keyFile, '--out', f(`${alg}.mismatch.json`)]);
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /not covered by a dns key at example[.]org/);
    // ...and a file signed some other way is reported by verify.
    write(`${alg}.mismatch.json`, signRaw(mismatch, k.loaded));
    const mm = run(['verify', f(`${alg}.mismatch.json`), '--pubkey', pubFile, '--now', '2026-11-18T12:00:00Z']);
    assert.equal(mm.status, 7);

    write(`${alg}.malformed.json`, '{"spec":');
    assert.equal(run(['verify', f(`${alg}.malformed.json`), '--pubkey', pubFile]).status, 2);
  });
}

test('chain: init --previous links to the earlier declaration', () => {
  const k = keys.ed25519;
  const pub = write('chain.pub.txt', k.record);
  const keyFile = write('chain.key.pem', k.pem);
  run(['init', '--name', 'com.example/weather', '--version', '1.0.0', '--tools', f('tools.json'), '--contact', 'https://example.com/security', '--issued-at', '2026-10-01T00:00:00Z', '--out', f('c1.unsigned.json')]);
  run(['sign', f('c1.unsigned.json'), '--key-file', keyFile, '--out', f('c1.json')]);
  const r1 = run(['init', '--name', 'com.example/weather', '--version', '1.1.0', '--tools', f('tools.json'), '--contact', 'https://example.com/security', '--issued-at', '2026-11-01T00:00:00Z', '--previous', f('c1.json'), '--out', f('c2.unsigned.json')]);
  assert.equal(r1.status, 0, r1.stderr);
  run(['sign', f('c2.unsigned.json'), '--key-file', keyFile, '--out', f('c2.json')]);
  const h1 = run(['hash-declaration', f('c1.json')]).stdout.trim();
  assert.equal(JSON.parse(fs.readFileSync(f('c2.json'), 'utf8')).previous, h1);
  assert.equal(run(['verify', f('c2.json'), '--pubkey', pub, '--previous', f('c1.json'), '--now', '2026-11-18T00:00:00Z']).status, 0);
  assert.equal(run(['verify', f('c1.json'), '--pubkey', pub, '--previous', f('c2.json'), '--now', '2026-11-18T00:00:00Z']).status, 9);
});

test('usage errors exit 1, say which error, and do not echo a bad key', () => {
  const junk = 'deadbeef'.repeat(9); // 36 bytes: not a valid key length
  const r = run(['sign', f('ed25519.unsigned.json'), '--key-env', 'TEST_DECL_KEY'], { TEST_DECL_KEY: junk });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /private key: hex private key has 72 digits/);
  assert.ok(!r.stderr.includes(junk) && !r.stdout.includes(junk));
  const pemJunk = '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBadBadBadBadBadBadBadBadBadBadBadBadBadBa\n-----END PRIVATE KEY-----\n';
  const r2 = run(['sign', f('ed25519.unsigned.json'), '--key-env', 'TEST_DECL_KEY'], { TEST_DECL_KEY: pemJunk });
  assert.equal(r2.status, 1);
  assert.match(r2.stderr, /PEM private key could not be read/);
  assert.ok(!r2.stderr.includes('BadBadBad'));
  const expect = (args, re) => {
    const x = run(args);
    assert.equal(x.status, 1, args.join(' '));
    assert.match(x.stderr, re, args.join(' '));
  };
  expect(['sign', f('ed25519.unsigned.json'), '--key-env', 'NOT_SET_ANYWHERE_123'], /environment variable NOT_SET_ANYWHERE_123 is empty or not set/);
  expect(['verify'], /expected exactly one declaration file/);
  expect(['verify', f('ed25519.signed.json'), '--pubkey', 'x', '--dns'], /at most one of --pubkey, --dns, --http/);
  expect(['frobnicate'], /unknown command frobnicate/);
  expect(['hash-tools', f('does-not-exist.json')], /cannot read tools file .*ENOENT/);
});

test('no private key material appears in any output or written file', () => {
  for (const name of fs.readdirSync(tmp)) {
    if (name.endsWith('.key.pem')) continue; // the key files the test itself wrote
    seen.push(fs.readFileSync(f(name), 'utf8'));
  }
  const all = seen.join('\n');
  assert.ok(all.length > 1000, 'expected the earlier tests to have produced output');
  for (const k of Object.values(keys)) {
    for (const s of k.secretStrings) assert.ok(!all.includes(s), `private key material leaked (${k.alg})`);
  }
});
