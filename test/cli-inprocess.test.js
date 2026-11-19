// CLI tests that call main() in this process, with fake key lookups in place of
// DNS and HTTP. Nothing here uses the network.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { main, esc } from '../lib/cli.js';
import { toolsHash } from '../lib/tools.js';
import { makeKey, TOOLS, baseUnsigned, signRaw } from '../testlib/helpers.js';
import { signDeclaration } from '../lib/declaration.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-inproc-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
const f = (name) => path.join(tmp, name);
function write(name, value) {
  fs.writeFileSync(f(name), typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value, null, 2));
  return f(name);
}

const ESC = String.fromCharCode(27);
const LF = String.fromCharCode(10);
const k = makeKey('ed25519');
const NOW = '2026-11-18T12:00:00Z';

async function cli(args, { env = {}, deps } = {}) {
  let stdout = '';
  let stderr = '';
  const code = await main(args, { stdout: { write: (s) => (stdout += s) }, stderr: { write: (s) => (stderr += s) }, env, deps });
  return { code, stdout, stderr };
}

// Fake lookups that record which method and resolver were used.
function fakeDeps(result) {
  const calls = [];
  return {
    calls,
    deps: {
      dnsResolverFor: (server) => ({ server }),
      keysFromDns: async (domain, { resolver }) => (calls.push(['dns', domain, resolver.server]), result),
      keysFromHttp: async (domain) => (calls.push(['http', domain]), result),
    },
  };
}

const tools = write('tools.json', TOOLS);
const signedDns = write('dns.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS) }), k.loaded));
const signedHttp = write('http.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), key: { method: 'http', domain: 'example.com' } }), k.loaded));

test('verify output cannot be steered by escape sequences in the file', async () => {
  const name = ESC + '[1A' + ESC + '[2K' + String.fromCharCode(13) + 'valid: com.good/weather 1.0.0' + LF + '  checked: signature' + ESC + '[8m';
  const evil = write('evil.json', JSON.stringify({ [name]: 1 }));
  const r = await cli(['verify', evil, '--pubkey', k.record]);
  assert.equal(r.code, 2);
  assert.ok(!r.stdout.includes(ESC), 'no raw ESC byte reaches the terminal');
  assert.ok(r.stdout.split(LF).every((l) => !l.startsWith('valid') && !l.startsWith('  checked')), r.stdout);
  assert.match(r.stdout, /^malformed/);
  // Same for messages on stderr (a tools file with a duplicate member name).
  const JE = String.fromCharCode(92) + 'u001b'; // the JSON escape for ESC
  const t = write('evil-tools.json', '{"' + JE + '[2K":1,"' + JE + '[2K":2}');
  const h = await cli(['hash-tools', t]);
  assert.equal(h.code, 1);
  assert.ok(!h.stderr.includes(ESC));
  assert.match(h.stderr, /u001b/);
  // C1 and bidirectional controls are escaped too.
  const BSL = String.fromCharCode(92);
  assert.equal(esc('a' + String.fromCharCode(0x9b) + String.fromCharCode(0x202e) + 'b'), 'a' + BSL + 'u009b' + BSL + 'u202eb');
});

test('sign: the key value is not echoed when passed in place of a name or path', async () => {
  const unsigned = write('u.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  for (const flag of ['--key-env', '--key-file']) {
    const r = await cli(['sign', unsigned, flag, k.hex]);
    assert.equal(r.code, 1, flag);
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s), `${flag} leaked the key`);
  }
  const env = await cli(['sign', unsigned, '--key-env', k.hex]);
  assert.match(env.stderr, /--key-env takes the NAME of an environment variable, not the key itself/);
  const pemAsName = await cli(['sign', unsigned, '--key-env', k.pem]);
  assert.match(pemAsName.stderr, /takes the NAME/);
  assert.ok(!pemAsName.stderr.includes(k.secretStrings[0]));
  const file = await cli(['sign', unsigned, '--key-file', k.hex]);
  assert.match(file.stderr, /cannot read the file given to --key-file \(ENOENT\)/);
});

test('sign: specific private key problems reach the publisher', async () => {
  const unsigned = write('u2.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const enc = crypto.generateKeyPairSync('ed25519', { privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'test only' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
  const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const cases = [
    [enc.privateKey, /encrypted private keys are not supported/],
    [p256, /neither Ed25519 nor ECDSA P-384/],
    [enc.publicKey, /this is a public key/],
    ['ab'.repeat(36), /hex private key has 72 digits/],
  ];
  for (const [text, re] of cases) {
    const r = await cli(['sign', unsigned, '--key-file', write('bad.key', text)]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, re);
  }
  const utf16 = await cli(['sign', unsigned, '--key-file', write('k16.key', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(k.hex, 'utf16le')]))]);
  assert.match(utf16.stderr, /UTF-16/);
  const ok = await cli(['sign', unsigned, '--key-env', 'MY_KEY'], { env: { MY_KEY: k.hex } });
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stderr, /by-hash\/[0-9a-f]{64}[.]json/);
  assert.match(ok.stderr, /v=ADKv1; k=ed25519/);
});

test('init: refuses what verify would reject, and names the flag to fix', async () => {
  const base = ['init', '--version', '1.0.0', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  const http = await cli([...base, '--name', 'com.example.api/weather', '--method', 'http', '--domain', 'example.com']);
  assert.equal(http.code, 1);
  assert.match(http.stderr, /works only with the dns method/);
  const okDns = await cli([...base, '--name', 'com.example.api/weather', '--domain', 'example.com']);
  assert.equal(okDns.code, 0, okDns.stderr);
  const gh = await cli([...base, '--name', 'io.github.alice/weather']);
  assert.match(gh.stderr, /GitHub account namespaces/);
  const noContact = await cli(['init', '--format', '0.1', '--name', 'com.example/weather', '--version', '1.0.0', '--tools', tools]);
  assert.equal(noContact.code, 1);
  assert.match(noContact.stderr, /give --contact/);
  // In format 0.2 (the default) contact is optional.
  const noContact02 = await cli(['init', '--name', 'com.example/weather', '--version', '1.0.0', '--tools', tools, '--issued-at', NOW]);
  assert.equal(noContact02.code, 0, noContact02.stderr);
  assert.equal(JSON.parse(noContact02.stdout).contact, undefined);
  // (base already has --issued-at; a flag given twice is refused, so it is replaced here)
  const badTime = await cli([...base.slice(0, -2), '--name', 'com.example/weather', '--issued-at', '2026-11-18 12:00']);
  assert.match(badTime.stderr, /--issued-at must be/);
  // --tools-hash, --name/--version over server.json, and an array payment file
  const sj = write('sj.json', { name: 'com.example/old', version: '0.1.0', remotes: [{ type: 'sse', url: 'https://mcp.example.com/sse' }] });
  const pay = write('pay.json', [{ network: 'eip155:8453', asset: '0xabc', payTo: '0xdef', amount: '1' }, { network: 'eip155:1', asset: '0xabc', payTo: '0xdef', amount: '2' }]);
  const out = await cli(['init', '--format', '0.1', '--server-json', sj, '--name', 'com.example/weather', '--version', '2.0.0', '--tools-hash', toolsHash(TOOLS), '--contact', 'mailto:a@example.com', '--payment', pay, '--issued-at', NOW]);
  assert.equal(out.code, 0, out.stderr);
  const d = JSON.parse(out.stdout);
  assert.equal(d.name, 'com.example/weather');
  assert.equal(d.version, '2.0.0');
  assert.equal(d.toolsHash, toolsHash(TOOLS));
  assert.equal(d.payment.length, 2);
});

test('init: server.json remote templates and http URLs are refused', async () => {
  const base = ['init', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  const tpl = write('tpl.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'streamable-http', url: 'https://{tenant}.example.com/mcp', variables: { tenant: {} } }] });
  const r = await cli([...base, '--server-json', tpl]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /URL template/);
  const plain = write('plain.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'sse', url: 'http://mcp.example.com/sse' }] });
  assert.match((await cli([...base, '--server-json', plain])).stderr, /not an https URL/);
});

test('init --previous and hash-declaration take a signed declaration of the same server', async () => {
  const unsigned = write('prev-unsigned.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const base = ['init', '--name', 'com.example/weather', '--version', '2.0.0', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  const r = await cli([...base, '--previous', unsigned]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /not signed; pass the signed declaration of the previous release/);
  assert.match((await cli(['hash-declaration', unsigned])).stderr, /not signed/);
  const other = write('other.json', signDeclaration(baseUnsigned({ name: 'com.example/other', toolsHash: toolsHash(TOOLS) }), k.loaded));
  assert.match((await cli([...base, '--previous', other])).stderr, /is for "com.example\/other"/);
  const ok = await cli([...base, '--previous', signedDns]);
  assert.equal(ok.code, 0, ok.stderr);
});

test('verify: live lookup uses key.method; --dns/--http must agree; failures exit 10', async () => {
  const found = { keys: [k.loaded.public], notes: [] };
  let x = fakeDeps(found);
  let r = await cli(['verify', signedDns, '--now', NOW, '--tools', tools], { deps: x.deps });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.deepEqual(x.calls, [['dns', 'example.com', undefined]]);
  assert.match(r.stdout, /key source: dns: TXT record at example[.]com/);

  x = fakeDeps(found);
  r = await cli(['verify', signedHttp, '--now', NOW], { deps: x.deps });
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.deepEqual(x.calls, [['http', 'example.com']]);

  x = fakeDeps(found);
  r = await cli(['verify', signedHttp, '--dns', '--now', NOW], { deps: x.deps });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /names key.method "http"/);
  assert.equal(x.calls.length, 0);

  x = fakeDeps(found);
  r = await cli(['verify', signedDns, '--dns', '--dns-server', '192.0.2.53', '--now', NOW], { deps: x.deps });
  assert.equal(r.code, 0);
  assert.deepEqual(x.calls, [['dns', 'example.com', '192.0.2.53']]);

  x = fakeDeps({ keys: [], notes: [], error: 'DNS lookup for example.com failed (ETIMEOUT)' });
  r = await cli(['verify', signedDns, '--now', NOW], { deps: x.deps });
  assert.equal(r.code, 10);
  assert.match(r.stdout, /^key_lookup_failed/);

  x = fakeDeps({ keys: [], notes: ['no TXT records at example.com'] });
  r = await cli(['verify', signedDns, '--now', NOW], { deps: x.deps });
  assert.equal(r.code, 4);
});

test('verify: argument mistakes get specific messages', async () => {
  const typo = await cli(['verify', signedDns, '--pubkey', f('pubkey-typo.txt')]);
  assert.equal(typo.code, 1);
  assert.match(typo.stderr, /public key file not found/);
  const ds = await cli(['verify', signedDns, '--dns-server', 'notanip']);
  assert.equal(ds.code, 1);
  assert.match(ds.stderr, /--dns-server must be an IP address/);
  assert.ok(!ds.stderr.includes('unexpected error'));
});

test('verify: an invalid received tool list gives tools_hash_mismatch, not a usage error', async () => {
  const dup = write('dup-tools.json', '[{"name":"a"},{"name":"a"}]');
  const r = await cli(['verify', signedDns, '--pubkey', k.record, '--tools', dup, '--now', NOW]);
  assert.equal(r.code, 8);
  assert.match(r.stdout, /received tool list is invalid/);
});

test('files saved as UTF-16 get a message that names the cause', async () => {
  const t16 = write('tools16.json', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(JSON.stringify(TOOLS), 'utf16le')]));
  const r = await cli(['hash-tools', t16]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /UTF-16.*Out-File -Encoding utf8/);
  const d16 = write('decl16.json', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(fs.readFileSync(signedDns, 'utf8'), 'utf16le')]));
  const v = await cli(['verify', d16, '--pubkey', k.record, '--now', NOW]);
  assert.equal(v.code, 2);
  assert.match(v.stdout, /UTF-16/);
  // UTF-8 with a byte order mark and CRLF line ends still work.
  const crlf = write('crlf.json', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(fs.readFileSync(signedDns, 'utf8').split(LF).join(String.fromCharCode(13) + LF))]));
  assert.equal((await cli(['verify', crlf, '--pubkey', k.record, '--now', NOW])).code, 0);
});

test('verify of a namespace mismatch signed outside the CLI', async () => {
  const d = write('mm.json', signRaw(baseUnsigned({ toolsHash: toolsHash(TOOLS), key: { method: 'dns', domain: 'example.org' } }), k.loaded));
  const r = await cli(['verify', d, '--pubkey', k.record, '--now', NOW]);
  assert.equal(r.code, 7);
});

// Review round 2 (18 November 2026).

test('verify --json escapes C1, bidi, separator, format and tag characters and stays valid JSON', async () => {
  const BSL = String.fromCharCode(92);
  const bad = [0x9b, 0x202e, 0x2028, 0x200b, 0xfeff, 0xe0041].map((c) => String.fromCodePoint(c));
  const name = bad[0] + '2K' + bad[1] + 'valid' + bad[2] + bad[3] + bad[4] + bad[5];
  const evil = write('evil-json.json', JSON.stringify({ [name]: 1 }));
  const r = await cli(['verify', evil, '--pubkey', k.record, '--json']);
  assert.equal(r.code, 2);
  for (const c of bad) assert.ok(!r.stdout.includes(c), `raw U+${c.codePointAt(0).toString(16)} in --json output`);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.state, 'malformed');
  assert.ok(parsed.reasons.some((x) => x.includes(name)), 'the escapes decode back to the same text');
  const text = await cli(['verify', evil, '--pubkey', k.record]);
  for (const c of bad) assert.ok(!text.stdout.includes(c));
  assert.ok(text.stdout.includes(BSL + 'udb40' + BSL + 'udc41'), 'a tag character is escaped as its two UTF-16 units');
  assert.equal(esc('1.0.0' + String.fromCharCode(0x200b)), '1.0.0' + BSL + 'u200b');
});

test('argument values that look like a key are not echoed from any path', async () => {
  const unsigned = write('u-leak.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const pub = write('pub-leak.txt', k.record);
  const cases = [
    ['verify', signedDns, '--pubkey', k.hex],
    ['sign', unsigned, '--private-key=' + k.hex],
    ['sign', unsigned, '--private-key', k.hex],
    ['verify', signedDns, '--pubkey', pub, '--tools', k.hex],
    ['hash-tools', k.hex],
    ['sign', k.hex, '--key-file', pub],
    [k.hex],
  ];
  for (const args of cases) {
    const r = await cli(args);
    assert.equal(r.code, 1, args.join(' ').slice(0, 40));
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s), `leaked by: ${args[0]} ${args[2] || ''}`);
  }
  assert.match((await cli(['sign', unsigned, '--private-key=' + k.hex])).stderr, /unknown option --private-key$/m);
  assert.match((await cli(['verify', signedDns, '--pubkey', k.hex])).stderr, /value hidden/);
});

test('publisher mistakes get a message that says what to do', async () => {
  const unsigned = write('u-msg.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const keyFile = write('msg.key.pem', k.pem);
  const out = await cli(['sign', unsigned, '--key-file', keyFile, '--out', f('no-such-dir/declaration.json')]);
  assert.equal(out.code, 1);
  assert.match(out.stderr, /cannot write --out .*\(ENOENT\); does the folder exist\?/);
  assert.ok(!out.stderr.includes('unexpected error'));
  // --flag=value works like --flag value.
  const eqEnv = await cli(['sign', unsigned, '--key-env=MY_KEY'], { env: { MY_KEY: k.hex } });
  assert.equal(eqEnv.code, 0, eqEnv.stderr);
  const eqFile = await cli(['sign', unsigned, '--key-file=' + keyFile]);
  assert.equal(eqFile.code, 0, eqFile.stderr);
  assert.match((await cli(['verify', signedDns, '--json=yes'])).stderr, /--json takes no value/);
  // verify on the unsigned file says so.
  const v = await cli(['verify', unsigned, '--pubkey', k.record]);
  assert.equal(v.code, 2);
  assert.match(v.stdout, /looks unsigned .*run sign on it first/);
  // Broken inputs are usage errors with the file named.
  const brokenJson = write('broken.json', '{"name":');
  const base = ['init', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  assert.match((await cli([...base, '--server-json', brokenJson])).stderr, /server\.json .*broken\.json is not valid JSON/);
  assert.match((await cli([...base, '--name', 'com.example/weather', '--version', '1.0.0', '--payment', brokenJson])).stderr, /payment file .*broken\.json is not valid JSON/);
  assert.match((await cli(['sign', brokenJson, '--key-file', keyFile])).stderr, /declaration .*broken\.json: unexpected end of input/);
  const noKey = write('nokey.txt', 'hello');
  assert.match((await cli(['verify', signedDns, '--pubkey', noKey])).stderr, /--pubkey: no usable MCPv1 or ADKv1 proof record or PEM public key found/);
});

test('init: a bare origin or other plain non canonical remote is declared in canonical form, with a note', async () => {
  const base = ['init', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  for (const [given, want] of [
    ['https://mcp.example.com', 'https://mcp.example.com/'],
    ['https://MCP.Example.com/mcp', 'https://mcp.example.com/mcp'],
    ['https://mcp.example.com:443/mcp', 'https://mcp.example.com/mcp'],
    ['https://mcp.example.com?x=1', 'https://mcp.example.com/?x=1'],
  ]) {
    const sj = write('sj-bare.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'streamable-http', url: given }] });
    const r = await cli([...base, '--server-json', sj]);
    assert.equal(r.code, 0, `${given}: ${r.stderr}`);
    assert.equal(JSON.parse(r.stdout).remotes[0].url, want);
    assert.match(r.stderr, /declared in its canonical form/);
  }
  // Other parser fixups change what the URL means to some parsers, so they are refused,
  // and the message names the canonical form instead of telling the publisher to drop remotes.
  for (const given of ['https://mcp.example.com/a/%2e%2e/b', "https://mcp.example.com/?x='"]) {
    const sj = write('sj-fix.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'streamable-http', url: given }] });
    const r = await cli([...base, '--server-json', sj]);
    assert.equal(r.code, 1, given);
    assert.match(r.stderr, /not in canonical form; write it in server\.json as https:\/\/mcp\.example\.com\//);
    assert.ok(!/instead of --server-json/.test(r.stderr), r.stderr);
  }
});

test('tools pages: hash-tools and --tools take one file per page, in order', async () => {
  const [t1, t2] = TOOLS.tools;
  const p1 = write('page1.json', { jsonrpc: '2.0', id: 1, result: { tools: [t1], nextCursor: 'c' } });
  const p2 = write('page2.json', { tools: [t2] });
  const joined = await cli(['hash-tools', p1, p2]);
  assert.equal(joined.code, 0, joined.stderr);
  assert.equal(joined.stdout.trim(), toolsHash(TOOLS));
  assert.notEqual((await cli(['hash-tools', p1])).stdout.trim(), toolsHash(TOOLS));
  const v = await cli(['verify', signedDns, '--pubkey', k.record, '--tools', p1, '--tools', p2, '--now', NOW]);
  assert.equal(v.code, 0, v.stdout + v.stderr);
  const dupPage = write('page-dup.json', [t1]);
  const dup = await cli(['hash-tools', p1, dupPage]);
  assert.equal(dup.code, 1);
  assert.match(dup.stderr, /duplicate tool name/);
});

test('verify text output names a key change across a chain link', async () => {
  const other = makeKey('ed25519');
  const old = write('old-chain.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), version: '1.0.0', issuedAt: '2026-10-01T00:00:00Z' }), k.loaded));
  const prevHash = (await cli(['hash-declaration', old])).stdout.trim();
  const newer = write('new-chain.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), version: '1.0.1', previous: prevHash }), other.loaded));
  const r = await cli(['verify', newer, '--pubkey', other.record, '--previous', old, '--now', NOW]);
  assert.equal(r.code, 0, r.stdout);
  assert.match(r.stdout, /note: key changed between the two declarations/);
  assert.match(r.stdout, /not checked: signature of previous declaration/);
  const j = JSON.parse((await cli(['verify', newer, '--pubkey', other.record, '--previous', old, '--now', NOW, '--json'])).stdout);
  assert.match(j.notes.join(' '), /key changed/);
});

// Review round 3 (18 November 2026).

test('--out: a value that looks like key material is refused before anything is written, and is not echoed', async () => {
  const unsigned = write('u-out.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const keyFile = write('out.key.pem', k.pem);
  const init = ['init', '--name', 'com.example/weather', '--version', '1.0.0', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  const before = new Set(fs.readdirSync(tmp));
  const cases = [
    [...init, '--out', k.hex],
    [...init, '--out', f(k.hex)],
    [...init, '--out=' + k.hex],
    ['sign', unsigned, '--key-file', keyFile, '--out', k.hex],
    ['sign', unsigned, '--key-env', 'MY_KEY', '--out', f(k.hex + '.json')],
    ['sign', unsigned, '--key-file', keyFile, '--out', k.pem],
    init.map((x, n) => (init[n - 1] === '--version' ? k.hex : x)),
  ];
  for (const args of cases) {
    const r = await cli(args, { env: { MY_KEY: k.hex } });
    assert.equal(r.code, 1, `${args[0]} ${args.slice(-2).join(' ').slice(0, 20)}: ${r.stderr}`);
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s), `leaked by ${args[0]}`);
    assert.match(r.stderr, /looks like key material/);
  }
  const after = fs.readdirSync(tmp).filter((n) => !before.has(n));
  assert.deepEqual(after, [], 'no file was created');
  for (const n of fs.readdirSync(tmp)) for (const s of k.secretStrings) assert.ok(!n.includes(s), `a file is named after the key: ${n}`);
  // An ordinary --out path is still written and named in the message.
  const ok = await cli(['sign', unsigned, '--key-file', keyFile, '--out', f('ok-out.json')]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.ok(ok.stderr.includes('wrote ' + f('ok-out.json')));
});

test('init: a server.json remote with userinfo is refused without repeating the URL, and the advice does not loop', async () => {
  const base = ['init', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  for (const url of ['https://user:S3cretPassw0rd@mcp.example.com', 'https://user:S3cretPassw0rd@mcp.example.com/', 'https://S3cretPassw0rd@mcp.example.com/mcp', 'HTTPS://user:S3cretPassw0rd@MCP.example.com']) {
    const sj = write('sj-userinfo.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'streamable-http', url }] });
    const r = await cli([...base, '--server-json', sj]);
    assert.equal(r.code, 1, url);
    assert.ok(!r.stderr.includes('S3cretPassw0rd'), `the password is repeated for ${url}`);
    assert.match(r.stderr, /carries a user name or password/);
    assert.ok(!/write it in server\.json as/.test(r.stderr), 'no hint that points back at a URL with userinfo');
  }
});

test('init: an uppercase https scheme is declared in canonical form, like an uppercase host', async () => {
  const base = ['init', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  for (const [given, want] of [['HTTPS://mcp.example.com/mcp', 'https://mcp.example.com/mcp'], ['Https://MCP.example.com', 'https://mcp.example.com/']]) {
    const sj = write('sj-scheme.json', { name: 'com.example/weather', version: '1.0.0', remotes: [{ type: 'streamable-http', url: given }] });
    const r = await cli([...base, '--server-json', sj]);
    assert.equal(r.code, 0, `${given}: ${r.stderr}`);
    assert.equal(JSON.parse(r.stdout).remotes[0].url, want);
    assert.match(r.stderr, /declared in its canonical form/);
  }
});

test('an option given to a command that does not take it is a usage error', async () => {
  const unsigned = write('u-flags.json', baseUnsigned({ toolsHash: toolsHash(TOOLS) }));
  const keyFile = write('flags.key.pem', k.pem);
  const r = await cli(['sign', unsigned, '--tools', keyFile, '--out', f('flags-out.json')]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /--tools is not an option of sign/);
  assert.ok(!fs.existsSync(f('flags-out.json')));
  const v = await cli(['verify', signedDns, '--pubkey', k.record, '--expires-in-days', '5']);
  assert.equal(v.code, 1);
  assert.match(v.stderr, /--expires-in-days is not an option of verify/);
  assert.match((await cli(['hash-tools', tools, '--json'])).stderr, /--json is not an option of hash-tools/);
  assert.equal((await cli(['verify', '--help'])).code, 0);
});

test('verify --json: a link across a key change carries chain.keyChanged, and the checked entry does not read as continuity', async () => {
  const other = makeKey('ed25519');
  const old = write('old-chain-j.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), version: '1.0.0', issuedAt: '2026-10-01T00:00:00Z' }), k.loaded));
  const prevHash = (await cli(['hash-declaration', old])).stdout.trim();
  const newer = write('new-chain-j.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), version: '1.0.1', previous: prevHash }), other.loaded));
  const j = JSON.parse((await cli(['verify', newer, '--pubkey', other.record, '--previous', old, '--now', NOW, '--json'])).stdout);
  assert.equal(j.state, 'valid');
  assert.equal(j.chain.keyChanged, true);
  assert.equal(j.chain.previousSignature, 'not_checked');
  assert.deepEqual(j.chain.previousKey, { method: 'dns', domain: 'example.com', alg: 'ed25519', id: k.loaded.public.id });
  assert.ok(!j.checked.includes('chain link to previous declaration'));
  assert.ok(j.checked.some((c) => /key changed/.test(c)));
  // Both keys given (a file with both records): the earlier signature is checked.
  const both = write('both-keys.txt', other.record + '\n' + k.record + '\n');
  const j2 = JSON.parse((await cli(['verify', newer, '--pubkey', both, '--previous', old, '--now', NOW, '--json'])).stdout);
  assert.equal(j2.state, 'valid');
  assert.equal(j2.chain.previousSignature, 'checked');
  // Same key: chain.keyChanged is false.
  const same = write('same-chain-j.json', signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), version: '1.0.1', previous: prevHash }), k.loaded));
  const j3 = JSON.parse((await cli(['verify', same, '--pubkey', k.record, '--previous', old, '--now', NOW, '--json'])).stdout);
  assert.equal(j3.chain.keyChanged, false);
  assert.ok(j3.checked.includes('chain link to previous declaration'));
});

test('hash-tools: a page saved as server sent events gets a message about the framing', async () => {
  const sse = write('sse-page.txt', 'event: message\ndata: ' + JSON.stringify({ jsonrpc: '2.0', id: 1, result: TOOLS }) + '\n\n');
  const r = await cli(['hash-tools', sse]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /server sent events: remove the framing/);
});

// Final check (18 November 2026): private key text as a bare argument, and a key inside a longer --out name.
test('private key PEM given as a bare argument is refused and not echoed, for every command', async () => {
  for (const args of [['sign', k.pem, '--key-env', 'K'], ['verify', k.pem], ['hash-tools', k.pem], ['verify', '--json', k.pem], ['hash-declaration', k.pem], ['init', k.pem]]) {
    const r = await cli(args);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /private key text/);
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s), `leaked by ${args[0]}`);
  }
});

test('--out: a key inside a longer file name is refused and no file is created', async () => {
  const init = ['init', '--name', 'com.example/weather', '--version', '1.0.0', '--tools', tools, '--contact', 'mailto:a@example.com', '--issued-at', NOW];
  const before = new Set(fs.readdirSync(tmp));
  for (const name of ['key-' + k.hex + '.json', k.hex + '.signed.json', k.hex + '_out', k.hex.toUpperCase() + '.signed.json']) {
    const r = await cli([...init, '--out', f(name)]);
    assert.equal(r.code, 1, r.stderr);
    assert.match(r.stderr, /looks like key material/);
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s));
  }
  assert.deepEqual(fs.readdirSync(tmp).filter((n) => !before.has(n)), []);
});
