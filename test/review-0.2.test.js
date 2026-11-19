// Review of format 0.2 (19 November 2026): one test per finding that changed
// code. Keys are throwaway keys made by each run.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SPEC_ID_01, SPEC_ID_02, signDeclaration, verifyDeclarationText, validate, GITHUB_OUT_OF_SCOPE } from '../lib/declaration.js';
import { toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages, repeatedToolNames } from '../lib/tool-set-digest.js';
import { main, HELP, parseArgs } from '../lib/cli.js';
import { makeKey, TOOLS, NOW, baseUnsigned } from '../testlib/helpers.js';

const k = makeKey('ed25519');
const offline = { kind: 'offline', keys: [k.loaded.public] };
const verify = (d, extra = {}) => verifyDeclarationText(typeof d === 'string' ? d : JSON.stringify(d), { keySource: offline, now: NOW, ...extra });
const digestsOf = (text) => {
  const r = toolSetDigestsFromPages([text]);
  return { spec: 'mcp-tool-set-digest/1', contract: r.contract.digest, extras: r.extras.digest };
};
const TSD = digestsOf(JSON.stringify(TOOLS));
const sign02 = (o = {}) => {
  const u = baseUnsigned({ spec: SPEC_ID_02, toolSetDigest: TSD, ...o });
  delete u.toolsHash;
  return signDeclaration(u, k.loaded);
};
const sign01 = (o = {}) => signDeclaration(baseUnsigned({ toolsHash: toolsHash(TOOLS), ...o }), k.loaded);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-review02-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
const f = (n) => path.join(tmp, n);
const write = (n, v) => (fs.writeFileSync(f(n), typeof v === 'string' ? v : JSON.stringify(v, null, 2)), f(n));
async function cli(args, env = {}) {
  let stdout = '';
  let stderr = '';
  const code = await main(args, { stdout: { write: (s) => (stdout += s) }, stderr: { write: (s) => (stderr += s) }, env });
  return { code, stdout, stderr };
}
const ISO = '2026-11-18T12:00:00Z';
const pub = write('k.pub', k.record + '\n');

// Two tools share a name, and the annotation moves from one to the other.
const S1 = [
  { name: 'f', description: 'Read only view', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true } },
  { name: 'f', description: 'Delete everything', inputSchema: { type: 'object' } },
];
const S2 = [
  { name: 'f', description: 'Read only view', inputSchema: { type: 'object' } },
  { name: 'f', description: 'Delete everything', inputSchema: { type: 'object' }, annotations: { readOnlyHint: true } },
];

test('repeated tool name: the two lists share both digests, and every output reports the name', async () => {
  const a = toolSetDigestsFromPages([JSON.stringify(S1)]);
  const b = toolSetDigestsFromPages([JSON.stringify(S2)]);
  assert.equal(a.contract.digest, b.contract.digest);
  assert.equal(a.extras.digest, b.extras.digest);
  assert.deepEqual(b.repeatedNames, [{ name: 'f', count: 2 }]);
  assert.equal(b.repeatedMembers, 0);
  assert.match(b.notes.join(' '), /tool name "f" appears 2 times; MCP requires unique tool names[\s\S]*not pinned/);
  assert.deepEqual(repeatedToolNames([{ name: 'a' }, { name: 'b' }, { name: 'a' }, 7, { name: 'a' }]), [{ name: 'a', count: 3 }]);
  // verify: still valid (both digests match), with the name in the notes, the checked line and --json.
  const d = sign02({ toolSetDigest: digestsOf(JSON.stringify(S1)) });
  const r = await verify(d, { toolsText: JSON.stringify(S2) });
  assert.equal(r.state, 'valid', r.reasons.join('; '));
  assert.deepEqual(r.details.toolSetDigest.repeatedNames, [{ name: 'f', count: 2 }]);
  assert.match(r.details.checked.join(' '), /repeats a tool name or a member name/);
  const declFile = write('dS1.json', d);
  const s2 = write('S2.json', S2);
  const text = await cli(['verify', declFile, '--pubkey', pub, '--tools', s2, '--now', ISO]);
  assert.equal(text.code, 0);
  assert.match(text.stdout, /note: tool name "f" appears 2 times/);
  const json = JSON.parse((await cli(['verify', declFile, '--pubkey', pub, '--tools', s2, '--now', ISO, '--json'])).stdout);
  assert.deepEqual(json.toolSetDigest.repeatedNames, [{ name: 'f', count: 2 }]);
  // tool-set-digest: a note in text, and repeatedNames in --json.
  const t = await cli(['tool-set-digest', s2]);
  assert.equal(t.code, 0);
  assert.match(t.stdout, /note: tool name "f" appears 2 times/);
  assert.deepEqual(JSON.parse((await cli(['tool-set-digest', s2, '--json'])).stdout).repeatedNames, [{ name: 'f', count: 2 }]);
});

test('repeated tool name: init refuses the list in 0.2 as it does in 0.1', async () => {
  const s1 = write('S1.json', S1);
  const common = ['init', '--name', 'com.example/weather', '--version', '1.0.0', '--issued-at', ISO];
  const r02 = await cli([...common, '--tools', s1]);
  assert.equal(r02.code, 1);
  assert.match(r02.stderr, /tool name "f" appears 2 times/);
  assert.equal(r02.stdout, '');
  const r01 = await cli([...common, '--format', '0.1', '--contact', 'mailto:a@example.com', '--tools', s1]);
  assert.equal(r01.code, 1);
  assert.match(r01.stderr, /duplicate tool name "f"/);
});

test('repeated member name: verify reports it as a count, init refuses it', async () => {
  const dup = '{"tools":[{"name":"a","annotations":{"readOnlyHint":true},"annotations":{"readOnlyHint":false}}]}';
  const last = '{"tools":[{"name":"a","annotations":{"readOnlyHint":false}}]}';
  const d = sign02({ toolSetDigest: digestsOf(last) });
  const r = await verify(d, { toolsText: dup });
  assert.equal(r.state, 'valid', r.reasons.join('; '));
  assert.equal(r.details.toolSetDigest.repeatedMembers, 1);
  assert.match(r.details.toolSetDigest.notes.join(' '), /keeps the first value, or refuses the list, reads other tool definitions/);
  // Under 0.1 the same list is refused.
  assert.equal((await verify(sign01({ toolsHash: toolsHash([{ name: 'a', annotations: { readOnlyHint: false } }]) }), { toolsText: dup })).state, 'tools_hash_mismatch');
  const init = await cli(['init', '--name', 'com.example/weather', '--version', '1.0.0', '--issued-at', ISO, '--tools', write('dup.json', dup)]);
  assert.equal(init.code, 1);
  assert.match(init.stderr, /1 repeated member name in the tools\/list page/);
  const j = JSON.parse((await cli(['tool-set-digest', f('dup.json'), '--json'])).stdout);
  assert.equal(j.repeatedMembers, 1);
});

test('no_digest: differs lists only real differences, noDigest and comparable say what could not be compared', async () => {
  const d = sign02();
  // A lone surrogate in an extra: the contract digest matches, the extras digest cannot be computed.
  const text = JSON.stringify(TOOLS).replace('"Get forecast"', '"Get forecast\\ud800"');
  let r = await verify(d, { toolsText: text });
  assert.equal(r.state, 'tools_hash_mismatch');
  assert.equal(r.exitCode, 8);
  const t = r.details.toolSetDigest;
  assert.equal(t.contract.result, 'match');
  assert.equal(t.extras.code, 'TSD-TEXT');
  assert.deepEqual(t.differs, []);
  assert.deepEqual(t.noDigest, ['extras']);
  assert.equal(t.comparable, false);
  assert.doesNotMatch(r.reasons.join(' '), /only the extras digest differs/);
  assert.match(r.reasons.join(' '), /the extras digest could not be computed[\s\S]*not evidence that the tools changed/);
  // An incomplete list: neither digest, and the reason says the input is incomplete.
  r = await verify(d, { toolsText: JSON.stringify({ ...TOOLS, nextCursor: 'more' }) });
  assert.deepEqual(r.details.toolSetDigest.differs, []);
  assert.deepEqual(r.details.toolSetDigest.noDigest, ['contract', 'extras']);
  assert.match(r.reasons[0], /the list given to the verifier is incomplete/);
  // A real difference is comparable.
  const ann = structuredClone(TOOLS);
  ann.tools[1].annotations = { readOnlyHint: false };
  r = await verify(d, { toolsText: JSON.stringify(ann) });
  assert.deepEqual(r.details.toolSetDigest.differs, ['extras']);
  assert.deepEqual(r.details.toolSetDigest.noDigest, []);
  assert.equal(r.details.toolSetDigest.comparable, true);
  // The text output says so too.
  const out = await cli(['verify', write('d.json', d), '--pubkey', pub, '--tools', write('ls.json', text), '--now', ISO]);
  assert.match(out.stdout, /^  tool set digest: contract match, extras no digest \(TSD-TEXT\) \(could not be compared\)$/m);
});

test('a tool check failure lists the chain step as not run, in both formats', async () => {
  const prev = sign02({ version: '1.3.0', issuedAt: '2026-10-01T00:00:00Z' });
  const ann = structuredClone(TOOLS);
  ann.tools[1].annotations = { readOnlyHint: false };
  const r = await verify(sign02(), { toolsText: JSON.stringify(ann), previousText: JSON.stringify(prev) });
  assert.equal(r.state, 'tools_hash_mismatch');
  assert.deepEqual(r.details.notChecked, ['chain link (not run: the check stopped at the tool check)']);
  const r1 = await verify(sign01(), { toolsText: JSON.stringify(ann), previousText: JSON.stringify(prev) });
  assert.equal(r1.state, 'tools_hash_mismatch');
  assert.deepEqual(r1.details.notChecked, ['chain link (not run: the check stopped at the tool check)']);
  // The declaration names a previous one that was not given.
  const r2 = await verify(sign02(), { toolsText: JSON.stringify(ann) });
  assert.deepEqual(r2.details.notChecked, ['chain link (previous declaration not given)']);
});

test('format refused by the check: still malformed and exit 2, with formatAccepted false', async () => {
  const d01 = sign01();
  const r = await verify(d01, { formats: [SPEC_ID_02] });
  assert.equal(r.state, 'malformed');
  assert.equal(r.exitCode, 2);
  assert.equal(r.details.formatAccepted, false);
  assert.match(r.reasons[0], /may be a well formed declaration of that format/);
  assert.equal((await verify(d01)).details.formatAccepted, true);
  // A broken file of an accepted format is malformed with formatAccepted true.
  const broken = { ...sign02(), contact: 'nope' };
  const b = await verify(broken, { formats: [SPEC_ID_02] });
  assert.equal(b.state, 'malformed');
  assert.equal(b.details.formatAccepted, true);
  const j = JSON.parse((await cli(['verify', write('d01.json', d01), '--pubkey', pub, '--format', '0.2', '--json'])).stdout);
  assert.equal(j.formatAccepted, false);
  assert.equal(j.exitCode, 2);
});

test('a value flag given twice is a usage error and the values are not echoed', async () => {
  assert.throws(() => parseArgs(['--format', '0.1', '--format', '0.2']), /--format was given more than once/);
  assert.throws(() => parseArgs(['--format=0.1', '--format=0.2']), /given more than once/);
  assert.throws(() => parseArgs(['--pubkey', 'a', '--pubkey', 'b']), /--pubkey was given more than once/);
  // --tools stays a list.
  assert.deepEqual(parseArgs(['--tools', 'a', '--tools', 'b']).flags.tools, ['a', 'b']);
  const d = write('d02.json', sign02());
  const r = await cli(['verify', d, '--pubkey', pub, '--format', '0.1', '--format', '0.2', '--now', ISO]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /--format was given more than once/);
  const v = await cli(['init', '--name', 'com.example/weather', '--version', '1.0.0', '--version', k.hex, '--tools', write('t.json', TOOLS)]);
  assert.equal(v.code, 1);
  for (const s of k.secretStrings) assert.ok(!v.stderr.includes(s) && !v.stdout.includes(s));
});

test('messages name formats with correct grammar', async () => {
  const newer = sign02({ version: '1.0.0', issuedAt: '2026-10-01T00:00:00Z' });
  const back = sign01({ version: '1.0.1', previous: (await verify(newer)).details.declarationHash });
  const r = await verify(back, { previousText: JSON.stringify(newer) });
  assert.equal(r.state, 'chain_mismatch');
  const all = [...r.reasons];
  all.push((await cli(['init', '--name', 'com.example/weather', '--version', '1', '--tools-hash', 'sha256:' + '0'.repeat(64)])).stderr);
  all.push((await cli(['init', '--format', '0.1', '--name', 'com.example/weather', '--version', '1', '--contract-digest', TSD.contract, '--extras-digest', 'null'])).stderr);
  all.push((await cli(['init', '--format', '0.1', '--name', 'com.example/weather', '--version', '1.0.1', '--tools', write('t2.json', TOOLS), '--contact', 'mailto:a@example.com', '--previous', write('n.json', newer)])).stderr);
  for (const m of all) assert.doesNotMatch(m, /\ba addon-declaration/, m);
  assert.match(r.reasons.join(' '), /a declaration in format addon-declaration\/0\.1 cannot follow one in format addon-declaration\/0\.2/);
});

test('digest form hints: hex, base64url, missing padding and loose bits are each named', () => {
  const bytes = Buffer.from(TSD.contract.slice(7), 'base64');
  // A value whose base64 holds "+" or "/", so its base64url form differs.
  let b = Buffer.from(bytes);
  for (let n = 0; !/[+/]/.test(b.toString('base64')); n++) b = Buffer.from(bytes.map((x, i) => (i === 0 ? (x + n) & 255 : x)));
  const b64 = b.toString('base64');
  const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const cases = [
    ['sha256:' + b.toString('hex'), /sha256:<hex> form/],
    ['sha256-' + b64.replace(/\+/g, '-').replace(/\//g, '_'), /base64url alphabet/],
    ['sha256-' + b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=$/, ''), /base64url alphabet/],
    ['sha256-' + b64.replace(/=$/, ''), /no "=" padding/],
    ['sha256-' + b64.slice(0, 42) + ALPH[ALPH.indexOf(b64[42]) ^ 1] + '=', /not canonical base64/],
    ['sha256-short', /"digest" value the tool-set-digest command prints \(not its "hex" value\)/],
  ];
  for (const [v, re] of cases) {
    const u = baseUnsigned({ spec: SPEC_ID_02, toolSetDigest: { ...TSD, contract: v } });
    delete u.toolsHash;
    const p = validate(u, { unsigned: true }).join(' ');
    assert.match(p, re, v);
  }
});

test('init: --name holding key material is refused without echo; explicit digests get a note', async () => {
  const tools = write('t3.json', TOOLS);
  for (const name of [`com.example/${k.hex}`, `com.${k.hex}/x`]) {
    const r = await cli(['init', '--name', name, '--version', '1', '--tools', tools]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--name looks like it holds key material/);
    for (const s of k.secretStrings) assert.ok(!r.stderr.includes(s) && !r.stdout.includes(s));
  }
  assert.equal((await cli(['init', '--name', 'com.example/weather', '--version', '1', '--tools', tools])).code, 0);
  const r = await cli(['init', '--name', 'com.example/weather', '--version', '1', '--contract-digest', TSD.contract, '--extras-digest', TSD.extras]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /note: --contract-digest and --extras-digest are written, signed and published exactly as given/);
  assert.doesNotMatch((await cli(['init', '--name', 'com.example/weather', '--version', '1', '--tools', tools])).stderr, /note: --contract-digest/);
});

test('messages for unsigned files fit the command, and scope messages name both formats', async () => {
  const u = baseUnsigned({ spec: SPEC_ID_02, toolSetDigest: TSD });
  delete u.toolsHash;
  const unsigned = write('u.json', u);
  const h = await cli(['hash-declaration', unsigned]);
  assert.equal(h.code, 1);
  assert.match(h.stderr, /run sign on it first, then hash-declaration on the signed output/);
  assert.doesNotMatch(h.stderr, /previous release/);
  const v = await cli(['verify', write('d3.json', sign02()), '--pubkey', pub, '--previous', unsigned, '--now', ISO]);
  assert.equal(v.code, 9);
  assert.match(v.stdout, /the previous declaration looks unsigned/);
  assert.match(GITHUB_OUT_OF_SCOPE, /out of scope in formats 0\.1 and 0\.2/);
  const fiat = baseUnsigned({ payment: [{ network: 'eip155:8453', asset: 'USD', payTo: '0x1', amount: '1' }] });
  assert.match(validate(fiat, { unsigned: true }).join(' '), /out of scope in formats 0\.1 and 0\.2/);
  assert.equal(SPEC_ID_01, 'addon-declaration/0.1');
});

// The action's own verify step passes the format it wrote. Run with bash when a
// bash that reads this machine's paths is available, against a stub CLI that
// records its arguments (the real step looks the key up live).
function actionScript(stepName) {
  const lines = fs.readFileSync(new URL('../action/action.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  assert.ok(start >= 0, stepName);
  const runAt = lines.findIndex((l, n) => n > start && /^\s+run: \|$/.test(l));
  const indent = lines[runAt].search(/\S/);
  const body = [];
  for (const l of lines.slice(runAt + 1)) {
    if (l.trim() !== '' && l.search(/\S/) <= indent) break;
    body.push(l.slice(indent + 2));
  }
  return body.join('\n');
}

test('action: the verify step checks the format the sign step wrote', async (t) => {
  const { spawnSync } = await import('node:child_process');
  const probe = f('probe');
  fs.writeFileSync(probe, 'x');
  if (spawnSync('bash', ['-c', 'test -f "$0"', probe], { encoding: 'utf8' }).status !== 0) return t.skip('no bash that reads this machine\'s paths');
  const stub = write('stub-cli.mjs', "import fs from 'node:fs'; fs.writeFileSync(process.env.ARGS_OUT, JSON.stringify(process.argv.slice(2)));\n");
  const script = actionScript('Verify against the published key');
  for (const [IN_FORMAT, want] of [['0.2', ['--format', '0.2']], ['0.1', ['--format', '0.1']], ['', []]]) {
    const out = f(`args-${IN_FORMAT || 'none'}.json`);
    const r = spawnSync('bash', ['-c', script], { cwd: tmp, env: { ...process.env, CLI: stub, IN_TOOLS: 'a.json\nb.json\n', IN_FORMAT, IN_OUT: 'declaration.json', ARGS_OUT: out }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(JSON.parse(fs.readFileSync(out, 'utf8')), ['verify', 'declaration.json', '--tools', 'a.json', '--tools', 'b.json', ...want]);
  }
});

test('docs: SPEC and README carry the review changes, in plain prose', () => {
  const SPEC = fs.readFileSync(new URL('../SPEC.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const README = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  for (const s of ['repeatedNames', 'repeatedMembers', 'noDigest', 'comparable', 'formatAccepted', 'MCP-Protocol-Version', 'valid-repeated-tool-name', 'formatChangeNote', 'contractCode', 'not evidence that the server changed its tools', 'departs from that on purpose']) {
    assert.ok(SPEC.includes(s), `SPEC mentions ${s}`);
  }
  for (const s of ['--format 0.2', 'noDigest', 'repeatedNames', 'this key must be published as:', 'SPEC.md section 17.8']) assert.ok(README.includes(s), `README mentions ${s}`);
  // Stale wording the review named.
  for (const s of ['open question for v0.2', 'candidate for v0.2', 'signing input starts with `addon-declaration/0.1` and', 'in place of the strict rules of section 5, which still apply to the declaration file. Pages are given and read as in section 4']) {
    assert.ok(!SPEC.includes(s), `SPEC still says ${s}`);
  }
  // The prose changed in this review: no dash punctuation and none of the barred words.
  const a = SPEC.indexOf('T17. Lenient digest input');
  const parts = [SPEC.slice(a, SPEC.indexOf('## 13.', a)), SPEC.slice(SPEC.indexOf('## 17.')), README];
  for (const p of parts) {
    const prose = p.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, '');
    assert.ok(!/[‒-―−]/.test(prose), 'a dash character');
    assert.ok(!/\s-\s|\s--\s/.test(prose), 'a hyphen used as a dash');
    assert.ok(!/\bguaranteed\b/i.test(prose), 'a promise word');
  }
});

test('help: tool-set-digest does not claim the digests never equal the tools hash; verify qualifies an extras only difference', () => {
  assert.match(HELP, /in general not the tools hash[\s\S]*SPEC\.md section 4a/);
  assert.doesNotMatch(HELP, /They are not the tools hash and do not match it\./);
  assert.match(HELP, /SPEC\.md 17\.8/);
  assert.match(HELP, /--format 0\.2 so an older 0\.1 file is not accepted/);
  assert.match(HELP, /toolSetDigest\.noDigest/);
});
