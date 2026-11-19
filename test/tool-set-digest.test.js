// tool-set-digest: the two digests of mcp-tool-set-digest/1, checked against
// that project's published conformance vectors (vendored with their licence
// in vectors/third_party/mcp-tool-set-digest-1/, see NOTICE there) and through
// the CLI.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { toolSetDigestsFromPages, toolSetDigests, InputError } from '../lib/tool-set-digest.js';
import { toolsHashFromText } from '../lib/tools.js';
import { parseStrict, JsonError } from '../lib/jcs.js';
import { main, HELP } from '../lib/cli.js';

const DIR = new URL('../vectors/third_party/mcp-tool-set-digest-1/', import.meta.url);
const VECTORS = new URL('vectors.json', DIR);
const present = fs.existsSync(VECTORS);
const suite = present ? JSON.parse(fs.readFileSync(VECTORS, 'utf8')) : null;

function check(got, want, id, kind) {
  if (want.error) {
    assert.equal(got.error, want.error, `${id} ${kind}: expected ${want.error}, got ${JSON.stringify(got)}`);
    assert.ok(!('digest' in got), `${id} ${kind}: a digest was given where none can be computed`);
  } else if (want.digest === null) {
    assert.deepEqual(got, { digest: null }, `${id} ${kind}: expected no extras digest`);
  } else {
    assert.ok(!got.error, `${id} ${kind}: ${got.error} ${got.detail}`);
    assert.equal(got.canonical, want.canonical, `${id} ${kind} canonical text`);
    assert.equal(got.digest, want.digest, `${id} ${kind} digest`);
    assert.equal(got.hex, want.hex, `${id} ${kind} hex`);
  }
}

test('every published mcp-tool-set-digest/1 vector', (t) => {
  if (!present) return t.skip('vectors not present (vectors/third_party/mcp-tool-set-digest-1/vectors.json)');
  assert.equal(suite.format, 'mcp-tool-set-digest/1 test vectors');
  assert.equal(suite.vectors.length, 73);
  let passed = 0;
  for (const v of suite.vectors) {
    const r = toolSetDigestsFromPages([v.tools]);
    check(r.contract, v.contract, v.id, 'contract');
    check(r.extras, v.extras, v.id, 'extras');
    passed++;
  }
  assert.equal(passed, 73);
});

test('the equal and differ pairs of the published vectors', (t) => {
  if (!present) return t.skip('vectors not present');
  const byId = Object.fromEntries(suite.vectors.map((v) => [v.id, toolSetDigestsFromPages([v.tools])]));
  assert.ok(suite.equal.length > 0 && suite.differ.length > 0);
  for (const { ids, digest } of suite.equal) {
    const [a, b] = ids.map((id) => byId[id][digest]);
    assert.ok(a && b, ids.join(' '));
    assert.equal(a.digest, b.digest, `${digest} of ${ids.join(' and ')} must match`);
  }
  for (const { ids, digest } of suite.differ) {
    const [a, b] = ids.map((id) => byId[id][digest]);
    assert.notEqual(a.digest, b.digest, `${digest} of ${ids.join(' and ')} must differ`);
  }
});

test('the vendored files match NOTICE', (t) => {
  if (!present) return t.skip('vectors not present');
  const notice = fs.readFileSync(new URL('NOTICE', DIR), 'utf8');
  // The upstream bytes at commit aca5812 (LF line ends). A CR here means a
  // checkout converted the files, so they are no longer what upstream published.
  const upstream = {
    'vectors.json': '530c0d876cbf2a22b178f703f145f6e286255267050dd54a6350445e633f88ed',
    'LICENSE-MIT': '5cc0f26c2644eba9290d80ac2b027afc66f148fee9debf9721ceeeffe29c4d80',
    'LICENSE-APACHE': 'e7e97143da6979addfc208e5606219b593f9982831e0f2e4b6408d5c0a655eed',
  };
  for (const [name, want] of Object.entries(upstream)) {
    const bytes = fs.readFileSync(new URL(name, DIR));
    assert.equal(bytes.includes(0x0d), false, `${name} has a CR byte`);
    const sha = crypto.createHash('sha256').update(bytes).digest('hex');
    assert.equal(sha, want, `${name} is not the upstream bytes`);
    assert.match(notice, new RegExp(`${name.replace('.', '\\.')}\\s+${sha}`), `NOTICE names the sha256 of ${name}`);
  }
});

test('toolsHash equals the contract digest only when the two canonical texts coincide', async () => {
  const hex = (b64) => 'sha256:' + Buffer.from(b64.slice('sha256-'.length), 'base64').toString('hex');
  // No extras, string descriptions, object inputSchemas: same bytes, same hash.
  for (const text of ['[]', '[{"name":"a","description":"d","inputSchema":{"type":"object"}}]']) {
    const r = toolSetDigestsFromPages([text]);
    assert.equal(r.extras.digest, null);
    assert.equal(await toolsHashFromText(text), hex(r.contract.digest), text);
  }
  // An extra, or a missing description: the texts differ, and so do the hashes.
  for (const text of ['[{"name":"a","description":"d","inputSchema":{"type":"object"},"title":"A"}]', '[{"name":"a","inputSchema":{"type":"object"}}]']) {
    const r = toolSetDigestsFromPages([text]);
    assert.notEqual(await toolsHashFromText(text), hex(r.contract.digest), text);
  }
});

// The worked example of that document's section 8.
const READ_FILE = '[{"name": "read_file", "title": "Read file", "description": "Read a file from disk.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}, "annotations": {"readOnlyHint": true}}]';

test('the section 8 example, bare and in each wrapper', () => {
  const tools = JSON.parse(READ_FILE);
  for (const text of [READ_FILE, JSON.stringify({ tools }), JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools } })]) {
    const r = toolSetDigestsFromPages([text]);
    assert.equal(r.contract.digest, 'sha256-pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g=');
    assert.equal(r.extras.digest, 'sha256-Kmdz0r/Y+YnXALUVpJTXG8TUbKQhoFKQ7CeEpIw+1Oc=');
    assert.equal(r.extras.canonical, '{"tools":{"read_file":{"annotations":{"readOnlyHint":true},"title":"Read file"}}}');
  }
});

test('pages: joined in order; a nextCursor on the last page is TSD-PAGE for both', () => {
  const [a] = JSON.parse(READ_FILE);
  const b = { name: 'list_files', description: 'List files.', inputSchema: { type: 'object' } };
  const one = toolSetDigestsFromPages([JSON.stringify([a, b])]);
  const two = toolSetDigestsFromPages([JSON.stringify({ tools: [a], nextCursor: 'c' }), JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: [b] } })]);
  assert.equal(two.contract.digest, one.contract.digest);
  assert.equal(two.extras.digest, one.extras.digest);
  for (const last of [{ tools: [b], nextCursor: '' }, { jsonrpc: '2.0', id: 2, result: { tools: [b], nextCursor: 'x' } }]) {
    const r = toolSetDigestsFromPages([JSON.stringify({ tools: [a], nextCursor: 'c' }), JSON.stringify(last)]);
    assert.equal(r.contract.error, 'TSD-PAGE');
    assert.equal(r.extras.error, 'TSD-PAGE');
  }
  assert.equal(toolSetDigests([{ name: 'x' }], { complete: false }).contract.error, 'TSD-PAGE');
});

test('input rules of that document, for this command only', () => {
  // A repeated member name: the last value counts, and it is reported.
  const dup = toolSetDigestsFromPages(['[{"name":"t","description":"first","description":"second"}]']);
  const last = toolSetDigestsFromPages(['[{"name":"t","description":"second"}]']);
  assert.equal(dup.contract.digest, last.contract.digest);
  assert.equal(dup.notes.length, 1);
  assert.match(dup.notes[0], /1 repeated member name; the last value/);
  // An integer beyond 2^53 is rounded to the nearest double; underflow becomes 0.
  assert.equal(toolSetDigestsFromPages(['[{"name":"n","inputSchema":{"maximum":18446744073709551615}}]']).contract.canonical, '[{"description":"","inputSchema":{"maximum":18446744073709552000},"name":"n"}]');
  assert.equal(toolSetDigestsFromPages(['[{"name":"n","inputSchema":{"minimum":1e-400}}]']).contract.canonical, '[{"description":"","inputSchema":{"minimum":0},"name":"n"}]');
  // A literal with no double in a wrongly typed contract member is read as absent, like any number there.
  assert.equal(toolSetDigestsFromPages(['[{"name":"n","description":1e400}]']).contract.digest, toolSetDigestsFromPages(['[{"name":"n"}]']).contract.digest);
  // The declaration rules are unchanged: the strict parser and the tools hash still refuse these.
  assert.throws(() => parseStrict('{"a":1,"a":2}'), (e) => e instanceof JsonError && e.reason === 'duplicate-member');
  assert.throws(() => parseStrict('[9007199254740993]'), (e) => e instanceof JsonError && e.reason === 'range');
  assert.throws(() => parseStrict('["\\ud800"]'), (e) => e instanceof JsonError && e.reason === 'lone-surrogate');
  assert.throws(() => toolsHashFromText('[{"name":"t","description":"a","description":"b"}]'), /duplicate member/);
});

test('input that is not a tool list has no digest and no code', () => {
  for (const text of ['{"tools":[],"result":{"tools":[]}}', '{"x":1}', '[1,', 'event: message\ndata: {"jsonrpc":"2.0"}\n', '['.repeat(513) + ']'.repeat(513)]) {
    assert.throws(() => toolSetDigestsFromPages([text]), InputError, text.slice(0, 40));
  }
  assert.throws(() => toolSetDigestsFromPages([Buffer.from([0x5b, 0xff, 0x5d])]), InputError);
  // 512 levels is within the resource bound.
  assert.equal(toolSetDigestsFromPages(['[{"name":"d","_meta":' + '['.repeat(510) + ']'.repeat(510) + '}]']).contract.error, undefined);
});

function run(argv) {
  const out = [];
  const err = [];
  const io = { stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) }, env: {} };
  return main(argv, io).then((code) => ({ code, stdout: out.join(''), stderr: err.join('') }));
}

test('CLI: tool-set-digest prints both digests labelled as that document labels them', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-tsd-'));
  try {
    const f = path.join(tmp, 'tools.json');
    fs.writeFileSync(f, JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: JSON.parse(READ_FILE) } }));
    let r = await run(['tool-set-digest', f]);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, 'mcp-tool-set-digest/1\ncontract digest: sha256-pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g=\nextras digest: sha256-Kmdz0r/Y+YnXALUVpJTXG8TUbKQhoFKQ7CeEpIw+1Oc=\n');
    r = await run(['tool-set-digest', f, '--json']);
    assert.equal(r.code, 0);
    const j = JSON.parse(r.stdout);
    assert.equal(j.profile, 'mcp-tool-set-digest/1');
    assert.equal(j.contract.digest, 'sha256-pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g=');
    assert.equal(j.contract.hex, 'sha256:' + Buffer.from('pUO5TdOtj4yR/mh2VDcu4y6axwVix4xgwST6cFkdd3g=', 'base64').toString('hex'));
    assert.deepEqual(j.notes, []);
    // No extras: null, exit 0.
    fs.writeFileSync(f, '[{"name":"ping"}]');
    r = await run(['tool-set-digest', f]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /^extras digest: null \(no tool has extras\)$/m);
    // A code: exit 2, the code and an escaped detail.
    fs.writeFileSync(f, '[{"name":"s\\u202e","title":"\\ud800"}]');
    r = await run(['tool-set-digest', f]);
    assert.equal(r.code, 2);
    assert.match(r.stdout, /^extras digest: none, TSD-TEXT \(extras: /m);
    fs.writeFileSync(f, '{"tools":[{"name":"a"}],"nextCursor":"n"}');
    r = await run(['tool-set-digest', f, '--json']);
    assert.equal(r.code, 2);
    assert.equal(JSON.parse(r.stdout).contract.error, 'TSD-PAGE');
    // Not a tool list: usage error, exit 1.
    fs.writeFileSync(f, '{"tools":[],"id":1}');
    r = await run(['tool-set-digest', f]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /ambiguous input/);
    r = await run(['tool-set-digest']);
    assert.equal(r.code, 1);
    r = await run(['tool-set-digest', f, '--tools', f]);
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--tools is not an option of tool-set-digest/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('CLI: help lists tool-set-digest and says it is not the tools hash', () => {
  assert.match(HELP, /\n {2}tool-set-digest <tools\.json> \[<page2\.json> \.\.\.\] \[--json\]\n/);
  assert.match(HELP, /not the tools hash/);
});
