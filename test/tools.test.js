import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { toolsHash, toolsHashFromText, toolsHashFromPages, canonicalTools, ToolsError, PAGE_RESOURCE_DEPTH } from '../lib/tools.js';
import { TOOLS } from '../testlib/helpers.js';

test('tools hash is SHA-256 of the canonical, name sorted tool array (hand computed vector)', () => {
  const tools = [
    { name: 'b', inputSchema: { type: 'object' }, description: 'B' },
    { name: 'a', description: 'é', inputSchema: { type: 'object', properties: {} } },
  ];
  const canonical = '[{"description":"é","inputSchema":{"properties":{},"type":"object"},"name":"a"},{"description":"B","inputSchema":{"type":"object"},"name":"b"}]';
  assert.equal(canonicalTools(tools), canonical);
  const want = 'sha256:' + crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
  assert.equal(toolsHash(tools), want);
});

test('tool order, member order and wrapper form do not change the hash', () => {
  const h = toolsHash(TOOLS);
  assert.equal(toolsHash([...TOOLS.tools].reverse()), h);
  assert.equal(toolsHash({ jsonrpc: '2.0', id: 7, result: { tools: TOOLS.tools, nextCursor: 'abc' } }), h);
  const reordered = TOOLS.tools.map((t) => Object.fromEntries(Object.entries(t).reverse()));
  assert.equal(toolsHash(reordered), h);
});

test('any change to a tool changes the hash', () => {
  const h = toolsHash(TOOLS);
  const variants = [
    (t) => (t[0].description += ' '),
    (t) => (t[0].inputSchema.properties.days.maximum = 8),
    (t) => (t[1].annotations.readOnlyHint = false),
    (t) => delete t[1].annotations,
    (t) => (t[0]._meta = { x: 1 }),
    (t) => t.push({ name: 'delete_everything', inputSchema: { type: 'object' } }),
    (t) => t.pop(),
    (t) => (t[0].name = 'get_forecast2'),
  ];
  for (const change of variants) {
    const copy = structuredClone(TOOLS.tools);
    change(copy);
    assert.notEqual(toolsHash(copy), h, change.toString());
  }
});

test('bad tool lists are refused', () => {
  assert.throws(() => toolsHash({ notTools: [] }), ToolsError);
  assert.throws(() => toolsHash([{ name: 'a' }, { name: 'a' }]), ToolsError);
  assert.throws(() => toolsHash([{ description: 'no name' }]), ToolsError);
  assert.throws(() => toolsHash([null]), ToolsError);
  assert.throws(() => toolsHash([{ name: '' }]), ToolsError);
});

test('an empty tool list has a defined hash', () => {
  assert.equal(toolsHash([]), 'sha256:' + crypto.createHash('sha256').update('[]').digest('hex'));
});

test('only one input shape is read: a second tools list cannot hide the real one', () => {
  const evil = '{"jsonrpc":"2.0","id":1,"tools":[],"result":{"tools":[{"name":"evil","description":"exfiltrate"}]}}';
  assert.throws(() => toolsHashFromText(evil), ToolsError);
  assert.throws(() => toolsHash({ tools: [], result: { tools: [] } }), /ambiguous/);
  assert.throws(() => toolsHash({ jsonrpc: '2.0', tools: [] }), /ambiguous/);
  assert.throws(() => toolsHash({ id: 1, tools: [] }), /ambiguous/);
  assert.throws(() => toolsHash({ result: { notTools: [] } }), ToolsError);
  // The three accepted shapes give one hash.
  const h = toolsHash(TOOLS.tools);
  assert.equal(toolsHash({ tools: TOOLS.tools, nextCursor: 'x' }), h);
  assert.equal(toolsHash({ jsonrpc: '2.0', id: 1, result: { tools: TOOLS.tools } }), h);
});

test('numbers in tool schemas: no two different literals share a hash by rounding', () => {
  const t = (n) => `[{"name":"t","inputSchema":{"maximum":${n}}}]`;
  assert.throws(() => toolsHashFromText(t('9007199254740993')), /range/);
  assert.throws(() => toolsHashFromText(t('1e-400')), /underflows/);
  assert.notEqual(toolsHashFromText(t('1')), toolsHashFromText(t('0')));
});

test('nesting depth is counted from the tools array, whatever the wrapper', () => {
  // A tool whose schema nests deep enough that the tools array holds exactly 64 levels.
  const deep = (levels) => {
    let schema = '1';
    for (let n = 0; n < levels - 3; n++) schema = '[' + schema + ']';
    return `[{"name":"t","inputSchema":{"x":${schema}}}]`;
  };
  const ok = deep(64);
  const bare = toolsHashFromText(ok);
  assert.equal(toolsHashFromText(`{"tools":${ok}}`), bare);
  assert.equal(toolsHashFromText(`{"jsonrpc":"2.0","id":1,"result":{"tools":${ok}}}`), bare);
  for (const wrap of [(x) => x, (x) => `{"tools":${x}}`, (x) => `{"jsonrpc":"2.0","id":1,"result":{"tools":${x}}}`]) {
    assert.throws(() => toolsHashFromText(wrap(deep(65))), /deeper than 64|nesting too deep/);
  }
});

// Review round 3 (18 November 2026).

test('nesting: members next to the tools array are not limited by the 64 level rule', () => {
  const nest = (n) => '['.repeat(n) + ']'.repeat(n);
  const plain = toolsHashFromText('[{"name":"a"}]');
  // A shallow tools array next to a deep _meta or nextCursor: accepted, and not hashed.
  for (const n of [65, 100, PAGE_RESOURCE_DEPTH - 2]) {
    assert.equal(toolsHashFromText(`{"tools":[{"name":"a"}],"_meta":{"x":${nest(n)}}}`), plain, `_meta ${n}`);
    assert.equal(toolsHashFromText(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}],"nextCursor":${nest(n)}}}`), plain, `nextCursor ${n}`);
  }
  // Beyond the resource limit the page is refused, without exhausting the stack.
  assert.throws(() => toolsHashFromText(`{"tools":[{"name":"a"}],"_meta":${nest(PAGE_RESOURCE_DEPTH + 10)}}`), (e) => e.reason === 'depth');
  assert.throws(() => toolsHashFromText(`{"tools":[],"_meta":${'['.repeat(200000)}`), (e) => e.reason === 'depth');
  // Inside a JSON-RPC wrapper the tools array may hold exactly 64 levels: the wrapper does not count.
  const t64 = '[{"name":"n","s":' + nest(62) + '}]';
  const t65 = '[{"name":"n","s":' + nest(63) + '}]';
  assert.equal(toolsHashFromText(`{"jsonrpc":"2.0","id":1,"result":{"tools":${t64}}}`), toolsHashFromText(t64));
  assert.throws(() => toolsHashFromText(`{"jsonrpc":"2.0","id":1,"result":{"tools":${t65}}}`), (e) => e.reason === 'depth');
  assert.throws(() => toolsHashFromText(`{"tools":${t65}}`), (e) => e.reason === 'depth');
});

test('a page saved as server sent events gets a message that says to remove the framing', () => {
  const body = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}';
  for (const text of [`event: message\ndata: ${body}\n\n`, `data: ${body}\n\n`, `: keepalive\ndata: ${body}\n`]) {
    assert.throws(() => toolsHashFromPages([text]), (e) => /server sent events: remove the framing/.test(e.message) && e.reason === 'syntax');
  }
  // Other bad JSON keeps the plain parser message.
  assert.throws(() => toolsHashFromText('{"tools":'), (e) => !/server sent events/.test(e.message));
  assert.equal(toolsHashFromPages([body]), toolsHashFromText('[{"name":"a"}]'));
});

test('an int64 or uint64 bound: the message says the change belongs in the server, not in tools.json', () => {
  assert.throws(
    () => toolsHashFromText('[{"name":"n","inputSchema":{"maximum":18446744073709551615}}]'),
    (e) => e.reason === 'range' && /change the server so its tools\/list no longer sends this literal/.test(e.message) && /editing tools\.json alone gives a hash/.test(e.message),
  );
});
