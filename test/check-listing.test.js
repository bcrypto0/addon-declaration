// check-listing against local test doubles: a registry on 127.0.0.1 (read
// through the real hardened fetch, which accepts a loopback http registry base),
// and a publisher site and MCP server reached through the same hardened fetch,
// with the made up host names pinned to 127.0.0.1. Nothing leaves the machine.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { main, HELP_CHECK_LISTING } from '../lib/cli.js';
import { httpsRequest, isPublicAddress, isLoopbackAddress, MAX_REQUEST_BODY } from '../lib/resolve.js';
import { signDeclaration, declarationHash, SPEC_ID_01, SPEC_ID_02 } from '../lib/declaration.js';
import { parseProofRecords } from '../lib/keys.js';
import { toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';
import { LISTING_STATES, registryBase, pointerHosts, compareRemotes, MAX_CHAIN_LINKS, checkListing, isVersionArgument } from '../lib/listing.js';
import { sseEvents, fetchToolsList, describe, MODERN_PROTOCOL_VERSION, MAX_TOOLS_PAGES } from '../lib/mcp-client.js';
import { makeKey, TOOLS, signRaw } from '../testlib/helpers.js';

const NAME = 'com.example/weather';
const VERSION = '1.0.0';
const HOST = 'example.com';
const REMOTE = 'https://example.com/mcp';
const NOW = '2026-11-19T12:00:00Z';
const PP = 'io.modelcontextprotocol.registry/publisher-provided';
const ESC = String.fromCharCode(27);
const RLO = String.fromCharCode(0x202e);
const k = makeKey('ed25519');
const k2 = makeKey('ed25519');
const keys = parseProofRecords(`${k.record}\n${k2.record}`).keys;
const TOOLS_TEXT = JSON.stringify(TOOLS);
const tsd = toolSetDigestsFromPages([TOOLS_TEXT]);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-listing-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

function decl01(over = {}, key = k) {
  return signDeclaration(
    { spec: SPEC_ID_01, name: NAME, version: VERSION, toolsHash: toolsHash(TOOLS), remotes: [{ type: 'streamable-http', url: REMOTE }], contact: 'mailto:security@example.com', issuedAt: '2026-11-18T10:00:00Z', expiresAt: '2027-05-18T10:00:00Z', key: { method: 'http', domain: HOST }, ...over },
    key.loaded,
  );
}
function decl02(over = {}, key = k) {
  return signDeclaration(
    { spec: SPEC_ID_02, name: NAME, version: VERSION, toolSetDigest: { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest }, remotes: [{ type: 'streamable-http', url: REMOTE }], issuedAt: '2026-11-18T11:00:00Z', expiresAt: '2027-05-18T10:00:00Z', key: { method: 'http', domain: HOST }, ...over },
    key.loaded,
  );
}
const hex = (d) => declarationHash(d).slice('sha256:'.length);
const text = (d) => JSON.stringify(d, null, 2) + '\n';
const folder = `/.well-known/addon-declaration/${NAME}/`;
const byHashPath = (d) => `${folder}by-hash/${hex(d)}.json`;

function listingFor(d, { name = NAME, version = VERSION, remotes = [{ type: 'streamable-http', url: REMOTE }], pointer } = {}) {
  const server = { name, version, remotes };
  const ptr = pointer !== undefined ? pointer : d ? { url: `https://${HOST}${byHashPath(d)}`, hash: declarationHash(d) } : undefined;
  if (ptr !== undefined) server._meta = { [PP]: { addonDeclaration: ptr } };
  return { server, _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', publishedAt: '2026-11-19T01:16:58.545256Z', updatedAt: '2026-11-19T01:16:58.545256Z', isLatest: true } } };
}

// A local server; routes maps "<method> <path>" or "<path>" to a handler or a reply.
async function serve(routes, seen) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const host = String(req.headers.host).replace(/:\d+$/, '');
      seen.push({ method: req.method, host, path: req.url, headers: req.headers, body });
      const r = routes[`${req.method} ${host}${req.url}`] ?? routes[`${host}${req.url}`] ?? routes[req.url];
      if (typeof r === 'function') return r(req, res, body);
      if (!r) {
        res.writeHead(404);
        return res.end('not found');
      }
      res.writeHead(r.status ?? 200, r.headers ?? { 'Content-Type': 'application/json' });
      res.end(typeof r.body === 'string' || Buffer.isBuffer(r.body) ? r.body : JSON.stringify(r.body));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

// The registry double and the site double (publisher files and MCP endpoint).
async function world({ registry = {}, site = {}, addresses = {}, keyResult = { keys, notes: [] } } = {}) {
  const seen = [];
  const reg = await serve(registry, seen);
  const st = await serve(site, seen);
  // https URLs on made up hosts go to the site double through the real
  // hardened fetch; the host's addresses can be set (for the private address test).
  const request = (url, opts) => {
    const u = new URL(url);
    if (u.protocol === 'http:') return httpsRequest(url, opts);
    const local = `http://${u.hostname}:${st.port}${u.pathname}${u.search}`;
    const addrs = addresses[u.hostname] ?? [{ address: '127.0.0.1', family: 4 }];
    return httpsRequest(local, { ...opts, transport: http, lookupAll: async () => addrs, allowAddress: (a) => a === '127.0.0.1' || isPublicAddress(a) });
  };
  const lookups = [];
  const deps = {
    httpsRequest: request,
    keysFromHttp: async (domain) => (lookups.push(['http', domain]), keyResult),
    keysFromDns: async (domain) => (lookups.push(['dns', domain]), keyResult),
    dnsResolverFor: () => ({}),
  };
  return {
    seen,
    lookups,
    deps,
    registryUrl: `http://127.0.0.1:${reg.port}`,
    async run(args) {
      let stdout = '';
      let stderr = '';
      const code = await main(['check-listing', ...args], { stdout: { write: (s) => (stdout += s) }, stderr: { write: (s) => (stderr += s) }, env: {}, deps });
      return { code, stdout, stderr, json: args.includes('--json') && stdout ? JSON.parse(stdout) : null };
    },
    async close() {
      await reg.close();
      await st.close();
    },
  };
}

const regPath = (name = NAME, version = 'latest') => `/v0.1/servers/${name.replace('/', '%2F')}/versions/${encodeURIComponent(version)}`;

async function scenario(opts, args, fn) {
  const w = await world(opts);
  try {
    const r = await w.run([NAME, '--registry', w.registryUrl, ...(args.includes('--now') ? [] : ['--now', NOW]), ...args]);
    await fn(r, w);
  } finally {
    await w.close();
  }
}

// An MCP server double. mode: 'modern-json', 'modern-sse', 'legacy', 'auth', 'paged'.
function mcpServer(mode, { tools = TOOLS.tools, log = [] } = {}) {
  const SID = 'session-7f3a';
  return (req, res, body) => {
    if (req.method === 'DELETE') {
      log.push({ method: req.method, headers: req.headers });
      res.writeHead(req.headers['mcp-session-id'] === SID ? 200 : 400);
      return res.end();
    }
    let m;
    try {
      m = JSON.parse(body);
    } catch {
      res.writeHead(400);
      return res.end();
    }
    log.push({ method: req.method, rpc: m && m.method, headers: req.headers, body: m });
    if (mode === 'auth') {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"' });
      return res.end();
    }
    const modern = req.headers['mcp-protocol-version'] === MODERN_PROTOCOL_VERSION && m.params && m.params._meta;
    const pageOf = (cursor) => {
      if (mode !== 'paged' && mode !== 'legacy') return { tools };
      const i = cursor === undefined ? 0 : Number(cursor);
      return i + 1 < tools.length ? { tools: [tools[i]], nextCursor: String(i + 1) } : { tools: [tools[i]] };
    };
    const reply = (obj, sse, headers = {}) => {
      if (sse) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream', ...headers });
        res.write(': keep alive\n\n');
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'hi' } })}\n\n`);
        res.end(`event: message\ndata: ${JSON.stringify(obj)}\n\n`);
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json', ...headers });
        res.end(JSON.stringify(obj));
      }
    };
    if (mode === 'legacy') {
      // Speaks only 2025-11-25: a modern request gets a plain 400; every
      // request after initialize must carry the session id.
      if (modern) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        return res.end('Bad Request: no valid session');
      }
      if (m.method === 'initialize') return reply({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'x', version: '1' } } }, true, { 'Mcp-Session-Id': SID });
      if (req.headers['mcp-session-id'] !== SID) {
        res.writeHead(400);
        return res.end('missing session');
      }
      if (m.method === 'notifications/initialized') {
        res.writeHead(202);
        return res.end();
      }
      if (m.method === 'tools/list') return reply({ jsonrpc: '2.0', id: m.id, result: pageOf(m.params && m.params.cursor) }, true);
    }
    if (!modern || m.method !== 'tools/list') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id ?? null, error: { code: -32020, message: 'Header mismatch' } }));
    }
    return reply({ jsonrpc: '2.0', id: m.id, result: { ...pageOf(m.params.cursor), resultType: 'complete' } }, mode === 'modern-sse');
  };
}

const d1 = decl01();
const d2 = decl02({ previous: declarationHash(d1) });

function siteWith(extra = {}) {
  return { [`${HOST}${byHashPath(d1)}`]: { body: text(d1) }, ...extra };
}

test('verified: the pointer declaration verifies, no newer one, tools given as a file', async () => {
  const toolsFile = path.join(tmp, 'tools.json');
  fs.writeFileSync(toolsFile, JSON.stringify({ jsonrpc: '2.0', id: 1, result: TOOLS }));
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith() }, ['--tools', toolsFile], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^verified: com\.example\/weather 1\.0\.0/);
    assert.match(r.stdout, /checked: tools hash/);
    assert.match(r.stdout, /meaning: the holder of the named key signed this content/);
    assert.match(r.stdout, /newer declaration at versions\/1\.0\.0\.json: absent/);
    assert.deepEqual(w.lookups, [['http', HOST]], 'one key lookup, by the declared method');
    // The registry was asked by the exact get by name endpoint.
    assert.ok(w.seen.some((s) => s.path === '/v0.1/servers/com.example%2Fweather/versions/latest'));
  });
});

test('verified_newer_declaration: latest.json chains to the pointer, tools fetched (modern, JSON), digests match', async () => {
  const log = [];
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`${HOST}${folder}versions/1.0.0.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('modern-json', { log }) });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 11, r.stdout + r.stderr);
    const j = r.json;
    assert.equal(j.state, 'verified_newer_declaration');
    assert.equal(j.exitCode, 11);
    assert.equal(j.listing.name, NAME);
    assert.equal(j.listing.version, VERSION);
    assert.equal(j.listing.publishedAt, '2026-11-19T01:16:58.545256Z');
    assert.deepEqual(j.pointer, { url: `https://${HOST}${byHashPath(d1)}`, hash: declarationHash(d1) });
    assert.equal(j.declaration.format, SPEC_ID_01);
    assert.equal(j.declaration.state, 'valid');
    assert.equal(j.inForce.hash, declarationHash(d2));
    assert.equal(j.inForce.format, SPEC_ID_02);
    assert.equal(j.inForce.state, 'valid');
    assert.deepEqual(j.chain.map((c) => c.hash), [declarationHash(d2), declarationHash(d1)]);
    assert.equal(j.inForce.verify.toolSetDigest.contract.result, 'match');
    assert.equal(j.inForce.verify.toolSetDigest.extras.result, 'match');
    assert.equal(j.inForce.verify.chain.previousFormat, SPEC_ID_01);
    assert.equal(j.tools.protocolVersion, MODERN_PROTOCOL_VERSION);
    assert.equal(j.tools.era, 'modern');
    assert.equal(j.tools.result, 'match');
    assert.ok(j.fetched.every((f) => typeof f.url === 'string' && 'status' in f));
    assert.ok(j.fetched.some((f) => f.purpose === 'mcp tools/list' && f.status === 200));
    assert.equal(j.fetched.filter((f) => f.purpose === 'key lookup (http)' && f.url === `https://${HOST}/.well-known/mcp-registry-auth`).length, 1, 'the key lookup is listed once');
    assert.deepEqual(j.newer.map((c) => c.result), ['in_force', 'in_force']);
    for (const key of ['command', 'state', 'exitCode', 'reasons', 'listing', 'pointer', 'fetched', 'declaration', 'newer', 'inForce', 'chain', 'remotes', 'tools', 'checked', 'notChecked', 'notes']) assert.ok(Object.hasOwn(j, key), key);
  });
  // The request carried the per request metadata and the mirrored headers.
  const first = log[0];
  assert.equal(first.headers['mcp-protocol-version'], MODERN_PROTOCOL_VERSION);
  assert.equal(first.headers['mcp-method'], 'tools/list');
  assert.match(first.headers.accept, /application\/json/);
  assert.match(first.headers.accept, /text\/event-stream/);
  assert.equal(first.body.params._meta['io.modelcontextprotocol/protocolVersion'], MODERN_PROTOCOL_VERSION);
  assert.deepEqual(first.body.params._meta['io.modelcontextprotocol/clientCapabilities'], {});
  assert.ok(log.every((l) => l.rpc !== 'tools/call'), 'no tool is called');
});

test('tools: an event stream answer is read (notifications and comments skipped) and the text output names the protocol version', async () => {
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('modern-sse') });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    assert.match(r.stdout, /tool set digest: contract match, extras match/);
    assert.match(r.stdout, /tools: read from https:\/\/example\.com\/mcp with MCP protocol version 2026-07-28/);
    assert.match(r.stdout, /in force: sha256:[0-9a-f]{64} \(addon-declaration\/0\.2\), from latest\.json/);
  });
});

test('tools: a legacy server (initialize, Mcp-Session-Id, event streams, two pages) is read with the session and the session is ended', async () => {
  const log = [];
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`${HOST}/mcp`]: mcpServer('legacy', { log }) });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    assert.equal(r.json.tools.era, 'legacy');
    assert.equal(r.json.tools.protocolVersion, '2025-11-25');
    assert.equal(r.json.tools.session, true);
    assert.equal(r.json.tools.pages, 2);
    assert.equal(r.json.tools.result, 'match');
    assert.match(r.json.tools.notes.join(' '), /no recognized modern error/);
  });
  assert.deepEqual(log.map((l) => `${l.method} ${l.rpc ?? ''}`.trim()), ['POST tools/list', 'POST initialize', 'POST notifications/initialized', 'POST tools/list', 'POST tools/list', 'DELETE']);
  assert.equal(log[3].headers['mcp-session-id'], 'session-7f3a');
  assert.equal(log[3].headers['mcp-protocol-version'], '2025-11-25');
  assert.equal(log[4].body.params.cursor, '1');
});

test('tools: paging is followed, and a list longer than the page bound fails the fetch', async () => {
  const many = Array.from({ length: MAX_TOOLS_PAGES + 1 }, (_, i) => ({ name: `t${i}`, description: 'x', inputSchema: { type: 'object' } }));
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('paged', { tools: many }) });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, LISTING_STATES.tools_fetch_failed, r.stdout);
    assert.match(r.stdout, /more than 16 pages/);
  });
  // Two pages that do not match the declared digests: tools_hash_mismatch.
  const two = [{ name: 'a', inputSchema: { type: 'object' } }, { name: 'b', inputSchema: { type: 'object' } }];
  const site2 = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('paged', { tools: two }) });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: site2 }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 8, r.stdout);
    assert.equal(r.json.tools.pages, 2);
    assert.equal(r.json.tools.result, 'mismatch');
    assert.deepEqual(r.json.inForce.verify.toolSetDigest.differs, ['contract', 'extras']);
  });
});

test('tools: a server that asks for authorization is "not checked", not a failure', async () => {
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('auth') });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    // One plain line, said once, and a line next to the state that the tools were not compared.
    assert.match(r.stdout, /^ {2}not checked: tools \(the server asked for authorization: HTTP 401 to tools\/list\)$/m);
    assert.equal(r.stdout.match(/asked for authorization/g).length, 1, r.stdout);
    assert.ok(!/tool set digest \(no tool list given\)/.test(r.stdout), r.stdout);
    assert.match(r.stdout.split('\n').slice(0, 4).join('\n'), /tools: NOT CHECKED/);
  });
});

test('no tool flag: the tool check is reported as not run, in one line', async () => {
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith() }, [], (r) => {
    assert.equal(r.code, 0);
    assert.match(r.stdout, /not checked: tools \(give --tools or --fetch-tools to compare the tool list with the declaration in force\)/);
    assert.ok(!/no tool list given/.test(r.stdout), r.stdout);
    assert.ok(!/NOT CHECKED/.test(r.stdout), 'no tool flag was given, so no warning line');
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith() }, ['--json'], (r) => {
    assert.deepEqual(r.json.notChecked, ['tools (give --tools or --fetch-tools to compare the tool list with the declaration in force)']);
    assert.equal(r.json.tools.check, 'not_run');
  });
});

test('no_declaration and pointer_malformed', async () => {
  await scenario({ registry: { [regPath()]: { body: listingFor(null) } } }, [], (r) => {
    assert.equal(r.code, 12);
    assert.match(r.stdout, /^no_declaration/);
  });
  for (const pointer of [{ url: `https://${HOST}${byHashPath(d1)}`, hash: declarationHash(d1), extra: 1 }, { url: `https://${HOST}${byHashPath(d1)}`, hash: 'sha256:ABC' }, 'https://example.com/x.json', { hash: declarationHash(d1) }]) {
    await scenario({ registry: { [regPath()]: { body: listingFor(d1, { pointer }) } } }, [], (r, w) => {
      assert.equal(r.code, 13, JSON.stringify(pointer) + r.stdout);
      assert.ok(!w.seen.some((s) => s.host === HOST), 'nothing fetched from the publisher');
    });
  }
});

test('pointer_refused: another domain, http, a port, a query, another path, a sub namespace host', async () => {
  const h = hex(d1);
  const bad = [
    `https://evil.example/.well-known/addon-declaration/${NAME}/by-hash/${h}.json`,
    `http://${HOST}${byHashPath(d1)}`,
    `https://${HOST}:8443${byHashPath(d1)}`,
    `https://${HOST}${byHashPath(d1)}?x=1`,
    `https://${HOST}/files/${h}.json`,
    `https://${HOST}/.well-known/addon-declaration/com.example/other/by-hash/${h}.json`,
    `https://sub.${HOST}${byHashPath(d1)}`,
    `https://user:pw@${HOST}${byHashPath(d1)}`,
  ];
  for (const url of bad) {
    await scenario({ registry: { [regPath()]: { body: listingFor(d1, { pointer: { url, hash: declarationHash(d1) } }) } } }, ['--json'], (r, w) => {
      assert.equal(r.code, 14, url + r.stdout);
      assert.equal(w.seen.filter((s) => s.host !== '127.0.0.1').length, 0, 'nothing fetched');
      assert.ok(!r.stdout.includes('pw@'), 'a password in a pointer URL is not repeated');
    });
  }
  // The rule: the reversed namespace and its parents with two labels or more.
  assert.deepEqual(pointerHosts('com.example.sub'), ['sub.example.com', 'example.com']);
  assert.deepEqual(pointerHosts('com.example'), ['example.com']);
  assert.deepEqual(pointerHosts('example'), []);
});

test('namespace_out_of_scope: io.github names are refused before the registry is asked', async () => {
  const w = await world();
  try {
    const r = await w.run(['io.github.someone/server', '--registry', w.registryUrl]);
    assert.equal(r.code, 15);
    assert.equal(w.seen.length, 0);
  } finally {
    await w.close();
  }
});

test('declaration_unreachable: 404, a redirect (not followed), a host with only private addresses', async () => {
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } } }, [], (r) => {
    assert.equal(r.code, 16);
    assert.match(r.stdout, /answered HTTP 404/);
  });
  const site = { [`${HOST}${byHashPath(d1)}`]: { status: 302, headers: { Location: 'http://127.0.0.1/internal' }, body: '' } };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, [], (r, w) => {
    assert.equal(r.code, 16);
    assert.match(r.stdout, /HTTP 302 \(a redirect, which is not followed\)/);
    assert.ok(!w.seen.some((s) => s.path === '/internal'));
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith(), addresses: { [HOST]: [{ address: '10.0.0.5', family: 4 }, { address: '169.254.169.254', family: 4 }] } }, [], (r, w) => {
    assert.equal(r.code, 16);
    assert.match(r.stdout, /refusing to connect/);
    assert.ok(!w.seen.some((s) => s.host === HOST));
  });
});

test('declaration_not_the_named_one: an oversized body, another declaration, not a declaration', async () => {
  const big = { [`${HOST}${byHashPath(d1)}`]: { body: ' '.repeat(16385) } };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: big }, [], (r) => {
    assert.equal(r.code, 17);
    assert.match(r.stdout, /more than 16384 bytes/);
  });
  const other = { [`${HOST}${byHashPath(d1)}`]: { body: text(d2) } };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: other }, ['--json'], (r) => {
    assert.equal(r.code, 17);
    assert.match(r.json.reasons[0], /the served file is not the one the listing names/);
  });
  const junk = { [`${HOST}${byHashPath(d1)}`]: { body: '<html>' } };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: junk }, [], (r) => assert.equal(r.code, 17));
});

test('listing_mismatch: version, name and remotes, both ways', async () => {
  // The declaration is for 1.0.0, the listing for 1.0.1.
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { version: '1.0.1' }) } }, site: siteWith() }, [], (r) => {
    assert.equal(r.code, 18);
    assert.match(r.stdout, /the declaration is for version 1\.0\.0, the listing for version 1\.0\.1/);
  });
  // A declaration for another server name, served at this listing's path.
  const dOther = decl01({ name: 'com.example/other' });
  const ptr = { url: `https://${HOST}${byHashPath(dOther)}`, hash: declarationHash(dOther) };
  await scenario({ registry: { [regPath()]: { body: listingFor(dOther, { pointer: ptr }) } }, site: { [`${HOST}${byHashPath(dOther)}`]: { body: text(dOther) } } }, [], (r) => {
    assert.equal(r.code, 18);
    assert.match(r.stdout, /the declaration is for com\.example\/other/);
  });
  // A listing remote the declaration does not name, and the reverse.
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { remotes: [{ type: 'streamable-http', url: REMOTE }, { type: 'streamable-http', url: 'https://evil.example/mcp' }] }) } }, site: siteWith() }, ['--json'], (r) => {
    assert.equal(r.code, 18);
    assert.deepEqual(r.json.remotes.onlyInListing, [{ type: 'streamable-http', url: 'https://evil.example/mcp' }]);
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { remotes: [] }) } }, site: siteWith() }, ['--json'], (r) => {
    assert.equal(r.code, 18);
    assert.deepEqual(r.json.remotes.onlyInDeclaration, [{ type: 'streamable-http', url: REMOTE }]);
  });
  // A bare origin in the listing equals its canonical form in a declaration.
  const dOrigin = decl01({ remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/' }] });
  await scenario({ registry: { [regPath()]: { body: listingFor(dOrigin, { remotes: [{ type: 'streamable-http', url: 'HTTPS://MCP.example.com:443' }] }) } }, site: { [`${HOST}${byHashPath(dOrigin)}`]: { body: text(dOrigin) } } }, [], (r) => assert.equal(r.code, 0, r.stdout));
  const cmp = compareRemotes([{ type: 'sse', url: REMOTE }], [{ type: 'streamable-http', url: REMOTE }]);
  assert.equal(cmp.match, false, 'the type is compared too');
  assert.equal(compareRemotes([{ type: 'streamable-http', url: 'https://{tenant}.example.com/mcp' }], []).match, false);
});

test('verify states pass through: the pointer declaration with a bad signature or an unpublished key', async () => {
  const tampered = { ...d1, contact: 'mailto:other@example.com' };
  const ptr = { url: `https://${HOST}${byHashPath(tampered)}`, hash: declarationHash(tampered) };
  await scenario({ registry: { [regPath()]: { body: listingFor(tampered, { pointer: ptr }) } }, site: { [`${HOST}${byHashPath(tampered)}`]: { body: text(tampered) } } }, [], (r) => {
    assert.equal(r.code, 3);
    assert.match(r.stdout, /^invalid_signature/);
  });
  const k3 = makeKey('ed25519');
  const d3 = decl01({}, k3);
  await scenario({ registry: { [regPath()]: { body: listingFor(d3) } }, site: { [`${HOST}${byHashPath(d3)}`]: { body: text(d3) } } }, [], (r) => assert.equal(r.code, 4));
});

test('verify states pass through: malformed, expired, not_yet_valid, name_domain_mismatch, key_lookup_failed', async () => {
  const one = async (d, args, want, opts = {}) =>
    scenario({ registry: { [regPath()]: { body: listingFor(d) } }, site: { [`${HOST}${byHashPath(d)}`]: { body: text(d) } }, ...opts }, args, (r) => {
      assert.equal(r.code, want, r.stdout);
      assert.match(r.stdout, new RegExp('^' + Object.keys(LISTING_STATES).find((s) => LISTING_STATES[s] === want)));
    });
  // The served file is the one the hash names, and it breaks a rule of its format.
  await one({ ...d1, extra: true }, [], 2);
  await one(d1, ['--now', '2027-06-01T00:00:00Z'], 5);
  await one(d1, ['--now', '2026-11-01T00:00:00Z'], 6);
  // A key at a parent domain proves only the exact namespace with the http method.
  const sub = signRaw({ ...decl01(), key: { method: 'http', domain: 'example.com' }, name: 'com.example.sub/weather' }, k.loaded);
  const subPath = `/.well-known/addon-declaration/com.example.sub/weather/by-hash/${hex(sub)}.json`;
  const w = await world({ registry: { [regPath('com.example.sub/weather')]: { body: listingFor(sub, { name: 'com.example.sub/weather', pointer: { url: `https://${HOST}${subPath}`, hash: declarationHash(sub) } }) } }, site: { [`${HOST}${subPath}`]: { body: text(sub) } } });
  try {
    const r = await w.run(['com.example.sub/weather', '--registry', w.registryUrl, '--now', NOW]);
    assert.equal(r.code, 7, r.stdout);
  } finally {
    await w.close();
  }
  await one(d1, [], 10, { keyResult: { keys: [], notes: [], error: 'https://example.com/.well-known/mcp-registry-auth answered HTTP 503 (a temporary failure, try again later)' } });
});

test('newer declarations: not chained, a forged by-hash file (attempted loop), too long, a key change, an invalid one; 8 links are accepted', async () => {
  const run = async (site, want, check) => scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith(site) }, ['--json'], (r) => {
    assert.equal(r.code, want, r.stdout);
    if (check) check(r.json);
  });
  // A valid 0.2 declaration for the same version that names no previous one.
  const loose = decl02();
  await run({ [`${HOST}${folder}latest.json`]: { body: text(loose) } }, 0, (j) => {
    assert.equal(j.newer[1].result, 'not_chained');
    assert.equal(j.inForce.hash, declarationHash(d1));
    assert.match(j.notes.join(' '), /latest\.json holds another declaration for this version that was not put in force/);
  });
  // N names M as previous, and the by-hash path of M serves N itself.
  const m = decl02({ previous: declarationHash(d1), issuedAt: '2026-11-18T11:00:00Z' });
  const n = decl02({ previous: declarationHash(m), issuedAt: '2026-11-18T12:00:00Z' });
  await run({ [`${HOST}${folder}latest.json`]: { body: text(n) }, [`${HOST}${byHashPath(m)}`]: { body: text(n) } }, 0, (j) => {
    assert.equal(j.newer[1].result, 'not_chained');
    assert.match(j.newer[1].reason, /is not the declaration with that hash/);
  });
  // Through M, served correctly: two links, in force.
  await run({ [`${HOST}${folder}latest.json`]: { body: text(n) }, [`${HOST}${byHashPath(m)}`]: { body: text(m) } }, 11, (j) => {
    assert.deepEqual(j.chain.map((c) => c.hash), [declarationHash(n), declarationHash(m), declarationHash(d1)]);
  });
  // A chain of MAX_CHAIN_LINKS links is accepted, one more is not.
  const chain = [d1];
  for (let i = 0; i < MAX_CHAIN_LINKS + 1; i++) chain.push(decl02({ previous: declarationHash(chain[chain.length - 1]), issuedAt: `2026-11-18T${String(11 + i).padStart(2, '0')}:00:00Z` }));
  const files = Object.fromEntries(chain.slice(1).map((d) => [`${HOST}${byHashPath(d)}`, { body: text(d) }]));
  await run({ ...files, [`${HOST}${folder}latest.json`]: { body: text(chain[MAX_CHAIN_LINKS]) } }, 11);
  await run({ ...files, [`${HOST}${folder}latest.json`]: { body: text(chain[MAX_CHAIN_LINKS + 1]) } }, 0, (j) => {
    assert.match(j.newer[1].reason, /within 8 links/);
  });
  // Signed with another key (both published): a key change is not put in force.
  const rotated = decl02({ previous: declarationHash(d1) }, k2);
  await run({ [`${HOST}${folder}latest.json`]: { body: text(rotated) } }, 0, (j) => assert.equal(j.newer[1].result, 'key_changed'));
  // A newer file with a broken signature.
  const broken = { ...d2, contact: 'mailto:x@example.com' };
  await run({ [`${HOST}${folder}latest.json`]: { body: text(broken) } }, 0, (j) => {
    assert.equal(j.newer[1].result, 'invalid');
    assert.equal(j.newer[1].state, 'invalid_signature');
  });
  // A 0.1 declaration that follows a 0.2 one is a format downgrade.
  const p02 = decl02();
  const back = decl01({ previous: declarationHash(p02), issuedAt: '2026-11-18T12:00:00Z' });
  await scenario({ registry: { [regPath()]: { body: listingFor(p02) } }, site: { [`${HOST}${byHashPath(p02)}`]: { body: text(p02) }, [`${HOST}${folder}latest.json`]: { body: text(back) } } }, ['--json'], (r) => {
    assert.equal(r.code, 0);
    assert.equal(r.json.newer[1].state, 'chain_mismatch');
  });
  // latest.json for a newer version is not a declaration for this listing.
  await run({ [`${HOST}${folder}latest.json`]: { body: text(decl02({ version: '2.0.0', previous: declarationHash(d1) })) } }, 0, (j) => assert.equal(j.newer[1].result, 'other_version'));
});

test('registry states: not found, unreachable, an answer that is not the listing', async () => {
  await scenario({}, [], (r) => assert.equal(r.code, 20));
  let n = 0;
  const flaky = (req, res) => {
    n++;
    res.writeHead(503);
    res.end();
  };
  await scenario({ registry: { [regPath()]: flaky } }, [], (r) => {
    assert.equal(r.code, 21);
    assert.equal(n, 2, 'a 503 is retried once');
  });
  await scenario({ registry: { [regPath()]: { body: '{"server":' } } }, [], (r) => assert.equal(r.code, 22));
  await scenario({ registry: { [regPath()]: { body: '{"server":{"name":"a","name":"b"}}' } } }, [], (r) => assert.equal(r.code, 22, 'duplicate members are refused'));
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { name: 'com.example/other' }) } } }, [], (r) => assert.equal(r.code, 22));
  await scenario({ registry: { [regPath(NAME, '1.0.0')]: { body: listingFor(d1, { version: '1.0.1' }) } } }, ['--version', '1.0.0'], (r) => assert.equal(r.code, 22));
});

test('hostile strings in listing fields reach the terminal escaped, in text and in --json', async () => {
  const evilVersion = `1.0.0${ESC}[2K${RLO}`;
  const listing = listingFor(d1, { version: evilVersion });
  listing._meta['io.modelcontextprotocol.registry/official'].publishedAt = `${ESC}]0;title${String.fromCharCode(7)}`;
  await scenario({ registry: { [regPath()]: { body: listing } }, site: siteWith() }, [], (r) => {
    assert.equal(r.code, 18);
    assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(RLO), r.stdout);
    assert.match(r.stdout, /\\u001b\[2K\\u202e/);
  });
  await scenario({ registry: { [regPath()]: { body: listing } }, site: siteWith() }, ['--json'], (r) => {
    assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(RLO));
    assert.equal(r.json.listing.version, evilVersion, 'the escapes decode back to the same string');
  });
  const ptr = { url: `https://${HOST}/${ESC}[31m${RLO}.json`, hash: declarationHash(d1) };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { pointer: ptr }) } } }, [], (r) => {
    assert.equal(r.code, 14);
    assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(RLO));
  });
  const badName = { server: { name: `com.example/weather${ESC}[8m`, version: '1' } };
  await scenario({ registry: { [regPath()]: { body: badName } } }, [], (r) => {
    assert.equal(r.code, 22);
    assert.ok(!r.stdout.includes(ESC));
  });
});

test('usage: registry base, name, version and tool flags', async () => {
  const w = await world();
  try {
    for (const args of [
      [NAME, '--registry', 'http://registry.example'],
      [NAME, '--registry', 'http://127.0.0.1/'],
      [NAME, '--registry', 'ftp://x.example'],
      [NAME, '--registry', 'https://u:p@registry.example'],
      [NAME, '--registry', 'https://registry.example/?q=1'],
      ['not a name'],
      [NAME, '--version', `1.0${ESC}`],
      [NAME, '--tools', 'x.json', '--fetch-tools'],
      [NAME, '--pubkey', 'x'],
      [],
    ]) {
      const r = await w.run(args);
      assert.equal(r.code, 1, args.join(' ') + r.stderr);
      assert.ok(!r.stderr.includes(ESC));
    }
    assert.equal(w.seen.length, 0);
  } finally {
    await w.close();
  }
  assert.deepEqual(registryBase('https://registry.modelcontextprotocol.io/'), { base: 'https://registry.modelcontextprotocol.io', loopback: false });
  assert.deepEqual(registryBase('http://localhost:8080'), { base: 'http://localhost:8080', loopback: true });
});

test('hardened fetch: https only unless a loopback http base is given, small request bodies, loopback addresses', async () => {
  await assert.rejects(httpsRequest('http://example.com/x'), /only https URLs/);
  await assert.rejects(httpsRequest('https://example.com/x', { method: 'POST', body: 'x'.repeat(MAX_REQUEST_BODY + 1) }), /request body larger/);
  // A loopback http base dials loopback addresses only.
  await assert.rejects(httpsRequest('http://localhost:1/x', { allowLoopbackHttp: true, lookupAll: async () => [{ address: '10.0.0.1', family: 4 }] }), /refusing to connect/);
  for (const ip of ['127.0.0.1', '127.1.2.3', '::1', '::ffff:127.0.0.1']) assert.equal(isLoopbackAddress(ip), true, ip);
  for (const ip of ['10.0.0.1', '8.8.8.8', '::', '::2', 'fe80::1']) assert.equal(isLoopbackAddress(ip), false, ip);
});

test('mcp client: event stream parsing and protocol version fallback', async () => {
  assert.deepEqual(sseEvents(': c\n\nevent: message\ndata: {"a":\ndata: 1}\n\ndata:x\r\n\r\n'), ['{"a":\n1}', 'x']);
  // An UnsupportedProtocolVersionError that lists 2025-06-18 leads to initialize with it.
  const calls = [];
  const request = async (url, opts) => {
    const m = JSON.parse(opts.body ?? '{}');
    calls.push([m.method, opts.headers['MCP-Protocol-Version'], m.params && m.params.protocolVersion]);
    const json = (status, obj, headers = {}) => ({ status, headers: { 'content-type': 'application/json', ...headers }, body: Buffer.from(JSON.stringify(obj)) });
    if (m.method === 'tools/list' && opts.headers['MCP-Protocol-Version'] === MODERN_PROTOCOL_VERSION) return json(400, { jsonrpc: '2.0', id: m.id, error: { code: -32022, message: 'Unsupported protocol version', data: { supported: ['2025-06-18'], requested: MODERN_PROTOCOL_VERSION } } });
    if (m.method === 'initialize') return json(200, { jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: {} } });
    if (m.method === 'notifications/initialized') return { status: 202, headers: {}, body: Buffer.alloc(0) };
    return json(200, { jsonrpc: '2.0', id: m.id, result: TOOLS });
  };
  const got = await fetchToolsList(REMOTE, { request });
  assert.equal(got.protocolVersion, '2025-06-18');
  assert.equal(got.session, false);
  assert.deepEqual(calls.map((c) => c[0]), ['tools/list', 'initialize', 'notifications/initialized', 'tools/list']);
  assert.equal(calls[1][2], '2025-06-18');
  // Only modern versions this client does not speak: unsupported.
  const only = async (url, opts) => ({ status: 400, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32022, message: 'x', data: { supported: ['2099-01-01'] } } })) });
  await assert.rejects(fetchToolsList(REMOTE, { request: only }), (e) => e.kind === 'unsupported');
  // A redirect is not followed.
  const redirect = async () => ({ status: 307, headers: { location: 'https://elsewhere.example/' }, body: Buffer.alloc(0) });
  await assert.rejects(fetchToolsList(REMOTE, { request: redirect }), /redirect, which is not followed/);
  // A response that is the answer to another request id is refused.
  const wrongId = async (url, opts) => ({ status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 99, result: TOOLS })) });
  await assert.rejects(fetchToolsList(REMOTE, { request: wrongId }), /not the JSON-RPC response to request 1/);
});

test('check-listing states and exit codes are distinct, and the verify codes are kept', () => {
  const codes = Object.values(LISTING_STATES);
  assert.equal(new Set(codes).size, codes.length);
  assert.ok(!codes.includes(1), 'exit code 1 stays for usage and file errors');
  assert.equal(LISTING_STATES.tools_hash_mismatch, 8);
  assert.equal(LISTING_STATES.verified, 0);
  assert.equal(LISTING_STATES.valid, undefined);
});

// Review round 5 (19 November 2026): hostile publisher sites and MCP servers,
// renewal after expiry, a bound on the whole check, and the text output.

test('a by-hash link with a "previous" that is not a declaration hash is set aside; the check does not crash', async () => {
  const k3 = makeKey('ed25519');
  for (const previous of [5, null, {}, 'sha256:../../../../../admin/secret?x=']) {
    // An unsigned file served at its own by-hash path, and a candidate signed
    // with any throwaway key that names it.
    const pd = { spec: SPEC_ID_02, name: NAME, version: VERSION, previous };
    const pdHash = declarationHash(pd);
    const cand = signRaw({ ...decl02({}, k3), previous: pdHash }, k3.loaded);
    const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(cand) }, [`${HOST}${folder}by-hash/${pdHash.slice(7)}.json`]: { body: JSON.stringify(pd) } });
    await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--json'], (r, w) => {
      assert.equal(r.code, 0, JSON.stringify(previous) + r.stdout + r.stderr);
      assert.equal(r.json.state, 'verified');
      assert.equal(r.json.newer[1].result, 'not_chained');
      assert.match(r.json.newer[1].reason, /not a valid declaration/);
      assert.equal(r.json.inForce.hash, declarationHash(d1));
      // Every request to the site stays in the folder of the declaration.
      for (const s of w.seen.filter((x) => x.host === HOST)) assert.ok(s.path.startsWith(folder), s.path);
      assert.ok(!w.seen.some((s) => s.path && s.path.includes('admin')), 'no request outside the folder');
    });
  }
});

test('an unexpected error while one newer file is checked sets that file aside and does not abort the check', async () => {
  const k3 = makeKey('ed25519');
  // Signed under a dns key, so its key lookup is a second, separate one.
  const cand = signRaw({ ...decl02({}, k3), previous: declarationHash(d1), key: { method: 'dns', domain: HOST, alg: 'ed25519', id: k3.loaded.public.id } }, k3.loaded);
  const w = await world({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith({ [`${HOST}${folder}latest.json`]: { body: text(cand) } }) });
  try {
    const keyLookup = async (method) => {
      if (method === 'dns') throw new TypeError('boom');
      return { keys, notes: [] };
    };
    const r = await checkListing({ name: NAME, registry: registryBase(w.registryUrl), now: Date.parse(NOW), keyLookup, request: w.deps.httpsRequest });
    assert.equal(r.state, 'verified');
    assert.equal(r.report.newer[1].result, 'invalid');
    assert.match(r.report.newer[1].reason, /it could not be checked \(boom\)/);
  } finally {
    await w.close();
  }
});

test('the declaration the listing names has expired: a renewed, chained declaration for the version is put in force', async () => {
  const A = decl01({ issuedAt: '2026-01-01T00:00:00Z', expiresAt: '2026-06-01T00:00:00Z' });
  const B = decl02({ previous: declarationHash(A), issuedAt: '2026-05-20T00:00:00Z', expiresAt: '2027-05-20T00:00:00Z' });
  const site = { [`${HOST}${byHashPath(A)}`]: { body: text(A) }, [`${HOST}${folder}latest.json`]: { body: text(B) } };
  await scenario({ registry: { [regPath()]: { body: listingFor(A) } }, site }, ['--json'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    assert.equal(r.json.declaration.state, 'expired');
    assert.equal(r.json.inForce.hash, declarationHash(B));
    assert.equal(r.json.inForce.state, 'valid');
    assert.match(r.json.notes.join(' '), /the declaration the listing names expired at 2026-06-01T00:00:00Z; a newer declaration for this version that follows it under the same key is in force/);
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(A) } }, site }, [], (r) => {
    assert.equal(r.code, 11);
    assert.match(r.stdout.split('\n')[1], /^ {2}the declaration the listing names has expired; a newer declaration/);
  });
  // The renewed one has expired too: expired, and the candidate says so.
  const B2 = decl02({ previous: declarationHash(A), issuedAt: '2026-05-20T00:00:00Z', expiresAt: '2026-10-01T00:00:00Z' });
  await scenario({ registry: { [regPath()]: { body: listingFor(A) } }, site: { ...site, [`${HOST}${folder}latest.json`]: { body: text(B2) } } }, ['--json'], (r) => {
    assert.equal(r.code, 5, r.stdout);
    assert.equal(r.json.newer[1].result, 'expired');
    assert.match(r.json.reasons[0], /expired at 2026-06-01/);
  });
  // A pointer with a bad signature is not rescued by a newer declaration.
  const tampered = { ...A, contact: 'mailto:other@example.com' };
  const B3 = decl02({ previous: declarationHash(tampered), issuedAt: '2026-05-20T00:00:00Z', expiresAt: '2027-05-20T00:00:00Z' });
  const ptr = { url: `https://${HOST}${byHashPath(tampered)}`, hash: declarationHash(tampered) };
  await scenario({ registry: { [regPath()]: { body: listingFor(tampered, { pointer: ptr }) } }, site: { [`${HOST}${byHashPath(tampered)}`]: { body: text(tampered) }, [`${HOST}${folder}latest.json`]: { body: text(B3) } } }, ['--json'], (r) => {
    assert.equal(r.code, 3, r.stdout);
    assert.deepEqual(r.json.newer, []);
  });
});

test('an expired declaration between the newest one and the named one does not set the newest aside', async () => {
  const m = decl02({ previous: declarationHash(d1), issuedAt: '2026-11-18T11:00:00Z', expiresAt: '2027-01-01T00:00:00Z' });
  const n = decl02({ previous: declarationHash(m), issuedAt: '2026-11-18T12:00:00Z', expiresAt: '2027-06-01T00:00:00Z' });
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(n) }, [`${HOST}${byHashPath(m)}`]: { body: text(m) } });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--now', '2027-02-01T00:00:00Z', '--json'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    assert.equal(r.json.inForce.hash, declarationHash(n));
    assert.deepEqual(r.json.chain.map((c) => c.hash), [declarationHash(n), declarationHash(m), declarationHash(d1)]);
  });
});

test('one time limit bounds every read of the check outside the tools fetch', async () => {
  const routes = {
    '/v0.1/servers/com.example%2Fweather/versions/latest': { delay: 0, body: JSON.stringify(listingFor(d1)) },
    [byHashPath(d1)]: { delay: 0, body: text(d1) },
    [`${folder}versions/1.0.0.json`]: { delay: 400, body: text(d2) },
    [`${folder}latest.json`]: { delay: 0, body: text(d2) },
  };
  const asked = [];
  const request = (url, opts) => {
    const u = new URL(url);
    asked.push(u.pathname);
    const r = routes[u.pathname];
    const delay = r ? r.delay : 0;
    return new Promise((resolve, reject) => {
      if (delay > opts.overallTimeoutMs) return setTimeout(() => reject(new Error('timed out')), opts.overallTimeoutMs);
      setTimeout(() => resolve(r ? { status: 200, headers: {}, body: Buffer.from(r.body) } : { status: 404, headers: {}, body: Buffer.alloc(0) }), delay);
    });
  };
  const t0 = Date.now();
  const r = await checkListing({ name: NAME, registry: { base: 'https://registry.example', loopback: false }, now: Date.parse(NOW), request, keyLookup: async () => ({ keys, notes: [] }), overallTimeoutMs: 250 });
  assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
  assert.equal(r.state, 'verified');
  assert.equal(r.report.newer[0].result, 'unreachable');
  assert.equal(r.report.newer[1].result, 'unreachable');
  assert.match(r.report.newer[1].reason, /overall time limit of 0\.25 seconds/);
  assert.ok(!asked.includes(`${folder}latest.json`), 'no request is sent once the time is up');
});

test('tools: a hostile MCP server cannot crash the command; any fetch error is tools_fetch_failed', async () => {
  const hostile = (req, res, body) => {
    const m = JSON.parse(body);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { tools: [], resultType: { toString: 1 } } }));
  };
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith({ [`POST ${HOST}/mcp`]: hostile }) }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 19, r.stdout + r.stderr);
    assert.match(r.json.reasons[0], /resultType a value of type object/);
  });
  // A replacement fetch that throws a plain TypeError: still 19, not "unexpected error".
  const w = await world({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith() });
  try {
    const fetchToolsListThrows = async () => {
      throw new TypeError('Cannot convert object to primitive value');
    };
    const r = await checkListing({ name: NAME, registry: registryBase(w.registryUrl), fetchTools: true, now: Date.parse(NOW), keyLookup: async () => ({ keys, notes: [] }), request: w.deps.httpsRequest, fetchToolsList: fetchToolsListThrows });
    assert.equal(r.state, 'tools_fetch_failed');
    assert.match(r.reasons[0], /the tools fetch failed: Cannot convert object to primitive value/);
  } finally {
    await w.close();
  }
  assert.equal(describe({ toString: 1, valueOf: 1 }), 'a value of type object');
  assert.equal(describe('x'.repeat(50)), JSON.stringify('x'.repeat(40) + '...'));
});

test('tools: any 4xx without a recognized modern error leads to the initialize flow (406 here); 408 and 429 do not', async () => {
  let calls = [];
  const make = (modernStatus) => async (url, opts) => {
    const m = JSON.parse(opts.body ?? '{}');
    calls.push(m.method);
    const json = (status, obj) => ({ status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(obj)) });
    if (m.method === 'tools/list' && opts.headers['MCP-Protocol-Version'] === MODERN_PROTOCOL_VERSION) return { status: modernStatus, headers: { 'content-type': 'text/plain' }, body: Buffer.from('no') };
    if (m.method === 'initialize') return json(200, { jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-11-25', capabilities: {} } });
    if (m.method === 'notifications/initialized') return { status: 202, headers: {}, body: Buffer.alloc(0) };
    return json(200, { jsonrpc: '2.0', id: m.id, result: TOOLS });
  };
  const got = await fetchToolsList(REMOTE, { request: make(406) });
  assert.equal(got.era, 'legacy');
  assert.deepEqual(calls, ['tools/list', 'initialize', 'notifications/initialized', 'tools/list']);
  for (const s of [408, 429, 500]) {
    calls = [];
    await assert.rejects(fetchToolsList(REMOTE, { request: make(s) }), new RegExp(`HTTP ${s}`));
    assert.deepEqual(calls, ['tools/list'], `no initialize after ${s}`);
  }
});

test('--version "." and ".." are refused before any request', async () => {
  const w = await world();
  try {
    for (const v of ['.', '..']) {
      const r = await w.run([NAME, '--registry', w.registryUrl, '--version', v]);
      assert.equal(r.code, 1, v);
      assert.match(r.stderr, /not "\." or "\.\."/);
    }
    assert.equal(w.seen.length, 0);
  } finally {
    await w.close();
  }
  assert.equal(isVersionArgument('1.0.0'), true);
  assert.equal(isVersionArgument('...'), true);
});

test('special use ranges are not public: IPv4 translated, benchmarking, protocol assignments, documentation, discard only', () => {
  for (const ip of ['::ffff:0:7f00:1', '::ffff:0:808:808', '198.18.0.1', '198.19.255.255', '192.0.0.8', '192.0.2.1', '198.51.100.7', '203.0.113.9', '100::1', '2001:db8::1']) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['198.17.255.255', '198.20.0.1', '192.0.1.1', '203.0.114.1', '2001:db9::1', '100:0:0:1::1', '::ffff:8.8.8.8']) assert.equal(isPublicAddress(ip), true, ip);
});

test('when a tool flag is given and the check stops early, the output says where it stopped, and every step not run is listed', async () => {
  await scenario({ registry: { [regPath()]: { body: listingFor(null) } } }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 12);
    assert.equal(r.json.tools.reason, 'the check stopped at no_declaration, before the tool check');
    assert.ok(r.json.notChecked.includes('the declaration the listing names (fetch and hash) (the check stopped at no_declaration)'), r.json.notChecked.join('\n'));
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1, { remotes: [] }) } }, site: siteWith() }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, 18);
    assert.match(r.stdout, /not checked: key lookup, signature and time window of the declaration the listing names \(the check stopped at listing_mismatch\)/);
    assert.match(r.stdout, /not checked: newer declarations for this version \(versions\/1\.0\.0\.json and latest\.json were not read\) \(the check stopped at listing_mismatch\)/);
    assert.match(r.stdout, /not checked: tools \(the check stopped at listing_mismatch, before the tool check\)/);
    assert.ok(!/neither --tools/.test(r.stdout));
  });
});

test('tools_fetch_failed with a newer declaration in force: its own checks are shown, and the meaning line is third', async () => {
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: { status: 500, body: 'x' } });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools', '--json'], (r) => {
    assert.equal(r.code, 19, r.stdout);
    assert.equal(r.json.inForce.state, 'valid');
    assert.ok(r.json.inForce.verify.checked.includes('chain link to previous declaration'));
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    const lines = r.stdout.split('\n');
    assert.match(lines[1], /^ {2}the declaration in force verifies, but the tool list could not be read/);
    assert.match(lines[2], /^ {2}meaning: the holder of the named key signed this content/);
    assert.match(r.stdout, /checked \(declaration in force\): chain link to previous declaration/);
    assert.ok(!/not checked.*chain link/.test(r.stdout), r.stdout);
    assert.ok(!/no tool list given/.test(r.stdout), r.stdout);
    assert.match(r.stdout, /request: HTTP 500 POST tools\/list https:\/\/example\.com\/mcp/);
  });
});

test('passed through states say which declaration fails; a 0.2 digest mismatch is explained', async () => {
  const tampered = { ...d1, contact: 'mailto:other@example.com' };
  const ptr = { url: `https://${HOST}${byHashPath(tampered)}`, hash: declarationHash(tampered) };
  await scenario({ registry: { [regPath()]: { body: listingFor(tampered, { pointer: ptr }) } }, site: { [`${HOST}${byHashPath(tampered)}`]: { body: text(tampered) } } }, [], (r) => {
    assert.equal(r.code, 3);
    assert.match(r.stdout.split('\n')[1], /^ {2}the declaration the listing names fails the declaration check \(invalid_signature, as verify reports it\); the reasons follow$/);
  });
  const two = [{ name: 'a', inputSchema: { type: 'object' } }, { name: 'b', inputSchema: { type: 'object' } }];
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`POST ${HOST}/mcp`]: mcpServer('paged', { tools: two }) });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, 8);
    const lines = r.stdout.split('\n');
    assert.match(lines[1], /the tool list differs from the two digests the declaration in force \(from latest\.json, sha256:[0-9a-f]{64}\) signs, or could not be compared with them \(exit 8, named tools_hash_mismatch as in verify\)/);
    assert.match(lines[2], /meaning:/);
    assert.ok(!/not checked.*chain link \(not run/.test(r.stdout), r.stdout);
  });
});

test('text output: request lines name the method, refusals are told apart, and the registry headline names the version asked', async () => {
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`${HOST}/mcp`]: mcpServer('legacy') });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--fetch-tools'], (r) => {
    assert.equal(r.code, 11, r.stdout);
    assert.match(r.stdout, /request: HTTP 200 GET http:\/\/127\.0\.0\.1:\d+\/v0\.1\/servers\/com\.example%2Fweather\/versions\/latest/);
    assert.match(r.stdout, /request: HTTP 400 POST tools\/list https:\/\/example\.com\/mcp/);
    assert.match(r.stdout, /request: HTTP 202 POST notifications\/initialized https:\/\/example\.com\/mcp/);
    assert.match(r.stdout, /request: HTTP 200 DELETE \(session end\) https:\/\/example\.com\/mcp/);
    assert.match(r.stdout, /newer declaration at latest\.json: in force, sha256:[0-9a-f]{64} \(addon-declaration\/0\.2\)/);
    assert.match(r.stdout, /key source: https:\/\/example\.com\/\.well-known\/mcp-registry-auth \(http method\)/);
    assert.match(r.stdout, /namespace covered by an http key at example\.com/);
    // The format change note says what was and was not compared.
    assert.match(r.stdout, /the tool list was compared with the declaration in force only/);
    assert.ok(!/fetched:/.test(r.stdout));
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith(), addresses: { [HOST]: [{ address: '10.0.0.5', family: 4 }] } }, [], (r) => {
    assert.match(r.stdout, /request: refused before connecting \(refusing to connect: every address of the host is private/);
  });
  await scenario({}, [], (r) => {
    assert.equal(r.code, 20);
    assert.match(r.stdout, /^registry_not_found: com\.example\/weather, latest version\n {2}the registry has no listing for this name and version \(HTTP 404\); nothing else was read\n {2}reason: the registry answered HTTP 404 for the latest version of com\.example\/weather\n/);
  });
  await scenario({}, ['--version', '9.9.9'], (r) => {
    assert.match(r.stdout, /^registry_not_found: com\.example\/weather, version 9\.9\.9\n/);
    assert.match(r.stdout, /reason: the registry answered HTTP 404 for com\.example\/weather version 9\.9\.9/);
  });
  await scenario({ registry: { [regPath()]: { headers: { 'Content-Type': 'text/html' }, body: '<html>' } } }, [], (r) => {
    assert.equal(r.code, 22);
    assert.match(r.stdout, /reason: the registry answer is not strict JSON \(.*\); the base URL may not be a registry API/);
  });
});

test('text output: an unreachable loopback registry is not called a public address', async () => {
  const s = http.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  let out = '';
  const code = await main(['check-listing', NAME, '--registry', `http://127.0.0.1:${port}`], { stdout: { write: (x) => (out += x) }, stderr: { write: () => {} }, env: {} });
  assert.equal(code, 21);
  assert.match(out, /reason: the request to the registry failed: every address tried failed \(last: /);
  assert.ok(!/public/.test(out), out);
  assert.equal(out.match(/could not be read/g), null, 'the words and the reason do not repeat each other');
});

test('text output: long listing strings are cut to 200 characters; --json keeps them whole', async () => {
  const long = 'z'.repeat(5000);
  const listing = listingFor(d1);
  listing._meta['io.modelcontextprotocol.registry/official'].status = long;
  listing._meta['io.modelcontextprotocol.registry/official'].publishedAt = long;
  await scenario({ registry: { [regPath()]: { body: listing } }, site: siteWith() }, [], (r) => {
    assert.equal(r.code, 0);
    for (const line of r.stdout.split('\n')) assert.ok(line.length < 700, `a line of ${line.length} characters`);
  });
  await scenario({ registry: { [regPath()]: { body: listing } }, site: siteWith() }, ['--json'], (r) => assert.equal(r.json.listing.registryStatus, long));
});

test('a newer declaration under another key: the words line and newerSetAside say so', async () => {
  const rotated = decl02({ previous: declarationHash(d1) }, k2);
  const site = siteWith({ [`${HOST}${folder}latest.json`]: { body: text(rotated) } });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, [], (r) => {
    assert.equal(r.code, 0);
    assert.match(r.stdout.split('\n')[1], /verifies and is in force; a newer declaration signed under another key was found and not used \(see note\)/);
    assert.match(r.stdout, /newer declaration at latest\.json: not used, it is signed under another key \(see note\)/);
  });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site }, ['--json'], (r) => assert.equal(r.json.newerSetAside, true));
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith() }, ['--json'], (r) => assert.equal(r.json.newerSetAside, false));
});

test('a newer declaration in force that declares other remotes: listing_mismatch, and the file reads remotes_differ, not in_force', async () => {
  const moved = decl02({ previous: declarationHash(d1), remotes: [{ type: 'streamable-http', url: 'https://example.com/mcp2' }] });
  await scenario({ registry: { [regPath()]: { body: listingFor(d1) } }, site: siteWith({ [`${HOST}${folder}versions/1.0.0.json`]: { body: text(moved) } }) }, ['--json'], (r) => {
    assert.equal(r.code, 18);
    assert.equal(r.json.newer[0].result, 'remotes_differ');
    assert.deepEqual(r.json.remotesInForce.onlyInDeclaration, [{ type: 'streamable-http', url: 'https://example.com/mcp2' }]);
  });
});

test('a server._meta that is present and not an object is pointer_malformed', async () => {
  const l = listingFor(d1);
  l.server._meta = null;
  await scenario({ registry: { [regPath()]: { body: l } } }, [], (r) => assert.equal(r.code, 13));
});

test('check-listing --help prints only its own part, within 80 columns', async () => {
  let out = '';
  const code = await main(['check-listing', '--help'], { stdout: { write: (x) => (out += x) }, stderr: { write: () => {} }, env: {} });
  assert.equal(code, 0);
  assert.equal(out, HELP_CHECK_LISTING);
  assert.ok(!out.includes('hash-tools'));
  for (const line of out.split('\n')) assert.ok(line.length <= 80, `${line.length}: ${line}`);
  assert.match(out.replace(/\s+/g, ' '), /--now sets the time the time window is checked against/);
  assert.match(out.replace(/\s+/g, ' '), /or a parent of it/);
});
