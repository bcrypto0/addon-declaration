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
import { httpsRequest, isPublicAddress } from '../lib/resolve.js';
import { signDeclaration, declarationHash, SPEC_ID_01, SPEC_ID_02, STATES } from '../lib/declaration.js';
import { parseProofRecords } from '../lib/keys.js';
import { toolsHash } from '../lib/tools.js';
import { toolSetDigestsFromPages } from '../lib/tool-set-digest.js';
import { LISTING_STATES, registryBase, DEFAULT_REGISTRY } from '../lib/listing.js';
import { MODERN_PROTOCOL_VERSION } from '../lib/mcp-client.js';
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

async function world({ registry = {}, site = {}, httpKeys = { keys: published, notes: [] }, dnsKeys = { keys: [], notes: ['no TXT records at example.com'] } } = {}) {
  const seen = [];
  const reg = await serve(registry, seen);
  const st = await serve(site, seen);
  const request = (url, opts) => {
    const u = new URL(url);
    if (u.protocol === 'http:') return httpsRequest(url, opts);
    const local = `http://${u.hostname}:${st.port}${u.pathname}${u.search}`;
    return httpsRequest(local, { ...opts, transport: http, lookupAll: async () => [{ address: '127.0.0.1', family: 4 }], allowAddress: (a) => a === '127.0.0.1' || isPublicAddress(a) });
  };
  const lookups = [];
  const deps = {
    httpsRequest: request,
    keysFromHttp: async (domain) => (lookups.push(['http', domain]), typeof httpKeys === 'function' ? httpKeys(domain) : httpKeys),
    keysFromDns: async (domain) => (lookups.push(['dns', domain]), typeof dnsKeys === 'function' ? dnsKeys(domain) : dnsKeys),
    dnsResolverFor: () => ({}),
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

const baseRegistry = (extra = {}) => ({ [regPath()]: { body: listingFor() }, ...extra });
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
  // A declaration whose signature does not verify under a published key is not linked, and the note says why.
  const forged = { ...JSON.parse(text(d2)), signature: JSON.parse(text(d1)).signature };
  await scenario({ registry: baseRegistry(), site: baseSite({ [`${HOST}${folder}latest.json`]: { body: text(forged) } }) }, [NAME, '--for-version', '1.0.1', '--key-env', 'MCP_PRIVATE_KEY', '--out', freshOut(), '--json'], (r) => {
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.previous.linked, false);
    assert.equal(r.json.previous.result, 'invalid_signature');
    assert.ok(r.json.notes.some((n) => /latest\.json is not linked as previous: it gives invalid_signature/.test(n)));
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
