// Proof record parsing, private key forms and the http key fetch. The fetch
// tests use a local plain HTTP server on 127.0.0.1 only; nothing leaves the machine.

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { parseProofRecords, loadPrivateKey, KeyError } from '../lib/keys.js';
import { EventEmitter } from 'node:events';
import { isPublicAddress, httpsGetText, dnsResolverFor, keysFromHttp, DNS_TIMEOUT_MS, HTTP_PER_ADDRESS_DIAL_MS } from '../lib/resolve.js';
import { DeclarationError } from '../lib/declaration.js';
import { ToolsError } from '../lib/tools.js';
import { JsonError } from '../lib/jcs.js';
import { makeKey } from '../testlib/helpers.js';

const ed = makeKey('ed25519');
const P = ed.loaded.public.raw.toString('base64');

test('proof records: k= is compared exactly, as the registry does', () => {
  assert.equal(parseProofRecords(`v=MCPv1; k=ed25519; p=${P}`).keys.length, 1);
  assert.equal(parseProofRecords(`v=MCPv1;k= ed25519 ;p=${P}`).keys.length, 0);
  assert.equal(parseProofRecords(`v=MCPv1; k=ed25519 ; p=${P}`).keys.length, 0);
});

test('proof records: only the RE2 spaces (tab, LF, FF, CR, space) may follow ";", as in the registry pattern', () => {
  for (const sep of ['', ' ', '  ', '\t', '\n', '\f', '\r', ' \t']) {
    assert.equal(parseProofRecords(`v=MCPv1;${sep}k=ed25519;${sep}p=${P}`).keys.length, 1, JSON.stringify(sep));
  }
  // JavaScript \s would match these; Go RE2 \s does not, so the registry would not read the record.
  for (const cp of [0x0b, 0xa0, 0x2003, 0x2000, 0x200a, 0x3000, 0xfeff, 0x1680, 0x2028]) {
    const sep = String.fromCodePoint(cp);
    assert.equal(parseProofRecords(`v=MCPv1;${sep}k=ed25519;${sep}p=${P}`).keys.length, 0, `U+${cp.toString(16)}`);
    assert.equal(parseProofRecords(`v=ADKv1;${sep}k=ed25519; p=${P}`).keys.length, 0, `ADKv1 U+${cp.toString(16)}`);
  }
});

test('proof records: p= is decoded as Go StdEncoding does (nonzero padding bits accepted, structure not)', () => {
  // A 32 byte key is 44 base64 characters ending in one "="; the last data
  // character carries 2 unused bits. Setting them gives the same bytes.
  const last = P[42];
  const ALPH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const idx = ALPH.indexOf(last);
  assert.equal(idx & 3, 0, 'canonical form has zero padding bits');
  const loose = P.slice(0, 42) + ALPH[idx | 1] + '=';
  assert.notEqual(loose, P);
  const r = parseProofRecords(`v=MCPv1; k=ed25519; p=${loose}`);
  assert.equal(r.keys.length, 1);
  assert.equal(r.keys[0].id, ed.loaded.public.id);
  // Missing padding, data after padding and a short value are still refused, with a note.
  for (const bad of [P.slice(0, 43), P + 'AAAA', P.slice(0, 3)]) {
    const x = parseProofRecords(`v=MCPv1; k=ed25519; p=${bad}`);
    assert.equal(x.keys.length, 0, bad);
    assert.match(x.notes.join(' '), /invalid base64|must be 32 bytes/, bad);
  }
  // A key that is not a compressed P-384 point gets a note too.
  const notCompressed = Buffer.alloc(49, 1);
  notCompressed[0] = 0x04;
  assert.match(parseProofRecords(`v=MCPv1; k=ecdsap384; p=${notCompressed.toString('base64')}`).notes.join(' '), /compressed point/);
});

test('proof records: ADKv1 declaration only records', () => {
  const both = parseProofRecords(`v=ADKv1; k=ed25519; p=${P}`);
  assert.equal(both.keys.length, 1);
  assert.equal(both.keys[0].record, 'addon');
  assert.equal(both.keys[0].id, ed.loaded.public.id);
  assert.equal(parseProofRecords(`v=ADKv1; k=ed25519; p=${P}`, { kinds: ['mcp'] }).keys.length, 0);
  // The registry's pattern does not match the declaration only record.
  assert.equal(/v=MCPv1;[\t\n\f\r ]*k=([^;]+);[\t\n\f\r ]*p=([A-Za-z0-9+/=]+)/.test(`v=ADKv1; k=ed25519; p=${P}`), false);
});

test('private key: P-384 scalars printed without leading zeros still load', () => {
  for (const top of [0x00, 0x0f]) {
    const d = crypto.randomBytes(48);
    d[0] = top;
    d[1] |= 0x01;
    const full = d.toString('hex');
    const want = loadPrivateKey(full).public.id;
    const short = top === 0 ? full.slice(2) : full.slice(1); // 94 or 95 digits
    assert.equal(loadPrivateKey(short).public.id, want, `${short.length} digits`);
    assert.equal(loadPrivateKey('00' + full).public.id, want, 'a leading 00 byte');
  }
  for (const bad of ['1'.repeat(63), '1'.repeat(65), '1'.repeat(92), '1'.repeat(97), '11'.repeat(36)]) {
    assert.throws(() => loadPrivateKey(bad), /digits; expected 64 \(ed25519\) or 96 \(ecdsap384\)/, `${bad.length} digits`);
  }
});

test('error classes carry their own name and a reason code', () => {
  for (const [C, name] of [[KeyError, 'KeyError'], [DeclarationError, 'DeclarationError'], [ToolsError, 'ToolsError'], [JsonError, 'JsonError']]) {
    assert.equal(new C('x').name, name);
  }
  assert.equal(new ToolsError('x', 'ambiguous').reason, 'ambiguous');
  assert.equal(new JsonError('x', 'range').reason, 'range');
  try {
    loadPrivateKey('zz');
  } catch (e) {
    assert.equal(e.name, 'KeyError');
  }
});

test('address filter refuses what the registry refuses', () => {
  const blocked = [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '100.127.255.255',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'fec0::1', 'ff02::1',
    '2002:c0a8:101::1', '64:ff9b::7f00:1', '64:ff9b:1::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', 'not an ip',
  ];
  for (const ip of blocked) assert.equal(isPublicAddress(ip), false, ip);
  for (const ip of ['93.184.215.14', '8.8.8.8', '172.32.0.1', '100.128.0.1', '2606:4700::1111', '::ffff:8.8.8.8']) assert.equal(isPublicAddress(ip), true, ip);
});

// A transport that records each address it is asked to dial and fails every dial.
function refusingTransport(dialed) {
  return {
    get: (url, options) => {
      const handlers = {};
      const req = { on: (ev, fn) => ((handlers[ev] = fn), req), destroy: () => {} };
      options.lookup('h', { all: true }, (err, list) => dialed.push(list[0].address));
      setImmediate(() => handlers.error && handlers.error(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })));
      return req;
    },
  };
}

test('http fetch: non public addresses are dropped and not dialed; none left means refused', async () => {
  const dialed = [];
  const transport = refusingTransport(dialed);
  for (const addrs of [[{ address: '127.0.0.1', family: 4 }], [{ address: '10.0.0.5', family: 4 }, { address: 'fd00::1', family: 6 }]]) {
    await assert.rejects(httpsGetText('https://evil.example/.well-known/mcp-registry-auth', { lookupAll: async () => addrs, transport }), /refusing to connect/);
  }
  assert.deepEqual(dialed, []);
  // A public A record next to a ULA or NAT64 record: the registry uses the public one, and so does this.
  const mixed = [{ address: 'fd00::1', family: 6 }, { address: '93.184.215.14', family: 4 }, { address: '64:ff9b::7f00:1', family: 6 }, { address: '8.8.8.8', family: 4 }];
  await assert.rejects(httpsGetText('https://good.example/.well-known/mcp-registry-auth', { lookupAll: async () => mixed, transport, attempts: 1 }), /all resolved public addresses failed/);
  assert.deepEqual(dialed, ['93.184.215.14', '8.8.8.8'], 'only the public addresses, in order');
});

test('http fetch: a host lookup failure is key_lookup_failed (the system resolver cannot tell NXDOMAIN from an outage)', async () => {
  const lookupAll = async () => {
    throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' });
  };
  const r = await keysFromHttp('gone.example', { get: (url) => httpsGetText(url, { lookupAll, attempts: 1 }) });
  assert.match(r.error, /could not resolve host \(ENOTFOUND\)/);
});

// A local server; the fetch is pointed at it through the pinned address while
// the URL keeps a made up host name, which must still be sent as Host.
async function withServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const opts = { transport: http, allowAddress: () => true, lookupAll: async () => [{ address: '127.0.0.1', family: 4 }] };
  try {
    return await fn(`http://key-host.example:${port}/.well-known/mcp-registry-auth`, opts);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

test('http fetch: pinned address, Host kept, redirect not followed, size cap, timeout, retry', async () => {
  const seen = [];
  await withServer((req, res) => {
    seen.push(req.headers.host);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(ed.record);
  }, async (url, opts) => {
    const r = await httpsGetText(url, opts);
    assert.deepEqual(r, { status: 200, body: ed.record });
    assert.match(seen[0], /^key-host\.example:\d+$/);
  });

  await withServer((req, res) => {
    res.writeHead(301, { Location: 'http://127.0.0.1/elsewhere' });
    res.end(ed.record);
  }, async (url, opts) => {
    assert.equal((await httpsGetText(url, opts)).status, 301);
  });

  await withServer((req, res) => {
    res.writeHead(200);
    res.end('x'.repeat(5000));
  }, async (url, opts) => {
    await assert.rejects(httpsGetText(url, { ...opts, attempts: 1 }), /larger than 4096/);
  });

  await withServer(() => {}, async (url, opts) => {
    const t0 = Date.now();
    await assert.rejects(httpsGetText(url, { ...opts, attemptTimeoutMs: 150, overallTimeoutMs: 1500 }), /timed out/);
    assert.ok(Date.now() - t0 < 1500 + 1000);
  });

  // 503, 408 and 429 are retried once, as the registry's transient set.
  for (const first of [503, 408, 429]) {
    let n = 0;
    await withServer((req, res) => {
      n++;
      res.writeHead(n === 1 ? first : 200);
      res.end(ed.record);
    }, async (url, opts) => {
      assert.equal((await httpsGetText(url, opts)).status, 200, String(first));
      assert.equal(n, 2, String(first));
    });
  }
  // 403 is not retried.
  let m = 0;
  await withServer((req, res) => {
    m++;
    res.writeHead(403);
    res.end();
  }, async (url, opts) => {
    assert.equal((await httpsGetText(url, opts)).status, 403);
    assert.equal(m, 1);
  });
});

test('http fetch: when the first checked address cannot be reached, the next one is used', async () => {
  await withServer((req, res) => {
    res.writeHead(200);
    res.end(ed.record);
  }, async (url, opts) => {
    // The server listens on 127.0.0.1 only; 127.0.0.2 refuses (or does not answer).
    const lookupAll = async () => [{ address: '127.0.0.2', family: 4 }, { address: '127.0.0.1', family: 4 }];
    const r = await httpsGetText(url, { ...opts, lookupAll, attempts: 1, dialTimeoutMs: 1500 });
    assert.equal(r.status, 200);
    assert.equal(r.body, ed.record);
  });
});

// Review round 3 (18 November 2026).

// A transport that does not connect to the address `hang` (no error, no connect,
// as a dead host behind a dropping firewall) and answers 200 from any other.
function hangingTransport(dialed, hang) {
  return {
    get: (url, options, cb) => {
      const handlers = {};
      const req = { on: (ev, fn) => ((handlers[ev] = fn), req), destroy: () => {} };
      let address;
      options.lookup('h', { all: true }, (err, list) => (address = list[0].address));
      dialed.push(address);
      if (address !== hang) {
        setImmediate(() => {
          const res = new EventEmitter();
          res.statusCode = 200;
          cb(res);
          res.emit('data', Buffer.from(ed.record));
          res.emit('end');
        });
      }
      return req;
    },
  };
}

test('http fetch: a first address that does not connect is left after the per address dial limit, not the attempt limit', async () => {
  const lookupAll = async () => [{ address: '93.184.215.14', family: 4 }, { address: '8.8.8.8', family: 4 }];
  const dialed = [];
  const t0 = Date.now();
  const r = await httpsGetText('https://k.example/.well-known/mcp-registry-auth', { lookupAll, transport: hangingTransport(dialed, '93.184.215.14'), attempts: 1, attemptTimeoutMs: 8000, overallTimeoutMs: 8000, dialTimeoutMs: 200 });
  const took = Date.now() - t0;
  assert.equal(r.status, 200);
  assert.deepEqual(dialed, ['93.184.215.14', '8.8.8.8'], 'the second address is dialed after the first');
  assert.ok(took >= 150 && took < 2000, `moved on after ${took} ms`);
});

test('http fetch: the default per address dial limit is 3 seconds', async () => {
  assert.equal(HTTP_PER_ADDRESS_DIAL_MS, 3000);
  const lookupAll = async () => [{ address: '93.184.215.14', family: 4 }, { address: '8.8.8.8', family: 4 }];
  const dialed = [];
  const t0 = Date.now();
  // The attempt limit (10 seconds) is far above 3 seconds, so only the dial limit can move on in time.
  const r = await httpsGetText('https://k.example/.well-known/mcp-registry-auth', { lookupAll, transport: hangingTransport(dialed, '93.184.215.14'), attempts: 1 });
  const took = Date.now() - t0;
  assert.equal(r.status, 200);
  assert.deepEqual(dialed, ['93.184.215.14', '8.8.8.8']);
  assert.ok(took >= 2900 && took < 6000, `moved on after ${took} ms`);
});

test('address filter: the IPv4 compatible range ::/96 is refused (SPEC section 9 lists it)', () => {
  for (const ip of ['::8.8.8.8', '::808:808', '::2']) assert.equal(isPublicAddress(ip), false, ip);
});

test('dns resolver: built with the registry timeout and one try; the server must be an IP address', () => {
  assert.equal(DNS_TIMEOUT_MS, 5000);
  let built;
  class FakeResolver {
    constructor(o) {
      built = o;
    }
    setServers(s) {
      this.servers = s;
    }
  }
  const r = dnsResolverFor('192.0.2.1', { Resolver: FakeResolver });
  assert.deepEqual(built, { timeout: 5000, tries: 1 });
  assert.deepEqual(r.servers, ['192.0.2.1']);
  assert.throws(() => dnsResolverFor('notanip'), /must be an IP address/);
  assert.ok(dnsResolverFor('192.0.2.1'));
});

test('proof records: every record in one TXT string or one http body is read, as the registry does since PR 1849', () => {
  const other = makeKey('ed25519').loaded.public.raw.toString('base64');
  const ids = (text) => parseProofRecords(text, { kinds: ['mcp'] }).keys.map((k) => k.raw.toString('base64'));
  // One record per line, as the registry documentation advises for an http body.
  assert.deepEqual(ids(`v=MCPv1; k=ed25519; p=${other}\nv=MCPv1; k=ed25519; p=${P}`), [other, P]);
  // Two records in one string, the first with an unsupported algorithm.
  assert.deepEqual(ids(`v=MCPv1; k=foo; p=AAAA v=MCPv1; k=ed25519; p=${P}`), [P]);
});
