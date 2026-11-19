// Live key lookup, following what the official MCP Registry does (SPEC.md
// section 9):
//   dns:  TXT records at the apex of the domain (no selector label), 5 seconds
//   http: GET https://<domain>/.well-known/mcp-registry-auth, Accept text/plain,
//         no redirects, 200 only, body at most 4096 bytes, at most 2 attempts of
//         10 seconds each within 15 seconds overall, and only to public
//         addresses (non public addresses are dropped, the public ones are
//         dialed in order, 3 seconds each, and only a checked address is dialed)
// Both return { keys, notes } on an answer, or { keys: [], notes, error } when
// the lookup itself failed (timeout, SERVFAIL, refused address, 408, 429, 5xx,
// an access refusal). Only this file touches the network.

import dns from 'node:dns';
import net from 'node:net';
import https from 'node:https';
import { parseProofRecords } from './keys.js';

export const MAX_KEY_RESPONSE = 4096;
export const DNS_TIMEOUT_MS = 5000;
export const HTTP_ATTEMPT_TIMEOUT_MS = 10000;
export const HTTP_OVERALL_TIMEOUT_MS = 15000;
export const HTTP_ATTEMPTS = 2;
export const HTTP_PER_ADDRESS_DIAL_MS = 3000;
const HTTP_RETRY_BACKOFF_MS = 500;
export const HTTP_USER_AGENT = 'addon-declare/0.2';

// The registry's transient set (isTransientHTTPStatus in http.go): retried.
export function isTransientStatus(status) {
  return status === 408 || status === 429 || status >= 500;
}

// Statuses that are an answer: the domain does not publish a key there that the
// registry would read (the registry source read for SPEC.md section 2 does not follow redirects either).
export function isNotPublishedStatus(status) {
  return (status >= 300 && status < 400) || status === 404 || status === 410;
}

// Answers that mean "the domain does not publish a key there" rather than "the
// lookup could not be completed".
const DNS_NO_RECORD_CODES = new Set(['ENODATA', 'ENOTFOUND']);

// NXDOMAIN and an empty answer come from a real DNS answer here (the resolver
// talks to a name server), so they mean "not published". The http method's host
// lookup goes through the system resolver, which cannot tell a missing name from
// an unreachable name server, so there a failed host lookup is a lookup failure.
// resolver: anything with resolveTxt(name) -> Promise<string[][]>, so tests can
// pass a fake. Each TXT record arrives as one or more character strings; they
// are joined per record (as Go's net.LookupTXT, used by the registry, does).
export async function keysFromDns(domain, { resolver } = {}) {
  const r = resolver || dnsResolverFor();
  let records;
  try {
    records = await r.resolveTxt(domain);
  } catch (e) {
    if (e && DNS_NO_RECORD_CODES.has(e.code)) return { keys: [], notes: [`no TXT records at ${domain}`] };
    return { keys: [], notes: [], error: `DNS lookup for ${domain} failed (${e && e.code ? e.code : 'unknown error'})` };
  }
  const keys = [];
  const notes = [];
  for (const rec of records) {
    const parsed = parseProofRecords(rec.join(''));
    keys.push(...parsed.keys);
    notes.push(...parsed.notes);
  }
  if (keys.length === 0) notes.push(`no usable proof record in ${records.length} TXT record(s) at ${domain}`);
  return { keys, notes };
}

// get: optional replacement for the HTTPS request, (url) -> Promise<{ status, body }>, for tests.
// Status rules (SPEC.md section 9): 200 is read; a 3xx, 404 or 410 means the key
// is not published there; every other status (408, 429, 5xx, and 401, 403, 451
// or another refusal, which may come from a CDN or bot challenge) and every
// network failure is a lookup failure that says nothing about the key.
export async function keysFromHttp(domain, { get } = {}) {
  const url = `https://${domain}/.well-known/mcp-registry-auth`;
  let res;
  try {
    res = await (get || httpsGetText)(url);
  } catch (e) {
    return { keys: [], notes: [], error: `could not fetch ${url} (${e.message})` };
  }
  if (isNotPublishedStatus(res.status)) return { keys: [], notes: [`${url} answered HTTP ${res.status}; only 200 is read and redirects are not followed`] };
  if (res.status !== 200) {
    const why = isTransientStatus(res.status)
      ? 'a temporary failure, try again later'
      : res.status === 401 || res.status === 403 || res.status === 451
        ? 'access was refused, possibly by a CDN, firewall or bot challenge; this does not show that the key is absent'
        : 'not an answer about the key';
    return { keys: [], notes: [], error: `${url} answered HTTP ${res.status} (${why})` };
  }
  // The registry reads only MCPv1 records from this file.
  const { keys, notes } = parseProofRecords(res.body.trim(), { kinds: ['mcp'] });
  if (keys.length === 0) notes.push(`no usable MCPv1 record at ${url}`);
  return { keys, notes };
}

// ---- address checks (same ranges the registry refuses) ----

function ipv4Bytes(s) {
  const p = s.split('.');
  if (p.length !== 4) return null;
  const b = p.map((x) => (/^\d{1,3}$/.test(x) ? Number(x) : NaN));
  return b.every((x) => x >= 0 && x <= 255) ? b : null;
}

function ipv6Bytes(s) {
  let t = s.split('%')[0];
  const lastColon = t.lastIndexOf(':');
  if (t.slice(lastColon + 1).includes('.')) {
    // Embedded dotted quad, as in ::ffff:127.0.0.1: rewrite it as two hex words.
    const v4 = ipv4Bytes(t.slice(lastColon + 1));
    if (!v4) return null;
    t = t.slice(0, lastColon + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = t.split('::');
  if (halves.length > 2) return null;
  const parse = (h) => (h === '' ? [] : h.split(':').map((x) => (/^[0-9a-fA-F]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
  const head = parse(halves[0]);
  const back = halves.length === 2 ? parse(halves[1]) : [];
  if ([...head, ...back].some(Number.isNaN)) return null;
  let full;
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 1) return null;
    full = [...head, ...Array(fill).fill(0), ...back];
  } else full = head;
  if (full.length !== 8) return null;
  return full.flatMap((w) => [w >> 8, w & 0xff]);
}

function v4Blocked([a, b]) {
  return (
    a === 0 || // "this network", unspecified
    a === 10 || // private
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // CGNAT 100.64.0.0/10
    (a === 169 && b === 254) || // link local
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 192 && b === 168) || // private
    a >= 224 // multicast 224/4, reserved 240/4, broadcast
  );
}

// true when the address may be fetched from (a public unicast address).
export function isPublicAddress(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return !v4Blocked(ipv4Bytes(ip));
  if (fam !== 6) return false;
  const b = ipv6Bytes(ip);
  if (!b) return false;
  const zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return !v4Blocked(b.slice(12)); // IPv4 mapped
  if (zero(0, 12)) return false; // ::, ::1 and IPv4 compatible
  if ((b[0] & 0xfe) === 0xfc) return false; // unique local fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return false; // link local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return false; // site local fec0::/10
  if (b[0] === 0xff) return false; // multicast
  if (b[0] === 0x20 && b[1] === 0x02) return false; // 6to4 2002::/16
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) return false; // NAT64 64:ff9b::/96
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b[4] === 0x00 && b[5] === 0x01) return false; // 64:ff9b:1::/48
  return true;
}

// For each attempt: resolve the host, drop every address that is not public,
// and dial the remaining checked addresses in order (3 seconds each) until one
// connects, as the registry's dialer does. Only a checked address is dialed, so
// a second DNS answer cannot point the request at an internal host. When no
// public address is left the fetch is refused. TLS name checks and the Host
// header still use the host name.
// opts (tests only): lookupAll, transport, attemptTimeoutMs, overallTimeoutMs,
// attempts, allowAddress, dialTimeoutMs
export async function httpsGetText(url, opts = {}) {
  const {
    lookupAll = (host) => dns.promises.lookup(host, { all: true, verbatim: true }),
    transport = https,
    attemptTimeoutMs = HTTP_ATTEMPT_TIMEOUT_MS,
    overallTimeoutMs = HTTP_OVERALL_TIMEOUT_MS,
    attempts = HTTP_ATTEMPTS,
    allowAddress = isPublicAddress,
    dialTimeoutMs = HTTP_PER_ADDRESS_DIAL_MS,
  } = opts;
  const deadline = Date.now() + overallTimeoutMs;
  const pause = () => new Promise((r) => setTimeout(r, Math.min(HTTP_RETRY_BACKOFF_MS, Math.max(0, deadline - Date.now()))));
  let lastError;
  for (let n = 0; n < attempts; n++) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    try {
      const res = await getOnce(url, { lookupAll, transport, allowAddress, dialTimeoutMs, timeoutMs: Math.min(attemptTimeoutMs, left) });
      if (isTransientStatus(res.status) && n + 1 < attempts) {
        lastError = new Error(`HTTP ${res.status}`);
        await pause();
        continue;
      }
      return res;
    } catch (e) {
      lastError = e;
      if (e.refused) throw e; // a refused address is not retried
      if (n + 1 < attempts) await pause();
    }
  }
  throw lastError || new Error('timed out');
}

async function getOnce(url, { lookupAll, transport, allowAddress, dialTimeoutMs, timeoutMs }) {
  const attemptDeadline = Date.now() + timeoutMs;
  const host = new URL(url).hostname;
  let addrs;
  try {
    addrs = await lookupAll(host);
  } catch (e) {
    throw new Error(`could not resolve host (${e && e.code ? e.code : 'error'})`);
  }
  if (!addrs.length) throw new Error('host has no address');
  const checked = addrs.filter((a) => allowAddress(a.address));
  if (!checked.length) {
    const e = new Error('refusing to connect: every address of the host is private, loopback, link local or otherwise not public');
    e.refused = true;
    throw e;
  }
  let lastDialError;
  for (const addr of checked) {
    const left = attemptDeadline - Date.now();
    if (left <= 0) break;
    try {
      return await requestVia(url, addr, { transport, timeoutMs: left, dialTimeoutMs: Math.min(dialTimeoutMs, left) });
    } catch (e) {
      if (!e.dialFailed) throw e; // connected, then failed: not a reason to try another address
      lastDialError = e;
    }
  }
  throw new Error(`all resolved public addresses failed${lastDialError ? ` (last: ${lastDialError.message})` : ' (timed out)'}`);
}

// One request, dialed to one checked address. agent: false, so no pooled
// socket (connected to some other address) is reused.
function requestVia(url, addr, { transport, timeoutMs, dialTimeoutMs }) {
  return new Promise((resolve, reject) => {
    let done = false;
    let connected = false;
    const finish = (fn, v) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(dialTimer);
      fn(v);
    };
    const family = addr.family === 6 || addr.family === 'IPv6' ? 6 : 4;
    const req = transport.get(
      url,
      {
        agent: false,
        headers: { Accept: 'text/plain', 'User-Agent': HTTP_USER_AGENT },
        lookup: (_h, o, cb) => (o && o.all ? cb(null, [{ address: addr.address, family }]) : cb(null, addr.address, family)),
      },
      (res) => {
        connected = true;
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > MAX_KEY_RESPONSE) {
            req.destroy();
            finish(reject, new Error(`body larger than ${MAX_KEY_RESPONSE} bytes`));
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => finish(resolve, { status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', (e) => finish(reject, e));
      },
    );
    req.on('socket', (sock) => {
      if (!sock.connecting) connected = true;
      else sock.once('connect', () => (connected = true));
    });
    const dialTimer = setTimeout(() => {
      if (connected) return;
      const e = new Error(`connect to ${addr.address} timed out`);
      e.dialFailed = true;
      req.destroy();
      finish(reject, e);
    }, dialTimeoutMs);
    // Whole request limit, not only socket idle time.
    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, new Error('timed out'));
    }, timeoutMs);
    req.on('error', (e) => {
      if (!connected) e.dialFailed = true;
      finish(reject, e);
    });
  });
}

// Resolver: replaceable in tests, to check the options it is built with.
export function dnsResolverFor(server, { Resolver = dns.promises.Resolver } = {}) {
  const r = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
  if (server) {
    if (!net.isIP(server)) throw new TypeError('--dns-server must be an IP address');
    r.setServers([server]);
  }
  return r;
}
